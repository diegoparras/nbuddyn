//! Keeps the secrets nbuddyn stores unreadable on disk.
//!
//! The addresses of other n8n databases and of Redis carry passwords, and so
//! do alert destinations. They are sealed with ChaCha20-Poly1305 before they
//! are written, so the settings file alone, in a backup or a copied volume,
//! gives nothing away. The key comes from `NBUDDYN_SECRET_KEY`; without it
//! nbuddyn makes one and keeps it in its data directory, which protects the
//! file when it travels alone but not against someone who has the whole
//! directory.

use std::path::Path;

use base64::Engine;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305, NONCE_LEN};
use sha2::{Digest, Sha256};

/// What every sealed value starts with, so plain ones are told apart.
const PREFIX: &str = "enc:v1:";
const KEY_FILE: &str = "secret.key";
/// The shortest key accepted from the environment.
pub const KEY_MIN: usize = 32;

/// Where the key came from, to tell the administrator how safe it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    /// `NBUDDYN_SECRET_KEY`: the key is not in the data directory.
    Environment,
    /// Made by nbuddyn and kept next to what it protects.
    DataDirectory,
}

pub struct Vault {
    key: LessSafeKey,
    pub source: KeySource,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the key itself.
        write!(f, "Vault({:?})", self.source)
    }
}

impl Vault {
    /// Uses the key from the environment, or else the one in the data
    /// directory, making it the first time.
    pub fn open(from_environment: Option<&str>, dir: &Path) -> Result<Self, String> {
        match from_environment {
            Some(secret) if secret.len() < KEY_MIN => Err(format!(
                "NBUDDYN_SECRET_KEY must be at least {KEY_MIN} characters"
            )),
            Some(secret) => Ok(Self::from_secret(secret.as_bytes(), KeySource::Environment)),
            None => {
                let file = dir.join(KEY_FILE);
                let secret = match std::fs::read(&file) {
                    Ok(secret) if secret.len() >= KEY_MIN => secret,
                    Ok(_) => return Err(format!("{} is too short to be a key", file.display())),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        let mut fresh = [0u8; 48];
                        getrandom::fill(&mut fresh).map_err(|e| e.to_string())?;
                        let text = base64::engine::general_purpose::STANDARD.encode(fresh);
                        write_private(dir, &file, text.as_bytes())
                            .map_err(|e| format!("cannot write {}: {e}", file.display()))?;
                        text.into_bytes()
                    }
                    Err(e) => return Err(format!("cannot read {}: {e}", file.display())),
                };
                Ok(Self::from_secret(&secret, KeySource::DataDirectory))
            }
        }
    }

    fn from_secret(secret: &[u8], source: KeySource) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"nbuddyn settings key v1\0");
        hasher.update(secret);
        let unbound = UnboundKey::new(&CHACHA20_POLY1305, &hasher.finalize())
            .expect("a SHA-256 digest is the size of a ChaCha20 key");
        Self {
            key: LessSafeKey::new(unbound),
            source,
        }
    }

    /// Seals a value. An empty value stays empty: there is nothing to hide,
    /// and "not set" should stay readable.
    pub fn seal(&self, plain: &str) -> Result<String, String> {
        if plain.is_empty() || plain.starts_with(PREFIX) {
            return Ok(plain.to_owned());
        }
        // A fresh random nonce per value: the same text never seals the same way.
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|e| e.to_string())?;
        let mut data = plain.as_bytes().to_vec();
        self.key
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut data)
            .map_err(|_| "could not seal a setting".to_owned())?;
        let mut sealed = nonce.to_vec();
        sealed.extend_from_slice(&data);
        Ok(format!(
            "{PREFIX}{}",
            base64::engine::general_purpose::STANDARD.encode(sealed)
        ))
    }

    /// Opens a sealed value. A value that was never sealed comes back as it
    /// is, so files written before sealing existed keep working.
    pub fn open_value(&self, stored: &str) -> Result<String, String> {
        let Some(encoded) = stored.strip_prefix(PREFIX) else {
            return Ok(stored.to_owned());
        };
        let wrong = || {
            "a saved setting cannot be opened with this key: NBUDDYN_SECRET_KEY changed, or \
             the key file is not the one these settings were saved with"
                .to_owned()
        };
        let mut sealed = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| wrong())?;
        if sealed.len() < NONCE_LEN {
            return Err(wrong());
        }
        let data = sealed.split_off(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(&sealed).map_err(|_| wrong())?;
        let mut data = data;
        let plain = self
            .key
            .open_in_place(nonce, Aad::empty(), &mut data)
            .map_err(|_| wrong())?;
        String::from_utf8(plain.to_vec()).map_err(|_| wrong())
    }
}

/// True when a stored value is sealed.
pub fn is_sealed(stored: &str) -> bool {
    stored.starts_with(PREFIX)
}

/// Writes a file only its owner can read.
fn write_private(dir: &Path, file: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    std::fs::create_dir_all(dir)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut out = options.open(file)?;
    out.write_all(bytes)?;
    out.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "a-key-that-is-long-enough-for-nbuddyn";

    #[test]
    fn a_sealed_value_opens_with_the_same_key_and_only_with_it() {
        let dir = std::env::temp_dir();
        let vault = Vault::open(Some(KEY), &dir).unwrap();
        let sealed = vault.seal("postgres://ro:s3cret@db:5432/n8n").unwrap();
        assert!(is_sealed(&sealed));
        assert!(!sealed.contains("s3cret"));
        assert_eq!(
            vault.open_value(&sealed).unwrap(),
            "postgres://ro:s3cret@db:5432/n8n"
        );
        // Sealing twice gives different text, and never seals a sealed value again.
        assert_ne!(
            vault.seal("postgres://ro:s3cret@db:5432/n8n").unwrap(),
            sealed
        );
        assert_eq!(vault.seal(&sealed).unwrap(), sealed);

        let other = Vault::open(Some("another-key-that-is-also-long-enough"), &dir).unwrap();
        assert!(other
            .open_value(&sealed)
            .unwrap_err()
            .contains("NBUDDYN_SECRET_KEY"));
        let mut tampered = sealed.clone();
        tampered.pop();
        tampered.push('A');
        assert!(vault.open_value(&tampered).is_err());
    }

    #[test]
    fn plain_and_empty_values_pass_through() {
        let vault = Vault::open(Some(KEY), &std::env::temp_dir()).unwrap();
        assert_eq!(
            vault.open_value("redis://n8n_redis:6379").unwrap(),
            "redis://n8n_redis:6379"
        );
        assert_eq!(vault.seal("").unwrap(), "");
        assert!(Vault::open(Some("short"), &std::env::temp_dir()).is_err());
    }

    #[test]
    fn without_a_key_one_is_made_once_and_kept_private() {
        let dir = std::env::temp_dir().join(format!("nbuddyn-vault-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let first = Vault::open(None, &dir).unwrap();
        assert_eq!(first.source, KeySource::DataDirectory);
        let sealed = first.seal("secret").unwrap();
        // A restart finds the same key.
        let second = Vault::open(None, &dir).unwrap();
        assert_eq!(second.open_value(&sealed).unwrap(), "secret");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join(KEY_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
