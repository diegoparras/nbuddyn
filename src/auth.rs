//! Who may use nbuddyn: users with a role, the sessions they hold, the brake
//! on password guessing, and the record of who did what.
//!
//! The administrator named in the environment always exists, so nobody can
//! lock themselves out. Other users live in `users.json` in the data
//! directory, with their passwords stored only as slow salted hashes.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::history::write_atomically;

const USERS_FILE: &str = "users.json";
const AUDIT_FILE: &str = "audit.json";
const SESSIONS_FILE: &str = "sessions.json";

/// Rounds of PBKDF2-HMAC-SHA256 for new passwords. Stored with each hash, so
/// raising it later does not break existing ones.
#[cfg(not(test))]
const ROUNDS: u32 = 310_000;
/// Tests check the logic, not the slowness.
#[cfg(test)]
const ROUNDS: u32 = 1_000;
/// The shortest password a user can be given.
pub const PASSWORD_MIN: usize = 10;
/// A session ends this long after it was opened.
const SESSION_SECONDS: u64 = 12 * 3600;
/// Wrong passwords in a row before a name is made to wait.
const FREE_TRIES: u32 = 5;
/// The first wait, doubled with every further wrong password.
const FIRST_WAIT: u64 = 30;
const LONGEST_WAIT: u64 = 15 * 60;
/// How many audit entries are kept.
const AUDIT_MAX: usize = 2000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Can read everything and change everything nbuddyn keeps.
    Admin,
    /// Can read reports. Cannot accept findings, change settings or see users.
    Viewer,
}

/// Who a request comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub name: String,
    pub role: Role,
}

impl Identity {
    pub fn is_admin(&self) -> bool {
        self.role == Role::Admin
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub name: String,
    pub role: Role,
    /// Hex. Random, one per user.
    salt: String,
    /// Hex. PBKDF2-HMAC-SHA256 of the password.
    hash: String,
    rounds: u32,
    /// Seconds since 1970.
    pub created: u64,
}

/// One line of the record of who did what.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Seconds since 1970.
    pub at: u64,
    pub user: String,
    /// `login`, `login_failed`, `logout`, `accept`, `unaccept`, `settings`,
    /// `instance_add`, `instance_remove`, `user_add`, `user_remove`.
    pub action: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

/// An open session. Kept by the hash of its token, in memory and on disk, so
/// neither holds anything a thief could present as a session.
#[derive(Clone, Serialize, Deserialize)]
struct Session {
    identity: Identity,
    expires: u64,
}

#[derive(Default)]
struct Tries {
    wrong: u32,
    /// Seconds since 1970 until which this name must wait.
    wait_until: u64,
}

/// Why a login did not go through.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    Wrong,
    /// Too many wrong passwords; try again in this many seconds.
    Wait(u64),
}

pub struct Auth {
    /// The administrator from the environment.
    env_user: String,
    /// `None` leaves nbuddyn open: everyone is an administrator.
    env_password: Option<String>,
    /// `None` when there is nowhere to keep users or the audit record.
    dir: Option<PathBuf>,
    users: Mutex<Vec<User>>,
    sessions: Mutex<HashMap<String, Session>>,
    tries: Mutex<HashMap<String, Tries>>,
    audit: Mutex<Vec<AuditEntry>>,
}

impl Auth {
    pub fn new(env_user: String, env_password: Option<String>, dir: Option<PathBuf>) -> Self {
        let read = |file: &str| {
            dir.as_ref()
                .and_then(|d| std::fs::read_to_string(d.join(file)).ok())
        };
        let users = read(USERS_FILE)
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default();
        let audit = read(AUDIT_FILE)
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default();
        // Sessions outlive a restart, so updating nbuddyn signs nobody out.
        let sessions: HashMap<String, Session> = read(SESSIONS_FILE)
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default();
        Self {
            env_user,
            env_password,
            dir,
            users: Mutex::new(users),
            sessions: Mutex::new(sessions),
            tries: Mutex::new(HashMap::new()),
            audit: Mutex::new(audit),
        }
    }

    /// True when nbuddyn was told to run without a login.
    pub fn open(&self) -> bool {
        self.env_password.is_none()
    }

    /// Whether users can be added: only with somewhere to keep them.
    pub fn can_store(&self) -> bool {
        self.dir.is_some()
    }

    /// The administrator from the environment, as the page lists users.
    pub fn fixed_user<T: From<(String, Role)>>(&self) -> Option<T> {
        self.env_password
            .as_ref()
            .map(|_| T::from((self.env_user.clone(), Role::Admin)))
    }

    pub fn anonymous(&self) -> Identity {
        Identity {
            name: "anonymous".into(),
            role: Role::Admin,
        }
    }

    /// Checks a name and password. Slow on purpose, so call it off the async
    /// threads. Takes the same time whether or not the name exists.
    pub fn check(&self, name: &str, password: &str, now: u64) -> Result<Identity, Refusal> {
        let key: String = name.trim().to_lowercase().chars().take(64).collect();
        if let Some(wait) = self.waiting(&key, now) {
            return Err(Refusal::Wait(wait));
        }

        let stored = lock(&self.users)
            .iter()
            .find(|u| u.name.to_lowercase() == key)
            .cloned();
        let identity = match (&stored, &self.env_password) {
            (_, Some(expected))
                if key == self.env_user.to_lowercase()
                    && constant_time_eq(password.as_bytes(), expected.as_bytes()) =>
            {
                Some(Identity {
                    name: self.env_user.clone(),
                    role: Role::Admin,
                })
            }
            (Some(user), _) => {
                let given = derive(password, &user.salt, user.rounds);
                constant_time_eq(given.as_bytes(), user.hash.as_bytes()).then(|| Identity {
                    name: user.name.clone(),
                    role: user.role,
                })
            }
            (None, _) => {
                // Spend the same effort as for a real user.
                let _ = derive(password, "00", ROUNDS);
                None
            }
        };

        let mut tries = lock(&self.tries);
        match identity {
            Some(identity) => {
                tries.remove(&key);
                Ok(identity)
            }
            None => {
                let entry = tries.entry(key).or_default();
                entry.wrong += 1;
                if entry.wrong >= FREE_TRIES {
                    let doublings = (entry.wrong - FREE_TRIES).min(10);
                    let wait = (FIRST_WAIT << doublings).min(LONGEST_WAIT);
                    entry.wait_until = now + wait;
                }
                // Names nobody will try again should not pile up for ever.
                if tries.len() > 10_000 {
                    tries.retain(|_, t| t.wait_until > now);
                }
                Err(Refusal::Wrong)
            }
        }
    }

    fn waiting(&self, key: &str, now: u64) -> Option<u64> {
        lock(&self.tries)
            .get(key)
            .map(|t| t.wait_until.saturating_sub(now))
            .filter(|wait| *wait > 0)
    }

    /// Opens a session and returns the token that proves it.
    pub fn open_session(&self, identity: Identity, now: u64) -> String {
        let token = random_hex(32);
        let mut sessions = lock(&self.sessions);
        sessions.retain(|_, s| s.expires > now);
        sessions.insert(
            token_hash(&token),
            Session {
                identity,
                expires: now + SESSION_SECONDS,
            },
        );
        self.keep_sessions(&sessions);
        token
    }

    pub fn session(&self, token: &str, now: u64) -> Option<Identity> {
        lock(&self.sessions)
            .get(&token_hash(token))
            .filter(|s| s.expires > now)
            .map(|s| s.identity.clone())
    }

    pub fn close_session(&self, token: &str) {
        let mut sessions = lock(&self.sessions);
        sessions.remove(&token_hash(token));
        self.keep_sessions(&sessions);
    }

    /// Writes the open sessions down, when there is somewhere to. Failing to
    /// only costs a new sign-in after the next restart.
    fn keep_sessions(&self, sessions: &HashMap<String, Session>) {
        if self.dir.is_some() {
            let _ = self.write(SESSIONS_FILE, sessions);
        }
    }

    /// Seconds a session lasts, for the cookie.
    pub fn session_seconds(&self) -> u64 {
        SESSION_SECONDS
    }

    pub fn users(&self) -> Vec<User> {
        lock(&self.users).clone()
    }

    /// Adds a user or replaces the one with that name. Names the field that
    /// is not acceptable.
    pub fn save_user(
        &self,
        name: &str,
        password: &str,
        role: Role,
        now: u64,
    ) -> Result<(), &'static str> {
        let name = name.trim();
        let valid_name = (2..=40).contains(&name.chars().count())
            && name
                .chars()
                .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | '@'));
        if !valid_name || name.eq_ignore_ascii_case(&self.env_user) {
            return Err("user");
        }
        if password.chars().count() < PASSWORD_MIN {
            return Err("password");
        }
        let salt = random_hex(16);
        let user = User {
            name: name.to_owned(),
            role,
            hash: derive(password, &salt, ROUNDS),
            salt,
            rounds: ROUNDS,
            created: now,
        };
        let mut users = lock(&self.users);
        let mut next = users.clone();
        next.retain(|u| !u.name.eq_ignore_ascii_case(name));
        next.push(user);
        self.write(USERS_FILE, &next).map_err(|_| "store")?;
        *users = next;
        Ok(())
    }

    /// Removes a user and ends their sessions.
    pub fn remove_user(&self, name: &str) -> bool {
        let mut users = lock(&self.users);
        let mut next = users.clone();
        next.retain(|u| !u.name.eq_ignore_ascii_case(name));
        if next.len() == users.len() || self.write(USERS_FILE, &next).is_err() {
            return false;
        }
        *users = next;
        let mut sessions = lock(&self.sessions);
        sessions.retain(|_, s| !s.identity.name.eq_ignore_ascii_case(name));
        self.keep_sessions(&sessions);
        true
    }

    /// Writes down that someone did something.
    pub fn record(&self, at: u64, user: &str, action: &str, detail: &str) {
        let mut audit = lock(&self.audit);
        audit.push(AuditEntry {
            at,
            user: user.chars().take(64).collect(),
            action: action.to_owned(),
            detail: detail.chars().take(300).collect(),
        });
        if audit.len() > AUDIT_MAX {
            let extra = audit.len() - AUDIT_MAX;
            audit.drain(..extra);
        }
        if let Err(reason) = self.write(AUDIT_FILE, &*audit) {
            eprintln!("audit record not saved: {reason}");
        }
    }

    /// The latest entries, newest first.
    pub fn audit(&self, limit: usize) -> Vec<AuditEntry> {
        lock(&self.audit)
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    fn write<T: Serialize>(&self, file: &str, value: &T) -> Result<(), String> {
        let Some(dir) = &self.dir else {
            return Err("no data directory".into());
        };
        let text = serde_json::to_string(value).map_err(|e| e.to_string())?;
        write_atomically(dir, &dir.join(file), text.as_bytes()).map_err(|e| e.to_string())
    }
}

/// A poisoned lock only means another request panicked; the data is still
/// what it was.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Compares without leaking, through timing, how many leading bytes matched.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// What a session is filed under: a token cannot be worked back from it.
pub(crate) fn token_hash(token: &str) -> String {
    use sha2::Digest;
    hex(&Sha256::digest(token.as_bytes()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Random bytes from the operating system, as hex.
pub(crate) fn random_hex(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    getrandom::fill(&mut buffer).expect("the operating system provides randomness");
    hex(&buffer)
}

/// PBKDF2-HMAC-SHA256, one block: 32 bytes as hex.
fn derive(password: &str, salt: &str, rounds: u32) -> String {
    let prf = |data: &[u8]| -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(password.as_bytes())
            .expect("HMAC accepts a key of any length");
        mac.update(data);
        mac.finalize().into_bytes().into()
    };
    let mut first = salt.as_bytes().to_vec();
    first.extend_from_slice(&1u32.to_be_bytes());
    let mut block = prf(&first);
    let mut out = block;
    for _ in 1..rounds {
        block = prf(&block);
        for (o, b) in out.iter_mut().zip(block) {
            *o ^= b;
        }
    }
    hex(&out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth(dir: Option<PathBuf>) -> Auth {
        Auth::new("nbuddyn".into(), Some("env-secret".into()), dir)
    }

    #[test]
    fn pbkdf2_matches_the_published_test_vector() {
        // RFC 7914 section 11: PBKDF2-HMAC-SHA256, "passwd" / "salt", 1 round.
        assert_eq!(
            derive("passwd", "salt", 1),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
        );
        assert_ne!(derive("passwd", "salt", 2), derive("passwd", "salt", 1));
    }

    #[test]
    fn the_environment_administrator_always_gets_in() {
        let auth = auth(None);
        let who = auth.check("NBuddyn", "env-secret", 0).unwrap();
        assert_eq!((who.name.as_str(), who.role), ("nbuddyn", Role::Admin));
        assert_eq!(auth.check("nbuddyn", "env-secre", 0), Err(Refusal::Wrong));
        assert_eq!(auth.check("ghost", "env-secret", 0), Err(Refusal::Wrong));
        assert!(!auth.can_store());
        assert_eq!(
            auth.save_user("ana", "long-enough-pw", Role::Viewer, 0),
            Err("store")
        );
    }

    #[test]
    fn stored_users_log_in_with_their_role_and_never_as_the_administrator() {
        let dir = std::env::temp_dir().join(format!("nbuddyn-auth-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let first = auth(Some(dir.clone()));
        assert_eq!(
            first.save_user("ana", "short", Role::Viewer, 1),
            Err("password")
        );
        assert_eq!(
            first.save_user("a b", "long-enough-pw", Role::Viewer, 1),
            Err("user")
        );
        assert_eq!(
            first.save_user("nbuddyn", "long-enough-pw", Role::Viewer, 1),
            Err("user")
        );
        first
            .save_user("ana", "long-enough-pw", Role::Viewer, 1)
            .unwrap();

        // A restart reads the same users; the file holds no password.
        let auth = auth(Some(dir.clone()));
        let who = auth.check("Ana", "long-enough-pw", 5).unwrap();
        assert_eq!((who.name.as_str(), who.role), ("ana", Role::Viewer));
        assert!(!who.is_admin());
        assert_eq!(auth.check("ana", "long-enough-pW", 5), Err(Refusal::Wrong));
        let file = std::fs::read_to_string(dir.join(USERS_FILE)).unwrap();
        assert!(!file.contains("long-enough-pw"));

        let token = auth.open_session(who, 10);
        assert!(auth.session(&token, 11).is_some());
        assert!(auth.session(&token, 10 + SESSION_SECONDS).is_none());
        assert!(auth.session("not-a-token", 11).is_none());
        // The session survives a restart, and the file does not hold the token.
        let restarted = super::Auth::new(
            "nbuddyn".into(),
            Some("env-secret".into()),
            Some(dir.clone()),
        );
        assert_eq!(
            restarted.session(&token, 11).map(|w| w.name),
            Some("ana".to_owned())
        );
        assert!(!std::fs::read_to_string(dir.join(SESSIONS_FILE))
            .unwrap()
            .contains(&token));
        assert!(auth.remove_user("ANA"));
        assert!(auth.session(&token, 11).is_none());
        assert!(!auth.remove_user("ana"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn guessing_is_slowed_down_and_a_right_password_resets_it() {
        let auth = auth(None);
        for _ in 0..FREE_TRIES {
            assert_eq!(auth.check("nbuddyn", "guess", 100), Err(Refusal::Wrong));
        }
        // Even the right password has to wait now.
        assert_eq!(
            auth.check("nbuddyn", "env-secret", 101),
            Err(Refusal::Wait(FIRST_WAIT - 1))
        );
        assert_eq!(
            auth.check("nbuddyn", "guess", 100 + FIRST_WAIT),
            Err(Refusal::Wrong)
        );
        let after = 100 + FIRST_WAIT + 2 * FIRST_WAIT;
        assert!(auth.check("nbuddyn", "env-secret", after).is_ok());
        assert_eq!(auth.check("nbuddyn", "guess", after), Err(Refusal::Wrong));
        assert!(auth.check("nbuddyn", "env-secret", after).is_ok());
    }

    #[test]
    fn the_audit_record_keeps_the_latest_entries_newest_first() {
        let auth = auth(None);
        auth.record(1, "ana", "login", "");
        auth.record(2, "ana", "accept", "a webhook");
        let entries = auth.audit(10);
        assert_eq!(entries[0].action, "accept");
        assert_eq!(entries[1].action, "login");
        assert_eq!(auth.audit(1).len(), 1);
    }
}
