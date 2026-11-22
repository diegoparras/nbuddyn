//! Encrypted connections to n8n's Postgres and Redis.
//!
//! Two levels, the same two Postgres itself has: encrypt without asking who
//! is on the other side (enough against someone listening on the network), or
//! encrypt and check the server's certificate against known authorities (also
//! protects against someone pretending to be the server).

use std::sync::{Arc, OnceLock};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ring, verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

/// How much the server has to prove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// Encrypt, and accept whatever certificate the server shows.
    Any,
    /// Encrypt, and only talk to a server whose certificate checks out.
    Verified,
}

/// Extra authorities to trust, as PEM: for servers with a private authority,
/// which is most managed databases.
static EXTRA_ROOTS: OnceLock<Vec<CertificateDer<'static>>> = OnceLock::new();

/// Reads `NBUDDYN_CA_FILE` once at start, so a bad file stops nbuddyn with a
/// clear message instead of failing every scan.
pub fn load_extra_roots(path: Option<&str>) -> Result<(), String> {
    let certificates = match path {
        None => Vec::new(),
        Some(path) => {
            let pem = std::fs::read(path)
                .map_err(|e| format!("NBUDDYN_CA_FILE: cannot read {path}: {e}"))?;
            let found: Vec<_> = rustls_pemfile::certs(&mut pem.as_slice())
                .collect::<Result<_, _>>()
                .map_err(|e| format!("NBUDDYN_CA_FILE: {path} is not valid PEM: {e}"))?;
            if found.is_empty() {
                return Err(format!("NBUDDYN_CA_FILE: {path} holds no certificate"));
            }
            found
        }
    };
    let _ = EXTRA_ROOTS.set(certificates);
    Ok(())
}

pub fn client_config(trust: Trust) -> Result<ClientConfig, String> {
    let provider = Arc::new(ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?;
    Ok(match trust {
        Trust::Any => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAny(provider)))
            .with_no_client_auth(),
        Trust::Verified => {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            for certificate in EXTRA_ROOTS.get().into_iter().flatten() {
                roots
                    .add(certificate.clone())
                    .map_err(|e| format!("NBUDDYN_CA_FILE holds an unusable certificate: {e}"))?;
            }
            builder.with_root_certificates(roots).with_no_client_auth()
        }
    })
}

/// Accepts any certificate but still checks the handshake's signatures, so
/// the connection is encrypted to whoever holds that certificate's key.
#[derive(Debug)]
struct AcceptAny(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// What `sslmode` in a Postgres address asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostgresTls {
    /// `sslmode=disable`.
    Off,
    /// No `sslmode`, or `prefer`: encrypted when the server offers it.
    IfOffered,
    /// `sslmode=require`: encrypted or nothing.
    Required,
    /// `sslmode=verify-ca` or `verify-full`: encrypted and the server checked.
    Verified,
}

/// Takes `sslmode` out of a Postgres address and says what it asked for. The
/// driver does not know the `verify-` values, so they are handled here.
pub fn split_sslmode(url: &str) -> Result<(String, PostgresTls), String> {
    let Some((base, query)) = url.split_once('?') else {
        return Ok((url.to_owned(), PostgresTls::IfOffered));
    };
    let mut mode = PostgresTls::IfOffered;
    let mut kept = Vec::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        match pair.strip_prefix("sslmode=") {
            None => kept.push(pair),
            Some("disable") => mode = PostgresTls::Off,
            Some("prefer" | "allow") => mode = PostgresTls::IfOffered,
            Some("require") => mode = PostgresTls::Required,
            Some("verify-ca" | "verify-full") => mode = PostgresTls::Verified,
            Some(other) => return Err(format!("sslmode={other} is not one nbuddyn knows")),
        }
    }
    let url = if kept.is_empty() {
        base.to_owned()
    } else {
        format!("{base}?{}", kept.join("&"))
    };
    Ok((url, mode))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sslmode_is_taken_out_of_the_address() {
        let split = |url| split_sslmode(url).unwrap();
        assert_eq!(
            split("postgres://u:p@db/n8n"),
            ("postgres://u:p@db/n8n".into(), PostgresTls::IfOffered)
        );
        assert_eq!(
            split("postgres://u:p@db/n8n?sslmode=verify-full&connect_timeout=5"),
            (
                "postgres://u:p@db/n8n?connect_timeout=5".into(),
                PostgresTls::Verified
            )
        );
        assert_eq!(
            split("postgres://db/n8n?sslmode=require").1,
            PostgresTls::Required
        );
        assert_eq!(
            split("postgres://db/n8n?sslmode=disable").1,
            PostgresTls::Off
        );
        assert!(split_sslmode("postgres://db/n8n?sslmode=maybe").is_err());
    }

    #[test]
    fn both_levels_of_trust_build_a_configuration() {
        assert!(client_config(Trust::Any).is_ok());
        assert!(client_config(Trust::Verified).is_ok());
    }
}
