//! Signing in with the company's own accounts: OpenID Connect, the protocol
//! Google, Microsoft Entra, Okta and Keycloak all speak.
//!
//! nbuddyn sends the browser to the provider, gets back a one-time code,
//! trades it for a signed statement of who signed in, checks that signature
//! and what it says, and maps the e-mail address to a role. It never sees a
//! password. The flow uses PKCE and a nonce, and is tied to the browser that
//! started it.

use std::collections::HashMap;
use std::sync::Mutex;

use base64::Engine;
use ring::signature::{RsaPublicKeyComponents, RSA_PKCS1_2048_8192_SHA256};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::auth::Role;
use crate::http;

/// A sign-in must be finished within this long of being started.
const PENDING_SECONDS: u64 = 600;
/// Clocks differ; a statement this far past its expiry is still taken.
const CLOCK_LEEWAY: u64 = 60;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
    /// The provider's address, such as `https://accounts.google.com`.
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    /// Where the provider sends the browser back: nbuddyn's own public
    /// address plus `/auth/oidc/callback`.
    pub redirect_uri: String,
    /// What the button on the login page says.
    pub name: String,
    /// Who becomes an administrator: e-mail addresses, or `@domain` for
    /// everyone in a domain. Lowercase.
    pub admins: Vec<String>,
    /// Who may look but not change. Same form.
    pub viewers: Vec<String>,
}

impl Config {
    /// The role an e-mail address gets, or `None` when it gets none.
    pub fn role_of(&self, email: &str) -> Option<Role> {
        let email = email.trim().to_lowercase();
        let listed = |list: &[String]| {
            list.iter().any(|entry| match entry.strip_prefix('@') {
                Some(domain) => email
                    .rsplit_once('@')
                    .is_some_and(|(_, theirs)| theirs == domain),
                None => *entry == email,
            })
        };
        if listed(&self.admins) {
            Some(Role::Admin)
        } else if listed(&self.viewers) {
            Some(Role::Viewer)
        } else {
            None
        }
    }
}

/// Entries of a comma-separated list of e-mail addresses and `@domains`.
pub fn parse_people(list: &str) -> Vec<String> {
    list.split([',', ';', ' ', '\n'])
        .map(|entry| entry.trim().to_lowercase())
        .filter(|entry| entry.contains('@') && entry.len() > 1)
        .collect()
}

/// A sign-in that was started and not yet finished.
struct Pending {
    verifier: String,
    nonce: String,
    /// Also kept in a cookie of the browser that started it.
    binding: String,
    expires: u64,
}

/// Why a sign-in did not go through.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The provider vouched for someone who is on neither list.
    NotAllowed(String),
    /// Anything else, with a reason for the log.
    Failed(String),
}

pub struct Oidc {
    pub config: Config,
    pending: Mutex<HashMap<String, Pending>>,
}

/// What the provider publishes about itself.
struct Provider {
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

impl Oidc {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            pending: Mutex::new(HashMap::new()),
        }
    }

    async fn provider(&self) -> Result<Provider, String> {
        let url = format!(
            "{}/.well-known/openid-configuration",
            self.config.issuer.trim_end_matches('/')
        );
        let answer = http::get(&url).await?;
        if answer.status != 200 {
            return Err(format!(
                "the provider answered {} to discovery",
                answer.status
            ));
        }
        let document: Value = serde_json::from_str(&answer.body)
            .map_err(|_| "the provider's discovery document is not JSON".to_owned())?;
        let text = |key: &str| {
            document
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(format!("the provider's discovery document has no {key}"))
        };
        // A provider that names another issuer is not the one configured.
        if text("issuer")?.trim_end_matches('/') != self.config.issuer.trim_end_matches('/') {
            return Err("the provider names a different issuer than the one configured".into());
        }
        let provider = Provider {
            authorization_endpoint: text("authorization_endpoint")?,
            token_endpoint: text("token_endpoint")?,
            jwks_uri: text("jwks_uri")?,
        };
        for endpoint in [
            &provider.authorization_endpoint,
            &provider.token_endpoint,
            &provider.jwks_uri,
        ] {
            if !is_safe_address(endpoint) {
                return Err(format!("the provider's {endpoint} is not https"));
            }
        }
        Ok(provider)
    }

    /// Starts a sign-in: where to send the browser, and the value to leave in
    /// its cookie so only that browser can finish it.
    pub async fn start(&self, now: u64) -> Result<(String, String), String> {
        let provider = self.provider().await?;
        let state = random_token();
        let pending = Pending {
            verifier: random_token(),
            nonce: random_token(),
            binding: random_token(),
            expires: now + PENDING_SECONDS,
        };
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(pending.verifier.as_bytes()));
        let separator = if provider.authorization_endpoint.contains('?') {
            '&'
        } else {
            '?'
        };
        let url = format!(
            "{}{separator}response_type=code&client_id={}&redirect_uri={}&scope=openid%20email%20profile\
             &state={state}&nonce={}&code_challenge={challenge}&code_challenge_method=S256",
            provider.authorization_endpoint,
            encode(&self.config.client_id),
            encode(&self.config.redirect_uri),
            pending.nonce,
        );
        let binding = pending.binding.clone();
        let mut all = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        all.retain(|_, p| p.expires > now);
        // Nobody starts a thousand sign-ins by accident.
        if all.len() >= 1000 {
            return Err("too many sign-ins are under way".into());
        }
        all.insert(state, pending);
        Ok((url, binding))
    }

    /// Finishes a sign-in: who it was and what they may do.
    pub async fn finish(
        &self,
        code: &str,
        state: &str,
        binding: Option<&str>,
        now: u64,
    ) -> Result<(String, Role), Refusal> {
        let failed = |reason: &str| Refusal::Failed(reason.to_owned());
        let pending = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(state)
            .filter(|p| p.expires > now)
            .ok_or_else(|| failed("this sign-in was not started here, or took too long"))?;
        if binding != Some(pending.binding.as_str()) {
            return Err(failed("this sign-in was started in another browser"));
        }

        let provider = self.provider().await.map_err(Refusal::Failed)?;
        let form = format!(
            "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&client_secret={}&code_verifier={}",
            encode(code),
            encode(&self.config.redirect_uri),
            encode(&self.config.client_id),
            encode(&self.config.client_secret),
            pending.verifier,
        );
        let answer = http::post_form(&provider.token_endpoint, &form)
            .await
            .map_err(Refusal::Failed)?;
        let tokens: Value = serde_json::from_str(&answer.body)
            .map_err(|_| failed("the provider's answer to the code is not JSON"))?;
        let id_token = tokens
            .get("id_token")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                let why = tokens
                    .get("error_description")
                    .or_else(|| tokens.get("error"))
                    .and_then(Value::as_str)
                    .unwrap_or("no id_token");
                Refusal::Failed(format!("the provider refused the code: {why}"))
            })?;

        let keys = http::get(&provider.jwks_uri)
            .await
            .map_err(Refusal::Failed)?;
        let claims = verify(id_token, &keys.body).map_err(Refusal::Failed)?;
        let email =
            check_claims(&claims, &self.config, &pending.nonce, now).map_err(Refusal::Failed)?;
        match self.config.role_of(&email) {
            Some(role) => Ok((email, role)),
            None => Err(Refusal::NotAllowed(email)),
        }
    }
}

/// `https`, or plain `http` only towards this same machine, for tests.
fn is_safe_address(url: &str) -> bool {
    url.starts_with("https://")
        || url.starts_with("http://127.0.0.1")
        || url.starts_with("http://localhost")
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("the operating system provides randomness");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Percent-encodes a value for an address or a form.
fn encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn from_base64url(text: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text.trim_end_matches('='))
        .map_err(|_| "the provider's statement is not well formed".to_owned())
}

/// Checks the signature of a signed statement against the provider's keys
/// and returns what it states. Only RS256, which every major provider uses.
fn verify(token: &str, keys_json: &str) -> Result<Value, String> {
    let mut parts = token.split('.');
    let (Some(head), Some(body), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("the provider's statement is not well formed".into());
    };
    let header: Value = serde_json::from_slice(&from_base64url(head)?)
        .map_err(|_| "the provider's statement is not well formed".to_owned())?;
    if header.get("alg").and_then(Value::as_str) != Some("RS256") {
        return Err("the provider signs with something other than RS256".into());
    }
    let wanted = header.get("kid").and_then(Value::as_str);

    let keys: Value = serde_json::from_str(keys_json)
        .map_err(|_| "the provider's keys are not JSON".to_owned())?;
    let candidates: Vec<&Value> = keys
        .get("keys")
        .and_then(Value::as_array)
        .map(|all| {
            all.iter()
                .filter(|k| k.get("kty").and_then(Value::as_str) == Some("RSA"))
                .filter(|k| wanted.is_none() || k.get("kid").and_then(Value::as_str) == wanted)
                .collect()
        })
        .unwrap_or_default();

    let message = format!("{head}.{body}");
    let signature = from_base64url(signature)?;
    let signed = candidates.iter().any(|key| {
        let part = |name: &str| {
            key.get(name)
                .and_then(Value::as_str)
                .and_then(|text| from_base64url(text).ok())
        };
        match (part("n"), part("e")) {
            (Some(n), Some(e)) => RsaPublicKeyComponents { n, e }
                .verify(&RSA_PKCS1_2048_8192_SHA256, message.as_bytes(), &signature)
                .is_ok(),
            _ => false,
        }
    });
    if !signed {
        return Err("the provider's statement is not signed by any of its keys".into());
    }
    serde_json::from_slice(&from_base64url(body)?)
        .map_err(|_| "the provider's statement is not well formed".to_owned())
}

/// Checks that a verified statement is for this nbuddyn, for this sign-in,
/// still valid, and about a confirmed e-mail address. Returns the address.
fn check_claims(claims: &Value, config: &Config, nonce: &str, now: u64) -> Result<String, String> {
    let text = |key: &str| claims.get(key).and_then(Value::as_str);
    if text("iss").map(|i| i.trim_end_matches('/')) != Some(config.issuer.trim_end_matches('/')) {
        return Err("the statement comes from another issuer".into());
    }
    let for_us = match claims.get("aud") {
        Some(Value::String(audience)) => *audience == config.client_id,
        Some(Value::Array(audiences)) => audiences
            .iter()
            .any(|a| a.as_str() == Some(config.client_id.as_str())),
        _ => false,
    };
    if !for_us {
        return Err("the statement was made for another application".into());
    }
    if claims.get("exp").and_then(Value::as_u64).unwrap_or(0) + CLOCK_LEEWAY < now {
        return Err("the statement has expired".into());
    }
    if text("nonce") != Some(nonce) {
        return Err("the statement belongs to another sign-in".into());
    }
    if claims.get("email_verified").and_then(Value::as_bool) == Some(false) {
        return Err("the provider has not confirmed this e-mail address".into());
    }
    text("email")
        .map(|email| email.trim().to_lowercase())
        .filter(|email| email.contains('@'))
        .ok_or_else(|| "the statement names no e-mail address".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config {
            issuer: "https://id.example.com".into(),
            client_id: "nbuddyn-client".into(),
            admins: parse_people("ana@example.com, @ops.example.com"),
            viewers: parse_people("@example.com"),
            ..Config::default()
        }
    }

    #[test]
    fn roles_come_from_the_lists_and_strangers_get_none() {
        let config = config();
        assert_eq!(config.role_of("Ana@Example.com"), Some(Role::Admin));
        assert_eq!(config.role_of("leo@ops.example.com"), Some(Role::Admin));
        assert_eq!(config.role_of("bea@example.com"), Some(Role::Viewer));
        assert_eq!(config.role_of("eve@evil.com"), None);
        // A domain that merely ends the same is another domain.
        assert_eq!(config.role_of("eve@notexample.com"), None);
        assert_eq!(config.role_of("eve@example.com.evil.com"), None);
        assert_eq!(parse_people("not-an-address, ,@"), Vec::<String>::new());
    }

    #[test]
    fn a_statement_must_be_for_us_fresh_and_about_this_sign_in() {
        let config = config();
        let good = serde_json::json!({
            "iss": "https://id.example.com/", "aud": ["other", "nbuddyn-client"], "exp": 1000,
            "nonce": "n1", "email": "Ana@Example.com", "email_verified": true
        });
        assert_eq!(
            check_claims(&good, &config, "n1", 900).unwrap(),
            "ana@example.com"
        );
        assert_eq!(
            check_claims(&good, &config, "n1", 1050).unwrap(),
            "ana@example.com"
        );
        let with = |key: &str, value: Value| {
            let mut changed = good.clone();
            changed[key] = value;
            changed
        };
        assert!(check_claims(&good, &config, "n1", 1100)
            .unwrap_err()
            .contains("expired"));
        assert!(check_claims(&good, &config, "n2", 900)
            .unwrap_err()
            .contains("another sign-in"));
        assert!(check_claims(
            &with("iss", "https://evil.example.com".into()),
            &config,
            "n1",
            900
        )
        .is_err());
        assert!(check_claims(&with("aud", "someone-else".into()), &config, "n1", 900).is_err());
        assert!(check_claims(&with("email_verified", false.into()), &config, "n1", 900).is_err());
        assert!(check_claims(&with("email", Value::Null), &config, "n1", 900).is_err());
    }

    #[test]
    fn a_statement_with_a_bad_signature_or_another_algorithm_is_refused() {
        let b64 = |text: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(text);
        let keys = r#"{"keys":[{"kty":"RSA","kid":"k1","n":"AQAB","e":"AQAB"}]}"#;
        let unsigned = format!(
            "{}.{}.",
            b64(r#"{"alg":"none"}"#),
            b64(r#"{"email":"ana@example.com"}"#)
        );
        assert!(verify(&unsigned, keys).unwrap_err().contains("RS256"));
        let forged = format!(
            "{}.{}.{}",
            b64(r#"{"alg":"RS256","kid":"k1"}"#),
            b64(r#"{"email":"ana@example.com"}"#),
            b64("not a signature")
        );
        assert!(verify(&forged, keys).unwrap_err().contains("not signed"));
        assert!(verify("only.two", keys).is_err());
    }

    #[test]
    fn values_are_encoded_for_addresses_and_forms() {
        assert_eq!(
            encode("https://nb.example.com/auth/oidc/callback"),
            "https%3A%2F%2Fnb.example.com%2Fauth%2Foidc%2Fcallback"
        );
        assert_eq!(encode("a b&c=d+e"), "a%20b%26c%3Dd%2Be");
        assert!(
            is_safe_address("https://id.example.com/x")
                && is_safe_address("http://127.0.0.1:5800/x")
        );
        assert!(!is_safe_address("http://id.example.com/x"));
    }
}
