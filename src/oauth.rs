//! Lets an assistant connect to the MCP endpoint by signing in, instead of
//! being handed a token to paste.
//!
//! This is the small OAuth 2.1 authorization server the MCP specification
//! asks for: an assistant registers itself, sends the person to nbuddyn, an
//! administrator who is signed in says yes, and the assistant gets a token
//! that only opens the read-only MCP endpoint. Tokens are random, are kept
//! only as hashes, and can be taken back from Settings.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::auth::{random_hex, token_hash, Identity};
use crate::web::{self, AppState};

/// How long someone has to say yes after an assistant sends them here.
const PENDING_SECONDS: u64 = 600;
/// How long an assistant has to trade its code for a token.
const CODE_SECONDS: u64 = 300;
/// An access token is short-lived; the assistant renews it by itself.
const ACCESS_SECONDS: u64 = 3600;
/// A connection nobody uses for this long ends.
const REFRESH_SECONDS: u64 = 90 * 24 * 3600;
const MAX_CLIENTS: usize = 200;
const MAX_PENDING: usize = 200;
const MAX_REDIRECTS: usize = 5;
const MAX_TEXT: usize = 500;

/// An assistant that registered itself.
#[derive(Clone, Serialize, Deserialize)]
struct Client {
    id: String,
    name: String,
    redirect_uris: Vec<String>,
    created: u64,
}

/// One assistant an administrator let in.
#[derive(Clone, Serialize, Deserialize)]
struct Grant {
    id: String,
    client_id: String,
    client: String,
    user: String,
    created: u64,
    last_used: u64,
    /// Hashes: the tokens themselves are never kept.
    access: String,
    access_until: u64,
    refresh: String,
    refresh_until: u64,
}

#[derive(Default, Serialize, Deserialize)]
struct Stored {
    #[serde(default)]
    clients: Vec<Client>,
    #[serde(default)]
    grants: Vec<Grant>,
}

/// A request to connect that waits for someone to say yes.
struct Pending {
    client_id: String,
    client: String,
    redirect_uri: String,
    state: Option<String>,
    challenge: String,
    until: u64,
}

/// A yes that waits for the assistant to collect its token.
struct Code {
    client_id: String,
    client: String,
    redirect_uri: String,
    challenge: String,
    user: String,
    until: u64,
}

#[derive(Default)]
struct Inner {
    stored: Stored,
    pending: HashMap<String, Pending>,
    codes: HashMap<String, Code>,
}

/// What an assistant is given to call the MCP endpoint with.
#[derive(Debug)]
pub struct Tokens {
    pub access: String,
    pub refresh: String,
}

/// What the page shows about a request to connect.
#[derive(Serialize)]
pub struct PendingView {
    client: String,
    /// Where the person is sent back to, so they can see who is asking.
    host: String,
}

/// What Settings shows about one connected assistant.
#[derive(Serialize)]
pub struct Connection {
    id: String,
    client: String,
    user: String,
    created: u64,
    last_used: u64,
}

/// Why a request to connect cannot go on.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Nothing is known about who asks, so nobody is sent anywhere.
    Stop(&'static str),
    /// The assistant is known and is told what was wrong.
    Back { to: String, error: &'static str },
}

pub struct Connect {
    file: Option<PathBuf>,
    inner: Mutex<Inner>,
}

impl Connect {
    /// Reads what was kept in the data directory, when there is one.
    pub fn new(dir: Option<&Path>) -> Self {
        let file = dir.map(|dir| dir.join("connections.json"));
        let stored = file
            .as_ref()
            .and_then(|file| std::fs::read(file).ok())
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        Self {
            file,
            inner: Mutex::new(Inner {
                stored,
                ..Inner::default()
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn keep(&self, stored: &Stored) {
        let Some(file) = &self.file else { return };
        let written = serde_json::to_vec(stored)
            .map_err(|e| e.to_string())
            .and_then(|bytes| {
                let dir = file.parent().unwrap_or(Path::new("."));
                crate::history::write_atomically(dir, file, &bytes).map_err(|e| e.to_string())
            });
        if let Err(reason) = written {
            eprintln!("connections not saved: {reason}");
        }
    }

    /// An assistant introduces itself and says where to send people back to.
    pub fn register(
        &self,
        name: &str,
        redirect_uris: &[String],
        now: u64,
    ) -> Result<(String, String), &'static str> {
        if redirect_uris.is_empty() || redirect_uris.len() > MAX_REDIRECTS {
            return Err("redirect_uris must list one to five addresses");
        }
        if !redirect_uris.iter().all(|uri| is_safe_redirect(uri)) {
            return Err("every redirect address must be https, or http on localhost");
        }
        let name: String = name.chars().filter(|c| !c.is_control()).take(80).collect();
        let name = if name.trim().is_empty() {
            "MCP client".to_owned()
        } else {
            name.trim().to_owned()
        };

        let mut inner = self.lock();
        if inner.stored.clients.len() >= MAX_CLIENTS {
            // Make room by forgetting the oldest one nobody ever let in.
            let connected: Vec<String> = inner
                .stored
                .grants
                .iter()
                .map(|g| g.client_id.clone())
                .collect();
            let Some(idle) = inner
                .stored
                .clients
                .iter()
                .position(|c| !connected.contains(&c.id))
            else {
                return Err("too many clients are registered");
            };
            inner.stored.clients.remove(idle);
        }
        let client = Client {
            id: random_hex(16),
            name: name.clone(),
            redirect_uris: redirect_uris.to_vec(),
            created: now,
        };
        let id = client.id.clone();
        inner.stored.clients.push(client);
        self.keep(&inner.stored);
        Ok((id, name))
    }

    /// An assistant sent someone here. Returns the name the page asks about.
    pub fn begin(&self, ask: &HashMap<String, String>, now: u64) -> Result<String, Refusal> {
        let get = |name: &str| ask.get(name).map(String::as_str).unwrap_or_default();
        let mut inner = self.lock();
        let Some(client) = inner
            .stored
            .clients
            .iter()
            .find(|c| c.id == get("client_id"))
            .cloned()
        else {
            return Err(Refusal::Stop("unknown client_id"));
        };
        let redirect_uri = get("redirect_uri");
        if !client.redirect_uris.iter().any(|uri| uri == redirect_uri) {
            return Err(Refusal::Stop(
                "redirect_uri is not one this client registered",
            ));
        }
        let state = ask.get("state").cloned();
        let back = |error: &'static str| Refusal::Back {
            to: with_query(
                redirect_uri,
                &[("error", error), ("state", state.as_deref().unwrap_or(""))],
            ),
            error,
        };
        if get("response_type") != "code" {
            return Err(back("unsupported_response_type"));
        }
        let challenge = get("code_challenge");
        if get("code_challenge_method") != "S256" || challenge.len() < 43 || challenge.len() > 128 {
            return Err(back("invalid_request"));
        }
        if state.as_ref().is_some_and(|s| s.len() > MAX_TEXT) {
            return Err(back("invalid_request"));
        }

        inner.pending.retain(|_, p| p.until > now);
        if inner.pending.len() >= MAX_PENDING {
            return Err(back("temporarily_unavailable"));
        }
        let id = random_hex(16);
        inner.pending.insert(
            id.clone(),
            Pending {
                client_id: client.id,
                client: client.name,
                redirect_uri: redirect_uri.to_owned(),
                state,
                challenge: challenge.to_owned(),
                until: now + PENDING_SECONDS,
            },
        );
        Ok(id)
    }

    /// What the page shows before someone says yes or no.
    pub fn pending(&self, id: &str, now: u64) -> Option<PendingView> {
        let inner = self.lock();
        let pending = inner.pending.get(id).filter(|p| p.until > now)?;
        Some(PendingView {
            client: pending.client.clone(),
            host: host_of(&pending.redirect_uri),
        })
    }

    /// Someone answered. Returns where to send their browser next.
    pub fn decide(&self, id: &str, allow: bool, user: &str, now: u64) -> Option<String> {
        let mut inner = self.lock();
        let pending = inner.pending.remove(id).filter(|p| p.until > now)?;
        let state = pending.state.as_deref().unwrap_or("");
        if !allow {
            return Some(with_query(
                &pending.redirect_uri,
                &[("error", "access_denied"), ("state", state)],
            ));
        }
        let code = random_hex(32);
        let to = with_query(&pending.redirect_uri, &[("code", &code), ("state", state)]);
        inner.codes.retain(|_, c| c.until > now);
        inner.codes.insert(
            token_hash(&code),
            Code {
                client_id: pending.client_id,
                client: pending.client,
                redirect_uri: pending.redirect_uri,
                challenge: pending.challenge,
                user: user.to_owned(),
                until: now + CODE_SECONDS,
            },
        );
        Some(to)
    }

    /// The assistant trades its code for tokens. A code works once.
    pub fn exchange(
        &self,
        form: &HashMap<String, String>,
        now: u64,
    ) -> Result<Tokens, &'static str> {
        let get = |name: &str| form.get(name).map(String::as_str).unwrap_or_default();
        let mut inner = self.lock();
        let code = inner
            .codes
            .remove(&token_hash(get("code")))
            .filter(|c| c.until > now)
            .ok_or("invalid_grant")?;
        let proof = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(get("code_verifier").as_bytes()));
        if code.client_id != get("client_id")
            || code.redirect_uri != get("redirect_uri")
            || !crate::auth::constant_time_eq(proof.as_bytes(), code.challenge.as_bytes())
        {
            return Err("invalid_grant");
        }
        let tokens = Tokens {
            access: random_hex(32),
            refresh: random_hex(32),
        };
        inner.stored.grants.push(Grant {
            id: random_hex(8),
            client_id: code.client_id,
            client: code.client,
            user: code.user,
            created: now,
            last_used: now,
            access: token_hash(&tokens.access),
            access_until: now + ACCESS_SECONDS,
            refresh: token_hash(&tokens.refresh),
            refresh_until: now + REFRESH_SECONDS,
        });
        self.keep(&inner.stored);
        Ok(tokens)
    }

    /// The assistant renews its access. Both tokens change every time.
    pub fn refresh(
        &self,
        form: &HashMap<String, String>,
        now: u64,
    ) -> Result<Tokens, &'static str> {
        let get = |name: &str| form.get(name).map(String::as_str).unwrap_or_default();
        let given = token_hash(get("refresh_token"));
        let mut inner = self.lock();
        inner.stored.grants.retain(|g| g.refresh_until > now);
        let grant = inner
            .stored
            .grants
            .iter_mut()
            .find(|g| g.refresh == given && g.client_id == get("client_id"))
            .ok_or("invalid_grant")?;
        let tokens = Tokens {
            access: random_hex(32),
            refresh: random_hex(32),
        };
        grant.access = token_hash(&tokens.access);
        grant.access_until = now + ACCESS_SECONDS;
        grant.refresh = token_hash(&tokens.refresh);
        grant.refresh_until = now + REFRESH_SECONDS;
        grant.last_used = now;
        self.keep(&inner.stored);
        Ok(tokens)
    }

    /// Whether this token opens the MCP endpoint right now.
    pub fn allows(&self, access: &str, now: u64) -> bool {
        let given = token_hash(access);
        let mut inner = self.lock();
        match inner
            .stored
            .grants
            .iter_mut()
            .find(|g| g.access == given && g.access_until > now)
        {
            Some(grant) => {
                grant.last_used = now;
                true
            }
            None => false,
        }
    }

    pub fn connections(&self, now: u64) -> Vec<Connection> {
        self.lock()
            .stored
            .grants
            .iter()
            .filter(|g| g.refresh_until > now)
            .map(|g| Connection {
                id: g.id.clone(),
                client: g.client.clone(),
                user: g.user.clone(),
                created: g.created,
                last_used: g.last_used,
            })
            .collect()
    }

    /// Takes a connection back. Returns the assistant's name if it existed.
    pub fn revoke(&self, id: &str) -> Option<String> {
        let mut inner = self.lock();
        let at = inner.stored.grants.iter().position(|g| g.id == id)?;
        let gone = inner.stored.grants.remove(at);
        self.keep(&inner.stored);
        Some(gone.client)
    }
}

/// https anywhere, or plain http on this machine, and nothing odd in it.
fn is_safe_redirect(uri: &str) -> bool {
    let local = ["http://localhost", "http://127.0.0.1", "http://[::1]"]
        .iter()
        .any(|start| {
            uri.strip_prefix(start)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with([':', '/']))
        });
    (uri.starts_with("https://") || local)
        && uri.len() <= MAX_TEXT
        && !uri.contains('#')
        && !uri.chars().any(|c| c.is_control() || c.is_whitespace())
        && !host_of(uri).is_empty()
}

fn host_of(uri: &str) -> String {
    uri.split_once("://")
        .map_or("", |(_, rest)| rest)
        .split(['/', '?'])
        .next()
        .unwrap_or_default()
        .rsplit('@')
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// Adds values to an address, after whatever query it already has.
fn with_query(uri: &str, values: &[(&str, &str)]) -> String {
    let mut out = uri.to_owned();
    for (name, value) in values.iter().filter(|(_, value)| !value.is_empty()) {
        out.push(if out.contains('?') { '&' } else { '?' });
        out.push_str(name);
        out.push('=');
        out.push_str(&encode(value));
    }
    out
}

fn encode(text: &str) -> String {
    text.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Reads a form as browsers and OAuth clients send it.
fn parse_form(body: &[u8]) -> HashMap<String, String> {
    let decode = |part: &[u8]| {
        let mut out = Vec::with_capacity(part.len());
        let mut at = 0;
        while at < part.len() {
            match part[at] {
                b'+' => out.push(b' '),
                b'%' if at + 2 < part.len() => {
                    let hex = std::str::from_utf8(&part[at + 1..at + 3]).unwrap_or("");
                    match u8::from_str_radix(hex, 16) {
                        Ok(byte) => {
                            out.push(byte);
                            at += 2;
                        }
                        Err(_) => out.push(b'%'),
                    }
                }
                byte => out.push(byte),
            }
            at += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    };
    body.split(|b| *b == b'&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let mut halves = pair.splitn(2, |b| *b == b'=');
            let name = decode(halves.next().unwrap_or_default());
            let value = decode(halves.next().unwrap_or_default());
            (name, value)
        })
        .collect()
}

/// The address people and assistants reach nbuddyn at.
pub fn base_url(state: &AppState, headers: &HeaderMap) -> String {
    if let Some(public) = &state.public_url {
        return public.trim_end_matches('/').to_owned();
    }
    let text = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(str::trim)
            .filter(|v| !v.is_empty())
    };
    let host = text("x-forwarded-host")
        .or_else(|| text("host"))
        .unwrap_or("localhost");
    let host: String = host
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
        .collect();
    let scheme = match text("x-forwarded-proto") {
        Some("http") => "http",
        Some(_) => "https",
        None if host.starts_with("localhost") || host.starts_with("127.0.0.1") => "http",
        None => "https",
    };
    format!("{scheme}://{host}")
}

fn no_store(body: Value) -> Response {
    ([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response()
}

/// Tells an assistant who can give it a token for the MCP endpoint.
pub async fn resource_metadata(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !state.mcp_on().await {
        return StatusCode::NOT_FOUND.into_response();
    }
    let base = base_url(&state, &headers);
    Json(json!({
        "resource": format!("{base}/mcp"),
        "authorization_servers": [base],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["read"],
        "resource_name": "nbuddyn",
    }))
    .into_response()
}

/// Tells an assistant how signing in here works.
pub async fn server_metadata(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !state.mcp_on().await {
        return StatusCode::NOT_FOUND.into_response();
    }
    let base = base_url(&state, &headers);
    Json(json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/oauth/authorize"),
        "token_endpoint": format!("{base}/oauth/token"),
        "registration_endpoint": format!("{base}/oauth/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": ["read"],
    }))
    .into_response()
}

fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({ "error": error, "error_description": description })),
    )
        .into_response()
}

pub async fn register(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    if !state.mcp_on().await {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Ok(ask) = serde_json::from_slice::<Value>(&body) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "not JSON",
        );
    };
    let redirect_uris: Vec<String> = ask
        .get("redirect_uris")
        .and_then(Value::as_array)
        .map(|uris| {
            uris.iter()
                .filter_map(|uri| uri.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let name = ask.get("client_name").and_then(Value::as_str).unwrap_or("");
    match state.connect.register(name, &redirect_uris, web::now()) {
        Ok((id, name)) => (
            StatusCode::CREATED,
            [(header::CACHE_CONTROL, "no-store")],
            Json(json!({
                "client_id": id,
                "client_name": name,
                "redirect_uris": redirect_uris,
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
            })),
        )
            .into_response(),
        Err(reason) => oauth_error(StatusCode::BAD_REQUEST, "invalid_redirect_uri", reason),
    }
}

fn redirect(to: &str) -> Response {
    (
        StatusCode::FOUND,
        [(header::LOCATION, to), (header::CACHE_CONTROL, "no-store")],
    )
        .into_response()
}

/// Where an assistant sends someone. The page takes it from here: it asks
/// them to sign in if they are not, and then to say yes or no.
pub async fn authorize(
    State(state): State<Arc<AppState>>,
    Query(ask): Query<HashMap<String, String>>,
) -> Response {
    if !state.mcp_on().await {
        return StatusCode::NOT_FOUND.into_response();
    }
    match state.connect.begin(&ask, web::now()) {
        Ok(id) => redirect(&format!("/#/connect/{id}")),
        Err(Refusal::Back { to, .. }) => redirect(&to),
        Err(Refusal::Stop(reason)) => (StatusCode::BAD_REQUEST, reason).into_response(),
    }
}

pub async fn token(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    if !state.mcp_on().await {
        return StatusCode::NOT_FOUND.into_response();
    }
    let form = parse_form(&body);
    let now = web::now();
    let issued = match form.get("grant_type").map(String::as_str) {
        Some("authorization_code") => state.connect.exchange(&form, now),
        Some("refresh_token") => state.connect.refresh(&form, now),
        _ => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                "use authorization_code or refresh_token",
            )
        }
    };
    match issued {
        Ok(tokens) => no_store(json!({
            "access_token": tokens.access,
            "token_type": "Bearer",
            "expires_in": ACCESS_SECONDS,
            "refresh_token": tokens.refresh,
            "scope": "read",
        })),
        Err(error) => oauth_error(StatusCode::BAD_REQUEST, error, "the grant is not valid"),
    }
}

#[derive(Deserialize)]
pub struct Which {
    id: String,
}

/// What the page shows someone who was sent here by an assistant.
pub async fn pending_view(
    State(state): State<Arc<AppState>>,
    Query(which): Query<Which>,
) -> Response {
    match state.connect.pending(&which.id, web::now()) {
        Some(view) => Json(view).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[derive(Deserialize)]
pub struct Decision {
    id: String,
    allow: bool,
}

/// Yes or no. Only an administrator can let an assistant in.
pub async fn decide(
    State(state): State<Arc<AppState>>,
    Extension(who): Extension<Identity>,
    headers: HeaderMap,
    Json(decision): Json<Decision>,
) -> Response {
    if !headers.contains_key(web::WRITE_HEADER) || (decision.allow && !who.is_admin()) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let now = web::now();
    let client = state.connect.pending(&decision.id, now).map(|p| p.client);
    match state
        .connect
        .decide(&decision.id, decision.allow, &who.name, now)
    {
        Some(to) => {
            if decision.allow {
                state.auth.record(
                    now,
                    &who.name,
                    "mcp_connect",
                    client.as_deref().unwrap_or_default(),
                );
            }
            no_store(json!({ "redirect": to }))
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BACK: &str = "https://claude.ai/api/mcp/auth_callback";
    const VERIFIER: &str = "a-verifier-that-is-long-enough-to-be-allowed-0123456789";

    fn challenge() -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()))
    }

    fn map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    /// Registers a client and walks it up to the moment it holds a code.
    fn code_for(connect: &Connect, now: u64) -> (String, String) {
        let (client, _) = connect.register("Claude", &[BACK.to_owned()], now).unwrap();
        let ask = map(&[
            ("client_id", &client),
            ("redirect_uri", BACK),
            ("response_type", "code"),
            ("code_challenge", &challenge()),
            ("code_challenge_method", "S256"),
            ("state", "xyz"),
        ]);
        let id = connect.begin(&ask, now).unwrap();
        assert_eq!(connect.pending(&id, now).unwrap().host, "claude.ai");
        let to = connect.decide(&id, true, "ana", now).unwrap();
        assert!(to.starts_with(BACK) && to.ends_with("&state=xyz"));
        let code = to.split("code=").nth(1).unwrap().split('&').next().unwrap();
        (client, code.to_owned())
    }

    fn trade(client: &str, code: &str, verifier: &str) -> HashMap<String, String> {
        map(&[
            ("client_id", client),
            ("redirect_uri", BACK),
            ("code", code),
            ("code_verifier", verifier),
        ])
    }

    #[test]
    fn an_assistant_signs_in_renews_and_is_taken_back() {
        let connect = Connect::new(None);
        let (client, code) = code_for(&connect, 1000);
        let tokens = connect
            .exchange(&trade(&client, &code, VERIFIER), 1010)
            .unwrap();
        assert!(connect.allows(&tokens.access, 1020));
        assert!(!connect.allows(&tokens.refresh, 1020));
        assert!(!connect.allows(&tokens.access, 1010 + ACCESS_SECONDS));

        // Renewing changes both tokens, and the old ones stop working.
        let renew = map(&[("client_id", &client), ("refresh_token", &tokens.refresh)]);
        let next = connect.refresh(&renew, 5000).unwrap();
        assert!(connect.allows(&next.access, 5001));
        assert!(!connect.allows(&tokens.access, 5001));
        assert_eq!(connect.refresh(&renew, 5002).unwrap_err(), "invalid_grant");

        let listed = connect.connections(5003);
        assert_eq!(listed.len(), 1);
        assert_eq!(
            (listed[0].client.as_str(), listed[0].user.as_str()),
            ("Claude", "ana")
        );
        assert_eq!(connect.revoke(&listed[0].id).as_deref(), Some("Claude"));
        assert!(!connect.allows(&next.access, 5004));
    }

    #[test]
    fn a_code_works_once_and_only_with_its_proof() {
        let connect = Connect::new(None);
        let (client, code) = code_for(&connect, 1000);
        // The wrong proof burns the code: whoever stole it gets nothing.
        assert!(connect
            .exchange(&trade(&client, &code, "not-the-verifier"), 1001)
            .is_err());
        assert!(connect
            .exchange(&trade(&client, &code, VERIFIER), 1002)
            .is_err());

        let (client, code) = code_for(&connect, 2000);
        assert!(connect
            .exchange(&trade(&client, &code, VERIFIER), 2000 + CODE_SECONDS)
            .is_err());

        let (client, code) = code_for(&connect, 3000);
        assert!(connect
            .exchange(&trade(&client, &code, VERIFIER), 3001)
            .is_ok());
        assert!(connect
            .exchange(&trade(&client, &code, VERIFIER), 3002)
            .is_err());
    }

    #[test]
    fn requests_that_do_not_add_up_are_refused() {
        let connect = Connect::new(None);
        assert!(connect.register("x", &[], 1).is_err());
        assert!(connect
            .register("x", &["http://evil.example/cb".into()], 1)
            .is_err());
        assert!(connect
            .register("x", &["https://a.example/cb#frag".into()], 1)
            .is_err());
        assert!(connect
            .register("x", &["http://localhost.evil.example/cb".into()], 1)
            .is_err());
        assert!(connect
            .register("x", &["http://localhost:8123/cb".into()], 1)
            .is_ok());

        let (client, _) = connect.register("Claude", &[BACK.to_owned()], 1).unwrap();
        let ask = |pairs: &[(&str, &str)]| {
            let mut all = map(&[
                ("client_id", client.as_str()),
                ("redirect_uri", BACK),
                ("response_type", "code"),
                ("code_challenge", &challenge()),
                ("code_challenge_method", "S256"),
            ]);
            all.extend(map(pairs));
            connect.begin(&all, 10)
        };
        // An unknown client or address: nobody is sent anywhere.
        assert!(matches!(
            ask(&[("client_id", "nobody")]),
            Err(Refusal::Stop(_))
        ));
        assert!(matches!(
            ask(&[("redirect_uri", "https://evil.example/cb")]),
            Err(Refusal::Stop(_))
        ));
        // A known client that asks wrongly is told so.
        assert!(matches!(
            ask(&[("code_challenge_method", "plain")]),
            Err(Refusal::Back {
                error: "invalid_request",
                ..
            })
        ));
        assert!(matches!(
            ask(&[("response_type", "token")]),
            Err(Refusal::Back {
                error: "unsupported_response_type",
                ..
            })
        ));

        // Saying no sends the assistant away without a code.
        let id = ask(&[("state", "s 1")]).unwrap();
        let to = connect.decide(&id, false, "ana", 11).unwrap();
        assert_eq!(to, format!("{BACK}?error=access_denied&state=s%201"));
        assert!(connect.decide(&id, true, "ana", 12).is_none());
        // An answer that comes too late counts for nothing.
        let id = ask(&[]).unwrap();
        assert!(connect
            .decide(&id, true, "ana", 10 + PENDING_SECONDS)
            .is_none());
    }

    #[test]
    fn forms_and_addresses_are_read_as_sent() {
        let form = parse_form(b"grant_type=authorization_code&code=a%2Bb+c&empty=&bad=%zz");
        assert_eq!(form["grant_type"], "authorization_code");
        assert_eq!(form["code"], "a+b c");
        assert_eq!(form["empty"], "");
        assert_eq!(form["bad"], "%zz");
        assert_eq!(
            with_query(
                "https://a.example/cb?x=1",
                &[("code", "a b"), ("state", "")]
            ),
            "https://a.example/cb?x=1&code=a%20b"
        );
        assert_eq!(host_of("https://user@claude.ai:443/api?x"), "claude.ai:443");
    }
}
