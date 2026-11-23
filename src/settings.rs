//! What can be changed from the page instead of from environment variables:
//! the n8n instances nbuddyn watches, how it watches them, and the findings
//! someone decided to live with.
//!
//! Environment variables describe the first instance and give the starting
//! values. Once something is saved from the page it is kept in one JSON file
//! next to the history and wins. The first instance's database and the
//! passwords of nbuddyn itself stay in the environment: without them there is
//! no page to change them from.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::alerts::{Alerts, Level};
use crate::cluster::RedisConfig;
use crate::db;
use crate::history::write_atomically;
use crate::i18n::Lang;
use crate::runners::{self, RunnerTarget};
use crate::vault::{self, KeySource, Vault};

const FILE: &str = "settings.json";

/// The id of the instance described by the environment. It always exists.
pub const PRIMARY: &str = "main";

/// The starting values, read from the environment once.
#[derive(Debug, Clone, Default)]
pub struct Defaults {
    /// The first instance's database. Never changed from the page.
    pub database_url: String,
    pub name: String,
    pub n8n_url: String,
    pub lang: String,
    pub interval_seconds: u64,
    pub timezone: String,
    pub history_days: u32,
    pub runner_urls: String,
    pub redis_url: String,
    pub telegram_token: String,
    pub telegram_chat: String,
    /// Only different in tests and for a self-hosted Bot API server.
    pub telegram_api: String,
    pub webhook_url: String,
    pub alert_level: String,
    /// Key names n8n can be told to change; these stay in the environment.
    pub bull_prefix: Option<String>,
    pub queue_name: Option<String>,
    pub redis_key_prefix: Option<String>,
}

/// A finding someone looked at and decided is fine as it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Accepted {
    pub key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
    /// Seconds since 1970.
    pub at: u64,
    /// Who accepted it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub by: String,
}

/// Another n8n, added from the page.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceSaved {
    pub id: String,
    pub name: String,
    pub database_url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub n8n_url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub timezone: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub runner_urls: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub redis_url: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted: Vec<Accepted>,
}

/// What was saved from the page. `None` means "never changed here". The
/// fields about one n8n describe the first instance.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Saved {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n8n_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lang: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_days: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runner_urls: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redis_url: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted: Vec<Accepted>,
    /// Where alerts go. The token and the webhook address are secrets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telegram_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telegram_chat: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
    /// `high` or `medium`: the mildest severity that alerts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alert_level: Option<String>,
    /// Whether workflow changes alert too.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alert_changes: Option<bool>,
    /// The team's own rules: how severe each check is here. A check that is
    /// not listed keeps the severity nbuddyn gives it; `off` silences it.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub policy: std::collections::BTreeMap<String, String>,
    /// Whether accepting a finding needs a reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accept_needs_note: Option<bool>,
    /// Whether the MCP endpoint answers. Absent: only if a token came from
    /// the environment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_enabled: Option<bool>,
    /// The hash of the MCP token made on the page. The token is not kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_token_hash: Option<String>,
    /// Whether unused credentials n8n made for itself are reported too.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub show_own_credentials: Option<bool>,
    /// Days an acceptance lasts before the finding comes back for another
    /// look. 0 or absent: for as long as the finding does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accept_days: Option<u32>,
    /// The instances added from the page, in the order they were added.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub instances: Vec<InstanceSaved>,
}

/// The settings as text, the way the page shows and sends them: the ones of
/// one instance, plus the ones nbuddyn has only once.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Form {
    #[serde(default)]
    pub name: String,
    /// Shown with its password hidden; sent back unchanged means "keep it".
    /// Not used for the first instance.
    #[serde(default)]
    pub database_url: String,
    #[serde(default)]
    pub n8n_url: String,
    #[serde(default)]
    pub timezone: String,
    #[serde(default)]
    pub runner_urls: String,
    /// Shown with its password hidden; sent back unchanged means "keep it".
    #[serde(default)]
    pub redis_url: String,
    #[serde(default)]
    pub lang: String,
    #[serde(default)]
    pub interval_seconds: String,
    #[serde(default)]
    pub history_days: String,
    /// Shown as dots when set; sent back unchanged means "keep it".
    #[serde(default)]
    pub telegram_token: String,
    #[serde(default)]
    pub telegram_chat: String,
    /// Shown without its path when set; sent back unchanged means "keep it".
    #[serde(default)]
    pub webhook_url: String,
    #[serde(default)]
    pub alert_level: String,
    /// `true` or `false`.
    #[serde(default)]
    pub alert_changes: String,
}

/// One instance, checked and ready to scan.
#[derive(Debug, Clone)]
pub struct Instance {
    pub id: String,
    pub name: String,
    pub database_url: String,
    /// Where n8n's editor is, without a trailing slash. Empty when unknown.
    pub n8n_url: String,
    pub timezone: Option<String>,
    pub runners: Vec<RunnerTarget>,
    pub redis: Option<RedisConfig>,
}

/// The settings in force, checked and ready to use.
#[derive(Debug, Clone)]
pub struct Effective {
    pub lang: Lang,
    pub interval: Duration,
    pub history_days: u32,
    /// The first instance first. Never empty.
    pub instances: Vec<Instance>,
    pub alerts: Alerts,
}

impl Effective {
    /// The instance with this id, or the first one when no id is given.
    pub fn instance(&self, id: Option<&str>) -> Option<&Instance> {
        match id.filter(|id| !id.is_empty()) {
            None => self.instances.first(),
            Some(id) => self.instances.iter().find(|i| i.id == id),
        }
    }
}

pub const MIN_INTERVAL: u64 = 10;
const MAX_INTERVAL: u64 = 86_400;
const MAX_HISTORY_DAYS: u32 = 3650;
/// How many instances one nbuddyn watches at most.
pub const MAX_INSTANCES: usize = 50;
const NAME_MAX: usize = 60;
/// The longest note kept with an accepted finding, in characters.
const NOTE_MAX: usize = 300;

/// The texts in force for one instance.
struct Raw {
    id: String,
    name: String,
    database_url: String,
    n8n_url: String,
    timezone: String,
    runner_urls: String,
    redis_url: String,
}

impl Saved {
    fn raws(&self, defaults: &Defaults) -> Vec<Raw> {
        let text = |saved: &Option<String>, default: &str| {
            saved.clone().unwrap_or_else(|| default.to_owned())
        };
        let first = Raw {
            id: PRIMARY.to_owned(),
            name: text(&self.name, &defaults.name),
            database_url: defaults.database_url.clone(),
            n8n_url: text(&self.n8n_url, &defaults.n8n_url),
            timezone: text(&self.timezone, &defaults.timezone),
            runner_urls: text(&self.runner_urls, &defaults.runner_urls),
            redis_url: text(&self.redis_url, &defaults.redis_url),
        };
        let others = self.instances.iter().map(|i| Raw {
            id: i.id.clone(),
            name: i.name.clone(),
            database_url: i.database_url.clone(),
            n8n_url: i.n8n_url.clone(),
            timezone: i.timezone.clone(),
            runner_urls: i.runner_urls.clone(),
            redis_url: i.redis_url.clone(),
        });
        std::iter::once(first).chain(others).collect()
    }

    /// What the page shows for one instance: the values in force, with
    /// passwords hidden. `None` when there is no such instance.
    pub fn form(&self, defaults: &Defaults, id: &str) -> Option<Form> {
        let raw = self.raws(defaults).into_iter().find(|r| r.id == id)?;
        Some(Form {
            name: raw.name,
            database_url: hide_password(&raw.database_url),
            n8n_url: raw.n8n_url,
            timezone: raw.timezone,
            runner_urls: lines(&raw.runner_urls).join("\n"),
            redis_url: hide_password(&raw.redis_url),
            lang: self.lang.clone().unwrap_or_else(|| defaults.lang.clone()),
            interval_seconds: self
                .interval_seconds
                .unwrap_or(defaults.interval_seconds)
                .to_string(),
            history_days: self
                .history_days
                .unwrap_or(defaults.history_days)
                .to_string(),
            telegram_token: mask(&self.alert_text(defaults).0),
            telegram_chat: self.alert_text(defaults).1,
            webhook_url: mask_address(&self.alert_text(defaults).2),
            alert_level: self.alert_text(defaults).3,
            alert_changes: self.alert_changes.unwrap_or(false).to_string(),
        })
    }

    /// The alert settings in force, as text: token, chat, webhook and level.
    fn alert_text(&self, defaults: &Defaults) -> (String, String, String, String) {
        let text = |saved: &Option<String>, default: &str| {
            saved.clone().unwrap_or_else(|| default.to_owned())
        };
        let level = text(&self.alert_level, &defaults.alert_level);
        (
            text(&self.telegram_token, &defaults.telegram_token),
            text(&self.telegram_chat, &defaults.telegram_chat),
            text(&self.webhook_url, &defaults.webhook_url),
            if level.is_empty() {
                "high".into()
            } else {
                level
            },
        )
    }

    /// Checks the values in force and turns them into something usable. On
    /// failure, names the fields that are wrong.
    pub fn resolve(&self, defaults: &Defaults) -> Result<Effective, Vec<&'static str>> {
        let mut wrong = Vec::new();

        let lang = self
            .lang
            .clone()
            .unwrap_or_else(|| defaults.lang.clone())
            .trim()
            .to_ascii_lowercase();
        if !lang.is_empty() && !["en", "es", "pt"].contains(&lang.as_str()) {
            wrong.push("lang");
        }
        let interval = self.interval_seconds.unwrap_or(defaults.interval_seconds);
        if !(MIN_INTERVAL..=MAX_INTERVAL).contains(&interval) {
            wrong.push("interval_seconds");
        }
        let history_days = self.history_days.unwrap_or(defaults.history_days);
        if !(1..=MAX_HISTORY_DAYS).contains(&history_days) {
            wrong.push("history_days");
        }

        let mut instances = Vec::new();
        for raw in self.raws(defaults) {
            match check(raw, defaults) {
                Ok(instance) => instances.push(instance),
                Err(more) => wrong.extend(more),
            }
        }

        let (token, chat, webhook, level) = self.alert_text(defaults);
        let (token, chat, webhook) = (token.trim(), chat.trim(), webhook.trim());
        let token_ok = token.is_empty()
            || token.split_once(':').is_some_and(|(id, key)| {
                !id.is_empty()
                    && id.bytes().all(|b| b.is_ascii_digit())
                    && key.len() >= 20
                    && key
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            });
        if !token_ok {
            wrong.push("telegram_token");
        }
        let chat_ok = chat.is_empty()
            || chat
                .trim_start_matches('-')
                .bytes()
                .all(|b| b.is_ascii_digit())
                && chat.trim_start_matches('-').len() >= 3
            || chat.strip_prefix('@').is_some_and(|name| {
                name.len() >= 4 && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            });
        // A token without a chat, or the other way round, can never deliver.
        if !chat_ok || token.is_empty() != chat.is_empty() {
            wrong.push(if token.is_empty() {
                "telegram_token"
            } else {
                "telegram_chat"
            });
        }
        if !webhook.is_empty() && crate::http::Target::parse(webhook).is_err() {
            wrong.push("webhook_url");
        }
        let level = match level.as_str() {
            "high" => Level::High,
            "medium" => Level::Medium,
            _ => {
                wrong.push("alert_level");
                Level::High
            }
        };
        let alerts = Alerts {
            telegram: (!token.is_empty() && !chat.is_empty())
                .then(|| (token.to_owned(), chat.to_owned())),
            telegram_api: if defaults.telegram_api.is_empty() {
                "https://api.telegram.org".into()
            } else {
                defaults.telegram_api.trim_end_matches('/').to_owned()
            },
            webhook: (!webhook.is_empty()).then(|| webhook.to_owned()),
            level,
            changes: self.alert_changes.unwrap_or(false),
        };

        if wrong.is_empty() {
            Ok(Effective {
                lang: Lang::parse(&lang),
                interval: Duration::from_secs(interval),
                history_days,
                instances,
                alerts,
            })
        } else {
            wrong.sort_unstable();
            wrong.dedup();
            Err(wrong)
        }
    }

    /// Takes what the page sent for one instance. Nothing changes unless
    /// everything is valid.
    pub fn with_form(
        &self,
        id: &str,
        form: &Form,
        defaults: &Defaults,
    ) -> Result<Saved, Vec<&'static str>> {
        let Some(shown) = self.form(defaults, id) else {
            return Err(vec!["instance"]);
        };
        let mut next = self.clone();
        let mut wrong = Vec::new();

        let name: String = form.name.trim().chars().take(NAME_MAX).collect();
        let n8n_url = form.n8n_url.trim().trim_end_matches('/').to_owned();
        let timezone = form.timezone.trim().to_owned();
        let runner_urls = lines(&form.runner_urls).join(",");
        // The page never had the passwords, so an address it shows coming
        // back untouched means it was not edited.
        let edited =
            |sent: &str, shown: &str| (sent.trim() != shown).then(|| sent.trim().to_owned());

        if id == PRIMARY {
            next.name = Some(name);
            next.n8n_url = Some(n8n_url);
            next.timezone = Some(timezone);
            next.runner_urls = Some(runner_urls);
            if let Some(url) = edited(&form.redis_url, &shown.redis_url) {
                next.redis_url = Some(url);
            }
        } else if let Some(instance) = next.instances.iter_mut().find(|i| i.id == id) {
            instance.name = name;
            instance.n8n_url = n8n_url;
            instance.timezone = timezone;
            instance.runner_urls = runner_urls;
            if let Some(url) = edited(&form.redis_url, &shown.redis_url) {
                instance.redis_url = url;
            }
            if let Some(url) = edited(&form.database_url, &shown.database_url) {
                instance.database_url = url;
            }
        }

        next.lang = Some(form.lang.trim().to_ascii_lowercase());
        if let Some(token) = edited(&form.telegram_token, &shown.telegram_token) {
            next.telegram_token = Some(token);
        }
        next.telegram_chat = Some(form.telegram_chat.trim().to_owned());
        if let Some(url) = edited(&form.webhook_url, &shown.webhook_url) {
            next.webhook_url = Some(url);
        }
        next.alert_level = Some(form.alert_level.trim().to_ascii_lowercase());
        next.alert_changes = Some(form.alert_changes.trim() == "true");
        match form.interval_seconds.trim().parse() {
            Ok(seconds) => next.interval_seconds = Some(seconds),
            Err(_) => wrong.push("interval_seconds"),
        }
        match form.history_days.trim().parse() {
            Ok(days) => next.history_days = Some(days),
            Err(_) => wrong.push("history_days"),
        }
        if let Err(more) = next.resolve(defaults) {
            wrong.extend(more);
        }
        wrong.sort_unstable();
        wrong.dedup();
        if wrong.is_empty() {
            Ok(next)
        } else {
            Err(wrong)
        }
    }

    /// Adds another n8n under a new id.
    pub fn with_instance(
        &self,
        id: &str,
        name: &str,
        database_url: &str,
        defaults: &Defaults,
    ) -> Result<Saved, Vec<&'static str>> {
        if self.instances.len() + 1 >= MAX_INSTANCES {
            return Err(vec!["instance"]);
        }
        let mut next = self.clone();
        next.instances.push(InstanceSaved {
            id: id.to_owned(),
            name: name.trim().chars().take(NAME_MAX).collect(),
            database_url: database_url.trim().to_owned(),
            ..InstanceSaved::default()
        });
        next.resolve(defaults).map(|_| next)
    }

    /// Forgets an instance added from the page. The first one cannot go.
    pub fn without_instance(&self, id: &str) -> Result<Saved, Vec<&'static str>> {
        let mut next = self.clone();
        let before = next.instances.len();
        next.instances.retain(|i| i.id != id);
        if next.instances.len() == before {
            return Err(vec!["instance"]);
        }
        Ok(next)
    }

    /// The acceptances in one instance that still hold at `now`: the ones
    /// that have not outlived the days the team's rules give them.
    pub fn accepted_valid(&self, id: &str, now: u64) -> Vec<Accepted> {
        let lasts = u64::from(self.accept_days.unwrap_or(0)) * 86_400;
        self.accepted_in(id)
            .iter()
            .filter(|a| lasts == 0 || a.at + lasts > now)
            .cloned()
            .collect()
    }

    /// The findings accepted in one instance.
    pub fn accepted_in(&self, id: &str) -> &[Accepted] {
        if id == PRIMARY {
            return &self.accepted;
        }
        self.instances
            .iter()
            .find(|i| i.id == id)
            .map_or(&[], |i| i.accepted.as_slice())
    }

    fn accepted_mut(&mut self, id: &str) -> Option<&mut Vec<Accepted>> {
        if id == PRIMARY {
            return Some(&mut self.accepted);
        }
        self.instances
            .iter_mut()
            .find(|i| i.id == id)
            .map(|i| &mut i.accepted)
    }

    pub fn accept(&mut self, id: &str, key: &str, note: &str, at: u64, by: &str) {
        if let Some(accepted) = self.accepted_mut(id) {
            accepted.retain(|a| a.key != key);
            accepted.push(Accepted {
                key: key.to_owned(),
                note: note.trim().chars().take(NOTE_MAX).collect(),
                at,
                by: by.to_owned(),
            });
        }
    }

    pub fn unaccept(&mut self, id: &str, key: &str) {
        if let Some(accepted) = self.accepted_mut(id) {
            accepted.retain(|a| a.key != key);
        }
    }
}

/// Entries separated by commas, new lines or semicolons, trimmed.
fn lines(text: &str) -> Vec<&str> {
    text.split([',', '\n', '\r', ';'])
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect()
}

fn check(raw: Raw, defaults: &Defaults) -> Result<Instance, Vec<&'static str>> {
    let mut wrong = Vec::new();

    let name = raw.name.trim().to_owned();
    if name.is_empty() || name.chars().any(char::is_control) {
        wrong.push("name");
    }

    let database_url = raw.database_url.trim().to_owned();
    let known = db::sqlite_path(&database_url).is_some()
        || ["postgres://", "postgresql://"]
            .iter()
            .any(|scheme| database_url.len() > scheme.len() && database_url.starts_with(scheme));
    if !known || database_url.len() > 500 || database_url.chars().any(char::is_whitespace) {
        wrong.push("database_url");
    }

    let n8n_url = raw.n8n_url.trim().trim_end_matches('/').to_owned();
    if !n8n_url.is_empty() && !is_web_address(&n8n_url) {
        wrong.push("n8n_url");
    }

    let timezone = raw.timezone.trim().to_owned();
    let zone_ok = timezone.len() <= 64
        && timezone
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '+' | '-'));
    if !zone_ok {
        wrong.push("timezone");
    }

    let runners = runners::parse_targets(&lines(&raw.runner_urls).join(","));
    if runners.is_err() {
        wrong.push("runner_urls");
    }

    let redis_url = raw.redis_url.trim();
    let redis = if redis_url.is_empty() {
        Ok(None)
    } else {
        RedisConfig::parse(redis_url).map(|mut redis| {
            if let Some(prefix) = &defaults.bull_prefix {
                redis.bull_prefix.clone_from(prefix);
            }
            if let Some(name) = &defaults.queue_name {
                redis.queue_name.clone_from(name);
            }
            if let Some(prefix) = &defaults.redis_key_prefix {
                redis.key_prefix.clone_from(prefix);
            }
            Some(redis)
        })
    };
    if redis.is_err() {
        wrong.push("redis_url");
    }

    match (runners, redis) {
        (Ok(runners), Ok(redis)) if wrong.is_empty() => Ok(Instance {
            id: raw.id,
            name,
            database_url,
            n8n_url,
            timezone: Some(timezone).filter(|z| !z.is_empty()),
            runners,
            redis,
        }),
        _ => Err(wrong),
    }
}

/// Whether one accepted list holds this finding.
pub fn is_accepted(accepted: &[Accepted], key: &str) -> bool {
    accepted.iter().any(|a| a.key == key)
}

/// An `http://` or `https://` address that is safe to put in a link.
fn is_web_address(url: &str) -> bool {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"));
    rest.is_some_and(|rest| {
        !rest.is_empty()
            && url.len() <= 300
            && url
                .chars()
                .all(|c| c.is_ascii_graphic() && !matches!(c, '"' | '\'' | '<' | '>' | '`' | '\\'))
    })
}

/// A secret the page should know exists but never see.
fn mask(secret: &str) -> String {
    if secret.is_empty() {
        String::new()
    } else {
        "••••••••".into()
    }
}

/// A webhook address with everything after the host hidden: the path is
/// usually the secret.
fn mask_address(url: &str) -> String {
    match url.split_once("://") {
        Some((scheme, rest)) if !rest.is_empty() => {
            let host = rest.split(['/', '?']).next().unwrap_or_default();
            format!("{scheme}://{host}/••••")
        }
        _ => String::new(),
    }
}

/// `redis://user:secret@host` becomes `redis://user:••••@host`, and the same
/// for a Postgres address.
fn hide_password(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_owned();
    };
    match rest.rsplit_once('@') {
        Some((auth, location)) => {
            let user = auth.split_once(':').map_or("", |(user, _)| user);
            format!("{scheme}://{user}:••••@{location}")
        }
        None => url.to_owned(),
    }
}

impl Saved {
    /// Every stored value that carries a password.
    fn secrets_mut(&mut self) -> Vec<&mut String> {
        let mut secrets: Vec<&mut String> = self
            .redis_url
            .iter_mut()
            .chain(self.telegram_token.iter_mut())
            .chain(self.webhook_url.iter_mut())
            .collect();
        for instance in &mut self.instances {
            secrets.push(&mut instance.database_url);
            secrets.push(&mut instance.redis_url);
        }
        secrets
    }
}

/// Where the settings live on disk.
#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
    vault: std::sync::Arc<Vault>,
}

impl Store {
    pub fn new(dir: impl Into<PathBuf>, vault: std::sync::Arc<Vault>) -> Self {
        Self {
            dir: dir.into(),
            vault,
        }
    }

    /// Where the key that seals the secrets comes from.
    pub fn key_source(&self) -> KeySource {
        self.vault.source
    }

    /// Reads what was saved, or nothing when nothing was. A file that cannot
    /// be understood, or opened with this key, is an error: guessing would
    /// silently drop decisions. A file written before secrets were sealed is
    /// sealed on the spot.
    pub fn load(&self) -> Result<Saved, String> {
        let file = self.dir.join(FILE);
        let text = match std::fs::read_to_string(&file) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Saved::default()),
            Err(e) => return Err(format!("cannot read {}: {e}", file.display())),
        };
        let mut saved: Saved = serde_json::from_str(&text)
            .map_err(|e| format!("{} is not valid: {e}", file.display()))?;
        let mut unsealed = false;
        for secret in saved.secrets_mut() {
            unsealed |= !secret.is_empty() && !vault::is_sealed(secret);
            *secret = self.vault.open_value(secret)?;
        }
        if unsealed {
            self.save(&saved)?;
        }
        Ok(saved)
    }

    pub fn save(&self, saved: &Saved) -> Result<(), String> {
        let file = self.dir.join(FILE);
        let mut sealed = saved.clone();
        for secret in sealed.secrets_mut() {
            *secret = self.vault.seal(secret)?;
        }
        let text = serde_json::to_string_pretty(&sealed).map_err(|e| e.to_string())?;
        write_atomically(&self.dir, &file, text.as_bytes())
            .map_err(|e| format!("cannot write {}: {e}", file.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn defaults() -> Defaults {
        Defaults {
            database_url: "postgres://nbuddyn:dbpass@n8n_postgres:5432/n8n".into(),
            name: "n8n".into(),
            lang: "es".into(),
            interval_seconds: 300,
            history_days: 400,
            runner_urls: "runner-01,runner-02".into(),
            redis_url: "redis://:s3cret@n8n_redis:6379".into(),
            ..Defaults::default()
        }
    }

    #[test]
    fn the_environment_describes_the_first_instance() {
        let effective = Saved::default().resolve(&defaults()).unwrap();
        assert_eq!(effective.lang, Lang::Es);
        assert_eq!(effective.interval, Duration::from_secs(300));
        assert_eq!(effective.instances.len(), 1);
        let first = effective.instance(None).unwrap();
        assert_eq!((first.id.as_str(), first.name.as_str()), (PRIMARY, "n8n"));
        assert_eq!(first.runners.len(), 2);
        assert_eq!(
            first.redis.as_ref().unwrap().password.as_deref(),
            Some("s3cret")
        );
        assert_eq!(first.n8n_url, "");
        assert_eq!(first.timezone, None);
        assert!(effective.instance(Some("nope")).is_none());
    }

    #[test]
    fn the_page_never_sees_passwords_and_keeps_them_when_untouched() {
        let saved = Saved::default();
        let mut form = saved.form(&defaults(), PRIMARY).unwrap();
        assert_eq!(form.redis_url, "redis://:••••@n8n_redis:6379");
        assert_eq!(
            form.database_url,
            "postgres://nbuddyn:••••@n8n_postgres:5432/n8n"
        );
        assert_eq!(form.runner_urls, "runner-01\nrunner-02");

        form.n8n_url = "https://n8n.example.com/".into();
        form.runner_urls = "runner-01\nrunner-03:5681\n".into();
        let next = saved.with_form(PRIMARY, &form, &defaults()).unwrap();
        assert_eq!(next.redis_url, None);
        assert_eq!(next.n8n_url.as_deref(), Some("https://n8n.example.com"));
        let effective = next.resolve(&defaults()).unwrap();
        let first = effective.instance(None).unwrap();
        assert_eq!(
            first.redis.as_ref().unwrap().password.as_deref(),
            Some("s3cret")
        );
        assert_eq!(first.runners[1].port, 5681);

        form.redis_url = String::new();
        let off = next.with_form(PRIMARY, &form, &defaults()).unwrap();
        assert!(off.resolve(&defaults()).unwrap().instances[0]
            .redis
            .is_none());
    }

    #[test]
    fn wrong_values_are_named_and_nothing_is_saved() {
        let saved = Saved::default();
        let mut form = saved.form(&defaults(), PRIMARY).unwrap();
        form.name = "  ".into();
        form.n8n_url = "javascript:alert(1)".into();
        form.interval_seconds = "3".into();
        form.history_days = "many".into();
        form.timezone = "Buenos Aires; drop".into();
        form.lang = "fr".into();
        form.runner_urls = "https://runner".into();
        form.redis_url = "n8n_redis".into();
        form.telegram_token = "not-a-token".into();
        form.webhook_url = "ftp://hooks".into();
        form.alert_level = "always".into();
        assert_eq!(
            saved.with_form(PRIMARY, &form, &defaults()).unwrap_err(),
            vec![
                "alert_level",
                "history_days",
                "interval_seconds",
                "lang",
                "n8n_url",
                "name",
                "redis_url",
                "runner_urls",
                "telegram_chat",
                "telegram_token",
                "timezone",
                "webhook_url"
            ]
        );
    }

    #[test]
    fn alert_destinations_are_kept_secret_and_checked() {
        let d = defaults();
        let saved = Saved::default();
        assert!(!saved.resolve(&d).unwrap().alerts.enabled());
        let mut form = saved.form(&d, PRIMARY).unwrap();
        assert_eq!(
            (form.alert_level.as_str(), form.alert_changes.as_str()),
            ("high", "false")
        );

        // Not a real token. Written in two halves so secret scanners, which
        // look for the shape of a Telegram token, do not raise a false alarm.
        form.telegram_token = format!("{}:{}", "123456", "made-up-token-for-this-test-only-000");
        assert_eq!(
            saved.with_form(PRIMARY, &form, &d).unwrap_err(),
            vec!["telegram_chat"]
        );
        form.telegram_chat = "-1001234567890".into();
        form.webhook_url = "https://hooks.slack.com/services/T0/B0/secret".into();
        form.alert_level = "medium".into();
        form.alert_changes = "true".into();
        let next = saved.with_form(PRIMARY, &form, &d).unwrap();
        let alerts = next.resolve(&d).unwrap().alerts;
        assert_eq!(alerts.telegram.as_ref().unwrap().1, "-1001234567890");
        assert_eq!(alerts.telegram_api, "https://api.telegram.org");
        assert_eq!((alerts.level, alerts.changes), (Level::Medium, true));

        // The page gets dots and a host, and sending them back keeps the secrets.
        let shown = next.form(&d, PRIMARY).unwrap();
        assert_eq!(shown.telegram_token, "••••••••");
        assert_eq!(shown.webhook_url, "https://hooks.slack.com/••••");
        let again = next.with_form(PRIMARY, &shown, &d).unwrap();
        assert_eq!(again.telegram_token, next.telegram_token);
        assert_eq!(again.webhook_url, next.webhook_url);
        // Emptying them turns alerts off.
        let mut off = shown.clone();
        off.telegram_token.clear();
        off.telegram_chat.clear();
        off.webhook_url.clear();
        assert!(!next
            .with_form(PRIMARY, &off, &d)
            .unwrap()
            .resolve(&d)
            .unwrap()
            .alerts
            .enabled());
    }

    #[test]
    fn more_instances_are_added_edited_and_removed() {
        let d = defaults();
        let saved = Saved::default();
        assert_eq!(
            saved
                .with_instance("n2", "Clientes", "mysql://x", &d)
                .unwrap_err(),
            vec!["database_url"]
        );
        assert_eq!(
            saved
                .with_instance("n2", "", "sqlite:/n8n/database.sqlite", &d)
                .unwrap_err(),
            vec!["name"]
        );
        let two = saved
            .with_instance("n2", "Clientes", "postgres://ro:pw@db2:5432/n8n", &d)
            .unwrap();
        let effective = two.resolve(&d).unwrap();
        assert_eq!(effective.instances.len(), 2);
        let second = effective.instance(Some("n2")).unwrap();
        assert_eq!(second.name, "Clientes");
        assert!(second.redis.is_none() && second.runners.is_empty());

        // Editing it keeps the database password it never showed.
        let mut form = two.form(&d, "n2").unwrap();
        assert_eq!(form.database_url, "postgres://ro:••••@db2:5432/n8n");
        form.name = "Clientes SA".into();
        form.n8n_url = "https://clientes.example.com".into();
        let edited = two.with_form("n2", &form, &d).unwrap();
        assert_eq!(
            edited.instances[0].database_url,
            "postgres://ro:pw@db2:5432/n8n"
        );
        assert_eq!(edited.instances[0].name, "Clientes SA");
        // The first instance did not take the second one's values.
        assert_eq!(edited.n8n_url, None);

        assert!(edited.with_form("gone", &form, &d).is_err());
        assert!(edited.without_instance(PRIMARY).is_err());
        assert!(edited.without_instance("n2").unwrap().instances.is_empty());
    }

    #[test]
    fn each_instance_keeps_its_own_accepted_findings() {
        let d = defaults();
        let mut saved = Saved::default()
            .with_instance("n2", "Clientes", "sqlite:/n8n/database.sqlite", &d)
            .unwrap();
        saved.accept(PRIMARY, "a|high|w1||", "public on purpose", 10, "ana");
        saved.accept(
            PRIMARY,
            "a|high|w1||",
            "  reviewed with the client  ",
            20,
            "ana",
        );
        saved.accept("n2", "b|low|||", "", 30, "ana");
        assert_eq!(saved.accepted_in(PRIMARY).len(), 1);
        assert_eq!(
            saved.accepted_in(PRIMARY)[0].note,
            "reviewed with the client"
        );
        assert!(is_accepted(saved.accepted_in("n2"), "b|low|||"));
        assert!(!is_accepted(saved.accepted_in("n2"), "a|high|w1||"));
        assert!(saved.accepted_in("gone").is_empty());
        saved.unaccept(PRIMARY, "a|high|w1||");
        assert!(saved.accepted_in(PRIMARY).is_empty());
    }

    #[test]
    fn an_acceptance_expires_when_the_rules_say_so() {
        let mut saved = Saved::default();
        saved.accept(PRIMARY, "k", "ok for now", 1_000, "ana");
        assert_eq!(saved.accepted_valid(PRIMARY, 9_999_999).len(), 1);
        saved.accept_days = Some(30);
        assert_eq!(saved.accepted_valid(PRIMARY, 1_000 + 29 * 86_400).len(), 1);
        assert!(saved
            .accepted_valid(PRIMARY, 1_000 + 30 * 86_400)
            .is_empty());
    }

    #[test]
    fn settings_survive_a_restart_with_their_secrets_sealed() {
        let dir = std::env::temp_dir().join(format!("nbuddyn-settings-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let key = "a-key-that-is-long-enough-for-nbuddyn";
        let vault = std::sync::Arc::new(Vault::open(Some(key), &dir).unwrap());
        let store = Store::new(&dir, vault);
        assert_eq!(store.load().unwrap(), Saved::default());
        let mut saved = Saved {
            n8n_url: Some("https://n8n.example.com".into()),
            redis_url: Some("redis://:r3dis@n8n_redis:6379".into()),
            ..Saved::default()
        }
        .with_instance(
            "n2",
            "Clientes",
            "postgres://ro:pgpass@db2:5432/n8n",
            &defaults(),
        )
        .unwrap();
        saved.accept(PRIMARY, "k", "", 5, "ana");
        store.save(&saved).unwrap();
        assert_eq!(store.load().unwrap(), saved);
        let on_disk = std::fs::read_to_string(dir.join(FILE)).unwrap();
        assert!(!on_disk.contains("pgpass") && !on_disk.contains("r3dis"));
        assert!(on_disk.contains("https://n8n.example.com"));

        // Another key cannot open them, and nbuddyn says so instead of guessing.
        let other = std::sync::Arc::new(
            Vault::open(Some("another-key-that-is-also-long-enough"), &dir).unwrap(),
        );
        assert!(Store::new(&dir, other).load().is_err());

        // A file from before sealing existed is read and sealed on the spot.
        let plain = r#"{"instances":[{"id":"n2","name":"Clientes","database_url":"postgres://ro:pgpass@db2:5432/n8n"}]}"#;
        std::fs::write(dir.join(FILE), plain).unwrap();
        let read = store.load().unwrap();
        assert_eq!(
            read.instances[0].database_url,
            "postgres://ro:pgpass@db2:5432/n8n"
        );
        assert!(!std::fs::read_to_string(dir.join(FILE))
            .unwrap()
            .contains("pgpass"));

        std::fs::write(dir.join(FILE), "{ nope").unwrap();
        assert!(store.load().is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
