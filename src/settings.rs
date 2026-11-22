//! What can be changed from the page instead of from environment variables,
//! and the findings someone decided to live with.
//!
//! Environment variables give the starting values. Once something is saved
//! from the page it is kept in one JSON file next to the history and wins.
//! The connection to n8n's database and the passwords of nbuddyn itself are
//! not here: without them there is no page to change them from.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::cluster::RedisConfig;
use crate::history::write_atomically;
use crate::i18n::Lang;
use crate::runners::{self, RunnerTarget};

const FILE: &str = "settings.json";

/// The starting values, read from the environment once.
#[derive(Debug, Clone, Default)]
pub struct Defaults {
    pub n8n_url: String,
    pub lang: String,
    pub interval_seconds: u64,
    pub timezone: String,
    pub history_days: u32,
    pub runner_urls: String,
    pub redis_url: String,
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
}

/// What was saved from the page. `None` means "never changed here".
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Saved {
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
}

/// The settings as text, the way the page shows and sends them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Form {
    #[serde(default)]
    pub n8n_url: String,
    #[serde(default)]
    pub lang: String,
    #[serde(default)]
    pub interval_seconds: String,
    #[serde(default)]
    pub timezone: String,
    #[serde(default)]
    pub history_days: String,
    #[serde(default)]
    pub runner_urls: String,
    /// Shown with its password hidden; sent back unchanged means "keep it".
    #[serde(default)]
    pub redis_url: String,
}

/// The settings in force, checked and ready to use.
#[derive(Debug, Clone)]
pub struct Effective {
    /// Where n8n's editor is, without a trailing slash. Empty when unknown.
    pub n8n_url: String,
    pub lang: Lang,
    pub interval: Duration,
    pub timezone: Option<String>,
    pub history_days: u32,
    pub runners: Vec<RunnerTarget>,
    pub redis: Option<RedisConfig>,
}

pub const MIN_INTERVAL: u64 = 10;
const MAX_INTERVAL: u64 = 86_400;
const MAX_HISTORY_DAYS: u32 = 3650;

impl Saved {
    /// The values in force as text: what was saved, or else the default.
    fn texts(&self, defaults: &Defaults) -> Form {
        let text = |saved: &Option<String>, default: &str| {
            saved.clone().unwrap_or_else(|| default.to_owned())
        };
        Form {
            n8n_url: text(&self.n8n_url, &defaults.n8n_url),
            lang: text(&self.lang, &defaults.lang),
            interval_seconds: self
                .interval_seconds
                .unwrap_or(defaults.interval_seconds)
                .to_string(),
            timezone: text(&self.timezone, &defaults.timezone),
            history_days: self
                .history_days
                .unwrap_or(defaults.history_days)
                .to_string(),
            runner_urls: text(&self.runner_urls, &defaults.runner_urls),
            redis_url: text(&self.redis_url, &defaults.redis_url),
        }
    }

    /// What the page shows: the values in force, with Redis' password hidden.
    pub fn form(&self, defaults: &Defaults) -> Form {
        let mut form = self.texts(defaults);
        form.redis_url = hide_password(&form.redis_url);
        form.runner_urls = form
            .runner_urls
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .collect::<Vec<_>>()
            .join("\n");
        form
    }

    /// Checks the values in force and turns them into something usable. On
    /// failure, names the fields that are wrong.
    pub fn resolve(&self, defaults: &Defaults) -> Result<Effective, Vec<&'static str>> {
        let texts = self.texts(defaults);
        let mut wrong = Vec::new();

        let n8n_url = texts.n8n_url.trim().trim_end_matches('/').to_owned();
        if !n8n_url.is_empty() && !is_web_address(&n8n_url) {
            wrong.push("n8n_url");
        }

        let lang = texts.lang.trim().to_ascii_lowercase();
        if !lang.is_empty() && !["en", "es", "pt"].contains(&lang.as_str()) {
            wrong.push("lang");
        }

        let interval = texts
            .interval_seconds
            .trim()
            .parse::<u64>()
            .ok()
            .filter(|s| (MIN_INTERVAL..=MAX_INTERVAL).contains(s));
        if interval.is_none() {
            wrong.push("interval_seconds");
        }

        let timezone = texts.timezone.trim().to_owned();
        let zone_ok = timezone.len() <= 64
            && timezone
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '+' | '-'));
        if !zone_ok {
            wrong.push("timezone");
        }

        let history_days = texts
            .history_days
            .trim()
            .parse::<u32>()
            .ok()
            .filter(|d| (1..=MAX_HISTORY_DAYS).contains(d));
        if history_days.is_none() {
            wrong.push("history_days");
        }

        let runners = runners::parse_targets(&texts.runner_urls.replace(['\n', '\r', ';'], ","));
        if runners.is_err() {
            wrong.push("runner_urls");
        }

        let redis_url = texts.redis_url.trim();
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

        match (interval, history_days, runners, redis) {
            (Some(interval), Some(history_days), Ok(runners), Ok(redis)) if wrong.is_empty() => {
                Ok(Effective {
                    n8n_url,
                    lang: Lang::parse(&lang),
                    interval: Duration::from_secs(interval),
                    timezone: Some(timezone).filter(|z| !z.is_empty()),
                    history_days,
                    runners,
                    redis,
                })
            }
            _ => Err(wrong),
        }
    }

    /// Takes what the page sent. Nothing changes unless everything is valid.
    pub fn with_form(&self, form: &Form, defaults: &Defaults) -> Result<Saved, Vec<&'static str>> {
        let shown = self.form(defaults);
        let mut next = self.clone();
        next.n8n_url = Some(form.n8n_url.trim().trim_end_matches('/').to_owned());
        next.lang = Some(form.lang.trim().to_ascii_lowercase());
        next.timezone = Some(form.timezone.trim().to_owned());
        next.runner_urls = Some(
            form.runner_urls
                .split([',', '\n', '\r', ';'])
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .collect::<Vec<_>>()
                .join(","),
        );
        // The page never had the password, so the address it shows coming
        // back untouched means Redis was not edited.
        if form.redis_url.trim() != shown.redis_url {
            next.redis_url = Some(form.redis_url.trim().to_owned());
        }

        let mut wrong = Vec::new();
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

    pub fn is_accepted(&self, key: &str) -> bool {
        self.accepted.iter().any(|a| a.key == key)
    }

    pub fn accept(&mut self, key: &str, note: &str, at: u64) {
        self.accepted.retain(|a| a.key != key);
        self.accepted.push(Accepted {
            key: key.to_owned(),
            note: note.trim().chars().take(NOTE_MAX).collect(),
            at,
        });
    }

    pub fn unaccept(&mut self, key: &str) {
        self.accepted.retain(|a| a.key != key);
    }
}

/// The longest note kept with an accepted finding, in characters.
const NOTE_MAX: usize = 300;

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

/// `redis://user:secret@host` becomes `redis://user:••••@host`.
fn hide_password(url: &str) -> String {
    let Some(rest) = url.strip_prefix("redis://") else {
        return url.to_owned();
    };
    match rest.rsplit_once('@') {
        Some((auth, location)) => {
            let user = auth.split_once(':').map_or("", |(user, _)| user);
            format!("redis://{user}:••••@{location}")
        }
        None => url.to_owned(),
    }
}

/// Where the settings live on disk.
#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Reads what was saved, or nothing when nothing was. A file that cannot
    /// be understood is an error: guessing would silently drop decisions.
    pub fn load(&self) -> Result<Saved, String> {
        let file = self.dir.join(FILE);
        match std::fs::read_to_string(&file) {
            Ok(text) => serde_json::from_str(&text)
                .map_err(|e| format!("{} is not valid: {e}", file.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Saved::default()),
            Err(e) => Err(format!("cannot read {}: {e}", file.display())),
        }
    }

    pub fn save(&self, saved: &Saved) -> Result<(), String> {
        let file = self.dir.join(FILE);
        let text = serde_json::to_string_pretty(saved).map_err(|e| e.to_string())?;
        write_atomically(&self.dir, &file, text.as_bytes())
            .map_err(|e| format!("cannot write {}: {e}", file.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn defaults() -> Defaults {
        Defaults {
            lang: "es".into(),
            interval_seconds: 300,
            history_days: 400,
            runner_urls: "runner-01,runner-02".into(),
            redis_url: "redis://:s3cret@n8n_redis:6379".into(),
            ..Defaults::default()
        }
    }

    #[test]
    fn the_environment_gives_the_starting_values() {
        let effective = Saved::default().resolve(&defaults()).unwrap();
        assert_eq!(effective.lang, Lang::Es);
        assert_eq!(effective.interval, Duration::from_secs(300));
        assert_eq!(effective.runners.len(), 2);
        assert_eq!(effective.redis.unwrap().password.as_deref(), Some("s3cret"));
        assert_eq!(effective.n8n_url, "");
        assert_eq!(effective.timezone, None);
    }

    #[test]
    fn the_page_never_sees_the_redis_password_and_keeps_it_when_untouched() {
        let saved = Saved::default();
        let mut form = saved.form(&defaults());
        assert_eq!(form.redis_url, "redis://:••••@n8n_redis:6379");
        assert_eq!(form.runner_urls, "runner-01\nrunner-02");

        form.n8n_url = "https://n8n.example.com/".into();
        form.runner_urls = "runner-01\nrunner-03:5681\n".into();
        let next = saved.with_form(&form, &defaults()).unwrap();
        assert_eq!(next.redis_url, None);
        assert_eq!(next.n8n_url.as_deref(), Some("https://n8n.example.com"));
        let effective = next.resolve(&defaults()).unwrap();
        assert_eq!(effective.redis.unwrap().password.as_deref(), Some("s3cret"));
        assert_eq!(effective.runners[1].port, 5681);

        form.redis_url = String::new();
        let off = next.with_form(&form, &defaults()).unwrap();
        assert!(off.resolve(&defaults()).unwrap().redis.is_none());
    }

    #[test]
    fn wrong_values_are_named_and_nothing_is_saved() {
        let saved = Saved::default();
        let mut form = saved.form(&defaults());
        form.n8n_url = "javascript:alert(1)".into();
        form.interval_seconds = "3".into();
        form.history_days = "many".into();
        form.timezone = "Buenos Aires; drop".into();
        form.lang = "fr".into();
        form.runner_urls = "https://runner".into();
        form.redis_url = "n8n_redis".into();
        assert_eq!(
            saved.with_form(&form, &defaults()).unwrap_err(),
            vec![
                "history_days",
                "interval_seconds",
                "lang",
                "n8n_url",
                "redis_url",
                "runner_urls",
                "timezone"
            ]
        );
    }

    #[test]
    fn accepting_twice_keeps_one_entry_with_the_latest_note() {
        let mut saved = Saved::default();
        saved.accept("a|high|w1||", "public on purpose", 10);
        saved.accept("a|high|w1||", "  reviewed with the client  ", 20);
        assert_eq!(saved.accepted.len(), 1);
        assert_eq!(saved.accepted[0].note, "reviewed with the client");
        assert!(saved.is_accepted("a|high|w1||"));
        saved.unaccept("a|high|w1||");
        assert!(!saved.is_accepted("a|high|w1||"));
    }

    #[test]
    fn settings_survive_a_restart() {
        let dir = std::env::temp_dir().join(format!("nbuddyn-settings-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(&dir);
        assert_eq!(store.load().unwrap(), Saved::default());
        let mut saved = Saved {
            n8n_url: Some("https://n8n.example.com".into()),
            ..Saved::default()
        };
        saved.accept("k", "", 5);
        store.save(&saved).unwrap();
        assert_eq!(store.load().unwrap(), saved);
        std::fs::write(dir.join(FILE), "{ nope").unwrap();
        assert!(store.load().is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
