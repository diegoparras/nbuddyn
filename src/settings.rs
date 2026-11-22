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

use crate::cluster::RedisConfig;
use crate::db;
use crate::history::write_atomically;
use crate::i18n::Lang;
use crate::runners::{self, RunnerTarget};

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
        })
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

        if wrong.is_empty() {
            Ok(Effective {
                lang: Lang::parse(&lang),
                interval: Duration::from_secs(interval),
                history_days,
                instances,
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

    pub fn accept(&mut self, id: &str, key: &str, note: &str, at: u64) {
        if let Some(accepted) = self.accepted_mut(id) {
            accepted.retain(|a| a.key != key);
            accepted.push(Accepted {
                key: key.to_owned(),
                note: note.trim().chars().take(NOTE_MAX).collect(),
                at,
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
        assert_eq!(
            saved.with_form(PRIMARY, &form, &defaults()).unwrap_err(),
            vec![
                "history_days",
                "interval_seconds",
                "lang",
                "n8n_url",
                "name",
                "redis_url",
                "runner_urls",
                "timezone"
            ]
        );
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
        saved.accept(PRIMARY, "a|high|w1||", "public on purpose", 10);
        saved.accept(PRIMARY, "a|high|w1||", "  reviewed with the client  ", 20);
        saved.accept("n2", "b|low|||", "", 30);
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
    fn settings_survive_a_restart() {
        let dir = std::env::temp_dir().join(format!("nbuddyn-settings-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(&dir);
        assert_eq!(store.load().unwrap(), Saved::default());
        let mut saved = Saved {
            n8n_url: Some("https://n8n.example.com".into()),
            ..Saved::default()
        };
        saved.accept(PRIMARY, "k", "", 5);
        store.save(&saved).unwrap();
        assert_eq!(store.load().unwrap(), saved);
        std::fs::write(dir.join(FILE), "{ nope").unwrap();
        assert!(store.load().is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
