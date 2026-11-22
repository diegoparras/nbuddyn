//! The web page and the JSON report behind it.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Query, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, RwLock};

use crate::cluster::Cluster;
use crate::history::{self, History};
use crate::i18n::{self, ui_text, Lang, UiText};
use crate::mcp;
use crate::radar::{Finding, Severity};
use crate::runners::RunnerProbe;
use crate::settings::{self, Accepted, Defaults, Effective, Instance, Saved, PRIMARY};

/// Result of the latest scan, kept in memory.
#[derive(Debug, Clone, Default)]
pub struct Scan {
    pub generated_at: u64,
    pub inventory: Inventory,
    pub findings: Vec<Finding>,
    pub cluster: Option<Cluster>,
    pub runners: Vec<RunnerProbe>,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct Inventory {
    pub workflows: usize,
    pub active: usize,
    pub credentials: usize,
    pub users: i64,
    pub nodes: usize,
    pub waiting: i64,
}

pub struct AppState {
    pub user: String,
    /// `None` means the page is open to anyone who can reach it.
    pub password: Option<String>,
    /// Starting values from the environment.
    pub defaults: Defaults,
    /// What was saved from the page, including the accepted findings.
    pub saved: RwLock<Saved>,
    /// `None` when there is nowhere to save, so the page can only read.
    pub settings_store: Option<settings::Store>,
    /// Why saved settings were ignored at start, if they were.
    pub settings_error: Option<String>,
    /// Wakes the scanner so a change shows without waiting for the interval.
    pub rescan: Notify,
    /// Whether nbuddyn was given a place to keep its own history.
    pub history_enabled: bool,
    /// What the scanner last saw in each instance, by instance id.
    pub runtimes: RwLock<HashMap<String, Arc<Runtime>>>,
    /// The token MCP clients must present. `None` turns the MCP endpoint off.
    pub mcp_token: Option<String>,
}

/// What the scanner last saw in one instance.
#[derive(Default)]
pub struct Runtime {
    pub latest: RwLock<Option<Scan>>,
    pub last_error: RwLock<Option<String>>,
    /// Why Redis could not be read in the latest scan, if it could not.
    pub cluster_error: RwLock<Option<String>>,
    pub history: RwLock<Option<Arc<History>>>,
    /// Why the history could not be updated in the latest scan, if it could not.
    pub history_error: RwLock<Option<String>>,
}

impl AppState {
    /// The scanner's notes about one instance, started empty on first use.
    pub async fn runtime(&self, id: &str) -> Arc<Runtime> {
        if let Some(runtime) = self.runtimes.read().await.get(id) {
            return runtime.clone();
        }
        self.runtimes
            .write()
            .await
            .entry(id.to_owned())
            .or_default()
            .clone()
    }

    /// Drops what was seen in instances that no longer exist.
    pub async fn forget_runtimes_except(&self, instances: &[Instance]) {
        self.runtimes
            .write()
            .await
            .retain(|id, _| instances.iter().any(|i| i.id == *id));
    }

    /// The instance a request is about: the one it names, or the first one
    /// when it names none or one that is gone.
    async fn pick(&self, id: Option<&str>) -> (Effective, Instance) {
        let effective = self.effective().await;
        let instance = effective
            .instance(id)
            .or_else(|| effective.instance(None))
            .expect("there is always a first instance")
            .clone();
        (effective, instance)
    }

    /// The settings in force. What is saved was checked when it was saved, and
    /// the starting values when nbuddyn started, so the fallback is never hit.
    pub async fn effective(&self) -> Effective {
        let saved = self.saved.read().await;
        saved
            .resolve(&self.defaults)
            .or_else(|_| Saved::default().resolve(&self.defaults))
            .expect("the starting values were checked at start")
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    let protected = Router::new()
        .route("/", get(index))
        .route("/api/report", get(report))
        .route("/api/history", get(history_report))
        .route("/api/activity", get(activity))
        .route("/api/settings", get(settings_view).post(settings_save))
        .route("/api/accept", post(accept))
        .route("/api/unaccept", post(unaccept))
        .route("/api/rescan", post(rescan))
        .route("/api/instances", post(instance_add))
        .route("/api/instances/remove", post(instance_remove))
        .layer(middleware::from_fn_with_state(state.clone(), require_login));

    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        // Checks its own token: MCP clients send a bearer token, not a login.
        .route("/mcp", post(mcp::post).fallback(mcp::other))
        .merge(protected)
        .with_state(state)
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../assets/index.html"))
}

#[derive(Deserialize)]
struct ReportQuery {
    lang: Option<String>,
    instance: Option<String>,
}

/// Which instance a request is about. Absent means the first one.
#[derive(Deserialize)]
struct Which {
    instance: Option<String>,
}

#[derive(Deserialize)]
struct HistoryQuery {
    days: Option<u32>,
    instance: Option<String>,
}

#[derive(Serialize)]
struct HistoryReport {
    /// False when nbuddyn has no data directory, so it remembers nothing.
    enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(flatten)]
    view: history::View,
}

const DAY: u64 = 86_400;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[derive(Serialize)]
struct ActivityReport {
    /// False when nbuddyn has no data directory, so it remembers nothing.
    enabled: bool,
    events: Vec<EventView>,
}

#[derive(Serialize)]
struct EventView {
    /// What happened, in words.
    label: String,
    #[serde(flatten)]
    event: history::Event,
}

async fn read_activity(
    state: &AppState,
    lang: Option<Lang>,
    days: Option<u32>,
    instance: Option<&str>,
) -> ActivityReport {
    let span = u64::from(days.unwrap_or(7).clamp(1, MAX_SPAN));
    let (effective, instance) = state.pick(instance).await;
    let lang = lang.unwrap_or(effective.lang);
    let history = state
        .runtime(&instance.id)
        .await
        .history
        .read()
        .await
        .clone();
    let events = history
        .iter()
        .flat_map(|h| h.events_since(now().saturating_sub(span * DAY)))
        .take(ACTIVITY_MAX)
        .map(|event| EventView {
            label: match &event.check {
                Some(check) => i18n::group_title(lang, check, 1),
                None => i18n::event_label(lang, &event.kind).to_owned(),
            },
            event: event.clone(),
        })
        .collect();
    ActivityReport {
        enabled: state.history_enabled,
        events,
    }
}

/// The most events one request returns.
const ACTIVITY_MAX: usize = 500;

#[derive(Deserialize)]
struct ActivityQuery {
    lang: Option<String>,
    days: Option<u32>,
    instance: Option<String>,
}

async fn activity(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ActivityQuery>,
) -> Json<ActivityReport> {
    let lang = q.lang.as_deref().map(Lang::parse);
    Json(read_activity(&state, lang, q.days, q.instance.as_deref()).await)
}

/// The activity as the page gets it, for the MCP tools.
pub async fn current_activity(
    state: &AppState,
    lang: Option<Lang>,
    days: Option<u32>,
    instance: Option<&str>,
) -> serde_json::Value {
    serde_json::to_value(read_activity(state, lang, days, instance).await).unwrap_or_default()
}

/// Days shown when the page does not ask for a span.
const DEFAULT_SPAN: u32 = 30;
/// The longest span one request can ask for.
pub const MAX_SPAN: u32 = 366;

async fn history_report(
    State(state): State<Arc<AppState>>,
    Query(q): Query<HistoryQuery>,
) -> Json<HistoryReport> {
    Json(read_history(&state, q.days, q.instance.as_deref()).await)
}

async fn read_history(
    state: &AppState,
    days: Option<u32>,
    instance: Option<&str>,
) -> HistoryReport {
    let span = days.unwrap_or(DEFAULT_SPAN).clamp(1, MAX_SPAN);
    let (_, instance) = state.pick(instance).await;
    let runtime = state.runtime(&instance.id).await;
    let history = runtime.history.read().await.clone();
    let error = runtime.history_error.read().await.clone();
    HistoryReport {
        enabled: state.history_enabled,
        error,
        view: history.map(|h| h.view(span)).unwrap_or_default(),
    }
}

/// The history as the page gets it, for the MCP tools.
pub async fn current_history(
    state: &AppState,
    days: Option<u32>,
    instance: Option<&str>,
) -> serde_json::Value {
    serde_json::to_value(read_history(state, days, instance).await).unwrap_or_default()
}

/// The report as the page gets it, for the MCP tools.
pub async fn current_report(
    state: &AppState,
    lang: Option<Lang>,
    instance: Option<&str>,
) -> serde_json::Value {
    serde_json::to_value(read_report(state, lang, instance).await).unwrap_or_default()
}

/// The id of the instance with this id or, failing that, this name.
pub async fn instance_id(state: &AppState, wanted: &str) -> Option<String> {
    let effective = state.effective().await;
    effective
        .instances
        .iter()
        .find(|i| i.id == wanted)
        .or_else(|| {
            effective
                .instances
                .iter()
                .find(|i| i.name.eq_ignore_ascii_case(wanted))
        })
        .map(|i| i.id.clone())
}

/// One line per instance: enough to choose between them.
pub async fn summaries(state: &AppState, effective: &Effective) -> Vec<InstanceSummary> {
    let saved = state.saved.read().await.clone();
    let mut list = Vec::with_capacity(effective.instances.len());
    for instance in &effective.instances {
        let runtime = state.runtime(&instance.id).await;
        let latest = runtime.latest.read().await;
        let accepted = saved.accepted_in(&instance.id);
        let open = |scan: &Scan| {
            scan.findings
                .iter()
                .filter(|f| !settings::is_accepted(accepted, &f.key()))
                .cloned()
                .collect::<Vec<_>>()
        };
        let findings = latest.as_ref().map(open);
        let score = findings.as_deref().map(crate::radar::score);
        list.push(InstanceSummary {
            id: instance.id.clone(),
            name: instance.name.clone(),
            available: latest.is_some(),
            score: score.unwrap_or(0),
            zone: score.map_or("off", zone_of),
            urgent: findings.map_or(0, |f| {
                f.iter().filter(|f| f.severity == Severity::High).count()
            }),
        });
    }
    list
}

/// `lang` is what the reader asked for; without it the configured one is used.
async fn read_report(state: &AppState, lang: Option<Lang>, instance: Option<&str>) -> Report {
    let (effective, instance) = state.pick(instance).await;
    let runtime = state.runtime(&instance.id).await;
    let scan = runtime.latest.read().await.clone();
    let error = runtime.last_error.read().await.clone();
    let cluster_error = runtime.cluster_error.read().await.clone();
    let extras = Extras {
        accepted: state.saved.read().await.accepted_in(&instance.id).to_vec(),
        n8n_url: instance.n8n_url.clone(),
        writable: state.settings_store.is_some(),
        interval_seconds: effective.interval.as_secs(),
        instances: summaries(state, &effective).await,
        instance: InstanceRef {
            id: instance.id.clone(),
            name: instance.name.clone(),
        },
        history: runtime.history.read().await.clone(),
        now: now(),
    };
    compose_report(
        lang.unwrap_or(effective.lang),
        scan,
        error,
        cluster_error,
        &extras,
    )
}

#[derive(Serialize)]
struct Report {
    lang: &'static str,
    available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    generated_at: u64,
    score: u32,
    /// `risk`, `caution` or `ok`: where the score sits on the gauge.
    zone: &'static str,
    headline: String,
    lead: String,
    lights: Vec<Light>,
    totals: Totals,
    inventory: Inventory,
    /// Queue, Redis and cluster members; absent when no Redis is configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    cluster: Option<ClusterView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cluster_error: Option<String>,
    /// Task runners that answered; absent when none is configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    runners: Option<RunnersView>,
    groups: Vec<Group>,
    /// What changed in the last day; absent without a history.
    #[serde(skip_serializing_if = "Option::is_none")]
    changes: Option<Changes>,
    /// Findings someone accepted: listed apart and left out of the score.
    accepted: Vec<AcceptedView>,
    /// Where n8n's editor is, for links. Empty when not configured.
    n8n_url: String,
    /// Whether findings can be accepted and settings saved.
    writable: bool,
    /// Seconds between scans, so the page can say when the next one is due.
    interval_seconds: u64,
    /// The instance this report is about, and all of them to switch between.
    instance: InstanceRef,
    instances: Vec<InstanceSummary>,
    ui: UiText,
}

#[derive(Serialize)]
struct ClusterView {
    waiting: i64,
    active: i64,
    delayed: i64,
    main: usize,
    workers: usize,
    webhooks: usize,
    versions: Vec<String>,
    redis_used_mb: i64,
    /// 0 means Redis has no memory limit.
    redis_max_mb: i64,
    eviction_policy: String,
    members: Vec<MemberView>,
}

impl ClusterView {
    fn of(cluster: &Cluster) -> Self {
        const MB: i64 = 1024 * 1024;
        Self {
            waiting: cluster.queue.waiting,
            active: cluster.queue.active,
            delayed: cluster.queue.delayed,
            main: cluster.count("main"),
            workers: cluster.count("worker"),
            webhooks: cluster.count("webhook"),
            versions: cluster.versions().into_iter().map(str::to_owned).collect(),
            redis_used_mb: (cluster.redis.used_memory + MB / 2) / MB,
            redis_max_mb: cluster.redis.max_memory / MB,
            eviction_policy: cluster.redis.eviction_policy.clone(),
            members: cluster
                .members
                .iter()
                .map(|m| MemberView {
                    kind: m.kind.clone(),
                    host: m.host_id.clone(),
                    version: m.version.clone(),
                })
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct AcceptedView {
    key: String,
    /// What the finding is, in the words of its group.
    title: String,
    #[serde(flatten)]
    item: Item,
    #[serde(skip_serializing_if = "String::is_empty")]
    note: String,
    /// Seconds since 1970.
    at: u64,
}

#[derive(Serialize)]
struct RunnersView {
    alive: usize,
    total: usize,
    list: Vec<RunnerView>,
}

#[derive(Serialize)]
struct RunnerView {
    name: String,
    /// Absent when the runner answered.
    #[serde(skip_serializing_if = "Option::is_none")]
    problem: Option<String>,
}

#[derive(Serialize)]
struct MemberView {
    /// `main`, `worker` or `webhook`.
    kind: String,
    host: String,
    version: String,
}

/// One annunciator light: an area of the instance and how bad it looks.
#[derive(Serialize)]
struct Light {
    key: &'static str,
    /// The checks this light watches, so the page can show its findings.
    checks: &'static [&'static str],
    count: usize,
    /// `high`, `medium` or `ok`.
    level: &'static str,
}

#[derive(Default, Serialize)]
struct Totals {
    urgent: usize,
    important: usize,
    minor: usize,
    info: usize,
}

/// Findings of one check and severity, reported together.
#[derive(Serialize)]
struct Group {
    check: &'static str,
    severity: Severity,
    count: usize,
    title: String,
    advice: &'static str,
    items: Vec<Item>,
}

#[derive(Serialize)]
struct Item {
    /// Identifies the finding when accepting it.
    key: String,
    /// Path under n8n's address where the finding can be seen.
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    workflow: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    node: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    active: Option<bool>,
    /// When it first appeared, in seconds since 1970, if nbuddyn saw it appear.
    #[serde(skip_serializing_if = "Option::is_none")]
    since: Option<u64>,
}

/// What changed in the last day.
#[derive(Clone, Copy, Default, Serialize)]
struct Changes {
    new: usize,
    resolved: usize,
    workflows: usize,
}

/// Scores below this are in the risk zone of the gauge.
const RISK_BELOW: u32 = 60;
/// Scores below this, and not in the risk zone, call for caution.
const CAUTION_BELOW: u32 = 85;

const LIGHTS: &[(&str, &[&str])] = &[
    ("doors", &["open_ai_entry", "public_entry_no_auth"]),
    (
        "failures",
        &["repeated_failures", "stuck_execution", "stale_workflow"],
    ),
    ("silent", &["no_error_workflow"]),
    ("secrets", &["hardcoded_secret"]),
];

/// The queue light exists only when Redis is being read.
const QUEUE_LIGHT: (&str, &[&str]) = (
    "queue",
    &[
        "redis_eviction",
        "redis_memory_high",
        "queue_backlog",
        "no_workers",
        "version_mismatch",
    ],
);

/// The runners light exists only when runners are being asked.
const RUNNERS_LIGHT: (&str, &[&str]) = ("runners", &["runner_down"]);

async fn report(State(state): State<Arc<AppState>>, Query(q): Query<ReportQuery>) -> Json<Report> {
    let lang = q.lang.as_deref().map(Lang::parse);
    Json(read_report(&state, lang, q.instance.as_deref()).await)
}

/// What a report needs besides the scan.
#[derive(Default)]
struct Extras {
    accepted: Vec<Accepted>,
    n8n_url: String,
    writable: bool,
    interval_seconds: u64,
    instance: InstanceRef,
    instances: Vec<InstanceSummary>,
    /// For telling which findings are new and what changed lately.
    history: Option<Arc<History>>,
    now: u64,
}

/// The instance a report is about.
#[derive(Clone, Default, Serialize)]
struct InstanceRef {
    id: String,
    name: String,
}

/// One instance in the list the page switches between.
#[derive(Clone, Serialize)]
pub struct InstanceSummary {
    id: String,
    name: String,
    /// False until its first scan works.
    available: bool,
    score: u32,
    /// `risk`, `caution`, `ok`, or `off` before the first scan.
    zone: &'static str,
    urgent: usize,
}

/// The score of the findings nobody accepted.
pub fn score_without_accepted(findings: &[Finding], accepted: &[Accepted]) -> u32 {
    let open: Vec<Finding> = findings
        .iter()
        .filter(|f| !settings::is_accepted(accepted, &f.key()))
        .cloned()
        .collect();
    crate::radar::score(&open)
}

fn zone_of(score: u32) -> &'static str {
    if score < RISK_BELOW {
        "risk"
    } else if score < CAUTION_BELOW {
        "caution"
    } else {
        "ok"
    }
}

#[cfg(test)]
fn build_report(
    lang: Lang,
    scan: Option<Scan>,
    error: Option<String>,
    cluster_error: Option<String>,
) -> Report {
    compose_report(lang, scan, error, cluster_error, &Extras::default())
}

fn compose_report(
    lang: Lang,
    scan: Option<Scan>,
    error: Option<String>,
    cluster_error: Option<String>,
    extras: &Extras,
) -> Report {
    let available = scan.is_some();
    let mut scan = scan.unwrap_or_default();

    // Accepted findings leave the score, the lights and the counts, and are
    // listed apart with the note they were accepted with.
    let (accepted, open): (Vec<Finding>, Vec<Finding>) = std::mem::take(&mut scan.findings)
        .into_iter()
        .partition(|f| settings::is_accepted(&extras.accepted, &f.key()));
    scan.findings = open;
    let score = crate::radar::score(&scan.findings);
    let accepted = accepted
        .into_iter()
        .map(|f| {
            let key = f.key();
            let decision = extras.accepted.iter().find(|a| a.key == key);
            AcceptedView {
                title: i18n::group_title(lang, f.check, 1),
                note: decision.map(|a| a.note.clone()).unwrap_or_default(),
                at: decision.map_or(0, |a| a.at),
                item: Item::of(f),
                key,
            }
        })
        .collect();

    let mut totals = Totals::default();
    for f in &scan.findings {
        match f.severity {
            Severity::High => totals.urgent += 1,
            Severity::Medium => totals.important += 1,
            Severity::Low => totals.minor += 1,
            Severity::Info => totals.info += 1,
        }
    }

    let cluster = scan.cluster.as_ref().map(ClusterView::of);
    let lights = LIGHTS
        .iter()
        .chain(cluster.is_some().then_some(&QUEUE_LIGHT))
        .chain((!scan.runners.is_empty()).then_some(&RUNNERS_LIGHT))
        .map(|(key, checks)| {
            let hits: Vec<&Finding> = scan
                .findings
                .iter()
                .filter(|f| checks.contains(&f.check))
                .collect();
            let level = if hits.iter().any(|f| f.severity == Severity::High) {
                "high"
            } else if hits.is_empty() {
                "ok"
            } else {
                "medium"
            };
            Light {
                key,
                checks,
                count: hits.len(),
                level,
            }
        })
        .collect();

    let runners = (!scan.runners.is_empty()).then(|| RunnersView {
        alive: scan.runners.iter().filter(|r| r.problem.is_none()).count(),
        total: scan.runners.len(),
        list: scan
            .runners
            .iter()
            .map(|r| RunnerView {
                name: r.name.clone(),
                problem: r.problem.clone(),
            })
            .collect(),
    });

    let mut groups = group(lang, scan.findings);
    let mut changes = None;
    if let Some(history) = &extras.history {
        for item in groups.iter_mut().flat_map(|g| &mut g.items) {
            item.since = history.since(&item.key);
        }
        let mut counted = Changes::default();
        for event in history.events_since(extras.now.saturating_sub(DAY)) {
            match event.kind.as_str() {
                "finding_new" => counted.new += 1,
                "finding_resolved" => counted.resolved += 1,
                _ => counted.workflows += 1,
            }
        }
        changes = Some(counted);
    }
    let urgent_titles: Vec<String> = groups
        .iter()
        .filter(|g| g.severity == Severity::High)
        .map(|g| g.title.clone())
        .collect();

    Report {
        lang: lang.code(),
        available,
        error,
        generated_at: scan.generated_at,
        score,
        zone: zone_of(score),
        headline: i18n::headline(lang, totals.urgent, totals.important + totals.minor),
        lead: i18n::lead(lang, &urgent_titles),
        lights,
        totals,
        inventory: scan.inventory,
        cluster,
        cluster_error,
        runners,
        groups,
        changes,
        accepted,
        n8n_url: extras.n8n_url.clone(),
        writable: extras.writable,
        interval_seconds: extras.interval_seconds,
        instance: extras.instance.clone(),
        instances: extras.instances.clone(),
        ui: ui_text(lang),
    }
}

/// Folds findings into groups by check and severity, keeping the radar's order.
fn group(lang: Lang, findings: Vec<Finding>) -> Vec<Group> {
    let mut groups: Vec<Group> = Vec::new();
    for f in findings {
        let (check, severity) = (f.check, f.severity);
        let item = Item::of(f);
        match groups
            .iter_mut()
            .find(|g| g.check == check && g.severity == severity)
        {
            Some(existing) => existing.items.push(item),
            None => groups.push(Group {
                check,
                severity,
                count: 0,
                title: String::new(),
                advice: i18n::advice(lang, check),
                items: vec![item],
            }),
        }
    }
    for g in &mut groups {
        g.count = g.items.len();
        g.title = i18n::group_title(lang, g.check, g.count);
    }
    groups
}

impl Item {
    fn of(f: Finding) -> Self {
        Self {
            key: f.key(),
            path: f.path(),
            workflow: f.workflow,
            node: f.node,
            detail: f.detail,
            active: f.active,
            since: None,
        }
    }
}

#[derive(Serialize)]
struct SettingsView {
    /// False when there is nowhere to save: no data directory, or saved
    /// settings that could not be read.
    writable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    values: settings::Form,
    instance: InstanceRef,
    /// True for the instance described by the environment: its database
    /// cannot be changed here and it cannot be removed.
    primary: bool,
    /// Where this instance's database is, without the user or the password.
    database: String,
    mcp: bool,
    version: &'static str,
}

async fn settings_view(
    State(state): State<Arc<AppState>>,
    Query(q): Query<Which>,
) -> Json<SettingsView> {
    let (_, instance) = state.pick(q.instance.as_deref()).await;
    let values = state
        .saved
        .read()
        .await
        .form(&state.defaults, &instance.id)
        .unwrap_or_default();
    Json(SettingsView {
        writable: state.settings_store.is_some(),
        error: state.settings_error.clone(),
        values,
        primary: instance.id == PRIMARY,
        database: crate::db::label(&instance.database_url),
        instance: InstanceRef {
            id: instance.id,
            name: instance.name,
        },
        mcp: state.mcp_token.is_some(),
        version: env!("CARGO_PKG_VERSION"),
    })
}

/// The answer to anything that changes what nbuddyn keeps.
#[derive(Serialize)]
struct Saving {
    ok: bool,
    /// Names of the settings that are not valid.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    wrong: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl Saving {
    fn done() -> Response {
        Json(Self {
            ok: true,
            wrong: Vec::new(),
            error: None,
        })
        .into_response()
    }

    fn refused(status: StatusCode, wrong: Vec<&'static str>, error: Option<String>) -> Response {
        let body = Self {
            ok: false,
            wrong,
            error,
        };
        (status, Json(body)).into_response()
    }
}

/// A browser only sends this header from nbuddyn's own page: another site
/// would need permission that nbuddyn never gives. It keeps a page elsewhere
/// from changing settings with the login the browser remembers.
const WRITE_HEADER: &str = "x-nbuddyn";

/// Applies `change` to a copy of what is saved, writes it, and only then puts
/// it in force.
async fn save_with(
    state: &AppState,
    headers: &HeaderMap,
    change: impl FnOnce(&Saved) -> Result<Saved, Vec<&'static str>>,
) -> Response {
    if !headers.contains_key(WRITE_HEADER) {
        return Saving::refused(StatusCode::FORBIDDEN, Vec::new(), None);
    }
    let Some(store) = &state.settings_store else {
        let reason = state.settings_error.clone();
        return Saving::refused(StatusCode::CONFLICT, Vec::new(), reason);
    };
    let mut saved = state.saved.write().await;
    let next = match change(&saved) {
        Ok(next) => next,
        Err(wrong) => return Saving::refused(StatusCode::UNPROCESSABLE_ENTITY, wrong, None),
    };
    if let Err(reason) = store.save(&next) {
        eprintln!("settings not saved: {reason}");
        return Saving::refused(StatusCode::INTERNAL_SERVER_ERROR, Vec::new(), Some(reason));
    }
    *saved = next;
    drop(saved);
    state.rescan.notify_one();
    Saving::done()
}

async fn settings_save(
    State(state): State<Arc<AppState>>,
    Query(q): Query<Which>,
    headers: HeaderMap,
    Json(form): Json<settings::Form>,
) -> Response {
    let id = q.instance.unwrap_or_else(|| PRIMARY.to_owned());
    save_with(&state, &headers, |saved| {
        saved.with_form(&id, &form, &state.defaults)
    })
    .await
}

#[derive(Deserialize)]
struct NewInstance {
    #[serde(default)]
    name: String,
    #[serde(default)]
    database_url: String,
}

async fn instance_add(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(new): Json<NewInstance>,
) -> Response {
    // Short, unique enough, and safe in a file name and in an address.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let id = format!("n{:x}", nanos & 0xffff_ffff_ffff);
    save_with(&state, &headers, |saved| {
        saved.with_instance(&id, &new.name, &new.database_url, &state.defaults)
    })
    .await
}

async fn instance_remove(
    State(state): State<Arc<AppState>>,
    Query(q): Query<Which>,
    headers: HeaderMap,
) -> Response {
    let id = q.instance.unwrap_or_default();
    save_with(&state, &headers, |saved| saved.without_instance(&id)).await
}

#[derive(Deserialize)]
struct Decision {
    key: String,
    #[serde(default)]
    note: String,
}

async fn accept(
    State(state): State<Arc<AppState>>,
    Query(q): Query<Which>,
    headers: HeaderMap,
    Json(decision): Json<Decision>,
) -> Response {
    let (_, instance) = state.pick(q.instance.as_deref()).await;
    // Only something the latest scan actually found can be accepted.
    let known = state
        .runtime(&instance.id)
        .await
        .latest
        .read()
        .await
        .as_ref()
        .is_some_and(|scan| scan.findings.iter().any(|f| f.key() == decision.key));
    if !known {
        return Saving::refused(StatusCode::NOT_FOUND, Vec::new(), None);
    }
    let now = now();
    save_with(&state, &headers, |saved| {
        let mut next = saved.clone();
        next.accept(&instance.id, &decision.key, &decision.note, now);
        Ok(next)
    })
    .await
}

async fn unaccept(
    State(state): State<Arc<AppState>>,
    Query(q): Query<Which>,
    headers: HeaderMap,
    Json(decision): Json<Decision>,
) -> Response {
    let id = q.instance.unwrap_or_else(|| PRIMARY.to_owned());
    save_with(&state, &headers, |saved| {
        let mut next = saved.clone();
        next.unaccept(&id, &decision.key);
        Ok(next)
    })
    .await
}

/// Asks for a scan now instead of at the next interval.
async fn rescan(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !headers.contains_key(WRITE_HEADER) {
        return Saving::refused(StatusCode::FORBIDDEN, Vec::new(), None);
    }
    state.rescan.notify_one();
    Saving::done()
}

async fn require_login(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let Some(password) = state.password.as_deref() else {
        return next.run(request).await;
    };
    if credentials_match(request.headers(), &state.user, password) {
        return next.run(request).await;
    }
    (
        StatusCode::UNAUTHORIZED,
        [(
            header::WWW_AUTHENTICATE,
            r#"Basic realm="nbuddyn", charset="UTF-8""#,
        )],
        "401",
    )
        .into_response()
}

fn credentials_match(headers: &HeaderMap, user: &str, password: &str) -> bool {
    let Some(encoded) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
    else {
        return false;
    };
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) else {
        return false;
    };
    let expected = format!("{user}:{password}");
    constant_time_eq(&decoded, expected.as_bytes())
}

/// Compares without leaking, through timing, how many leading bytes matched.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basic(user: &str, pass: &str) -> HeaderMap {
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Basic {token}").parse().unwrap(),
        );
        headers
    }

    fn finding(check: &'static str, severity: Severity, workflow: &str) -> Finding {
        Finding {
            check,
            severity,
            workflow: Some(workflow.into()),
            node: None,
            detail: None,
            active: Some(true),
            workflow_id: None,
            subject: None,
        }
    }

    fn scan_of(_score: u32, findings: Vec<Finding>) -> Scan {
        Scan {
            generated_at: 1,
            inventory: Inventory::default(),
            findings,
            cluster: None,
            runners: Vec::new(),
        }
    }

    #[test]
    fn login_accepts_only_the_exact_user_and_password() {
        assert!(credentials_match(
            &basic("nbuddyn", "s3cret"),
            "nbuddyn",
            "s3cret"
        ));
        assert!(!credentials_match(
            &basic("nbuddyn", "s3cre"),
            "nbuddyn",
            "s3cret"
        ));
        assert!(!credentials_match(
            &basic("admin", "s3cret"),
            "nbuddyn",
            "s3cret"
        ));
        assert!(!credentials_match(&HeaderMap::new(), "nbuddyn", "s3cret"));
    }

    #[test]
    fn report_before_the_first_scan_says_it_is_unavailable() {
        let report = build_report(Lang::Es, None, Some("connection refused".into()), None);
        assert!(!report.available);
        assert_eq!(report.lang, "es");
        assert_eq!(report.error.as_deref(), Some("connection refused"));
        assert!(report.groups.is_empty());
    }

    #[test]
    fn findings_of_one_kind_are_reported_as_one_group() {
        let scan = scan_of(
            53,
            vec![
                finding("open_ai_entry", Severity::High, "a"),
                finding("open_ai_entry", Severity::High, "b"),
                finding("repeated_failures", Severity::High, "c"),
                finding("no_error_workflow", Severity::Medium, "a"),
            ],
        );
        let report = build_report(Lang::Es, Some(scan), None, None);

        let summary: Vec<(&str, usize)> =
            report.groups.iter().map(|g| (g.check, g.count)).collect();
        assert_eq!(
            summary,
            vec![
                ("open_ai_entry", 2),
                ("repeated_failures", 1),
                ("no_error_workflow", 1)
            ]
        );
        assert_eq!(
            report.groups[0].title,
            "2 servidores MCP o chats sin autenticación"
        );
        assert_eq!(report.groups[0].items[1].workflow.as_deref(), Some("b"));
        assert_eq!((report.totals.urgent, report.totals.important), (3, 1));
        assert_eq!(
            report.headline,
            "Tu n8n vuela, pero con 3 luces rojas encendidas."
        );
        assert_eq!(
            report.lead,
            "Lo más urgente: 2 servidores MCP o chats sin autenticación y un workflow falla una y otra vez."
        );
    }

    #[test]
    fn lights_show_the_worst_level_of_their_area() {
        let scan = scan_of(
            70,
            vec![
                finding("open_ai_entry", Severity::High, "a"),
                finding("public_entry_no_auth", Severity::Medium, "a"),
                finding("no_error_workflow", Severity::Medium, "a"),
            ],
        );
        let report = build_report(Lang::En, Some(scan), None, None);
        let lights: Vec<(&str, usize, &str)> = report
            .lights
            .iter()
            .map(|l| (l.key, l.count, l.level))
            .collect();
        assert_eq!(
            lights,
            vec![
                ("doors", 2, "high"),
                ("failures", 0, "ok"),
                ("silent", 1, "medium"),
                ("secrets", 0, "ok")
            ]
        );
    }

    #[test]
    fn cluster_adds_its_view_and_the_queue_light() {
        use crate::cluster::{Member, Queue, RedisHealth};
        let member = |kind: &str| Member {
            kind: kind.into(),
            host_id: String::new(),
            version: "3.3.0".into(),
        };
        let mut scan = scan_of(
            90,
            vec![Finding {
                check: "redis_eviction",
                severity: Severity::Medium,
                workflow: None,
                node: None,
                detail: Some("allkeys-lru".into()),
                active: None,
                workflow_id: None,
                subject: None,
            }],
        );
        scan.cluster = Some(Cluster {
            queue: Queue {
                waiting: 4,
                active: 2,
                delayed: 0,
                failed: 0,
            },
            redis: RedisHealth {
                used_memory: 6_651_904,
                max_memory: 943_718_400,
                eviction_policy: "allkeys-lru".into(),
                evicted_keys: 0,
            },
            members: vec![
                member("main"),
                member("worker"),
                member("worker"),
                member("webhook"),
            ],
        });
        let report = build_report(Lang::Es, Some(scan), None, None);

        let view = report.cluster.as_ref().expect("cluster view");
        assert_eq!((view.waiting, view.active), (4, 2));
        assert_eq!((view.main, view.workers, view.webhooks), (1, 2, 1));
        assert_eq!((view.redis_used_mb, view.redis_max_mb), (6, 900));
        assert_eq!(view.versions, vec!["3.3.0"]);
        let queue = report.lights.last().expect("queue light");
        assert_eq!(
            (queue.key, queue.count, queue.level),
            ("queue", 1, "medium")
        );
        assert_eq!(
            report.groups[0].title,
            "Redis puede descartar trabajos de la cola"
        );
    }

    #[test]
    fn without_redis_there_is_no_queue_light_and_a_failed_read_is_reported() {
        let report = build_report(
            Lang::En,
            Some(scan_of(100, vec![])),
            None,
            Some("cannot connect".into()),
        );
        assert!(report.cluster.is_none());
        assert!(report.lights.iter().all(|l| l.key != "queue"));
        assert_eq!(report.cluster_error.as_deref(), Some("cannot connect"));
    }

    #[test]
    fn runners_add_their_count_and_their_light() {
        let mut scan = scan_of(
            80,
            vec![Finding {
                check: "runner_down",
                severity: Severity::High,
                workflow: None,
                node: None,
                detail: Some("n8n_runner-02 · cannot connect".into()),
                active: None,
                workflow_id: None,
                subject: None,
            }],
        );
        scan.runners = vec![
            RunnerProbe {
                name: "n8n_runner-01".into(),
                problem: None,
            },
            RunnerProbe {
                name: "n8n_runner-02".into(),
                problem: Some("cannot connect".into()),
            },
        ];
        let report = build_report(Lang::Es, Some(scan), None, None);

        let view = report.runners.as_ref().expect("runners view");
        assert_eq!((view.alive, view.total), (1, 2));
        let light = report.lights.last().expect("runners light");
        assert_eq!(
            (light.key, light.count, light.level),
            ("runners", 1, "high")
        );
        assert_eq!(report.groups[0].title, "Un runner no responde");

        let none = build_report(Lang::Es, Some(scan_of(100, vec![])), None, None);
        assert!(none.runners.is_none());
        assert!(none.lights.iter().all(|l| l.key != "runners"));
    }

    #[test]
    fn zone_follows_the_score() {
        let zone = zone_of;
        assert_eq!(
            (zone(53), zone(59), zone(60), zone(84), zone(85), zone(100)),
            ("risk", "risk", "caution", "caution", "ok", "ok")
        );
    }

    #[test]
    fn an_accepted_finding_leaves_the_score_and_is_listed_apart() {
        let mut door = finding("public_entry_no_auth", Severity::Medium, "Formulario");
        door.workflow_id = Some("abc123".into());
        door.node = Some("Webhook".into());
        let failing = finding("repeated_failures", Severity::High, "Stock");
        let scan = scan_of(0, vec![failing.clone(), door.clone()]);

        let before = build_report(Lang::Es, Some(scan.clone()), None, None);
        assert_eq!(before.totals.important, 1);
        assert_eq!(
            before.groups[1].items[0].path.as_deref(),
            Some("/workflow/abc123")
        );
        assert!(before.accepted.is_empty());

        let mut extras = Extras {
            n8n_url: "https://n8n.example.com".into(),
            ..Extras::default()
        };
        extras.accepted.push(Accepted {
            key: door.key(),
            note: "público a propósito".into(),
            at: 99,
        });
        let after = compose_report(Lang::Es, Some(scan), None, None, &extras);

        assert_eq!(after.totals.important, 0);
        assert!(after.score > before.score);
        assert_eq!(after.score, crate::radar::score(&[failing]));
        assert!(after
            .lights
            .iter()
            .all(|l| l.key != "doors" || l.level == "ok"));
        assert_eq!(after.groups.len(), 1);
        let accepted = &after.accepted[0];
        assert_eq!(accepted.title, "Un webhook o formulario sin autenticación");
        assert_eq!(
            (accepted.note.as_str(), accepted.at),
            ("público a propósito", 99)
        );
        assert_eq!(accepted.item.workflow.as_deref(), Some("Formulario"));
        assert_eq!(after.n8n_url, "https://n8n.example.com");
    }

    #[test]
    fn report_serializes_what_the_page_reads() {
        let scan = scan_of(92, vec![finding("repeated_failures", Severity::High, "wf")]);
        let json = serde_json::to_value(build_report(Lang::Pt, Some(scan), None, None)).unwrap();
        assert_eq!(json["groups"][0]["check"], "repeated_failures");
        assert_eq!(json["groups"][0]["severity"], "high");
        assert_eq!(
            json["groups"][0]["title"],
            "Um workflow falha repetidamente"
        );
        assert_eq!(json["zone"], "ok");
        assert_eq!(json["lights"][1]["level"], "high");
        assert_eq!(json["ui"]["zone_risk"], "Zona de risco");
    }
}
