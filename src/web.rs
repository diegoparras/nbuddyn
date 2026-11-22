//! The web page and the JSON report behind it.

use std::sync::Arc;

use axum::extract::{Query, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::cluster::Cluster;
use crate::history::{self, History};
use crate::i18n::{self, ui_text, Lang, UiText};
use crate::radar::{Finding, Severity};
use crate::runners::RunnerProbe;

/// Result of the latest scan, kept in memory.
#[derive(Debug, Clone, Default)]
pub struct Scan {
    pub generated_at: u64,
    pub score: u32,
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
    pub default_lang: Lang,
    pub latest: RwLock<Option<Scan>>,
    pub last_error: RwLock<Option<String>>,
    /// Why Redis could not be read in the latest scan, if it could not.
    pub cluster_error: RwLock<Option<String>>,
    /// Whether nbuddyn was given a place to keep its own history.
    pub history_enabled: bool,
    pub history: RwLock<Option<Arc<History>>>,
    /// Why the history could not be updated in the latest scan, if it could not.
    pub history_error: RwLock<Option<String>>,
}

pub fn router(state: Arc<AppState>) -> Router {
    let protected = Router::new()
        .route("/", get(index))
        .route("/api/report", get(report))
        .route("/api/history", get(history_report))
        .layer(middleware::from_fn_with_state(state.clone(), require_login));

    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .merge(protected)
        .with_state(state)
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../assets/index.html"))
}

#[derive(Deserialize)]
struct ReportQuery {
    lang: Option<String>,
}

#[derive(Deserialize)]
struct HistoryQuery {
    days: Option<u32>,
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

/// Days shown when the page does not ask for a span.
const DEFAULT_SPAN: u32 = 30;
/// The longest span one request can ask for.
const MAX_SPAN: u32 = 366;

async fn history_report(
    State(state): State<Arc<AppState>>,
    Query(q): Query<HistoryQuery>,
) -> Json<HistoryReport> {
    let span = q.days.unwrap_or(DEFAULT_SPAN).clamp(1, MAX_SPAN);
    let history = state.history.read().await.clone();
    Json(HistoryReport {
        enabled: state.history_enabled,
        error: state.history_error.read().await.clone(),
        view: history.map(|h| h.view(span)).unwrap_or_default(),
    })
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
        }
    }
}

#[derive(Serialize)]
struct RunnersView {
    alive: usize,
    total: usize,
}

/// One annunciator light: an area of the instance and how bad it looks.
#[derive(Serialize)]
struct Light {
    key: &'static str,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    workflow: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    node: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    active: Option<bool>,
}

/// Scores below this are in the risk zone of the gauge.
const RISK_BELOW: u32 = 60;
/// Scores below this, and not in the risk zone, call for caution.
const CAUTION_BELOW: u32 = 85;

const LIGHTS: &[(&str, &[&str])] = &[
    ("doors", &["open_ai_entry", "public_entry_no_auth"]),
    ("failures", &["repeated_failures", "stuck_execution"]),
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
    let lang = q
        .lang
        .as_deref()
        .map(Lang::parse)
        .unwrap_or(state.default_lang);
    let scan = state.latest.read().await.clone();
    let error = state.last_error.read().await.clone();
    let cluster_error = state.cluster_error.read().await.clone();
    Json(build_report(lang, scan, error, cluster_error))
}

fn build_report(
    lang: Lang,
    scan: Option<Scan>,
    error: Option<String>,
    cluster_error: Option<String>,
) -> Report {
    let available = scan.is_some();
    let scan = scan.unwrap_or_default();

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
                count: hits.len(),
                level,
            }
        })
        .collect();

    let runners = (!scan.runners.is_empty()).then(|| RunnersView {
        alive: scan.runners.iter().filter(|r| r.problem.is_none()).count(),
        total: scan.runners.len(),
    });

    let groups = group(lang, scan.findings);
    let urgent_titles: Vec<String> = groups
        .iter()
        .filter(|g| g.severity == Severity::High)
        .map(|g| g.title.clone())
        .collect();

    let zone = if scan.score < RISK_BELOW {
        "risk"
    } else if scan.score < CAUTION_BELOW {
        "caution"
    } else {
        "ok"
    };

    Report {
        lang: lang.code(),
        available,
        error,
        generated_at: scan.generated_at,
        score: scan.score,
        zone,
        headline: i18n::headline(lang, totals.urgent, totals.important + totals.minor),
        lead: i18n::lead(lang, &urgent_titles),
        lights,
        totals,
        inventory: scan.inventory,
        cluster,
        cluster_error,
        runners,
        groups,
        ui: ui_text(lang),
    }
}

/// Folds findings into groups by check and severity, keeping the radar's order.
fn group(lang: Lang, findings: Vec<Finding>) -> Vec<Group> {
    let mut groups: Vec<Group> = Vec::new();
    for f in findings {
        let item = Item {
            workflow: f.workflow,
            node: f.node,
            detail: f.detail,
            active: f.active,
        };
        match groups
            .iter_mut()
            .find(|g| g.check == f.check && g.severity == f.severity)
        {
            Some(existing) => existing.items.push(item),
            None => groups.push(Group {
                check: f.check,
                severity: f.severity,
                count: 0,
                title: String::new(),
                advice: i18n::advice(lang, f.check),
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
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
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
        }
    }

    fn scan_of(score: u32, findings: Vec<Finding>) -> Scan {
        Scan {
            generated_at: 1,
            score,
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
        let zone = |score| build_report(Lang::En, Some(scan_of(score, vec![])), None, None).zone;
        assert_eq!(
            (zone(53), zone(59), zone(60), zone(84), zone(85), zone(100)),
            ("risk", "risk", "caution", "caution", "ok", "ok")
        );
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
