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

use crate::i18n::{self, ui_text, Lang, UiText};
use crate::radar::{Finding, Severity};

/// Result of the latest scan, kept in memory.
#[derive(Debug, Clone, Default)]
pub struct Scan {
    pub generated_at: u64,
    pub score: u32,
    pub inventory: Inventory,
    pub findings: Vec<Finding>,
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
}

pub fn router(state: Arc<AppState>) -> Router {
    let protected = Router::new()
        .route("/", get(index))
        .route("/api/report", get(report))
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
    groups: Vec<Group>,
    ui: UiText,
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

async fn report(State(state): State<Arc<AppState>>, Query(q): Query<ReportQuery>) -> Json<Report> {
    let lang = q
        .lang
        .as_deref()
        .map(Lang::parse)
        .unwrap_or(state.default_lang);
    let scan = state.latest.read().await.clone();
    let error = state.last_error.read().await.clone();
    Json(build_report(lang, scan, error))
}

fn build_report(lang: Lang, scan: Option<Scan>, error: Option<String>) -> Report {
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

    let lights = LIGHTS
        .iter()
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
        let report = build_report(Lang::Es, None, Some("connection refused".into()));
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
        let report = build_report(Lang::Es, Some(scan), None);

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
        let report = build_report(Lang::En, Some(scan), None);
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
    fn zone_follows_the_score() {
        let zone = |score| build_report(Lang::En, Some(scan_of(score, vec![])), None).zone;
        assert_eq!(
            (zone(53), zone(59), zone(60), zone(84), zone(85), zone(100)),
            ("risk", "risk", "caution", "caution", "ok", "ok")
        );
    }

    #[test]
    fn report_serializes_what_the_page_reads() {
        let scan = scan_of(92, vec![finding("repeated_failures", Severity::High, "wf")]);
        let json = serde_json::to_value(build_report(Lang::Pt, Some(scan), None)).unwrap();
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
