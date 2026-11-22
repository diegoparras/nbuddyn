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

use crate::i18n::{check_text, ui_text, Lang, UiText};
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
    inventory: Inventory,
    counts: Counts,
    findings: Vec<LocalizedFinding>,
    ui: UiText,
}

#[derive(Default, Serialize)]
struct Counts {
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
}

#[derive(Serialize)]
struct LocalizedFinding {
    #[serde(flatten)]
    finding: Finding,
    title: &'static str,
    advice: &'static str,
}

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

    let mut counts = Counts::default();
    for f in &scan.findings {
        match f.severity {
            Severity::High => counts.high += 1,
            Severity::Medium => counts.medium += 1,
            Severity::Low => counts.low += 1,
            Severity::Info => counts.info += 1,
        }
    }

    let findings = scan
        .findings
        .into_iter()
        .map(|finding| {
            let text = check_text(lang, finding.check);
            LocalizedFinding {
                finding,
                title: text.title,
                advice: text.advice,
            }
        })
        .collect();

    Report {
        lang: lang.code(),
        available,
        error,
        generated_at: scan.generated_at,
        score: scan.score,
        inventory: scan.inventory,
        counts,
        findings,
        ui: ui_text(lang),
    }
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
        assert!(report.findings.is_empty());
    }

    #[test]
    fn report_localizes_findings_and_counts_by_severity() {
        let finding = |check, severity| Finding {
            check,
            severity,
            workflow: Some("wf".into()),
            node: None,
            detail: None,
            active: Some(true),
        };
        let scan = Scan {
            generated_at: 1,
            score: 80,
            inventory: Inventory::default(),
            findings: vec![
                finding("repeated_failures", Severity::High),
                finding("no_error_workflow", Severity::Medium),
                finding("no_error_workflow", Severity::Medium),
            ],
        };
        let report = build_report(Lang::Pt, Some(scan), None);
        assert!(report.available);
        assert_eq!(
            (report.counts.high, report.counts.medium, report.counts.low),
            (1, 2, 0)
        );
        assert_eq!(report.findings[0].title, "Workflow falhando repetidamente");

        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["findings"][0]["check"], "repeated_failures");
        assert_eq!(json["findings"][0]["severity"], "high");
    }
}
