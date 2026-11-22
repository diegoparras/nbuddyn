//! The radar: turns a snapshot of the instance into a list of findings.
//! Pure functions over data, so every check is testable without a database.

use std::collections::HashSet;
use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;

use crate::model::{Node, Snapshot, Workflow};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    /// The most one kind of problem at this severity can take off the score,
    /// as a fraction of what is left.
    fn max_cost(self) -> f64 {
        match self {
            Severity::High => 0.20,
            Severity::Medium => 0.08,
            Severity::Low => 0.03,
            Severity::Info => 0.0,
        }
    }
}

/// One thing the owner of the instance should know about.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Stable identifier of the check; also the translation key.
    pub check: &'static str,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// Extra context. Never contains a secret value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
}

const PUBLIC_ENTRY_TYPES: &[(&str, &str, Severity)] = &[
    ("@n8n/n8n-nodes-langchain.mcpTrigger", "MCP", Severity::High),
    (
        "@n8n/n8n-nodes-langchain.chatTrigger",
        "chat",
        Severity::High,
    ),
    ("n8n-nodes-base.webhook", "webhook", Severity::Medium),
    ("n8n-nodes-base.formTrigger", "form", Severity::Medium),
];

/// Node types removed in n8n 3.0 (partial list, base nodes only).
const REMOVED_IN_V3: &[&str] = &[
    "n8n-nodes-base.function",
    "n8n-nodes-base.functionItem",
    "n8n-nodes-base.itemLists",
    "n8n-nodes-base.cron",
    "n8n-nodes-base.interval",
    "n8n-nodes-base.htmlExtract",
    "n8n-nodes-base.iCal",
    "n8n-nodes-base.moveBinaryData",
    "n8n-nodes-base.readBinaryFile",
    "n8n-nodes-base.readBinaryFiles",
    "n8n-nodes-base.writeBinaryFile",
    "n8n-nodes-base.readPDF",
    "n8n-nodes-base.workflowTrigger",
    "n8n-nodes-base.orbit",
];

static SECRET_PATTERNS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    let re = |p: &str| Regex::new(p).expect("valid secret pattern");
    vec![
        ("sk- key", re(r"sk-[A-Za-z0-9_-]{20,}")),
        ("AWS access key", re(r"AKIA[0-9A-Z]{16}")),
        ("Slack token", re(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
        ("GitHub token", re(r"gh[pousr]_[A-Za-z0-9]{30,}")),
        ("Google API key", re(r"AIza[0-9A-Za-z_-]{30,}")),
        ("JWT", re(r"eyJ[A-Za-z0-9_-]{15,}\.eyJ[A-Za-z0-9_-]{15,}")),
        ("Bearer token", re(r"(?i)Bearer +[A-Za-z0-9._-]{24,}")),
        (
            "named secret field",
            re(
                r#"(?i)"(password|passwd|secret|api[_-]?key|apikey|access[_-]?token)" *: *"[^"=${}]{12,}""#,
            ),
        ),
    ]
});

static JS_COMMANDS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)child_process|execSync|spawnSync|\.exec\(").expect("valid"));
static PY_COMMANDS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)subprocess|os\.system|os\.popen").expect("valid"));
static INTERNAL_HOST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)^=?http://(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|[a-z0-9_-]+(:[0-9]+)?(/|$))",
    )
    .expect("valid")
});

/// Runs every check and returns findings ordered by severity.
pub fn scan(snapshot: &Snapshot) -> Vec<Finding> {
    let mut findings = Vec::new();

    for wf in snapshot.workflows.iter().filter(|w| !w.archived) {
        if wf.active && !wf.has_error_workflow {
            findings.push(on_workflow("no_error_workflow", Severity::Medium, wf));
        }
        for node in wf.nodes.iter().filter(|n| !n.disabled) {
            check_node(wf, node, &mut findings);
        }
    }

    for e in snapshot
        .error_counts
        .iter()
        .filter(|e| e.errors >= REPEATED_FAILURE_THRESHOLD)
    {
        findings.push(Finding {
            check: "repeated_failures",
            severity: Severity::High,
            workflow: Some(e.workflow.clone()),
            node: None,
            detail: Some(format!("{} · {}", e.errors, e.last)),
            active: None,
        });
    }

    for s in &snapshot.stuck {
        findings.push(Finding {
            check: "stuck_execution",
            severity: Severity::High,
            workflow: Some(s.workflow.clone()),
            node: None,
            detail: Some(format!("#{} · {} · {}", s.id, s.status, s.since)),
            active: None,
        });
    }

    let used: HashSet<&str> = snapshot
        .workflows
        .iter()
        .flat_map(|w| w.nodes.iter())
        .flat_map(|n| n.credential_ids.iter().map(String::as_str))
        .collect();
    for c in snapshot
        .credentials
        .iter()
        .filter(|c| !used.contains(c.id.as_str()))
    {
        findings.push(Finding {
            check: "unused_credential",
            severity: Severity::Low,
            workflow: None,
            node: None,
            detail: Some(format!("{} ({})", c.name, c.kind)),
            active: None,
        });
    }

    if snapshot.users_without_mfa > 0 {
        findings.push(Finding {
            check: "no_mfa",
            severity: Severity::Medium,
            workflow: None,
            node: None,
            detail: Some(format!(
                "{}/{}",
                snapshot.users_without_mfa, snapshot.users_total
            )),
            active: None,
        });
    }

    findings.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then_with(|| b.active.cmp(&a.active))
            .then_with(|| a.check.cmp(b.check))
            .then_with(|| a.workflow.cmp(&b.workflow))
    });
    findings
}

/// A workflow needs this many errors in the window to count as failing repeatedly.
const REPEATED_FAILURE_THRESHOLD: i64 = 5;

fn check_node(wf: &Workflow, node: &Node, out: &mut Vec<Finding>) {
    let params_text = node.params.to_string();

    // Public entry points only matter while the workflow is live.
    if wf.active {
        if let Some((_, label, severity)) = PUBLIC_ENTRY_TYPES
            .iter()
            .find(|(t, _, _)| *t == node.node_type)
        {
            let auth = node.param_str("authentication");
            let is_chat = *label == "chat";
            let chat_is_public = node
                .params
                .get("public")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            if (auth.is_empty() || auth == "none") && (!is_chat || chat_is_public) {
                let path = node.param_str("path");
                let detail = if path.is_empty() {
                    (*label).to_owned()
                } else {
                    format!("{label} · /{path}")
                };
                // AI entry points hand tools and data to whoever calls, so they
                // are reported apart from ordinary webhooks and forms.
                let check = if *severity == Severity::High {
                    "open_ai_entry"
                } else {
                    "public_entry_no_auth"
                };
                out.push(on_node(check, *severity, wf, node, Some(detail)));
            }
        }
    }

    if let Some((kind, _)) = SECRET_PATTERNS
        .iter()
        .find(|(_, re)| re.is_match(&params_text))
    {
        let severity = if wf.active {
            Severity::High
        } else {
            Severity::Medium
        };
        out.push(on_node(
            "hardcoded_secret",
            severity,
            wf,
            node,
            Some((*kind).to_owned()),
        ));
    }

    let runs_commands = matches!(
        node.node_type.as_str(),
        "n8n-nodes-base.executeCommand" | "n8n-nodes-base.ssh"
    ) || JS_COMMANDS.is_match(node.param_str("jsCode"))
        || PY_COMMANDS.is_match(node.param_str("pythonCode"));
    if runs_commands {
        out.push(on_node("command_execution", Severity::Info, wf, node, None));
    }

    if REMOVED_IN_V3.contains(&node.node_type.as_str()) {
        let severity = if wf.active {
            Severity::Medium
        } else {
            Severity::Low
        };
        let short = node
            .node_type
            .trim_start_matches("n8n-nodes-base.")
            .to_owned();
        out.push(on_node("removed_node_v3", severity, wf, node, Some(short)));
    }

    if params_text.contains("$env") || params_text.contains("process.env") {
        out.push(on_node("env_access", Severity::Low, wf, node, None));
    }

    let url = node.param_str("url");
    let plain = url
        .trim_start_matches('=')
        .to_ascii_lowercase()
        .starts_with("http://");
    if plain && !INTERNAL_HOST.is_match(url) {
        let shown: String = url.chars().take(60).collect();
        out.push(on_node(
            "plaintext_http",
            Severity::Medium,
            wf,
            node,
            Some(shown),
        ));
    }
}

fn on_workflow(check: &'static str, severity: Severity, wf: &Workflow) -> Finding {
    Finding {
        check,
        severity,
        workflow: Some(wf.name.clone()),
        node: None,
        detail: None,
        active: Some(wf.active),
    }
}

fn on_node(
    check: &'static str,
    severity: Severity,
    wf: &Workflow,
    node: &Node,
    detail: Option<String>,
) -> Finding {
    Finding {
        check,
        severity,
        workflow: Some(wf.name.clone()),
        node: Some(node.name.clone()),
        detail,
        active: Some(wf.active),
    }
}

/// 100 means nothing to report.
///
/// Findings are grouped by check and severity. Each group removes a share of
/// the remaining score: the first finding costs the most and every further one
/// of the same kind costs less, so twelve workflows with the same gap weigh
/// about as much as five. Shares multiply, so the score falls with every new
/// kind of problem but never collapses to zero.
pub fn score(findings: &[Finding]) -> u32 {
    /// How much of a group's cost is still unspent after each finding.
    const REPEAT_DECAY: f64 = 0.6;

    let mut groups: Vec<(&str, Severity, i32)> = Vec::new();
    for f in findings {
        match groups
            .iter_mut()
            .find(|(c, s, _)| *c == f.check && *s == f.severity)
        {
            Some(group) => group.2 += 1,
            None => groups.push((f.check, f.severity, 1)),
        }
    }

    let remaining: f64 = groups
        .iter()
        .map(|(_, severity, count)| 1.0 - severity.max_cost() * (1.0 - REPEAT_DECAY.powi(*count)))
        .product();
    (100.0 * remaining).round() as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Credential, ErrorCount};

    fn wf(name: &str, active: bool, nodes: &str, settings: Option<&str>) -> Workflow {
        Workflow::from_raw(name.into(), active, false, nodes, settings)
    }

    fn checks(findings: &[Finding]) -> Vec<&'static str> {
        findings.iter().map(|f| f.check).collect()
    }

    fn snapshot_of(workflows: Vec<Workflow>) -> Snapshot {
        Snapshot {
            workflows,
            ..Snapshot::default()
        }
    }

    #[test]
    fn open_webhook_and_mcp_are_flagged_only_when_active_and_unauthenticated() {
        let open = r#"[{"name":"W","type":"n8n-nodes-base.webhook","parameters":{"path":"in"}},
                       {"name":"M","type":"@n8n/n8n-nodes-langchain.mcpTrigger","parameters":{"path":"m"}}]"#;
        let guarded = r#"[{"name":"W","type":"n8n-nodes-base.webhook","parameters":{"path":"in","authentication":"headerAuth"}}]"#;
        let err = Some(r#"{"errorWorkflow":"x"}"#);

        let active = scan(&snapshot_of(vec![wf("a", true, open, err)]));
        assert_eq!(
            checks(&active),
            vec!["open_ai_entry", "public_entry_no_auth"]
        );
        assert_eq!(
            active[0].severity,
            Severity::High,
            "MCP outranks a plain webhook"
        );
        assert_eq!(active[0].detail.as_deref(), Some("MCP · /m"));

        assert!(scan(&snapshot_of(vec![wf("a", false, open, err)])).is_empty());
        assert!(scan(&snapshot_of(vec![wf("a", true, guarded, err)])).is_empty());
    }

    #[test]
    fn secrets_are_reported_by_kind_and_never_by_value() {
        let nodes = r#"[{"name":"Call","type":"n8n-nodes-base.httpRequest",
            "parameters":{"headers":"Bearer abcdefghijklmnopqrstuvwxyz123456"}}]"#;
        let found = scan(&snapshot_of(vec![wf("a", false, nodes, None)]));
        assert_eq!(checks(&found), vec!["hardcoded_secret"]);
        assert_eq!(found[0].detail.as_deref(), Some("Bearer token"));
        assert!(!serde_json::to_string(&found)
            .unwrap()
            .contains("abcdefghijklmnop"));
    }

    #[test]
    fn expressions_and_credential_references_are_not_secrets() {
        let nodes = r#"[{"name":"Call","type":"n8n-nodes-base.httpRequest",
            "parameters":{"apiKey":"={{ $json.key }}","url":"https://example.com"},
            "credentials":{"openAiApi":{"id":"c1","name":"OpenAI"}}}]"#;
        assert!(scan(&snapshot_of(vec![wf("a", false, nodes, None)])).is_empty());
    }

    #[test]
    fn disabled_nodes_are_ignored() {
        let nodes = r#"[{"name":"Py","type":"n8n-nodes-base.code","disabled":true,
            "parameters":{"pythonCode":"import subprocess"}}]"#;
        assert!(scan(&snapshot_of(vec![wf("a", false, nodes, None)])).is_empty());
    }

    #[test]
    fn code_commands_removed_nodes_env_and_plain_http_are_detected() {
        let nodes = r#"[
            {"name":"Code","type":"n8n-nodes-base.code","parameters":{"jsCode":"require('child_process').execSync('ls'); $env.X"}},
            {"name":"Old","type":"n8n-nodes-base.itemLists","parameters":{}},
            {"name":"Ext","type":"n8n-nodes-base.httpRequest","parameters":{"url":"http://api.example.com/x"}},
            {"name":"Int","type":"n8n-nodes-base.httpRequest","parameters":{"url":"http://n8n_main:5678/healthz"}}]"#;
        let found = scan(&snapshot_of(vec![wf("a", false, nodes, None)]));
        let mut got = checks(&found);
        got.sort_unstable();
        assert_eq!(
            got,
            vec![
                "command_execution",
                "env_access",
                "plaintext_http",
                "removed_node_v3"
            ]
        );
        let http = found.iter().find(|f| f.check == "plaintext_http").unwrap();
        assert_eq!(
            http.node.as_deref(),
            Some("Ext"),
            "internal hosts are not external plaintext"
        );
    }

    #[test]
    fn active_workflow_without_error_workflow_is_flagged() {
        let found = scan(&snapshot_of(vec![
            wf("live", true, "[]", Some(r#"{"executionOrder":"v1"}"#)),
            wf("covered", true, "[]", Some(r#"{"errorWorkflow":"w9"}"#)),
            wf("draft", false, "[]", None),
        ]));
        assert_eq!(checks(&found), vec!["no_error_workflow"]);
        assert_eq!(found[0].workflow.as_deref(), Some("live"));
    }

    #[test]
    fn instance_level_checks() {
        let nodes = r#"[{"name":"N","type":"n8n-nodes-base.set","parameters":{},
            "credentials":{"x":{"id":"used","name":"Used"}}}]"#;
        let snapshot = Snapshot {
            workflows: vec![wf("a", false, nodes, None)],
            credentials: vec![
                Credential {
                    id: "used".into(),
                    name: "Used".into(),
                    kind: "x".into(),
                },
                Credential {
                    id: "idle".into(),
                    name: "Idle".into(),
                    kind: "smtp".into(),
                },
            ],
            error_counts: vec![
                ErrorCount {
                    workflow: "noisy".into(),
                    errors: 1008,
                    last: "2026-11-22 02:55".into(),
                },
                ErrorCount {
                    workflow: "blip".into(),
                    errors: 2,
                    last: "2026-11-21 20:46".into(),
                },
            ],
            users_total: 1,
            users_without_mfa: 1,
            ..Snapshot::default()
        };
        let found = scan(&snapshot);
        assert_eq!(
            checks(&found),
            vec!["repeated_failures", "no_mfa", "unused_credential"]
        );
        assert_eq!(found[0].workflow.as_deref(), Some("noisy"));
        assert_eq!(found[2].detail.as_deref(), Some("Idle (smtp)"));
    }

    fn repeated(check: &'static str, severity: Severity, count: usize) -> Vec<Finding> {
        (0..count)
            .map(|i| Finding {
                check,
                severity,
                workflow: Some(format!("w{i}")),
                node: None,
                detail: None,
                active: Some(true),
            })
            .collect()
    }

    #[test]
    fn score_is_full_with_nothing_to_report_and_ignores_informational_findings() {
        assert_eq!(score(&[]), 100);
        assert_eq!(
            score(&repeated("command_execution", Severity::Info, 21)),
            100
        );
    }

    #[test]
    fn more_of_the_same_problem_costs_less_each_time() {
        let one = score(&repeated("no_error_workflow", Severity::Medium, 1));
        let five = score(&repeated("no_error_workflow", Severity::Medium, 5));
        let twelve = score(&repeated("no_error_workflow", Severity::Medium, 12));
        assert_eq!((one, five, twelve), (97, 93, 92));
    }

    #[test]
    fn one_high_finding_weighs_more_than_many_low_ones() {
        let high = score(&repeated("repeated_failures", Severity::High, 1));
        let low = score(&repeated("unused_credential", Severity::Low, 10));
        assert_eq!((high, low), (92, 97));
    }

    #[test]
    fn a_troubled_instance_scores_low_but_never_zero() {
        // The mix found on a real instance: open MCP servers and webhooks, a workflow
        // failing a thousand times, no error workflows, no 2FA, some housekeeping.
        let mut findings = repeated("open_ai_entry", Severity::High, 5);
        findings.extend(repeated("public_entry_no_auth", Severity::Medium, 10));
        findings.extend(repeated("repeated_failures", Severity::High, 1));
        findings.extend(repeated("hardcoded_secret", Severity::Medium, 3));
        findings.extend(repeated("no_error_workflow", Severity::Medium, 12));
        findings.extend(repeated("no_mfa", Severity::Medium, 1));
        findings.extend(repeated("unused_credential", Severity::Low, 10));
        findings.extend(repeated("env_access", Severity::Low, 4));
        findings.extend(repeated("removed_node_v3", Severity::Low, 2));
        findings.extend(repeated("command_execution", Severity::Info, 21));
        let troubled = score(&findings);
        assert_eq!(troubled, 53);

        // Closing the open MCP servers is the single biggest improvement.
        let without_open_mcp: Vec<Finding> = findings
            .iter()
            .filter(|f| f.check != "open_ai_entry")
            .cloned()
            .collect();
        assert_eq!(score(&without_open_mcp), 66);

        let hopeless: Vec<Finding> = [
            "open_ai_entry",
            "repeated_failures",
            "stuck_execution",
            "hardcoded_secret",
        ]
        .into_iter()
        .flat_map(|check| repeated(check, Severity::High, 50))
        .collect();
        assert!(score(&hopeless) > 0);
    }
}
