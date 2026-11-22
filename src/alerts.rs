//! Tells people when something changes, where they already are: a Telegram
//! chat, or any address that takes a JSON POST (Slack, n8n itself, a pager).
//!
//! An alert is about what changed in one scan, never about the whole report:
//! findings that appeared at or above the chosen severity, the urgent ones
//! that went away, and an instance that stopped answering or came back.

use serde_json::json;

use crate::history::Event;
use crate::http;
use crate::i18n::{self, Lang};

/// Where alerts go and what is worth one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Alerts {
    /// Bot token and chat id.
    pub telegram: Option<(String, String)>,
    /// The Telegram API's address; only different in tests and for people
    /// who run their own Bot API server.
    pub telegram_api: String,
    pub webhook: Option<String>,
    /// The mildest severity that still alerts.
    pub level: Level,
    /// Whether workflow changes alert too.
    pub changes: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Level {
    /// Urgent findings only.
    #[default]
    High,
    /// Urgent and important findings.
    Medium,
}

impl Alerts {
    pub fn enabled(&self) -> bool {
        self.telegram.is_some() || self.webhook.is_some()
    }

    fn wants(&self, severity: Option<&str>) -> bool {
        matches!(
            (self.level, severity),
            (_, Some("high")) | (Level::Medium, Some("medium"))
        )
    }
}

/// The most lines of one kind a message lists before it says "and N more".
const LINES_MAX: usize = 8;

/// One message ready to send, as text and as data.
#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    pub text: String,
    pub data: serde_json::Value,
}

/// Writes the message for what one scan saw change, or `None` when nothing in
/// it is worth interrupting someone for.
pub fn compose(
    alerts: &Alerts,
    lang: Lang,
    instance: &str,
    n8n_url: &str,
    events: &[Event],
    score: u32,
) -> Option<Message> {
    let new: Vec<&Event> = events
        .iter()
        .filter(|e| e.kind == "finding_new" && alerts.wants(e.severity.as_deref()))
        .collect();
    let resolved: Vec<&Event> = events
        .iter()
        .filter(|e| e.kind == "finding_resolved" && alerts.wants(e.severity.as_deref()))
        .collect();
    let changed: Vec<&Event> = events
        .iter()
        .filter(|e| alerts.changes && e.kind.starts_with("workflow_"))
        .collect();
    if new.is_empty() && resolved.is_empty() && changed.is_empty() {
        return None;
    }

    let line = |e: &Event| {
        let what = match &e.check {
            Some(check) => i18n::group_title(lang, check, 1),
            None => i18n::event_label(lang, &e.kind).to_owned(),
        };
        let place = [e.workflow.as_deref(), e.node.as_deref()]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" › ");
        let link = match (&e.path, n8n_url.is_empty()) {
            (Some(path), false) => format!("\n   {n8n_url}{path}"),
            _ => String::new(),
        };
        let by = e
            .author
            .as_ref()
            .map(|a| format!(" ({a})"))
            .unwrap_or_default();
        if place.is_empty() {
            format!("• {what}{by}{link}")
        } else {
            format!("• {what} — {place}{by}{link}")
        }
    };
    let section = |heading: String, items: &[&Event], text: &mut String| {
        if items.is_empty() {
            return;
        }
        text.push_str(&format!("\n\n{heading}"));
        for item in items.iter().take(LINES_MAX) {
            text.push('\n');
            text.push_str(&line(item));
        }
        if items.len() > LINES_MAX {
            text.push_str(&format!(
                "\n{}",
                i18n::alert_more(lang, items.len() - LINES_MAX)
            ));
        }
    };

    let urgent = new.iter().any(|e| e.severity.as_deref() == Some("high"));
    let mark = if urgent {
        "🔴"
    } else if !new.is_empty() {
        "🟠"
    } else if !resolved.is_empty() {
        "🟢"
    } else {
        "✏️"
    };
    let mut text = format!("{mark} nbuddyn · {instance}");
    section(i18n::alert_new(lang, new.len()), &new, &mut text);
    section(
        i18n::alert_resolved(lang, resolved.len()),
        &resolved,
        &mut text,
    );
    section(
        i18n::alert_changes(lang, changed.len()),
        &changed,
        &mut text,
    );
    text.push_str(&format!("\n\n{}: {score}/100", i18n::alert_score(lang)));

    Some(Message {
        data: json!({
            "instance": instance,
            "score": score,
            "new": new,
            "resolved": resolved,
            "changes": changed,
        }),
        text,
    })
}

/// The message for an instance that stopped answering, or answers again.
pub fn compose_reachability(lang: Lang, instance: &str, problem: Option<&str>) -> Message {
    let text = match problem {
        Some(reason) => format!(
            "⚠️ nbuddyn · {instance}\n\n{}\n{reason}",
            i18n::alert_unreachable(lang)
        ),
        None => format!("🟢 nbuddyn · {instance}\n\n{}", i18n::alert_back(lang)),
    };
    Message {
        data: json!({ "instance": instance, "reachable": problem.is_none(), "reason": problem }),
        text,
    }
}

/// The message the "send a test" button sends.
pub fn compose_test(lang: Lang) -> Message {
    Message {
        text: format!("🛫 nbuddyn\n\n{}", i18n::alert_test(lang)),
        data: json!({ "test": true }),
    }
}

/// Sends a message everywhere alerts go. Returns what went wrong, one line
/// per destination that did not take it; empty means all of them did.
pub async fn deliver(alerts: &Alerts, message: &Message) -> Vec<String> {
    let mut problems = Vec::new();
    if let Some((token, chat)) = &alerts.telegram {
        let url = format!("{}/bot{token}/sendMessage", alerts.telegram_api);
        let body = json!({
            "chat_id": chat,
            "text": message.text,
            "disable_web_page_preview": true,
        });
        match http::post_json(&url, &body.to_string()).await {
            Ok(answer) if answer.status == 200 => {}
            // Telegram explains itself in the body; the address is never
            // repeated, because the token is part of it.
            Ok(answer) => problems.push(format!(
                "Telegram: {} {}",
                answer.status,
                telegram_reason(&answer.body)
            )),
            Err(reason) => problems.push(format!("Telegram: {reason}")),
        }
    }
    if let Some(url) = &alerts.webhook {
        let mut body = message.data.clone();
        // `text` is what Slack and most chat tools show.
        if let Some(fields) = body.as_object_mut() {
            fields.insert("text".into(), json!(message.text));
        }
        match http::post_json(url, &body.to_string()).await {
            Ok(answer) if (200..300).contains(&answer.status) => {}
            Ok(answer) => problems.push(format!("webhook: {}", answer.status)),
            Err(reason) => problems.push(format!("webhook: {reason}")),
        }
    }
    problems
}

fn telegram_reason(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.get("description")
                .and_then(|d| d.as_str())
                .map(str::to_owned)
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(kind: &str, severity: Option<&str>, check: Option<&str>, workflow: &str) -> Event {
        Event {
            at: 1,
            kind: kind.into(),
            check: check.map(str::to_owned),
            severity: severity.map(str::to_owned),
            workflow: Some(workflow.into()),
            path: Some("/workflow/w1".into()),
            ..Event::default()
        }
    }

    #[test]
    fn only_what_matters_at_the_chosen_level_makes_a_message() {
        let events = vec![
            event("finding_new", Some("high"), Some("open_ai_entry"), "Ventas"),
            event(
                "finding_new",
                Some("medium"),
                Some("no_error_workflow"),
                "Stock",
            ),
            event("finding_new", Some("low"), Some("env_access"), "Otro"),
            event("finding_resolved", Some("high"), Some("runner_down"), "x"),
            event("workflow_changed", None, None, "Ventas"),
        ];
        let urgent_only = Alerts::default();
        let message = compose(
            &urgent_only,
            Lang::Es,
            "Producción",
            "https://n8n.example.com",
            &events,
            48,
        )
        .unwrap();
        assert!(message.text.starts_with("🔴 nbuddyn · Producción"));
        assert!(message
            .text
            .contains("Un servidor MCP o chat sin autenticación — Ventas"));
        assert!(message.text.contains("https://n8n.example.com/workflow/w1"));
        assert!(!message.text.contains("Stock"));
        assert!(!message.text.contains("Workflow modificado"));
        assert!(message.text.ends_with("Puntaje: 48/100"));
        assert_eq!(message.data["new"].as_array().unwrap().len(), 1);
        assert_eq!(message.data["resolved"].as_array().unwrap().len(), 1);

        let wider = Alerts {
            level: Level::Medium,
            changes: true,
            ..Alerts::default()
        };
        let message = compose(&wider, Lang::En, "prod", "", &events, 48).unwrap();
        assert!(message.text.contains("Stock"));
        assert!(message.text.contains("Workflow edited — Ventas"));
        assert!(!message.text.contains("http"));
        assert!(!message.text.contains("Otro"));
    }

    #[test]
    fn nothing_worth_an_alert_makes_no_message() {
        let quiet = vec![
            event("finding_new", Some("low"), Some("env_access"), "Otro"),
            event("workflow_changed", None, None, "Ventas"),
        ];
        assert_eq!(
            compose(&Alerts::default(), Lang::Es, "n8n", "", &quiet, 90),
            None
        );
        assert_eq!(
            compose(&Alerts::default(), Lang::Es, "n8n", "", &[], 90),
            None
        );
    }

    #[test]
    fn long_lists_are_cut_with_a_count() {
        let many: Vec<Event> = (0..12)
            .map(|i| {
                event(
                    "finding_new",
                    Some("high"),
                    Some("runner_down"),
                    &format!("wf{i}"),
                )
            })
            .collect();
        let message = compose(&Alerts::default(), Lang::Es, "n8n", "", &many, 10).unwrap();
        assert_eq!(message.text.matches("• ").count(), LINES_MAX);
        assert!(message.text.contains("y 4 más"));
    }

    #[tokio::test]
    async fn telegram_and_the_webhook_both_get_the_message_and_failures_are_named() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let mut seen = Vec::new();
            for answer in [
                "HTTP/1.1 200 OK\r\n\r\n{\"ok\":true}",
                "HTTP/1.1 500 Internal Server Error\r\n\r\n",
            ] {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buffer = vec![0u8; 4096];
                let n = socket.read(&mut buffer).await.unwrap();
                seen.push(String::from_utf8_lossy(&buffer[..n]).into_owned());
                socket.write_all(answer.as_bytes()).await.unwrap();
            }
            seen
        });
        let alerts = Alerts {
            telegram: Some(("123:abc".into(), "-100".into())),
            telegram_api: format!("http://127.0.0.1:{port}"),
            webhook: Some(format!("http://127.0.0.1:{port}/hook")),
            ..Alerts::default()
        };
        let problems = deliver(&alerts, &compose_test(Lang::Es)).await;
        assert_eq!(problems, vec!["webhook: 500".to_owned()]);
        let seen = server.await.unwrap();
        assert!(seen[0].starts_with("POST /bot123:abc/sendMessage "));
        assert!(seen[0].contains("\"chat_id\":\"-100\""));
        assert!(seen[1].starts_with("POST /hook "));
        assert!(seen[1].contains("\"test\":true") && seen[1].contains("\"text\":"));
    }
}
