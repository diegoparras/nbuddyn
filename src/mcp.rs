//! A read-only MCP endpoint, so an AI assistant can ask nbuddyn what it sees.
//!
//! It speaks the Model Context Protocol over plain HTTP: every request is one
//! JSON-RPC message in a POST and gets one JSON answer. It keeps no session,
//! offers five tools that only read what the page already shows, and is off
//! unless a token is configured.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

use crate::i18n::Lang;
use crate::web::{self, AppState};

/// Protocol revisions this endpoint answers, newest first.
const VERSIONS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];

const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;

pub async fn post(State(state): State<Arc<AppState>>, headers: HeaderMap, body: Bytes) -> Response {
    let Some(token) = state.mcp_token.as_deref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !token_matches(&headers, token) {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, r#"Bearer realm="nbuddyn""#)],
            "401",
        )
            .into_response();
    }

    let message: Value = match serde_json::from_slice(&body) {
        Ok(message) => message,
        Err(_) => return Json(failure(Value::Null, PARSE_ERROR, "not valid JSON")).into_response(),
    };
    let Some(method) = message.get("method").and_then(Value::as_str) else {
        // Batches and stray responses: nothing here ever asks the client anything.
        return Json(failure(
            Value::Null,
            INVALID_REQUEST,
            "expected one JSON-RPC request",
        ))
        .into_response();
    };
    let Some(id) = message.get("id").filter(|id| !id.is_null()).cloned() else {
        // A notification expects no answer.
        return StatusCode::ACCEPTED.into_response();
    };
    let params = message.get("params").cloned().unwrap_or(Value::Null);

    let answer = match method {
        "initialize" => Ok(initialize(&params)),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tools() })),
        "tools/call" => call(&state, &params).await,
        _ => Err((METHOD_NOT_FOUND, format!("unknown method {method}"))),
    };
    Json(match answer {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err((code, text)) => failure(id, code, &text),
    })
    .into_response()
}

/// The endpoint opens no stream of its own, so anything but POST is refused.
pub async fn other() -> Response {
    (StatusCode::METHOD_NOT_ALLOWED, [(header::ALLOW, "POST")]).into_response()
}

fn token_matches(headers: &HeaderMap, token: &str) -> bool {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|given| web::constant_time_eq(given.trim().as_bytes(), token.as_bytes()))
}

fn failure(id: Value, code: i64, text: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": text } })
}

fn initialize(params: &Value) -> Value {
    let asked = params.get("protocolVersion").and_then(Value::as_str);
    let version = VERSIONS
        .iter()
        .find(|v| Some(**v) == asked)
        .unwrap_or(&VERSIONS[0]);
    json!({
        "protocolVersion": version,
        "capabilities": { "tools": {} },
        "serverInfo": { "name": "nbuddyn", "version": env!("CARGO_PKG_VERSION") },
        "instructions": "nbuddyn watches one self-hosted n8n instance and only reads. \
            Start with get_status. Findings name workflows and nodes but never include \
            secrets or execution data. Nothing here can change n8n.",
    })
}

fn tools() -> Value {
    let lang = json!({
        "type": "string",
        "enum": ["en", "es", "pt"],
        "description": "Language of titles and advice. Defaults to the server's language.",
    });
    let read_only = json!({ "readOnlyHint": true, "openWorldHint": false });
    let instance = json!({
        "type": "string",
        "description": "Which n8n, by the id or name list_instances gives. Defaults to the first.",
    });
    json!([
        {
            "name": "list_instances",
            "title": "n8n instances",
            "description": "The n8n instances nbuddyn watches, each with its score and how many \
                urgent findings it has. Call it first when there may be more than one.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false },
            "annotations": read_only,
        },
        {
            "name": "get_status",
            "title": "n8n status",
            "description": "The current state of the n8n instance: a 0-100 score, how many \
                urgent, important and minor findings there are, the queue, workers, webhook \
                processors, task runners and Redis memory.",
            "inputSchema": {
                "type": "object",
                "properties": { "lang": lang, "instance": instance },
                "additionalProperties": false,
            },
            "annotations": read_only,
        },
        {
            "name": "list_findings",
            "title": "n8n findings",
            "description": "What nbuddyn found wrong or risky in the n8n instance, grouped by \
                kind, with the workflows and nodes involved and what to do about each.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "severity": {
                        "type": "string",
                        "enum": ["high", "medium", "low", "info"],
                        "description": "Only findings of this severity. Omit for all.",
                    },
                    "lang": lang,
                    "instance": instance,
                },
                "additionalProperties": false,
            },
            "annotations": read_only,
        },
        {
            "name": "get_activity",
            "title": "n8n activity",
            "description": "What changed lately in the n8n instance, newest first: findings that \
                appeared or were resolved, and workflows created, edited, renamed, activated, \
                deactivated or deleted, with who saved them when n8n records it.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "days": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": web::MAX_SPAN,
                        "description": "How many days back. Defaults to 7.",
                    },
                    "lang": lang,
                    "instance": instance,
                },
                "additionalProperties": false,
            },
            "annotations": read_only,
        },
        {
            "name": "get_history",
            "title": "n8n execution history",
            "description": "Executions per day and per workflow (succeeded, failed, canceled) \
                and the score of each day, from nbuddyn's own history, which keeps totals \
                after n8n deletes the executions.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "days": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": web::MAX_SPAN,
                        "description": "How many days back, ending today. Defaults to 30.",
                    },
                    "instance": instance,
                },
                "additionalProperties": false,
            },
            "annotations": read_only,
        },
    ])
}

async fn call(state: &AppState, params: &Value) -> Result<Value, (i64, String)> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or((INVALID_PARAMS, "missing tool name".to_owned()))?;
    let args = params.get("arguments").cloned().unwrap_or(Value::Null);
    let lang = args.get("lang").and_then(Value::as_str).map(Lang::parse);

    // An instance can be named by its id or by its name; none means the first.
    let wanted = args.get("instance").and_then(Value::as_str);
    let found = match wanted {
        None => None,
        Some(wanted) => Some(
            web::instance_id(state, wanted)
                .await
                .ok_or((INVALID_PARAMS, format!("no instance called {wanted}")))?,
        ),
    };
    let instance = found.as_deref();

    let answer = match name {
        "list_instances" => {
            let effective = state.effective().await;
            json!({ "instances": web::summaries(state, &effective).await })
        }
        "get_status" => status(web::current_report(state, lang, instance).await),
        "list_findings" => {
            let severity = args.get("severity").and_then(Value::as_str);
            findings(web::current_report(state, lang, instance).await, severity)
        }
        "get_activity" => {
            let days = args
                .get("days")
                .and_then(Value::as_u64)
                .and_then(|d| u32::try_from(d).ok());
            web::current_activity(state, lang, days, instance).await
        }
        "get_history" => {
            let days = args
                .get("days")
                .and_then(Value::as_u64)
                .and_then(|d| u32::try_from(d).ok());
            web::current_history(state, days, instance).await
        }
        _ => return Err((INVALID_PARAMS, format!("unknown tool {name}"))),
    };
    let failed = answer.get("available") == Some(&Value::Bool(false))
        || answer.get("enabled") == Some(&Value::Bool(false));
    Ok(json!({
        "content": [{ "type": "text", "text": answer.to_string() }],
        "isError": failed,
    }))
}

/// The report without the list of findings and without the page's labels.
fn status(mut report: Value) -> Value {
    // Before the first good scan the rest of the report is empty, and an empty
    // report reads like a clean one.
    if report.get("available") == Some(&Value::Bool(false)) {
        return json!({ "available": false, "error": report.get("error") });
    }
    if let Some(fields) = report.as_object_mut() {
        fields.remove("groups");
        fields.remove("ui");
        fields.remove("lang");
    }
    report
}

fn findings(mut report: Value, severity: Option<&str>) -> Value {
    let groups: Vec<Value> = report
        .get_mut("groups")
        .and_then(Value::as_array_mut)
        .map(std::mem::take)
        .unwrap_or_default()
        .into_iter()
        .filter(|g| severity.is_none_or(|s| g.get("severity").and_then(Value::as_str) == Some(s)))
        .collect();
    json!({
        "available": report.get("available"),
        "generated_at": report.get("generated_at"),
        "findings": groups,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_keeps_a_known_version_and_offers_the_newest_otherwise() {
        let known = initialize(&json!({ "protocolVersion": "2025-03-26" }));
        assert_eq!(known["protocolVersion"], "2025-03-26");
        let unknown = initialize(&json!({ "protocolVersion": "1999-01-01" }));
        assert_eq!(unknown["protocolVersion"], VERSIONS[0]);
        assert_eq!(unknown["serverInfo"]["name"], "nbuddyn");
    }

    #[test]
    fn every_tool_is_declared_read_only() {
        let tools = tools();
        let tools = tools.as_array().unwrap();
        assert_eq!(tools.len(), 5);
        for tool in tools {
            assert_eq!(
                tool["annotations"]["readOnlyHint"], true,
                "{}",
                tool["name"]
            );
            assert_eq!(tool["inputSchema"]["type"], "object");
        }
    }

    #[test]
    fn only_the_exact_bearer_token_is_accepted() {
        let with = |value: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(header::AUTHORIZATION, value.parse().unwrap());
            headers
        };
        assert!(token_matches(
            &with("Bearer a-long-secret-token"),
            "a-long-secret-token"
        ));
        assert!(!token_matches(
            &with("Bearer a-long-secret-toke"),
            "a-long-secret-token"
        ));
        assert!(!token_matches(
            &with("Basic a-long-secret-token"),
            "a-long-secret-token"
        ));
        assert!(!token_matches(&HeaderMap::new(), "a-long-secret-token"));
    }

    #[test]
    fn findings_can_be_narrowed_to_one_severity() {
        let report = json!({
            "available": true,
            "generated_at": 7,
            "groups": [
                { "severity": "high", "title": "a" },
                { "severity": "low", "title": "b" },
            ],
        });
        let all = findings(report.clone(), None);
        assert_eq!(all["findings"].as_array().unwrap().len(), 2);
        let high = findings(report, Some("high"));
        assert_eq!(high["findings"][0]["title"], "a");
        assert_eq!(high["findings"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn status_leaves_out_the_findings_and_the_page_labels() {
        let trimmed = status(json!({ "score": 53, "groups": [1], "ui": {}, "lang": "es" }));
        assert_eq!(trimmed, json!({ "score": 53 }));
        let unread = status(
            json!({ "available": false, "error": "no db", "score": 0, "headline": "clean" }),
        );
        assert_eq!(unread, json!({ "available": false, "error": "no db" }));
    }
}
