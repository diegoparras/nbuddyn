//! Plain data read from an n8n instance. Nothing here ever writes back.

use serde_json::Value;

use crate::cluster::Cluster;

#[derive(Debug, Clone, Default)]
pub struct Node {
    pub name: String,
    pub node_type: String,
    pub params: Value,
    pub credential_ids: Vec<String>,
    pub disabled: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Workflow {
    pub name: String,
    pub active: bool,
    pub archived: bool,
    pub has_error_workflow: bool,
    pub nodes: Vec<Node>,
}

#[derive(Debug, Clone, Default)]
pub struct Credential {
    pub id: String,
    pub name: String,
    pub kind: String,
}

#[derive(Debug, Clone, Default)]
pub struct ErrorCount {
    pub workflow: String,
    pub errors: i64,
    pub last: String,
}

#[derive(Debug, Clone, Default)]
pub struct StuckExecution {
    pub id: String,
    pub workflow: String,
    pub status: String,
    pub since: String,
}

/// Everything nbuddyn knows about the instance at one point in time.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub workflows: Vec<Workflow>,
    pub credentials: Vec<Credential>,
    pub error_counts: Vec<ErrorCount>,
    pub stuck: Vec<StuckExecution>,
    pub users_total: i64,
    pub users_without_mfa: i64,
    pub waiting_executions: i64,
    /// `None` when no Redis is configured or it could not be read.
    pub cluster: Option<Cluster>,
}

impl Workflow {
    /// Builds a workflow from the raw `nodes` and `settings` JSON stored by n8n.
    pub fn from_raw(
        name: String,
        active: bool,
        archived: bool,
        nodes_json: &str,
        settings_json: Option<&str>,
    ) -> Self {
        let nodes = serde_json::from_str::<Value>(nodes_json)
            .ok()
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default()
            .iter()
            .map(Node::from_value)
            .collect();

        let has_error_workflow = settings_json
            .and_then(|s| serde_json::from_str::<Value>(s).ok())
            .and_then(|v| {
                v.get("errorWorkflow")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .is_some_and(|s| !s.trim().is_empty());

        Self {
            name,
            active,
            archived,
            has_error_workflow,
            nodes,
        }
    }
}

impl Node {
    pub fn from_value(v: &Value) -> Self {
        let text = |key: &str| {
            v.get(key)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        let credential_ids = v
            .get("credentials")
            .and_then(Value::as_object)
            .map(|creds| {
                creds
                    .values()
                    .filter_map(|c| c.get("id").and_then(Value::as_str).map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();

        Self {
            name: text("name"),
            node_type: text("type"),
            params: v.get("parameters").cloned().unwrap_or(Value::Null),
            credential_ids,
            disabled: v.get("disabled").and_then(Value::as_bool).unwrap_or(false),
        }
    }

    pub fn param_str(&self, key: &str) -> &str {
        self.params
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
    }
}
