//! `nbuddyn demo`: a made-up n8n to look around in, for someone deciding
//! whether nbuddyn is worth installing. It builds a small database shaped
//! like n8n's, with the kinds of problems real instances have, and runs
//! nbuddyn against it. Nothing in it is real and nothing leaves the machine.

use std::path::Path;

use rusqlite::{params, Connection};

/// What a demo workflow is made of: name, whether it is active, its nodes as
/// n8n would store them, and its settings.
const WORKFLOWS: &[(&str, bool, &str, &str)] = &[
    (
        "Support agent (MCP)",
        true,
        r#"[{"name":"MCP Server Trigger","type":"@n8n/n8n-nodes-langchain.mcpTrigger","parameters":{"path":"support"}},
            {"name":"Gmail","type":"n8n-nodes-base.gmail","parameters":{},"credentials":{"gmailOAuth2":{"id":"c1"}}}]"#,
        "{}",
    ),
    (
        "Orders webhook",
        true,
        r#"[{"name":"Webhook","type":"n8n-nodes-base.webhook","parameters":{"path":"orders","httpMethod":"POST"}},
            {"name":"Save order","type":"n8n-nodes-base.postgres","parameters":{},"credentials":{"postgres":{"id":"c2"}}}]"#,
        r#"{"errorWorkflow":"demo0000000008"}"#,
    ),
    (
        "Nightly cleanup",
        true,
        r#"[{"name":"Schedule","type":"n8n-nodes-base.scheduleTrigger","parameters":{}},
            {"name":"Delete expired","type":"n8n-nodes-base.postgres","parameters":{},"credentials":{"postgres":{"id":"c2"}}}]"#,
        "{}",
    ),
    (
        "Sync CRM",
        true,
        r#"[{"name":"Schedule","type":"n8n-nodes-base.scheduleTrigger","parameters":{}},
            {"name":"Call CRM","type":"n8n-nodes-base.httpRequest","parameters":{"url":"http://crm.example.com/api/contacts",
             "headerParameters":{"parameters":[{"name":"Authorization","value":"Bearer demoDEMOdemoDEMOdemoDEMOdemoDEMO1234"}]}}}]"#,
        "{}",
    ),
    (
        "Invoice generator",
        true,
        r#"[{"name":"Schedule","type":"n8n-nodes-base.scheduleTrigger","parameters":{}},
            {"name":"Build PDF","type":"n8n-nodes-base.code","parameters":{"jsCode":"const { execSync } = require('child_process'); return items;"}},
            {"name":"Send","type":"n8n-nodes-base.gmail","parameters":{},"credentials":{"gmailOAuth2":{"id":"c1"}}}]"#,
        r#"{"errorWorkflow":"demo0000000008"}"#,
    ),
    (
        "Lead form",
        true,
        r#"[{"name":"Form","type":"n8n-nodes-base.formTrigger","parameters":{"path":"lead"}},
            {"name":"Notify","type":"n8n-nodes-base.slack","parameters":{},"credentials":{"slackApi":{"id":"c3"}}}]"#,
        "{}",
    ),
    (
        "Daily report",
        true,
        r#"[{"name":"Schedule","type":"n8n-nodes-base.scheduleTrigger","parameters":{}},
            {"name":"Read env","type":"n8n-nodes-base.code","parameters":{"jsCode":"return [{ json: { region: $env.REGION } }];"}},
            {"name":"Post","type":"n8n-nodes-base.slack","parameters":{},"credentials":{"slackApi":{"id":"c3"}}}]"#,
        r#"{"errorWorkflow":"demo0000000008"}"#,
    ),
    (
        "Error handler",
        true,
        r#"[{"name":"Error Trigger","type":"n8n-nodes-base.errorTrigger","parameters":{}},
            {"name":"Alert","type":"n8n-nodes-base.slack","parameters":{},"credentials":{"slackApi":{"id":"c3"}}}]"#,
        r#"{"errorWorkflow":"demo0000000008"}"#,
    ),
    (
        "Old importer",
        false,
        r#"[{"name":"Cron","type":"n8n-nodes-base.cron","parameters":{}},
            {"name":"Function","type":"n8n-nodes-base.function","parameters":{}}]"#,
        "{}",
    ),
];

const CREDENTIALS: &[(&str, &str, &str)] = &[
    ("c1", "Gmail (support)", "gmailOAuth2"),
    ("c2", "Postgres (orders)", "postgres"),
    ("c3", "Slack (alerts)", "slackApi"),
    ("c4", "Stripe (old key)", "stripeApi"),
    ("c5", "Airtable (pilot)", "airtableTokenApi"),
];

/// How each demo workflow behaves over two months: runs a day, the share
/// that fail, and how many days ago it stopped running (0: it still runs).
const BEHAVIOUR: &[(usize, u32, u32, u32)] = &[
    (0, 14, 2, 0),
    (1, 60, 1, 0),
    (2, 24, 100, 0),
    (3, 8, 12, 0),
    (4, 3, 0, 5),
    (5, 6, 0, 0),
    (6, 1, 0, 0),
];

/// Builds the demo database at `file`, replacing one left by an earlier run.
pub fn build(file: &Path) -> Result<(), String> {
    let _ = std::fs::remove_file(file);
    let conn = Connection::open(file).map_err(|e| e.to_string())?;
    create(&conn).map_err(|e| format!("could not build the demo database: {e}"))
}

fn create(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"create table workflow_entity (id varchar(36) primary key, name varchar(128), active boolean,
               "isArchived" boolean default 0, nodes text, settings text, "versionId" varchar(36));
           create table credentials_entity (id varchar(36) primary key, name varchar(128), type varchar(32));
           create table execution_entity (id integer primary key autoincrement, "workflowId" varchar(36),
               status varchar, "startedAt" datetime, "stoppedAt" datetime, "createdAt" datetime, "deletedAt" datetime);
           create table "user" (id varchar primary key, disabled boolean default 0, "mfaEnabled" boolean default 0);
           create table workflow_history ("versionId" varchar(36) primary key, authors varchar);
           insert into "user" values ('u1', 0, 1), ('u2', 0, 0), ('u3', 0, 0);"#,
    )?;
    let authors = ["Ana Paz", "Leo Ruiz", "Bea Soto"];
    for (index, (name, active, nodes, settings)) in WORKFLOWS.iter().enumerate() {
        let id = format!("demo{:010}", index + 1);
        let version = format!("v{index}");
        conn.execute(
            r#"insert into workflow_entity (id, name, active, nodes, settings, "versionId") values (?1, ?2, ?3, ?4, ?5, ?6)"#,
            params![id, name, active, nodes, settings, version],
        )?;
        conn.execute(
            "insert into workflow_history values (?1, ?2)",
            params![version, authors[index % authors.len()]],
        )?;
    }
    for (id, name, kind) in CREDENTIALS {
        conn.execute(
            "insert into credentials_entity values (?1, ?2, ?3)",
            params![id, name, kind],
        )?;
    }

    // Two months of executions, placed by a fixed recipe so the demo looks
    // the same every time.
    let tx = conn.unchecked_transaction()?;
    {
        let mut insert = tx.prepare(
            r#"insert into execution_entity ("workflowId", status, "startedAt", "stoppedAt", "createdAt")
               values (?1, ?2, datetime('now', ?3), datetime('now', ?3, ?4), datetime('now', ?3))"#,
        )?;
        for (workflow, per_day, fail_percent, quiet_days) in BEHAVIOUR {
            let id = format!("demo{:010}", workflow + 1);
            for day in *quiet_days..60 {
                for run in 0..*per_day {
                    let seed = day * 131 + run * 17 + *workflow as u32 * 7;
                    let status = if seed % 100 < *fail_percent {
                        "error"
                    } else {
                        "success"
                    };
                    let minutes_ago = day * 1440 + (run * 1440 / per_day.max(&1)) + seed % 30;
                    insert.execute(params![
                        id,
                        status,
                        format!("-{minutes_ago} minutes"),
                        format!("+{} seconds", 2 + seed % 40),
                    ])?;
                }
            }
        }
        // One execution that never finished.
        insert.execute(params![
            "demo0000000004",
            "running",
            "-300 minutes",
            "+0 seconds"
        ])?;
    }
    tx.commit()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_demo_database_reads_like_an_n8n_and_shows_real_kinds_of_problems() {
        let file = std::env::temp_dir().join(format!("nbuddyn-demo-{}.sqlite", std::process::id()));
        build(&file).unwrap();
        assert!(crate::sqlite::preflight(&file).unwrap().ok());
        let snapshot = crate::sqlite::read_snapshot(&file).unwrap();
        assert_eq!(snapshot.workflows.len(), WORKFLOWS.len());
        let findings = crate::radar::scan(&snapshot);
        let checks: std::collections::HashSet<&str> = findings.iter().map(|f| f.check).collect();
        for expected in [
            "open_ai_entry",
            "public_entry_no_auth",
            "hardcoded_secret",
            "repeated_failures",
            "stuck_execution",
            "no_error_workflow",
            "plaintext_http",
            "no_mfa",
            "unused_credential",
            "removed_node_v3",
            "env_access",
            "command_execution",
        ] {
            assert!(
                checks.contains(expected),
                "the demo does not show {expected}"
            );
        }
        let delta = crate::sqlite::read_executions(&file, 0, &[]).unwrap();
        assert!(delta.upto > 5000);
        assert_eq!(snapshot.authors.len(), WORKFLOWS.len());
        let _ = std::fs::remove_file(&file);
    }
}
