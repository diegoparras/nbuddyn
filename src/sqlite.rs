//! Reads n8n's SQLite file, the database n8n uses when it is given none.
//!
//! The file is opened read-only and told to refuse writes, for every read
//! anew. n8n keeps writing to it meanwhile; SQLite lets a reader see a
//! consistent picture without getting in the writer's way. Dates in the file
//! are UTC, so days are cut in UTC here.

use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags};

use crate::db::{ExecutionDelta, UNFINISHED_MAX};
use crate::history::{Outcome, Tally};
use crate::model::{Credential, ErrorCount, Snapshot, StuckExecution, Workflow};

/// How long to wait when n8n is in the middle of a write.
const BUSY_WAIT: Duration = Duration::from_secs(5);

fn open(path: &Path) -> Result<Connection, String> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags(path, flags)
        .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    conn.busy_timeout(BUSY_WAIT).map_err(text)?;
    conn.pragma_update(None, "query_only", true).map_err(text)?;
    Ok(conn)
}

fn text(error: rusqlite::Error) -> String {
    // SQLite's own wording for this is "attempt to write a readonly
    // database", which sounds like nbuddyn tried to change something.
    if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ReadOnly) {
        return "the SQLite file can only be read this way while n8n is running: \
                start n8n, or let nbuddyn write in the folder that holds the file"
            .to_owned();
    }
    error.to_string()
}

pub fn read_snapshot(path: &Path) -> Result<Snapshot, String> {
    let conn = open(path)?;
    snapshot(&conn).map_err(text)
}

fn snapshot(conn: &Connection) -> rusqlite::Result<Snapshot> {
    let workflows = conn
        .prepare(r#"select id, name, active, "isArchived", nodes, settings from workflow_entity"#)?
        .query_map([], |r| {
            let nodes: Option<String> = r.get(4)?;
            let settings: Option<String> = r.get(5)?;
            Ok(Workflow::from_raw(
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                nodes.as_deref().unwrap_or("[]"),
                settings.as_deref(),
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;

    let credentials = conn
        .prepare("select id, name, type from credentials_entity")?
        .query_map([], |r| {
            Ok(Credential {
                id: r.get(0)?,
                name: r.get(1)?,
                kind: r.get(2)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?;

    let error_counts = conn
        .prepare(
            r#"select coalesce(w.name, e."workflowId", ''), count(*),
                      coalesce(strftime('%Y-%m-%d %H:%M', max(e."startedAt")), ''),
                      coalesce(e."workflowId", '')
               from execution_entity e
               left join workflow_entity w on w.id = e."workflowId"
               where e."deletedAt" is null
                 and e.status in ('error', 'crashed')
                 and datetime(e."startedAt") > datetime('now', '-7 days')
               group by 1, 4
               order by 2 desc"#,
        )?
        .query_map([], |r| {
            Ok(ErrorCount {
                workflow: r.get(0)?,
                errors: r.get(1)?,
                last: r.get(2)?,
                workflow_id: r.get(3)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?;

    let stuck = conn
        .prepare(
            r#"select cast(e.id as text), coalesce(w.name, e."workflowId", ''), e.status,
                      coalesce(strftime('%Y-%m-%d %H:%M',
                                        coalesce(e."startedAt", e."createdAt")), ''),
                      coalesce(e."workflowId", '')
               from execution_entity e
               left join workflow_entity w on w.id = e."workflowId"
               where e."deletedAt" is null
                 and e.status in ('running', 'new')
                 and datetime(coalesce(e."startedAt", e."createdAt"))
                     < datetime('now', '-1 hour')
               order by 4
               limit 50"#,
        )?
        .query_map([], |r| {
            Ok(StuckExecution {
                id: r.get(0)?,
                workflow: r.get(1)?,
                status: r.get(2)?,
                since: r.get(3)?,
                workflow_id: r.get(4)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?;

    // Older n8n versions have no workflow history; then nobody is named.
    let authors = conn
        .prepare(
            r#"select w.id, h.authors from workflow_entity w
               join workflow_history h on h."versionId" = w."versionId"
               where h.authors is not null"#,
        )
        .and_then(|mut query| {
            query
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<_>>()
        })
        .unwrap_or_default();

    let count = |sql: &str| conn.query_row(sql, [], |r| r.get::<_, i64>(0));
    Ok(Snapshot {
        cluster: None,
        runners: Vec::new(),
        authors,
        workflows,
        credentials,
        error_counts,
        stuck,
        users_total: count(r#"select count(*) from "user""#)?,
        users_without_mfa: count(
            r#"select count(*) from "user" u
               where not coalesce(u.disabled, 0)
                 and not coalesce(u."mfaEnabled", 0)"#,
        )?,
        waiting_executions: count(
            r#"select count(*) from execution_entity
               where "deletedAt" is null and status = 'waiting'"#,
        )?,
    })
}

pub fn read_executions(
    path: &Path,
    cursor: i64,
    pending: &[i64],
) -> Result<ExecutionDelta, String> {
    let mut conn = open(path)?;
    // One read transaction: every query below sees the same instant.
    let tx = conn.transaction().map_err(text)?;
    executions(&tx, cursor, pending).map_err(text)
}

fn executions(conn: &Connection, cursor: i64, pending: &[i64]) -> rusqlite::Result<ExecutionDelta> {
    let (upto, today): (i64, String) = conn.query_row(
        "select coalesce(max(id), 0), date('now') from execution_entity",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    // A database restored from a backup can be behind what was already counted.
    let cursor = cursor.min(upto);
    // Numbers only, so they can be written into the query as they are.
    let again = pending
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let range = format!("((e.id > {cursor} and e.id <= {upto}) or e.id in ({again}))");

    // Soft-deleted rows count too: n8n deletes what it is told not to keep,
    // and those executions still happened.
    let finished = conn
        .prepare(&format!(
            r#"select coalesce(e."workflowId", ''), coalesce(max(w.name), ''),
                      date(coalesce(e."startedAt", e."createdAt")), e.status, count(*)
               from execution_entity e
               left join workflow_entity w on w.id = e."workflowId"
               where {range}
                 and e.status in ('success', 'error', 'crashed', 'canceled')
               group by 1, 3, 4"#
        ))?
        .query_map([], |r| {
            let day: Option<String> = r.get(2)?;
            let status: String = r.get(3)?;
            Ok(day.zip(Outcome::of_status(&status)).map(|(day, outcome)| {
                Ok(Tally {
                    workflow_id: r.get(0)?,
                    workflow_name: r.get(1)?,
                    day,
                    outcome,
                    count: r.get(4)?,
                })
            }))
        })?
        .filter_map(Result::transpose)
        .map(|row| row.and_then(|tally| tally))
        .collect::<rusqlite::Result<_>>()?;

    let mut unfinished: Vec<i64> = conn
        .prepare(&format!(
            r#"select e.id from execution_entity e
               where {range}
                 and (e.status is null
                      or e.status not in ('success', 'error', 'crashed', 'canceled'))
               order by e.id desc
               limit {UNFINISHED_MAX}"#
        ))?
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    unfinished.reverse();

    Ok(ExecutionDelta {
        today,
        upto,
        finished,
        unfinished,
    })
}
