//! Reads a snapshot from n8n's Postgres. The session is switched to read-only
//! before the first query, so nbuddyn cannot change n8n even by mistake.

use tokio_postgres::{Client, NoTls};

use crate::history::{Outcome, Tally};
use crate::model::{Credential, ErrorCount, Snapshot, StuckExecution, Workflow};

pub type DbError = tokio_postgres::Error;

/// The server's own message when there is one ("password authentication failed
/// for user ..."), instead of the driver's generic "db error".
pub fn describe(error: &DbError) -> String {
    match error.as_db_error() {
        Some(db) => db.message().to_owned(),
        None => {
            let mut text = error.to_string();
            let mut source = std::error::Error::source(error);
            while let Some(cause) = source {
                text.push_str(": ");
                text.push_str(&cause.to_string());
                source = cause.source();
            }
            text
        }
    }
}

/// Opens a session that can only read. `timezone`, when given, decides where
/// one day ends and the next begins.
pub async fn connect(database_url: &str, timezone: Option<&str>) -> Result<Client, DbError> {
    let (client, connection) = tokio_postgres::connect(database_url, NoTls).await?;
    // The connection object drives the socket; it ends when the client is dropped.
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
        .batch_execute("SET default_transaction_read_only = on")
        .await?;
    if let Some(zone) = timezone {
        // `Config` only lets through names made of letters, digits and `/_+-`.
        client
            .batch_execute(&format!("SET TIME ZONE '{zone}'"))
            .await?;
    }
    Ok(client)
}

pub async fn read_snapshot(client: &Client) -> Result<Snapshot, DbError> {
    Ok(Snapshot {
        cluster: None,
        runners: Vec::new(),
        workflows: workflows(client).await?,
        credentials: credentials(client).await?,
        error_counts: error_counts(client).await?,
        stuck: stuck(client).await?,
        users_total: count(client, r#"select count(*) from "user""#).await?,
        users_without_mfa: count(
            client,
            r#"select count(*) from "user" u
               where not u.disabled
                 and not coalesce(u."mfaEnabled", false)"#,
        )
        .await?,
        waiting_executions: count(
            client,
            r#"select count(*) from execution_entity
               where "deletedAt" is null and status = 'waiting'"#,
        )
        .await?,
    })
}

async fn workflows(client: &Client) -> Result<Vec<Workflow>, DbError> {
    let rows = client
        .query(
            r#"select name::text, active, "isArchived", nodes::text, settings::text
               from workflow_entity"#,
            &[],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| {
            let nodes: String = r.get(3);
            let settings: Option<String> = r.get(4);
            Workflow::from_raw(r.get(0), r.get(1), r.get(2), &nodes, settings.as_deref())
        })
        .collect())
}

async fn credentials(client: &Client) -> Result<Vec<Credential>, DbError> {
    let rows = client
        .query(
            "select id::text, name::text, type::text from credentials_entity",
            &[],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| Credential {
            id: r.get(0),
            name: r.get(1),
            kind: r.get(2),
        })
        .collect())
}

async fn error_counts(client: &Client) -> Result<Vec<ErrorCount>, DbError> {
    let rows = client
        .query(
            r#"select coalesce(w.name, e."workflowId")::text, count(*),
                      to_char(max(e."startedAt"), 'YYYY-MM-DD HH24:MI')
               from execution_entity e
               left join workflow_entity w on w.id = e."workflowId"
               where e."deletedAt" is null
                 and e.status in ('error', 'crashed')
                 and e."startedAt" > now() - interval '7 days'
               group by 1
               order by 2 desc"#,
            &[],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| ErrorCount {
            workflow: r.get(0),
            errors: r.get(1),
            last: r.get::<_, Option<String>>(2).unwrap_or_default(),
        })
        .collect())
}

async fn stuck(client: &Client) -> Result<Vec<StuckExecution>, DbError> {
    let rows = client
        .query(
            r#"select e.id::text, coalesce(w.name, e."workflowId")::text, e.status::text,
                      to_char(coalesce(e."startedAt", e."createdAt"), 'YYYY-MM-DD HH24:MI')
               from execution_entity e
               left join workflow_entity w on w.id = e."workflowId"
               where e."deletedAt" is null
                 and e.status in ('running', 'new')
                 and coalesce(e."startedAt", e."createdAt") < now() - interval '1 hour'
               order by 4
               limit 50"#,
            &[],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| StuckExecution {
            id: r.get(0),
            workflow: r.get(1),
            status: r.get(2),
            since: r.get::<_, Option<String>>(3).unwrap_or_default(),
        })
        .collect())
}

async fn count(client: &Client, sql: &str) -> Result<i64, DbError> {
    Ok(client.query_one(sql, &[]).await?.get(0))
}

/// What happened in n8n's executions since the last time nbuddyn looked.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecutionDelta {
    /// Today's date in the session's time zone, as `YYYY-MM-DD`.
    pub today: String,
    /// The highest execution id that exists; the next read starts after it.
    pub upto: i64,
    /// Finished executions not counted before, grouped.
    pub finished: Vec<Tally>,
    /// Executions seen but not finished yet, to look at again next time.
    pub unfinished: Vec<i64>,
}

/// How many unfinished executions are remembered between scans.
const UNFINISHED_MAX: i64 = 5000;

/// Reads the executions above `cursor`, plus the ones in `pending` that were
/// unfinished last time. Everything is read at one instant, so an execution
/// that finishes meanwhile is counted exactly once: now or on the next read.
pub async fn read_executions(
    client: &Client,
    cursor: i64,
    pending: &[i64],
) -> Result<ExecutionDelta, DbError> {
    client
        .batch_execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .await?;
    let result = executions(client, cursor, pending).await;
    // Nothing was written, so ending the transaction either way is the same.
    let _ = client.batch_execute("ROLLBACK").await;
    result
}

async fn executions(
    client: &Client,
    cursor: i64,
    pending: &[i64],
) -> Result<ExecutionDelta, DbError> {
    let head = client
        .query_one(
            "select coalesce(max(id), 0)::bigint, to_char(now(), 'YYYY-MM-DD')
             from execution_entity",
            &[],
        )
        .await?;
    let upto: i64 = head.get(0);
    // A database restored from a backup can be behind what was already counted.
    let cursor = cursor.min(upto);

    let pending: Vec<i64> = pending.to_vec();
    // Soft-deleted rows count too: n8n deletes what it is told not to keep,
    // and those executions still happened.
    let rows = client
        .query(
            r#"select coalesce(e."workflowId", '')::text,
                      coalesce(max(w.name), '')::text,
                      to_char(coalesce(e."startedAt", e."createdAt"), 'YYYY-MM-DD'),
                      e.status::text,
                      count(*)
               from execution_entity e
               left join workflow_entity w on w.id = e."workflowId"
               where ((e.id > $1::bigint and e.id <= $2::bigint) or e.id = any($3::bigint[]))
                 and e.status in ('success', 'error', 'crashed', 'canceled')
               group by 1, 3, 4"#,
            &[&cursor, &upto, &pending],
        )
        .await?;
    let finished = rows
        .iter()
        .filter_map(|r| {
            let status: String = r.get(3);
            Some(Tally {
                workflow_id: r.get(0),
                workflow_name: r.get(1),
                day: r.get::<_, Option<String>>(2)?,
                outcome: Outcome::of_status(&status)?,
                count: r.get(4),
            })
        })
        .collect();

    let rows = client
        .query(
            r#"select e.id::bigint
               from execution_entity e
               where ((e.id > $1::bigint and e.id <= $2::bigint) or e.id = any($3::bigint[]))
                 and (e.status is null
                      or e.status not in ('success', 'error', 'crashed', 'canceled'))
               order by e.id desc
               limit $4"#,
            &[&cursor, &upto, &pending, &UNFINISHED_MAX],
        )
        .await?;
    let mut unfinished: Vec<i64> = rows.iter().map(|r| r.get(0)).collect();
    unfinished.reverse();

    Ok(ExecutionDelta {
        today: head.get(1),
        upto,
        finished,
        unfinished,
    })
}
