//! Reads from n8n's database: Postgres over the network, or the SQLite file
//! n8n uses when it is given no database. Either way the session can only
//! read, so nbuddyn cannot change n8n even by mistake.

use std::path::PathBuf;

use tokio_postgres::{Client, NoTls};

use crate::history::{Outcome, Tally};
use crate::model::{Credential, ErrorCount, Snapshot, StuckExecution, Workflow};
use crate::sqlite;

type DbError = tokio_postgres::Error;

/// An open way to read n8n's database.
pub enum Source {
    Postgres(Client),
    /// The file is opened again for every read, so nothing is held between scans.
    Sqlite(PathBuf),
}

/// The path in `sqlite:/path/to/database.sqlite`, or `None` for anything else.
pub fn sqlite_path(database_url: &str) -> Option<PathBuf> {
    let rest = database_url.strip_prefix("sqlite:")?;
    // `sqlite:///data/x` and `sqlite:/data/x` both mean `/data/x`.
    let path = match rest.strip_prefix("//") {
        Some(absolute) => absolute,
        None => rest,
    };
    (!path.is_empty()).then(|| PathBuf::from(path))
}

/// `host/database` or the file's path, without the user or the password.
pub fn label(database_url: &str) -> String {
    if let Some(path) = sqlite_path(database_url) {
        return path.display().to_string();
    }
    let rest = database_url
        .split_once("://")
        .map_or(database_url, |(_, rest)| rest);
    let rest = rest.rsplit_once('@').map_or(rest, |(_, location)| location);
    rest.split(['?', '#']).next().unwrap_or_default().to_owned()
}

/// Opens a session that can only read. `timezone`, when given, decides where
/// one day ends and the next begins; SQLite has no time zones and always cuts
/// days in UTC.
pub async fn connect(database_url: &str, timezone: Option<&str>) -> Result<Source, String> {
    match sqlite_path(database_url) {
        Some(path) => Ok(Source::Sqlite(path)),
        None => pg_connect(database_url, timezone)
            .await
            .map(Source::Postgres)
            .map_err(|e| describe(&e)),
    }
}

impl Source {
    pub async fn read_snapshot(&self) -> Result<Snapshot, String> {
        match self {
            Source::Postgres(client) => pg_snapshot(client).await.map_err(|e| describe(&e)),
            Source::Sqlite(path) => {
                let path = path.clone();
                blocking(move || sqlite::read_snapshot(&path)).await
            }
        }
    }

    /// Reads the executions above `cursor`, plus the ones in `pending` that
    /// were unfinished last time. Everything is read at one instant, so an
    /// execution that finishes meanwhile is counted exactly once: now or on
    /// the next read.
    pub async fn read_executions(
        &self,
        cursor: i64,
        pending: &[i64],
    ) -> Result<ExecutionDelta, String> {
        match self {
            Source::Postgres(client) => pg_executions(client, cursor, pending)
                .await
                .map_err(|e| describe(&e)),
            Source::Sqlite(path) => {
                let (path, pending) = (path.clone(), pending.to_vec());
                blocking(move || sqlite::read_executions(&path, cursor, &pending)).await
            }
        }
    }
}

/// SQLite reads block, so they run off the async threads.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| "the database read did not finish".to_owned())?
}

/// The server's own message when there is one ("password authentication failed
/// for user ..."), instead of the driver's generic "db error".
fn describe(error: &DbError) -> String {
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

async fn pg_connect(database_url: &str, timezone: Option<&str>) -> Result<Client, DbError> {
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

async fn pg_snapshot(client: &Client) -> Result<Snapshot, DbError> {
    Ok(Snapshot {
        cluster: None,
        runners: Vec::new(),
        authors: authors(client).await,
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
            r#"select name::text, active, "isArchived", nodes::text, settings::text, id::text
               from workflow_entity"#,
            &[],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| {
            let nodes: String = r.get(3);
            let settings: Option<String> = r.get(4);
            Workflow::from_raw(
                r.get(5),
                r.get(0),
                r.get(1),
                r.get(2),
                &nodes,
                settings.as_deref(),
            )
        })
        .collect())
}

/// Optional: needs two more grants than the rest. Without them the change log
/// still works, it just cannot say who made a change.
async fn authors(client: &Client) -> std::collections::HashMap<String, String> {
    let rows = client
        .query(
            r#"select w.id::text, h.authors::text
               from workflow_entity w
               join workflow_history h on h."versionId" = w."versionId"
               where h.authors is not null"#,
            &[],
        )
        .await
        .unwrap_or_default();
    rows.iter().map(|r| (r.get(0), r.get(1))).collect()
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
                      to_char(max(e."startedAt"), 'YYYY-MM-DD HH24:MI'),
                      coalesce(e."workflowId", '')::text
               from execution_entity e
               left join workflow_entity w on w.id = e."workflowId"
               where e."deletedAt" is null
                 and e.status in ('error', 'crashed')
                 and e."startedAt" > now() - interval '7 days'
               group by 1, 4
               order by 2 desc"#,
            &[],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| ErrorCount {
            workflow_id: r.get(3),
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
                      to_char(coalesce(e."startedAt", e."createdAt"), 'YYYY-MM-DD HH24:MI'),
                      coalesce(e."workflowId", '')::text
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
            workflow_id: r.get(4),
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
pub const UNFINISHED_MAX: i64 = 5000;

async fn pg_executions(
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_addresses_are_told_from_postgres_ones() {
        let path = |url| sqlite_path(url).map(|p| p.display().to_string());
        assert_eq!(
            path("sqlite:///home/node/.n8n/database.sqlite").as_deref(),
            Some("/home/node/.n8n/database.sqlite")
        );
        assert_eq!(
            path("sqlite:/n8n/database.sqlite").as_deref(),
            Some("/n8n/database.sqlite")
        );
        assert_eq!(path("sqlite:"), None);
        assert_eq!(path("postgres://u:p@host/n8n"), None);
    }

    #[test]
    fn the_label_never_shows_the_user_or_the_password() {
        assert_eq!(
            label("postgres://nbuddyn:s3cret@n8n_postgres:5432/n8n?sslmode=disable"),
            "n8n_postgres:5432/n8n"
        );
        assert_eq!(label("sqlite:/n8n/database.sqlite"), "/n8n/database.sqlite");
    }
}
