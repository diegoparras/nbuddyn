//! Reads from n8n's database: Postgres over the network, or the SQLite file
//! n8n uses when it is given no database. Either way the session can only
//! read, so nbuddyn cannot change n8n even by mistake.

use std::path::PathBuf;

use tokio_postgres::config::SslMode;
use tokio_postgres::{Client, NoTls};
use tokio_postgres_rustls::MakeRustlsConnect;

use crate::history::{Outcome, Tally};
use crate::model::{Credential, ErrorCount, Snapshot, StuckExecution, Workflow};
use crate::radar::{self, Finding};
use crate::sqlite;
use crate::tls::{self, PostgresTls, Trust};

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
            .map(Source::Postgres),
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

/// One execution as a list shows it: when, how it ended and how long it
/// took. Never what went through it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ExecutionRow {
    pub id: i64,
    /// n8n's own word: `success`, `error`, `running`...
    pub status: String,
    /// The time of day it started, `HH:MM:SS`, in the instance's time zone.
    pub started: String,
    /// Milliseconds, when n8n recorded an end and nbuddyn may read it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ms: Option<i64>,
    /// n8n no longer keeps it, so there is nothing to open there.
    pub deleted: bool,
}

impl Source {
    /// The executions of one workflow on one day that n8n still has, newest
    /// first. Read when someone asks; nothing of it is kept.
    pub async fn list_executions(
        &self,
        workflow: &str,
        day: &str,
        limit: i64,
    ) -> Result<Vec<ExecutionRow>, String> {
        match self {
            Source::Postgres(client) => pg_list_executions(client, workflow, day, limit)
                .await
                .map_err(|e| describe(&e)),
            Source::Sqlite(path) => {
                let (path, workflow, day) = (path.clone(), workflow.to_owned(), day.to_owned());
                blocking(move || sqlite::list_executions(&path, &workflow, &day, limit)).await
            }
        }
    }
}

async fn pg_list_executions(
    client: &Client,
    workflow: &str,
    day: &str,
    limit: i64,
) -> Result<Vec<ExecutionRow>, DbError> {
    let may_time: bool = client
        .query_one(
            r#"select has_column_privilege('execution_entity', 'stoppedAt', 'select')"#,
            &[],
        )
        .await?
        .get(0);
    let took = if may_time {
        r#"case when e."stoppedAt" >= e."startedAt"
                then (extract(epoch from e."stoppedAt" - e."startedAt") * 1000)::bigint end"#
    } else {
        "null::bigint"
    };
    // The day is cut exactly as the history cuts it, so the list adds up to
    // the totals it is opened from.
    let rows = client
        .query(
            &format!(
                r#"select e.id::bigint, e.status::text,
                          to_char(coalesce(e."startedAt", e."createdAt"), 'HH24:MI:SS'),
                          {took},
                          e."deletedAt" is not null
                   from execution_entity e
                   where e."workflowId" = $1::text
                     and to_char(coalesce(e."startedAt", e."createdAt"), 'YYYY-MM-DD') = $2::text
                   order by coalesce(e."startedAt", e."createdAt") desc, e.id desc
                   limit $3::bigint"#
            ),
            &[&workflow, &day, &limit],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| ExecutionRow {
            id: r.get(0),
            status: r.get(1),
            started: r.get::<_, Option<String>>(2).unwrap_or_default(),
            ms: r.get(3),
            deleted: r.get(4),
        })
        .collect())
}

/// The tables and columns nbuddyn cannot work without.
pub const REQUIRED: &[(&str, &[&str])] = &[
    (
        "workflow_entity",
        &["id", "name", "active", "isArchived", "nodes", "settings"],
    ),
    ("credentials_entity", &["id", "name", "type"]),
    (
        "execution_entity",
        &[
            "id",
            "workflowId",
            "status",
            "startedAt",
            "createdAt",
            "deletedAt",
        ],
    ),
    ("user", &["disabled", "mfaEnabled"]),
];

/// The n8n versions nbuddyn is tested against on every change.
pub const TESTED_WITH: &str = "1.123, 2.48, 3.3";

/// What stands between nbuddyn and the columns it needs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Preflight {
    /// Columns that do not exist: `(table, column)`.
    pub missing: Vec<(String, String)>,
    /// Columns that exist but this database user may not read.
    pub forbidden: Vec<(String, String)>,
    /// The database user nbuddyn connects as, for the grants.
    pub user: String,
}

impl Preflight {
    pub fn ok(&self) -> bool {
        self.missing.is_empty() && self.forbidden.is_empty()
    }

    /// What is wrong and what to do about it, in a form a person can act on.
    pub fn explain(&self) -> String {
        let list = |columns: &[(String, String)]| {
            columns
                .iter()
                .map(|(table, column)| format!("{table}.{column}"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let mut text = String::new();
        if !self.missing.is_empty() {
            text.push_str(&format!(
                "this n8n's database has no {}. nbuddyn is tested with n8n {TESTED_WITH}; \
                 this version may be older or newer than it supports.",
                list(&self.missing)
            ));
        }
        if !self.forbidden.is_empty() {
            if !text.is_empty() {
                text.push(' ');
            }
            text.push_str(&format!(
                "the database user {} may not read {}. Run in n8n's Postgres:",
                self.user,
                list(&self.forbidden)
            ));
            for (table, _) in REQUIRED {
                let columns: Vec<String> = self
                    .forbidden
                    .iter()
                    .filter(|(t, _)| t == table)
                    .map(|(_, c)| format!("\"{c}\""))
                    .collect();
                if !columns.is_empty() {
                    text.push_str(&format!(
                        " GRANT SELECT ({}) ON \"{table}\" TO {};",
                        columns.join(", "),
                        self.user
                    ));
                }
            }
        }
        text
    }
}

impl Source {
    /// Looks at what the database has and what this user may read, without
    /// reading any of it.
    pub async fn preflight(&self) -> Result<Preflight, String> {
        match self {
            Source::Postgres(client) => pg_preflight(client).await.map_err(|e| describe(&e)),
            Source::Sqlite(path) => {
                let path = path.clone();
                blocking(move || sqlite::preflight(&path)).await
            }
        }
    }
}

async fn pg_preflight(client: &Client) -> Result<Preflight, DbError> {
    let tables: Vec<&str> = REQUIRED.iter().map(|(table, _)| *table).collect();
    let rows = client
        .query(
            "select c.relname::text, a.attname::text,
                    has_column_privilege(c.oid, a.attnum, 'select'), current_user::text
             from pg_class c
             join pg_namespace n on n.oid = c.relnamespace
             join pg_attribute a on a.attrelid = c.oid
             where n.nspname = any(current_schemas(false))
               and c.relname = any($1) and a.attnum > 0 and not a.attisdropped",
            &[&tables],
        )
        .await?;
    let user = match rows.first() {
        Some(row) => row.get(3),
        None => client
            .query_one("select current_user::text", &[])
            .await?
            .get(0),
    };
    let mut preflight = Preflight {
        user,
        ..Preflight::default()
    };
    for (table, columns) in REQUIRED {
        for column in *columns {
            let found = rows
                .iter()
                .find(|r| r.get::<_, String>(0) == *table && r.get::<_, String>(1) == *column);
            let place = ((*table).to_owned(), (*column).to_owned());
            match found {
                None => preflight.missing.push(place),
                Some(row) if !row.get::<_, bool>(2) => preflight.forbidden.push(place),
                Some(_) => {}
            }
        }
    }
    Ok(preflight)
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

async fn pg_connect(database_url: &str, timezone: Option<&str>) -> Result<Client, String> {
    let (url, wanted) = tls::split_sslmode(database_url)?;
    let mut config: tokio_postgres::Config = url.parse().map_err(|e: DbError| describe(&e))?;
    // The connection object drives the socket; it ends when the client is dropped.
    let client = match wanted {
        PostgresTls::Off => {
            config.ssl_mode(SslMode::Disable);
            let (client, connection) = config.connect(NoTls).await.map_err(|e| describe(&e))?;
            tokio::spawn(connection);
            client
        }
        encrypted => {
            let trust = if encrypted == PostgresTls::Verified {
                Trust::Verified
            } else {
                Trust::Any
            };
            config.ssl_mode(if encrypted == PostgresTls::IfOffered {
                SslMode::Prefer
            } else {
                SslMode::Require
            });
            let connector = MakeRustlsConnect::new(tls::client_config(trust)?);
            let (client, connection) = config.connect(connector).await.map_err(|e| describe(&e))?;
            tokio::spawn(connection);
            client
        }
    };
    let prepare = async {
        client
            .batch_execute("SET default_transaction_read_only = on")
            .await?;
        if let Some(zone) = timezone {
            // Only names made of letters, digits and `/_+-` get this far.
            client
                .batch_execute(&format!("SET TIME ZONE '{zone}'"))
                .await?;
        }
        Ok::<(), DbError>(())
    };
    prepare.await.map_err(|e| describe(&e))?;
    Ok(client)
}

/// The version n8n recorded when it last started. n8n keeps that list from
/// some version on, and reading it takes a grant of its own, so anything
/// short of an answer is simply "not known".
async fn n8n_version(client: &Client) -> Option<String> {
    let may: bool = client
        .query_one(
            "select coalesce(has_table_privilege(to_regclass('instance_version_history'), 'select'), false)",
            &[],
        )
        .await
        .ok()?
        .get(0);
    if !may {
        return None;
    }
    let row = client
        .query_opt(
            "select major::bigint, minor::bigint, patch::bigint
             from instance_version_history order by id desc limit 1",
            &[],
        )
        .await
        .ok()??;
    let part = |i: usize| row.get::<_, i64>(i);
    Some(format!("{}.{}.{}", part(0), part(1), part(2)))
}

async fn pg_snapshot(client: &Client) -> Result<Snapshot, DbError> {
    let (workflows, workflow_findings) = workflows(client).await?;
    Ok(Snapshot {
        cluster: None,
        runners: Vec::new(),
        authors: authors(client).await,
        n8n_version: n8n_version(client).await,
        workflows,
        workflow_findings,
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

/// Workflows read at a time. Each is checked and lightened before the next
/// page is asked for, so memory holds one page of definitions, not all.
const PAGE: i64 = 200;

async fn workflows(client: &Client) -> Result<(Vec<Workflow>, Vec<Finding>), DbError> {
    let mut workflows = Vec::new();
    let mut findings = Vec::new();
    let mut after = String::new();
    loop {
        let rows = client
            .query(
                r#"select name::text, active, "isArchived", nodes::text, settings::text, id::text
                   from workflow_entity
                   where id::text > $1
                   order by id::text
                   limit $2"#,
                &[&after, &PAGE],
            )
            .await?;
        for r in &rows {
            let nodes: String = r.get(3);
            let settings: Option<String> = r.get(4);
            let mut workflow = Workflow::from_raw(
                r.get(5),
                r.get(0),
                r.get(1),
                r.get(2),
                &nodes,
                settings.as_deref(),
            );
            findings.extend(radar::check_workflow(&workflow));
            workflow.lighten();
            workflows.push(workflow);
        }
        match rows.last() {
            Some(last) if rows.len() as i64 == PAGE => after = last.get(5),
            _ => return Ok((workflows, findings)),
        }
    }
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
    // How long executions took needs one more column than the rest. Without
    // the grant for it everything else still works.
    let may_time: bool = client
        .query_one(
            r#"select has_column_privilege('execution_entity', 'stoppedAt', 'select')"#,
            &[],
        )
        .await?
        .get(0);
    let durations = if may_time {
        r#"count(*) filter (where e."stoppedAt" >= e."startedAt"),
           coalesce(sum(extract(epoch from e."stoppedAt" - e."startedAt") * 1000)
                    filter (where e."stoppedAt" >= e."startedAt"), 0)::bigint,
           coalesce(max(extract(epoch from e."stoppedAt" - e."startedAt") * 1000)
                    filter (where e."stoppedAt" >= e."startedAt"), 0)::bigint"#
    } else {
        "0::bigint, 0::bigint, 0::bigint"
    };
    // Soft-deleted rows count too: n8n deletes what it is told not to keep,
    // and those executions still happened.
    let rows = client
        .query(
            &format!(
                r#"select coalesce(e."workflowId", '')::text,
                      coalesce(max(w.name), '')::text,
                      to_char(coalesce(e."startedAt", e."createdAt"), 'YYYY-MM-DD'),
                      e.status::text,
                      count(*),
                      {durations}
               from execution_entity e
               left join workflow_entity w on w.id = e."workflowId"
               where ((e.id > $1::bigint and e.id <= $2::bigint) or e.id = any($3::bigint[]))
                 and e.status in ('success', 'error', 'crashed', 'canceled')
               group by 1, 3, 4"#
            ),
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
                timed: r.get(5),
                ms: r.get(6),
                slowest: r.get(7),
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
