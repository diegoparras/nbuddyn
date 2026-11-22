//! Reads a snapshot from n8n's Postgres. The session is switched to read-only
//! before the first query, so nbuddyn cannot change n8n even by mistake.

use tokio_postgres::{Client, NoTls};

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

pub async fn read_snapshot(database_url: &str) -> Result<Snapshot, DbError> {
    let (client, connection) = tokio_postgres::connect(database_url, NoTls).await?;
    // The connection object drives the socket; it ends when the client is dropped.
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
        .batch_execute("SET default_transaction_read_only = on")
        .await?;

    Ok(Snapshot {
        workflows: workflows(&client).await?,
        credentials: credentials(&client).await?,
        error_counts: error_counts(&client).await?,
        stuck: stuck(&client).await?,
        users_total: count(&client, r#"select count(*) from "user""#).await?,
        users_without_mfa: count(
            &client,
            r#"select count(*) from "user" u
               where not u.disabled
                 and not coalesce(u."mfaEnabled", false)"#,
        )
        .await?,
        waiting_executions: count(
            &client,
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
