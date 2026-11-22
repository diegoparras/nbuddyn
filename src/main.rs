//! nbuddyn: a tiny, read-only cockpit for self-hosted n8n.

mod cluster;
mod db;
mod history;
mod i18n;
mod model;
mod radar;
mod runners;
mod web;

use std::env;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::net::TcpListener;
use tokio::sync::RwLock;

use crate::cluster::RedisConfig;
use crate::history::{History, Store};
use crate::i18n::Lang;
use crate::model::Snapshot;
use crate::runners::RunnerTarget;
use crate::web::{AppState, Inventory, Scan};

struct Config {
    database_url: String,
    listen: String,
    user: String,
    password: Option<String>,
    interval: Duration,
    lang: Lang,
    /// `None` leaves the queue and cluster checks out.
    redis: Option<RedisConfig>,
    /// Empty leaves the task runner check out.
    runners: Vec<RunnerTarget>,
    /// `None` leaves nbuddyn without a memory of its own.
    data_dir: Option<String>,
    history_days: u32,
    /// Decides where a day ends. `None` uses the database's own time zone.
    timezone: Option<String>,
}

impl Config {
    fn from_env() -> Result<Self, String> {
        let var = |name: &str| env::var(name).ok().filter(|v| !v.trim().is_empty());

        let database_url = var("NBUDDYN_DATABASE_URL")
            .ok_or("NBUDDYN_DATABASE_URL is required (a read-only Postgres user is recommended)")?;

        let password = var("NBUDDYN_PASSWORD");
        let anonymous = var("NBUDDYN_ALLOW_ANONYMOUS").is_some_and(|v| v == "true");
        if password.is_none() && !anonymous {
            return Err(
                "NBUDDYN_PASSWORD is required. The report lists the weak points of your \
                        instance, so it must not be public. Set NBUDDYN_ALLOW_ANONYMOUS=true only \
                        behind another login."
                    .into(),
            );
        }

        let interval = match var("NBUDDYN_INTERVAL_SECONDS") {
            None => 300,
            Some(v) => v
                .parse::<u64>()
                .ok()
                .filter(|s| *s >= 10)
                .ok_or("NBUDDYN_INTERVAL_SECONDS must be a number of seconds, 10 or more")?,
        };

        let redis = match var("NBUDDYN_REDIS_URL") {
            None => None,
            Some(url) => {
                let mut redis = RedisConfig::parse(&url)?;
                if let Some(prefix) = var("NBUDDYN_BULL_PREFIX") {
                    redis.bull_prefix = prefix;
                }
                if let Some(name) = var("NBUDDYN_QUEUE_NAME") {
                    redis.queue_name = name;
                }
                if let Some(prefix) = var("NBUDDYN_REDIS_KEY_PREFIX") {
                    redis.key_prefix = prefix;
                }
                Some(redis)
            }
        };

        let runners = match var("NBUDDYN_RUNNER_URLS") {
            None => Vec::new(),
            Some(list) => runners::parse_targets(&list)?,
        };

        let history_days = match var("NBUDDYN_HISTORY_DAYS") {
            None => 400,
            Some(v) => v
                .parse::<u32>()
                .ok()
                .filter(|d| (1..=3650).contains(d))
                .ok_or("NBUDDYN_HISTORY_DAYS must be a number of days between 1 and 3650")?,
        };

        let timezone = var("NBUDDYN_TIMEZONE");
        if let Some(zone) = &timezone {
            let valid = zone.len() <= 64
                && zone
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '+' | '-'));
            if !valid {
                return Err(
                    "NBUDDYN_TIMEZONE must be a time zone name such as America/Argentina/Buenos_Aires"
                        .into(),
                );
            }
        }

        Ok(Self {
            redis,
            runners,
            data_dir: var("NBUDDYN_DATA_DIR"),
            history_days,
            timezone,
            database_url,
            listen: var("NBUDDYN_LISTEN").unwrap_or_else(|| "0.0.0.0:8787".into()),
            user: var("NBUDDYN_USER").unwrap_or_else(|| "nbuddyn".into()),
            password,
            interval: Duration::from_secs(interval),
            lang: Lang::parse(&var("NBUDDYN_LANG").unwrap_or_default()),
        })
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(message) => {
            eprintln!("nbuddyn: {message}");
            return ExitCode::from(2);
        }
    };

    let state = Arc::new(AppState {
        user: config.user.clone(),
        password: config.password.clone(),
        default_lang: config.lang,
        latest: RwLock::new(None),
        last_error: RwLock::new(None),
        cluster_error: RwLock::new(None),
        history_enabled: config.data_dir.is_some(),
        history: RwLock::new(None),
        history_error: RwLock::new(None),
    });

    let listener = match TcpListener::bind(&config.listen).await {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("nbuddyn: cannot listen on {}: {e}", config.listen);
            return ExitCode::from(1);
        }
    };
    println!(
        "nbuddyn {} listening on {}",
        env!("CARGO_PKG_VERSION"),
        config.listen
    );

    tokio::spawn(scan_forever(
        state.clone(),
        Scanner {
            database_url: config.database_url,
            timezone: config.timezone,
            redis: config.redis,
            runners: config.runners,
            store: config.data_dir.map(Store::new),
            history_days: config.history_days,
        },
        config.interval,
    ));

    let served = axum::serve(listener, web::router(state))
        .with_graceful_shutdown(shutdown())
        .await;
    match served {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("nbuddyn: server error: {e}");
            ExitCode::from(1)
        }
    }
}

/// What a scan reads from, and where it remembers.
struct Scanner {
    database_url: String,
    timezone: Option<String>,
    redis: Option<RedisConfig>,
    runners: Vec<RunnerTarget>,
    store: Option<Store>,
    history_days: u32,
}

/// Scans on start and then on every interval. A failed scan keeps the previous
/// result on screen and records why the new one failed.
async fn scan_forever(state: Arc<AppState>, scanner: Scanner, interval: Duration) {
    // Loaded on the first scan that can read it, then kept here between scans.
    let mut history: Option<History> = None;
    loop {
        match scan_once(&state, &scanner, &mut history).await {
            Ok(scan) => {
                println!(
                    "scan ok: score {} with {} findings",
                    scan.score,
                    scan.findings.len()
                );
                *state.latest.write().await = Some(scan);
                *state.last_error.write().await = None;
            }
            Err(e) => {
                let reason = db::describe(&e);
                eprintln!("scan failed: {reason}");
                *state.last_error.write().await = Some(reason);
            }
        }
        tokio::time::sleep(interval).await;
    }
}

async fn scan_once(
    state: &AppState,
    scanner: &Scanner,
    history: &mut Option<History>,
) -> Result<Scan, db::DbError> {
    let client = db::connect(&scanner.database_url, scanner.timezone.as_deref()).await?;
    let mut snapshot = db::read_snapshot(&client).await?;

    // The database is the report; Redis adds the cluster to it. A Redis that
    // cannot be read is reported without losing the rest.
    let cluster_error = match &scanner.redis {
        None => None,
        Some(config) => match cluster::read_cluster(config).await {
            Ok(cluster) => {
                snapshot.cluster = Some(cluster);
                None
            }
            Err(reason) => {
                eprintln!("cluster read failed: {reason}");
                Some(reason)
            }
        },
    };
    *state.cluster_error.write().await = cluster_error;
    snapshot.runners = runners::probe_all(&scanner.runners).await;
    let scan = evaluate(&snapshot);

    if let Some(store) = &scanner.store {
        let outcome = remember(&client, store, history, scan.score, scanner.history_days).await;
        if let Err(reason) = &outcome {
            eprintln!("history not updated: {reason}");
        }
        *state.history_error.write().await = outcome.err();
        *state.history.write().await = history.clone().map(Arc::new);
    }
    Ok(scan)
}

/// Counts the executions that finished since the last scan and saves the
/// result. The copy in memory only moves forward once the file is written, so
/// a scan that cannot save is repeated by the next one instead of being lost.
async fn remember(
    client: &tokio_postgres::Client,
    store: &Store,
    history: &mut Option<History>,
    score: u32,
    keep_days: u32,
) -> Result<(), String> {
    let mut next = match history {
        Some(history) => history.clone(),
        None => store.load()?,
    };
    let delta = db::read_executions(client, next.cursor, &next.pending)
        .await
        .map_err(|e| db::describe(&e))?;
    next.record(delta, score, keep_days);
    store.save(&next)?;
    *history = Some(next);
    Ok(())
}

fn evaluate(snapshot: &Snapshot) -> Scan {
    let findings = radar::scan(snapshot);
    Scan {
        generated_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
        score: radar::score(&findings),
        inventory: Inventory {
            workflows: snapshot.workflows.len(),
            active: snapshot.workflows.iter().filter(|w| w.active).count(),
            credentials: snapshot.credentials.len(),
            users: snapshot.users_total,
            nodes: snapshot.workflows.iter().map(|w| w.nodes.len()).sum(),
            waiting: snapshot.waiting_executions,
        },
        cluster: snapshot.cluster.clone(),
        runners: snapshot.runners.clone(),
        findings,
    }
}

async fn shutdown() {
    let interrupt = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = interrupt => {}
                    _ = terminate.recv() => {}
                }
            }
            Err(_) => {
                let _ = interrupt.await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = interrupt.await;
    }
}
