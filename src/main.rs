//! nbuddyn: a tiny, read-only cockpit for self-hosted n8n.

mod db;
mod i18n;
mod model;
mod radar;
mod web;

use std::env;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::net::TcpListener;
use tokio::sync::RwLock;

use crate::i18n::Lang;
use crate::model::Snapshot;
use crate::web::{AppState, Inventory, Scan};

struct Config {
    database_url: String,
    listen: String,
    user: String,
    password: Option<String>,
    interval: Duration,
    lang: Lang,
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

        Ok(Self {
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
        config.database_url,
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

/// Scans on start and then on every interval. A failed scan keeps the previous
/// result on screen and records why the new one failed.
async fn scan_forever(state: Arc<AppState>, database_url: String, interval: Duration) {
    loop {
        match db::read_snapshot(&database_url).await {
            Ok(snapshot) => {
                let scan = evaluate(&snapshot);
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
