//! nbuddyn: a tiny, read-only cockpit for self-hosted n8n.

mod cluster;
mod db;
mod history;
mod i18n;
mod mcp;
mod model;
mod radar;
mod runners;
mod settings;
mod sqlite;
mod web;

use std::collections::HashMap;
use std::env;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::net::TcpListener;
use tokio::sync::{Notify, RwLock};

use crate::history::History;
use crate::model::Snapshot;
use crate::settings::{Defaults, Instance};
use crate::web::{AppState, Inventory, Runtime, Scan};

/// What only the environment can set: how to reach n8n's database, who may
/// open the page, and where nbuddyn keeps its own files.
struct Config {
    listen: String,
    user: String,
    password: Option<String>,
    /// `None` leaves the MCP endpoint off.
    mcp_token: Option<String>,
    /// `None` leaves nbuddyn without memory: no history, no saved settings.
    data_dir: Option<String>,
    /// Starting values for everything the page can change.
    defaults: Defaults,
}

impl Config {
    fn from_env() -> Result<Self, String> {
        let var = |name: &str| env::var(name).ok().filter(|v| !v.trim().is_empty());

        let database_url = var("NBUDDYN_DATABASE_URL").ok_or(
            "NBUDDYN_DATABASE_URL is required: postgres://user:password@host:5432/n8n \
                 (a read-only user is recommended) or sqlite:/path/to/database.sqlite",
        )?;

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

        let number = |name: &str, default: u64| match var(name) {
            None => Ok(default),
            Some(v) => v
                .trim()
                .parse::<u64>()
                .map_err(|_| format!("{name} must be a number")),
        };

        let mcp_token = var("NBUDDYN_MCP_TOKEN");
        if mcp_token.as_ref().is_some_and(|t| t.len() < 24) {
            return Err(
                "NBUDDYN_MCP_TOKEN must be at least 24 characters. It is the only thing \
                 between an AI client and the report."
                    .into(),
            );
        }

        let defaults = Defaults {
            database_url: database_url.clone(),
            name: var("NBUDDYN_NAME").unwrap_or_else(|| "n8n".into()),
            n8n_url: var("NBUDDYN_N8N_URL").unwrap_or_default(),
            lang: var("NBUDDYN_LANG").unwrap_or_else(|| "en".into()),
            interval_seconds: number("NBUDDYN_INTERVAL_SECONDS", 300)?,
            timezone: var("NBUDDYN_TIMEZONE").unwrap_or_default(),
            history_days: u32::try_from(number("NBUDDYN_HISTORY_DAYS", 400)?).unwrap_or(u32::MAX),
            runner_urls: var("NBUDDYN_RUNNER_URLS").unwrap_or_default(),
            redis_url: var("NBUDDYN_REDIS_URL").unwrap_or_default(),
            bull_prefix: var("NBUDDYN_BULL_PREFIX"),
            queue_name: var("NBUDDYN_QUEUE_NAME"),
            redis_key_prefix: var("NBUDDYN_REDIS_KEY_PREFIX"),
        };
        // The same checks the page applies, so a bad variable stops the start
        // instead of surfacing later as a scan that never works.
        if let Err(wrong) = settings::Saved::default().resolve(&defaults) {
            let names: Vec<String> = wrong
                .iter()
                .map(|field| format!("NBUDDYN_{}", field.to_ascii_uppercase()))
                .collect();
            return Err(format!("not valid: {}", names.join(", ")));
        }

        Ok(Self {
            listen: var("NBUDDYN_LISTEN").unwrap_or_else(|| "0.0.0.0:8787".into()),
            user: var("NBUDDYN_USER").unwrap_or_else(|| "nbuddyn".into()),
            password,
            mcp_token,
            data_dir: var("NBUDDYN_DATA_DIR"),
            defaults,
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

    // Saved settings that cannot be read are left alone: nbuddyn runs on its
    // starting values and refuses to save until someone looks at the file.
    let store = config.data_dir.as_deref().map(settings::Store::new);
    let (saved, settings_store, settings_error) = match store.map(|s| (s.load(), s)) {
        None => (settings::Saved::default(), None, None),
        Some((Ok(saved), store)) => match saved.resolve(&config.defaults) {
            Ok(_) => (saved, Some(store), None),
            Err(wrong) => (
                settings::Saved::default(),
                None,
                Some(format!(
                    "saved settings are not valid: {}",
                    wrong.join(", ")
                )),
            ),
        },
        Some((Err(reason), _)) => (settings::Saved::default(), None, Some(reason)),
    };
    if let Some(reason) = &settings_error {
        eprintln!("nbuddyn: {reason}; running on the starting values");
    }

    let state = Arc::new(AppState {
        user: config.user.clone(),
        password: config.password.clone(),
        mcp_token: config.mcp_token.clone(),
        defaults: config.defaults,
        saved: RwLock::new(saved),
        settings_store,
        settings_error,
        rescan: Notify::new(),
        history_enabled: config.data_dir.is_some(),
        runtimes: RwLock::new(HashMap::new()),
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

    tokio::spawn(scan_forever(state.clone(), config.data_dir));

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

/// Scans every instance on start, then on every interval or as soon as the
/// settings change. A failed scan keeps the previous result on screen and
/// records why the new one failed.
async fn scan_forever(state: Arc<AppState>, data_dir: Option<String>) {
    // Loaded on the first scan that can read them, then kept between scans.
    let mut histories: HashMap<String, History> = HashMap::new();
    loop {
        let effective = state.effective().await;
        histories.retain(|id, _| effective.instances.iter().any(|i| i.id == *id));
        for instance in &effective.instances {
            let runtime = state.runtime(&instance.id).await;
            let store = data_dir
                .as_deref()
                .map(|dir| history::Store::new(dir, &instance.id));
            let mut history = histories.remove(&instance.id);
            let scanned = scan_once(
                &state,
                &runtime,
                instance,
                store.as_ref(),
                &mut history,
                effective.history_days,
            )
            .await;
            if let Some(history) = history {
                histories.insert(instance.id.clone(), history);
            }
            match scanned {
                Ok(scan) => {
                    println!(
                        "scan ok: {}: {} findings",
                        instance.name,
                        scan.findings.len()
                    );
                    *runtime.latest.write().await = Some(scan);
                    *runtime.last_error.write().await = None;
                }
                Err(reason) => {
                    eprintln!("scan failed: {}: {reason}", instance.name);
                    *runtime.last_error.write().await = Some(reason);
                }
            }
        }
        state.forget_runtimes_except(&effective.instances).await;
        tokio::select! {
            () = tokio::time::sleep(effective.interval) => {}
            () = state.rescan.notified() => {}
        }
    }
}

async fn scan_once(
    state: &AppState,
    runtime: &Runtime,
    instance: &Instance,
    store: Option<&history::Store>,
    history: &mut Option<History>,
    history_days: u32,
) -> Result<Scan, String> {
    let source = db::connect(&instance.database_url, instance.timezone.as_deref()).await?;
    let mut snapshot = source.read_snapshot().await?;

    // The database is the report; Redis adds the cluster to it. A Redis that
    // cannot be read is reported without losing the rest.
    let cluster_error = match &instance.redis {
        None => None,
        Some(config) => match cluster::read_cluster(config).await {
            Ok(cluster) => {
                snapshot.cluster = Some(cluster);
                None
            }
            Err(reason) => {
                eprintln!("cluster read failed: {}: {reason}", instance.name);
                Some(reason)
            }
        },
    };
    *runtime.cluster_error.write().await = cluster_error;
    snapshot.runners = runners::probe_all(&instance.runners).await;
    let mut scan = evaluate(&snapshot);

    if let Some(store) = store {
        let accepted = state.saved.read().await.accepted_in(&instance.id).to_vec();
        let outcome = remember(
            &source,
            store,
            history,
            &snapshot,
            &mut scan,
            &accepted,
            history_days,
        )
        .await;
        if let Err(reason) = &outcome {
            eprintln!("history not updated: {}: {reason}", instance.name);
        }
        *runtime.history_error.write().await = outcome.err();
        *runtime.history.write().await = history.clone().map(Arc::new);
    }
    Ok(scan)
}

/// Brings the history up to this scan and saves it: the executions that
/// finished since the last one, the score, and what changed. The history also
/// adds to the scan what only it can know: workflows that stopped running.
///
/// The copy in memory only moves forward once the file is written, so a scan
/// that cannot save is repeated by the next one instead of being lost.
async fn remember(
    source: &db::Source,
    store: &history::Store,
    history: &mut Option<History>,
    snapshot: &Snapshot,
    scan: &mut Scan,
    accepted: &[settings::Accepted],
    keep_days: u32,
) -> Result<(), String> {
    let mut next = match history {
        Some(history) => history.clone(),
        None => store.load()?,
    };
    let delta = source.read_executions(next.cursor, &next.pending).await?;
    let today = delta.today.clone();
    next.record_runs(delta);

    scan.findings
        .extend(radar::silent_workflows(&snapshot.workflows, &next.quiet()));
    radar::sort(&mut scan.findings);

    // The history keeps the score people see: without what they accepted.
    let score = web::score_without_accepted(&scan.findings, accepted);
    next.record_score(&today, score, keep_days);
    next.observe(
        scan.generated_at,
        &scan.findings,
        &snapshot.workflows,
        &snapshot.authors,
        keep_days,
    );
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
