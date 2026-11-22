//! nbuddyn: a tiny, read-only cockpit for self-hosted n8n.

mod alerts;
mod auth;
mod cluster;
mod db;
mod demo;
mod history;
mod http;
mod i18n;
mod mcp;
mod model;
mod oidc;
mod radar;
mod runners;
mod settings;
mod sqlite;
mod tls;
mod vault;
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
    /// Seals the secrets nbuddyn stores. `None` makes nbuddyn keep its own key.
    secret_key: Option<String>,
    /// Signing in with the company's accounts. `None` leaves it off.
    oidc: Option<oidc::Config>,
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

        tls::load_extra_roots(var("NBUDDYN_CA_FILE").as_deref())?;

        let oidc = match var("NBUDDYN_OIDC_ISSUER") {
            None => None,
            Some(issuer) => {
                let need = |name: &str| {
                    var(name).ok_or(format!("{name} is required with NBUDDYN_OIDC_ISSUER"))
                };
                let public = need("NBUDDYN_PUBLIC_URL")?;
                if !(public.starts_with("https://")
                    || public.starts_with("http://127.0.0.1")
                    || public.starts_with("http://localhost"))
                {
                    return Err(
                        "NBUDDYN_PUBLIC_URL must be the https address people open nbuddyn at"
                            .into(),
                    );
                }
                let config = oidc::Config {
                    issuer: issuer.trim_end_matches('/').to_owned(),
                    client_id: need("NBUDDYN_OIDC_CLIENT_ID")?,
                    client_secret: need("NBUDDYN_OIDC_CLIENT_SECRET")?,
                    redirect_uri: format!("{}/auth/oidc/callback", public.trim_end_matches('/')),
                    name: var("NBUDDYN_OIDC_NAME").unwrap_or_else(|| "SSO".into()),
                    admins: oidc::parse_people(&var("NBUDDYN_OIDC_ADMINS").unwrap_or_default()),
                    viewers: oidc::parse_people(&var("NBUDDYN_OIDC_VIEWERS").unwrap_or_default()),
                };
                if config.admins.is_empty() && config.viewers.is_empty() {
                    return Err(
                        "NBUDDYN_OIDC_ADMINS or NBUDDYN_OIDC_VIEWERS must name who may sign in: \
                         e-mail addresses, or @domain for a whole domain"
                            .into(),
                    );
                }
                Some(config)
            }
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
            telegram_token: var("NBUDDYN_TELEGRAM_TOKEN").unwrap_or_default(),
            telegram_chat: var("NBUDDYN_TELEGRAM_CHAT").unwrap_or_default(),
            telegram_api: var("NBUDDYN_TELEGRAM_API").unwrap_or_default(),
            webhook_url: var("NBUDDYN_WEBHOOK_URL").unwrap_or_default(),
            alert_level: var("NBUDDYN_ALERT_LEVEL").unwrap_or_default(),
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
            secret_key: var("NBUDDYN_SECRET_KEY"),
            oidc,
            data_dir: var("NBUDDYN_DATA_DIR"),
            defaults,
        })
    }
}

/// `nbuddyn check`: reads n8n once, says what it found and what is missing,
/// and exits. For trying a database address before running nbuddyn, and for
/// the tests that run against every supported n8n version.
async fn check() -> ExitCode {
    let Some(url) = env::var("NBUDDYN_DATABASE_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
    else {
        eprintln!("nbuddyn check: NBUDDYN_DATABASE_URL is required");
        return ExitCode::from(2);
    };
    println!("database: {}", db::label(&url));
    let source = match db::connect(&url, None).await {
        Ok(source) => source,
        Err(reason) => {
            eprintln!("cannot connect: {reason}");
            return ExitCode::from(1);
        }
    };
    match source.preflight().await {
        Ok(preflight) if preflight.ok() => {
            println!("schema: every table and column nbuddyn needs is readable")
        }
        Ok(preflight) => {
            eprintln!("schema: {}", preflight.explain());
            return ExitCode::from(1);
        }
        Err(reason) => {
            eprintln!("schema: could not be inspected: {reason}");
            return ExitCode::from(1);
        }
    }
    let snapshot = match source.read_snapshot().await {
        Ok(snapshot) => snapshot,
        Err(reason) => {
            eprintln!("read failed: {reason}");
            return ExitCode::from(1);
        }
    };
    let scan = evaluate(&snapshot);
    println!(
        "read: {} workflows ({} active), {} credentials, {} users",
        scan.inventory.workflows,
        scan.inventory.active,
        scan.inventory.credentials,
        scan.inventory.users
    );
    println!(
        "findings: {} · score {}",
        scan.findings.len(),
        radar::score(&scan.findings)
    );
    match source.read_executions(0, &[]).await {
        Ok(delta) => println!(
            "executions: read up to #{} ({} groups finished, {} unfinished)",
            delta.upto,
            delta.finished.len(),
            delta.unfinished.len()
        ),
        Err(reason) => {
            eprintln!("executions could not be read: {reason}");
            return ExitCode::from(1);
        }
    }
    println!("ok: tested with n8n {}", db::TESTED_WITH);
    ExitCode::SUCCESS
}

#[tokio::main]
async fn main() -> ExitCode {
    match env::args().nth(1).as_deref() {
        Some("check") => return check().await,
        Some("demo") => {
            // A made-up n8n in a temporary folder, and settings to match.
            // Anything already set in the environment is left as it is.
            // Inside the image the only place nbuddyn may write is its data
            // directory; elsewhere a temporary folder does.
            let dir = match env::var("NBUDDYN_DATA_DIR") {
                Ok(data) if !data.trim().is_empty() => std::path::PathBuf::from(data).join("demo"),
                _ => env::temp_dir().join("nbuddyn-demo"),
            };
            let file = dir.join("database.sqlite");
            if let Err(reason) = std::fs::create_dir_all(&dir)
                .map_err(|e| e.to_string())
                .and_then(|()| demo::build(&file))
            {
                eprintln!("nbuddyn demo: {reason}");
                return ExitCode::from(1);
            }
            let _ = std::fs::remove_dir_all(dir.join("data"));
            let defaults = [
                ("NBUDDYN_DATABASE_URL", format!("sqlite:{}", file.display())),
                ("NBUDDYN_DATA_DIR", dir.join("data").display().to_string()),
                ("NBUDDYN_USER", "demo".to_owned()),
                ("NBUDDYN_PASSWORD", "demo".to_owned()),
                ("NBUDDYN_NAME", "Demo n8n".to_owned()),
                ("NBUDDYN_N8N_URL", "https://n8n.example.com".to_owned()),
            ];
            for (name, value) in defaults {
                // The data directory is always the demo's own, so a demo
                // never touches a real history.
                if name == "NBUDDYN_DATA_DIR"
                    || name == "NBUDDYN_DATABASE_URL"
                    || env::var(name).is_err()
                {
                    env::set_var(name, value);
                }
            }
            println!("nbuddyn demo: a made-up n8n. Open the page and sign in as demo / demo.");
        }
        _ => {}
    }
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(message) => {
            eprintln!("nbuddyn: {message}");
            return ExitCode::from(2);
        }
    };

    // Saved settings that cannot be read are left alone: nbuddyn runs on its
    // starting values and refuses to save until someone looks at the file.
    let vault = match config.data_dir.as_deref() {
        None => None,
        Some(dir) => match vault::Vault::open(config.secret_key.as_deref(), dir.as_ref()) {
            Ok(vault) => Some((dir, Arc::new(vault))),
            Err(reason) => {
                eprintln!("nbuddyn: {reason}");
                return ExitCode::from(2);
            }
        },
    };
    let store = vault.map(|(dir, vault)| settings::Store::new(dir, vault));
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
        auth: auth::Auth::new(
            config.user.clone(),
            config.password.clone(),
            config.data_dir.as_deref().map(std::path::PathBuf::from),
        ),
        mcp_token: config.mcp_token.clone(),
        oidc: config.oidc.map(oidc::Oidc::new),
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
    // Scans in a row that could not read each instance, to alert on the third
    // and again when it comes back.
    let mut failures: HashMap<String, u32> = HashMap::new();
    // When each finding last alerted, so one that flaps does not nag.
    let mut alerted: HashMap<String, u64> = HashMap::new();
    loop {
        let effective = state.effective().await;
        for instance in &effective.instances {
            let runtime = state.runtime(&instance.id).await;
            let store = data_dir
                .as_deref()
                .map(|dir| history::Store::new(dir, &instance.id));
            let scanned = scan_once(
                &state,
                &runtime,
                instance,
                store.as_ref(),
                effective.history_days,
            )
            .await;
            let failed_before = failures.get(&instance.id).copied().unwrap_or(0);
            let message = match scanned {
                Ok((scan, mut events)) => {
                    println!(
                        "scan ok: {}: {} findings",
                        instance.name,
                        scan.findings.len()
                    );
                    let now = scan.generated_at;
                    events.retain(|e| {
                        if e.kind != "finding_new" {
                            return true;
                        }
                        let key = format!(
                            "{}|{:?}|{:?}|{:?}",
                            instance.id, e.check, e.workflow, e.node
                        );
                        let recent = alerted
                            .get(&key)
                            .is_some_and(|at| now.saturating_sub(*at) < ALERT_AGAIN_AFTER);
                        alerted.insert(key, now);
                        !recent
                    });
                    alerted.retain(|_, at| now.saturating_sub(*at) < ALERT_AGAIN_AFTER);
                    let score = web::score_without_accepted(
                        &scan.findings,
                        &state.saved.read().await.accepted_valid(&instance.id, now),
                    );
                    *runtime.latest.write().await = Some(scan);
                    *runtime.last_error.write().await = None;
                    failures.remove(&instance.id);
                    if failed_before >= FAILURES_TO_ALERT {
                        Some(alerts::compose_reachability(
                            effective.lang,
                            &instance.name,
                            None,
                        ))
                    } else {
                        alerts::compose(
                            &effective.alerts,
                            effective.lang,
                            &instance.name,
                            &instance.n8n_url,
                            &events,
                            score,
                        )
                    }
                }
                Err(reason) => {
                    eprintln!("scan failed: {}: {reason}", instance.name);
                    failures.insert(instance.id.clone(), failed_before + 1);
                    let message = (failed_before + 1 == FAILURES_TO_ALERT).then(|| {
                        alerts::compose_reachability(effective.lang, &instance.name, Some(&reason))
                    });
                    *runtime.last_error.write().await = Some(reason);
                    message
                }
            };
            if let Some(message) = message.filter(|_| effective.alerts.enabled()) {
                // Sent on the side: a slow chat must not hold up the next scan.
                let destinations = effective.alerts.clone();
                tokio::spawn(async move {
                    for problem in alerts::deliver(&destinations, &message).await {
                        eprintln!("alert not delivered: {problem}");
                    }
                });
            }
        }
        failures.retain(|id, _| effective.instances.iter().any(|i| i.id == *id));
        state.forget_runtimes_except(&effective.instances).await;
        tokio::select! {
            () = tokio::time::sleep(effective.interval) => {}
            () = state.rescan.notified() => {}
        }
    }
}

/// Failed scans in a row before saying an instance cannot be read.
const FAILURES_TO_ALERT: u32 = 3;
/// A finding that comes back sooner than this after alerting stays quiet.
const ALERT_AGAIN_AFTER: u64 = 6 * 3600;

async fn scan_once(
    state: &AppState,
    runtime: &Runtime,
    instance: &Instance,
    store: Option<&history::Store>,
    history_days: u32,
) -> Result<(Scan, Vec<history::Event>), String> {
    let source = db::connect(&instance.database_url, instance.timezone.as_deref()).await?;
    let mut snapshot = match source.read_snapshot().await {
        Ok(snapshot) => snapshot,
        // A failed read gets a second look that says why in plain words: a
        // missing grant with the SQL to fix it, or a version nbuddyn does
        // not know.
        Err(reason) => {
            return Err(match source.preflight().await {
                Ok(preflight) if !preflight.ok() => preflight.explain(),
                _ => reason,
            })
        }
    };

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
    let policy = state.saved.read().await.policy.clone();
    radar::apply_policy(&mut scan.findings, &policy);
    let mut events = Vec::new();

    if let Some(store) = store {
        let accepted = state
            .saved
            .read()
            .await
            .accepted_valid(&instance.id, scan.generated_at);
        let outcome = remember(
            &source,
            store,
            &runtime.history,
            &snapshot,
            &mut scan,
            (&accepted, &policy),
            history_days,
        )
        .await;
        let outcome = match outcome {
            Ok(changed) => {
                events = changed;
                None
            }
            Err(reason) => {
                eprintln!("history not updated: {}: {reason}", instance.name);
                Some(reason)
            }
        };
        *runtime.history_error.write().await = outcome;
    }
    Ok((scan, events))
}

/// Brings the history up to this scan and saves it: the executions that
/// finished since the last one, the score, and what changed. The history also
/// adds to the scan what only it can know: workflows that stopped running.
///
/// The history is changed where it is kept, never copied: on a big instance
/// it is the largest thing nbuddyn holds. If writing it fails it is still
/// right in memory, and the next scan writes it again.
async fn remember(
    source: &db::Source,
    store: &history::Store,
    history: &RwLock<Option<History>>,
    snapshot: &Snapshot,
    scan: &mut Scan,
    (accepted, policy): (
        &[settings::Accepted],
        &std::collections::BTreeMap<String, String>,
    ),
    keep_days: u32,
) -> Result<Vec<history::Event>, String> {
    // Read from disk the first time, and again after a failed load.
    if history.read().await.is_none() {
        let loaded = store.load()?;
        *history.write().await = Some(loaded);
    }
    let (cursor, pending) = match history.read().await.as_ref() {
        Some(history) => (history.cursor, history.pending.clone()),
        None => (0, Vec::new()),
    };
    // The slow part, reading n8n, happens without holding the history.
    let delta = source.read_executions(cursor, &pending).await?;
    let today = delta.today.clone();

    let (events, encoded) = {
        let mut guard = history.write().await;
        let history = guard.get_or_insert_with(History::default);
        history.record_runs(delta);
        scan.findings.extend(radar::silent_workflows(
            &snapshot.workflows,
            &history.quiet(),
        ));
        radar::sort(&mut scan.findings);
        radar::apply_policy(&mut scan.findings, policy);
        // The history keeps the score people see: without what they accepted.
        let score = web::score_without_accepted(&scan.findings, accepted);
        history.record_score(&today, score, keep_days);
        let events = history.observe(
            scan.generated_at,
            &scan.findings,
            &snapshot.workflows,
            &snapshot.authors,
            keep_days,
        );
        (events, history::Store::encode(history)?)
    };
    store.write(&encoded)?;
    Ok(events)
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
        credentials: credential_map(snapshot),
        findings,
    }
}

/// Which workflows use each credential, most used first.
fn credential_map(snapshot: &Snapshot) -> Vec<web::CredentialUse> {
    let mut map: Vec<web::CredentialUse> = snapshot
        .credentials
        .iter()
        .map(|credential| web::CredentialUse {
            name: credential.name.clone(),
            kind: credential.kind.clone(),
            workflows: snapshot
                .workflows
                .iter()
                .filter(|wf| !wf.archived)
                .filter_map(|wf| {
                    let nodes = wf
                        .nodes
                        .iter()
                        .filter(|n| n.credential_ids.contains(&credential.id))
                        .count();
                    (nodes > 0).then(|| web::CredentialWorkflow {
                        name: wf.name.clone(),
                        active: wf.active,
                        nodes,
                        path: radar::workflow_path(&wf.id),
                    })
                })
                .collect(),
        })
        .collect();
    map.sort_by(|a, b| {
        b.workflows
            .len()
            .cmp(&a.workflows.len())
            .then_with(|| a.name.cmp(&b.name))
    });
    map
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
