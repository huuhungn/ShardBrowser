mod audit;
mod auth;
mod authz;
mod blob;
mod bootstrap;
mod cli;
mod config;
mod db;
mod error;
mod extract;
mod fleet;
mod fleet_generations;
mod generations;
mod grants;
mod idempotency;
mod identity;
mod integrity;
mod models;
mod quarantine;
mod ratelimit;
mod restore;
mod routes;
mod state;
mod util;

use std::net::SocketAddr;
use std::str::FromStr;

use anyhow::Context;

use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Non-UTF-8 arguments are a usage error, not a panic.
    let args: Result<Vec<String>, _> = std::env::args_os()
        .skip(1)
        .map(|a| a.into_string())
        .collect();
    let command = match args
        .map_err(|_| "arguments must be valid UTF-8".to_string())
        .and_then(|args| cli::parse(&args))
    {
        Ok(command) => command,
        Err(e) => {
            eprintln!("{e}\n\n{}", cli::USAGE);
            std::process::exit(2);
        }
    };
    if command != cli::Command::Serve {
        return cli::run(command).await;
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,shardx_team_server=debug")),
        )
        .init();

    let cfg = Config::from_env();
    let _lock = cli::lock_data_dir(&cfg.data_dir)?;
    if cfg.admin_pass == "admin" {
        tracing::warn!(
            "SHARDX_ADMIN_PASS is the default 'admin' — anyone reaching this \
             server can take it over; set a real password before exposing it"
        );
    }
    // ADR 0002 D-1: classify before any write. While a restore is in
    // progress the DB is opened read-only, so nothing (no migration, admin
    // bootstrap, blob GC, v1 or v2 write) changes it until `restore commit`
    // or `restore abort`; the server never resumes a restore itself.
    let (class, episode) = restore::startup_gate(&cfg).await?;
    if class.read_only() {
        // init_pool makes this check on a writable start; the count file is
        // written into the data directory, so only after it.
        db::refuse_network_storage(&cfg)?;
    }
    if let Some(aside) = audit::init_read_only_count(&cfg.data_dir, episode.as_deref())? {
        tracing::warn!(
            file = %aside.display(),
            "the audit failure count file was not understood; set aside, its valid lines kept"
        );
    }
    if let Some(episode) = &episode {
        // The incident output (ADR 0002 D-1): the failed audit writes of this episode.
        tracing::warn!(
            ?class,
            audit_write_failures = audit::read_only_failures(&cfg.data_dir, episode),
            "the database is opened read-only"
        );
    }
    let (pool, mut authority) = if class.read_only() {
        let pool = identity::open_read_only(&cfg).await?.with_context(|| {
            format!("a restore is in progress ({class:?}) and no database is at the DB path")
        })?;
        let refusal = identity::Refusal {
            code: identity::ReasonCode::ReconciliationRequired,
            detail: format!(
                "a restore is in progress ({class:?}, plan {}); the database is read-only; \
                 run `restore status`",
                class.row()
            ),
        };
        // K2 keeps the incident's own reason code (L2264, C-3).
        let authority = match class {
            restore::Class::K2 => {
                let mirror = identity::read_mirror(&pool).await?;
                identity::authority(&cfg, mirror.as_ref()).and(Err(refusal))
            }
            _ => Err(refusal),
        };
        (pool, authority)
    } else {
        let pool = db::init_pool(&cfg).await?;
        db::bootstrap_admin(&pool, &cfg).await?;
        blob::gc_orphans(&cfg, &pool).await;
        // The server only reads the record; it never creates or repairs it.
        let mirror = identity::read_mirror(&pool).await?;
        let authority = identity::authority(&cfg, mirror.as_ref());
        (pool, authority)
    };
    // ADR 0001 R1/R4: reconcile the control plane before any request runs.
    if let Ok(verified) = &authority {
        // A failed pass turns v2 writes off; it never stops v1.
        match integrity::run(&pool, verified).await {
            Ok(report) => {
                tracing::info!(?report, "v2 integrity pass");
                if let Some(refusal) = report.refusal() {
                    authority = Err(refusal);
                }
            }
            Err(e) => {
                authority = Err(identity::Refusal {
                    code: identity::ReasonCode::ControlPlaneIntegrityUntrusted,
                    detail: format!("the integrity pass failed: {e:#}"),
                })
            }
        }
    }
    // Plan L1216: no v2 write before every upload is reconciled.
    if let Ok(verified) = &authority {
        match routes::v2_upload_recovery::run(&pool, verified, &cfg.blob_dir).await {
            Ok(report) => tracing::info!(?report, "v2 upload reconciliation"),
            Err(e) => {
                authority = Err(identity::Refusal {
                    code: identity::ReasonCode::ControlPlaneIntegrityUntrusted,
                    detail: format!("the upload reconciliation failed: {e:#}"),
                })
            }
        }
    }
    match &authority {
        Ok(v) => tracing::info!(
            "server identity verified: instance {} epoch {}",
            identity::hex(&v.server_instance_id),
            v.restore_epoch
        ),
        Err(r) => tracing::warn!(
            "v2 writes disabled: {}: {}; v1 is unaffected",
            r.code.as_str(),
            r.detail
        ),
    }

    let state = AppState {
        db: pool,
        cfg: cfg.clone(),
        login_throttle: std::sync::Arc::new(ratelimit::LoginThrottle::new()),
        upload_slots: std::sync::Arc::new(tokio::sync::Semaphore::new(8)),
        download_slots: std::sync::Arc::new(tokio::sync::Semaphore::new(8)),
        authority: std::sync::Arc::new(authority),
    };
    // No CORS layer on purpose: the only client is the desktop launcher
    // (reqwest, no Origin). Browser-origin access stays blocked by default.
    let app = routes::router(state).layer(TraceLayer::new_for_http());

    let addr = SocketAddr::from_str(&cfg.bind)?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("ShardX Team Server listening on http://{addr}");
    // `into_make_service_with_connect_info` so handlers can read the peer IP
    // (the login throttle keys on it).
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}
