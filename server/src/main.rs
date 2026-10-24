mod audit;
mod auth;
mod authz;
mod blob;
mod cli;
mod config;
mod db;
mod enrollment;
mod error;
mod extract;
mod fleet;
mod fleet_generations;
mod fleet_grants;
mod generations;
mod grants;
mod idempotency;
mod identity;
mod models;
mod ratelimit;
mod routes;
mod state;
mod util;

use std::net::SocketAddr;
use std::str::FromStr;

use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = match cli::parse(&args) {
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
    let pool = db::init_pool(&cfg).await?;
    db::bootstrap_admin(&pool, &cfg).await?;
    blob::gc_orphans(&cfg, &pool).await;

    // The server only reads the record; it never creates or repairs it.
    let mirror = identity::read_mirror(&pool).await?;
    let authority = identity::authority(&cfg, mirror.as_ref());
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
