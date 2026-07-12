//! bridgefu — deployable SIP → Amazon Connect screen-pop gateway.
//!
//! Loads a YAML config, stands up the `rvoip-amazon-connect`
//! `ConnectScreenPopServer` (SIP UAS → header→attribute mapping →
//! StartWebRTCContact → Chime media bridge), and serves `/healthz` + `/metrics`,
//! until SIGTERM/SIGINT triggers a graceful shutdown.

mod api;
mod config;
mod context;
mod imds;
mod observability;
mod providers;
mod runtime;
mod screen_pop_evidence;

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rvoip_amazon_connect::ConnectScreenPopServer;

#[derive(Parser, Debug)]
#[command(name = "bridgefu", version, about = "SIP → Amazon Connect gateway")]
struct Args {
    /// Path to the YAML config file.
    #[arg(short, long, default_value = "/etc/bridgefu/bridgefu.yaml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Clone, Debug, Subcommand)]
enum Command {
    /// Run the configured Bridgefu process (the default).
    Run,
    /// Parse configuration, apply environment overrides, and exit.
    Validate,
    /// Print the effective configuration with all secrets redacted.
    PrintEffectiveConfig,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let cfg = config::Config::load(&args.config)?;

    match args.command.clone().unwrap_or(Command::Run) {
        Command::Validate => {
            println!("configuration is valid: {}", args.config.display());
            return Ok(());
        }
        Command::PrintEffectiveConfig => {
            print!("{}", config::Config::redacted_effective_yaml(&args.config)?);
            return Ok(());
        }
        Command::Run => {}
    }

    observability::init_tracing(&cfg.observability.log_level, &cfg.observability.log_format)?;
    let prom = observability::install_metrics()?;

    let tenants = cfg.tenant_names()?;
    tracing::info!(
        config = %args.config.display(),
        region = %cfg.aws.region,
        tenants = ?tenants,
        "starting bridgefu"
    );

    let http_bind: SocketAddr = cfg.observability.http_bind.parse().with_context(|| {
        format!(
            "invalid observability.http_bind: {}",
            cfg.observability.http_bind
        )
    })?;

    // Build the gateway from config (resolves AWS creds + any `auto` IPs).
    let server_cfg = cfg.into_server_config().await?;
    let server = ConnectScreenPopServer::build(server_cfg)
        .await
        .map_err(|e| anyhow::anyhow!("building gateway: {e}"))?;
    // Subscribe before `serve()` can emit the first INVITE lifecycle event.
    // The broadcast channel intentionally has no replay buffer for late
    // subscribers.
    let lifecycle_events = server.subscribe_lifecycle();

    observability::spawn_metrics_updater(server.clone(), tenants.clone());

    let generic_runtime = if cfg.generic_bridge.enabled {
        Some(runtime::GenericBridgeRuntime::start(&cfg.generic_bridge, &cfg.runtime).await?)
    } else {
        None
    };

    let api_state =
        api::ApiState::from_config(&cfg, server.clone(), prom, tenants, generic_runtime.clone())
            .await?;
    let (shutdown_tx, _) = tokio::sync::watch::channel(false);
    let mut lifecycle_task = screen_pop_evidence::spawn_lifecycle_ingest(
        lifecycle_events,
        api_state.screen_pop_evidence_store(),
        shutdown_tx.subscribe(),
    );
    let app = api::router(api_state);

    // Control/health/metrics HTTP server, shut down on the same signal as the gateway.
    let mut http = tokio::spawn(api::serve(
        http_bind,
        app,
        wait_for_shutdown(shutdown_tx.subscribe()),
    ));

    // Run the SIP→Connect gateway until a shutdown signal.
    tokio::select! {
        res = server.clone().serve() => {
            if let Err(e) = res {
                tracing::error!(error = %e, "gateway serve loop ended with error");
            } else {
                tracing::info!("gateway serve loop ended");
            }
        }
        _ = shutdown_signal() => {
            tracing::info!("shutdown signal received; stopping gateway");
        }
    }

    let _ = shutdown_tx.send(true);
    // The lifecycle consumer must stop before its store and API state are
    // dropped. Abort only as a bounded fallback for a runtime bug.
    if tokio::time::timeout(std::time::Duration::from_secs(3), &mut lifecycle_task)
        .await
        .is_err()
    {
        tracing::warn!("screen-pop lifecycle consumer did not stop; aborting task");
        lifecycle_task.abort();
        let _ = lifecycle_task.await;
    }

    // Give the HTTP server a moment to drain from the shared shutdown signal.
    if tokio::time::timeout(std::time::Duration::from_secs(3), &mut http)
        .await
        .is_err()
    {
        tracing::warn!("HTTP API did not drain; aborting task");
        http.abort();
        let _ = http.await;
    }
    if let Some(runtime) = generic_runtime {
        runtime
            .shutdown(std::time::Duration::from_secs(
                cfg.runtime.drain_timeout_secs,
            ))
            .await;
    }
    tracing::info!("bridgefu stopped");
    Ok(())
}

async fn wait_for_shutdown(mut shutdown: tokio::sync::watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    while shutdown.changed().await.is_ok() {
        if *shutdown.borrow() {
            return;
        }
    }
}

/// Resolves when the process receives SIGINT (Ctrl-C) or SIGTERM (systemd/Docker stop).
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let term = async {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = term => {}
    }
}
