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

    observability::spawn_metrics_updater(server.clone(), tenants.clone());

    let generic_runtime = if cfg.generic_bridge.enabled {
        Some(runtime::GenericBridgeRuntime::start(&cfg.generic_bridge, &cfg.runtime).await?)
    } else {
        None
    };

    let api_state =
        api::ApiState::from_config(&cfg, server.clone(), prom, tenants, generic_runtime.clone())?;
    let app = api::router(api_state);

    // Control/health/metrics HTTP server, shut down on the same signal as the gateway.
    let http = tokio::spawn(api::serve(http_bind, app, shutdown_signal()));

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

    // Give the HTTP server a moment to drain (its own shutdown future fires too).
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), http).await;
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
