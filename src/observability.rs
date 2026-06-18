//! Logging (tracing) + a small HTTP server exposing `/healthz` and `/metrics`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::{extract::State, routing::get, Router};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use rvoip_amazon_connect::ConnectScreenPopServer;
use tracing_subscriber::{prelude::*, EnvFilter};

/// Initialize tracing from the configured level + format (`json` | `pretty`).
pub fn init_tracing(level: &str, format: &str) -> Result<()> {
    let filter = EnvFilter::try_new(level)
        .with_context(|| format!("invalid log_level filter: {level}"))?;
    let registry = tracing_subscriber::registry().with(filter);
    match format {
        "pretty" => registry
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::stdout))
            .init(),
        _ => registry
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_writer(std::io::stdout),
            )
            .init(),
    }
    Ok(())
}

/// Install the Prometheus recorder as the process-global metrics recorder. This
/// captures both bridgefu's gauges and rvoip's internal `metrics` counters.
pub fn install_metrics() -> Result<PrometheusHandle> {
    PrometheusBuilder::new()
        .install_recorder()
        .context("installing Prometheus recorder")
}

/// Serve `/healthz` (liveness) and `/metrics` (Prometheus) until `shutdown`.
pub async fn serve_http(
    bind: SocketAddr,
    handle: PrometheusHandle,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route(
            "/metrics",
            get(|State(h): State<PrometheusHandle>| async move { h.render() }),
        )
        .with_state(handle);

    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("binding observability HTTP on {bind}"))?;
    tracing::info!(%bind, "observability HTTP server listening (/healthz, /metrics)");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .context("observability HTTP server")
}

/// Periodically publish the adapter's counters as Prometheus gauges.
pub fn spawn_metrics_updater(server: Arc<ConnectScreenPopServer>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(10));
        loop {
            tick.tick().await;
            let m = server.adapter().metrics();
            metrics::gauge!("bridgefu_active_sessions").set(m.active_sessions as f64);
            metrics::gauge!("bridgefu_contacts_started_total").set(m.contacts_started as f64);
            metrics::gauge!("bridgefu_failures_total").set(m.failures as f64);
        }
    });
}
