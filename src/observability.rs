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

/// Serve `/healthz` (liveness + loaded tenants, CONTRACTS.md B.4) and
/// `/metrics` (Prometheus) until `shutdown`.
pub async fn serve_http(
    bind: SocketAddr,
    handle: PrometheusHandle,
    tenants: Vec<String>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    // The tenant set is fixed for the process lifetime (the reconciler
    // restarts bridgefu on config change), so the body is pre-rendered.
    let healthz = serde_json::json!({ "ok": true, "tenants": tenants }).to_string();
    let app = Router::new()
        .route(
            "/healthz",
            get(move || async move {
                (
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    healthz,
                )
            }),
        )
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

/// Periodically publish the per-tenant route counters as Prometheus gauges
/// (`tenant` label, CONTRACTS.md B.4). Every configured tenant is pre-seeded
/// so its series exist from startup.
pub fn spawn_metrics_updater(server: Arc<ConnectScreenPopServer>, tenants: Vec<String>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(10));
        loop {
            tick.tick().await;
            let stats = server.route_metrics();
            for tenant in &tenants {
                let m = stats.get(tenant).cloned().unwrap_or_default();
                metrics::gauge!("bridgefu_active_sessions", "tenant" => tenant.clone())
                    .set(m.active_sessions as f64);
                metrics::gauge!("bridgefu_contacts_started_total", "tenant" => tenant.clone())
                    .set(m.contacts_started as f64);
                metrics::gauge!("bridgefu_failures_total", "tenant" => tenant.clone())
                    .set(m.failures as f64);
            }
        }
    });
}
