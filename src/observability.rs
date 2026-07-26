//! Structured stdout logging, optional OTLP traces, and process metrics.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use opentelemetry::global;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{
    BatchConfigBuilder, BatchSpanProcessor, Sampler, SdkTracerProvider,
};
use opentelemetry_sdk::Resource;
use rvoip_amazon_connect::{ConnectScreenPopServer, RouteMetrics};
use serde::Serialize;
use serde_json::{json, Value};
use tokio::sync::watch;
use tracing_subscriber::{prelude::*, util::SubscriberInitExt, EnvFilter};

use crate::config::{ObsCfg, OtlpTracingCfg, RuntimeMode};

/// Aggregate process lifecycle exposed by role-specific operational servers.
///
/// The all-in-one compatibility path retains its existing API health behavior;
/// this state is used by split worker and, once implemented, gateway/relay
/// processes so readiness follows their concrete dependencies.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RoleLifecycle {
    Starting,
    Ready,
    Degraded,
    Draining,
    Stopped,
    Failed,
}

impl RoleLifecycle {
    #[must_use]
    pub const fn is_ready(self) -> bool {
        matches!(self, Self::Ready)
    }

    #[must_use]
    pub const fn is_live(self) -> bool {
        !matches!(self, Self::Stopped | Self::Failed)
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Ready => "ready",
            Self::Degraded => "degraded",
            Self::Draining => "draining",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
        }
    }

    const fn is_terminal(self) -> bool {
        matches!(self, Self::Stopped | Self::Failed)
    }
}

/// Cloneable, aggregate-safe process health handle.
#[derive(Clone, Debug)]
pub struct RoleHealth {
    mode: RuntimeMode,
    state: watch::Sender<RoleLifecycle>,
}

impl RoleHealth {
    #[must_use]
    pub fn new(mode: RuntimeMode) -> Self {
        let (state, _) = watch::channel(RoleLifecycle::Starting);
        metrics::gauge!("bridgefu_process_ready", "role" => mode.as_str()).set(0.0);
        Self { mode, state }
    }

    #[must_use]
    pub const fn mode(&self) -> RuntimeMode {
        self.mode
    }

    #[must_use]
    pub fn current(&self) -> RoleLifecycle {
        *self.state.borrow()
    }

    /// Move to a new lifecycle state. Terminal states are sticky so cleanup
    /// cannot accidentally turn a failed process into a healthy one.
    pub fn transition(&self, next: RoleLifecycle) {
        let current = self.current();
        if current == next || current.is_terminal() {
            return;
        }
        self.state.send_replace(next);
        metrics::gauge!("bridgefu_process_ready", "role" => self.mode.as_str())
            .set(if next.is_ready() { 1.0 } else { 0.0 });
        metrics::counter!(
            "bridgefu_process_lifecycle_transitions_total",
            "role" => self.mode.as_str(),
            "state" => next.as_str()
        )
        .increment(1);
    }
}

#[derive(Clone)]
struct RoleHttpState {
    health: RoleHealth,
    metrics: PrometheusHandle,
}

/// Owns the optional OTLP provider so the process can flush and stop its
/// bounded exporter on every post-initialization exit path.
pub struct TracingGuard {
    provider: Option<SdkTracerProvider>,
    shutdown_timeout: Duration,
}

impl TracingGuard {
    /// Flush pending spans and stop the provider. Shutdown is synchronous and
    /// bounded by the configured exporter timeout.
    pub fn shutdown(mut self) -> Result<()> {
        self.shutdown_inner()
    }

    fn shutdown_inner(&mut self) -> Result<()> {
        let Some(provider) = self.provider.take() else {
            return Ok(());
        };
        // The SDK batch processor's shutdown operation first exports every
        // queued span, then stops its exporter/background thread. Using the
        // timeout-aware operation makes that combined flush+shutdown one
        // bounded lifecycle step.
        provider
            .shutdown_with_timeout(self.shutdown_timeout)
            .map_err(|shutdown| {
                anyhow::anyhow!("flushing and shutting down OTLP trace provider: {shutdown}")
            })
    }
}

impl Drop for TracingGuard {
    fn drop(&mut self) {
        // Explicit shutdown in `main` reports errors. This is the panic/early
        // return safety net and deliberately cannot emit a tracing event after
        // the subscriber/provider may already be unwinding.
        let _ = self.shutdown_inner();
    }
}

/// Initialize stdout tracing plus optional OTLP/gRPC export. Prometheus uses
/// its existing independent recorder and is never routed through OTLP.
pub fn init_tracing(config: &ObsCfg) -> Result<TracingGuard> {
    let filter = EnvFilter::try_new(&config.log_level)
        .with_context(|| format!("invalid log_level filter: {}", config.log_level))?;
    let provider = build_otlp_provider(&config.otlp)?;

    match config.log_format.as_str() {
        "pretty" => {
            let telemetry = provider.as_ref().map(|provider| {
                tracing_opentelemetry::layer().with_tracer(provider.tracer("bridgefu"))
            });
            tracing_subscriber::registry()
                .with(filter)
                .with(tracing_subscriber::fmt::layer().with_writer(std::io::stdout))
                .with(telemetry)
                .try_init()
                .context("installing tracing subscriber")?;
        }
        _ => {
            let telemetry = provider.as_ref().map(|provider| {
                tracing_opentelemetry::layer().with_tracer(provider.tracer("bridgefu"))
            });
            tracing_subscriber::registry()
                .with(filter)
                .with(
                    tracing_subscriber::fmt::layer()
                        .json()
                        .with_writer(std::io::stdout),
                )
                .with(telemetry)
                .try_init()
                .context("installing tracing subscriber")?;
        }
    }

    install_w3c_propagation();
    if let Some(provider) = provider.as_ref() {
        global::set_tracer_provider(provider.clone());
        tracing::info!(
            service_name = %config.otlp.service_name,
            sampling_ratio = config.otlp.sampling_ratio,
            max_queue_size = config.otlp.max_queue_size,
            max_export_batch_size = config.otlp.max_export_batch_size,
            "OTLP trace export enabled"
        );
    }

    Ok(TracingGuard {
        provider,
        shutdown_timeout: Duration::from_millis(config.otlp.export_timeout_millis),
    })
}

fn install_w3c_propagation() {
    global::set_text_map_propagator(TraceContextPropagator::new());
}

fn build_otlp_provider(config: &OtlpTracingCfg) -> Result<Option<SdkTracerProvider>> {
    config.validate().context("validating OTLP tracing")?;
    if !config.enabled {
        return Ok(None);
    }
    let endpoint = config
        .endpoint
        .as_deref()
        .context("OTLP tracing enabled without a collector endpoint")?;
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .with_timeout(Duration::from_millis(config.export_timeout_millis))
        .build()
        .context("building OTLP/gRPC span exporter")?;
    let batch = BatchSpanProcessor::builder(exporter)
        .with_batch_config(
            BatchConfigBuilder::default()
                .with_max_queue_size(config.max_queue_size)
                .with_max_export_batch_size(config.max_export_batch_size)
                .with_scheduled_delay(Duration::from_millis(config.scheduled_delay_millis))
                .build(),
        )
        .build();
    let resource = Resource::builder()
        .with_service_name(config.service_name.clone())
        .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
        .build();
    let provider = SdkTracerProvider::builder()
        .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
            config.sampling_ratio,
        ))))
        .with_resource(resource)
        .with_span_processor(batch)
        .build();
    Ok(Some(provider))
}

/// Install the Prometheus recorder as the process-global metrics recorder. This
/// captures both bridgefu's gauges and rvoip's internal `metrics` counters.
pub fn install_metrics() -> Result<PrometheusHandle> {
    PrometheusBuilder::new()
        .install_recorder()
        .context("installing Prometheus recorder")
}

/// Health/metrics-only router for non-gateway roles. It deliberately exposes
/// no control API, provider webhook, SIP, or WebRTC route.
pub fn role_health_router(health: RoleHealth, metrics: PrometheusHandle) -> Router {
    Router::new()
        .route("/healthz", get(role_ready))
        .route("/livez", get(role_live))
        .route("/readyz", get(role_ready))
        .route("/metrics", get(role_metrics))
        .with_state(RoleHttpState { health, metrics })
}

/// Serve an already-bound operational listener. Binding happens before a role
/// becomes ready so a bad address or occupied port fails startup closed.
pub async fn serve_role_health(
    listener: tokio::net::TcpListener,
    app: Router,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let bind = listener
        .local_addr()
        .context("reading operational listener address")?;
    tracing::info!(%bind, "Bridgefu role health server listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .context("serving role health endpoint")
}

async fn role_live(State(state): State<RoleHttpState>) -> (StatusCode, Json<Value>) {
    let lifecycle = state.health.current();
    let status = if lifecycle.is_live() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(json!({
            "ok": lifecycle.is_live(),
            "mode": state.health.mode().as_str(),
            "state": lifecycle,
        })),
    )
}

async fn role_ready(State(state): State<RoleHttpState>) -> (StatusCode, Json<Value>) {
    let lifecycle = state.health.current();
    let status = if lifecycle.is_ready() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(json!({
            "ok": lifecycle.is_ready(),
            "mode": state.health.mode().as_str(),
            "state": lifecycle,
        })),
    )
}

async fn role_metrics(State(state): State<RoleHttpState>) -> String {
    state.metrics.render()
}

/// Periodically publish the per-tenant route counters as Prometheus gauges
/// (`tenant` label, CONTRACTS.md B.4). Every configured tenant is pre-seeded
/// so its series exist from startup.
pub fn spawn_metrics_updater(
    server: Arc<ConnectScreenPopServer>,
    tenants: Vec<String>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    spawn_metrics_updater_with(tenants, shutdown, Duration::from_secs(10), move || {
        server.route_metrics()
    })
}

fn spawn_metrics_updater_with<F>(
    tenants: Vec<String>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    interval: Duration,
    snapshot: F,
) -> tokio::task::JoinHandle<()>
where
    F: Fn() -> BTreeMap<String, RouteMetrics> + Send + Sync + 'static,
{
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        loop {
            tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                    continue;
                }
                _ = tick.tick() => {}
            }
            let stats = snapshot();
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;

    const RELEASE_METRICS: &[(&str, &[&str])] = &[
        ("bridgefu_process_ready", &["role"]),
        (
            "bridgefu_process_lifecycle_transitions_total",
            &["role", "state"],
        ),
        ("bridgefu_active_sessions", &["tenant"]),
        ("bridgefu_contacts_started_total", &["tenant"]),
        ("bridgefu_failures_total", &["tenant"]),
        ("bridgefu_calls_routed_total", &["tenant"]),
        ("bridgefu_unknown_tenant_total", &[]),
        ("bridgefu_auth_failures_total", &["surface"]),
        ("bridgefu_call_operations_total", &["operation", "result"]),
        ("bridgefu_attachment_admission_total", &["result"]),
        (
            "bridgefu_standardcharter_canary_admission_total",
            &["result"],
        ),
        ("bridgefu_transfer_status_total", &["transport", "result"]),
        ("bridgefu_operational_ephemeral_total", &["kind"]),
        (
            "bridgefu_context_data_messages_total",
            &["result", "reason"],
        ),
        ("bridgefu_initial_context_total", &["result", "reason"]),
        ("bridgefu_active_broadcasts", &["transport"]),
        (
            "bridgefu_broadcast_commands_total",
            &["operation", "result"],
        ),
        (
            "bridgefu_sanitized_broadcast_events_total",
            &["result", "reason"],
        ),
        ("bridgefu_provider_webhooks_total", &["provider", "result"]),
        ("bridgefu_provider_circuit_open", &["provider"]),
        ("bridgefu_provider_circuit_rejections_total", &["provider"]),
        (
            "bridgefu_provider_circuit_transitions_total",
            &["provider", "state"],
        ),
        (
            "bridgefu_api_rate_limit_requests_total",
            &["surface", "outcome"],
        ),
        ("bridgefu_api_rate_limit_tracked_identities", &[]),
        ("bridgefu_gateway_native_ingress_ready", &[]),
        ("bridgefu_gateway_native_active_routes", &[]),
        ("bridgefu_gateway_native_admissions_total", &["outcome"]),
        (
            "bridgefu_gateway_native_media_dropped_total",
            &["direction"],
        ),
        ("bridgefu_gateway_native_route_failures_total", &["reason"]),
        (
            "bridgefu_gateway_native_rtcp_terminated_total",
            &["direction"],
        ),
        ("bridgefu_gateway_native_unsupported_total", &["operation"]),
        ("bridgefu_gateway_public_uctp_ready", &[]),
        (
            "bridgefu_gateway_public_uctp_admissions_total",
            &["outcome"],
        ),
        (
            "bridgefu_gateway_public_uctp_media_dropped_total",
            &["direction"],
        ),
        (
            "bridgefu_gateway_public_uctp_route_failures_total",
            &["reason"],
        ),
        (
            "bridgefu_gateway_public_uctp_control_dropped_total",
            &["direction"],
        ),
        ("bridgefu_private_forwarding_worker_ready", &[]),
        ("bridgefu_private_forwarding_active_routes", &[]),
        ("bridgefu_private_forwarding_peer_connections", &[]),
        ("bridgefu_private_forwarding_routes_total", &["outcome"]),
        ("bridgefu_private_forwarding_packets_total", &["direction"]),
        ("bridgefu_private_forwarding_drops_total", &["reason"]),
        ("bridgefu_amazon_durable_cleanups_pending", &[]),
        ("bridgefu_amazon_cleanup_reconcile_failures_total", &[]),
        ("bridgefu_amazon_pending_contact_cleanups", &[]),
        ("bridgefu_legacy_drain_incomplete", &[]),
        ("bridgefu_screen_pop_evidence_entries", &[]),
        (
            "bridgefu_screen_pop_evidence_records_total",
            &["stage", "result"],
        ),
        ("bridgefu_screen_pop_evidence_evictions_total", &["reason"]),
        ("bridgefu_screen_pop_evidence_lookups_total", &["result"]),
        (
            "bridgefu_screen_pop_lifecycle_events_total",
            &["stage", "result"],
        ),
        ("bridgefu_screen_pop_lifecycle_errors_total", &["error"]),
        ("bridgefu_screen_pop_lifecycle_lag_seconds", &["stage"]),
    ];

    fn test_metrics() -> PrometheusHandle {
        PrometheusBuilder::new().build_recorder().handle()
    }

    #[tokio::test]
    async fn metrics_updater_is_owned_and_joins_on_shutdown() {
        let snapshots = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&snapshots);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = spawn_metrics_updater_with(
            vec!["tenant-a".into()],
            shutdown_rx,
            Duration::from_secs(3_600),
            move || {
                observed.fetch_add(1, Ordering::SeqCst);
                BTreeMap::new()
            },
        );

        tokio::time::timeout(Duration::from_secs(1), async {
            while snapshots.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("initial metrics snapshot");
        shutdown_tx.send_replace(true);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("metrics updater shutdown deadline")
            .expect("metrics updater task");
    }

    #[test]
    fn disabled_otlp_constructs_no_provider() {
        let config = OtlpTracingCfg::default();
        assert!(build_otlp_provider(&config).unwrap().is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn enabled_otlp_provider_construction_is_lazy_and_shutdown_is_bounded() {
        let config = OtlpTracingCfg {
            enabled: true,
            // Exporter construction is lazy. The reserved `.invalid` endpoint
            // proves the production TLS path builds without network access.
            endpoint: Some("https://collector.invalid:4317".into()),
            service_name: "bridgefu-provider-test".into(),
            export_timeout_millis: 250,
            ..OtlpTracingCfg::default()
        };
        let provider = build_otlp_provider(&config).unwrap().unwrap();
        TracingGuard {
            provider: Some(provider),
            shutdown_timeout: Duration::from_millis(config.export_timeout_millis),
        }
        .shutdown()
        .unwrap();
    }

    #[test]
    fn installs_w3c_trace_context_propagation() {
        install_w3c_propagation();
        let fields = global::get_text_map_propagator(|propagator| {
            propagator.fields().map(str::to_owned).collect::<Vec<_>>()
        });
        assert!(fields.iter().any(|field| field == "traceparent"));
        assert!(fields.iter().any(|field| field == "tracestate"));
    }

    #[tokio::test]
    async fn role_readiness_tracks_concrete_lifecycle() {
        let health = RoleHealth::new(RuntimeMode::Worker);
        let app = role_health_router(health.clone(), test_metrics());

        let ready = app
            .clone()
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);

        health.transition(RoleLifecycle::Ready);
        let ready = app
            .clone()
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(ready.status(), StatusCode::OK);

        health.transition(RoleLifecycle::Draining);
        let ready = app
            .clone()
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let live = app
            .oneshot(Request::get("/livez").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(live.status(), StatusCode::OK);
    }

    #[test]
    fn terminal_failure_is_sticky() {
        let health = RoleHealth::new(RuntimeMode::Worker);
        health.transition(RoleLifecycle::Failed);
        health.transition(RoleLifecycle::Ready);
        assert_eq!(health.current(), RoleLifecycle::Failed);
    }

    #[test]
    fn release_metric_inventory_is_documented_and_bounded() {
        let docs = include_str!("../docs/observability.md");
        let forbidden_labels = [
            "call_id",
            "leg_id",
            "connection_id",
            "broadcast_id",
            "message_id",
            "subject",
            "issuer",
            "correlation_id",
            "token",
            "remote_address",
        ];
        let mut declared = std::collections::BTreeMap::new();
        for (metric, labels) in RELEASE_METRICS {
            assert!(
                declared
                    .insert(
                        (*metric).to_owned(),
                        labels.iter().map(|label| (*label).to_owned()).collect(),
                    )
                    .is_none(),
                "duplicate metric inventory: {metric}"
            );
            assert!(
                docs.contains(&format!("`{metric}`")),
                "metric missing from docs/observability.md: {metric}"
            );
            for label in *labels {
                assert!(
                    !forbidden_labels.contains(label),
                    "high-cardinality metric label is forbidden: {metric}.{label}"
                );
            }
        }
        let invocations = emitted_bridgefu_metrics();
        let emitted = invocations
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        let documented = declared
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            emitted, documented,
            "Bridgefu emitters and docs/observability.md inventory diverged"
        );
        for (metric, label_sets) in invocations {
            let expected = &declared[&metric];
            for actual in label_sets {
                assert_eq!(
                    &actual, expected,
                    "metric emitter label schema diverged for {metric}"
                );
            }
        }
    }

    fn bridgefu_rust_source() -> String {
        fn collect(directory: &std::path::Path, output: &mut String) {
            for entry in std::fs::read_dir(directory).expect("read Bridgefu source directory") {
                let path = entry.expect("read Bridgefu source entry").path();
                if path.is_dir() {
                    collect(&path, output);
                } else if path.extension().is_some_and(|extension| extension == "rs") {
                    output.push_str(&std::fs::read_to_string(path).expect("read Bridgefu source"));
                    output.push('\n');
                }
            }
        }
        let mut source = String::new();
        collect(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut source,
        );
        source
    }

    fn emitted_bridgefu_metrics(
    ) -> std::collections::BTreeMap<String, Vec<std::collections::BTreeSet<String>>> {
        let source = bridgefu_rust_source();
        let mut metrics = std::collections::BTreeMap::<String, Vec<_>>::new();
        for invocation in metric_macro_invocations(&source) {
            let literals = rust_string_literals(invocation);
            let Some(name) = literals
                .iter()
                .find(|(value, _)| value.starts_with("bridgefu_"))
                .map(|(value, _)| value.clone())
            else {
                continue;
            };
            let labels = literals
                .into_iter()
                .filter_map(|(value, followed_by_arrow)| followed_by_arrow.then_some(value))
                .collect();
            metrics.entry(name).or_default().push(labels);
        }
        metrics
    }

    fn metric_macro_invocations(source: &str) -> Vec<&str> {
        const MARKERS: [&[u8]; 3] = [
            b"metrics::counter!",
            b"metrics::gauge!",
            b"metrics::histogram!",
        ];
        let bytes = source.as_bytes();
        let mut invocations = Vec::new();
        let mut index = 0;
        let mut block_depth = 0_u32;
        while index < bytes.len() {
            if block_depth > 0 {
                if bytes[index..].starts_with(b"/*") {
                    block_depth += 1;
                    index += 2;
                } else if bytes[index..].starts_with(b"*/") {
                    block_depth -= 1;
                    index += 2;
                } else {
                    index += 1;
                }
                continue;
            }
            if bytes[index..].starts_with(b"//") {
                index = bytes[index..]
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .map_or(bytes.len(), |offset| index + offset + 1);
                continue;
            }
            if bytes[index..].starts_with(b"/*") {
                block_depth = 1;
                index += 2;
                continue;
            }
            if bytes[index] == b'"' {
                index = skip_quoted(bytes, index);
                continue;
            }
            let Some(marker) = MARKERS
                .iter()
                .find(|marker| bytes[index..].starts_with(marker))
            else {
                index += 1;
                continue;
            };
            let mut open = index + marker.len();
            while open < bytes.len() && bytes[open].is_ascii_whitespace() {
                open += 1;
            }
            assert_eq!(bytes.get(open), Some(&b'('), "metric macro has no body");
            let close = matching_parenthesis(bytes, open).expect("balanced metric macro body");
            invocations.push(&source[open..=close]);
            index = close + 1;
        }
        invocations
    }

    fn matching_parenthesis(bytes: &[u8], open: usize) -> Option<usize> {
        let mut depth = 0_u32;
        let mut index = open;
        let mut block_depth = 0_u32;
        while index < bytes.len() {
            if block_depth > 0 {
                if bytes[index..].starts_with(b"/*") {
                    block_depth += 1;
                    index += 2;
                } else if bytes[index..].starts_with(b"*/") {
                    block_depth -= 1;
                    index += 2;
                } else {
                    index += 1;
                }
                continue;
            }
            if bytes[index..].starts_with(b"//") {
                index = bytes[index..]
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .map_or(bytes.len(), |offset| index + offset + 1);
                continue;
            }
            if bytes[index..].starts_with(b"/*") {
                block_depth = 1;
                index += 2;
                continue;
            }
            if bytes[index] == b'"' {
                index = skip_quoted(bytes, index);
                continue;
            }
            match bytes[index] {
                b'(' => depth += 1,
                b')' if depth == 1 => return Some(index),
                b')' => depth -= 1,
                _ => {}
            }
            index += 1;
        }
        None
    }

    fn skip_quoted(bytes: &[u8], quote: usize) -> usize {
        let mut index = quote + 1;
        while index < bytes.len() {
            match bytes[index] {
                b'\\' => index = (index + 2).min(bytes.len()),
                b'"' => return index + 1,
                _ => index += 1,
            }
        }
        bytes.len()
    }

    fn rust_string_literals(invocation: &str) -> Vec<(String, bool)> {
        let bytes = invocation.as_bytes();
        let mut values = Vec::new();
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] != b'"' {
                index += 1;
                continue;
            }
            let start = index + 1;
            let end_after_quote = skip_quoted(bytes, index);
            assert!(end_after_quote <= bytes.len(), "unterminated metric string");
            let end = end_after_quote - 1;
            let mut next = end_after_quote;
            while next < bytes.len() && bytes[next].is_ascii_whitespace() {
                next += 1;
            }
            let followed_by_arrow = bytes.get(next..next + 2) == Some(b"=>");
            values.push((invocation[start..end].to_owned(), followed_by_arrow));
            index = end_after_quote;
        }
        values
    }
}
