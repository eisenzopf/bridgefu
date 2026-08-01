//! bridgefu — programmable SIP/RTP, WebRTC/RTP, provider, and QUIC bridge.
//!
//! Loads a YAML config, stands up the `rvoip-amazon-connect`
//! `ConnectScreenPopServer` (SIP UAS → header→attribute mapping →
//! StartWebRTCContact → Chime media bridge), and serves `/healthz` + `/metrics`,
//! until SIGTERM/SIGINT triggers a graceful shutdown.

mod api;
mod api_rate_limit;
mod config;
mod imds;
mod moq_relay_role;
mod observability;
mod process_role;
mod runtime;
mod screen_pop_evidence;

pub(crate) use bridgefu::providers;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bridgefu::context;
use clap::{Parser, Subcommand};
use metrics_exporter_prometheus::PrometheusHandle;
use rvoip_amazon_connect::ConnectScreenPopServer;

use crate::config::RuntimeMode;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessRunner {
    AllInOne,
    Gateway,
    Worker,
    MoqRelay,
}

const fn process_runner(mode: RuntimeMode) -> ProcessRunner {
    match mode {
        RuntimeMode::AllInOne => ProcessRunner::AllInOne,
        RuntimeMode::Gateway => ProcessRunner::Gateway,
        RuntimeMode::Worker => ProcessRunner::Worker,
        RuntimeMode::MoqRelay => ProcessRunner::MoqRelay,
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "bridgefu",
    version,
    about = "Programmable SIP, WebRTC, provider-control, and QUIC audio bridge"
)]
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
    /// Probe the local liveness endpoint without loading configuration.
    Healthcheck {
        /// Local operations endpoint to probe.
        #[arg(long, default_value = "127.0.0.1:9090")]
        address: SocketAddr,
        /// HTTP liveness path to request.
        #[arg(long, default_value = "/livez")]
        path: String,
        /// Per-operation network timeout in milliseconds.
        #[arg(long, default_value_t = 2_500)]
        timeout_ms: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let command = args.command.clone().unwrap_or(Command::Run);

    // Printing must remain available before runtime secrets are provisioned.
    // The helper still parses the complete typed shape and rejects unknown
    // fields before redacting every credential-bearing value.
    if matches!(command, Command::PrintEffectiveConfig) {
        print!("{}", config::Config::redacted_effective_yaml(&args.config)?);
        return Ok(());
    }

    // Container liveness must work in a package-free runtime before a config
    // file or any deployment secret is mounted. Keeping the probe in this
    // executable removes curl and its transitive userland from the image.
    if let Command::Healthcheck {
        address,
        path,
        timeout_ms,
    } = &command
    {
        probe_liveness(*address, path, Duration::from_millis(*timeout_ms))?;
        return Ok(());
    }

    let cfg = config::Config::load(&args.config)?;

    match command {
        Command::Validate => {
            process_role::preflight(&cfg)?;
            println!("configuration is valid: {}", args.config.display());
            return Ok(());
        }
        Command::PrintEffectiveConfig => unreachable!("handled before secret-resolving load"),
        Command::Healthcheck { .. } => unreachable!("handled before configuration load"),
        Command::Run => {
            // Role prerequisites are checked before tracing, metrics, or any
            // listener/task is installed. Unsupported topologies never fall
            // back to the all-in-one compatibility process.
            process_role::preflight(&cfg)?;
        }
    }

    let tracing_guard = observability::init_tracing(&cfg.observability)?;
    let process_result = async {
        let prom = observability::install_metrics()?;
        tracing::info!(
            config = %args.config.display(),
            runtime_mode = %cfg.runtime.mode,
            "starting bridgefu process"
        );
        match process_runner(cfg.runtime.mode) {
            ProcessRunner::AllInOne => run_all_in_one(&cfg, &args.config, prom).await,
            ProcessRunner::Gateway => {
                process_role::run_gateway(&cfg, prom, shutdown_signal()).await
            }
            ProcessRunner::Worker => process_role::run_worker(&cfg, prom, shutdown_signal()).await,
            ProcessRunner::MoqRelay => {
                moq_relay_role::run_moq_relay(&cfg, prom, shutdown_signal()).await
            }
        }
    }
    .await;
    let tracing_shutdown = tracing_guard.shutdown();
    match (process_result, tracing_shutdown) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(process), Ok(())) => Err(process),
        (Ok(()), Err(shutdown)) => Err(shutdown),
        (Err(process), Err(shutdown)) => {
            Err(process.context(format!("OTLP trace shutdown also failed: {shutdown:#}")))
        }
    }
}

fn probe_liveness(address: SocketAddr, path: &str, timeout: Duration) -> Result<()> {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpStream;

    anyhow::ensure!(!timeout.is_zero(), "healthcheck timeout must be non-zero");
    anyhow::ensure!(
        path.starts_with('/')
            && path.len() <= 2_048
            && path.is_ascii()
            && !path.bytes().any(|byte| byte <= b' ' || byte == 0x7f),
        "healthcheck path must be a safe absolute ASCII HTTP path"
    );

    let mut stream = TcpStream::connect_timeout(&address, timeout)
        .with_context(|| format!("connecting to Bridgefu liveness endpoint at {address}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .context("setting healthcheck read timeout")?;
    stream
        .set_write_timeout(Some(timeout))
        .context("setting healthcheck write timeout")?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
    )
    .context("sending Bridgefu liveness request")?;
    stream
        .flush()
        .context("flushing Bridgefu liveness request")?;

    let mut status_line = String::new();
    BufReader::new(stream)
        .take(1_025)
        .read_line(&mut status_line)
        .context("reading Bridgefu liveness response")?;
    anyhow::ensure!(
        status_line.ends_with('\n') && status_line.len() <= 1_024,
        "Bridgefu liveness endpoint returned an invalid HTTP status line"
    );
    let mut fields = status_line.split_whitespace();
    let protocol = fields.next().unwrap_or_default();
    anyhow::ensure!(
        matches!(protocol, "HTTP/1.0" | "HTTP/1.1"),
        "Bridgefu liveness endpoint returned an invalid HTTP status line"
    );
    let status = fields
        .next()
        .context("Bridgefu liveness response omitted its status code")?
        .parse::<u16>()
        .context("Bridgefu liveness response contained an invalid status code")?;
    anyhow::ensure!(
        (200..300).contains(&status),
        "Bridgefu liveness endpoint returned HTTP {status}"
    );
    Ok(())
}

/// Existing StandardCharter-compatible single-process lifecycle. This remains
/// the default and deliberately retains the original listener construction,
/// call-runtime sharing, and shutdown ordering.
async fn run_all_in_one(
    cfg: &config::Config,
    config_path: &std::path::Path,
    prom: PrometheusHandle,
) -> Result<()> {
    let tenants = cfg.tenant_names()?;
    tracing::info!(
        config = %config_path.display(),
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
    let server_cfg = cfg.build_server_config().await?;
    let server = ConnectScreenPopServer::build(server_cfg)
        .await
        .map_err(|e| anyhow::anyhow!("building gateway: {e}"))?;
    // Subscribe before `serve()` can emit the first INVITE lifecycle event.
    // The broadcast channel intentionally has no replay buffer for late
    // subscribers.
    let lifecycle_events = server.subscribe_lifecycle();
    // The lifecycle and metrics loops remain live through the complete legacy
    // server drain. They are stopped and joined only after the final teardown
    // evidence and route counters have been emitted.
    let (owned_task_shutdown_tx, _) = tokio::sync::watch::channel(false);

    // Construct the durable authority before any generic signaling listener.
    // HTTP, SIP, and WebRTC must share this exact repository, worker fence,
    // validator, and cryptographic policy.
    let mut api_state =
        api::ApiState::from_config(cfg, server.clone(), prom, tenants.clone(), None).await?;
    let call_runtime_owner = api_state.call_runtime();
    let amazon_cleanup =
        bridgefu::amazon_cleanup::AmazonCleanupJournal::connect(cfg.call_repository_backend()?)
            .await
            .context("opening durable Amazon cleanup journal")?;
    let cleanup_observer: Arc<dyn rvoip_amazon_connect::AmazonConnectCleanupObserver> =
        amazon_cleanup.clone();
    server
        .adapter()
        .install_cleanup_observer(cleanup_observer)
        .map_err(|error| anyhow::anyhow!("installing Amazon cleanup journal: {error}"))?;
    let cleanup_reconcile = amazon_cleanup
        .reconcile(server.adapter())
        .await
        .context("reconciling retained Amazon cleanup authority")?;
    metrics::gauge!("bridgefu_amazon_durable_cleanups_pending")
        .set(cleanup_reconcile.remaining as f64);
    tracing::info!(
        attempted = cleanup_reconcile.attempted,
        resolved = cleanup_reconcile.resolved,
        remaining = cleanup_reconcile.remaining,
        "initial Amazon cleanup reconciliation completed"
    );
    let generic_runtime = if cfg.generic_bridge.enabled {
        let call_runtime = call_runtime_owner.as_ref().map(Arc::clone).ok_or_else(|| {
            anyhow::anyhow!("generic_bridge requires the authenticated transactional call runtime")
        })?;
        let bearer_validator = api_state.bearer_validator().ok_or_else(|| {
            anyhow::anyhow!("generic_bridge requires the shared API bearer validator")
        })?;
        let webrtc_bearer_validator =
            api_state
                .webrtc_signaling_bearer_validator()
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "generic_bridge requires the attachment-bound WebRTC bearer validator"
                    )
                })?;
        let webrtc_session_binding = api_state.webrtc_session_binding().ok_or_else(|| {
            anyhow::anyhow!("generic_bridge requires the WebRTC attachment binding authority")
        })?;
        let sip_tenant = cfg
            .api
            .static_tenant
            .as_deref()
            .or_else(|| (tenants.len() == 1).then(|| tenants[0].as_str()))
            .ok_or_else(|| {
                anyhow::anyhow!("generic_bridge requires one explicit signaling tenant")
            })?;
        let sip_listener_auth = cfg
            .sip_listener_auth_policy(sip_tenant, Arc::clone(&bearer_validator), "sip:connect")
            .context("configuring all-in-one SIP listener authentication")?;
        let generic_sip_bind = cfg
            .generic_bridge
            .sip_bind
            .parse::<SocketAddr>()
            .context("parsing generic_bridge.sip_bind")?;
        let sip_stack = cfg
            .generic_sip_stack_config("bridgefu-generic", generic_sip_bind)
            .context("configuring generic SIP/RTP networking")?;
        let sip_egress_profiles = cfg
            .sip_egress_profile_configs("bridgefu-generic", generic_sip_bind)
            .context("configuring isolated named SIP egress profiles")?;
        let outbound_profiles = cfg
            .outbound_profile_resolver()
            .context("configuring named outbound signaling profiles")?;
        let provider_executor: Arc<dyn bridgefu::call_service::ProviderLegExecutor> =
            Arc::new(api_state.provider_registry());
        // The legacy StandardCharter server keeps exclusive ownership of its
        // adapter event receiver and routes. Generic execution gets a fresh
        // isolated adapter only when this opt-in runtime is enabled.
        let generic_amazon_connect = server.adapter().fork_isolated();
        let cleanup_observer: Arc<dyn rvoip_amazon_connect::AmazonConnectCleanupObserver> =
            amazon_cleanup.clone();
        generic_amazon_connect
            .install_cleanup_observer(cleanup_observer)
            .map_err(|error| {
                anyhow::anyhow!("installing generic Amazon cleanup journal: {error}")
            })?;
        let standardcharter_canary = cfg.standardcharter_canary_policy()?;
        let signaling_tls = cfg.api.tls.as_ref().map(|tls| runtime::GenericBridgeTls {
            certificate_chain: &tls.certificate_chain,
            private_key: &tls.private_key,
        });
        let runtime = runtime::GenericBridgeRuntime::start(runtime::GenericBridgeStart {
            config: &cfg.generic_bridge,
            runtime: &cfg.runtime,
            call_runtime,
            sip_stack,
            sip_egress_profiles,
            sip_listener_auth,
            webrtc_bearer_validator,
            webrtc_session_binding,
            context_policy: &cfg.context,
            standardcharter_canary,
            provider_executor,
            outbound_profiles,
            amazon_connect: generic_amazon_connect,
            signaling_tls,
        })
        .await?;
        if let Err(error) = api_state.set_generic_runtime(Arc::clone(&runtime)).await {
            runtime
                .shutdown(Duration::from_secs(cfg.runtime.drain_timeout_secs.max(1)))
                .await;
            return Err(error).context("publishing concrete all-in-one worker capabilities");
        }
        Some(runtime)
    } else {
        None
    };
    let public_uctp_listener_result: anyhow::Result<_> = async {
        match &cfg.broadcast.uctp_listener {
            Some(listener_config) => {
                let runtime = generic_runtime.as_ref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "broadcast.uctp_listener requires the generic media Orchestrator"
                    )
                })?;
                let listener = bridgefu::broadcast::PublicUctpBroadcastListener::bind(
                    runtime.orchestrator(),
                    api_state.broadcast_token_service(),
                    listener_config.runtime()?,
                )
                .await
                .context("starting authenticated public UCTP broadcast listener")?;
                tracing::info!(
                    local_addr = %listener.local_addr(),
                    advertised_endpoint = cfg.broadcast.public_endpoint.as_deref().unwrap_or(""),
                    "authenticated public UCTP broadcast listener started"
                );
                Ok(Some(listener))
            }
            None => Ok(None),
        }
    }
    .await;
    let public_uctp_listener = match public_uctp_listener_result {
        Ok(listener) => listener,
        Err(error) => {
            if let Some(runtime) = &generic_runtime {
                runtime
                    .shutdown(std::time::Duration::from_secs(
                        cfg.runtime.drain_timeout_secs,
                    ))
                    .await;
            }
            return Err(error);
        }
    };
    // Start owned observers only after every fallible listener/runtime
    // construction above has succeeded. A startup error therefore cannot
    // strand detached metrics or cleanup tasks.
    let mut metrics_task = observability::spawn_metrics_updater(
        server.clone(),
        tenants.clone(),
        owned_task_shutdown_tx.subscribe(),
    );
    let mut cleanup_reconciler = amazon_cleanup.spawn_reconciler(
        server.adapter().clone(),
        owned_task_shutdown_tx.subscribe(),
        std::time::Duration::from_secs(30),
    );
    let (http_shutdown_tx, _) = tokio::sync::watch::channel(false);
    let mut lifecycle_task = screen_pop_evidence::spawn_lifecycle_ingest(
        lifecycle_events,
        api_state.screen_pop_evidence_store(),
        owned_task_shutdown_tx.subscribe(),
    );
    let api_shutdown_owner = api_state.clone();
    let app = api::router(api_state);

    // Control/health/metrics HTTP server, shut down on the same signal as the gateway.
    let mut http = tokio::spawn(api::serve(
        http_bind,
        app,
        wait_for_shutdown(http_shutdown_tx.subscribe()),
    ));

    // Retain the outer accept-loop owner. Dropping the `serve` future on a
    // process signal used to bypass the server's owned drain protocol.
    let mut legacy_serve = tokio::spawn(server.clone().serve());
    tokio::select! {
        res = &mut legacy_serve => {
            match res {
                Ok(Ok(())) => tracing::info!("gateway serve loop ended"),
                Ok(Err(error)) => tracing::error!(%error, "gateway serve loop ended with error"),
                Err(error) => tracing::error!(%error, "gateway serve task failed"),
            }
        }
        _ = shutdown_signal() => {
            tracing::info!("shutdown signal received; draining gateway");
        }
    }

    let shutdown_deadline = tokio::time::Instant::now()
        + std::time::Duration::from_secs(cfg.runtime.drain_timeout_secs);
    // Close public admission together. HTTP stops accepting mutations now,
    // while lifecycle/metrics consumers intentionally remain alive until the
    // legacy server has completed its exact teardown protocol.
    let _ = http_shutdown_tx.send(true);
    server.begin_drain();
    if let Some(listener) = &public_uctp_listener {
        listener.begin_drain();
    }

    let legacy_report = server
        .drain_until(
            std::time::Instant::now()
                .checked_add(shutdown_budget(shutdown_deadline))
                .unwrap_or_else(std::time::Instant::now),
        )
        .await;
    tracing::info!(
        attempted_tasks = legacy_report.attempted_tasks,
        joined_tasks = legacy_report.joined_tasks,
        failed_tasks = legacy_report.failed_tasks,
        detached_tasks = legacy_report.detached_tasks,
        remaining_setups = legacy_report.remaining_setups,
        remaining_active = legacy_report.remaining_active,
        remaining_connect_routes = legacy_report.remaining_connect_routes,
        pending_contact_cleanups = legacy_report.adapter.pending_contact_cleanups,
        serve_stopped = legacy_report.serve_stopped,
        coordinator_stopped = legacy_report.coordinator_stopped,
        "legacy screen-pop server drain completed"
    );
    metrics::gauge!("bridgefu_legacy_drain_incomplete").set(if legacy_report.is_complete() {
        0.0
    } else {
        1.0
    });
    metrics::gauge!("bridgefu_amazon_pending_contact_cleanups")
        .set(legacy_report.adapter.pending_contact_cleanups as f64);
    if !legacy_report.is_complete() {
        tracing::error!(
            detached_tasks = legacy_report.detached_tasks,
            remaining_setups = legacy_report.remaining_setups,
            remaining_active = legacy_report.remaining_active,
            remaining_connect_routes = legacy_report.remaining_connect_routes,
            pending_contact_cleanups = legacy_report.adapter.pending_contact_cleanups,
            "legacy screen-pop shutdown retained unfinished cleanup authority"
        );
    }
    if !legacy_serve.is_finished()
        && tokio::time::timeout(shutdown_budget(shutdown_deadline), &mut legacy_serve)
            .await
            .is_err()
    {
        // This is a bounded fallback only after `drain_until` has transferred
        // ambiguous contact cleanup to retained owners and stopped the SIP
        // coordinator. It is never the primary shutdown mechanism.
        tracing::error!("legacy serve owner remained live after completed drain; aborting task");
        legacy_serve.abort();
        let _ = legacy_serve.await;
    }

    let _ = owned_task_shutdown_tx.send(true);
    // The lifecycle consumer must stop before its store and API state are
    // dropped. Abort only as a bounded fallback for a runtime bug.
    if tokio::time::timeout(
        shutdown_budget(shutdown_deadline).min(std::time::Duration::from_secs(3)),
        &mut lifecycle_task,
    )
    .await
    .is_err()
    {
        tracing::warn!("screen-pop lifecycle consumer did not stop; aborting task");
        lifecycle_task.abort();
        let _ = lifecycle_task.await;
    }
    if tokio::time::timeout(
        shutdown_budget(shutdown_deadline).min(std::time::Duration::from_secs(3)),
        &mut metrics_task,
    )
    .await
    .is_err()
    {
        tracing::warn!("metrics updater did not stop; aborting task");
        metrics_task.abort();
        let _ = metrics_task.await;
    }
    if tokio::time::timeout(
        shutdown_budget(shutdown_deadline).min(std::time::Duration::from_secs(3)),
        &mut cleanup_reconciler,
    )
    .await
    .is_err()
    {
        tracing::warn!("Amazon cleanup reconciler did not stop; aborting task");
        cleanup_reconciler.abort();
        let _ = cleanup_reconciler.await;
    }

    // Give the HTTP server a moment to drain from the shared shutdown signal.
    if tokio::time::timeout(
        shutdown_budget(shutdown_deadline).min(std::time::Duration::from_secs(3)),
        &mut http,
    )
    .await
    .is_err()
    {
        tracing::warn!("HTTP API did not drain; aborting task");
        http.abort();
        let _ = http.await;
    }
    let closed_broadcasts = api_shutdown_owner.shutdown_local_broadcasts().await;
    tracing::info!(closed_broadcasts, "local broadcasts drained");
    // Release the retained API clone before CallServiceRuntime::try_unwrap.
    drop(api_shutdown_owner);
    if let Some(listener) = public_uctp_listener {
        if tokio::time::timeout(shutdown_budget(shutdown_deadline), listener.shutdown())
            .await
            .is_err()
        {
            tracing::warn!("public UCTP listener exceeded the shutdown deadline");
        }
    }
    if let Some(runtime) = generic_runtime {
        runtime.shutdown(shutdown_budget(shutdown_deadline)).await;
    }
    shutdown_call_runtime(call_runtime_owner, shutdown_deadline).await?;
    tracing::info!("bridgefu stopped");
    Ok(())
}

async fn shutdown_call_runtime(
    runtime: Option<Arc<bridgefu::call_service::CallServiceRuntime>>,
    deadline: tokio::time::Instant,
) -> Result<()> {
    let Some(runtime) = runtime else {
        return Ok(());
    };
    let strong_count = Arc::strong_count(&runtime);
    let runtime = Arc::try_unwrap(runtime).map_err(|_| {
        anyhow::anyhow!(
            "call-service runtime still has {strong_count} owners after HTTP and media drain"
        )
    })?;
    runtime
        .shutdown(shutdown_budget(deadline))
        .await
        .context("shutting down durable call-service worker")
}

fn shutdown_budget(deadline: tokio::time::Instant) -> std::time::Duration {
    deadline.saturating_duration_since(tokio::time::Instant::now())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::thread;

    use bridgefu::call_engine::WorkerId;
    use bridgefu::call_service::{
        build_call_service_runtime, CallRepositoryBackendConfig, CallServiceCoordinationConfig,
        CallServiceRuntimeConfig, CallTimeoutPolicy, SamePrincipalAttachmentResolver,
        SystemCallServiceClock,
    };
    use bridgefu::coordination::DeploymentId;

    #[test]
    fn gateway_mode_dispatches_to_the_gateway_runner_without_fallback() {
        assert_eq!(
            process_runner(RuntimeMode::AllInOne),
            ProcessRunner::AllInOne
        );
        assert_eq!(process_runner(RuntimeMode::Gateway), ProcessRunner::Gateway);
        assert_ne!(
            process_runner(RuntimeMode::Gateway),
            ProcessRunner::AllInOne
        );
        assert_eq!(process_runner(RuntimeMode::Worker), ProcessRunner::Worker);
        assert_eq!(
            process_runner(RuntimeMode::MoqRelay),
            ProcessRunner::MoqRelay
        );
    }

    fn spawn_liveness_endpoint(status: &'static str) -> (SocketAddr, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut connection, _) = listener.accept().unwrap();
            connection
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request_line = String::new();
            BufReader::new(&mut connection)
                .read_line(&mut request_line)
                .unwrap();
            write!(
                connection,
                "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
            request_line
        });
        (address, server)
    }

    #[test]
    fn native_healthcheck_accepts_a_live_endpoint() {
        let (address, server) = spawn_liveness_endpoint("200 OK");
        probe_liveness(address, "/livez", Duration::from_secs(2)).unwrap();
        assert_eq!(server.join().unwrap(), "GET /livez HTTP/1.1\r\n");
    }

    #[test]
    fn native_healthcheck_rejects_an_unhealthy_endpoint() {
        let (address, server) = spawn_liveness_endpoint("503 Service Unavailable");
        let error = probe_liveness(address, "/livez", Duration::from_secs(2)).unwrap_err();
        assert!(error.to_string().contains("returned HTTP 503"));
        assert_eq!(server.join().unwrap(), "GET /livez HTTP/1.1\r\n");
    }

    #[test]
    fn native_healthcheck_rejects_unsafe_inputs_before_connecting() {
        let address = "127.0.0.1:9".parse().unwrap();
        for path in ["livez", "/livez\r\nInjected: true", "/bad path"] {
            let error = probe_liveness(address, path, Duration::from_secs(1)).unwrap_err();
            assert!(error.to_string().contains("safe absolute ASCII HTTP path"));
        }
        let error = probe_liveness(address, "/livez", Duration::ZERO).unwrap_err();
        assert!(error.to_string().contains("timeout must be non-zero"));
    }

    #[test]
    fn healthcheck_cli_defaults_do_not_require_a_config_path() {
        let args = Args::try_parse_from(["bridgefu", "healthcheck"]).unwrap();
        let Some(Command::Healthcheck {
            address,
            path,
            timeout_ms,
        }) = args.command
        else {
            panic!("healthcheck command was not parsed");
        };
        assert_eq!(address, "127.0.0.1:9090".parse::<SocketAddr>().unwrap());
        assert_eq!(path, "/livez");
        assert_eq!(timeout_ms, 2_500);
    }

    #[tokio::test]
    async fn owned_call_runtime_shutdown_marks_worker_draining_and_joins() {
        let mut coordination = CallServiceCoordinationConfig::new(
            DeploymentId::parse("main-runtime-shutdown-test").unwrap(),
        );
        coordination.worker_lease_ttl = std::time::Duration::from_secs(300);
        coordination.worker_renew_interval = std::time::Duration::from_secs(100);
        let runtime = build_call_service_runtime(
            CallServiceRuntimeConfig {
                backend: CallRepositoryBackendConfig::Memory,
                worker_id: WorkerId::new(),
                max_calls: 2,
                worker_capabilities: BTreeSet::from(["sip".into(), "webrtc".into()]),
                control_key: vec![0x38; 32],
                timeouts: CallTimeoutPolicy {
                    setup: std::time::Duration::from_secs(30),
                    media_idle: std::time::Duration::from_secs(30),
                    transfer: std::time::Duration::from_secs(30),
                    ending: std::time::Duration::from_secs(30),
                },
                coordination,
            },
            Arc::new(SamePrincipalAttachmentResolver),
            Arc::new(SystemCallServiceClock),
        )
        .await
        .unwrap();
        let repository = runtime.repository();
        let worker_id = runtime.worker().lease.worker_id;
        shutdown_call_runtime(
            Some(Arc::new(runtime)),
            tokio::time::Instant::now() + std::time::Duration::from_secs(2),
        )
        .await
        .unwrap();
        let worker = repository.worker_snapshot(worker_id).await.unwrap();
        assert!(worker.draining);
    }
}
