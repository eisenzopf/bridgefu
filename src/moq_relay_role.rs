//! Standalone, role-separated MOQT relay process.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use axum::extract::State;
use axum::http::{header::AUTHORIZATION, HeaderMap, StatusCode};
use axum::routing::get;
use axum::{Json, Router};
use bridgefu::broadcast::{
    BroadcastGrantRegistry, BroadcastGrantVerifier, BroadcastTokenService,
    RedisBroadcastGrantConfig, RedisBroadcastGrantRevocationChecker, RedisBroadcastGrantStore,
};
use metrics_exporter_prometheus::PrometheusHandle;
use rvoip_auth_core::BearerValidator;
use rvoip_moq::{
    BoundedMemoryMoqReplayStore, MoqAuthorizer, MoqRelayAdmissionConfig,
    MoqRelayAdmissionSubstrate, MoqRelayCertificateBinding, MoqRelayDeploymentMode,
    MoqRelayRuntime, MoqRelayRuntimeConfig, MoqRelayRuntimeLifecycle, MoqRelayRuntimeLimits,
    MoqRelayRuntimeSecurity, MoqRelayRuntimeSnapshot, MoqRelayRuntimeTimeouts,
    MoqRelayServerTlsConfig, MoqRelayTopology, MoqRevocationChecker, MoqSessionLeaseStore,
    RvoipMoqRelayAdmission, SecureMoqAuthorizer,
};
use rvoip_redis::{RedisMoqSessionLeaseConfig, RedisMoqSessionLeaseStore};
use serde_json::{json, Value};
use subtle::ConstantTimeEq;
use url::Url;
use zeroize::Zeroize;

use crate::config::{Config, MoqRelayCfg, MoqRelayListenerCfg, RuntimeMode};
use crate::observability::{serve_role_health, RoleHealth, RoleLifecycle};
use crate::process_role::preflight;

const MAX_DIAGNOSTICS_BEARER_BYTES: usize = 4_096;

struct DiagnosticsBearer(Vec<u8>);

impl Drop for DiagnosticsBearer {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct MoqRelayRoleRuntime {
    listeners: Vec<MoqRelayRuntime>,
    grants: Arc<RedisBroadcastGrantStore>,
    leases: Arc<RedisMoqSessionLeaseStore>,
    dependency_check_interval: Duration,
}

impl MoqRelayRoleRuntime {
    async fn start(config: &Config) -> Result<Self> {
        let relay = config
            .moq_relay
            .as_ref()
            .context("moq_relay configuration is missing")?;
        let redis_ref = config
            .persistence
            .redis_url
            .as_ref()
            .context("clustered Redis is missing")?;
        let mut redis_url = redis_ref
            .resolve()
            .context("resolving MOQT relay Redis dependency")?;
        let grants = RedisBroadcastGrantStore::connect(RedisBroadcastGrantConfig::new(
            redis_url.clone(),
            config.persistence.deployment_id.clone(),
        ))
        .await
        .context("connecting MOQT active-grant authority")?;
        let leases = Arc::new(
            RedisMoqSessionLeaseStore::from_config(
                RedisMoqSessionLeaseConfig::new(redis_url.clone())
                    .with_namespace(config.persistence.deployment_id.clone())
                    .with_max_active_sessions_per_tenant(
                        relay.limits.max_active_sessions_per_tenant,
                    ),
            )
            .context("constructing MOQT durable session-lease store")?,
        );
        redis_url.zeroize();

        // Both dependencies are checked before any public relay socket binds.
        grants
            .health_check()
            .await
            .context("checking MOQT active-grant authority")?;
        leases
            .snapshot(chrono::Utc::now())
            .await
            .context("checking MOQT durable session-lease store")?;

        let token_secret = config
            .broadcast
            .token_secret
            .as_ref()
            .context("broadcast.token_secret is missing")?
            .resolve()
            .context("resolving MOQT subscriber token secret")?
            .into_bytes();
        let verifier: Arc<dyn BroadcastGrantVerifier> = grants.clone();
        let validator: Arc<dyn BearerValidator> = Arc::new(
            BroadcastTokenService::new(
                token_secret,
                BroadcastGrantRegistry::new(),
                Duration::from_secs(config.broadcast.token_ttl_secs),
            )?
            .with_shared_verifier(verifier),
        );
        let replay = Arc::new(
            BoundedMemoryMoqReplayStore::new(relay.limits.max_replay_claims)
                .context("constructing bounded MOQT replay store")?,
        );
        // The local authorizer gives each process a fast replay boundary. The
        // Redis lease is the cluster-authoritative token/session tombstone and
        // tenant quota, so another relay cannot reuse the same credential.
        let revocation: Arc<dyn MoqRevocationChecker> =
            Arc::new(RedisBroadcastGrantRevocationChecker::new(grants.clone()));
        let authorizer: Arc<dyn MoqAuthorizer> =
            Arc::new(SecureMoqAuthorizer::new(replay, revocation));
        let lease_store: Arc<dyn MoqSessionLeaseStore> = leases.clone();
        let operation_timeout = Duration::from_secs(relay.timeouts.admission_operation_secs);
        let webtransport_admission = Arc::new(RvoipMoqRelayAdmission::with_config(
            validator.clone(),
            authorizer.clone(),
            lease_store.clone(),
            MoqRelayAdmissionConfig::for_substrate(
                operation_timeout,
                MoqRelayAdmissionSubstrate::WebTransport,
            )?,
        )?);
        let raw_quic_admission = Arc::new(RvoipMoqRelayAdmission::with_config(
            validator,
            authorizer,
            lease_store,
            MoqRelayAdmissionConfig::for_substrate(
                operation_timeout,
                MoqRelayAdmissionSubstrate::RawQuic,
            )?,
        )?);

        let publisher_endpoint = listener_endpoint(&relay.publisher.listener)?;
        let publisher_socket = listener_advertised_socket(&relay.publisher.listener)?;
        let topology = MoqRelayTopology::new(
            publisher_endpoint,
            publisher_socket,
            relay.limits.max_coordinated_namespaces,
        )?;
        let common_limits = runtime_limits(relay);
        let common_timeouts = runtime_timeouts(relay);
        let bindings = relay
            .publisher
            .certificate_bindings
            .iter()
            .map(|binding| MoqRelayCertificateBinding {
                certificate_sha256: binding.certificate_sha256.clone(),
                scope: binding.scope.clone(),
            })
            .collect();
        let publisher = listener_runtime_config(
            relay,
            &relay.publisher.listener,
            MoqRelayRuntimeSecurity::PublisherMutualTls {
                bindings,
                max_active_sessions_per_certificate: relay
                    .publisher
                    .max_active_sessions_per_certificate,
            },
            true,
            common_limits.clone(),
            common_timeouts,
        )?;
        let webtransport = listener_runtime_config(
            relay,
            &relay.subscriber_webtransport,
            MoqRelayRuntimeSecurity::SubscriberWebTransport {
                admission: webtransport_admission,
            },
            false,
            common_limits.clone(),
            common_timeouts,
        )?;
        let raw_quic = listener_runtime_config(
            relay,
            &relay.subscriber_raw_quic,
            MoqRelayRuntimeSecurity::SubscriberRawQuic {
                admission: raw_quic_admission,
            },
            false,
            common_limits,
            common_timeouts,
        )?;

        let mut listeners = Vec::with_capacity(3);
        for listener in [publisher, webtransport, raw_quic] {
            match MoqRelayRuntime::start_with_topology(listener, topology.clone()) {
                Ok(runtime) => listeners.push(runtime),
                Err(error) => {
                    drain_listeners(&listeners, Duration::from_secs(5)).await;
                    return Err(error).context("starting role-separated MOQT listener");
                }
            }
        }
        Ok(Self {
            listeners,
            grants,
            leases,
            dependency_check_interval: Duration::from_secs(
                relay.timeouts.dependency_check_interval_secs,
            ),
        })
    }

    fn listeners_ready(&self) -> bool {
        self.listeners
            .iter()
            .all(|listener| listener.lifecycle() == MoqRelayRuntimeLifecycle::Ready)
    }

    fn listener_failed(&self) -> bool {
        self.listeners.iter().any(|listener| {
            matches!(
                listener.lifecycle(),
                MoqRelayRuntimeLifecycle::Stopped | MoqRelayRuntimeLifecycle::Failed
            )
        })
    }

    async fn dependencies_healthy(&self) -> bool {
        let (grants, leases) = tokio::join!(
            self.grants.health_check(),
            self.leases.snapshot(chrono::Utc::now())
        );
        grants.is_ok() && leases.is_ok()
    }

    async fn snapshots(&self) -> Vec<MoqRelayRuntimeSnapshot> {
        futures_util::future::join_all(self.listeners.iter().map(MoqRelayRuntime::snapshot)).await
    }

    async fn drain(&self, timeout: Duration) -> Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        let results = futures_util::future::join_all(self.listeners.iter().map(|listener| {
            listener.drain(deadline.saturating_duration_since(tokio::time::Instant::now()))
        }))
        .await;
        if results.iter().any(Result::is_err) {
            return Err(anyhow!("one or more MOQT relay listeners failed to drain"));
        }
        Ok(())
    }
}

#[derive(Clone)]
struct RelayHttpState {
    health: RoleHealth,
    metrics: PrometheusHandle,
    runtime: Arc<MoqRelayRoleRuntime>,
    diagnostics_bearer: Arc<DiagnosticsBearer>,
}

pub async fn run_moq_relay(
    config: &Config,
    metrics: PrometheusHandle,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> Result<()> {
    let plan = preflight(config)?;
    debug_assert!(plan.moq_relay);
    debug_assert!(!plan.public_control_http && !plan.public_signaling);
    let http_bind: SocketAddr = config
        .observability
        .http_bind
        .parse()
        .context("invalid observability.http_bind")?;
    let relay_config = config
        .moq_relay
        .as_ref()
        .context("moq_relay configuration is missing")?;
    let mut diagnostics_bearer = relay_config
        .diagnostics_bearer_token
        .resolve()
        .context("resolving MOQT diagnostics bearer")?
        .into_bytes();
    if diagnostics_bearer.len() < 32 || diagnostics_bearer.len() > MAX_DIAGNOSTICS_BEARER_BYTES {
        diagnostics_bearer.zeroize();
        return Err(anyhow!("MOQT diagnostics bearer length is invalid"));
    }
    let diagnostics_bearer = Arc::new(DiagnosticsBearer(diagnostics_bearer));

    // Dependency checks happen inside `start` before the first relay bind.
    let runtime = Arc::new(MoqRelayRoleRuntime::start(config).await?);
    let listener = match tokio::net::TcpListener::bind(http_bind).await {
        Ok(listener) => listener,
        Err(error) => {
            let _ = runtime
                .drain(Duration::from_secs(
                    config.runtime.drain_timeout_secs.max(1),
                ))
                .await;
            return Err(error)
                .with_context(|| format!("binding MOQT role health endpoint {http_bind}"));
        }
    };
    let health = RoleHealth::new(RuntimeMode::MoqRelay);
    let state = RelayHttpState {
        health: health.clone(),
        metrics,
        runtime: runtime.clone(),
        diagnostics_bearer,
    };
    let app = relay_router(state);
    let (http_shutdown, http_shutdown_rx) = tokio::sync::watch::channel(false);
    let mut http = tokio::spawn(serve_role_health(
        listener,
        app,
        wait_for_stop(http_shutdown_rx),
    ));
    let mut http_finished = false;
    let mut dependency_tick = tokio::time::interval(runtime.dependency_check_interval);
    dependency_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    health.transition(RoleLifecycle::Ready);
    tracing::info!(
        listeners = runtime.listeners.len(),
        protocol = %rvoip_moq::MOQT_NEGOTIATED_PROTOCOL,
        "standalone role-separated MOQT relay ready"
    );

    tokio::pin!(shutdown);
    let run_error = loop {
        tokio::select! {
            _ = &mut shutdown => break None,
            result = &mut http => {
                http_finished = true;
                let error = match result {
                    Ok(Ok(())) => anyhow!("MOQT operational server stopped before process drain"),
                    Ok(Err(error)) => error.context("MOQT operational server failed"),
                    Err(error) => anyhow!(error).context("MOQT operational server task failed"),
                };
                break Some(error);
            }
            _ = dependency_tick.tick() => {
                if runtime.listener_failed() {
                    break Some(anyhow!("MOQT relay listener stopped unexpectedly"));
                }
                if runtime.listeners_ready() && runtime.dependencies_healthy().await {
                    health.transition(RoleLifecycle::Ready);
                } else {
                    health.transition(RoleLifecycle::Degraded);
                }
            }
        }
    };

    if run_error.is_none() {
        health.transition(RoleLifecycle::Draining);
    } else {
        health.transition(RoleLifecycle::Failed);
    }
    let deadline =
        tokio::time::Instant::now() + Duration::from_secs(config.runtime.drain_timeout_secs.max(1));
    let drain = runtime
        .drain(deadline.saturating_duration_since(tokio::time::Instant::now()))
        .await;
    let _ = http_shutdown.send(true);
    if !http_finished
        && tokio::time::timeout(
            deadline
                .saturating_duration_since(tokio::time::Instant::now())
                .min(Duration::from_secs(3)),
            &mut http,
        )
        .await
        .is_err()
    {
        http.abort();
        let _ = http.await;
    }
    if let Some(error) = run_error {
        return Err(error);
    }
    drain?;
    health.transition(RoleLifecycle::Stopped);
    Ok(())
}

fn relay_router(state: RelayHttpState) -> Router {
    Router::new()
        .route("/healthz", get(relay_ready))
        .route("/livez", get(relay_live))
        .route("/readyz", get(relay_ready))
        .route("/metrics", get(relay_metrics))
        .route("/diagnostics", get(relay_diagnostics))
        .with_state(state)
}

async fn relay_live(State(state): State<RelayHttpState>) -> (StatusCode, Json<Value>) {
    let lifecycle = state.health.current();
    let live = !matches!(lifecycle, RoleLifecycle::Stopped | RoleLifecycle::Failed);
    (
        if live {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(json!({"ok": live, "mode": "moq-relay", "state": lifecycle})),
    )
}

async fn relay_ready(State(state): State<RelayHttpState>) -> (StatusCode, Json<Value>) {
    let lifecycle = state.health.current();
    let ready = lifecycle == RoleLifecycle::Ready;
    (
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(json!({"ok": ready, "mode": "moq-relay", "state": lifecycle})),
    )
}

async fn relay_metrics(State(state): State<RelayHttpState>) -> String {
    state.metrics.render()
}

async fn relay_diagnostics(
    State(state): State<RelayHttpState>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    if !valid_diagnostics_bearer(&headers, &state.diagnostics_bearer.0) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "unauthorized"})),
        );
    }
    let dependencies_healthy = state.runtime.dependencies_healthy().await;
    let listeners = state.runtime.snapshots().await;
    (
        StatusCode::OK,
        Json(json!({
            "version": env!("CARGO_PKG_VERSION"),
            "mode": "moq-relay",
            "state": state.health.current(),
            "dependencies_healthy": dependencies_healthy,
            "protocol": rvoip_moq::MoqProtocolVersion::PINNED,
            "listeners": listeners,
        })),
    )
}

fn valid_diagnostics_bearer(headers: &HeaderMap, expected: &[u8]) -> bool {
    let Some(value) = headers.get(AUTHORIZATION) else {
        return false;
    };
    let Ok(value) = value.to_str() else {
        return false;
    };
    let Some(token) = value.strip_prefix("Bearer ") else {
        return false;
    };
    token.len() <= MAX_DIAGNOSTICS_BEARER_BYTES && token.as_bytes().ct_eq(expected).unwrap_u8() == 1
}

fn listener_runtime_config(
    relay: &MoqRelayCfg,
    listener: &MoqRelayListenerCfg,
    security: MoqRelayRuntimeSecurity,
    publisher: bool,
    limits: MoqRelayRuntimeLimits,
    timeouts: MoqRelayRuntimeTimeouts,
) -> Result<MoqRelayRuntimeConfig> {
    Ok(MoqRelayRuntimeConfig {
        deployment: MoqRelayDeploymentMode::Standalone,
        bind: listener
            .bind
            .parse()
            .context("parsing MOQT listener bind")?,
        advertised_endpoint: listener_endpoint(listener)?,
        advertised_socket_addr: listener_advertised_socket(listener)?,
        tls: MoqRelayServerTlsConfig {
            server_certificates: relay
                .tls
                .server_certificates
                .iter()
                .map(PathBuf::from)
                .collect(),
            server_private_keys: relay
                .tls
                .server_private_keys
                .iter()
                .map(PathBuf::from)
                .collect(),
            publisher_client_ca_certificates: if publisher {
                relay
                    .tls
                    .publisher_client_ca_certificates
                    .iter()
                    .map(PathBuf::from)
                    .collect()
            } else {
                Vec::new()
            },
            ..MoqRelayServerTlsConfig::default()
        },
        security,
        limits,
        timeouts,
    })
}

fn listener_endpoint(listener: &MoqRelayListenerCfg) -> Result<Url> {
    Url::parse(&listener.advertised_endpoint).context("parsing MOQT advertised endpoint")
}

fn listener_advertised_socket(listener: &MoqRelayListenerCfg) -> Result<Option<SocketAddr>> {
    listener
        .advertised_socket_addr
        .as_deref()
        .map(str::parse)
        .transpose()
        .context("parsing MOQT advertised socket address")
}

fn runtime_limits(relay: &MoqRelayCfg) -> MoqRelayRuntimeLimits {
    let mut limits = MoqRelayRuntimeLimits::default();
    limits.max_pending_admissions = relay.limits.max_pending_admissions;
    limits.max_active_sessions = relay.limits.max_active_sessions;
    limits.max_coordinated_namespaces = relay.limits.max_coordinated_namespaces;
    limits.max_cached_tracks_per_namespace = relay.limits.max_cached_tracks_per_namespace;
    limits.max_pending_track_requests_per_namespace =
        relay.limits.max_pending_track_requests_per_namespace;
    limits.max_upstream_connections = relay.limits.max_upstream_connections;
    limits.max_upstream_tracks = relay.limits.max_upstream_tracks;
    limits
}

fn runtime_timeouts(relay: &MoqRelayCfg) -> MoqRelayRuntimeTimeouts {
    MoqRelayRuntimeTimeouts {
        setup: Duration::from_secs(relay.timeouts.setup_secs),
        admission: Duration::from_secs(relay.timeouts.admission_secs),
        pre_admission_cleanup: Duration::from_secs(relay.timeouts.pre_admission_cleanup_secs),
        admission_session_close: Duration::from_secs(relay.timeouts.admission_session_close_secs),
        token_revalidation_interval: Duration::from_secs(
            relay.timeouts.token_revalidation_interval_secs,
        ),
        upstream_track_idle: Duration::from_secs(relay.timeouts.upstream_track_idle_secs),
        upstream_connection_idle: Duration::from_secs(relay.timeouts.upstream_connection_idle_secs),
        drop_cleanup: Duration::from_secs(relay.timeouts.drop_cleanup_secs),
    }
}

async fn drain_listeners(listeners: &[MoqRelayRuntime], timeout: Duration) {
    let _ =
        futures_util::future::join_all(listeners.iter().map(|listener| listener.drain(timeout)))
            .await;
}

async fn wait_for_stop(mut stop: tokio::sync::watch::Receiver<bool>) {
    if *stop.borrow() {
        return;
    }
    while stop.changed().await.is_ok() {
        if *stop.borrow() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostics_bearer_is_exact_and_bounded_and_absence_fails_closed() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let mut headers = HeaderMap::new();
        assert!(!valid_diagnostics_bearer(&headers, secret));

        headers.insert(
            AUTHORIZATION,
            "Bearer 0123456789abcdef0123456789abcdef".parse().unwrap(),
        );
        assert!(valid_diagnostics_bearer(&headers, secret));

        headers.insert(AUTHORIZATION, "Bearer wrong".parse().unwrap());
        assert!(!valid_diagnostics_bearer(&headers, secret));

        headers.insert(
            AUTHORIZATION,
            "Basic MDEyMzQ1Njc4OWFiY2RlZg==".parse().unwrap(),
        );
        assert!(!valid_diagnostics_bearer(&headers, secret));

        let oversized = format!("Bearer {}", "a".repeat(MAX_DIAGNOSTICS_BEARER_BYTES + 1));
        headers.insert(AUTHORIZATION, oversized.parse().unwrap());
        assert!(!valid_diagnostics_bearer(&headers, secret));
    }
}
