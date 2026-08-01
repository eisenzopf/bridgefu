//! Manual Gate 11 MOQT relay-session qualification.
//!
//! Each simulated listener is a real raw-QUIC MOQT catalog subscriber. The
//! publisher enters through a distinct mTLS listener and both listeners share
//! an embedded relay topology. rvoip does not yet expose a managed audio-track
//! subscriber, so this harness separately proves origin audio-object creation
//! but does not claim end-to-end audio delivery or media latency.

#[path = "support/qualification.rs"]
mod qualification_support;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use futures_util::future::join_all;
use metrics_exporter_prometheus::PrometheusBuilder;
use qualification_support::{
    bounded_environment_u64, bounded_environment_usize, current_rss_bytes, git_revision,
    host_evidence, memory_growth_percent, prometheus_counter_sum_with_label,
    rvoip_registry_evidence, write_report, HostEvidence, QualificationMode, RevisionEvidence,
    RvoipRegistryEvidence,
};
use rvoip_auth_core::{BearerAuthError, BearerValidator, ValidatedBearer};
use rvoip_core::broadcast::{
    BroadcastHealthDescriptor, BroadcastHealthStatus, BroadcastPublisher, BroadcastSubstrate,
    BroadcastTransport,
};
use rvoip_core::ids::StreamId;
use rvoip_core::stream::{MediaFrame, StreamKind};
use rvoip_core::{AuthenticatedPrincipal, AuthenticationMethod, IdentityAssurance};
use rvoip_moq::{
    BoundedMemoryMoqReplayStore, BoundedMemoryMoqSessionLeaseStore, MoqAction,
    MoqAudioObjectReceiver, MoqAudioReceiveError, MoqAudioSubscriber, MoqAudioSubscriberConfig,
    MoqAudioSubscriberLifecycle, MoqAuthorizer, MoqBroadcastPublisher,
    MoqCatalogSubscriberLifecycle, MoqCatalogSubscriberTlsConfig, MoqNamespace, MoqPeerIdentity,
    MoqProtocolVersion, MoqPublisherConfig, MoqRelayAdmissionConfig, MoqRelayAdmissionSubstrate,
    MoqRelayClient, MoqRelayConnectionPolicy, MoqRelayDeploymentMode, MoqRelayPublisherBinding,
    MoqRelayResourceLimits, MoqRelayRuntime, MoqRelayRuntimeConfig, MoqRelayRuntimeLimits,
    MoqRelayRuntimeSecurity, MoqRelayRuntimeSnapshot, MoqRelayRuntimeTimeouts,
    MoqRelayServerTlsConfig, MoqRelaySubstratePolicy, MoqRelayTlsConfig, MoqRelayTopology,
    MoqResource, MoqRevocationChecker, MoqRevocationError, MoqRevocationStatus,
    MoqSessionLeaseLimits, MoqSubscriberCredential, MoqSubscriberCredentialError,
    MoqSubscriberCredentialProvider, MoqSubscriberCredentialRequest, MoqTokenBinding,
    RvoipMoqRelayAdmission, SecureMoqAuthorizer, MOQT_NEGOTIATED_PROTOCOL,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use url::Url;

const TENANT: &str = "qualification-tenant";
const BROADCAST: &str = "qualification-broadcast";
const FRAME_PERIOD: Duration = Duration::from_millis(20);
const RELEASE_LISTENERS: usize = 10_000;
const RELEASE_DURATION: Duration = Duration::from_secs(60 * 60);
const RELEASE_WARMUP: Duration = Duration::from_secs(5 * 60);
const RELEASE_SUBSCRIBER_ATTEMPTS_PER_SECOND: u64 = 500;
const RELEASE_SETUP_DEADLINE: Duration = Duration::from_secs(10 * 60);
const MAX_RELEASE_MEMORY_GROWTH_PERCENT: f64 = 10.0;
const MAX_AUDIO_DELIVERY_P95_MS: u64 = 100;
const OPUS_SILENCE: &[u8] = &[0x78, 0x00];

const LATENCY_BUCKET_UPPER_US: [u64; 12] = [
    1_000,
    2_500,
    5_000,
    10_000,
    20_000,
    50_000,
    100_000,
    250_000,
    500_000,
    1_000_000,
    2_500_000,
    u64::MAX,
];

#[derive(Clone, Copy)]
struct QualificationParameters {
    listeners: usize,
    active_duration: Duration,
    warmup: Duration,
    attempts_per_second: u64,
    setup_deadline: Duration,
}

impl QualificationMode {
    fn moqt_parameters(self) -> QualificationParameters {
        match self {
            Self::Release => QualificationParameters {
                listeners: RELEASE_LISTENERS,
                active_duration: RELEASE_DURATION,
                warmup: RELEASE_WARMUP,
                attempts_per_second: RELEASE_SUBSCRIBER_ATTEMPTS_PER_SECOND,
                setup_deadline: RELEASE_SETUP_DEADLINE,
            },
            Self::Smoke => QualificationParameters {
                listeners: bounded_environment_usize(
                    "BRIDGEFU_MOQT_SMOKE_LISTENERS",
                    8,
                    1,
                    RELEASE_LISTENERS,
                ),
                active_duration: Duration::from_secs(bounded_environment_u64(
                    "BRIDGEFU_MOQT_SMOKE_SECONDS",
                    5,
                    3,
                    60,
                )),
                warmup: Duration::from_secs(1),
                attempts_per_second: bounded_environment_u64(
                    "BRIDGEFU_MOQT_SMOKE_ATTEMPTS_PER_SECOND",
                    100,
                    1,
                    RELEASE_SUBSCRIBER_ATTEMPTS_PER_SECOND,
                ),
                setup_deadline: Duration::from_secs(30),
            },
        }
    }
}

#[derive(Default)]
struct OriginCounters {
    frames_admitted: AtomicU64,
    frames_dropped: AtomicU64,
}

#[derive(Default)]
struct ListenerAudioCounters {
    received: AtomicU64,
    lagged: AtomicU64,
    unmatched_timestamp: AtomicU64,
}

struct LatencyHistogram {
    buckets: [AtomicU64; LATENCY_BUCKET_UPPER_US.len()],
    samples: AtomicU64,
    maximum_us: AtomicU64,
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        Self {
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            samples: AtomicU64::new(0),
            maximum_us: AtomicU64::new(0),
        }
    }
}

impl LatencyHistogram {
    fn record(&self, latency: Duration) {
        let micros = u64::try_from(latency.as_micros()).unwrap_or(u64::MAX);
        let bucket = LATENCY_BUCKET_UPPER_US
            .iter()
            .position(|upper| micros <= *upper)
            .unwrap_or(LATENCY_BUCKET_UPPER_US.len() - 1);
        self.buckets[bucket].fetch_add(1, Ordering::Relaxed);
        self.samples.fetch_add(1, Ordering::Relaxed);
        self.maximum_us.fetch_max(micros, Ordering::Relaxed);
    }

    fn p95_ms(&self) -> Option<u64> {
        let samples = self.samples.load(Ordering::Relaxed);
        if samples == 0 {
            return None;
        }
        let target = samples.saturating_mul(95).div_ceil(100);
        let mut seen = 0_u64;
        for (index, bucket) in self.buckets.iter().enumerate() {
            seen = seen.saturating_add(bucket.load(Ordering::Relaxed));
            if seen >= target {
                let upper = LATENCY_BUCKET_UPPER_US[index];
                return Some(if upper == u64::MAX {
                    self.maximum_us.load(Ordering::Relaxed).div_ceil(1_000)
                } else {
                    upper.div_ceil(1_000)
                });
            }
        }
        None
    }
}

struct ManagedListener {
    subscriber: Arc<MoqAudioSubscriber>,
    started: Instant,
    setup_ms: Option<u64>,
    audio: Arc<ListenerAudioCounters>,
    task: Option<JoinHandle<()>>,
}

#[derive(Serialize)]
struct MoqtQualificationReport {
    schema: &'static str,
    mode: QualificationMode,
    started_at: DateTime<Utc>,
    finished_at: DateTime<Utc>,
    bridgefu: RevisionEvidence,
    rvoip: RvoipRegistryEvidence,
    host: HostEvidence,
    transport: BroadcastTransport,
    protocol: MoqProtocolVersion,
    negotiated_protocol: String,
    substrate: BroadcastSubstrate,
    relay_path: &'static str,
    listeners_requested: usize,
    listeners_live_at_setup: usize,
    listeners_live_at_finish: usize,
    listeners_terminal_at_finish: usize,
    subscriber_reconnects: u64,
    subscriber_attempts_per_second: u64,
    setup_elapsed_ms: u128,
    subscriber_setup_p95_ms: Option<u64>,
    active_elapsed_ms: u128,
    origin_frames_admitted: u64,
    origin_frames_dropped: u64,
    origin_audio_objects: u64,
    listeners_receiving_audio: usize,
    listener_audio_objects_min: u64,
    listener_audio_objects_max: u64,
    listener_audio_objects_total: u64,
    listener_audio_lagged_objects: u64,
    listener_audio_unmatched_timestamps: u64,
    audio_delivery_samples: u64,
    audio_delivery_p95_ms: Option<u64>,
    audio_delivery_max_ms: Option<u64>,
    delivery_drain_elapsed_ms: u128,
    publisher_health: BroadcastHealthDescriptor,
    publisher_relay_health: BroadcastHealthDescriptor,
    publisher_listener: MoqRelayRuntimeSnapshot,
    subscriber_listener: MoqRelayRuntimeSnapshot,
    warmup_rss_bytes: Option<u64>,
    final_rss_bytes: Option<u64>,
    steady_state_memory_growth_percent: Option<f64>,
    subscriber_cleanup_errors: usize,
    release_thresholds: ReleaseThresholds,
    scope: &'static str,
    passed: bool,
}

#[derive(Serialize)]
struct ReleaseThresholds {
    listeners: usize,
    active_duration_seconds: u64,
    setup_deadline_seconds: u64,
    steady_state_memory_growth_percent: f64,
    audio_delivery_p95_ms: u64,
}

struct TestPki {
    directory: PathBuf,
    server_certificate: PathBuf,
    server_private_key: PathBuf,
    publisher_certificate: PathBuf,
    publisher_private_key: PathBuf,
    publisher_fingerprint: String,
}

impl TestPki {
    fn new() -> Self {
        let (server_certificate, server_private_key) =
            rvoip_uctp::substrate::self_signed_for_dev(&["localhost".into()]).unwrap();
        let (publisher_certificate, publisher_private_key) =
            rvoip_uctp::substrate::self_signed_for_dev(&["publisher.test".into()]).unwrap();
        let directory = std::env::temp_dir().join(format!(
            "bridgefu-moqt-qualification-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        fs::create_dir_all(&directory).unwrap();
        let server_certificate_path = directory.join("server.pem");
        let server_private_key_path = directory.join("server.key");
        let publisher_certificate_path = directory.join("publisher.pem");
        let publisher_private_key_path = directory.join("publisher.key");
        fs::write(
            &server_certificate_path,
            pem("CERTIFICATE", server_certificate.as_ref()),
        )
        .unwrap();
        fs::write(
            &server_private_key_path,
            pem("PRIVATE KEY", server_private_key.secret_der()),
        )
        .unwrap();
        fs::write(
            &publisher_certificate_path,
            pem("CERTIFICATE", publisher_certificate.as_ref()),
        )
        .unwrap();
        fs::write(
            &publisher_private_key_path,
            pem("PRIVATE KEY", publisher_private_key.secret_der()),
        )
        .unwrap();
        Self {
            directory,
            server_certificate: server_certificate_path,
            server_private_key: server_private_key_path,
            publisher_certificate: publisher_certificate_path,
            publisher_private_key: publisher_private_key_path,
            publisher_fingerprint: lower_hex(&Sha256::digest(publisher_certificate.as_ref())),
        }
    }

    fn publisher_server_tls(&self) -> MoqRelayServerTlsConfig {
        MoqRelayServerTlsConfig {
            server_certificates: vec![self.server_certificate.clone()],
            server_private_keys: vec![self.server_private_key.clone()],
            server_root_certificates: vec![self.server_certificate.clone()],
            publisher_client_ca_certificates: vec![self.publisher_certificate.clone()],
            ..MoqRelayServerTlsConfig::default()
        }
    }

    fn subscriber_server_tls(&self) -> MoqRelayServerTlsConfig {
        MoqRelayServerTlsConfig {
            server_certificates: vec![self.server_certificate.clone()],
            server_private_keys: vec![self.server_private_key.clone()],
            server_root_certificates: vec![self.server_certificate.clone()],
            ..MoqRelayServerTlsConfig::default()
        }
    }

    fn publisher_client_tls(&self) -> MoqRelayTlsConfig {
        MoqRelayTlsConfig {
            root_certificates: vec![self.server_certificate.clone()],
            client_certificate: Some(self.publisher_certificate.clone()),
            client_private_key: Some(self.publisher_private_key.clone()),
        }
    }
}

impl Drop for TestPki {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[derive(Clone)]
struct QualificationBearerValidator {
    principal: AuthenticatedPrincipal,
}

#[async_trait]
impl BearerValidator for QualificationBearerValidator {
    async fn validate(&self, token: &str) -> Result<IdentityAssurance, BearerAuthError> {
        if token.is_empty() {
            return Err(BearerAuthError::Empty);
        }
        Ok(self.principal.assurance.clone())
    }

    async fn validate_credential(&self, token: &str) -> Result<ValidatedBearer, BearerAuthError> {
        if token.is_empty() {
            return Err(BearerAuthError::Empty);
        }
        Ok(ValidatedBearer {
            principal: self.principal.clone(),
            token_id: Some(format!("qualification-{token}")),
            issued_at: None,
        })
    }
}

struct AlwaysActiveRevocation;

#[async_trait]
impl MoqRevocationChecker for AlwaysActiveRevocation {
    async fn check(
        &self,
        _peer: &MoqPeerIdentity,
        _action: MoqAction,
        _resource: &MoqResource,
        _binding: &MoqTokenBinding,
        _now: DateTime<Utc>,
    ) -> Result<MoqRevocationStatus, MoqRevocationError> {
        Ok(MoqRevocationStatus::Active)
    }
}

struct FreshCredentials {
    next: AtomicU64,
}

#[async_trait]
impl MoqSubscriberCredentialProvider for FreshCredentials {
    async fn issue(
        &self,
        _request: MoqSubscriberCredentialRequest,
    ) -> Result<MoqSubscriberCredential, MoqSubscriberCredentialError> {
        let next = self.next.fetch_add(1, Ordering::Relaxed);
        MoqSubscriberCredential::new(format!("moqt-qualification-{next}").into_bytes())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 12)]
#[ignore = "manual Gate 11 MOQT relay qualification; select smoke or release explicitly"]
async fn qualifies_moqt_origin_through_relay() {
    let mode = QualificationMode::from_environment("MOQT relay");
    let parameters = mode.moqt_parameters();
    assert!(parameters.warmup < parameters.active_duration);
    let _ = rustls::crypto::ring::default_provider().install_default();
    let metrics = PrometheusBuilder::new()
        .install_recorder()
        .expect("install isolated qualification metrics recorder");
    let started_at = Utc::now();
    let wall_started = Instant::now();
    let pki = TestPki::new();
    let publisher_address = unused_udp_address();
    let subscriber_address = unused_udp_address();
    assert_ne!(publisher_address, subscriber_address);

    let topology =
        MoqRelayTopology::new(endpoint(publisher_address), Some(publisher_address), 8).unwrap();
    let publisher_runtime = MoqRelayRuntime::start_with_topology(
        runtime_config(
            publisher_address,
            pki.publisher_server_tls(),
            MoqRelayRuntimeSecurity::PublisherMutualTls {
                bindings: vec![MoqRelayPublisherBinding {
                    certificate_sha256: pki.publisher_fingerprint.clone(),
                    scope: format!("/{TENANT}/{BROADCAST}"),
                }],
                max_active_sessions_per_certificate: 4,
            },
            8,
        ),
        topology.clone(),
    )
    .unwrap();
    let subscriber_runtime = MoqRelayRuntime::start_with_topology(
        runtime_config(
            subscriber_address,
            pki.subscriber_server_tls(),
            MoqRelayRuntimeSecurity::SubscriberRawQuic {
                admission: subscriber_admission(parameters.listeners),
            },
            parameters.listeners,
        ),
        topology.clone(),
    )
    .unwrap();

    let publisher = MoqBroadcastPublisher::new(MoqPublisherConfig {
        tenant_id: TENANT.to_owned(),
        broadcast_id: BROADCAST.to_owned(),
        bitrate: 32_000,
        language: None,
        queue_frames: 10,
    })
    .unwrap();
    let descriptor = publisher.descriptor();
    assert_eq!(descriptor.transport, BroadcastTransport::Moqt);
    let relay_client = MoqRelayClient::bind_with_policy(
        "127.0.0.1:0".parse().unwrap(),
        pki.publisher_client_tls(),
        MoqRelayConnectionPolicy {
            attempt_timeout: Duration::from_secs(10),
            publish_namespace_acceptance_timeout: Duration::from_secs(5),
            substrate: MoqRelaySubstratePolicy::RawQuic,
            max_reconnect_attempts: 1,
            reconnect_initial_backoff: Duration::from_millis(20),
            reconnect_max_backoff: Duration::from_millis(20),
            reconnect_deadline: Duration::from_secs(5),
            jitter_percent: 0,
        },
    )
    .unwrap();
    let publish_target = Url::parse(&format!(
        "moqt://localhost:{}/{TENANT}/{BROADCAST}",
        publisher_address.port()
    ))
    .unwrap();
    let publication = tokio::time::timeout(
        Duration::from_secs(15),
        publisher.publish_to_relay(&relay_client, &publish_target),
    )
    .await
    .expect("publisher relay connection timed out")
    .expect("publisher relay connection failed");
    assert_eq!(publication.substrate, BroadcastSubstrate::RawQuic);
    assert_eq!(publication.negotiated_protocol, MOQT_NEGOTIATED_PROTOCOL);

    let namespace = MoqNamespace::new(TENANT, BROADCAST).unwrap();
    let subscriber_target = Url::parse(&format!(
        "moqt://localhost:{}/{TENANT}/{BROADCAST}",
        subscriber_address.port()
    ))
    .unwrap();
    let credentials: Arc<dyn MoqSubscriberCredentialProvider> = Arc::new(FreshCredentials {
        next: AtomicU64::new(1),
    });
    let sent_at = Arc::new(DashMap::<u64, Instant>::new());
    let latency = Arc::new(LatencyHistogram::default());
    let listener_cancellation = CancellationToken::new();
    let setup_started = Instant::now();
    let mut subscribers = Vec::with_capacity(parameters.listeners);
    let attempt_period = Duration::from_secs_f64(1.0 / parameters.attempts_per_second as f64);
    let mut ramp = tokio::time::interval_at(tokio::time::Instant::now(), attempt_period);
    ramp.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    for _ in 0..parameters.listeners {
        ramp.tick().await;
        let listener_started = Instant::now();
        let mut config =
            MoqAudioSubscriberConfig::new(subscriber_target.clone(), namespace.clone());
        config.catalog.substrate = MoqRelaySubstratePolicy::RawQuic;
        config.catalog.attempt_timeout = Duration::from_secs(10);
        config.catalog.max_reconnect_attempts = 1;
        config.catalog.reconnect_initial_backoff = Duration::from_millis(20);
        config.catalog.reconnect_max_backoff = Duration::from_millis(20);
        config.catalog.reconnect_deadline = Duration::from_secs(15);
        let subscriber = MoqAudioSubscriber::bind(
            "127.0.0.1:0".parse().unwrap(),
            config,
            MoqCatalogSubscriberTlsConfig {
                root_certificates: vec![pki.server_certificate.clone()],
            },
            Arc::clone(&credentials),
        )
        .unwrap();
        let audio = Arc::new(ListenerAudioCounters::default());
        let task = spawn_listener_audio_collector(
            subscriber.audio_objects(),
            Arc::clone(&audio),
            Arc::clone(&sent_at),
            Arc::clone(&latency),
            listener_cancellation.clone(),
        );
        subscribers.push(ManagedListener {
            subscriber,
            started: listener_started,
            setup_ms: None,
            audio,
            task: Some(task),
        });
    }
    let listeners_live_at_setup =
        wait_for_live_subscribers(&mut subscribers, parameters.setup_deadline).await;
    let setup_elapsed = setup_started.elapsed();
    let subscriber_setup_p95_ms = setup_p95_ms(&subscribers);

    let counters = Arc::new(OriginCounters::default());
    let cancellation = CancellationToken::new();
    let source = (listeners_live_at_setup == parameters.listeners).then(|| {
        spawn_origin_source(
            publisher.frames_out(),
            Arc::clone(&counters),
            Arc::clone(&sent_at),
            cancellation.clone(),
        )
    });
    let active_started = Instant::now();
    let (warmup_rss_bytes, final_rss_bytes, active_elapsed) = if source.is_some() {
        tokio::time::sleep(parameters.warmup).await;
        let warmup = current_rss_bytes();
        tokio::time::sleep(parameters.active_duration - parameters.warmup).await;
        (warmup, current_rss_bytes(), active_started.elapsed())
    } else {
        (None, None, Duration::ZERO)
    };
    cancellation.cancel();
    if let Some(source) = source {
        source.await.expect("MOQT origin source task panicked");
    }

    let origin_frames_admitted = counters.frames_admitted.load(Ordering::Relaxed);
    let origin_frames_dropped = counters.frames_dropped.load(Ordering::Relaxed);
    let delivery_drain_started = Instant::now();
    wait_for_listener_audio(
        &subscribers,
        origin_frames_admitted,
        match mode {
            QualificationMode::Smoke => Duration::from_secs(10),
            QualificationMode::Release => Duration::from_secs(60),
        },
    )
    .await;
    let delivery_drain_elapsed = delivery_drain_started.elapsed();
    let listeners_live_at_finish = subscribers
        .iter()
        .filter(|listener| {
            listener.subscriber.snapshot().lifecycle == MoqCatalogSubscriberLifecycle::Live
                && listener.subscriber.audio_snapshot().lifecycle
                    == MoqAudioSubscriberLifecycle::Live
        })
        .count();
    let listeners_terminal_at_finish = subscribers
        .iter()
        .filter(|listener| listener.subscriber.snapshot().is_terminal())
        .count();
    let subscriber_reconnects = subscribers
        .iter()
        .map(|listener| u64::from(listener.subscriber.snapshot().reconnects))
        .sum();
    let listener_counts = subscribers
        .iter()
        .map(|listener| listener.audio.received.load(Ordering::Relaxed))
        .collect::<Vec<_>>();
    let listeners_receiving_audio = listener_counts.iter().filter(|count| **count > 0).count();
    let listener_audio_objects_min = listener_counts.iter().copied().min().unwrap_or(0);
    let listener_audio_objects_max = listener_counts.iter().copied().max().unwrap_or(0);
    let listener_audio_objects_total = listener_counts.iter().copied().sum();
    let listener_audio_lagged_objects = subscribers
        .iter()
        .map(|listener| listener.audio.lagged.load(Ordering::Relaxed))
        .sum();
    let listener_audio_unmatched_timestamps = subscribers
        .iter()
        .map(|listener| listener.audio.unmatched_timestamp.load(Ordering::Relaxed))
        .sum();
    let audio_delivery_samples = latency.samples.load(Ordering::Relaxed);
    let audio_delivery_p95_ms = latency.p95_ms();
    let audio_delivery_max_us = latency.maximum_us.load(Ordering::Relaxed);
    let audio_delivery_max_ms =
        (audio_delivery_samples > 0).then(|| audio_delivery_max_us.div_ceil(1_000));
    let origin_audio_objects = wait_for_audio_objects(&metrics, origin_frames_admitted).await;
    let publisher_health = publisher.health();
    let publisher_relay_health = publication.health();
    let publisher_listener = publisher_runtime.snapshot().await;
    let subscriber_listener = subscriber_runtime.snapshot().await;
    let steady_state_memory_growth_percent =
        memory_growth_percent(warmup_rss_bytes, final_rss_bytes);

    listener_cancellation.cancel();
    for listener in &mut subscribers {
        if let Some(task) = listener.task.take() {
            task.await.expect("listener audio collector panicked");
        }
    }
    let mut subscriber_cleanup_errors = 0_usize;
    for chunk in subscribers.chunks(256) {
        subscriber_cleanup_errors +=
            join_all(chunk.iter().map(|listener| async move {
                listener.subscriber.close().await.is_err() as usize
            }))
            .await
            .into_iter()
            .sum::<usize>();
    }
    Arc::clone(&publisher)
        .close()
        .await
        .expect("close MOQT publisher");
    tokio::time::timeout(Duration::from_secs(10), publication.wait())
        .await
        .expect("publisher relay completion timed out")
        .expect("publisher relay completion failed");
    subscriber_runtime
        .drain(Duration::from_secs(30))
        .await
        .unwrap();
    publisher_runtime
        .drain(Duration::from_secs(10))
        .await
        .unwrap();

    let common_passed = listeners_live_at_setup == parameters.listeners
        && listeners_live_at_finish == parameters.listeners
        && listeners_terminal_at_finish == 0
        && subscriber_reconnects == 0
        && setup_elapsed <= parameters.setup_deadline
        && origin_frames_admitted > 0
        && origin_frames_dropped == 0
        && origin_audio_objects == origin_frames_admitted
        && listeners_receiving_audio == parameters.listeners
        && listener_audio_objects_min == origin_frames_admitted
        && listener_audio_objects_max == origin_frames_admitted
        && listener_audio_lagged_objects == 0
        && listener_audio_unmatched_timestamps == 0
        && audio_delivery_samples == listener_audio_objects_total
        && audio_delivery_p95_ms.is_some_and(|value| value < MAX_AUDIO_DELIVERY_P95_MS)
        && publisher_health.status == BroadcastHealthStatus::Healthy
        && publisher_relay_health.status == BroadcastHealthStatus::Healthy
        && publisher_listener.ready()
        && subscriber_listener.ready()
        && subscriber_cleanup_errors == 0;
    let passed = common_passed
        && match mode {
            QualificationMode::Smoke => true,
            QualificationMode::Release => {
                active_elapsed >= RELEASE_DURATION
                    && steady_state_memory_growth_percent
                        .is_some_and(|value| value < MAX_RELEASE_MEMORY_GROWTH_PERCENT)
            }
        };

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let report = MoqtQualificationReport {
        schema: "bridgefu.qualification.moqt-relay.v3",
        mode,
        started_at,
        finished_at: Utc::now(),
        bridgefu: git_revision(&manifest_dir),
        rvoip: rvoip_registry_evidence(&manifest_dir),
        host: host_evidence(),
        transport: descriptor.transport,
        protocol: publisher.protocol_version(),
        negotiated_protocol: publication.negotiated_protocol.clone(),
        substrate: publication.substrate,
        relay_path: publication.relay_path,
        listeners_requested: parameters.listeners,
        listeners_live_at_setup,
        listeners_live_at_finish,
        listeners_terminal_at_finish,
        subscriber_reconnects,
        subscriber_attempts_per_second: parameters.attempts_per_second,
        setup_elapsed_ms: setup_elapsed.as_millis(),
        subscriber_setup_p95_ms,
        active_elapsed_ms: active_elapsed.as_millis(),
        origin_frames_admitted,
        origin_frames_dropped,
        origin_audio_objects,
        listeners_receiving_audio,
        listener_audio_objects_min,
        listener_audio_objects_max,
        listener_audio_objects_total,
        listener_audio_lagged_objects,
        listener_audio_unmatched_timestamps,
        audio_delivery_samples,
        audio_delivery_p95_ms,
        audio_delivery_max_ms,
        delivery_drain_elapsed_ms: delivery_drain_elapsed.as_millis(),
        publisher_health,
        publisher_relay_health,
        publisher_listener,
        subscriber_listener,
        warmup_rss_bytes,
        final_rss_bytes,
        steady_state_memory_growth_percent,
        subscriber_cleanup_errors,
        release_thresholds: ReleaseThresholds {
            listeners: RELEASE_LISTENERS,
            active_duration_seconds: RELEASE_DURATION.as_secs(),
            setup_deadline_seconds: RELEASE_SETUP_DEADLINE.as_secs(),
            steady_state_memory_growth_percent: MAX_RELEASE_MEMORY_GROWTH_PERCENT,
            audio_delivery_p95_ms: MAX_AUDIO_DELIVERY_P95_MS,
        },
        scope: "real raw-QUIC publisher and managed MSF/LOC audio-subscriber sessions through role-separated embedded relay listeners; every listener receipt and source-admission-to-receiver latency sample is measured",
        passed,
    };
    let report_path = write_report(
        &manifest_dir,
        "BRIDGEFU_MOQT_QUALIFICATION_OUTPUT",
        "moqt-relay",
        started_at,
        &report,
    );
    eprintln!("MOQT qualification report: {}", report_path.display());
    eprintln!(
        "MOQT qualification wall time: {:.2?}",
        wall_started.elapsed()
    );
    assert!(
        passed,
        "MOQT relay qualification failed; retained evidence is at {}",
        report_path.display()
    );
}

fn subscriber_admission(listeners: usize) -> Arc<RvoipMoqRelayAdmission> {
    let principal = AuthenticatedPrincipal {
        subject: "qualification-listener".to_owned(),
        tenant: Some(TENANT.to_owned()),
        scopes: vec![format!("broadcast:subscribe:{BROADCAST}")],
        issuer: Some("https://qualification.invalid".to_owned()),
        expires_at: Some(Utc::now() + chrono::Duration::hours(2)),
        method: AuthenticationMethod::Jwt,
        assurance: IdentityAssurance::Anonymous,
    };
    let validator: Arc<dyn BearerValidator> = Arc::new(QualificationBearerValidator { principal });
    let replay = Arc::new(
        BoundedMemoryMoqReplayStore::new(listeners.saturating_mul(2).saturating_add(128)).unwrap(),
    );
    let revocation: Arc<dyn MoqRevocationChecker> = Arc::new(AlwaysActiveRevocation);
    let authorizer: Arc<dyn MoqAuthorizer> = Arc::new(SecureMoqAuthorizer::new(replay, revocation));
    let capacity = listeners.saturating_add(32);
    let leases = Arc::new(
        BoundedMemoryMoqSessionLeaseStore::new(
            MoqSessionLeaseLimits::new(capacity, capacity).unwrap(),
        )
        .unwrap(),
    );
    Arc::new(
        RvoipMoqRelayAdmission::with_config(
            validator,
            authorizer,
            leases,
            MoqRelayAdmissionConfig::for_substrate(
                Duration::from_secs(5),
                MoqRelayAdmissionSubstrate::RawQuic,
            )
            .unwrap(),
        )
        .unwrap(),
    )
}

fn runtime_config(
    bind: SocketAddr,
    tls: MoqRelayServerTlsConfig,
    security: MoqRelayRuntimeSecurity,
    listeners: usize,
) -> MoqRelayRuntimeConfig {
    MoqRelayRuntimeConfig {
        deployment: MoqRelayDeploymentMode::Embedded,
        bind,
        advertised_endpoint: endpoint(bind),
        advertised_socket_addr: Some(bind),
        tls,
        security,
        limits: relay_limits(listeners),
        timeouts: MoqRelayRuntimeTimeouts::default(),
    }
}

fn relay_limits(listeners: usize) -> MoqRelayRuntimeLimits {
    let capacity = listeners.saturating_add(32);
    let resource = MoqRelayResourceLimits {
        total: capacity.saturating_mul(8),
        publish_namespaces: 32,
        publish_tracks: 64,
        subscribes: capacity.saturating_mul(2),
        track_statuses: capacity.saturating_mul(2),
        fetches: capacity.saturating_mul(2),
    };
    MoqRelayRuntimeLimits {
        max_pending_admissions: capacity.clamp(32, 2_048),
        max_active_sessions: capacity,
        process: resource,
        per_principal: resource,
        per_scope: resource,
        ..MoqRelayRuntimeLimits::default()
    }
}

async fn wait_for_live_subscribers(
    subscribers: &mut [ManagedListener],
    timeout: Duration,
) -> usize {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let mut live = 0_usize;
        let mut terminal = 0_usize;
        for listener in subscribers.iter_mut() {
            let snapshot = listener.subscriber.snapshot();
            let audio = listener.subscriber.audio_snapshot();
            if snapshot.lifecycle == MoqCatalogSubscriberLifecycle::Live
                && audio.lifecycle == MoqAudioSubscriberLifecycle::Live
            {
                live += 1;
                listener
                    .setup_ms
                    .get_or_insert(listener.started.elapsed().as_millis() as u64);
            } else if snapshot.is_terminal() || audio.lifecycle.is_terminal() {
                terminal += 1;
            }
        }
        if live == subscribers.len() || terminal > 0 || tokio::time::Instant::now() >= deadline {
            return live;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn setup_p95_ms(subscribers: &[ManagedListener]) -> Option<u64> {
    let mut values = subscribers
        .iter()
        .filter_map(|listener| listener.setup_ms)
        .collect::<Vec<_>>();
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    let index = ((values.len() as f64 * 0.95).ceil() as usize)
        .saturating_sub(1)
        .min(values.len() - 1);
    Some(values[index])
}

fn spawn_origin_source(
    sender: mpsc::Sender<MediaFrame>,
    counters: Arc<OriginCounters>,
    sent_at: Arc<DashMap<u64, Instant>>,
    cancellation: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let stream_id = StreamId::new();
        let mut timestamp = 0_u32;
        let mut interval = tokio::time::interval_at(tokio::time::Instant::now(), FRAME_PERIOD);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => break,
                _ = interval.tick() => {
                    let timestamp_key = u64::from(timestamp);
                    let frame = MediaFrame {
                        stream_id: stream_id.clone(),
                        kind: StreamKind::Audio,
                        payload: Bytes::from_static(OPUS_SILENCE),
                        timestamp_rtp: timestamp,
                        captured_at: Utc::now(),
                        payload_type: Some(111),
                    };
                    timestamp = timestamp.wrapping_add(960);
                    sent_at.insert(timestamp_key, Instant::now());
                    match sender.try_send(frame) {
                        Ok(()) => {
                            counters.frames_admitted.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            sent_at.remove(&timestamp_key);
                            counters.frames_dropped.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            sent_at.remove(&timestamp_key);
                            break;
                        }
                    }
                }
            }
        }
    })
}

fn spawn_listener_audio_collector(
    mut receiver: MoqAudioObjectReceiver,
    counters: Arc<ListenerAudioCounters>,
    sent_at: Arc<DashMap<u64, Instant>>,
    latency: Arc<LatencyHistogram>,
    cancellation: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let received = tokio::select! {
                biased;
                () = cancellation.cancelled() => break,
                received = receiver.recv() => received,
            };
            match received {
                Ok(received) => {
                    counters.received.fetch_add(1, Ordering::Relaxed);
                    if let Some(sent) = sent_at.get(&received.object.timestamp) {
                        latency.record(sent.elapsed());
                    } else {
                        counters.unmatched_timestamp.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(MoqAudioReceiveError::Lagged { skipped }) => {
                    counters.lagged.fetch_add(skipped, Ordering::Relaxed);
                }
                Err(MoqAudioReceiveError::Closed) => break,
            }
        }
    })
}

async fn wait_for_listener_audio(
    listeners: &[ManagedListener],
    expected_per_listener: u64,
    timeout: Duration,
) {
    if expected_per_listener == 0 {
        return;
    }
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if listeners.iter().all(|listener| {
            listener.audio.received.load(Ordering::Relaxed) >= expected_per_listener
        }) || tokio::time::Instant::now() >= deadline
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_for_audio_objects(
    metrics: &metrics_exporter_prometheus::PrometheusHandle,
    expected: u64,
) -> u64 {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let objects = prometheus_counter_sum_with_label(
            &metrics.render(),
            "rvoip_moq_objects_total",
            "track=\"audio\"",
        );
        if objects >= expected || tokio::time::Instant::now() >= deadline {
            return objects;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn unused_udp_address() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.local_addr().unwrap()
}

fn endpoint(address: SocketAddr) -> Url {
    Url::parse(&format!("moqt://localhost:{}", address.port())).unwrap()
}

fn pem(label: &str, bytes: &[u8]) -> String {
    let encoded = STANDARD.encode(bytes);
    let mut output = format!("-----BEGIN {label}-----\n");
    for line in encoded.as_bytes().chunks(64) {
        output.push_str(std::str::from_utf8(line).unwrap());
        output.push('\n');
    }
    output.push_str(&format!("-----END {label}-----\n"));
    output
}

fn lower_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut output, byte| {
            write!(output, "{byte:02x}").expect("writing to a String cannot fail");
            output
        },
    )
}
