//! Manual Gate 11 authenticated raw-QUIC UCTP network qualification.
//!
//! Unlike `qualification_uctp_fanout`, this harness creates one real QUIC
//! connection per listener and crosses Bridgefu's production public-listener,
//! token, Session resolver, rvoip Orchestrator subscription, MediaGraph, and
//! complete-RTP datagram boundaries. It remains ignored: a smoke proves the
//! topology works locally, never the immutable 1,000-listener/one-hour result.

#[path = "support/qualification.rs"]
mod qualification_support;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bridgefu::broadcast::{
    BroadcastGrantRegistry, BroadcastGrantTransport, BroadcastTokenService, PublicUctpBindConfig,
    PublicUctpBroadcastListener, DEFAULT_MAX_BROADCAST_TOKEN_TTL,
};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use metrics_exporter_prometheus::PrometheusBuilder;
use qualification_support::{
    bounded_environment_u64, bounded_environment_usize, current_rss_bytes, git_revision,
    host_evidence, memory_growth_percent, prometheus_counter_sum, write_report, HostEvidence,
    LatencyHistogram, QualificationMode, RevisionEvidence,
};
use rvoip_auth_core::BearerValidator;
use rvoip_core::adapter::{
    AdapterEvent, AdapterKind, ConnectionAdapter, ConnectionHandle, EndReason, OriginateRequest,
    RejectReason, SignatureHeaders, TransferTarget,
};
use rvoip_core::capability::{CapabilityDescriptor, CodecInfo, NegotiatedCodecs};
use rvoip_core::connection::{Connection, ConnectionState, Direction, Transport, TransportHandle};
use rvoip_core::identity::IdentityAssurance;
use rvoip_core::ids::{ConnectionId, ParticipantId, SessionId, StreamId};
use rvoip_core::message::Message;
use rvoip_core::stream::{MediaFrame, MediaStream, QualitySnapshot, StreamKind};
use rvoip_core::{Config, Orchestrator, Result as RvoipResult, RvoipError};
use rvoip_quic::{UctpQuicClient, UCTP_QUIC_PROTOCOL_VERSION};
use rvoip_uctp::envelope::UctpEnvelope;
use rvoip_uctp::payloads::{auth, connection, session, stream};
use rvoip_uctp::substrate::{
    dev_client_config_trusting, make_client_endpoint, self_signed_for_dev, unpack_rtp_datagram,
};
use rvoip_uctp::types::MessageType;
use serde::Serialize;
use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const TENANT_ID: &str = "qualification-tenant";
const BROADCAST_ID: &str = "qualification-uctp-network";
const PUBLISHED_STREAM_ID: &str = "audio/main";
const FRAME_PERIOD: Duration = Duration::from_millis(20);
const RELEASE_LISTENERS: usize = 1_000;
const RELEASE_DURATION: Duration = Duration::from_secs(60 * 60);
const RELEASE_WARMUP: Duration = Duration::from_secs(5 * 60);
const RELEASE_ATTEMPTS_PER_SECOND: usize = 100;
const RELEASE_SETUP_DEADLINE: Duration = Duration::from_secs(10 * 60);
const TOKEN_TTL: Duration = Duration::from_secs(10 * 60);
const TOKEN_REFRESH_PERIOD: Duration = Duration::from_secs(5 * 60);
const MAX_RELEASE_P95_US: u64 = 100_000;
const MAX_RELEASE_MEMORY_GROWTH_PERCENT: f64 = 10.0;
const MIN_DELIVERY_RATIO: f64 = 0.99;
const OPUS_SILENCE: &[u8] = &[0x78, 0x00];

#[derive(Clone, Copy)]
struct QualificationParameters {
    listeners: usize,
    active_duration: Duration,
    warmup: Duration,
    attempts_per_second: usize,
    setup_deadline: Duration,
    initial_token_ttl: Duration,
    token_ttl: Duration,
    token_refresh_period: Duration,
}

impl QualificationMode {
    fn uctp_network_parameters(self) -> QualificationParameters {
        match self {
            Self::Release => QualificationParameters {
                listeners: RELEASE_LISTENERS,
                active_duration: RELEASE_DURATION,
                warmup: RELEASE_WARMUP,
                attempts_per_second: RELEASE_ATTEMPTS_PER_SECOND,
                setup_deadline: RELEASE_SETUP_DEADLINE,
                initial_token_ttl: TOKEN_TTL,
                token_ttl: TOKEN_TTL,
                token_refresh_period: TOKEN_REFRESH_PERIOD,
            },
            Self::Smoke => QualificationParameters {
                listeners: bounded_environment_usize(
                    "BRIDGEFU_UCTP_NETWORK_SMOKE_LISTENERS",
                    4,
                    1,
                    32,
                ),
                active_duration: Duration::from_secs(bounded_environment_u64(
                    "BRIDGEFU_UCTP_NETWORK_SMOKE_SECONDS",
                    3,
                    3,
                    60,
                )),
                warmup: Duration::from_secs(1),
                attempts_per_second: bounded_environment_usize(
                    "BRIDGEFU_UCTP_NETWORK_SMOKE_ATTEMPTS_PER_SECOND",
                    50,
                    1,
                    RELEASE_ATTEMPTS_PER_SECOND,
                ),
                setup_deadline: Duration::from_secs(30),
                initial_token_ttl: Duration::from_secs(3),
                token_ttl: Duration::from_secs(6),
                token_refresh_period: Duration::from_secs(1),
            },
        }
    }
}

#[derive(Serialize)]
struct UctpNetworkQualificationReport {
    schema: &'static str,
    mode: QualificationMode,
    started_at: DateTime<Utc>,
    finished_at: DateTime<Utc>,
    bridgefu: RevisionEvidence,
    rvoip: RevisionEvidence,
    host: HostEvidence,
    transport: &'static str,
    protocol_version: &'static str,
    media_profile: &'static str,
    listeners: usize,
    setup_attempts_per_second: usize,
    setup_elapsed_ms: u128,
    setup_p95_us: Option<u64>,
    authenticated_connections_observed: usize,
    media_ready_listeners: usize,
    active_elapsed_ms: u128,
    source_frames: u64,
    expected_deliveries: u64,
    deliveries: u64,
    delivery_ratio: f64,
    minimum_listener_deliveries: u64,
    maximum_listener_deliveries: u64,
    complete_rtp_datagrams: u64,
    invalid_datagrams: u64,
    sequence_discontinuities: u64,
    unmatched_timestamps: u64,
    latency_p95_upper_bound_us: Option<u64>,
    token_refreshes: u64,
    initial_credential_ttl_seconds: u64,
    credential_ttl_seconds: u64,
    credential_refresh_period_seconds: u64,
    refresh_replay_id_rotated: bool,
    initial_token_replay_rejected: bool,
    refreshed_token_replay_rejected_after_initial_expiry: bool,
    unsubscribe_acks: usize,
    connection_end_events: usize,
    adapter_routes_retained: usize,
    orchestrator_connections_retained: usize,
    direct_listener_permits_after_cleanup: usize,
    publisher_registration_retained: bool,
    publisher_route_terminal: bool,
    warmup_rss_bytes: Option<u64>,
    final_rss_bytes: Option<u64>,
    steady_state_memory_growth_percent: Option<f64>,
    network_datagrams_sent_metric: u64,
    virtual_publisher_deliveries_metric: u64,
    per_listener: Vec<ListenerEvidence>,
    release_parameters: ReleaseParameters,
    scope: &'static str,
    release_criterion_satisfied: bool,
    passed: bool,
}

#[derive(Serialize)]
struct ReleaseParameters {
    listeners: usize,
    active_duration_seconds: u64,
    warmup_seconds: u64,
    attempts_per_second: usize,
    setup_deadline_seconds: u64,
    token_ttl_seconds: u64,
    token_refresh_period_seconds: u64,
    minimum_delivery_ratio: f64,
    latency_p95_us: u64,
    steady_state_memory_growth_percent: f64,
}

#[derive(Serialize)]
struct ListenerEvidence {
    setup_us: u64,
    media_stream_opened: bool,
    deliveries: u64,
    complete_rtp_datagrams: u64,
    invalid_datagrams: u64,
    sequence_discontinuities: u64,
    unmatched_timestamps: u64,
    latency_p95_upper_bound_us: Option<u64>,
    token_refreshes: u64,
    protocol_errors: u64,
    unsubscribe_acknowledged: bool,
    connection_end_sent: bool,
    connection_closed: bool,
}

struct SourceStream {
    id: StreamId,
    inbound: Mutex<Option<mpsc::Receiver<MediaFrame>>>,
    outbound: mpsc::Sender<MediaFrame>,
}

impl SourceStream {
    fn new() -> (Arc<Self>, mpsc::Sender<MediaFrame>) {
        let (inbound_tx, inbound_rx) = mpsc::channel(64);
        let (outbound, _outbound_rx) = mpsc::channel(1);
        (
            Arc::new(Self {
                id: StreamId::from_string("qualification-source"),
                inbound: Mutex::new(Some(inbound_rx)),
                outbound,
            }),
            inbound_tx,
        )
    }
}

#[async_trait]
impl MediaStream for SourceStream {
    fn id(&self) -> StreamId {
        self.id.clone()
    }

    fn kind(&self) -> StreamKind {
        StreamKind::Audio
    }

    fn codec(&self) -> CodecInfo {
        CodecInfo::from_name_with_defaults("opus")
    }

    fn direction(&self) -> Direction {
        Direction::Inbound
    }

    fn frames_in(&self) -> mpsc::Receiver<MediaFrame> {
        self.inbound
            .lock()
            .expect("qualification source receiver lock")
            .take()
            .unwrap_or_else(|| mpsc::channel(1).1)
    }

    fn try_frames_in(&self) -> RvoipResult<mpsc::Receiver<MediaFrame>> {
        self.inbound
            .lock()
            .expect("qualification source receiver lock")
            .take()
            .ok_or(RvoipError::InvalidState(
                "qualification source receiver already acquired",
            ))
    }

    fn frames_out(&self) -> mpsc::Sender<MediaFrame> {
        self.outbound.clone()
    }

    fn quality_snapshot(&self) -> QualitySnapshot {
        QualitySnapshot::default()
    }

    async fn close(self: Arc<Self>) -> RvoipResult<()> {
        Ok(())
    }
}

struct SourceAdapter {
    connection_id: ConnectionId,
    stream: Arc<SourceStream>,
    events: Mutex<Option<mpsc::Receiver<AdapterEvent>>>,
}

impl SourceAdapter {
    fn new(
        connection_id: ConnectionId,
        stream: Arc<SourceStream>,
    ) -> (Arc<Self>, mpsc::Sender<AdapterEvent>) {
        let (events_tx, events_rx) = mpsc::channel(16);
        (
            Arc::new(Self {
                connection_id,
                stream,
                events: Mutex::new(Some(events_rx)),
            }),
            events_tx,
        )
    }
}

#[async_trait]
impl ConnectionAdapter for SourceAdapter {
    fn transport(&self) -> Transport {
        Transport::Sip
    }

    fn kind(&self) -> AdapterKind {
        AdapterKind::Substrate
    }

    async fn originate(&self, _: OriginateRequest) -> RvoipResult<ConnectionHandle> {
        Err(RvoipError::NotImplemented("qualification source originate"))
    }

    async fn accept(&self, _: ConnectionId) -> RvoipResult<()> {
        Ok(())
    }

    async fn reject(&self, _: ConnectionId, _: RejectReason) -> RvoipResult<()> {
        Ok(())
    }

    async fn end(&self, _: ConnectionId, _: EndReason) -> RvoipResult<()> {
        Ok(())
    }

    async fn hold(&self, _: ConnectionId) -> RvoipResult<()> {
        Ok(())
    }

    async fn resume(&self, _: ConnectionId) -> RvoipResult<()> {
        Ok(())
    }

    async fn transfer(&self, _: ConnectionId, _: TransferTarget) -> RvoipResult<()> {
        Ok(())
    }

    async fn streams(&self, connection_id: ConnectionId) -> RvoipResult<Vec<Arc<dyn MediaStream>>> {
        if connection_id != self.connection_id {
            return Err(RvoipError::ConnectionNotFound(connection_id));
        }
        Ok(vec![Arc::clone(&self.stream) as Arc<dyn MediaStream>])
    }

    async fn send_message(&self, _: ConnectionId, _: Message) -> RvoipResult<()> {
        Ok(())
    }

    async fn send_dtmf(&self, _: ConnectionId, _: &str, _: u32) -> RvoipResult<()> {
        Ok(())
    }

    async fn renegotiate_media(
        &self,
        _: ConnectionId,
        _: CapabilityDescriptor,
    ) -> RvoipResult<NegotiatedCodecs> {
        Ok(NegotiatedCodecs::default())
    }

    fn subscribe_events(&self) -> mpsc::Receiver<AdapterEvent> {
        self.events
            .lock()
            .expect("qualification source event lock")
            .take()
            .expect("qualification source events subscribed exactly once")
    }

    fn capabilities(&self) -> CapabilityDescriptor {
        CapabilityDescriptor::default()
    }

    async fn verify_request_signature(
        &self,
        _: ConnectionId,
        _: SignatureHeaders,
    ) -> RvoipResult<IdentityAssurance> {
        Ok(IdentityAssurance::Anonymous)
    }
}

struct NetworkListener {
    client: Arc<UctpQuicClient>,
    inbound: mpsc::Receiver<UctpEnvelope>,
    token: String,
    current_token: Arc<Mutex<String>>,
    wire_connection: String,
    setup_us: u64,
}

#[derive(Default)]
struct ListenerAccumulator {
    deliveries: u64,
    complete_rtp_datagrams: u64,
    invalid_datagrams: u64,
    sequence_discontinuities: u64,
    unmatched_timestamps: u64,
    token_refreshes: u64,
    protocol_errors: u64,
    last_sequence: Option<u16>,
}

impl ListenerAccumulator {
    fn observe_datagram(
        &mut self,
        bytes: &[u8],
        stream_local_id: u16,
        measuring: bool,
        emissions: &dashmap::DashMap<u32, DateTime<Utc>>,
        latency: &LatencyHistogram,
        aggregate_latency: &LatencyHistogram,
    ) {
        let Ok(datagram) = unpack_rtp_datagram(bytes) else {
            if measuring {
                self.invalid_datagrams = self.invalid_datagrams.saturating_add(1);
            }
            return;
        };
        if datagram.stream_local_id != stream_local_id {
            if measuring {
                self.invalid_datagrams = self.invalid_datagrams.saturating_add(1);
            }
            return;
        }
        if !measuring {
            return;
        }
        if datagram.rtp.payload_type != 111
            || datagram.rtp.payload.as_ref() != OPUS_SILENCE
            || bytes.len() < 8 + 12 + OPUS_SILENCE.len()
        {
            self.invalid_datagrams = self.invalid_datagrams.saturating_add(1);
            return;
        }
        self.deliveries = self.deliveries.saturating_add(1);
        self.complete_rtp_datagrams = self.complete_rtp_datagrams.saturating_add(1);
        if let Some(previous) = self.last_sequence {
            if datagram.rtp.sequence_number != previous.wrapping_add(1) {
                self.sequence_discontinuities = self.sequence_discontinuities.saturating_add(1);
            }
        }
        self.last_sequence = Some(datagram.rtp.sequence_number);
        if let Some(emitted_at) = emissions.get(&datagram.rtp.timestamp) {
            latency.observe(*emitted_at);
            aggregate_latency.observe(*emitted_at);
        } else {
            self.unmatched_timestamps = self.unmatched_timestamps.saturating_add(1);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "manual Gate 11 real-network UCTP qualification; select smoke or release explicitly"]
async fn qualifies_authenticated_uctp_network_fanout() {
    let mode = QualificationMode::from_environment("UCTP network fanout");
    let parameters = mode.uctp_network_parameters();
    assert!(parameters.warmup < parameters.active_duration);
    let _ = rustls::crypto::ring::default_provider().install_default();
    let metrics = PrometheusBuilder::new()
        .install_recorder()
        .expect("install isolated UCTP network qualification metrics recorder");
    let started_at = Utc::now();
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let core_config = Config {
        max_direct_subscribers: parameters.listeners,
        capacity_report_interval: None,
        ..Config::default()
    };
    let orchestrator = Orchestrator::new(core_config);
    let source_connection_id = ConnectionId::new();
    let (source_stream, source_tx) = SourceStream::new();
    let (source_adapter, source_events) =
        SourceAdapter::new(source_connection_id.clone(), source_stream);
    orchestrator
        .register(source_adapter as Arc<dyn ConnectionAdapter>)
        .expect("register qualification source adapter");
    source_events
        .send(AdapterEvent::InboundConnection {
            connection: source_connection(source_connection_id.clone()),
        })
        .await
        .expect("publish qualification source connection");
    wait_for_source(&orchestrator, &source_connection_id).await;

    let descriptor = rvoip_core::VirtualPublisherDescriptor::new(
        SessionId::from_string(BROADCAST_ID),
        StreamId::from_string(PUBLISHED_STREAM_ID),
        "qualification-origin",
    );
    let publisher = orchestrator
        .register_virtual_publisher(source_connection_id.clone(), descriptor.clone())
        .await
        .expect("register MediaGraph-backed qualification publisher");
    let publisher_route = publisher.route_status();

    let grants = BroadcastGrantRegistry::new();
    let grant_expires_at = Utc::now()
        + chrono::Duration::from_std(
            parameters
                .setup_deadline
                .saturating_add(parameters.active_duration)
                .saturating_add(Duration::from_secs(30 * 60)),
        )
        .expect("qualification grant lifetime");
    let _grant = grants
        .register(
            TENANT_ID,
            BROADCAST_ID,
            BroadcastGrantTransport::UctpQuic,
            grant_expires_at,
        )
        .expect("register qualification broadcast grant");
    let tokens = Arc::new(
        BroadcastTokenService::new(
            b"bridgefu-uctp-network-qualification-secret".to_vec(),
            grants,
            DEFAULT_MAX_BROADCAST_TOKEN_TTL,
        )
        .expect("construct qualification token service"),
    );

    let (certificate, private_key) =
        self_signed_for_dev(&["localhost".into()]).expect("generate qualification TLS identity");
    let tls_directory =
        std::env::temp_dir().join(format!("bridgefu-uctp-network-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&tls_directory).expect("create qualification TLS directory");
    let certificate_path = tls_directory.join("server.pem");
    let private_key_path = tls_directory.join("server.key");
    std::fs::write(&certificate_path, pem("CERTIFICATE", certificate.as_ref()))
        .expect("write qualification certificate");
    std::fs::write(
        &private_key_path,
        pem("PRIVATE KEY", private_key.secret_der()),
    )
    .expect("write qualification private key");
    let listener = PublicUctpBroadcastListener::bind(
        Arc::clone(&orchestrator),
        Arc::clone(&tokens),
        PublicUctpBindConfig {
            bind: "127.0.0.1:0".parse().expect("loopback bind address"),
            certificate_chain: vec![certificate_path],
            private_key: private_key_path,
            max_concurrent_connections: parameters.listeners.saturating_add(1),
        },
    )
    .await
    .expect("bind production public UCTP listener");

    let client_tls = dev_client_config_trusting(&certificate).expect("trust qualification server");
    let client_endpoint = Arc::new(
        make_client_endpoint(
            "127.0.0.1:0".parse().expect("client loopback bind"),
            Arc::new(client_tls.clone()),
        )
        .expect("create shared qualification client endpoint"),
    );

    let authenticated_connections = Arc::new(Mutex::new(HashSet::<ConnectionId>::new()));
    let ended_connections = Arc::new(Mutex::new(HashSet::<ConnectionId>::new()));
    let event_cancel = CancellationToken::new();
    let event_task = spawn_event_collector(
        orchestrator.subscribe_events(),
        Arc::clone(&authenticated_connections),
        Arc::clone(&ended_connections),
        parameters.listeners,
        event_cancel.clone(),
    );

    let setup_started = Instant::now();
    let mut setup_tasks = JoinSet::new();
    let attempt_period = Duration::from_secs_f64(1.0 / parameters.attempts_per_second as f64);
    let mut attempt_interval = tokio::time::interval(attempt_period);
    attempt_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    for listener_index in 0..parameters.listeners {
        attempt_interval.tick().await;
        let issued = tokens
            .issue(TENANT_ID, BROADCAST_ID, parameters.initial_token_ttl)
            .expect("issue unique qualification listener token");
        let endpoint = Arc::clone(&client_endpoint);
        let client_config = client_tls.clone();
        let server = listener.local_addr();
        setup_tasks.spawn(async move {
            setup_network_listener(
                listener_index,
                endpoint,
                server,
                client_config,
                issued.token,
            )
            .await
        });
    }
    let mut network_listeners = Vec::with_capacity(parameters.listeners);
    let setup_deadline = tokio::time::Instant::now() + parameters.setup_deadline;
    while network_listeners.len() < parameters.listeners {
        let remaining = setup_deadline.saturating_duration_since(tokio::time::Instant::now());
        let result = tokio::time::timeout(remaining, setup_tasks.join_next())
            .await
            .expect("UCTP listener setup deadline")
            .expect("UCTP setup task set ended early")
            .expect("UCTP setup task panicked");
        network_listeners.push(result);
    }
    let setup_elapsed = setup_started.elapsed();
    assert_eq!(
        orchestrator.active_direct_listener_count(),
        parameters.listeners,
        "every authenticated wire subscription must hold one direct-listener permit"
    );
    wait_for_authenticated_connections(&authenticated_connections, parameters.listeners).await;

    let replay_probe = network_listeners
        .first()
        .map(|listener| (listener.token.clone(), Arc::clone(&listener.current_token)))
        .expect("qualification requires at least one listener");

    let measuring = Arc::new(AtomicBool::new(false));
    let media_ready = Arc::new(AtomicUsize::new(0));
    let aggregate_deliveries = Arc::new(AtomicU64::new(0));
    let aggregate_latency = Arc::new(LatencyHistogram::new());
    let emissions = Arc::new(dashmap::DashMap::<u32, DateTime<Utc>>::new());
    let listener_cancel = CancellationToken::new();
    let mut listener_tasks = Vec::with_capacity(parameters.listeners);
    for network_listener in network_listeners {
        listener_tasks.push(spawn_network_listener(
            network_listener,
            Arc::clone(&tokens),
            Arc::clone(&measuring),
            Arc::clone(&media_ready),
            Arc::clone(&aggregate_deliveries),
            Arc::clone(&aggregate_latency),
            Arc::clone(&emissions),
            parameters.token_ttl,
            parameters.token_refresh_period,
            listener_cancel.clone(),
        ));
    }

    prime_media_routes(
        &source_tx,
        &media_ready,
        parameters.listeners,
        parameters.setup_deadline,
    )
    .await;
    let first_refreshed_token = wait_for_refreshed_token(
        &replay_probe.0,
        &replay_probe.1,
        parameters
            .token_refresh_period
            .saturating_add(Duration::from_secs(3)),
    )
    .await;
    let original_validation = tokens
        .validate_credential(&replay_probe.0)
        .await
        .expect("validate original replay-probe credential");
    let refreshed_validation = tokens
        .validate_credential(&first_refreshed_token)
        .await
        .expect("validate refreshed replay-probe credential");
    let first_refresh_rotated = original_validation.token_id != refreshed_validation.token_id;
    let initial_token_replay_rejected = session_replay_rejected(
        Arc::clone(&client_endpoint),
        listener.local_addr(),
        client_tls.clone(),
        replay_probe.0.clone(),
        parameters.listeners,
    )
    .await;
    wait_until_after_expiry(
        original_validation
            .principal
            .expires_at
            .expect("broadcast credentials always have an expiry"),
    )
    .await;
    let refreshed_token = replay_probe
        .1
        .lock()
        .expect("current credential lock")
        .clone();
    let latest_refreshed_validation = tokens
        .validate_credential(&refreshed_token)
        .await
        .expect("the bound peer must retain a valid refreshed credential");
    let refresh_replay_id_rotated = first_refresh_rotated
        && original_validation.token_id != latest_refreshed_validation.token_id;
    let refreshed_token_replay_rejected_after_initial_expiry = session_replay_rejected(
        Arc::clone(&client_endpoint),
        listener.local_addr(),
        client_tls.clone(),
        refreshed_token,
        parameters.listeners.saturating_add(1),
    )
    .await;
    measuring.store(true, Ordering::Release);
    let source_cancel = CancellationToken::new();
    let source_frames = Arc::new(AtomicU64::new(0));
    let source_task = spawn_source(
        source_tx,
        Arc::clone(&source_frames),
        Arc::clone(&emissions),
        source_cancel.clone(),
    );
    let active_started = Instant::now();
    tokio::time::sleep(parameters.warmup).await;
    let warmup_rss_bytes = current_rss_bytes();
    tokio::time::sleep(parameters.active_duration - parameters.warmup).await;
    let final_rss_bytes = current_rss_bytes();
    let active_elapsed = active_started.elapsed();
    source_cancel.cancel();
    source_task
        .await
        .expect("UCTP network source task panicked");

    let source_frames = source_frames.load(Ordering::Relaxed);
    let expected_deliveries = source_frames.saturating_mul(parameters.listeners as u64);
    wait_for_delivery_quiescence(&aggregate_deliveries, expected_deliveries).await;
    measuring.store(false, Ordering::Release);
    listener_cancel.cancel();
    let mut per_listener = Vec::with_capacity(parameters.listeners);
    for task in listener_tasks {
        per_listener.push(task.await.expect("UCTP network listener task panicked"));
    }

    wait_for_listener_cleanup(&orchestrator, &ended_connections, parameters.listeners).await;
    let listener_connection_ids = authenticated_connections
        .lock()
        .expect("authenticated connection set")
        .clone();
    let connection_end_events = ended_connections
        .lock()
        .expect("ended connection set")
        .intersection(&listener_connection_ids)
        .count();
    let mut adapter_routes_retained = 0;
    let mut orchestrator_connections_retained = 0;
    for connection_id in &listener_connection_ids {
        if listener
            .adapter()
            .streams(connection_id.clone())
            .await
            .is_ok()
        {
            adapter_routes_retained += 1;
        }
        if orchestrator.connection_transport(connection_id).is_ok() {
            orchestrator_connections_retained += 1;
        }
    }
    let direct_listener_permits_after_cleanup = orchestrator.active_direct_listener_count();

    publisher.close().await.expect("close virtual publisher");
    let publisher_registration_retained = orchestrator
        .publisher_registry()
        .entry(&descriptor.session_id, descriptor.stream_id.as_str())
        .is_some();
    let publisher_route_terminal =
        tokio::time::timeout(Duration::from_secs(5), publisher_route.wait_terminal())
            .await
            .is_ok();
    listener.shutdown().await;
    client_endpoint.close(0u32.into(), b"qualification complete");
    client_endpoint.wait_idle().await;
    event_cancel.cancel();
    let _ = event_task.await;
    std::fs::remove_dir_all(&tls_directory).expect("remove qualification TLS directory");

    let deliveries = per_listener
        .iter()
        .map(|listener| listener.deliveries)
        .sum::<u64>();
    assert_eq!(deliveries, aggregate_deliveries.load(Ordering::Relaxed));
    let complete_rtp_datagrams = per_listener
        .iter()
        .map(|listener| listener.complete_rtp_datagrams)
        .sum::<u64>();
    let invalid_datagrams = per_listener
        .iter()
        .map(|listener| listener.invalid_datagrams)
        .sum::<u64>();
    let sequence_discontinuities = per_listener
        .iter()
        .map(|listener| listener.sequence_discontinuities)
        .sum::<u64>();
    let unmatched_timestamps = per_listener
        .iter()
        .map(|listener| listener.unmatched_timestamps)
        .sum::<u64>();
    let token_refreshes = per_listener
        .iter()
        .map(|listener| listener.token_refreshes)
        .sum::<u64>();
    let unsubscribe_acks = per_listener
        .iter()
        .filter(|listener| listener.unsubscribe_acknowledged)
        .count();
    let minimum_listener_deliveries = per_listener
        .iter()
        .map(|listener| listener.deliveries)
        .min()
        .unwrap_or(0);
    let maximum_listener_deliveries = per_listener
        .iter()
        .map(|listener| listener.deliveries)
        .max()
        .unwrap_or(0);
    let delivery_ratio = if expected_deliveries == 0 {
        0.0
    } else {
        deliveries as f64 / expected_deliveries as f64
    };
    let setup_p95_us = percentile_upper_bound(
        per_listener
            .iter()
            .map(|listener| listener.setup_us)
            .collect(),
        0.95,
    );
    let latency_p95_upper_bound_us = aggregate_latency.percentile_upper_bound_us(0.95);
    let steady_state_memory_growth_percent =
        memory_growth_percent(warmup_rss_bytes, final_rss_bytes);
    let rendered_metrics = metrics.render();
    let network_datagrams_sent_metric =
        prometheus_counter_sum(&rendered_metrics, "uctp_datagrams_total");
    let virtual_publisher_deliveries_metric = prometheus_counter_sum(
        &rendered_metrics,
        "rvoip_virtual_publisher_deliveries_total",
    );
    let nominal_frames = parameters.active_duration.as_millis() as u64 / 20;
    let minimum_source_frames = nominal_frames.saturating_mul(9) / 10;
    let minimum_refreshes = parameters.active_duration.as_secs().saturating_sub(1)
        / parameters.token_refresh_period.as_secs();
    let common_passed = setup_elapsed <= parameters.setup_deadline
        && listener_connection_ids.len() == parameters.listeners
        && media_ready.load(Ordering::Relaxed) == parameters.listeners
        && source_frames >= minimum_source_frames
        && deliveries <= expected_deliveries
        && delivery_ratio >= MIN_DELIVERY_RATIO
        && minimum_listener_deliveries > 0
        && complete_rtp_datagrams == deliveries
        && invalid_datagrams == 0
        && unmatched_timestamps == 0
        && refresh_replay_id_rotated
        && initial_token_replay_rejected
        && refreshed_token_replay_rejected_after_initial_expiry
        && per_listener.iter().all(|listener| {
            listener.media_stream_opened
                && listener.protocol_errors == 0
                && listener.unsubscribe_acknowledged
                && listener.connection_end_sent
                && listener.connection_closed
                && listener.token_refreshes >= minimum_refreshes
        })
        && unsubscribe_acks == parameters.listeners
        && connection_end_events == parameters.listeners
        && adapter_routes_retained == 0
        && orchestrator_connections_retained == 0
        && direct_listener_permits_after_cleanup == 0
        && !publisher_registration_retained
        && publisher_route_terminal
        && network_datagrams_sent_metric >= deliveries
        && virtual_publisher_deliveries_metric >= deliveries;
    let passed = common_passed
        && match mode {
            QualificationMode::Smoke => {
                latency_p95_upper_bound_us.is_some_and(|value| value <= MAX_RELEASE_P95_US * 2)
            }
            QualificationMode::Release => {
                active_elapsed >= RELEASE_DURATION
                    && latency_p95_upper_bound_us.is_some_and(|value| value <= MAX_RELEASE_P95_US)
                    && steady_state_memory_growth_percent
                        .is_some_and(|value| value < MAX_RELEASE_MEMORY_GROWTH_PERCENT)
            }
        };
    let release_criterion_satisfied = mode == QualificationMode::Release && passed;

    let report = UctpNetworkQualificationReport {
        schema: "bridgefu.qualification.uctp-network.v1",
        mode,
        started_at,
        finished_at: Utc::now(),
        bridgefu: git_revision(&manifest_dir),
        rvoip: git_revision(&manifest_dir.join("../rvoip")),
        host: host_evidence(),
        transport: "raw-quic",
        protocol_version: UCTP_QUIC_PROTOCOL_VERSION,
        media_profile: "8-byte UCTP header + complete RTP packet",
        listeners: parameters.listeners,
        setup_attempts_per_second: parameters.attempts_per_second,
        setup_elapsed_ms: setup_elapsed.as_millis(),
        setup_p95_us,
        authenticated_connections_observed: listener_connection_ids.len(),
        media_ready_listeners: media_ready.load(Ordering::Relaxed),
        active_elapsed_ms: active_elapsed.as_millis(),
        source_frames,
        expected_deliveries,
        deliveries,
        delivery_ratio,
        minimum_listener_deliveries,
        maximum_listener_deliveries,
        complete_rtp_datagrams,
        invalid_datagrams,
        sequence_discontinuities,
        unmatched_timestamps,
        latency_p95_upper_bound_us,
        token_refreshes,
        initial_credential_ttl_seconds: parameters.initial_token_ttl.as_secs(),
        credential_ttl_seconds: parameters.token_ttl.as_secs(),
        credential_refresh_period_seconds: parameters.token_refresh_period.as_secs(),
        refresh_replay_id_rotated,
        initial_token_replay_rejected,
        refreshed_token_replay_rejected_after_initial_expiry,
        unsubscribe_acks,
        connection_end_events,
        adapter_routes_retained,
        orchestrator_connections_retained,
        direct_listener_permits_after_cleanup,
        publisher_registration_retained,
        publisher_route_terminal,
        warmup_rss_bytes,
        final_rss_bytes,
        steady_state_memory_growth_percent,
        network_datagrams_sent_metric,
        virtual_publisher_deliveries_metric,
        per_listener,
        release_parameters: ReleaseParameters {
            listeners: RELEASE_LISTENERS,
            active_duration_seconds: RELEASE_DURATION.as_secs(),
            warmup_seconds: RELEASE_WARMUP.as_secs(),
            attempts_per_second: RELEASE_ATTEMPTS_PER_SECOND,
            setup_deadline_seconds: RELEASE_SETUP_DEADLINE.as_secs(),
            token_ttl_seconds: TOKEN_TTL.as_secs(),
            token_refresh_period_seconds: TOKEN_REFRESH_PERIOD.as_secs(),
            minimum_delivery_ratio: MIN_DELIVERY_RATIO,
            latency_p95_us: MAX_RELEASE_P95_US,
            steady_state_memory_growth_percent: MAX_RELEASE_MEMORY_GROWTH_PERCENT,
        },
        scope: "real localhost raw-QUIC peers through PublicUctpBroadcastListener, Bridgefu bearer/session authorization, rvoip Orchestrator subscription and MediaGraph-backed virtual publisher, with complete UCTP 0.2 RTP datagram parsing; smoke is not one-hour or deployed-network evidence",
        release_criterion_satisfied,
        passed,
    };
    let report_path = write_report(
        &manifest_dir,
        "BRIDGEFU_UCTP_NETWORK_QUALIFICATION_OUTPUT",
        "uctp-network",
        started_at,
        &report,
    );
    eprintln!(
        "UCTP network qualification report: {}",
        report_path.display()
    );
    assert!(
        passed,
        "UCTP network qualification failed; retained evidence is at {}",
        report_path.display()
    );
}

fn source_connection(connection_id: ConnectionId) -> Connection {
    Connection {
        id: connection_id,
        session_id: SessionId::from_string("qualification-source-session"),
        participant_id: ParticipantId::from_string("qualification-source"),
        transport: Transport::Sip,
        direction: Direction::Inbound,
        state: ConnectionState::Connected,
        capabilities: CapabilityDescriptor::default(),
        negotiated_codecs: NegotiatedCodecs::default(),
        streams: Vec::new(),
        messaging_enabled: false,
        transport_handle: TransportHandle(Arc::new(())),
        opened_at: Utc::now(),
        closed_at: None,
    }
}

async fn wait_for_source(orchestrator: &Orchestrator, connection_id: &ConnectionId) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if orchestrator.connection_transport(connection_id).is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("qualification source registration timeout");
}

async fn setup_network_listener(
    listener_index: usize,
    endpoint: Arc<quinn::Endpoint>,
    server: std::net::SocketAddr,
    client_config: rustls::ClientConfig,
    token: String,
) -> NetworkListener {
    let started = Instant::now();
    let current_token = Arc::new(Mutex::new(token.clone()));
    let client = UctpQuicClient::connect(&endpoint, server, "localhost", Arc::new(client_config))
        .await
        .expect("connect raw-QUIC qualification listener");
    let mut inbound = client
        .take_inbound()
        .expect("take listener signaling receiver");
    authenticate(&client, &mut inbound, &token, listener_index).await;
    let wire_connection = format!("listener-{listener_index}");
    client
        .send(
            UctpEnvelope::new(
                MessageType::SessionInvite,
                serde_json::to_value(session::SessionInvite {
                    from: "listener".into(),
                    to: vec!["broadcast".into()],
                    medium: "voice".into(),
                    intent: "broadcast-subscribe".into(),
                    capabilities_offer: serde_json::Value::Object(Default::default()),
                })
                .expect("encode Session invite"),
            )
            .with_sid(BROADCAST_ID),
        )
        .await
        .expect("send Session invite");
    client
        .send(
            UctpEnvelope::new(
                MessageType::ConnectionOffer,
                serde_json::to_value(connection::ConnectionOffer {
                    by_participant: "listener".into(),
                    substrate: "quic".into(),
                    capabilities: serde_json::Value::Object(Default::default()),
                    streams_offered: vec![connection::StreamOffer {
                        id: "listener-receive".into(),
                        kind: "audio".into(),
                        direction: "recvonly".into(),
                        codec_preferences: vec!["opus".into()],
                    }],
                    substrate_setup: serde_json::Value::Null,
                })
                .expect("encode receive-only Connection offer"),
            )
            .with_sid(BROADCAST_ID)
            .with_connid(wire_connection.clone()),
        )
        .await
        .expect("send receive-only Connection offer");
    client
        .send(
            UctpEnvelope::new(MessageType::ConnectionReady, serde_json::json!({}))
                .with_sid(BROADCAST_ID)
                .with_connid(wire_connection.clone()),
        )
        .await
        .expect("send Connection ready");
    next_stream_opened(&mut inbound, "listener-receive").await;

    let subscribe = UctpEnvelope::new(
        MessageType::StreamSubscribe,
        serde_json::to_value(stream::StreamSubscribe {
            by_participant: "listener".into(),
            subscriptions: vec![stream::StreamSubscription {
                strm_id: Some(PUBLISHED_STREAM_ID.into()),
                ..Default::default()
            }],
        })
        .expect("encode Stream subscription"),
    )
    .with_sid(BROADCAST_ID)
    .with_connid(wire_connection.clone());
    let subscribe_id = subscribe.id.clone();
    client
        .send(subscribe)
        .await
        .expect("send Stream subscription");
    next_ack(&mut inbound, &subscribe_id).await;
    NetworkListener {
        client,
        inbound,
        token,
        current_token,
        wire_connection,
        setup_us: started.elapsed().as_micros().min(u64::MAX as u128) as u64,
    }
}

async fn wait_for_refreshed_token(
    initial: &str,
    current: &Mutex<String>,
    deadline: Duration,
) -> String {
    tokio::time::timeout(deadline, async {
        loop {
            let token = current.lock().expect("current credential lock").clone();
            if token != initial {
                break token;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("real-network auth.refresh deadline")
}

async fn wait_until_after_expiry(expires_at: DateTime<Utc>) {
    let until_expiry = expires_at
        .signed_duration_since(Utc::now())
        .to_std()
        .unwrap_or_default();
    tokio::time::sleep(until_expiry.saturating_add(Duration::from_millis(250))).await;
}

async fn session_replay_rejected(
    endpoint: Arc<quinn::Endpoint>,
    server: std::net::SocketAddr,
    client_config: rustls::ClientConfig,
    token: String,
    listener_index: usize,
) -> bool {
    let client = UctpQuicClient::connect(&endpoint, server, "localhost", Arc::new(client_config))
        .await
        .expect("connect replay-probe peer");
    let mut inbound = client
        .take_inbound()
        .expect("take replay-probe signaling receiver");
    authenticate(&client, &mut inbound, &token, listener_index).await;
    let invite = UctpEnvelope::new(
        MessageType::SessionInvite,
        serde_json::to_value(session::SessionInvite {
            from: "replay-probe".into(),
            to: vec!["broadcast".into()],
            medium: "voice".into(),
            intent: "broadcast-subscribe".into(),
            capabilities_offer: serde_json::Value::Object(Default::default()),
        })
        .expect("encode replay-probe Session invite"),
    )
    .with_sid(BROADCAST_ID);
    let request_id = invite.id.clone();
    client
        .send(invite)
        .await
        .expect("send replay-probe Session invite");
    let rejected = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let Some(envelope) = inbound.recv().await else {
                break false;
            };
            if envelope.in_reply_to.as_deref() == Some(request_id.as_str()) {
                break envelope.msg_type == MessageType::Error;
            }
        }
    })
    .await
    .unwrap_or(false);
    client
        .connection
        .close(0u32.into(), b"replay probe complete");
    let _ = tokio::time::timeout(Duration::from_secs(2), client.connection.closed()).await;
    rejected
}

async fn authenticate(
    client: &UctpQuicClient,
    inbound: &mut mpsc::Receiver<UctpEnvelope>,
    token: &str,
    listener_index: usize,
) {
    client
        .send(UctpEnvelope::new(
            MessageType::AuthHello,
            serde_json::to_value(auth::AuthHello {
                device: auth::Device {
                    id: format!("qualification-{listener_index}"),
                    kind: "service".into(),
                    platform: "qualification".into(),
                    sdk_version: "bridgefu-qualification/1".into(),
                },
                auth_methods: vec!["bearer".into()],
                capabilities: serde_json::Value::Object(Default::default()),
            })
            .expect("encode auth hello"),
        ))
        .await
        .expect("send auth hello");
    let challenge = next_message(inbound, MessageType::AuthChallenge).await;
    client
        .send(
            UctpEnvelope::new(
                MessageType::AuthResponse,
                serde_json::to_value(auth::AuthResponse {
                    method: "bearer".into(),
                    credential: token.into(),
                    actor_token: None,
                })
                .expect("encode auth response"),
            )
            .with_in_reply_to(challenge.id),
        )
        .await
        .expect("send auth response");
    next_message(inbound, MessageType::AuthSession).await;
}

async fn next_message(
    inbound: &mut mpsc::Receiver<UctpEnvelope>,
    expected: MessageType,
) -> UctpEnvelope {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let envelope = inbound.recv().await.expect("listener signaling closed");
            if envelope.msg_type == MessageType::Error {
                panic!("listener command rejected: {envelope:?}");
            }
            if envelope.msg_type == expected {
                break envelope;
            }
        }
    })
    .await
    .expect("listener signaling response timeout")
}

async fn next_stream_opened(inbound: &mut mpsc::Receiver<UctpEnvelope>, stream_id: &str) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let envelope = inbound.recv().await.expect("listener signaling closed");
            if envelope.msg_type == MessageType::Error {
                panic!("listener stream setup rejected: {envelope:?}");
            }
            if envelope.msg_type != MessageType::StreamOpened {
                continue;
            }
            let opened: stream::StreamOpened = envelope
                .decode_payload()
                .expect("decode qualification stream.opened");
            if opened.stream.strm_id == stream_id {
                break;
            }
        }
    })
    .await
    .expect("stream.opened timeout");
}

async fn next_ack(inbound: &mut mpsc::Receiver<UctpEnvelope>, request_id: &str) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let envelope = inbound.recv().await.expect("listener signaling closed");
            if envelope.in_reply_to.as_deref() != Some(request_id) {
                continue;
            }
            match envelope.msg_type {
                MessageType::Ack => break,
                MessageType::Error => panic!("listener command rejected: {envelope:?}"),
                _ => {}
            }
        }
    })
    .await
    .expect("listener command acknowledgement timeout");
}

#[allow(clippy::too_many_arguments)]
fn spawn_network_listener(
    listener: NetworkListener,
    tokens: Arc<BroadcastTokenService>,
    measuring: Arc<AtomicBool>,
    media_ready: Arc<AtomicUsize>,
    aggregate_deliveries: Arc<AtomicU64>,
    aggregate_latency: Arc<LatencyHistogram>,
    emissions: Arc<dashmap::DashMap<u32, DateTime<Utc>>>,
    token_ttl: Duration,
    token_refresh_period: Duration,
    cancellation: CancellationToken,
) -> JoinHandle<ListenerEvidence> {
    tokio::spawn(async move {
        let NetworkListener {
            client,
            mut inbound,
            mut token,
            current_token,
            wire_connection,
            setup_us,
        } = listener;
        let latency = LatencyHistogram::new();
        let mut accumulator = ListenerAccumulator::default();
        let mut media_stream_local_id = None;
        let mut pending_datagrams = VecDeque::<Bytes>::new();
        let mut pending_refresh: Option<(String, String)> = None;
        let mut refresh_interval = tokio::time::interval_at(
            tokio::time::Instant::now() + token_refresh_period,
            token_refresh_period,
        );
        refresh_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => break,
                envelope = inbound.recv() => {
                    let Some(envelope) = envelope else {
                        accumulator.protocol_errors = accumulator.protocol_errors.saturating_add(1);
                        break;
                    };
                    match envelope.msg_type {
                        MessageType::StreamOpened if media_stream_local_id.is_none() => {
                            let opened: stream::StreamOpened = match envelope.decode_payload() {
                                Ok(opened) => opened,
                                Err(_) => {
                                    accumulator.protocol_errors = accumulator.protocol_errors.saturating_add(1);
                                    continue;
                                }
                            };
                            if opened.stream.strm_id != "listener-receive" {
                                media_stream_local_id = Some(opened.stream.stream_local_id);
                                media_ready.fetch_add(1, Ordering::AcqRel);
                                while let Some(bytes) = pending_datagrams.pop_front() {
                                    accumulator.observe_datagram(
                                        &bytes,
                                        opened.stream.stream_local_id,
                                        measuring.load(Ordering::Acquire),
                                        &emissions,
                                        &latency,
                                        &aggregate_latency,
                                    );
                                }
                            }
                        }
                        MessageType::AuthSession => {
                            if let Some((request_id, next_token)) = pending_refresh.take() {
                                if envelope.in_reply_to.as_deref() == Some(request_id.as_str()) {
                                    current_token
                                        .lock()
                                        .expect("current credential lock")
                                        .clone_from(&next_token);
                                    token = next_token;
                                    accumulator.token_refreshes = accumulator.token_refreshes.saturating_add(1);
                                } else {
                                    pending_refresh = Some((request_id, next_token));
                                }
                            }
                        }
                        MessageType::Error => {
                            accumulator.protocol_errors = accumulator.protocol_errors.saturating_add(1);
                        }
                        _ => {}
                    }
                }
                datagram = client.connection.read_datagram() => {
                    match datagram {
                        Ok(bytes) => {
                            if let Some(local_id) = media_stream_local_id {
                                let before = accumulator.deliveries;
                                accumulator.observe_datagram(
                                    &bytes,
                                    local_id,
                                    measuring.load(Ordering::Acquire),
                                    &emissions,
                                    &latency,
                                    &aggregate_latency,
                                );
                                aggregate_deliveries.fetch_add(
                                    accumulator.deliveries.saturating_sub(before),
                                    Ordering::Relaxed,
                                );
                            } else if pending_datagrams.len() < 64 {
                                pending_datagrams.push_back(bytes);
                            }
                        }
                        Err(_) => {
                            if !cancellation.is_cancelled() {
                                accumulator.protocol_errors = accumulator.protocol_errors.saturating_add(1);
                            }
                            break;
                        }
                    }
                }
                _ = refresh_interval.tick(), if pending_refresh.is_none() => {
                    match tokens.refresh(&token, token_ttl).await {
                        Ok(refreshed) => {
                            let refresh = UctpEnvelope::new(
                                MessageType::AuthRefresh,
                                serde_json::to_value(auth::AuthRefresh {
                                    method: "bearer".into(),
                                    credential: refreshed.token.clone(),
                                    actor_token: None,
                                }).expect("encode auth refresh"),
                            );
                            let request_id = refresh.id.clone();
                            if client.send(refresh).await.is_ok() {
                                pending_refresh = Some((request_id, refreshed.token));
                            } else {
                                accumulator.protocol_errors = accumulator.protocol_errors.saturating_add(1);
                            }
                        }
                        Err(_) => {
                            accumulator.protocol_errors = accumulator.protocol_errors.saturating_add(1);
                        }
                    }
                }
            }
        }

        let unsubscribe = UctpEnvelope::new(
            MessageType::StreamUnsubscribe,
            serde_json::to_value(stream::StreamUnsubscribe {
                strm_ids: vec![PUBLISHED_STREAM_ID.into()],
            })
            .expect("encode Stream unsubscribe"),
        )
        .with_sid(BROADCAST_ID)
        .with_connid(wire_connection.clone());
        let unsubscribe_acknowledged =
            graceful_unsubscribe(&client, &mut inbound, unsubscribe).await;
        let connection_end_sent = client
            .send(
                UctpEnvelope::new(
                    MessageType::ConnectionEnd,
                    serde_json::to_value(connection::ConnectionEnd {
                        reason_code: 200,
                        reason: "qualification-complete".into(),
                    })
                    .expect("encode Connection end"),
                )
                .with_sid(BROADCAST_ID)
                .with_connid(wire_connection),
            )
            .await
            .is_ok();
        tokio::time::sleep(Duration::from_millis(20)).await;
        client
            .connection
            .close(0u32.into(), b"qualification listener complete");
        let connection_closed =
            tokio::time::timeout(Duration::from_secs(5), client.connection.closed())
                .await
                .is_ok();
        ListenerEvidence {
            setup_us,
            media_stream_opened: media_stream_local_id.is_some(),
            deliveries: accumulator.deliveries,
            complete_rtp_datagrams: accumulator.complete_rtp_datagrams,
            invalid_datagrams: accumulator.invalid_datagrams,
            sequence_discontinuities: accumulator.sequence_discontinuities,
            unmatched_timestamps: accumulator.unmatched_timestamps,
            latency_p95_upper_bound_us: latency.percentile_upper_bound_us(0.95),
            token_refreshes: accumulator.token_refreshes,
            protocol_errors: accumulator.protocol_errors,
            unsubscribe_acknowledged,
            connection_end_sent,
            connection_closed,
        }
    })
}

async fn graceful_unsubscribe(
    client: &UctpQuicClient,
    inbound: &mut mpsc::Receiver<UctpEnvelope>,
    unsubscribe: UctpEnvelope,
) -> bool {
    let request_id = unsubscribe.id.clone();
    if client.send(unsubscribe).await.is_err() {
        return false;
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let Some(envelope) = inbound.recv().await else {
                return false;
            };
            if envelope.in_reply_to.as_deref() == Some(request_id.as_str()) {
                return envelope.msg_type == MessageType::Ack;
            }
        }
    })
    .await
    .unwrap_or(false)
}

async fn prime_media_routes(
    source: &mpsc::Sender<MediaFrame>,
    media_ready: &AtomicUsize,
    listeners: usize,
    deadline: Duration,
) {
    tokio::time::timeout(deadline, async {
        let mut timestamp = 0_u32;
        while media_ready.load(Ordering::Acquire) < listeners {
            source
                .send(MediaFrame {
                    stream_id: StreamId::from_string("qualification-source"),
                    kind: StreamKind::Audio,
                    payload: Bytes::from_static(OPUS_SILENCE),
                    timestamp_rtp: timestamp,
                    captured_at: Utc::now(),
                    payload_type: Some(111),
                })
                .await
                .expect("prime subscriber media routes");
            timestamp = timestamp.wrapping_add(960);
            tokio::time::sleep(FRAME_PERIOD).await;
        }
    })
    .await
    .expect("subscriber media-stream allocation timeout");
}

fn spawn_source(
    source: mpsc::Sender<MediaFrame>,
    frames: Arc<AtomicU64>,
    emissions: Arc<dashmap::DashMap<u32, DateTime<Utc>>>,
    cancellation: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let stream_id = StreamId::from_string("qualification-source");
        let mut timestamp = 1_000_000_u32;
        let mut interval = tokio::time::interval_at(tokio::time::Instant::now(), FRAME_PERIOD);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => break,
                _ = interval.tick() => {
                    let captured_at = Utc::now();
                    emissions.insert(timestamp, captured_at);
                    if source.send(MediaFrame {
                        stream_id: stream_id.clone(),
                        kind: StreamKind::Audio,
                        payload: Bytes::from_static(OPUS_SILENCE),
                        timestamp_rtp: timestamp,
                        captured_at,
                        payload_type: Some(111),
                    }).await.is_err() {
                        break;
                    }
                    frames.fetch_add(1, Ordering::Relaxed);
                    timestamp = timestamp.wrapping_add(960);
                }
            }
        }
    })
}

fn spawn_event_collector(
    mut events: tokio::sync::broadcast::Receiver<rvoip_core::events::Event>,
    authenticated: Arc<Mutex<HashSet<ConnectionId>>>,
    ended: Arc<Mutex<HashSet<ConnectionId>>>,
    expected_authenticated: usize,
    cancellation: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancellation.cancelled() => break,
                event = events.recv() => match event {
                    Ok(rvoip_core::events::Event::ConnectionPrincipalAuthenticated { connection_id, .. }) => {
                        let mut authenticated = authenticated.lock().expect("authenticated event set");
                        if authenticated.len() < expected_authenticated {
                            authenticated.insert(connection_id);
                        }
                    }
                    Ok(rvoip_core::events::Event::ConnectionEnded { connection_id, .. }) => {
                        ended.lock().expect("ended event set").insert(connection_id);
                    }
                    Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    })
}

async fn wait_for_listener_cleanup(
    orchestrator: &Orchestrator,
    ended: &Mutex<HashSet<ConnectionId>>,
    listeners: usize,
) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if orchestrator.active_direct_listener_count() == 0
                && ended.lock().expect("ended listener set").len() >= listeners
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("UCTP listener cleanup timeout");
}

async fn wait_for_authenticated_connections(
    authenticated: &Mutex<HashSet<ConnectionId>>,
    listeners: usize,
) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if authenticated
                .lock()
                .expect("authenticated listener set")
                .len()
                >= listeners
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("authenticated listener event deadline");
}

async fn wait_for_delivery_quiescence(deliveries: &AtomicU64, expected: u64) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut previous = deliveries.load(Ordering::Relaxed);
    let mut unchanged = 0_u8;
    while tokio::time::Instant::now() < deadline && previous < expected {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let current = deliveries.load(Ordering::Relaxed);
        if current == previous {
            unchanged = unchanged.saturating_add(1);
            if unchanged >= 5 {
                break;
            }
        } else {
            previous = current;
            unchanged = 0;
        }
    }
}

fn percentile_upper_bound(mut values: Vec<u64>, percentile: f64) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    let index = ((values.len() as f64 * percentile).ceil() as usize)
        .saturating_sub(1)
        .min(values.len() - 1);
    Some(values[index])
}

fn pem(label: &str, bytes: &[u8]) -> String {
    let encoded = STANDARD.encode(bytes);
    let mut output = format!("-----BEGIN {label}-----\n");
    for line in encoded.as_bytes().chunks(64) {
        output.push_str(std::str::from_utf8(line).expect("PEM base64 is UTF-8"));
        output.push('\n');
    }
    output.push_str(&format!("-----END {label}-----\n"));
    output
}
