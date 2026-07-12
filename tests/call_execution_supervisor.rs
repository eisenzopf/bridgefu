use std::collections::{BTreeSet, HashMap, HashSet};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use bridgefu::api_principal::ApiPrincipal;
use bridgefu::call_engine::{CallId, CallState, LegDirection, LegId, LegState, TenantId, WorkerId};
use bridgefu::call_service::{
    build_call_service_runtime, CallExecutionSupervisor, CallRepositoryBackendConfig,
    CallServiceCoordinationConfig, CallServiceRuntime, CallServiceRuntimeConfig, CallTimeoutPolicy,
    CreateCallInput, IdempotencyKey, InboundAttachmentRequest, LegEndpointConfig, RequestedLeg,
    SamePrincipalAttachmentResolver, SipEndpointConfig, SystemCallServiceClock,
    WebRtcEndpointConfig,
};
use bridgefu::coordination::DeploymentId;
use chrono::Utc;
use rvoip_auth_core::{AuthenticatedPrincipal, AuthenticationMethod};
use rvoip_core::{
    adapter::{
        AdapterEvent, AdapterKind, AdapterLifecycleCapabilities, AdapterLifecycleSink,
        AdapterLifecycleSinkSlot, ConnectionAdapter, ConnectionHandle, EndReason,
        InboundConnectionContext, InboundRoutingHint, InboundSignalingMetadata,
        OrchestratorAdapterEvent, OriginateRequest, RejectReason, SignatureHeaders, TransferTarget,
    },
    capability::{CapabilityDescriptor, CodecInfo, NegotiatedCodecs},
    config::Config as CoreConfig,
    connection::{Connection, ConnectionState, Direction, Transport, TransportHandle},
    ids::{ConnectionId, ParticipantId, SessionId, StreamId},
    message::Message,
    stream::{MediaFrame, MediaStream, QualitySnapshot, StreamKind},
    IdentityAssurance, Jwk, OperationalEventStreamHealth, Orchestrator, Result as RvoipResult,
    RvoipError,
};
use tokio::sync::{mpsc, Barrier};

fn runtime_config(
    backend: CallRepositoryBackendConfig,
    worker_id: WorkerId,
) -> CallServiceRuntimeConfig {
    let mut coordination = CallServiceCoordinationConfig::new(
        DeploymentId::parse("execution-supervisor-test").unwrap(),
    );
    coordination.worker_lease_ttl = Duration::from_secs(300);
    coordination.worker_renew_interval = Duration::from_secs(100);
    CallServiceRuntimeConfig {
        backend,
        worker_id,
        max_calls: 8,
        worker_capabilities: BTreeSet::from(["sip".into(), "webrtc".into()]),
        control_key: vec![0x41; 32],
        timeouts: CallTimeoutPolicy {
            setup: Duration::from_secs(30),
            media_idle: Duration::from_secs(30),
            transfer: Duration::from_secs(30),
            ending: Duration::from_secs(30),
        },
        coordination,
    }
}

async fn runtime(
    backend: CallRepositoryBackendConfig,
    worker_id: WorkerId,
) -> Arc<CallServiceRuntime> {
    Arc::new(
        build_call_service_runtime(
            runtime_config(backend, worker_id),
            Arc::new(SamePrincipalAttachmentResolver),
            Arc::new(SystemCallServiceClock),
        )
        .await
        .unwrap(),
    )
}

fn principal() -> ApiPrincipal {
    ApiPrincipal::new(
        AuthenticatedPrincipal {
            subject: "execution-owner".into(),
            tenant: Some("execution-tenant".into()),
            scopes: vec!["*".into()],
            issuer: Some("execution-test".into()),
            expires_at: None,
            method: AuthenticationMethod::Jwt,
            assurance: IdentityAssurance::Pseudonymous {
                ephemeral_key: Jwk(serde_json::json!({"kty": "test"})),
            },
        },
        Utc::now(),
    )
    .unwrap()
}

fn two_inbound_legs() -> CreateCallInput {
    CreateCallInput {
        tenant_id: None,
        legs: [
            RequestedLeg {
                direction: LegDirection::Inbound,
                endpoint: LegEndpointConfig::Sip(SipEndpointConfig { uri: None }),
            },
            RequestedLeg {
                direction: LegDirection::Inbound,
                endpoint: LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
                    signaling_uri: None,
                }),
            },
        ],
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AcceptEvents {
    Connected,
    ConnectedThenEnded,
}

#[derive(Debug, Default)]
struct AdapterCounts {
    accept: AtomicUsize,
    reject: AtomicUsize,
    end: AtomicUsize,
    ended_connections: Mutex<Vec<ConnectionId>>,
    admission_outcomes: Mutex<Vec<(ConnectionId, u64, bool)>>,
}

struct TestMediaStream {
    id: StreamId,
    inbound: Mutex<Option<mpsc::Receiver<MediaFrame>>>,
    _source: mpsc::Sender<MediaFrame>,
    outbound: mpsc::Sender<MediaFrame>,
    _sink: Mutex<Option<mpsc::Receiver<MediaFrame>>>,
}

impl TestMediaStream {
    fn new() -> Arc<Self> {
        let (source, inbound) = mpsc::channel(32);
        let (outbound, sink) = mpsc::channel(32);
        Arc::new(Self {
            id: StreamId::new(),
            inbound: Mutex::new(Some(inbound)),
            _source: source,
            outbound,
            _sink: Mutex::new(Some(sink)),
        })
    }
}

#[async_trait::async_trait]
impl MediaStream for TestMediaStream {
    fn id(&self) -> StreamId {
        self.id.clone()
    }

    fn kind(&self) -> StreamKind {
        StreamKind::Audio
    }

    fn codec(&self) -> CodecInfo {
        CodecInfo {
            name: "pcmu".into(),
            clock_rate_hz: 8_000,
            channels: 1,
            fmtp: None,
        }
    }

    fn direction(&self) -> Direction {
        Direction::Inbound
    }

    fn frames_in(&self) -> mpsc::Receiver<MediaFrame> {
        self.inbound
            .lock()
            .unwrap()
            .take()
            .unwrap_or_else(|| mpsc::channel(1).1)
    }

    fn try_frames_in(&self) -> RvoipResult<mpsc::Receiver<MediaFrame>> {
        self.inbound
            .lock()
            .unwrap()
            .take()
            .ok_or(RvoipError::InvalidState(
                "test media receiver was already acquired",
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

type AcceptGate = (Arc<Barrier>, Arc<Barrier>);

struct LifecycleTestAdapter {
    transport: Transport,
    events: mpsc::Sender<OrchestratorAdapterEvent>,
    receiver: Mutex<Option<mpsc::Receiver<OrchestratorAdapterEvent>>>,
    live: Mutex<HashSet<ConnectionId>>,
    contexts: Mutex<HashMap<ConnectionId, InboundConnectionContext>>,
    streams: Mutex<HashMap<ConnectionId, Arc<dyn MediaStream>>>,
    accept_events: Mutex<HashMap<ConnectionId, AcceptEvents>>,
    accept_gates: Mutex<HashMap<ConnectionId, AcceptGate>>,
    lifecycle: AdapterLifecycleSinkSlot,
    counts: Arc<AdapterCounts>,
}

impl LifecycleTestAdapter {
    fn new(transport: Transport) -> Arc<Self> {
        let (events, receiver) = mpsc::channel(64);
        Arc::new(Self {
            transport,
            events,
            receiver: Mutex::new(Some(receiver)),
            live: Mutex::new(HashSet::new()),
            contexts: Mutex::new(HashMap::new()),
            streams: Mutex::new(HashMap::new()),
            accept_events: Mutex::new(HashMap::new()),
            accept_gates: Mutex::new(HashMap::new()),
            lifecycle: AdapterLifecycleSinkSlot::default(),
            counts: Arc::new(AdapterCounts::default()),
        })
    }

    fn prepare_inbound(
        &self,
        connection_id: ConnectionId,
        owner: &AuthenticatedPrincipal,
        token: String,
        events: AcceptEvents,
    ) {
        self.live.lock().unwrap().insert(connection_id.clone());
        self.streams.lock().unwrap().insert(
            connection_id.clone(),
            TestMediaStream::new() as Arc<dyn MediaStream>,
        );
        self.contexts.lock().unwrap().insert(
            connection_id.clone(),
            InboundConnectionContext::new(
                connection_id.clone(),
                self.transport,
                owner,
                Some(InboundRoutingHint::new(token).unwrap()),
                InboundSignalingMetadata::default(),
            )
            .unwrap(),
        );
        self.accept_events
            .lock()
            .unwrap()
            .insert(connection_id, events);
    }

    fn gate_accept(&self, connection_id: &ConnectionId) -> AcceptGate {
        let gate = (Arc::new(Barrier::new(2)), Arc::new(Barrier::new(2)));
        self.accept_gates
            .lock()
            .unwrap()
            .insert(connection_id.clone(), gate.clone());
        gate
    }

    async fn announce_inbound(&self, connection_id: ConnectionId, owner: AuthenticatedPrincipal) {
        self.events
            .send(OrchestratorAdapterEvent::AuthenticatedInboundConnection {
                connection: inbound_connection(connection_id, self.transport),
                participant_id: format!("{}-participant", transport_label(self.transport)),
                principal: owner,
            })
            .await
            .unwrap();
    }

    async fn remote_end(&self, connection_id: ConnectionId) {
        self.live.lock().unwrap().remove(&connection_id);
        self.events
            .send(
                AdapterEvent::Ended {
                    connection_id,
                    reason: EndReason::Normal,
                }
                .into(),
            )
            .await
            .unwrap();
    }

    fn admission_was_accepted(&self, connection_id: &ConnectionId) -> bool {
        self.counts
            .admission_outcomes
            .lock()
            .unwrap()
            .iter()
            .any(|(observed, _, accepted)| observed == connection_id && *accepted)
    }
}

#[async_trait::async_trait]
impl ConnectionAdapter for LifecycleTestAdapter {
    fn transport(&self) -> Transport {
        self.transport
    }

    fn kind(&self) -> AdapterKind {
        AdapterKind::Interop
    }

    fn lifecycle_capabilities(&self) -> AdapterLifecycleCapabilities {
        AdapterLifecycleCapabilities::FAIL_CLOSED_INBOUND
    }

    fn supports_inbound_admission_confirmation(&self) -> bool {
        true
    }

    fn notify_inbound_admission_outcome(
        &self,
        connection_id: &ConnectionId,
        generation: u64,
        accepted: bool,
    ) {
        self.counts.admission_outcomes.lock().unwrap().push((
            connection_id.clone(),
            generation,
            accepted,
        ));
    }

    fn install_lifecycle_sink(&self, sink: Arc<dyn AdapterLifecycleSink>) -> RvoipResult<()> {
        self.lifecycle
            .install(sink)
            .map_err(|_| RvoipError::InvalidState("test lifecycle sink already installed"))
    }

    fn is_connection_live(&self, connection_id: &ConnectionId) -> bool {
        self.live.lock().unwrap().contains(connection_id)
    }

    fn take_inbound_context(
        &self,
        connection_id: &ConnectionId,
    ) -> Option<InboundConnectionContext> {
        self.contexts.lock().unwrap().remove(connection_id)
    }

    async fn originate(&self, _: OriginateRequest) -> RvoipResult<ConnectionHandle> {
        Err(RvoipError::NotImplemented("lifecycle test originate"))
    }

    async fn accept(&self, connection_id: ConnectionId) -> RvoipResult<()> {
        self.counts.accept.fetch_add(1, Ordering::SeqCst);
        let gate = self.accept_gates.lock().unwrap().remove(&connection_id);
        if let Some((entered, release)) = gate {
            entered.wait().await;
            release.wait().await;
        }
        let events = self
            .accept_events
            .lock()
            .unwrap()
            .get(&connection_id)
            .copied()
            .unwrap_or(AcceptEvents::Connected);
        self.events
            .send(
                AdapterEvent::Connected {
                    connection_id: connection_id.clone(),
                }
                .into(),
            )
            .await
            .map_err(|_| RvoipError::InvalidState("test event receiver closed"))?;
        if events == AcceptEvents::ConnectedThenEnded {
            self.live.lock().unwrap().remove(&connection_id);
            self.events
                .send(
                    AdapterEvent::Ended {
                        connection_id,
                        reason: EndReason::Normal,
                    }
                    .into(),
                )
                .await
                .map_err(|_| RvoipError::InvalidState("test event receiver closed"))?;
        }
        Ok(())
    }

    async fn reject(&self, connection_id: ConnectionId, _: RejectReason) -> RvoipResult<()> {
        self.counts.reject.fetch_add(1, Ordering::SeqCst);
        self.live.lock().unwrap().remove(&connection_id);
        Ok(())
    }

    async fn end(&self, connection_id: ConnectionId, _: EndReason) -> RvoipResult<()> {
        self.counts.end.fetch_add(1, Ordering::SeqCst);
        self.counts
            .ended_connections
            .lock()
            .unwrap()
            .push(connection_id.clone());
        let was_live = self.live.lock().unwrap().remove(&connection_id);
        if was_live {
            self.events
                .send(
                    AdapterEvent::Ended {
                        connection_id,
                        reason: EndReason::Normal,
                    }
                    .into(),
                )
                .await
                .map_err(|_| RvoipError::InvalidState("test event receiver closed"))?;
        }
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
        Ok(self
            .streams
            .lock()
            .unwrap()
            .get(&connection_id)
            .cloned()
            .into_iter()
            .collect())
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
        mpsc::channel(1).1
    }

    fn subscribe_orchestrator_events(&self) -> mpsc::Receiver<OrchestratorAdapterEvent> {
        self.receiver
            .lock()
            .unwrap()
            .take()
            .expect("orchestrator subscribes exactly once")
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

fn inbound_connection(connection_id: ConnectionId, transport: Transport) -> Connection {
    Connection {
        id: connection_id,
        session_id: SessionId::new(),
        participant_id: ParticipantId::new(),
        transport,
        direction: Direction::Inbound,
        state: ConnectionState::Connecting,
        capabilities: CapabilityDescriptor::default(),
        negotiated_codecs: NegotiatedCodecs::default(),
        streams: Vec::new(),
        messaging_enabled: false,
        transport_handle: TransportHandle(Arc::new(())),
        opened_at: Utc::now(),
        closed_at: None,
    }
}

fn transport_label(transport: Transport) -> &'static str {
    match transport {
        Transport::Sip => "sip",
        Transport::WebRtc => "webrtc",
        _ => "other",
    }
}

struct CreatedInboundCall {
    call_id: CallId,
    sip_leg: LegId,
    sip_token: String,
    webrtc_leg: LegId,
    webrtc_token: String,
}

async fn create_inbound_call(
    runtime: &CallServiceRuntime,
    idempotency: &str,
) -> CreatedInboundCall {
    let created = runtime
        .service()
        .create_call(
            &principal(),
            &IdempotencyKey::parse(idempotency).unwrap(),
            two_inbound_legs(),
        )
        .await
        .unwrap();
    let sip = created
        .value
        .call
        .legs
        .iter()
        .find(|leg| leg.kind == bridgefu::call_engine::LegKind::Sip)
        .unwrap();
    let webrtc = created
        .value
        .call
        .legs
        .iter()
        .find(|leg| leg.kind == bridgefu::call_engine::LegKind::InteractiveWebRtc)
        .unwrap();
    CreatedInboundCall {
        call_id: created.value.call.call_id,
        sip_leg: sip.leg_id,
        sip_token: sip.attachment.as_ref().unwrap().token.clone(),
        webrtc_leg: webrtc.leg_id,
        webrtc_token: webrtc.attachment.as_ref().unwrap().token.clone(),
    }
}

async fn execution_harness(
    max_calls: usize,
) -> (
    Arc<CallServiceRuntime>,
    Arc<Orchestrator>,
    CallExecutionSupervisor,
    Arc<LifecycleTestAdapter>,
    Arc<LifecycleTestAdapter>,
) {
    let worker_id = WorkerId::new();
    let mut config = runtime_config(CallRepositoryBackendConfig::Memory, worker_id);
    config.max_calls = max_calls;
    let runtime = Arc::new(
        build_call_service_runtime(
            config,
            Arc::new(SamePrincipalAttachmentResolver),
            Arc::new(SystemCallServiceClock),
        )
        .await
        .unwrap(),
    );
    let orchestrator = Orchestrator::new(CoreConfig::default());
    let supervisor = CallExecutionSupervisor::install(
        Arc::clone(&orchestrator),
        Arc::clone(&runtime),
        max_calls * 2,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    let sip = LifecycleTestAdapter::new(Transport::Sip);
    let webrtc = LifecycleTestAdapter::new(Transport::WebRtc);
    orchestrator
        .register(Arc::clone(&sip) as Arc<dyn ConnectionAdapter>)
        .unwrap();
    orchestrator
        .register(Arc::clone(&webrtc) as Arc<dyn ConnectionAdapter>)
        .unwrap();
    (runtime, orchestrator, supervisor, sip, webrtc)
}

async fn attach(
    adapter: &LifecycleTestAdapter,
    owner: &AuthenticatedPrincipal,
    token: String,
    events: AcceptEvents,
) -> ConnectionId {
    let connection_id = ConnectionId::new();
    adapter.prepare_inbound(connection_id.clone(), owner, token, events);
    adapter
        .announce_inbound(connection_id.clone(), owner.clone())
        .await;
    connection_id
}

async fn wait_for_call<F>(
    runtime: &CallServiceRuntime,
    call_id: CallId,
    predicate: F,
) -> bridgefu::call_service::StoredServiceCall
where
    F: Fn(&bridgefu::call_service::StoredServiceCall) -> bool,
{
    let tenant = TenantId::parse("execution-tenant").unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let stored = runtime
                .service_repository()
                .load_service_call(&tenant, call_id)
                .await
                .unwrap();
            if predicate(&stored) {
                return stored;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    match result {
        Ok(stored) => stored,
        Err(_) => {
            let stored = runtime
                .service_repository()
                .load_service_call(&tenant, call_id)
                .await
                .unwrap();
            panic!(
                "call did not reach the expected durable state: {:?}",
                stored.call.aggregate
            );
        }
    }
}

async fn wait_for_accepted(adapter: &LifecycleTestAdapter, connection_id: &ConnectionId) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !adapter.admission_was_accepted(connection_id) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("inbound connection was durably accepted");
}

async fn stop_harness(supervisor: CallExecutionSupervisor, orchestrator: Arc<Orchestrator>) {
    supervisor.shutdown(Duration::from_secs(2)).await;
    orchestrator.drain_prepared_outbound_connections().await;
    orchestrator.drain_connection_lifecycle_tasks().await;
}

#[tokio::test]
async fn begin_drain_retains_authoritative_operational_receiver() {
    let worker_id = WorkerId::new();
    let runtime = runtime(CallRepositoryBackendConfig::Memory, worker_id).await;
    let orchestrator = Orchestrator::new(CoreConfig::default());
    let supervisor = CallExecutionSupervisor::install(
        Arc::clone(&orchestrator),
        Arc::clone(&runtime),
        8,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(
        orchestrator.operational_event_stream_health(),
        OperationalEventStreamHealth::Healthy
    );

    supervisor.begin_drain();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        orchestrator.operational_event_stream_health(),
        OperationalEventStreamHealth::Healthy,
        "draining admission must not drop the correctness receiver"
    );

    supervisor.shutdown(Duration::from_secs(2)).await;
    drop(orchestrator);
    drop(runtime);
}

#[tokio::test]
async fn startup_recovery_finishes_old_fence_and_cleanup_before_returning() {
    let path = std::env::temp_dir().join(format!(
        "bridgefu-execution-supervisor-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    let url = format!("sqlite://{}", path.display());
    let worker_id = WorkerId::from_str("00000000-0000-4000-8000-0000000000e6").unwrap();
    let first = runtime(
        CallRepositoryBackendConfig::Sqlite {
            database_url: url.clone(),
        },
        worker_id,
    )
    .await;
    let created = first
        .service()
        .create_call(
            &principal(),
            &IdempotencyKey::parse("execution-startup-recovery").unwrap(),
            two_inbound_legs(),
        )
        .await
        .unwrap();
    let call_id = created.value.call.call_id;
    let bound_leg_id = created.value.call.legs[0].leg_id;
    let attachment = created.value.call.legs[0].attachment.as_ref().unwrap();
    let bound_connection_id = ConnectionId::new();
    first
        .service()
        .consume_inbound_attachment(InboundAttachmentRequest::new(
            principal().authenticated().clone(),
            Some(attachment.token.clone()),
            attachment.transport,
            first.worker().lease,
            bound_connection_id.clone(),
        ))
        .await
        .unwrap();
    let tenant = TenantId::parse("execution-tenant").unwrap();
    let before_restart = first
        .service_repository()
        .load_service_call(&tenant, call_id)
        .await
        .unwrap();
    assert_eq!(
        before_restart
            .call
            .bindings
            .get(&bound_leg_id)
            .unwrap()
            .connection_id,
        bound_connection_id
    );
    assert_eq!(
        before_restart
            .call
            .aggregate
            .leg(bound_leg_id)
            .unwrap()
            .state(),
        LegState::Signaling
    );
    let first_fence = first.worker().lease.fence;
    drop(first);

    let second = runtime(
        CallRepositoryBackendConfig::Sqlite { database_url: url },
        worker_id,
    )
    .await;
    assert!(second.worker().lease.fence > first_fence);
    let orchestrator = Orchestrator::new(CoreConfig::default());
    let supervisor = CallExecutionSupervisor::install(
        Arc::clone(&orchestrator),
        Arc::clone(&second),
        8,
        Duration::from_secs(5),
    )
    .await
    .unwrap();

    let recovered = second
        .service_repository()
        .load_service_call(&tenant, call_id)
        .await
        .unwrap();
    assert!(matches!(
        recovered.call.aggregate.state(),
        CallState::Ended | CallState::Failed
    ));
    let recovered_bound_leg = recovered.call.aggregate.leg(bound_leg_id).unwrap();
    assert_eq!(recovered_bound_leg.state(), LegState::Failed);
    assert_eq!(
        recovered_bound_leg.failure().map(|failure| failure.code()),
        Some("worker_restarted")
    );
    assert!(second
        .repository()
        .claim_outbox(
            second.worker().lease,
            Utc::now(),
            Duration::from_secs(60),
            64,
        )
        .await
        .unwrap()
        .is_empty());

    supervisor.shutdown(Duration::from_secs(2)).await;
    drop(orchestrator);
    drop(second);
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn simultaneous_authenticated_legs_are_bound_before_accept_and_cannot_outrun_ownership() {
    let (runtime, orchestrator, supervisor, sip, webrtc) = execution_harness(2).await;
    let created = create_inbound_call(&runtime, "execution-simultaneous-legs").await;
    let owner = principal().authenticated().clone();
    let sip_id = ConnectionId::new();
    let webrtc_id = ConnectionId::new();
    sip.prepare_inbound(
        sip_id.clone(),
        &owner,
        created.sip_token,
        AcceptEvents::Connected,
    );
    webrtc.prepare_inbound(
        webrtc_id.clone(),
        &owner,
        created.webrtc_token,
        AcceptEvents::Connected,
    );
    let sip_gate = sip.gate_accept(&sip_id);

    let ((), ()) = tokio::join!(
        sip.announce_inbound(sip_id.clone(), owner.clone()),
        webrtc.announce_inbound(webrtc_id.clone(), owner.clone()),
    );
    tokio::time::timeout(Duration::from_secs(5), sip_gate.0.wait())
        .await
        .expect("the gated same-call leg reached adapter accept");

    let bound = wait_for_call(&runtime, created.call_id, |stored| {
        stored.call.bindings.len() == 2
    })
    .await;
    assert_eq!(
        bound
            .call
            .bindings
            .get(&created.sip_leg)
            .unwrap()
            .connection_id,
        sip_id
    );
    assert_eq!(
        bound
            .call
            .bindings
            .get(&created.webrtc_leg)
            .unwrap()
            .connection_id,
        webrtc_id
    );
    assert_eq!(
        bound.call.aggregate.leg(created.sip_leg).unwrap().state(),
        LegState::Signaling
    );
    assert_eq!(
        bound
            .call
            .aggregate
            .leg(created.webrtc_leg)
            .unwrap()
            .state(),
        LegState::Signaling
    );
    assert!(sip.admission_was_accepted(&sip_id));
    // The actor serializes external admission operations. The other proof is
    // already durably bound and queued even though its adapter accept cannot
    // begin until the gated first operation is released.

    sip_gate.1.wait().await;
    wait_for_accepted(&webrtc, &webrtc_id).await;
    let active = wait_for_call(&runtime, created.call_id, |stored| {
        stored.call.aggregate.state() == CallState::Active
    })
    .await;
    assert_eq!(
        active.call.aggregate.leg(created.sip_leg).unwrap().state(),
        LegState::Connected
    );
    assert_eq!(
        active
            .call
            .aggregate
            .leg(created.webrtc_leg)
            .unwrap()
            .state(),
        LegState::Connected
    );
    assert_eq!(sip.counts.reject.load(Ordering::SeqCst), 0);
    assert_eq!(webrtc.counts.reject.load(Ordering::SeqCst), 0);

    stop_harness(supervisor, orchestrator).await;
}

#[tokio::test]
async fn immediate_connected_then_ended_is_reconciled_after_exact_durable_binding() {
    let (runtime, orchestrator, supervisor, sip, webrtc) = execution_harness(2).await;
    let created = create_inbound_call(&runtime, "execution-immediate-terminal").await;
    let owner = principal().authenticated().clone();
    let webrtc_id = attach(
        &webrtc,
        &owner,
        created.webrtc_token,
        AcceptEvents::Connected,
    )
    .await;
    wait_for_accepted(&webrtc, &webrtc_id).await;
    let sip_id = ConnectionId::new();
    sip.prepare_inbound(
        sip_id.clone(),
        &owner,
        created.sip_token,
        AcceptEvents::ConnectedThenEnded,
    );
    let sip_gate = sip.gate_accept(&sip_id);
    sip.announce_inbound(sip_id.clone(), owner.clone()).await;
    tokio::time::timeout(Duration::from_secs(5), sip_gate.0.wait())
        .await
        .expect("immediate-terminal leg reached adapter accept");
    let bound = wait_for_call(&runtime, created.call_id, |stored| {
        stored
            .call
            .bindings
            .get(&created.sip_leg)
            .is_some_and(|binding| binding.connection_id == sip_id)
    })
    .await;
    assert_eq!(
        bound.call.aggregate.leg(created.sip_leg).unwrap().state(),
        LegState::Signaling
    );
    sip_gate.1.wait().await;
    wait_for_accepted(&sip, &sip_id).await;

    let terminal = wait_for_call(&runtime, created.call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    for leg in terminal.call.aggregate.legs() {
        assert!(leg.state().is_terminal());
        assert_ne!(
            leg.failure().map(|failure| failure.code()),
            Some("execution_unavailable")
        );
    }
    assert!(
        webrtc
            .counts
            .ended_connections
            .lock()
            .unwrap()
            .contains(&webrtc_id),
        "the immediate terminal event must durably tear down its peer"
    );

    stop_harness(supervisor, orchestrator).await;
}

#[tokio::test]
async fn interleaved_unrelated_calls_never_cross_connection_ownership() {
    let (runtime, orchestrator, supervisor, sip, webrtc) = execution_harness(2).await;
    let first = create_inbound_call(&runtime, "execution-interleaved-first").await;
    let second = create_inbound_call(&runtime, "execution-interleaved-second").await;
    let owner = principal().authenticated().clone();

    let first_sip = attach(&sip, &owner, first.sip_token, AcceptEvents::Connected).await;
    let second_sip = attach(&sip, &owner, second.sip_token, AcceptEvents::Connected).await;
    let second_webrtc = attach(
        &webrtc,
        &owner,
        second.webrtc_token,
        AcceptEvents::Connected,
    )
    .await;
    let first_webrtc = attach(&webrtc, &owner, first.webrtc_token, AcceptEvents::Connected).await;

    let (first_stored, second_stored) = tokio::join!(
        wait_for_call(&runtime, first.call_id, |stored| {
            stored.call.aggregate.state() == CallState::Active
        }),
        wait_for_call(&runtime, second.call_id, |stored| {
            stored.call.aggregate.state() == CallState::Active
        }),
    );
    assert_eq!(
        first_stored
            .call
            .bindings
            .get(&first.sip_leg)
            .unwrap()
            .connection_id,
        first_sip
    );
    assert_eq!(
        first_stored
            .call
            .bindings
            .get(&first.webrtc_leg)
            .unwrap()
            .connection_id,
        first_webrtc
    );
    assert_eq!(
        second_stored
            .call
            .bindings
            .get(&second.sip_leg)
            .unwrap()
            .connection_id,
        second_sip
    );
    assert_eq!(
        second_stored
            .call
            .bindings
            .get(&second.webrtc_leg)
            .unwrap()
            .connection_id,
        second_webrtc
    );
    assert_ne!(first_sip, second_sip);
    assert_ne!(first_webrtc, second_webrtc);

    stop_harness(supervisor, orchestrator).await;
}

#[tokio::test]
async fn remote_terminal_tears_down_peer_and_retiring_actor_does_not_consume_capacity() {
    let (runtime, orchestrator, supervisor, sip, webrtc) = execution_harness(1).await;
    let first = create_inbound_call(&runtime, "execution-capacity-first").await;
    let owner = principal().authenticated().clone();
    let first_sip = attach(&sip, &owner, first.sip_token, AcceptEvents::Connected).await;
    let first_webrtc = attach(&webrtc, &owner, first.webrtc_token, AcceptEvents::Connected).await;
    wait_for_call(&runtime, first.call_id, |stored| {
        stored.call.aggregate.state() == CallState::Active
    })
    .await;

    sip.remote_end(first_sip).await;
    wait_for_call(&runtime, first.call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    assert!(webrtc
        .counts
        .ended_connections
        .lock()
        .unwrap()
        .contains(&first_webrtc));

    // The first actor intentionally remains for a one-second late-event
    // quiet window. Durable worker capacity is already free, so a replacement
    // call must not be rejected by that retiring actor's slot.
    let second = create_inbound_call(&runtime, "execution-capacity-second").await;
    let second_sip = attach(&sip, &owner, second.sip_token, AcceptEvents::Connected).await;
    wait_for_accepted(&sip, &second_sip).await;
    let second_bound = wait_for_call(&runtime, second.call_id, |stored| {
        stored
            .call
            .aggregate
            .leg(second.sip_leg)
            .is_some_and(|leg| leg.state() == LegState::Connected)
    })
    .await;
    assert_eq!(
        second_bound
            .call
            .bindings
            .get(&second.sip_leg)
            .unwrap()
            .connection_id,
        second_sip
    );
    assert_ne!(
        second_bound
            .call
            .aggregate
            .leg(second.sip_leg)
            .unwrap()
            .failure()
            .map(|failure| failure.code()),
        Some("execution_unavailable")
    );

    stop_harness(supervisor, orchestrator).await;
}
