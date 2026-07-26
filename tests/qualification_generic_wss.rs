//! Hermetic all-in-one qualification for named browser-WebRTC and Vapi-like
//! SIPS/SRTP ingress routes to authenticated interactive WSS and generic SIP
//! destinations.
//!
//! This deliberately uses real rvoip WebRTC adapters, WSS signaling, TLS,
//! ICE/DTLS, Opus RTP, DataChannels, and RFC 4733 DTMF. The only wrapper is a
//! test-owned target-policy adapter which permits the loopback fixture; the
//! production target policy continues to reject loopback/private addresses.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bridgefu::api_principal::ApiPrincipal;
use bridgefu::call_engine::{
    BindingGeneration, CallId, CallState, LegDirection, LegId, MediaFlow, SignalingInitiator,
    TenantId, WorkerId,
};
use bridgefu::call_service::{
    build_call_service_runtime, CallExecutionSupervisor, CallRepositoryBackendConfig,
    CallServiceCoordinationConfig, CallServiceRuntime, CallServiceRuntimeConfig, CallTimeoutPolicy,
    ConfiguredIceServer, ConfiguredSipOutboundProfile, ConfiguredSipProfileAuth,
    ConfiguredWebRtcOutboundProfile, CreateCallInput, DisabledProviderLegExecutor, IdempotencyKey,
    LegEndpointConfig, NamedProfileBinding, NamedProfileKind, NamedProfileRole, NamedRouteBinding,
    ReplaceLegInput, RequestedLeg, SamePrincipalAttachmentResolver, SipEndpointConfig,
    SipInitialContextMode, StaticOutboundProfileResolver, SystemCallServiceClock,
    WebRtcEndpointConfig,
};
use bridgefu::context::{ContextEnvelope, ContextPolicy, CONTEXT_LABEL};
use bridgefu::coordination::DeploymentId;
use bridgefu::handoff_status::{HandoffStatusEnvelope, HandoffStatusKind, HANDOFF_STATUS_LABEL};
use bridgefu::secret_ref::SecretRef;
use chrono::Utc;
use rvoip_auth_core::{AuthenticatedPrincipal, AuthenticationMethod};
use rvoip_core::adapter::{
    AdapterEvent, AdapterKind, AdapterLifecycleCapabilities, AdapterLifecycleSink,
    ConnectionAdapter, ConnectionHandle, EndReason, InboundConnectionContext,
    OrchestratorAdapterEvent, OriginateContext, OriginateRequest, OutboundActivation, RejectReason,
    SignatureHeaders, TransferTarget,
};
use rvoip_core::capability::{CapabilityDescriptor, NegotiatedCodecs};
use rvoip_core::config::Config as CoreConfig;
use rvoip_core::connection::{Direction, Transport};
use rvoip_core::ids::{ConnectionId, ParticipantId, SessionId};
use rvoip_core::message::Message;
use rvoip_core::stream::{MediaFrame, MediaStream, StreamKind};
use rvoip_core::{
    DataMessage, Event, IdentityAssurance, Jwk, Orchestrator, Result as RvoipResult, RvoipError,
};
use rvoip_sip::{
    Event as SipEvent, EventReceiver as SipEventReceiver, MediaSecurityProfile, SessionHandle,
    SipAdapter, SipAuthService, SipInboundContextPolicy, SipInitialHeaders, SipListenerAuthPolicy,
    SipOriginateContext,
};
use rvoip_webrtc::signaling::auth::{AuthContext, AuthRejection, WsAuthHook};
use rvoip_webrtc::signaling::websocket::serve_tls_listener_with_auth_and_shutdown;
use rvoip_webrtc::tls::TlsConfig;
use rvoip_webrtc::{
    StaticWebRtcBearerCredentialProvider, WebRtcAdapter, WebRtcBearerCredential, WebRtcConfig,
    WebRtcOriginateContext, WebRtcServer, WebRtcServerBuilder, WebRtcTargetPolicy,
    WebRtcTlsClientTrust,
};
use tokio::sync::mpsc;

#[path = "support/browser_sdk.rs"]
mod browser_sdk;
#[path = "support/sip_fixture.rs"]
mod sip_fixture;
use sip_fixture::{reserve_tcp, reserve_udp, tls_sip_config, TestTlsFiles};

const DESTINATION_BEARER: &str = "destination-wss-secret";
const PROFILE_REVISION: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SIP_PROFILE_ID: &str = "generic-sip-agent";
const SIP_PROFILE_REVISION: &str =
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const SIP_DIGEST_REALM: &str = "bridgefu-generic-sip-destination";
const SIP_DIGEST_USER: &str = "bridgefu-browser";
const SIP_DIGEST_PASSWORD: &str = "hermetic-browser-sip-password";
const CALL_CENTER_PROFILE_ID: &str = "named-call-center";
const CALL_CENTER_PROFILE_REVISION: &str =
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const CALL_CENTER_DIGEST_REALM: &str = "bridgefu-named-call-center";
const CALL_CENTER_DIGEST_USER: &str = "bridgefu-call-center";
const CALL_CENTER_DIGEST_PASSWORD: &str = "hermetic-call-center-password";
static QUALIFICATION_TEST_LOCK: Mutex<()> = Mutex::new(());

async fn bounded<T>(label: &'static str, future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(20), future)
        .await
        .unwrap_or_else(|_| panic!("{label} deadline"))
}

#[derive(Clone, Debug)]
struct ObservedOutboundContext {
    bearer_present: bool,
    tls_trust_present: bool,
    ice_urls: Vec<String>,
}

/// Delegates every operation to the real adapter, changing only the frozen
/// target policy for this loopback test. No production config or global state
/// can select this wrapper.
struct LoopbackFixtureWebRtcAdapter {
    inner: Arc<WebRtcAdapter>,
    observed: Mutex<Vec<ObservedOutboundContext>>,
}

impl LoopbackFixtureWebRtcAdapter {
    fn new(inner: Arc<WebRtcAdapter>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            observed: Mutex::new(Vec::new()),
        })
    }

    fn last_observed(&self) -> ObservedOutboundContext {
        self.observed
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("outbound WSS context reached the adapter boundary")
    }
}

#[async_trait::async_trait]
impl ConnectionAdapter for LoopbackFixtureWebRtcAdapter {
    fn transport(&self) -> Transport {
        self.inner.transport()
    }

    fn kind(&self) -> AdapterKind {
        self.inner.kind()
    }

    fn lifecycle_capabilities(&self) -> AdapterLifecycleCapabilities {
        self.inner.lifecycle_capabilities()
    }

    fn supports_inbound_admission_confirmation(&self) -> bool {
        self.inner.supports_inbound_admission_confirmation()
    }

    fn notify_inbound_admission_outcome(
        &self,
        connection_id: &ConnectionId,
        lifecycle_generation: u64,
        accepted: bool,
    ) {
        self.inner
            .notify_inbound_admission_outcome(connection_id, lifecycle_generation, accepted);
    }

    fn install_lifecycle_sink(&self, sink: Arc<dyn AdapterLifecycleSink>) -> RvoipResult<()> {
        self.inner.install_lifecycle_sink(sink)
    }

    fn is_connection_live(&self, connection_id: &ConnectionId) -> bool {
        self.inner.is_connection_live(connection_id)
    }

    fn take_inbound_context(
        &self,
        connection_id: &ConnectionId,
    ) -> Option<InboundConnectionContext> {
        self.inner.take_inbound_context(connection_id)
    }

    fn subscribe_orchestrator_events(&self) -> mpsc::Receiver<OrchestratorAdapterEvent> {
        self.inner.subscribe_orchestrator_events()
    }

    async fn originate(&self, mut request: OriginateRequest) -> RvoipResult<ConnectionHandle> {
        let context = request
            .context
            .downcast_arc::<WebRtcOriginateContext>()
            .ok_or(RvoipError::AdmissionRejected(
                "fixture expected a typed WebRTC context",
            ))?;
        let diagnostic = format!("{context:?}");
        self.observed.lock().unwrap().push(ObservedOutboundContext {
            bearer_present: diagnostic.contains("bearer_provider_present: true"),
            tls_trust_present: diagnostic.contains("tls_trust_present: true"),
            ice_urls: context
                .ice_servers_override()
                .unwrap_or_default()
                .iter()
                .flat_map(|server| server.urls.iter().cloned())
                .collect(),
        });
        let policy = context.target_policy().clone().allow_loopback(true);
        let context = context
            .as_ref()
            .clone()
            .with_target_policy(policy)
            .map_err(|_| RvoipError::AdmissionRejected("invalid fixture target policy"))?;
        request.context = OriginateContext::new(context);
        self.inner.originate(request).await
    }

    async fn activate_outbound(&self, connection_id: ConnectionId) -> RvoipResult<()> {
        self.inner.activate_outbound(connection_id).await
    }

    async fn activate_outbound_with_receipt(
        &self,
        connection_id: ConnectionId,
    ) -> RvoipResult<OutboundActivation> {
        self.inner
            .activate_outbound_with_receipt(connection_id)
            .await
    }

    async fn accept(&self, connection_id: ConnectionId) -> RvoipResult<()> {
        self.inner.accept(connection_id).await
    }

    async fn reject(&self, connection_id: ConnectionId, reason: RejectReason) -> RvoipResult<()> {
        self.inner.reject(connection_id, reason).await
    }

    async fn end(&self, connection_id: ConnectionId, reason: EndReason) -> RvoipResult<()> {
        self.inner.end(connection_id, reason).await
    }

    async fn hold(&self, connection_id: ConnectionId) -> RvoipResult<()> {
        self.inner.hold(connection_id).await
    }

    async fn resume(&self, connection_id: ConnectionId) -> RvoipResult<()> {
        self.inner.resume(connection_id).await
    }

    async fn transfer(
        &self,
        connection_id: ConnectionId,
        target: TransferTarget,
    ) -> RvoipResult<()> {
        self.inner.transfer(connection_id, target).await
    }

    async fn streams(&self, connection_id: ConnectionId) -> RvoipResult<Vec<Arc<dyn MediaStream>>> {
        self.inner.streams(connection_id).await
    }

    async fn send_message(&self, connection_id: ConnectionId, message: Message) -> RvoipResult<()> {
        self.inner.send_message(connection_id, message).await
    }

    async fn send_data_message(
        &self,
        connection_id: ConnectionId,
        message: DataMessage,
    ) -> RvoipResult<()> {
        self.inner.send_data_message(connection_id, message).await
    }

    async fn send_dtmf(
        &self,
        connection_id: ConnectionId,
        digits: &str,
        duration_ms: u32,
    ) -> RvoipResult<()> {
        self.inner
            .send_dtmf(connection_id, digits, duration_ms)
            .await
    }

    async fn renegotiate_media(
        &self,
        connection_id: ConnectionId,
        capabilities: CapabilityDescriptor,
    ) -> RvoipResult<NegotiatedCodecs> {
        self.inner
            .renegotiate_media(connection_id, capabilities)
            .await
    }

    fn subscribe_events(&self) -> mpsc::Receiver<AdapterEvent> {
        self.inner.subscribe_events()
    }

    fn capabilities(&self) -> CapabilityDescriptor {
        self.inner.capabilities()
    }

    async fn verify_request_signature(
        &self,
        connection_id: ConnectionId,
        signature: SignatureHeaders,
    ) -> RvoipResult<IdentityAssurance> {
        self.inner
            .verify_request_signature(connection_id, signature)
            .await
    }
}

struct AttachmentAuth {
    principal: AuthenticatedPrincipal,
}

#[async_trait::async_trait]
impl WsAuthHook for AttachmentAuth {
    async fn authenticate(
        &self,
        subprotocols: &[String],
        _query_token: Option<&str>,
        _peer_addr: std::net::SocketAddr,
    ) -> Result<AuthContext, AuthRejection> {
        let token = subprotocols
            .iter()
            .find_map(|value| value.strip_prefix("token."))
            .filter(|value| !value.is_empty() && value.len() <= 512)
            .ok_or(AuthRejection::Unauthorized {
                www_authenticate: "Bearer realm=\"bridgefu-test\"".into(),
            })?;
        Ok(AuthContext {
            subject: self.principal.subject.clone(),
            scopes: vec!["webrtc:connect".into()],
            session_hint: Some(token.to_owned()),
            principal: Some(self.principal.clone()),
        })
    }
}

struct DestinationAuth {
    calls: AtomicUsize,
}

#[async_trait::async_trait]
impl WsAuthHook for DestinationAuth {
    async fn authenticate(
        &self,
        subprotocols: &[String],
        _query_token: Option<&str>,
        _peer_addr: std::net::SocketAddr,
    ) -> Result<AuthContext, AuthRejection> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        let authenticated = subprotocols
            .iter()
            .any(|value| value == &format!("token.{DESTINATION_BEARER}"));
        if !authenticated {
            return Err(AuthRejection::Unauthorized {
                www_authenticate: "Bearer realm=\"destination-test\"".into(),
            });
        }
        Ok(AuthContext {
            subject: "destination-test".into(),
            scopes: vec!["webrtc:answer".into()],
            session_hint: None,
            // Bridgefu's staged outbound WSS lifecycle deliberately uses the
            // rvoip `offer-ready` extension. The remote route can send the
            // request-bound readiness outcome only when its authentication
            // hook retained a complete, non-anonymous principal; a legacy
            // subject is intentionally insufficient for that protocol.
            principal: Some(AuthenticatedPrincipal {
                subject: "destination-test".into(),
                tenant: Some("generic-wss-destination".into()),
                scopes: vec!["webrtc:answer".into()],
                issuer: Some("generic-wss-fixture".into()),
                expires_at: None,
                method: AuthenticationMethod::Jwt,
                assurance: IdentityAssurance::Pseudonymous {
                    ephemeral_key: Jwk(serde_json::json!({"kty":"test"})),
                },
            }),
        })
    }
}

fn principal() -> ApiPrincipal {
    ApiPrincipal::new(
        AuthenticatedPrincipal {
            subject: "generic-wss-owner".into(),
            tenant: Some("generic-wss-tenant".into()),
            scopes: vec![
                "*".into(),
                bridgefu::api_principal::CallScope::ArbitraryDestination
                    .as_str()
                    .into(),
            ],
            issuer: Some("generic-wss-test".into()),
            expires_at: None,
            method: AuthenticationMethod::Jwt,
            assurance: IdentityAssurance::Pseudonymous {
                ephemeral_key: Jwk(serde_json::json!({"kty":"test"})),
            },
        },
        Utc::now(),
    )
    .unwrap()
}

async fn call_runtime() -> Arc<CallServiceRuntime> {
    let worker = WorkerId::new();
    let mut coordination = CallServiceCoordinationConfig::new(
        DeploymentId::parse("generic-wss-qualification").unwrap(),
    );
    coordination.worker_lease_ttl = Duration::from_secs(300);
    coordination.worker_renew_interval = Duration::from_secs(100);
    Arc::new(
        build_call_service_runtime(
            CallServiceRuntimeConfig {
                backend: CallRepositoryBackendConfig::Memory,
                worker_id: worker,
                max_calls: 4,
                worker_capabilities: BTreeSet::from([
                    "sip".into(),
                    "sip_egress".into(),
                    "webrtc".into(),
                    "webrtc_egress".into(),
                ]),
                control_key: vec![0x77; 32],
                timeouts: CallTimeoutPolicy {
                    setup: Duration::from_secs(20),
                    media_idle: Duration::from_secs(20),
                    transfer: Duration::from_secs(20),
                    ending: Duration::from_secs(10),
                },
                coordination,
            },
            Arc::new(SamePrincipalAttachmentResolver),
            Arc::new(SystemCallServiceClock),
        )
        .await
        .unwrap(),
    )
}

fn route_input(endpoint: String) -> CreateCallInput {
    CreateCallInput {
        tenant_id: None,
        legs: [
            RequestedLeg {
                direction: LegDirection::Inbound,
                signaling_initiator: Some(SignalingInitiator::Remote),
                media_flow: MediaFlow::SendReceive,
                endpoint: LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
                    signaling_uri: None,
                }),
                amazon_connect_start: None,
            },
            RequestedLeg {
                direction: LegDirection::Outbound,
                signaling_initiator: Some(SignalingInitiator::Bridgefu),
                media_flow: MediaFlow::SendReceive,
                endpoint: LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
                    signaling_uri: Some(endpoint),
                }),
                amazon_connect_start: None,
            },
        ],
    }
}

fn sip_route_input(endpoint: String) -> CreateCallInput {
    CreateCallInput {
        tenant_id: None,
        legs: [
            RequestedLeg {
                direction: LegDirection::Inbound,
                signaling_initiator: Some(SignalingInitiator::Remote),
                media_flow: MediaFlow::SendReceive,
                endpoint: LegEndpointConfig::Sip(SipEndpointConfig {
                    uri: None,
                    initial_context: SipInitialContextMode::None,
                }),
                amazon_connect_start: None,
            },
            RequestedLeg {
                direction: LegDirection::Outbound,
                signaling_initiator: Some(SignalingInitiator::Bridgefu),
                media_flow: MediaFlow::SendReceive,
                endpoint: LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
                    signaling_uri: Some(endpoint),
                }),
                amazon_connect_start: None,
            },
        ],
    }
}

fn browser_to_sip_route_input(endpoint: String) -> CreateCallInput {
    CreateCallInput {
        tenant_id: None,
        legs: [
            RequestedLeg {
                direction: LegDirection::Inbound,
                signaling_initiator: Some(SignalingInitiator::Remote),
                media_flow: MediaFlow::SendReceive,
                endpoint: LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
                    signaling_uri: None,
                }),
                amazon_connect_start: None,
            },
            RequestedLeg {
                direction: LegDirection::Outbound,
                signaling_initiator: Some(SignalingInitiator::Bridgefu),
                media_flow: MediaFlow::SendReceive,
                endpoint: LegEndpointConfig::Sip(SipEndpointConfig {
                    uri: Some(endpoint),
                    initial_context: SipInitialContextMode::Required,
                }),
                amazon_connect_start: None,
            },
        ],
    }
}

fn route_binding() -> NamedRouteBinding {
    NamedRouteBinding::new_with_profiles(
        "generic-wss",
        None,
        vec![NamedProfileBinding::new(
            NamedProfileRole::Destination,
            NamedProfileKind::WebRtc,
            "generic-agent",
            PROFILE_REVISION,
        )
        .unwrap()],
    )
    .unwrap()
}

fn browser_to_sip_route_binding() -> NamedRouteBinding {
    NamedRouteBinding::new_with_profiles(
        "generic-sip",
        None,
        vec![NamedProfileBinding::new(
            NamedProfileRole::Destination,
            NamedProfileKind::Sip,
            SIP_PROFILE_ID,
            SIP_PROFILE_REVISION,
        )
        .unwrap()],
    )
    .unwrap()
}

fn sip_replacement_destination(endpoint: String) -> RequestedLeg {
    RequestedLeg {
        direction: LegDirection::Outbound,
        signaling_initiator: Some(SignalingInitiator::Bridgefu),
        media_flow: MediaFlow::SendReceive,
        endpoint: LegEndpointConfig::Sip(SipEndpointConfig {
            uri: Some(endpoint),
            initial_context: SipInitialContextMode::None,
        }),
        amazon_connect_start: None,
    }
}

fn webrtc_replacement_destination(endpoint: String) -> RequestedLeg {
    RequestedLeg {
        direction: LegDirection::Outbound,
        signaling_initiator: Some(SignalingInitiator::Bridgefu),
        media_flow: MediaFlow::SendReceive,
        endpoint: LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
            signaling_uri: Some(endpoint),
        }),
        amazon_connect_start: None,
    }
}

async fn start_webrtc_replacement(
    runtime: &CallServiceRuntime,
    call_id: CallId,
    leg_id: LegId,
    endpoint: String,
    route_id: &str,
    idempotency: &str,
) {
    let replacement_route = NamedRouteBinding::new_with_profiles(
        route_id,
        None,
        vec![NamedProfileBinding::new(
            NamedProfileRole::Destination,
            NamedProfileKind::WebRtc,
            "generic-agent",
            PROFILE_REVISION,
        )
        .unwrap()],
    )
    .unwrap();
    runtime
        .service()
        .replace_leg(
            &principal(),
            call_id,
            leg_id,
            &IdempotencyKey::parse(idempotency).unwrap(),
            ReplaceLegInput {
                tenant_id: None,
                route_id: replacement_route.route_id().to_owned(),
            },
            webrtc_replacement_destination(endpoint),
            replacement_route,
        )
        .await
        .expect("server-owned WebRTC replacement is accepted");
}

async fn start_sip_replacement(
    runtime: &CallServiceRuntime,
    call_id: CallId,
    leg_id: LegId,
    endpoint: String,
    route_id: &str,
    idempotency: &str,
) {
    start_sip_replacement_with_route(
        runtime,
        call_id,
        leg_id,
        endpoint,
        NamedRouteBinding::new_with_profiles(
            route_id,
            None,
            vec![NamedProfileBinding::new(
                NamedProfileRole::Destination,
                NamedProfileKind::Sip,
                CALL_CENTER_PROFILE_ID,
                CALL_CENTER_PROFILE_REVISION,
            )
            .unwrap()],
        )
        .unwrap(),
        idempotency,
    )
    .await;
}

async fn start_sip_replacement_with_route(
    runtime: &CallServiceRuntime,
    call_id: CallId,
    leg_id: LegId,
    endpoint: String,
    replacement_route: NamedRouteBinding,
    idempotency: &str,
) {
    let route_id = replacement_route.route_id().to_owned();
    runtime
        .service()
        .replace_leg(
            &principal(),
            call_id,
            leg_id,
            &IdempotencyKey::parse(idempotency).unwrap(),
            ReplaceLegInput {
                tenant_id: None,
                route_id,
            },
            sip_replacement_destination(endpoint),
            replacement_route,
        )
        .await
        .expect("server-owned SIP replacement is accepted");
}

async fn current_outbound_binding(
    runtime: &CallServiceRuntime,
    call_id: CallId,
) -> (LegId, BindingGeneration, ConnectionId) {
    let stored = runtime
        .service_repository()
        .load_service_call(&TenantId::parse("generic-wss-tenant").unwrap(), call_id)
        .await
        .unwrap();
    let leg = stored
        .call
        .aggregate
        .legs()
        .iter()
        .find(|leg| leg.direction() == LegDirection::Outbound)
        .expect("call has one outbound logical leg");
    let binding = &stored.call.bindings[&leg.id()];
    (
        leg.id(),
        binding.binding_generation,
        binding.connection_id.clone(),
    )
}

async fn current_inbound_binding(
    runtime: &CallServiceRuntime,
    call_id: CallId,
) -> (LegId, BindingGeneration, ConnectionId) {
    let stored = runtime
        .service_repository()
        .load_service_call(&TenantId::parse("generic-wss-tenant").unwrap(), call_id)
        .await
        .unwrap();
    let leg = stored
        .call
        .aggregate
        .legs()
        .iter()
        .find(|leg| leg.direction() == LegDirection::Inbound)
        .expect("call has one inbound logical leg");
    let binding = &stored.call.bindings[&leg.id()];
    (
        leg.id(),
        binding.binding_generation,
        binding.connection_id.clone(),
    )
}

async fn wait_for_active_bridge_count(orchestrator: &Orchestrator, expected: u64) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if matches!(
                orchestrator.capacity_report(),
                Event::CapacityReport { active_bridges, .. } if active_bridges == expected
            ) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("active bridge count did not become {expected}"));
}

async fn assert_replacement_is_still_pending(
    runtime: &CallServiceRuntime,
    orchestrator: &Orchestrator,
    call_id: CallId,
    leg_id: LegId,
    generation: BindingGeneration,
) {
    let stored = runtime
        .service_repository()
        .load_service_call(&TenantId::parse("generic-wss-tenant").unwrap(), call_id)
        .await
        .unwrap();
    assert_eq!(
        stored.call.aggregate.state(),
        CallState::Transferring,
        "WSS replacement promoted before destination acceptance"
    );
    assert!(stored
        .call
        .aggregate
        .replacement()
        .is_some_and(|replacement| {
            replacement.leg_id() == leg_id && replacement.pending_binding_generation() == generation
        }));
    assert!(matches!(
        orchestrator.capacity_report(),
        Event::CapacityReport {
            active_bridges: 0,
            ..
        }
    ));
}

async fn handoff_statuses_until(
    events: &mut mpsc::Receiver<AdapterEvent>,
    browser_connection: &ConnectionId,
    terminal: HandoffStatusKind,
) -> Vec<HandoffStatusEnvelope> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut statuses = Vec::new();
        loop {
            match events.recv().await {
                Some(AdapterEvent::DataMessage {
                    connection_id,
                    message,
                }) if &connection_id == browser_connection
                    && message.label == HANDOFF_STATUS_LABEL =>
                {
                    let status = HandoffStatusEnvelope::from_data_message(&message)
                        .expect("handoff status uses the signed server wire contract");
                    let complete = status.status == terminal;
                    statuses.push(status);
                    if complete {
                        return statuses;
                    }
                }
                Some(_) => {}
                None => panic!("browser event stream closed before handoff terminal status"),
            }
        }
    })
    .await
    .expect("handoff terminal status deadline")
}

fn assert_handoff_statuses(
    statuses: &[HandoffStatusEnvelope],
    call_id: CallId,
    leg_id: LegId,
    generation: BindingGeneration,
    expected: &[HandoffStatusKind],
) {
    assert_eq!(
        statuses
            .iter()
            .map(|status| status.status)
            .collect::<Vec<_>>(),
        expected
    );
    for status in statuses {
        assert_eq!(status.call_id, call_id);
        assert_eq!(status.replacement_leg_id, leg_id);
        assert_eq!(status.binding_generation, generation);
    }
}

async fn drain_audio_until_quiet(receiver: &mut mpsc::Receiver<MediaFrame>) {
    while tokio::time::timeout(Duration::from_millis(100), receiver.recv())
        .await
        .is_ok_and(|frame| frame.is_some())
    {}
}

async fn assert_no_audio(receiver: &mut mpsc::Receiver<MediaFrame>, reason: &'static str) {
    match tokio::time::timeout(Duration::from_millis(350), receiver.recv()).await {
        Err(_) => {}
        Ok(Some(frame)) => panic!(
            "{reason}: received unexpected media payload type {:?}",
            frame.payload_type
        ),
        Ok(None) => panic!("{reason}: stable browser media receiver closed"),
    }
}

async fn assert_no_audio_or_closed(
    receiver: &mut mpsc::Receiver<MediaFrame>,
    reason: &'static str,
) {
    match tokio::time::timeout(Duration::from_millis(350), receiver.recv()).await {
        Err(_) | Ok(None) => {}
        Ok(Some(frame)) => panic!(
            "{reason}: received unexpected media payload type {:?}",
            frame.payload_type
        ),
    }
}

async fn baseline_browser_assistant_media(
    call: &LiveBrowserSipCall,
    assistant: &Arc<SipAdapter>,
    timestamp: u32,
) -> (
    Arc<dyn MediaStream>,
    mpsc::Receiver<MediaFrame>,
    Arc<dyn MediaStream>,
    mpsc::Receiver<MediaFrame>,
) {
    let browser_stream = audio_stream(call.browser.as_ref(), &call.browser_connection).await;
    let assistant_stream = audio_stream(assistant.as_ref(), &call.destination_connection).await;
    assert_eq!(browser_stream.codec().name.to_ascii_lowercase(), "opus");
    assert_eq!(
        assistant_stream.codec().name.to_ascii_lowercase(),
        "g.711-mu"
    );
    let mut browser_audio = browser_stream.try_frames_in().unwrap();
    let mut assistant_audio = assistant_stream.try_frames_in().unwrap();

    send_opus(&browser_stream, timestamp).await;
    let at_assistant = tokio::time::timeout(Duration::from_secs(10), assistant_audio.recv())
        .await
        .expect("browser-to-assistant audio deadline")
        .expect("assistant media route remained live");
    assert_eq!(at_assistant.payload_type, Some(0));
    assert_eq!(at_assistant.payload.len(), 160);

    send_encoded(
        &assistant_stream,
        bytes::Bytes::from(vec![0xff; 160]),
        0,
        timestamp / 6,
        160,
    )
    .await;
    let at_browser = tokio::time::timeout(Duration::from_secs(10), browser_audio.recv())
        .await
        .expect("assistant-to-browser audio deadline")
        .expect("browser media route remained live");
    assert_eq!(at_browser.payload_type, Some(111));
    assert!(!at_browser.payload.is_empty());
    drain_audio_until_quiet(&mut browser_audio).await;
    drain_audio_until_quiet(&mut assistant_audio).await;

    (
        browser_stream,
        browser_audio,
        assistant_stream,
        assistant_audio,
    )
}

async fn wait_connection_dead(adapter: &dyn ConnectionAdapter, connection_id: &ConnectionId) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while adapter.is_connection_live(connection_id) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("terminal signaling route was retained");
}

async fn wait_for_call(
    runtime: &CallServiceRuntime,
    call_id: CallId,
    predicate: impl Fn(&bridgefu::call_service::StoredServiceCall) -> bool,
) -> bridgefu::call_service::StoredServiceCall {
    let tenant = TenantId::parse("generic-wss-tenant").unwrap();
    let result = tokio::time::timeout(Duration::from_secs(15), async {
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
            panic!("durable call state deadline: {:?}", stored.call.aggregate);
        }
    }
}

async fn next_inbound(events: &mut mpsc::Receiver<AdapterEvent>) -> Option<ConnectionId> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match events.recv().await {
                Some(AdapterEvent::InboundConnection { connection }) => return connection.id,
                Some(_) => {}
                None => panic!("destination event stream closed"),
            }
        }
    })
    .await
    .ok()
}

async fn next_data(
    events: &mut mpsc::Receiver<AdapterEvent>,
    connection_id: &ConnectionId,
) -> DataMessage {
    next_data_labeled("DataMessage", events, connection_id).await
}

async fn next_data_with_label(
    events: &mut mpsc::Receiver<AdapterEvent>,
    connection_id: &ConnectionId,
    expected_label: &str,
) -> DataMessage {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match events.recv().await {
                Some(AdapterEvent::DataMessage {
                    connection_id: observed,
                    message,
                }) if &observed == connection_id && message.label == expected_label => {
                    return message;
                }
                Some(_) => {}
                None => panic!("WebRTC event stream closed before {expected_label}"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("DataMessage {expected_label} deadline"))
}

async fn next_data_labeled(
    label: &'static str,
    events: &mut mpsc::Receiver<AdapterEvent>,
    connection_id: &ConnectionId,
) -> DataMessage {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match events.recv().await {
                Some(AdapterEvent::DataMessage {
                    connection_id: observed,
                    message,
                }) if &observed == connection_id => return message,
                Some(_) => {}
                None => panic!("WebRTC event stream closed before DataMessage"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{label} deadline"))
}

async fn next_dtmf(
    events: &mut mpsc::Receiver<AdapterEvent>,
    connection_id: &ConnectionId,
) -> (String, u32) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match events.recv().await {
                Some(AdapterEvent::Dtmf {
                    connection_id: observed,
                    digits,
                    duration_ms,
                }) if &observed == connection_id => return (digits, duration_ms),
                Some(_) => {}
                None => panic!("WebRTC event stream closed before DTMF"),
            }
        }
    })
    .await
    .expect("DTMF deadline")
}

async fn next_authenticated_sip_session(
    coordinator: &Arc<rvoip_sip::UnifiedCoordinator>,
    events: &mut SipEventReceiver,
) -> (String, SessionHandle) {
    next_authenticated_sip_session_for_tenant(coordinator, events, SIP_PROFILE_ID).await
}

async fn next_authenticated_sip_session_for_tenant(
    coordinator: &Arc<rvoip_sip::UnifiedCoordinator>,
    events: &mut SipEventReceiver,
    expected_tenant: &str,
) -> (String, SessionHandle) {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut incoming = None;
        let mut authenticated = None;
        loop {
            match events.next().await {
                Some(SipEvent::IncomingCall { call_id, from, .. }) => {
                    incoming = Some((call_id, from));
                }
                Some(SipEvent::IncomingCallAuthenticated { call_id, principal }) => {
                    assert_eq!(
                        principal.tenant.as_deref(),
                        Some(expected_tenant),
                        "Digest authentication bound the wrong destination tenant"
                    );
                    authenticated = Some(call_id);
                }
                Some(_) => {}
                None => panic!("SIP event stream closed before authenticated INVITE"),
            }
            if let (Some((incoming_id, from)), Some(authenticated_id)) =
                (incoming.as_ref(), authenticated.as_ref())
            {
                if incoming_id == authenticated_id {
                    return (from.clone(), coordinator.session(incoming_id));
                }
            }
        }
    })
    .await
    .expect("authenticated SIPS INVITE deadline")
}

async fn wait_for_orchestrator_idle(orchestrator: &Orchestrator) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if matches!(
                orchestrator.capacity_report(),
                Event::CapacityReport {
                    active_connections: 0,
                    active_bridges: 0,
                    admission_in_use: 0,
                    ..
                }
            ) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("orchestrator retained a connection, bridge, or admission permit");
}

async fn audio_stream(
    adapter: &dyn ConnectionAdapter,
    connection_id: &ConnectionId,
) -> Arc<dyn MediaStream> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(Some(stream)) = adapter.streams(connection_id.clone()).await.map(|streams| {
                streams
                    .into_iter()
                    .find(|stream| stream.kind() == StreamKind::Audio)
            }) {
                return stream;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("Opus stream deadline")
}

async fn send_encoded(
    stream: &Arc<dyn MediaStream>,
    payload: bytes::Bytes,
    payload_type: u8,
    timestamp: u32,
    timestamp_step: u32,
) {
    for offset in 0..8 {
        bounded(
            "encoded media frame send",
            stream.frames_out().send(MediaFrame {
                stream_id: stream.id(),
                kind: StreamKind::Audio,
                payload: payload.clone(),
                timestamp_rtp: timestamp + offset * timestamp_step,
                captured_at: Utc::now(),
                payload_type: Some(payload_type),
            }),
        )
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn send_opus(stream: &Arc<dyn MediaStream>, timestamp: u32) {
    send_encoded(
        stream,
        rvoip_webrtc::media::silent_opus_payload(),
        111,
        timestamp,
        960,
    )
    .await;
}

struct LiveCall {
    call_id: CallId,
    browser: Arc<WebRtcAdapter>,
    browser_events: mpsc::Receiver<AdapterEvent>,
    browser_connection: ConnectionId,
    destination_connection: ConnectionId,
}

struct LiveSipCall {
    call_id: CallId,
    source_connection: ConnectionId,
    destination_connection: ConnectionId,
}

struct LiveBrowserSipCall {
    call_id: CallId,
    browser: Arc<WebRtcAdapter>,
    browser_events: mpsc::Receiver<AdapterEvent>,
    browser_connection: ConnectionId,
    destination_connection: ConnectionId,
}

struct SipDestinationFixture {
    coordinator: Arc<rvoip_sip::UnifiedCoordinator>,
    adapter: Arc<SipAdapter>,
    events: mpsc::Receiver<AdapterEvent>,
    sip_events: SipEventReceiver,
    tls_address: std::net::SocketAddr,
}

async fn sip_destination_fixture(
    name: &str,
    tls: &TestTlsFiles,
    codecs: Vec<u8>,
) -> SipDestinationFixture {
    sip_destination_fixture_with_auth(
        name,
        tls,
        codecs,
        SIP_PROFILE_ID,
        SIP_DIGEST_REALM,
        SIP_DIGEST_USER,
        SIP_DIGEST_PASSWORD,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn sip_destination_fixture_with_auth(
    name: &str,
    tls: &TestTlsFiles,
    codecs: Vec<u8>,
    tenant: &str,
    realm: &str,
    username: &str,
    password: &str,
) -> SipDestinationFixture {
    let udp_address = reserve_udp();
    let tls_address = reserve_tcp();
    let policy = SipListenerAuthPolicy::authenticated_for_tenant(
        tenant,
        SipAuthService::digest(realm).with_digest_user(username, password),
    )
    .unwrap();
    let config = tls_sip_config(name, udp_address, tls_address, tls, codecs);
    assert!(
        config.srtp_required,
        "destination fixture must require SRTP"
    );
    let coordinator = rvoip_sip::UnifiedCoordinator::new_with_listener_auth(config, policy)
        .await
        .unwrap();
    let sip_events = coordinator.events().await.unwrap();
    let adapter = SipAdapter::new_with_inbound_context_policy(
        Arc::clone(&coordinator),
        SipInboundContextPolicy::new(["X-Correlation-Id", "X-Account-Tier", "X-Unmapped-Private"])
            .unwrap(),
    )
    .await
    .unwrap();
    let events = adapter.subscribe_events();
    SipDestinationFixture {
        coordinator,
        adapter,
        events,
        sip_events,
        tls_address,
    }
}

#[allow(clippy::too_many_arguments)]
async fn establish_call(
    runtime: &CallServiceRuntime,
    bridge_address: std::net::SocketAddr,
    destination_endpoint: String,
    trust: Arc<WebRtcTlsClientTrust>,
    destination_adapter: &Arc<WebRtcAdapter>,
    destination_events: &mut mpsc::Receiver<AdapterEvent>,
    idempotency: &str,
) -> LiveCall {
    let created = runtime
        .service()
        .create_named_route_call(
            &principal(),
            &IdempotencyKey::parse(idempotency).unwrap(),
            route_input(destination_endpoint),
            route_binding(),
        )
        .await
        .unwrap();
    let source = created
        .value
        .call
        .legs
        .iter()
        .find(|leg| leg.direction == LegDirection::Inbound)
        .unwrap();
    let token = source.attachment.as_ref().unwrap().token.clone();
    let call_id = created.value.call.call_id;

    let browser = WebRtcAdapter::new(WebRtcConfig::loopback());
    let browser_events = browser.subscribe_events();
    let ingress_endpoint = format!("wss://localhost:{}/signal", bridge_address.port());
    let provider = Arc::new(StaticWebRtcBearerCredentialProvider::new(
        WebRtcBearerCredential::new(token).unwrap(),
    ));
    let context = WebRtcOriginateContext::websocket(
        &ingress_endpoint,
        WebRtcTargetPolicy::default()
            .allow_port(bridge_address.port())
            .allow_loopback(true)
            .with_timeouts(Duration::from_secs(3), Duration::from_secs(15))
            .unwrap(),
    )
    .unwrap()
    .with_bearer_provider(provider)
    .with_tls_trust(trust);
    let browser_connection = bounded(
        "browser WSS originate",
        browser.originate(
            OriginateRequest::new(
                SessionId::new(),
                ParticipantId::new(),
                ingress_endpoint,
                Direction::Outbound,
                browser.capabilities(),
            )
            .with_context(context),
        ),
    )
    .await
    .unwrap()
    .connection
    .id;
    let activation = {
        let browser = Arc::clone(&browser);
        let connection = browser_connection.clone();
        tokio::spawn(async move { browser.activate_outbound(connection).await })
    };

    let Some(destination_connection) = next_inbound(destination_events).await else {
        let stored = runtime
            .service_repository()
            .load_service_call(&TenantId::parse("generic-wss-tenant").unwrap(), call_id)
            .await
            .unwrap();
        let activation_result = if activation.is_finished() {
            Some(activation.await)
        } else {
            activation.abort();
            None
        };
        panic!(
            "destination inbound WSS deadline: activation={activation_result:?}, call={:?}",
            stored.call.aggregate
        );
    };
    bounded(
        "destination ICE/DTLS accept",
        destination_adapter.accept(destination_connection.clone()),
    )
    .await
    .expect("destination accepts ICE/DTLS");
    bounded("browser WSS/ICE/DTLS activation", activation)
        .await
        .expect("browser activation task")
        .expect("browser WSS/ICE/DTLS activation");
    wait_for_call(runtime, call_id, |stored| {
        stored.call.aggregate.state() == CallState::Active
    })
    .await;

    LiveCall {
        call_id,
        browser,
        browser_events,
        browser_connection,
        destination_connection,
    }
}

#[allow(clippy::too_many_arguments)]
async fn establish_sips_call(
    runtime: &CallServiceRuntime,
    bridge_tls_address: std::net::SocketAddr,
    destination_endpoint: String,
    source_adapter: &Arc<SipAdapter>,
    destination_adapter: &Arc<WebRtcAdapter>,
    destination_events: &mut mpsc::Receiver<AdapterEvent>,
    idempotency: &str,
    correlation_id: &str,
) -> LiveSipCall {
    let created = runtime
        .service()
        .create_named_route_call(
            &principal(),
            &IdempotencyKey::parse(idempotency).unwrap(),
            sip_route_input(destination_endpoint),
            route_binding(),
        )
        .await
        .unwrap();
    let source = created
        .value
        .call
        .legs
        .iter()
        .find(|leg| leg.direction == LegDirection::Inbound)
        .unwrap();
    let token = source.attachment.as_ref().unwrap().token.clone();
    let call_id = created.value.call.call_id;
    let target = format!(
        "sips:{token}@localhost:{};transport=tls",
        bridge_tls_address.port()
    );
    let context = SipOriginateContext::new()
        .with_from_uri("sips:vapi-widget@localhost;transport=tls")
        .unwrap()
        .with_initial_headers(
            SipInitialHeaders::new([
                ("X-Correlation-Id", correlation_id),
                ("X-Account-Tier", "platinum"),
                ("X-Unmapped-Private", "must-not-cross"),
            ])
            .unwrap(),
        );
    let source_connection = bounded(
        "Vapi-like SIPS originate",
        source_adapter.originate(
            OriginateRequest::new(
                SessionId::new(),
                ParticipantId::new(),
                target,
                Direction::Outbound,
                source_adapter.capabilities(),
            )
            .with_transport(Transport::Sip)
            .with_context(context),
        ),
    )
    .await
    .unwrap()
    .connection
    .id;
    let activation = {
        let source_adapter = Arc::clone(source_adapter);
        let connection = source_connection.clone();
        tokio::spawn(async move { source_adapter.activate_outbound(connection).await })
    };
    let destination_connection = next_inbound(destination_events)
        .await
        .expect("Vapi-like SIPS route reached WSS destination");
    bounded(
        "SIPS destination ICE/DTLS accept",
        destination_adapter.accept(destination_connection.clone()),
    )
    .await
    .expect("WSS destination accepts SIPS-originated call");
    bounded("Vapi-like SIPS activation", activation)
        .await
        .expect("SIPS activation task")
        .expect("SIPS/TLS/SRTP activation");
    wait_for_call(runtime, call_id, |stored| {
        stored.call.aggregate.state() == CallState::Active
    })
    .await;

    LiveSipCall {
        call_id,
        source_connection,
        destination_connection,
    }
}

#[allow(clippy::too_many_arguments)]
async fn establish_browser_to_sips_call(
    runtime: &CallServiceRuntime,
    bridge_address: std::net::SocketAddr,
    trust: Arc<WebRtcTlsClientTrust>,
    destination_endpoint: String,
    destination_coordinator: &Arc<rvoip_sip::UnifiedCoordinator>,
    destination_adapter: &Arc<SipAdapter>,
    destination_events: &mut mpsc::Receiver<AdapterEvent>,
    destination_sip_events: &mut SipEventReceiver,
    idempotency: &str,
    correlation_id: &str,
) -> LiveBrowserSipCall {
    let created = runtime
        .service()
        .create_named_route_call(
            &principal(),
            &IdempotencyKey::parse(idempotency).unwrap(),
            browser_to_sip_route_input(destination_endpoint),
            browser_to_sip_route_binding(),
        )
        .await
        .unwrap();
    let source = created
        .value
        .call
        .legs
        .iter()
        .find(|leg| leg.direction == LegDirection::Inbound)
        .unwrap();
    let source_leg_id = source.leg_id;
    let token = source.attachment.as_ref().unwrap().token.clone();
    let call_id = created.value.call.call_id;

    let browser = WebRtcAdapter::new(WebRtcConfig::loopback());
    let browser_events = browser.subscribe_events();
    let ingress_endpoint = format!("wss://localhost:{}/signal", bridge_address.port());
    let provider = Arc::new(StaticWebRtcBearerCredentialProvider::new(
        WebRtcBearerCredential::new(token).unwrap(),
    ));
    let context = WebRtcOriginateContext::websocket(
        &ingress_endpoint,
        WebRtcTargetPolicy::default()
            .allow_port(bridge_address.port())
            .allow_loopback(true)
            .with_timeouts(Duration::from_secs(3), Duration::from_secs(15))
            .unwrap(),
    )
    .unwrap()
    .with_bearer_provider(provider)
    .with_tls_trust(trust);
    let browser_connection = bounded(
        "browser-to-SIP WSS originate",
        browser.originate(
            OriginateRequest::new(
                SessionId::new(),
                ParticipantId::new(),
                ingress_endpoint,
                Direction::Outbound,
                browser.capabilities(),
            )
            .with_context(context),
        ),
    )
    .await
    .unwrap()
    .connection
    .id;
    bounded(
        "browser-to-SIP WSS activation",
        browser.activate_outbound(browser_connection.clone()),
    )
    .await
    .expect("authenticated browser attachment activates before required context");

    assert!(
        tokio::time::timeout(Duration::from_millis(200), async {
            loop {
                match destination_events.recv().await {
                    Some(AdapterEvent::InboundConnection { .. }) => return,
                    Some(_) => {}
                    None => panic!("SIP destination event stream closed before context"),
                }
            }
        })
        .await
        .is_err(),
        "required browser context did not gate the first outbound INVITE"
    );

    let mut initial_context = ContextEnvelope::new(
        correlation_id,
        "generic-wss-tenant",
        call_id.to_string(),
        source_leg_id.to_string(),
    );
    initial_context
        .metadata
        .insert("account_tier".into(), "gold".into());
    initial_context
        .metadata
        .insert("must_not_forward".into(), "private-browser-value".into());
    bounded(
        "initial browser context DataChannel send",
        browser.send_data_message(
            browser_connection.clone(),
            initial_context.to_data_message().unwrap(),
        ),
    )
    .await
    .unwrap();

    let destination_connection = next_inbound(destination_events)
        .await
        .expect("browser context released the authenticated SIPS destination");
    let inbound_context = destination_adapter
        .take_inbound_context(&destination_connection)
        .expect("destination retained sanitized initial INVITE metadata");
    assert_eq!(
        inbound_context
            .metadata()
            .values("X-Correlation-Id")
            .collect::<Vec<_>>(),
        [correlation_id]
    );
    assert_eq!(
        inbound_context
            .metadata()
            .values("X-Account-Tier")
            .collect::<Vec<_>>(),
        ["gold"]
    );
    assert!(
        inbound_context
            .metadata()
            .values("X-Unmapped-Private")
            .next()
            .is_none(),
        "unallowlisted browser context became a SIP header"
    );

    let (from, destination_session) =
        next_authenticated_sip_session(destination_coordinator, destination_sip_events).await;
    assert!(
        from.contains("sips:bridgefu-browser@localhost"),
        "named SIP profile From identity was not applied: {from}"
    );
    if !destination_adapter.is_connection_live(&destination_connection) {
        let mut terminal_events = Vec::new();
        while let Ok(event) = destination_events.try_recv() {
            terminal_events.push(format!("{event:?}"));
        }
        let session_state = destination_coordinator
            .get_state(destination_session.id())
            .await;
        panic!(
            "authenticated inbound SIPS route retired before application acceptance; \
             session_state={session_state:?}; adapter_events={terminal_events:?}"
        );
    }
    let accept_result = bounded(
        "authenticated SIPS destination accept",
        destination_adapter.accept(destination_connection.clone()),
    )
    .await;
    if let Err(error) = accept_result {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut terminal_events = Vec::new();
        while let Ok(event) = destination_events.try_recv() {
            terminal_events.push(format!("{event:?}"));
        }
        let session_state = destination_coordinator
            .get_state(destination_session.id())
            .await;
        let stream_mapping = destination_adapter
            .streams(destination_connection.clone())
            .await
            .map(|streams| streams.len());
        panic!(
            "authenticated inbound SIPS acceptance failed; error={error:?}; \
             session_state={session_state:?}; route_live={}; stream_mapping={stream_mapping:?}; \
             adapter_events={terminal_events:?}",
            destination_adapter.is_connection_live(&destination_connection),
        );
    }
    wait_for_call(runtime, call_id, |stored| {
        stored.call.aggregate.state() == CallState::Active
    })
    .await;
    let security = destination_session
        .wait_for_media_security(Some(Duration::from_secs(5)))
        .await
        .expect("mandatory destination SRTP security context");
    assert!(security.contexts_installed);
    assert_eq!(security.profile, MediaSecurityProfile::RtpSavp);

    LiveBrowserSipCall {
        call_id,
        browser,
        browser_events,
        browser_connection,
        destination_connection,
    }
}

async fn exercise_browser_sip_media_and_control(
    runtime: &CallServiceRuntime,
    orchestrator: &Orchestrator,
    call: &mut LiveBrowserSipCall,
    destination: &Arc<SipAdapter>,
    destination_events: &mut mpsc::Receiver<AdapterEvent>,
    expected_codec: &str,
    expected_payload_type: u8,
    g711_silence: u8,
    case_name: &str,
) {
    let browser_stream = audio_stream(call.browser.as_ref(), &call.browser_connection).await;
    let destination_stream = audio_stream(destination.as_ref(), &call.destination_connection).await;
    assert_eq!(browser_stream.codec().name.to_ascii_lowercase(), "opus");
    assert_eq!(
        destination_stream.codec().name.to_ascii_lowercase(),
        expected_codec
    );
    let mut browser_audio = browser_stream.try_frames_in().unwrap();
    let mut destination_audio = destination_stream.try_frames_in().unwrap();

    send_opus(&browser_stream, 96_000).await;
    let at_sip = tokio::time::timeout(Duration::from_secs(10), destination_audio.recv())
        .await
        .expect("Opus to G.711 media deadline")
        .expect("SIP destination media remained live");
    assert_eq!(at_sip.payload_type, Some(expected_payload_type));
    assert_eq!(at_sip.payload.len(), 160);

    send_encoded(
        &destination_stream,
        bytes::Bytes::from(vec![g711_silence; 160]),
        expected_payload_type,
        32_000,
        160,
    )
    .await;
    let at_browser = tokio::time::timeout(Duration::from_secs(10), browser_audio.recv())
        .await
        .expect("G.711 to Opus media deadline")
        .expect("browser media remained live");
    assert_eq!(at_browser.payload_type, Some(111));
    assert!(!at_browser.payload.is_empty());

    let stored = runtime
        .service_repository()
        .load_service_call(
            &TenantId::parse("generic-wss-tenant").unwrap(),
            call.call_id,
        )
        .await
        .unwrap();
    let destination_leg = stored
        .call
        .aggregate
        .legs()
        .iter()
        .find(|leg| leg.direction() == LegDirection::Outbound)
        .unwrap()
        .id();
    let bridgefu_sip_connection = stored.call.bindings[&destination_leg].connection_id.clone();
    let direct_probe = DataMessage::reliable(
        format!("bridgefu.sip.probe.{case_name}"),
        "application/octet-stream",
        bytes::Bytes::from_static(b"sip-dialog-probe"),
    );
    bounded(
        "Bridgefu outbound SIP MESSAGE probe",
        orchestrator.send_data_message(bridgefu_sip_connection, direct_probe.clone()),
    )
    .await
    .expect("active outbound SIP dialog accepts DataMessage");
    assert_eq!(
        next_data_labeled(
            "Bridgefu outbound SIP MESSAGE probe",
            destination_events,
            &call.destination_connection,
        )
        .await,
        direct_probe
    );

    let browser_message = DataMessage::reliable(
        format!("browser.to.sip.{case_name}"),
        "application/octet-stream",
        bytes::Bytes::from_static(b"\0\xffbrowser-to-sip-message"),
    );
    bounded(
        "browser DataChannel to SIP MESSAGE",
        call.browser
            .send_data_message(call.browser_connection.clone(), browser_message.clone()),
    )
    .await
    .unwrap();
    assert_eq!(
        next_data_labeled(
            "browser DataChannel to SIP MESSAGE",
            destination_events,
            &call.destination_connection,
        )
        .await,
        browser_message
    );
    let sip_message = DataMessage::reliable(
        format!("sip.to.browser.{case_name}"),
        "application/json",
        bytes::Bytes::from_static(br#"{"source":"sip-message"}"#),
    );
    bounded(
        "SIP MESSAGE to browser DataChannel",
        destination.send_data_message(call.destination_connection.clone(), sip_message.clone()),
    )
    .await
    .unwrap();
    assert_eq!(
        next_data_labeled(
            "SIP MESSAGE to browser DataChannel",
            &mut call.browser_events,
            &call.browser_connection,
        )
        .await,
        sip_message
    );

    bounded(
        "browser RFC4733 DTMF to SIP",
        call.browser
            .send_dtmf(call.browser_connection.clone(), "6", 120),
    )
    .await
    .unwrap();
    assert_eq!(
        next_dtmf(destination_events, &call.destination_connection)
            .await
            .0,
        "6"
    );
    bounded(
        "SIP RFC4733 DTMF to browser",
        destination.send_dtmf(call.destination_connection.clone(), "3", 140),
    )
    .await
    .unwrap();
    assert_eq!(
        next_dtmf(&mut call.browser_events, &call.browser_connection)
            .await
            .0,
        "3"
    );
}

#[test]
fn browser_and_vapi_like_sips_to_wss_are_full_duplex_and_clean_both_hangup_directions() {
    let _serial = QUALIFICATION_TEST_LOCK.lock().unwrap();
    std::thread::Builder::new()
        .name("browser-and-vapi-sips-to-wss-qualification".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .thread_stack_size(8 * 1024 * 1024)
                .enable_all()
                .build()
                .unwrap()
                .block_on(Box::pin(run_browser_and_vapi_like_sips_to_wss()));
        })
        .unwrap()
        .join()
        .expect("browser and Vapi-like SIPS to WSS qualification panicked");
}

async fn run_browser_and_vapi_like_sips_to_wss() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let certificate = generated.cert.pem().into_bytes();
    let private_key = generated.signing_key.serialize_pem().into_bytes();
    let tls = TlsConfig::from_pem_bytes(&certificate, &private_key)
        .await
        .unwrap();
    let trust = Arc::new(WebRtcTlsClientTrust::from_pem(&certificate).unwrap());
    let trust_path =
        std::env::temp_dir().join(format!("bridgefu-generic-wss-{}.pem", uuid::Uuid::new_v4()));
    std::fs::write(&trust_path, &certificate).unwrap();

    let destination_auth = Arc::new(DestinationAuth {
        calls: AtomicUsize::new(0),
    });
    let mut destination_config = WebRtcConfig::loopback();
    destination_config.trickle_ice = true;
    destination_config.max_concurrent_sessions = 4;
    let destination_server: WebRtcServer = WebRtcServerBuilder::new(destination_config)
        .with_wss("127.0.0.1:0", tls.clone())
        .with_ws_auth(Arc::clone(&destination_auth) as Arc<dyn WsAuthHook>)
        .build()
        .await
        .unwrap();
    let destination_address = destination_server.wss_addr().unwrap();
    let destination_endpoint = format!("wss://localhost:{}/signal", destination_address.port());
    let destination_adapter = destination_server.adapter();
    let mut destination_events = destination_adapter.subscribe_events();

    let runtime = call_runtime().await;
    let orchestrator = Orchestrator::new(CoreConfig::default());
    let mut bridge_config = WebRtcConfig::loopback();
    bridge_config.max_concurrent_sessions = 8;
    bridge_config.trickle_ice = true;
    let bridge_inner = WebRtcAdapter::new_with_inbound_admission_confirmation(
        bridge_config,
        Duration::from_secs(10),
    )
    .unwrap();
    let bridge_adapter = LoopbackFixtureWebRtcAdapter::new(Arc::clone(&bridge_inner));
    let mut resolver = StaticOutboundProfileResolver::default();
    resolver.insert_webrtc(
        "generic-agent".into(),
        PROFILE_REVISION.into(),
        ConfiguredWebRtcOutboundProfile {
            bearer_token: Some(SecretRef::new(DESTINATION_BEARER)),
            tls_roots: vec![trust_path.to_string_lossy().into_owned()],
            ice_servers: vec![ConfiguredIceServer {
                urls: vec!["turn:127.0.0.1:9?transport=udp".into()],
                username: Some("turn-fixture".into()),
                credential: Some(SecretRef::new("turn-fixture-secret")),
            }],
            audio_codecs: vec![
                rvoip_webrtc::WebRtcAudioCodec::Opus,
                rvoip_webrtc::WebRtcAudioCodec::Pcmu,
                rvoip_webrtc::WebRtcAudioCodec::Pcma,
            ],
            data_channels: true,
        },
    );
    let supervisor = CallExecutionSupervisor::install_with_leg_executors_context_canary_broadcast_and_outbound_profiles(
        Arc::clone(&orchestrator),
        Arc::clone(&runtime),
        Arc::new(DisabledProviderLegExecutor),
        None,
        Arc::new(ContextPolicy {
            allow_headers: BTreeMap::from([
                ("X-Correlation-Id".into(), "correlation_id".into()),
                ("X-Account-Tier".into(), "account_tier".into()),
            ]),
        }),
        None,
        None,
        Arc::new(resolver),
        8,
        Duration::from_secs(15),
    )
    .await
    .unwrap();
    orchestrator
        .register(Arc::clone(&bridge_adapter) as Arc<dyn ConnectionAdapter>)
        .unwrap();

    let sip_tls = TestTlsFiles::create();
    let bridge_sip_udp = reserve_udp();
    let bridge_sip_tls = reserve_tcp();
    let source_sip_udp = reserve_udp();
    let source_sip_tls = reserve_tcp();
    let bridge_sip_config = tls_sip_config(
        "bridgefu-vapi-sips",
        bridge_sip_udp,
        bridge_sip_tls,
        &sip_tls,
        vec![0, 8, 101],
    );
    let bridge_sip_policy = SipListenerAuthPolicy::enabled_for_tenant("generic-wss-tenant")
        .unwrap()
        .with_trusted_cidr(
            "127.0.0.1/32".parse().unwrap(),
            principal().authenticated().clone(),
        );
    let bridge_sip_coordinator =
        rvoip_sip::UnifiedCoordinator::new_with_listener_auth(bridge_sip_config, bridge_sip_policy)
            .await
            .unwrap();
    let bridge_sip_adapter = SipAdapter::new_with_inbound_context_policy(
        Arc::clone(&bridge_sip_coordinator),
        SipInboundContextPolicy::new(["X-Correlation-Id", "X-Account-Tier"]).unwrap(),
    )
    .await
    .unwrap();
    orchestrator
        .register(Arc::clone(&bridge_sip_adapter) as Arc<dyn ConnectionAdapter>)
        .unwrap();

    let source_sip_config = tls_sip_config(
        "vapi-like-source",
        source_sip_udp,
        source_sip_tls,
        &sip_tls,
        vec![0, 101],
    );
    let source_sip_coordinator = rvoip_sip::UnifiedCoordinator::new(source_sip_config)
        .await
        .unwrap();
    let source_sip_adapter = SipAdapter::new(Arc::clone(&source_sip_coordinator))
        .await
        .unwrap();
    let mut source_sip_events = source_sip_adapter.subscribe_events();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_address = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let bridge_listener = {
        let adapter = Arc::clone(&bridge_inner);
        let auth: Arc<dyn WsAuthHook> = Arc::new(AttachmentAuth {
            principal: principal().authenticated().clone(),
        });
        tokio::spawn(async move {
            serve_tls_listener_with_auth_and_shutdown(listener, tls, adapter, auth, async {
                let _ = shutdown_rx.await;
            })
            .await
        })
    };

    let mut first = establish_call(
        &runtime,
        bridge_address,
        destination_endpoint.clone(),
        Arc::clone(&trust),
        &destination_adapter,
        &mut destination_events,
        "generic-wss-browser-hangup",
    )
    .await;
    let observed = bridge_adapter.last_observed();
    assert!(observed.bearer_present, "named profile omitted WSS bearer");
    assert!(
        observed.tls_trust_present,
        "named profile omitted TLS roots"
    );
    assert_eq!(
        observed.ice_urls,
        ["turn:127.0.0.1:9?transport=udp"],
        "the exact TURN-only profile must reach the rvoip adapter boundary"
    );
    assert_eq!(destination_auth.calls.load(Ordering::Acquire), 1);

    let browser_stream = audio_stream(first.browser.as_ref(), &first.browser_connection).await;
    let destination_stream =
        audio_stream(destination_adapter.as_ref(), &first.destination_connection).await;
    assert_eq!(browser_stream.codec().name.to_ascii_lowercase(), "opus");
    assert_eq!(destination_stream.codec().name.to_ascii_lowercase(), "opus");
    let mut browser_audio = browser_stream.try_frames_in().unwrap();
    let mut destination_audio = destination_stream.try_frames_in().unwrap();
    send_opus(&browser_stream, 9_600).await;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(10), destination_audio.recv())
            .await
            .unwrap()
            .unwrap()
            .payload,
        rvoip_webrtc::media::silent_opus_payload()
    );
    send_opus(&destination_stream, 19_200).await;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(10), browser_audio.recv())
            .await
            .unwrap()
            .unwrap()
            .payload,
        rvoip_webrtc::media::silent_opus_payload()
    );

    let browser_message = DataMessage::reliable(
        "customer.browser.binary.v2",
        "application/octet-stream",
        bytes::Bytes::from_static(b"\0\xffbrowser"),
    );
    bounded(
        "browser DataMessage send",
        first
            .browser
            .send_data_message(first.browser_connection.clone(), browser_message.clone()),
    )
    .await
    .unwrap();
    assert_eq!(
        next_data(&mut destination_events, &first.destination_connection).await,
        browser_message
    );
    let destination_message = DataMessage::reliable(
        "agent.status.v3",
        "application/json",
        bytes::Bytes::from_static(br#"{"state":"ready"}"#),
    );
    bounded(
        "destination DataMessage send",
        destination_adapter.send_data_message(
            first.destination_connection.clone(),
            destination_message.clone(),
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        next_data(&mut first.browser_events, &first.browser_connection).await,
        destination_message
    );

    bounded(
        "browser DTMF send",
        first
            .browser
            .send_dtmf(first.browser_connection.clone(), "5", 120),
    )
    .await
    .unwrap();
    assert_eq!(
        next_dtmf(&mut destination_events, &first.destination_connection).await,
        ("5".into(), 120)
    );
    bounded(
        "destination DTMF send",
        destination_adapter.send_dtmf(first.destination_connection.clone(), "8", 140),
    )
    .await
    .unwrap();
    assert_eq!(
        next_dtmf(&mut first.browser_events, &first.browser_connection).await,
        ("8".into(), 140)
    );

    let active = runtime
        .service_repository()
        .load_service_call(
            &TenantId::parse("generic-wss-tenant").unwrap(),
            first.call_id,
        )
        .await
        .unwrap();
    let source_leg = active
        .call
        .aggregate
        .legs()
        .iter()
        .find(|leg| leg.direction() == LegDirection::Inbound)
        .unwrap()
        .id();
    let source_connection = active.call.bindings[&source_leg].connection_id.clone();
    let mut core_events = orchestrator.subscribe_events();
    bounded(
        "browser hangup",
        first
            .browser
            .end(first.browser_connection.clone(), EndReason::Normal),
    )
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match core_events.recv().await {
                Ok(Event::ConnectionEnded { connection_id, .. })
                | Ok(Event::ConnectionFailed { connection_id, .. })
                    if connection_id == source_connection =>
                {
                    return;
                }
                Ok(_) => {}
                Err(error) => panic!("core event stream failed before source terminal: {error}"),
            }
        }
    })
    .await
    .expect("browser BYE did not reach the Bridgefu source connection");
    wait_for_call(&runtime, first.call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    tokio::time::timeout(Duration::from_secs(10), async {
        while destination_adapter.is_connection_live(&first.destination_connection) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("browser hangup left destination WSS live");

    let second = establish_call(
        &runtime,
        bridge_address,
        destination_endpoint.clone(),
        Arc::clone(&trust),
        &destination_adapter,
        &mut destination_events,
        "generic-wss-destination-hangup",
    )
    .await;
    bounded(
        "destination hangup",
        destination_adapter.end(second.destination_connection.clone(), EndReason::Normal),
    )
    .await
    .unwrap();
    wait_for_call(&runtime, second.call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    tokio::time::timeout(Duration::from_secs(10), async {
        while second
            .browser
            .is_connection_live(&second.browser_connection)
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("destination hangup left browser WSS live");

    let first_sips = establish_sips_call(
        &runtime,
        bridge_sip_tls,
        destination_endpoint.clone(),
        &source_sip_adapter,
        &destination_adapter,
        &mut destination_events,
        "generic-wss-sips-source-hangup",
        "vapi-like-correlation-1",
    )
    .await;
    let initial_context =
        next_data(&mut destination_events, &first_sips.destination_connection).await;
    assert_eq!(initial_context.label, CONTEXT_LABEL);
    let envelope = ContextEnvelope::from_data_message(&initial_context).unwrap();
    assert_eq!(envelope.correlation_id, "vapi-like-correlation-1");
    assert_eq!(
        envelope.metadata.get("account_tier").map(String::as_str),
        Some("platinum")
    );
    assert_eq!(envelope.metadata.len(), 1, "unmapped SIP header crossed");

    let source_sip_stream =
        audio_stream(source_sip_adapter.as_ref(), &first_sips.source_connection).await;
    let sips_destination_stream = audio_stream(
        destination_adapter.as_ref(),
        &first_sips.destination_connection,
    )
    .await;
    assert_eq!(
        source_sip_stream.codec().name.to_ascii_lowercase(),
        "g.711-mu"
    );
    assert_eq!(
        sips_destination_stream.codec().name.to_ascii_lowercase(),
        "opus"
    );
    let mut source_sip_audio = source_sip_stream.try_frames_in().unwrap();
    let mut sips_destination_audio = sips_destination_stream.try_frames_in().unwrap();
    send_encoded(
        &source_sip_stream,
        bytes::Bytes::from(vec![0xff; 160]),
        0,
        32_000,
        160,
    )
    .await;
    let at_wss = tokio::time::timeout(Duration::from_secs(10), sips_destination_audio.recv())
        .await
        .expect("PCMU to Opus media deadline")
        .expect("WSS media stream remained live");
    assert_eq!(at_wss.payload_type, Some(111));
    assert!(!at_wss.payload.is_empty());
    send_opus(&sips_destination_stream, 48_000).await;
    let at_sips = tokio::time::timeout(Duration::from_secs(10), source_sip_audio.recv())
        .await
        .expect("Opus to PCMU media deadline")
        .expect("SIPS media stream remained live");
    assert_eq!(at_sips.payload_type, Some(0));
    assert_eq!(at_sips.payload.len(), 160);

    let sip_live_message = DataMessage::reliable(
        "sip.customer.live.v1",
        "application/json",
        bytes::Bytes::from_static(br#"{"from":"sip"}"#),
    );
    bounded(
        "SIP MESSAGE to DataChannel send",
        source_sip_adapter.send_data_message(
            first_sips.source_connection.clone(),
            sip_live_message.clone(),
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        next_data(&mut destination_events, &first_sips.destination_connection).await,
        sip_live_message
    );
    let wss_live_message = DataMessage::reliable(
        "agent.live.v1",
        "application/octet-stream",
        bytes::Bytes::from_static(b"\0\xffwss-to-sip"),
    );
    bounded(
        "DataChannel to SIP MESSAGE send",
        destination_adapter.send_data_message(
            first_sips.destination_connection.clone(),
            wss_live_message.clone(),
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        next_data(&mut source_sip_events, &first_sips.source_connection).await,
        wss_live_message
    );

    bounded(
        "SIPS RFC4733 DTMF send",
        source_sip_adapter.send_dtmf(first_sips.source_connection.clone(), "4", 120),
    )
    .await
    .unwrap();
    assert_eq!(
        next_dtmf(&mut destination_events, &first_sips.destination_connection)
            .await
            .0,
        "4"
    );
    bounded(
        "WSS to SIPS RFC4733 DTMF send",
        destination_adapter.send_dtmf(first_sips.destination_connection.clone(), "9", 140),
    )
    .await
    .unwrap();
    assert_eq!(
        next_dtmf(&mut source_sip_events, &first_sips.source_connection)
            .await
            .0,
        "9"
    );

    bounded(
        "Vapi-like SIPS source hangup",
        source_sip_adapter.end(first_sips.source_connection.clone(), EndReason::Normal),
    )
    .await
    .unwrap();
    wait_for_call(&runtime, first_sips.call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    tokio::time::timeout(Duration::from_secs(10), async {
        while destination_adapter.is_connection_live(&first_sips.destination_connection) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("SIPS source hangup left WSS destination live");

    let second_sips = establish_sips_call(
        &runtime,
        bridge_sip_tls,
        destination_endpoint,
        &source_sip_adapter,
        &destination_adapter,
        &mut destination_events,
        "generic-wss-sips-destination-hangup",
        "vapi-like-correlation-2",
    )
    .await;
    let second_context =
        next_data(&mut destination_events, &second_sips.destination_connection).await;
    assert_eq!(
        ContextEnvelope::from_data_message(&second_context)
            .unwrap()
            .correlation_id,
        "vapi-like-correlation-2"
    );
    bounded(
        "SIPS call WSS destination hangup",
        destination_adapter.end(
            second_sips.destination_connection.clone(),
            EndReason::Normal,
        ),
    )
    .await
    .unwrap();
    wait_for_call(&runtime, second_sips.call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    tokio::time::timeout(Duration::from_secs(10), async {
        while source_sip_adapter.is_connection_live(&second_sips.source_connection) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("WSS destination hangup left SIPS source live");

    assert_eq!(destination_auth.calls.load(Ordering::Acquire), 4);
    assert!(bridge_inner.routes().is_empty());
    assert!(destination_adapter.routes().is_empty());
    assert!(matches!(
        orchestrator.capacity_report(),
        Event::CapacityReport {
            active_bridges: 0,
            ..
        }
    ));

    let _ = shutdown_tx.send(());
    bounded("Bridgefu WSS listener shutdown", bridge_listener)
        .await
        .unwrap()
        .unwrap();
    bounded("destination server shutdown", destination_server.shutdown()).await;
    bounded(
        "call execution supervisor shutdown",
        supervisor.shutdown(Duration::from_secs(5)),
    )
    .await;
    bounded(
        "prepared outbound drain",
        orchestrator.drain_prepared_outbound_connections(),
    )
    .await;
    bounded(
        "connection lifecycle drain",
        orchestrator.drain_connection_lifecycle_tasks(),
    )
    .await;
    bounded("source SIP adapter drain", source_sip_adapter.drain())
        .await
        .unwrap();
    bounded(
        "source SIPS coordinator shutdown",
        source_sip_coordinator.shutdown_gracefully(Some(Duration::from_secs(5))),
    )
    .await
    .unwrap();
    bounded("Bridgefu SIP adapter drain", bridge_sip_adapter.drain())
        .await
        .unwrap();
    bounded(
        "Bridgefu SIPS coordinator shutdown",
        bridge_sip_coordinator.shutdown_gracefully(Some(Duration::from_secs(5))),
    )
    .await
    .unwrap();
    assert_eq!(source_sip_adapter.retained_task_count(), 0);
    assert_eq!(bridge_sip_adapter.retained_task_count(), 0);
    drop(bridge_adapter);
    drop(bridge_inner);
    bounded(
        "call runtime shutdown",
        Arc::try_unwrap(runtime)
            .expect("qualification runtime owner released")
            .shutdown(Duration::from_secs(5)),
    )
    .await
    .unwrap();
    std::fs::remove_file(trust_path).unwrap();
}

#[test]
fn direct_browser_to_named_generic_sips_qualifies_pcmu_pcma_context_and_cleanup() {
    let _serial = QUALIFICATION_TEST_LOCK.lock().unwrap();
    std::thread::Builder::new()
        .name("browser-to-generic-sips-qualification".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(6)
                .thread_stack_size(8 * 1024 * 1024)
                .enable_all()
                .build()
                .unwrap()
                .block_on(Box::pin(run_direct_browser_to_named_generic_sips()));
        })
        .unwrap()
        .join()
        .expect("browser-to-SIPS qualification panicked");
}

async fn run_direct_browser_to_named_generic_sips() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let web_certificate = generated.cert.pem().into_bytes();
    let web_private_key = generated.signing_key.serialize_pem().into_bytes();
    let web_tls = TlsConfig::from_pem_bytes(&web_certificate, &web_private_key)
        .await
        .unwrap();
    let web_trust = Arc::new(WebRtcTlsClientTrust::from_pem(&web_certificate).unwrap());
    let sip_tls = TestTlsFiles::create();

    let runtime = call_runtime().await;
    let orchestrator = Orchestrator::new(CoreConfig::default());
    let mut bridge_web_config = WebRtcConfig::loopback();
    bridge_web_config.max_concurrent_sessions = 4;
    bridge_web_config.trickle_ice = true;
    let bridge_web_adapter = WebRtcAdapter::new_with_inbound_admission_confirmation(
        bridge_web_config,
        Duration::from_secs(10),
    )
    .unwrap();

    let bridge_sip_udp = reserve_udp();
    let bridge_sip_tls = reserve_tcp();
    let bridge_sip_config = tls_sip_config(
        "bridgefu-browser-sips-egress",
        bridge_sip_udp,
        bridge_sip_tls,
        &sip_tls,
        vec![0, 8, 101],
    );
    assert!(bridge_sip_config.srtp_required);
    let bridge_sip_policy = SipListenerAuthPolicy::enabled_for_tenant("generic-wss-tenant")
        .unwrap()
        .with_trusted_cidr(
            "127.0.0.1/32".parse().unwrap(),
            principal().authenticated().clone(),
        );
    let bridge_sip_coordinator =
        rvoip_sip::UnifiedCoordinator::new_with_listener_auth(bridge_sip_config, bridge_sip_policy)
            .await
            .unwrap();
    let bridge_sip_adapter = SipAdapter::new(Arc::clone(&bridge_sip_coordinator))
        .await
        .unwrap();

    let mut resolver = StaticOutboundProfileResolver::default();
    resolver.insert_sip(
        SIP_PROFILE_ID.into(),
        SIP_PROFILE_REVISION.into(),
        ConfiguredSipOutboundProfile {
            from_uri: format!(
                "sips:bridgefu-browser@localhost:{};transport=tls",
                bridge_sip_tls.port()
            ),
            outbound_proxy: None,
            auth: Some(ConfiguredSipProfileAuth::Digest {
                realm: Some(SIP_DIGEST_REALM.into()),
                username: SIP_DIGEST_USER.into(),
                password: SecretRef::new(SIP_DIGEST_PASSWORD),
            }),
        },
    );
    let supervisor = CallExecutionSupervisor::install_with_leg_executors_context_canary_broadcast_and_outbound_profiles(
        Arc::clone(&orchestrator),
        Arc::clone(&runtime),
        Arc::new(DisabledProviderLegExecutor),
        None,
        Arc::new(ContextPolicy {
            allow_headers: BTreeMap::from([
                ("X-Correlation-Id".into(), "correlation_id".into()),
                ("X-Account-Tier".into(), "account_tier".into()),
            ]),
        }),
        None,
        None,
        Arc::new(resolver),
        4,
        Duration::from_secs(15),
    )
    .await
    .unwrap();
    orchestrator
        .register(Arc::clone(&bridge_web_adapter) as Arc<dyn ConnectionAdapter>)
        .unwrap();
    orchestrator
        .register(Arc::clone(&bridge_sip_adapter) as Arc<dyn ConnectionAdapter>)
        .unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_web_address = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let bridge_web_listener = {
        let adapter = Arc::clone(&bridge_web_adapter);
        let auth: Arc<dyn WsAuthHook> = Arc::new(AttachmentAuth {
            principal: principal().authenticated().clone(),
        });
        tokio::spawn(async move {
            serve_tls_listener_with_auth_and_shutdown(listener, web_tls, adapter, auth, async {
                let _ = shutdown_rx.await;
            })
            .await
        })
    };

    let mut pcmu_destination =
        sip_destination_fixture("generic-sip-pcmu", &sip_tls, vec![0, 101]).await;
    let mut pcma_destination =
        sip_destination_fixture("generic-sip-pcma", &sip_tls, vec![8, 101]).await;
    let pcmu_coordinator = Arc::clone(&pcmu_destination.coordinator);
    let pcmu_adapter = Arc::clone(&pcmu_destination.adapter);
    let pcma_coordinator = Arc::clone(&pcma_destination.coordinator);
    let pcma_adapter = Arc::clone(&pcma_destination.adapter);

    let mut pcmu_call = establish_browser_to_sips_call(
        &runtime,
        bridge_web_address,
        Arc::clone(&web_trust),
        format!(
            "sips:agent@localhost:{};transport=tls",
            pcmu_destination.tls_address.port()
        ),
        &pcmu_coordinator,
        &pcmu_adapter,
        &mut pcmu_destination.events,
        &mut pcmu_destination.sip_events,
        "generic-sip-browser-pcmu-source-hangup",
        "browser-pcmu-correlation",
    )
    .await;
    exercise_browser_sip_media_and_control(
        &runtime,
        &orchestrator,
        &mut pcmu_call,
        &pcmu_adapter,
        &mut pcmu_destination.events,
        "g.711-mu",
        0,
        0xff,
        "pcmu",
    )
    .await;
    bounded(
        "browser source hangup on PCMU call",
        pcmu_call
            .browser
            .end(pcmu_call.browser_connection.clone(), EndReason::Normal),
    )
    .await
    .unwrap();
    wait_for_call(&runtime, pcmu_call.call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    tokio::time::timeout(Duration::from_secs(10), async {
        while pcmu_adapter.is_connection_live(&pcmu_call.destination_connection) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("browser hangup retained the PCMU destination route");
    wait_for_orchestrator_idle(&orchestrator).await;

    let mut pcma_call = establish_browser_to_sips_call(
        &runtime,
        bridge_web_address,
        Arc::clone(&web_trust),
        format!(
            "sips:agent@localhost:{};transport=tls",
            pcma_destination.tls_address.port()
        ),
        &pcma_coordinator,
        &pcma_adapter,
        &mut pcma_destination.events,
        &mut pcma_destination.sip_events,
        "generic-sip-browser-pcma-destination-hangup",
        "browser-pcma-correlation",
    )
    .await;
    exercise_browser_sip_media_and_control(
        &runtime,
        &orchestrator,
        &mut pcma_call,
        &pcma_adapter,
        &mut pcma_destination.events,
        "g.711-a",
        8,
        0xd5,
        "pcma",
    )
    .await;
    bounded(
        "SIPS destination hangup on PCMA call",
        pcma_adapter.end(pcma_call.destination_connection.clone(), EndReason::Normal),
    )
    .await
    .unwrap();
    wait_for_call(&runtime, pcma_call.call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    tokio::time::timeout(Duration::from_secs(10), async {
        while pcma_call
            .browser
            .is_connection_live(&pcma_call.browser_connection)
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("PCMA destination hangup retained the browser route");
    wait_for_orchestrator_idle(&orchestrator).await;
    assert!(bridge_web_adapter.routes().is_empty());
    assert!(pcmu_call.browser.routes().is_empty());
    assert!(pcma_call.browser.routes().is_empty());

    let _ = shutdown_tx.send(());
    bounded("browser ingress WSS listener shutdown", bridge_web_listener)
        .await
        .unwrap()
        .unwrap();
    bounded(
        "browser-to-SIP supervisor shutdown",
        supervisor.shutdown(Duration::from_secs(5)),
    )
    .await;
    bounded(
        "browser-to-SIP prepared outbound drain",
        orchestrator.drain_prepared_outbound_connections(),
    )
    .await;
    bounded(
        "browser-to-SIP lifecycle drain",
        orchestrator.drain_connection_lifecycle_tasks(),
    )
    .await;
    bounded("Bridgefu SIP adapter drain", bridge_sip_adapter.drain())
        .await
        .unwrap();
    bounded("PCMU destination adapter drain", pcmu_adapter.drain())
        .await
        .unwrap();
    bounded("PCMA destination adapter drain", pcma_adapter.drain())
        .await
        .unwrap();
    bounded(
        "Bridgefu SIP coordinator shutdown",
        bridge_sip_coordinator.shutdown_gracefully(Some(Duration::from_secs(5))),
    )
    .await
    .unwrap();
    bounded(
        "PCMU destination coordinator shutdown",
        pcmu_coordinator.shutdown_gracefully(Some(Duration::from_secs(5))),
    )
    .await
    .unwrap();
    bounded(
        "PCMA destination coordinator shutdown",
        pcma_coordinator.shutdown_gracefully(Some(Duration::from_secs(5))),
    )
    .await
    .unwrap();
    assert_eq!(bridge_sip_adapter.retained_task_count(), 0);
    assert_eq!(pcmu_adapter.retained_task_count(), 0);
    assert_eq!(pcma_adapter.retained_task_count(), 0);
    assert_eq!(orchestrator.connection_lifecycle_task_count(), 0);
    assert!(matches!(
        orchestrator.capacity_report(),
        Event::CapacityReport {
            active_connections: 0,
            active_bridges: 0,
            admission_in_use: 0,
            ..
        }
    ));
    drop(pcmu_destination);
    drop(pcma_destination);
    drop(bridge_web_adapter);
    bounded(
        "browser-to-SIP call runtime shutdown",
        Arc::try_unwrap(runtime)
            .expect("browser-to-SIP qualification runtime owner released")
            .shutdown(Duration::from_secs(5)),
    )
    .await
    .unwrap();
}

#[test]
fn direct_browser_vapi_sip_handoff_is_make_before_break_and_profile_mismatch_fails_closed() {
    let _serial = QUALIFICATION_TEST_LOCK.lock().unwrap();
    std::thread::Builder::new()
        .name("direct-browser-vapi-sip-handoff-qualification".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(6)
                .thread_stack_size(8 * 1024 * 1024)
                .enable_all()
                .build()
                .unwrap()
                .block_on(Box::pin(run_direct_browser_vapi_sip_handoff()));
        })
        .unwrap()
        .join()
        .expect("direct browser handoff qualification panicked");
}

async fn run_direct_browser_vapi_sip_handoff() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let web_certificate = generated.cert.pem().into_bytes();
    let web_private_key = generated.signing_key.serialize_pem().into_bytes();
    let web_tls = TlsConfig::from_pem_bytes(&web_certificate, &web_private_key)
        .await
        .unwrap();
    let web_trust = Arc::new(WebRtcTlsClientTrust::from_pem(&web_certificate).unwrap());
    let sip_tls = TestTlsFiles::create();

    let runtime = call_runtime().await;
    let orchestrator = Orchestrator::new(CoreConfig::default());
    let mut bridge_web_config = WebRtcConfig::loopback();
    bridge_web_config.max_concurrent_sessions = 4;
    bridge_web_config.trickle_ice = true;
    let bridge_web_adapter = WebRtcAdapter::new_with_inbound_admission_confirmation(
        bridge_web_config,
        Duration::from_secs(10),
    )
    .unwrap();

    let bridge_sip_udp = reserve_udp();
    let bridge_sip_tls = reserve_tcp();
    let bridge_sip_config = tls_sip_config(
        "bridgefu-direct-handoff-egress",
        bridge_sip_udp,
        bridge_sip_tls,
        &sip_tls,
        vec![0, 101],
    );
    assert!(bridge_sip_config.srtp_required);
    let bridge_sip_policy = SipListenerAuthPolicy::enabled_for_tenant("generic-wss-tenant")
        .unwrap()
        .with_trusted_cidr(
            "127.0.0.1/32".parse().unwrap(),
            principal().authenticated().clone(),
        );
    let bridge_sip_coordinator =
        rvoip_sip::UnifiedCoordinator::new_with_listener_auth(bridge_sip_config, bridge_sip_policy)
            .await
            .unwrap();
    let bridge_sip_adapter = SipAdapter::new(Arc::clone(&bridge_sip_coordinator))
        .await
        .unwrap();

    let mut resolver = StaticOutboundProfileResolver::default();
    resolver.insert_sip(
        SIP_PROFILE_ID.into(),
        SIP_PROFILE_REVISION.into(),
        ConfiguredSipOutboundProfile {
            from_uri: format!(
                "sips:bridgefu-browser@localhost:{};transport=tls",
                bridge_sip_tls.port()
            ),
            outbound_proxy: None,
            auth: Some(ConfiguredSipProfileAuth::Digest {
                realm: Some(SIP_DIGEST_REALM.into()),
                username: SIP_DIGEST_USER.into(),
                password: SecretRef::new(SIP_DIGEST_PASSWORD),
            }),
        },
    );
    resolver.insert_sip(
        CALL_CENTER_PROFILE_ID.into(),
        CALL_CENTER_PROFILE_REVISION.into(),
        ConfiguredSipOutboundProfile {
            from_uri: format!(
                "sips:bridgefu-call-center@localhost:{};transport=tls",
                bridge_sip_tls.port()
            ),
            outbound_proxy: None,
            auth: Some(ConfiguredSipProfileAuth::Digest {
                realm: Some(CALL_CENTER_DIGEST_REALM.into()),
                username: CALL_CENTER_DIGEST_USER.into(),
                password: SecretRef::new(CALL_CENTER_DIGEST_PASSWORD),
            }),
        },
    );
    let supervisor = CallExecutionSupervisor::install_with_leg_executors_context_canary_broadcast_and_outbound_profiles(
        Arc::clone(&orchestrator),
        Arc::clone(&runtime),
        Arc::new(DisabledProviderLegExecutor),
        None,
        Arc::new(ContextPolicy {
            allow_headers: BTreeMap::from([
                ("X-Correlation-Id".into(), "correlation_id".into()),
                ("X-Account-Tier".into(), "account_tier".into()),
            ]),
        }),
        None,
        None,
        Arc::new(resolver),
        4,
        Duration::from_secs(15),
    )
    .await
    .unwrap();
    orchestrator
        .register(Arc::clone(&bridge_web_adapter) as Arc<dyn ConnectionAdapter>)
        .unwrap();
    orchestrator
        .register(Arc::clone(&bridge_sip_adapter) as Arc<dyn ConnectionAdapter>)
        .unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_web_address = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let bridge_web_listener = {
        let adapter = Arc::clone(&bridge_web_adapter);
        let auth: Arc<dyn WsAuthHook> = Arc::new(AttachmentAuth {
            principal: principal().authenticated().clone(),
        });
        tokio::spawn(async move {
            serve_tls_listener_with_auth_and_shutdown(listener, web_tls, adapter, auth, async {
                let _ = shutdown_rx.await;
            })
            .await
        })
    };

    let mut assistant =
        sip_destination_fixture("vapi-like-assistant", &sip_tls, vec![0, 101]).await;
    let mut call_center = sip_destination_fixture_with_auth(
        "named-call-center",
        &sip_tls,
        vec![0, 101],
        CALL_CENTER_PROFILE_ID,
        CALL_CENTER_DIGEST_REALM,
        CALL_CENTER_DIGEST_USER,
        CALL_CENTER_DIGEST_PASSWORD,
    )
    .await;
    let mut mismatched_profile = sip_destination_fixture_with_auth(
        "mismatched-call-center-profile",
        &sip_tls,
        vec![0, 101],
        "unavailable-call-center",
        "bridgefu-unavailable-call-center",
        "bridgefu-unavailable",
        "unavailable-profile-password",
    )
    .await;

    successful_direct_sip_handoff(
        &runtime,
        &orchestrator,
        bridge_web_address,
        Arc::clone(&web_trust),
        &mut assistant,
        &mut call_center,
    )
    .await;
    rejected_direct_sip_handoff_resumes_assistant(
        &runtime,
        &orchestrator,
        bridge_web_address,
        Arc::clone(&web_trust),
        &mut assistant,
        &mut call_center,
    )
    .await;
    mismatched_replacement_profile_fails_closed(
        &runtime,
        &orchestrator,
        bridge_web_address,
        Arc::clone(&web_trust),
        &mut assistant,
        &mut mismatched_profile,
    )
    .await;
    source_hangup_cancels_pending_direct_sip_handoff(
        &runtime,
        &orchestrator,
        bridge_web_address,
        Arc::clone(&web_trust),
        &mut assistant,
        &mut call_center,
    )
    .await;

    assert!(bridge_web_adapter.routes().is_empty());
    wait_for_orchestrator_idle(&orchestrator).await;

    let _ = shutdown_tx.send(());
    bounded("direct handoff WSS listener shutdown", bridge_web_listener)
        .await
        .unwrap()
        .unwrap();
    bounded(
        "direct handoff supervisor shutdown",
        supervisor.shutdown(Duration::from_secs(5)),
    )
    .await;
    bounded(
        "direct handoff prepared outbound drain",
        orchestrator.drain_prepared_outbound_connections(),
    )
    .await;
    bounded(
        "direct handoff lifecycle drain",
        orchestrator.drain_connection_lifecycle_tasks(),
    )
    .await;
    bounded(
        "direct handoff Bridgefu SIP adapter drain",
        bridge_sip_adapter.drain(),
    )
    .await
    .unwrap();
    bounded("assistant adapter drain", assistant.adapter.drain())
        .await
        .unwrap();
    bounded("call-center adapter drain", call_center.adapter.drain())
        .await
        .unwrap();
    bounded(
        "mismatched-profile adapter drain",
        mismatched_profile.adapter.drain(),
    )
    .await
    .unwrap();
    bounded(
        "direct handoff Bridgefu SIP coordinator shutdown",
        bridge_sip_coordinator.shutdown_gracefully(Some(Duration::from_secs(5))),
    )
    .await
    .unwrap();
    bounded(
        "assistant coordinator shutdown",
        assistant
            .coordinator
            .shutdown_gracefully(Some(Duration::from_secs(5))),
    )
    .await
    .unwrap();
    bounded(
        "call-center coordinator shutdown",
        call_center
            .coordinator
            .shutdown_gracefully(Some(Duration::from_secs(5))),
    )
    .await
    .unwrap();
    bounded(
        "mismatched-profile coordinator shutdown",
        mismatched_profile
            .coordinator
            .shutdown_gracefully(Some(Duration::from_secs(5))),
    )
    .await
    .unwrap();
    assert_eq!(bridge_sip_adapter.retained_task_count(), 0);
    assert_eq!(assistant.adapter.retained_task_count(), 0);
    assert_eq!(call_center.adapter.retained_task_count(), 0);
    assert_eq!(mismatched_profile.adapter.retained_task_count(), 0);
    assert_eq!(orchestrator.connection_lifecycle_task_count(), 0);
    assert!(matches!(
        orchestrator.capacity_report(),
        Event::CapacityReport {
            active_connections: 0,
            active_bridges: 0,
            admission_in_use: 0,
            ..
        }
    ));
    drop(assistant);
    drop(call_center);
    drop(mismatched_profile);
    drop(bridge_web_adapter);
    bounded(
        "direct handoff call runtime shutdown",
        Arc::try_unwrap(runtime)
            .expect("direct handoff runtime owner released")
            .shutdown(Duration::from_secs(5)),
    )
    .await
    .unwrap();
}

async fn establish_direct_assistant_call(
    runtime: &CallServiceRuntime,
    bridge_web_address: std::net::SocketAddr,
    web_trust: Arc<WebRtcTlsClientTrust>,
    assistant: &mut SipDestinationFixture,
    idempotency: &str,
    correlation_id: &str,
) -> LiveBrowserSipCall {
    let coordinator = Arc::clone(&assistant.coordinator);
    let adapter = Arc::clone(&assistant.adapter);
    establish_browser_to_sips_call(
        runtime,
        bridge_web_address,
        web_trust,
        format!(
            "sips:vapi-assistant@localhost:{};transport=tls",
            assistant.tls_address.port()
        ),
        &coordinator,
        &adapter,
        &mut assistant.events,
        &mut assistant.sip_events,
        idempotency,
        correlation_id,
    )
    .await
}

async fn successful_direct_sip_handoff(
    runtime: &CallServiceRuntime,
    orchestrator: &Orchestrator,
    bridge_web_address: std::net::SocketAddr,
    web_trust: Arc<WebRtcTlsClientTrust>,
    assistant: &mut SipDestinationFixture,
    call_center: &mut SipDestinationFixture,
) {
    let mut call = establish_direct_assistant_call(
        runtime,
        bridge_web_address,
        web_trust,
        assistant,
        "direct-handoff-success-call",
        "direct-handoff-success-correlation",
    )
    .await;
    let (source_leg_id, source_generation, source_server_connection) =
        current_inbound_binding(runtime, call.call_id).await;
    let (destination_leg_id, assistant_generation, assistant_server_connection) =
        current_outbound_binding(runtime, call.call_id).await;
    let pending_generation = assistant_generation.next().unwrap();
    let (browser_stream, mut browser_audio, assistant_stream, _assistant_audio) =
        baseline_browser_assistant_media(&call, &assistant.adapter, 192_000).await;

    start_sip_replacement(
        runtime,
        call.call_id,
        destination_leg_id,
        format!(
            "sips:call-center@localhost:{};transport=tls",
            call_center.tls_address.port()
        ),
        "named-call-center",
        "direct-handoff-success-replacement",
    )
    .await;
    wait_for_call(runtime, call.call_id, |stored| {
        stored.call.aggregate.state() == CallState::Transferring
            && stored
                .call
                .aggregate
                .replacement()
                .is_some_and(|replacement| {
                    replacement.pending_binding_generation() == pending_generation
                })
    })
    .await;
    let replacement_connection = next_inbound(&mut call_center.events)
        .await
        .expect("named call center received replacement INVITE");
    let (_, replacement_session) = next_authenticated_sip_session_for_tenant(
        &call_center.coordinator,
        &mut call_center.sip_events,
        CALL_CENTER_PROFILE_ID,
    )
    .await;
    wait_for_active_bridge_count(orchestrator, 0).await;
    assert!(
        assistant
            .adapter
            .is_connection_live(&call.destination_connection),
        "assistant was retired before replacement media was ready"
    );
    assert!(
        call.browser.is_connection_live(&call.browser_connection),
        "browser peer connection changed while replacement was pending"
    );

    send_encoded(
        &assistant_stream,
        bytes::Bytes::from(vec![0xff; 160]),
        0,
        40_000,
        160,
    )
    .await;
    assert_no_audio(
        &mut browser_audio,
        "held assistant leaked into the browser during make-before-break",
    )
    .await;

    bounded(
        "named call-center replacement accept",
        call_center.adapter.accept(replacement_connection.clone()),
    )
    .await
    .unwrap();
    let active = wait_for_call(runtime, call.call_id, |stored| {
        stored.call.aggregate.state() == CallState::Active
            && stored.call.aggregate.replacement().is_none()
            && stored
                .call
                .bindings
                .get(&destination_leg_id)
                .is_some_and(|binding| binding.binding_generation == pending_generation)
    })
    .await;
    wait_for_active_bridge_count(orchestrator, 1).await;
    let security = replacement_session
        .wait_for_media_security(Some(Duration::from_secs(5)))
        .await
        .expect("replacement installed mandatory SRTP contexts");
    assert!(security.contexts_installed);
    assert_eq!(security.profile, MediaSecurityProfile::RtpSavp);
    let statuses = handoff_statuses_until(
        &mut call.browser_events,
        &call.browser_connection,
        HandoffStatusKind::Connected,
    )
    .await;
    assert_handoff_statuses(
        &statuses,
        call.call_id,
        destination_leg_id,
        pending_generation,
        &[
            HandoffStatusKind::Preparing,
            HandoffStatusKind::Ringing,
            HandoffStatusKind::Attaching,
            HandoffStatusKind::Connected,
        ],
    );
    assert_ne!(
        active.call.bindings[&destination_leg_id].connection_id,
        assistant_server_connection
    );
    wait_connection_dead(assistant.adapter.as_ref(), &call.destination_connection).await;
    assert!(call.browser.is_connection_live(&call.browser_connection));
    assert_eq!(
        active.call.bindings[&source_leg_id].connection_id, source_server_connection,
        "browser source binding changed during handoff"
    );
    assert_eq!(
        active.call.bindings[&source_leg_id].binding_generation,
        source_generation
    );

    let call_center_stream =
        audio_stream(call_center.adapter.as_ref(), &replacement_connection).await;
    let mut call_center_audio = call_center_stream.try_frames_in().unwrap();
    send_opus(&browser_stream, 288_000).await;
    let at_call_center = tokio::time::timeout(Duration::from_secs(10), call_center_audio.recv())
        .await
        .expect("browser-to-call-center media deadline")
        .expect("call-center media route remained live");
    assert_eq!(at_call_center.payload_type, Some(0));
    send_encoded(
        &call_center_stream,
        bytes::Bytes::from(vec![0xff; 160]),
        0,
        48_000,
        160,
    )
    .await;
    let at_browser = tokio::time::timeout(Duration::from_secs(10), browser_audio.recv())
        .await
        .expect("call-center-to-browser media deadline")
        .expect("browser media route remained stable");
    assert_eq!(at_browser.payload_type, Some(111));
    drain_audio_until_quiet(&mut browser_audio).await;
    let _ = assistant_stream
        .frames_out()
        .send(MediaFrame {
            stream_id: assistant_stream.id(),
            kind: StreamKind::Audio,
            payload: bytes::Bytes::from(vec![0xff; 160]),
            timestamp_rtp: 56_000,
            captured_at: Utc::now(),
            payload_type: Some(0),
        })
        .await;
    assert_no_audio(
        &mut browser_audio,
        "retired assistant leaked into the promoted browser route",
    )
    .await;

    bounded(
        "successful handoff browser hangup",
        call.browser
            .end(call.browser_connection.clone(), EndReason::Normal),
    )
    .await
    .unwrap();
    wait_for_call(runtime, call.call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    wait_connection_dead(call_center.adapter.as_ref(), &replacement_connection).await;
    wait_for_orchestrator_idle(orchestrator).await;
    assert!(call.browser.routes().is_empty());
}

async fn rejected_direct_sip_handoff_resumes_assistant(
    runtime: &CallServiceRuntime,
    orchestrator: &Orchestrator,
    bridge_web_address: std::net::SocketAddr,
    web_trust: Arc<WebRtcTlsClientTrust>,
    assistant: &mut SipDestinationFixture,
    call_center: &mut SipDestinationFixture,
) {
    let mut call = establish_direct_assistant_call(
        runtime,
        bridge_web_address,
        web_trust,
        assistant,
        "direct-handoff-rejected-call",
        "direct-handoff-rejected-correlation",
    )
    .await;
    let (source_leg_id, source_generation, source_server_connection) =
        current_inbound_binding(runtime, call.call_id).await;
    let (destination_leg_id, assistant_generation, assistant_server_connection) =
        current_outbound_binding(runtime, call.call_id).await;
    let pending_generation = assistant_generation.next().unwrap();
    let (browser_stream, mut browser_audio, assistant_stream, mut assistant_audio) =
        baseline_browser_assistant_media(&call, &assistant.adapter, 384_000).await;

    start_sip_replacement(
        runtime,
        call.call_id,
        destination_leg_id,
        format!(
            "sips:busy-call-center@localhost:{};transport=tls",
            call_center.tls_address.port()
        ),
        "busy-call-center",
        "direct-handoff-rejected-replacement",
    )
    .await;
    let replacement_connection = next_inbound(&mut call_center.events)
        .await
        .expect("rejecting call center received replacement INVITE");
    let _ = next_authenticated_sip_session_for_tenant(
        &call_center.coordinator,
        &mut call_center.sip_events,
        CALL_CENTER_PROFILE_ID,
    )
    .await;
    wait_for_active_bridge_count(orchestrator, 0).await;
    assert!(assistant
        .adapter
        .is_connection_live(&call.destination_connection));
    bounded(
        "call-center replacement rejection",
        call_center
            .adapter
            .reject(replacement_connection.clone(), RejectReason::Decline),
    )
    .await
    .unwrap();
    let resumed = wait_for_call(runtime, call.call_id, |stored| {
        stored.call.aggregate.state() == CallState::Active
            && stored.call.aggregate.replacement().is_none()
            && stored
                .call
                .bindings
                .get(&destination_leg_id)
                .is_some_and(|binding| {
                    binding.binding_generation == assistant_generation
                        && binding.connection_id == assistant_server_connection
                })
    })
    .await;
    wait_for_active_bridge_count(orchestrator, 1).await;
    let statuses = handoff_statuses_until(
        &mut call.browser_events,
        &call.browser_connection,
        HandoffStatusKind::Resumed,
    )
    .await;
    assert_handoff_statuses(
        &statuses,
        call.call_id,
        destination_leg_id,
        pending_generation,
        &[
            HandoffStatusKind::Preparing,
            HandoffStatusKind::Ringing,
            HandoffStatusKind::Attaching,
            HandoffStatusKind::Resumed,
        ],
    );
    assert_eq!(
        resumed.call.bindings[&destination_leg_id].connection_id,
        assistant_server_connection
    );
    assert_eq!(
        current_inbound_binding(runtime, call.call_id).await,
        (source_leg_id, source_generation, source_server_connection)
    );
    assert!(call.browser.is_connection_live(&call.browser_connection));
    wait_connection_dead(call_center.adapter.as_ref(), &replacement_connection).await;

    send_opus(&browser_stream, 480_000).await;
    let at_assistant = tokio::time::timeout(Duration::from_secs(10), assistant_audio.recv())
        .await
        .expect("resumed browser-to-assistant audio deadline")
        .expect("resumed assistant route remained live");
    assert_eq!(at_assistant.payload_type, Some(0));
    send_encoded(
        &assistant_stream,
        bytes::Bytes::from(vec![0xff; 160]),
        0,
        80_000,
        160,
    )
    .await;
    let at_browser = tokio::time::timeout(Duration::from_secs(10), browser_audio.recv())
        .await
        .expect("resumed assistant-to-browser audio deadline")
        .expect("stable browser route remained live");
    assert_eq!(at_browser.payload_type, Some(111));

    bounded(
        "rejected handoff browser hangup",
        call.browser
            .end(call.browser_connection.clone(), EndReason::Normal),
    )
    .await
    .unwrap();
    wait_for_call(runtime, call.call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    wait_connection_dead(assistant.adapter.as_ref(), &call.destination_connection).await;
    wait_for_orchestrator_idle(orchestrator).await;
    assert!(call.browser.routes().is_empty());
}

async fn mismatched_replacement_profile_fails_closed(
    runtime: &CallServiceRuntime,
    orchestrator: &Orchestrator,
    bridge_web_address: std::net::SocketAddr,
    web_trust: Arc<WebRtcTlsClientTrust>,
    assistant: &mut SipDestinationFixture,
    mismatched_profile: &mut SipDestinationFixture,
) {
    let mut call = establish_direct_assistant_call(
        runtime,
        bridge_web_address,
        web_trust,
        assistant,
        "direct-handoff-profile-mismatch-call",
        "direct-handoff-profile-mismatch-correlation",
    )
    .await;
    let (destination_leg_id, assistant_generation, assistant_server_connection) =
        current_outbound_binding(runtime, call.call_id).await;
    let pending_generation = assistant_generation.next().unwrap();
    let selected_route = NamedRouteBinding::new_with_profiles(
        "unavailable-call-center",
        None,
        vec![NamedProfileBinding::new(
            NamedProfileRole::Destination,
            NamedProfileKind::Sip,
            "unavailable-call-center",
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        )
        .unwrap()],
    )
    .unwrap();
    start_sip_replacement_with_route(
        runtime,
        call.call_id,
        destination_leg_id,
        format!(
            "sips:unavailable-call-center@localhost:{};transport=tls",
            mismatched_profile.tls_address.port()
        ),
        selected_route,
        "direct-handoff-profile-mismatch-replacement",
    )
    .await;
    let statuses = handoff_statuses_until(
        &mut call.browser_events,
        &call.browser_connection,
        HandoffStatusKind::Resumed,
    )
    .await;
    assert_eq!(statuses.last().unwrap().status, HandoffStatusKind::Resumed);
    assert!(
        statuses
            .iter()
            .all(|status| status.status != HandoffStatusKind::Connected),
        "a route whose selected profile revision is unavailable must not silently connect"
    );
    assert_handoff_statuses(
        &statuses,
        call.call_id,
        destination_leg_id,
        pending_generation,
        &[HandoffStatusKind::Preparing, HandoffStatusKind::Resumed],
    );
    assert!(
        matches!(
            mismatched_profile.events.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ),
        "an unavailable selected profile revision contacted the destination"
    );
    let resumed = wait_for_call(runtime, call.call_id, |stored| {
        stored.call.aggregate.state() == CallState::Active
            && stored.call.aggregate.replacement().is_none()
            && stored
                .call
                .bindings
                .get(&destination_leg_id)
                .is_some_and(|binding| {
                    binding.binding_generation == assistant_generation
                        && binding.connection_id == assistant_server_connection
                })
    })
    .await;
    assert_eq!(
        resumed.call.bindings[&destination_leg_id].connection_id,
        assistant_server_connection
    );
    assert!(assistant
        .adapter
        .is_connection_live(&call.destination_connection));
    wait_for_active_bridge_count(orchestrator, 1).await;

    bounded(
        "profile-mismatch browser hangup",
        call.browser
            .end(call.browser_connection.clone(), EndReason::Normal),
    )
    .await
    .unwrap();
    wait_for_call(runtime, call.call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    wait_connection_dead(assistant.adapter.as_ref(), &call.destination_connection).await;
    wait_for_orchestrator_idle(orchestrator).await;
    assert!(call.browser.routes().is_empty());
}

async fn source_hangup_cancels_pending_direct_sip_handoff(
    runtime: &CallServiceRuntime,
    orchestrator: &Orchestrator,
    bridge_web_address: std::net::SocketAddr,
    web_trust: Arc<WebRtcTlsClientTrust>,
    assistant: &mut SipDestinationFixture,
    call_center: &mut SipDestinationFixture,
) {
    let call = establish_direct_assistant_call(
        runtime,
        bridge_web_address,
        web_trust,
        assistant,
        "direct-handoff-source-cancel-call",
        "direct-handoff-source-cancel-correlation",
    )
    .await;
    let (destination_leg_id, _assistant_generation, _assistant_server_connection) =
        current_outbound_binding(runtime, call.call_id).await;
    start_sip_replacement(
        runtime,
        call.call_id,
        destination_leg_id,
        format!(
            "sips:pending-call-center@localhost:{};transport=tls",
            call_center.tls_address.port()
        ),
        "pending-call-center",
        "direct-handoff-source-cancel-replacement",
    )
    .await;
    let replacement_connection = next_inbound(&mut call_center.events)
        .await
        .expect("pending call center received replacement INVITE");
    let _ = next_authenticated_sip_session_for_tenant(
        &call_center.coordinator,
        &mut call_center.sip_events,
        CALL_CENTER_PROFILE_ID,
    )
    .await;
    wait_for_active_bridge_count(orchestrator, 0).await;
    assert!(assistant
        .adapter
        .is_connection_live(&call.destination_connection));
    assert!(call_center
        .adapter
        .is_connection_live(&replacement_connection));

    bounded(
        "browser hangup while replacement pending",
        call.browser
            .end(call.browser_connection.clone(), EndReason::Normal),
    )
    .await
    .unwrap();
    wait_for_call(runtime, call.call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    wait_connection_dead(assistant.adapter.as_ref(), &call.destination_connection).await;
    wait_connection_dead(call_center.adapter.as_ref(), &replacement_connection).await;
    wait_connection_dead(call.browser.as_ref(), &call.browser_connection).await;
    wait_for_orchestrator_idle(orchestrator).await;
    assert!(call.browser.routes().is_empty());
}

#[derive(Clone, Copy)]
enum DirectWssHandoffMode {
    AdapterFixture,
    ChromiumSdk(crate::browser_sdk::BrowserTerminalSide),
}

#[test]
fn direct_browser_vapi_sip_to_generic_wss_handoff_is_connected_gated_and_resumable() {
    let _serial = QUALIFICATION_TEST_LOCK.lock().unwrap();
    std::thread::Builder::new()
        .name("direct-browser-vapi-sip-to-wss-handoff-qualification".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(6)
                .thread_stack_size(8 * 1024 * 1024)
                .enable_all()
                .build()
                .unwrap()
                .block_on(Box::pin(
                    run_direct_browser_vapi_sip_to_generic_wss_handoff(
                        DirectWssHandoffMode::AdapterFixture,
                    ),
                ));
        })
        .unwrap()
        .join()
        .expect("direct browser to generic WSS handoff qualification panicked");
}

#[test]
#[ignore = "requires the pinned StandardCharter Playwright Chromium; run explicitly with --ignored"]
fn built_typescript_sdk_hands_off_to_generic_wss_and_cleans_both_terminal_directions() {
    let _serial = QUALIFICATION_TEST_LOCK.lock().unwrap();
    std::thread::Builder::new()
        .name("chromium-vapi-assistant-generic-wss-handoff".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(6)
                .thread_stack_size(8 * 1024 * 1024)
                .enable_all()
                .build()
                .unwrap()
                .block_on(Box::pin(async {
                    run_direct_browser_vapi_sip_to_generic_wss_handoff(
                        DirectWssHandoffMode::ChromiumSdk(
                            crate::browser_sdk::BrowserTerminalSide::Browser,
                        ),
                    )
                    .await;
                    run_direct_browser_vapi_sip_to_generic_wss_handoff(
                        DirectWssHandoffMode::ChromiumSdk(
                            crate::browser_sdk::BrowserTerminalSide::Destination,
                        ),
                    )
                    .await;
                }));
        })
        .unwrap()
        .join()
        .expect("actual Chromium generic WSS qualification panicked");
}

async fn run_direct_browser_vapi_sip_to_generic_wss_handoff(mode: DirectWssHandoffMode) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let web_certificate = generated.cert.pem().into_bytes();
    let web_private_key = generated.signing_key.serialize_pem().into_bytes();
    let web_tls = TlsConfig::from_pem_bytes(&web_certificate, &web_private_key)
        .await
        .unwrap();
    let web_trust = Arc::new(WebRtcTlsClientTrust::from_pem(&web_certificate).unwrap());
    let web_trust_path = std::env::temp_dir().join(format!(
        "bridgefu-direct-wss-handoff-{}.pem",
        uuid::Uuid::new_v4()
    ));
    std::fs::write(&web_trust_path, &web_certificate).unwrap();
    let sip_tls = TestTlsFiles::create();

    let destination_auth = Arc::new(DestinationAuth {
        calls: AtomicUsize::new(0),
    });
    let mut destination_config = WebRtcConfig::loopback();
    destination_config.trickle_ice = true;
    destination_config.max_concurrent_sessions = 4;
    let destination_server = WebRtcServerBuilder::new(destination_config)
        .with_wss("127.0.0.1:0", web_tls.clone())
        .with_ws_auth(Arc::clone(&destination_auth) as Arc<dyn WsAuthHook>)
        .build()
        .await
        .unwrap();
    let destination_address = destination_server.wss_addr().unwrap();
    let destination_endpoint = format!("wss://localhost:{}/signal", destination_address.port());
    let destination_adapter = destination_server.adapter();
    let mut destination_events = destination_adapter.subscribe_events();

    let runtime = call_runtime().await;
    let orchestrator = Orchestrator::new(CoreConfig::default());
    let mut bridge_web_config = WebRtcConfig::loopback();
    bridge_web_config.max_concurrent_sessions = 6;
    bridge_web_config.trickle_ice = true;
    let bridge_web_inner = WebRtcAdapter::new_with_inbound_admission_confirmation(
        bridge_web_config,
        Duration::from_secs(10),
    )
    .unwrap();
    let bridge_web_adapter = LoopbackFixtureWebRtcAdapter::new(Arc::clone(&bridge_web_inner));

    let bridge_sip_udp = reserve_udp();
    let bridge_sip_tls = reserve_tcp();
    let bridge_sip_config = tls_sip_config(
        "bridgefu-direct-wss-handoff-egress",
        bridge_sip_udp,
        bridge_sip_tls,
        &sip_tls,
        vec![0, 101],
    );
    assert!(bridge_sip_config.srtp_required);
    let bridge_sip_policy = SipListenerAuthPolicy::enabled_for_tenant("generic-wss-tenant")
        .unwrap()
        .with_trusted_cidr(
            "127.0.0.1/32".parse().unwrap(),
            principal().authenticated().clone(),
        );
    let bridge_sip_coordinator =
        rvoip_sip::UnifiedCoordinator::new_with_listener_auth(bridge_sip_config, bridge_sip_policy)
            .await
            .unwrap();
    let bridge_sip_adapter = SipAdapter::new(Arc::clone(&bridge_sip_coordinator))
        .await
        .unwrap();

    let mut resolver = StaticOutboundProfileResolver::default();
    resolver.insert_sip(
        SIP_PROFILE_ID.into(),
        SIP_PROFILE_REVISION.into(),
        ConfiguredSipOutboundProfile {
            from_uri: format!(
                "sips:bridgefu-browser@localhost:{};transport=tls",
                bridge_sip_tls.port()
            ),
            outbound_proxy: None,
            auth: Some(ConfiguredSipProfileAuth::Digest {
                realm: Some(SIP_DIGEST_REALM.into()),
                username: SIP_DIGEST_USER.into(),
                password: SecretRef::new(SIP_DIGEST_PASSWORD),
            }),
        },
    );
    resolver.insert_webrtc(
        "generic-agent".into(),
        PROFILE_REVISION.into(),
        ConfiguredWebRtcOutboundProfile {
            bearer_token: Some(SecretRef::new(DESTINATION_BEARER)),
            tls_roots: vec![web_trust_path.to_string_lossy().into_owned()],
            ice_servers: Vec::new(),
            audio_codecs: vec![
                rvoip_webrtc::WebRtcAudioCodec::Opus,
                rvoip_webrtc::WebRtcAudioCodec::Pcmu,
                rvoip_webrtc::WebRtcAudioCodec::Pcma,
            ],
            data_channels: true,
        },
    );
    let supervisor = CallExecutionSupervisor::install_with_leg_executors_context_canary_broadcast_and_outbound_profiles(
        Arc::clone(&orchestrator),
        Arc::clone(&runtime),
        Arc::new(DisabledProviderLegExecutor),
        None,
        Arc::new(ContextPolicy {
            allow_headers: BTreeMap::from([
                ("X-Correlation-Id".into(), "correlation_id".into()),
                ("X-Account-Tier".into(), "account_tier".into()),
            ]),
        }),
        None,
        None,
        Arc::new(resolver),
        4,
        Duration::from_secs(15),
    )
    .await
    .unwrap();
    orchestrator
        .register(Arc::clone(&bridge_web_adapter) as Arc<dyn ConnectionAdapter>)
        .unwrap();
    orchestrator
        .register(Arc::clone(&bridge_sip_adapter) as Arc<dyn ConnectionAdapter>)
        .unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_web_address = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let bridge_web_listener = {
        let adapter = Arc::clone(&bridge_web_inner);
        let auth: Arc<dyn WsAuthHook> = Arc::new(AttachmentAuth {
            principal: principal().authenticated().clone(),
        });
        tokio::spawn(async move {
            serve_tls_listener_with_auth_and_shutdown(listener, web_tls, adapter, auth, async {
                let _ = shutdown_rx.await;
            })
            .await
        })
    };

    let mut assistant =
        sip_destination_fixture("vapi-like-assistant-to-generic-wss", &sip_tls, vec![0, 101]).await;

    match mode {
        DirectWssHandoffMode::AdapterFixture => {
            successful_direct_wss_handoff(
                &runtime,
                &orchestrator,
                bridge_web_address,
                Arc::clone(&web_trust),
                &mut assistant,
                destination_endpoint.clone(),
                &destination_adapter,
                &mut destination_events,
            )
            .await;
            rejected_direct_wss_handoff_resumes_assistant(
                &runtime,
                &orchestrator,
                bridge_web_address,
                Arc::clone(&web_trust),
                &mut assistant,
                destination_endpoint,
                &destination_adapter,
                &mut destination_events,
            )
            .await;
        }
        DirectWssHandoffMode::ChromiumSdk(terminal_side) => {
            actual_chromium_wss_handoff(
                &runtime,
                &orchestrator,
                bridge_web_address,
                &mut assistant,
                destination_endpoint,
                &destination_adapter,
                &mut destination_events,
                terminal_side,
            )
            .await;
        }
    }
    let observed = bridge_web_adapter.last_observed();
    assert!(observed.bearer_present, "named WSS profile omitted bearer");
    assert!(
        observed.tls_trust_present,
        "named WSS profile omitted TLS roots"
    );
    assert!(observed.ice_urls.is_empty());
    assert_eq!(destination_auth.calls.load(Ordering::Acquire), 2);

    assert!(bridge_web_inner.routes().is_empty());
    assert!(destination_adapter.routes().is_empty());
    wait_for_orchestrator_idle(&orchestrator).await;

    let _ = shutdown_tx.send(());
    bounded(
        "direct WSS handoff ingress listener shutdown",
        bridge_web_listener,
    )
    .await
    .unwrap()
    .unwrap();
    bounded(
        "direct WSS handoff destination shutdown",
        destination_server.shutdown(),
    )
    .await;
    bounded(
        "direct WSS handoff supervisor shutdown",
        supervisor.shutdown(Duration::from_secs(5)),
    )
    .await;
    bounded(
        "direct WSS handoff prepared outbound drain",
        orchestrator.drain_prepared_outbound_connections(),
    )
    .await;
    bounded(
        "direct WSS handoff lifecycle drain",
        orchestrator.drain_connection_lifecycle_tasks(),
    )
    .await;
    bounded(
        "direct WSS handoff Bridgefu SIP adapter drain",
        bridge_sip_adapter.drain(),
    )
    .await
    .unwrap();
    bounded(
        "direct WSS handoff assistant drain",
        assistant.adapter.drain(),
    )
    .await
    .unwrap();
    bounded(
        "direct WSS handoff Bridgefu SIP coordinator shutdown",
        bridge_sip_coordinator.shutdown_gracefully(Some(Duration::from_secs(5))),
    )
    .await
    .unwrap();
    bounded(
        "direct WSS handoff assistant coordinator shutdown",
        assistant
            .coordinator
            .shutdown_gracefully(Some(Duration::from_secs(5))),
    )
    .await
    .unwrap();
    assert_eq!(bridge_sip_adapter.retained_task_count(), 0);
    assert_eq!(assistant.adapter.retained_task_count(), 0);
    assert_eq!(orchestrator.connection_lifecycle_task_count(), 0);
    assert!(matches!(
        orchestrator.capacity_report(),
        Event::CapacityReport {
            active_connections: 0,
            active_bridges: 0,
            admission_in_use: 0,
            ..
        }
    ));
    std::fs::remove_file(&web_trust_path).unwrap();
    drop(assistant);
    drop(bridge_web_adapter);
    drop(bridge_web_inner);
    bounded(
        "direct WSS handoff call runtime shutdown",
        Arc::try_unwrap(runtime)
            .expect("direct WSS handoff runtime owner released")
            .shutdown(Duration::from_secs(5)),
    )
    .await
    .unwrap();
}

struct ChromiumWssAssistantCall {
    call_id: CallId,
    source_leg_id: LegId,
    destination_leg_id: LegId,
    source_generation: BindingGeneration,
    source_connection: ConnectionId,
    assistant_generation: BindingGeneration,
    assistant_server_connection: ConnectionId,
    assistant_connection: ConnectionId,
    browser: crate::browser_sdk::BrowserSdkController,
}

async fn establish_chromium_wss_assistant_call(
    runtime: &CallServiceRuntime,
    orchestrator: &Orchestrator,
    bridge_web_address: std::net::SocketAddr,
    assistant: &mut SipDestinationFixture,
    terminal_side: crate::browser_sdk::BrowserTerminalSide,
) -> ChromiumWssAssistantCall {
    let correlation_id = "chromium-generic-wss-initial-context";
    let created = runtime
        .service()
        .create_named_route_call(
            &principal(),
            &IdempotencyKey::parse("chromium-generic-wss-assistant-call").unwrap(),
            browser_to_sip_route_input(format!(
                "sips:vapi-assistant@localhost:{};transport=tls",
                assistant.tls_address.port()
            )),
            browser_to_sip_route_binding(),
        )
        .await
        .unwrap();
    let call_id = created.value.call.call_id;
    let source = created
        .value
        .call
        .legs
        .iter()
        .find(|leg| leg.direction == LegDirection::Inbound)
        .unwrap();
    let source_leg_id = source.leg_id;
    let destination_leg_id = created
        .value
        .call
        .legs
        .iter()
        .find(|leg| leg.direction == LegDirection::Outbound)
        .unwrap()
        .leg_id;
    let attachment = source.attachment.as_ref().unwrap();
    let mut scenario = crate::browser_sdk::BrowserScenario::handoff(
        "generic-wss",
        correlation_id,
        crate::browser_sdk::BrowserDestinationBoundary::AuthenticatedGenericWss,
        crate::browser_sdk::BrowserContextSemantics::LiveDataChannel,
        crate::browser_sdk::BrowserDtmfSemantics::BidirectionalMediaPlane,
    )
    .with_terminal_side(terminal_side)
    .with_remote_context("generic-wss-agent-context");
    scenario
        .initial_metadata
        .insert("account_tier".into(), "gold".into());
    scenario = scenario.with_remote_message(crate::browser_sdk::ExpectedBrowserMessage {
        label: "generic-wss.to.chromium.v1".into(),
        content_type: "application/json".into(),
        bytes: br#"{"agent":"connected"}"#.to_vec(),
    });
    let browser =
        crate::browser_sdk::BrowserSdkController::launch(crate::browser_sdk::attachment_fixture(
            format!("wss://localhost:{}/signal", bridge_web_address.port()),
            attachment.token.clone(),
            attachment.expires_at.to_rfc3339(),
            "generic-wss-tenant",
            call_id.to_string(),
            source_leg_id.to_string(),
            scenario,
        ))
        .await;

    let assistant_connection = next_inbound(&mut assistant.events)
        .await
        .expect("Chromium initial context released the Vapi-like assistant");
    let inbound = assistant
        .adapter
        .take_inbound_context(&assistant_connection)
        .expect("assistant retained sanitized Chromium context");
    assert_eq!(
        inbound
            .metadata()
            .values("X-Correlation-Id")
            .collect::<Vec<_>>(),
        [correlation_id]
    );
    assert_eq!(
        inbound
            .metadata()
            .values("X-Account-Tier")
            .collect::<Vec<_>>(),
        ["gold"]
    );
    assert!(inbound
        .metadata()
        .values("X-Unmapped-Private")
        .next()
        .is_none());
    let (_, session) = next_authenticated_sip_session_for_tenant(
        &assistant.coordinator,
        &mut assistant.sip_events,
        SIP_PROFILE_ID,
    )
    .await;
    assistant
        .adapter
        .accept(assistant_connection.clone())
        .await
        .unwrap();
    wait_for_call(runtime, call_id, |stored| {
        stored.call.aggregate.state() == CallState::Active
    })
    .await;
    let security = session
        .wait_for_media_security(Some(Duration::from_secs(5)))
        .await
        .unwrap();
    assert!(security.contexts_installed);
    assert_eq!(security.profile, MediaSecurityProfile::RtpSavp);
    let (_, source_generation, source_connection) = current_inbound_binding(runtime, call_id).await;
    let (_, assistant_generation, assistant_server_connection) =
        current_outbound_binding(runtime, call_id).await;
    // `CallState::Active` records that both logical legs connected. The
    // bridge/data-route outbox effect is a subsequent durable operation, so
    // do not release browser controls until that exact route is installed.
    wait_for_active_bridge_count(orchestrator, 1).await;
    browser.mark_initial_destination_ready();

    ChromiumWssAssistantCall {
        call_id,
        source_leg_id,
        destination_leg_id,
        source_generation,
        source_connection,
        assistant_generation,
        assistant_server_connection,
        assistant_connection,
        browser,
    }
}

// The pre-handoff Vapi-like assistant is a SIP leg. This topology requires its
// initial INVITE context and RFC 4733, not live SIP MESSAGE delivery. Arbitrary
// DataChannel and live context behavior are asserted against the WSS call
// center after promotion below.
async fn wait_for_chromium_wss_assistant_dtmf(
    events: &mut mpsc::Receiver<AdapterEvent>,
    connection_id: &ConnectionId,
    browser: &crate::browser_sdk::BrowserSdkController,
) {
    let mut saw_dtmf = false;
    let mut observed = Vec::new();
    let result = tokio::time::timeout(Duration::from_secs(20), async {
        while !saw_dtmf {
            let event = events
                .recv()
                .await
                .expect("assistant events ended before Chromium controls");
            if observed.len() < 32 {
                observed.push(match &event {
                    AdapterEvent::DataMessage {
                        connection_id: observed,
                        message,
                    } => format!("data:{observed}:{}", message.label),
                    AdapterEvent::Dtmf {
                        connection_id: observed,
                        digits,
                        ..
                    } => format!("dtmf:{observed}:{digits}"),
                    AdapterEvent::Connected { connection_id } => {
                        format!("connected:{connection_id}")
                    }
                    AdapterEvent::Ended { connection_id, .. } => {
                        format!("ended:{connection_id}")
                    }
                    _ => "other".into(),
                });
            }
            match event {
                AdapterEvent::Dtmf {
                    connection_id: observed,
                    digits,
                    ..
                } if &observed == connection_id && digits == "6" => saw_dtmf = true,
                _ => {}
            }
        }
    })
    .await;
    assert!(
        result.is_ok(),
        "Chromium WSS assistant DTMF deadline: dtmf={saw_dtmf}, observed={observed:?}, diagnostics={:?}, phases={:?}",
        browser.diagnostics(),
        browser.phases()
    );
}

#[allow(clippy::too_many_arguments)]
async fn actual_chromium_wss_handoff(
    runtime: &CallServiceRuntime,
    orchestrator: &Orchestrator,
    bridge_web_address: std::net::SocketAddr,
    assistant: &mut SipDestinationFixture,
    destination_endpoint: String,
    destination_adapter: &Arc<WebRtcAdapter>,
    destination_events: &mut mpsc::Receiver<AdapterEvent>,
    terminal_side: crate::browser_sdk::BrowserTerminalSide,
) {
    let call = establish_chromium_wss_assistant_call(
        runtime,
        orchestrator,
        bridge_web_address,
        assistant,
        terminal_side,
    )
    .await;
    let assistant_stream =
        audio_stream(assistant.adapter.as_ref(), &call.assistant_connection).await;
    let mut assistant_audio = assistant_stream.try_frames_in().unwrap();
    let initial_media = tokio::spawn({
        let stream = Arc::clone(&assistant_stream);
        async move {
            send_encoded(
                &stream,
                bytes::Bytes::from(vec![0xff; 160]),
                0,
                208_000,
                160,
            )
            .await;
        }
    });
    assert_eq!(
        bounded("Chromium-to-WSS-assistant audio", assistant_audio.recv())
            .await
            .expect("assistant microphone route remained live")
            .payload_type,
        Some(0)
    );
    call.browser.wait_for_phase("assistant-ready").await;
    initial_media.await.unwrap();
    wait_for_chromium_wss_assistant_dtmf(
        &mut assistant.events,
        &call.assistant_connection,
        &call.browser,
    )
    .await;

    let rejected_generation = call.assistant_generation.next().unwrap();
    start_webrtc_replacement(
        runtime,
        call.call_id,
        call.destination_leg_id,
        destination_endpoint.clone(),
        "busy-generic-wss-call-center",
        "chromium-generic-wss-rejected-replacement",
    )
    .await;
    let rejected_connection = next_inbound(destination_events)
        .await
        .expect("rejecting WSS destination received Chromium handoff");
    wait_for_active_bridge_count(orchestrator, 0).await;
    call.browser.wait_for_phase("reject-hold-ready").await;
    drain_audio_until_quiet(&mut assistant_audio).await;
    send_encoded(
        &assistant_stream,
        bytes::Bytes::from(vec![0xff; 160]),
        0,
        224_000,
        160,
    )
    .await;
    assert_no_audio(
        &mut assistant_audio,
        "Chromium audio leaked into held assistant during rejected WSS handoff",
    )
    .await;
    destination_adapter
        .reject(rejected_connection.clone(), RejectReason::Decline)
        .await
        .unwrap();
    call.browser.wait_for_phase("reject-resumed").await;
    wait_for_active_bridge_count(orchestrator, 1).await;
    wait_connection_dead(destination_adapter.as_ref(), &rejected_connection).await;
    send_encoded(
        &assistant_stream,
        bytes::Bytes::from(vec![0xff; 160]),
        0,
        240_000,
        160,
    )
    .await;
    call.browser.wait_for_phase("reject-resume-audio").await;

    let successful_generation = rejected_generation.next().unwrap();
    start_webrtc_replacement(
        runtime,
        call.call_id,
        call.destination_leg_id,
        destination_endpoint,
        "named-generic-wss-call-center",
        "chromium-generic-wss-successful-replacement",
    )
    .await;
    let successful_connection = next_inbound(destination_events)
        .await
        .expect("successful WSS destination received Chromium handoff");
    wait_for_active_bridge_count(orchestrator, 0).await;
    call.browser.wait_for_phase("success-hold-ready").await;
    drain_audio_until_quiet(&mut assistant_audio).await;
    send_encoded(
        &assistant_stream,
        bytes::Bytes::from(vec![0xff; 160]),
        0,
        256_000,
        160,
    )
    .await;
    assert_no_audio(
        &mut assistant_audio,
        "Chromium audio leaked into held assistant during successful WSS handoff",
    )
    .await;
    destination_adapter
        .accept(successful_connection.clone())
        .await
        .expect("authenticated WSS destination became application-ready");
    let active = wait_for_call(runtime, call.call_id, |stored| {
        stored.call.aggregate.state() == CallState::Active
            && stored.call.aggregate.replacement().is_none()
            && stored
                .call
                .bindings
                .get(&call.destination_leg_id)
                .is_some_and(|binding| binding.binding_generation == successful_generation)
    })
    .await;
    call.browser.wait_for_phase("success-connected").await;
    assert_eq!(
        active.call.bindings[&call.source_leg_id].binding_generation,
        call.source_generation
    );
    assert_eq!(
        active.call.bindings[&call.source_leg_id].connection_id,
        call.source_connection
    );
    assert_ne!(
        active.call.bindings[&call.destination_leg_id].connection_id,
        call.assistant_server_connection
    );
    wait_connection_dead(assistant.adapter.as_ref(), &call.assistant_connection).await;

    let destination_stream =
        audio_stream(destination_adapter.as_ref(), &successful_connection).await;
    let mut destination_audio = destination_stream.try_frames_in().unwrap();
    assert_eq!(
        bounded("Chromium-to-generic-WSS audio", destination_audio.recv())
            .await
            .expect("WSS destination media route remained live")
            .payload_type,
        Some(111)
    );
    send_opus(&destination_stream, 1_248_000).await;
    call.browser.wait_for_phase("agent-audio").await;
    call.browser
        .wait_for_phase("destination-actions-sent")
        .await;

    let mut saw_context = false;
    let mut saw_arbitrary = false;
    let mut saw_dtmf = false;
    bounded("Chromium-to-generic-WSS data and DTMF", async {
        while !saw_context || !saw_arbitrary || !saw_dtmf {
            match destination_events
                .recv()
                .await
                .expect("WSS destination events ended before browser actions")
            {
                AdapterEvent::DataMessage {
                    connection_id,
                    message,
                } if connection_id == successful_connection && message.label == CONTEXT_LABEL => {
                    let context = ContextEnvelope::from_data_message(&message).unwrap();
                    if context.correlation_id == "chromium-browser-final-context" {
                        saw_context = true;
                    }
                }
                AdapterEvent::DataMessage {
                    connection_id,
                    message,
                } if connection_id == successful_connection
                    && message.label == "browser.arbitrary.v1" =>
                {
                    assert_eq!(message.content_type, "application/octet-stream");
                    assert_eq!(message.bytes.as_ref(), [7, 0, 255, 42]);
                    saw_arbitrary = true;
                }
                AdapterEvent::Dtmf {
                    connection_id,
                    digits,
                    ..
                } if connection_id == successful_connection && digits == "5" => {
                    saw_dtmf = true;
                }
                _ => {}
            }
        }
    })
    .await;
    call.browser.wait_for_phase("remote-dtmf-ready").await;
    destination_adapter
        .send_dtmf(successful_connection.clone(), "7", 140)
        .await
        .unwrap();
    destination_adapter
        .send_data_message(
            successful_connection.clone(),
            DataMessage::reliable(
                "generic-wss.to.chromium.v1",
                "application/json",
                bytes::Bytes::from_static(br#"{"agent":"connected"}"#),
            ),
        )
        .await
        .unwrap();
    let mut remote_context = ContextEnvelope::new(
        "generic-wss-agent-context",
        "generic-wss-tenant",
        call.call_id.to_string(),
        call.destination_leg_id.to_string(),
    );
    remote_context
        .metadata
        .insert("agent_state".into(), "connected".into());
    destination_adapter
        .send_data_message(
            successful_connection.clone(),
            remote_context.to_data_message().unwrap(),
        )
        .await
        .unwrap();

    let call_id = call.call_id;
    let call_id_string = call_id.to_string();
    let destination_leg_id_string = call.destination_leg_id.to_string();
    call.browser.mark_destination_verified();
    if terminal_side == crate::browser_sdk::BrowserTerminalSide::Destination {
        call.browser
            .wait_for_phase("destination-hangup-ready")
            .await;
        destination_adapter
            .end(successful_connection.clone(), EndReason::Normal)
            .await
            .unwrap();
    }
    let result = call.browser.complete().await;
    crate::browser_sdk::assert_common_handoff_result(
        &result,
        &call_id_string,
        &destination_leg_id_string,
        rejected_generation.value(),
        successful_generation.value(),
        terminal_side,
        crate::browser_sdk::BrowserDestinationBoundary::AuthenticatedGenericWss,
        crate::browser_sdk::BrowserContextSemantics::LiveDataChannel,
        crate::browser_sdk::BrowserDtmfSemantics::BidirectionalMediaPlane,
    );
    assert_eq!(
        result["remoteContext"]["correlation_id"],
        "generic-wss-agent-context"
    );
    assert_eq!(
        result["remoteMessage"]["label"],
        "generic-wss.to.chromium.v1"
    );
    assert_eq!(
        result["remoteMessage"]["bytes"],
        serde_json::json!(br#"{"agent":"connected"}"#.to_vec())
    );

    wait_for_call(runtime, call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    wait_connection_dead(destination_adapter.as_ref(), &successful_connection).await;
    wait_for_orchestrator_idle(orchestrator).await;
}

#[allow(clippy::too_many_arguments)]
async fn successful_direct_wss_handoff(
    runtime: &CallServiceRuntime,
    orchestrator: &Orchestrator,
    bridge_web_address: std::net::SocketAddr,
    web_trust: Arc<WebRtcTlsClientTrust>,
    assistant: &mut SipDestinationFixture,
    destination_endpoint: String,
    destination_adapter: &Arc<WebRtcAdapter>,
    destination_events: &mut mpsc::Receiver<AdapterEvent>,
) {
    let mut call = establish_direct_assistant_call(
        runtime,
        bridge_web_address,
        web_trust,
        assistant,
        "direct-wss-handoff-success-call",
        "direct-wss-handoff-success-correlation",
    )
    .await;
    let (source_leg_id, source_generation, source_server_connection) =
        current_inbound_binding(runtime, call.call_id).await;
    let (destination_leg_id, assistant_generation, assistant_server_connection) =
        current_outbound_binding(runtime, call.call_id).await;
    let pending_generation = assistant_generation.next().unwrap();
    let (browser_stream, mut browser_audio, assistant_stream, mut assistant_audio) =
        baseline_browser_assistant_media(&call, &assistant.adapter, 576_000).await;

    start_webrtc_replacement(
        runtime,
        call.call_id,
        destination_leg_id,
        destination_endpoint,
        "named-generic-wss-call-center",
        "direct-wss-handoff-success-replacement",
    )
    .await;
    wait_for_call(runtime, call.call_id, |stored| {
        stored.call.aggregate.state() == CallState::Transferring
            && stored
                .call
                .aggregate
                .replacement()
                .is_some_and(|replacement| {
                    replacement.pending_binding_generation() == pending_generation
                })
    })
    .await;
    let replacement_connection = next_inbound(destination_events)
        .await
        .expect("generic WSS call center received replacement offer");
    let mut statuses = handoff_statuses_until(
        &mut call.browser_events,
        &call.browser_connection,
        HandoffStatusKind::Attaching,
    )
    .await;
    assert_handoff_statuses(
        &statuses,
        call.call_id,
        destination_leg_id,
        pending_generation,
        &[
            HandoffStatusKind::Preparing,
            HandoffStatusKind::Ringing,
            HandoffStatusKind::Attaching,
        ],
    );
    wait_for_active_bridge_count(orchestrator, 0).await;
    assert!(
        assistant
            .adapter
            .is_connection_live(&call.destination_connection),
        "assistant was retired before WSS destination Connected"
    );
    assert!(call.browser.is_connection_live(&call.browser_connection));
    assert!(destination_adapter.is_connection_live(&replacement_connection));

    send_opus(&browser_stream, 672_000).await;
    assert_no_audio(
        &mut assistant_audio,
        "browser microphone leaked to the held assistant before WSS Connected",
    )
    .await;
    send_encoded(
        &assistant_stream,
        bytes::Bytes::from(vec![0xff; 160]),
        0,
        112_000,
        160,
    )
    .await;
    assert_no_audio(
        &mut browser_audio,
        "held assistant leaked to the browser before WSS Connected",
    )
    .await;
    assert_replacement_is_still_pending(
        runtime,
        orchestrator,
        call.call_id,
        destination_leg_id,
        pending_generation,
    )
    .await;
    assert!(statuses
        .iter()
        .all(|status| status.status != HandoffStatusKind::Connected));

    bounded(
        "generic WSS replacement accept",
        destination_adapter.accept(replacement_connection.clone()),
    )
    .await
    .expect("generic WSS replacement completes ICE/DTLS");
    let active = wait_for_call(runtime, call.call_id, |stored| {
        stored.call.aggregate.state() == CallState::Active
            && stored.call.aggregate.replacement().is_none()
            && stored
                .call
                .bindings
                .get(&destination_leg_id)
                .is_some_and(|binding| binding.binding_generation == pending_generation)
    })
    .await;
    wait_for_active_bridge_count(orchestrator, 1).await;
    statuses.extend(
        handoff_statuses_until(
            &mut call.browser_events,
            &call.browser_connection,
            HandoffStatusKind::Connected,
        )
        .await,
    );
    assert_handoff_statuses(
        &statuses,
        call.call_id,
        destination_leg_id,
        pending_generation,
        &[
            HandoffStatusKind::Preparing,
            HandoffStatusKind::Ringing,
            HandoffStatusKind::Attaching,
            HandoffStatusKind::Connected,
        ],
    );
    assert_ne!(
        active.call.bindings[&destination_leg_id].connection_id,
        assistant_server_connection
    );
    assert_eq!(
        current_inbound_binding(runtime, call.call_id).await,
        (source_leg_id, source_generation, source_server_connection),
        "browser source binding changed during the WSS handoff"
    );
    assert!(call.browser.is_connection_live(&call.browser_connection));
    wait_connection_dead(assistant.adapter.as_ref(), &call.destination_connection).await;

    let destination_stream =
        audio_stream(destination_adapter.as_ref(), &replacement_connection).await;
    assert_eq!(destination_stream.codec().name.to_ascii_lowercase(), "opus");
    let mut destination_audio = destination_stream.try_frames_in().unwrap();
    send_opus(&browser_stream, 768_000).await;
    let at_destination = tokio::time::timeout(Duration::from_secs(10), destination_audio.recv())
        .await
        .expect("browser-to-WSS-agent media deadline")
        .expect("WSS agent media route remained live");
    assert_eq!(at_destination.payload_type, Some(111));
    assert_eq!(
        at_destination.payload,
        rvoip_webrtc::media::silent_opus_payload()
    );
    assert_no_audio_or_closed(
        &mut assistant_audio,
        "browser media leaked to the retired assistant after WSS promotion",
    )
    .await;

    send_opus(&destination_stream, 864_000).await;
    let at_browser = tokio::time::timeout(Duration::from_secs(10), browser_audio.recv())
        .await
        .expect("WSS-agent-to-browser media deadline")
        .expect("stable browser media route remained live");
    assert_eq!(at_browser.payload_type, Some(111));
    assert_eq!(
        at_browser.payload,
        rvoip_webrtc::media::silent_opus_payload()
    );
    drain_audio_until_quiet(&mut browser_audio).await;
    let _ = assistant_stream
        .frames_out()
        .send(MediaFrame {
            stream_id: assistant_stream.id(),
            kind: StreamKind::Audio,
            payload: bytes::Bytes::from(vec![0xff; 160]),
            timestamp_rtp: 160_000,
            captured_at: Utc::now(),
            payload_type: Some(0),
        })
        .await;
    assert_no_audio(
        &mut browser_audio,
        "retired assistant leaked into the promoted WSS route",
    )
    .await;

    let browser_message = DataMessage::reliable(
        "browser.to.generic-wss.handoff.v1",
        "application/octet-stream",
        bytes::Bytes::from_static(b"\0\xffbrowser-to-wss"),
    );
    bounded(
        "browser arbitrary DataChannel after WSS handoff",
        call.browser
            .send_data_message(call.browser_connection.clone(), browser_message.clone()),
    )
    .await
    .unwrap();
    assert_eq!(
        next_data_with_label(
            destination_events,
            &replacement_connection,
            &browser_message.label,
        )
        .await,
        browser_message
    );
    let destination_message = DataMessage::reliable(
        "generic-wss.to.browser.handoff.v1",
        "application/json",
        bytes::Bytes::from_static(br#"{"agent":"connected"}"#),
    );
    bounded(
        "generic WSS arbitrary DataChannel after handoff",
        destination_adapter
            .send_data_message(replacement_connection.clone(), destination_message.clone()),
    )
    .await
    .unwrap();
    assert_eq!(
        next_data_with_label(
            &mut call.browser_events,
            &call.browser_connection,
            &destination_message.label,
        )
        .await,
        destination_message
    );

    bounded(
        "browser RFC4733 DTMF after WSS handoff",
        call.browser
            .send_dtmf(call.browser_connection.clone(), "2", 120),
    )
    .await
    .unwrap();
    assert_eq!(
        next_dtmf(destination_events, &replacement_connection).await,
        ("2".into(), 120)
    );
    bounded(
        "generic WSS RFC4733 DTMF after handoff",
        destination_adapter.send_dtmf(replacement_connection.clone(), "7", 140),
    )
    .await
    .unwrap();
    assert_eq!(
        next_dtmf(&mut call.browser_events, &call.browser_connection).await,
        ("7".into(), 140)
    );

    bounded(
        "successful WSS handoff browser hangup",
        call.browser
            .end(call.browser_connection.clone(), EndReason::Normal),
    )
    .await
    .unwrap();
    wait_for_call(runtime, call.call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    wait_connection_dead(destination_adapter.as_ref(), &replacement_connection).await;
    wait_for_orchestrator_idle(orchestrator).await;
    assert!(call.browser.routes().is_empty());
}

#[allow(clippy::too_many_arguments)]
async fn rejected_direct_wss_handoff_resumes_assistant(
    runtime: &CallServiceRuntime,
    orchestrator: &Orchestrator,
    bridge_web_address: std::net::SocketAddr,
    web_trust: Arc<WebRtcTlsClientTrust>,
    assistant: &mut SipDestinationFixture,
    destination_endpoint: String,
    destination_adapter: &Arc<WebRtcAdapter>,
    destination_events: &mut mpsc::Receiver<AdapterEvent>,
) {
    let mut call = establish_direct_assistant_call(
        runtime,
        bridge_web_address,
        web_trust,
        assistant,
        "direct-wss-handoff-rejected-call",
        "direct-wss-handoff-rejected-correlation",
    )
    .await;
    let (source_leg_id, source_generation, source_server_connection) =
        current_inbound_binding(runtime, call.call_id).await;
    let (destination_leg_id, assistant_generation, assistant_server_connection) =
        current_outbound_binding(runtime, call.call_id).await;
    let pending_generation = assistant_generation.next().unwrap();
    let (browser_stream, mut browser_audio, assistant_stream, mut assistant_audio) =
        baseline_browser_assistant_media(&call, &assistant.adapter, 960_000).await;

    start_webrtc_replacement(
        runtime,
        call.call_id,
        destination_leg_id,
        destination_endpoint,
        "busy-generic-wss-call-center",
        "direct-wss-handoff-rejected-replacement",
    )
    .await;
    wait_for_call(runtime, call.call_id, |stored| {
        stored.call.aggregate.state() == CallState::Transferring
            && stored
                .call
                .aggregate
                .replacement()
                .is_some_and(|replacement| {
                    replacement.pending_binding_generation() == pending_generation
                })
    })
    .await;
    let replacement_connection = next_inbound(destination_events)
        .await
        .expect("rejecting generic WSS call center received replacement offer");
    let mut statuses = handoff_statuses_until(
        &mut call.browser_events,
        &call.browser_connection,
        HandoffStatusKind::Attaching,
    )
    .await;
    assert_handoff_statuses(
        &statuses,
        call.call_id,
        destination_leg_id,
        pending_generation,
        &[
            HandoffStatusKind::Preparing,
            HandoffStatusKind::Ringing,
            HandoffStatusKind::Attaching,
        ],
    );
    wait_for_active_bridge_count(orchestrator, 0).await;
    assert!(
        assistant
            .adapter
            .is_connection_live(&call.destination_connection),
        "assistant was retired before rejected WSS attempt completed"
    );
    assert!(call.browser.is_connection_live(&call.browser_connection));

    send_opus(&browser_stream, 1_056_000).await;
    assert_no_audio(
        &mut assistant_audio,
        "browser microphone leaked to the held assistant during rejected WSS handoff",
    )
    .await;
    send_encoded(
        &assistant_stream,
        bytes::Bytes::from(vec![0xff; 160]),
        0,
        176_000,
        160,
    )
    .await;
    assert_no_audio(
        &mut browser_audio,
        "held assistant leaked to browser during rejected WSS handoff",
    )
    .await;
    assert_replacement_is_still_pending(
        runtime,
        orchestrator,
        call.call_id,
        destination_leg_id,
        pending_generation,
    )
    .await;

    bounded(
        "generic WSS replacement rejection",
        destination_adapter.reject(replacement_connection.clone(), RejectReason::Decline),
    )
    .await
    .unwrap();
    let resumed = wait_for_call(runtime, call.call_id, |stored| {
        stored.call.aggregate.state() == CallState::Active
            && stored.call.aggregate.replacement().is_none()
            && stored
                .call
                .bindings
                .get(&destination_leg_id)
                .is_some_and(|binding| {
                    binding.binding_generation == assistant_generation
                        && binding.connection_id == assistant_server_connection
                })
    })
    .await;
    wait_for_active_bridge_count(orchestrator, 1).await;
    statuses.extend(
        handoff_statuses_until(
            &mut call.browser_events,
            &call.browser_connection,
            HandoffStatusKind::Resumed,
        )
        .await,
    );
    assert_handoff_statuses(
        &statuses,
        call.call_id,
        destination_leg_id,
        pending_generation,
        &[
            HandoffStatusKind::Preparing,
            HandoffStatusKind::Ringing,
            HandoffStatusKind::Attaching,
            HandoffStatusKind::Resumed,
        ],
    );
    assert_eq!(
        resumed.call.bindings[&destination_leg_id].connection_id,
        assistant_server_connection
    );
    assert_eq!(
        current_inbound_binding(runtime, call.call_id).await,
        (source_leg_id, source_generation, source_server_connection),
        "browser source binding changed during rejected WSS handoff"
    );
    assert!(call.browser.is_connection_live(&call.browser_connection));
    assert!(assistant
        .adapter
        .is_connection_live(&call.destination_connection));
    wait_connection_dead(destination_adapter.as_ref(), &replacement_connection).await;

    send_opus(&browser_stream, 1_152_000).await;
    let at_assistant = tokio::time::timeout(Duration::from_secs(10), assistant_audio.recv())
        .await
        .expect("resumed browser-to-assistant media deadline")
        .expect("resumed assistant media route remained live");
    assert_eq!(at_assistant.payload_type, Some(0));
    send_encoded(
        &assistant_stream,
        bytes::Bytes::from(vec![0xff; 160]),
        0,
        192_000,
        160,
    )
    .await;
    let at_browser = tokio::time::timeout(Duration::from_secs(10), browser_audio.recv())
        .await
        .expect("resumed assistant-to-browser media deadline")
        .expect("stable browser route remained live");
    assert_eq!(at_browser.payload_type, Some(111));

    bounded(
        "rejected WSS handoff browser hangup",
        call.browser
            .end(call.browser_connection.clone(), EndReason::Normal),
    )
    .await
    .unwrap();
    wait_for_call(runtime, call.call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    wait_connection_dead(assistant.adapter.as_ref(), &call.destination_connection).await;
    wait_for_orchestrator_idle(orchestrator).await;
    assert!(call.browser.routes().is_empty());
}
