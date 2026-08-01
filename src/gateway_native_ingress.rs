//! Authenticated native SIP/RTP and WebRTC edge termination for split gateways.
//!
//! This runtime deliberately owns no durable call engine. Each public inbound
//! lifecycle must present one principal-bound, transport-typed attachment
//! proof. Redis selects the exact worker, the worker atomically consumes the
//! proof over private mTLS UCTP 0.2, and only then does this edge acknowledge
//! SIP or WebRTC signaling. The local rvoip `Orchestrator` exists solely to
//! activate and supervise the public protocol adapters.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use futures_util::FutureExt;
use rvoip_auth_core::{AuthenticatedPrincipal, BearerValidator};
use rvoip_core::adapter::{ConnectionAdapter, EndReason, RejectReason};
use rvoip_core::capability::CodecInfo;
use rvoip_core::connection::Transport;
use rvoip_core::ids::{ConnectionId, StreamId};
use rvoip_core::operational_events::{
    OperationalEvent, OperationalEventKind, OperationalEventStreamHealth,
};
use rvoip_core::stream::{MediaFrame, MediaStream, StreamKind};
use rvoip_core::{
    DataMessage, InboundAction, InboundAdmission, Orchestrator, ParticipantId, SessionMedium,
};
use rvoip_sip::{
    Config as SipConfig, ProfiledSipAdapter, SipAdapter, SipEgressProfileRegistration,
    SipInboundContextPolicy, SipListenerAuthPolicy, SipNatConfig, SipProfileRevision,
    UnifiedCoordinator,
};
use rvoip_webrtc::signaling::auth::{AuthCoreHook, WsBearerSessionBinding};
use rvoip_webrtc::{
    tls::TlsConfig as WebRtcTlsConfig, WebRtcAdapter, WebRtcConfig, WebRtcServer,
    WebRtcServerBuilder,
};
use sha2::Digest;
use thiserror::Error;
use tokio::sync::{mpsc, watch, Notify};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

use crate::call_engine::AttachmentTransport;
use crate::gateway_attachment::GatewayAttachmentResolver;
use crate::gateway_forwarding::{
    ForwardedPacket, GatewayForwarder, GatewayForwardingError, GatewayForwardingRoute,
};
use crate::gateway_uctp_ingress::{GatewayIngressAdmission, GatewayUctpIngressError};
use crate::private_egress::PrivateEgressError;
use crate::private_egress_stream::PrivateEgressGatewayLifecycleSource;

/// Private WebSocket subprotocol prefix carrying an attachment proof.
pub const NATIVE_WEBRTC_ATTACHMENT_PREFIX: &str = "bridgefu.attach.";

const CONTROL_QUEUE_CAPACITY: usize = 64;
const RTP_FIXED_HEADER_BYTES: usize = 12;
const MAX_CONSECUTIVE_MEDIA_DROPS: usize = 50;
const PUBLIC_CONTROL_SEND_TIMEOUT: Duration = Duration::from_secs(2);
const EGRESS_EVENT_QUEUE_CAPACITY: usize = 64;

/// Bounded authoritative branch from the native Orchestrator's single
/// operational stream to gateway-owned outbound proxy routes.
pub struct GatewayNativeEgressEventRouter {
    routes: Mutex<HashMap<ConnectionId, mpsc::Sender<OperationalEvent>>>,
}

impl GatewayNativeEgressEventRouter {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            routes: Mutex::new(HashMap::new()),
        })
    }

    fn sender(&self, connection_id: &ConnectionId) -> Option<mpsc::Sender<OperationalEvent>> {
        self.routes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(connection_id)
            .cloned()
    }

    fn remove_exact(
        &self,
        connection_id: &ConnectionId,
        expected: &mpsc::Sender<OperationalEvent>,
    ) {
        let mut routes = self
            .routes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if routes
            .get(connection_id)
            .is_some_and(|registered| registered.same_channel(expected))
        {
            routes.remove(connection_id);
        }
    }

    #[must_use]
    pub fn active_routes(&self) -> usize {
        self.routes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }
}

impl PrivateEgressGatewayLifecycleSource for GatewayNativeEgressEventRouter {
    fn subscribe(
        &self,
        connection_id: ConnectionId,
    ) -> Result<mpsc::Receiver<OperationalEvent>, PrivateEgressError> {
        let (sender, receiver) = mpsc::channel(EGRESS_EVENT_QUEUE_CAPACITY);
        let mut routes = self
            .routes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if routes.insert(connection_id, sender).is_some() {
            return Err(PrivateEgressError::InvalidTransition);
        }
        Ok(receiver)
    }

    fn unsubscribe(&self, connection_id: &ConnectionId) {
        self.routes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(connection_id);
    }
}

/// SIP listener inputs after configuration and secret validation.
#[derive(Clone)]
pub struct GatewayNativeSipConfig {
    pub stack: SipConfig,
    pub nat: SipNatConfig,
    pub authentication: SipListenerAuthPolicy,
    pub inbound_context: SipInboundContextPolicy,
    /// Independently secured outbound children selected by exact durable
    /// profile revision. These children never accept inbound signaling.
    pub egress_profiles: Vec<SipEgressProfileConfig>,
}

impl fmt::Debug for GatewayNativeSipConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayNativeSipConfig")
            .field("bind", &self.stack.bind_addr)
            .field("authentication", &self.authentication)
            .field("inbound_context", &"[configured]")
            .field("egress_profile_count", &self.egress_profiles.len())
            .finish_non_exhaustive()
    }
}

/// Runtime-only, secret-bearing SIP egress construction material.
///
/// The durable call contains only `revision`. The exact stack and header
/// policy are resolved at process startup and are never exposed by route or
/// diagnostics APIs.
#[derive(Clone)]
pub struct SipEgressProfileConfig {
    pub revision: SipProfileRevision,
    pub stack: SipConfig,
    pub nat: SipNatConfig,
    pub allowed_initial_headers: Vec<String>,
    pub sip_message: bool,
}

impl fmt::Debug for SipEgressProfileConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SipEgressProfileConfig")
            .field("revision", &"[opaque]")
            .field("bind", &self.stack.bind_addr)
            .field("offered_codec_count", &self.stack.offered_codecs.len())
            .field(
                "allowed_initial_header_count",
                &self.allowed_initial_headers.len(),
            )
            .field("sip_message", &self.sip_message)
            .finish_non_exhaustive()
    }
}

/// WebRTC media and signaling listener inputs.
#[derive(Clone)]
pub struct GatewayNativeWebRtcConfig {
    pub stack: WebRtcConfig,
    pub websocket_bind: String,
    /// One HTTP listener serves both `/whip/{attachment}` and
    /// `/whep/{attachment}`.
    pub whip_whep_bind: String,
    /// When configured, both signaling listeners terminate TLS in rvoip and
    /// become WSS plus WHIP/WHEP over HTTPS.
    pub tls: Option<GatewayNativeWebRtcTlsConfig>,
}

/// PEM files shared by the WSS and HTTPS WHIP/WHEP listeners.
#[derive(Clone)]
pub struct GatewayNativeWebRtcTlsConfig {
    pub certificate_chain: PathBuf,
    pub private_key: PathBuf,
}

impl fmt::Debug for GatewayNativeWebRtcTlsConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayNativeWebRtcTlsConfig")
            .field("certificate_chain", &"[configured]")
            .field("private_key", &"[configured]")
            .finish()
    }
}

impl fmt::Debug for GatewayNativeWebRtcConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayNativeWebRtcConfig")
            .field("websocket_bind", &self.websocket_bind)
            .field("whip_whep_bind", &self.whip_whep_bind)
            .field("media_udp_bind", &self.stack.udp_bind)
            .field("tls", &self.tls.is_some())
            .finish_non_exhaustive()
    }
}

/// Complete native edge configuration. Private forwarding, coordination, and
/// process-wide admission are injected separately so this runtime cannot
/// accidentally construct a local worker.
#[derive(Clone, Debug)]
pub struct GatewayNativeIngressConfig {
    pub sip: GatewayNativeSipConfig,
    pub webrtc: GatewayNativeWebRtcConfig,
    pub admission_capacity: usize,
    pub setup_timeout: Duration,
}

impl GatewayNativeIngressConfig {
    fn validate(&self) -> Result<(), GatewayNativeIngressError> {
        self.sip
            .authentication
            .validate()
            .map_err(|_| GatewayNativeIngressError::InvalidConfiguration)?;
        let websocket_bind = self
            .webrtc
            .websocket_bind
            .parse::<SocketAddr>()
            .map_err(|_| GatewayNativeIngressError::InvalidConfiguration)?;
        let whip_whep_bind = self
            .webrtc
            .whip_whep_bind
            .parse::<SocketAddr>()
            .map_err(|_| GatewayNativeIngressError::InvalidConfiguration)?;
        if self.admission_capacity == 0
            || self.setup_timeout.is_zero()
            || self.setup_timeout > Duration::from_secs(30)
            || (self.webrtc.tls.is_none()
                && (!websocket_bind.ip().is_loopback() || !whip_whep_bind.ip().is_loopback()))
        {
            return Err(GatewayNativeIngressError::InvalidConfiguration);
        }
        if self.sip.egress_profiles.len() > rvoip_sip::MAX_INSTALLED_SIP_EGRESS_PROFILES {
            return Err(GatewayNativeIngressError::InvalidConfiguration);
        }
        let mut revisions = BTreeSet::new();
        let mut media_ranges = vec![(
            self.sip.stack.media_port_start,
            self.sip.stack.media_port_end,
        )];
        for profile in &self.sip.egress_profiles {
            if !revisions.insert(profile.revision.clone()) || profile.stack.validate().is_err() {
                return Err(GatewayNativeIngressError::InvalidConfiguration);
            }
            media_ranges.push((profile.stack.media_port_start, profile.stack.media_port_end));
        }
        media_ranges.sort_unstable();
        if media_ranges
            .windows(2)
            .any(|ranges| ranges[0].1 >= ranges[1].0)
        {
            return Err(GatewayNativeIngressError::InvalidConfiguration);
        }
        Ok(())
    }
}

/// Aggregate-safe native edge health.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayNativeIngressHealth {
    Healthy,
    Degraded,
    Draining,
    Stopped,
}

#[async_trait]
trait NativeMediaRoute: Send + Sync {
    fn try_send_rtp(&self, packet: Bytes) -> Result<(), GatewayForwardingError>;
    fn try_send_dtmf(&self, digits: String, duration_ms: u32)
        -> Result<(), GatewayForwardingError>;
    fn try_send_data(&self, message: DataMessage) -> Result<(), GatewayForwardingError>;
    async fn recv(&self) -> Option<ForwardedPacket>;
    async fn close(&self);
}

#[async_trait]
impl NativeMediaRoute for GatewayForwardingRoute {
    fn try_send_rtp(&self, packet: Bytes) -> Result<(), GatewayForwardingError> {
        GatewayForwardingRoute::try_send_rtp(self, packet)
    }

    fn try_send_dtmf(
        &self,
        digits: String,
        duration_ms: u32,
    ) -> Result<(), GatewayForwardingError> {
        GatewayForwardingRoute::try_send_dtmf(self, digits, duration_ms)
    }

    fn try_send_data(&self, message: DataMessage) -> Result<(), GatewayForwardingError> {
        GatewayForwardingRoute::try_send_data(self, message)
    }

    async fn recv(&self) -> Option<ForwardedPacket> {
        GatewayForwardingRoute::recv(self).await
    }

    async fn close(&self) {
        GatewayForwardingRoute::close(self).await;
    }
}

#[async_trait]
trait NativeAttachmentRouteOpener: Send + Sync {
    async fn open(
        &self,
        principal: AuthenticatedPrincipal,
        token: String,
        transport: AttachmentTransport,
        codec: CodecInfo,
    ) -> Result<Arc<dyn NativeMediaRoute>, GatewayNativeIngressError>;
}

struct ForwardingRouteOpener {
    resolver: Arc<GatewayAttachmentResolver>,
    forwarder: Arc<GatewayForwarder>,
}

#[async_trait]
impl NativeAttachmentRouteOpener for ForwardingRouteOpener {
    async fn open(
        &self,
        principal: AuthenticatedPrincipal,
        token: String,
        transport: AttachmentTransport,
        codec: CodecInfo,
    ) -> Result<Arc<dyn NativeMediaRoute>, GatewayNativeIngressError> {
        let authorization = self
            .resolver
            .resolve(principal, token, transport, Utc::now())
            .await
            .map_err(|_| GatewayNativeIngressError::AttachmentRejected)?;
        self.forwarder
            .open_attachment_route(authorization, codec)
            .await
            .map(|route| Arc::new(route) as Arc<dyn NativeMediaRoute>)
            .map_err(GatewayNativeIngressError::Forwarding)
    }
}

/// Concrete native public edge. It owns protocol listeners, a transport-only
/// Orchestrator, route pumps, and ordered drain; it never owns `CallService`.
pub struct GatewayNativeIngress {
    orchestrator: Arc<Orchestrator>,
    sip: Arc<ProfiledSipAdapter>,
    webrtc_adapter: Arc<WebRtcAdapter>,
    webrtc_server: tokio::sync::Mutex<Option<WebRtcServer>>,
    sip_addr: SocketAddr,
    websocket_addr: SocketAddr,
    whip_whep_addr: SocketAddr,
    secure_signaling: bool,
    draining: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
    idle: Arc<Notify>,
    cancel: CancellationToken,
    supervisor: Mutex<Option<JoinHandle<()>>>,
    health: watch::Sender<GatewayNativeIngressHealth>,
    egress_events: Arc<GatewayNativeEgressEventRouter>,
}

impl fmt::Debug for GatewayNativeIngress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayNativeIngress")
            .field("sip_addr", &self.sip_addr)
            .field("websocket_addr", &self.websocket_addr)
            .field("whip_whep_addr", &self.whip_whep_addr)
            .field("secure_signaling", &self.secure_signaling)
            .field("active_routes", &self.active.load(Ordering::Acquire))
            .field("draining", &self.draining.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

async fn build_profiled_sip_adapter(
    default: Arc<SipAdapter>,
    profiles: Vec<SipEgressProfileConfig>,
    timeout: Duration,
) -> Result<Arc<ProfiledSipAdapter>, GatewayNativeIngressError> {
    let mut registrations = Vec::with_capacity(profiles.len());
    for profile in profiles {
        match SipEgressProfileRegistration::from_config_and_nat(
            profile.revision,
            profile.stack,
            profile.nat,
            profile.allowed_initial_headers,
            profile.sip_message,
        )
        .await
        {
            Ok(registration) => registrations.push(registration),
            Err(_) => {
                for registration in registrations {
                    let _ = registration.shutdown(timeout).await;
                }
                return Err(GatewayNativeIngressError::ListenerUnavailable);
            }
        }
    }
    ProfiledSipAdapter::new(default, registrations)
        .map_err(|_| GatewayNativeIngressError::ListenerUnavailable)
}

impl GatewayNativeIngress {
    pub async fn start(
        config: GatewayNativeIngressConfig,
        bearer_validator: Arc<dyn BearerValidator>,
        attachment_resolver: Arc<GatewayAttachmentResolver>,
        forwarder: Arc<GatewayForwarder>,
        admission: Arc<dyn GatewayIngressAdmission>,
    ) -> Result<Arc<Self>, GatewayNativeIngressError> {
        let opener: Arc<dyn NativeAttachmentRouteOpener> = Arc::new(ForwardingRouteOpener {
            resolver: attachment_resolver,
            forwarder,
        });
        Self::start_with_opener(config, bearer_validator, opener, admission).await
    }

    /// Starts the production WebRTC edge with a pre-upgrade relationship
    /// between the short-lived signaling bearer and the one-use attachment.
    pub async fn start_with_session_binding(
        config: GatewayNativeIngressConfig,
        bearer_validator: Arc<dyn BearerValidator>,
        session_binding: Arc<dyn WsBearerSessionBinding>,
        attachment_resolver: Arc<GatewayAttachmentResolver>,
        forwarder: Arc<GatewayForwarder>,
        admission: Arc<dyn GatewayIngressAdmission>,
    ) -> Result<Arc<Self>, GatewayNativeIngressError> {
        let opener: Arc<dyn NativeAttachmentRouteOpener> = Arc::new(ForwardingRouteOpener {
            resolver: attachment_resolver,
            forwarder,
        });
        Self::start_with_opener_and_binding(
            config,
            bearer_validator,
            Some(session_binding),
            opener,
            admission,
        )
        .await
    }

    async fn start_with_opener(
        config: GatewayNativeIngressConfig,
        bearer_validator: Arc<dyn BearerValidator>,
        opener: Arc<dyn NativeAttachmentRouteOpener>,
        admission: Arc<dyn GatewayIngressAdmission>,
    ) -> Result<Arc<Self>, GatewayNativeIngressError> {
        Self::start_with_opener_and_binding(config, bearer_validator, None, opener, admission).await
    }

    async fn start_with_opener_and_binding(
        mut config: GatewayNativeIngressConfig,
        bearer_validator: Arc<dyn BearerValidator>,
        session_binding: Option<Arc<dyn WsBearerSessionBinding>>,
        opener: Arc<dyn NativeAttachmentRouteOpener>,
        admission: Arc<dyn GatewayIngressAdmission>,
    ) -> Result<Arc<Self>, GatewayNativeIngressError> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        config.validate()?;
        let sip_egress_profiles = std::mem::take(&mut config.sip.egress_profiles);
        // Load every file-backed signaling dependency before binding SIP or
        // spawning adapter tasks so a bad certificate cannot leave a partial
        // native edge alive.
        let webrtc_tls = match config.webrtc.tls.clone() {
            Some(tls) => Some(
                WebRtcTlsConfig::from_pem_files(tls.certificate_chain, tls.private_key)
                    .await
                    .map_err(|_| GatewayNativeIngressError::ListenerUnavailable)?,
            ),
            None => None,
        };
        let orchestrator = Orchestrator::new(rvoip_core::config::Config::default());
        let admissions = orchestrator
            .install_inbound_admission_gate(config.admission_capacity, config.setup_timeout)
            .map_err(|_| GatewayNativeIngressError::InvalidConfiguration)?;
        let operational = orchestrator
            .install_operational_event_stream(config.admission_capacity.saturating_mul(4).max(64))
            .map_err(|_| GatewayNativeIngressError::InvalidConfiguration)?;
        let operational_health = orchestrator
            .subscribe_operational_event_stream_health()
            .map_err(|_| GatewayNativeIngressError::InvalidConfiguration)?;

        let sip_addr = config.sip.stack.bind_addr;
        let coordinator = UnifiedCoordinator::new_with_listener_auth_and_nat(
            config.sip.stack,
            config.sip.authentication,
            config.sip.nat,
        )
        .await
        .map_err(|_| GatewayNativeIngressError::ListenerUnavailable)?;
        let default_sip = match SipAdapter::new_with_inbound_context_policy(
            Arc::clone(&coordinator),
            config.sip.inbound_context,
        )
        .await
        {
            Ok(adapter) => adapter,
            Err(_) => {
                let _ = coordinator
                    .shutdown_gracefully(Some(config.setup_timeout))
                    .await;
                return Err(GatewayNativeIngressError::ListenerUnavailable);
            }
        };
        let sip = match build_profiled_sip_adapter(
            default_sip,
            sip_egress_profiles,
            config.setup_timeout,
        )
        .await
        {
            Ok(adapter) => adapter,
            Err(_) => {
                let _ = coordinator
                    .shutdown_gracefully(Some(config.setup_timeout))
                    .await;
                return Err(GatewayNativeIngressError::ListenerUnavailable);
            }
        };
        let auth = AuthCoreHook::new(bearer_validator)
            .try_with_session_hint_subprotocol_prefix(NATIVE_WEBRTC_ATTACHMENT_PREFIX)
            .map_err(|_| GatewayNativeIngressError::InvalidConfiguration)?;
        let auth = match session_binding {
            Some(binding) => auth.with_session_binding(binding),
            None => auth,
        };
        let auth = Arc::new(auth);
        let secure_signaling = webrtc_tls.is_some();
        let mut webrtc_builder = WebRtcServerBuilder::new(config.webrtc.stack)
            .with_ws_auth(auth.clone())
            .with_whip_auth(auth)
            .with_inbound_admission_confirmation(config.setup_timeout);
        if let Some(tls) = webrtc_tls {
            webrtc_builder = webrtc_builder
                .with_wss(config.webrtc.websocket_bind, tls.clone())
                .with_whips(config.webrtc.whip_whep_bind, tls);
        } else {
            webrtc_builder = webrtc_builder
                .with_ws(config.webrtc.websocket_bind)
                .with_whip(config.webrtc.whip_whep_bind);
        }
        let webrtc_server = match webrtc_builder.build().await {
            Ok(server) => server,
            Err(_) => {
                let _ = sip.drain(config.setup_timeout).await;
                return Err(GatewayNativeIngressError::ListenerUnavailable);
            }
        };
        let Some(websocket_addr) = webrtc_server.ws_addr().or_else(|| webrtc_server.wss_addr())
        else {
            webrtc_server
                .shutdown_with_deadline(config.setup_timeout)
                .await;
            let _ = sip.drain(config.setup_timeout).await;
            return Err(GatewayNativeIngressError::ListenerUnavailable);
        };
        let Some(whip_whep_addr) = webrtc_server
            .whip_addr()
            .or_else(|| webrtc_server.whips_addr())
        else {
            webrtc_server
                .shutdown_with_deadline(config.setup_timeout)
                .await;
            let _ = sip.drain(config.setup_timeout).await;
            return Err(GatewayNativeIngressError::ListenerUnavailable);
        };
        let webrtc_adapter = webrtc_server.adapter();
        if orchestrator
            .register(Arc::clone(&sip) as Arc<dyn ConnectionAdapter>)
            .is_err()
            || orchestrator
                .register(Arc::clone(&webrtc_adapter) as Arc<dyn ConnectionAdapter>)
                .is_err()
        {
            webrtc_server
                .shutdown_with_deadline(config.setup_timeout)
                .await;
            let _ = sip.drain(config.setup_timeout).await;
            return Err(GatewayNativeIngressError::ListenerUnavailable);
        }

        let draining = Arc::new(AtomicBool::new(false));
        let active = Arc::new(AtomicUsize::new(0));
        let idle = Arc::new(Notify::new());
        let cancel = CancellationToken::new();
        let (health, _) = watch::channel(GatewayNativeIngressHealth::Healthy);
        let egress_events = GatewayNativeEgressEventRouter::new();
        let supervisor = tokio::spawn(run_native_supervisor(NativeSupervisor {
            admissions,
            operational,
            operational_health,
            orchestrator: Arc::clone(&orchestrator),
            sip: Arc::clone(&sip),
            webrtc: Arc::clone(&webrtc_adapter),
            opener,
            admission,
            draining: Arc::clone(&draining),
            active: Arc::clone(&active),
            idle: Arc::clone(&idle),
            cancel: cancel.clone(),
            health: health.clone(),
            setup_timeout: config.setup_timeout,
            egress_events: Arc::clone(&egress_events),
        }));
        metrics::gauge!("bridgefu_gateway_native_ingress_ready").set(1.0);
        metrics::gauge!("bridgefu_gateway_native_active_routes").set(0.0);
        Ok(Arc::new(Self {
            orchestrator,
            sip,
            webrtc_adapter,
            webrtc_server: tokio::sync::Mutex::new(Some(webrtc_server)),
            sip_addr,
            websocket_addr,
            whip_whep_addr,
            secure_signaling,
            draining,
            active,
            idle,
            cancel,
            supervisor: Mutex::new(Some(supervisor)),
            health,
            egress_events,
        }))
    }

    #[must_use]
    pub const fn sip_addr(&self) -> SocketAddr {
        self.sip_addr
    }

    #[must_use]
    pub const fn websocket_addr(&self) -> SocketAddr {
        self.websocket_addr
    }

    #[must_use]
    pub const fn whip_whep_addr(&self) -> SocketAddr {
        self.whip_whep_addr
    }

    #[must_use]
    pub const fn secure_signaling(&self) -> bool {
        self.secure_signaling
    }

    #[must_use]
    pub fn active_routes(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    pub fn subscribe_health(&self) -> watch::Receiver<GatewayNativeIngressHealth> {
        self.health.subscribe()
    }

    pub fn sip_egress_adapter(&self) -> Arc<dyn ConnectionAdapter> {
        Arc::clone(&self.sip) as Arc<dyn ConnectionAdapter>
    }

    pub fn webrtc_egress_adapter(&self) -> Arc<dyn ConnectionAdapter> {
        Arc::clone(&self.webrtc_adapter) as Arc<dyn ConnectionAdapter>
    }

    pub fn egress_event_router(&self) -> Arc<GatewayNativeEgressEventRouter> {
        Arc::clone(&self.egress_events)
    }

    /// Native signaling ownership used by the private-egress proxy. The
    /// adapters and their single event streams are registered here, so every
    /// outbound route must be prepared and committed through this exact
    /// Orchestrator rather than calling an adapter directly.
    pub fn egress_orchestrator(&self) -> Arc<Orchestrator> {
        Arc::clone(&self.orchestrator)
    }

    pub fn begin_drain(&self) {
        if !self.draining.swap(true, Ordering::AcqRel) {
            self.health
                .send_replace(GatewayNativeIngressHealth::Draining);
            metrics::gauge!("bridgefu_gateway_native_ingress_ready").set(0.0);
        }
    }

    pub async fn shutdown(&self, timeout: Duration) -> Result<(), GatewayNativeIngressError> {
        self.begin_drain();
        let deadline = tokio::time::Instant::now() + timeout;
        if let Some(server) = self.webrtc_server.lock().await.take() {
            server
                .shutdown_with_deadline(
                    deadline.saturating_duration_since(tokio::time::Instant::now()),
                )
                .await;
        }
        let _ = self
            .sip
            .drain(deadline.saturating_duration_since(tokio::time::Instant::now()))
            .await;

        loop {
            let notified = self.idle.notified();
            if self.active.load(Ordering::Acquire) == 0 {
                break;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                break;
            }
        }
        self.cancel.cancel();
        let supervisor = self
            .supervisor
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(mut supervisor) = supervisor {
            if tokio::time::timeout_at(deadline, &mut supervisor)
                .await
                .is_err()
            {
                supervisor.abort();
                let _ = supervisor.await;
            }
        }
        let _ = self
            .webrtc_adapter
            .drain_outbound_signaling(
                deadline.saturating_duration_since(tokio::time::Instant::now()),
            )
            .await;
        let _ = tokio::time::timeout_at(
            deadline,
            self.orchestrator.drain_connection_lifecycle_tasks(),
        )
        .await;
        self.health
            .send_replace(GatewayNativeIngressHealth::Stopped);
        Ok(())
    }
}

struct NativeSupervisor {
    admissions: mpsc::Receiver<InboundAdmission>,
    operational: mpsc::Receiver<OperationalEvent>,
    operational_health: rvoip_core::OperationalEventStreamHealthSubscription,
    orchestrator: Arc<Orchestrator>,
    sip: Arc<ProfiledSipAdapter>,
    webrtc: Arc<WebRtcAdapter>,
    opener: Arc<dyn NativeAttachmentRouteOpener>,
    admission: Arc<dyn GatewayIngressAdmission>,
    draining: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
    idle: Arc<Notify>,
    cancel: CancellationToken,
    health: watch::Sender<GatewayNativeIngressHealth>,
    setup_timeout: Duration,
    egress_events: Arc<GatewayNativeEgressEventRouter>,
}

async fn run_native_supervisor(mut input: NativeSupervisor) {
    let routes = Arc::new(tokio::sync::Mutex::new(HashMap::<
        ConnectionId,
        mpsc::Sender<NativeRouteControl>,
    >::new()));
    let mut resources = HashMap::<ConnectionId, Arc<NativeTaskResources>>::new();
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            _ = input.cancel.cancelled() => break,
            changed = input.operational_health.changed() => {
                if changed == OperationalEventStreamHealth::Degraded {
                    input.health.send_replace(GatewayNativeIngressHealth::Degraded);
                    break;
                }
            }
            Some(ticket) = input.admissions.recv() => {
                if input.draining.load(Ordering::Acquire) {
                    let _ = ticket.reject(RejectReason::ServerError).await;
                    continue;
                }
                let route = NativeAttachmentTask {
                    ticket,
                    orchestrator: Arc::clone(&input.orchestrator),
                    sip: Arc::clone(&input.sip),
                    webrtc: Arc::clone(&input.webrtc),
                    opener: Arc::clone(&input.opener),
                    admission: Arc::clone(&input.admission),
                    routes: Arc::clone(&routes),
                    cancel: input.cancel.clone(),
                    setup_timeout: input.setup_timeout,
                };
                let connection_id = route.ticket.connection_id().clone();
                let owned = Arc::new(NativeTaskResources::new(
                    connection_id.clone(),
                    Arc::clone(&route.routes),
                    Arc::clone(&route.orchestrator),
                ));
                resources.insert(connection_id.clone(), Arc::clone(&owned));
                let active = Arc::clone(&input.active);
                let idle = Arc::clone(&input.idle);
                tasks.spawn(async move {
                    let active_routes = active.fetch_add(1, Ordering::AcqRel) + 1;
                    metrics::gauge!("bridgefu_gateway_native_active_routes").set(active_routes as f64);
                    let _active = ActiveRouteGuard { active, idle };
                    let result = supervise_native_attachment(
                        Arc::clone(&owned),
                        run_native_attachment(route, owned),
                    )
                    .await;
                    if result.is_err() {
                        metrics::counter!("bridgefu_gateway_native_admissions_total", "outcome" => "rejected").increment(1);
                    }
                    (connection_id, result)
                });
            }
            Some(event) = input.operational.recv() => {
                let sender = routes.lock().await.get(&event.connection_id).cloned();
                if let Some(sender) = sender {
                    let command = match event.kind {
                        OperationalEventKind::DataMessage { message } => Some(NativeRouteControl::Data(message)),
                        OperationalEventKind::Dtmf { digits, duration_ms } => Some(NativeRouteControl::Dtmf { digits, duration_ms }),
                        OperationalEventKind::Ended { .. } | OperationalEventKind::Failed { .. } => Some(NativeRouteControl::Terminal),
                        OperationalEventKind::Transfer { .. } | OperationalEventKind::TransferStatus { .. } => Some(NativeRouteControl::Unsupported),
                        _ => None,
                    };
                    if let Some(command) = command {
                        if sender.try_send(command).is_err() {
                            remove_route_sender_exact(&routes, &event.connection_id, &sender).await;
                            let _ = input.orchestrator.end_connection(
                                event.connection_id,
                                EndReason::Failed { detail: "native gateway control queue unavailable".into() },
                            ).await;
                        }
                    }
                } else if let Some(sender) = input.egress_events.sender(&event.connection_id) {
                    let connection_id = event.connection_id.clone();
                    if sender.try_send(event).is_err() {
                        input.egress_events.remove_exact(&connection_id, &sender);
                        let _ = input.orchestrator.end_connection(
                            connection_id,
                            EndReason::Failed { detail: "native egress event queue unavailable".into() },
                        ).await;
                    }
                }
            }
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                match result {
                    Ok((connection_id, outcome)) => {
                        resources.remove(&connection_id);
                        if outcome.is_err() {
                            metrics::counter!("bridgefu_gateway_native_route_failures_total", "reason" => "lifecycle").increment(1);
                        }
                    }
                    Err(_) => {
                        metrics::counter!("bridgefu_gateway_native_route_failures_total", "reason" => "task").increment(1);
                    }
                }
            }
            else => break,
        }
    }
    input.admissions.close();
    while let Ok(ticket) = input.admissions.try_recv() {
        let _ = ticket.reject(RejectReason::ServerError).await;
    }
    // Preserve why the loop stopped before using cancellation to unwind the
    // remaining tasks. A closed admission/operational stream is a dependency
    // failure, while an already-cancelled token is the normal drain path.
    let draining = input.cancel.is_cancelled();
    input.cancel.cancel();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    for (_, owned) in resources.drain() {
        owned.cleanup(true).await;
    }
    if !draining {
        input
            .health
            .send_replace(GatewayNativeIngressHealth::Degraded);
        metrics::gauge!("bridgefu_gateway_native_ingress_ready").set(0.0);
    }
}

async fn remove_route_sender_exact(
    routes: &tokio::sync::Mutex<HashMap<ConnectionId, mpsc::Sender<NativeRouteControl>>>,
    connection_id: &ConnectionId,
    expected: &mpsc::Sender<NativeRouteControl>,
) {
    let mut routes = routes.lock().await;
    if routes
        .get(connection_id)
        .is_some_and(|registered| registered.same_channel(expected))
    {
        routes.remove(connection_id);
    }
}

struct NativeAttachmentTask {
    ticket: InboundAdmission,
    orchestrator: Arc<Orchestrator>,
    sip: Arc<ProfiledSipAdapter>,
    webrtc: Arc<WebRtcAdapter>,
    opener: Arc<dyn NativeAttachmentRouteOpener>,
    admission: Arc<dyn GatewayIngressAdmission>,
    routes: Arc<tokio::sync::Mutex<HashMap<ConnectionId, mpsc::Sender<NativeRouteControl>>>>,
    cancel: CancellationToken,
    setup_timeout: Duration,
}

#[derive(Default)]
struct NativeOwnedResources {
    route: Option<Arc<dyn NativeMediaRoute>>,
    session: Option<rvoip_core::SessionId>,
    conversation: Option<rvoip_core::ConversationId>,
    control: Option<mpsc::Sender<NativeRouteControl>>,
}

struct NativeTaskResources {
    connection_id: ConnectionId,
    routes: Arc<tokio::sync::Mutex<HashMap<ConnectionId, mpsc::Sender<NativeRouteControl>>>>,
    orchestrator: Arc<Orchestrator>,
    owned: Mutex<NativeOwnedResources>,
    cleaned: AtomicBool,
}

impl NativeTaskResources {
    fn new(
        connection_id: ConnectionId,
        routes: Arc<tokio::sync::Mutex<HashMap<ConnectionId, mpsc::Sender<NativeRouteControl>>>>,
        orchestrator: Arc<Orchestrator>,
    ) -> Self {
        Self {
            connection_id,
            routes,
            orchestrator,
            owned: Mutex::new(NativeOwnedResources::default()),
            cleaned: AtomicBool::new(false),
        }
    }

    fn set_route(&self, route: Arc<dyn NativeMediaRoute>) {
        self.owned
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .route = Some(route);
    }

    fn set_conversation(&self, conversation: rvoip_core::ConversationId) {
        self.owned
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .conversation = Some(conversation);
    }

    fn set_session(&self, session: rvoip_core::SessionId) {
        self.owned
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .session = Some(session);
    }

    fn set_control(&self, control: mpsc::Sender<NativeRouteControl>) {
        self.owned
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .control = Some(control);
    }

    async fn cleanup(&self, failed: bool) {
        if self.cleaned.swap(true, Ordering::AcqRel) {
            return;
        }
        let NativeOwnedResources {
            route,
            session,
            conversation,
            control,
        } = std::mem::take(
            &mut *self
                .owned
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        if let Some(control) = control {
            remove_route_sender_exact(&self.routes, &self.connection_id, &control).await;
        }
        if let Some(route) = route {
            route.close().await;
        }
        let reason = if failed {
            EndReason::Failed {
                detail: "native gateway attachment lifecycle failed".into(),
            }
        } else {
            EndReason::Normal
        };
        let _ = self
            .orchestrator
            .end_connection(self.connection_id.clone(), reason.clone())
            .await;
        if let Some(session) = session {
            let _ = self.orchestrator.end_session(session, reason).await;
        }
        if let Some(conversation) = conversation {
            let _ = self
                .orchestrator
                .close_conversation(conversation, true)
                .await;
        }
    }
}

async fn supervise_native_attachment<F>(
    resources: Arc<NativeTaskResources>,
    future: F,
) -> Result<(), GatewayNativeIngressError>
where
    F: Future<Output = Result<(), GatewayNativeIngressError>>,
{
    let result = match AssertUnwindSafe(future).catch_unwind().await {
        Ok(result) => result,
        Err(_) => Err(GatewayNativeIngressError::Lifecycle),
    };
    resources.cleanup(result.is_err()).await;
    result
}

enum NativeRouteControl {
    Data(DataMessage),
    Dtmf { digits: String, duration_ms: u32 },
    Terminal,
    Unsupported,
}

struct ActiveRouteGuard {
    active: Arc<AtomicUsize>,
    idle: Arc<Notify>,
}

impl Drop for ActiveRouteGuard {
    fn drop(&mut self) {
        let previous = self.active.fetch_sub(1, Ordering::AcqRel);
        metrics::gauge!("bridgefu_gateway_native_active_routes")
            .set(previous.saturating_sub(1) as f64);
        if previous == 1 {
            self.idle.notify_waiters();
        }
    }
}

async fn run_native_attachment(
    mut input: NativeAttachmentTask,
    resources: Arc<NativeTaskResources>,
) -> Result<(), GatewayNativeIngressError> {
    let setup_deadline = tokio::time::Instant::now() + input.setup_timeout;
    let connection_id = input.ticket.connection_id().clone();
    let public_transport = input.ticket.transport();
    let attachment_transport = match public_transport {
        Transport::Sip => AttachmentTransport::Sip,
        Transport::WebRtc => AttachmentTransport::WebRtc,
        _ => {
            let _ = input.ticket.reject(RejectReason::NotAcceptable).await;
            return Err(GatewayNativeIngressError::AttachmentRejected);
        }
    };
    let principal = match input.ticket.authenticated_principal() {
        Ok(principal) => principal,
        Err(_) => {
            let _ = input.ticket.reject(RejectReason::Forbidden).await;
            return Err(GatewayNativeIngressError::AttachmentRejected);
        }
    };
    let orchestrator_tenant = match principal
        .tenant
        .as_deref()
        .filter(|tenant| !tenant.trim().is_empty())
    {
        Some(tenant) => rvoip_core::TenantId::from_string(tenant),
        None => {
            let _ = input.ticket.reject(RejectReason::Forbidden).await;
            return Err(GatewayNativeIngressError::AttachmentRejected);
        }
    };
    let mut context = match input.ticket.take_inbound_context() {
        Ok(Some(context)) if context.is_bound_to(&connection_id, public_transport, &principal) => {
            context
        }
        _ => {
            let _ = input.ticket.reject(RejectReason::Forbidden).await;
            return Err(GatewayNativeIngressError::AttachmentRejected);
        }
    };
    let token = match context.take_routing_hint() {
        Some(token) => token.into_secret(),
        None => {
            let _ = input.ticket.reject(RejectReason::Forbidden).await;
            return Err(GatewayNativeIngressError::AttachmentRejected);
        }
    };
    let lease = match input.admission.try_admit() {
        Ok(lease) => lease,
        Err(GatewayUctpIngressError::CapacityExceeded) => {
            let _ = input.ticket.reject(RejectReason::Busy).await;
            return Err(GatewayNativeIngressError::CapacityExceeded);
        }
        Err(error) => {
            let _ = input.ticket.reject(RejectReason::ServerError).await;
            return Err(error.into());
        }
    };
    // The public adapter has already authenticated and completed codec
    // negotiation before emitting the admission ticket. SIP exposes a
    // dormant pre-answer stream, while WebRTC intentionally withholds streams
    // and media tasks until the exact admission is accepted. Read only the
    // WebRTC negotiation descriptor here so downstream preparation cannot
    // create a circular `streams() -> admission -> streams()` dependency.
    let provisional_stream = match public_transport {
        Transport::Sip => match tokio::time::timeout_at(
            setup_deadline,
            wait_for_audio_stream(&input.sip, &input.webrtc, public_transport, &connection_id),
        )
        .await
        {
            Ok(Ok(stream)) => Some(stream),
            _ => {
                let _ = input.ticket.reject(RejectReason::NotAcceptable).await;
                return Err(GatewayNativeIngressError::Lifecycle);
            }
        },
        Transport::WebRtc => None,
        _ => unreachable!("the public transport was validated above"),
    };
    let codec = match provisional_stream.as_ref() {
        Some(stream) => stream.codec(),
        None => match input.webrtc.negotiated_audio_codec(&connection_id) {
            Ok(Some(codec)) => codec,
            _ => {
                let _ = input.ticket.reject(RejectReason::NotAcceptable).await;
                return Err(GatewayNativeIngressError::Lifecycle);
            }
        },
    };
    let route = match tokio::time::timeout_at(
        setup_deadline,
        input
            .opener
            .open(principal, token, attachment_transport, codec),
    )
    .await
    {
        Ok(Ok(route)) => route,
        Ok(Err(error)) => {
            let _ = input.ticket.reject(RejectReason::Forbidden).await;
            return Err(error);
        }
        Err(_) => {
            let _ = input.ticket.reject(RejectReason::ServerError).await;
            return Err(GatewayNativeIngressError::Lifecycle);
        }
    };
    resources.set_route(Arc::clone(&route));
    let conversation = match tokio::time::timeout_at(
        setup_deadline,
        input.orchestrator.open_conversation(
            orchestrator_tenant,
            rvoip_core::ConversationPolicy::default(),
            HashMap::new(),
        ),
    )
    .await
    {
        Ok(Ok(conversation)) => conversation,
        _ => {
            let _ = input.ticket.reject(RejectReason::ServerError).await;
            return Err(GatewayNativeIngressError::Lifecycle);
        }
    };
    resources.set_conversation(conversation.clone());
    let session = match tokio::time::timeout_at(
        setup_deadline,
        input
            .orchestrator
            .start_session(conversation.clone(), SessionMedium::Voice, Vec::new()),
    )
    .await
    {
        Ok(Ok(session)) => session,
        _ => {
            let _ = input.ticket.reject(RejectReason::ServerError).await;
            return Err(GatewayNativeIngressError::Lifecycle);
        }
    };
    resources.set_session(session.clone());
    let (control_tx, control_rx) = mpsc::channel(CONTROL_QUEUE_CAPACITY);
    input
        .routes
        .lock()
        .await
        .insert(connection_id.clone(), control_tx.clone());
    resources.set_control(control_tx);
    let accepted = matches!(
        tokio::time::timeout_at(setup_deadline, input.ticket.accept()).await,
        Ok(Ok(()))
    );
    let routed = accepted
        && matches!(
            tokio::time::timeout_at(
                setup_deadline,
                input.orchestrator.route_inbound_connection(
                    connection_id.clone(),
                    InboundAction::Accept {
                        session_id: session.clone(),
                        participant_id: ParticipantId::new(),
                    },
                ),
            )
            .await,
            Ok(Ok(()))
        );
    if !routed {
        return Err(GatewayNativeIngressError::Lifecycle);
    }
    let stream = match provisional_stream {
        Some(stream) => stream,
        None => match tokio::time::timeout_at(
            setup_deadline,
            wait_for_audio_stream(&input.sip, &input.webrtc, public_transport, &connection_id),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            _ => return Err(GatewayNativeIngressError::Lifecycle),
        },
    };
    metrics::counter!("bridgefu_gateway_native_admissions_total", "outcome" => "accepted")
        .increment(1);
    run_native_pumps(
        connection_id.clone(),
        Arc::clone(&input.orchestrator),
        stream,
        Arc::clone(&route),
        control_rx,
        input.cancel,
    )
    .await;
    drop(lease);
    Ok(())
}

async fn wait_for_audio_stream(
    sip: &Arc<ProfiledSipAdapter>,
    webrtc: &Arc<WebRtcAdapter>,
    transport: Transport,
    connection_id: &ConnectionId,
) -> Result<Arc<dyn MediaStream>, GatewayNativeIngressError> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let streams = match transport {
            Transport::Sip => sip.streams(connection_id.clone()).await,
            Transport::WebRtc => webrtc.streams(connection_id.clone()).await,
            _ => return Err(GatewayNativeIngressError::Lifecycle),
        };
        if let Ok(streams) = streams {
            if let Some(stream) = streams
                .into_iter()
                .find(|stream| stream.kind() == StreamKind::Audio)
            {
                return Ok(stream);
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(GatewayNativeIngressError::Lifecycle);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn run_native_pumps(
    connection_id: ConnectionId,
    orchestrator: Arc<Orchestrator>,
    stream: Arc<dyn MediaStream>,
    route: Arc<dyn NativeMediaRoute>,
    mut control: mpsc::Receiver<NativeRouteControl>,
    cancel: CancellationToken,
) {
    let mut inbound = match stream.try_frames_in() {
        Ok(inbound) => inbound,
        Err(_) => return,
    };
    let outbound = match stream.try_frames_out() {
        Ok(outbound) => outbound,
        Err(_) => return,
    };
    let codec = stream.codec();
    let stream_id = stream.id();
    let sequence = AtomicU32::new(0);
    let ssrc = stable_ssrc(&connection_id);
    let mut public_drops = 0usize;
    let mut private_drops = 0usize;
    let (public_control_tx, mut public_control_rx) = mpsc::channel(CONTROL_QUEUE_CAPACITY);
    let (public_control_failed, mut public_control_failure) = tokio::sync::oneshot::channel();
    let control_connection_id = connection_id.clone();
    let public_control_task = tokio::spawn(async move {
        while let Some(command) = public_control_rx.recv().await {
            let sent = match command {
                NativePublicControl::Data(message) => {
                    tokio::time::timeout(
                        PUBLIC_CONTROL_SEND_TIMEOUT,
                        orchestrator.send_data_message(control_connection_id.clone(), message),
                    )
                    .await
                }
                NativePublicControl::Dtmf {
                    digits,
                    duration_ms,
                } => {
                    tokio::time::timeout(
                        PUBLIC_CONTROL_SEND_TIMEOUT,
                        orchestrator.send_dtmf(control_connection_id.clone(), &digits, duration_ms),
                    )
                    .await
                }
            };
            if !matches!(sent, Ok(Ok(()))) {
                let _ = public_control_failed.send(());
                return;
            }
        }
    });
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = &mut public_control_failure => break,
            frame = inbound.recv() => {
                let Some(frame) = frame else { break; };
                let packet = encode_rtp(
                    &frame,
                    &codec,
                    sequence.fetch_add(1, Ordering::Relaxed) as u16,
                    ssrc,
                );
                match route.try_send_rtp(packet) {
                    Ok(()) => public_drops = 0,
                    Err(GatewayForwardingError::Backpressure) => {
                        public_drops += 1;
                        metrics::counter!("bridgefu_gateway_native_media_dropped_total", "direction" => "public-to-worker").increment(1);
                        if public_drops >= MAX_CONSECUTIVE_MEDIA_DROPS { break; }
                    }
                    Err(_) => break,
                }
            }
            packet = route.recv() => {
                let Some(packet) = packet else { break; };
                match packet {
                    ForwardedPacket::Rtp(packet) => {
                        let Some(parsed) = decode_rtp(&packet, stream_id.clone()) else { break; };
                        match outbound.try_send(parsed) {
                            Ok(()) => private_drops = 0,
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                private_drops += 1;
                                metrics::counter!("bridgefu_gateway_native_media_dropped_total", "direction" => "worker-to-public").increment(1);
                                if private_drops >= MAX_CONSECUTIVE_MEDIA_DROPS { break; }
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => break,
                        }
                    }
                    ForwardedPacket::Rtcp(_) => {
                        // SIP and WebRTC terminate RTCP hop-by-hop in their
                        // first-party rvoip stacks. Never leak a private RTCP
                        // control packet as a SIP MESSAGE or DataChannel.
                        metrics::counter!("bridgefu_gateway_native_rtcp_terminated_total", "direction" => "worker-to-public").increment(1);
                    }
                    ForwardedPacket::Dtmf { digits, duration_ms } => {
                        if public_control_tx.try_send(NativePublicControl::Dtmf { digits, duration_ms }).is_err() {
                            break;
                        }
                    }
                    ForwardedPacket::Data(message) => {
                        if public_control_tx.try_send(NativePublicControl::Data(message)).is_err() {
                            break;
                        }
                    }
                }
            }
            command = control.recv() => match command {
                Some(NativeRouteControl::Data(message)) => {
                    if route.try_send_data(message).is_err() { break; }
                }
                Some(NativeRouteControl::Dtmf { digits, duration_ms }) => {
                    if route.try_send_dtmf(digits, duration_ms).is_err() { break; }
                }
                Some(NativeRouteControl::Unsupported) => {
                    metrics::counter!("bridgefu_gateway_native_unsupported_total", "operation" => "peer-transfer").increment(1);
                    break;
                }
                Some(NativeRouteControl::Terminal) | None => break,
            }
        }
    }
    drop(public_control_tx);
    public_control_task.abort();
    let _ = public_control_task.await;
}

enum NativePublicControl {
    Data(DataMessage),
    Dtmf { digits: String, duration_ms: u32 },
}

fn payload_type(codec: &CodecInfo) -> u8 {
    match codec.name.to_ascii_lowercase().as_str() {
        "pcmu" | "g.711-mu" => 0,
        "pcma" | "g.711-a" => 8,
        _ => 111,
    }
}

fn encode_rtp(frame: &MediaFrame, codec: &CodecInfo, sequence: u16, ssrc: u32) -> Bytes {
    let mut packet = Vec::with_capacity(RTP_FIXED_HEADER_BYTES + frame.payload.len());
    packet.extend_from_slice(&[
        0x80,
        // Private UCTP uses one canonical PT per exact negotiated codec.
        // Public WebRTC may use any dynamic Opus PT; its adapter repacketizes
        // again on the reverse path, so carrying that public PT internally
        // would make otherwise-valid media fail the worker codec gate.
        payload_type(codec) & 0x7f,
    ]);
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&frame.timestamp_rtp.to_be_bytes());
    packet.extend_from_slice(&ssrc.to_be_bytes());
    packet.extend_from_slice(&frame.payload);
    Bytes::from(packet)
}

fn decode_rtp(packet: &[u8], stream_id: StreamId) -> Option<MediaFrame> {
    if packet.len() < RTP_FIXED_HEADER_BYTES || packet[0] >> 6 != 2 {
        return None;
    }
    let csrc_bytes = usize::from(packet[0] & 0x0f).checked_mul(4)?;
    let mut offset = RTP_FIXED_HEADER_BYTES.checked_add(csrc_bytes)?;
    if offset > packet.len() {
        return None;
    }
    if packet[0] & 0x10 != 0 {
        if offset.checked_add(4)? > packet.len() {
            return None;
        }
        let words = usize::from(u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]));
        offset = offset.checked_add(4)?.checked_add(words.checked_mul(4)?)?;
        if offset > packet.len() {
            return None;
        }
    }
    let padding = if packet[0] & 0x20 != 0 {
        usize::from(*packet.last()?)
    } else {
        0
    };
    if padding > packet.len().saturating_sub(offset) {
        return None;
    }
    let end = packet.len() - padding;
    Some(MediaFrame {
        stream_id,
        kind: StreamKind::Audio,
        payload: Bytes::copy_from_slice(&packet[offset..end]),
        timestamp_rtp: u32::from_be_bytes(packet[4..8].try_into().ok()?),
        captured_at: Utc::now(),
        payload_type: Some(packet[1] & 0x7f),
    })
}

fn stable_ssrc(connection_id: &ConnectionId) -> u32 {
    let digest = sha2::Sha256::digest(connection_id.as_str().as_bytes());
    u32::from_be_bytes(digest[..4].try_into().expect("SHA-256 has four bytes"))
}

/// Redacted native edge failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GatewayNativeIngressError {
    #[error("native gateway configuration is invalid")]
    InvalidConfiguration,
    #[error("native gateway listener is unavailable")]
    ListenerUnavailable,
    #[error("native attachment proof was rejected")]
    AttachmentRejected,
    #[error("gateway dependency is not ready")]
    NotReady,
    #[error("gateway is draining")]
    Draining,
    #[error("gateway admission capacity is exhausted")]
    CapacityExceeded,
    #[error("private forwarding route failed")]
    Forwarding(#[from] GatewayForwardingError),
    #[error("native gateway lifecycle failed")]
    Lifecycle,
}

impl From<crate::gateway_uctp_ingress::GatewayUctpIngressError> for GatewayNativeIngressError {
    fn from(error: crate::gateway_uctp_ingress::GatewayUctpIngressError) -> Self {
        use crate::gateway_uctp_ingress::GatewayUctpIngressError;
        match error {
            GatewayUctpIngressError::NotReady => Self::NotReady,
            GatewayUctpIngressError::Draining => Self::Draining,
            GatewayUctpIngressError::CapacityExceeded => Self::CapacityExceeded,
            _ => Self::Lifecycle,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use rvoip_auth_core::AuthenticationMethod;
    use rvoip_core::capability::default_audio_codec;
    use rvoip_core::connection::Direction;
    use rvoip_core::stream::QualitySnapshot;
    use rvoip_core::{IdentityAssurance, Jwk};
    use rvoip_webrtc::peer::{PeerRole, RvoipPeerConnection};

    use crate::api_principal::ConfiguredApiKeyValidator;

    struct TestAdmission;

    impl GatewayIngressAdmission for TestAdmission {
        fn try_admit(
            &self,
        ) -> Result<
            Box<dyn crate::gateway_uctp_ingress::GatewayIngressAdmissionLease>,
            GatewayUctpIngressError,
        > {
            Ok(Box::new(()))
        }
    }

    struct TestRoute {
        sent: mpsc::Sender<ForwardedPacket>,
        inbound: tokio::sync::Mutex<mpsc::Receiver<ForwardedPacket>>,
        closed: AtomicBool,
    }

    impl TestRoute {
        fn try_record(&self, packet: ForwardedPacket) -> Result<(), GatewayForwardingError> {
            self.sent.try_send(packet).map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => GatewayForwardingError::Backpressure,
                mpsc::error::TrySendError::Closed(_) => GatewayForwardingError::Closed,
            })
        }
    }

    #[async_trait]
    impl NativeMediaRoute for TestRoute {
        fn try_send_rtp(&self, packet: Bytes) -> Result<(), GatewayForwardingError> {
            self.try_record(ForwardedPacket::Rtp(packet))
        }

        fn try_send_dtmf(
            &self,
            digits: String,
            duration_ms: u32,
        ) -> Result<(), GatewayForwardingError> {
            self.try_record(ForwardedPacket::Dtmf {
                digits,
                duration_ms,
            })
        }

        fn try_send_data(&self, message: DataMessage) -> Result<(), GatewayForwardingError> {
            self.try_record(ForwardedPacket::Data(message))
        }

        async fn recv(&self) -> Option<ForwardedPacket> {
            self.inbound.lock().await.recv().await
        }

        async fn close(&self) {
            self.closed.store(true, Ordering::Release);
        }
    }

    struct OpenRecord {
        principal: AuthenticatedPrincipal,
        token: String,
        transport: AttachmentTransport,
        codec: CodecInfo,
    }

    struct TestOpener {
        opened: mpsc::Sender<OpenRecord>,
        routes: Mutex<Vec<TestRouteFixture>>,
    }

    struct TestRouteFixture {
        route: Arc<TestRoute>,
        _sent: mpsc::Receiver<ForwardedPacket>,
        _private_source: mpsc::Sender<ForwardedPacket>,
    }

    impl TestOpener {
        fn new(opened: mpsc::Sender<OpenRecord>) -> Self {
            Self {
                opened,
                routes: Mutex::new(Vec::new()),
            }
        }

        fn opened_routes(&self) -> Vec<Arc<TestRoute>> {
            self.routes
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .iter()
                .map(|fixture| Arc::clone(&fixture.route))
                .collect()
        }
    }

    #[async_trait]
    impl NativeAttachmentRouteOpener for TestOpener {
        async fn open(
            &self,
            principal: AuthenticatedPrincipal,
            token: String,
            transport: AttachmentTransport,
            codec: CodecInfo,
        ) -> Result<Arc<dyn NativeMediaRoute>, GatewayNativeIngressError> {
            let (sent, sent_rx) = mpsc::channel(8);
            let (private_source, private_inbound) = mpsc::channel(8);
            let route = Arc::new(TestRoute {
                sent,
                inbound: tokio::sync::Mutex::new(private_inbound),
                closed: AtomicBool::new(false),
            });
            self.opened
                .send(OpenRecord {
                    principal,
                    token,
                    transport,
                    codec,
                })
                .await
                .map_err(|_| GatewayNativeIngressError::Lifecycle)?;
            self.routes
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(TestRouteFixture {
                    route: Arc::clone(&route),
                    _sent: sent_rx,
                    _private_source: private_source,
                });
            Ok(route as Arc<dyn NativeMediaRoute>)
        }
    }

    struct TestStream {
        id: StreamId,
        inbound: Mutex<Option<mpsc::Receiver<MediaFrame>>>,
        outbound: mpsc::Sender<MediaFrame>,
    }

    #[async_trait]
    impl MediaStream for TestStream {
        fn id(&self) -> StreamId {
            self.id.clone()
        }

        fn kind(&self) -> StreamKind {
            StreamKind::Audio
        }

        fn codec(&self) -> CodecInfo {
            default_audio_codec()
        }

        fn direction(&self) -> Direction {
            Direction::Inbound
        }

        fn frames_in(&self) -> mpsc::Receiver<MediaFrame> {
            self.inbound
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
                .unwrap_or_else(|| mpsc::channel(1).1)
        }

        fn try_frames_in(&self) -> rvoip_core::Result<mpsc::Receiver<MediaFrame>> {
            self.inbound
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
                .ok_or(rvoip_core::RvoipError::InvalidState(
                    "test media source already acquired",
                ))
        }

        fn frames_out(&self) -> mpsc::Sender<MediaFrame> {
            self.outbound.clone()
        }

        fn quality_snapshot(&self) -> QualitySnapshot {
            QualitySnapshot::default()
        }

        async fn close(self: Arc<Self>) -> rvoip_core::Result<()> {
            Ok(())
        }
    }

    fn principal() -> AuthenticatedPrincipal {
        AuthenticatedPrincipal {
            subject: "native-edge-owner".into(),
            tenant: Some("native-edge-tenant".into()),
            scopes: vec![
                "sip:connect".into(),
                "webrtc:connect".into(),
                "whip:publish".into(),
                "whep:subscribe".into(),
            ],
            issuer: Some("native-edge-test".into()),
            expires_at: None,
            method: AuthenticationMethod::Jwt,
            assurance: IdentityAssurance::Pseudonymous {
                ephemeral_key: Jwk(serde_json::json!({"kty": "test"})),
            },
        }
    }

    fn reserve_udp() -> SocketAddr {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.local_addr().unwrap()
    }

    fn reserve_tcp() -> SocketAddr {
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        socket.local_addr().unwrap()
    }

    fn test_config() -> GatewayNativeIngressConfig {
        let sip_addr = reserve_udp();
        let authentication = SipListenerAuthPolicy::enabled_for_tenant("native-edge-tenant")
            .unwrap()
            .with_trusted_cidr("127.0.0.1/32".parse().unwrap(), principal());
        GatewayNativeIngressConfig {
            sip: GatewayNativeSipConfig {
                stack: SipConfig::local("native-edge", sip_addr.port()),
                nat: SipNatConfig::default(),
                authentication,
                inbound_context: SipInboundContextPolicy::default(),
                egress_profiles: Vec::new(),
            },
            webrtc: GatewayNativeWebRtcConfig {
                stack: WebRtcConfig::loopback(),
                websocket_bind: reserve_tcp().to_string(),
                whip_whep_bind: reserve_tcp().to_string(),
                tls: None,
            },
            admission_capacity: 8,
            setup_timeout: Duration::from_secs(5),
        }
    }

    #[test]
    fn configuration_requires_bounded_admission_and_both_webrtc_surfaces() {
        let mut config = test_config();
        config.admission_capacity = 0;
        assert_eq!(
            config.validate(),
            Err(GatewayNativeIngressError::InvalidConfiguration)
        );
        config.admission_capacity = 1;
        config.webrtc.websocket_bind = "192.0.2.1:8443".into();
        assert_eq!(
            config.validate(),
            Err(GatewayNativeIngressError::InvalidConfiguration)
        );
        config.webrtc.websocket_bind = reserve_tcp().to_string();
        config.webrtc.whip_whep_bind = "not-a-socket".into();
        assert_eq!(
            config.validate(),
            Err(GatewayNativeIngressError::InvalidConfiguration)
        );
    }

    #[tokio::test]
    async fn panicked_attachment_task_removes_its_exact_route_and_closes_resources() {
        let connection_id = ConnectionId::from_string("native-panicked-connection");
        let routes = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let (control, _control_rx) = mpsc::channel(1);
        routes
            .lock()
            .await
            .insert(connection_id.clone(), control.clone());
        let (sent, _sent_rx) = mpsc::channel(1);
        let (_private_source, private_inbound) = mpsc::channel(1);
        let route = Arc::new(TestRoute {
            sent,
            inbound: tokio::sync::Mutex::new(private_inbound),
            closed: AtomicBool::new(false),
        });
        let resources = Arc::new(NativeTaskResources::new(
            connection_id,
            Arc::clone(&routes),
            Orchestrator::new(rvoip_core::config::Config::default()),
        ));
        resources.set_control(control);
        resources.set_route(Arc::clone(&route) as Arc<dyn NativeMediaRoute>);

        let result = supervise_native_attachment(Arc::clone(&resources), async {
            panic!("injected native attachment failure");
            #[allow(unreachable_code)]
            Ok(())
        })
        .await;

        assert_eq!(result, Err(GatewayNativeIngressError::Lifecycle));
        assert!(routes.lock().await.is_empty());
        assert!(route.closed.load(Ordering::Acquire));
        assert!(resources.cleaned.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn stale_task_cleanup_cannot_remove_a_successor_control_route() {
        let connection_id = ConnectionId::from_string("native-reused-connection");
        let routes = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let (original, _original_rx) = mpsc::channel(1);
        let (successor, _successor_rx) = mpsc::channel(1);
        routes
            .lock()
            .await
            .insert(connection_id.clone(), successor.clone());
        let resources = NativeTaskResources::new(
            connection_id.clone(),
            Arc::clone(&routes),
            Orchestrator::new(rvoip_core::config::Config::default()),
        );
        resources.set_control(original);

        resources.cleanup(true).await;

        assert!(routes
            .lock()
            .await
            .get(&connection_id)
            .is_some_and(|registered| registered.same_channel(&successor)));
    }

    #[tokio::test]
    async fn media_pump_preserves_rtp_data_dtmf_and_terminates_rtcp_hop_by_hop() {
        let stream_id = StreamId::from_string("native-public-audio");
        let (public_source, public_inbound) = mpsc::channel(8);
        let (public_outbound, mut public_sink) = mpsc::channel(8);
        let stream: Arc<dyn MediaStream> = Arc::new(TestStream {
            id: stream_id.clone(),
            inbound: Mutex::new(Some(public_inbound)),
            outbound: public_outbound,
        });
        let (sent, mut sent_packets) = mpsc::channel(8);
        let (private_source, private_inbound) = mpsc::channel(8);
        let route: Arc<dyn NativeMediaRoute> = Arc::new(TestRoute {
            sent,
            inbound: tokio::sync::Mutex::new(private_inbound),
            closed: AtomicBool::new(false),
        });
        let (control, control_rx) = mpsc::channel(8);
        let pump = tokio::spawn(run_native_pumps(
            ConnectionId::from_string("native-public-connection"),
            Orchestrator::new(rvoip_core::config::Config::default()),
            stream,
            Arc::clone(&route),
            control_rx,
            CancellationToken::new(),
        ));

        public_source
            .send(MediaFrame {
                stream_id,
                kind: StreamKind::Audio,
                payload: Bytes::from_static(b"public-opus"),
                timestamp_rtp: 960,
                captured_at: Utc::now(),
                payload_type: Some(109),
            })
            .await
            .unwrap();
        let ForwardedPacket::Rtp(packet) = sent_packets.recv().await.unwrap() else {
            panic!("public frame must become complete RTP")
        };
        assert_eq!(packet[1] & 0x7f, 111);
        assert_eq!(&packet[12..], b"public-opus");

        control
            .send(NativeRouteControl::Dtmf {
                digits: "12#".into(),
                duration_ms: 120,
            })
            .await
            .unwrap();
        assert!(matches!(
            sent_packets.recv().await,
            Some(ForwardedPacket::Dtmf { digits, duration_ms: 120 }) if digits == "12#"
        ));
        control
            .send(NativeRouteControl::Data(DataMessage::reliable(
                "bridgefu.context.v1",
                "application/json",
                Bytes::from_static(br#"{"correlation_id":"edge"}"#),
            )))
            .await
            .unwrap();
        assert!(matches!(
            sent_packets.recv().await,
            Some(ForwardedPacket::Data(message)) if message.label == "bridgefu.context.v1"
        ));

        private_source
            .send(ForwardedPacket::Rtcp(Bytes::from_static(&[
                0x80, 200, 0, 1, 0, 0, 0, 1,
            ])))
            .await
            .unwrap();
        private_source
            .send(ForwardedPacket::Rtp(encode_rtp(
                &MediaFrame {
                    stream_id: StreamId::from_string("worker"),
                    kind: StreamKind::Audio,
                    payload: Bytes::from_static(b"worker-opus"),
                    timestamp_rtp: 1_920,
                    captured_at: Utc::now(),
                    payload_type: Some(111),
                },
                &default_audio_codec(),
                5,
                7,
            )))
            .await
            .unwrap();
        let public_frame = public_sink.recv().await.unwrap();
        assert_eq!(public_frame.payload, Bytes::from_static(b"worker-opus"));

        control.send(NativeRouteControl::Terminal).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), pump)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn invalid_signaling_tls_fails_before_sip_binds() {
        let mut config = test_config();
        let sip_addr = config.sip.stack.bind_addr;
        config.webrtc.tls = Some(GatewayNativeWebRtcTlsConfig {
            certificate_chain: "/definitely/missing/native-edge.crt".into(),
            private_key: "/definitely/missing/native-edge.key".into(),
        });
        let (opened, _opened_rx) = mpsc::channel(1);
        let result = GatewayNativeIngress::start_with_opener(
            config,
            Arc::new(
                ConfiguredApiKeyValidator::new(
                    "native-edge-api-key".into(),
                    ["native-edge-tenant"],
                )
                .unwrap(),
            ),
            Arc::new(TestOpener::new(opened)),
            Arc::new(TestAdmission),
        )
        .await;
        assert!(matches!(
            result,
            Err(GatewayNativeIngressError::ListenerUnavailable)
        ));
        let rebound = std::net::UdpSocket::bind(sip_addr).unwrap();
        assert_eq!(rebound.local_addr().unwrap(), sip_addr);
    }

    #[tokio::test]
    async fn real_sip_and_whip_attachments_use_only_the_exact_native_edge_routes() {
        let config = test_config();
        let sip_addr = config.sip.stack.bind_addr;
        let (opened, mut opened_rx) = mpsc::channel(4);
        let test_opener = Arc::new(TestOpener::new(opened));
        let opener: Arc<dyn NativeAttachmentRouteOpener> = test_opener.clone();
        let validator: Arc<dyn BearerValidator> = Arc::new(
            ConfiguredApiKeyValidator::new("native-edge-api-key".into(), ["native-edge-tenant"])
                .unwrap(),
        );
        let runtime = GatewayNativeIngress::start_with_opener(
            config,
            validator,
            opener,
            Arc::new(TestAdmission),
        )
        .await
        .unwrap();

        let token = URL_SAFE_NO_PAD.encode([9_u8; 32]);
        let unauthorized = reqwest::Client::new()
            .post(format!("http://{}/whip/{token}", runtime.whip_whep_addr()))
            .header(reqwest::header::CONTENT_TYPE, "application/sdp")
            .body("v=0\r\n")
            .send()
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), reqwest::StatusCode::UNAUTHORIZED);
        assert!(opened_rx.try_recv().is_err());

        let peer = Arc::new(
            RvoipPeerConnection::new(&WebRtcConfig::loopback(), PeerRole::Offerer)
                .await
                .unwrap(),
        );
        peer.add_local_audio_track().await.unwrap();
        let offer = peer.create_offer_and_gather().await.unwrap();
        let authorized = reqwest::Client::new()
            .post(format!("http://{}/whip/{token}", runtime.whip_whep_addr()))
            .bearer_auth("native-edge-api-key")
            .header(reqwest::header::CONTENT_TYPE, "application/sdp")
            .body(offer)
            .send()
            .await
            .unwrap();
        assert_eq!(authorized.status(), reqwest::StatusCode::CREATED);
        let location = authorized
            .headers()
            .get(reqwest::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let etag = authorized
            .headers()
            .get(reqwest::header::ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let answer = authorized.text().await.unwrap();
        peer.set_remote_answer(&answer).await.unwrap();
        let record = tokio::time::timeout(Duration::from_secs(5), opened_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.transport, AttachmentTransport::WebRtc);
        assert_eq!(record.codec.name.to_ascii_lowercase(), "opus");
        assert_eq!(record.codec.clock_rate_hz, 48_000);
        assert_eq!(record.codec.channels, 1);
        assert_eq!(record.token, token);
        assert_eq!(record.principal.subject, "bridgefu-static-api-key");
        assert_eq!(
            record.principal.issuer.as_deref(),
            Some("bridgefu:configured-api-key")
        );
        assert_eq!(
            record.principal.tenant.as_deref(),
            Some("native-edge-tenant")
        );
        assert_eq!(runtime.active_routes(), 1);
        let deleted = reqwest::Client::new()
            .delete(format!("http://{}{}", runtime.whip_whep_addr(), location))
            .bearer_auth("native-edge-api-key")
            .header(reqwest::header::IF_MATCH, etag)
            .send()
            .await
            .unwrap();
        assert_eq!(deleted.status(), reqwest::StatusCode::OK);
        peer.close().await.unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while runtime.active_routes() != 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(runtime.active_routes(), 0);
        let whip_routes = test_opener.opened_routes();
        assert_eq!(whip_routes.len(), 1);
        assert!(whip_routes[0].closed.load(Ordering::Acquire));

        let sip_token = URL_SAFE_NO_PAD.encode([10_u8; 32]);
        let caller_addr = reserve_udp();
        let caller =
            UnifiedCoordinator::new(SipConfig::local("native-edge-caller", caller_addr.port()))
                .await
                .unwrap();
        let session = caller
            .invite(
                Some(format!("sip:native-edge-caller@{caller_addr}")),
                format!("sip:{sip_token}@{sip_addr}"),
            )
            .send()
            .await
            .unwrap();
        let record = tokio::time::timeout(Duration::from_secs(5), opened_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.transport, AttachmentTransport::Sip);
        assert!(matches!(
            record.codec.name.to_ascii_lowercase().as_str(),
            "pcmu" | "g.711-mu"
        ));
        assert_eq!(record.codec.clock_rate_hz, 8_000);
        assert_eq!(record.codec.channels, 1);
        assert_eq!(record.token, sip_token);
        assert_eq!(
            record.principal.tenant.as_deref(),
            Some("native-edge-tenant")
        );
        assert_eq!(runtime.active_routes(), 1);
        let sip_routes = test_opener.opened_routes();
        assert_eq!(sip_routes.len(), 2);
        assert!(!Arc::ptr_eq(&sip_routes[0], &sip_routes[1]));
        assert!(!sip_routes[1].closed.load(Ordering::Acquire));

        // Route provisioning deliberately precedes the SIP 200/ACK lifecycle,
        // so observing the opened attachment is not proof that the caller has
        // finished processing the answer. Wait for authoritative answer
        // evidence before issuing teardown; otherwise a busy executor can
        // make hangup classify the session as early while its dialog is
        // already confirmed and incorrectly attempt CANCEL instead of BYE.
        let answered = caller
            .session(&session)
            .wait_for_answered(Some(Duration::from_secs(5)))
            .await
            .unwrap();
        answered.hangup().await.unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while runtime.active_routes() != 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(runtime.active_routes(), 0);
        assert!(sip_routes[1].closed.load(Ordering::Acquire));

        caller
            .shutdown_gracefully(Some(Duration::from_secs(2)))
            .await
            .unwrap();
        runtime.shutdown(Duration::from_secs(5)).await.unwrap();
        assert_eq!(
            *runtime.subscribe_health().borrow(),
            GatewayNativeIngressHealth::Stopped
        );
    }
}
