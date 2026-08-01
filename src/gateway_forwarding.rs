//! Private gateway-to-worker forwarding over authenticated UCTP 0.2.
//!
//! Public SIP, RTP, WebRTC, and provider listeners terminate on a gateway.
//! This module carries the resulting media and data to the worker selected by
//! the durable call router.  It deliberately owns no call-state policy: the
//! caller supplies an exact tenant/call/leg key and worker, and this layer
//! enforces that every leg of an active call remains pinned to that worker.
//!
//! RTP is transported as the UCTP eight-byte datagram header followed by the
//! complete original RTP packet.  UCTP has no RTCP datagram type, so complete
//! RTCP packets use a reserved, reliable `message.send` DataMessage.  Generic
//! DataMessages cannot claim that reserved label.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::fs::File;
use std::hash::Hash;
use std::io::{BufReader, Read};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bytes::Bytes;
use dashmap::DashMap;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use quinn::{Endpoint, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rvoip_auth_core::{BearerValidator, JwtValidator};
use rvoip_core::adapter::{ConnectionAdapter, InboundRoutingHint};
use rvoip_core::capability::CodecInfo;
use rvoip_core::ids::{ConnectionId, SessionId};
use rvoip_core::{DataMessage, Orchestrator};
use rvoip_quic::{UctpQuicAdapter, UctpQuicClient, UctpQuicConfig};
use rvoip_uctp::envelope::UctpEnvelope;
use rvoip_uctp::payloads::{auth, connection, message, session, stream};
use rvoip_uctp::state::{
    OrchestratorSubscriptionHandler, PublisherInfo, ResourceBindingError, SessionBindingResolver,
    SubscriptionHandler, SubscriptionOutcome, UctpCoordinatorCaps, UCTP_SESSION_SCOPE,
};
use rvoip_uctp::substrate::datagram::unpack_rtp;
use rvoip_uctp::substrate::{
    dispatch_by_alpn, make_client_endpoint, make_server_endpoint, pack, unpack,
    unpack_rtp_datagram, MediaDatagram,
};
use rvoip_uctp::types::MessageType;
use rvoip_uctp::UCTP_RAW_QUIC_ALPN_BYTES;
use serde::Serialize;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot, watch, Notify, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::broadcast::WorkerBroadcastSubscriptionAuthority;
use crate::call_engine::{BindingGeneration, CallId, LegId, TenantId, WorkerId, WorkerLease};
use crate::gateway_attachment::{
    GatewayAttachmentAuthorization, GatewayAttachmentError, WorkerAttachmentAdmissionReceipt,
    WorkerAttachmentAdmissionRequest, WorkerAttachmentAdmissionResponse,
    PRIVATE_ATTACHMENT_ADMISSION_RESPONSE_LABEL,
};
use crate::private_egress::{
    is_private_egress_label, PrivateEgressCommand, PrivateEgressCommandService, PrivateEgressError,
    PrivateEgressLifecycleAck, PrivateEgressLifecycleEvent, PrivateEgressResponse,
    PrivateEgressRouteAuthority, PrivateEgressRouteKey, PrivateEgressSource,
    PRIVATE_EGRESS_COMMAND_LABEL, PRIVATE_EGRESS_LIFECYCLE_ACK_LABEL,
    PRIVATE_EGRESS_LIFECYCLE_LABEL, PRIVATE_EGRESS_RESPONSE_LABEL,
};
use crate::private_egress_stream::{
    PrivateEgressStreamAdmission, PrivateEgressStreamAdmissionRegistry, PrivateEgressStreamError,
    PrivateEgressWorkerConnection,
};

/// Application label reserved for byte-exact RTCP carriage.
pub const PRIVATE_RTCP_LABEL: &str = "bridgefu.rtcp.v1";
/// Media type paired with [`PRIVATE_RTCP_LABEL`].
pub const PRIVATE_RTCP_CONTENT_TYPE: &str = "application/rtcp";
/// Scope proving that the authenticated UCTP participant is a Bridgefu edge.
pub const PRIVATE_FORWARD_SCOPE: &str = "bridgefu:gateway-forward";

const TOKEN_ISSUER: &str = "bridgefu-private-forwarding";
const WIRE_SESSION_PREFIX: &str = "bf-private-v1";
const WIRE_ATTACHMENT_SESSION_PREFIX: &str = "bf-admit-v1";
const WIRE_BROADCAST_SESSION_PREFIX: &str = "bf-broadcast-session-v1";
const WIRE_EGRESS_SESSION_PREFIX: &str = "bf-egress-v1";
const PRIVATE_EGRESS_LIFECYCLE_RETRY_INTERVAL: Duration = Duration::from_millis(100);
const PRIVATE_ATTACHMENT_INTENT: &str = "private-attachment-forward";
const PRIVATE_ATTACHMENT_CAPABILITY: &str = "bridgefu_private_attachment_admission";
const PRIVATE_BROADCAST_INTENT: &str = "private-broadcast-subscribe";
const PRIVATE_BROADCAST_CAPABILITY: &str = "bridgefu_private_broadcast_subscription";
const PRIVATE_BROADCAST_ADMISSION_PREFIX: &str = "bf-broadcast-admit-v1";
const PRIVATE_EGRESS_STREAM_INTENT: &str = "private-egress-stream";
const PRIVATE_EGRESS_STREAM_CAPABILITY: &str = "bridgefu_private_egress_stream_admission";
const BROADCAST_STREAM_ID: &str = "audio/main";
const MIN_TOKEN_KEY_BYTES: usize = 32;
const MAX_ID_BYTES: usize = 128;
// Opus' largest 20 ms packet plus RTP headers is comfortably below this.
// Keeping the race buffer deliberately small prevents an authenticated peer
// from turning unannounced stream IDs into a large allocation surface.
const MAX_PENDING_RTP_BYTES: usize = 4 * 1024;
const MAX_PENDING_STREAMS_HARD: usize = 1_000;
const PENDING_DATAGRAM_SWEEP_INTERVAL: Duration = Duration::from_millis(100);

/// Bounded, non-secret classifier carried only between the authenticated
/// private UCTP resolver and Bridgefu's single process admission owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WorkerBroadcastAdmissionRequest {
    broadcast_id: uuid::Uuid,
    listener_id: uuid::Uuid,
}

impl WorkerBroadcastAdmissionRequest {
    fn new(broadcast_id: uuid::Uuid, listener_id: uuid::Uuid) -> Option<Self> {
        (!broadcast_id.is_nil() && !listener_id.is_nil()).then_some(Self {
            broadcast_id,
            listener_id,
        })
    }

    fn routing_hint(self) -> String {
        format!(
            "{PRIVATE_BROADCAST_ADMISSION_PREFIX}.{}.{}",
            self.broadcast_id, self.listener_id
        )
    }

    pub(crate) fn from_routing_hint(value: &str) -> Option<Self> {
        let mut components = value.split('.');
        if components.next() != Some(PRIVATE_BROADCAST_ADMISSION_PREFIX) {
            return None;
        }
        let broadcast_id = components
            .next()
            .and_then(|value| uuid::Uuid::parse_str(value).ok())?;
        let listener_id = components
            .next()
            .and_then(|value| uuid::Uuid::parse_str(value).ok())?;
        if components.next().is_some() {
            return None;
        }
        Self::new(broadcast_id, listener_id)
    }

    pub(crate) fn broadcast_id(self) -> uuid::Uuid {
        self.broadcast_id
    }

    pub(crate) fn listener_id(self) -> uuid::Uuid {
        self.listener_id
    }
}

/// Aggregate-safe forwarding dependency state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForwardingHealth {
    Healthy,
    Degraded,
    Draining,
    Stopped,
}

/// Non-secret forwarding failures.  Inner TLS, token, and peer values are
/// intentionally not retained in `Display`/`Debug` strings.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GatewayForwardingError {
    #[error("private forwarding configuration is invalid")]
    InvalidConfiguration,
    #[error("private forwarding TLS material is invalid or unavailable")]
    TlsConfiguration,
    #[error("private forwarding token creation failed")]
    TokenCreation,
    #[error("private forwarding worker is unknown")]
    UnknownWorker,
    #[error("private forwarding call is pinned to another worker")]
    WorkerPinMismatch,
    #[error("private forwarding route already exists")]
    RouteAlreadyExists,
    #[error("private forwarding route is not active")]
    RouteNotActive,
    #[error("private forwarding admission capacity is exhausted")]
    CapacityExceeded,
    #[error("private forwarding runtime is draining")]
    Draining,
    #[error("private forwarding peer is unavailable")]
    PeerUnavailable,
    #[error("private forwarding authentication failed")]
    AuthenticationFailed,
    #[error("private forwarding signaling failed")]
    SignalingFailed,
    #[error("private forwarding media codec is unsupported")]
    UnsupportedCodec,
    #[error("private forwarding operation timed out")]
    Timeout,
    #[error("private forwarding queue is backpressured")]
    Backpressure,
    #[error("private forwarding route is closed")]
    Closed,
    #[error("private forwarding route is receive-only")]
    ReceiveOnly,
    #[error("private forwarding RTP packet is invalid")]
    InvalidRtp,
    #[error("private forwarding RTCP packet is invalid")]
    InvalidRtcp,
    #[error("private forwarding DataMessage is invalid")]
    InvalidDataMessage,
    #[error("private attachment admission was rejected")]
    AttachmentRejected,
}

/// Secret used only to mint and validate short-lived internal JWTs.
#[derive(Clone)]
pub struct PrivateTokenKey(Arc<Zeroizing<Vec<u8>>>);

impl PrivateTokenKey {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, GatewayForwardingError> {
        let bytes = bytes.into();
        if bytes.len() < MIN_TOKEN_KEY_BYTES {
            return Err(GatewayForwardingError::InvalidConfiguration);
        }
        Ok(Self(Arc::new(Zeroizing::new(bytes))))
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for PrivateTokenKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateTokenKey([redacted])")
    }
}

/// PEM files for one side of the mutually authenticated QUIC connection.
#[derive(Clone, Debug)]
pub struct MutualTlsFiles {
    pub certificate_chain: Vec<PathBuf>,
    pub private_key: PathBuf,
    /// Trust anchors for the opposite side.  An empty trust store is never
    /// replaced by system roots: private forwarding must be explicitly pinned.
    pub peer_ca_certificates: Vec<PathBuf>,
}

impl MutualTlsFiles {
    fn validate(&self) -> Result<(), GatewayForwardingError> {
        if self.certificate_chain.is_empty()
            || self.private_key.as_os_str().is_empty()
            || self.peer_ca_certificates.is_empty()
        {
            return Err(GatewayForwardingError::InvalidConfiguration);
        }
        Ok(())
    }
}

/// Resource and queue bounds shared by both role halves.
#[derive(Clone, Debug)]
pub struct PrivateForwardingLimits {
    pub max_active_routes: usize,
    pub max_peer_connections: usize,
    pub max_routes_per_peer: usize,
    pub media_queue_capacity: usize,
    pub reliable_queue_capacity: usize,
    pub inbound_queue_capacity: usize,
}

impl Default for PrivateForwardingLimits {
    fn default() -> Self {
        Self {
            max_active_routes: 2_000,
            max_peer_connections: 256,
            max_routes_per_peer: 512,
            media_queue_capacity: 10,
            reliable_queue_capacity: 64,
            inbound_queue_capacity: 64,
        }
    }
}

impl PrivateForwardingLimits {
    fn validate(&self) -> Result<(), GatewayForwardingError> {
        if self.max_active_routes == 0
            || self.max_peer_connections == 0
            || self.max_routes_per_peer == 0
            || self.media_queue_capacity == 0
            || self.reliable_queue_capacity == 0
            || self.inbound_queue_capacity == 0
            || self.max_routes_per_peer > self.max_active_routes
        {
            return Err(GatewayForwardingError::InvalidConfiguration);
        }
        Ok(())
    }
}

/// Bounded setup, refresh, health, and shutdown timings.
#[derive(Clone, Debug)]
pub struct PrivateForwardingTimeouts {
    pub connect: Duration,
    pub signaling: Duration,
    pub token_ttl: Duration,
    pub health_interval: Duration,
}

impl Default for PrivateForwardingTimeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(5),
            signaling: Duration::from_secs(5),
            token_ttl: Duration::from_secs(300),
            health_interval: Duration::from_secs(5),
        }
    }
}

impl PrivateForwardingTimeouts {
    fn validate(&self) -> Result<(), GatewayForwardingError> {
        if self.connect.is_zero()
            || self.signaling.is_zero()
            || self.health_interval.is_zero()
            || !(Duration::from_secs(60)..=Duration::from_secs(3_600)).contains(&self.token_ttl)
        {
            return Err(GatewayForwardingError::InvalidConfiguration);
        }
        Ok(())
    }
}

/// One exact private worker dial target.
#[derive(Clone, Debug)]
pub struct PrivateWorkerTarget {
    pub worker_id: WorkerId,
    /// DNS name or IP plus explicit UDP port, for example
    /// `worker-01.bridgefu.internal:9443`.
    pub endpoint: String,
    pub server_name: String,
}

/// Gateway-side forwarding configuration.
#[derive(Clone, Debug)]
pub struct GatewayForwardingConfig {
    pub gateway_id: String,
    pub bind: SocketAddr,
    pub tls: MutualTlsFiles,
    pub token_key: PrivateTokenKey,
    pub workers: Vec<PrivateWorkerTarget>,
    pub limits: PrivateForwardingLimits,
    pub timeouts: PrivateForwardingTimeouts,
}

/// Read-only classification of gateway teardown work that is still running.
/// This intentionally exposes counts rather than task handles or route IDs so
/// diagnostics remain aggregate-safe and cannot mutate lifecycle authority.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GatewayShutdownTaskSnapshot {
    pub lifecycle_failure_cleanup: usize,
    pub lifecycle_delivery: usize,
    pub source_cleanup: usize,
}

impl GatewayShutdownTaskSnapshot {
    #[must_use]
    pub const fn total(self) -> usize {
        self.lifecycle_failure_cleanup + self.lifecycle_delivery + self.source_cleanup
    }
}

impl GatewayForwardingConfig {
    fn validate(&self) -> Result<(), GatewayForwardingError> {
        validate_component_id(&self.gateway_id)?;
        self.tls.validate()?;
        self.limits.validate()?;
        self.timeouts.validate()?;
        if self.workers.is_empty()
            || self.workers.iter().any(|worker| {
                !valid_worker_authority(&worker.endpoint)
                    || worker.server_name.is_empty()
                    || worker.server_name.len() > 253
                    || worker.server_name.chars().any(char::is_control)
            })
        {
            return Err(GatewayForwardingError::InvalidConfiguration);
        }
        let mut seen = std::collections::HashSet::new();
        if self
            .workers
            .iter()
            .any(|worker| !seen.insert(worker.worker_id))
        {
            return Err(GatewayForwardingError::InvalidConfiguration);
        }
        Ok(())
    }
}

/// Worker-side private listener configuration.
#[derive(Clone, Debug)]
pub struct WorkerForwardingConfig {
    pub worker_id: WorkerId,
    pub bind: SocketAddr,
    pub tls: MutualTlsFiles,
    pub token_key: PrivateTokenKey,
    pub limits: PrivateForwardingLimits,
    pub timeouts: PrivateForwardingTimeouts,
}

impl WorkerForwardingConfig {
    fn validate(&self) -> Result<(), GatewayForwardingError> {
        self.tls.validate()?;
        self.limits.validate()?;
        self.timeouts.validate()
    }
}

/// Exact logical route.  The type prevents a public edge from accidentally
/// selecting a worker using untrusted packet or DataMessage contents.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct GatewayRouteKey {
    tenant_id: TenantId,
    call_id: CallId,
    leg_id: LegId,
    // Public/source routes have one active generation and keep the historical
    // `None` identity. Destination-side private egress must stage the next
    // generation beside the held current route during make-before-break.
    binding_generation: Option<BindingGeneration>,
}

impl GatewayRouteKey {
    #[must_use]
    pub fn new(tenant_id: TenantId, call_id: CallId, leg_id: LegId) -> Self {
        Self {
            tenant_id,
            call_id,
            leg_id,
            binding_generation: None,
        }
    }

    fn for_binding_generation(
        tenant_id: TenantId,
        call_id: CallId,
        leg_id: LegId,
        binding_generation: BindingGeneration,
    ) -> Self {
        Self {
            tenant_id,
            call_id,
            leg_id,
            binding_generation: Some(binding_generation),
        }
    }

    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub const fn call_id(&self) -> CallId {
        self.call_id
    }

    pub const fn leg_id(&self) -> LegId {
        self.leg_id
    }

    /// Generation discriminator for destination-side make-before-break
    /// routes. Public/source routes retain the historical unversioned key.
    pub const fn binding_generation(&self) -> Option<BindingGeneration> {
        self.binding_generation
    }

    fn call_key(&self) -> CallRouteKey {
        CallRouteKey {
            tenant_id: self.tenant_id.clone(),
            call_id: self.call_id,
        }
    }

    fn wire_session_id(&self) -> String {
        format!(
            "{WIRE_SESSION_PREFIX}.{}.{}.{}",
            URL_SAFE_NO_PAD.encode(self.tenant_id.as_str()),
            self.call_id,
            self.leg_id
        )
    }

    fn wire_connection_id(&self) -> String {
        format!("bf-conn-v1.{}", self.leg_id)
    }

    fn wire_stream_id(&self) -> String {
        format!("bf-stream-v1.{}", self.leg_id)
    }

    fn wire_conversation_id(&self) -> String {
        format!(
            "bf-conversation-v1.{}.{}",
            URL_SAFE_NO_PAD.encode(self.tenant_id.as_str()),
            self.call_id
        )
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct CallRouteKey {
    tenant_id: TenantId,
    call_id: CallId,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct PeerKey {
    worker_id: WorkerId,
    tenant_id: TenantId,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct WireRouteKey {
    sid: String,
    connid: String,
}

struct OpenedWireRoute {
    wire: WireRouteKey,
    conversation_id: String,
    stream_local_id: u16,
    attachment_receipt: Option<WorkerAttachmentAdmissionReceipt>,
    pending_attachment_guard: Option<PendingAttachmentGuard>,
}

/// Packet delivered from a pinned worker back to its public gateway leg.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ForwardedPacket {
    Rtp(Bytes),
    Rtcp(Bytes),
    /// Transport-neutral DTMF control received from the pinned worker.
    Dtmf {
        digits: String,
        duration_ms: u32,
    },
    Data(DataMessage),
}

fn validate_component_id(value: &str) -> Result<(), GatewayForwardingError> {
    let valid = !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte));
    if valid {
        Ok(())
    } else {
        Err(GatewayForwardingError::InvalidConfiguration)
    }
}

fn parse_wire_session(wire: &str) -> Result<(TenantId, CallId, LegId), GatewayForwardingError> {
    let mut parts = wire.split('.');
    if parts.next() != Some(WIRE_SESSION_PREFIX) {
        return Err(GatewayForwardingError::SignalingFailed);
    }
    let tenant = parts
        .next()
        .and_then(|encoded| URL_SAFE_NO_PAD.decode(encoded).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|tenant| TenantId::parse(tenant).ok())
        .ok_or(GatewayForwardingError::SignalingFailed)?;
    let call = parts
        .next()
        .and_then(|value| CallId::from_str(value).ok())
        .ok_or(GatewayForwardingError::SignalingFailed)?;
    let leg = parts
        .next()
        .and_then(|value| LegId::from_str(value).ok())
        .ok_or(GatewayForwardingError::SignalingFailed)?;
    if parts.next().is_some() {
        return Err(GatewayForwardingError::SignalingFailed);
    }
    Ok((tenant, call, leg))
}

fn parse_attachment_wire_session(
    wire: &str,
) -> Result<(TenantId, uuid::Uuid), GatewayForwardingError> {
    let mut parts = wire.split('.');
    if parts.next() != Some(WIRE_ATTACHMENT_SESSION_PREFIX) {
        return Err(GatewayForwardingError::SignalingFailed);
    }
    let tenant = parts
        .next()
        .and_then(|encoded| URL_SAFE_NO_PAD.decode(encoded).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|tenant| TenantId::parse(tenant).ok())
        .ok_or(GatewayForwardingError::SignalingFailed)?;
    let request_id = parts
        .next()
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
        .filter(|value| !value.is_nil())
        .ok_or(GatewayForwardingError::SignalingFailed)?;
    if parts.next().is_some() {
        return Err(GatewayForwardingError::SignalingFailed);
    }
    Ok((tenant, request_id))
}

fn private_egress_wire_session(
    admission: &PrivateEgressStreamAdmission,
) -> Result<String, GatewayForwardingError> {
    admission
        .validate(current_unix_time_ms())
        .map_err(map_private_egress_stream_error)?;
    Ok(format!(
        "{WIRE_EGRESS_SESSION_PREFIX}.{}.{}",
        URL_SAFE_NO_PAD.encode(admission.source.tenant_id.as_str()),
        admission.admission_id
    ))
}

fn parse_private_egress_wire_session(
    wire: &str,
) -> Result<(TenantId, uuid::Uuid), GatewayForwardingError> {
    let mut parts = wire.split('.');
    if parts.next() != Some(WIRE_EGRESS_SESSION_PREFIX) {
        return Err(GatewayForwardingError::SignalingFailed);
    }
    let tenant = parts
        .next()
        .and_then(|encoded| URL_SAFE_NO_PAD.decode(encoded).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|tenant| TenantId::parse(tenant).ok())
        .ok_or(GatewayForwardingError::SignalingFailed)?;
    let admission_id = parts
        .next()
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
        .filter(|value| !value.is_nil())
        .ok_or(GatewayForwardingError::SignalingFailed)?;
    if parts.next().is_some() {
        return Err(GatewayForwardingError::SignalingFailed);
    }
    Ok((tenant, admission_id))
}

fn private_broadcast_wire_session(
    broadcast_id: uuid::Uuid,
    listener_id: uuid::Uuid,
) -> Result<String, GatewayForwardingError> {
    if broadcast_id.is_nil() || listener_id.is_nil() {
        return Err(GatewayForwardingError::SignalingFailed);
    }
    Ok(format!(
        "{WIRE_BROADCAST_SESSION_PREFIX}.{broadcast_id}.{listener_id}"
    ))
}

fn parse_private_broadcast_wire_session(value: &str) -> Option<(uuid::Uuid, uuid::Uuid)> {
    let mut parts = value.split('.');
    if parts.next() != Some(WIRE_BROADCAST_SESSION_PREFIX) {
        return None;
    }
    let broadcast_id = parts
        .next()
        .and_then(|value| uuid::Uuid::parse_str(value).ok())?;
    let listener_id = parts
        .next()
        .and_then(|value| uuid::Uuid::parse_str(value).ok())?;
    if parts.next().is_some() || broadcast_id.is_nil() || listener_id.is_nil() {
        return None;
    }
    Some((broadcast_id, listener_id))
}

fn private_broadcast_listener_id(connection_id: &ConnectionId) -> Option<uuid::Uuid> {
    connection_id
        .as_str()
        .strip_prefix("bf-broadcast-conn-v1.")
        .and_then(|listener| uuid::Uuid::parse_str(listener).ok())
        .filter(|listener| !listener.is_nil())
}

#[derive(Serialize)]
struct GatewayTokenClaims<'a> {
    sub: &'a str,
    iss: &'static str,
    aud: String,
    tenant_id: &'a str,
    scope: &'static str,
    iat: u64,
    exp: u64,
    jti: String,
}

fn mint_gateway_token(
    key: &PrivateTokenKey,
    gateway_id: &str,
    worker_id: WorkerId,
    tenant_id: &TenantId,
    ttl: Duration,
) -> Result<String, GatewayForwardingError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| GatewayForwardingError::TokenCreation)?
        .as_secs();
    let exp = now
        .checked_add(ttl.as_secs())
        .ok_or(GatewayForwardingError::TokenCreation)?;
    let claims = GatewayTokenClaims {
        sub: gateway_id,
        iss: TOKEN_ISSUER,
        aud: worker_id.to_string(),
        tenant_id: tenant_id.as_str(),
        // One authenticated tenant-scoped peer carries both ordinary private
        // call routes and receive-only broadcast subscriptions.  The latter
        // is still constrained to the exact active listener generation by
        // `PrivateSubscriptionHandler`; this scope merely permits the UCTP
        // `stream.subscribe` command to reach that authority check.
        scope: "uctp:session uctp:data uctp:subscribe bridgefu:gateway-forward",
        iat: now,
        exp,
        jti: uuid::Uuid::new_v4().to_string(),
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(key.as_bytes()),
    )
    .map_err(|_| GatewayForwardingError::TokenCreation)
}

fn load_certificate_chain(
    paths: &[PathBuf],
) -> Result<Vec<CertificateDer<'static>>, GatewayForwardingError> {
    let mut certificates = Vec::new();
    for path in paths {
        let file = File::open(path).map_err(|_| GatewayForwardingError::TlsConfiguration)?;
        let mut reader = BufReader::new(file);
        let parsed = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| GatewayForwardingError::TlsConfiguration)?;
        certificates.extend(parsed);
    }
    if certificates.is_empty() {
        return Err(GatewayForwardingError::TlsConfiguration);
    }
    Ok(certificates)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, GatewayForwardingError> {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|_| GatewayForwardingError::TlsConfiguration)?;
    rustls_pemfile::private_key(&mut bytes.as_slice())
        .map_err(|_| GatewayForwardingError::TlsConfiguration)?
        .ok_or(GatewayForwardingError::TlsConfiguration)
}

fn load_roots(paths: &[PathBuf]) -> Result<RootCertStore, GatewayForwardingError> {
    let mut roots = RootCertStore::empty();
    for certificate in load_certificate_chain(paths)? {
        roots
            .add(certificate)
            .map_err(|_| GatewayForwardingError::TlsConfiguration)?;
    }
    if roots.is_empty() {
        return Err(GatewayForwardingError::TlsConfiguration);
    }
    Ok(roots)
}

fn build_client_tls(files: &MutualTlsFiles) -> Result<Arc<ClientConfig>, GatewayForwardingError> {
    files.validate()?;
    let mut config = ClientConfig::builder()
        .with_root_certificates(load_roots(&files.peer_ca_certificates)?)
        .with_client_auth_cert(
            load_certificate_chain(&files.certificate_chain)?,
            load_private_key(&files.private_key)?,
        )
        .map_err(|_| GatewayForwardingError::TlsConfiguration)?;
    config.alpn_protocols = vec![UCTP_RAW_QUIC_ALPN_BYTES.to_vec()];
    Ok(Arc::new(config))
}

fn build_server_tls(files: &MutualTlsFiles) -> Result<Arc<ServerConfig>, GatewayForwardingError> {
    files.validate()?;
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(load_roots(
        &files.peer_ca_certificates,
    )?))
    .build()
    .map_err(|_| GatewayForwardingError::TlsConfiguration)?;
    let mut config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            load_certificate_chain(&files.certificate_chain)?,
            load_private_key(&files.private_key)?,
        )
        .map_err(|_| GatewayForwardingError::TlsConfiguration)?;
    config.alpn_protocols = vec![UCTP_RAW_QUIC_ALPN_BYTES.to_vec()];
    Ok(Arc::new(config))
}

fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn validate_rtcp(packet: &[u8]) -> Result<(), GatewayForwardingError> {
    if packet.len() < 4 || (packet.len() & 3) != 0 {
        return Err(GatewayForwardingError::InvalidRtcp);
    }
    let mut offset = 0usize;
    while offset < packet.len() {
        if packet.len() - offset < 4
            || packet[offset] >> 6 != 2
            || !(192..=223).contains(&packet[offset + 1])
        {
            return Err(GatewayForwardingError::InvalidRtcp);
        }
        let words_minus_one = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
        let length = usize::from(words_minus_one)
            .checked_add(1)
            .and_then(|words| words.checked_mul(4))
            .ok_or(GatewayForwardingError::InvalidRtcp)?;
        if length < 4
            || offset
                .checked_add(length)
                .filter(|end| *end <= packet.len())
                .is_none()
        {
            return Err(GatewayForwardingError::InvalidRtcp);
        }
        offset += length;
    }
    Ok(())
}

fn rtp_payload_type(packet: &[u8]) -> Option<u8> {
    (packet.len() >= 2 && packet[0] >> 6 == 2).then(|| packet[1] & 0x7f)
}

fn valid_dtmf(digits: &str, duration_ms: u32) -> bool {
    !digits.is_empty()
        && digits.len() <= 32
        && (40..=6_000).contains(&duration_ms)
        && digits.bytes().all(|digit| {
            digit.is_ascii_digit() || matches!(digit, b'*' | b'#' | b'A'..=b'D' | b'a'..=b'd')
        })
}

struct PrivateSessionResolver {
    draining: Arc<AtomicBool>,
    broadcast_authority: Option<Arc<WorkerBroadcastSubscriptionAuthority>>,
    private_egress_admissions: Option<Arc<PrivateEgressStreamAdmissionRegistry>>,
}

impl SessionBindingResolver for PrivateSessionResolver {
    fn resolve_session(
        &self,
        principal: &rvoip_auth_core::AuthenticatedPrincipal,
        wire_session: &SessionId,
    ) -> Result<SessionId, ResourceBindingError> {
        if self.draining.load(Ordering::Acquire) {
            return Err(ResourceBindingError::unavailable("worker-draining"));
        }
        principal
            .require_scope(PRIVATE_FORWARD_SCOPE)
            .and_then(|_| principal.require_scope(UCTP_SESSION_SCOPE))
            .map_err(|_| ResourceBindingError::forbidden("forwarding-scope-required"))?;
        let principal_tenant = principal
            .tenant
            .as_deref()
            .ok_or_else(|| ResourceBindingError::forbidden("tenant-required"))?;
        let tenant = if let Ok((tenant, _, _)) = parse_wire_session(wire_session.as_str()) {
            Some(tenant)
        } else if let Ok((tenant, _)) = parse_attachment_wire_session(wire_session.as_str()) {
            Some(tenant)
        } else if let Ok((tenant, admission_id)) =
            parse_private_egress_wire_session(wire_session.as_str())
        {
            let authorized = self
                .private_egress_admissions
                .as_ref()
                .is_some_and(|registry| registry.authorizes_id(admission_id, tenant.as_str()));
            if !authorized {
                return Err(ResourceBindingError::forbidden(
                    "private-egress-admission-inactive",
                ));
            }
            // The full descriptor is validated in the routing-hint callback;
            // at this stage the opaque Session ID can only select an admission
            // that is present in this worker's bounded registry.
            Some(tenant)
        } else if let Some((broadcast_id, _)) =
            parse_private_broadcast_wire_session(wire_session.as_str())
        {
            if !self.broadcast_authority.as_ref().is_some_and(|authority| {
                authority.active_for_tenant(principal_tenant, &broadcast_id.to_string())
            }) {
                return Err(ResourceBindingError::forbidden(
                    "private-broadcast-inactive",
                ));
            }
            None
        } else {
            return Err(ResourceBindingError::forbidden("invalid-route-id"));
        };
        if tenant.is_some_and(|tenant| tenant.as_str() != principal_tenant) {
            return Err(ResourceBindingError::forbidden("route-tenant-mismatch"));
        }
        // The authenticated wire ID is already globally stable and contains
        // tenant, call, and leg.  Returning it unchanged lets the call engine
        // recover the exact attachment while rejecting cross-tenant aliases.
        Ok(wire_session.clone())
    }

    fn resolve_inbound_routing_hint(
        &self,
        principal: &rvoip_auth_core::AuthenticatedPrincipal,
        wire_session: &SessionId,
        intent: &str,
        capabilities_offer: &serde_json::Value,
    ) -> Result<Option<InboundRoutingHint>, ResourceBindingError> {
        if let Ok((tenant, admission_id)) = parse_private_egress_wire_session(wire_session.as_str())
        {
            principal
                .require_scope(PRIVATE_FORWARD_SCOPE)
                .and_then(|_| principal.require_scope(UCTP_SESSION_SCOPE))
                .map_err(|_| ResourceBindingError::forbidden("forwarding-scope-required"))?;
            if principal.tenant.as_deref() != Some(tenant.as_str())
                || intent != PRIVATE_EGRESS_STREAM_INTENT
            {
                return Err(ResourceBindingError::forbidden(
                    "private-egress-route-mismatch",
                ));
            }
            let routing_hint = capabilities_offer
                .as_object()
                .and_then(|capabilities| capabilities.get(PRIVATE_EGRESS_STREAM_CAPABILITY))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    ResourceBindingError::forbidden("private-egress-routing-hint-required")
                })?;
            let admission =
                PrivateEgressStreamAdmission::from_routing_hint(routing_hint).map_err(|_| {
                    ResourceBindingError::forbidden("invalid-private-egress-routing-hint")
                })?;
            if admission.admission_id != admission_id
                || admission.source.tenant_id != tenant
                || !self
                    .private_egress_admissions
                    .as_ref()
                    .is_some_and(|registry| registry.authorizes(&admission))
            {
                return Err(ResourceBindingError::forbidden(
                    "private-egress-admission-mismatch",
                ));
            }
            return InboundRoutingHint::new(routing_hint.to_owned())
                .map(Some)
                .map_err(|_| {
                    ResourceBindingError::forbidden("invalid-private-egress-routing-hint")
                });
        }
        if let Some((broadcast_id, wire_listener_id)) =
            parse_private_broadcast_wire_session(wire_session.as_str())
        {
            if intent != PRIVATE_BROADCAST_INTENT {
                return Err(ResourceBindingError::forbidden(
                    "private-broadcast-route-mismatch",
                ));
            }
            principal
                .require_scope(PRIVATE_FORWARD_SCOPE)
                .and_then(|_| principal.require_scope(UCTP_SESSION_SCOPE))
                .map_err(|_| ResourceBindingError::forbidden("forwarding-scope-required"))?;
            let capability = capabilities_offer
                .as_object()
                .and_then(|capabilities| capabilities.get(PRIVATE_BROADCAST_CAPABILITY))
                .and_then(serde_json::Value::as_object)
                .ok_or_else(|| {
                    ResourceBindingError::forbidden("private-broadcast-route-mismatch")
                })?;
            let broadcast_id = broadcast_id.to_string();
            let tenant_id = capability
                .get("tenant_id")
                .and_then(serde_json::Value::as_str)
                .filter(|tenant| Some(*tenant) == principal.tenant.as_deref());
            let listener_id = capability
                .get("listener_id")
                .and_then(serde_json::Value::as_str)
                .and_then(|listener| uuid::Uuid::parse_str(listener).ok())
                .filter(|listener| *listener == wire_listener_id);
            let worker_fence = capability
                .get("worker_fence")
                .and_then(serde_json::Value::as_i64)
                .filter(|fence| *fence > 0);
            let grant_generation = capability
                .get("grant_generation")
                .and_then(serde_json::Value::as_str)
                .and_then(|generation| uuid::Uuid::parse_str(generation).ok())
                .filter(|generation| !generation.is_nil());
            if capability
                .get("broadcast_id")
                .and_then(serde_json::Value::as_str)
                != Some(broadcast_id.as_str())
            {
                return Err(ResourceBindingError::forbidden(
                    "private-broadcast-route-mismatch",
                ));
            }
            let Some(((tenant_id, listener_id), (worker_fence, grant_generation))) = tenant_id
                .zip(listener_id)
                .zip(worker_fence.zip(grant_generation))
            else {
                return Err(ResourceBindingError::forbidden(
                    "private-broadcast-route-mismatch",
                ));
            };
            if !self.broadcast_authority.as_ref().is_some_and(|authority| {
                authority.authorize_and_bind(
                    tenant_id,
                    &broadcast_id,
                    listener_id,
                    worker_fence,
                    grant_generation,
                )
            }) {
                return Err(ResourceBindingError::forbidden(
                    "private-broadcast-route-mismatch",
                ));
            }
            let request = WorkerBroadcastAdmissionRequest::new(
                broadcast_id.parse().map_err(|_| {
                    ResourceBindingError::forbidden("private-broadcast-route-mismatch")
                })?,
                listener_id,
            )
            .ok_or_else(|| ResourceBindingError::forbidden("private-broadcast-route-mismatch"))?;
            let routing_hint = InboundRoutingHint::new(request.routing_hint()).map_err(|_| {
                if let Some(authority) = &self.broadcast_authority {
                    authority.unbind_listener(&broadcast_id, listener_id);
                }
                ResourceBindingError::forbidden("private-broadcast-route-mismatch")
            })?;
            return Ok(Some(routing_hint));
        }
        let Ok((tenant, session_request_id)) = parse_attachment_wire_session(wire_session.as_str())
        else {
            return Ok(None);
        };
        principal
            .require_scope(PRIVATE_FORWARD_SCOPE)
            .and_then(|_| principal.require_scope(UCTP_SESSION_SCOPE))
            .map_err(|_| ResourceBindingError::forbidden("forwarding-scope-required"))?;
        if principal.tenant.as_deref() != Some(tenant.as_str())
            || intent != PRIVATE_ATTACHMENT_INTENT
        {
            return Err(ResourceBindingError::forbidden(
                "private-attachment-route-mismatch",
            ));
        }
        let routing_hint = capabilities_offer
            .as_object()
            .and_then(|capabilities| capabilities.get(PRIVATE_ATTACHMENT_CAPABILITY))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ResourceBindingError::forbidden("attachment-routing-hint-required"))?;
        let request = WorkerAttachmentAdmissionRequest::from_routing_hint(routing_hint.to_owned())
            .map_err(|_| ResourceBindingError::forbidden("invalid-attachment-routing-hint"))?;
        if request.request_id() != session_request_id {
            return Err(ResourceBindingError::forbidden(
                "attachment-request-id-mismatch",
            ));
        }
        InboundRoutingHint::new(routing_hint.to_owned())
            .map(Some)
            .map_err(|_| ResourceBindingError::forbidden("invalid-attachment-routing-hint"))
    }

    fn reauthorize_session(
        &self,
        principal: &rvoip_auth_core::AuthenticatedPrincipal,
        wire_session: &SessionId,
        canonical_session: &SessionId,
    ) -> Result<(), ResourceBindingError> {
        let resolved = self.resolve_session(principal, wire_session)?;
        if &resolved != canonical_session {
            return Err(ResourceBindingError::forbidden(
                "private-session-ownership-changed",
            ));
        }
        Ok(())
    }

    fn reauthorize_connection(
        &self,
        principal: &rvoip_auth_core::AuthenticatedPrincipal,
        wire_session: &SessionId,
        canonical_session: &SessionId,
        wire_connection: &ConnectionId,
        _core_connection: &ConnectionId,
    ) -> Result<(), ResourceBindingError> {
        self.reauthorize_session(principal, wire_session, canonical_session)?;
        if let Some((broadcast, listener)) =
            parse_private_broadcast_wire_session(wire_session.as_str())
        {
            let canonical_broadcast = broadcast.to_string();
            if private_broadcast_listener_id(wire_connection) != Some(listener)
                || !self.broadcast_authority.as_ref().is_some_and(|authority| {
                    authority.revalidate_listener(&canonical_broadcast, listener)
                })
            {
                return Err(ResourceBindingError::forbidden(
                    "private-broadcast-connection-mismatch",
                ));
            }
        }
        Ok(())
    }
}

struct PrivateSubscriptionHandler {
    inner: Arc<OrchestratorSubscriptionHandler>,
    broadcast_authority: Option<Arc<WorkerBroadcastSubscriptionAuthority>>,
}

impl SubscriptionHandler for PrivateSubscriptionHandler {
    fn subscribe(
        &self,
        sid: &SessionId,
        subscriber: &ConnectionId,
        request: &stream::StreamSubscribe,
    ) -> SubscriptionOutcome {
        let Some((broadcast_id, broadcast_listener)) =
            parse_private_broadcast_wire_session(sid.as_str())
        else {
            return SubscriptionOutcome::reject(403, "private-broadcast-not-authorized");
        };
        let canonical_session = SessionId::from_string(broadcast_id.to_string());
        let authorized = self.broadcast_authority.as_ref().is_some_and(|authority| {
            authority.revalidate_listener(canonical_session.as_str(), broadcast_listener)
        });
        let exact_stream = request.subscriptions.len() == 1
            && request.subscriptions[0].strm_id.as_deref() == Some(BROADCAST_STREAM_ID)
            && request.subscriptions[0].from_participant.is_none()
            && request.subscriptions[0].kinds.is_empty();
        if !authorized || !exact_stream {
            return SubscriptionOutcome::reject(403, "private-broadcast-not-authorized");
        }
        let outcome = self
            .inner
            .subscribe(&canonical_session, subscriber, request);
        if !matches!(&outcome, SubscriptionOutcome::Ok) {
            if let Some(authority) = self.broadcast_authority.as_ref() {
                authority.unbind_listener(canonical_session.as_str(), broadcast_listener);
            }
        }
        outcome
    }

    fn unsubscribe(
        &self,
        sid: &SessionId,
        subscriber: &ConnectionId,
        request: &stream::StreamUnsubscribe,
    ) -> SubscriptionOutcome {
        let Some((broadcast_id, listener)) = parse_private_broadcast_wire_session(sid.as_str())
        else {
            return SubscriptionOutcome::reject(403, "private-broadcast-not-authorized");
        };
        let canonical_session = SessionId::from_string(broadcast_id.to_string());
        let authorized = self.broadcast_authority.as_ref().is_some_and(|authority| {
            authority.revalidate_listener(canonical_session.as_str(), listener)
        }) && request.strm_ids.as_slice() == [BROADCAST_STREAM_ID];
        if !authorized {
            return SubscriptionOutcome::reject(403, "private-broadcast-not-authorized");
        }
        self.inner
            .unsubscribe(&canonical_session, subscriber, request)
    }

    fn register_publisher(&self, info: PublisherInfo<'_>) {
        self.inner.register_publisher(info);
    }

    fn unregister_publisher(&self, sid: &SessionId, strm_id: &str, publisher: &ConnectionId) {
        self.inner.unregister_publisher(sid, strm_id, publisher);
    }

    fn unregister_connection(&self, sid: &SessionId, connid: &ConnectionId) {
        if let Some((broadcast_id, listener)) = parse_private_broadcast_wire_session(sid.as_str()) {
            if let Some(authority) = &self.broadcast_authority {
                authority.unbind_listener(&broadcast_id.to_string(), listener);
            }
            self.inner
                .unregister_connection(&SessionId::from_string(broadcast_id.to_string()), connid);
            return;
        }
        self.inner.unregister_connection(sid, connid);
    }
}

/// Worker-side UCTP listener installed into the worker's existing rvoip
/// Orchestrator.  The Orchestrator receives normal authenticated Connection,
/// MediaStream, and DataMessage events; no Bridgefu-private event bus is added.
pub struct WorkerForwardingRuntime {
    worker_id: WorkerId,
    endpoint: Arc<Endpoint>,
    adapter: Arc<UctpQuicAdapter>,
    draining: Arc<AtomicBool>,
    health: watch::Sender<ForwardingHealth>,
}

impl fmt::Debug for WorkerForwardingRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkerForwardingRuntime")
            .field("worker_id", &self.worker_id)
            .field("local_addr", &self.local_addr().ok())
            .field("draining", &self.draining.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl WorkerForwardingRuntime {
    pub async fn start(
        config: WorkerForwardingConfig,
        orchestrator: Arc<Orchestrator>,
    ) -> Result<Arc<Self>, GatewayForwardingError> {
        Self::start_inner(config, orchestrator, None, None).await
    }

    pub async fn start_with_broadcast_authority(
        config: WorkerForwardingConfig,
        orchestrator: Arc<Orchestrator>,
        broadcast_authority: Arc<WorkerBroadcastSubscriptionAuthority>,
    ) -> Result<Arc<Self>, GatewayForwardingError> {
        Self::start_inner(config, orchestrator, Some(broadcast_authority), None).await
    }

    /// Start a worker listener that can admit generation-bound destination
    /// media Connections in addition to ordinary source attachments. Merely
    /// installing the registry does not advertise SIP/WebRTC egress; a worker
    /// proxy owner must still reserve and consume every exact admission.
    pub async fn start_with_private_egress_admissions(
        config: WorkerForwardingConfig,
        orchestrator: Arc<Orchestrator>,
        private_egress_admissions: Arc<PrivateEgressStreamAdmissionRegistry>,
    ) -> Result<Arc<Self>, GatewayForwardingError> {
        if private_egress_admissions.worker().worker_id != config.worker_id {
            return Err(GatewayForwardingError::InvalidConfiguration);
        }
        Self::start_inner(config, orchestrator, None, Some(private_egress_admissions)).await
    }

    /// Start the production split listener with both broadcast authority and
    /// exact private-egress destination admission installed. Keeping this as
    /// one constructor prevents a process role from accidentally selecting
    /// one admission resolver and silently dropping the other.
    pub async fn start_with_broadcast_and_private_egress(
        config: WorkerForwardingConfig,
        orchestrator: Arc<Orchestrator>,
        broadcast_authority: Arc<WorkerBroadcastSubscriptionAuthority>,
        private_egress_admissions: Arc<PrivateEgressStreamAdmissionRegistry>,
    ) -> Result<Arc<Self>, GatewayForwardingError> {
        if private_egress_admissions.worker().worker_id != config.worker_id {
            return Err(GatewayForwardingError::InvalidConfiguration);
        }
        Self::start_inner(
            config,
            orchestrator,
            Some(broadcast_authority),
            Some(private_egress_admissions),
        )
        .await
    }

    async fn start_inner(
        config: WorkerForwardingConfig,
        orchestrator: Arc<Orchestrator>,
        broadcast_authority: Option<Arc<WorkerBroadcastSubscriptionAuthority>>,
        private_egress_admissions: Option<Arc<PrivateEgressStreamAdmissionRegistry>>,
    ) -> Result<Arc<Self>, GatewayForwardingError> {
        config.validate()?;
        install_crypto_provider();

        let endpoint = Arc::new(
            make_server_endpoint(
                config.bind,
                build_server_tls(&config.tls)?,
                TransportConfig::default(),
            )
            .map_err(|_| GatewayForwardingError::TlsConfiguration)?,
        );
        let mut alpn = dispatch_by_alpn(Arc::clone(&endpoint), &[UCTP_RAW_QUIC_ALPN_BYTES])
            .map_err(|_| GatewayForwardingError::PeerUnavailable)?;
        let accept_rx = alpn
            .take(UCTP_RAW_QUIC_ALPN_BYTES)
            .ok_or(GatewayForwardingError::PeerUnavailable)?;

        let validator: Arc<dyn BearerValidator> =
            JwtValidator::from_hmac_secret(config.token_key.as_bytes())
                .with_issuer([TOKEN_ISSUER])
                .with_audience([config.worker_id.to_string()])
                .with_required_jti()
                .into_arc();
        let draining = Arc::new(AtomicBool::new(false));
        let resolver: Arc<dyn SessionBindingResolver> = Arc::new(PrivateSessionResolver {
            draining: Arc::clone(&draining),
            broadcast_authority: broadcast_authority.clone(),
            private_egress_admissions,
        });
        let caps = UctpCoordinatorCaps {
            authentication_deadline: config.timeouts.connect,
            signaling_send_timeout: config.timeouts.signaling,
            max_sessions_per_peer: config.limits.max_routes_per_peer,
            max_connections_per_peer: config.limits.max_routes_per_peer,
            max_streams_per_connection: 1,
            ..UctpCoordinatorCaps::default()
        };

        let subscription_handler = Arc::new(PrivateSubscriptionHandler {
            inner: OrchestratorSubscriptionHandler::with_accepted_codecs(
                Arc::clone(&orchestrator),
                orchestrator.publisher_registry(),
                ["opus"],
            ),
            broadcast_authority,
        });
        let mut adapter_config = UctpQuicConfig::new(Arc::clone(&endpoint), accept_rx, validator)
            .with_coordinator_caps(caps)
            .with_session_binding_resolver(resolver)
            .with_subscription_handler(subscription_handler)
            .with_orchestrator(Arc::clone(&orchestrator));
        adapter_config.max_concurrent_connections = config.limits.max_peer_connections;
        let adapter = UctpQuicAdapter::new(adapter_config)
            .await
            .map_err(|_| GatewayForwardingError::PeerUnavailable)?;
        orchestrator
            .register(Arc::clone(&adapter) as Arc<dyn ConnectionAdapter>)
            .map_err(|_| GatewayForwardingError::PeerUnavailable)?;

        let (health, _) = watch::channel(ForwardingHealth::Healthy);
        metrics::gauge!("bridgefu_private_forwarding_worker_ready").set(1.0);
        Ok(Arc::new(Self {
            worker_id: config.worker_id,
            endpoint,
            adapter,
            draining,
            health,
        }))
    }

    pub fn local_addr(&self) -> Result<SocketAddr, GatewayForwardingError> {
        self.endpoint
            .local_addr()
            .map_err(|_| GatewayForwardingError::PeerUnavailable)
    }

    pub const fn worker_id(&self) -> WorkerId {
        self.worker_id
    }

    pub fn adapter(&self) -> Arc<UctpQuicAdapter> {
        Arc::clone(&self.adapter)
    }

    pub fn subscribe_health(&self) -> watch::Receiver<ForwardingHealth> {
        self.health.subscribe()
    }

    /// Stop admitting new Sessions while existing Connections remain live.
    pub fn begin_drain(&self) {
        if !self.draining.swap(true, Ordering::AcqRel) {
            self.health.send_replace(ForwardingHealth::Draining);
            metrics::gauge!("bridgefu_private_forwarding_worker_ready").set(0.0);
        }
    }

    /// Close the QUIC endpoint after the call engine has drained active calls.
    pub async fn shutdown(&self, timeout: Duration) -> Result<(), GatewayForwardingError> {
        self.begin_drain();
        self.endpoint
            .close(quinn::VarInt::from_u32(0), b"bridgefu-worker-drain");
        tokio::time::timeout(timeout, self.endpoint.wait_idle())
            .await
            .map_err(|_| GatewayForwardingError::Timeout)?;
        self.health.send_replace(ForwardingHealth::Stopped);
        Ok(())
    }
}

/// Consume one exact private-egress routing hint and publish the resulting
/// destination Connection/MediaStream to the worker reservation owner. This
/// helper is intentionally separate from ordinary public attachment
/// consumption: it never creates or selects a call and cannot change either
/// leg generation.
pub async fn admit_private_egress_worker_connection(
    mut admission_ticket: rvoip_core::InboundAdmission,
    orchestrator: Arc<Orchestrator>,
    worker: Arc<WorkerForwardingRuntime>,
    registry: Arc<PrivateEgressStreamAdmissionRegistry>,
    session_id: SessionId,
    timeout: Duration,
) -> Result<PrivateEgressWorkerConnection, GatewayForwardingError> {
    use rvoip_core::adapter::RejectReason;
    use rvoip_core::commands::InboundAction;
    use rvoip_core::connection::Transport;
    use rvoip_core::ids::ParticipantId;

    if timeout.is_zero()
        || admission_ticket.transport() != Transport::Quic
        || registry.worker().worker_id != worker.worker_id()
    {
        let _ = admission_ticket.reject(RejectReason::Forbidden).await;
        return Err(GatewayForwardingError::AttachmentRejected);
    }
    let connection_id = admission_ticket.connection_id().clone();
    let principal = admission_ticket
        .authenticated_principal()
        .map_err(|_| GatewayForwardingError::AuthenticationFailed)?;
    principal
        .require_scope(PRIVATE_FORWARD_SCOPE)
        .and_then(|_| principal.require_scope(UCTP_SESSION_SCOPE))
        .map_err(|_| GatewayForwardingError::AuthenticationFailed)?;
    let mut context = admission_ticket
        .take_inbound_context()
        .map_err(|_| GatewayForwardingError::AttachmentRejected)?
        .ok_or(GatewayForwardingError::AttachmentRejected)?;
    if !context.is_bound_to(&connection_id, Transport::Quic, &principal) {
        let _ = admission_ticket.reject(RejectReason::Forbidden).await;
        return Err(GatewayForwardingError::AttachmentRejected);
    }
    let hint = context
        .take_routing_hint()
        .map(|hint| hint.into_secret())
        .ok_or(GatewayForwardingError::AttachmentRejected)?;
    let stream_admission = PrivateEgressStreamAdmission::from_routing_hint(&hint)
        .map_err(map_private_egress_stream_error)?;
    if principal.tenant.as_deref() != Some(stream_admission.source.tenant_id.as_str())
        || !registry.authorizes(&stream_admission)
    {
        let _ = admission_ticket.reject(RejectReason::Forbidden).await;
        return Err(GatewayForwardingError::AttachmentRejected);
    }
    let deadline = tokio::time::Instant::now() + timeout;
    if !matches!(
        tokio::time::timeout_at(deadline, admission_ticket.accept()).await,
        Ok(Ok(()))
    ) {
        return Err(GatewayForwardingError::SignalingFailed);
    }
    if !matches!(
        tokio::time::timeout_at(
            deadline,
            orchestrator.route_inbound_connection(
                connection_id.clone(),
                InboundAction::Accept {
                    session_id,
                    participant_id: ParticipantId::new(),
                },
            ),
        )
        .await,
        Ok(Ok(()))
    ) {
        let _ = orchestrator
            .end_connection(connection_id, rvoip_core::adapter::EndReason::Cancelled)
            .await;
        return Err(GatewayForwardingError::SignalingFailed);
    }
    let stream = loop {
        if let Ok(streams) = worker.adapter().streams(connection_id.clone()).await {
            if let Some(stream) = streams
                .into_iter()
                .find(|stream| stream.kind() == rvoip_core::stream::StreamKind::Audio)
            {
                break stream;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            let _ = orchestrator
                .end_connection(connection_id, rvoip_core::adapter::EndReason::Timeout)
                .await;
            return Err(GatewayForwardingError::Timeout);
        }
        tokio::task::yield_now().await;
    };
    if stream.codec() != stream_admission.codec {
        let _ = orchestrator
            .end_connection(
                connection_id,
                rvoip_core::adapter::EndReason::Failed {
                    detail: "private egress codec mismatch".into(),
                },
            )
            .await;
        return Err(GatewayForwardingError::UnsupportedCodec);
    }
    registry
        .admit(&stream_admission, connection_id, stream)
        .map_err(map_private_egress_stream_error)
}

struct TokenMinter {
    key: PrivateTokenKey,
    gateway_id: String,
    ttl: Duration,
}

impl TokenMinter {
    fn mint(
        &self,
        worker_id: WorkerId,
        tenant_id: &TenantId,
    ) -> Result<String, GatewayForwardingError> {
        mint_gateway_token(&self.key, &self.gateway_id, worker_id, tenant_id, self.ttl)
    }
}

#[derive(Clone)]
struct WorkerTargetRuntime {
    worker_id: WorkerId,
    endpoint: String,
    server_name: String,
}

impl From<&PrivateWorkerTarget> for WorkerTargetRuntime {
    fn from(value: &PrivateWorkerTarget) -> Self {
        Self {
            worker_id: value.worker_id,
            endpoint: value.endpoint.clone(),
            server_name: value.server_name.clone(),
        }
    }
}

#[derive(Debug)]
struct PendingRtpDatagram {
    received_at: Instant,
    packet: Bytes,
}

/// A tiny, per-peer reorder buffer for the one QUIC ordering gap UCTP cannot
/// avoid: a publisher DATAGRAM can overtake the reliable `stream.opened`
/// envelope that announces its dynamically allocated local stream ID.
///
/// It keeps only the newest complete RTP packet per unannounced ID. Both the
/// ID count and packet size are bounded, entries expire quickly, and callers
/// only insert while an active broadcast route is awaiting that announcement.
#[derive(Debug)]
struct PendingDatagrams {
    by_stream: HashMap<u16, PendingRtpDatagram>,
    fifo: VecDeque<(u16, Instant)>,
    max_streams: usize,
    ttl: Duration,
}

const DYNAMIC_STREAM_DISABLED: u8 = 0;
const DYNAMIC_STREAM_AWAITING: u8 = 1;
const DYNAMIC_STREAM_REGISTERED: u8 = 2;
const DYNAMIC_STREAM_CLOSED: u8 = 3;

/// One-shot state for the additional media stream created by a broadcast
/// subscription. A route can transition from awaiting to registered once;
/// close is terminal from every state.
struct DynamicBroadcastStreamState(AtomicU8);

impl DynamicBroadcastStreamState {
    fn disabled() -> Self {
        Self(AtomicU8::new(DYNAMIC_STREAM_DISABLED))
    }

    fn awaiting() -> Self {
        Self(AtomicU8::new(DYNAMIC_STREAM_AWAITING))
    }

    fn is_awaiting(&self) -> bool {
        self.0.load(Ordering::Acquire) == DYNAMIC_STREAM_AWAITING
    }

    fn claim(&self) -> bool {
        self.0
            .compare_exchange(
                DYNAMIC_STREAM_AWAITING,
                DYNAMIC_STREAM_REGISTERED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    fn close(&self) {
        self.0.store(DYNAMIC_STREAM_CLOSED, Ordering::Release);
    }

    #[cfg(test)]
    fn is_closed(&self) -> bool {
        self.0.load(Ordering::Acquire) == DYNAMIC_STREAM_CLOSED
    }
}

impl PendingDatagrams {
    fn new(max_routes_per_peer: usize, signaling_timeout: Duration) -> Self {
        Self {
            by_stream: HashMap::new(),
            fifo: VecDeque::new(),
            max_streams: max_routes_per_peer.clamp(1, MAX_PENDING_STREAMS_HARD),
            ttl: signaling_timeout.min(Duration::from_secs(1)),
        }
    }

    fn expire(&mut self, now: Instant) -> usize {
        let mut expired = 0usize;
        while let Some((stream_local_id, inserted_at)) = self.fifo.front().copied() {
            if now.saturating_duration_since(inserted_at) < self.ttl {
                break;
            }
            self.fifo.pop_front();
            let current = self
                .by_stream
                .get(&stream_local_id)
                .is_some_and(|pending| pending.received_at == inserted_at);
            if current {
                self.by_stream.remove(&stream_local_id);
                expired += 1;
            }
        }
        expired
    }

    fn insert(&mut self, stream_local_id: u16, packet: Bytes, now: Instant) -> bool {
        if stream_local_id == 0 || packet.len() > MAX_PENDING_RTP_BYTES {
            return false;
        }
        self.expire(now);
        if let Some(pending) = self.by_stream.get_mut(&stream_local_id) {
            // Keep the original, non-extendable expiry while retaining the
            // newest media packet. A hot unknown ID therefore cannot grow the
            // FIFO or keep itself alive indefinitely.
            pending.packet = packet;
            return true;
        }
        if self.by_stream.len() >= self.max_streams {
            return false;
        }
        self.by_stream.insert(
            stream_local_id,
            PendingRtpDatagram {
                received_at: now,
                packet,
            },
        );
        self.fifo.push_back((stream_local_id, now));
        true
    }

    fn take(&mut self, stream_local_id: u16, now: Instant) -> Option<Bytes> {
        self.expire(now);
        let packet = self
            .by_stream
            .remove(&stream_local_id)
            .map(|pending| pending.packet);
        if packet.is_some() {
            self.fifo
                .retain(|(queued_stream_id, _)| *queued_stream_id != stream_local_id);
        }
        packet
    }

    fn clear(&mut self) -> usize {
        let cleared = self.by_stream.len();
        self.by_stream.clear();
        self.fifo.clear();
        cleared
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.by_stream.len()
    }
}

/// Receipt-derived authority for one provisional attachment. It exists only
/// between the worker's durable consume acknowledgement and promotion of the
/// same exact wire route into the public gateway route table.
struct PendingAttachmentAdmission {
    wire: WireRouteKey,
    conversation_id: String,
    request_id: uuid::Uuid,
    tenant_id: TenantId,
    expected_worker: WorkerLease,
    response: Mutex<
        Option<oneshot::Sender<Result<WorkerAttachmentAdmissionReceipt, GatewayForwardingError>>>,
    >,
    authority: Mutex<Option<PrivateEgressRouteAuthority>>,
    active: AtomicBool,
}

struct PendingAttachmentGuard {
    peer: Weak<WorkerPeer>,
    wire: WireRouteKey,
    armed: bool,
}

impl PendingAttachmentGuard {
    fn new(peer: &Arc<WorkerPeer>, wire: WireRouteKey) -> Self {
        Self {
            peer: Arc::downgrade(peer),
            wire,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PendingAttachmentGuard {
    fn drop(&mut self) {
        if self.armed {
            if let Some(peer) = self.peer.upgrade() {
                peer.revoke_pending_attachment(&self.wire, GatewayForwardingError::Closed);
            }
        }
    }
}

impl PendingAttachmentAdmission {
    fn new(
        wire: WireRouteKey,
        conversation_id: String,
        request_id: uuid::Uuid,
        tenant_id: TenantId,
        expected_worker: WorkerLease,
    ) -> (
        Arc<Self>,
        oneshot::Receiver<Result<WorkerAttachmentAdmissionReceipt, GatewayForwardingError>>,
    ) {
        let (response, receiver) = oneshot::channel();
        (
            Arc::new(Self {
                wire,
                conversation_id,
                request_id,
                tenant_id,
                expected_worker,
                response: Mutex::new(Some(response)),
                authority: Mutex::new(None),
                active: AtomicBool::new(true),
            }),
            receiver,
        )
    }

    fn receive_receipt(
        &self,
        cid: Option<&str>,
        message: DataMessage,
    ) -> Result<WorkerAttachmentAdmissionReceipt, GatewayForwardingError> {
        if !self.active.load(Ordering::Acquire) || cid != Some(self.conversation_id.as_str()) {
            return Err(GatewayForwardingError::AttachmentRejected);
        }
        let response = WorkerAttachmentAdmissionResponse::from_data_message(message)
            .map_err(map_attachment_error)?;
        let receipt = response
            .into_receipt(self.request_id, self.expected_worker)
            .map_err(|_| GatewayForwardingError::AttachmentRejected)?;
        if receipt.tenant_id != self.tenant_id || receipt.worker != self.expected_worker {
            return Err(GatewayForwardingError::AttachmentRejected);
        }
        let authority = PrivateEgressRouteAuthority {
            worker: receipt.worker,
            source: PrivateEgressSource {
                tenant_id: receipt.tenant_id.clone(),
                call_id: receipt.call_id,
                leg_id: receipt.leg_id,
                binding_generation: receipt.binding_generation,
            },
        };
        {
            let mut retained = self
                .authority
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if retained.is_some() {
                return Err(GatewayForwardingError::AttachmentRejected);
            }
            *retained = Some(authority);
        }
        let sender = self
            .response
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .ok_or(GatewayForwardingError::AttachmentRejected)?;
        if sender.send(Ok(receipt.clone())).is_err() {
            return Err(GatewayForwardingError::Closed);
        }
        Ok(receipt)
    }

    fn authority(&self) -> Option<PrivateEgressRouteAuthority> {
        self.active
            .load(Ordering::Acquire)
            .then(|| {
                self.authority
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone()
            })
            .flatten()
    }

    fn authority_for(
        &self,
        command: &PrivateEgressCommand,
    ) -> Result<PrivateEgressRouteAuthority, GatewayForwardingError> {
        let authority = self
            .authority()
            .ok_or(GatewayForwardingError::RouteNotActive)?;
        if command.worker != authority.worker || command.source != authority.source {
            return Err(GatewayForwardingError::AttachmentRejected);
        }
        Ok(authority)
    }

    fn matches_authority(&self, worker: WorkerLease, source: &PrivateEgressSource) -> bool {
        self.authority()
            .is_some_and(|authority| authority.worker == worker && authority.source == *source)
    }

    fn promote(
        &self,
        receipt: &WorkerAttachmentAdmissionReceipt,
    ) -> Result<(), GatewayForwardingError> {
        let expected = PrivateEgressRouteAuthority {
            worker: receipt.worker,
            source: PrivateEgressSource {
                tenant_id: receipt.tenant_id.clone(),
                call_id: receipt.call_id,
                leg_id: receipt.leg_id,
                binding_generation: receipt.binding_generation,
            },
        };
        if self.authority().as_ref() != Some(&expected)
            || !self.active.swap(false, Ordering::AcqRel)
        {
            return Err(GatewayForwardingError::AttachmentRejected);
        }
        self.authority
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        Ok(())
    }

    fn revoke(&self, error: GatewayForwardingError) {
        self.active.store(false, Ordering::Release);
        self.authority
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(sender) = self
            .response
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            let _ = sender.send(Err(error));
        }
    }
}

struct WorkerPeer {
    key: PeerKey,
    gateway_id: String,
    client: Arc<UctpQuicClient>,
    pending_opens: DashMap<WireRouteKey, oneshot::Sender<Result<u16, GatewayForwardingError>>>,
    pending_accepts: DashMap<
        String,
        (
            WireRouteKey,
            oneshot::Sender<Result<(), GatewayForwardingError>>,
        ),
    >,
    pending_admissions: DashMap<WireRouteKey, Arc<PendingAttachmentAdmission>>,
    pending_replies: DashMap<String, oneshot::Sender<Result<(), GatewayForwardingError>>>,
    routes_by_wire: DashMap<WireRouteKey, Weak<RouteInner>>,
    routes_by_local: DashMap<u16, Weak<RouteInner>>,
    pending_datagrams: Mutex<PendingDatagrams>,
    route_capacity: Arc<Semaphore>,
    cancel: CancellationToken,
    closed: AtomicBool,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    owner: Weak<GatewayForwarderInner>,
}

impl fmt::Debug for WorkerPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkerPeer")
            .field("worker_id", &self.key.worker_id)
            .field("tenant", &self.key.tenant_id)
            .field("closed", &self.closed.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl WorkerPeer {
    async fn connect(
        owner: &Arc<GatewayForwarderInner>,
        key: PeerKey,
        target: WorkerTargetRuntime,
    ) -> Result<Arc<Self>, GatewayForwardingError> {
        let timeouts = owner.timeouts.clone();
        let server = resolve_worker_endpoint(&target.endpoint, timeouts.connect).await?;
        let client = tokio::time::timeout(
            timeouts.connect,
            UctpQuicClient::connect(
                &owner.endpoint,
                server,
                &target.server_name,
                Arc::clone(&owner.tls),
            ),
        )
        .await
        .map_err(|_| GatewayForwardingError::Timeout)?
        .map_err(|_| GatewayForwardingError::PeerUnavailable)?;
        let mut inbound = client
            .take_inbound()
            .ok_or(GatewayForwardingError::PeerUnavailable)?;
        Self::authenticate(
            &client,
            &mut inbound,
            &owner.gateway_id,
            owner.minter.mint(target.worker_id, &key.tenant_id)?,
            timeouts.signaling,
        )
        .await?;

        let peer = Arc::new(Self {
            key,
            gateway_id: owner.gateway_id.clone(),
            client,
            pending_opens: DashMap::new(),
            pending_accepts: DashMap::new(),
            pending_admissions: DashMap::new(),
            pending_replies: DashMap::new(),
            routes_by_wire: DashMap::new(),
            routes_by_local: DashMap::new(),
            pending_datagrams: Mutex::new(PendingDatagrams::new(
                owner.limits.max_routes_per_peer,
                timeouts.signaling,
            )),
            route_capacity: Arc::new(Semaphore::new(owner.limits.max_routes_per_peer)),
            cancel: CancellationToken::new(),
            closed: AtomicBool::new(false),
            tasks: Mutex::new(Vec::new()),
            owner: Arc::downgrade(owner),
        });
        peer.spawn_envelope_pump(inbound);
        peer.spawn_datagram_pump();
        peer.spawn_refresh(Arc::clone(&owner.minter), timeouts);
        Ok(peer)
    }

    async fn authenticate(
        client: &Arc<UctpQuicClient>,
        inbound: &mut mpsc::Receiver<UctpEnvelope>,
        gateway_id: &str,
        token: String,
        timeout: Duration,
    ) -> Result<(), GatewayForwardingError> {
        let hello = auth::AuthHello {
            device: auth::Device {
                id: gateway_id.to_owned(),
                kind: "gateway".into(),
                platform: "bridgefu".into(),
                sdk_version: env!("CARGO_PKG_VERSION").into(),
            },
            auth_methods: vec!["bearer".into()],
            capabilities: serde_json::json!({"private_forwarding": 1}),
        };
        client
            .send(UctpEnvelope::new(
                MessageType::AuthHello,
                serde_json::to_value(hello)
                    .map_err(|_| GatewayForwardingError::AuthenticationFailed)?,
            ))
            .await
            .map_err(|_| GatewayForwardingError::PeerUnavailable)?;
        let challenge = wait_for_envelope(inbound, MessageType::AuthChallenge, timeout).await?;
        let response = auth::AuthResponse {
            method: "bearer".into(),
            credential: token,
            actor_token: None,
        };
        client
            .send(
                UctpEnvelope::new(
                    MessageType::AuthResponse,
                    serde_json::to_value(response)
                        .map_err(|_| GatewayForwardingError::AuthenticationFailed)?,
                )
                .with_in_reply_to(challenge.id),
            )
            .await
            .map_err(|_| GatewayForwardingError::PeerUnavailable)?;
        let session = wait_for_envelope(inbound, MessageType::AuthSession, timeout).await?;
        let authenticated: auth::AuthSession = session
            .decode_payload()
            .map_err(|_| GatewayForwardingError::AuthenticationFailed)?;
        if authenticated.identity_id != gateway_id || authenticated.participant_id != gateway_id {
            return Err(GatewayForwardingError::AuthenticationFailed);
        }
        Ok(())
    }

    fn is_live(&self) -> bool {
        !self.closed.load(Ordering::Acquire)
            && !self.cancel.is_cancelled()
            && self.client.connection.close_reason().is_none()
    }

    fn push_task(&self, task: JoinHandle<()>) {
        self.tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(task);
    }

    fn expire_pending_datagrams(&self, now: Instant) {
        let expired = self
            .pending_datagrams
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .expire(now);
        if expired > 0 {
            metrics::counter!(
                "bridgefu_private_forwarding_drops_total",
                "reason" => "unannounced-stream-expired"
            )
            .increment(expired as u64);
        }
    }

    fn has_route_awaiting_broadcast_stream(&self) -> bool {
        self.routes_by_wire.iter().any(|entry| {
            entry.value().upgrade().is_some_and(|route| {
                route.broadcast_subscription
                    && route.dynamic_broadcast_stream.is_awaiting()
                    && !route.closed.load(Ordering::Acquire)
            })
        })
    }

    fn deliver_validated_rtp(route: &Arc<RouteInner>, packet: Bytes) {
        let Ok(parsed) = unpack_rtp(packet.clone()) else {
            metrics::counter!(
                "bridgefu_private_forwarding_drops_total",
                "reason" => "invalid-rtp"
            )
            .increment(1);
            return;
        };
        if route
            .expected_payload_type
            .is_some_and(|expected| parsed.payload_type != expected)
        {
            metrics::counter!(
                "bridgefu_private_forwarding_drops_total",
                "reason" => "codec-payload-type-mismatch"
            )
            .increment(1);
            route.fail(GatewayForwardingError::UnsupportedCodec);
            return;
        }
        route.deliver(ForwardedPacket::Rtp(packet));
    }

    /// Deliver a known stream immediately or retain one bounded packet while
    /// a broadcast's dynamic stream announcement is still in flight.
    ///
    /// The same mutex is held while checking the route map and while a
    /// `stream.opened` handler installs/drains a route. This makes the switch
    /// from buffered to live delivery atomic and prevents a later packet from
    /// overtaking the buffered first packet.
    fn deliver_or_buffer_rtp(&self, stream_local_id: u16, packet: Bytes) {
        // Normal media never touches the reorder mutex or scans routes. Only
        // an ID that has not yet been announced enters the slow path.
        if let Some(route) = self
            .routes_by_local
            .get(&stream_local_id)
            .and_then(|route| route.upgrade())
        {
            Self::deliver_validated_rtp(&route, packet);
            return;
        }
        let now = Instant::now();
        let mut pending = self
            .pending_datagrams
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let expired = pending.expire(now);
        if expired > 0 {
            metrics::counter!(
                "bridgefu_private_forwarding_drops_total",
                "reason" => "unannounced-stream-expired"
            )
            .increment(expired as u64);
        }
        // A stream.opened handler may have installed the route between the
        // lock-free lookup and this mutex acquisition.
        if let Some(route) = self
            .routes_by_local
            .get(&stream_local_id)
            .and_then(|route| route.upgrade())
        {
            Self::deliver_validated_rtp(&route, packet);
            return;
        }
        if !self.has_route_awaiting_broadcast_stream() {
            metrics::counter!(
                "bridgefu_private_forwarding_drops_total",
                "reason" => "unknown-stream"
            )
            .increment(1);
            return;
        }
        if pending.insert(stream_local_id, packet, now) {
            metrics::counter!(
                "bridgefu_private_forwarding_packets_total",
                "direction" => "worker-to-gateway-buffered"
            )
            .increment(1);
        } else {
            metrics::counter!(
                "bridgefu_private_forwarding_drops_total",
                "reason" => "unannounced-stream-buffer-capacity"
            )
            .increment(1);
        }
    }

    fn register_broadcast_stream(
        &self,
        route: &Arc<RouteInner>,
        local_id: u16,
    ) -> Result<(), GatewayForwardingError> {
        let now = Instant::now();
        let mut pending = self
            .pending_datagrams
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let expired = pending.expire(now);
        if expired > 0 {
            metrics::counter!(
                "bridgefu_private_forwarding_drops_total",
                "reason" => "unannounced-stream-expired"
            )
            .increment(expired as u64);
        }
        if !route.broadcast_subscription
            || route.closed.load(Ordering::Acquire)
            || !route.dynamic_broadcast_stream.claim()
        {
            return Err(GatewayForwardingError::SignalingFailed);
        }
        if local_id == 0 || self.routes_by_local.contains_key(&local_id) {
            return Err(GatewayForwardingError::SignalingFailed);
        }
        // Drain before publishing the local-ID mapping. Unknown-packet slow
        // paths are blocked on this mutex until the buffered first packet has
        // been delivered; subsequent known packets then take the fast path.
        if let Some(packet) = pending.take(local_id, now) {
            Self::deliver_validated_rtp(route, packet);
            metrics::counter!(
                "bridgefu_private_forwarding_packets_total",
                "direction" => "worker-to-gateway-buffer-drained"
            )
            .increment(1);
        }
        self.routes_by_local.insert(local_id, Arc::downgrade(route));
        route
            .additional_stream_local_ids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(local_id);
        Ok(())
    }

    /// Atomically close a route with respect to dynamic stream registration.
    /// Once this returns, no StreamOpened handler can leave a local-ID entry
    /// behind for the retired route.
    fn retire_route_streams(&self, route: &Arc<RouteInner>) -> bool {
        let mut pending = self
            .pending_datagrams
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if route.closed.swap(true, Ordering::AcqRel) {
            return false;
        }
        route.dynamic_broadcast_stream.close();
        self.routes_by_wire.remove(&route.wire);
        if self
            .routes_by_local
            .get(&route.stream_local_id)
            .and_then(|entry| entry.upgrade())
            .is_some_and(|registered| Arc::ptr_eq(&registered, route))
        {
            self.routes_by_local.remove(&route.stream_local_id);
        }
        let additional_stream_local_ids = std::mem::take(
            &mut *route
                .additional_stream_local_ids
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        for local_id in additional_stream_local_ids {
            if self
                .routes_by_local
                .get(&local_id)
                .and_then(|entry| entry.upgrade())
                .is_some_and(|registered| Arc::ptr_eq(&registered, route))
            {
                self.routes_by_local.remove(&local_id);
            }
        }
        if !self.has_route_awaiting_broadcast_stream() {
            let cleared = pending.clear();
            if cleared > 0 {
                metrics::counter!(
                    "bridgefu_private_forwarding_drops_total",
                    "reason" => "unannounced-stream-peer-closed"
                )
                .increment(cleared as u64);
            }
        }
        true
    }

    fn clear_pending_datagrams(&self) {
        let cleared = self
            .pending_datagrams
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        if cleared > 0 {
            metrics::counter!(
                "bridgefu_private_forwarding_drops_total",
                "reason" => "unannounced-stream-peer-closed"
            )
            .increment(cleared as u64);
        }
    }

    fn spawn_envelope_pump(self: &Arc<Self>, mut inbound: mpsc::Receiver<UctpEnvelope>) {
        let peer = Arc::clone(self);
        let cancel = self.cancel.clone();
        self.push_task(tokio::spawn(async move {
            loop {
                let envelope = tokio::select! {
                    _ = cancel.cancelled() => break,
                    envelope = inbound.recv() => match envelope {
                        Some(envelope) => envelope,
                        None => break,
                    },
                };
                peer.handle_envelope(envelope);
            }
            peer.fail(GatewayForwardingError::PeerUnavailable);
        }));
    }

    fn spawn_datagram_pump(self: &Arc<Self>) {
        let peer = Arc::clone(self);
        let cancel = self.cancel.clone();
        let connection = self.client.connection.clone();
        self.push_task(tokio::spawn(async move {
            let mut sweep = tokio::time::interval(PENDING_DATAGRAM_SWEEP_INTERVAL);
            sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                let bytes = tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = sweep.tick() => {
                        peer.expire_pending_datagrams(Instant::now());
                        continue;
                    }
                    result = connection.read_datagram() => match result {
                        Ok(bytes) => bytes,
                        Err(_) => break,
                    },
                };
                // Typed validation proves this is UCTP 0.2 + complete RTP;
                // the raw compatibility view retains every RTP header byte,
                // extension, CSRC, padding byte, and codec byte unchanged.
                if unpack_rtp_datagram(&bytes).is_err() {
                    metrics::counter!(
                        "bridgefu_private_forwarding_drops_total",
                        "reason" => "invalid-rtp"
                    )
                    .increment(1);
                    continue;
                }
                let Ok(raw) = unpack(&bytes) else {
                    continue;
                };
                peer.deliver_or_buffer_rtp(raw.stream_local_id, raw.payload);
            }
            peer.fail(GatewayForwardingError::PeerUnavailable);
        }));
    }

    fn spawn_refresh(
        self: &Arc<Self>,
        minter: Arc<TokenMinter>,
        timeouts: PrivateForwardingTimeouts,
    ) {
        let peer = Arc::clone(self);
        let cancel = self.cancel.clone();
        self.push_task(tokio::spawn(async move {
            let refresh_interval = timeouts.token_ttl / 2;
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep(refresh_interval) => {}
                }
                let token = match minter.mint(peer.key.worker_id, &peer.key.tenant_id) {
                    Ok(token) => token,
                    Err(error) => {
                        peer.fail(error);
                        return;
                    }
                };
                let response = auth::AuthRefresh {
                    method: "bearer".into(),
                    credential: token,
                    actor_token: None,
                };
                let envelope = match serde_json::to_value(response) {
                    Ok(value) => UctpEnvelope::new(MessageType::AuthRefresh, value),
                    Err(_) => {
                        peer.fail(GatewayForwardingError::TokenCreation);
                        return;
                    }
                };
                if !matches!(
                    tokio::time::timeout(timeouts.signaling, peer.client.send(envelope)).await,
                    Ok(Ok(()))
                ) {
                    peer.fail(GatewayForwardingError::Timeout);
                    return;
                }
            }
        }));
    }

    fn handle_envelope(self: &Arc<Self>, envelope: UctpEnvelope) {
        let peer_error = envelope.msg_type == MessageType::Error;
        if envelope.msg_type == MessageType::SessionReject {
            if let Ok(rejected) = envelope.decode_payload::<session::SessionReject>() {
                tracing::warn!(
                    reason_code = rejected.reason_code,
                    reason = %rejected.reason,
                    "private worker rejected Session admission"
                );
            }
        }
        match envelope.msg_type {
            MessageType::SessionAccept => {
                let Some(sid) = envelope.sid.as_deref() else {
                    return;
                };
                if let Some((_, (key, pending))) = self.pending_accepts.remove(sid) {
                    if key.sid == sid {
                        let _ = pending.send(Ok(()));
                    } else {
                        let _ = pending.send(Err(GatewayForwardingError::SignalingFailed));
                    }
                }
            }
            MessageType::StreamOpened => {
                let Some(key) = wire_key(&envelope) else {
                    return;
                };
                let opened = envelope
                    .decode_payload::<stream::StreamOpened>()
                    .map_err(|_| GatewayForwardingError::SignalingFailed);
                let result = opened
                    .as_ref()
                    .map(|opened| opened.stream.stream_local_id)
                    .map_err(|error| *error);
                if let Some((_, pending)) = self.pending_opens.remove(&key) {
                    let _ = pending.send(result);
                    return;
                }
                let Some(route) = self
                    .routes_by_wire
                    .get(&key)
                    .and_then(|route| route.upgrade())
                else {
                    return;
                };
                let Ok(opened) = opened else {
                    route.fail(GatewayForwardingError::SignalingFailed);
                    return;
                };
                let local_id = opened.stream.stream_local_id;
                if opened.stream.kind != "audio"
                    || opened.stream.direction != "recvonly"
                    || self.register_broadcast_stream(&route, local_id).is_err()
                {
                    route.fail(GatewayForwardingError::SignalingFailed);
                }
            }
            MessageType::Ack => {
                if let Some(reply_to) = envelope.in_reply_to.as_deref() {
                    if let Some((_, pending)) = self.pending_replies.remove(reply_to) {
                        let _ = pending.send(Ok(()));
                    }
                }
            }
            MessageType::MessageSend => {
                let Some(key) = wire_key(&envelope) else {
                    return;
                };
                let Ok(payload) = envelope.decode_payload::<message::MessageSend>() else {
                    self.revoke_pending_attachment(
                        &key,
                        GatewayForwardingError::InvalidDataMessage,
                    );
                    return;
                };
                let Ok(data) = payload.to_data_message() else {
                    self.revoke_pending_attachment(
                        &key,
                        GatewayForwardingError::InvalidDataMessage,
                    );
                    return;
                };
                if data.label == PRIVATE_ATTACHMENT_ADMISSION_RESPONSE_LABEL {
                    let pending = self
                        .pending_admissions
                        .get(&key)
                        .map(|pending| Arc::clone(pending.value()));
                    let Some(pending) = pending else {
                        if let Some(route) = self
                            .routes_by_wire
                            .get(&key)
                            .and_then(|route| route.upgrade())
                        {
                            route.fail(GatewayForwardingError::InvalidDataMessage);
                        }
                        return;
                    };
                    if pending
                        .receive_receipt(envelope.cid.as_deref(), data)
                        .is_err()
                    {
                        self.revoke_pending_attachment(
                            &key,
                            GatewayForwardingError::AttachmentRejected,
                        );
                    }
                    return;
                }
                let route = self
                    .routes_by_wire
                    .get(&key)
                    .and_then(|route| route.upgrade());
                if data.label == PRIVATE_EGRESS_LIFECYCLE_ACK_LABEL {
                    let ack = match PrivateEgressLifecycleAck::from_data_message(&data) {
                        Ok(ack) => ack,
                        Err(_) => {
                            if let Some(route) = route {
                                route.fail(GatewayForwardingError::InvalidDataMessage);
                            } else if self.pending_admissions.contains_key(&key) {
                                self.revoke_pending_attachment(
                                    &key,
                                    GatewayForwardingError::InvalidDataMessage,
                                );
                            } else {
                                self.fail(GatewayForwardingError::InvalidDataMessage);
                            }
                            return;
                        }
                    };
                    let service = self
                        .owner
                        .upgrade()
                        .and_then(|owner| owner.private_egress.get().cloned());
                    if let Some(route) = route {
                        let authority = route.private_egress_authority();
                        let event_id = ack.event_id;
                        let target_generation = ack.target.binding_generation;
                        let source_generation = ack.source.binding_generation;
                        tokio::spawn(async move {
                            let acknowledged = match (service, authority) {
                                (Some(service), Some(authority)) => {
                                    match service.acknowledge_lifecycle(&authority, &ack).await {
                                        Ok(()) => {
                                            tracing::debug!(
                                                ack_branch = "active-route",
                                                %event_id,
                                                ?source_generation,
                                                ?target_generation,
                                                "accepted private-egress lifecycle ACK"
                                            );
                                            true
                                        }
                                        Err(error) => {
                                            tracing::warn!(
                                                ack_branch = "active-route",
                                                %event_id,
                                                ?source_generation,
                                                ?target_generation,
                                                ?error,
                                                "rejected private-egress lifecycle ACK"
                                            );
                                            false
                                        }
                                    }
                                }
                                _ => {
                                    tracing::warn!(
                                        ack_branch = "active-route",
                                        %event_id,
                                        ?source_generation,
                                        ?target_generation,
                                        "private-egress lifecycle ACK had no active authority"
                                    );
                                    false
                                }
                            };
                            if !acknowledged {
                                route.fail(GatewayForwardingError::InvalidDataMessage);
                            }
                        });
                        return;
                    }
                    let pending = self
                        .pending_admissions
                        .get(&key)
                        .map(|pending| Arc::clone(pending.value()));
                    let Some(pending) = pending else {
                        // Terminal reconciliation can retire the route before
                        // the worker's asynchronous lifecycle ACK reaches this
                        // peer. The authenticated peer identity plus the
                        // durable journal remain sufficient authority: the
                        // service verifies the exact fence, source generation,
                        // target, event, gateway epoch, and sequence.
                        if ack.worker.worker_id != self.key.worker_id
                            || ack.source.tenant_id != self.key.tenant_id
                        {
                            tracing::warn!(
                                ack_branch = "route-retired",
                                event_id = %ack.event_id,
                                source_generation = ?ack.source.binding_generation,
                                target_generation = ?ack.target.binding_generation,
                                "private-egress lifecycle ACK peer identity mismatch"
                            );
                            self.fail(GatewayForwardingError::InvalidDataMessage);
                            return;
                        }
                        let event_id = ack.event_id;
                        let target_generation = ack.target.binding_generation;
                        let source_generation = ack.source.binding_generation;
                        let authority = PrivateEgressRouteAuthority {
                            worker: ack.worker,
                            source: ack.source.clone(),
                        };
                        let peer = Arc::clone(self);
                        tokio::spawn(async move {
                            let acknowledged = match service {
                                Some(service) => {
                                    match service.acknowledge_lifecycle(&authority, &ack).await {
                                        Ok(()) => {
                                            tracing::debug!(
                                                ack_branch = "route-retired",
                                                %event_id,
                                                ?source_generation,
                                                ?target_generation,
                                                "accepted private-egress lifecycle ACK"
                                            );
                                            true
                                        }
                                        Err(error) => {
                                            tracing::warn!(
                                                ack_branch = "route-retired",
                                                %event_id,
                                                ?source_generation,
                                                ?target_generation,
                                                ?error,
                                                "rejected private-egress lifecycle ACK"
                                            );
                                            false
                                        }
                                    }
                                }
                                None => {
                                    tracing::warn!(
                                        ack_branch = "route-retired",
                                        %event_id,
                                        ?source_generation,
                                        ?target_generation,
                                        "private-egress lifecycle ACK had no command service"
                                    );
                                    false
                                }
                            };
                            if !acknowledged {
                                peer.fail(GatewayForwardingError::InvalidDataMessage);
                            }
                        });
                        return;
                    };
                    if envelope.cid.as_deref() != Some(pending.conversation_id.as_str()) {
                        self.revoke_pending_attachment(
                            &key,
                            GatewayForwardingError::AttachmentRejected,
                        );
                        return;
                    }
                    let authority = pending.authority();
                    let peer = Arc::clone(self);
                    let event_id = ack.event_id;
                    let target_generation = ack.target.binding_generation;
                    let source_generation = ack.source.binding_generation;
                    tokio::spawn(async move {
                        let acknowledged = match (service, authority) {
                            (Some(service), Some(authority)) => {
                                match service.acknowledge_lifecycle(&authority, &ack).await {
                                    Ok(()) => {
                                        tracing::debug!(
                                            ack_branch = "pending-admission",
                                            %event_id,
                                            ?source_generation,
                                            ?target_generation,
                                            "accepted private-egress lifecycle ACK"
                                        );
                                        true
                                    }
                                    Err(error) => {
                                        tracing::warn!(
                                            ack_branch = "pending-admission",
                                            %event_id,
                                            ?source_generation,
                                            ?target_generation,
                                            ?error,
                                            "rejected private-egress lifecycle ACK"
                                        );
                                        false
                                    }
                                }
                            }
                            _ => {
                                tracing::warn!(
                                    ack_branch = "pending-admission",
                                    %event_id,
                                    ?source_generation,
                                    ?target_generation,
                                    "private-egress lifecycle ACK had no pending authority"
                                );
                                false
                            }
                        };
                        if !acknowledged {
                            peer.revoke_pending_attachment(
                                &pending.wire,
                                GatewayForwardingError::InvalidDataMessage,
                            );
                        }
                    });
                    return;
                }
                if data.label == PRIVATE_EGRESS_COMMAND_LABEL {
                    let now_ms = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .ok()
                        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
                        .unwrap_or_default();
                    let command = match PrivateEgressCommand::from_data_message(&data, now_ms) {
                        Ok(command) => command,
                        Err(_) => {
                            if let Some(route) = route {
                                route.fail(GatewayForwardingError::InvalidDataMessage);
                            } else {
                                self.revoke_pending_attachment(
                                    &key,
                                    GatewayForwardingError::InvalidDataMessage,
                                );
                            }
                            return;
                        }
                    };
                    let service = self
                        .owner
                        .upgrade()
                        .and_then(|owner| owner.private_egress.get().cloned());
                    if let Some(route) = route {
                        let authority = route.private_egress_authority();
                        tokio::spawn(async move {
                            let response = match (service, authority) {
                                (Some(service), Some(authority)) => service
                                    .execute(authority, command.clone(), now_ms)
                                    .await
                                    .unwrap_or_else(|error| {
                                        PrivateEgressResponse::rejected(command.command_id, error)
                                    }),
                                (_, None) => PrivateEgressResponse::rejected(
                                    command.command_id,
                                    PrivateEgressError::OwnershipMismatch,
                                ),
                                (None, Some(_)) => PrivateEgressResponse::rejected(
                                    command.command_id,
                                    PrivateEgressError::HandlerRejected,
                                ),
                            };
                            let sent = response
                                .to_data_message()
                                .map_err(|_| GatewayForwardingError::InvalidDataMessage)
                                .and_then(|message| route.try_send_private_data(message));
                            if let Err(error) = sent {
                                route.fail(error);
                            }
                        });
                        return;
                    }
                    let pending = self
                        .pending_admissions
                        .get(&key)
                        .map(|pending| Arc::clone(pending.value()));
                    let Some(pending) = pending else {
                        return;
                    };
                    if envelope.cid.as_deref() != Some(pending.conversation_id.as_str()) {
                        self.revoke_pending_attachment(
                            &key,
                            GatewayForwardingError::AttachmentRejected,
                        );
                        return;
                    }
                    let authority = match pending.authority_for(&command) {
                        Ok(authority) => authority,
                        Err(_) => {
                            self.revoke_pending_attachment(
                                &key,
                                GatewayForwardingError::AttachmentRejected,
                            );
                            return;
                        }
                    };
                    let peer = Arc::clone(self);
                    tokio::spawn(async move {
                        let response = match (service, authority) {
                            (Some(service), authority) => service
                                .execute(authority, command.clone(), now_ms)
                                .await
                                .unwrap_or_else(|error| {
                                    PrivateEgressResponse::rejected(command.command_id, error)
                                }),
                            (None, _) => PrivateEgressResponse::rejected(
                                command.command_id,
                                PrivateEgressError::HandlerRejected,
                            ),
                        };
                        let sent = response
                            .to_data_message()
                            .map_err(|_| GatewayForwardingError::InvalidDataMessage);
                        let sent = match sent {
                            Ok(message) => {
                                peer.send_private_data_during_promotion(&pending, message)
                                    .await
                            }
                            Err(error) => Err(error),
                        };
                        if let Err(error) = sent {
                            peer.revoke_pending_attachment(&pending.wire, error);
                        }
                    });
                    return;
                }
                let Some(route) = route else {
                    if matches!(
                        data.label.as_str(),
                        PRIVATE_EGRESS_RESPONSE_LABEL | PRIVATE_EGRESS_LIFECYCLE_LABEL
                    ) {
                        self.revoke_pending_attachment(
                            &key,
                            GatewayForwardingError::InvalidDataMessage,
                        );
                    }
                    return;
                };
                if matches!(
                    data.label.as_str(),
                    PRIVATE_EGRESS_RESPONSE_LABEL | PRIVATE_EGRESS_LIFECYCLE_LABEL
                ) {
                    route.fail(GatewayForwardingError::InvalidDataMessage);
                    return;
                }
                if data.label == PRIVATE_RTCP_LABEL {
                    if data.content_type != PRIVATE_RTCP_CONTENT_TYPE
                        || data.reliability != rvoip_core::DataReliability::ReliableOrdered
                        || validate_rtcp(&data.bytes).is_err()
                    {
                        route.fail(GatewayForwardingError::InvalidRtcp);
                        return;
                    }
                    route.deliver(ForwardedPacket::Rtcp(data.bytes));
                } else {
                    route.deliver(ForwardedPacket::Data(data));
                }
            }
            MessageType::DtmfSend => {
                let Some(key) = wire_key(&envelope) else {
                    return;
                };
                let Ok(dtmf) = envelope.decode_payload::<rvoip_uctp::payloads::control::DtmfSend>()
                else {
                    if let Some(route) = self
                        .routes_by_wire
                        .get(&key)
                        .and_then(|route| route.upgrade())
                    {
                        route.fail(GatewayForwardingError::SignalingFailed);
                    }
                    return;
                };
                let Some(route) = self
                    .routes_by_wire
                    .get(&key)
                    .and_then(|route| route.upgrade())
                else {
                    return;
                };
                if !valid_dtmf(&dtmf.digits, dtmf.duration_ms) || dtmf.method != "rfc4733" {
                    route.fail(GatewayForwardingError::SignalingFailed);
                    return;
                }
                route.deliver(ForwardedPacket::Dtmf {
                    digits: dtmf.digits,
                    duration_ms: dtmf.duration_ms,
                });
            }
            MessageType::Error | MessageType::SessionReject => {
                if let Some(reply_to) = envelope.in_reply_to.as_deref() {
                    if let Some((_, pending)) = self.pending_replies.remove(reply_to) {
                        let _ = pending.send(Err(GatewayForwardingError::SignalingFailed));
                    }
                }
                if let Some(key) = wire_key(&envelope) {
                    if let Some((_, (pending_key, pending))) = self.pending_accepts.remove(&key.sid)
                    {
                        let result = if pending_key == key {
                            GatewayForwardingError::SignalingFailed
                        } else {
                            GatewayForwardingError::RouteAlreadyExists
                        };
                        let _ = pending.send(Err(result));
                    }
                    if let Some((_, pending)) = self.pending_opens.remove(&key) {
                        let _ = pending.send(Err(GatewayForwardingError::SignalingFailed));
                    }
                    self.revoke_pending_attachment(
                        &key,
                        GatewayForwardingError::AttachmentRejected,
                    );
                    if let Some(route) = self
                        .routes_by_wire
                        .get(&key)
                        .and_then(|route| route.upgrade())
                    {
                        route.retire_remote();
                    }
                } else if let Some(sid) = envelope.sid.as_deref() {
                    if let Some((_, (_, pending))) = self.pending_accepts.remove(sid) {
                        let _ = pending.send(Err(GatewayForwardingError::SignalingFailed));
                    }
                    let keys = self
                        .pending_opens
                        .iter()
                        .filter(|entry| entry.key().sid == sid)
                        .map(|entry| entry.key().clone())
                        .collect::<Vec<_>>();
                    for key in keys {
                        if let Some((_, pending)) = self.pending_opens.remove(&key) {
                            let _ = pending.send(Err(GatewayForwardingError::SignalingFailed));
                        }
                        self.revoke_pending_attachment(
                            &key,
                            GatewayForwardingError::AttachmentRejected,
                        );
                    }
                    self.fail_routes_for_sid(sid, GatewayForwardingError::SignalingFailed);
                } else if peer_error {
                    self.fail(GatewayForwardingError::AuthenticationFailed);
                }
            }
            MessageType::SessionCancel
            | MessageType::SessionEnd
            | MessageType::SessionEnded
            | MessageType::ConnectionEnd
            | MessageType::StreamClosed => {
                if let Some(key) = wire_key(&envelope) {
                    self.revoke_pending_attachment(&key, GatewayForwardingError::Closed);
                    if let Some(route) = self
                        .routes_by_wire
                        .get(&key)
                        .and_then(|route| route.upgrade())
                    {
                        route.retire_remote();
                    }
                } else if let Some(sid) = envelope.sid.as_deref() {
                    self.fail_routes_for_sid(sid, GatewayForwardingError::Closed);
                }
            }
            MessageType::AuthSession => {
                let valid = envelope
                    .decode_payload::<auth::AuthSession>()
                    .is_ok_and(|session| {
                        session.identity_id == self.gateway_id
                            && session.participant_id == self.gateway_id
                    });
                if !valid {
                    self.fail(GatewayForwardingError::AuthenticationFailed);
                }
            }
            MessageType::AuthBye => self.fail(GatewayForwardingError::AuthenticationFailed),
            _ => {}
        }
    }

    async fn send_pending_private_data(
        &self,
        pending: &PendingAttachmentAdmission,
        data: DataMessage,
    ) -> Result<(), GatewayForwardingError> {
        data.validate()
            .map_err(|_| GatewayForwardingError::InvalidDataMessage)?;
        if !pending.active.load(Ordering::Acquire)
            || !matches!(
                data.label.as_str(),
                PRIVATE_EGRESS_RESPONSE_LABEL | PRIVATE_EGRESS_LIFECYCLE_LABEL
            )
            || data.reliability != rvoip_core::DataReliability::ReliableOrdered
        {
            return Err(GatewayForwardingError::InvalidDataMessage);
        }
        let payload = message::MessageSend::from_data_message(
            &data,
            self.gateway_id.clone(),
            serde_json::json!("all"),
        )
        .map_err(|_| GatewayForwardingError::InvalidDataMessage)?;
        let envelope = UctpEnvelope::new(
            MessageType::MessageSend,
            serde_json::to_value(payload)
                .map_err(|_| GatewayForwardingError::InvalidDataMessage)?,
        )
        .with_cid(pending.conversation_id.clone())
        .with_sid(pending.wire.sid.clone())
        .with_connid(pending.wire.connid.clone());
        let timeout = self
            .owner
            .upgrade()
            .map_or(Duration::from_secs(2), |owner| owner.timeouts.signaling);
        match tokio::time::timeout(timeout, self.client.send(envelope)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(GatewayForwardingError::PeerUnavailable),
            Err(_) => Err(GatewayForwardingError::Timeout),
        }
    }

    async fn send_private_data_during_promotion(
        &self,
        pending: &PendingAttachmentAdmission,
        data: DataMessage,
    ) -> Result<(), GatewayForwardingError> {
        if pending.active.load(Ordering::Acquire)
            && self
                .send_pending_private_data(pending, data.clone())
                .await
                .is_ok()
        {
            return Ok(());
        }
        let route = self
            .routes_by_wire
            .get(&pending.wire)
            .and_then(|route| route.upgrade())
            .ok_or(GatewayForwardingError::RouteNotActive)?;
        match route.try_send_private_data(data) {
            Ok(()) => Ok(()),
            Err(error) => {
                route.fail(error);
                Err(error)
            }
        }
    }

    fn revoke_pending_attachment(&self, key: &WireRouteKey, error: GatewayForwardingError) {
        if let Some((_, pending)) = self.pending_admissions.remove(key) {
            pending.revoke(error);
            let peer = self.client.clone();
            let gateway_id = self.gateway_id.clone();
            let sid = key.sid.clone();
            let timeout = self
                .owner
                .upgrade()
                .map_or(Duration::from_secs(2), |owner| owner.timeouts.signaling);
            tokio::spawn(async move {
                let payload = session::SessionEnd {
                    by: gateway_id,
                    reason_code: 500,
                    reason: "attachment-control-rejected".into(),
                };
                if let Ok(payload) = serde_json::to_value(payload) {
                    let envelope =
                        UctpEnvelope::new(MessageType::SessionEnd, payload).with_sid(sid);
                    let _ = tokio::time::timeout(timeout, peer.send(envelope)).await;
                }
            });
        }
    }

    fn promote_pending_attachment(
        &self,
        wire: &WireRouteKey,
        receipt: &WorkerAttachmentAdmissionReceipt,
    ) -> Result<(), GatewayForwardingError> {
        let pending = self
            .pending_admissions
            .get(wire)
            .map(|pending| Arc::clone(pending.value()))
            .ok_or(GatewayForwardingError::AttachmentRejected)?;
        pending.promote(receipt)?;
        self.pending_admissions.remove(wire);
        Ok(())
    }

    fn pending_for_authority(
        &self,
        worker: WorkerLease,
        source: &PrivateEgressSource,
    ) -> Option<Arc<PendingAttachmentAdmission>> {
        self.pending_admissions
            .iter()
            .find(|pending| pending.matches_authority(worker, source))
            .map(|pending| Arc::clone(pending.value()))
    }

    fn fail_routes_for_sid(&self, sid: &str, error: GatewayForwardingError) {
        let pending = self
            .pending_admissions
            .iter()
            .filter(|entry| entry.key().sid == sid)
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        for key in pending {
            self.revoke_pending_attachment(&key, error);
        }
        let routes = self
            .routes_by_wire
            .iter()
            .filter(|entry| entry.key().sid == sid)
            .filter_map(|entry| entry.value().upgrade())
            .collect::<Vec<_>>();
        let _ = error;
        for route in routes {
            route.retire_remote();
        }
    }

    fn fail(&self, error: GatewayForwardingError) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.cancel.cancel();
        self.clear_pending_datagrams();
        for entry in self.pending_opens.iter() {
            let key = entry.key().clone();
            drop(entry);
            if let Some((_, pending)) = self.pending_opens.remove(&key) {
                let _ = pending.send(Err(error));
            }
        }
        for entry in self.pending_accepts.iter() {
            let sid = entry.key().clone();
            drop(entry);
            if let Some((_, (_, pending))) = self.pending_accepts.remove(&sid) {
                let _ = pending.send(Err(error));
            }
        }
        for entry in self.pending_admissions.iter() {
            let key = entry.key().clone();
            drop(entry);
            if let Some((_, pending)) = self.pending_admissions.remove(&key) {
                pending.revoke(error);
            }
        }
        for entry in self.pending_replies.iter() {
            let key = entry.key().clone();
            drop(entry);
            if let Some((_, pending)) = self.pending_replies.remove(&key) {
                let _ = pending.send(Err(error));
            }
        }
        let routes = self
            .routes_by_wire
            .iter()
            .filter_map(|entry| entry.value().upgrade())
            .collect::<Vec<_>>();
        let _ = error;
        for route in routes {
            route.retire_remote();
        }
        if let Some(owner) = self.owner.upgrade() {
            owner.health.send_replace(ForwardingHealth::Degraded);
        }
    }

    async fn open_route(
        self: &Arc<Self>,
        key: &GatewayRouteKey,
        codec_preferences: Vec<String>,
        timeout: Duration,
    ) -> Result<OpenedWireRoute, GatewayForwardingError> {
        self.open_wire_route(
            WireRouteKey {
                sid: key.wire_session_id(),
                connid: key.wire_connection_id(),
            },
            key.wire_conversation_id(),
            key.wire_stream_id(),
            "private-forward",
            serde_json::json!({"bridgefu_private_forwarding": 1}),
            codec_preferences,
            "sendrecv",
            None,
            false,
            timeout,
        )
        .await
    }

    async fn open_attachment_route(
        self: &Arc<Self>,
        tenant_id: &TenantId,
        expected_worker: WorkerLease,
        request: WorkerAttachmentAdmissionRequest,
        codec: String,
        timeout: Duration,
    ) -> Result<OpenedWireRoute, GatewayForwardingError> {
        if expected_worker.worker_id != self.key.worker_id
            || request.expected_worker() != expected_worker
        {
            return Err(GatewayForwardingError::WorkerPinMismatch);
        }
        let request_id = request.request_id();
        let routing_hint = request.to_routing_hint().map_err(map_attachment_error)?;
        let wire = WireRouteKey {
            sid: format!(
                "{WIRE_ATTACHMENT_SESSION_PREFIX}.{}.{}",
                URL_SAFE_NO_PAD.encode(tenant_id.as_str()),
                request_id
            ),
            connid: format!("bf-admit-conn-v1.{request_id}"),
        };
        let conversation_id = format!("bf-admit-conversation-v1.{request_id}");
        let (pending, response_rx) = PendingAttachmentAdmission::new(
            wire.clone(),
            conversation_id.clone(),
            request_id,
            tenant_id.clone(),
            expected_worker,
        );
        match self.pending_admissions.entry(wire.clone()) {
            dashmap::mapref::entry::Entry::Occupied(_) => {
                return Err(GatewayForwardingError::RouteAlreadyExists)
            }
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert(Arc::clone(&pending));
            }
        }
        let guard = PendingAttachmentGuard::new(self, wire.clone());
        let open = self.open_wire_route(
            wire.clone(),
            conversation_id,
            format!("bf-admit-stream-v1.{request_id}"),
            PRIVATE_ATTACHMENT_INTENT,
            serde_json::json!({
                "bridgefu_private_forwarding": 1,
                (PRIVATE_ATTACHMENT_CAPABILITY): routing_hint,
            }),
            vec![codec],
            "sendrecv",
            None,
            true,
            timeout,
        );
        // Poll the provisional receipt and final Session acceptance together.
        // Returning remains gated on both, so the public ingress is never
        // answered merely because durable consume succeeded.
        let receipt = async {
            match tokio::time::timeout(timeout, response_rx).await {
                Ok(Ok(result)) => result,
                Ok(Err(_)) => Err(GatewayForwardingError::PeerUnavailable),
                Err(_) => Err(GatewayForwardingError::Timeout),
            }
        };
        let (opened, receipt) = tokio::join!(open, receipt);
        let (mut opened, receipt) = match (opened, receipt) {
            (Ok(opened), Ok(receipt)) => (opened, receipt),
            (Err(error), _) | (_, Err(error)) => {
                if let Some((_, retained)) = self.pending_admissions.remove(&wire) {
                    retained.revoke(error);
                } else {
                    pending.revoke(error);
                }
                self.send_session_end(&wire.sid, timeout).await;
                return Err(error);
            }
        };
        opened.attachment_receipt = Some(receipt);
        opened.pending_attachment_guard = Some(guard);
        Ok(opened)
    }

    async fn open_private_egress_route(
        self: &Arc<Self>,
        admission: &PrivateEgressStreamAdmission,
        timeout: Duration,
    ) -> Result<OpenedWireRoute, GatewayForwardingError> {
        if admission.worker.worker_id != self.key.worker_id
            || admission.source.tenant_id != self.key.tenant_id
        {
            return Err(GatewayForwardingError::WorkerPinMismatch);
        }
        admission
            .validate(current_unix_time_ms())
            .map_err(map_private_egress_stream_error)?;
        let routing_hint = admission
            .to_routing_hint()
            .map_err(map_private_egress_stream_error)?;
        let wire = WireRouteKey {
            sid: private_egress_wire_session(admission)?,
            connid: format!("bf-egress-conn-v1.{}", admission.admission_id),
        };
        self.open_wire_route(
            wire,
            format!("bf-egress-conversation-v1.{}", admission.admission_id),
            format!("bf-egress-stream-v1.{}", admission.admission_id),
            PRIVATE_EGRESS_STREAM_INTENT,
            serde_json::json!({
                "bridgefu_private_forwarding": 1,
                (PRIVATE_EGRESS_STREAM_CAPABILITY): routing_hint,
            }),
            vec![admission.codec.name.clone()],
            "sendrecv",
            None,
            true,
            timeout,
        )
        .await
    }

    async fn open_broadcast_route(
        self: &Arc<Self>,
        tenant_id: &TenantId,
        broadcast_id: uuid::Uuid,
        listener_id: uuid::Uuid,
        worker: WorkerLease,
        grant_generation: uuid::Uuid,
        timeout: Duration,
    ) -> Result<OpenedWireRoute, GatewayForwardingError> {
        if worker.worker_id != self.key.worker_id {
            return Err(GatewayForwardingError::WorkerPinMismatch);
        }
        let wire = WireRouteKey {
            sid: private_broadcast_wire_session(broadcast_id, listener_id)?,
            connid: format!("bf-broadcast-conn-v1.{listener_id}"),
        };
        self.open_wire_route(
            wire.clone(),
            format!("bf-broadcast-conversation-v1.{listener_id}"),
            format!("bf-broadcast-receiver-v1.{listener_id}"),
            PRIVATE_BROADCAST_INTENT,
            serde_json::json!({
                "bridgefu_private_forwarding": 1,
                (PRIVATE_BROADCAST_CAPABILITY): {
                    "broadcast_id": broadcast_id,
                    "tenant_id": tenant_id.as_str(),
                    "listener_id": listener_id,
                    "worker_fence": worker.fence.as_i64(),
                    "grant_generation": grant_generation,
                },
            }),
            vec!["opus".into()],
            "recvonly",
            None,
            true,
            timeout,
        )
        .await
    }

    async fn subscribe_broadcast_route(
        &self,
        opened: &OpenedWireRoute,
        timeout: Duration,
    ) -> Result<(), GatewayForwardingError> {
        let subscription = stream::StreamSubscribe {
            by_participant: self.gateway_id.clone(),
            subscriptions: vec![stream::StreamSubscription {
                strm_id: Some(BROADCAST_STREAM_ID.into()),
                ..stream::StreamSubscription::default()
            }],
        };
        let envelope = UctpEnvelope::new(
            MessageType::StreamSubscribe,
            serde_json::to_value(subscription)
                .map_err(|_| GatewayForwardingError::SignalingFailed)?,
        )
        .with_cid(opened.conversation_id.clone())
        .with_sid(opened.wire.sid.clone())
        .with_connid(opened.wire.connid.clone());
        let envelope_id = envelope.id.clone();
        let (reply, receiver) = oneshot::channel();
        if self
            .pending_replies
            .insert(envelope_id.clone(), reply)
            .is_some()
        {
            self.send_session_end(&opened.wire.sid, timeout).await;
            return Err(GatewayForwardingError::RouteAlreadyExists);
        }
        let send_result = tokio::time::timeout(timeout, self.client.send(envelope)).await;
        if !matches!(send_result, Ok(Ok(()))) {
            self.pending_replies.remove(&envelope_id);
            self.send_session_end(&opened.wire.sid, timeout).await;
            return Err(if send_result.is_err() {
                GatewayForwardingError::Timeout
            } else {
                GatewayForwardingError::PeerUnavailable
            });
        }
        let reply = tokio::time::timeout(timeout, receiver).await;
        self.pending_replies.remove(&envelope_id);
        match reply {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(error))) => {
                self.send_session_end(&opened.wire.sid, timeout).await;
                Err(error)
            }
            Ok(Err(_)) => {
                self.send_session_end(&opened.wire.sid, timeout).await;
                Err(GatewayForwardingError::PeerUnavailable)
            }
            Err(_) => {
                self.send_session_end(&opened.wire.sid, timeout).await;
                Err(GatewayForwardingError::Timeout)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn open_wire_route(
        self: &Arc<Self>,
        wire: WireRouteKey,
        conversation_id: String,
        stream_id: String,
        intent: &str,
        capabilities_offer: serde_json::Value,
        codec_preferences: Vec<String>,
        direction: &str,
        attachment_receipt: Option<WorkerAttachmentAdmissionReceipt>,
        require_session_accept: bool,
        timeout: Duration,
    ) -> Result<OpenedWireRoute, GatewayForwardingError> {
        if !self.is_live() {
            return Err(GatewayForwardingError::PeerUnavailable);
        }
        let (reply, receiver) = oneshot::channel();
        if self.pending_opens.insert(wire.clone(), reply).is_some() {
            return Err(GatewayForwardingError::RouteAlreadyExists);
        }
        // Durable attachment and broadcast admissions have an application
        // owner on the worker and must not become media-active until that
        // owner accepts the exact Session. The low-level `open_route` API is
        // also used with a bare rvoip Orchestrator, whose contract is to
        // expose (not auto-accept) inbound Connections. Preserve that legacy
        // transport-only route by allowing it to proceed directly to Ready;
        // any worker rejection still resolves `pending_opens` as an error.
        let accept_receiver = if require_session_accept {
            let (accept_reply, accept_receiver) = oneshot::channel();
            if self
                .pending_accepts
                .insert(wire.sid.clone(), (wire.clone(), accept_reply))
                .is_some()
            {
                self.pending_opens.remove(&wire);
                return Err(GatewayForwardingError::RouteAlreadyExists);
            }
            Some(accept_receiver)
        } else {
            None
        };

        let invite = session::SessionInvite {
            from: self.gateway_id.clone(),
            to: vec![format!("worker:{}", self.key.worker_id)],
            medium: "voice".into(),
            intent: intent.into(),
            capabilities_offer,
        };
        let offer = connection::ConnectionOffer {
            by_participant: self.gateway_id.clone(),
            substrate: "quic".into(),
            capabilities: serde_json::json!({"bridgefu_private_forwarding": 1}),
            streams_offered: vec![connection::StreamOffer {
                id: stream_id,
                kind: "audio".into(),
                direction: direction.into(),
                codec_preferences,
            }],
            substrate_setup: serde_json::Value::Null,
        };
        let setup_deadline = tokio::time::Instant::now() + timeout;
        let pre_accept_envelopes = [
            UctpEnvelope::new(
                MessageType::SessionInvite,
                serde_json::to_value(invite)
                    .map_err(|_| GatewayForwardingError::SignalingFailed)?,
            )
            .with_cid(conversation_id.clone())
            .with_sid(wire.sid.clone()),
            UctpEnvelope::new(
                MessageType::ConnectionOffer,
                serde_json::to_value(offer).map_err(|_| GatewayForwardingError::SignalingFailed)?,
            )
            .with_cid(conversation_id.clone())
            .with_sid(wire.sid.clone())
            .with_connid(wire.connid.clone()),
        ];
        for envelope in pre_accept_envelopes {
            match tokio::time::timeout_at(setup_deadline, self.client.send(envelope)).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => {
                    self.pending_opens.remove(&wire);
                    self.pending_accepts.remove(&wire.sid);
                    self.send_session_end(&wire.sid, timeout).await;
                    return Err(GatewayForwardingError::PeerUnavailable);
                }
                Err(_) => {
                    self.pending_opens.remove(&wire);
                    self.pending_accepts.remove(&wire.sid);
                    self.send_session_end(&wire.sid, timeout).await;
                    return Err(GatewayForwardingError::Timeout);
                }
            }
        }
        if let Some(accept_receiver) = accept_receiver {
            let accepted = tokio::time::timeout_at(setup_deadline, accept_receiver).await;
            self.pending_accepts.remove(&wire.sid);
            match accepted {
                Ok(Ok(Ok(()))) => {}
                Ok(Ok(Err(error))) => {
                    self.pending_opens.remove(&wire);
                    self.send_session_end(&wire.sid, timeout).await;
                    return Err(error);
                }
                Ok(Err(_)) => {
                    self.pending_opens.remove(&wire);
                    self.send_session_end(&wire.sid, timeout).await;
                    return Err(GatewayForwardingError::PeerUnavailable);
                }
                Err(_) => {
                    self.pending_opens.remove(&wire);
                    self.send_session_end(&wire.sid, timeout).await;
                    return Err(GatewayForwardingError::Timeout);
                }
            }
        }
        let ready = UctpEnvelope::new(MessageType::ConnectionReady, serde_json::json!({}))
            .with_cid(conversation_id.clone())
            .with_sid(wire.sid.clone())
            .with_connid(wire.connid.clone());
        match tokio::time::timeout_at(setup_deadline, self.client.send(ready)).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                self.pending_opens.remove(&wire);
                self.send_session_end(&wire.sid, timeout).await;
                return Err(GatewayForwardingError::PeerUnavailable);
            }
            Err(_) => {
                self.pending_opens.remove(&wire);
                self.send_session_end(&wire.sid, timeout).await;
                return Err(GatewayForwardingError::Timeout);
            }
        }
        let opened = tokio::time::timeout_at(setup_deadline, receiver).await;
        self.pending_opens.remove(&wire);
        let stream_local_id = match opened {
            Ok(Ok(Ok(stream_local_id))) => stream_local_id,
            Ok(Ok(Err(error))) => {
                self.send_session_end(&wire.sid, timeout).await;
                return Err(error);
            }
            Ok(Err(_)) => {
                self.send_session_end(&wire.sid, timeout).await;
                return Err(GatewayForwardingError::PeerUnavailable);
            }
            Err(_) => {
                self.send_session_end(&wire.sid, timeout).await;
                return Err(GatewayForwardingError::Timeout);
            }
        };
        Ok(OpenedWireRoute {
            wire,
            conversation_id,
            stream_local_id,
            attachment_receipt,
            pending_attachment_guard: None,
        })
    }

    async fn send_session_end(&self, wire_session_id: &str, timeout: Duration) {
        let payload = session::SessionEnd {
            by: self.gateway_id.clone(),
            reason_code: 200,
            reason: "normal-clearing".into(),
        };
        if let Ok(payload) = serde_json::to_value(payload) {
            let envelope = UctpEnvelope::new(MessageType::SessionEnd, payload)
                .with_sid(wire_session_id.to_owned());
            let _ = tokio::time::timeout(timeout, self.client.send(envelope)).await;
        }
    }

    fn close(&self) {
        self.clear_pending_datagrams();
        self.cancel.cancel();
        self.client
            .connection
            .close(quinn::VarInt::from_u32(0), b"bridgefu-gateway-drain");
    }
}

fn wire_key(envelope: &UctpEnvelope) -> Option<WireRouteKey> {
    Some(WireRouteKey {
        sid: envelope.sid.clone()?,
        connid: envelope.connid.clone()?,
    })
}

fn map_attachment_error(error: GatewayAttachmentError) -> GatewayForwardingError {
    match error {
        GatewayAttachmentError::ProofRejected | GatewayAttachmentError::AdmissionRejected => {
            GatewayForwardingError::AttachmentRejected
        }
        GatewayAttachmentError::RoutingUnavailable => GatewayForwardingError::PeerUnavailable,
        GatewayAttachmentError::InvalidProtocol => GatewayForwardingError::InvalidDataMessage,
    }
}

fn map_private_egress_stream_error(error: PrivateEgressStreamError) -> GatewayForwardingError {
    match error {
        PrivateEgressStreamError::CapacityExceeded => GatewayForwardingError::CapacityExceeded,
        PrivateEgressStreamError::Timeout => GatewayForwardingError::Timeout,
        PrivateEgressStreamError::ConnectionUnavailable => GatewayForwardingError::PeerUnavailable,
        PrivateEgressStreamError::InvalidAdmission
        | PrivateEgressStreamError::Expired
        | PrivateEgressStreamError::OwnershipMismatch
        | PrivateEgressStreamError::AlreadyUsed => GatewayForwardingError::AttachmentRejected,
    }
}

fn current_unix_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .unwrap_or_default()
}

struct PrivateAudioCodec {
    name: String,
    payload_type: u8,
}

fn private_audio_codec(codec: &CodecInfo) -> Result<PrivateAudioCodec, GatewayForwardingError> {
    if codec.channels != 1 {
        return Err(GatewayForwardingError::UnsupportedCodec);
    }
    let (canonical, payload_type) = match codec.name.trim().to_ascii_lowercase().as_str() {
        "opus" if codec.clock_rate_hz == 48_000 => ("opus", 111),
        "pcmu" | "g.711-mu" | "g711-mu" | "g711u" if codec.clock_rate_hz == 8_000 => {
            ("g.711-mu", 0)
        }
        "pcma" | "g.711-a" | "g711-a" | "g711a" if codec.clock_rate_hz == 8_000 => ("g.711-a", 8),
        _ => return Err(GatewayForwardingError::UnsupportedCodec),
    };
    Ok(PrivateAudioCodec {
        name: canonical.to_owned(),
        payload_type,
    })
}

fn valid_worker_authority(authority: &str) -> bool {
    if authority.is_empty()
        || authority.len() > 512
        || authority.chars().any(char::is_control)
        || authority.contains(['/', '@', '?', '#'])
    {
        return false;
    }
    let Ok(url) = url::Url::parse(&format!("uctp+quic://{authority}")) else {
        return false;
    };
    url.host_str().is_some() && url.port().is_some()
}

async fn resolve_worker_endpoint(
    authority: &str,
    timeout: Duration,
) -> Result<SocketAddr, GatewayForwardingError> {
    if !valid_worker_authority(authority) {
        return Err(GatewayForwardingError::InvalidConfiguration);
    }
    let url = url::Url::parse(&format!("uctp+quic://{authority}"))
        .map_err(|_| GatewayForwardingError::InvalidConfiguration)?;
    let host = url
        .host_str()
        .ok_or(GatewayForwardingError::InvalidConfiguration)?
        .to_owned();
    let port = url
        .port()
        .ok_or(GatewayForwardingError::InvalidConfiguration)?;
    let mut resolved = tokio::time::timeout(timeout, tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| GatewayForwardingError::Timeout)?
        .map_err(|_| GatewayForwardingError::PeerUnavailable)?;
    resolved
        .next()
        .ok_or(GatewayForwardingError::PeerUnavailable)
}

async fn wait_for_envelope(
    inbound: &mut mpsc::Receiver<UctpEnvelope>,
    expected: MessageType,
    timeout: Duration,
) -> Result<UctpEnvelope, GatewayForwardingError> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let envelope = tokio::time::timeout_at(deadline, inbound.recv())
            .await
            .map_err(|_| GatewayForwardingError::Timeout)?
            .ok_or(GatewayForwardingError::PeerUnavailable)?;
        if envelope.msg_type == MessageType::Error {
            return Err(GatewayForwardingError::AuthenticationFailed);
        }
        if envelope.msg_type == expected {
            return Ok(envelope);
        }
    }
}

enum ReliableCommand {
    Rtcp(Bytes),
    Dtmf { digits: String, duration_ms: u32 },
    Data(DataMessage),
}

struct RouteInner {
    key: GatewayRouteKey,
    worker_id: WorkerId,
    wire: WireRouteKey,
    wire_conversation_id: String,
    stream_local_id: u16,
    binding_generation: Option<BindingGeneration>,
    worker_lease: Option<WorkerLease>,
    private_egress_source: bool,
    expected_payload_type: Option<u8>,
    broadcast_subscription: bool,
    dynamic_broadcast_stream: DynamicBroadcastStreamState,
    additional_stream_local_ids: Mutex<Vec<u16>>,
    peer: Arc<WorkerPeer>,
    inbound: Mutex<Option<mpsc::Sender<ForwardedPacket>>>,
    media: Mutex<Option<mpsc::Sender<Bytes>>>,
    reliable: Mutex<Option<mpsc::Sender<ReliableCommand>>>,
    permit: Mutex<Option<OwnedSemaphorePermit>>,
    peer_permit: Mutex<Option<OwnedSemaphorePermit>>,
    datagram_seq: AtomicU32,
    terminal_signaled: AtomicBool,
    closed: AtomicBool,
    owner: Weak<GatewayForwarderInner>,
}

impl fmt::Debug for RouteInner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RouteInner")
            .field("key", &self.key)
            .field("worker_id", &self.worker_id)
            .field("stream_local_id", &self.stream_local_id)
            .field("closed", &self.closed.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl RouteInner {
    fn private_egress_authority(&self) -> Option<PrivateEgressRouteAuthority> {
        if !self.private_egress_source {
            return None;
        }
        Some(PrivateEgressRouteAuthority {
            worker: self.worker_lease?,
            source: PrivateEgressSource {
                tenant_id: self.key.tenant_id().clone(),
                call_id: self.key.call_id(),
                leg_id: self.key.leg_id(),
                binding_generation: self.binding_generation?,
            },
        })
    }

    fn try_send_private_data(&self, message: DataMessage) -> Result<(), GatewayForwardingError> {
        message
            .validate()
            .map_err(|_| GatewayForwardingError::InvalidDataMessage)?;
        if !matches!(
            message.label.as_str(),
            PRIVATE_EGRESS_RESPONSE_LABEL | PRIVATE_EGRESS_LIFECYCLE_LABEL
        ) || message.reliability != rvoip_core::DataReliability::ReliableOrdered
        {
            return Err(GatewayForwardingError::InvalidDataMessage);
        }
        if self.closed.load(Ordering::Acquire) {
            return Err(GatewayForwardingError::Closed);
        }
        let sender = self
            .reliable
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
            .ok_or(GatewayForwardingError::Closed)?;
        sender
            .try_send(ReliableCommand::Data(message))
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => GatewayForwardingError::Backpressure,
                mpsc::error::TrySendError::Closed(_) => GatewayForwardingError::Closed,
            })
    }

    fn deliver(self: &Arc<Self>, packet: ForwardedPacket) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        let sender = self
            .inbound
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let Some(sender) = sender else {
            return;
        };
        match sender.try_send(packet) {
            Ok(()) => {
                metrics::counter!(
                    "bridgefu_private_forwarding_packets_total",
                    "direction" => "worker-to-gateway"
                )
                .increment(1);
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                metrics::counter!(
                    "bridgefu_private_forwarding_drops_total",
                    "reason" => "inbound-queue-full"
                )
                .increment(1);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => self.fail(GatewayForwardingError::Closed),
        }
    }

    fn fail(self: &Arc<Self>, _error: GatewayForwardingError) {
        if self.terminal_signaled.swap(true, Ordering::AcqRel) {
            return;
        }
        let route = Arc::clone(self);
        tokio::spawn(async move {
            let timeout = route
                .owner
                .upgrade()
                .map_or(Duration::from_secs(2), |owner| owner.timeouts.signaling);
            route.peer.send_session_end(&route.wire.sid, timeout).await;
            if let Some(owner) = route.owner.upgrade() {
                owner.retire_route(&route.key);
            }
        });
    }

    fn retire_remote(&self) {
        if let Some(owner) = self.owner.upgrade() {
            owner.retire_route(&self.key);
        }
    }

    fn close_channels(&self) {
        self.inbound
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        self.media
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        self.reliable
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        self.permit
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        self.peer_permit
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
    }

    fn take_global_permit(&self) -> Option<OwnedSemaphorePermit> {
        self.permit
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
    }
}

struct CallPin {
    worker_id: WorkerId,
    route_count: usize,
}

enum RouteSlot {
    Pending { worker_id: WorkerId },
    Active(Arc<RouteInner>),
}

struct RoutingState {
    calls: HashMap<CallRouteKey, CallPin>,
    routes: HashMap<GatewayRouteKey, RouteSlot>,
}

/// Tracks source-loss cleanup and lifecycle delivery independently from route
/// objects so process drain can await or abort every task before closing the
/// private transport. Source cleanup retains the route's global admission
/// permit, bounding that work by `max_active_routes` during rapid route churn.
struct SupervisedGatewayTasks {
    active: AtomicUsize,
    idle: Notify,
    tasks: Mutex<Vec<SupervisedGatewayTask>>,
}

struct SupervisedGatewayTaskGuard {
    owner: Arc<SupervisedGatewayTasks>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SupervisedGatewayTaskKind {
    LifecycleFailureCleanup,
    LifecycleDelivery,
    SourceCleanup,
}

struct SupervisedGatewayTask {
    kind: SupervisedGatewayTaskKind,
    handle: JoinHandle<()>,
}

impl Drop for SupervisedGatewayTaskGuard {
    fn drop(&mut self) {
        if self.owner.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.owner.idle.notify_waiters();
        }
    }
}

impl SupervisedGatewayTasks {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            active: AtomicUsize::new(0),
            idle: Notify::new(),
            tasks: Mutex::new(Vec::new()),
        })
    }

    fn spawn(
        self: &Arc<Self>,
        kind: SupervisedGatewayTaskKind,
        route_permit: Option<OwnedSemaphorePermit>,
        future: impl std::future::Future<Output = ()> + Send + 'static,
    ) {
        self.active.fetch_add(1, Ordering::AcqRel);
        let owner = Arc::clone(self);
        let task = tokio::spawn(async move {
            let _guard = SupervisedGatewayTaskGuard {
                owner: Arc::clone(&owner),
            };
            let _route_permit = route_permit;
            future.await;
        });
        let mut tasks = self
            .tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        tasks.retain(|task| !task.handle.is_finished());
        tasks.push(SupervisedGatewayTask { kind, handle: task });
    }

    fn active(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    fn snapshot(&self) -> GatewayShutdownTaskSnapshot {
        let tasks = self
            .tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut snapshot = GatewayShutdownTaskSnapshot::default();
        for task in tasks.iter().filter(|task| !task.handle.is_finished()) {
            match task.kind {
                SupervisedGatewayTaskKind::LifecycleFailureCleanup => {
                    snapshot.lifecycle_failure_cleanup += 1;
                }
                SupervisedGatewayTaskKind::LifecycleDelivery => {
                    snapshot.lifecycle_delivery += 1;
                }
                SupervisedGatewayTaskKind::SourceCleanup => {
                    snapshot.source_cleanup += 1;
                }
            }
        }
        snapshot
    }

    async fn drain_until(&self, deadline: tokio::time::Instant) -> bool {
        let mut timed_out = false;
        loop {
            let tasks = {
                let mut tasks = self
                    .tasks
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                std::mem::take(&mut *tasks)
            };
            for mut task in tasks {
                if tokio::time::timeout_at(deadline, &mut task.handle)
                    .await
                    .is_err()
                {
                    timed_out = true;
                    tracing::warn!(
                        task_kind = ?task.kind,
                        "supervised gateway teardown task exceeded the shutdown deadline"
                    );
                    task.handle.abort();
                    let _ = task.handle.await;
                }
            }
            if self.active() == 0 {
                let tasks_empty = self
                    .tasks
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .is_empty();
                if tasks_empty {
                    return timed_out;
                }
                continue;
            }
            let notified = self.idle.notified();
            if self.active() == 0 {
                continue;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                timed_out = true;
            }
        }
    }
}

struct GatewayForwarderInner {
    gateway_id: String,
    endpoint: Arc<Endpoint>,
    tls: Arc<ClientConfig>,
    minter: Arc<TokenMinter>,
    targets: HashMap<WorkerId, WorkerTargetRuntime>,
    peers: tokio::sync::Mutex<HashMap<PeerKey, Arc<WorkerPeer>>>,
    routing: Mutex<RoutingState>,
    capacity: Arc<Semaphore>,
    limits: PrivateForwardingLimits,
    timeouts: PrivateForwardingTimeouts,
    health: watch::Sender<ForwardingHealth>,
    draining: AtomicBool,
    idle: Notify,
    cancel: CancellationToken,
    monitor: Mutex<Option<JoinHandle<()>>>,
    warm_tenants: Vec<TenantId>,
    private_egress: OnceLock<Arc<PrivateEgressCommandService>>,
    lifecycle_delivery_locks: DashMap<PrivateEgressRouteKey, Arc<tokio::sync::Mutex<()>>>,
    shutdown_tasks: Arc<SupervisedGatewayTasks>,
}

impl GatewayForwarderInner {
    async fn send_private_egress_lifecycle_event(
        self: &Arc<Self>,
        authority: &PrivateEgressRouteAuthority,
        event: &PrivateEgressLifecycleEvent,
    ) -> Result<(), GatewayForwardingError> {
        let message = event
            .to_data_message()
            .map_err(|_| GatewayForwardingError::InvalidDataMessage)?;
        let source_key = GatewayRouteKey::new(
            authority.source.tenant_id.clone(),
            authority.source.call_id,
            authority.source.leg_id,
        );
        let route = {
            let routing = self
                .routing
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match routing.routes.get(&source_key) {
                Some(RouteSlot::Active(route)) => Some(Arc::clone(route)),
                Some(RouteSlot::Pending { .. }) | None => None,
            }
        };
        if let Some(route) = route {
            if route.private_egress_authority().as_ref() != Some(authority) {
                return Err(GatewayForwardingError::RouteNotActive);
            }
            return route.try_send_private_data(message);
        }
        let peer = {
            let peers = self.peers.lock().await;
            peers
                .get(&PeerKey {
                    worker_id: authority.worker.worker_id,
                    tenant_id: authority.source.tenant_id.clone(),
                })
                .cloned()
        }
        .ok_or(GatewayForwardingError::RouteNotActive)?;
        let pending = peer
            .pending_for_authority(authority.worker, &authority.source)
            .ok_or(GatewayForwardingError::RouteNotActive)?;
        if pending.authority().as_ref() != Some(authority) {
            return Err(GatewayForwardingError::RouteNotActive);
        }
        peer.send_private_data_during_promotion(&pending, message)
            .await
    }

    fn fail_private_egress_lifecycle_route(
        self: &Arc<Self>,
        authority: &PrivateEgressRouteAuthority,
        error: GatewayForwardingError,
    ) {
        let source_key = GatewayRouteKey::new(
            authority.source.tenant_id.clone(),
            authority.source.call_id,
            authority.source.leg_id,
        );
        let route = {
            let routing = self
                .routing
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match routing.routes.get(&source_key) {
                Some(RouteSlot::Active(route)) => Some(Arc::clone(route)),
                Some(RouteSlot::Pending { .. }) | None => None,
            }
        };
        if let Some(route) = route {
            if route.private_egress_authority().as_ref() == Some(authority) {
                route.fail(error);
            }
            return;
        }
        let inner = Arc::clone(self);
        let authority = authority.clone();
        self.shutdown_tasks.spawn(
            SupervisedGatewayTaskKind::LifecycleFailureCleanup,
            None,
            async move {
                let peer = {
                    let peers = inner.peers.lock().await;
                    peers
                        .get(&PeerKey {
                            worker_id: authority.worker.worker_id,
                            tenant_id: authority.source.tenant_id.clone(),
                        })
                        .cloned()
                };
                let Some(peer) = peer else {
                    return;
                };
                if let Some(pending) =
                    peer.pending_for_authority(authority.worker, &authority.source)
                {
                    peer.revoke_pending_attachment(&pending.wire, error);
                }
            },
        );
    }

    /// Serialize every lifecycle delivery for one exact route, replaying the
    /// durable monotonic journal until this event is acknowledged or the
    /// signaling deadline expires. A separate task is created per journaled
    /// event, but the shared route mutex preserves FIFO and bounds concurrent
    /// network writes to one.
    async fn deliver_private_egress_lifecycle(
        self: &Arc<Self>,
        service: Arc<PrivateEgressCommandService>,
        authority: PrivateEgressRouteAuthority,
        target: crate::private_egress::PrivateEgressTarget,
        event_id: uuid::Uuid,
    ) -> Result<(), GatewayForwardingError> {
        let key = PrivateEgressRouteKey::new(authority.worker, &authority.source, target);
        let delivery_lock = self
            .lifecycle_delivery_locks
            .entry(key.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let inner = Arc::clone(self);
        let (first_delivery, delivered) = oneshot::channel();
        self.shutdown_tasks.spawn(
            SupervisedGatewayTaskKind::LifecycleDelivery,
            None,
            async move {
                tracing::debug!(
                    %event_id,
                    source_generation = ?authority.source.binding_generation,
                    target_generation = ?target.binding_generation,
                    "private-egress lifecycle delivery waiting for its exact route lock"
                );
                let guard = delivery_lock.lock().await;
                tracing::debug!(
                    %event_id,
                    source_generation = ?authority.source.binding_generation,
                    target_generation = ?target.binding_generation,
                    "private-egress lifecycle delivery acquired its exact route lock"
                );
                let deadline = tokio::time::Instant::now() + inner.timeouts.signaling;
                let mut first_delivery = Some(first_delivery);
                let mut delivery_attempts = 0_u64;
                let outcome = loop {
                    if inner.cancel.is_cancelled() {
                        break Err(GatewayForwardingError::Draining);
                    }
                    let unacked = match service.unacked_lifecycle(&authority, target).await {
                        Ok(events) => events,
                        Err(_) => break Err(GatewayForwardingError::SignalingFailed),
                    };
                    if !unacked.iter().any(|event| event.event_id == event_id) {
                        break Ok(());
                    }
                    let mut sent = Ok(());
                    for event in &unacked {
                        delivery_attempts = delivery_attempts.saturating_add(1);
                        if let Err(error) = inner
                            .send_private_egress_lifecycle_event(&authority, event)
                            .await
                        {
                            if delivery_attempts == 1 {
                                tracing::debug!(
                                    awaited_event_id = %event_id,
                                    delivered_event_id = %event.event_id,
                                    source_generation = ?authority.source.binding_generation,
                                    target_generation = ?target.binding_generation,
                                    ?error,
                                    "initial private-egress lifecycle delivery failed"
                                );
                            }
                            sent = Err(error);
                            break;
                        } else if delivery_attempts == 1 {
                            tracing::debug!(
                                awaited_event_id = %event_id,
                                delivered_event_id = %event.event_id,
                                source_generation = ?authority.source.binding_generation,
                                target_generation = ?target.binding_generation,
                                "initial private-egress lifecycle delivery was enqueued"
                            );
                        }
                    }
                    if sent.is_ok() {
                        if let Some(first_delivery) = first_delivery.take() {
                            let _ = first_delivery.send(Ok(()));
                        }
                    }
                    if tokio::time::Instant::now() >= deadline {
                        break Err(sent.err().unwrap_or(GatewayForwardingError::Timeout));
                    }
                    tokio::select! {
                        _ = inner.cancel.cancelled() => {
                            break Err(GatewayForwardingError::Draining);
                        }
                        _ = tokio::time::sleep(PRIVATE_EGRESS_LIFECYCLE_RETRY_INTERVAL) => {}
                    }
                };
                match &outcome {
                    Ok(()) => tracing::debug!(
                        %event_id,
                        source_generation = ?authority.source.binding_generation,
                        target_generation = ?target.binding_generation,
                        delivery_attempts,
                        "private-egress lifecycle delivery was durably acknowledged"
                    ),
                    Err(error) => tracing::warn!(
                        %event_id,
                        source_generation = ?authority.source.binding_generation,
                        target_generation = ?target.binding_generation,
                        delivery_attempts,
                        ?error,
                        "private-egress lifecycle delivery ended without an ACK"
                    ),
                }
                if let Err(error) = outcome {
                    inner.fail_private_egress_lifecycle_route(&authority, error);
                }
                if let Some(first_delivery) = first_delivery.take() {
                    let _ = first_delivery.send(outcome);
                }
                drop(guard);
                inner
                    .lifecycle_delivery_locks
                    .remove_if(&key, |_, candidate| {
                        Arc::ptr_eq(candidate, &delivery_lock) && Arc::strong_count(candidate) == 2
                    });
            },
        );
        match tokio::time::timeout(self.timeouts.signaling, delivered).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(GatewayForwardingError::SignalingFailed),
            Err(_) => Err(GatewayForwardingError::Timeout),
        }
    }

    async fn ensure_peer(
        self: &Arc<Self>,
        worker_id: WorkerId,
        tenant_id: &TenantId,
    ) -> Result<Arc<WorkerPeer>, GatewayForwardingError> {
        if self.draining.load(Ordering::Acquire) {
            return Err(GatewayForwardingError::Draining);
        }
        let target = self
            .targets
            .get(&worker_id)
            .cloned()
            .ok_or(GatewayForwardingError::UnknownWorker)?;
        let key = PeerKey {
            worker_id,
            tenant_id: tenant_id.clone(),
        };
        let mut peers = self.peers.lock().await;
        let stale = peers
            .values()
            .filter(|peer| !peer.is_live())
            .cloned()
            .collect::<Vec<_>>();
        for peer in stale {
            peer.fail(GatewayForwardingError::PeerUnavailable);
        }
        peers.retain(|_, peer| peer.is_live());
        if let Some(peer) = peers.get(&key) {
            if peer.is_live() {
                return Ok(Arc::clone(peer));
            }
            peer.close();
            peers.remove(&key);
        }
        if peers.len() >= self.limits.max_peer_connections {
            return Err(GatewayForwardingError::CapacityExceeded);
        }
        let peer = WorkerPeer::connect(self, key.clone(), target).await?;
        peers.insert(key, Arc::clone(&peer));
        metrics::gauge!("bridgefu_private_forwarding_peer_connections").set(peers.len() as f64);
        Ok(peer)
    }

    fn reserve_route(
        &self,
        key: &GatewayRouteKey,
        worker_id: WorkerId,
    ) -> Result<(), GatewayForwardingError> {
        let mut routing = self
            .routing
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if routing.routes.contains_key(key) {
            return Err(GatewayForwardingError::RouteAlreadyExists);
        }
        let call_key = key.call_key();
        match routing.calls.get_mut(&call_key) {
            Some(pin) if pin.worker_id != worker_id => {
                return Err(GatewayForwardingError::WorkerPinMismatch)
            }
            Some(pin) => pin.route_count += 1,
            None => {
                routing.calls.insert(
                    call_key,
                    CallPin {
                        worker_id,
                        route_count: 1,
                    },
                );
            }
        }
        routing
            .routes
            .insert(key.clone(), RouteSlot::Pending { worker_id });
        Ok(())
    }

    fn activate_route(
        &self,
        key: &GatewayRouteKey,
        route: Arc<RouteInner>,
    ) -> Result<(), GatewayForwardingError> {
        let mut routing = self
            .routing
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match routing.routes.get(key) {
            Some(RouteSlot::Pending { worker_id }) if *worker_id == route.worker_id => {
                routing.routes.insert(key.clone(), RouteSlot::Active(route));
                Ok(())
            }
            _ => Err(GatewayForwardingError::RouteNotActive),
        }
    }

    fn rollback_route(&self, key: &GatewayRouteKey) {
        let mut routing = self
            .routing
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if routing.routes.remove(key).is_some() {
            release_call_pin(&mut routing, key);
        }
        if routing.routes.is_empty() {
            self.idle.notify_waiters();
        }
    }

    fn retire_route(&self, key: &GatewayRouteKey) {
        let route = {
            let mut routing = self
                .routing
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let removed = routing.routes.remove(key);
            let route = match removed.as_ref() {
                Some(RouteSlot::Active(route)) => Some(Arc::clone(route)),
                Some(RouteSlot::Pending { .. }) | None => None,
            };
            // A pending route already incremented the call pin in
            // `reserve_route`. Shutdown can retire that slot while its
            // signaling future is still in flight, so release the pin for
            // every removed slot rather than only activated routes.
            if removed.is_some() {
                release_call_pin(&mut routing, key);
            }
            if routing.routes.is_empty() {
                self.idle.notify_waiters();
            }
            route
        };
        let Some(route) = route else {
            return;
        };
        if let (Some(service), Some(authority)) = (
            self.private_egress.get().cloned(),
            route.private_egress_authority(),
        ) {
            let route_permit = route.take_global_permit();
            self.shutdown_tasks.spawn(
                SupervisedGatewayTaskKind::SourceCleanup,
                route_permit,
                async move {
                    service.end_source(&authority).await;
                },
            );
        }
        if !route.peer.retire_route_streams(&route) {
            return;
        }
        route.close_channels();
        metrics::counter!("bridgefu_private_forwarding_routes_total", "outcome" => "closed")
            .increment(1);
        metrics::gauge!("bridgefu_private_forwarding_active_routes").set(self.route_count() as f64);
    }

    fn route_count(&self) -> usize {
        self.routing
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .routes
            .len()
    }

    async fn check_workers(self: &Arc<Self>) -> ForwardingHealth {
        if self.draining.load(Ordering::Acquire) {
            return ForwardingHealth::Draining;
        }
        let Some(tenant) = self.warm_tenants.first().cloned() else {
            return ForwardingHealth::Degraded;
        };
        let worker_ids = self.targets.keys().copied().collect::<Vec<_>>();
        let mut healthy = true;
        for worker_id in worker_ids {
            if self.ensure_peer(worker_id, &tenant).await.is_err() {
                healthy = false;
            }
        }
        if healthy {
            ForwardingHealth::Healthy
        } else {
            ForwardingHealth::Degraded
        }
    }

    fn spawn_monitor(self: &Arc<Self>) {
        let owner = Arc::downgrade(self);
        let cancel = self.cancel.clone();
        let interval = self.timeouts.health_interval;
        let task = tokio::spawn(async move {
            loop {
                let Some(inner) = owner.upgrade() else {
                    return;
                };
                let health = inner.check_workers().await;
                inner.health.send_replace(health);
                drop(inner);
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep(interval) => {}
                }
            }
        });
        *self
            .monitor
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(task);
    }
}

fn release_call_pin(routing: &mut RoutingState, key: &GatewayRouteKey) {
    let call_key = key.call_key();
    let remove = routing.calls.get_mut(&call_key).is_some_and(|pin| {
        pin.route_count = pin.route_count.saturating_sub(1);
        pin.route_count == 0
    });
    if remove {
        routing.calls.remove(&call_key);
    }
}

/// Concrete gateway edge.  Clone the `Arc`, not individual routes; each route
/// has one bounded inbound receiver and one explicit lifecycle.
pub struct GatewayForwarder {
    inner: Arc<GatewayForwarderInner>,
}

impl fmt::Debug for GatewayForwarder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayForwarder")
            .field("gateway_id_present", &!self.inner.gateway_id.is_empty())
            .field("worker_count", &self.inner.targets.len())
            .field("active_routes", &self.inner.route_count())
            .field("draining", &self.inner.draining.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl GatewayForwarder {
    pub async fn start(
        config: GatewayForwardingConfig,
        warm_tenants: Vec<TenantId>,
    ) -> Result<Arc<Self>, GatewayForwardingError> {
        config.validate()?;
        if warm_tenants.is_empty() {
            return Err(GatewayForwardingError::InvalidConfiguration);
        }
        install_crypto_provider();
        let tls = build_client_tls(&config.tls)?;
        let endpoint = Arc::new(
            make_client_endpoint(config.bind, Arc::clone(&tls))
                .map_err(|_| GatewayForwardingError::PeerUnavailable)?,
        );
        let targets = config
            .workers
            .iter()
            .map(|target| (target.worker_id, WorkerTargetRuntime::from(target)))
            .collect();
        let minter = Arc::new(TokenMinter {
            key: config.token_key,
            gateway_id: config.gateway_id.clone(),
            ttl: config.timeouts.token_ttl,
        });
        let (health, _) = watch::channel(ForwardingHealth::Degraded);
        let inner = Arc::new(GatewayForwarderInner {
            gateway_id: config.gateway_id,
            endpoint,
            tls,
            minter,
            targets,
            peers: tokio::sync::Mutex::new(HashMap::new()),
            routing: Mutex::new(RoutingState {
                calls: HashMap::new(),
                routes: HashMap::new(),
            }),
            capacity: Arc::new(Semaphore::new(config.limits.max_active_routes)),
            limits: config.limits,
            timeouts: config.timeouts,
            health,
            draining: AtomicBool::new(false),
            idle: Notify::new(),
            cancel: CancellationToken::new(),
            monitor: Mutex::new(None),
            warm_tenants,
            private_egress: OnceLock::new(),
            lifecycle_delivery_locks: DashMap::new(),
            shutdown_tasks: SupervisedGatewayTasks::new(),
        });
        let forwarder = Arc::new(Self {
            inner: Arc::clone(&inner),
        });
        let initial = inner.check_workers().await;
        inner.health.send_replace(initial);
        inner.spawn_monitor();
        Ok(forwarder)
    }

    pub fn subscribe_health(&self) -> watch::Receiver<ForwardingHealth> {
        self.inner.health.subscribe()
    }

    /// Install the only gateway-side private egress command authority. The
    /// forwarding socket may be constructed before signaling adapters, but a
    /// second handler can never replace the reviewed first installation.
    pub fn install_private_egress_service(
        &self,
        service: Arc<PrivateEgressCommandService>,
    ) -> Result<(), GatewayForwardingError> {
        self.inner
            .private_egress
            .set(service)
            .map_err(|_| GatewayForwardingError::InvalidConfiguration)
    }

    /// Publish one gateway-adapter lifecycle event after the exact source and
    /// target generations have been applied to the private egress state
    /// machine. Terminal events release egress capacity before delivery.
    pub async fn publish_private_egress_lifecycle(
        &self,
        event: PrivateEgressLifecycleEvent,
    ) -> Result<(), GatewayForwardingError> {
        let source_key = GatewayRouteKey::new(
            event.source.tenant_id.clone(),
            event.source.call_id,
            event.source.leg_id,
        );
        let route = {
            let routing = self
                .inner
                .routing
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match routing.routes.get(&source_key) {
                Some(RouteSlot::Active(route)) => Some(Arc::clone(route)),
                Some(RouteSlot::Pending { .. }) | None => None,
            }
        };
        let service = self
            .inner
            .private_egress
            .get()
            .cloned()
            .ok_or(GatewayForwardingError::RouteNotActive)?;
        let authority = if let Some(route) = route {
            route
                .private_egress_authority()
                .ok_or(GatewayForwardingError::RouteNotActive)?
        } else {
            let peer = {
                let peers = self.inner.peers.lock().await;
                peers
                    .get(&PeerKey {
                        worker_id: event.worker.worker_id,
                        tenant_id: event.source.tenant_id.clone(),
                    })
                    .cloned()
            }
            .ok_or(GatewayForwardingError::RouteNotActive)?;
            let pending = peer
                .pending_for_authority(event.worker, &event.source)
                .ok_or(GatewayForwardingError::RouteNotActive)?;
            pending
                .authority()
                .ok_or(GatewayForwardingError::RouteNotActive)?
        };
        let stamped = service
            .record_lifecycle(&authority, &event)
            .await
            .map_err(|_| GatewayForwardingError::SignalingFailed)?;
        self.inner
            .deliver_private_egress_lifecycle(service, authority, stamped.target, stamped.event_id)
            .await
    }

    pub fn active_routes(&self) -> usize {
        self.inner.route_count()
    }

    #[must_use]
    pub fn active_shutdown_tasks(&self) -> usize {
        self.inner.shutdown_tasks.active()
    }

    #[must_use]
    pub fn shutdown_task_snapshot(&self) -> GatewayShutdownTaskSnapshot {
        self.inner.shutdown_tasks.snapshot()
    }

    pub async fn open_route(
        &self,
        key: GatewayRouteKey,
        worker_id: WorkerId,
    ) -> Result<GatewayForwardingRoute, GatewayForwardingError> {
        self.open_route_inner(key, worker_id, None).await
    }

    /// Open a non-attachment private route constrained to one exact public
    /// codec. This is used by native-edge integration tests and by callers
    /// that already own an exact durable route key.
    pub async fn open_route_with_codec(
        &self,
        key: GatewayRouteKey,
        worker_id: WorkerId,
        codec: CodecInfo,
    ) -> Result<GatewayForwardingRoute, GatewayForwardingError> {
        let codec = private_audio_codec(&codec)?;
        self.open_route_inner(key, worker_id, Some(codec)).await
    }

    async fn open_route_inner(
        &self,
        key: GatewayRouteKey,
        worker_id: WorkerId,
        codec: Option<PrivateAudioCodec>,
    ) -> Result<GatewayForwardingRoute, GatewayForwardingError> {
        if self.inner.draining.load(Ordering::Acquire) {
            return Err(GatewayForwardingError::Draining);
        }
        if !self.inner.targets.contains_key(&worker_id) {
            return Err(GatewayForwardingError::UnknownWorker);
        }
        let permit = Arc::clone(&self.inner.capacity)
            .try_acquire_owned()
            .map_err(|_| GatewayForwardingError::CapacityExceeded)?;
        self.inner.reserve_route(&key, worker_id)?;

        let opened = async {
            let peer = self.inner.ensure_peer(worker_id, key.tenant_id()).await?;
            let peer_permit = Arc::clone(&peer.route_capacity)
                .try_acquire_owned()
                .map_err(|_| GatewayForwardingError::CapacityExceeded)?;
            let codec_preferences = codec.as_ref().map_or_else(
                || vec!["opus".into(), "g.711-mu".into(), "g.711-a".into()],
                |codec| vec![codec.name.clone()],
            );
            let opened = peer
                .open_route(&key, codec_preferences, self.inner.timeouts.signaling)
                .await?;
            if opened.stream_local_id == 0
                || peer.routes_by_local.contains_key(&opened.stream_local_id)
            {
                peer.send_session_end(&opened.wire.sid, self.inner.timeouts.signaling)
                    .await;
                return Err(GatewayForwardingError::SignalingFailed);
            }
            let (inbound_tx, inbound_rx) = mpsc::channel(self.inner.limits.inbound_queue_capacity);
            let (media_tx, media_rx) = mpsc::channel(self.inner.limits.media_queue_capacity);
            let (reliable_tx, reliable_rx) =
                mpsc::channel(self.inner.limits.reliable_queue_capacity);
            let wire = opened.wire;
            let stream_local_id = opened.stream_local_id;
            let route = Arc::new(RouteInner {
                key: key.clone(),
                worker_id,
                wire: wire.clone(),
                wire_conversation_id: opened.conversation_id,
                stream_local_id,
                binding_generation: None,
                worker_lease: None,
                private_egress_source: false,
                expected_payload_type: codec.as_ref().map(|codec| codec.payload_type),
                broadcast_subscription: false,
                dynamic_broadcast_stream: DynamicBroadcastStreamState::disabled(),
                additional_stream_local_ids: Mutex::new(Vec::new()),
                peer: Arc::clone(&peer),
                inbound: Mutex::new(Some(inbound_tx)),
                media: Mutex::new(Some(media_tx)),
                reliable: Mutex::new(Some(reliable_tx)),
                permit: Mutex::new(Some(permit)),
                peer_permit: Mutex::new(Some(peer_permit)),
                datagram_seq: AtomicU32::new(0),
                terminal_signaled: AtomicBool::new(false),
                closed: AtomicBool::new(false),
                owner: Arc::downgrade(&self.inner),
            });
            if let Err(error) = self.inner.activate_route(&key, Arc::clone(&route)) {
                peer.send_session_end(&wire.sid, self.inner.timeouts.signaling)
                    .await;
                return Err(error);
            }
            peer.routes_by_wire.insert(wire, Arc::downgrade(&route));
            peer.routes_by_local
                .insert(stream_local_id, Arc::downgrade(&route));
            spawn_reliable_pump(
                Arc::clone(&route),
                reliable_rx,
                self.inner.timeouts.signaling,
            );
            spawn_media_pump(Arc::clone(&route), media_rx, self.inner.timeouts.signaling);
            Ok(GatewayForwardingRoute {
                inner: route,
                inbound: tokio::sync::Mutex::new(inbound_rx),
            })
        }
        .await;

        match opened {
            Ok(route) => {
                metrics::counter!("bridgefu_private_forwarding_routes_total", "outcome" => "opened")
                    .increment(1);
                metrics::gauge!("bridgefu_private_forwarding_active_routes")
                    .set(self.inner.route_count() as f64);
                Ok(route)
            }
            Err(error) => {
                self.inner.rollback_route(&key);
                metrics::counter!("bridgefu_private_forwarding_routes_total", "outcome" => "failed")
                    .increment(1);
                Err(error)
            }
        }
    }

    /// Resolve and consume one public attachment on exactly the worker fence
    /// selected by the gateway's coordination projection. Call/leg identity
    /// is disclosed only by the worker's post-activation receipt.
    pub async fn open_attachment_route(
        &self,
        authorization: GatewayAttachmentAuthorization,
        codec: CodecInfo,
    ) -> Result<GatewayForwardingRoute, GatewayForwardingError> {
        if self.inner.draining.load(Ordering::Acquire) {
            return Err(GatewayForwardingError::Draining);
        }
        let codec = private_audio_codec(&codec)?;
        let tenant_id = authorization.tenant_id().map_err(map_attachment_error)?;
        let expected_worker = authorization.worker();
        if !self.inner.targets.contains_key(&expected_worker.worker_id) {
            return Err(GatewayForwardingError::UnknownWorker);
        }
        let permit = Arc::clone(&self.inner.capacity)
            .try_acquire_owned()
            .map_err(|_| GatewayForwardingError::CapacityExceeded)?;
        let peer = self
            .inner
            .ensure_peer(expected_worker.worker_id, &tenant_id)
            .await?;
        let peer_permit = Arc::clone(&peer.route_capacity)
            .try_acquire_owned()
            .map_err(|_| GatewayForwardingError::CapacityExceeded)?;
        let request_id = uuid::Uuid::new_v4();
        let request = authorization.into_request(request_id);
        let mut opened = peer
            .open_attachment_route(
                &tenant_id,
                expected_worker,
                request,
                codec.name.clone(),
                self.inner.timeouts.signaling,
            )
            .await?;
        let receipt = match opened.attachment_receipt.take() {
            Some(receipt) => receipt,
            None => {
                peer.revoke_pending_attachment(
                    &opened.wire,
                    GatewayForwardingError::InvalidDataMessage,
                );
                return Err(GatewayForwardingError::InvalidDataMessage);
            }
        };
        let mut pending_guard = match opened.pending_attachment_guard.take() {
            Some(guard) => guard,
            None => {
                peer.revoke_pending_attachment(
                    &opened.wire,
                    GatewayForwardingError::AttachmentRejected,
                );
                return Err(GatewayForwardingError::AttachmentRejected);
            }
        };
        if receipt.tenant_id != tenant_id || receipt.worker != expected_worker {
            peer.revoke_pending_attachment(
                &opened.wire,
                GatewayForwardingError::AttachmentRejected,
            );
            return Err(GatewayForwardingError::AttachmentRejected);
        }
        if opened.stream_local_id == 0 || peer.routes_by_local.contains_key(&opened.stream_local_id)
        {
            peer.revoke_pending_attachment(&opened.wire, GatewayForwardingError::SignalingFailed);
            return Err(GatewayForwardingError::SignalingFailed);
        }
        let key = GatewayRouteKey::new(receipt.tenant_id.clone(), receipt.call_id, receipt.leg_id);
        if let Err(error) = self.inner.reserve_route(&key, expected_worker.worker_id) {
            peer.revoke_pending_attachment(&opened.wire, error);
            return Err(error);
        }

        let stream_local_id = opened.stream_local_id;
        let wire = opened.wire;
        let (inbound_tx, inbound_rx) = mpsc::channel(self.inner.limits.inbound_queue_capacity);
        let (media_tx, media_rx) = mpsc::channel(self.inner.limits.media_queue_capacity);
        let (reliable_tx, reliable_rx) = mpsc::channel(self.inner.limits.reliable_queue_capacity);
        let route = Arc::new(RouteInner {
            key: key.clone(),
            worker_id: expected_worker.worker_id,
            wire: wire.clone(),
            wire_conversation_id: opened.conversation_id,
            stream_local_id,
            binding_generation: Some(receipt.binding_generation),
            worker_lease: Some(receipt.worker),
            private_egress_source: true,
            expected_payload_type: Some(codec.payload_type),
            broadcast_subscription: false,
            dynamic_broadcast_stream: DynamicBroadcastStreamState::disabled(),
            additional_stream_local_ids: Mutex::new(Vec::new()),
            peer: Arc::clone(&peer),
            inbound: Mutex::new(Some(inbound_tx)),
            media: Mutex::new(Some(media_tx)),
            reliable: Mutex::new(Some(reliable_tx)),
            permit: Mutex::new(Some(permit)),
            peer_permit: Mutex::new(Some(peer_permit)),
            datagram_seq: AtomicU32::new(0),
            terminal_signaled: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            owner: Arc::downgrade(&self.inner),
        });
        if let Err(error) = self.inner.activate_route(&key, Arc::clone(&route)) {
            self.inner.rollback_route(&key);
            peer.revoke_pending_attachment(&wire, error);
            return Err(error);
        }
        peer.routes_by_wire
            .insert(wire.clone(), Arc::downgrade(&route));
        peer.routes_by_local
            .insert(stream_local_id, Arc::downgrade(&route));
        if let Err(error) = peer.promote_pending_attachment(&wire, &receipt) {
            peer.routes_by_wire.remove(&wire);
            peer.routes_by_local.remove(&stream_local_id);
            peer.revoke_pending_attachment(&wire, error);
            route.fail(error);
            return Err(error);
        }
        pending_guard.disarm();
        spawn_reliable_pump(
            Arc::clone(&route),
            reliable_rx,
            self.inner.timeouts.signaling,
        );
        spawn_media_pump(Arc::clone(&route), media_rx, self.inner.timeouts.signaling);
        metrics::counter!("bridgefu_private_forwarding_routes_total", "outcome" => "opened")
            .increment(1);
        metrics::gauge!("bridgefu_private_forwarding_active_routes")
            .set(self.inner.route_count() as f64);
        Ok(GatewayForwardingRoute {
            inner: route,
            inbound: tokio::sync::Mutex::new(inbound_rx),
        })
    }

    /// Open the destination-side private media route for one exact worker
    /// reservation. This is a separate UCTP Session/Connection/Stream from
    /// the admitted source route, so the worker MediaGraph can consume both
    /// directions without aliasing the source receiver.
    pub async fn open_private_egress_stream_route(
        &self,
        admission: PrivateEgressStreamAdmission,
    ) -> Result<GatewayForwardingRoute, GatewayForwardingError> {
        if self.inner.draining.load(Ordering::Acquire) {
            return Err(GatewayForwardingError::Draining);
        }
        admission
            .validate(current_unix_time_ms())
            .map_err(map_private_egress_stream_error)?;
        if !self.inner.targets.contains_key(&admission.worker.worker_id) {
            return Err(GatewayForwardingError::UnknownWorker);
        }
        let codec = private_audio_codec(&admission.codec)?;
        let permit = Arc::clone(&self.inner.capacity)
            .try_acquire_owned()
            .map_err(|_| GatewayForwardingError::CapacityExceeded)?;
        let peer = self
            .inner
            .ensure_peer(admission.worker.worker_id, &admission.source.tenant_id)
            .await?;
        let peer_permit = Arc::clone(&peer.route_capacity)
            .try_acquire_owned()
            .map_err(|_| GatewayForwardingError::CapacityExceeded)?;
        let key = GatewayRouteKey::for_binding_generation(
            admission.source.tenant_id.clone(),
            admission.source.call_id,
            admission.target.leg_id,
            admission.target.binding_generation,
        );
        self.inner.reserve_route(&key, admission.worker.worker_id)?;

        let opened = match peer
            .open_private_egress_route(&admission, self.inner.timeouts.signaling)
            .await
        {
            Ok(opened) => opened,
            Err(error) => {
                self.inner.rollback_route(&key);
                return Err(error);
            }
        };
        if opened.stream_local_id == 0 || peer.routes_by_local.contains_key(&opened.stream_local_id)
        {
            self.inner.rollback_route(&key);
            peer.send_session_end(&opened.wire.sid, self.inner.timeouts.signaling)
                .await;
            return Err(GatewayForwardingError::SignalingFailed);
        }
        let stream_local_id = opened.stream_local_id;
        let wire = opened.wire;
        let (inbound_tx, inbound_rx) = mpsc::channel(self.inner.limits.inbound_queue_capacity);
        let (media_tx, media_rx) = mpsc::channel(self.inner.limits.media_queue_capacity);
        let (reliable_tx, reliable_rx) = mpsc::channel(self.inner.limits.reliable_queue_capacity);
        let route = Arc::new(RouteInner {
            key: key.clone(),
            worker_id: admission.worker.worker_id,
            wire: wire.clone(),
            wire_conversation_id: opened.conversation_id,
            stream_local_id,
            binding_generation: Some(admission.target.binding_generation),
            worker_lease: Some(admission.worker),
            private_egress_source: false,
            expected_payload_type: Some(codec.payload_type),
            broadcast_subscription: false,
            dynamic_broadcast_stream: DynamicBroadcastStreamState::disabled(),
            additional_stream_local_ids: Mutex::new(Vec::new()),
            peer: Arc::clone(&peer),
            inbound: Mutex::new(Some(inbound_tx)),
            media: Mutex::new(Some(media_tx)),
            reliable: Mutex::new(Some(reliable_tx)),
            permit: Mutex::new(Some(permit)),
            peer_permit: Mutex::new(Some(peer_permit)),
            datagram_seq: AtomicU32::new(0),
            terminal_signaled: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            owner: Arc::downgrade(&self.inner),
        });
        if let Err(error) = self.inner.activate_route(&key, Arc::clone(&route)) {
            self.inner.rollback_route(&key);
            peer.send_session_end(&wire.sid, self.inner.timeouts.signaling)
                .await;
            return Err(error);
        }
        peer.routes_by_wire.insert(wire, Arc::downgrade(&route));
        peer.routes_by_local
            .insert(stream_local_id, Arc::downgrade(&route));
        spawn_reliable_pump(
            Arc::clone(&route),
            reliable_rx,
            self.inner.timeouts.signaling,
        );
        spawn_media_pump(Arc::clone(&route), media_rx, self.inner.timeouts.signaling);
        metrics::counter!(
            "bridgefu_private_forwarding_routes_total",
            "outcome" => "egress-opened"
        )
        .increment(1);
        metrics::gauge!("bridgefu_private_forwarding_active_routes")
            .set(self.inner.route_count() as f64);
        Ok(GatewayForwardingRoute {
            inner: route,
            inbound: tokio::sync::Mutex::new(inbound_rx),
        })
    }

    /// Open a receive-only route from one durable UCTP broadcast on the
    /// worker that owns its fenced call. The canonical broadcast session is
    /// resolved only on the authenticated private worker connection; public
    /// subscriber credentials never cross this seam.
    pub async fn open_broadcast_route(
        &self,
        tenant_id: TenantId,
        call_id: CallId,
        broadcast_id: uuid::Uuid,
        worker: WorkerLease,
        grant_generation: uuid::Uuid,
    ) -> Result<GatewayForwardingRoute, GatewayForwardingError> {
        if self.inner.draining.load(Ordering::Acquire) {
            return Err(GatewayForwardingError::Draining);
        }
        if !self.inner.targets.contains_key(&worker.worker_id) {
            return Err(GatewayForwardingError::UnknownWorker);
        }
        let permit = Arc::clone(&self.inner.capacity)
            .try_acquire_owned()
            .map_err(|_| GatewayForwardingError::CapacityExceeded)?;
        let peer = self.inner.ensure_peer(worker.worker_id, &tenant_id).await?;
        let peer_permit = Arc::clone(&peer.route_capacity)
            .try_acquire_owned()
            .map_err(|_| GatewayForwardingError::CapacityExceeded)?;
        let listener_id = uuid::Uuid::new_v4();
        let key = GatewayRouteKey::new(tenant_id.clone(), call_id, LegId::new());
        self.inner.reserve_route(&key, worker.worker_id)?;

        let opened = match peer
            .open_broadcast_route(
                &tenant_id,
                broadcast_id,
                listener_id,
                worker,
                grant_generation,
                self.inner.timeouts.signaling,
            )
            .await
        {
            Ok(opened) => opened,
            Err(error) => {
                tracing::warn!(error = ?error, "private broadcast wire route open failed");
                self.inner.rollback_route(&key);
                return Err(error);
            }
        };
        if opened.stream_local_id == 0 || peer.routes_by_local.contains_key(&opened.stream_local_id)
        {
            self.inner.rollback_route(&key);
            peer.send_session_end(&opened.wire.sid, self.inner.timeouts.signaling)
                .await;
            return Err(GatewayForwardingError::SignalingFailed);
        }

        let stream_local_id = opened.stream_local_id;
        let wire = opened.wire;
        let (inbound_tx, inbound_rx) = mpsc::channel(self.inner.limits.inbound_queue_capacity);
        let (media_tx, media_rx) = mpsc::channel(self.inner.limits.media_queue_capacity);
        let (reliable_tx, reliable_rx) = mpsc::channel(self.inner.limits.reliable_queue_capacity);
        let route = Arc::new(RouteInner {
            key: key.clone(),
            worker_id: worker.worker_id,
            wire: wire.clone(),
            wire_conversation_id: opened.conversation_id,
            stream_local_id,
            binding_generation: None,
            worker_lease: Some(worker),
            private_egress_source: false,
            expected_payload_type: Some(111),
            broadcast_subscription: true,
            dynamic_broadcast_stream: DynamicBroadcastStreamState::awaiting(),
            additional_stream_local_ids: Mutex::new(Vec::new()),
            peer: Arc::clone(&peer),
            inbound: Mutex::new(Some(inbound_tx)),
            media: Mutex::new(Some(media_tx)),
            reliable: Mutex::new(Some(reliable_tx)),
            permit: Mutex::new(Some(permit)),
            peer_permit: Mutex::new(Some(peer_permit)),
            datagram_seq: AtomicU32::new(0),
            terminal_signaled: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            owner: Arc::downgrade(&self.inner),
        });
        if let Err(error) = self.inner.activate_route(&key, Arc::clone(&route)) {
            self.inner.rollback_route(&key);
            peer.send_session_end(&wire.sid, self.inner.timeouts.signaling)
                .await;
            return Err(error);
        }
        peer.routes_by_wire.insert(wire, Arc::downgrade(&route));
        peer.routes_by_local
            .insert(stream_local_id, Arc::downgrade(&route));
        spawn_reliable_pump(
            Arc::clone(&route),
            reliable_rx,
            self.inner.timeouts.signaling,
        );
        spawn_media_pump(Arc::clone(&route), media_rx, self.inner.timeouts.signaling);

        if let Err(error) = peer
            .subscribe_broadcast_route(
                &OpenedWireRoute {
                    wire: route.wire.clone(),
                    conversation_id: route.wire_conversation_id.clone(),
                    stream_local_id,
                    attachment_receipt: None,
                    pending_attachment_guard: None,
                },
                self.inner.timeouts.signaling,
            )
            .await
        {
            tracing::warn!(error = ?error, "private broadcast subscription failed");
            self.inner.retire_route(&key);
            return Err(error);
        }
        metrics::counter!("bridgefu_private_forwarding_routes_total", "outcome" => "opened")
            .increment(1);
        metrics::gauge!("bridgefu_private_forwarding_active_routes")
            .set(self.inner.route_count() as f64);
        Ok(GatewayForwardingRoute {
            inner: route,
            inbound: tokio::sync::Mutex::new(inbound_rx),
        })
    }

    pub fn begin_drain(&self) {
        if !self.inner.draining.swap(true, Ordering::AcqRel) {
            if let Some(service) = self.inner.private_egress.get() {
                service.begin_drain();
            }
            self.inner.health.send_replace(ForwardingHealth::Draining);
        }
    }

    pub async fn shutdown(&self, timeout: Duration) -> Result<(), GatewayForwardingError> {
        self.begin_drain();
        let started = tokio::time::Instant::now();
        let deadline = started + timeout;
        // Preserve half of the process budget for private End/Abort, proxy
        // teardown, and lifecycle acknowledgements after source routes stop.
        let route_deadline = started + timeout / 2;
        let mut timed_out = false;
        let mut service_failed = false;
        loop {
            let notified = self.inner.idle.notified();
            if self.inner.route_count() == 0 {
                break;
            }
            if tokio::time::timeout_at(route_deadline, notified)
                .await
                .is_err()
            {
                timed_out = true;
                tracing::warn!(
                    active_routes = self.inner.route_count(),
                    "gateway routes exceeded their shutdown deadline"
                );
                let keys = self
                    .inner
                    .routing
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .routes
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>();
                for key in keys {
                    self.inner.retire_route(&key);
                }
                break;
            }
        }

        timed_out |= self.inner.shutdown_tasks.drain_until(deadline).await;
        if let Some(service) = self.inner.private_egress.get() {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            match service.drain(remaining).await {
                Ok(()) => {}
                Err(PrivateEgressError::Timeout) => {
                    timed_out = true;
                    tracing::warn!(
                        ?remaining,
                        "private-egress service exceeded the gateway shutdown deadline"
                    );
                }
                Err(error) => {
                    service_failed = true;
                    tracing::warn!(
                        ?error,
                        "private-egress service failed during gateway shutdown"
                    );
                }
            }
        }
        // Proxy drain can force-close private media routes and enqueue their
        // exact source cleanup. Await that second wave before transport close.
        timed_out |= self.inner.shutdown_tasks.drain_until(deadline).await;
        self.inner.cancel.cancel();
        let monitor = self
            .inner
            .monitor
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(monitor) = monitor {
            let _ = tokio::time::timeout(
                deadline.saturating_duration_since(tokio::time::Instant::now()),
                monitor,
            )
            .await;
        }
        let peers = {
            let mut peers = self.inner.peers.lock().await;
            let values = peers.drain().map(|(_, peer)| peer).collect::<Vec<_>>();
            values
        };
        for peer in peers {
            peer.close();
        }
        self.inner
            .endpoint
            .close(quinn::VarInt::from_u32(0), b"bridgefu-gateway-stop");
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if tokio::time::timeout(remaining, self.inner.endpoint.wait_idle())
            .await
            .is_err()
        {
            timed_out = true;
            tracing::warn!("gateway QUIC endpoint did not become idle before shutdown deadline");
        }
        self.inner.health.send_replace(ForwardingHealth::Stopped);
        if service_failed {
            Err(GatewayForwardingError::SignalingFailed)
        } else if timed_out {
            Err(GatewayForwardingError::Timeout)
        } else {
            Ok(())
        }
    }
}

fn spawn_reliable_pump(
    route: Arc<RouteInner>,
    mut receiver: mpsc::Receiver<ReliableCommand>,
    timeout: Duration,
) {
    tokio::spawn(async move {
        while let Some(command) = receiver.recv().await {
            if let ReliableCommand::Dtmf {
                digits,
                duration_ms,
            } = command
            {
                let payload = rvoip_uctp::payloads::control::DtmfSend {
                    digits,
                    duration_ms,
                    method: "rfc4733".into(),
                };
                let envelope = match serde_json::to_value(payload) {
                    Ok(payload) => UctpEnvelope::new(MessageType::DtmfSend, payload)
                        .with_cid(route.wire_conversation_id.clone())
                        .with_sid(route.wire.sid.clone())
                        .with_connid(route.wire.connid.clone()),
                    Err(_) => {
                        route.fail(GatewayForwardingError::SignalingFailed);
                        return;
                    }
                };
                match tokio::time::timeout(timeout, route.peer.client.send(envelope)).await {
                    Ok(Ok(())) => {
                        metrics::counter!(
                            "bridgefu_private_forwarding_packets_total",
                            "direction" => "gateway-to-worker"
                        )
                        .increment(1);
                    }
                    Ok(Err(_)) => {
                        route.fail(GatewayForwardingError::PeerUnavailable);
                        return;
                    }
                    Err(_) => {
                        route.fail(GatewayForwardingError::Timeout);
                        return;
                    }
                }
                continue;
            }
            let message = match command {
                ReliableCommand::Rtcp(bytes) => {
                    DataMessage::reliable(PRIVATE_RTCP_LABEL, PRIVATE_RTCP_CONTENT_TYPE, bytes)
                }
                ReliableCommand::Data(message) => message,
                ReliableCommand::Dtmf { .. } => unreachable!("DTMF handled above"),
            };
            let payload = match message::MessageSend::from_data_message(
                &message,
                route.peer.gateway_id.clone(),
                serde_json::json!("all"),
            ) {
                Ok(payload) => payload,
                Err(_) => {
                    route.fail(GatewayForwardingError::InvalidDataMessage);
                    return;
                }
            };
            let envelope = match serde_json::to_value(payload) {
                Ok(payload) => UctpEnvelope::new(MessageType::MessageSend, payload)
                    .with_cid(route.wire_conversation_id.clone())
                    .with_sid(route.wire.sid.clone())
                    .with_connid(route.wire.connid.clone()),
                Err(_) => {
                    route.fail(GatewayForwardingError::InvalidDataMessage);
                    return;
                }
            };
            match tokio::time::timeout(timeout, route.peer.client.send(envelope)).await {
                Ok(Ok(())) => {
                    metrics::counter!(
                        "bridgefu_private_forwarding_packets_total",
                        "direction" => "gateway-to-worker"
                    )
                    .increment(1);
                }
                Ok(Err(_)) => {
                    route.fail(GatewayForwardingError::PeerUnavailable);
                    return;
                }
                Err(_) => {
                    route.fail(GatewayForwardingError::Timeout);
                    return;
                }
            }
        }
    });
}

fn spawn_media_pump(
    route: Arc<RouteInner>,
    mut receiver: mpsc::Receiver<Bytes>,
    timeout: Duration,
) {
    tokio::spawn(async move {
        while let Some(wire) = receiver.recv().await {
            match tokio::time::timeout(
                timeout,
                route.peer.client.connection.send_datagram_wait(wire),
            )
            .await
            {
                Ok(Ok(())) => {
                    metrics::counter!(
                        "bridgefu_private_forwarding_packets_total",
                        "direction" => "gateway-to-worker"
                    )
                    .increment(1);
                }
                Ok(Err(_)) => {
                    route.fail(GatewayForwardingError::PeerUnavailable);
                    return;
                }
                Err(_) => {
                    route.fail(GatewayForwardingError::Timeout);
                    return;
                }
            }
        }
    });
}

/// One active gateway leg.  Sending is nonblocking: QUIC datagram pressure or
/// a full reliable queue returns [`GatewayForwardingError::Backpressure`].
pub struct GatewayForwardingRoute {
    inner: Arc<RouteInner>,
    inbound: tokio::sync::Mutex<mpsc::Receiver<ForwardedPacket>>,
}

impl fmt::Debug for GatewayForwardingRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayForwardingRoute")
            .field("key", &self.inner.key)
            .field("worker_id", &self.inner.worker_id)
            .field("closed", &self.inner.closed.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl GatewayForwardingRoute {
    pub fn key(&self) -> &GatewayRouteKey {
        &self.inner.key
    }

    pub fn worker_id(&self) -> WorkerId {
        self.inner.worker_id
    }

    pub fn stream_local_id(&self) -> u16 {
        self.inner.stream_local_id
    }

    pub fn binding_generation(&self) -> Option<BindingGeneration> {
        self.inner.binding_generation
    }

    pub fn try_send_rtp(&self, packet: Bytes) -> Result<(), GatewayForwardingError> {
        if self.inner.broadcast_subscription {
            return Err(GatewayForwardingError::ReceiveOnly);
        }
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(GatewayForwardingError::Closed);
        }
        if self
            .inner
            .expected_payload_type
            .is_some_and(|expected| rtp_payload_type(&packet) != Some(expected))
        {
            return Err(GatewayForwardingError::UnsupportedCodec);
        }
        let seq = self.inner.datagram_seq.fetch_add(1, Ordering::Relaxed);
        let wire = pack(&MediaDatagram {
            flags: 0,
            stream_local_id: self.inner.stream_local_id,
            seq,
            payload: packet,
        });
        unpack_rtp_datagram(&wire).map_err(|_| GatewayForwardingError::InvalidRtp)?;
        let sender = self
            .inner
            .media
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
            .ok_or(GatewayForwardingError::Closed)?;
        sender.try_send(wire).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => GatewayForwardingError::Backpressure,
            mpsc::error::TrySendError::Closed(_) => GatewayForwardingError::Closed,
        })
    }

    pub fn try_send_rtcp(&self, packet: Bytes) -> Result<(), GatewayForwardingError> {
        validate_rtcp(&packet)?;
        self.try_send_reliable(ReliableCommand::Rtcp(packet))
    }

    pub fn try_send_dtmf(
        &self,
        digits: String,
        duration_ms: u32,
    ) -> Result<(), GatewayForwardingError> {
        if !valid_dtmf(&digits, duration_ms) {
            return Err(GatewayForwardingError::InvalidDataMessage);
        }
        self.try_send_reliable(ReliableCommand::Dtmf {
            digits,
            duration_ms,
        })
    }

    pub fn try_send_data(&self, message: DataMessage) -> Result<(), GatewayForwardingError> {
        message
            .validate()
            .map_err(|_| GatewayForwardingError::InvalidDataMessage)?;
        if message.label == PRIVATE_RTCP_LABEL
            || is_private_egress_label(&message.label)
            || message.reliability != rvoip_core::DataReliability::ReliableOrdered
        {
            return Err(GatewayForwardingError::InvalidDataMessage);
        }
        self.try_send_reliable(ReliableCommand::Data(message))
    }

    fn try_send_reliable(&self, command: ReliableCommand) -> Result<(), GatewayForwardingError> {
        if self.inner.broadcast_subscription {
            return Err(GatewayForwardingError::ReceiveOnly);
        }
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(GatewayForwardingError::Closed);
        }
        let sender = self
            .inner
            .reliable
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
            .ok_or(GatewayForwardingError::Closed)?;
        sender.try_send(command).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => GatewayForwardingError::Backpressure,
            mpsc::error::TrySendError::Closed(_) => GatewayForwardingError::Closed,
        })
    }

    pub async fn recv(&self) -> Option<ForwardedPacket> {
        self.inbound.lock().await.recv().await
    }

    pub async fn close(&self) {
        if self.inner.closed.load(Ordering::Acquire) {
            return;
        }
        self.inner
            .peer
            .send_session_end(&self.inner.wire.sid, Duration::from_secs(2))
            .await;
        if let Some(owner) = self.inner.owner.upgrade() {
            owner.retire_route(&self.inner.key);
        }
        self.inbound.lock().await.close();
    }

    /// Forced process-drain close. This skips the best-effort peer handshake
    /// but still runs the owner's supervised source cleanup and releases the
    /// exact route registrations. Normal call teardown must use `close`.
    pub(crate) fn force_close(&self) {
        if let Some(owner) = self.inner.owner.upgrade() {
            owner.retire_route(&self.inner.key);
        }
        if let Ok(mut inbound) = self.inbound.try_lock() {
            inbound.close();
        }
    }
}

impl Drop for GatewayForwardingRoute {
    fn drop(&mut self) {
        if self.inner.closed.load(Ordering::Acquire) {
            return;
        }
        let route = Arc::clone(&self.inner);
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                route
                    .peer
                    .send_session_end(&route.wire.sid, Duration::from_secs(1))
                    .await;
                if let Some(owner) = route.owner.upgrade() {
                    owner.retire_route(&route.key);
                }
            });
        } else if let Some(owner) = self.inner.owner.upgrade() {
            owner.retire_route(&self.inner.key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rvoip_auth_core::{AuthenticatedPrincipal, AuthenticationMethod};
    use rvoip_core::IdentityAssurance;

    use crate::call_engine::WorkerFence;

    #[test]
    fn private_egress_route_keys_allow_parallel_binding_generations() {
        let tenant = TenantId::parse("generation-key-tenant").unwrap();
        let call_id = CallId::new();
        let leg_id = LegId::new();
        let current_generation = BindingGeneration::INITIAL;
        let pending_generation = current_generation.next().unwrap();
        let current = GatewayRouteKey::for_binding_generation(
            tenant.clone(),
            call_id,
            leg_id,
            current_generation,
        );
        let pending = GatewayRouteKey::for_binding_generation(
            tenant.clone(),
            call_id,
            leg_id,
            pending_generation,
        );
        let source = GatewayRouteKey::new(tenant, call_id, leg_id);

        assert_ne!(current, pending);
        assert_ne!(current, source);
        assert_ne!(pending, source);
        assert_eq!(current.call_key(), pending.call_key());
        assert_eq!(current.leg_id(), pending.leg_id());
        assert_eq!(current.binding_generation(), Some(current_generation));
        assert_eq!(pending.binding_generation(), Some(pending_generation));
        assert_eq!(source.binding_generation(), None);

        let routes = HashMap::from([
            (
                current,
                RouteSlot::Pending {
                    worker_id: WorkerId::new(),
                },
            ),
            (
                pending,
                RouteSlot::Pending {
                    worker_id: WorkerId::new(),
                },
            ),
        ]);
        assert_eq!(routes.len(), 2);
    }

    #[tokio::test]
    async fn supervised_gateway_tasks_gracefully_drain_to_zero() {
        let tasks = SupervisedGatewayTasks::new();
        let capacity = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&capacity).acquire_owned().await.unwrap();
        let completed = Arc::new(AtomicBool::new(false));
        let mark_completed = Arc::clone(&completed);
        tasks.spawn(
            SupervisedGatewayTaskKind::SourceCleanup,
            Some(permit),
            async move {
                tokio::task::yield_now().await;
                mark_completed.store(true, Ordering::Release);
            },
        );

        assert!(
            !tasks
                .drain_until(tokio::time::Instant::now() + Duration::from_secs(1))
                .await
        );
        assert!(completed.load(Ordering::Acquire));
        assert_eq!(tasks.active(), 0);
        assert_eq!(capacity.available_permits(), 1);
    }

    #[tokio::test]
    async fn supervised_gateway_tasks_forced_timeout_aborts_and_releases_to_zero() {
        let tasks = SupervisedGatewayTasks::new();
        let capacity = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&capacity).acquire_owned().await.unwrap();
        tasks.spawn(
            SupervisedGatewayTaskKind::SourceCleanup,
            Some(permit),
            std::future::pending(),
        );

        assert!(
            tasks
                .drain_until(tokio::time::Instant::now() + Duration::from_millis(1))
                .await
        );
        assert_eq!(tasks.active(), 0);
        assert_eq!(capacity.available_permits(), 1);
    }

    fn pending_attachment_fixture() -> (
        Arc<PendingAttachmentAdmission>,
        oneshot::Receiver<Result<WorkerAttachmentAdmissionReceipt, GatewayForwardingError>>,
        WorkerAttachmentAdmissionReceipt,
    ) {
        let request_id = uuid::Uuid::new_v4();
        let tenant = TenantId::parse("tenant-a").expect("tenant");
        let worker = WorkerLease {
            worker_id: WorkerId::new(),
            fence: WorkerFence::INITIAL,
        };
        let receipt = WorkerAttachmentAdmissionReceipt {
            tenant_id: tenant.clone(),
            call_id: CallId::new(),
            leg_id: LegId::new(),
            binding_generation: BindingGeneration::INITIAL,
            worker,
        };
        let (pending, receiver) = PendingAttachmentAdmission::new(
            WireRouteKey {
                sid: format!("pending-session-{request_id}"),
                connid: format!("pending-connection-{request_id}"),
            },
            format!("pending-conversation-{request_id}"),
            request_id,
            tenant,
            worker,
        );
        (pending, receiver, receipt)
    }

    fn receipt_message(
        pending: &PendingAttachmentAdmission,
        receipt: WorkerAttachmentAdmissionReceipt,
    ) -> DataMessage {
        WorkerAttachmentAdmissionResponse::admitted(pending.request_id, receipt)
            .to_data_message()
            .expect("receipt message")
    }

    #[test]
    fn pending_attachment_receipt_installs_only_exact_authority() {
        let (pending, mut receiver, receipt) = pending_attachment_fixture();
        let message = receipt_message(&pending, receipt.clone());
        assert_eq!(
            pending
                .receive_receipt(Some(&pending.conversation_id), message)
                .expect("exact receipt"),
            receipt
        );
        let delivered = receiver.try_recv().expect("receipt delivered");
        assert_eq!(delivered.expect("admitted"), receipt);
        assert!(pending.matches_authority(
            receipt.worker,
            &PrivateEgressSource {
                tenant_id: receipt.tenant_id.clone(),
                call_id: receipt.call_id,
                leg_id: receipt.leg_id,
                binding_generation: receipt.binding_generation,
            }
        ));
        assert!(!pending.matches_authority(
            receipt.worker,
            &PrivateEgressSource {
                tenant_id: receipt.tenant_id.clone(),
                call_id: CallId::new(),
                leg_id: receipt.leg_id,
                binding_generation: receipt.binding_generation,
            }
        ));
    }

    #[test]
    fn pending_attachment_rejects_tampered_conversation_tenant_worker_and_request() {
        let (pending, _receiver, receipt) = pending_attachment_fixture();
        assert_eq!(
            pending.receive_receipt(
                Some("wrong-conversation"),
                receipt_message(&pending, receipt.clone()),
            ),
            Err(GatewayForwardingError::AttachmentRejected)
        );

        let (pending, _receiver, mut wrong_tenant) = pending_attachment_fixture();
        wrong_tenant.tenant_id = TenantId::parse("tenant-b").expect("tenant");
        assert_eq!(
            pending.receive_receipt(
                Some(&pending.conversation_id),
                receipt_message(&pending, wrong_tenant),
            ),
            Err(GatewayForwardingError::AttachmentRejected)
        );

        let (pending, _receiver, mut wrong_worker) = pending_attachment_fixture();
        wrong_worker.worker.worker_id = WorkerId::new();
        assert_eq!(
            pending.receive_receipt(
                Some(&pending.conversation_id),
                receipt_message(&pending, wrong_worker),
            ),
            Err(GatewayForwardingError::AttachmentRejected)
        );

        let (pending, _receiver, receipt) = pending_attachment_fixture();
        let wrong_request =
            WorkerAttachmentAdmissionResponse::admitted(uuid::Uuid::new_v4(), receipt)
                .to_data_message()
                .expect("receipt message");
        assert_eq!(
            pending.receive_receipt(Some(&pending.conversation_id), wrong_request),
            Err(GatewayForwardingError::AttachmentRejected)
        );
    }

    #[test]
    fn pending_attachment_replay_revocation_and_promotion_are_terminal() {
        let (pending, mut receiver, receipt) = pending_attachment_fixture();
        let message = receipt_message(&pending, receipt.clone());
        pending
            .receive_receipt(Some(&pending.conversation_id), message.clone())
            .expect("initial receipt");
        assert!(pending
            .receive_receipt(Some(&pending.conversation_id), message)
            .is_err());
        pending.revoke(GatewayForwardingError::AttachmentRejected);
        assert!(pending.authority().is_none());
        assert!(receiver.try_recv().expect("initial delivery").is_ok());

        let (pending, mut receiver, receipt) = pending_attachment_fixture();
        pending
            .receive_receipt(
                Some(&pending.conversation_id),
                receipt_message(&pending, receipt.clone()),
            )
            .expect("receipt");
        assert!(receiver.try_recv().expect("delivery").is_ok());
        pending.promote(&receipt).expect("exact promotion");
        assert!(pending.authority().is_none());
        assert_eq!(
            pending.promote(&receipt),
            Err(GatewayForwardingError::AttachmentRejected)
        );
    }

    #[test]
    fn pending_attachment_cleanup_clears_authority_and_wakes_waiter() {
        let (pending, mut receiver, _receipt) = pending_attachment_fixture();
        pending.revoke(GatewayForwardingError::Closed);
        assert!(pending.authority().is_none());
        assert_eq!(
            receiver.try_recv().expect("cleanup result"),
            Err(GatewayForwardingError::Closed)
        );
    }

    #[test]
    fn pending_datagrams_are_strictly_bounded_and_replace_in_place() {
        let now = Instant::now();
        let mut pending = PendingDatagrams::new(2, Duration::from_secs(5));
        assert!(pending.insert(1, Bytes::from_static(b"first"), now));
        assert!(pending.insert(
            1,
            Bytes::from_static(b"newest"),
            now + Duration::from_millis(100)
        ));
        assert_eq!(pending.len(), 1);
        assert_eq!(pending.fifo.len(), 1);
        assert!(pending.insert(2, Bytes::from_static(b"second"), now));
        assert!(!pending.insert(3, Bytes::from_static(b"over-cap"), now));
        assert!(!pending.insert(0, Bytes::from_static(b"reserved"), now));
        assert!(!pending.insert(4, Bytes::from(vec![0; MAX_PENDING_RTP_BYTES + 1]), now));

        assert!(pending.take(99, now).is_none());
        assert_eq!(pending.len(), 2);
        assert_eq!(pending.take(1, now), Some(Bytes::from_static(b"newest")));
        assert_eq!(pending.len(), 1);
        assert_eq!(pending.fifo.len(), 1);
        assert_eq!(pending.clear(), 1);
        assert_eq!(pending.len(), 0);
        assert!(pending.fifo.is_empty());
    }

    #[test]
    fn pending_datagram_replacement_cannot_extend_original_expiry() {
        let now = Instant::now();
        let mut pending = PendingDatagrams::new(1, Duration::from_secs(5));
        assert!(pending.insert(7, Bytes::from_static(b"first"), now));
        assert!(pending.insert(
            7,
            Bytes::from_static(b"replacement"),
            now + Duration::from_millis(900)
        ));

        assert_eq!(pending.expire(now + Duration::from_millis(999)), 0);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending.expire(now + Duration::from_secs(1)), 1);
        assert_eq!(pending.len(), 0);
        assert!(pending.fifo.is_empty());
    }

    #[test]
    fn dynamic_broadcast_stream_registration_is_one_shot() {
        let state = DynamicBroadcastStreamState::awaiting();
        assert!(state.is_awaiting());
        assert!(state.claim());
        assert!(!state.is_awaiting());
        assert!(!state.claim(), "a second StreamOpened must be rejected");
        state.close();
        assert!(state.is_closed());
        assert!(!state.claim(), "close is terminal");

        let disabled = DynamicBroadcastStreamState::disabled();
        assert!(
            !disabled.claim(),
            "ordinary routes cannot add dynamic streams"
        );
    }

    #[test]
    fn dynamic_stream_registration_and_retirement_have_one_terminal_owner() {
        for _ in 0..64 {
            let state = Arc::new(DynamicBroadcastStreamState::awaiting());
            let barrier = Arc::new(std::sync::Barrier::new(3));
            let registering = Arc::clone(&state);
            let registering_barrier = Arc::clone(&barrier);
            let register = std::thread::spawn(move || {
                registering_barrier.wait();
                registering.claim()
            });
            let retiring = Arc::clone(&state);
            let retiring_barrier = Arc::clone(&barrier);
            let retire = std::thread::spawn(move || {
                retiring_barrier.wait();
                retiring.close();
            });
            barrier.wait();
            let _ = register.join().expect("registration thread");
            retire.join().expect("retirement thread");
            assert!(state.is_closed());
            assert!(!state.claim(), "retirement must prevent stale registration");
        }
    }

    #[test]
    fn wrong_private_broadcast_intent_does_not_bind_listener() {
        let worker = WorkerLease {
            worker_id: WorkerId::new(),
            fence: WorkerFence::INITIAL,
        };
        let authority = WorkerBroadcastSubscriptionAuthority::new(worker);
        let tenant = TenantId::parse("tenant-a").expect("tenant");
        let broadcast_id = uuid::Uuid::new_v4();
        let listener_id = uuid::Uuid::new_v4();
        let generation = uuid::Uuid::new_v4();
        authority.activate_for_test(tenant, broadcast_id.to_string(), generation);
        let resolver = PrivateSessionResolver {
            draining: Arc::new(AtomicBool::new(false)),
            broadcast_authority: Some(Arc::clone(&authority)),
            private_egress_admissions: None,
        };
        let principal = AuthenticatedPrincipal {
            subject: "gateway-a".into(),
            tenant: Some("tenant-a".into()),
            scopes: vec![PRIVATE_FORWARD_SCOPE.into(), UCTP_SESSION_SCOPE.into()],
            issuer: Some(TOKEN_ISSUER.into()),
            expires_at: None,
            method: AuthenticationMethod::Jwt,
            assurance: IdentityAssurance::Anonymous,
        };
        let capability = serde_json::json!({
            PRIVATE_BROADCAST_CAPABILITY: {
                "broadcast_id": broadcast_id,
                "tenant_id": "tenant-a",
                "listener_id": listener_id,
                "worker_fence": worker.fence.as_i64(),
                "grant_generation": generation,
            }
        });

        let result = resolver.resolve_inbound_routing_hint(
            &principal,
            &SessionId::from_string(
                private_broadcast_wire_session(broadcast_id, listener_id).unwrap(),
            ),
            "wrong-intent",
            &capability,
        );

        assert!(result.is_err());
        assert_eq!(authority.listener_count(), 0);
    }

    #[test]
    fn private_broadcast_connection_reauthorization_is_exact_and_revocable() {
        let worker = WorkerLease {
            worker_id: WorkerId::new(),
            fence: WorkerFence::INITIAL,
        };
        let authority = WorkerBroadcastSubscriptionAuthority::new(worker);
        let tenant = TenantId::parse("tenant-a").expect("tenant");
        let broadcast_id = uuid::Uuid::new_v4();
        let listener_id = uuid::Uuid::new_v4();
        let generation = uuid::Uuid::new_v4();
        authority.activate_for_test(tenant, broadcast_id.to_string(), generation);
        assert!(authority.authorize_and_bind(
            "tenant-a",
            &broadcast_id.to_string(),
            listener_id,
            worker.fence.as_i64(),
            generation,
        ));
        let resolver = PrivateSessionResolver {
            draining: Arc::new(AtomicBool::new(false)),
            broadcast_authority: Some(Arc::clone(&authority)),
            private_egress_admissions: None,
        };
        let principal = AuthenticatedPrincipal {
            subject: "gateway-a".into(),
            tenant: Some("tenant-a".into()),
            scopes: vec![PRIVATE_FORWARD_SCOPE.into(), UCTP_SESSION_SCOPE.into()],
            issuer: Some(TOKEN_ISSUER.into()),
            expires_at: None,
            method: AuthenticationMethod::Jwt,
            assurance: IdentityAssurance::Anonymous,
        };
        let wire_session = SessionId::from_string(
            private_broadcast_wire_session(broadcast_id, listener_id).unwrap(),
        );
        let correct_connection =
            ConnectionId::from_string(format!("bf-broadcast-conn-v1.{listener_id}"));
        let sibling_connection =
            ConnectionId::from_string(format!("bf-broadcast-conn-v1.{}", uuid::Uuid::new_v4()));

        assert!(resolver
            .reauthorize_connection(
                &principal,
                &wire_session,
                &wire_session,
                &correct_connection,
                &ConnectionId::from_string("core-connection"),
            )
            .is_ok());
        assert!(resolver
            .reauthorize_connection(
                &principal,
                &wire_session,
                &wire_session,
                &sibling_connection,
                &ConnectionId::from_string("core-connection"),
            )
            .is_err());

        authority.unbind_listener(&broadcast_id.to_string(), listener_id);
        assert!(resolver
            .reauthorize_connection(
                &principal,
                &wire_session,
                &wire_session,
                &correct_connection,
                &ConnectionId::from_string("core-connection"),
            )
            .is_err());
    }

    #[test]
    fn private_subscription_scope_is_confined_to_exact_broadcast_generation() {
        let worker = WorkerLease {
            worker_id: WorkerId::new(),
            fence: WorkerFence::INITIAL,
        };
        let authority = WorkerBroadcastSubscriptionAuthority::new(worker);
        let tenant = TenantId::parse("tenant-a").expect("tenant");
        let broadcast_id = uuid::Uuid::new_v4();
        let other_broadcast_id = uuid::Uuid::new_v4();
        let listener_id = uuid::Uuid::new_v4();
        let generation = uuid::Uuid::new_v4();
        authority.activate_for_test(tenant.clone(), broadcast_id.to_string(), generation);
        assert!(authority.authorize_and_bind(
            tenant.as_str(),
            &broadcast_id.to_string(),
            listener_id,
            worker.fence.as_i64(),
            generation,
        ));

        let orchestrator = Orchestrator::new(rvoip_core::config::Config::default());
        let inner = OrchestratorSubscriptionHandler::with_accepted_codecs(
            Arc::clone(&orchestrator),
            orchestrator.publisher_registry(),
            ["opus"],
        );
        let handler = PrivateSubscriptionHandler {
            inner,
            broadcast_authority: Some(Arc::clone(&authority)),
        };
        let subscriber = ConnectionId::from_string("core-subscriber");
        let publisher = ConnectionId::from_string("authorized-publisher");
        let other_publisher = ConnectionId::from_string("other-tenant-publisher");
        let broadcast_session = SessionId::from_string(broadcast_id.to_string());
        let other_broadcast_session = SessionId::from_string(other_broadcast_id.to_string());
        let wire_broadcast_session = SessionId::from_string(
            private_broadcast_wire_session(broadcast_id, listener_id).unwrap(),
        );
        let other_wire_broadcast_session = SessionId::from_string(
            private_broadcast_wire_session(other_broadcast_id, uuid::Uuid::new_v4()).unwrap(),
        );
        let other_tenant_session = SessionId::from_string("tenant-b/private-call");
        handler.register_publisher(PublisherInfo {
            sid: &broadcast_session,
            strm_id: BROADCAST_STREAM_ID,
            connection: &publisher,
            participant: "origin-a",
            kind: "audio",
            codec: Some(CodecInfo::from_name_with_defaults("opus")),
        });
        for sid in [&other_broadcast_session, &other_tenant_session] {
            handler.register_publisher(PublisherInfo {
                sid,
                strm_id: BROADCAST_STREAM_ID,
                connection: &other_publisher,
                participant: "origin-b",
                kind: "audio",
                codec: Some(CodecInfo::from_name_with_defaults("opus")),
            });
        }
        let request = stream::StreamSubscribe {
            by_participant: "gateway-a".into(),
            subscriptions: vec![stream::StreamSubscription {
                strm_id: Some(BROADCAST_STREAM_ID.into()),
                ..Default::default()
            }],
        };

        assert_eq!(
            handler.subscribe(&wire_broadcast_session, &subscriber, &request),
            SubscriptionOutcome::Ok
        );
        assert!(matches!(
            handler.subscribe(&other_wire_broadcast_session, &subscriber, &request),
            SubscriptionOutcome::Reject { code: 403, .. }
        ));
        assert!(matches!(
            handler.subscribe(&other_tenant_session, &subscriber, &request),
            SubscriptionOutcome::Reject { code: 403, .. }
        ));
        assert_eq!(
            orchestrator.subscribers_for(
                &broadcast_session,
                &publisher,
                &rvoip_core::ids::StreamId::from_string(BROADCAST_STREAM_ID),
            ),
            vec![subscriber.clone()]
        );
        assert!(orchestrator
            .subscribers_for(
                &other_broadcast_session,
                &other_publisher,
                &rvoip_core::ids::StreamId::from_string(BROADCAST_STREAM_ID),
            )
            .is_empty());
        assert!(orchestrator
            .subscribers_for(
                &other_tenant_session,
                &other_publisher,
                &rvoip_core::ids::StreamId::from_string(BROADCAST_STREAM_ID),
            )
            .is_empty());
    }
}
