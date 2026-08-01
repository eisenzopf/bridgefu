//! Authenticated public UCTP attachment ingress for role-separated gateways.
//!
//! This is deliberately the only public media surface implemented by the
//! split `gateway` role today. A public peer authenticates with the configured
//! Bridgefu bearer validator and opens a UCTP Session whose ID contains one
//! exact, single-use SIP or WebRTC attachment token. The gateway resolves only
//! the token digest through Redis; the selected worker remains the sole
//! authority that consumes the bearer and discloses call/leg identity.
//!
//! Once admitted, encoded media is repacketized as complete RTP for the
//! private UCTP 0.2 route. Complete RTCP packets use Bridgefu's reserved
//! reliable DataMessage, while ordinary reliable DataMessages remain
//! transport-neutral in both directions.

use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::future::Future;
use std::io::{BufReader, Read};
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bytes::Bytes;
use chrono::Utc;
use futures_util::FutureExt;
use rvoip_auth_core::{AuthenticatedPrincipal, BearerAuthError, BearerValidator};
use rvoip_core::adapter::{ConnectionAdapter, EndReason, InboundRoutingHint, RejectReason};
use rvoip_core::capability::CodecInfo;
use rvoip_core::connection::Transport;
use rvoip_core::ids::{ConnectionId, SessionId, StreamId};
use rvoip_core::operational_events::{
    OperationalEvent, OperationalEventKind, OperationalEventStreamHealth,
};
use rvoip_core::stream::{MediaFrame, MediaStream, StreamKind};
use rvoip_core::{
    DataMessage, InboundAction, InboundAdmission, Orchestrator, ParticipantId, SessionMedium,
};
use rvoip_quic::{UctpQuicAdapter, UctpQuicConfig};
use rvoip_uctp::payloads::stream::{StreamSubscribe, StreamUnsubscribe};
use rvoip_uctp::state::{
    ResourceBindingError, SessionBindingResolver, SubscriptionHandler, SubscriptionOutcome,
    UctpCoordinatorCaps, UCTP_DATA_SCOPE, UCTP_RECEIVE_ONLY_SCOPE, UCTP_SESSION_SCOPE,
    UCTP_SUBSCRIBE_SCOPE,
};
use rvoip_uctp::substrate::{dispatch_by_alpn, make_server_endpoint};
use rvoip_uctp::UCTP_RAW_QUIC_ALPN_BYTES;
use sha2::Digest;
use thiserror::Error;
use tokio::sync::{mpsc, watch, Notify};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

use crate::broadcast::{
    exact_subscriber_broadcast, BroadcastCommandRepository, BroadcastGrantTransport,
    BroadcastTokenService, DurableBroadcastState, DurableBroadcastTransport,
    RedisBroadcastGrantStore, RedisUctpListenerLease,
};
use crate::call_engine::{AttachmentTransport, CallId, TenantId, WorkerLease};
use crate::call_service::parse_presented_attachment_token;
use crate::gateway_attachment::GatewayAttachmentResolver;
use crate::gateway_forwarding::{
    ForwardedPacket, GatewayForwarder, GatewayForwardingError, GatewayForwardingRoute,
    PRIVATE_RTCP_CONTENT_TYPE, PRIVATE_RTCP_LABEL,
};

/// Required scope added only to the gateway's public UCTP validator.
pub const PUBLIC_GATEWAY_ATTACHMENT_SCOPE: &str = "bridgefu:gateway-attach";
/// Stable wire prefix. The suffix is `sip|webrtc` plus a canonical token.
pub const PUBLIC_GATEWAY_SESSION_PREFIX: &str = "bf-public-attach-v1";
/// Session intent accepted by this listener.
pub const PUBLIC_GATEWAY_ATTACHMENT_INTENT: &str = "bridgefu-public-attachment";
/// Session intent accepted for a receive-only UCTP broadcast listener.
pub const PUBLIC_GATEWAY_BROADCAST_INTENT: &str = "bridgefu-public-broadcast-subscribe";
/// Canonical UCTP stream exposed by every audio broadcast.
pub const PUBLIC_GATEWAY_BROADCAST_STREAM: &str = "audio/main";

const MAX_CONTROL_QUEUE: usize = 64;
const RTP_FIXED_HEADER_BYTES: usize = 12;
const MAX_CONSECUTIVE_MEDIA_DROPS: usize = 50;
const PUBLIC_CONTROL_SEND_TIMEOUT: Duration = Duration::from_secs(2);
const BROADCAST_REVALIDATE_INTERVAL: Duration = Duration::from_millis(250);

/// Aggregate-safe state of the concrete public listener and its correctness
/// consumers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayUctpIngressHealth {
    Healthy,
    Degraded,
    Draining,
    Stopped,
}

/// Public listener configuration after YAML validation and secret resolution.
#[derive(Clone)]
pub struct GatewayUctpIngressConfig {
    pub bind: SocketAddr,
    pub certificate_chain: Vec<PathBuf>,
    pub private_key: PathBuf,
    pub max_concurrent_connections: usize,
    pub admission_capacity: usize,
    pub setup_timeout: Duration,
}

impl fmt::Debug for GatewayUctpIngressConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayUctpIngressConfig")
            .field("bind", &self.bind)
            .field("certificate_chain_files", &self.certificate_chain.len())
            .field(
                "private_key_configured",
                &!self.private_key.as_os_str().is_empty(),
            )
            .field(
                "max_concurrent_connections",
                &self.max_concurrent_connections,
            )
            .field("admission_capacity", &self.admission_capacity)
            .field("setup_timeout", &self.setup_timeout)
            .finish()
    }
}

impl GatewayUctpIngressConfig {
    fn validate(&self) -> Result<(), GatewayUctpIngressError> {
        if self.bind.port() == 0
            || self.certificate_chain.is_empty()
            || self.private_key.as_os_str().is_empty()
            || self.max_concurrent_connections == 0
            || self.admission_capacity == 0
            || self.setup_timeout.is_zero()
        {
            return Err(GatewayUctpIngressError::InvalidConfiguration);
        }
        Ok(())
    }
}

/// Process admission lease. Dropping the returned object must release the
/// gateway-wide capacity slot.
pub trait GatewayIngressAdmissionLease: Send {}
impl<T: Send> GatewayIngressAdmissionLease for T {}

/// Shared dependency/readiness admission used before any token is resolved.
pub trait GatewayIngressAdmission: Send + Sync {
    fn try_admit(&self) -> Result<Box<dyn GatewayIngressAdmissionLease>, GatewayUctpIngressError>;
}

#[async_trait]
trait GatewayMediaRoute: Send + Sync {
    fn try_send_rtp(&self, packet: Bytes) -> Result<(), GatewayForwardingError>;
    fn try_send_rtcp(&self, packet: Bytes) -> Result<(), GatewayForwardingError>;
    fn try_send_dtmf(&self, digits: String, duration_ms: u32)
        -> Result<(), GatewayForwardingError>;
    fn try_send_data(&self, message: DataMessage) -> Result<(), GatewayForwardingError>;
    async fn recv(&self) -> Option<ForwardedPacket>;
    async fn close(&self);
}

#[async_trait]
impl GatewayMediaRoute for GatewayForwardingRoute {
    fn try_send_rtp(&self, packet: Bytes) -> Result<(), GatewayForwardingError> {
        GatewayForwardingRoute::try_send_rtp(self, packet)
    }

    fn try_send_rtcp(&self, packet: Bytes) -> Result<(), GatewayForwardingError> {
        GatewayForwardingRoute::try_send_rtcp(self, packet)
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

/// Capability-reduced view used for public broadcast subscribers. No caller
/// holding this object can place RTP, RTCP, DTMF, or DataMessages on the
/// private worker route even if the public pump is changed later.
struct ReceiveOnlyGatewayMediaRoute(GatewayForwardingRoute);

#[async_trait]
impl GatewayMediaRoute for ReceiveOnlyGatewayMediaRoute {
    fn try_send_rtp(&self, _packet: Bytes) -> Result<(), GatewayForwardingError> {
        Err(GatewayForwardingError::InvalidRtp)
    }

    fn try_send_rtcp(&self, _packet: Bytes) -> Result<(), GatewayForwardingError> {
        Err(GatewayForwardingError::InvalidRtcp)
    }

    fn try_send_dtmf(
        &self,
        _digits: String,
        _duration_ms: u32,
    ) -> Result<(), GatewayForwardingError> {
        Err(GatewayForwardingError::InvalidDataMessage)
    }

    fn try_send_data(&self, _message: DataMessage) -> Result<(), GatewayForwardingError> {
        Err(GatewayForwardingError::InvalidDataMessage)
    }

    async fn recv(&self) -> Option<ForwardedPacket> {
        self.0.recv().await
    }

    async fn close(&self) {
        self.0.close().await;
    }
}

#[async_trait]
trait AttachmentRouteOpener: Send + Sync {
    async fn open(
        &self,
        principal: AuthenticatedPrincipal,
        token: String,
        transport: AttachmentTransport,
        codec: CodecInfo,
    ) -> Result<Arc<dyn GatewayMediaRoute>, GatewayUctpIngressError>;
}

struct ForwardingRouteOpener {
    resolver: Arc<GatewayAttachmentResolver>,
    forwarder: Arc<GatewayForwarder>,
}

#[async_trait]
impl AttachmentRouteOpener for ForwardingRouteOpener {
    async fn open(
        &self,
        principal: AuthenticatedPrincipal,
        token: String,
        transport: AttachmentTransport,
        codec: CodecInfo,
    ) -> Result<Arc<dyn GatewayMediaRoute>, GatewayUctpIngressError> {
        let authorization = self
            .resolver
            .resolve(principal, token, transport, Utc::now())
            .await
            .map_err(|_| GatewayUctpIngressError::AttachmentRejected)?;
        self.forwarder
            .open_attachment_route(authorization, codec)
            .await
            .map(|route| Arc::new(route) as Arc<dyn GatewayMediaRoute>)
            .map_err(GatewayUctpIngressError::Forwarding)
    }
}

/// Exact receive-only listener lease. Revalidation is fail-closed and close
/// removes only the ownership generation acquired by this gateway connection.
#[async_trait]
pub trait GatewayBroadcastListenerLease: Send + Sync {
    async fn revalidate(
        &self,
        principal: &AuthenticatedPrincipal,
    ) -> Result<bool, GatewayUctpIngressError>;
    async fn close(&self);
}

struct RedisGatewayBroadcastListenerLease {
    lease: tokio::sync::Mutex<Option<RedisUctpListenerLease>>,
}

#[async_trait]
impl GatewayBroadcastListenerLease for RedisGatewayBroadcastListenerLease {
    async fn revalidate(
        &self,
        principal: &AuthenticatedPrincipal,
    ) -> Result<bool, GatewayUctpIngressError> {
        let mut lease = self.lease.lock().await;
        let Some(lease) = lease.as_mut() else {
            return Ok(false);
        };
        if !lease
            .renew(principal)
            .await
            .map_err(|_| GatewayUctpIngressError::BroadcastRejected)?
        {
            return Ok(false);
        }
        lease
            .revalidate()
            .await
            .map_err(|_| GatewayUctpIngressError::BroadcastRejected)
    }

    async fn close(&self) {
        if let Some(lease) = self.lease.lock().await.take() {
            let _ = lease.close().await;
        }
    }
}

/// Durable route identity returned only after PostgreSQL and Redis agree on
/// the exact active UCTP publication and its call-pinned worker.
pub struct GatewayBroadcastAuthorization {
    tenant_id: TenantId,
    call_id: CallId,
    broadcast_id: uuid::Uuid,
    worker: WorkerLease,
    grant_generation: uuid::Uuid,
    lease: Arc<dyn GatewayBroadcastListenerLease>,
}

impl fmt::Debug for GatewayBroadcastAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayBroadcastAuthorization")
            .field("tenant_id", &self.tenant_id)
            .field("worker", &self.worker)
            .finish_non_exhaustive()
    }
}

/// Cluster authority used by the public gateway before it opens a private
/// worker route. Implementations must atomically reject credential replay.
#[async_trait]
pub trait GatewayBroadcastAuthority: Send + Sync {
    async fn authorize(
        &self,
        principal: &AuthenticatedPrincipal,
        broadcast_id: &str,
        connection_owner: &str,
    ) -> Result<GatewayBroadcastAuthorization, GatewayUctpIngressError>;
}

/// PostgreSQL durable state plus Redis exact-generation listener authority.
pub struct DurableGatewayBroadcastAuthority {
    repository: Arc<dyn BroadcastCommandRepository>,
    grants: Arc<RedisBroadcastGrantStore>,
}

impl DurableGatewayBroadcastAuthority {
    pub fn new(
        repository: Arc<dyn BroadcastCommandRepository>,
        grants: Arc<RedisBroadcastGrantStore>,
    ) -> Arc<Self> {
        Arc::new(Self { repository, grants })
    }
}

#[async_trait]
impl GatewayBroadcastAuthority for DurableGatewayBroadcastAuthority {
    async fn authorize(
        &self,
        principal: &AuthenticatedPrincipal,
        broadcast_id: &str,
        connection_owner: &str,
    ) -> Result<GatewayBroadcastAuthorization, GatewayUctpIngressError> {
        let scoped = exact_subscriber_broadcast(principal)
            .map_err(|_| GatewayUctpIngressError::BroadcastRejected)?;
        if scoped != broadcast_id || principal.is_expired() {
            return Err(GatewayUctpIngressError::BroadcastRejected);
        }
        let tenant_id = principal
            .tenant
            .as_deref()
            .ok_or(GatewayUctpIngressError::BroadcastRejected)
            .and_then(|tenant| {
                TenantId::parse(tenant).map_err(|_| GatewayUctpIngressError::BroadcastRejected)
            })?;
        let record = self
            .repository
            .get(&tenant_id, broadcast_id)
            .await
            .map_err(|_| GatewayUctpIngressError::NotReady)?
            .ok_or(GatewayUctpIngressError::BroadcastRejected)?;
        let runtime = record
            .runtime
            .as_ref()
            .filter(|_| record.state == DurableBroadcastState::Active)
            .ok_or(GatewayUctpIngressError::BroadcastRejected)?;
        if record.specification.transport != DurableBroadcastTransport::UctpQuic
            || record.specification.expires_at <= Utc::now()
            || record.specification.broadcast_id != broadcast_id
        {
            return Err(GatewayUctpIngressError::BroadcastRejected);
        }
        let grant_generation = runtime
            .grant_generation
            .ok_or(GatewayUctpIngressError::BroadcastRejected)?;
        let active = self
            .grants
            .active_grant(broadcast_id)
            .await
            .map_err(|_| GatewayUctpIngressError::NotReady)?
            .filter(|grant| {
                grant.tenant_id == tenant_id.as_str()
                    && grant.transport == BroadcastGrantTransport::UctpQuic
                    && grant.generation == grant_generation
            })
            .ok_or(GatewayUctpIngressError::BroadcastRejected)?;
        if !grant_expiry_covers_durable_expiry(active.expires_at, record.specification.expires_at) {
            return Err(GatewayUctpIngressError::BroadcastRejected);
        }
        let lease = self
            .grants
            .acquire_uctp_listener(principal, broadcast_id, connection_owner)
            .await
            .map_err(|_| GatewayUctpIngressError::BroadcastRejected)?;
        Ok(GatewayBroadcastAuthorization {
            tenant_id,
            call_id: record.specification.call_id,
            broadcast_id: uuid::Uuid::parse_str(broadcast_id)
                .ok()
                .filter(|id| !id.is_nil())
                .ok_or(GatewayUctpIngressError::BroadcastRejected)?,
            worker: record.specification.worker,
            grant_generation,
            lease: Arc::new(RedisGatewayBroadcastListenerLease {
                lease: tokio::sync::Mutex::new(Some(lease)),
            }),
        })
    }
}

// Redis stores grant deadlines with millisecond precision. Durable SQL rows
// may retain sub-millisecond nanoseconds, so comparing DateTime values directly
// would reject an otherwise identical deadline after the Redis round trip.
fn grant_expiry_covers_durable_expiry(
    grant_expires_at: chrono::DateTime<chrono::Utc>,
    durable_expires_at: chrono::DateTime<chrono::Utc>,
) -> bool {
    grant_expires_at.timestamp_millis() >= durable_expires_at.timestamp_millis()
}

struct OpenedGatewayBroadcastRoute {
    route: Arc<dyn GatewayMediaRoute>,
    lease: Arc<dyn GatewayBroadcastListenerLease>,
}

#[async_trait]
trait BroadcastRouteOpener: Send + Sync {
    async fn open(
        &self,
        principal: AuthenticatedPrincipal,
        broadcast_id: String,
        connection_owner: String,
    ) -> Result<OpenedGatewayBroadcastRoute, GatewayUctpIngressError>;
}

struct ForwardingBroadcastRouteOpener {
    authority: Arc<dyn GatewayBroadcastAuthority>,
    forwarder: Arc<GatewayForwarder>,
}

#[async_trait]
impl BroadcastRouteOpener for ForwardingBroadcastRouteOpener {
    async fn open(
        &self,
        principal: AuthenticatedPrincipal,
        broadcast_id: String,
        connection_owner: String,
    ) -> Result<OpenedGatewayBroadcastRoute, GatewayUctpIngressError> {
        let authorization = self
            .authority
            .authorize(&principal, &broadcast_id, &connection_owner)
            .await?;
        let route = self
            .forwarder
            .open_broadcast_route(
                authorization.tenant_id.clone(),
                authorization.call_id,
                authorization.broadcast_id,
                authorization.worker,
                authorization.grant_generation,
            )
            .await;
        let route = match route {
            Ok(route) => route,
            Err(error) => {
                // Authorization may own a Redis listener slot. Release it
                // deterministically when private route setup fails; Drop is
                // only a last-resort safety net and cannot be awaited.
                let _ = tokio::time::timeout(
                    PUBLIC_CONTROL_SEND_TIMEOUT,
                    AssertUnwindSafe(authorization.lease.close()).catch_unwind(),
                )
                .await;
                return Err(GatewayUctpIngressError::Forwarding(error));
            }
        };
        Ok(OpenedGatewayBroadcastRoute {
            route: Arc::new(ReceiveOnlyGatewayMediaRoute(route)),
            lease: authorization.lease,
        })
    }
}

/// Validator wrapper that retains the API validator's complete principal and
/// grants only the two scopes needed by this dedicated listener.
struct GatewayUctpBearerValidator {
    attachment: Arc<dyn BearerValidator>,
    broadcast: Arc<BroadcastTokenService>,
}

#[async_trait]
impl BearerValidator for GatewayUctpBearerValidator {
    async fn validate(
        &self,
        token: &str,
    ) -> Result<rvoip_core::IdentityAssurance, BearerAuthError> {
        Ok(self.validate_principal(token).await?.assurance)
    }

    async fn validate_principal(
        &self,
        token: &str,
    ) -> Result<AuthenticatedPrincipal, BearerAuthError> {
        let attachment = self.attachment.validate_principal(token).await;
        if let Ok(mut principal) = attachment {
            if exact_subscriber_broadcast(&principal).is_ok() {
                return Err(BearerAuthError::Invalid(
                    "attachment credential has broadcast authority".into(),
                ));
            }
            for scope in [
                UCTP_SESSION_SCOPE,
                UCTP_DATA_SCOPE,
                PUBLIC_GATEWAY_ATTACHMENT_SCOPE,
            ] {
                if !principal.scopes.iter().any(|candidate| candidate == scope) {
                    principal.scopes.push(scope.to_owned());
                }
            }
            return Ok(principal);
        }
        let principal = self.broadcast.validate_principal(token).await?;
        exact_subscriber_broadcast(&principal).map_err(|_| {
            BearerAuthError::Invalid("broadcast credential is not receive-only".into())
        })?;
        if principal
            .scopes
            .iter()
            .any(|scope| scope == PUBLIC_GATEWAY_ATTACHMENT_SCOPE)
        {
            return Err(BearerAuthError::Invalid(
                "broadcast credential has attachment authority".into(),
            ));
        }
        Ok(principal)
    }
}

/// Synchronous, secret-preserving Session boundary. Redis lookup remains in
/// the asynchronous admission task; this resolver validates only canonical
/// wire shape and binds the canonical Session to the token digest.
struct PublicGatewaySessionResolver {
    draining: Arc<AtomicBool>,
}

impl SessionBindingResolver for PublicGatewaySessionResolver {
    fn resolve_session(
        &self,
        principal: &AuthenticatedPrincipal,
        wire_session: &SessionId,
    ) -> Result<SessionId, ResourceBindingError> {
        if self.draining.load(Ordering::Acquire) {
            return Err(ResourceBindingError::unavailable("gateway-draining"));
        }
        if let Ok(broadcast_id) = exact_subscriber_broadcast(principal) {
            principal
                .require_scope(UCTP_SESSION_SCOPE)
                .and_then(|_| principal.require_scope(UCTP_SUBSCRIBE_SCOPE))
                .and_then(|_| principal.require_scope(UCTP_RECEIVE_ONLY_SCOPE))
                .map_err(|_| ResourceBindingError::forbidden("broadcast-scope-required"))?;
            if wire_session.as_str() != broadcast_id
                || uuid::Uuid::parse_str(&broadcast_id).is_err()
            {
                return Err(ResourceBindingError::forbidden(
                    "broadcast-session-mismatch",
                ));
            }
            return Ok(SessionId::from_string(broadcast_id));
        }
        principal
            .require_scope(PUBLIC_GATEWAY_ATTACHMENT_SCOPE)
            .and_then(|_| principal.require_scope(UCTP_SESSION_SCOPE))
            .map_err(|_| ResourceBindingError::forbidden("attachment-scope-required"))?;
        let (_, token) = parse_public_session(wire_session.as_str())
            .map_err(|_| ResourceBindingError::forbidden("invalid-attachment-session"))?;
        let presented = parse_presented_attachment_token(token)
            .map_err(|_| ResourceBindingError::forbidden("invalid-attachment-session"))?;
        let digest = URL_SAFE_NO_PAD.encode(presented.digest().expose_bytes());
        Ok(SessionId::from_string(format!(
            "{PUBLIC_GATEWAY_SESSION_PREFIX}:digest:{digest}"
        )))
    }

    fn reauthorize_session(
        &self,
        principal: &AuthenticatedPrincipal,
        wire_session: &SessionId,
        canonical_session: &SessionId,
    ) -> Result<(), ResourceBindingError> {
        let expected = self.resolve_session(principal, wire_session)?;
        if &expected != canonical_session {
            return Err(ResourceBindingError::forbidden(
                "attachment-session-changed",
            ));
        }
        Ok(())
    }

    fn resolve_inbound_routing_hint(
        &self,
        principal: &AuthenticatedPrincipal,
        wire_session: &SessionId,
        intent: &str,
        _capabilities_offer: &serde_json::Value,
    ) -> Result<Option<InboundRoutingHint>, ResourceBindingError> {
        if let Ok(broadcast_id) = exact_subscriber_broadcast(principal) {
            if intent != PUBLIC_GATEWAY_BROADCAST_INTENT || wire_session.as_str() != broadcast_id {
                return Err(ResourceBindingError::forbidden("broadcast-intent-required"));
            }
            self.resolve_session(principal, wire_session)?;
            return InboundRoutingHint::new(broadcast_id)
                .map(Some)
                .map_err(|_| ResourceBindingError::forbidden("invalid-broadcast-session"));
        }
        if intent != PUBLIC_GATEWAY_ATTACHMENT_INTENT {
            return Err(ResourceBindingError::forbidden(
                "attachment-intent-required",
            ));
        }
        self.resolve_session(principal, wire_session)?;
        InboundRoutingHint::new(wire_session.as_str().to_owned())
            .map(Some)
            .map_err(|_| ResourceBindingError::forbidden("invalid-attachment-session"))
    }
}

/// Public subscriptions are acknowledgements only. Durable authorization and
/// the worker's direct-listener permit are acquired by the admission task;
/// this handler merely rejects every shape except the canonical audio track.
struct PublicBroadcastSubscriptionHandler;

impl SubscriptionHandler for PublicBroadcastSubscriptionHandler {
    fn subscribe(
        &self,
        sid: &SessionId,
        _subscriber: &ConnectionId,
        request: &StreamSubscribe,
    ) -> SubscriptionOutcome {
        let valid_session = uuid::Uuid::parse_str(sid.as_str()).is_ok_and(|id| !id.is_nil());
        let valid_request = request.subscriptions.len() == 1
            && request.subscriptions[0].strm_id.as_deref() == Some(PUBLIC_GATEWAY_BROADCAST_STREAM)
            && request.subscriptions[0].from_participant.is_none()
            && request.subscriptions[0].kinds.is_empty();
        if valid_session && valid_request {
            SubscriptionOutcome::Ok
        } else {
            SubscriptionOutcome::reject(403, "broadcast-subscription-mismatch")
        }
    }

    fn unsubscribe(
        &self,
        sid: &SessionId,
        _subscriber: &ConnectionId,
        request: &StreamUnsubscribe,
    ) -> SubscriptionOutcome {
        if uuid::Uuid::parse_str(sid.as_str()).is_ok_and(|id| !id.is_nil())
            && request.strm_ids.len() == 1
            && request.strm_ids[0] == PUBLIC_GATEWAY_BROADCAST_STREAM
        {
            SubscriptionOutcome::Ok
        } else {
            SubscriptionOutcome::reject(403, "broadcast-subscription-mismatch")
        }
    }
}

/// One concrete public UCTP edge. It owns listener, correctness queues, active
/// route tasks, and ordered drain.
pub struct GatewayUctpIngress {
    endpoint: Arc<quinn::Endpoint>,
    adapter: Arc<UctpQuicAdapter>,
    orchestrator: Arc<Orchestrator>,
    draining: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
    idle: Arc<Notify>,
    cancel: CancellationToken,
    supervisor: Mutex<Option<JoinHandle<()>>>,
    health: watch::Sender<GatewayUctpIngressHealth>,
}

impl fmt::Debug for GatewayUctpIngress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayUctpIngress")
            .field("local_addr", &self.adapter.local_addr())
            .field("active_routes", &self.active.load(Ordering::Acquire))
            .field("draining", &self.draining.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl GatewayUctpIngress {
    #[allow(clippy::too_many_arguments)]
    pub async fn start(
        config: GatewayUctpIngressConfig,
        bearer_validator: Arc<dyn BearerValidator>,
        broadcast_validator: Arc<BroadcastTokenService>,
        broadcast_authority: Arc<dyn GatewayBroadcastAuthority>,
        attachment_resolver: Arc<GatewayAttachmentResolver>,
        forwarder: Arc<GatewayForwarder>,
        admission: Arc<dyn GatewayIngressAdmission>,
    ) -> Result<Arc<Self>, GatewayUctpIngressError> {
        config.validate()?;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                load_certificate_chain(&config.certificate_chain)?,
                load_private_key(&config.private_key)?,
            )
            .map_err(|_| GatewayUctpIngressError::TlsConfiguration)?;
        tls.alpn_protocols = vec![UCTP_RAW_QUIC_ALPN_BYTES.to_vec()];
        let endpoint = Arc::new(
            make_server_endpoint(
                config.bind,
                Arc::new(tls),
                quinn::TransportConfig::default(),
            )
            .map_err(|_| GatewayUctpIngressError::ListenerUnavailable)?,
        );
        let mut protocols = dispatch_by_alpn(Arc::clone(&endpoint), &[UCTP_RAW_QUIC_ALPN_BYTES])
            .map_err(|_| GatewayUctpIngressError::ListenerUnavailable)?;
        let accept_rx = protocols
            .take(UCTP_RAW_QUIC_ALPN_BYTES)
            .ok_or(GatewayUctpIngressError::ListenerUnavailable)?;

        let orchestrator = Orchestrator::new(rvoip_core::config::Config::default());
        let admissions = orchestrator
            .install_inbound_admission_gate(config.admission_capacity, config.setup_timeout)
            .map_err(|_| GatewayUctpIngressError::InvalidConfiguration)?;
        let operational = orchestrator
            .install_operational_event_stream(config.admission_capacity.saturating_mul(4).max(64))
            .map_err(|_| GatewayUctpIngressError::InvalidConfiguration)?;
        let operational_health = orchestrator
            .subscribe_operational_event_stream_health()
            .map_err(|_| GatewayUctpIngressError::InvalidConfiguration)?;
        let draining = Arc::new(AtomicBool::new(false));
        let resolver: Arc<dyn SessionBindingResolver> = Arc::new(PublicGatewaySessionResolver {
            draining: Arc::clone(&draining),
        });
        let validator: Arc<dyn BearerValidator> = Arc::new(GatewayUctpBearerValidator {
            attachment: bearer_validator,
            broadcast: broadcast_validator,
        });
        let caps = UctpCoordinatorCaps {
            authentication_deadline: config.setup_timeout,
            signaling_send_timeout: config.setup_timeout,
            max_sessions_per_peer: 16,
            max_connections_per_peer: 16,
            max_streams_per_connection: 1,
            ..UctpCoordinatorCaps::default()
        };
        let mut adapter_config = UctpQuicConfig::new(Arc::clone(&endpoint), accept_rx, validator)
            .with_coordinator_caps(caps)
            .with_session_binding_resolver(resolver)
            .with_subscription_handler(Arc::new(PublicBroadcastSubscriptionHandler))
            .with_orchestrator(Arc::clone(&orchestrator));
        adapter_config.max_concurrent_connections = config.max_concurrent_connections;
        let adapter = UctpQuicAdapter::new(adapter_config)
            .await
            .map_err(|_| GatewayUctpIngressError::ListenerUnavailable)?;
        orchestrator
            .register(Arc::clone(&adapter) as Arc<dyn ConnectionAdapter>)
            .map_err(|_| GatewayUctpIngressError::ListenerUnavailable)?;

        let (health, _) = watch::channel(GatewayUctpIngressHealth::Healthy);
        let active = Arc::new(AtomicUsize::new(0));
        let idle = Arc::new(Notify::new());
        let cancel = CancellationToken::new();
        let opener: Arc<dyn AttachmentRouteOpener> = Arc::new(ForwardingRouteOpener {
            resolver: attachment_resolver,
            forwarder: Arc::clone(&forwarder),
        });
        let broadcast_opener: Arc<dyn BroadcastRouteOpener> =
            Arc::new(ForwardingBroadcastRouteOpener {
                authority: broadcast_authority,
                forwarder,
            });
        let supervisor = tokio::spawn(run_ingress_supervisor(
            admissions,
            operational,
            operational_health,
            Arc::clone(&orchestrator),
            Arc::clone(&adapter),
            opener,
            broadcast_opener,
            admission,
            Arc::clone(&active),
            Arc::clone(&idle),
            cancel.clone(),
            health.clone(),
            config.setup_timeout,
        ));
        metrics::gauge!("bridgefu_gateway_public_uctp_ready").set(1.0);
        Ok(Arc::new(Self {
            endpoint,
            adapter,
            orchestrator,
            draining,
            active,
            idle,
            cancel,
            supervisor: Mutex::new(Some(supervisor)),
            health,
        }))
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.adapter.local_addr()
    }

    pub fn active_routes(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    pub fn subscribe_health(&self) -> watch::Receiver<GatewayUctpIngressHealth> {
        self.health.subscribe()
    }

    pub fn begin_drain(&self) {
        if !self.draining.swap(true, Ordering::AcqRel) {
            self.adapter.begin_drain();
            self.health.send_replace(GatewayUctpIngressHealth::Draining);
            metrics::gauge!("bridgefu_gateway_public_uctp_ready").set(0.0);
        }
    }

    pub async fn shutdown(&self, timeout: Duration) -> Result<(), GatewayUctpIngressError> {
        self.begin_drain();
        let deadline = tokio::time::Instant::now() + timeout;
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
        self.endpoint
            .close(quinn::VarInt::from_u32(0), b"bridgefu-public-uctp-drain");
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
        let _ = tokio::time::timeout_at(deadline, self.endpoint.wait_idle()).await;
        let _ = tokio::time::timeout_at(
            deadline,
            self.orchestrator.drain_connection_lifecycle_tasks(),
        )
        .await;
        self.health.send_replace(GatewayUctpIngressHealth::Stopped);
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_ingress_supervisor(
    mut admissions: mpsc::Receiver<InboundAdmission>,
    mut operational: mpsc::Receiver<OperationalEvent>,
    mut operational_health: rvoip_core::OperationalEventStreamHealthSubscription,
    orchestrator: Arc<Orchestrator>,
    adapter: Arc<UctpQuicAdapter>,
    opener: Arc<dyn AttachmentRouteOpener>,
    broadcast_opener: Arc<dyn BroadcastRouteOpener>,
    admission: Arc<dyn GatewayIngressAdmission>,
    active: Arc<AtomicUsize>,
    idle: Arc<Notify>,
    cancel: CancellationToken,
    health: watch::Sender<GatewayUctpIngressHealth>,
    setup_timeout: Duration,
) {
    let routes = Arc::new(tokio::sync::Mutex::new(HashMap::<
        ConnectionId,
        mpsc::Sender<RouteControl>,
    >::new()));
    let mut resources = HashMap::<ConnectionId, Arc<UctpTaskResources>>::new();
    let mut tasks = JoinSet::new();
    let mut task_connections = HashMap::new();
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            changed = operational_health.changed() => {
                if changed == OperationalEventStreamHealth::Degraded {
                    health.send_replace(GatewayUctpIngressHealth::Degraded);
                    break;
                }
            }
            Some(ticket) = admissions.recv() => {
                let orchestrator = Arc::clone(&orchestrator);
                let adapter = Arc::clone(&adapter);
                let opener = Arc::clone(&opener);
                let broadcast_opener = Arc::clone(&broadcast_opener);
                let admission = Arc::clone(&admission);
                let routes = Arc::clone(&routes);
                let active = Arc::clone(&active);
                let idle = Arc::clone(&idle);
                let cancel = cancel.clone();
                let connection_id = ticket.connection_id().clone();
                let owned = Arc::new(UctpTaskResources::new(
                    connection_id.clone(),
                    Arc::clone(&routes),
                    Arc::clone(&orchestrator),
                ));
                resources.insert(connection_id.clone(), Arc::clone(&owned));
                let task_connection_id = connection_id.clone();
                let abort = tasks.spawn(async move {
                    active.fetch_add(1, Ordering::AcqRel);
                    let _active = ActiveRouteGuard { active, idle };
                    let is_broadcast = ticket
                        .authenticated_principal()
                        .is_ok_and(|principal| exact_subscriber_broadcast(&principal).is_ok());
                    let task = if is_broadcast {
                        run_broadcast(
                            ticket,
                            orchestrator,
                            adapter,
                            broadcast_opener,
                            admission,
                            routes,
                            cancel,
                            setup_timeout,
                            Arc::clone(&owned),
                        )
                        .boxed()
                    } else {
                        run_attachment(
                            ticket,
                            orchestrator,
                            adapter,
                            opener,
                            admission,
                            routes,
                            cancel,
                            setup_timeout,
                            Arc::clone(&owned),
                        )
                        .boxed()
                    };
                    let result = supervise_uctp_attachment(
                        Arc::clone(&owned),
                        task,
                    )
                    .await;
                    if result.is_err() {
                        metrics::counter!("bridgefu_gateway_public_uctp_admissions_total", "outcome" => "rejected").increment(1);
                    }
                    (connection_id, result)
                });
                task_connections.insert(abort.id(), task_connection_id);
            }
            Some(event) = operational.recv() => {
                let sender = routes.lock().await.get(&event.connection_id).cloned();
                if let Some(sender) = sender {
                    let command = match event.kind {
                        OperationalEventKind::DataMessage { message } => Some(RouteControl::Data(message)),
                        OperationalEventKind::Ended { .. } | OperationalEventKind::Failed { .. } => Some(RouteControl::Terminal),
                        OperationalEventKind::Dtmf { digits, duration_ms } => Some(RouteControl::Dtmf { digits, duration_ms }),
                        _ => None,
                    };
                    if let Some(command) = command {
                        if sender.try_send(command).is_err() {
                            remove_uctp_route_sender_exact(&routes, &event.connection_id, &sender).await;
                            metrics::counter!(
                                "bridgefu_gateway_public_uctp_control_dropped_total",
                                "direction" => "public-to-worker"
                            )
                            .increment(1);
                            let _ = orchestrator.end_connection(event.connection_id, EndReason::Failed { detail: "gateway control queue unavailable".into() }).await;
                        }
                    }
                }
            }
            Some(result) = tasks.join_next_with_id(), if !tasks.is_empty() => {
                match result {
                    Ok((task_id, (connection_id, outcome))) => {
                        task_connections.remove(&task_id);
                        resources.remove(&connection_id);
                        if outcome.is_err() {
                            metrics::counter!("bridgefu_gateway_public_uctp_route_failures_total", "reason" => "lifecycle").increment(1);
                        }
                    }
                    Err(error) => {
                        if let Some(connection_id) = task_connections.remove(&error.id()) {
                            if let Some(owned) = resources.remove(&connection_id) {
                                owned.cleanup(true).await;
                            }
                        }
                        metrics::counter!("bridgefu_gateway_public_uctp_route_failures_total", "reason" => "task").increment(1);
                    }
                }
            }
            else => break,
        }
    }
    admissions.close();
    while let Ok(ticket) = admissions.try_recv() {
        let _ = ticket.reject(RejectReason::ServerError).await;
    }
    // Preserve why the loop stopped before using cancellation to unwind the
    // remaining tasks. A closed admission/operational stream is a dependency
    // failure, while an already-cancelled token is the normal drain path.
    let draining = cancel.is_cancelled();
    cancel.cancel();
    tasks.abort_all();
    while let Some(result) = tasks.join_next_with_id().await {
        match result {
            Ok((task_id, (connection_id, _))) => {
                task_connections.remove(&task_id);
                resources.remove(&connection_id);
            }
            Err(error) => {
                if let Some(connection_id) = task_connections.remove(&error.id()) {
                    if let Some(owned) = resources.remove(&connection_id) {
                        owned.cleanup(true).await;
                    }
                }
            }
        }
    }
    for (_, owned) in resources.drain() {
        owned.cleanup(true).await;
    }
    if !draining {
        health.send_replace(GatewayUctpIngressHealth::Degraded);
        metrics::gauge!("bridgefu_gateway_public_uctp_ready").set(0.0);
    }
}

async fn remove_uctp_route_sender_exact(
    routes: &tokio::sync::Mutex<HashMap<ConnectionId, mpsc::Sender<RouteControl>>>,
    connection_id: &ConnectionId,
    expected: &mpsc::Sender<RouteControl>,
) {
    let mut routes = routes.lock().await;
    if routes
        .get(connection_id)
        .is_some_and(|registered| registered.same_channel(expected))
    {
        routes.remove(connection_id);
    }
}

enum RouteControl {
    Data(DataMessage),
    Dtmf { digits: String, duration_ms: u32 },
    Terminal,
}

#[derive(Default)]
struct UctpOwnedResources {
    route: Option<Arc<dyn GatewayMediaRoute>>,
    broadcast_lease: Option<Arc<dyn GatewayBroadcastListenerLease>>,
    session: Option<SessionId>,
    conversation: Option<rvoip_core::ConversationId>,
    control: Option<mpsc::Sender<RouteControl>>,
}

struct UctpTaskResources {
    connection_id: ConnectionId,
    routes: Arc<tokio::sync::Mutex<HashMap<ConnectionId, mpsc::Sender<RouteControl>>>>,
    orchestrator: Arc<Orchestrator>,
    owned: Mutex<UctpOwnedResources>,
    cleaned: AtomicBool,
}

impl UctpTaskResources {
    fn new(
        connection_id: ConnectionId,
        routes: Arc<tokio::sync::Mutex<HashMap<ConnectionId, mpsc::Sender<RouteControl>>>>,
        orchestrator: Arc<Orchestrator>,
    ) -> Self {
        Self {
            connection_id,
            routes,
            orchestrator,
            owned: Mutex::new(UctpOwnedResources::default()),
            cleaned: AtomicBool::new(false),
        }
    }

    fn update(&self, update: impl FnOnce(&mut UctpOwnedResources)) {
        update(
            &mut self
                .owned
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
    }

    async fn cleanup(&self, failed: bool) {
        if self.cleaned.swap(true, Ordering::AcqRel) {
            return;
        }
        let UctpOwnedResources {
            route,
            broadcast_lease,
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
            remove_uctp_route_sender_exact(&self.routes, &self.connection_id, &control).await;
        }
        if let Some(route) = route {
            let _ = AssertUnwindSafe(route.close()).catch_unwind().await;
        }
        if let Some(lease) = broadcast_lease {
            let _ = AssertUnwindSafe(lease.close()).catch_unwind().await;
        }
        let reason = if failed {
            EndReason::Failed {
                detail: "public UCTP gateway lifecycle failed".into(),
            }
        } else {
            EndReason::Normal
        };
        let _ = AssertUnwindSafe(
            self.orchestrator
                .end_connection(self.connection_id.clone(), reason.clone()),
        )
        .catch_unwind()
        .await;
        if let Some(session) = session {
            let _ = AssertUnwindSafe(self.orchestrator.end_session(session, reason))
                .catch_unwind()
                .await;
        }
        if let Some(conversation) = conversation {
            let _ = AssertUnwindSafe(self.orchestrator.close_conversation(conversation, true))
                .catch_unwind()
                .await;
        }
    }
}

async fn supervise_uctp_attachment<F>(
    resources: Arc<UctpTaskResources>,
    future: F,
) -> Result<(), GatewayUctpIngressError>
where
    F: Future<Output = Result<(), GatewayUctpIngressError>>,
{
    let result = match AssertUnwindSafe(future).catch_unwind().await {
        Ok(result) => result,
        Err(_) => Err(GatewayUctpIngressError::Lifecycle),
    };
    resources.cleanup(result.is_err()).await;
    result
}

struct ActiveRouteGuard {
    active: Arc<AtomicUsize>,
    idle: Arc<Notify>,
}

impl Drop for ActiveRouteGuard {
    fn drop(&mut self) {
        if self.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.idle.notify_waiters();
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_broadcast(
    mut ticket: InboundAdmission,
    orchestrator: Arc<Orchestrator>,
    adapter: Arc<UctpQuicAdapter>,
    opener: Arc<dyn BroadcastRouteOpener>,
    admission: Arc<dyn GatewayIngressAdmission>,
    routes: Arc<tokio::sync::Mutex<HashMap<ConnectionId, mpsc::Sender<RouteControl>>>>,
    cancel: CancellationToken,
    setup_timeout: Duration,
    resources: Arc<UctpTaskResources>,
) -> Result<(), GatewayUctpIngressError> {
    let setup_deadline = tokio::time::Instant::now() + setup_timeout;
    let connection_id = ticket.connection_id().clone();
    if ticket.transport() != Transport::Quic {
        let _ = ticket.reject(RejectReason::NotAcceptable).await;
        return Err(GatewayUctpIngressError::BroadcastRejected);
    }
    let principal = match ticket.authenticated_principal() {
        Ok(principal) if exact_subscriber_broadcast(&principal).is_ok() => principal,
        _ => {
            let _ = ticket.reject(RejectReason::Forbidden).await;
            return Err(GatewayUctpIngressError::BroadcastRejected);
        }
    };
    let broadcast_id = exact_subscriber_broadcast(&principal)
        .map_err(|_| GatewayUctpIngressError::BroadcastRejected)?;
    let tenant = principal
        .tenant
        .as_deref()
        .filter(|tenant| !tenant.trim().is_empty())
        .ok_or(GatewayUctpIngressError::BroadcastRejected)?;
    let orchestrator_tenant = rvoip_core::TenantId::from_string(tenant);
    let mut context = match ticket.take_inbound_context() {
        Ok(Some(context)) if context.is_bound_to(&connection_id, Transport::Quic, &principal) => {
            context
        }
        _ => {
            let _ = ticket.reject(RejectReason::Forbidden).await;
            return Err(GatewayUctpIngressError::BroadcastRejected);
        }
    };
    if context
        .take_routing_hint()
        .is_none_or(|hint| hint.into_secret() != broadcast_id)
    {
        let _ = ticket.reject(RejectReason::Forbidden).await;
        return Err(GatewayUctpIngressError::BroadcastRejected);
    }
    let admission_lease = match admission.try_admit() {
        Ok(lease) => lease,
        Err(error) => {
            let reason = if error == GatewayUctpIngressError::CapacityExceeded {
                RejectReason::Busy
            } else {
                RejectReason::ServerError
            };
            let _ = ticket.reject(reason).await;
            return Err(error);
        }
    };
    let opened = match tokio::time::timeout_at(
        setup_deadline,
        opener.open(
            principal,
            broadcast_id,
            format!("gateway-uctp:{}", connection_id.as_str()),
        ),
    )
    .await
    {
        Ok(Ok(opened)) => opened,
        Ok(Err(error)) => {
            tracing::warn!(error = ?error, "private broadcast route admission failed");
            let reason = if error == GatewayUctpIngressError::NotReady {
                RejectReason::ServerError
            } else {
                RejectReason::Forbidden
            };
            let _ = ticket.reject(reason).await;
            return Err(error);
        }
        Err(_) => {
            let _ = ticket.reject(RejectReason::ServerError).await;
            return Err(GatewayUctpIngressError::Lifecycle);
        }
    };
    resources.update(|owned| {
        owned.route = Some(Arc::clone(&opened.route));
        owned.broadcast_lease = Some(Arc::clone(&opened.lease));
    });
    let conversation = tokio::time::timeout_at(
        setup_deadline,
        orchestrator.open_conversation(
            orchestrator_tenant,
            rvoip_core::ConversationPolicy::default(),
            HashMap::new(),
        ),
    )
    .await
    .map_err(|_| GatewayUctpIngressError::Lifecycle)?
    .map_err(|_| GatewayUctpIngressError::Lifecycle)?;
    resources.update(|owned| owned.conversation = Some(conversation.clone()));
    let session = tokio::time::timeout_at(
        setup_deadline,
        orchestrator.start_session(conversation.clone(), SessionMedium::Voice, Vec::new()),
    )
    .await
    .map_err(|_| GatewayUctpIngressError::Lifecycle)?
    .map_err(|_| GatewayUctpIngressError::Lifecycle)?;
    resources.update(|owned| owned.session = Some(session.clone()));
    let (control_tx, control_rx) = mpsc::channel(MAX_CONTROL_QUEUE);
    routes
        .lock()
        .await
        .insert(connection_id.clone(), control_tx.clone());
    resources.update(|owned| owned.control = Some(control_tx));
    let accepted = matches!(
        tokio::time::timeout_at(setup_deadline, ticket.accept()).await,
        Ok(Ok(()))
    );
    let routed = accepted
        && matches!(
            tokio::time::timeout_at(
                setup_deadline,
                orchestrator.route_inbound_connection(
                    connection_id.clone(),
                    InboundAction::Accept {
                        session_id: session,
                        participant_id: ParticipantId::new(),
                    },
                ),
            )
            .await,
            Ok(Ok(()))
        );
    if !routed {
        return Err(GatewayUctpIngressError::Lifecycle);
    }
    // `session.accept` is the peer-visible admission boundary.  The peer can
    // now send `connection.ready`; only then does the adapter allocate and
    // announce the negotiated stream.  Waiting for that stream before
    // accepting would expose `stream.opened` before the Connection was
    // actionable and make the first subscription race admission.
    let stream = match tokio::time::timeout_at(
        setup_deadline,
        wait_for_audio_stream(&adapter, &connection_id),
    )
    .await
    {
        Ok(Ok(stream))
            if stream.direction() == rvoip_core::connection::Direction::Outbound
                && stream.codec().name.eq_ignore_ascii_case("opus")
                && stream.codec().clock_rate_hz == 48_000
                && stream.codec().channels == 1 =>
        {
            stream
        }
        Ok(Ok(_)) | Ok(Err(_)) | Err(_) => {
            return Err(GatewayUctpIngressError::BroadcastRejected);
        }
    };
    metrics::counter!("bridgefu_gateway_public_uctp_admissions_total", "outcome" => "accepted-broadcast")
        .increment(1);
    let monitor_lease = Arc::clone(&opened.lease);
    tokio::select! {
        _ = run_broadcast_route_pump(
            stream,
            opened.route,
            control_rx,
            cancel.clone(),
        ) => {}
        _ = monitor_broadcast_lease(
            monitor_lease,
            adapter,
            connection_id,
            cancel,
        ) => {}
    }
    drop(admission_lease);
    Ok(())
}

async fn run_broadcast_route_pump(
    stream: Arc<dyn MediaStream>,
    route: Arc<dyn GatewayMediaRoute>,
    mut control: mpsc::Receiver<RouteControl>,
    cancel: CancellationToken,
) {
    // The negotiated stream is Outbound, so rvoip-quic rejects peer media at
    // its local-ID direction gate. This pump intentionally never reserves a
    // frames_in receiver and has no public-to-worker route method.
    let outbound = match stream.try_frames_out() {
        Ok(outbound) => outbound,
        Err(_) => return,
    };
    let stream_id = stream.id();
    let mut private_drops = 0usize;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            packet = route.recv() => {
                let Some(packet) = packet else { break; };
                let ForwardedPacket::Rtp(packet) = packet else {
                    metrics::counter!(
                        "bridgefu_gateway_public_uctp_control_dropped_total",
                        "direction" => "worker-to-broadcast"
                    )
                    .increment(1);
                    continue;
                };
                let Some(frame) = decode_rtp(&packet, stream_id.clone()) else { break; };
                match outbound.try_send(frame) {
                    Ok(()) => private_drops = 0,
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        private_drops += 1;
                        metrics::counter!(
                            "bridgefu_gateway_public_uctp_media_dropped_total",
                            "direction" => "worker-to-public-broadcast"
                        )
                        .increment(1);
                        if private_drops >= MAX_CONSECUTIVE_MEDIA_DROPS { break; }
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => break,
                }
            }
            command = control.recv() => match command {
                Some(RouteControl::Terminal) | None => break,
                Some(RouteControl::Data(_)) | Some(RouteControl::Dtmf { .. }) => {
                    metrics::counter!(
                        "bridgefu_gateway_public_uctp_control_dropped_total",
                        "direction" => "broadcast-to-worker"
                    )
                    .increment(1);
                    break;
                }
            }
        }
    }
}

async fn monitor_broadcast_lease(
    lease: Arc<dyn GatewayBroadcastListenerLease>,
    adapter: Arc<UctpQuicAdapter>,
    connection_id: ConnectionId,
    cancel: CancellationToken,
) {
    let mut interval = tokio::time::interval(BROADCAST_REVALIDATE_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = interval.tick() => {
                let Some(principal) = adapter.authenticated_principal(&connection_id) else {
                    return;
                };
                if !matches!(lease.revalidate(&principal).await, Ok(true)) {
                    return;
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_attachment(
    mut ticket: InboundAdmission,
    orchestrator: Arc<Orchestrator>,
    adapter: Arc<UctpQuicAdapter>,
    opener: Arc<dyn AttachmentRouteOpener>,
    admission: Arc<dyn GatewayIngressAdmission>,
    routes: Arc<tokio::sync::Mutex<HashMap<ConnectionId, mpsc::Sender<RouteControl>>>>,
    cancel: CancellationToken,
    setup_timeout: Duration,
    resources: Arc<UctpTaskResources>,
) -> Result<(), GatewayUctpIngressError> {
    let setup_deadline = tokio::time::Instant::now() + setup_timeout;
    let connection_id = ticket.connection_id().clone();
    if ticket.transport() != Transport::Quic {
        let _ = ticket.reject(RejectReason::NotAcceptable).await;
        return Err(GatewayUctpIngressError::AttachmentRejected);
    }
    let principal = match ticket.authenticated_principal() {
        Ok(principal)
            if principal
                .require_scope(PUBLIC_GATEWAY_ATTACHMENT_SCOPE)
                .is_ok() =>
        {
            principal
        }
        _ => {
            let _ = ticket.reject(RejectReason::Forbidden).await;
            return Err(GatewayUctpIngressError::AttachmentRejected);
        }
    };
    let orchestrator_tenant = match principal
        .tenant
        .as_deref()
        .filter(|tenant| !tenant.trim().is_empty())
    {
        Some(tenant) => rvoip_core::TenantId::from_string(tenant),
        None => {
            let _ = ticket.reject(RejectReason::Forbidden).await;
            return Err(GatewayUctpIngressError::AttachmentRejected);
        }
    };
    let mut context = match ticket.take_inbound_context() {
        Ok(Some(context)) if context.is_bound_to(&connection_id, Transport::Quic, &principal) => {
            context
        }
        _ => {
            let _ = ticket.reject(RejectReason::Forbidden).await;
            return Err(GatewayUctpIngressError::AttachmentRejected);
        }
    };
    let hint = match context.take_routing_hint() {
        Some(hint) => hint.into_secret(),
        None => {
            let _ = ticket.reject(RejectReason::Forbidden).await;
            return Err(GatewayUctpIngressError::AttachmentRejected);
        }
    };
    let (transport, token) = match parse_public_session(&hint) {
        Ok(parsed) => parsed,
        Err(error) => {
            let _ = ticket.reject(RejectReason::Forbidden).await;
            return Err(error);
        }
    };
    let lease = match admission.try_admit() {
        Ok(lease) => lease,
        Err(error) => {
            let reason = if error == GatewayUctpIngressError::CapacityExceeded {
                RejectReason::Busy
            } else {
                RejectReason::ServerError
            };
            let _ = ticket.reject(reason).await;
            return Err(error);
        }
    };
    // The UCTP connection.offer has already negotiated its only audio stream
    // before admission. Resolve that exact codec before the worker consumes
    // the single-use attachment, so the private offer cannot fall back from
    // PCMU/PCMA to Opus.
    let stream = match tokio::time::timeout_at(
        setup_deadline,
        wait_for_audio_stream(&adapter, &connection_id),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(_)) | Err(_) => {
            let _ = ticket.reject(RejectReason::NotAcceptable).await;
            return Err(GatewayUctpIngressError::Lifecycle);
        }
    };
    let codec = stream.codec();
    let route = match tokio::time::timeout_at(
        setup_deadline,
        opener.open(principal, token, transport, codec),
    )
    .await
    {
        Ok(Ok(route)) => route,
        Ok(Err(error)) => {
            let _ = ticket.reject(RejectReason::Forbidden).await;
            return Err(error);
        }
        Err(_) => {
            let _ = ticket.reject(RejectReason::ServerError).await;
            return Err(GatewayUctpIngressError::Lifecycle);
        }
    };
    resources.update(|owned| owned.route = Some(Arc::clone(&route)));
    let conversation = match tokio::time::timeout_at(
        setup_deadline,
        orchestrator.open_conversation(
            orchestrator_tenant,
            rvoip_core::ConversationPolicy::default(),
            HashMap::new(),
        ),
    )
    .await
    {
        Ok(Ok(conversation)) => conversation,
        Ok(Err(_)) | Err(_) => {
            let _ = ticket.reject(RejectReason::ServerError).await;
            return Err(GatewayUctpIngressError::Lifecycle);
        }
    };
    resources.update(|owned| owned.conversation = Some(conversation.clone()));
    let session = match tokio::time::timeout_at(
        setup_deadline,
        orchestrator.start_session(conversation.clone(), SessionMedium::Voice, Vec::new()),
    )
    .await
    {
        Ok(Ok(session)) => session,
        Ok(Err(_)) | Err(_) => {
            let _ = ticket.reject(RejectReason::ServerError).await;
            return Err(GatewayUctpIngressError::Lifecycle);
        }
    };
    resources.update(|owned| owned.session = Some(session.clone()));
    let (control_tx, control_rx) = mpsc::channel(MAX_CONTROL_QUEUE);
    routes
        .lock()
        .await
        .insert(connection_id.clone(), control_tx.clone());
    resources.update(|owned| owned.control = Some(control_tx));
    let accepted = matches!(
        tokio::time::timeout_at(setup_deadline, ticket.accept()).await,
        Ok(Ok(()))
    );
    let routed = accepted
        && matches!(
            tokio::time::timeout_at(
                setup_deadline,
                orchestrator.route_inbound_connection(
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
        return Err(GatewayUctpIngressError::Lifecycle);
    }
    metrics::counter!("bridgefu_gateway_public_uctp_admissions_total", "outcome" => "accepted")
        .increment(1);
    run_route_pumps(
        connection_id.clone(),
        Arc::clone(&orchestrator),
        stream,
        Arc::clone(&route),
        control_rx,
        cancel,
    )
    .await;
    drop(lease);
    Ok(())
}

async fn wait_for_audio_stream(
    adapter: &Arc<UctpQuicAdapter>,
    connection_id: &ConnectionId,
) -> Result<Arc<dyn MediaStream>, GatewayUctpIngressError> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(streams) = adapter.streams(connection_id.clone()).await {
            if let Some(stream) = streams
                .into_iter()
                .find(|stream| stream.kind() == StreamKind::Audio)
            {
                return Ok(stream);
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(GatewayUctpIngressError::Lifecycle);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn run_route_pumps(
    connection_id: ConnectionId,
    orchestrator: Arc<Orchestrator>,
    stream: Arc<dyn MediaStream>,
    route: Arc<dyn GatewayMediaRoute>,
    mut control: mpsc::Receiver<RouteControl>,
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
    let (public_control_tx, mut public_control_rx) = mpsc::channel(MAX_CONTROL_QUEUE);
    let (public_control_failed, mut public_control_failure) = tokio::sync::oneshot::channel();
    let control_connection_id = connection_id.clone();
    let public_control_task = tokio::spawn(async move {
        while let Some(command) = public_control_rx.recv().await {
            let sent = match command {
                PublicControl::Data(message) => {
                    tokio::time::timeout(
                        PUBLIC_CONTROL_SEND_TIMEOUT,
                        orchestrator.send_data_message(control_connection_id.clone(), message),
                    )
                    .await
                }
                PublicControl::Dtmf {
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
                let packet = encode_rtp(&frame, &codec, sequence.fetch_add(1, Ordering::Relaxed) as u16, ssrc);
                match route.try_send_rtp(packet) {
                    Ok(()) => public_drops = 0,
                    Err(GatewayForwardingError::Backpressure) => {
                        public_drops += 1;
                        metrics::counter!("bridgefu_gateway_public_uctp_media_dropped_total", "direction" => "public-to-worker").increment(1);
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
                                metrics::counter!("bridgefu_gateway_public_uctp_media_dropped_total", "direction" => "worker-to-public").increment(1);
                                if private_drops >= MAX_CONSECUTIVE_MEDIA_DROPS { break; }
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => break,
                        }
                    }
                    ForwardedPacket::Rtcp(bytes) => {
                        let message = DataMessage::reliable(PRIVATE_RTCP_LABEL, PRIVATE_RTCP_CONTENT_TYPE, bytes);
                        if public_control_tx.try_send(PublicControl::Data(message)).is_err() {
                            metrics::counter!("bridgefu_gateway_public_uctp_control_dropped_total", "direction" => "worker-to-public").increment(1);
                            break;
                        }
                    }
                    ForwardedPacket::Dtmf { digits, duration_ms } => {
                        if public_control_tx.try_send(PublicControl::Dtmf { digits, duration_ms }).is_err() {
                            metrics::counter!("bridgefu_gateway_public_uctp_control_dropped_total", "direction" => "worker-to-public").increment(1);
                            break;
                        }
                    }
                    ForwardedPacket::Data(message) => {
                        if public_control_tx.try_send(PublicControl::Data(message)).is_err() {
                            metrics::counter!("bridgefu_gateway_public_uctp_control_dropped_total", "direction" => "worker-to-public").increment(1);
                            break;
                        }
                    }
                }
            }
            command = control.recv() => match command {
                Some(RouteControl::Data(message)) if message.label == PRIVATE_RTCP_LABEL && message.content_type == PRIVATE_RTCP_CONTENT_TYPE => {
                    if route.try_send_rtcp(message.bytes).is_err() { break; }
                }
                Some(RouteControl::Data(message)) => {
                    if route.try_send_data(message).is_err() { break; }
                }
                Some(RouteControl::Dtmf { digits, duration_ms }) => {
                    if route.try_send_dtmf(digits, duration_ms).is_err() { break; }
                }
                Some(RouteControl::Terminal) | None => break,
            }
        }
    }
    drop(public_control_tx);
    public_control_task.abort();
    let _ = public_control_task.await;
}

enum PublicControl {
    Data(DataMessage),
    Dtmf { digits: String, duration_ms: u32 },
}

fn parse_public_session(
    value: &str,
) -> Result<(AttachmentTransport, String), GatewayUctpIngressError> {
    let suffix = value
        .strip_prefix(PUBLIC_GATEWAY_SESSION_PREFIX)
        .and_then(|suffix| suffix.strip_prefix(':'))
        .ok_or(GatewayUctpIngressError::AttachmentRejected)?;
    let (transport, token) = suffix
        .split_once(':')
        .ok_or(GatewayUctpIngressError::AttachmentRejected)?;
    let transport = match transport {
        "sip" => AttachmentTransport::Sip,
        "webrtc" => AttachmentTransport::WebRtc,
        _ => return Err(GatewayUctpIngressError::AttachmentRejected),
    };
    parse_presented_attachment_token(token.to_owned())
        .map_err(|_| GatewayUctpIngressError::AttachmentRejected)?;
    Ok((transport, token.to_owned()))
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
        // Normalize public dynamic payload types (for example Opus PT 109)
        // to the canonical exact-codec private route. The public adapter
        // repacketizes into its own negotiated PT in the reverse direction.
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

fn load_certificate_chain(
    paths: &[PathBuf],
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, GatewayUctpIngressError> {
    let mut certificates = Vec::new();
    for path in paths {
        let file = File::open(path).map_err(|_| GatewayUctpIngressError::TlsConfiguration)?;
        let mut reader = BufReader::new(file);
        certificates.extend(
            rustls_pemfile::certs(&mut reader)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| GatewayUctpIngressError::TlsConfiguration)?,
        );
    }
    if certificates.is_empty() {
        return Err(GatewayUctpIngressError::TlsConfiguration);
    }
    Ok(certificates)
}

fn load_private_key(
    path: &Path,
) -> Result<rustls::pki_types::PrivateKeyDer<'static>, GatewayUctpIngressError> {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|_| GatewayUctpIngressError::TlsConfiguration)?;
    rustls_pemfile::private_key(&mut bytes.as_slice())
        .map_err(|_| GatewayUctpIngressError::TlsConfiguration)?
        .ok_or(GatewayUctpIngressError::TlsConfiguration)
}

/// Redacted public-edge failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GatewayUctpIngressError {
    #[error("public UCTP gateway configuration is invalid")]
    InvalidConfiguration,
    #[error("public UCTP gateway TLS configuration is invalid")]
    TlsConfiguration,
    #[error("public UCTP gateway listener is unavailable")]
    ListenerUnavailable,
    #[error("public attachment proof was rejected")]
    AttachmentRejected,
    #[error("public broadcast subscription was rejected")]
    BroadcastRejected,
    #[error("gateway dependency is not ready")]
    NotReady,
    #[error("gateway is draining")]
    Draining,
    #[error("gateway admission capacity is exhausted")]
    CapacityExceeded,
    #[error("private forwarding route failed")]
    Forwarding(#[from] GatewayForwardingError),
    #[error("public UCTP lifecycle failed")]
    Lifecycle,
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use futures_util::{SinkExt, StreamExt};
    use rvoip_auth_core::BearerAuthError;
    use rvoip_core::capability::default_audio_codec;
    use rvoip_core::connection::Direction;
    use rvoip_core::events::Event;
    use rvoip_core::stream::QualitySnapshot;
    use rvoip_core::subscriptions::PublisherEntry;
    use rvoip_core::IdentityAssurance;
    use rvoip_quic::UctpQuicClient;
    use rvoip_uctp::envelope::UctpEnvelope;
    use rvoip_uctp::payloads::{auth, connection, message, session, stream};
    use rvoip_uctp::substrate::{
        dev_client_config_trusting, envelope_reader, envelope_writer, make_client_endpoint, pack,
        self_signed_for_dev, unpack_rtp_datagram, MediaDatagram,
    };
    use rvoip_uctp::types::MessageType;
    use std::collections::BTreeSet;

    use crate::broadcast::{
        BroadcastGrantRegistry, BroadcastTokenService, WorkerBroadcastSubscriptionAuthority,
        DEFAULT_MAX_BROADCAST_TOKEN_TTL,
    };
    use crate::call_engine::WorkerId;
    use crate::call_service::{
        build_call_service_runtime, CallExecutionSupervisor, CallRepositoryBackendConfig,
        CallServiceCoordinationConfig, CallServiceRuntimeConfig, CallTimeoutPolicy,
        DisabledProviderLegExecutor, RuntimeSupervisorHealth, SamePrincipalAttachmentResolver,
        SystemCallServiceClock,
    };
    use crate::context::ContextPolicy;
    use crate::coordination::{
        CoordinationClock, DeploymentId, ManualCoordinationClock, MemoryCoordinator,
    };
    use crate::gateway_forwarding::{
        GatewayForwardingConfig, MutualTlsFiles, PrivateForwardingLimits,
        PrivateForwardingTimeouts, PrivateTokenKey, PrivateWorkerTarget, WorkerForwardingConfig,
        WorkerForwardingRuntime,
    };

    struct PumpTestStream {
        id: StreamId,
        inbound: Mutex<Option<mpsc::Receiver<MediaFrame>>>,
        outbound: mpsc::Sender<MediaFrame>,
        inbound_acquired: Arc<AtomicBool>,
    }

    #[async_trait]
    impl MediaStream for PumpTestStream {
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
            self.inbound_acquired.store(true, Ordering::Release);
            self.inbound
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
                .unwrap_or_else(|| mpsc::channel(1).1)
        }

        fn try_frames_in(&self) -> rvoip_core::Result<mpsc::Receiver<MediaFrame>> {
            self.inbound_acquired.store(true, Ordering::Release);
            self.inbound
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
                .ok_or(rvoip_core::RvoipError::InvalidState(
                    "pump test source already acquired",
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

    struct PumpTestRoute {
        sent: mpsc::Sender<ForwardedPacket>,
        inbound: tokio::sync::Mutex<mpsc::Receiver<ForwardedPacket>>,
        closed: AtomicBool,
    }

    struct PanickingCleanupRoute;

    #[async_trait]
    impl GatewayMediaRoute for PanickingCleanupRoute {
        fn try_send_rtp(&self, _packet: Bytes) -> Result<(), GatewayForwardingError> {
            Err(GatewayForwardingError::Closed)
        }

        fn try_send_rtcp(&self, _packet: Bytes) -> Result<(), GatewayForwardingError> {
            Err(GatewayForwardingError::Closed)
        }

        fn try_send_dtmf(
            &self,
            _digits: String,
            _duration_ms: u32,
        ) -> Result<(), GatewayForwardingError> {
            Err(GatewayForwardingError::Closed)
        }

        fn try_send_data(&self, _message: DataMessage) -> Result<(), GatewayForwardingError> {
            Err(GatewayForwardingError::Closed)
        }

        async fn recv(&self) -> Option<ForwardedPacket> {
            None
        }

        async fn close(&self) {
            panic!("injected route cleanup panic");
        }
    }

    struct RecordingCleanupLease(Arc<AtomicBool>);

    struct CountingCleanupLease(Arc<AtomicUsize>);

    #[async_trait]
    impl GatewayBroadcastListenerLease for RecordingCleanupLease {
        async fn revalidate(
            &self,
            _principal: &AuthenticatedPrincipal,
        ) -> Result<bool, GatewayUctpIngressError> {
            Ok(true)
        }

        async fn close(&self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[async_trait]
    impl GatewayBroadcastListenerLease for CountingCleanupLease {
        async fn revalidate(
            &self,
            _principal: &AuthenticatedPrincipal,
        ) -> Result<bool, GatewayUctpIngressError> {
            Ok(true)
        }

        async fn close(&self) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
    }

    struct RejectingAttachmentValidator;

    #[async_trait]
    impl BearerValidator for RejectingAttachmentValidator {
        async fn validate(&self, _token: &str) -> Result<IdentityAssurance, BearerAuthError> {
            Err(BearerAuthError::Invalid(
                "not an attachment credential".into(),
            ))
        }
    }

    struct CountingAdmission {
        active: Arc<AtomicUsize>,
    }

    struct CountingAdmissionLease(Arc<AtomicUsize>);

    impl Drop for CountingAdmissionLease {
        fn drop(&mut self) {
            let previous = self.0.fetch_sub(1, Ordering::AcqRel);
            assert!(previous > 0, "gateway admission lease underflow");
        }
    }

    impl GatewayIngressAdmission for CountingAdmission {
        fn try_admit(
            &self,
        ) -> Result<Box<dyn GatewayIngressAdmissionLease>, GatewayUctpIngressError> {
            self.active.fetch_add(1, Ordering::AcqRel);
            Ok(Box::new(CountingAdmissionLease(Arc::clone(&self.active))))
        }
    }

    struct FixedBroadcastAuthority {
        tenant_id: TenantId,
        call_id: CallId,
        broadcast_id: uuid::Uuid,
        worker: WorkerLease,
        grant_generation: uuid::Uuid,
        listeners_closed: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl GatewayBroadcastAuthority for FixedBroadcastAuthority {
        async fn authorize(
            &self,
            principal: &AuthenticatedPrincipal,
            broadcast_id: &str,
            _connection_owner: &str,
        ) -> Result<GatewayBroadcastAuthorization, GatewayUctpIngressError> {
            if broadcast_id != self.broadcast_id.to_string()
                || principal.tenant.as_deref() != Some(self.tenant_id.as_str())
                || exact_subscriber_broadcast(principal).ok().as_deref() != Some(broadcast_id)
            {
                return Err(GatewayUctpIngressError::BroadcastRejected);
            }
            Ok(GatewayBroadcastAuthorization {
                tenant_id: self.tenant_id.clone(),
                call_id: self.call_id,
                broadcast_id: self.broadcast_id,
                worker: self.worker,
                grant_generation: self.grant_generation,
                lease: Arc::new(CountingCleanupLease(Arc::clone(&self.listeners_closed))),
            })
        }
    }

    struct NetworkTlsFixture {
        root: std::path::PathBuf,
        worker: MutualTlsFiles,
        gateway: MutualTlsFiles,
        public_certificate: rustls::pki_types::CertificateDer<'static>,
    }

    impl Drop for NetworkTlsFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn write_test_pem(path: &std::path::Path, label: &str, der: &[u8]) {
        let encoded = STANDARD.encode(der);
        let mut pem = format!("-----BEGIN {label}-----\n");
        for line in encoded.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(line).expect("base64 is UTF-8"));
            pem.push('\n');
        }
        pem.push_str(&format!("-----END {label}-----\n"));
        std::fs::write(path, pem).expect("write TLS fixture");
    }

    fn network_tls_fixture() -> NetworkTlsFixture {
        let root = std::env::temp_dir().join(format!(
            "bridgefu-public-broadcast-network-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).expect("create TLS fixture directory");
        let (worker_certificate, worker_key) =
            self_signed_for_dev(&["localhost".into()]).expect("worker TLS identity");
        let (gateway_certificate, gateway_key) =
            self_signed_for_dev(&["gateway.local".into()]).expect("gateway TLS identity");
        let worker_certificate_path = root.join("worker.pem");
        let worker_key_path = root.join("worker.key");
        let gateway_certificate_path = root.join("gateway.pem");
        let gateway_key_path = root.join("gateway.key");
        write_test_pem(
            &worker_certificate_path,
            "CERTIFICATE",
            worker_certificate.as_ref(),
        );
        write_test_pem(&worker_key_path, "PRIVATE KEY", worker_key.secret_der());
        write_test_pem(
            &gateway_certificate_path,
            "CERTIFICATE",
            gateway_certificate.as_ref(),
        );
        write_test_pem(&gateway_key_path, "PRIVATE KEY", gateway_key.secret_der());
        NetworkTlsFixture {
            root,
            worker: MutualTlsFiles {
                certificate_chain: vec![worker_certificate_path.clone()],
                private_key: worker_key_path,
                peer_ca_certificates: vec![gateway_certificate_path.clone()],
            },
            gateway: MutualTlsFiles {
                certificate_chain: vec![gateway_certificate_path],
                private_key: gateway_key_path,
                peer_ca_certificates: vec![worker_certificate_path],
            },
            public_certificate: worker_certificate,
        }
    }

    fn private_limits() -> PrivateForwardingLimits {
        PrivateForwardingLimits {
            max_active_routes: 4,
            max_peer_connections: 2,
            max_routes_per_peer: 2,
            media_queue_capacity: 10,
            reliable_queue_capacity: 16,
            inbound_queue_capacity: 16,
        }
    }

    fn private_timeouts() -> PrivateForwardingTimeouts {
        PrivateForwardingTimeouts {
            connect: Duration::from_secs(3),
            signaling: Duration::from_secs(3),
            token_ttl: Duration::from_secs(60),
            health_interval: Duration::from_secs(60),
        }
    }

    fn available_udp_addr() -> std::net::SocketAddr {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("reserve UDP port");
        socket.local_addr().expect("reserved UDP address")
    }

    #[derive(Clone, Copy, Debug)]
    enum WorkerBroadcastShutdownMode {
        GracefulDrain,
        LeaseLoss,
    }

    async fn assert_private_broadcast_worker_shutdown(mode: WorkerBroadcastShutdownMode) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tls = network_tls_fixture();
        let tenant_id = TenantId::parse("tenant-a").unwrap();
        let broadcast_id = uuid::Uuid::new_v4();
        let grant_generation = uuid::Uuid::new_v4();
        let worker_orchestrator = Orchestrator::new(rvoip_core::config::Config {
            max_direct_subscribers: 1,
            ..rvoip_core::config::Config::default()
        });
        let mut coordination = CallServiceCoordinationConfig::new(
            DeploymentId::parse(format!(
                "private-broadcast-shutdown-{}",
                match mode {
                    WorkerBroadcastShutdownMode::GracefulDrain => "graceful",
                    WorkerBroadcastShutdownMode::LeaseLoss => "lease-loss",
                }
            ))
            .unwrap(),
        );
        coordination.worker_lease_ttl = Duration::from_secs(300);
        coordination.worker_renew_interval = Duration::from_secs(100);
        let call_runtime = Arc::new(
            build_call_service_runtime(
                CallServiceRuntimeConfig {
                    backend: CallRepositoryBackendConfig::Memory,
                    worker_id: WorkerId::new(),
                    max_calls: 2,
                    worker_capabilities: BTreeSet::from(["quic".into()]),
                    control_key: vec![0x62; 32],
                    timeouts: CallTimeoutPolicy::default(),
                    coordination,
                },
                Arc::new(SamePrincipalAttachmentResolver),
                Arc::new(SystemCallServiceClock),
            )
            .await
            .unwrap(),
        );
        let worker = call_runtime.worker().lease;
        let authority = WorkerBroadcastSubscriptionAuthority::new(worker);
        let execution = CallExecutionSupervisor::install_with_leg_executors_context_canary_and_broadcast_authority(
            Arc::clone(&worker_orchestrator),
            Arc::clone(&call_runtime),
            Arc::new(DisabledProviderLegExecutor),
            None,
            Arc::new(ContextPolicy::default()),
            None,
            Some(Arc::clone(&authority)),
            2,
            Duration::from_secs(3),
        )
        .await
        .unwrap();
        let source_connection = ConnectionId::from_string("shutdown-broadcast-source");
        worker_orchestrator.publisher_registry().register(
            SessionId::from_string(broadcast_id.to_string()),
            PUBLIC_GATEWAY_BROADCAST_STREAM.into(),
            PublisherEntry {
                connection: source_connection,
                participant: "broadcast-origin".into(),
                kind: "audio".into(),
                codec: Some(default_audio_codec()),
            },
        );
        authority.activate_for_test(
            tenant_id.clone(),
            broadcast_id.to_string(),
            grant_generation,
        );
        let private_key =
            PrivateTokenKey::new(b"private-forwarding-test-key-32-bytes".to_vec()).unwrap();
        let worker_runtime = WorkerForwardingRuntime::start_with_broadcast_authority(
            WorkerForwardingConfig {
                worker_id: worker.worker_id,
                bind: "127.0.0.1:0".parse().unwrap(),
                tls: tls.worker.clone(),
                token_key: private_key.clone(),
                limits: private_limits(),
                timeouts: private_timeouts(),
            },
            Arc::clone(&worker_orchestrator),
            Arc::clone(&authority),
        )
        .await
        .unwrap();
        let forwarder = GatewayForwarder::start(
            GatewayForwardingConfig {
                gateway_id: "gateway-a".into(),
                bind: "127.0.0.1:0".parse().unwrap(),
                tls: tls.gateway.clone(),
                token_key: private_key,
                workers: vec![PrivateWorkerTarget {
                    worker_id: worker.worker_id,
                    endpoint: worker_runtime.local_addr().unwrap().to_string(),
                    server_name: "localhost".into(),
                }],
                limits: private_limits(),
                timeouts: private_timeouts(),
            },
            vec![tenant_id.clone()],
        )
        .await
        .unwrap();
        let route = forwarder
            .open_broadcast_route(
                tenant_id,
                CallId::new(),
                broadcast_id,
                worker,
                grant_generation,
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if forwarder.active_routes() == 1
                    && worker_orchestrator.active_direct_listener_count() == 1
                    && authority.listener_count() == 1
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("private listener activation deadline");

        match mode {
            WorkerBroadcastShutdownMode::GracefulDrain => execution.begin_drain(),
            WorkerBroadcastShutdownMode::LeaseLoss => {
                call_runtime.force_supervisor_health_for_test(RuntimeSupervisorHealth::LeaseLost)
            }
        }
        execution.shutdown(Duration::from_secs(3)).await;
        assert!(
            tokio::time::timeout(Duration::from_secs(3), route.recv())
                .await
                .expect("peer SessionEnd deadline")
                .is_none(),
            "worker shutdown must close the exact private media route"
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if forwarder.active_routes() == 0
                    && worker_orchestrator.active_direct_listener_count() == 0
                    && authority.listener_count() == 0
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("private listener shutdown convergence deadline");
        drop(route);
        forwarder.shutdown(Duration::from_secs(3)).await.unwrap();
        worker_runtime
            .shutdown(Duration::from_secs(3))
            .await
            .unwrap();
        drop(worker_orchestrator);
        Arc::try_unwrap(call_runtime)
            .expect("broadcast shutdown released call runtime")
            .shutdown(Duration::from_secs(3))
            .await
            .unwrap();
    }

    fn empty_attachment_resolver() -> Arc<GatewayAttachmentResolver> {
        let deployment = DeploymentId::parse("public-broadcast-network-test").unwrap();
        let clock: Arc<dyn CoordinationClock> = Arc::new(ManualCoordinationClock::new(Utc::now()));
        let coordinator =
            Arc::new(MemoryCoordinator::new(deployment, clock, 8).expect("memory coordinator"));
        Arc::new(
            GatewayAttachmentResolver::new(
                coordinator,
                b"public-broadcast-attachment-key-32-bytes".to_vec(),
            )
            .expect("empty attachment resolver"),
        )
    }

    impl PumpTestRoute {
        fn try_record(&self, packet: ForwardedPacket) -> Result<(), GatewayForwardingError> {
            self.sent.try_send(packet).map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => GatewayForwardingError::Backpressure,
                mpsc::error::TrySendError::Closed(_) => GatewayForwardingError::Closed,
            })
        }
    }

    #[async_trait]
    impl GatewayMediaRoute for PumpTestRoute {
        fn try_send_rtp(&self, packet: Bytes) -> Result<(), GatewayForwardingError> {
            self.try_record(ForwardedPacket::Rtp(packet))
        }

        fn try_send_rtcp(&self, packet: Bytes) -> Result<(), GatewayForwardingError> {
            self.try_record(ForwardedPacket::Rtcp(packet))
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

    fn token() -> String {
        URL_SAFE_NO_PAD.encode([7_u8; 32])
    }

    async fn next_network_message(
        inbound: &mut mpsc::Receiver<UctpEnvelope>,
        expected: MessageType,
    ) -> UctpEnvelope {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let envelope = inbound.recv().await.expect("network signaling closed");
                if envelope.msg_type == MessageType::Error {
                    panic!("network command rejected: {envelope:?}");
                }
                if envelope.msg_type == expected {
                    return envelope;
                }
            }
        })
        .await
        .expect("network signaling response deadline")
    }

    async fn authenticate_network_listener(
        client: &UctpQuicClient,
        inbound: &mut mpsc::Receiver<UctpEnvelope>,
        token: &str,
    ) {
        client
            .send(UctpEnvelope::new(
                MessageType::AuthHello,
                serde_json::to_value(auth::AuthHello {
                    device: auth::Device {
                        id: "malicious-listener".into(),
                        kind: "service".into(),
                        platform: "test".into(),
                        sdk_version: "bridgefu-test/1".into(),
                    },
                    auth_methods: vec!["bearer".into()],
                    capabilities: serde_json::Value::Object(Default::default()),
                })
                .unwrap(),
            ))
            .await
            .expect("send auth.hello");
        let challenge = next_network_message(inbound, MessageType::AuthChallenge).await;
        client
            .send(
                UctpEnvelope::new(
                    MessageType::AuthResponse,
                    serde_json::to_value(auth::AuthResponse {
                        method: "bearer".into(),
                        credential: token.into(),
                        actor_token: None,
                    })
                    .unwrap(),
                )
                .with_in_reply_to(challenge.id),
            )
            .await
            .expect("send auth.response");
        next_network_message(inbound, MessageType::AuthSession).await;
    }

    async fn open_network_broadcast_listener(
        client: &UctpQuicClient,
        inbound: &mut mpsc::Receiver<UctpEnvelope>,
        broadcast_id: &str,
        connection_id: &str,
    ) -> (u16, String) {
        client
            .send(
                UctpEnvelope::new(
                    MessageType::SessionInvite,
                    serde_json::to_value(session::SessionInvite {
                        from: "listener".into(),
                        to: vec!["broadcast".into()],
                        medium: "voice".into(),
                        intent: PUBLIC_GATEWAY_BROADCAST_INTENT.into(),
                        capabilities_offer: serde_json::Value::Object(Default::default()),
                    })
                    .unwrap(),
                )
                .with_sid(broadcast_id),
            )
            .await
            .expect("send broadcast Session invite");
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
                    .unwrap(),
                )
                .with_sid(broadcast_id)
                .with_connid(connection_id),
            )
            .await
            .expect("send receive-only Connection offer");
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let envelope = inbound.recv().await.expect("network signaling closed");
                if matches!(
                    envelope.msg_type,
                    MessageType::Error | MessageType::SessionReject
                ) {
                    if envelope.msg_type == MessageType::SessionReject {
                        let rejected: session::SessionReject = envelope.decode_payload().unwrap();
                        panic!(
                            "network admission rejected: {} {}",
                            rejected.reason_code, rejected.reason
                        );
                    }
                    let rejected: rvoip_uctp::payloads::control::Error =
                        envelope.decode_payload().unwrap();
                    panic!(
                        "network admission rejected: {} {}",
                        rejected.code, rejected.reason
                    );
                }
                if envelope.msg_type == MessageType::SessionAccept
                    && envelope.sid.as_deref() == Some(broadcast_id)
                {
                    break;
                }
            }
        })
        .await
        .expect("session.accept deadline");
        client
            .send(
                UctpEnvelope::new(MessageType::ConnectionReady, serde_json::json!({}))
                    .with_sid(broadcast_id)
                    .with_connid(connection_id),
            )
            .await
            .expect("send Connection ready");
        let (stream_local_id, bound_connection_id) =
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let envelope = inbound.recv().await.expect("network signaling closed");
                    if envelope.msg_type == MessageType::Error {
                        panic!("network stream setup rejected: {envelope:?}");
                    }
                    if envelope.msg_type != MessageType::StreamOpened {
                        continue;
                    }
                    let opened: stream::StreamOpened = envelope.decode_payload().unwrap();
                    if opened.stream.strm_id == "listener-receive" {
                        break (
                            opened.stream.stream_local_id,
                            envelope.connid.expect("stream.opened bound Connection ID"),
                        );
                    }
                }
            })
            .await
            .expect("stream.opened deadline");
        let subscribe = UctpEnvelope::new(
            MessageType::StreamSubscribe,
            serde_json::to_value(stream::StreamSubscribe {
                by_participant: "listener".into(),
                subscriptions: vec![stream::StreamSubscription {
                    strm_id: Some(PUBLIC_GATEWAY_BROADCAST_STREAM.into()),
                    ..Default::default()
                }],
            })
            .unwrap(),
        )
        .with_sid(broadcast_id)
        .with_connid(bound_connection_id.clone());
        let subscribe_id = subscribe.id.clone();
        client
            .send(subscribe)
            .await
            .expect("send Stream subscription");
        let reply = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let envelope = inbound.recv().await.expect("network signaling closed");
                if envelope.in_reply_to.as_deref() == Some(subscribe_id.as_str()) {
                    break envelope;
                }
            }
        })
        .await
        .expect("Stream subscription acknowledgement");
        assert_eq!(
            reply.msg_type,
            MessageType::Ack,
            "the first subscription after session.accept must succeed: {reply:?}"
        );
        (stream_local_id, bound_connection_id)
    }

    async fn next_worker_connection(
        events: &mut tokio::sync::broadcast::Receiver<Event>,
    ) -> ConnectionId {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(Event::ConnectionInbound { connection_id, .. }) = events.recv().await {
                    break connection_id;
                }
            }
        })
        .await
        .expect("private worker Connection deadline")
    }

    #[test]
    fn public_session_is_canonical_transport_typed_and_secret_safe() {
        let sip = format!("{PUBLIC_GATEWAY_SESSION_PREFIX}:sip:{}", token());
        let webrtc = format!("{PUBLIC_GATEWAY_SESSION_PREFIX}:webrtc:{}", token());
        assert_eq!(
            parse_public_session(&sip).unwrap().0,
            AttachmentTransport::Sip
        );
        assert_eq!(
            parse_public_session(&webrtc).unwrap().0,
            AttachmentTransport::WebRtc
        );
        assert_eq!(
            parse_public_session(&format!("{PUBLIC_GATEWAY_SESSION_PREFIX}:quic:{}", token())),
            Err(GatewayUctpIngressError::AttachmentRejected)
        );
        assert_eq!(
            parse_public_session(&format!("{PUBLIC_GATEWAY_SESSION_PREFIX}:sip:not-a-token")),
            Err(GatewayUctpIngressError::AttachmentRejected)
        );
        let error = format!(
            "{:?}",
            parse_public_session(&format!(
                "{PUBLIC_GATEWAY_SESSION_PREFIX}:unsupported:{}",
                token()
            ))
            .unwrap_err()
        );
        assert!(!error.contains(&token()));
    }

    #[test]
    fn session_resolver_requires_scope_intent_and_binds_only_token_digest() {
        let resolver = PublicGatewaySessionResolver {
            draining: Arc::new(AtomicBool::new(false)),
        };
        let mut principal = AuthenticatedPrincipal::anonymous();
        principal.scopes = vec![
            PUBLIC_GATEWAY_ATTACHMENT_SCOPE.to_owned(),
            UCTP_SESSION_SCOPE.to_owned(),
        ];
        let wire = SessionId::from_string(format!(
            "{PUBLIC_GATEWAY_SESSION_PREFIX}:webrtc:{}",
            token()
        ));
        let canonical = resolver.resolve_session(&principal, &wire).unwrap();
        assert!(canonical
            .as_str()
            .starts_with(&format!("{PUBLIC_GATEWAY_SESSION_PREFIX}:digest:")));
        assert!(!canonical.as_str().contains(&token()));
        resolver
            .reauthorize_session(&principal, &wire, &canonical)
            .unwrap();
        assert!(resolver
            .resolve_inbound_routing_hint(
                &principal,
                &wire,
                PUBLIC_GATEWAY_ATTACHMENT_INTENT,
                &serde_json::json!({}),
            )
            .unwrap()
            .is_some());
        assert!(resolver
            .resolve_inbound_routing_hint(
                &principal,
                &wire,
                "untrusted-intent",
                &serde_json::json!({}),
            )
            .is_err());

        principal.scopes.clear();
        assert!(resolver.resolve_session(&principal, &wire).is_err());
        principal.scopes = vec![
            PUBLIC_GATEWAY_ATTACHMENT_SCOPE.to_owned(),
            UCTP_SESSION_SCOPE.to_owned(),
        ];
        resolver.draining.store(true, Ordering::Release);
        assert!(resolver.resolve_session(&principal, &wire).is_err());
    }

    #[test]
    fn redis_millisecond_expiry_covers_the_same_durable_submillisecond_deadline() {
        let redis_expiry = chrono::DateTime::from_timestamp_millis(1_800_000_000_000).unwrap();
        let durable_expiry = redis_expiry + chrono::TimeDelta::microseconds(999);
        assert!(redis_expiry < durable_expiry);
        assert_eq!(
            redis_expiry.timestamp_millis(),
            durable_expiry.timestamp_millis()
        );
        assert!(grant_expiry_covers_durable_expiry(
            redis_expiry,
            durable_expiry
        ));
        assert!(!grant_expiry_covers_durable_expiry(
            redis_expiry,
            durable_expiry + chrono::TimeDelta::milliseconds(1)
        ));
    }

    #[test]
    fn rtp_round_trip_normalizes_dynamic_opus_pt_and_preserves_media() {
        let frame = MediaFrame {
            stream_id: StreamId::from_string("source"),
            kind: StreamKind::Audio,
            payload: Bytes::from_static(b"encoded-audio"),
            timestamp_rtp: 48_000,
            captured_at: Utc::now(),
            payload_type: Some(109),
        };
        let packet = encode_rtp(&frame, &default_audio_codec(), 42, 0x1020_3040);
        assert_eq!(packet.len(), RTP_FIXED_HEADER_BYTES + frame.payload.len());
        let decoded = decode_rtp(&packet, StreamId::from_string("destination")).unwrap();
        assert_eq!(decoded.payload, frame.payload);
        assert_eq!(decoded.timestamp_rtp, frame.timestamp_rtp);
        assert_eq!(decoded.payload_type, Some(111));
    }

    #[tokio::test]
    async fn panicked_public_uctp_task_removes_exact_route_and_closes_resources() {
        let connection_id = ConnectionId::from_string("public-uctp-panicked");
        let routes = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let (control, _control_rx) = mpsc::channel(1);
        routes
            .lock()
            .await
            .insert(connection_id.clone(), control.clone());
        let (sent, _sent_rx) = mpsc::channel(1);
        let (_private_source, private_inbound) = mpsc::channel(1);
        let route = Arc::new(PumpTestRoute {
            sent,
            inbound: tokio::sync::Mutex::new(private_inbound),
            closed: AtomicBool::new(false),
        });
        let resources = Arc::new(UctpTaskResources::new(
            connection_id,
            Arc::clone(&routes),
            Orchestrator::new(rvoip_core::config::Config::default()),
        ));
        resources.update(|owned| {
            owned.control = Some(control);
            owned.route = Some(Arc::clone(&route) as Arc<dyn GatewayMediaRoute>);
        });

        let result = supervise_uctp_attachment(Arc::clone(&resources), async {
            panic!("injected public UCTP attachment failure");
            #[allow(unreachable_code)]
            Ok(())
        })
        .await;

        assert_eq!(result, Err(GatewayUctpIngressError::Lifecycle));
        assert!(routes.lock().await.is_empty());
        assert!(route.closed.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn panicking_route_cleanup_still_releases_listener_lease_and_exact_route() {
        let connection_id = ConnectionId::from_string("public-uctp-cleanup-panic");
        let routes = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let (control, _control_rx) = mpsc::channel(1);
        routes
            .lock()
            .await
            .insert(connection_id.clone(), control.clone());
        let listener_closed = Arc::new(AtomicBool::new(false));
        let orchestrator = Orchestrator::new(rvoip_core::config::Config::default());
        let conversation = orchestrator
            .open_conversation(
                rvoip_core::ids::TenantId::from_string("cleanup-tenant"),
                rvoip_core::conversation::ConversationPolicy::default(),
                HashMap::new(),
            )
            .await
            .unwrap();
        let session = orchestrator
            .start_session(
                conversation.clone(),
                rvoip_core::session::SessionMedium::Voice,
                Vec::new(),
            )
            .await
            .unwrap();
        let resources = Arc::new(UctpTaskResources::new(
            connection_id,
            Arc::clone(&routes),
            Arc::clone(&orchestrator),
        ));
        resources.update(|owned| {
            owned.control = Some(control);
            owned.route = Some(Arc::new(PanickingCleanupRoute));
            owned.broadcast_lease = Some(Arc::new(RecordingCleanupLease(Arc::clone(
                &listener_closed,
            ))));
            owned.conversation = Some(conversation.clone());
            owned.session = Some(session.clone());
        });

        resources.cleanup(true).await;
        resources.cleanup(true).await;

        assert!(routes.lock().await.is_empty());
        assert!(listener_closed.load(Ordering::Acquire));
        assert!(matches!(
            orchestrator
                .session(&session)
                .unwrap()
                .read()
                .unwrap()
                .state,
            rvoip_core::session::SessionState::Ended | rvoip_core::session::SessionState::Failed
        ));
        assert_eq!(
            orchestrator
                .conversation(&conversation)
                .unwrap()
                .read()
                .unwrap()
                .state,
            rvoip_core::conversation::ConversationState::Closed
        );
    }

    #[tokio::test]
    async fn private_route_open_failure_awaits_exact_listener_lease_cleanup() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tls = network_tls_fixture();
        let tenant_id = TenantId::parse("tenant-a").unwrap();
        let configured_worker = WorkerLease {
            worker_id: crate::call_engine::WorkerId::new(),
            fence: crate::call_engine::WorkerFence::INITIAL,
        };
        let unauthorized_worker = WorkerLease {
            worker_id: crate::call_engine::WorkerId::new(),
            fence: crate::call_engine::WorkerFence::INITIAL,
        };
        let forwarder = GatewayForwarder::start(
            GatewayForwardingConfig {
                gateway_id: "gateway-a".into(),
                bind: "127.0.0.1:0".parse().unwrap(),
                tls: tls.gateway.clone(),
                token_key: PrivateTokenKey::new(b"private-forwarding-test-key-32-bytes".to_vec())
                    .unwrap(),
                workers: vec![PrivateWorkerTarget {
                    worker_id: configured_worker.worker_id,
                    endpoint: "127.0.0.1:9".into(),
                    server_name: "localhost".into(),
                }],
                limits: private_limits(),
                timeouts: private_timeouts(),
            },
            vec![tenant_id.clone()],
        )
        .await
        .expect("start gateway forwarder");
        let broadcast_id = uuid::Uuid::new_v4();
        let listeners_closed = Arc::new(AtomicUsize::new(0));
        let opener = ForwardingBroadcastRouteOpener {
            authority: Arc::new(FixedBroadcastAuthority {
                tenant_id: tenant_id.clone(),
                call_id: CallId::new(),
                broadcast_id,
                worker: unauthorized_worker,
                grant_generation: uuid::Uuid::new_v4(),
                listeners_closed: Arc::clone(&listeners_closed),
            }),
            forwarder: Arc::clone(&forwarder),
        };
        let mut principal = AuthenticatedPrincipal::anonymous();
        principal.tenant = Some(tenant_id.to_string());
        principal.scopes = vec![format!("broadcast:subscribe:{broadcast_id}")];

        assert!(matches!(
            opener
                .open(
                    principal,
                    broadcast_id.to_string(),
                    "public-connection".into(),
                )
                .await,
            Err(GatewayUctpIngressError::Forwarding(
                GatewayForwardingError::UnknownWorker
            ))
        ));
        assert_eq!(
            listeners_closed.load(Ordering::Acquire),
            1,
            "route-open failure must await exact listener lease close"
        );
        forwarder.shutdown(Duration::from_secs(6)).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn peer_visible_private_accept_timeout_sends_exact_session_end() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tls = network_tls_fixture();
        let mut server_tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                load_certificate_chain(&tls.worker.certificate_chain).unwrap(),
                load_private_key(&tls.worker.private_key).unwrap(),
            )
            .unwrap();
        server_tls.alpn_protocols = vec![UCTP_RAW_QUIC_ALPN_BYTES.to_vec()];
        let server_endpoint = Arc::new(
            make_server_endpoint(
                "127.0.0.1:0".parse().unwrap(),
                Arc::new(server_tls),
                quinn::TransportConfig::default(),
            )
            .unwrap(),
        );
        let server_addr = server_endpoint.local_addr().unwrap();
        let mut protocols =
            dispatch_by_alpn(Arc::clone(&server_endpoint), &[UCTP_RAW_QUIC_ALPN_BYTES]).unwrap();
        let mut accepts = protocols.take(UCTP_RAW_QUIC_ALPN_BYTES).unwrap();
        let (ended_tx, ended_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let connection = accepts.recv().await.expect("private gateway connected");
            let (send, receive) = connection.accept_bi().await.expect("UCTP control stream");
            let mut reader = Box::pin(envelope_reader(receive));
            let mut writer = Box::pin(envelope_writer(send));
            let hello = reader.next().await.unwrap().unwrap();
            assert_eq!(hello.msg_type, MessageType::AuthHello);
            writer
                .send(UctpEnvelope::new(
                    MessageType::AuthChallenge,
                    serde_json::to_value(auth::AuthChallenge {
                        nonce: "test-nonce".into(),
                        accepted_methods: vec!["bearer".into()],
                        server_capabilities: serde_json::json!({}),
                    })
                    .unwrap(),
                ))
                .await
                .unwrap();
            let response = reader.next().await.unwrap().unwrap();
            assert_eq!(response.msg_type, MessageType::AuthResponse);
            writer
                .send(
                    UctpEnvelope::new(
                        MessageType::AuthSession,
                        serde_json::to_value(auth::AuthSession {
                            identity_id: "gateway-a".into(),
                            participant_id: "gateway-a".into(),
                            session_token: "test-session".into(),
                            expires_at: Utc::now() + chrono::Duration::minutes(5),
                            assurance: "anonymous".into(),
                            reachability: Vec::new(),
                        })
                        .unwrap(),
                    )
                    .with_in_reply_to(response.id),
                )
                .await
                .unwrap();

            let mut accepted_sid = None;
            let mut saw_offer = false;
            while accepted_sid.is_none() || !saw_offer {
                let envelope = reader.next().await.unwrap().unwrap();
                match envelope.msg_type {
                    MessageType::SessionInvite => accepted_sid = envelope.sid,
                    MessageType::ConnectionOffer => saw_offer = true,
                    _ => {}
                }
            }
            let accepted_sid = accepted_sid.unwrap();
            writer
                .send(
                    UctpEnvelope::new(
                        MessageType::SessionAccept,
                        serde_json::to_value(session::SessionAccept {
                            by: "worker".into(),
                            capabilities_answer: serde_json::json!({}),
                        })
                        .unwrap(),
                    )
                    .with_sid(accepted_sid.clone()),
                )
                .await
                .unwrap();

            loop {
                let envelope = reader.next().await.unwrap().unwrap();
                if envelope.msg_type == MessageType::SessionEnd {
                    ended_tx.send((accepted_sid, envelope.sid)).ok();
                    break;
                }
            }
            connection.close(quinn::VarInt::from_u32(0), b"test complete");
        });

        let tenant = TenantId::parse("tenant-a").unwrap();
        let worker = WorkerLease {
            worker_id: WorkerId::new(),
            fence: crate::call_engine::WorkerFence::INITIAL,
        };
        let mut timeouts = private_timeouts();
        timeouts.signaling = Duration::from_millis(150);
        let forwarder = GatewayForwarder::start(
            GatewayForwardingConfig {
                gateway_id: "gateway-a".into(),
                bind: "127.0.0.1:0".parse().unwrap(),
                tls: tls.gateway.clone(),
                token_key: PrivateTokenKey::new(b"private-forwarding-test-key-32-bytes".to_vec())
                    .unwrap(),
                workers: vec![PrivateWorkerTarget {
                    worker_id: worker.worker_id,
                    endpoint: server_addr.to_string(),
                    server_name: "localhost".into(),
                }],
                limits: private_limits(),
                timeouts,
            },
            vec![tenant.clone()],
        )
        .await
        .unwrap();
        let broadcast_id = uuid::Uuid::new_v4();
        assert_eq!(
            forwarder
                .open_broadcast_route(
                    tenant,
                    CallId::new(),
                    broadcast_id,
                    worker,
                    uuid::Uuid::new_v4(),
                )
                .await
                .unwrap_err(),
            GatewayForwardingError::Timeout
        );
        let (accepted_sid, ended_sid) = tokio::time::timeout(Duration::from_secs(2), ended_rx)
            .await
            .expect("peer-visible SessionEnd deadline")
            .expect("SessionEnd observation");
        assert_eq!(ended_sid.as_deref(), Some(accepted_sid.as_str()));
        assert!(accepted_sid.contains(&broadcast_id.to_string()));
        assert_eq!(forwarder.active_routes(), 0);
        server.await.unwrap();
        forwarder.shutdown(Duration::from_secs(3)).await.unwrap();
        server_endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
    }

    #[tokio::test]
    async fn route_pump_carries_rtp_rtcp_and_reliable_data_without_competing_receivers() {
        let stream_id = StreamId::from_string("public-audio");
        let (public_source, public_inbound) = mpsc::channel(8);
        let (public_outbound, mut public_sink) = mpsc::channel(8);
        let stream: Arc<dyn MediaStream> = Arc::new(PumpTestStream {
            id: stream_id.clone(),
            inbound: Mutex::new(Some(public_inbound)),
            outbound: public_outbound,
            inbound_acquired: Arc::new(AtomicBool::new(false)),
        });
        let (sent, mut sent_packets) = mpsc::channel(8);
        let (private_source, private_inbound) = mpsc::channel(8);
        let route: Arc<dyn GatewayMediaRoute> = Arc::new(PumpTestRoute {
            sent,
            inbound: tokio::sync::Mutex::new(private_inbound),
            closed: AtomicBool::new(false),
        });
        let (control, control_rx) = mpsc::channel(8);
        let connection_id = ConnectionId::from_string("public-connection");
        let pump = tokio::spawn(run_route_pumps(
            connection_id,
            Orchestrator::new(rvoip_core::config::Config::default()),
            stream,
            Arc::clone(&route),
            control_rx,
            CancellationToken::new(),
        ));

        let public_frame = MediaFrame {
            stream_id,
            kind: StreamKind::Audio,
            payload: Bytes::from_static(b"public-opus"),
            timestamp_rtp: 960,
            captured_at: Utc::now(),
            // A browser may negotiate any dynamic Opus payload type. The
            // private UCTP hop has one canonical payload type for the exact
            // negotiated codec and must not inherit the browser's PT.
            payload_type: Some(109),
        };
        public_source.send(public_frame.clone()).await.unwrap();
        let ForwardedPacket::Rtp(public_rtp) = sent_packets.recv().await.unwrap() else {
            panic!("public media must become a complete private RTP packet");
        };
        assert_eq!(public_rtp[1] & 0x7f, 111);
        let decoded = decode_rtp(&public_rtp, StreamId::from_string("decoded")).unwrap();
        assert_eq!(decoded.payload, public_frame.payload);
        assert_eq!(decoded.timestamp_rtp, 960);

        let rtcp = Bytes::from_static(&[0x80, 200, 0, 0]);
        control
            .send(RouteControl::Data(DataMessage::reliable(
                PRIVATE_RTCP_LABEL,
                PRIVATE_RTCP_CONTENT_TYPE,
                rtcp.clone(),
            )))
            .await
            .unwrap();
        let ForwardedPacket::Rtcp(forwarded_rtcp) = sent_packets.recv().await.unwrap() else {
            panic!("reserved reliable control must remain RTCP");
        };
        assert_eq!(forwarded_rtcp, rtcp);

        let context = DataMessage::reliable(
            "bridgefu.context.v1",
            "application/json",
            Bytes::from_static(br#"{"correlation_id":"example"}"#),
        );
        control.send(RouteControl::Data(context)).await.unwrap();
        let ForwardedPacket::Data(forwarded_context) = sent_packets.recv().await.unwrap() else {
            panic!("ordinary reliable control must remain a DataMessage");
        };
        assert_eq!(forwarded_context.label, "bridgefu.context.v1");

        control
            .send(RouteControl::Dtmf {
                digits: "9#".into(),
                duration_ms: 120,
            })
            .await
            .unwrap();
        assert!(matches!(
            sent_packets.recv().await,
            Some(ForwardedPacket::Dtmf { digits, duration_ms: 120 }) if digits == "9#"
        ));

        let private_frame = MediaFrame {
            stream_id: StreamId::from_string("worker-audio"),
            kind: StreamKind::Audio,
            payload: Bytes::from_static(b"worker-opus"),
            timestamp_rtp: 1_920,
            captured_at: Utc::now(),
            payload_type: Some(111),
        };
        private_source
            .send(ForwardedPacket::Rtp(encode_rtp(
                &private_frame,
                &default_audio_codec(),
                19,
                0x0102_0304,
            )))
            .await
            .unwrap();
        let public_output = public_sink.recv().await.unwrap();
        assert_eq!(public_output.payload, private_frame.payload);
        assert_eq!(public_output.timestamp_rtp, private_frame.timestamp_rtp);

        control.send(RouteControl::Terminal).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), pump)
            .await
            .expect("route pump stops")
            .expect("route pump task succeeds");
    }

    #[tokio::test]
    async fn broadcast_pump_rejects_malicious_public_media_and_control_while_downstream_flows() {
        let stream_id = StreamId::from_string("public-broadcast-audio");
        let (public_source, public_inbound) = mpsc::channel(8);
        let (public_outbound, mut public_sink) = mpsc::channel(8);
        let inbound_acquired = Arc::new(AtomicBool::new(false));
        let stream: Arc<dyn MediaStream> = Arc::new(PumpTestStream {
            id: stream_id.clone(),
            inbound: Mutex::new(Some(public_inbound)),
            outbound: public_outbound,
            inbound_acquired: Arc::clone(&inbound_acquired),
        });
        public_source
            .send(MediaFrame {
                stream_id: stream_id.clone(),
                kind: StreamKind::Audio,
                payload: Bytes::from_static(b"malicious-upstream-opus"),
                timestamp_rtp: 960,
                captured_at: Utc::now(),
                payload_type: Some(111),
            })
            .await
            .unwrap();

        let (sent, mut sent_packets) = mpsc::channel(8);
        let (private_source, private_inbound) = mpsc::channel(8);
        let route: Arc<dyn GatewayMediaRoute> = Arc::new(PumpTestRoute {
            sent,
            inbound: tokio::sync::Mutex::new(private_inbound),
            closed: AtomicBool::new(false),
        });
        let (control, control_rx) = mpsc::channel(8);
        let pump = tokio::spawn(run_broadcast_route_pump(
            stream,
            Arc::clone(&route),
            control_rx,
            CancellationToken::new(),
        ));

        let downstream = MediaFrame {
            stream_id: StreamId::from_string("worker-broadcast-audio"),
            kind: StreamKind::Audio,
            payload: Bytes::from_static(b"authorized-downstream-opus"),
            timestamp_rtp: 1_920,
            captured_at: Utc::now(),
            payload_type: Some(111),
        };
        private_source
            .send(ForwardedPacket::Rtp(encode_rtp(
                &downstream,
                &default_audio_codec(),
                1,
                0x1020_3040,
            )))
            .await
            .unwrap();
        let received = tokio::time::timeout(Duration::from_secs(1), public_sink.recv())
            .await
            .expect("downstream broadcast media arrives")
            .expect("public sink remains open");
        assert_eq!(received.payload, downstream.payload);
        assert!(!inbound_acquired.load(Ordering::Acquire));
        assert!(sent_packets.try_recv().is_err());

        control
            .send(RouteControl::Data(DataMessage::reliable(
                "bridgefu.context.v1",
                "application/json",
                Bytes::from_static(b"{}"),
            )))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), pump)
            .await
            .expect("malicious control closes receive-only pump")
            .expect("broadcast pump task succeeds");
        assert!(!inbound_acquired.load(Ordering::Acquire));
        assert!(sent_packets.try_recv().is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn active_private_broadcast_graceful_drain_sends_session_end_and_releases_ownership() {
        assert_private_broadcast_worker_shutdown(WorkerBroadcastShutdownMode::GracefulDrain).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn active_private_broadcast_lease_loss_sends_session_end_and_releases_ownership() {
        assert_private_broadcast_worker_shutdown(WorkerBroadcastShutdownMode::LeaseLoss).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn real_network_two_listener_broadcast_is_receive_only_and_independently_owned() {
        let _ = tracing_subscriber::fmt::try_init();
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tls = network_tls_fixture();
        let tenant_id = TenantId::parse("tenant-a").unwrap();
        let broadcast_id = uuid::Uuid::new_v4();
        let grant_generation = uuid::Uuid::new_v4();
        let private_key =
            PrivateTokenKey::new(b"private-forwarding-test-key-32-bytes".to_vec()).unwrap();

        let worker_orchestrator = Orchestrator::new(rvoip_core::config::Config {
            max_direct_subscribers: 2,
            ..rvoip_core::config::Config::default()
        });
        let mut coordination = CallServiceCoordinationConfig::new(
            DeploymentId::parse("public-broadcast-network-worker").unwrap(),
        );
        coordination.worker_lease_ttl = Duration::from_secs(300);
        coordination.worker_renew_interval = Duration::from_secs(100);
        let call_runtime = Arc::new(
            build_call_service_runtime(
                CallServiceRuntimeConfig {
                    backend: CallRepositoryBackendConfig::Memory,
                    worker_id: WorkerId::new(),
                    max_calls: 2,
                    worker_capabilities: BTreeSet::from(["quic".into()]),
                    control_key: vec![0x61; 32],
                    timeouts: CallTimeoutPolicy::default(),
                    coordination,
                },
                Arc::new(SamePrincipalAttachmentResolver),
                Arc::new(SystemCallServiceClock),
            )
            .await
            .unwrap(),
        );
        let worker = call_runtime.worker().lease;
        let worker_authority = WorkerBroadcastSubscriptionAuthority::new(worker);
        let execution = CallExecutionSupervisor::install_with_leg_executors_context_canary_and_broadcast_authority(
            Arc::clone(&worker_orchestrator),
            Arc::clone(&call_runtime),
            Arc::new(DisabledProviderLegExecutor),
            None,
            Arc::new(ContextPolicy::default()),
            None,
            Some(Arc::clone(&worker_authority)),
            2,
            Duration::from_secs(5),
        )
        .await
        .expect("install worker broadcast admission owner");
        let mut worker_events = worker_orchestrator.subscribe_events();
        let source_connection_id = ConnectionId::from_string("broadcast-source");
        worker_orchestrator.publisher_registry().register(
            SessionId::from_string(broadcast_id.to_string()),
            PUBLIC_GATEWAY_BROADCAST_STREAM.into(),
            PublisherEntry {
                connection: source_connection_id.clone(),
                participant: "broadcast-origin".into(),
                kind: "audio".into(),
                codec: Some(default_audio_codec()),
            },
        );
        worker_authority.activate_for_test(
            tenant_id.clone(),
            broadcast_id.to_string(),
            grant_generation,
        );
        let worker_runtime = WorkerForwardingRuntime::start_with_broadcast_authority(
            WorkerForwardingConfig {
                worker_id: worker.worker_id,
                bind: "127.0.0.1:0".parse().unwrap(),
                tls: tls.worker.clone(),
                token_key: private_key.clone(),
                limits: private_limits(),
                timeouts: private_timeouts(),
            },
            Arc::clone(&worker_orchestrator),
            Arc::clone(&worker_authority),
        )
        .await
        .expect("start private worker listener");
        let gateway_forwarder = GatewayForwarder::start(
            GatewayForwardingConfig {
                gateway_id: "gateway-a".into(),
                bind: "127.0.0.1:0".parse().unwrap(),
                tls: tls.gateway.clone(),
                token_key: private_key,
                workers: vec![PrivateWorkerTarget {
                    worker_id: worker.worker_id,
                    endpoint: worker_runtime.local_addr().unwrap().to_string(),
                    server_name: "localhost".into(),
                }],
                limits: private_limits(),
                timeouts: private_timeouts(),
            },
            vec![tenant_id.clone()],
        )
        .await
        .expect("start private gateway forwarder");

        let grants = BroadcastGrantRegistry::new();
        let _grant = grants
            .register(
                tenant_id.as_str(),
                broadcast_id.to_string(),
                BroadcastGrantTransport::UctpQuic,
                Utc::now() + chrono::Duration::minutes(5),
            )
            .unwrap();
        let tokens = Arc::new(
            BroadcastTokenService::new(
                b"public-broadcast-network-token-key".to_vec(),
                grants,
                DEFAULT_MAX_BROADCAST_TOKEN_TTL,
            )
            .unwrap(),
        );
        let issued = tokens
            .issue(
                tenant_id.as_str(),
                &broadcast_id.to_string(),
                Duration::from_secs(60),
            )
            .unwrap();
        let second_issued = tokens
            .issue(
                tenant_id.as_str(),
                &broadcast_id.to_string(),
                Duration::from_secs(60),
            )
            .unwrap();
        let listeners_closed = Arc::new(AtomicUsize::new(0));
        let broadcast_authority: Arc<dyn GatewayBroadcastAuthority> =
            Arc::new(FixedBroadcastAuthority {
                tenant_id: tenant_id.clone(),
                call_id: CallId::new(),
                broadcast_id,
                worker,
                grant_generation,
                listeners_closed: Arc::clone(&listeners_closed),
            });
        let admission_active = Arc::new(AtomicUsize::new(0));
        let ingress = GatewayUctpIngress::start(
            GatewayUctpIngressConfig {
                bind: available_udp_addr(),
                certificate_chain: tls.worker.certificate_chain.clone(),
                private_key: tls.worker.private_key.clone(),
                max_concurrent_connections: 3,
                admission_capacity: 3,
                setup_timeout: Duration::from_secs(5),
            },
            Arc::new(RejectingAttachmentValidator),
            tokens,
            broadcast_authority,
            empty_attachment_resolver(),
            Arc::clone(&gateway_forwarder),
            Arc::new(CountingAdmission {
                active: Arc::clone(&admission_active),
            }),
        )
        .await
        .expect("start public UCTP ingress");

        let client_tls = dev_client_config_trusting(&tls.public_certificate).unwrap();
        let client_endpoint =
            make_client_endpoint("127.0.0.1:0".parse().unwrap(), Arc::new(client_tls.clone()))
                .unwrap();
        let client = UctpQuicClient::connect(
            &client_endpoint,
            ingress.local_addr(),
            "localhost",
            Arc::new(client_tls.clone()),
        )
        .await
        .expect("connect real public QUIC listener");
        let mut inbound = client.take_inbound().expect("take signaling receiver");
        authenticate_network_listener(&client, &mut inbound, &issued.token).await;
        let wire_connection = "malicious-receive-only-listener";
        let (public_stream_local_id, bound_public_connection) = open_network_broadcast_listener(
            &client,
            &mut inbound,
            &broadcast_id.to_string(),
            wire_connection,
        )
        .await;
        let private_connection_id = next_worker_connection(&mut worker_events).await;

        let second_client_endpoint =
            make_client_endpoint("127.0.0.1:0".parse().unwrap(), Arc::new(client_tls.clone()))
                .unwrap();
        let second_client = UctpQuicClient::connect(
            &second_client_endpoint,
            ingress.local_addr(),
            "localhost",
            Arc::new(client_tls),
        )
        .await
        .expect("connect second real public QUIC listener");
        let mut second_inbound = second_client
            .take_inbound()
            .expect("take second signaling receiver");
        authenticate_network_listener(&second_client, &mut second_inbound, &second_issued.token)
            .await;
        let (second_public_stream_local_id, _second_bound_public_connection) =
            open_network_broadcast_listener(
                &second_client,
                &mut second_inbound,
                &broadcast_id.to_string(),
                "independent-receive-only-listener",
            )
            .await;
        let second_private_connection_id = next_worker_connection(&mut worker_events).await;
        assert_ne!(
            private_connection_id, second_private_connection_id,
            "each listener must own a distinct private Connection and wire route"
        );

        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if gateway_forwarder.active_routes() == 2
                    && worker_orchestrator.active_direct_listener_count() == 2
                    && worker_authority.listener_count() == 2
                    && admission_active.load(Ordering::Acquire) == 2
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("public-to-private route activation deadline");
        let private_stream = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(mut streams) = worker_runtime
                    .adapter()
                    .streams(private_connection_id.clone())
                    .await
                {
                    if let Some(stream) = streams.pop() {
                        break stream;
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("private receive-only media stream deadline");
        assert_eq!(private_stream.direction(), Direction::Outbound);
        let mut worker_inbound = private_stream
            .try_frames_in()
            .expect("observe forbidden private ingress");

        let malicious_frame = MediaFrame {
            stream_id: StreamId::from_string("malicious-upstream"),
            kind: StreamKind::Audio,
            payload: Bytes::from_static(b"malicious-upstream-opus"),
            timestamp_rtp: 960,
            captured_at: Utc::now(),
            payload_type: Some(111),
        };
        client
            .connection
            .send_datagram(pack(&MediaDatagram {
                flags: 0,
                stream_local_id: public_stream_local_id,
                seq: 1,
                payload: encode_rtp(&malicious_frame, &default_audio_codec(), 7, 0x1020_3040),
            }))
            .expect("send malicious full-RTP datagram");
        let malicious_message = DataMessage::reliable(
            "bridgefu.context.v1",
            "application/json",
            Bytes::from_static(b"{}"),
        );
        let message_request = UctpEnvelope::new(
            MessageType::MessageSend,
            serde_json::to_value(
                message::MessageSend::from_data_message(
                    &malicious_message,
                    "listener",
                    serde_json::json!("all"),
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .with_sid(broadcast_id.to_string())
        .with_connid(bound_public_connection);
        let message_request_id = message_request.id.clone();
        client
            .send(message_request)
            .await
            .expect("send malicious control message");
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let response = inbound.recv().await.expect("signaling remains open");
                if response.in_reply_to.as_deref() == Some(message_request_id.as_str()) {
                    assert_eq!(response.msg_type, MessageType::Error);
                    break;
                }
            }
        })
        .await
        .expect("receive-only control rejection deadline");
        assert!(
            tokio::time::timeout(Duration::from_millis(250), worker_inbound.recv())
                .await
                .is_err(),
            "malicious public RTP reached the private worker"
        );
        while let Ok(event) = worker_events.try_recv() {
            assert!(
                !matches!(
                    event,
                    Event::DataMessageReceived { connection_id, .. }
                        if connection_id == private_connection_id
                ),
                "malicious public control reached the private worker"
            );
        }

        let downstream = MediaFrame {
            stream_id: StreamId::from_string(PUBLIC_GATEWAY_BROADCAST_STREAM),
            kind: StreamKind::Audio,
            payload: Bytes::from_static(&[0x78, 0x00]),
            timestamp_rtp: 1_920,
            captured_at: Utc::now(),
            payload_type: Some(111),
        };
        assert_eq!(
            worker_orchestrator
                .fanout_frame(
                    &SessionId::from_string(broadcast_id.to_string()),
                    &source_connection_id,
                    &StreamId::from_string(PUBLIC_GATEWAY_BROADCAST_STREAM),
                    downstream.clone(),
                )
                .await,
            2
        );
        let public_datagram =
            tokio::time::timeout(Duration::from_secs(2), client.connection.read_datagram())
                .await
                .expect("downstream public datagram deadline")
                .expect("downstream public datagram");
        let decoded = unpack_rtp_datagram(&public_datagram).expect("complete UCTP/RTP datagram");
        assert_eq!(decoded.stream_local_id, public_stream_local_id);
        assert_eq!(decoded.rtp.payload_type, 111);
        assert_eq!(decoded.rtp.payload, downstream.payload);
        assert_eq!(decoded.rtp.timestamp, downstream.timestamp_rtp);
        let second_public_datagram = tokio::time::timeout(
            Duration::from_secs(2),
            second_client.connection.read_datagram(),
        )
        .await
        .expect("second downstream public datagram deadline")
        .expect("second downstream public datagram");
        let second_decoded = unpack_rtp_datagram(&second_public_datagram)
            .expect("second complete UCTP/RTP datagram");
        assert_eq!(
            second_decoded.stream_local_id,
            second_public_stream_local_id
        );
        assert_eq!(second_decoded.rtp.payload_type, 111);
        assert_eq!(second_decoded.rtp.payload, downstream.payload);
        assert_eq!(second_decoded.rtp.timestamp, downstream.timestamp_rtp);

        client
            .send(
                UctpEnvelope::new(
                    MessageType::SessionEnd,
                    serde_json::to_value(session::SessionEnd {
                        by: "listener".into(),
                        reason_code: 0,
                        reason: "test complete".into(),
                    })
                    .unwrap(),
                )
                .with_sid(broadcast_id.to_string()),
            )
            .await
            .expect("send public Session end");
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if ingress.active_routes() == 1
                    && gateway_forwarder.active_routes() == 1
                    && worker_orchestrator.active_direct_listener_count() == 1
                    && worker_authority.listener_count() == 1
                    && admission_active.load(Ordering::Acquire) == 1
                    && listeners_closed.load(Ordering::Acquire) == 1
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("first listener exact teardown deadline");

        let survivor_frame = MediaFrame {
            payload: Bytes::from_static(&[0x78, 0x01]),
            timestamp_rtp: 2_880,
            ..downstream.clone()
        };
        assert_eq!(
            worker_orchestrator
                .fanout_frame(
                    &SessionId::from_string(broadcast_id.to_string()),
                    &source_connection_id,
                    &StreamId::from_string(PUBLIC_GATEWAY_BROADCAST_STREAM),
                    survivor_frame.clone(),
                )
                .await,
            1
        );
        let survivor_datagram = tokio::time::timeout(
            Duration::from_secs(2),
            second_client.connection.read_datagram(),
        )
        .await
        .expect("surviving listener datagram deadline")
        .expect("surviving listener datagram");
        let survivor =
            unpack_rtp_datagram(&survivor_datagram).expect("surviving complete UCTP/RTP datagram");
        assert_eq!(survivor.stream_local_id, second_public_stream_local_id);
        assert_eq!(survivor.rtp.payload, survivor_frame.payload);
        assert_eq!(survivor.rtp.timestamp, survivor_frame.timestamp_rtp);
        assert!(
            tokio::time::timeout(
                Duration::from_millis(250),
                client.connection.read_datagram()
            )
            .await
            .is_err(),
            "retired listener received media owned by the surviving route"
        );

        second_client
            .send(
                UctpEnvelope::new(
                    MessageType::SessionEnd,
                    serde_json::to_value(session::SessionEnd {
                        by: "listener".into(),
                        reason_code: 0,
                        reason: "test complete".into(),
                    })
                    .unwrap(),
                )
                .with_sid(broadcast_id.to_string()),
            )
            .await
            .expect("send second public Session end");
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if ingress.active_routes() == 0
                    && gateway_forwarder.active_routes() == 0
                    && worker_orchestrator.active_direct_listener_count() == 0
                    && worker_authority.listener_count() == 0
                    && admission_active.load(Ordering::Acquire) == 0
                    && listeners_closed.load(Ordering::Acquire) == 2
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("exact public/private broadcast cleanup deadline");
        client
            .connection
            .close(quinn::VarInt::from_u32(0), b"test complete");
        second_client
            .connection
            .close(quinn::VarInt::from_u32(0), b"test complete");
        ingress.shutdown(Duration::from_secs(3)).await.unwrap();
        gateway_forwarder
            .shutdown(Duration::from_secs(3))
            .await
            .unwrap();
        worker_runtime
            .shutdown(Duration::from_secs(3))
            .await
            .unwrap();
        execution.shutdown(Duration::from_secs(3)).await;
        drop(worker_orchestrator);
        Arc::try_unwrap(call_runtime)
            .expect("broadcast execution released call runtime")
            .shutdown(Duration::from_secs(3))
            .await
            .unwrap();
    }
}
