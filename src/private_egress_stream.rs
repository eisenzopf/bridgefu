//! Generation-bound private egress media admission and gateway adapter proxy.
//!
//! The command plane in [`crate::private_egress`] deliberately does not reuse
//! the public/source media stream for a destination.  A worker first reserves
//! one [`PrivateEgressStreamAdmission`].  The gateway then opens a distinct
//! authenticated UCTP Session/Connection/Stream carrying that descriptor.
//! Only the exact worker fence, tenant, call, source attachment generation,
//! target leg generation, and admission ID can satisfy the reservation.

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use dashmap::DashMap;
use rvoip_core::adapter::{ConnectionAdapter, EndReason, OriginateContext, OriginateRequest};
use rvoip_core::capability::{CapabilityDescriptor, CodecInfo};
use rvoip_core::connection::{Direction, Transport};
use rvoip_core::conversation::ConversationPolicy;
use rvoip_core::ids::{
    ConnectionId, ConversationId, ParticipantId, StreamId, TenantId as RvoipTenantId,
};
use rvoip_core::operational_events::{OperationalEvent, OperationalEventKind};
use rvoip_core::session::SessionMedium;
use rvoip_core::stream::{MediaFrame, MediaStream, StreamKind};
use rvoip_core::{Orchestrator, PreparedOutboundConnection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::call_engine::{RouteCatalogFingerprint, TenantId, WorkerLease};
use crate::gateway_forwarding::{ForwardedPacket, GatewayForwarder, GatewayForwardingRoute};
use crate::private_egress::{
    PrivateEgressCommand, PrivateEgressControlClient, PrivateEgressEndReason, PrivateEgressError,
    PrivateEgressHandler, PrivateEgressHandlerResult, PrivateEgressLifecycleEvent,
    PrivateEgressLifecycleState, PrivateEgressOperation, PrivateEgressProfile,
    PrivateEgressRouteAuthority, PrivateEgressSource, PrivateEgressTarget, PrivateEgressTransport,
};

const STREAM_ADMISSION_VERSION: u8 = 1;
const MAX_STREAM_ADMISSION_BYTES: usize = 4 * 1024;
const MAX_STREAM_ADMISSION_LIFETIME: Duration = Duration::from_secs(30);
const ACTIVATION_PENDING: u8 = 0;
const ACTIVATION_COMMITTED: u8 = 1;
const ACTIVATION_FAILED: u8 = 2;

/// Complete worker-side dependency bundle for split SIP/WebRTC egress. The
/// durable call supervisor owns reservations and admission; the process role
/// owns draining and final control-client shutdown.
pub struct PrivateEgressWorkerRuntime {
    control: Arc<PrivateEgressControlClient>,
    admissions: Arc<PrivateEgressStreamAdmissionRegistry>,
    routes: Arc<PrivateEgressWorkerRouteCatalog>,
    restart_safe: bool,
}

impl fmt::Debug for PrivateEgressWorkerRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateEgressWorkerRuntime")
            .field("worker", &self.admissions.worker())
            .field("active_admissions", &self.admissions.active_admissions())
            .field("configured_routes", &self.routes.len())
            .field("restart_safe", &self.restart_safe)
            .finish_non_exhaustive()
    }
}

impl PrivateEgressWorkerRuntime {
    pub fn new(
        control: Arc<PrivateEgressControlClient>,
        admissions: Arc<PrivateEgressStreamAdmissionRegistry>,
        restart_safe: bool,
    ) -> Result<Arc<Self>, PrivateEgressStreamError> {
        Self::new_with_routes(
            control,
            admissions,
            PrivateEgressWorkerRouteCatalog::new(Vec::new())?,
            restart_safe,
        )
    }

    pub fn new_with_routes(
        control: Arc<PrivateEgressControlClient>,
        admissions: Arc<PrivateEgressStreamAdmissionRegistry>,
        routes: Arc<PrivateEgressWorkerRouteCatalog>,
        restart_safe: bool,
    ) -> Result<Arc<Self>, PrivateEgressStreamError> {
        if control.worker() != admissions.worker() {
            return Err(PrivateEgressStreamError::OwnershipMismatch);
        }
        Ok(Arc::new(Self {
            control,
            admissions,
            routes,
            restart_safe,
        }))
    }

    pub fn control(&self) -> Arc<PrivateEgressControlClient> {
        Arc::clone(&self.control)
    }

    pub fn admissions(&self) -> Arc<PrivateEgressStreamAdmissionRegistry> {
        Arc::clone(&self.admissions)
    }

    pub fn routes(&self) -> Arc<PrivateEgressWorkerRouteCatalog> {
        Arc::clone(&self.routes)
    }

    #[must_use]
    pub const fn restart_safe(&self) -> bool {
        self.restart_safe
    }

    pub fn begin_drain(&self) {
        self.control.begin_drain();
        self.admissions.begin_drain();
    }

    pub async fn shutdown(&self) {
        self.begin_drain();
        self.admissions.release_all();
        self.control.shutdown().await;
    }
}

/// Exact non-secret route material installed in both the worker and gateway
/// processes from the same validated named-route configuration. The worker
/// can therefore select a codec and target without trusting public input,
/// while the gateway remains the authority that resolves credentials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateEgressWorkerRouteDescriptor {
    pub tenant_id: TenantId,
    pub route_id: String,
    pub transport: PrivateEgressTransport,
    pub profile: PrivateEgressProfile,
    pub target: String,
    pub codecs: Vec<CodecInfo>,
}

impl PrivateEgressWorkerRouteDescriptor {
    pub fn validate(&self) -> Result<(), PrivateEgressStreamError> {
        let route_id_ok = !self.route_id.is_empty()
            && self.route_id.len() <= 256
            && self.route_id.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
            });
        let target_ok = !self.target.is_empty()
            && self.target.len() <= 2_048
            && !self.target.chars().any(char::is_control)
            && match self.transport {
                PrivateEgressTransport::Sip => {
                    self.target.starts_with("sip:") || self.target.starts_with("sips:")
                }
                PrivateEgressTransport::WebRtc => self.target.starts_with("wss://"),
            };
        let profile_ok = !self.profile.profile_id.is_empty()
            && !self.profile.revision.is_empty()
            && self.profile.revision.len() == 64
            && self
                .profile
                .revision
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        let codecs_ok = !self.codecs.is_empty()
            && self.codecs.len() <= 8
            && self.codecs.iter().all(|codec| {
                !codec.name.is_empty()
                    && codec.name.len() <= 64
                    && codec.clock_rate_hz > 0
                    && (1..=2).contains(&codec.channels)
            });
        if route_id_ok && target_ok && profile_ok && codecs_ok {
            Ok(())
        } else {
            Err(PrivateEgressStreamError::InvalidAdmission)
        }
    }
}

/// Immutable exact-match catalog. Duplicate route identities are rejected so
/// a worker can never select between two conflicting profile snapshots.
pub struct PrivateEgressWorkerRouteCatalog {
    entries: Vec<PrivateEgressWorkerRouteDescriptor>,
    fingerprint: RouteCatalogFingerprint,
}

impl fmt::Debug for PrivateEgressWorkerRouteCatalog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateEgressWorkerRouteCatalog")
            .field("entries", &self.entries.len())
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}

impl PrivateEgressWorkerRouteCatalog {
    pub fn new(
        entries: Vec<PrivateEgressWorkerRouteDescriptor>,
    ) -> Result<Arc<Self>, PrivateEgressStreamError> {
        let fingerprint = route_catalog_fingerprint(&entries);
        Self::new_with_fingerprint(entries, fingerprint)
    }

    /// Builds an exact private-egress resolver while retaining the broader
    /// gateway/worker configuration fingerprint used for placement. The
    /// supplied fingerprint may cover provider and Amazon routes plus worker
    /// capability policy that are intentionally absent from this resolver.
    pub fn new_with_fingerprint(
        entries: Vec<PrivateEgressWorkerRouteDescriptor>,
        fingerprint: RouteCatalogFingerprint,
    ) -> Result<Arc<Self>, PrivateEgressStreamError> {
        for (index, entry) in entries.iter().enumerate() {
            entry.validate()?;
            if entries[..index].iter().any(|candidate| {
                candidate.tenant_id == entry.tenant_id
                    && candidate.route_id == entry.route_id
                    && candidate.transport == entry.transport
            }) {
                return Err(PrivateEgressStreamError::InvalidAdmission);
            }
        }
        Ok(Arc::new(Self {
            entries,
            fingerprint,
        }))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Deterministic SHA-256 identity of the canonical sorted route catalog.
    #[must_use]
    pub const fn fingerprint(&self) -> RouteCatalogFingerprint {
        self.fingerprint
    }

    #[must_use]
    pub fn supports_transport(&self, transport: PrivateEgressTransport) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.transport == transport)
    }

    pub fn resolve(
        &self,
        tenant_id: &TenantId,
        route_id: &str,
        transport: PrivateEgressTransport,
        profile: &PrivateEgressProfile,
        target: &str,
    ) -> Result<PrivateEgressWorkerRouteDescriptor, PrivateEgressStreamError> {
        self.entries
            .iter()
            .find(|entry| {
                entry.tenant_id == *tenant_id
                    && entry.route_id == route_id
                    && entry.transport == transport
                    && entry.profile == *profile
                    && entry.target == target
            })
            .cloned()
            .ok_or(PrivateEgressStreamError::OwnershipMismatch)
    }
}

fn route_catalog_fingerprint(
    entries: &[PrivateEgressWorkerRouteDescriptor],
) -> RouteCatalogFingerprint {
    let mut canonical_entries = entries.iter().collect::<Vec<_>>();
    canonical_entries.sort_by(|left, right| {
        left.tenant_id
            .cmp(&right.tenant_id)
            .then_with(|| left.route_id.cmp(&right.route_id))
            .then_with(|| transport_tag(left.transport).cmp(&transport_tag(right.transport)))
            .then_with(|| left.profile.profile_id.cmp(&right.profile.profile_id))
            .then_with(|| left.profile.revision.cmp(&right.profile.revision))
            .then_with(|| left.target.cmp(&right.target))
    });

    let mut hasher = Sha256::new();
    hash_field(&mut hasher, b"bridgefu.private-egress-route-catalog.v1");
    hash_count(&mut hasher, canonical_entries.len());
    for entry in canonical_entries {
        hash_field(&mut hasher, entry.tenant_id.as_str().as_bytes());
        hash_field(&mut hasher, entry.route_id.as_bytes());
        hasher.update([transport_tag(entry.transport)]);
        hash_field(&mut hasher, entry.profile.profile_id.as_bytes());
        hash_field(&mut hasher, entry.profile.revision.as_bytes());
        hash_field(&mut hasher, entry.target.as_bytes());

        let mut codecs = entry.codecs.iter().collect::<Vec<_>>();
        codecs.sort_by_cached_key(|codec| {
            (
                codec.name.to_ascii_lowercase(),
                codec.clock_rate_hz,
                codec.channels,
                codec.fmtp.clone(),
            )
        });
        hash_count(&mut hasher, codecs.len());
        for codec in codecs {
            hash_field(&mut hasher, codec.name.to_ascii_lowercase().as_bytes());
            hasher.update(codec.clock_rate_hz.to_be_bytes());
            hasher.update([codec.channels]);
            match &codec.fmtp {
                Some(fmtp) => {
                    hasher.update([1]);
                    hash_field(&mut hasher, fmtp.as_bytes());
                }
                None => hasher.update([0]),
            }
        }
    }
    RouteCatalogFingerprint::new(hasher.finalize().into())
}

const fn transport_tag(transport: PrivateEgressTransport) -> u8 {
    match transport {
        PrivateEgressTransport::Sip => 1,
        PrivateEgressTransport::WebRtc => 2,
    }
}

fn hash_count(hasher: &mut Sha256, count: usize) {
    hasher.update(u64::try_from(count).unwrap_or(u64::MAX).to_be_bytes());
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hash_count(hasher, value.len());
    hasher.update(value);
}

/// Immutable descriptor for the second, destination-side private media
/// connection.  The descriptor is generated by the worker from the same
/// Prepare command that the gateway receives, so no public input can select a
/// worker, call, leg, generation, or codec independently.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateEgressStreamAdmission {
    pub version: u8,
    pub admission_id: Uuid,
    pub worker: WorkerLease,
    pub source: PrivateEgressSource,
    pub target: PrivateEgressTarget,
    pub codec: CodecInfo,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
}

impl PrivateEgressStreamAdmission {
    /// Derive a one-use stream admission from an exact Prepare command.  The
    /// command ID becomes the admission ID, binding command replay and media
    /// admission to the same incarnation.
    pub fn from_prepare(command: &PrivateEgressCommand) -> Result<Self, PrivateEgressStreamError> {
        let PrivateEgressOperation::Prepare { codec, .. } = &command.operation else {
            return Err(PrivateEgressStreamError::InvalidAdmission);
        };
        let admission = Self {
            version: STREAM_ADMISSION_VERSION,
            admission_id: command.command_id,
            worker: command.worker,
            source: command.source.clone(),
            target: command.target,
            codec: codec.clone(),
            issued_at_ms: command.issued_at_ms,
            expires_at_ms: command.expires_at_ms,
        };
        admission.validate(unix_time_ms())?;
        Ok(admission)
    }

    pub fn authority(&self) -> PrivateEgressRouteAuthority {
        PrivateEgressRouteAuthority {
            worker: self.worker,
            source: self.source.clone(),
        }
    }

    pub fn validate(&self, now_ms: i64) -> Result<(), PrivateEgressStreamError> {
        if self.version != STREAM_ADMISSION_VERSION
            || self.admission_id.is_nil()
            || self.worker.fence.as_i64() <= 0
            || self.codec.name.is_empty()
            || self.codec.name.len() > 64
            || self.codec.clock_rate_hz == 0
            || self.codec.channels == 0
            || self.codec.channels > 2
            || self
                .codec
                .name
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || b"._-".contains(&byte)))
        {
            return Err(PrivateEgressStreamError::InvalidAdmission);
        }
        let lifetime = self
            .expires_at_ms
            .checked_sub(self.issued_at_ms)
            .filter(|lifetime| *lifetime > 0)
            .ok_or(PrivateEgressStreamError::InvalidAdmission)?;
        if u128::try_from(lifetime).unwrap_or(u128::MAX) > MAX_STREAM_ADMISSION_LIFETIME.as_millis()
        {
            return Err(PrivateEgressStreamError::InvalidAdmission);
        }
        if self.expires_at_ms < now_ms {
            return Err(PrivateEgressStreamError::Expired);
        }
        Ok(())
    }

    pub fn to_routing_hint(&self) -> Result<String, PrivateEgressStreamError> {
        self.validate(unix_time_ms())?;
        let encoded =
            serde_json::to_string(self).map_err(|_| PrivateEgressStreamError::InvalidAdmission)?;
        if encoded.len() > MAX_STREAM_ADMISSION_BYTES
            || encoded.len() > rvoip_core::adapter::MAX_INBOUND_ROUTING_HINT_BYTES
        {
            return Err(PrivateEgressStreamError::InvalidAdmission);
        }
        Ok(encoded)
    }

    pub fn from_routing_hint(value: &str) -> Result<Self, PrivateEgressStreamError> {
        if value.is_empty()
            || value.len() > MAX_STREAM_ADMISSION_BYTES
            || value.len() > rvoip_core::adapter::MAX_INBOUND_ROUTING_HINT_BYTES
        {
            return Err(PrivateEgressStreamError::InvalidAdmission);
        }
        let admission = serde_json::from_str::<Self>(value)
            .map_err(|_| PrivateEgressStreamError::InvalidAdmission)?;
        admission.validate(unix_time_ms())?;
        Ok(admission)
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PrivateEgressStreamError {
    #[error("private egress stream admission is invalid")]
    InvalidAdmission,
    #[error("private egress stream admission expired")]
    Expired,
    #[error("private egress stream admission ownership does not match")]
    OwnershipMismatch,
    #[error("private egress stream admission was already used")]
    AlreadyUsed,
    #[error("private egress stream admission capacity is exhausted")]
    CapacityExceeded,
    #[error("private egress stream admission timed out")]
    Timeout,
    #[error("private egress stream connection is unavailable")]
    ConnectionUnavailable,
}

struct StreamAdmissionEntry {
    admission: PrivateEgressStreamAdmission,
    sender: Option<oneshot::Sender<PrivateEgressWorkerConnection>>,
    bound: bool,
    _permit: OwnedSemaphorePermit,
}

/// Worker-side, bounded reservation registry.  A successful admission remains
/// registered until the resulting connection is dropped, allowing transport
/// token refresh to revalidate the exact bound route without making the token
/// reusable.
pub struct PrivateEgressStreamAdmissionRegistry {
    worker: WorkerLease,
    entries: DashMap<Uuid, StreamAdmissionEntry>,
    capacity: Arc<Semaphore>,
    draining: AtomicBool,
}

impl fmt::Debug for PrivateEgressStreamAdmissionRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateEgressStreamAdmissionRegistry")
            .field("worker", &self.worker)
            .field("active", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl PrivateEgressStreamAdmissionRegistry {
    pub fn new(
        worker: WorkerLease,
        max_active_admissions: usize,
    ) -> Result<Arc<Self>, PrivateEgressStreamError> {
        if worker.fence.as_i64() <= 0 || max_active_admissions == 0 {
            return Err(PrivateEgressStreamError::InvalidAdmission);
        }
        Ok(Arc::new(Self {
            worker,
            entries: DashMap::new(),
            capacity: Arc::new(Semaphore::new(max_active_admissions)),
            draining: AtomicBool::new(false),
        }))
    }

    pub const fn worker(&self) -> WorkerLease {
        self.worker
    }

    pub fn active_admissions(&self) -> usize {
        self.entries.len()
    }

    pub fn reserve(
        self: &Arc<Self>,
        admission: PrivateEgressStreamAdmission,
    ) -> Result<PrivateEgressStreamReservation, PrivateEgressStreamError> {
        if self.draining.load(Ordering::Acquire) {
            return Err(PrivateEgressStreamError::ConnectionUnavailable);
        }
        admission.validate(unix_time_ms())?;
        if admission.worker != self.worker {
            return Err(PrivateEgressStreamError::OwnershipMismatch);
        }
        self.sweep_expired(unix_time_ms());
        let permit = Arc::clone(&self.capacity)
            .try_acquire_owned()
            .map_err(|_| PrivateEgressStreamError::CapacityExceeded)?;
        let (sender, receiver) = oneshot::channel();
        match self.entries.entry(admission.admission_id) {
            dashmap::mapref::entry::Entry::Occupied(_) => {
                Err(PrivateEgressStreamError::AlreadyUsed)
            }
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert(StreamAdmissionEntry {
                    admission: admission.clone(),
                    sender: Some(sender),
                    bound: false,
                    _permit: permit,
                });
                Ok(PrivateEgressStreamReservation {
                    registry: Arc::downgrade(self),
                    admission,
                    receiver: Some(receiver),
                })
            }
        }
    }

    /// Revalidate a pending or already-bound descriptor without consuming it.
    /// This is safe for synchronous UCTP Session/Connection reauthorization.
    pub fn authorizes(&self, admission: &PrivateEgressStreamAdmission) -> bool {
        if admission.validate(unix_time_ms()).is_err() || admission.worker != self.worker {
            return false;
        }
        self.entries
            .get(&admission.admission_id)
            .is_some_and(|entry| entry.admission == *admission)
    }

    /// Minimal Session-ID preflight used before the authenticated routing
    /// hint is decoded. Full descriptor equality is still required by
    /// [`Self::authorizes`].
    pub fn authorizes_id(&self, admission_id: Uuid, tenant_id: &str) -> bool {
        self.entries.get(&admission_id).is_some_and(|entry| {
            entry.admission.worker == self.worker
                && entry.admission.source.tenant_id.as_str() == tenant_id
                && entry.admission.expires_at_ms >= unix_time_ms()
        })
    }

    pub fn admit(
        self: &Arc<Self>,
        admission: &PrivateEgressStreamAdmission,
        connection_id: ConnectionId,
        stream: Arc<dyn MediaStream>,
    ) -> Result<PrivateEgressWorkerConnection, PrivateEgressStreamError> {
        admission.validate(unix_time_ms())?;
        let mut entry = self
            .entries
            .get_mut(&admission.admission_id)
            .ok_or(PrivateEgressStreamError::OwnershipMismatch)?;
        if entry.admission != *admission {
            return Err(PrivateEgressStreamError::OwnershipMismatch);
        }
        if entry.bound {
            return Err(PrivateEgressStreamError::AlreadyUsed);
        }
        let sender = entry
            .sender
            .take()
            .ok_or(PrivateEgressStreamError::AlreadyUsed)?;
        entry.bound = true;
        drop(entry);
        let connection = PrivateEgressWorkerConnection {
            inner: Arc::new(PrivateEgressWorkerConnectionInner {
                admission: admission.clone(),
                connection_id,
                stream,
                registry: Arc::downgrade(self),
            }),
        };
        sender
            .send(connection.clone())
            .map_err(|_| PrivateEgressStreamError::ConnectionUnavailable)?;
        Ok(connection)
    }

    pub fn release(&self, admission_id: Uuid) {
        self.entries.remove(&admission_id);
    }

    pub fn begin_drain(&self) {
        self.draining.store(true, Ordering::Release);
    }

    pub fn release_all(&self) {
        self.entries.clear();
    }

    fn sweep_expired(&self, now_ms: i64) {
        let expired = self
            .entries
            .iter()
            .filter(|entry| entry.admission.expires_at_ms < now_ms && !entry.bound)
            .map(|entry| *entry.key())
            .collect::<Vec<_>>();
        for admission_id in expired {
            self.entries.remove(&admission_id);
        }
    }
}

pub struct PrivateEgressStreamReservation {
    registry: Weak<PrivateEgressStreamAdmissionRegistry>,
    admission: PrivateEgressStreamAdmission,
    receiver: Option<oneshot::Receiver<PrivateEgressWorkerConnection>>,
}

impl fmt::Debug for PrivateEgressStreamReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateEgressStreamReservation")
            .field("admission_id", &self.admission.admission_id)
            .field("target", &self.admission.target)
            .finish_non_exhaustive()
    }
}

impl PrivateEgressStreamReservation {
    pub fn admission(&self) -> &PrivateEgressStreamAdmission {
        &self.admission
    }

    pub async fn wait(
        mut self,
        timeout: Duration,
    ) -> Result<PrivateEgressWorkerConnection, PrivateEgressStreamError> {
        if timeout.is_zero() {
            return Err(PrivateEgressStreamError::InvalidAdmission);
        }
        let receiver = self
            .receiver
            .take()
            .ok_or(PrivateEgressStreamError::AlreadyUsed)?;
        let mut release = ReservationReleaseGuard {
            registry: self.registry.clone(),
            admission_id: self.admission.admission_id,
            armed: true,
        };
        match tokio::time::timeout(timeout, receiver).await {
            Ok(Ok(connection)) => {
                release.armed = false;
                Ok(connection)
            }
            Ok(Err(_)) => Err(PrivateEgressStreamError::ConnectionUnavailable),
            Err(_) => Err(PrivateEgressStreamError::Timeout),
        }
    }

    pub fn cancel(mut self) {
        self.receiver.take();
        if let Some(registry) = self.registry.upgrade() {
            registry.release(self.admission.admission_id);
        }
    }
}

impl Drop for PrivateEgressStreamReservation {
    fn drop(&mut self) {
        if self.receiver.is_some() {
            if let Some(registry) = self.registry.upgrade() {
                registry.release(self.admission.admission_id);
            }
        }
    }
}

struct ReservationReleaseGuard {
    registry: Weak<PrivateEgressStreamAdmissionRegistry>,
    admission_id: Uuid,
    armed: bool,
}

impl Drop for ReservationReleaseGuard {
    fn drop(&mut self) {
        if self.armed {
            if let Some(registry) = self.registry.upgrade() {
                registry.release(self.admission_id);
            }
        }
    }
}

#[derive(Clone)]
pub struct PrivateEgressWorkerConnection {
    inner: Arc<PrivateEgressWorkerConnectionInner>,
}

struct PrivateEgressWorkerConnectionInner {
    admission: PrivateEgressStreamAdmission,
    connection_id: ConnectionId,
    stream: Arc<dyn MediaStream>,
    registry: Weak<PrivateEgressStreamAdmissionRegistry>,
}

impl fmt::Debug for PrivateEgressWorkerConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateEgressWorkerConnection")
            .field("admission_id", &self.inner.admission.admission_id)
            .field("connection_id", &self.inner.connection_id)
            .field("target", &self.inner.admission.target)
            .finish_non_exhaustive()
    }
}

impl PrivateEgressWorkerConnection {
    pub fn admission(&self) -> &PrivateEgressStreamAdmission {
        &self.inner.admission
    }

    pub fn connection_id(&self) -> &ConnectionId {
        &self.inner.connection_id
    }

    pub fn stream(&self) -> Arc<dyn MediaStream> {
        Arc::clone(&self.inner.stream)
    }
}

impl Drop for PrivateEgressWorkerConnectionInner {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.upgrade() {
            registry.release(self.admission.admission_id);
        }
    }
}

/// Resolved non-secret adapter options for a named egress profile. Secret
/// references are resolved by the implementation and remain inside the
/// adapter-owned [`OriginateContext`].
#[derive(Clone, Default)]
pub struct PrivateEgressResolvedOriginate {
    pub capabilities: CapabilityDescriptor,
    pub context: OriginateContext,
}

impl fmt::Debug for PrivateEgressResolvedOriginate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateEgressResolvedOriginate")
            .field("capabilities", &self.capabilities)
            .field("context", &self.context)
            .finish()
    }
}

/// Gateway-local resolver for exact profile revisions. Implementations must
/// fail closed when the requested revision is absent; the handler never falls
/// back to a default credential or arbitrary destination policy.
#[async_trait]
pub trait PrivateEgressGatewayProfileResolver: Send + Sync {
    async fn resolve(
        &self,
        tenant_id: &crate::call_engine::TenantId,
        transport: PrivateEgressTransport,
        profile: &PrivateEgressProfile,
        codec: &CodecInfo,
        target: &str,
        initial_context: &[(String, String)],
    ) -> Result<PrivateEgressResolvedOriginate, PrivateEgressError>;
}

/// Authoritative gateway-local delivery of native adapter events. The native
/// SIP/WebRTC Orchestrator remains the sole consumer of adapter events; this
/// router gives the egress proxy one bounded per-Connection branch without
/// subscribing to a lossy compatibility broadcast.
pub trait PrivateEgressGatewayLifecycleSource: Send + Sync {
    fn subscribe(
        &self,
        connection_id: ConnectionId,
    ) -> Result<mpsc::Receiver<OperationalEvent>, PrivateEgressError>;

    fn unsubscribe(&self, connection_id: &ConnectionId);
}

/// The only native adapters available to the gateway proxy. Registering these
/// seams does not advertise a worker capability; process capability reporting
/// remains fail-closed until the complete split runtime is installed.
pub struct PrivateEgressGatewayAdapters {
    sip: Option<Arc<dyn ConnectionAdapter>>,
    webrtc: Option<Arc<dyn ConnectionAdapter>>,
}

impl fmt::Debug for PrivateEgressGatewayAdapters {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateEgressGatewayAdapters")
            .field("sip", &self.sip.is_some())
            .field("webrtc", &self.webrtc.is_some())
            .finish()
    }
}

impl PrivateEgressGatewayAdapters {
    pub fn new(
        sip: Option<Arc<dyn ConnectionAdapter>>,
        webrtc: Option<Arc<dyn ConnectionAdapter>>,
    ) -> Result<Arc<Self>, PrivateEgressError> {
        if sip.as_ref().is_some_and(|adapter| {
            adapter.transport() != Transport::Sip
                || !adapter.lifecycle_capabilities().staged_outbound_activation
        }) || webrtc.as_ref().is_some_and(|adapter| {
            adapter.transport() != Transport::WebRtc
                || !adapter.lifecycle_capabilities().staged_outbound_activation
        }) {
            return Err(PrivateEgressError::HandlerRejected);
        }
        Ok(Arc::new(Self { sip, webrtc }))
    }

    fn adapter(
        &self,
        transport: PrivateEgressTransport,
    ) -> Result<Arc<dyn ConnectionAdapter>, PrivateEgressError> {
        match transport {
            PrivateEgressTransport::Sip => self.sip.clone(),
            PrivateEgressTransport::WebRtc => self.webrtc.clone(),
        }
        .ok_or(PrivateEgressError::HandlerRejected)
    }
}

#[derive(Clone, Debug)]
pub struct PrivateEgressGatewayProxyConfig {
    pub media_setup_timeout: Duration,
    pub operation_timeout: Duration,
}

impl Default for PrivateEgressGatewayProxyConfig {
    fn default() -> Self {
        Self {
            media_setup_timeout: Duration::from_secs(5),
            operation_timeout: Duration::from_secs(5),
        }
    }
}

impl PrivateEgressGatewayProxyConfig {
    fn validate(&self) -> Result<(), PrivateEgressError> {
        if self.media_setup_timeout.is_zero()
            || self.operation_timeout.is_zero()
            || self.media_setup_timeout > Duration::from_secs(30)
            || self.operation_timeout > Duration::from_secs(30)
        {
            return Err(PrivateEgressError::HandlerRejected);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ProxyRouteKey {
    worker: WorkerLease,
    source: PrivateEgressSource,
    target: PrivateEgressTarget,
}

impl ProxyRouteKey {
    fn new(authority: &PrivateEgressRouteAuthority, target: PrivateEgressTarget) -> Self {
        Self {
            worker: authority.worker,
            source: authority.source.clone(),
            target,
        }
    }
}

struct PreparedProxyRoute {
    adapter: Arc<dyn ConnectionAdapter>,
    native_connection_id: ConnectionId,
    native_conversation_id: ConversationId,
    prepared: Option<PreparedOutboundConnection>,
    codec: CodecInfo,
    private_route: Arc<GatewayForwardingRoute>,
    activated: bool,
    cancel: CancellationToken,
    pump: Option<JoinHandle<()>>,
    native_events: Option<mpsc::Receiver<OperationalEvent>>,
}

/// Gateway implementation of the private command handler. Prepare allocates a
/// dormant native SIP/WebRTC route plus a distinct generation-bound private
/// UCTP route. Activate publishes native signaling and starts bounded
/// full-duplex media/control pumps. Abort/End own both halves' cleanup.
pub struct PrivateEgressGatewayProxyHandler {
    forwarder: Arc<GatewayForwarder>,
    orchestrator: Arc<Orchestrator>,
    adapters: Arc<PrivateEgressGatewayAdapters>,
    profiles: Arc<dyn PrivateEgressGatewayProfileResolver>,
    lifecycle: Option<Arc<dyn PrivateEgressGatewayLifecycleSource>>,
    config: PrivateEgressGatewayProxyConfig,
    routes: DashMap<ProxyRouteKey, Arc<tokio::sync::Mutex<Option<PreparedProxyRoute>>>>,
    draining: AtomicBool,
}

impl fmt::Debug for PrivateEgressGatewayProxyHandler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateEgressGatewayProxyHandler")
            .field("active_routes", &self.routes.len())
            .finish_non_exhaustive()
    }
}

impl PrivateEgressGatewayProxyHandler {
    fn log_prepare_failure(
        authority: &PrivateEgressRouteAuthority,
        command: &PrivateEgressCommand,
        phase: &'static str,
        error: PrivateEgressError,
    ) {
        tracing::warn!(
            call_id = %authority.source.call_id,
            source_leg_id = %authority.source.leg_id,
            source_generation = authority.source.binding_generation.value(),
            destination_leg_id = %command.target.leg_id,
            destination_generation = command.target.binding_generation.value(),
            phase,
            error_code = error.code(),
            "gateway private egress prepare failed"
        );
    }

    pub fn new(
        forwarder: Arc<GatewayForwarder>,
        orchestrator: Arc<Orchestrator>,
        adapters: Arc<PrivateEgressGatewayAdapters>,
        profiles: Arc<dyn PrivateEgressGatewayProfileResolver>,
        config: PrivateEgressGatewayProxyConfig,
    ) -> Result<Arc<Self>, PrivateEgressError> {
        Self::new_inner(forwarder, orchestrator, adapters, profiles, None, config)
    }

    pub fn new_with_lifecycle(
        forwarder: Arc<GatewayForwarder>,
        orchestrator: Arc<Orchestrator>,
        adapters: Arc<PrivateEgressGatewayAdapters>,
        profiles: Arc<dyn PrivateEgressGatewayProfileResolver>,
        lifecycle: Arc<dyn PrivateEgressGatewayLifecycleSource>,
        config: PrivateEgressGatewayProxyConfig,
    ) -> Result<Arc<Self>, PrivateEgressError> {
        Self::new_inner(
            forwarder,
            orchestrator,
            adapters,
            profiles,
            Some(lifecycle),
            config,
        )
    }

    fn new_inner(
        forwarder: Arc<GatewayForwarder>,
        orchestrator: Arc<Orchestrator>,
        adapters: Arc<PrivateEgressGatewayAdapters>,
        profiles: Arc<dyn PrivateEgressGatewayProfileResolver>,
        lifecycle: Option<Arc<dyn PrivateEgressGatewayLifecycleSource>>,
        config: PrivateEgressGatewayProxyConfig,
    ) -> Result<Arc<Self>, PrivateEgressError> {
        config.validate()?;
        Ok(Arc::new(Self {
            forwarder,
            orchestrator,
            adapters,
            profiles,
            lifecycle,
            config,
            routes: DashMap::new(),
            draining: AtomicBool::new(false),
        }))
    }

    #[must_use]
    pub fn has_authoritative_lifecycle(&self) -> bool {
        self.lifecycle.is_some()
    }

    pub fn active_routes(&self) -> usize {
        self.routes.len()
    }

    /// Await process-local adapter and pump teardown while the native gateway
    /// transports are still alive. Registrations are removed before waiting,
    /// so a forced timeout cannot leave a route eligible for reuse.
    pub async fn drain(&self, timeout: Duration) -> Result<(), PrivateEgressError> {
        self.draining.store(true, Ordering::Release);
        let deadline = tokio::time::Instant::now() + timeout;
        let entries = self
            .routes
            .iter()
            .map(|entry| (entry.key().clone(), Arc::clone(entry.value())))
            .collect::<Vec<_>>();
        let mut timed_out = false;

        for (key, cell) in entries {
            self.routes
                .remove_if(&key, |_, candidate| Arc::ptr_eq(candidate, &cell));
            let mut route_guard = match tokio::time::timeout_at(deadline, cell.lock()).await {
                Ok(route_guard) => route_guard,
                Err(_) => {
                    timed_out = true;
                    continue;
                }
            };
            let Some(mut route) = route_guard.take() else {
                continue;
            };
            drop(route_guard);

            route.cancel.cancel();
            if let Some(lifecycle) = &self.lifecycle {
                lifecycle.unsubscribe(&route.native_connection_id);
            }
            if let Some(pump) = route.pump.take() {
                // Drain owns every remaining transport cleanup step. Do not
                // spend the shared shutdown budget waiting for a cooperative
                // pump exit while that task may be inside adapter I/O.
                pump.abort();
                let _ = pump.await;
            }
            if tokio::time::timeout_at(deadline, route.private_route.close())
                .await
                .is_err()
            {
                timed_out = true;
                route.private_route.force_close();
            }

            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let termination_timed_out = if let Some(prepared) = route.prepared.take() {
                tokio::time::timeout(remaining, prepared.abort())
                    .await
                    .is_err()
            } else if route.activated {
                tokio::time::timeout(
                    remaining,
                    self.orchestrator
                        .end_connection(route.native_connection_id.clone(), EndReason::Cancelled),
                )
                .await
                .is_err()
            } else {
                false
            };
            if termination_timed_out {
                timed_out = true;
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if tokio::time::timeout(
                remaining,
                self.orchestrator
                    .close_conversation(route.native_conversation_id.clone(), true),
            )
            .await
            .is_err()
            {
                timed_out = true;
            }
        }

        if timed_out || tokio::time::Instant::now() > deadline {
            Err(PrivateEgressError::Timeout)
        } else {
            Ok(())
        }
    }

    async fn close_native_scope(&self, conversation_id: &ConversationId) {
        let _ = tokio::time::timeout(
            self.config.operation_timeout,
            self.orchestrator
                .close_conversation(conversation_id.clone(), true),
        )
        .await;
    }

    async fn abandon_prepared(
        &self,
        prepared: PreparedOutboundConnection,
        conversation_id: &ConversationId,
    ) {
        let _ = tokio::time::timeout(self.config.operation_timeout, prepared.abort()).await;
        self.close_native_scope(conversation_id).await;
    }

    // These values are the independently authenticated pieces of a private
    // route command; retaining them as parameters keeps validation explicit.
    #[allow(clippy::too_many_arguments)]
    async fn prepare(
        &self,
        authority: &PrivateEgressRouteAuthority,
        command: &PrivateEgressCommand,
        transport: PrivateEgressTransport,
        profile: &PrivateEgressProfile,
        codec: &CodecInfo,
        target: &str,
        initial_context: &[(String, String)],
    ) -> Result<PrivateEgressHandlerResult, PrivateEgressError> {
        if self.draining.load(Ordering::Acquire) {
            return Err(PrivateEgressError::Draining);
        }
        let key = ProxyRouteKey::new(authority, command.target);
        if self.routes.contains_key(&key) {
            Self::log_prepare_failure(
                authority,
                command,
                "route_already_present",
                PrivateEgressError::InvalidTransition,
            );
            return Err(PrivateEgressError::InvalidTransition);
        }
        let adapter = self.adapters.adapter(transport).inspect_err(|&error| {
            Self::log_prepare_failure(authority, command, "adapter_lookup", error);
        })?;
        let resolved = self
            .profiles
            .resolve(
                &authority.source.tenant_id,
                transport,
                profile,
                codec,
                target,
                initial_context,
            )
            .await
            .inspect_err(|&error| {
                Self::log_prepare_failure(authority, command, "profile_resolution", error);
            })?;
        if !resolved
            .capabilities
            .audio_codecs
            .iter()
            .any(|candidate| candidate == codec)
        {
            Self::log_prepare_failure(
                authority,
                command,
                "profile_codec",
                PrivateEgressError::HandlerRejected,
            );
            return Err(PrivateEgressError::HandlerRejected);
        }
        let transport_kind = match transport {
            PrivateEgressTransport::Sip => Transport::Sip,
            PrivateEgressTransport::WebRtc => Transport::WebRtc,
        };
        let owned_adapter = self.orchestrator.adapter(transport_kind).map_err(|_| {
            Self::log_prepare_failure(
                authority,
                command,
                "orchestrator_adapter_lookup",
                PrivateEgressError::HandlerRejected,
            );
            PrivateEgressError::HandlerRejected
        })?;
        if !Arc::ptr_eq(&adapter, &owned_adapter) {
            Self::log_prepare_failure(
                authority,
                command,
                "adapter_ownership",
                PrivateEgressError::OwnershipMismatch,
            );
            return Err(PrivateEgressError::OwnershipMismatch);
        }
        let native_conversation_id = self
            .orchestrator
            .open_conversation(
                RvoipTenantId::from_string(authority.source.tenant_id.as_str()),
                ConversationPolicy::default(),
                std::collections::HashMap::new(),
            )
            .await
            .map_err(|_| {
                Self::log_prepare_failure(
                    authority,
                    command,
                    "conversation_open",
                    PrivateEgressError::HandlerRejected,
                );
                PrivateEgressError::HandlerRejected
            })?;
        let native_session_id = match self
            .orchestrator
            .start_session(
                native_conversation_id.clone(),
                SessionMedium::Voice,
                Vec::new(),
            )
            .await
        {
            Ok(session_id) => session_id,
            Err(_) => {
                Self::log_prepare_failure(
                    authority,
                    command,
                    "session_start",
                    PrivateEgressError::HandlerRejected,
                );
                self.close_native_scope(&native_conversation_id).await;
                return Err(PrivateEgressError::HandlerRejected);
            }
        };
        let request = OriginateRequest::new(
            native_session_id,
            ParticipantId::new(),
            target,
            Direction::Outbound,
            resolved.capabilities,
        )
        .with_transport(transport_kind)
        .with_originate_context(resolved.context);
        let prepared = match tokio::time::timeout(
            self.config.operation_timeout,
            self.orchestrator.prepare_outbound_connection(request),
        )
        .await
        {
            Ok(Ok(prepared)) => prepared,
            Ok(Err(_)) => {
                Self::log_prepare_failure(
                    authority,
                    command,
                    "outbound_prepare",
                    PrivateEgressError::HandlerRejected,
                );
                self.close_native_scope(&native_conversation_id).await;
                return Err(PrivateEgressError::HandlerRejected);
            }
            Err(_) => {
                Self::log_prepare_failure(
                    authority,
                    command,
                    "outbound_prepare",
                    PrivateEgressError::Timeout,
                );
                self.close_native_scope(&native_conversation_id).await;
                return Err(PrivateEgressError::Timeout);
            }
        };
        if prepared.transport() != transport_kind {
            Self::log_prepare_failure(
                authority,
                command,
                "outbound_transport",
                PrivateEgressError::HandlerRejected,
            );
            self.abandon_prepared(prepared, &native_conversation_id)
                .await;
            return Err(PrivateEgressError::HandlerRejected);
        }
        let native_connection_id = prepared.connection_id().clone();
        let native_events = match self.lifecycle.as_ref() {
            Some(lifecycle) => match lifecycle.subscribe(native_connection_id.clone()) {
                Ok(events) => Some(events),
                Err(_) => {
                    Self::log_prepare_failure(
                        authority,
                        command,
                        "lifecycle_subscribe",
                        PrivateEgressError::HandlerRejected,
                    );
                    self.abandon_prepared(prepared, &native_conversation_id)
                        .await;
                    return Err(PrivateEgressError::HandlerRejected);
                }
            },
            None => None,
        };
        let stream_admission =
            PrivateEgressStreamAdmission::from_prepare(command).map_err(|_| {
                Self::log_prepare_failure(
                    authority,
                    command,
                    "stream_admission",
                    PrivateEgressError::HandlerRejected,
                );
                PrivateEgressError::HandlerRejected
            })?;
        let private_route = match tokio::time::timeout(
            self.config.operation_timeout,
            self.forwarder
                .open_private_egress_stream_route(stream_admission),
        )
        .await
        {
            Ok(Ok(route)) => Arc::new(route),
            Ok(Err(_)) => {
                Self::log_prepare_failure(
                    authority,
                    command,
                    "private_route_open",
                    PrivateEgressError::HandlerRejected,
                );
                if let Some(lifecycle) = &self.lifecycle {
                    lifecycle.unsubscribe(&native_connection_id);
                }
                self.abandon_prepared(prepared, &native_conversation_id)
                    .await;
                return Err(PrivateEgressError::HandlerRejected);
            }
            Err(_) => {
                Self::log_prepare_failure(
                    authority,
                    command,
                    "private_route_open",
                    PrivateEgressError::Timeout,
                );
                if let Some(lifecycle) = &self.lifecycle {
                    lifecycle.unsubscribe(&native_connection_id);
                }
                self.abandon_prepared(prepared, &native_conversation_id)
                    .await;
                return Err(PrivateEgressError::Timeout);
            }
        };
        let cell = Arc::new(tokio::sync::Mutex::new(Some(PreparedProxyRoute {
            adapter,
            native_connection_id,
            native_conversation_id,
            prepared: Some(prepared),
            codec: codec.clone(),
            private_route,
            activated: false,
            cancel: CancellationToken::new(),
            pump: None,
            native_events,
        })));
        let occupied = match self.routes.entry(key) {
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert(Arc::clone(&cell));
                false
            }
            dashmap::mapref::entry::Entry::Occupied(_) => true,
        };
        if occupied {
            Self::log_prepare_failure(
                authority,
                command,
                "route_publish_race",
                PrivateEgressError::InvalidTransition,
            );
            let mut route = cell.lock().await;
            let mut route = route.take().ok_or(PrivateEgressError::InvalidTransition)?;
            if let Some(lifecycle) = &self.lifecycle {
                lifecycle.unsubscribe(&route.native_connection_id);
            }
            route.private_route.close().await;
            if let Some(prepared) = route.prepared.take() {
                self.abandon_prepared(prepared, &route.native_conversation_id)
                    .await;
            } else {
                self.close_native_scope(&route.native_conversation_id).await;
            }
            return Err(PrivateEgressError::InvalidTransition);
        }
        Ok(PrivateEgressHandlerResult::default())
    }

    async fn activate(
        &self,
        authority: &PrivateEgressRouteAuthority,
        command: &PrivateEgressCommand,
    ) -> Result<PrivateEgressHandlerResult, PrivateEgressError> {
        let key = ProxyRouteKey::new(authority, command.target);
        let cell = self
            .routes
            .get(&key)
            .map(|entry| Arc::clone(entry.value()))
            .ok_or(PrivateEgressError::InvalidTransition)?;
        let mut route = cell.lock().await;
        let active = route
            .as_mut()
            .ok_or(PrivateEgressError::InvalidTransition)?;
        if active.activated {
            return Err(PrivateEgressError::InvalidTransition);
        }
        let activation = async {
            let native_transport = active.adapter.transport();
            let activation_phase = Arc::new(AtomicU8::new(ACTIVATION_PENDING));
            let mut pump_failure = None;
            if native_transport == Transport::Sip {
                // A staged SIP adapter owns a dormant MediaStream as soon as
                // prepare succeeds. Attach the private route and lifecycle
                // branch before publishing the INVITE: `commit()` may wait
                // through provisional responses until final answer, while 183
                // media and its Progress event must already reach the worker.
                // If the exact prepared stream is unavailable, fail before any
                // peer-visible signaling rather than claim early-media support.
                let stream = wait_for_native_audio_stream(
                    &active.adapter,
                    &active.native_connection_id,
                    self.config.media_setup_timeout,
                )
                .await?;
                if stream.codec() != active.codec {
                    return Err(PrivateEgressError::HandlerRejected);
                }
                let (pump, failure) = spawn_proxy_pump(
                    Arc::clone(&self.orchestrator),
                    active.native_connection_id.clone(),
                    native_transport,
                    stream,
                    Arc::clone(&active.private_route),
                    active.cancel.clone(),
                    self.config.operation_timeout,
                    active.native_events.take(),
                    self.lifecycle.clone(),
                    Arc::clone(&self.forwarder),
                    authority.clone(),
                    command.target,
                    Arc::clone(&activation_phase),
                )?;
                active.pump = Some(pump);
                pump_failure = Some(failure);
            }
            let prepared = active
                .prepared
                .take()
                .ok_or(PrivateEgressError::InvalidTransition)?;
            let commit = async {
                tokio::time::timeout(self.config.operation_timeout, prepared.commit())
                    .await
                    .map_err(|_| PrivateEgressError::Timeout)?
                    .map_err(|_| PrivateEgressError::HandlerRejected)
            };
            tokio::pin!(commit);
            let committed = match pump_failure.as_mut() {
                Some(failure) => {
                    tokio::select! {
                        result = &mut commit => result,
                        failure = failure => Err(failure.unwrap_or(PrivateEgressError::HandlerRejected)),
                    }
                }
                None => commit.await,
            };
            let handle = match committed {
                Ok(handle) => handle,
                Err(error) => {
                    activation_phase.store(ACTIVATION_FAILED, Ordering::Release);
                    return Err(error);
                }
            };
            if activation_phase
                .compare_exchange(
                    ACTIVATION_PENDING,
                    ACTIVATION_COMMITTED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                return Err(PrivateEgressError::HandlerRejected);
            }
            if handle.connection.id != active.native_connection_id
                || handle.connection.transport != active.adapter.transport()
                || handle.connection.direction != Direction::Outbound
            {
                return Err(PrivateEgressError::OwnershipMismatch);
            }
            if native_transport == Transport::WebRtc {
                // Interactive WebRTC has no SIP provisional-media contract.
                // Preserve its established behavior: wait for final commit,
                // then require the negotiated stream and start forwarding.
                let stream = wait_for_native_audio_stream(
                    &active.adapter,
                    &active.native_connection_id,
                    self.config.media_setup_timeout,
                )
                .await?;
                if stream.codec() != active.codec {
                    return Err(PrivateEgressError::HandlerRejected);
                }
                let (pump, _failure) = spawn_proxy_pump(
                    Arc::clone(&self.orchestrator),
                    active.native_connection_id.clone(),
                    native_transport,
                    stream,
                    Arc::clone(&active.private_route),
                    active.cancel.clone(),
                    self.config.operation_timeout,
                    active.native_events.take(),
                    self.lifecycle.clone(),
                    Arc::clone(&self.forwarder),
                    authority.clone(),
                    command.target,
                    Arc::clone(&activation_phase),
                )?;
                active.pump = Some(pump);
            }
            active.activated = true;
            Ok::<(), PrivateEgressError>(())
        }
        .await;
        if let Err(error) = activation {
            let mut failed = route.take().ok_or(PrivateEgressError::InvalidTransition)?;
            drop(route);
            failed.cancel.cancel();
            if let Some(lifecycle) = &self.lifecycle {
                lifecycle.unsubscribe(&failed.native_connection_id);
            }
            if let Some(pump) = failed.pump.take() {
                // Activation rollback is the sole owner of both transport
                // halves below, so an in-flight pump must not consume the
                // entire operation timeout before cleanup can begin.
                pump.abort();
                let _ = pump.await;
            }
            failed.private_route.close().await;
            if self
                .orchestrator
                .connection_transport(&failed.native_connection_id)
                .is_ok()
            {
                let _ = tokio::time::timeout(
                    self.config.operation_timeout,
                    self.orchestrator.end_connection(
                        failed.native_connection_id.clone(),
                        EndReason::Failed {
                            detail: "private egress activation failed".into(),
                        },
                    ),
                )
                .await;
            }
            if let Some(prepared) = failed.prepared.take() {
                let _ = tokio::time::timeout(self.config.operation_timeout, prepared.abort()).await;
            }
            self.close_native_scope(&failed.native_conversation_id)
                .await;
            drop(failed);
            self.routes
                .remove_if(&key, |_, candidate| Arc::ptr_eq(candidate, &cell));
            return Err(error);
        }
        let active = route
            .as_ref()
            .ok_or(PrivateEgressError::InvalidTransition)?;
        Ok(PrivateEgressHandlerResult {
            external_reference: Some(active.native_connection_id.to_string()),
        })
    }

    async fn control(
        &self,
        authority: &PrivateEgressRouteAuthority,
        command: &PrivateEgressCommand,
    ) -> Result<PrivateEgressHandlerResult, PrivateEgressError> {
        let key = ProxyRouteKey::new(authority, command.target);
        let cell = self
            .routes
            .get(&key)
            .map(|entry| Arc::clone(entry.value()))
            .ok_or(PrivateEgressError::InvalidTransition)?;
        let route = cell.lock().await;
        let route = route
            .as_ref()
            .filter(|route| route.activated)
            .ok_or(PrivateEgressError::InvalidTransition)?;
        let operation = match &command.operation {
            PrivateEgressOperation::Dtmf {
                digits,
                duration_ms,
            } => {
                tokio::time::timeout(
                    self.config.operation_timeout,
                    self.orchestrator.send_dtmf(
                        route.native_connection_id.clone(),
                        digits,
                        *duration_ms,
                    ),
                )
                .await
            }
            PrivateEgressOperation::DataMessage { message } => {
                tokio::time::timeout(
                    self.config.operation_timeout,
                    self.orchestrator.send_data_message_to_connection(
                        route.native_connection_id.clone(),
                        message.clone(),
                    ),
                )
                .await
            }
            _ => return Err(PrivateEgressError::InvalidTransition),
        };
        operation
            .map_err(|_| PrivateEgressError::Timeout)?
            .map_err(|_| PrivateEgressError::HandlerRejected)?;
        Ok(PrivateEgressHandlerResult::default())
    }

    async fn finish(
        &self,
        authority: &PrivateEgressRouteAuthority,
        command: &PrivateEgressCommand,
    ) -> Result<PrivateEgressHandlerResult, PrivateEgressError> {
        let reason = match &command.operation {
            PrivateEgressOperation::Abort => EndReason::Cancelled,
            PrivateEgressOperation::End { reason } => match reason {
                PrivateEgressEndReason::Normal => EndReason::Normal,
                PrivateEgressEndReason::Cancelled | PrivateEgressEndReason::WorkerDrain => {
                    EndReason::Cancelled
                }
                PrivateEgressEndReason::Timeout => EndReason::Timeout,
                PrivateEgressEndReason::Rejected | PrivateEgressEndReason::Failed => {
                    EndReason::Failed {
                        detail: "private egress ended".into(),
                    }
                }
            },
            _ => return Err(PrivateEgressError::InvalidTransition),
        };
        let key = ProxyRouteKey::new(authority, command.target);
        tracing::debug!(
            call_id = %authority.source.call_id,
            source_leg_id = %authority.source.leg_id,
            source_generation = authority.source.binding_generation.value(),
            destination_leg_id = %command.target.leg_id,
            destination_generation = command.target.binding_generation.value(),
            operation = ?command.operation,
            "starting gateway private egress route finish"
        );
        let Some(cell) = self.routes.get(&key).map(|entry| Arc::clone(entry.value())) else {
            // The activation path owns native-route rollback. If that rollback
            // completed before the authoritative command service reconciles
            // its Prepared record, the exact generation-bound Abort/End must
            // still be able to advance the service record to Ended and release
            // its capacity permit. Treat an already-absent proxy route as
            // successful cleanup; the command service has already fenced the
            // worker, source, target, transition, and replay authority.
            return Ok(PrivateEgressHandlerResult::default());
        };
        let mut route_guard = cell.lock().await;
        let Some(mut route) = route_guard.take() else {
            drop(route_guard);
            self.routes
                .remove_if(&key, |_, candidate| Arc::ptr_eq(candidate, &cell));
            return Ok(PrivateEgressHandlerResult::default());
        };
        drop(route_guard);
        route.cancel.cancel();
        if let Some(lifecycle) = &self.lifecycle {
            lifecycle.unsubscribe(&route.native_connection_id);
        }
        if let Some(pump) = route.pump.take() {
            // This handler owns the pump and performs the authoritative
            // private-route and native-adapter teardown below. Cooperative
            // cancellation alone is insufficient here because the pump may
            // already be inside a bounded adapter/control await; waiting that
            // full timeout serializes StopLeg and prevents the replacement
            // media graph from being restored. Abort-and-join releases every
            // borrowed receiver before either transport is closed.
            pump.abort();
            let _ = pump.await;
        }
        tracing::debug!(
            call_id = %authority.source.call_id,
            source_generation = authority.source.binding_generation.value(),
            destination_generation = command.target.binding_generation.value(),
            "gateway private egress media pump stopped"
        );
        route.private_route.close().await;
        tracing::debug!(
            call_id = %authority.source.call_id,
            source_generation = authority.source.binding_generation.value(),
            destination_generation = command.target.binding_generation.value(),
            "gateway private egress private route closed"
        );
        let termination = if let Some(prepared) = route.prepared.take() {
            match tokio::time::timeout(self.config.operation_timeout, prepared.abort()).await {
                Ok(result) => result.map_err(|_| PrivateEgressError::HandlerRejected),
                Err(_) => Err(PrivateEgressError::Timeout),
            }
        } else if route.activated {
            match tokio::time::timeout(
                self.config.operation_timeout,
                self.orchestrator
                    .end_connection(route.native_connection_id.clone(), reason),
            )
            .await
            {
                Ok(result) => result.map_err(|_| PrivateEgressError::HandlerRejected),
                Err(_) => Err(PrivateEgressError::Timeout),
            }
        } else {
            Ok(())
        };
        tracing::debug!(
            call_id = %authority.source.call_id,
            source_generation = authority.source.binding_generation.value(),
            destination_generation = command.target.binding_generation.value(),
            native_termination_succeeded = termination.is_ok(),
            "gateway private egress native route termination finished"
        );
        self.close_native_scope(&route.native_conversation_id).await;
        drop(route);
        self.routes
            .remove_if(&key, |_, candidate| Arc::ptr_eq(candidate, &cell));
        termination?;
        Ok(PrivateEgressHandlerResult::default())
    }

    async fn retire_terminal(
        &self,
        authority: &PrivateEgressRouteAuthority,
        event: &PrivateEgressLifecycleEvent,
    ) {
        if !matches!(
            event.state(),
            Some(PrivateEgressLifecycleState::Ended | PrivateEgressLifecycleState::Failed)
        ) {
            return;
        }
        let key = ProxyRouteKey::new(authority, event.target);
        let Some(cell) = self.routes.get(&key).map(|entry| Arc::clone(entry.value())) else {
            return;
        };
        let mut route_guard = cell.lock().await;
        let Some(mut route) = route_guard.take() else {
            return;
        };
        drop(route_guard);
        route.cancel.cancel();
        if let Some(lifecycle) = &self.lifecycle {
            lifecycle.unsubscribe(&route.native_connection_id);
        }
        if let Some(pump) = route.pump.take() {
            // Terminal observations reach this callback only after the
            // worker's exact lifecycle ACK is durable, from the gateway peer
            // ACK task rather than from this pump. Abort-and-join therefore
            // cannot self-await and guarantees the borrowed media/event
            // receivers are released before the private route is closed.
            pump.abort();
            let _ = pump.await;
        }
        route.private_route.close().await;
        self.close_native_scope(&route.native_conversation_id).await;
        drop(route);
        self.routes
            .remove_if(&key, |_, candidate| Arc::ptr_eq(candidate, &cell));
    }
}

#[async_trait]
impl PrivateEgressHandler for PrivateEgressGatewayProxyHandler {
    async fn execute(
        &self,
        authority: &PrivateEgressRouteAuthority,
        command: &PrivateEgressCommand,
    ) -> Result<PrivateEgressHandlerResult, PrivateEgressError> {
        match &command.operation {
            PrivateEgressOperation::Prepare {
                transport,
                profile,
                codec,
                target,
                initial_context,
            } => {
                self.prepare(
                    authority,
                    command,
                    *transport,
                    profile,
                    codec,
                    target,
                    initial_context,
                )
                .await
            }
            PrivateEgressOperation::Activate => self.activate(authority, command).await,
            PrivateEgressOperation::Dtmf { .. } | PrivateEgressOperation::DataMessage { .. } => {
                self.control(authority, command).await
            }
            PrivateEgressOperation::Abort | PrivateEgressOperation::End { .. } => {
                self.finish(authority, command).await
            }
        }
    }

    async fn recover_dead_epoch_route(
        &self,
        authority: &PrivateEgressRouteAuthority,
        target: PrivateEgressTarget,
        _dead_epoch: Uuid,
    ) -> Result<(), PrivateEgressError> {
        let key = ProxyRouteKey::new(authority, target);
        if self.routes.contains_key(&key) {
            Err(PrivateEgressError::DeadEpochRecoveryFailed)
        } else {
            // This handler is newly constructed for the current process. An
            // absent exact route proves there is no reachable local adapter,
            // pump, or media-forwarding handle to clean up. OS teardown owns
            // resources from the dead process incarnation.
            Ok(())
        }
    }

    async fn observe_lifecycle(
        &self,
        authority: &PrivateEgressRouteAuthority,
        event: &PrivateEgressLifecycleEvent,
    ) {
        self.retire_terminal(authority, event).await;
    }

    async fn drain(&self, timeout: Duration) -> Result<(), PrivateEgressError> {
        PrivateEgressGatewayProxyHandler::drain(self, timeout).await
    }
}

async fn wait_for_native_audio_stream(
    adapter: &Arc<dyn ConnectionAdapter>,
    connection_id: &ConnectionId,
    timeout: Duration,
) -> Result<Arc<dyn MediaStream>, PrivateEgressError> {
    let deadline = tokio::time::Instant::now() + timeout;
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
            return Err(PrivateEgressError::Timeout);
        }
        tokio::task::yield_now().await;
    }
}

// A proxy pump owns a complete, immutable route authority snapshot. Keeping
// those ownership fields explicit avoids a second partially validated type;
// the nested event arms must also move their payloads after pattern matching,
// which Rust does not permit from a collapsed pattern guard.
#[allow(clippy::too_many_arguments, clippy::collapsible_match)]
fn spawn_proxy_pump(
    orchestrator: Arc<Orchestrator>,
    native_connection_id: ConnectionId,
    native_transport: Transport,
    stream: Arc<dyn MediaStream>,
    private_route: Arc<GatewayForwardingRoute>,
    cancel: CancellationToken,
    operation_timeout: Duration,
    mut native_events: Option<mpsc::Receiver<OperationalEvent>>,
    lifecycle: Option<Arc<dyn PrivateEgressGatewayLifecycleSource>>,
    forwarder: Arc<GatewayForwarder>,
    authority: PrivateEgressRouteAuthority,
    target: PrivateEgressTarget,
    activation_phase: Arc<AtomicU8>,
) -> Result<(JoinHandle<()>, oneshot::Receiver<PrivateEgressError>), PrivateEgressError> {
    let mut from_native = stream
        .try_frames_in()
        .map_err(|_| PrivateEgressError::HandlerRejected)?;
    let to_native = stream
        .try_frames_out()
        .map_err(|_| PrivateEgressError::HandlerRejected)?;
    let codec = stream.codec();
    let stream_id = stream.id();
    let ssrc = stable_ssrc(&native_connection_id);
    let (failure_tx, failure_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut sequence = 0u16;
        let mut terminal = None;
        let mut suppress_initial_connected = true;
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                frame = from_native.recv() => {
                    let Some(frame) = frame else { break; };
                    let packet = encode_rtp(&frame, &codec, sequence, ssrc);
                    sequence = sequence.wrapping_add(1);
                    if private_route.try_send_rtp(packet).is_err() {
                        break;
                    }
                }
                packet = private_route.recv() => {
                    let Some(packet) = packet else { break; };
                    match packet {
                        ForwardedPacket::Rtp(packet) => {
                            let Some(frame) = decode_rtp(&packet, stream_id.clone()) else { break; };
                            if to_native.try_send(frame).is_err() { break; }
                        }
                        ForwardedPacket::Rtcp(_) => {}
                        ForwardedPacket::Dtmf { digits, duration_ms } => {
                            if !matches!(
                                tokio::time::timeout(
                                    operation_timeout,
                                    orchestrator.send_dtmf(native_connection_id.clone(), &digits, duration_ms),
                                ).await,
                                Ok(Ok(()))
                            ) { break; }
                        }
                        ForwardedPacket::Data(message) => {
                            if !matches!(
                                tokio::time::timeout(
                                    operation_timeout,
                                    orchestrator.send_data_message_to_connection(native_connection_id.clone(), message),
                                ).await,
                                Ok(Ok(()))
                            ) { break; }
                        }
                    }
                }
                event = async {
                    match native_events.as_mut() {
                        Some(events) => events.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    let Some(event) = event else {
                        if cancel.is_cancelled() {
                            break;
                        }
                        terminal = Some((PrivateEgressLifecycleState::Failed, "native_event_stream_closed"));
                        break;
                    };
                    if event.connection_id != native_connection_id
                        || event.transport != native_transport
                    {
                        continue;
                    }
                    match event.kind {
                        OperationalEventKind::Progress {
                            status_code,
                            early_media,
                        } if native_transport == Transport::Sip => {
                            // SIP provisional responses are lifecycle facts, not
                            // command states. Publish them in this pump's serial
                            // event order while it is already carrying early RTP.
                            // WebRTC has no equivalent SIP early-media contract
                            // and is deliberately excluded by the transport
                            // guard rather than manufacturing a false claim.
                            if let Ok(event) = PrivateEgressLifecycleEvent::progress(
                                authority.worker,
                                authority.source.clone(),
                                target,
                                status_code,
                                early_media,
                            ) {
                                let _ = forwarder.publish_private_egress_lifecycle(event).await;
                            }
                        }
                        OperationalEventKind::Connected => {
                            if suppress_initial_connected {
                                // The Activate command response is the sole
                                // authoritative initial promotion to Active.
                                // Consuming this adapter notification avoids a
                                // competing state event while that durable
                                // command transition is still pending.
                                suppress_initial_connected = false;
                            } else if activation_phase.load(Ordering::Acquire)
                                == ACTIVATION_COMMITTED
                            {
                                if let Ok(event) = PrivateEgressLifecycleEvent::new(
                                    authority.worker,
                                    authority.source.clone(),
                                    target,
                                    PrivateEgressLifecycleState::Active,
                                    None,
                                ) {
                                    let _ = forwarder.publish_private_egress_lifecycle(event).await;
                                }
                            }
                        }
                        OperationalEventKind::DataMessage { message } => {
                            if private_route.try_send_data(message).is_err() {
                                break;
                            }
                        }
                        OperationalEventKind::Dtmf { digits, duration_ms } => {
                            if private_route.try_send_dtmf(digits, duration_ms).is_err() {
                                break;
                            }
                        }
                        OperationalEventKind::Ended { .. } => {
                            terminal = Some((PrivateEgressLifecycleState::Ended, "remote_ended"));
                            break;
                        }
                        OperationalEventKind::Failed { .. } => {
                            terminal = Some((PrivateEgressLifecycleState::Failed, "remote_failed"));
                            break;
                        }
                        OperationalEventKind::MediaActivity { .. } => {}
                        _ => {}
                    }
                }
            }
        }
        if let Some(lifecycle) = lifecycle {
            lifecycle.unsubscribe(&native_connection_id);
        }
        // A local Abort/End/drain owns transport teardown and must not be
        // reinterpreted as a remote failure merely because unsubscribing also
        // closed the native event receiver. In particular, do not enter the
        // terminal lifecycle publication retry after the owner cancelled us.
        if cancel.is_cancelled() {
            return;
        }
        let failed_before_commit = activation_phase
            .compare_exchange(
                ACTIVATION_PENDING,
                ACTIVATION_FAILED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok();
        if failed_before_commit {
            let _ = failure_tx.send(PrivateEgressError::HandlerRejected);
            private_route.close().await;
            return;
        }
        if let Some((state, reason)) = terminal {
            if let Ok(event) = PrivateEgressLifecycleEvent::new(
                authority.worker,
                authority.source,
                target,
                state,
                Some(reason.to_owned()),
            ) {
                // Native commit and the durable Activate response are adjacent
                // but not atomic. If a remote terminal arrives in that narrow
                // interval, retain it until the command transition clears so a
                // real hangup cannot be lost as an in-flight state conflict.
                let deadline = tokio::time::Instant::now() + operation_timeout;
                loop {
                    if forwarder
                        .publish_private_egress_lifecycle(event.clone())
                        .await
                        .is_ok()
                    {
                        break;
                    }
                    if tokio::time::Instant::now() >= deadline {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            }
            // Do not close the generation-bound private route here. A
            // successful publish means only that the lifecycle event was
            // journaled and its first delivery was enqueued; the worker may
            // not have durably ACKed it yet. `retire_terminal`, invoked only
            // after exact ACK validation, is the sole terminal route closer.
        }
    });
    Ok((task, failure_rx))
}

const RTP_FIXED_HEADER_BYTES: usize = 12;

fn codec_payload_type(codec: &CodecInfo) -> u8 {
    match codec.name.to_ascii_lowercase().as_str() {
        "pcmu" | "g.711-mu" => 0,
        "pcma" | "g.711-a" => 8,
        _ => 111,
    }
}

fn encode_rtp(frame: &MediaFrame, codec: &CodecInfo, sequence: u16, ssrc: u32) -> Bytes {
    let mut packet = Vec::with_capacity(RTP_FIXED_HEADER_BYTES + frame.payload.len());
    packet.extend_from_slice(&[0x80, codec_payload_type(codec) & 0x7f]);
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
    Some(MediaFrame {
        stream_id,
        kind: StreamKind::Audio,
        payload: Bytes::copy_from_slice(&packet[offset..packet.len() - padding]),
        timestamp_rtp: u32::from_be_bytes(packet[4..8].try_into().ok()?),
        captured_at: Utc::now(),
        payload_type: Some(packet[1] & 0x7f),
    })
}

fn stable_ssrc(connection_id: &ConnectionId) -> u32 {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(connection_id.as_str().as_bytes());
    u32::from_be_bytes(digest[..4].try_into().expect("SHA-256 has four bytes"))
}

fn unix_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::call_engine::{BindingGeneration, CallId, LegId, TenantId};
    use crate::private_egress::{PrivateEgressProfile, PrivateEgressTransport};
    use rvoip_core::connection::Direction;
    use rvoip_core::ids::StreamId;
    use rvoip_core::stream::{MediaFrame, QualitySnapshot, StreamKind};
    use tokio::sync::mpsc;

    struct TestStream {
        id: StreamId,
        codec: CodecInfo,
        inbound: std::sync::Mutex<Option<mpsc::Receiver<MediaFrame>>>,
        outbound: mpsc::Sender<MediaFrame>,
    }

    #[async_trait::async_trait]
    impl MediaStream for TestStream {
        fn id(&self) -> StreamId {
            self.id.clone()
        }
        fn kind(&self) -> StreamKind {
            StreamKind::Audio
        }
        fn codec(&self) -> CodecInfo {
            self.codec.clone()
        }
        fn direction(&self) -> Direction {
            Direction::Outbound
        }
        fn frames_in(&self) -> mpsc::Receiver<MediaFrame> {
            self.inbound.lock().unwrap().take().unwrap()
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

    fn worker() -> WorkerLease {
        serde_json::from_value(serde_json::json!({
            "worker_id": "00000000-0000-4000-8000-000000000151",
            "fence": 9
        }))
        .unwrap()
    }

    fn prepare(now_ms: i64) -> PrivateEgressCommand {
        let source = PrivateEgressSource {
            tenant_id: TenantId::parse("tenant-a").unwrap(),
            call_id: CallId::new(),
            leg_id: LegId::new(),
            binding_generation: BindingGeneration::INITIAL,
        };
        PrivateEgressCommand::new(
            Uuid::new_v4(),
            now_ms,
            Duration::from_secs(5),
            worker(),
            source,
            PrivateEgressTarget {
                leg_id: LegId::new(),
                binding_generation: BindingGeneration::INITIAL,
            },
            PrivateEgressOperation::Prepare {
                transport: PrivateEgressTransport::Sip,
                profile: PrivateEgressProfile {
                    profile_id: "primary".into(),
                    revision: "revision-1".into(),
                },
                codec: CodecInfo::from_name_with_defaults("opus"),
                target: "sips:queue@example.test".into(),
                initial_context: Vec::new(),
            },
        )
        .unwrap()
    }

    fn catalog_route(
        route_id: &str,
        target: &str,
        codecs: Vec<CodecInfo>,
    ) -> PrivateEgressWorkerRouteDescriptor {
        PrivateEgressWorkerRouteDescriptor {
            tenant_id: TenantId::parse("tenant-a").unwrap(),
            route_id: route_id.to_owned(),
            transport: PrivateEgressTransport::Sip,
            profile: PrivateEgressProfile {
                profile_id: "primary".into(),
                revision: "a".repeat(64),
            },
            target: target.to_owned(),
            codecs,
        }
    }

    #[test]
    fn route_catalog_fingerprint_is_order_independent_and_configuration_sensitive() {
        let opus = CodecInfo::from_name_with_defaults("Opus");
        let pcmu = CodecInfo::from_name_with_defaults("g.711-mu");
        let first = catalog_route(
            "alpha",
            "sips:alpha@example.test",
            vec![opus.clone(), pcmu.clone()],
        );
        let second = catalog_route(
            "beta",
            "sips:beta@example.test",
            vec![pcmu.clone(), opus.clone()],
        );
        let forward =
            PrivateEgressWorkerRouteCatalog::new(vec![first.clone(), second.clone()]).unwrap();
        let reversed =
            PrivateEgressWorkerRouteCatalog::new(vec![second.clone(), first.clone()]).unwrap();
        assert_eq!(forward.fingerprint(), reversed.fingerprint());

        let changed = PrivateEgressWorkerRouteCatalog::new(vec![
            first,
            catalog_route("beta", "sips:changed@example.test", vec![opus, pcmu]),
        ])
        .unwrap();
        assert_ne!(forward.fingerprint(), changed.fingerprint());

        let capability = forward.fingerprint().advertisement_capability();
        let advertised = std::collections::BTreeSet::from([capability]);
        assert_eq!(
            RouteCatalogFingerprint::from_capabilities(&advertised).unwrap(),
            Some(forward.fingerprint())
        );
    }

    #[tokio::test]
    async fn reservation_is_exact_one_use_and_generation_bound() {
        let now_ms = unix_time_ms();
        let command = prepare(now_ms);
        let codec = CodecInfo::from_name_with_defaults("opus");
        let descriptor = PrivateEgressStreamAdmission::from_prepare(&command).unwrap();
        let registry = PrivateEgressStreamAdmissionRegistry::new(worker(), 1).unwrap();
        let reservation = registry.reserve(descriptor.clone()).unwrap();
        assert_eq!(
            PrivateEgressStreamAdmission::from_routing_hint(&descriptor.to_routing_hint().unwrap())
                .unwrap(),
            descriptor
        );

        let (_in_tx, in_rx) = mpsc::channel(2);
        let (out_tx, _out_rx) = mpsc::channel(2);
        let stream: Arc<dyn MediaStream> = Arc::new(TestStream {
            id: StreamId::new(),
            codec,
            inbound: std::sync::Mutex::new(Some(in_rx)),
            outbound: out_tx,
        });
        let connection_id = ConnectionId::new();
        let admitted = registry
            .admit(&descriptor, connection_id.clone(), stream)
            .unwrap();
        assert_eq!(admitted.connection_id(), &connection_id);
        assert!(matches!(
            registry.admit(&descriptor, ConnectionId::new(), admitted.stream(),),
            Err(PrivateEgressStreamError::AlreadyUsed)
        ));
        let from_waiter = reservation.wait(Duration::from_secs(1)).await.unwrap();
        assert_eq!(from_waiter.connection_id(), &connection_id);
        drop(admitted);
        drop(from_waiter);
        assert_eq!(registry.active_admissions(), 0);
    }
}
