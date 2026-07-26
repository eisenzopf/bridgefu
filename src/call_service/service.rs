//! Authenticated transactional application service for the versioned call API.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rvoip_auth_core::AuthenticatedPrincipal;
use rvoip_core::ids::ConnectionId;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

use crate::api_principal::{ApiPrincipal, ApiPrincipalError, CallScope};
use crate::call_engine::{
    AggregateVersion, AttachmentConsume, AttachmentId, AttachmentIssue, AttachmentLookup,
    AttachmentPurpose, AttachmentTransport, BindingGeneration, CallAggregate, CallCommand, CallId,
    CallRepository, CommandCommitView, CommandId, ConnectionBinding, LegDirection, LegId,
    LegSemantics, LegSpec, LegState, MediaFlow, PrincipalFingerprint, RepositoryError,
    SignalingInitiator, StopLegReason, TenantId, WorkerId, WorkerLease,
};
use crate::coordination::{CoordinationProjection, WorkerSelectionRequest};

use super::{
    digest_presented_attachment_token, AmazonConnectEndpointConfig, AmazonConnectStartSpec,
    AttachmentTokenContext, AttachmentView, BoundConnectionStateCommit, CallExecutionPlan,
    CallOperationResult, CallServiceCrypto, CallServiceRepository, CallView,
    CanonicalRequestTranscript, ControlCommandOutcome, ControlCommandTransaction, ControlIntent,
    CreateCallView, DtmfAcceptedView, DtmfSequence, IdempotencyKey, LegEndpointConfig,
    LegExecutionSpec, MediaActivityCommit, MediaActivityGeneration, NamedProfileKind,
    NamedProfileRole, NamedRouteBinding, OperationIdempotency, ProviderEndpointConfig,
    ProviderEventReconciliationOutcome, ProviderEventReconciliationTransaction, ProviderKind,
    ProviderMediaAttachmentToken, ServiceCommandOutcome, ServiceCommandTransaction,
    ServiceCreateCandidate, ServiceCreateOutcome, ServiceCreateTransaction, ServiceEffectPayload,
    ServiceEffectPayloadInput, ServiceOperationKind, SipEndpointConfig, SipInitialContextMode,
    StoredServiceCall, TransferTarget, WebRtcEndpointConfig, WhepEndpointConfig,
    WhipEndpointConfig,
};

/// One API-requested logical leg.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedLeg {
    /// Direction relative to Bridgefu.
    pub direction: LegDirection,
    /// Explicit signaling initiator. Omission preserves the historical
    /// direction-derived default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signaling_initiator: Option<SignalingInitiator>,
    /// Media permitted on the leg, relative to Bridgefu.
    #[serde(default)]
    pub media_flow: MediaFlow,
    /// Typed, credential-free endpoint configuration.
    pub endpoint: LegEndpointConfig,
    /// Exact immutable Amazon `StartWebRTCContact` authority for an outbound
    /// Amazon leg. It is rejected for every other endpoint/direction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amazon_connect_start: Option<AmazonConnectStartSpec>,
}

impl RequestedLeg {
    /// Resolves the explicit value or the exact historical default.
    #[must_use]
    pub const fn resolved_signaling_initiator(&self) -> SignalingInitiator {
        match self.signaling_initiator {
            Some(value) => value,
            None => SignalingInitiator::legacy_default(self.direction),
        }
    }

    #[must_use]
    const fn semantics(&self) -> LegSemantics {
        LegSemantics {
            signaling_initiator: self.resolved_signaling_initiator(),
            media_flow: self.media_flow,
        }
    }

    /// Validates a server-owned named-route destination. Named routes are
    /// deliberately full-duplex, outbound, and Bridgefu-initiated; a public
    /// caller selects only the route ID and can never replace this endpoint.
    pub fn validate_named_route_destination(&self) -> Result<(), RepositoryError> {
        if self.direction != LegDirection::Outbound
            || self.resolved_signaling_initiator() != SignalingInitiator::Bridgefu
            || self.media_flow != MediaFlow::SendReceive
        {
            return Err(RepositoryError::InvalidInput(
                "named-route destination must be outbound, Bridgefu-initiated, and full-duplex",
            ));
        }
        if matches!(
            &self.endpoint,
            LegEndpointConfig::Provider(ProviderEndpointConfig {
                provider: ProviderKind::Twilio | ProviderKind::Vonage,
                ..
            })
        ) {
            return Err(RepositoryError::InvalidInput(
                "named-route provider is deferred",
            ));
        }
        self.endpoint
            .validate(self.direction, self.resolved_signaling_initiator())?;
        match (&self.endpoint, &self.amazon_connect_start) {
            (LegEndpointConfig::AmazonConnect(endpoint), Some(start))
                if endpoint.instance_id == start.instance_id()
                    && endpoint.contact_flow_id == start.contact_flow_id() =>
            {
                Ok(())
            }
            (LegEndpointConfig::AmazonConnect(_), _) => Err(RepositoryError::InvalidInput(
                "named Amazon route requires a matching durable start specification",
            )),
            (_, None) => Ok(()),
            (_, Some(_)) => Err(RepositoryError::InvalidInput(
                "Amazon start specification is valid only for an Amazon route",
            )),
        }
    }
}

/// Exactly two explicitly bridged legs and an optional administrative tenant override.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateCallInput {
    /// Optional tenant override; requires the literal administrative scope.
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Exactly two legs. The fixed array rejects every other cardinality.
    pub legs: [RequestedLeg; 2],
}

/// Common optional tenant override for a call mutation.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallMutationInput {
    /// Optional tenant override; requires the literal administrative scope.
    #[serde(default)]
    pub tenant_id: Option<String>,
}

/// Transfer request stored with the core transfer effect.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferCallInput {
    /// Optional tenant override; requires the literal administrative scope.
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Exact existing call leg whose signaling session receives transfer.
    pub target_leg_id: LegId,
    /// Typed transfer destination.
    pub target: TransferTarget,
}

/// Server-controlled logical-leg replacement request. The public caller may
/// select only a configured route; concrete endpoint addresses are resolved
/// by the API process and never accepted from this body.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplaceLegInput {
    /// Optional tenant override; requires the literal administrative scope.
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Name of a configured destination route.
    pub route_id: String,
}

fn default_dtmf_duration_ms() -> u16 {
    120
}

fn default_dtmf_gap_ms() -> u16 {
    70
}

/// Bound-leg DTMF request.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DtmfCallInput {
    /// Optional tenant override; requires the literal administrative scope.
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Exact connected leg receiving DTMF.
    pub leg_id: LegId,
    /// Symbols `0-9`, `*`, `#`, and uppercase `A-D`.
    pub digits: String,
    /// Per-tone duration.
    #[serde(default = "default_dtmf_duration_ms")]
    pub duration_ms: u16,
    /// Gap between tones.
    #[serde(default = "default_dtmf_gap_ms")]
    pub gap_ms: u16,
}

impl fmt::Debug for DtmfCallInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DtmfCallInput")
            .field("tenant_id", &self.tenant_id)
            .field("leg_id", &self.leg_id)
            .field("digits", &"[redacted]")
            .field("digit_count", &self.digits.len())
            .field("duration_ms", &self.duration_ms)
            .field("gap_ms", &self.gap_ms)
            .finish()
    }
}

/// Optional tenant override on a read.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetCallInput {
    /// Optional tenant override; requires the literal administrative scope.
    #[serde(default)]
    pub tenant_id: Option<String>,
}

/// Time source used to make expiry and replay behavior deterministic in tests.
pub trait CallServiceClock: Send + Sync {
    /// Returns the current UTC observation time.
    fn now(&self) -> DateTime<Utc>;
}

/// Production UTC clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCallServiceClock;

impl CallServiceClock for SystemCallServiceClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// Worker-selection seam. Gate 6 item 6 replaces the fixed implementation.
#[async_trait]
pub trait WorkerPlacement: Send + Sync {
    /// Returns bounded, ordered candidate fences for a validated plan. The
    /// authoritative repository still chooses and reserves inside creation.
    async fn select_workers(
        &self,
        tenant: &TenantId,
        plan: &CallExecutionPlan,
        at: DateTime<Utc>,
    ) -> Result<Vec<WorkerLease>, PlacementError>;

    /// Whether leg replacement commits must atomically revalidate the exact
    /// pinned remote worker. All-in-one runtimes own execution in-process and
    /// deliberately retain the legacy behavior; split control runtimes opt in.
    fn requires_replacement_worker_guard(&self) -> bool {
        false
    }

    /// Whether this control process can reach the pinned worker through its
    /// configured private-forwarding catalog.
    fn allows_worker(&self, _worker_id: WorkerId) -> bool {
        true
    }
}

const MAX_WORKER_CANDIDATES: usize = 8;

/// Safe worker-placement failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PlacementError {
    /// No worker currently has capacity.
    #[error("worker capacity exhausted")]
    CapacityExceeded,
    /// Live reachable workers do not expose the required adapter set.
    #[error("worker capability is unavailable")]
    UnsupportedCapability,
    /// Placement coordination is unavailable.
    #[error("worker placement unavailable")]
    Unavailable,
}

/// Single-worker placement for all-in-one and hermetic test mode.
#[derive(Clone, Copy, Debug)]
pub struct FixedWorkerPlacement {
    worker: WorkerLease,
}

impl FixedWorkerPlacement {
    /// Pins every call to one already-registered worker lease.
    #[must_use]
    pub const fn new(worker: WorkerLease) -> Self {
        Self { worker }
    }
}

#[async_trait]
impl WorkerPlacement for FixedWorkerPlacement {
    async fn select_workers(
        &self,
        _tenant: &TenantId,
        _plan: &CallExecutionPlan,
        _at: DateTime<Utc>,
    ) -> Result<Vec<WorkerLease>, PlacementError> {
        Ok(vec![self.worker])
    }
}

/// Database-authoritative placement used by durable runtimes. Any Redis view
/// may order candidates before this seam in the future, but these snapshots
/// are always revalidated by the repository and reservation remains atomic.
pub struct RepositoryWorkerPlacement {
    repository: Arc<dyn CallRepository>,
    projection: Option<Arc<dyn CoordinationProjection>>,
    limit: usize,
    replacement_worker_guard: bool,
    allowed_worker_ids: Option<BTreeSet<WorkerId>>,
}

impl RepositoryWorkerPlacement {
    /// Creates bounded durable placement.
    #[must_use]
    pub fn new(repository: Arc<dyn CallRepository>) -> Self {
        Self {
            repository,
            projection: None,
            limit: MAX_WORKER_CANDIDATES,
            replacement_worker_guard: false,
            allowed_worker_ids: None,
        }
    }

    /// Adds a best-effort ordered projection. Every hint is revalidated in
    /// the authoritative repository and database fallback remains mandatory.
    #[must_use]
    pub fn with_projection(mut self, projection: Arc<dyn CoordinationProjection>) -> Self {
        self.projection = Some(projection);
        self
    }

    /// Requires replacement admission to be committed only while the exact
    /// call-pinned remote worker is live, non-draining, and capable.
    #[must_use]
    pub fn with_replacement_worker_guard(mut self) -> Self {
        self.replacement_worker_guard = true;
        self
    }

    /// Restricts placement to the workers reachable by this gateway. This is
    /// the same set used for route capability advertisement and private
    /// forwarding, preventing an otherwise-capable but unreachable worker
    /// from receiving a call.
    #[must_use]
    pub fn with_allowed_workers(mut self, worker_ids: BTreeSet<WorkerId>) -> Self {
        self.allowed_worker_ids = Some(worker_ids);
        self
    }
}

impl fmt::Debug for RepositoryWorkerPlacement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RepositoryWorkerPlacement")
            .field("repository", &"[configured]")
            .field(
                "projection",
                &self.projection.as_ref().map(|_| "[configured]"),
            )
            .field("limit", &self.limit)
            .field("replacement_worker_guard", &self.replacement_worker_guard)
            .field(
                "allowed_worker_count",
                &self.allowed_worker_ids.as_ref().map(BTreeSet::len),
            )
            .finish()
    }
}

#[async_trait]
impl WorkerPlacement for RepositoryWorkerPlacement {
    async fn select_workers(
        &self,
        _tenant: &TenantId,
        plan: &CallExecutionPlan,
        at: DateTime<Utc>,
    ) -> Result<Vec<WorkerLease>, PlacementError> {
        let required = plan
            .required_worker_capabilities()
            .map_err(|_| PlacementError::Unavailable)?;
        let mut selected = Vec::new();
        let mut reachable_worker_is_live = false;
        let mut reachable_worker_is_capable = false;
        if let Some(projection) = &self.projection {
            if let Ok(hints) = projection
                .worker_hints(&WorkerSelectionRequest {
                    required_capabilities: required.clone(),
                    limit: self.limit,
                })
                .await
            {
                for hint in hints {
                    if self
                        .allowed_worker_ids
                        .as_ref()
                        .is_some_and(|allowed| !allowed.contains(&hint.lease.worker_id))
                    {
                        continue;
                    }
                    let Ok(observed) = self.repository.worker_snapshot(hint.lease.worker_id).await
                    else {
                        continue;
                    };
                    if observed.lease != hint.lease {
                        continue;
                    }
                    let Ok(worker) = self
                        .repository
                        .active_worker_snapshot(observed.lease, at)
                        .await
                    else {
                        continue;
                    };
                    if worker.reserved_calls < worker.max_calls
                        && required.is_subset(&worker.capabilities)
                        && !selected.contains(&worker.lease)
                    {
                        selected.push(worker.lease);
                    }
                }
            }
        }
        if let Some(allowed) = &self.allowed_worker_ids {
            for worker_id in allowed {
                if selected.len() >= self.limit {
                    break;
                }
                let observed = match self.repository.worker_snapshot(*worker_id).await {
                    Ok(worker) => worker,
                    Err(RepositoryError::NotFound) => continue,
                    Err(_) => return Err(PlacementError::Unavailable),
                };
                let worker = match self
                    .repository
                    .active_worker_snapshot(observed.lease, at)
                    .await
                {
                    Ok(worker) => worker,
                    Err(RepositoryError::NotFound | RepositoryError::StaleWorkerFence) => continue,
                    Err(_) => return Err(PlacementError::Unavailable),
                };
                reachable_worker_is_live = true;
                if !required.is_subset(&worker.capabilities) {
                    continue;
                }
                reachable_worker_is_capable = true;
                if worker.reserved_calls < worker.max_calls && !selected.contains(&worker.lease) {
                    selected.push(worker.lease);
                }
            }
        } else {
            let workers = self
                .repository
                .worker_candidates(&required, at, self.limit)
                .await
                .map_err(|_| PlacementError::Unavailable)?;
            for worker in workers {
                if !selected.contains(&worker.lease) && selected.len() < self.limit {
                    selected.push(worker.lease);
                }
            }
        }
        if selected.is_empty() {
            if self.allowed_worker_ids.is_some() && !reachable_worker_is_live {
                Err(PlacementError::Unavailable)
            } else if self.allowed_worker_ids.is_some() && !reachable_worker_is_capable {
                Err(PlacementError::UnsupportedCapability)
            } else {
                Err(PlacementError::CapacityExceeded)
            }
        } else {
            Ok(selected)
        }
    }

    fn requires_replacement_worker_guard(&self) -> bool {
        self.replacement_worker_guard
    }

    fn allows_worker(&self, worker_id: WorkerId) -> bool {
        self.allowed_worker_ids
            .as_ref()
            .is_none_or(|allowed| allowed.contains(&worker_id))
    }
}

/// Validated inbound leg passed to signaling-principal policy.
pub struct AttachmentPrincipalRequest<'a> {
    /// Authenticated call owner tenant.
    pub tenant: &'a TenantId,
    /// Validated execution spec; profiles are configured names, not credentials.
    pub leg: &'a LegExecutionSpec,
    /// Exact durable named-route snapshot selected by trusted configuration.
    ///
    /// A named SIP ingress uses this snapshot to select its configured Vapi
    /// signaling identity. Low-level calls have no route snapshot and retain
    /// the compatibility same-principal policy.
    pub named_route: Option<&'a NamedRouteBinding>,
    /// Ownership fingerprint of the API principal that created the call.
    pub api_principal: PrincipalFingerprint,
}

impl fmt::Debug for AttachmentPrincipalRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AttachmentPrincipalRequest")
            .field("tenant", self.tenant)
            .field("leg", self.leg)
            .field("named_route", &self.named_route)
            .field("api_principal", &"[redacted]")
            .finish()
    }
}

/// Resolves the authenticated signaling identity expected to consume an inbound token.
#[async_trait]
pub trait AttachmentPrincipalResolver: Send + Sync {
    /// Returns `None` when no safe configured signaling identity exists.
    async fn resolve_principal(
        &self,
        request: AttachmentPrincipalRequest<'_>,
    ) -> Result<Option<PrincipalFingerprint>, AttachmentPrincipalResolverError>;

    /// Returns a complete configured signaling identity when the transport
    /// principal differs from the API caller. The call service validates its
    /// tenant/expiry and derives the keyed fingerprint itself.
    async fn resolve_authenticated_principal(
        &self,
        _request: AttachmentPrincipalRequest<'_>,
    ) -> Result<Option<AuthenticatedPrincipal>, AttachmentPrincipalResolverError> {
        Ok(None)
    }
}

/// Redacted resolver backend failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AttachmentPrincipalResolverError {
    /// Profile or identity storage is temporarily unavailable.
    #[error("attachment principal resolver unavailable")]
    Unavailable,
}

/// Same-principal policy for generic SIP/WebRTC endpoints only.
///
/// Amazon Connect and native provider legs require configured transport identities
/// and deliberately fail closed under this compatibility policy.
#[derive(Clone, Copy, Debug, Default)]
pub struct SamePrincipalAttachmentResolver;

#[async_trait]
impl AttachmentPrincipalResolver for SamePrincipalAttachmentResolver {
    async fn resolve_principal(
        &self,
        request: AttachmentPrincipalRequest<'_>,
    ) -> Result<Option<PrincipalFingerprint>, AttachmentPrincipalResolverError> {
        let same_principal = matches!(
            request.leg.endpoint,
            LegEndpointConfig::Sip(_)
                | LegEndpointConfig::WebRtc(_)
                | LegEndpointConfig::Whip(_)
                | LegEndpointConfig::Whep(_)
        );
        Ok(same_principal.then_some(request.api_principal))
    }
}

/// Same-principal generic policy plus exact configured identities for native
/// provider SIP media attachments.
#[derive(Clone, Default)]
pub struct ConfiguredAttachmentPrincipalResolver {
    providers: BTreeMap<(String, String), (ProviderKind, AuthenticatedPrincipal)>,
    vapi_ingress: BTreeMap<(String, String, String), AuthenticatedPrincipal>,
}

impl ConfiguredAttachmentPrincipalResolver {
    /// Creates an empty resolver. Generic SIP/WebRTC attachments continue to
    /// use the API caller; native provider legs fail closed until configured.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one exact globally unique account-profile identity.
    #[must_use]
    pub fn with_provider(
        mut self,
        kind: ProviderKind,
        account_profile: impl Into<String>,
        principal: AuthenticatedPrincipal,
    ) -> Self {
        let tenant = principal.tenant.clone().unwrap_or_default();
        self.providers
            .insert((account_profile.into(), tenant), (kind, principal));
        self
    }

    /// Adds one exact tenant/profile/revision identity shared with the SIP
    /// listener's trusted-CIDR or verified-mTLS projection.
    #[must_use]
    pub fn with_vapi_ingress(
        mut self,
        profile_id: impl Into<String>,
        revision: impl Into<String>,
        principal: AuthenticatedPrincipal,
    ) -> Self {
        let tenant = principal.tenant.clone().unwrap_or_default();
        self.vapi_ingress
            .insert((tenant, profile_id.into(), revision.into()), principal);
        self
    }
}

impl fmt::Debug for ConfiguredAttachmentPrincipalResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfiguredAttachmentPrincipalResolver")
            .field("provider_count", &self.providers.len())
            .field("vapi_ingress_count", &self.vapi_ingress.len())
            .finish()
    }
}

#[async_trait]
impl AttachmentPrincipalResolver for ConfiguredAttachmentPrincipalResolver {
    async fn resolve_principal(
        &self,
        request: AttachmentPrincipalRequest<'_>,
    ) -> Result<Option<PrincipalFingerprint>, AttachmentPrincipalResolverError> {
        // A named SIP ingress is authenticated by its configured Vapi profile,
        // not by the control-plane principal that selected the route. Never
        // fall back to the API identity when the durable profile snapshot is
        // missing, stale, or malformed.
        if request.named_route.is_some()
            && matches!(request.leg.endpoint, LegEndpointConfig::Sip(_))
        {
            return Ok(None);
        }
        let same_principal = matches!(
            request.leg.endpoint,
            LegEndpointConfig::Sip(_)
                | LegEndpointConfig::WebRtc(_)
                | LegEndpointConfig::Whip(_)
                | LegEndpointConfig::Whep(_)
        );
        Ok(same_principal.then_some(request.api_principal))
    }

    async fn resolve_authenticated_principal(
        &self,
        request: AttachmentPrincipalRequest<'_>,
    ) -> Result<Option<AuthenticatedPrincipal>, AttachmentPrincipalResolverError> {
        if matches!(request.leg.endpoint, LegEndpointConfig::Sip(_)) {
            let Some(route) = request.named_route else {
                return Ok(None);
            };
            let mut ingress = route
                .profiles()
                .iter()
                .filter(|profile| profile.role() == NamedProfileRole::Ingress);
            let Some(binding) = ingress.next() else {
                return Ok(None);
            };
            if ingress.next().is_some() || binding.kind() != NamedProfileKind::VapiIngress {
                return Ok(None);
            }
            return Ok(self
                .vapi_ingress
                .get(&(
                    request.tenant.as_str().to_owned(),
                    binding.profile_id().to_owned(),
                    binding.revision().to_owned(),
                ))
                .cloned());
        }
        let LegEndpointConfig::Provider(endpoint) = &request.leg.endpoint else {
            return Ok(None);
        };
        Ok(self
            .providers
            .get(&(
                endpoint.account_profile.clone(),
                request.tenant.as_str().to_owned(),
            ))
            .filter(|(kind, _)| *kind == endpoint.provider)
            .map(|(_, principal)| principal.clone()))
    }
}

/// Lifecycle deadline policy retained by the transactional service.
#[derive(Clone, Copy, Debug)]
pub struct CallTimeoutPolicy {
    /// Maximum setup time.
    pub setup: Duration,
    /// Maximum time without authoritative media activity once active.
    pub media_idle: Duration,
    /// Maximum native/signaling transfer time.
    pub transfer: Duration,
    /// Maximum peer teardown time.
    pub ending: Duration,
}

impl Default for CallTimeoutPolicy {
    fn default() -> Self {
        Self {
            setup: Duration::from_secs(30),
            media_idle: Duration::from_secs(30),
            transfer: Duration::from_secs(30),
            ending: Duration::from_secs(30),
        }
    }
}

/// One authoritative rvoip media-activity observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaActivityObservation {
    /// Authenticated tenant ownership.
    pub tenant_id: TenantId,
    /// Durable call receiving the observation.
    pub call_id: CallId,
    /// Compare-and-swap version retained across lost-response retries.
    pub expected_version: AggregateVersion,
    /// Stable event delivery identity retained across retries.
    pub command_id: CommandId,
    /// Exact logical leg carrying observed media.
    pub leg_id: LegId,
    /// Exact signaling/media incarnation.
    pub binding_generation: BindingGeneration,
    /// Exact rvoip route that emitted activity.
    pub connection_id: ConnectionId,
    /// Strictly consecutive route-local activity generation.
    pub activity_generation: MediaActivityGeneration,
    /// Current fenced worker.
    pub worker: WorkerLease,
    /// Authoritative activity observation time.
    pub at: DateTime<Utc>,
}

/// Opaque, tenant-authorized reference to one exact connected media source.
///
/// The rvoip connection identifier is intentionally private and this type is
/// not serializable. Control-plane callers may pass its cloned identifier to
/// the colocated media runtime, but must never include it in an API response.
#[derive(Clone, Eq, PartialEq)]
pub struct BroadcastSourceBinding {
    tenant_id: TenantId,
    call_id: CallId,
    leg_id: LegId,
    binding_generation: BindingGeneration,
    connection_id: ConnectionId,
    worker: WorkerLease,
}

impl fmt::Debug for BroadcastSourceBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BroadcastSourceBinding")
            .field("tenant_id", &self.tenant_id)
            .field("call_id", &self.call_id)
            .field("leg_id", &self.leg_id)
            .field("binding_generation", &self.binding_generation)
            .field("connection_id", &"[redacted]")
            .field("worker", &self.worker)
            .finish()
    }
}

impl BroadcastSourceBinding {
    /// Authenticated owner inherited by the broadcast.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Durable call that owns the source.
    #[must_use]
    pub const fn call_id(&self) -> CallId {
        self.call_id
    }

    /// Exact logical leg selected by the caller.
    #[must_use]
    pub const fn leg_id(&self) -> LegId {
        self.leg_id
    }

    /// Exact durable attachment generation workers must revalidate before
    /// installing a media-graph route.
    #[must_use]
    pub const fn binding_generation(&self) -> BindingGeneration {
        self.binding_generation
    }

    /// Exact call-pinned worker incarnation selected by the authoritative
    /// repository.
    #[must_use]
    pub const fn worker(&self) -> WorkerLease {
        self.worker
    }

    /// Clones the private process-local rvoip route identifier.
    #[must_use]
    pub fn connection_id(&self) -> ConnectionId {
        self.connection_id.clone()
    }
}

/// Service-layer error with safe HTTP mapping semantics.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CallServiceError {
    /// Authentication, expiry, scope, or tenant failure.
    #[error(transparent)]
    Principal(#[from] ApiPrincipalError),
    /// Public cryptographic/header input failure.
    #[error(transparent)]
    Crypto(#[from] super::ControlCryptoError),
    /// Durable state or repository failure.
    #[error(transparent)]
    Repository(#[from] RepositoryError),
    /// Placement capacity was exhausted.
    #[error("worker capacity exhausted")]
    CapacityExceeded,
    /// Placement or attachment-profile lookup is unavailable.
    #[error("call service dependency unavailable")]
    DependencyUnavailable,
    /// No configured signaling principal can consume an inbound leg.
    #[error("inbound leg has no configured attachment principal")]
    AttachmentPrincipalUnresolved,
    /// The requested provider remains readable in persisted state but cannot
    /// be selected for new work in this release.
    #[error("provider control is deferred beyond Bridgefu 1.0")]
    ProviderDeferred,
    /// The selected leg/target pair has no authoritative transfer mechanism.
    #[error("the selected leg does not support this transfer target")]
    UnsupportedCapability,
    /// Request violated a service boundary invariant.
    #[error("invalid call request: {0}")]
    InvalidInput(&'static str),
    /// Current durable state cannot perform the requested operation.
    #[error("call state does not allow this operation")]
    InvalidTransition,
}

/// Complete signaling proof presented by an inbound rvoip connection.
///
/// Sensitive fields are private so callers cannot accidentally derive a
/// verbose `Debug` representation containing the bearer or principal. The
/// request intentionally owns the optional routing token so the service can
/// zeroize it on every return path.
pub struct InboundAttachmentRequest {
    principal: AuthenticatedPrincipal,
    routing_token: Option<String>,
    transport: AttachmentTransport,
    worker: WorkerLease,
    connection_id: ConnectionId,
}

impl InboundAttachmentRequest {
    /// Creates one complete inbound signaling proof request.
    #[must_use]
    pub fn new(
        principal: AuthenticatedPrincipal,
        routing_token: Option<String>,
        transport: AttachmentTransport,
        worker: WorkerLease,
        connection_id: ConnectionId,
    ) -> Self {
        Self {
            principal,
            routing_token,
            transport,
            worker,
            connection_id,
        }
    }
}

impl fmt::Debug for InboundAttachmentRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InboundAttachmentRequest")
            .field("principal", &"[redacted]")
            .field(
                "routing_token",
                &self.routing_token.as_ref().map(|_| "[redacted]"),
            )
            .field("transport", &self.transport)
            .field("worker", &self.worker)
            .field("connection_id", &self.connection_id)
            .finish()
    }
}

impl Drop for InboundAttachmentRequest {
    fn drop(&mut self) {
        if let Some(token) = &mut self.routing_token {
            token.zeroize();
        }
    }
}

/// Successful atomic attachment consumption and signaling transition.
#[derive(Clone, Eq, PartialEq)]
pub struct InboundAttachmentResult {
    /// Durable rvoip connection ownership binding.
    pub binding: ConnectionBinding,
    /// Atomic state-machine commit that moved the exact leg generation to signaling.
    pub commit: CommandCommitView,
}

impl fmt::Debug for InboundAttachmentResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InboundAttachmentResult")
            .field("call_id", &self.commit.call.aggregate.id())
            .field("binding", &self.binding)
            .field("aggregate_version", &self.commit.call.aggregate.version())
            .finish()
    }
}

/// Public, oracle-resistant result of inbound attachment admission.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum InboundAttachmentError {
    /// Any missing, malformed, stale, replayed, conflicting, or mismatched proof.
    #[error("attachment proof rejected")]
    ProofRejected,
    /// The durable repository could not complete the proof transaction.
    #[error("attachment proof service unavailable")]
    Unavailable,
}

/// Authenticated transaction boundary used by HTTP and future command transports.
pub struct CallService {
    repository: Arc<dyn CallServiceRepository>,
    placement: Arc<dyn WorkerPlacement>,
    attachment_principals: Arc<dyn AttachmentPrincipalResolver>,
    crypto: CallServiceCrypto,
    clock: Arc<dyn CallServiceClock>,
    timeouts: CallTimeoutPolicy,
}

impl fmt::Debug for CallService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallService")
            .field("repository", &"[configured]")
            .field("placement", &"[configured]")
            .field("attachment_principals", &"[configured]")
            .field("crypto", &self.crypto)
            .field("clock", &"[configured]")
            .field("timeouts", &self.timeouts)
            .finish()
    }
}

impl CallService {
    /// Creates an authenticated service over a durable repository.
    #[must_use]
    pub fn new(
        repository: Arc<dyn CallServiceRepository>,
        placement: Arc<dyn WorkerPlacement>,
        attachment_principals: Arc<dyn AttachmentPrincipalResolver>,
        crypto: CallServiceCrypto,
        clock: Arc<dyn CallServiceClock>,
        timeouts: CallTimeoutPolicy,
    ) -> Self {
        Self {
            repository,
            placement,
            attachment_principals,
            crypto,
            clock,
            timeouts,
        }
    }

    /// Validates and atomically consumes one inbound signaling attachment.
    ///
    /// Every proof mismatch deliberately collapses to
    /// [`InboundAttachmentError::ProofRejected`]. Only a true repository
    /// availability failure remains distinguishable. The complete rvoip
    /// principal is validated before the first await, then its expiry and the
    /// candidate token expiry are observed again after inspection. Their
    /// absolute deadlines are also enforced against authoritative time inside
    /// the atomic binding transaction.
    pub async fn consume_inbound_attachment(
        &self,
        mut request: InboundAttachmentRequest,
    ) -> Result<InboundAttachmentResult, InboundAttachmentError> {
        // Consume the owned bearer first so even principal-validation failures
        // take the parser's guaranteed zeroizing path.
        let token_digest = request
            .routing_token
            .take()
            .ok_or(InboundAttachmentError::ProofRejected)
            .and_then(|token| {
                digest_presented_attachment_token(token)
                    .map_err(|_| InboundAttachmentError::ProofRejected)
            })?;
        let principal = ApiPrincipal::new(request.principal.clone(), self.clock.now())
            .map_err(|_| InboundAttachmentError::ProofRejected)?;
        let tenant = principal.tenant().clone();
        let principal_fingerprint = self.crypto.principal_fingerprint(&principal);
        let command_id = CommandId::new();

        // Two valid legs of the same call can arrive concurrently. Their
        // opaque attachment candidates necessarily observe the same aggregate
        // version, so one atomic consume may lose the optimistic-version race
        // even though its proof remains valid. Re-inspect a small bounded
        // number of times using the already-digested token; every attempt
        // rechecks both absolute expiries after the database await. The stable
        // command ID preserves exact replay if a backend loses a response.
        const MAX_VERSION_RACE_ATTEMPTS: usize = 4;
        for attempt in 0..MAX_VERSION_RACE_ATTEMPTS {
            let inspected_at = self.clock.now();
            if principal.authenticated().is_expired_at(inspected_at) {
                return Err(InboundAttachmentError::ProofRejected);
            }
            let candidate = self
                .repository
                .inspect_inbound_attachment(AttachmentLookup {
                    token_digest,
                    tenant_id: tenant.clone(),
                    transport: request.transport,
                    principal_fingerprint,
                    worker: request.worker,
                    at: inspected_at,
                })
                .await
                .map_err(map_inbound_attachment_repository_error)?;

            // The inspection await is an attacker-controlled delay at a remote
            // database boundary. Never reuse its pre-await time observation.
            let consume_at = self.clock.now();
            if principal.authenticated().is_expired_at(consume_at)
                || candidate.expires_at() <= consume_at
            {
                return Err(InboundAttachmentError::ProofRejected);
            }
            let leg_id = candidate.leg_id();
            let binding_generation = candidate.binding_generation();
            let command = if candidate.purpose() == AttachmentPurpose::ProviderMedia {
                CallCommand::ProviderMediaAttached {
                    at: consume_at,
                    leg_id,
                    binding_generation,
                }
            } else {
                CallCommand::SetLegState {
                    at: consume_at,
                    leg_id,
                    binding_generation,
                    state: LegState::Signaling,
                    failure: None,
                }
            };
            match self
                .repository
                .consume_inbound_attachment(AttachmentConsume {
                    candidate,
                    command_id,
                    command,
                    connection_id: request.connection_id.clone(),
                    principal_fingerprint,
                    principal_expires_at: principal.authenticated().expires_at,
                    at: consume_at,
                })
                .await
            {
                Ok(consumed) => {
                    return Ok(InboundAttachmentResult {
                        binding: consumed.binding,
                        commit: consumed.commit,
                    });
                }
                Err(RepositoryError::VersionConflict)
                    if attempt + 1 < MAX_VERSION_RACE_ATTEMPTS =>
                {
                    tokio::task::yield_now().await;
                }
                Err(RepositoryError::VersionConflict) => {
                    return Err(InboundAttachmentError::Unavailable);
                }
                Err(error) => return Err(map_inbound_attachment_repository_error(error)),
            }
        }
        unreachable!("bounded attachment consume loop always returns")
    }

    /// Commits one worker-internal lifecycle observation against the exact
    /// durable rvoip connection binding.
    ///
    /// This is intentionally not a tenant-facing control API. The execution
    /// supervisor supplies the retained command ID/version and current worker
    /// fence so retries are exact and delayed events cannot target a rotated
    /// leg.
    pub async fn commit_bound_connection_state(
        &self,
        request: BoundConnectionStateCommit,
    ) -> Result<ServiceCommandOutcome, CallServiceError> {
        Ok(self
            .repository
            .commit_bound_connection_state(request)
            .await?)
    }

    /// Reconciles one claimed provider callback through the service-managed
    /// transaction boundary. The execution supervisor supplies the exact
    /// retained request on every ambiguous retry.
    pub async fn reconcile_provider_event(
        &self,
        request: ProviderEventReconciliationTransaction,
    ) -> Result<ProviderEventReconciliationOutcome, CallServiceError> {
        Ok(self.repository.reconcile_provider_event(request).await?)
    }

    /// Reconstructs one hidden provider-media bearer inside its owned
    /// `StartLeg` operation. The descriptor remains digest-only at rest and
    /// the returned wrapper redacts and zeroizes its raw bytes.
    pub(crate) fn provider_media_attachment_token(
        &self,
        stored: &StoredServiceCall,
        leg_id: LegId,
    ) -> Result<ProviderMediaAttachmentToken, CallServiceError> {
        let leg = stored
            .call
            .aggregate
            .leg(leg_id)
            .filter(|leg| {
                leg.signaling_initiator() == SignalingInitiator::Bridgefu
                    && leg.kind() == crate::call_engine::LegKind::Telnyx
            })
            .ok_or(CallServiceError::InvalidInput(
                "provider media attachment requires a Bridgefu-initiated Telnyx leg",
            ))?;
        self.provider_media_attachment_token_for_generation(
            stored,
            leg_id,
            leg.binding_generation(),
        )
    }

    /// Reconstructs the hidden provider-media bearer for an exact ordinary or
    /// pending replacement generation.
    pub(crate) fn provider_media_attachment_token_for_generation(
        &self,
        stored: &StoredServiceCall,
        leg_id: LegId,
        binding_generation: BindingGeneration,
    ) -> Result<ProviderMediaAttachmentToken, CallServiceError> {
        let mut descriptors = stored.attachments.iter().filter(|descriptor| {
            descriptor.leg_id == leg_id
                && descriptor.binding_generation == binding_generation
                && descriptor.purpose == AttachmentPurpose::ProviderMedia
                && descriptor.transport == AttachmentTransport::Sip
        });
        let descriptor = descriptors
            .next()
            .ok_or(CallServiceError::DependencyUnavailable)?;
        if descriptors.next().is_some() || descriptor.expires_at <= self.clock.now() {
            return Err(CallServiceError::DependencyUnavailable);
        }
        let issued_at = descriptor
            .expires_at
            .checked_sub_signed(chrono::Duration::seconds(
                super::ATTACHMENT_TOKEN_TTL_SECONDS,
            ))
            .ok_or(CallServiceError::DependencyUnavailable)?;
        let token = self.crypto.attachment_token(AttachmentTokenContext {
            tenant: stored.call.aggregate.tenant_id(),
            call_id: stored.call.aggregate.id(),
            leg_id,
            generation: descriptor.binding_generation,
            transport: AttachmentTransport::Sip,
            purpose: AttachmentPurpose::ProviderMedia,
            worker: stored.call.assignment.lease,
            principal: descriptor.expected_principal,
            created_at: issued_at,
        })?;
        if token.digest != descriptor.token_digest || token.expires_at != descriptor.expires_at {
            return Err(CallServiceError::DependencyUnavailable);
        }
        Ok(ProviderMediaAttachmentToken::new(
            token.expose_secret().to_owned(),
        ))
    }

    /// Arms or refreshes the media-idle timer from an authoritative, exact
    /// rvoip route observation. The configured policy is applied here so an
    /// executor cannot choose an unbounded deadline.
    pub async fn record_media_activity(
        &self,
        observation: MediaActivityObservation,
    ) -> Result<ServiceCommandOutcome, CallServiceError> {
        let due_at = checked_deadline(observation.at, self.timeouts.media_idle)?;
        Ok(self
            .repository
            .commit_media_activity(MediaActivityCommit {
                tenant_id: observation.tenant_id,
                call_id: observation.call_id,
                expected_version: observation.expected_version,
                command_id: observation.command_id,
                leg_id: observation.leg_id,
                binding_generation: observation.binding_generation,
                connection_id: observation.connection_id,
                activity_generation: observation.activity_generation,
                worker: observation.worker,
                at: observation.at,
                due_at,
            })
            .await?)
    }

    /// Authenticates ownership, reserves a worker, and creates both legs atomically.
    pub async fn create_call(
        &self,
        principal: &ApiPrincipal,
        key: &IdempotencyKey,
        input: CreateCallInput,
    ) -> Result<CallOperationResult<CreateCallView>, CallServiceError> {
        self.create_call_inner(principal, key, input, None).await
    }

    /// Creates a call from a server-owned named route while retaining the
    /// route selection and sanitized context in both idempotency and the
    /// durable execution plan. Public endpoint values remain supplied only by
    /// trusted configuration.
    pub async fn create_named_route_call(
        &self,
        principal: &ApiPrincipal,
        key: &IdempotencyKey,
        input: CreateCallInput,
        named_route: NamedRouteBinding,
    ) -> Result<CallOperationResult<CreateCallView>, CallServiceError> {
        if input.tenant_id.is_some() {
            return Err(CallServiceError::InvalidInput(
                "named routes inherit tenant ownership from the principal",
            ));
        }
        let remote = input
            .legs
            .iter()
            .filter(|leg| leg.resolved_signaling_initiator() == SignalingInitiator::Remote)
            .collect::<Vec<_>>();
        let destinations = input
            .legs
            .iter()
            .filter(|leg| leg.resolved_signaling_initiator() == SignalingInitiator::Bridgefu)
            .collect::<Vec<_>>();
        if remote.len() != 1
            || destinations.len() != 1
            || remote[0].direction != LegDirection::Inbound
            || remote[0].media_flow != MediaFlow::SendReceive
            || !matches!(
                &remote[0].endpoint,
                LegEndpointConfig::Sip(_) | LegEndpointConfig::WebRtc(_)
            )
        {
            return Err(CallServiceError::InvalidInput(
                "named route requires one full-duplex SIP or WebRTC remote ingress",
            ));
        }
        destinations[0].validate_named_route_destination()?;
        self.create_call_inner(principal, key, input, Some(named_route))
            .await
    }

    async fn create_call_inner(
        &self,
        principal: &ApiPrincipal,
        key: &IdempotencyKey,
        input: CreateCallInput,
        named_route: Option<NamedRouteBinding>,
    ) -> Result<CallOperationResult<CreateCallView>, CallServiceError> {
        let request_at = self.clock.now();
        let tenant =
            principal.resolve_tenant(input.tenant_id.as_deref(), CallScope::Create, request_at)?;
        if named_route.is_none() {
            principal.authorize(CallScope::ArbitraryDestination, request_at)?;
        }
        let owner_fingerprint = self.crypto.principal_fingerprint(principal);
        let mut transcript = create_transcript(&input.legs);
        if let Some(binding) = &named_route {
            push_named_route(&mut transcript, binding);
        }
        let operation = self.crypto.operation_idempotency(
            &tenant,
            owner_fingerprint,
            key,
            ServiceOperationKind::CreateCall,
            None,
            &transcript,
        );
        let replay = match self
            .repository
            .load_create_replay(
                &tenant,
                operation.key_digest,
                operation.request_digest,
                request_at,
            )
            .await
        {
            Ok(replay) => replay,
            Err(RepositoryError::IdempotencyConflict) => {
                if named_route.is_some() {
                    return Err(RepositoryError::IdempotencyConflict.into());
                }
                let Some(legacy_transcript) = legacy_create_transcript(&input.legs) else {
                    return Err(RepositoryError::IdempotencyConflict.into());
                };
                let legacy = self.crypto.operation_idempotency(
                    &tenant,
                    owner_fingerprint,
                    key,
                    ServiceOperationKind::CreateCall,
                    None,
                    &legacy_transcript,
                );
                self.repository
                    .load_create_replay(
                        &tenant,
                        legacy.key_digest,
                        legacy.request_digest,
                        request_at,
                    )
                    .await?
            }
            Err(error) => return Err(error.into()),
        };
        if let Some(stored) = replay {
            return self.create_view(stored, true);
        }
        reject_deferred_provider_legs(&input.legs)?;
        let setup_deadline = checked_deadline(request_at, self.timeouts.setup)?;
        let creation_deadline = if input.legs.iter().any(requested_leg_needs_attachment) {
            setup_deadline.min(checked_deadline(
                request_at,
                Duration::from_secs(
                    u64::try_from(super::ATTACHMENT_TOKEN_TTL_SECONDS)
                        .expect("positive attachment TTL fits u64"),
                ),
            )?)
        } else {
            setup_deadline
        };
        let aggregate = CallAggregate::new_with_semantics(
            tenant.clone(),
            input.legs.clone().map(|leg| LegSpec {
                direction: leg.direction,
                kind: leg.endpoint.kind(),
            }),
            input.legs.each_ref().map(RequestedLeg::semantics),
            request_at,
        )
        .map_err(|_| CallServiceError::InvalidInput("invalid two-leg media plan"))?;
        let amazon_connect_starts = input
            .legs
            .iter()
            .zip(aggregate.legs())
            .filter_map(|(requested, leg)| {
                requested
                    .amazon_connect_start
                    .clone()
                    .map(|spec| (leg.id(), spec))
            })
            .collect::<BTreeMap<_, _>>();
        let execution_legs = [
            LegExecutionSpec {
                leg_id: aggregate.legs()[0].id(),
                endpoint: input.legs[0].endpoint.clone(),
            },
            LegExecutionSpec {
                leg_id: aggregate.legs()[1].id(),
                endpoint: input.legs[1].endpoint.clone(),
            },
        ];
        let plan = match named_route {
            Some(binding) => CallExecutionPlan::new_with_named_route(
                &aggregate,
                execution_legs,
                owner_fingerprint,
                amazon_connect_starts,
                binding,
            )?,
            None => CallExecutionPlan::new_with_amazon_connect_starts(
                &aggregate,
                execution_legs,
                owner_fingerprint,
                amazon_connect_starts,
            )?,
        };

        let resolver_budget = match remaining_budget(self.clock.now(), creation_deadline) {
            Ok(remaining) => remaining,
            Err(error) => {
                return self
                    .replay_create_or_error(&tenant, &operation, error)
                    .await;
            }
        };
        let resolved_principals = match tokio::time::timeout(
            resolver_budget,
            self.resolve_attachment_principals(&tenant, &aggregate, &plan, owner_fingerprint),
        )
        .await
        {
            Ok(Ok(principals)) => principals,
            Ok(Err(error)) => {
                // A concurrent request may commit while profile resolution is
                // blocked or failing. Its durable receipt outranks dependency
                // health and contains the original attachment descriptors.
                return self
                    .replay_create_or_error(&tenant, &operation, error)
                    .await;
            }
            Err(_) => {
                return self
                    .replay_create_or_error(
                        &tenant,
                        &operation,
                        CallServiceError::DependencyUnavailable,
                    )
                    .await;
            }
        };
        let placement_at = self.clock.now();
        let placement_budget = match remaining_budget(placement_at, creation_deadline) {
            Ok(remaining) => remaining,
            Err(error) => {
                return self
                    .replay_create_or_error(&tenant, &operation, error)
                    .await;
            }
        };
        let workers = match tokio::time::timeout(
            placement_budget,
            self.placement.select_workers(&tenant, &plan, placement_at),
        )
        .await
        {
            Ok(Ok(worker)) => worker,
            Ok(Err(error)) => {
                // A concurrent request may have won after the preflight. Exact
                // retained results outrank current placement health/capacity.
                return self
                    .replay_create_or_error(&tenant, &operation, map_placement_error(error))
                    .await;
            }
            Err(_) => {
                return self
                    .replay_create_or_error(
                        &tenant,
                        &operation,
                        CallServiceError::DependencyUnavailable,
                    )
                    .await;
            }
        };
        if workers.is_empty() {
            return self
                .replay_create_or_error(&tenant, &operation, CallServiceError::CapacityExceeded)
                .await;
        }
        if workers.len() > MAX_WORKER_CANDIDATES
            || workers
                .iter()
                .enumerate()
                .any(|(index, worker)| workers[..index].contains(worker))
        {
            return self
                .replay_create_or_error(
                    &tenant,
                    &operation,
                    CallServiceError::DependencyUnavailable,
                )
                .await;
        }
        let commit_at = self.clock.now();
        if let Err(error) = remaining_budget(commit_at, creation_deadline) {
            return self
                .replay_create_or_error(&tenant, &operation, error)
                .await;
        }
        let command = CallCommand::StartConnecting {
            at: commit_at,
            setup_deadline,
        };
        let decided = aggregate
            .decide(command.clone())
            .map_err(|_| CallServiceError::InvalidTransition)?;
        let mut candidates = Vec::with_capacity(workers.len());
        for worker in workers {
            candidates.push(ServiceCreateCandidate {
                worker,
                attachments: self.attachment_issues(
                    &tenant,
                    decided.aggregate(),
                    &resolved_principals,
                    worker,
                    request_at,
                )?,
            });
        }
        let selected = candidates.remove(0);
        let outcome = self
            .repository
            .create_with_plan(ServiceCreateTransaction {
                create: crate::call_engine::CreateCall {
                    initial: aggregate,
                    command_id: CommandId::new(),
                    command,
                    worker: selected.worker,
                    idempotency_key: operation.key_digest,
                    request_digest: operation.request_digest,
                    attachments: selected.attachments,
                    at: commit_at,
                },
                plan,
                alternatives: candidates,
            })
            .await
            .map_err(|error| match error {
                RepositoryError::WorkerCapabilityUnavailable => {
                    CallServiceError::UnsupportedCapability
                }
                error => CallServiceError::Repository(error),
            })?;
        let (stored, replayed) = match outcome {
            ServiceCreateOutcome::Created(stored) => (stored, false),
            ServiceCreateOutcome::Replayed(stored) => (stored, true),
        };
        self.create_view(stored, replayed)
    }

    async fn replay_create_or_error(
        &self,
        tenant: &TenantId,
        operation: &OperationIdempotency,
        error: CallServiceError,
    ) -> Result<CallOperationResult<CreateCallView>, CallServiceError> {
        let observed_at = self.clock.now();
        if let Some(stored) = self
            .repository
            .load_create_replay(
                tenant,
                operation.key_digest,
                operation.request_digest,
                observed_at,
            )
            .await?
        {
            self.create_view(stored, true)
        } else {
            Err(error)
        }
    }

    /// Loads only a call owned by the authenticated tenant.
    pub async fn get_call(
        &self,
        principal: &ApiPrincipal,
        call_id: CallId,
        input: GetCallInput,
    ) -> Result<CallView, CallServiceError> {
        let tenant = principal.resolve_tenant(
            input.tenant_id.as_deref(),
            CallScope::Read,
            self.clock.now(),
        )?;
        let stored = self.repository.load_service_call(&tenant, call_id).await?;
        Ok(CallView::from_stored(&stored))
    }

    /// Resolves one tenant-owned, connected logical leg to its exact current
    /// process-local media binding.
    ///
    /// This is the only control-plane path that may reveal the opaque rvoip
    /// route to another in-process component. It verifies tenant/scope,
    /// worker pinning, lifecycle state, and binding generation after the
    /// authoritative repository read. A disconnected, unbound, or rotated
    /// leg fails closed and cannot fall back to legacy media lookup.
    pub async fn resolve_broadcast_source(
        &self,
        principal: &ApiPrincipal,
        call_id: CallId,
        leg_id: LegId,
        requested_tenant: Option<&str>,
        worker: WorkerLease,
    ) -> Result<BroadcastSourceBinding, CallServiceError> {
        let source = self
            .resolve_assigned_broadcast_source(principal, call_id, leg_id, requested_tenant)
            .await?;
        if source.worker != worker {
            return Err(CallServiceError::DependencyUnavailable);
        }
        Ok(source)
    }

    /// Resolves a connected source together with its authoritative worker
    /// assignment. Split gateways use this to enqueue a durable command; only
    /// the returned worker may later reveal/use the private connection route.
    pub async fn resolve_assigned_broadcast_source(
        &self,
        principal: &ApiPrincipal,
        call_id: CallId,
        leg_id: LegId,
        requested_tenant: Option<&str>,
    ) -> Result<BroadcastSourceBinding, CallServiceError> {
        let tenant =
            principal.resolve_tenant(requested_tenant, CallScope::Read, self.clock.now())?;
        let stored = self.repository.load_service_call(&tenant, call_id).await?;
        // The repository boundary can stall until after a credential expires.
        principal.authorize(CallScope::Read, self.clock.now())?;
        if stored.call.assignment.released_at.is_some() {
            return Err(CallServiceError::DependencyUnavailable);
        }
        let leg = stored
            .call
            .aggregate
            .leg(leg_id)
            .ok_or(CallServiceError::InvalidInput(
                "broadcast source leg does not belong to call",
            ))?;
        if leg.state() != LegState::Connected {
            return Err(CallServiceError::InvalidTransition);
        }
        let binding = stored
            .call
            .bindings
            .get(&leg_id)
            .filter(|binding| {
                binding.leg_id == leg_id && binding.binding_generation == leg.binding_generation()
            })
            .ok_or(CallServiceError::InvalidTransition)?;
        Ok(BroadcastSourceBinding {
            tenant_id: tenant,
            call_id,
            leg_id,
            binding_generation: binding.binding_generation,
            connection_id: binding.connection_id.clone(),
            worker: stored.call.assignment.lease,
        })
    }

    /// Starts durable peer teardown; no provider or signaling I/O occurs inline.
    pub async fn hangup_call(
        &self,
        principal: &ApiPrincipal,
        call_id: CallId,
        key: &IdempotencyKey,
        input: CallMutationInput,
    ) -> Result<CallOperationResult<CallView>, CallServiceError> {
        let at = self.clock.now();
        let tenant = principal.resolve_tenant(input.tenant_id.as_deref(), CallScope::Hangup, at)?;
        let stored = self.repository.load_service_call(&tenant, call_id).await?;
        let principal_fingerprint = self.crypto.principal_fingerprint(principal);
        let operation = self.operation(
            &tenant,
            principal_fingerprint,
            key,
            ServiceOperationKind::HangupCall,
            call_id,
            CanonicalRequestTranscript::new(),
        );
        let command = CallCommand::BeginEnding {
            at,
            ending_deadline: Some(checked_deadline(at, self.timeouts.ending)?),
            reason: StopLegReason::Requested,
        };
        self.commit_state_command(stored, command, Vec::new(), operation)
            .await
    }

    /// Starts a durable transfer and persists its typed target beside the effect.
    pub async fn transfer_call(
        &self,
        principal: &ApiPrincipal,
        call_id: CallId,
        key: &IdempotencyKey,
        input: TransferCallInput,
    ) -> Result<CallOperationResult<CallView>, CallServiceError> {
        let at = self.clock.now();
        let tenant =
            principal.resolve_tenant(input.tenant_id.as_deref(), CallScope::Transfer, at)?;
        principal.authorize(CallScope::ArbitraryDestination, at)?;
        let mut transcript = CanonicalRequestTranscript::new();
        transcript.push_bytes(input.target_leg_id.as_uuid().as_bytes());
        push_transfer_target(&mut transcript, &input.target);
        let operation = self.operation(
            &tenant,
            self.crypto.principal_fingerprint(principal),
            key,
            ServiceOperationKind::TransferCall,
            call_id,
            transcript,
        );
        if let Some(view) = self
            .repository
            .load_service_command_replay(
                &tenant,
                call_id,
                operation.key_digest,
                operation.request_digest,
                operation.operation,
                at,
            )
            .await?
        {
            return Ok(CallOperationResult {
                value: CallView::from_aggregate(&view.command.call.aggregate),
                replayed: true,
            });
        }
        reject_deferred_provider_transfer(&input.target)?;
        input.target.validate()?;
        let stored = self.repository.load_service_call(&tenant, call_id).await?;
        let target_leg = stored.call.aggregate.leg(input.target_leg_id).ok_or(
            CallServiceError::InvalidInput("transfer target leg does not belong to call"),
        )?;
        if !matches!(target_leg.state(), LegState::Connected | LegState::Held) {
            return Err(CallServiceError::InvalidTransition);
        }
        let endpoint = stored
            .plan
            .legs
            .iter()
            .find(|leg| leg.leg_id == input.target_leg_id)
            .map(|leg| &leg.endpoint)
            .ok_or(CallServiceError::InvalidTransition)?;
        ensure_transfer_capability(endpoint, &input.target)?;
        let target_binding_generation = target_leg.binding_generation();
        let command = CallCommand::BeginTransfer {
            at,
            transfer_deadline: checked_deadline(at, self.timeouts.transfer)?,
        };
        self.commit_state_command(
            stored,
            command,
            vec![ServiceEffectPayloadInput {
                // `BeginTransfer` emits ScheduleDeadline followed by ExecuteTransfer.
                // The repository validates this semantic mapping before persistence.
                ordinal: 1,
                payload: ServiceEffectPayload::Transfer {
                    target_leg_id: input.target_leg_id,
                    target_binding_generation,
                    target: input.target,
                },
            }],
            operation,
        )
        .await
    }

    /// Starts a durable make-before-break replacement of one stable logical
    /// leg. `destination` must come from trusted named-route configuration;
    /// the public request carries only its route ID.
    pub async fn replace_leg(
        &self,
        principal: &ApiPrincipal,
        call_id: CallId,
        leg_id: LegId,
        key: &IdempotencyKey,
        input: ReplaceLegInput,
        destination: RequestedLeg,
        replacement_route: NamedRouteBinding,
    ) -> Result<CallOperationResult<CallView>, CallServiceError> {
        let at = self.clock.now();
        let tenant =
            principal.resolve_tenant(input.tenant_id.as_deref(), CallScope::Transfer, at)?;
        destination.validate_named_route_destination()?;
        replacement_route
            .validate_replacement_destination(&input.route_id, &destination.endpoint)?;

        let mut transcript = CanonicalRequestTranscript::new();
        transcript.push_bytes(leg_id.as_uuid().as_bytes());
        transcript.push_str("bridgefu.leg-replacement.v2");
        push_replacement_route(&mut transcript, &replacement_route);
        let destination_bytes = serde_json::to_vec(&destination)
            .map_err(|_| CallServiceError::InvalidInput("invalid replacement destination"))?;
        transcript.push_bytes(&destination_bytes);
        let principal_fingerprint = self.crypto.principal_fingerprint(principal);
        let operation = self.operation(
            &tenant,
            principal_fingerprint,
            key,
            ServiceOperationKind::TransferCall,
            call_id,
            transcript,
        );
        if let Some(view) = self
            .repository
            .load_service_command_replay(
                &tenant,
                call_id,
                operation.key_digest,
                operation.request_digest,
                operation.operation,
                at,
            )
            .await?
        {
            return Ok(CallOperationResult {
                value: CallView::from_aggregate(&view.command.call.aggregate),
                replayed: true,
            });
        }

        let stored = self.repository.load_service_call(&tenant, call_id).await?;
        if self.placement.requires_replacement_worker_guard()
            && !self
                .placement
                .allows_worker(stored.call.assignment.lease.worker_id)
        {
            return Err(CallServiceError::DependencyUnavailable);
        }
        if stored.call.aggregate.state() != crate::call_engine::CallState::Active
            || stored.call.aggregate.replacement().is_some()
        {
            return Err(CallServiceError::InvalidTransition);
        }
        let target = stored
            .call
            .aggregate
            .leg(leg_id)
            .ok_or(CallServiceError::InvalidInput(
                "replacement leg does not belong to call",
            ))?;
        if target.state() != LegState::Connected
            || target.signaling_initiator() != SignalingInitiator::Bridgefu
        {
            return Err(CallServiceError::InvalidTransition);
        }
        let previous_binding_generation = target.binding_generation();
        let pending_binding_generation = target
            .next_replacement_binding_generation()
            .map_err(|_| CallServiceError::InvalidTransition)?;
        let pending_kind = destination.endpoint.kind();
        let mut authorization_principal_fingerprint = principal_fingerprint;
        let mut attachments = Vec::new();
        if matches!(
            &destination.endpoint,
            LegEndpointConfig::Provider(ProviderEndpointConfig {
                provider: ProviderKind::Telnyx,
                ..
            })
        ) {
            let spec = LegExecutionSpec {
                leg_id,
                endpoint: destination.endpoint.clone(),
            };
            let provider_principal = tokio::time::timeout(
                self.timeouts.transfer,
                self.resolve_attachment_principal(&tenant, &spec, None, principal_fingerprint),
            )
            .await
            .map_err(|_| CallServiceError::DependencyUnavailable)??;
            authorization_principal_fingerprint = provider_principal;
            let token = self.crypto.attachment_token(AttachmentTokenContext {
                tenant: &tenant,
                call_id,
                leg_id,
                generation: pending_binding_generation,
                transport: AttachmentTransport::Sip,
                purpose: AttachmentPurpose::ProviderMedia,
                worker: stored.call.assignment.lease,
                principal: provider_principal,
                created_at: at,
            })?;
            attachments.push(AttachmentIssue {
                attachment_id: AttachmentId::new(),
                token_digest: token.digest,
                purpose: AttachmentPurpose::ProviderMedia,
                leg_id,
                binding_generation: pending_binding_generation,
                transport: AttachmentTransport::Sip,
                expected_principal: provider_principal,
                expires_at: token.expires_at,
            });
        }
        let command = CallCommand::BeginLegReplacement {
            at,
            leg_id,
            pending_kind,
            transfer_deadline: checked_deadline(at, self.timeouts.transfer)?,
        };
        self.commit_state_command_with_attachments(
            stored,
            command,
            vec![ServiceEffectPayloadInput {
                // UnbridgeMedia, ScheduleDeadline, then StartLegReplacement.
                ordinal: 2,
                payload: ServiceEffectPayload::LegReplacement {
                    leg_id,
                    previous_binding_generation,
                    pending_binding_generation,
                    endpoint: destination.endpoint,
                    amazon_connect_start: destination.amazon_connect_start,
                    route_id: input.route_id,
                    replacement_route: Some(replacement_route),
                    authorization_principal_fingerprint,
                },
            }],
            attachments,
            operation,
        )
        .await
    }

    /// Enqueues DTMF against the exact current connection binding and worker fence.
    pub async fn send_dtmf(
        &self,
        principal: &ApiPrincipal,
        call_id: CallId,
        key: &IdempotencyKey,
        input: DtmfCallInput,
    ) -> Result<CallOperationResult<DtmfAcceptedView>, CallServiceError> {
        let at = self.clock.now();
        let tenant = principal.resolve_tenant(input.tenant_id.as_deref(), CallScope::Dtmf, at)?;
        let stored = self.repository.load_service_call(&tenant, call_id).await?;
        let leg = stored
            .call
            .aggregate
            .leg(input.leg_id)
            .ok_or(CallServiceError::InvalidTransition)?;
        let sequence = DtmfSequence {
            digits: input.digits,
            duration_ms: input.duration_ms,
            gap_ms: input.gap_ms,
        };
        sequence.validate()?;
        let mut transcript = CanonicalRequestTranscript::new();
        transcript.push_bytes(input.leg_id.as_uuid().as_bytes());
        transcript.push_str(&sequence.digits);
        transcript.push_u64(u64::from(sequence.duration_ms));
        transcript.push_u64(u64::from(sequence.gap_ms));
        let operation = self.operation(
            &tenant,
            self.crypto.principal_fingerprint(principal),
            key,
            ServiceOperationKind::DtmfCall,
            call_id,
            transcript,
        );
        let outcome = self
            .repository
            .enqueue_control(ControlCommandTransaction {
                command_id: CommandId::new(),
                tenant_id: tenant,
                call_id,
                leg_id: input.leg_id,
                binding_generation: leg.binding_generation(),
                worker: stored.call.assignment.lease,
                intent: ControlIntent::Dtmf { sequence },
                at,
                operation_idempotency: Some(operation),
            })
            .await?;
        let (view, replayed) = match outcome {
            ControlCommandOutcome::Enqueued(view) => (view, false),
            ControlCommandOutcome::Replayed(view) => (view, true),
        };
        Ok(CallOperationResult {
            value: DtmfAcceptedView::from_control(&view),
            replayed,
        })
    }

    async fn commit_state_command(
        &self,
        stored: StoredServiceCall,
        command: CallCommand,
        effect_payloads: Vec<ServiceEffectPayloadInput>,
        operation: OperationIdempotency,
    ) -> Result<CallOperationResult<CallView>, CallServiceError> {
        self.commit_state_command_with_attachments(
            stored,
            command,
            effect_payloads,
            Vec::new(),
            operation,
        )
        .await
    }

    async fn commit_state_command_with_attachments(
        &self,
        stored: StoredServiceCall,
        command: CallCommand,
        effect_payloads: Vec<ServiceEffectPayloadInput>,
        attachments: Vec<AttachmentIssue>,
        operation: OperationIdempotency,
    ) -> Result<CallOperationResult<CallView>, CallServiceError> {
        let at = command.at();
        let guarded_replacement = matches!(&command, CallCommand::BeginLegReplacement { .. })
            && self.placement.requires_replacement_worker_guard();
        let request = ServiceCommandTransaction {
            command: crate::call_engine::CommandCommit {
                tenant_id: stored.call.aggregate.tenant_id().clone(),
                call_id: stored.call.aggregate.id(),
                expected_version: stored.call.aggregate.version(),
                command_id: CommandId::new(),
                command,
                worker: stored.call.assignment.lease,
                attachments,
                deadline_claim: None,
                at,
            },
            effect_payloads,
            operation_idempotency: Some(operation),
            bound_connection: None,
            media_activity: None,
            replacement_connection: None,
        };
        let outcome = if guarded_replacement {
            self.repository
                .commit_leg_replacement_with_worker_guard(request)
                .await?
        } else {
            self.repository.commit_with_effect_payloads(request).await?
        };
        let (view, replayed) = match outcome {
            ServiceCommandOutcome::Committed(view) => (view, false),
            ServiceCommandOutcome::Replayed(view) => (view, true),
        };
        Ok(CallOperationResult {
            value: CallView::from_aggregate(&view.command.call.aggregate),
            replayed,
        })
    }

    fn operation(
        &self,
        tenant: &TenantId,
        principal: PrincipalFingerprint,
        key: &IdempotencyKey,
        kind: ServiceOperationKind,
        call_id: CallId,
        transcript: CanonicalRequestTranscript,
    ) -> OperationIdempotency {
        self.crypto
            .operation_idempotency(tenant, principal, key, kind, Some(call_id), &transcript)
    }

    async fn resolve_attachment_principals(
        &self,
        tenant: &TenantId,
        aggregate: &CallAggregate,
        plan: &CallExecutionPlan,
        api_principal: PrincipalFingerprint,
    ) -> Result<[Option<PrincipalFingerprint>; 2], CallServiceError> {
        let mut resolved = [None, None];
        for (index, spec) in plan.legs.iter().enumerate() {
            let leg = aggregate
                .leg(spec.leg_id)
                .ok_or(CallServiceError::InvalidInput(
                    "execution leg is outside call",
                ))?;
            if !leg_needs_attachment(leg) {
                continue;
            }
            resolved[index] = Some(
                self.resolve_attachment_principal(tenant, spec, plan.named_route(), api_principal)
                    .await?,
            );
        }
        Ok(resolved)
    }

    async fn resolve_attachment_principal(
        &self,
        tenant: &TenantId,
        spec: &LegExecutionSpec,
        named_route: Option<&NamedRouteBinding>,
        api_principal: PrincipalFingerprint,
    ) -> Result<PrincipalFingerprint, CallServiceError> {
        if let Some(principal) = self
            .attachment_principals
            .resolve_principal(AttachmentPrincipalRequest {
                tenant,
                leg: spec,
                named_route,
                api_principal,
            })
            .await
            .map_err(|_| CallServiceError::DependencyUnavailable)?
        {
            return Ok(principal);
        }
        let configured = self
            .attachment_principals
            .resolve_authenticated_principal(AttachmentPrincipalRequest {
                tenant,
                leg: spec,
                named_route,
                api_principal,
            })
            .await
            .map_err(|_| CallServiceError::DependencyUnavailable)?
            .ok_or(CallServiceError::AttachmentPrincipalUnresolved)?;
        let configured = ApiPrincipal::new(configured, self.clock.now())
            .map_err(|_| CallServiceError::AttachmentPrincipalUnresolved)?;
        if configured.tenant() != tenant {
            return Err(CallServiceError::AttachmentPrincipalUnresolved);
        }
        Ok(self.crypto.principal_fingerprint(&configured))
    }

    fn attachment_issues(
        &self,
        tenant: &TenantId,
        aggregate: &CallAggregate,
        principals: &[Option<PrincipalFingerprint>; 2],
        worker: WorkerLease,
        created_at: DateTime<Utc>,
    ) -> Result<Vec<AttachmentIssue>, CallServiceError> {
        let mut attachments = Vec::new();
        for (index, leg) in aggregate.legs().iter().enumerate() {
            let Some(principal) = principals[index] else {
                continue;
            };
            let transport = attachment_transport(leg.kind());
            let purpose = attachment_purpose(leg);
            let token = self.crypto.attachment_token(AttachmentTokenContext {
                tenant,
                call_id: aggregate.id(),
                leg_id: leg.id(),
                generation: leg.binding_generation(),
                transport,
                purpose,
                worker,
                principal,
                created_at,
            })?;
            attachments.push(AttachmentIssue {
                attachment_id: AttachmentId::new(),
                token_digest: token.digest,
                purpose,
                leg_id: leg.id(),
                binding_generation: leg.binding_generation(),
                transport,
                expected_principal: principal,
                expires_at: token.expires_at,
            });
        }
        Ok(attachments)
    }

    fn create_view(
        &self,
        stored: StoredServiceCall,
        replayed: bool,
    ) -> Result<CallOperationResult<CreateCallView>, CallServiceError> {
        let tenant = stored.call.aggregate.tenant_id().clone();
        stored
            .plan
            .validate_against(&stored.call.aggregate)
            .map_err(|_| CallServiceError::DependencyUnavailable)?;
        let expected_attachment_count = stored
            .call
            .aggregate
            .legs()
            .iter()
            .filter(|leg| leg_needs_attachment(leg))
            .count();
        if stored.attachments.len() != expected_attachment_count {
            return Err(CallServiceError::DependencyUnavailable);
        }
        let mut view = CallView::from_stored(&stored);
        let mut attached_legs = BTreeSet::new();
        for descriptor in &stored.attachments {
            let leg = stored
                .call
                .aggregate
                .leg(descriptor.leg_id)
                .ok_or(CallServiceError::DependencyUnavailable)?;
            let transport = attachment_transport(leg.kind());
            let purpose = attachment_purpose(leg);
            if !leg_needs_attachment(leg)
                || descriptor.binding_generation != leg.binding_generation()
                || descriptor.transport != transport
                || descriptor.purpose != purpose
                || !attached_legs.insert(leg.id())
            {
                return Err(CallServiceError::DependencyUnavailable);
            }
            let token = self.crypto.attachment_token(AttachmentTokenContext {
                tenant: &tenant,
                call_id: stored.call.aggregate.id(),
                leg_id: leg.id(),
                generation: descriptor.binding_generation,
                transport,
                purpose,
                worker: stored.call.assignment.lease,
                principal: descriptor.expected_principal,
                created_at: stored.call.aggregate.created_at(),
            })?;
            if token.digest != descriptor.token_digest || token.expires_at != descriptor.expires_at
            {
                return Err(CallServiceError::DependencyUnavailable);
            }
            if purpose == AttachmentPurpose::PublicInbound {
                view.attach(leg.id(), AttachmentView::from_token(token, transport));
            }
        }
        Ok(CallOperationResult {
            value: CreateCallView { call: view },
            replayed,
        })
    }
}

fn map_placement_error(error: PlacementError) -> CallServiceError {
    match error {
        PlacementError::CapacityExceeded => CallServiceError::CapacityExceeded,
        PlacementError::UnsupportedCapability => CallServiceError::UnsupportedCapability,
        PlacementError::Unavailable => CallServiceError::DependencyUnavailable,
    }
}

fn map_inbound_attachment_repository_error(error: RepositoryError) -> InboundAttachmentError {
    match error {
        RepositoryError::Unavailable
        | RepositoryError::CapacityExceeded
        | RepositoryError::WorkerCapabilityUnavailable
        | RepositoryError::IdempotencyConflict
        | RepositoryError::ProviderEventConflict
        | RepositoryError::ProviderReferenceConflict
        | RepositoryError::StaleClaim
        | RepositoryError::CounterExhausted
        | RepositoryError::InvalidInput(_) => InboundAttachmentError::Unavailable,
        RepositoryError::NotFound
        | RepositoryError::StaleWorkerFence
        | RepositoryError::VersionConflict
        | RepositoryError::CommandConflict
        | RepositoryError::AttachmentRejected
        | RepositoryError::AttachmentConflict
        | RepositoryError::DomainRejected => InboundAttachmentError::ProofRejected,
    }
}

fn checked_deadline(
    at: DateTime<Utc>,
    duration: Duration,
) -> Result<DateTime<Utc>, CallServiceError> {
    if duration.is_zero() {
        return Err(CallServiceError::InvalidInput(
            "deadline duration must be positive",
        ));
    }
    let duration = chrono::Duration::from_std(duration)
        .map_err(|_| CallServiceError::InvalidInput("deadline duration is too large"))?;
    at.checked_add_signed(duration)
        .ok_or(CallServiceError::InvalidInput(
            "deadline is outside supported range",
        ))
}

fn remaining_budget(
    observed_at: DateTime<Utc>,
    deadline: DateTime<Utc>,
) -> Result<Duration, CallServiceError> {
    let remaining = deadline
        .signed_duration_since(observed_at)
        .to_std()
        .map_err(|_| CallServiceError::DependencyUnavailable)?;
    if remaining.is_zero() {
        Err(CallServiceError::DependencyUnavailable)
    } else {
        Ok(remaining)
    }
}

fn attachment_transport(kind: crate::call_engine::LegKind) -> AttachmentTransport {
    match kind {
        crate::call_engine::LegKind::Sip
        | crate::call_engine::LegKind::Twilio
        | crate::call_engine::LegKind::Telnyx
        | crate::call_engine::LegKind::Vonage => AttachmentTransport::Sip,
        crate::call_engine::LegKind::InteractiveWebRtc
        | crate::call_engine::LegKind::Whip
        | crate::call_engine::LegKind::Whep
        | crate::call_engine::LegKind::AmazonConnect => AttachmentTransport::WebRtc,
    }
}

fn requested_leg_needs_attachment(leg: &RequestedLeg) -> bool {
    leg.resolved_signaling_initiator() == SignalingInitiator::Remote
        || matches!(
            &leg.endpoint,
            LegEndpointConfig::Provider(ProviderEndpointConfig {
                provider: ProviderKind::Telnyx,
                ..
            })
        )
}

fn leg_needs_attachment(leg: &crate::call_engine::Leg) -> bool {
    leg.signaling_initiator() == SignalingInitiator::Remote
        || leg.kind() == crate::call_engine::LegKind::Telnyx
}

fn attachment_purpose(leg: &crate::call_engine::Leg) -> AttachmentPurpose {
    if leg.kind() == crate::call_engine::LegKind::Telnyx {
        AttachmentPurpose::ProviderMedia
    } else {
        AttachmentPurpose::PublicInbound
    }
}

fn create_transcript(legs: &[RequestedLeg; 2]) -> CanonicalRequestTranscript {
    let mut transcript = CanonicalRequestTranscript::new();
    for leg in legs {
        transcript.push_str(match leg.direction {
            LegDirection::Inbound => "inbound",
            LegDirection::Outbound => "outbound",
        });
        transcript.push_str(match leg.resolved_signaling_initiator() {
            SignalingInitiator::Bridgefu => "bridgefu_initiated",
            SignalingInitiator::Remote => "remote_initiated",
        });
        transcript.push_str(match leg.media_flow {
            MediaFlow::SendReceive => "send_receive",
            MediaFlow::SendOnly => "send_only",
            MediaFlow::ReceiveOnly => "receive_only",
            MediaFlow::Inactive => "inactive",
        });
        push_endpoint(&mut transcript, &leg.endpoint);
        match &leg.amazon_connect_start {
            Some(spec) => {
                transcript.push_str("amazon_connect_start");
                transcript.push_str(spec.profile());
                transcript.push_str(spec.instance_id());
                transcript.push_str(spec.contact_flow_id());
                transcript.push_str(spec.display_name());
                transcript.push_optional_str(spec.description());
                transcript.push_u64(
                    u64::try_from(spec.attributes().len())
                        .expect("bounded Amazon attribute count fits u64"),
                );
                for (name, value) in spec.attributes() {
                    transcript.push_str(name);
                    transcript.push_str(value);
                }
            }
            None => transcript.push_str("no_amazon_connect_start"),
        }
    }
    transcript
}

fn push_named_route(transcript: &mut CanonicalRequestTranscript, binding: &NamedRouteBinding) {
    transcript.push_str("bridgefu.named-route.v1");
    transcript.push_str(binding.route_id());
    match binding.context() {
        Some(context) => {
            transcript.push_str("context");
            transcript.push_str(&context.correlation_id);
            transcript.push_u64(
                u64::try_from(context.metadata.len())
                    .expect("bounded named-route metadata count fits u64"),
            );
            for (name, value) in &context.metadata {
                transcript.push_str(name);
                transcript.push_str(value);
            }
        }
        None => transcript.push_str("no_context"),
    }
}

/// Canonical replacement-route identity. Profile order in configuration is
/// irrelevant: the durable role/kind/ID/revision tuple is sorted before it is
/// hashed into command idempotency.
fn push_replacement_route(
    transcript: &mut CanonicalRequestTranscript,
    binding: &NamedRouteBinding,
) {
    transcript.push_str("bridgefu.leg-replacement.route.v1");
    transcript.push_str(binding.route_id());
    let mut profiles = binding.profiles().iter().collect::<Vec<_>>();
    profiles.sort_by(|left, right| {
        (left.role(), left.kind(), left.profile_id(), left.revision()).cmp(&(
            right.role(),
            right.kind(),
            right.profile_id(),
            right.revision(),
        ))
    });
    transcript.push_u64(u64::try_from(profiles.len()).expect("bounded profile count fits u64"));
    for profile in profiles {
        transcript.push_str(match profile.role() {
            NamedProfileRole::Ingress => "ingress",
            NamedProfileRole::Destination => "destination",
        });
        transcript.push_str(match profile.kind() {
            NamedProfileKind::VapiIngress => "vapi_ingress",
            NamedProfileKind::Sip => "sip",
            NamedProfileKind::WebRtc => "webrtc",
            NamedProfileKind::AmazonConnect => "amazon_connect",
            NamedProfileKind::Telnyx => "telnyx",
        });
        transcript.push_str(profile.profile_id());
        transcript.push_str(profile.revision());
    }
}

/// Reconstructs the exact pre-v3 request transcript only when every newly
/// introduced field resolves to its historical value. This is a read-only
/// replay fallback; all new receipts retain the current transcript.
fn legacy_create_transcript(legs: &[RequestedLeg; 2]) -> Option<CanonicalRequestTranscript> {
    if legs.iter().any(|leg| {
        leg.amazon_connect_start.is_some()
            || matches!(
                &leg.endpoint,
                LegEndpointConfig::Sip(SipEndpointConfig {
                    initial_context: SipInitialContextMode::Required,
                    ..
                })
            )
            || leg.resolved_signaling_initiator()
                != SignalingInitiator::legacy_default(leg.direction)
            || leg.media_flow != MediaFlow::SendReceive
    }) {
        return None;
    }
    let mut transcript = CanonicalRequestTranscript::new();
    for leg in legs {
        transcript.push_str(match leg.direction {
            LegDirection::Inbound => "inbound",
            LegDirection::Outbound => "outbound",
        });
        push_endpoint(&mut transcript, &leg.endpoint);
    }
    Some(transcript)
}

fn push_endpoint(transcript: &mut CanonicalRequestTranscript, endpoint: &LegEndpointConfig) {
    match endpoint {
        LegEndpointConfig::Sip(SipEndpointConfig {
            uri,
            initial_context,
        }) => {
            transcript.push_str("sip");
            transcript.push_optional_str(uri.as_deref());
            transcript.push_str(match initial_context {
                SipInitialContextMode::None => "initial_context_none",
                SipInitialContextMode::Required => "initial_context_required",
            });
        }
        LegEndpointConfig::WebRtc(WebRtcEndpointConfig { signaling_uri }) => {
            transcript.push_str("webrtc");
            transcript.push_optional_str(signaling_uri.as_deref());
        }
        LegEndpointConfig::Whip(WhipEndpointConfig { endpoint_uri }) => {
            transcript.push_str("whip");
            transcript.push_optional_str(endpoint_uri.as_deref());
        }
        LegEndpointConfig::Whep(WhepEndpointConfig { endpoint_uri }) => {
            transcript.push_str("whep");
            transcript.push_optional_str(endpoint_uri.as_deref());
        }
        LegEndpointConfig::AmazonConnect(AmazonConnectEndpointConfig {
            instance_id,
            contact_flow_id,
        }) => {
            transcript.push_str("amazon_connect");
            transcript.push_str(instance_id);
            transcript.push_str(contact_flow_id);
        }
        LegEndpointConfig::Provider(ProviderEndpointConfig {
            provider,
            account_profile,
            destination,
        }) => {
            transcript.push_str("provider");
            transcript.push_str(provider_label(*provider));
            transcript.push_str(account_profile);
            transcript.push_optional_str(destination.as_deref());
        }
    }
}

fn push_transfer_target(transcript: &mut CanonicalRequestTranscript, target: &TransferTarget) {
    match target {
        TransferTarget::Sip { uri } => {
            transcript.push_str("sip");
            transcript.push_str(uri);
        }
        TransferTarget::WebRtc { uri } => {
            transcript.push_str("webrtc");
            transcript.push_str(uri);
        }
        TransferTarget::AmazonConnect {
            instance_id,
            contact_flow_id,
        } => {
            transcript.push_str("amazon_connect");
            transcript.push_str(instance_id);
            transcript.push_str(contact_flow_id);
        }
        TransferTarget::Provider {
            provider,
            account_profile,
            destination,
        } => {
            transcript.push_str("provider");
            transcript.push_str(provider_label(*provider));
            transcript.push_str(account_profile);
            transcript.push_str(destination);
        }
    }
}

fn reject_deferred_provider_legs(legs: &[RequestedLeg; 2]) -> Result<(), CallServiceError> {
    if legs.iter().any(|leg| {
        matches!(
            &leg.endpoint,
            LegEndpointConfig::Provider(ProviderEndpointConfig {
                provider: ProviderKind::Twilio | ProviderKind::Vonage,
                ..
            })
        )
    }) {
        return Err(CallServiceError::ProviderDeferred);
    }
    Ok(())
}

fn reject_deferred_provider_transfer(target: &TransferTarget) -> Result<(), CallServiceError> {
    if matches!(
        target,
        TransferTarget::Provider {
            provider: ProviderKind::Twilio | ProviderKind::Vonage,
            ..
        }
    ) {
        return Err(CallServiceError::ProviderDeferred);
    }
    Ok(())
}

fn ensure_transfer_capability(
    endpoint: &LegEndpointConfig,
    target: &TransferTarget,
) -> Result<(), CallServiceError> {
    let supported = match (endpoint, target) {
        (LegEndpointConfig::Sip(_), TransferTarget::Sip { .. }) => true,
        (
            LegEndpointConfig::Provider(ProviderEndpointConfig {
                provider: ProviderKind::Telnyx,
                ..
            }),
            TransferTarget::Sip { .. },
        ) => true,
        (
            LegEndpointConfig::Provider(ProviderEndpointConfig {
                provider: ProviderKind::Telnyx,
                account_profile,
                ..
            }),
            TransferTarget::Provider {
                provider: ProviderKind::Telnyx,
                account_profile: target_profile,
                ..
            },
        ) => account_profile == target_profile,
        _ => false,
    };
    if supported {
        Ok(())
    } else {
        Err(CallServiceError::UnsupportedCapability)
    }
}

fn provider_label(provider: ProviderKind) -> &'static str {
    match provider {
        ProviderKind::Twilio => "twilio",
        ProviderKind::Telnyx => "telnyx",
        ProviderKind::Vonage => "vonage",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use chrono::TimeZone;
    use rvoip_auth_core::{AuthenticatedPrincipal, AuthenticationMethod};
    use rvoip_core::ids::ConnectionId;
    use rvoip_core::{CredentialKind, IdentityAssurance, Jwk};
    use sha2::{Digest, Sha256};

    use crate::call_engine::{
        AttachmentCandidate, AttachmentConsume, AttachmentLookup, AttachmentTokenDigest,
        BindingGeneration, CallRepository, CallState, CommandCommit, ConsumedAttachment,
        DeadlineKind, EffectId, IdempotencyKeyDigest, LegState, RegisterWorker, RequestDigest,
        WorkerId,
    };
    use crate::call_service::{
        ClaimedControlEffect, ControlCommandOutcome, ControlCommandTransaction,
        EffectResultOutcome, EffectResultReconciliation, NamedProfileBinding,
        OutboundConnectionBind, OutboundConnectionBindOutcome, StoredExternalReference,
        StoredServiceEffectPayload,
    };
    use crate::persistence::MemoryRepository;

    use super::*;

    #[derive(Debug)]
    struct TestClock(Mutex<DateTime<Utc>>);

    impl TestClock {
        fn new(at: DateTime<Utc>) -> Self {
            Self(Mutex::new(at))
        }

        fn set(&self, at: DateTime<Utc>) {
            *self.0.lock().unwrap() = at;
        }
    }

    impl CallServiceClock for TestClock {
        fn now(&self) -> DateTime<Utc> {
            *self.0.lock().unwrap()
        }
    }

    #[derive(Debug)]
    struct SwitchablePlacement {
        worker: WorkerLease,
        failure: Mutex<Option<PlacementError>>,
    }

    impl SwitchablePlacement {
        fn set_failure(&self, failure: Option<PlacementError>) {
            *self.failure.lock().unwrap() = failure;
        }
    }

    #[async_trait]
    impl WorkerPlacement for SwitchablePlacement {
        async fn select_workers(
            &self,
            _tenant: &TenantId,
            _plan: &CallExecutionPlan,
            _at: DateTime<Utc>,
        ) -> Result<Vec<WorkerLease>, PlacementError> {
            match *self.failure.lock().unwrap() {
                Some(error) => Err(error),
                None => Ok(vec![self.worker]),
            }
        }
    }

    #[derive(Debug, Default)]
    struct SwitchableAttachmentResolver(Mutex<bool>);

    impl SwitchableAttachmentResolver {
        fn set_unavailable(&self, unavailable: bool) {
            *self.0.lock().unwrap() = unavailable;
        }
    }

    #[async_trait]
    impl AttachmentPrincipalResolver for SwitchableAttachmentResolver {
        async fn resolve_principal(
            &self,
            request: AttachmentPrincipalRequest<'_>,
        ) -> Result<Option<PrincipalFingerprint>, AttachmentPrincipalResolverError> {
            if *self.0.lock().unwrap() {
                Err(AttachmentPrincipalResolverError::Unavailable)
            } else {
                Ok(Some(request.api_principal))
            }
        }
    }

    #[derive(Debug)]
    struct BarrierFailingResolver {
        entered: Arc<tokio::sync::Barrier>,
        release: Arc<tokio::sync::Barrier>,
    }

    #[async_trait]
    impl AttachmentPrincipalResolver for BarrierFailingResolver {
        async fn resolve_principal(
            &self,
            _request: AttachmentPrincipalRequest<'_>,
        ) -> Result<Option<PrincipalFingerprint>, AttachmentPrincipalResolverError> {
            self.entered.wait().await;
            self.release.wait().await;
            Err(AttachmentPrincipalResolverError::Unavailable)
        }
    }

    #[derive(Debug)]
    struct BarrierSuccessfulResolver {
        entered: Arc<tokio::sync::Barrier>,
        release: Arc<tokio::sync::Barrier>,
    }

    #[async_trait]
    impl AttachmentPrincipalResolver for BarrierSuccessfulResolver {
        async fn resolve_principal(
            &self,
            request: AttachmentPrincipalRequest<'_>,
        ) -> Result<Option<PrincipalFingerprint>, AttachmentPrincipalResolverError> {
            self.entered.wait().await;
            self.release.wait().await;
            Ok(Some(request.api_principal))
        }
    }

    #[derive(Debug)]
    struct BarrierPendingResolver {
        entered: Arc<tokio::sync::Barrier>,
    }

    #[async_trait]
    impl AttachmentPrincipalResolver for BarrierPendingResolver {
        async fn resolve_principal(
            &self,
            _request: AttachmentPrincipalRequest<'_>,
        ) -> Result<Option<PrincipalFingerprint>, AttachmentPrincipalResolverError> {
            self.entered.wait().await;
            std::future::pending().await
        }
    }

    #[derive(Debug)]
    struct BarrierSuccessfulPlacement {
        worker: WorkerLease,
        entered: Arc<tokio::sync::Barrier>,
        release: Arc<tokio::sync::Barrier>,
    }

    #[derive(Debug)]
    struct BlockingAttachmentRepository {
        inner: Arc<MemoryRepository>,
        clock: Arc<TestClock>,
        block_next_inspection: AtomicBool,
        concurrent_inspections_remaining: AtomicUsize,
        block_next_consumption: AtomicBool,
        unavailable: AtomicBool,
        inspection_entered: tokio::sync::Notify,
        inspection_release: tokio::sync::Notify,
        concurrent_inspection_barrier: tokio::sync::Barrier,
        consumption_entered: tokio::sync::Notify,
        consumption_release: tokio::sync::Notify,
    }

    impl BlockingAttachmentRepository {
        fn new(inner: Arc<MemoryRepository>, clock: Arc<TestClock>) -> Self {
            Self {
                inner,
                clock,
                block_next_inspection: AtomicBool::new(false),
                concurrent_inspections_remaining: AtomicUsize::new(0),
                block_next_consumption: AtomicBool::new(false),
                unavailable: AtomicBool::new(false),
                inspection_entered: tokio::sync::Notify::new(),
                inspection_release: tokio::sync::Notify::new(),
                concurrent_inspection_barrier: tokio::sync::Barrier::new(2),
                consumption_entered: tokio::sync::Notify::new(),
                consumption_release: tokio::sync::Notify::new(),
            }
        }

        fn block_next_inspection(&self) {
            self.block_next_inspection.store(true, Ordering::SeqCst);
        }

        fn synchronize_next_two_inspections(&self) {
            self.concurrent_inspections_remaining
                .store(2, Ordering::SeqCst);
        }

        async fn wait_until_inspection(&self) {
            self.inspection_entered.notified().await;
        }

        fn release_inspection(&self) {
            self.inspection_release.notify_one();
        }

        fn block_next_consumption(&self) {
            self.block_next_consumption.store(true, Ordering::SeqCst);
        }

        async fn wait_until_consumption(&self) {
            self.consumption_entered.notified().await;
        }

        fn release_consumption(&self) {
            self.consumption_release.notify_one();
        }

        fn set_unavailable(&self, unavailable: bool) {
            self.unavailable.store(unavailable, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl CallServiceRepository for BlockingAttachmentRepository {
        async fn inspect_inbound_attachment(
            &self,
            request: AttachmentLookup,
        ) -> Result<AttachmentCandidate, RepositoryError> {
            if self.unavailable.load(Ordering::SeqCst) {
                return Err(RepositoryError::Unavailable);
            }
            if self.block_next_inspection.swap(false, Ordering::SeqCst) {
                self.inspection_entered.notify_one();
                self.inspection_release.notified().await;
            }
            let candidate = self.inner.inspect_inbound_attachment(request).await?;
            if self
                .concurrent_inspections_remaining
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
            {
                self.concurrent_inspection_barrier.wait().await;
            }
            Ok(candidate)
        }

        async fn consume_inbound_attachment(
            &self,
            request: AttachmentConsume,
        ) -> Result<ConsumedAttachment, RepositoryError> {
            if self.block_next_consumption.swap(false, Ordering::SeqCst) {
                self.consumption_entered.notify_one();
                self.consumption_release.notified().await;
            }
            let authorization_at = self.clock.now();
            if request.candidate.expires_at() <= authorization_at
                || request
                    .principal_expires_at
                    .is_some_and(|expires_at| expires_at <= authorization_at)
            {
                return Err(RepositoryError::AttachmentRejected);
            }
            self.inner.consume_inbound_attachment(request).await
        }

        async fn commit_bound_connection_state(
            &self,
            request: BoundConnectionStateCommit,
        ) -> Result<ServiceCommandOutcome, RepositoryError> {
            self.inner.commit_bound_connection_state(request).await
        }

        async fn commit_media_activity(
            &self,
            request: MediaActivityCommit,
        ) -> Result<ServiceCommandOutcome, RepositoryError> {
            self.inner.commit_media_activity(request).await
        }

        async fn load_create_replay(
            &self,
            _tenant_id: &TenantId,
            _key_digest: IdempotencyKeyDigest,
            _request_digest: RequestDigest,
            _at: DateTime<Utc>,
        ) -> Result<Option<StoredServiceCall>, RepositoryError> {
            Err(RepositoryError::Unavailable)
        }

        async fn load_service_command_replay(
            &self,
            _tenant_id: &TenantId,
            _call_id: CallId,
            _key_digest: IdempotencyKeyDigest,
            _request_digest: RequestDigest,
            _operation: ServiceOperationKind,
            _at: DateTime<Utc>,
        ) -> Result<Option<crate::call_service::ServiceCommandView>, RepositoryError> {
            Err(RepositoryError::Unavailable)
        }

        async fn create_with_plan(
            &self,
            _request: ServiceCreateTransaction,
        ) -> Result<ServiceCreateOutcome, RepositoryError> {
            Err(RepositoryError::Unavailable)
        }

        async fn load_service_call(
            &self,
            _tenant_id: &TenantId,
            _call_id: CallId,
        ) -> Result<StoredServiceCall, RepositoryError> {
            Err(RepositoryError::Unavailable)
        }

        async fn commit_with_effect_payloads(
            &self,
            _request: ServiceCommandTransaction,
        ) -> Result<ServiceCommandOutcome, RepositoryError> {
            Err(RepositoryError::Unavailable)
        }

        async fn commit_leg_replacement_with_worker_guard(
            &self,
            _request: ServiceCommandTransaction,
        ) -> Result<ServiceCommandOutcome, RepositoryError> {
            Err(RepositoryError::Unavailable)
        }

        async fn load_effect_payload(
            &self,
            _tenant_id: &TenantId,
            _effect_id: EffectId,
        ) -> Result<Option<StoredServiceEffectPayload>, RepositoryError> {
            Err(RepositoryError::Unavailable)
        }

        async fn enqueue_control(
            &self,
            _request: ControlCommandTransaction,
        ) -> Result<ControlCommandOutcome, RepositoryError> {
            Err(RepositoryError::Unavailable)
        }

        async fn claim_control_effects(
            &self,
            _worker: WorkerLease,
            _at: DateTime<Utc>,
            _claim_ttl: Duration,
            _limit: usize,
        ) -> Result<Vec<ClaimedControlEffect>, RepositoryError> {
            Err(RepositoryError::Unavailable)
        }

        async fn bind_outbound_connection(
            &self,
            _request: OutboundConnectionBind,
        ) -> Result<OutboundConnectionBindOutcome, RepositoryError> {
            Err(RepositoryError::Unavailable)
        }

        async fn load_external_reference(
            &self,
            _tenant_id: &TenantId,
            _call_id: CallId,
            _leg_id: LegId,
        ) -> Result<Option<StoredExternalReference>, RepositoryError> {
            Err(RepositoryError::Unavailable)
        }

        async fn reconcile_effect_result(
            &self,
            _request: EffectResultReconciliation,
        ) -> Result<EffectResultOutcome, RepositoryError> {
            Err(RepositoryError::Unavailable)
        }

        async fn reconcile_provider_event(
            &self,
            _request: ProviderEventReconciliationTransaction,
        ) -> Result<ProviderEventReconciliationOutcome, RepositoryError> {
            Err(RepositoryError::Unavailable)
        }
    }

    #[async_trait]
    impl WorkerPlacement for BarrierSuccessfulPlacement {
        async fn select_workers(
            &self,
            _tenant: &TenantId,
            _plan: &CallExecutionPlan,
            _at: DateTime<Utc>,
        ) -> Result<Vec<WorkerLease>, PlacementError> {
            self.entered.wait().await;
            self.release.wait().await;
            Ok(vec![self.worker])
        }
    }

    fn at(second: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_900_000_000 + second, 0).unwrap()
    }

    fn test_worker_capabilities() -> BTreeSet<String> {
        [
            "sip",
            "webrtc",
            "sip_egress",
            "webrtc_egress",
            "amazon_connect",
            "telnyx",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    fn authenticated_principal(
        tenant: &str,
        subject: &str,
        expires_at: Option<DateTime<Utc>>,
    ) -> AuthenticatedPrincipal {
        AuthenticatedPrincipal {
            subject: subject.into(),
            tenant: Some(tenant.into()),
            scopes: vec!["*".into(), CallScope::ArbitraryDestination.as_str().into()],
            issuer: Some("test-issuer".into()),
            expires_at,
            method: AuthenticationMethod::Jwt,
            assurance: IdentityAssurance::Pseudonymous {
                ephemeral_key: Jwk(serde_json::json!({"kty": "test"})),
            },
        }
    }

    fn principal(tenant: &str) -> ApiPrincipal {
        ApiPrincipal::new(
            authenticated_principal(tenant, &format!("subject-{tenant}"), None),
            at(0),
        )
        .unwrap()
    }

    async fn harness(
        max_calls: usize,
    ) -> (
        Arc<MemoryRepository>,
        CallService,
        Arc<TestClock>,
        WorkerLease,
    ) {
        let repository = Arc::new(MemoryRepository::new());
        let clock = Arc::new(TestClock::new(at(0)));
        let worker = repository
            .register_worker(RegisterWorker {
                worker_id: WorkerId::new(),
                max_calls,
                capabilities: test_worker_capabilities(),
                at: at(0),
                lease_ttl: std::time::Duration::from_secs(300),
            })
            .await
            .unwrap()
            .lease;
        let service = CallService::new(
            repository.clone(),
            Arc::new(FixedWorkerPlacement::new(worker)),
            Arc::new(SamePrincipalAttachmentResolver),
            CallServiceCrypto::new(vec![0x61; 32]).unwrap(),
            clock.clone(),
            CallTimeoutPolicy::default(),
        );
        (repository, service, clock, worker)
    }

    fn generic_input() -> CreateCallInput {
        CreateCallInput {
            tenant_id: None,
            legs: [
                RequestedLeg {
                    direction: LegDirection::Inbound,
                    signaling_initiator: None,
                    media_flow: MediaFlow::SendReceive,
                    endpoint: LegEndpointConfig::Sip(SipEndpointConfig {
                        uri: None,
                        initial_context: Default::default(),
                    }),
                    amazon_connect_start: None,
                },
                RequestedLeg {
                    direction: LegDirection::Outbound,
                    signaling_initiator: None,
                    media_flow: MediaFlow::SendReceive,
                    endpoint: LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
                        signaling_uri: Some("wss://signal.example.test/session".into()),
                    }),
                    amazon_connect_start: None,
                },
            ],
        }
    }

    fn execution_plan_for(input: &CreateCallInput) -> CallExecutionPlan {
        let tenant = TenantId::parse("tenant-placement").unwrap();
        let aggregate = CallAggregate::new_with_semantics(
            tenant,
            input.legs.clone().map(|leg| LegSpec {
                direction: leg.direction,
                kind: leg.endpoint.kind(),
            }),
            input.legs.each_ref().map(RequestedLeg::semantics),
            at(0),
        )
        .unwrap();
        CallExecutionPlan::new(
            &aggregate,
            [
                LegExecutionSpec {
                    leg_id: aggregate.legs()[0].id(),
                    endpoint: input.legs[0].endpoint.clone(),
                },
                LegExecutionSpec {
                    leg_id: aggregate.legs()[1].id(),
                    endpoint: input.legs[1].endpoint.clone(),
                },
            ],
            PrincipalFingerprint::new([0x53; 32]),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn arbitrary_destinations_require_a_literal_advanced_scope() {
        let (_repository, service, _clock, _worker) = harness(2).await;
        let mut authenticated = authenticated_principal("tenant-a", "route-only", None);
        authenticated.scopes = vec![
            CallScope::Create.as_str().into(),
            CallScope::Transfer.as_str().into(),
        ];
        let route_only = ApiPrincipal::new(authenticated, at(0)).unwrap();

        assert!(matches!(
            service
                .create_call(
                    &route_only,
                    &IdempotencyKey::parse("raw-destination-denied").unwrap(),
                    generic_input(),
                )
                .await,
            Err(CallServiceError::Principal(
                ApiPrincipalError::MissingScope("calls:destinations:arbitrary")
            ))
        ));

        let named = service
            .create_named_route_call(
                &route_only,
                &IdempotencyKey::parse("named-destination-allowed").unwrap(),
                generic_input(),
                NamedRouteBinding::new("support", None).unwrap(),
            )
            .await
            .unwrap();
        assert!(!named.replayed);

        assert!(matches!(
            service
                .transfer_call(
                    &route_only,
                    named.value.call.call_id,
                    &IdempotencyKey::parse("raw-transfer-denied").unwrap(),
                    TransferCallInput {
                        tenant_id: None,
                        target_leg_id: named.value.call.legs[0].leg_id,
                        target: TransferTarget::Sip {
                            uri: "sip:queue@sip.example.test".into(),
                        },
                    },
                )
                .await,
            Err(CallServiceError::Principal(
                ApiPrincipalError::MissingScope("calls:destinations:arbitrary")
            ))
        ));
    }

    #[tokio::test]
    async fn placement_requires_one_worker_with_initiator_aware_capabilities() {
        let plan = execution_plan_for(&generic_input());
        assert_eq!(
            plan.required_worker_capabilities().unwrap(),
            BTreeSet::from(["sip".to_owned(), "webrtc_egress".to_owned()])
        );

        let repository = Arc::new(MemoryRepository::new());
        let sip_only = repository
            .register_worker(RegisterWorker {
                worker_id: WorkerId::new(),
                max_calls: 2,
                capabilities: BTreeSet::from(["sip".to_owned()]),
                at: at(0),
                lease_ttl: Duration::from_secs(300),
            })
            .await
            .unwrap()
            .lease;
        let egress_only = repository
            .register_worker(RegisterWorker {
                worker_id: WorkerId::new(),
                max_calls: 2,
                capabilities: BTreeSet::from(["webrtc_egress".to_owned()]),
                at: at(0),
                lease_ttl: Duration::from_secs(300),
            })
            .await
            .unwrap()
            .lease;
        let core: Arc<dyn CallRepository> = repository.clone();
        let placement = RepositoryWorkerPlacement::new(core);
        assert_eq!(
            placement
                .select_workers(&TenantId::parse("tenant-placement").unwrap(), &plan, at(1))
                .await
                .unwrap_err(),
            PlacementError::CapacityExceeded
        );

        let complete = repository
            .register_worker(RegisterWorker {
                worker_id: WorkerId::new(),
                max_calls: 2,
                capabilities: BTreeSet::from(["sip".to_owned(), "webrtc_egress".to_owned()]),
                at: at(0),
                lease_ttl: Duration::from_secs(300),
            })
            .await
            .unwrap()
            .lease;
        let core: Arc<dyn CallRepository> = repository;
        assert_eq!(
            RepositoryWorkerPlacement::new(Arc::clone(&core))
                .with_allowed_workers(BTreeSet::from([sip_only.worker_id, egress_only.worker_id,]))
                .select_workers(&TenantId::parse("tenant-placement").unwrap(), &plan, at(1),)
                .await
                .unwrap_err(),
            PlacementError::UnsupportedCapability
        );
        let selected = RepositoryWorkerPlacement::new(core)
            .with_allowed_workers(BTreeSet::from([complete.worker_id]))
            .select_workers(&TenantId::parse("tenant-placement").unwrap(), &plan, at(1))
            .await
            .unwrap();
        assert_eq!(selected, vec![complete]);
        assert!(!selected.contains(&sip_only));
        assert!(!selected.contains(&egress_only));
    }

    #[test]
    fn create_transcript_binds_sip_initial_context_policy() {
        let mut none = generic_input();
        none.legs[1].endpoint = LegEndpointConfig::Sip(SipEndpointConfig {
            uri: Some("sip:callee@voice.example.test".into()),
            initial_context: SipInitialContextMode::None,
        });
        let mut required = none.clone();
        required.legs[1].endpoint = LegEndpointConfig::Sip(SipEndpointConfig {
            uri: Some("sip:callee@voice.example.test".into()),
            initial_context: SipInitialContextMode::Required,
        });

        assert_ne!(
            create_transcript(&none.legs),
            create_transcript(&required.legs)
        );
        assert!(legacy_create_transcript(&none.legs).is_some());
        assert!(legacy_create_transcript(&required.legs).is_none());
    }

    fn two_inbound_input() -> CreateCallInput {
        CreateCallInput {
            tenant_id: None,
            legs: [
                RequestedLeg {
                    direction: LegDirection::Inbound,
                    signaling_initiator: None,
                    media_flow: MediaFlow::SendReceive,
                    endpoint: LegEndpointConfig::Sip(SipEndpointConfig {
                        uri: None,
                        initial_context: Default::default(),
                    }),
                    amazon_connect_start: None,
                },
                RequestedLeg {
                    direction: LegDirection::Inbound,
                    signaling_initiator: None,
                    media_flow: MediaFlow::SendReceive,
                    endpoint: LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
                        signaling_uri: None,
                    }),
                    amazon_connect_start: None,
                },
            ],
        }
    }

    fn token_digest(token: &str) -> AttachmentTokenDigest {
        let raw = URL_SAFE_NO_PAD.decode(token).unwrap();
        assert_eq!(raw.len(), 32);
        AttachmentTokenDigest::new(Sha256::digest(raw).into())
    }

    fn take_first_attachment(
        created: &mut CallOperationResult<CreateCallView>,
    ) -> (CallId, LegId, String, DateTime<Utc>) {
        let call_id = created.value.call.call_id;
        let leg = &mut created.value.call.legs[0];
        let leg_id = leg.leg_id;
        let attachment = leg.attachment.as_mut().unwrap();
        (
            call_id,
            leg_id,
            std::mem::take(&mut attachment.token),
            attachment.expires_at,
        )
    }

    fn inbound_request(
        tenant: &str,
        subject: &str,
        expires_at: Option<DateTime<Utc>>,
        token: Option<String>,
        transport: AttachmentTransport,
        worker: WorkerLease,
        connection_id: ConnectionId,
    ) -> InboundAttachmentRequest {
        InboundAttachmentRequest::new(
            authenticated_principal(tenant, subject, expires_at),
            token,
            transport,
            worker,
            connection_id,
        )
    }

    async fn connect_created_call(
        repository: &MemoryRepository,
        service: &CallService,
        owner: &ApiPrincipal,
        worker: WorkerLease,
        created: &CreateCallView,
    ) {
        let tenant = TenantId::parse("tenant-a").unwrap();
        for (index, leg) in created.call.legs.iter().enumerate() {
            let attachment = leg.attachment.as_ref().unwrap();
            let observed_at = at(1 + index as i64);
            let candidate = repository
                .inspect_attachment(AttachmentLookup {
                    token_digest: token_digest(&attachment.token),
                    tenant_id: tenant.clone(),
                    transport: attachment.transport,
                    principal_fingerprint: service.crypto.principal_fingerprint(owner),
                    worker,
                    at: observed_at,
                })
                .await
                .unwrap();
            repository
                .consume_attachment(AttachmentConsume {
                    candidate,
                    command_id: CommandId::new(),
                    command: CallCommand::SetLegState {
                        at: observed_at,
                        leg_id: leg.leg_id,
                        binding_generation: BindingGeneration::INITIAL,
                        state: LegState::Signaling,
                        failure: None,
                    },
                    connection_id: ConnectionId::new(),
                    principal_fingerprint: service.crypto.principal_fingerprint(owner),
                    principal_expires_at: None,
                    at: observed_at,
                })
                .await
                .unwrap();
        }
        for (index, leg) in created.call.legs.iter().enumerate() {
            let observed_at = at(3 + index as i64);
            let current = repository
                .load_call(&tenant, created.call.call_id)
                .await
                .unwrap();
            repository
                .commit_with_effect_payloads(ServiceCommandTransaction {
                    command: CommandCommit {
                        tenant_id: tenant.clone(),
                        call_id: created.call.call_id,
                        expected_version: current.aggregate.version(),
                        command_id: CommandId::new(),
                        command: CallCommand::SetLegState {
                            at: observed_at,
                            leg_id: leg.leg_id,
                            binding_generation: BindingGeneration::INITIAL,
                            state: LegState::Connected,
                            failure: None,
                        },
                        worker,
                        attachments: Vec::new(),
                        deadline_claim: None,
                        at: observed_at,
                    },
                    effect_payloads: Vec::new(),
                    operation_idempotency: None,
                    bound_connection: None,
                    media_activity: None,
                    replacement_connection: None,
                })
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn broadcast_source_resolution_requires_exact_owned_connected_binding_and_worker() {
        let (repository, service, _, worker) = harness(3).await;
        let owner = principal("tenant-a");
        let created = service
            .create_call(
                &owner,
                &IdempotencyKey::parse("broadcast-source-connected").unwrap(),
                two_inbound_input(),
            )
            .await
            .unwrap();
        connect_created_call(&repository, &service, &owner, worker, &created.value).await;

        let tenant = TenantId::parse("tenant-a").unwrap();
        let call_id = created.value.call.call_id;
        let leg_id = created.value.call.legs[0].leg_id;
        let stored = repository
            .load_service_call(&tenant, call_id)
            .await
            .unwrap();
        let expected_connection = stored
            .call
            .bindings
            .get(&leg_id)
            .expect("connected leg binding")
            .connection_id
            .clone();

        let source = service
            .resolve_broadcast_source(&owner, call_id, leg_id, None, worker)
            .await
            .unwrap();
        assert_eq!(source.tenant_id(), &tenant);
        assert_eq!(source.call_id(), call_id);
        assert_eq!(source.leg_id(), leg_id);
        assert_eq!(source.connection_id(), expected_connection);
        assert!(!format!("{source:?}").contains(&expected_connection.to_string()));

        assert_eq!(
            service
                .resolve_broadcast_source(&owner, call_id, LegId::new(), None, worker)
                .await
                .unwrap_err(),
            CallServiceError::InvalidInput("broadcast source leg does not belong to call")
        );
        assert_eq!(
            service
                .resolve_broadcast_source(&principal("tenant-b"), call_id, leg_id, None, worker,)
                .await
                .unwrap_err(),
            CallServiceError::Repository(RepositoryError::NotFound)
        );

        let other_worker = repository
            .register_worker(RegisterWorker {
                worker_id: WorkerId::new(),
                max_calls: 3,
                capabilities: test_worker_capabilities(),
                at: at(0),
                lease_ttl: Duration::from_secs(300),
            })
            .await
            .unwrap()
            .lease;
        assert_eq!(
            service
                .resolve_broadcast_source(&owner, call_id, leg_id, None, other_worker)
                .await
                .unwrap_err(),
            CallServiceError::DependencyUnavailable
        );

        let disconnected = service
            .create_call(
                &owner,
                &IdempotencyKey::parse("broadcast-source-disconnected").unwrap(),
                two_inbound_input(),
            )
            .await
            .unwrap();
        assert_eq!(
            service
                .resolve_broadcast_source(
                    &owner,
                    disconnected.value.call.call_id,
                    disconnected.value.call.legs[0].leg_id,
                    None,
                    worker,
                )
                .await
                .unwrap_err(),
            CallServiceError::InvalidTransition
        );
    }

    #[test]
    fn inbound_attachment_error_mapping_separates_proofs_from_operational_faults() {
        for error in [
            RepositoryError::AttachmentRejected,
            RepositoryError::AttachmentConflict,
            RepositoryError::StaleWorkerFence,
            RepositoryError::VersionConflict,
            RepositoryError::CommandConflict,
            RepositoryError::DomainRejected,
        ] {
            assert_eq!(
                map_inbound_attachment_repository_error(error),
                InboundAttachmentError::ProofRejected
            );
        }
        for error in [
            RepositoryError::Unavailable,
            RepositoryError::CounterExhausted,
            RepositoryError::ProviderEventConflict,
            RepositoryError::ProviderReferenceConflict,
            RepositoryError::StaleClaim,
            RepositoryError::InvalidInput("impossible attachment path error"),
        ] {
            assert_eq!(
                map_inbound_attachment_repository_error(error),
                InboundAttachmentError::Unavailable
            );
        }
    }

    #[tokio::test]
    async fn create_replays_exact_call_and_tokens_and_isolates_tenants() {
        let (_repository, service, _clock, _) = harness(8).await;
        let key = IdempotencyKey::parse("create-1").unwrap();
        let created = service
            .create_call(&principal("tenant-a"), &key, generic_input())
            .await
            .unwrap();
        assert!(!created.replayed);
        assert_eq!(created.value.call.legs[0].state, LegState::AwaitingAttach);
        let attachment = created.value.call.legs[0].attachment.as_ref().unwrap();
        assert_eq!(attachment.token.len(), 43);
        assert_eq!(attachment.expires_at, at(120));
        assert!(created.value.call.legs[1].attachment.is_none());

        let replayed = service
            .create_call(&principal("tenant-a"), &key, generic_input())
            .await
            .unwrap();
        assert!(replayed.replayed);
        assert_eq!(replayed.value, created.value);

        let mut changed = generic_input();
        changed.legs[1].endpoint = LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
            signaling_uri: Some("wss://signal.example.test/other".into()),
        });
        assert!(matches!(
            service
                .create_call(&principal("tenant-a"), &key, changed)
                .await,
            Err(CallServiceError::Repository(
                RepositoryError::IdempotencyConflict
            ))
        ));

        let other = service
            .create_call(&principal("tenant-b"), &key, generic_input())
            .await
            .unwrap();
        assert_ne!(other.value.call.call_id, created.value.call.call_id);
        assert!(matches!(
            service
                .get_call(
                    &principal("tenant-b"),
                    created.value.call.call_id,
                    GetCallInput::default()
                )
                .await,
            Err(CallServiceError::Repository(RepositoryError::NotFound))
        ));
    }

    #[tokio::test]
    async fn create_replays_pre_v3_digest_only_for_exact_legacy_defaults() {
        let (repository, service, _clock, worker) = harness(4).await;
        let owner = principal("tenant-a");
        let tenant = owner.tenant().clone();
        let key = IdempotencyKey::parse("legacy-create-digest").unwrap();
        let input = generic_input();
        let aggregate = CallAggregate::new_with_semantics(
            tenant.clone(),
            input.legs.clone().map(|leg| LegSpec {
                direction: leg.direction,
                kind: leg.endpoint.kind(),
            }),
            input.legs.each_ref().map(RequestedLeg::semantics),
            at(0),
        )
        .unwrap();
        let owner_fingerprint = service.crypto.principal_fingerprint(&owner);
        let plan = CallExecutionPlan::new(
            &aggregate,
            [
                LegExecutionSpec {
                    leg_id: aggregate.legs()[0].id(),
                    endpoint: input.legs[0].endpoint.clone(),
                },
                LegExecutionSpec {
                    leg_id: aggregate.legs()[1].id(),
                    endpoint: input.legs[1].endpoint.clone(),
                },
            ],
            owner_fingerprint,
        )
        .unwrap();
        let principals = service
            .resolve_attachment_principals(&tenant, &aggregate, &plan, owner_fingerprint)
            .await
            .unwrap();
        let attachments = service
            .attachment_issues(&tenant, &aggregate, &principals, worker, at(0))
            .unwrap();
        let legacy_transcript = legacy_create_transcript(&input.legs).unwrap();
        let legacy_operation = service.crypto.operation_idempotency(
            &tenant,
            owner_fingerprint,
            &key,
            ServiceOperationKind::CreateCall,
            None,
            &legacy_transcript,
        );
        repository
            .create_with_plan(ServiceCreateTransaction {
                create: crate::call_engine::CreateCall {
                    initial: aggregate,
                    command_id: CommandId::new(),
                    command: CallCommand::StartConnecting {
                        at: at(0),
                        setup_deadline: at(30),
                    },
                    worker,
                    idempotency_key: legacy_operation.key_digest,
                    request_digest: legacy_operation.request_digest,
                    attachments,
                    at: at(0),
                },
                plan,
                alternatives: Vec::new(),
            })
            .await
            .unwrap();

        let replay = service
            .create_call(&owner, &key, input.clone())
            .await
            .unwrap();
        assert!(replay.replayed);

        let mut nonlegacy = input;
        nonlegacy.legs[0].media_flow = MediaFlow::ReceiveOnly;
        nonlegacy.legs[1].media_flow = MediaFlow::SendOnly;
        assert!(matches!(
            service.create_call(&owner, &key, nonlegacy).await,
            Err(CallServiceError::Repository(
                RepositoryError::IdempotencyConflict
            ))
        ));
    }

    #[tokio::test]
    async fn create_replay_precedes_resolver_and_placement_health_or_capacity() {
        let repository = Arc::new(MemoryRepository::new());
        let worker = repository
            .register_worker(RegisterWorker {
                worker_id: WorkerId::new(),
                max_calls: 4,
                capabilities: test_worker_capabilities(),
                at: at(0),
                lease_ttl: std::time::Duration::from_secs(300),
            })
            .await
            .unwrap()
            .lease;
        let placement = Arc::new(SwitchablePlacement {
            worker,
            failure: Mutex::new(None),
        });
        let resolver = Arc::new(SwitchableAttachmentResolver::default());
        let service = CallService::new(
            repository.clone(),
            placement.clone(),
            resolver.clone(),
            CallServiceCrypto::new(vec![0x62; 32]).unwrap(),
            Arc::new(TestClock::new(at(0))),
            CallTimeoutPolicy::default(),
        );
        let owner = principal("tenant-a");
        let key = IdempotencyKey::parse("placement-replay").unwrap();
        let created = service
            .create_call(&owner, &key, generic_input())
            .await
            .unwrap();

        resolver.set_unavailable(true);
        placement.set_failure(Some(PlacementError::Unavailable));
        let replayed = service
            .create_call(&owner, &key, generic_input())
            .await
            .unwrap();
        assert!(replayed.replayed);
        assert_eq!(replayed.value, created.value);

        let mut changed = generic_input();
        changed.legs[1].endpoint = LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
            signaling_uri: Some("wss://signal.example.test/conflict".into()),
        });
        assert!(matches!(
            service.create_call(&owner, &key, changed).await,
            Err(CallServiceError::Repository(
                RepositoryError::IdempotencyConflict
            ))
        ));

        resolver.set_unavailable(false);
        assert_eq!(
            service
                .create_call(
                    &owner,
                    &IdempotencyKey::parse("placement-unavailable").unwrap(),
                    generic_input(),
                )
                .await
                .unwrap_err(),
            CallServiceError::DependencyUnavailable
        );
        placement.set_failure(Some(PlacementError::CapacityExceeded));
        assert_eq!(
            service
                .create_call(
                    &owner,
                    &IdempotencyKey::parse("placement-capacity").unwrap(),
                    generic_input(),
                )
                .await
                .unwrap_err(),
            CallServiceError::CapacityExceeded
        );
        assert_eq!(repository.counts().unwrap().calls, 1);
    }

    #[tokio::test]
    async fn stalled_resolver_crossing_setup_deadline_leaks_no_state_or_capacity() {
        let repository = Arc::new(MemoryRepository::new());
        let worker = repository
            .register_worker(RegisterWorker {
                worker_id: WorkerId::new(),
                max_calls: 1,
                capabilities: test_worker_capabilities(),
                at: at(0),
                lease_ttl: std::time::Duration::from_secs(300),
            })
            .await
            .unwrap()
            .lease;
        let entered = Arc::new(tokio::sync::Barrier::new(2));
        let release = Arc::new(tokio::sync::Barrier::new(2));
        let clock = Arc::new(TestClock::new(at(0)));
        let service = Arc::new(CallService::new(
            repository.clone(),
            Arc::new(FixedWorkerPlacement::new(worker)),
            Arc::new(BarrierSuccessfulResolver {
                entered: entered.clone(),
                release: release.clone(),
            }),
            CallServiceCrypto::new(vec![0x65; 32]).unwrap(),
            clock.clone(),
            CallTimeoutPolicy {
                setup: Duration::from_secs(30),
                ..CallTimeoutPolicy::default()
            },
        ));
        let task = tokio::spawn(async move {
            service
                .create_call(
                    &principal("tenant-a"),
                    &IdempotencyKey::parse("stalled-resolver").unwrap(),
                    generic_input(),
                )
                .await
        });
        entered.wait().await;
        clock.set(at(31));
        release.wait().await;
        assert_eq!(
            task.await.unwrap().unwrap_err(),
            CallServiceError::DependencyUnavailable
        );
        assert_eq!(repository.counts().unwrap().calls, 0);

        let recovery = CallService::new(
            repository.clone(),
            Arc::new(FixedWorkerPlacement::new(worker)),
            Arc::new(SamePrincipalAttachmentResolver),
            CallServiceCrypto::new(vec![0x65; 32]).unwrap(),
            clock,
            CallTimeoutPolicy::default(),
        );
        recovery
            .create_call(
                &principal("tenant-a"),
                &IdempotencyKey::parse("resolver-recovery").unwrap(),
                generic_input(),
            )
            .await
            .unwrap();
        assert_eq!(repository.counts().unwrap().calls, 1);
    }

    #[tokio::test]
    async fn stalled_placement_crossing_token_window_leaks_no_state_or_capacity() {
        let repository = Arc::new(MemoryRepository::new());
        let worker = repository
            .register_worker(RegisterWorker {
                worker_id: WorkerId::new(),
                max_calls: 1,
                capabilities: test_worker_capabilities(),
                at: at(0),
                lease_ttl: std::time::Duration::from_secs(300),
            })
            .await
            .unwrap()
            .lease;
        let entered = Arc::new(tokio::sync::Barrier::new(2));
        let release = Arc::new(tokio::sync::Barrier::new(2));
        let clock = Arc::new(TestClock::new(at(0)));
        let service = Arc::new(CallService::new(
            repository.clone(),
            Arc::new(BarrierSuccessfulPlacement {
                worker,
                entered: entered.clone(),
                release: release.clone(),
            }),
            Arc::new(SamePrincipalAttachmentResolver),
            CallServiceCrypto::new(vec![0x66; 32]).unwrap(),
            clock.clone(),
            CallTimeoutPolicy {
                setup: Duration::from_secs(300),
                ..CallTimeoutPolicy::default()
            },
        ));
        let task = tokio::spawn(async move {
            service
                .create_call(
                    &principal("tenant-a"),
                    &IdempotencyKey::parse("stalled-placement").unwrap(),
                    generic_input(),
                )
                .await
        });
        entered.wait().await;
        clock.set(at(121));
        release.wait().await;
        assert_eq!(
            task.await.unwrap().unwrap_err(),
            CallServiceError::DependencyUnavailable
        );
        assert_eq!(repository.counts().unwrap().calls, 0);

        let recovery = CallService::new(
            repository.clone(),
            Arc::new(FixedWorkerPlacement::new(worker)),
            Arc::new(SamePrincipalAttachmentResolver),
            CallServiceCrypto::new(vec![0x66; 32]).unwrap(),
            clock,
            CallTimeoutPolicy::default(),
        );
        recovery
            .create_call(
                &principal("tenant-a"),
                &IdempotencyKey::parse("placement-recovery").unwrap(),
                generic_input(),
            )
            .await
            .unwrap();
        assert_eq!(repository.counts().unwrap().calls, 1);
    }

    #[tokio::test]
    async fn consumed_expired_attachment_replays_exactly_without_live_dependencies() {
        let repository = Arc::new(MemoryRepository::new());
        let worker = repository
            .register_worker(RegisterWorker {
                worker_id: WorkerId::new(),
                max_calls: 2,
                capabilities: test_worker_capabilities(),
                at: at(0),
                lease_ttl: std::time::Duration::from_secs(300),
            })
            .await
            .unwrap()
            .lease;
        let placement = Arc::new(SwitchablePlacement {
            worker,
            failure: Mutex::new(None),
        });
        let resolver = Arc::new(SwitchableAttachmentResolver::default());
        let clock = Arc::new(TestClock::new(at(0)));
        let service = CallService::new(
            repository.clone(),
            placement.clone(),
            resolver.clone(),
            CallServiceCrypto::new(vec![0x64; 32]).unwrap(),
            clock.clone(),
            CallTimeoutPolicy::default(),
        );
        let owner = principal("tenant-a");
        let key = IdempotencyKey::parse("consumed-expired-replay").unwrap();
        let created = service
            .create_call(&owner, &key, generic_input())
            .await
            .unwrap();
        let leg = &created.value.call.legs[0];
        let attachment = leg.attachment.as_ref().unwrap();
        let lookup = AttachmentLookup {
            token_digest: token_digest(&attachment.token),
            tenant_id: TenantId::parse("tenant-a").unwrap(),
            transport: AttachmentTransport::Sip,
            principal_fingerprint: service.crypto.principal_fingerprint(&owner),
            worker,
            at: at(1),
        };
        let candidate = repository.inspect_attachment(lookup.clone()).await.unwrap();
        repository
            .consume_attachment(AttachmentConsume {
                candidate,
                command_id: CommandId::new(),
                command: CallCommand::SetLegState {
                    at: at(1),
                    leg_id: leg.leg_id,
                    binding_generation: BindingGeneration::INITIAL,
                    state: LegState::Signaling,
                    failure: None,
                },
                connection_id: ConnectionId::new(),
                principal_fingerprint: service.crypto.principal_fingerprint(&owner),
                principal_expires_at: None,
                at: at(1),
            })
            .await
            .unwrap();

        clock.set(at(121));
        resolver.set_unavailable(true);
        placement.set_failure(Some(PlacementError::Unavailable));
        let replayed = service
            .create_call(&owner, &key, generic_input())
            .await
            .unwrap();
        assert!(replayed.replayed);
        assert_eq!(replayed.value, created.value);
        assert!(
            replayed.value.call.legs[0]
                .attachment
                .as_ref()
                .unwrap()
                .expires_at
                < clock.now()
        );
        assert_eq!(
            repository
                .inspect_attachment(AttachmentLookup {
                    at: at(121),
                    ..lookup
                })
                .await
                .unwrap_err(),
            RepositoryError::AttachmentRejected
        );
    }

    #[tokio::test]
    async fn concurrent_winner_outranks_inflight_resolver_failure() {
        let repository = Arc::new(MemoryRepository::new());
        let worker = repository
            .register_worker(RegisterWorker {
                worker_id: WorkerId::new(),
                max_calls: 4,
                capabilities: test_worker_capabilities(),
                at: at(0),
                lease_ttl: std::time::Duration::from_secs(300),
            })
            .await
            .unwrap()
            .lease;
        let entered = Arc::new(tokio::sync::Barrier::new(2));
        let release = Arc::new(tokio::sync::Barrier::new(2));
        let loser = Arc::new(CallService::new(
            repository.clone(),
            Arc::new(FixedWorkerPlacement::new(worker)),
            Arc::new(BarrierFailingResolver {
                entered: entered.clone(),
                release: release.clone(),
            }),
            CallServiceCrypto::new(vec![0x63; 32]).unwrap(),
            Arc::new(TestClock::new(at(0))),
            CallTimeoutPolicy::default(),
        ));
        let winner = CallService::new(
            repository.clone(),
            Arc::new(FixedWorkerPlacement::new(worker)),
            Arc::new(SamePrincipalAttachmentResolver),
            CallServiceCrypto::new(vec![0x63; 32]).unwrap(),
            Arc::new(TestClock::new(at(0))),
            CallTimeoutPolicy::default(),
        );
        let loser_task = tokio::spawn(async move {
            loser
                .create_call(
                    &principal("tenant-a"),
                    &IdempotencyKey::parse("resolver-race").unwrap(),
                    generic_input(),
                )
                .await
        });
        entered.wait().await;
        let committed = winner
            .create_call(
                &principal("tenant-a"),
                &IdempotencyKey::parse("resolver-race").unwrap(),
                generic_input(),
            )
            .await
            .unwrap();
        release.wait().await;
        let raced = loser_task.await.unwrap().unwrap();
        assert!(raced.replayed);
        assert_eq!(raced.value, committed.value);
        assert_eq!(repository.counts().unwrap().calls, 1);
    }

    #[tokio::test]
    async fn concurrent_winner_outranks_resolver_timeout() {
        let repository = Arc::new(MemoryRepository::new());
        let worker = repository
            .register_worker(RegisterWorker {
                worker_id: WorkerId::new(),
                max_calls: 2,
                capabilities: test_worker_capabilities(),
                at: at(0),
                lease_ttl: std::time::Duration::from_secs(300),
            })
            .await
            .unwrap()
            .lease;
        let entered = Arc::new(tokio::sync::Barrier::new(2));
        let clock = Arc::new(TestClock::new(at(0)));
        let loser = Arc::new(CallService::new(
            repository.clone(),
            Arc::new(FixedWorkerPlacement::new(worker)),
            Arc::new(BarrierPendingResolver {
                entered: entered.clone(),
            }),
            CallServiceCrypto::new(vec![0x67; 32]).unwrap(),
            clock.clone(),
            CallTimeoutPolicy {
                setup: Duration::from_secs(1),
                ..CallTimeoutPolicy::default()
            },
        ));
        let winner = CallService::new(
            repository.clone(),
            Arc::new(FixedWorkerPlacement::new(worker)),
            Arc::new(SamePrincipalAttachmentResolver),
            CallServiceCrypto::new(vec![0x67; 32]).unwrap(),
            clock,
            CallTimeoutPolicy::default(),
        );
        let loser_task = tokio::spawn(async move {
            loser
                .create_call(
                    &principal("tenant-a"),
                    &IdempotencyKey::parse("resolver-timeout-race").unwrap(),
                    generic_input(),
                )
                .await
        });
        entered.wait().await;
        let committed = winner
            .create_call(
                &principal("tenant-a"),
                &IdempotencyKey::parse("resolver-timeout-race").unwrap(),
                generic_input(),
            )
            .await
            .unwrap();
        let raced = loser_task.await.unwrap().unwrap();
        assert!(raced.replayed);
        assert_eq!(raced.value, committed.value);
        assert_eq!(repository.counts().unwrap().calls, 1);
    }

    #[tokio::test]
    async fn create_view_rejects_attachment_descriptor_drift() {
        let (repository, service, _, _) = harness(2).await;
        let owner = principal("tenant-a");
        let created = service
            .create_call(
                &owner,
                &IdempotencyKey::parse("descriptor-drift").unwrap(),
                generic_input(),
            )
            .await
            .unwrap();
        let mut stored = repository
            .load_service_call(
                &TenantId::parse("tenant-a").unwrap(),
                created.value.call.call_id,
            )
            .await
            .unwrap();
        stored.attachments[0].token_digest = AttachmentTokenDigest::new([0x99; 32]);
        assert_eq!(
            service.create_view(stored, true).unwrap_err(),
            CallServiceError::DependencyUnavailable
        );
    }

    #[tokio::test]
    async fn inbound_attachment_rechecks_principal_and_token_expiry_after_blocked_inspection() {
        let repository = Arc::new(MemoryRepository::new());
        let clock = Arc::new(TestClock::new(at(0)));
        let worker = repository
            .register_worker(RegisterWorker {
                worker_id: WorkerId::new(),
                max_calls: 4,
                capabilities: test_worker_capabilities(),
                at: at(0),
                lease_ttl: Duration::from_secs(300),
            })
            .await
            .unwrap()
            .lease;
        let creator = CallService::new(
            repository.clone(),
            Arc::new(FixedWorkerPlacement::new(worker)),
            Arc::new(SamePrincipalAttachmentResolver),
            CallServiceCrypto::new(vec![0x71; 32]).unwrap(),
            clock.clone(),
            CallTimeoutPolicy::default(),
        );
        let owner = principal("tenant-a");
        let mut principal_expiry_call = creator
            .create_call(
                &owner,
                &IdempotencyKey::parse("service-attachment-principal-expiry").unwrap(),
                generic_input(),
            )
            .await
            .unwrap();
        let mut token_expiry_call = creator
            .create_call(
                &owner,
                &IdempotencyKey::parse("service-attachment-token-expiry").unwrap(),
                generic_input(),
            )
            .await
            .unwrap();
        let (_, _, principal_token, _) = take_first_attachment(&mut principal_expiry_call);
        let principal_retry_token = principal_token.clone();
        let (_, _, token_expiring, token_expires_at) =
            take_first_attachment(&mut token_expiry_call);

        let blocking = Arc::new(BlockingAttachmentRepository::new(repository, clock.clone()));
        let service = Arc::new(CallService::new(
            blocking.clone(),
            Arc::new(FixedWorkerPlacement::new(worker)),
            Arc::new(SamePrincipalAttachmentResolver),
            CallServiceCrypto::new(vec![0x71; 32]).unwrap(),
            clock.clone(),
            CallTimeoutPolicy::default(),
        ));

        clock.set(at(1));
        blocking.block_next_inspection();
        let principal_expiry_task = {
            let service = service.clone();
            tokio::spawn(async move {
                service
                    .consume_inbound_attachment(inbound_request(
                        "tenant-a",
                        "subject-tenant-a",
                        Some(at(2)),
                        Some(principal_token),
                        AttachmentTransport::Sip,
                        worker,
                        ConnectionId::new(),
                    ))
                    .await
            })
        };
        blocking.wait_until_inspection().await;
        clock.set(at(2));
        blocking.release_inspection();
        assert_eq!(
            principal_expiry_task.await.unwrap(),
            Err(InboundAttachmentError::ProofRejected)
        );
        service
            .consume_inbound_attachment(inbound_request(
                "tenant-a",
                "subject-tenant-a",
                None,
                Some(principal_retry_token),
                AttachmentTransport::Sip,
                worker,
                ConnectionId::new(),
            ))
            .await
            .unwrap();

        clock.set(token_expires_at - chrono::Duration::seconds(1));
        blocking.block_next_inspection();
        let token_expiry_task = {
            let service = service.clone();
            tokio::spawn(async move {
                service
                    .consume_inbound_attachment(inbound_request(
                        "tenant-a",
                        "subject-tenant-a",
                        None,
                        Some(token_expiring),
                        AttachmentTransport::Sip,
                        worker,
                        ConnectionId::new(),
                    ))
                    .await
            })
        };
        blocking.wait_until_inspection().await;
        clock.set(token_expires_at);
        blocking.release_inspection();
        assert_eq!(
            token_expiry_task.await.unwrap(),
            Err(InboundAttachmentError::ProofRejected)
        );
    }

    #[tokio::test]
    async fn inbound_attachment_rejects_expiry_while_atomic_consumption_is_blocked() {
        let repository = Arc::new(MemoryRepository::new());
        let clock = Arc::new(TestClock::new(at(0)));
        let worker = repository
            .register_worker(RegisterWorker {
                worker_id: WorkerId::new(),
                max_calls: 4,
                capabilities: test_worker_capabilities(),
                at: at(0),
                lease_ttl: Duration::from_secs(300),
            })
            .await
            .unwrap()
            .lease;
        let creator = CallService::new(
            repository.clone(),
            Arc::new(FixedWorkerPlacement::new(worker)),
            Arc::new(SamePrincipalAttachmentResolver),
            CallServiceCrypto::new(vec![0x73; 32]).unwrap(),
            clock.clone(),
            CallTimeoutPolicy::default(),
        );
        let owner = principal("tenant-a");
        let mut principal_expiry_call = creator
            .create_call(
                &owner,
                &IdempotencyKey::parse("service-atomic-principal-expiry").unwrap(),
                generic_input(),
            )
            .await
            .unwrap();
        let mut token_expiry_call = creator
            .create_call(
                &owner,
                &IdempotencyKey::parse("service-atomic-token-expiry").unwrap(),
                generic_input(),
            )
            .await
            .unwrap();
        let (_, _, principal_token, _) = take_first_attachment(&mut principal_expiry_call);
        let principal_retry_token = principal_token.clone();
        let (_, _, token_expiring, token_expires_at) =
            take_first_attachment(&mut token_expiry_call);
        let blocking = Arc::new(BlockingAttachmentRepository::new(repository, clock.clone()));
        let service = Arc::new(CallService::new(
            blocking.clone(),
            Arc::new(FixedWorkerPlacement::new(worker)),
            Arc::new(SamePrincipalAttachmentResolver),
            CallServiceCrypto::new(vec![0x73; 32]).unwrap(),
            clock.clone(),
            CallTimeoutPolicy::default(),
        ));

        clock.set(at(1));
        blocking.block_next_consumption();
        let principal_expiry_task = {
            let service = service.clone();
            tokio::spawn(async move {
                service
                    .consume_inbound_attachment(inbound_request(
                        "tenant-a",
                        "subject-tenant-a",
                        Some(at(2)),
                        Some(principal_token),
                        AttachmentTransport::Sip,
                        worker,
                        ConnectionId::new(),
                    ))
                    .await
            })
        };
        blocking.wait_until_consumption().await;
        clock.set(at(2));
        blocking.release_consumption();
        assert_eq!(
            principal_expiry_task.await.unwrap(),
            Err(InboundAttachmentError::ProofRejected)
        );
        service
            .consume_inbound_attachment(inbound_request(
                "tenant-a",
                "subject-tenant-a",
                None,
                Some(principal_retry_token),
                AttachmentTransport::Sip,
                worker,
                ConnectionId::new(),
            ))
            .await
            .unwrap();

        clock.set(token_expires_at - chrono::Duration::seconds(1));
        blocking.block_next_consumption();
        let token_expiry_task = {
            let service = service.clone();
            tokio::spawn(async move {
                service
                    .consume_inbound_attachment(inbound_request(
                        "tenant-a",
                        "subject-tenant-a",
                        None,
                        Some(token_expiring),
                        AttachmentTransport::Sip,
                        worker,
                        ConnectionId::new(),
                    ))
                    .await
            })
        };
        blocking.wait_until_consumption().await;
        clock.set(token_expires_at);
        blocking.release_consumption();
        assert_eq!(
            token_expiry_task.await.unwrap(),
            Err(InboundAttachmentError::ProofRejected)
        );
    }

    #[tokio::test]
    async fn inbound_attachment_exposes_only_true_repository_unavailability() {
        let repository = Arc::new(MemoryRepository::new());
        let clock = Arc::new(TestClock::new(at(0)));
        let worker = repository
            .register_worker(RegisterWorker {
                worker_id: WorkerId::new(),
                max_calls: 2,
                capabilities: test_worker_capabilities(),
                at: at(0),
                lease_ttl: Duration::from_secs(300),
            })
            .await
            .unwrap()
            .lease;
        let creator = CallService::new(
            repository.clone(),
            Arc::new(FixedWorkerPlacement::new(worker)),
            Arc::new(SamePrincipalAttachmentResolver),
            CallServiceCrypto::new(vec![0x72; 32]).unwrap(),
            clock.clone(),
            CallTimeoutPolicy::default(),
        );
        let mut created = creator
            .create_call(
                &principal("tenant-a"),
                &IdempotencyKey::parse("service-attachment-unavailable").unwrap(),
                generic_input(),
            )
            .await
            .unwrap();
        let (_, _, token, _) = take_first_attachment(&mut created);
        let retry_token = token.clone();
        let blocking = Arc::new(BlockingAttachmentRepository::new(repository, clock.clone()));
        let service = CallService::new(
            blocking.clone(),
            Arc::new(FixedWorkerPlacement::new(worker)),
            Arc::new(SamePrincipalAttachmentResolver),
            CallServiceCrypto::new(vec![0x72; 32]).unwrap(),
            clock.clone(),
            CallTimeoutPolicy::default(),
        );
        clock.set(at(1));
        blocking.set_unavailable(true);
        assert_eq!(
            service
                .consume_inbound_attachment(inbound_request(
                    "tenant-a",
                    "subject-tenant-a",
                    None,
                    Some(token),
                    AttachmentTransport::Sip,
                    worker,
                    ConnectionId::new(),
                ))
                .await,
            Err(InboundAttachmentError::Unavailable)
        );
        blocking.set_unavailable(false);
        service
            .consume_inbound_attachment(inbound_request(
                "tenant-a",
                "subject-tenant-a",
                None,
                Some(retry_token),
                AttachmentTransport::Sip,
                worker,
                ConnectionId::new(),
            ))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn inbound_attachment_service_binds_exact_leg_and_rejects_replay() {
        let (repository, service, clock, worker) = harness(4).await;
        let owner = principal("tenant-a");
        let mut created = service
            .create_call(
                &owner,
                &IdempotencyKey::parse("service-attachment-success").unwrap(),
                generic_input(),
            )
            .await
            .unwrap();
        let (call_id, leg_id, token, _) = take_first_attachment(&mut created);
        let replay_token = token.clone();
        let connection_id = ConnectionId::new();
        clock.set(at(1));
        let request = inbound_request(
            "tenant-a",
            "subject-tenant-a",
            None,
            Some(token.clone()),
            AttachmentTransport::Sip,
            worker,
            connection_id.clone(),
        );
        let request_debug = format!("{request:?}");
        assert!(!request_debug.contains(&token));
        assert!(!request_debug.contains("subject-tenant-a"));

        let result = service.consume_inbound_attachment(request).await.unwrap();
        assert_eq!(result.commit.call.aggregate.id(), call_id);
        assert_eq!(result.binding.leg_id, leg_id);
        assert_eq!(result.binding.connection_id, connection_id);
        assert_eq!(
            result.binding.binding_generation,
            BindingGeneration::INITIAL
        );
        assert_eq!(
            result.commit.call.aggregate.leg(leg_id).unwrap().state(),
            LegState::Signaling
        );
        let result_debug = format!("{result:?}");
        assert!(!result_debug.contains("subject-tenant-a"));
        assert!(!result_debug.contains(&token));

        assert_eq!(
            service
                .consume_inbound_attachment(inbound_request(
                    "tenant-a",
                    "subject-tenant-a",
                    None,
                    Some(replay_token),
                    AttachmentTransport::Sip,
                    worker,
                    ConnectionId::new(),
                ))
                .await,
            Err(InboundAttachmentError::ProofRejected)
        );
        let stored = repository
            .load_call(&TenantId::parse("tenant-a").unwrap(), call_id)
            .await
            .unwrap();
        assert_eq!(stored.bindings.len(), 1);
    }

    #[tokio::test]
    async fn inbound_attachment_service_collapses_missing_malformed_and_expired_proofs() {
        let (_repository, service, clock, worker) = harness(4).await;
        let owner = principal("tenant-a");
        let mut created = service
            .create_call(
                &owner,
                &IdempotencyKey::parse("service-attachment-malformed").unwrap(),
                generic_input(),
            )
            .await
            .unwrap();
        let (_, _, token, expires_at) = take_first_attachment(&mut created);
        let mut noncanonical = URL_SAFE_NO_PAD.encode([0_u8; 32]);
        assert_eq!(noncanonical.pop(), Some('A'));
        noncanonical.push('B');
        for malformed in [None, Some("short".into()), Some(noncanonical)] {
            assert_eq!(
                service
                    .consume_inbound_attachment(inbound_request(
                        "tenant-a",
                        "subject-tenant-a",
                        None,
                        malformed,
                        AttachmentTransport::Sip,
                        worker,
                        ConnectionId::new(),
                    ))
                    .await,
                Err(InboundAttachmentError::ProofRejected)
            );
        }

        let mut missing_tenant = authenticated_principal("tenant-a", "subject-tenant-a", None);
        missing_tenant.tenant = None;
        assert_eq!(
            service
                .consume_inbound_attachment(InboundAttachmentRequest::new(
                    missing_tenant,
                    Some(token.clone()),
                    AttachmentTransport::Sip,
                    worker,
                    ConnectionId::new(),
                ))
                .await,
            Err(InboundAttachmentError::ProofRejected)
        );

        clock.set(at(1));
        assert_eq!(
            service
                .consume_inbound_attachment(inbound_request(
                    "tenant-a",
                    "subject-tenant-a",
                    Some(at(1)),
                    Some(token.clone()),
                    AttachmentTransport::Sip,
                    worker,
                    ConnectionId::new(),
                ))
                .await,
            Err(InboundAttachmentError::ProofRejected)
        );

        clock.set(expires_at);
        assert_eq!(
            service
                .consume_inbound_attachment(inbound_request(
                    "tenant-a",
                    "subject-tenant-a",
                    None,
                    Some(token),
                    AttachmentTransport::Sip,
                    worker,
                    ConnectionId::new(),
                ))
                .await,
            Err(InboundAttachmentError::ProofRejected)
        );
    }

    #[tokio::test]
    async fn inbound_attachment_service_collapses_transport_tenant_principal_and_fence_mismatch() {
        let (_repository, service, clock, worker) = harness(4).await;
        let owner = principal("tenant-a");
        let mut created = service
            .create_call(
                &owner,
                &IdempotencyKey::parse("service-attachment-mismatches").unwrap(),
                generic_input(),
            )
            .await
            .unwrap();
        let (call_id, _, token, _) = take_first_attachment(&mut created);
        clock.set(at(1));
        let wrong_fence = WorkerLease {
            worker_id: worker.worker_id,
            fence: serde_json::from_value(serde_json::json!(2)).unwrap(),
        };
        let mut wrong_issuer = authenticated_principal("tenant-a", "subject-tenant-a", None);
        wrong_issuer.issuer = Some("another-issuer".into());
        let mismatches = [
            inbound_request(
                "tenant-a",
                "subject-tenant-a",
                None,
                Some(token.clone()),
                AttachmentTransport::WebRtc,
                worker,
                ConnectionId::new(),
            ),
            inbound_request(
                "tenant-b",
                "subject-tenant-b",
                None,
                Some(token.clone()),
                AttachmentTransport::Sip,
                worker,
                ConnectionId::new(),
            ),
            inbound_request(
                "tenant-a",
                "another-subject",
                None,
                Some(token.clone()),
                AttachmentTransport::Sip,
                worker,
                ConnectionId::new(),
            ),
            InboundAttachmentRequest::new(
                wrong_issuer,
                Some(token.clone()),
                AttachmentTransport::Sip,
                worker,
                ConnectionId::new(),
            ),
            inbound_request(
                "tenant-a",
                "subject-tenant-a",
                None,
                Some(token.clone()),
                AttachmentTransport::Sip,
                wrong_fence,
                ConnectionId::new(),
            ),
        ];
        for request in mismatches {
            assert_eq!(
                service.consume_inbound_attachment(request).await,
                Err(InboundAttachmentError::ProofRejected)
            );
        }

        let result = service
            .consume_inbound_attachment(inbound_request(
                "tenant-a",
                "subject-tenant-a",
                None,
                Some(token),
                AttachmentTransport::Sip,
                worker,
                ConnectionId::new(),
            ))
            .await
            .unwrap();
        assert_eq!(result.commit.call.aggregate.id(), call_id);
    }

    #[tokio::test]
    async fn configured_attachment_resolver_requires_exact_vapi_snapshot_and_preserves_generic_policy(
    ) {
        const REVISION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const OTHER_REVISION: &str =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let tenant = TenantId::parse("tenant-a").unwrap();
        let other_tenant = TenantId::parse("tenant-b").unwrap();
        let api_principal = PrincipalFingerprint::new([0x17; 32]);
        let mut vapi = authenticated_principal("tenant-a", "vapi-edge", None);
        vapi.issuer = Some("vapi-managed".into());
        let resolver = ConfiguredAttachmentPrincipalResolver::new().with_vapi_ingress(
            "vapi-public",
            REVISION,
            vapi.clone(),
        );
        let sip = LegExecutionSpec {
            leg_id: LegId::new(),
            endpoint: LegEndpointConfig::Sip(SipEndpointConfig {
                uri: None,
                initial_context: SipInitialContextMode::None,
            }),
        };
        let web = LegExecutionSpec {
            leg_id: LegId::new(),
            endpoint: LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
                signaling_uri: None,
            }),
        };
        let vapi_binding = NamedProfileBinding::new(
            NamedProfileRole::Ingress,
            NamedProfileKind::VapiIngress,
            "vapi-public",
            REVISION,
        )
        .unwrap();
        let exact =
            NamedRouteBinding::new_with_profiles("support", None, vec![vapi_binding.clone()])
                .unwrap();

        assert_eq!(
            resolver
                .resolve_principal(AttachmentPrincipalRequest {
                    tenant: &tenant,
                    leg: &sip,
                    named_route: Some(&exact),
                    api_principal,
                })
                .await
                .unwrap(),
            None
        );
        let resolved = resolver
            .resolve_authenticated_principal(AttachmentPrincipalRequest {
                tenant: &tenant,
                leg: &sip,
                named_route: Some(&exact),
                api_principal,
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resolved.subject, vapi.subject);
        assert_eq!(resolved.issuer, vapi.issuer);
        assert_eq!(resolved.tenant, vapi.tenant);

        let missing = NamedRouteBinding::new("support", None).unwrap();
        assert!(resolver
            .resolve_authenticated_principal(AttachmentPrincipalRequest {
                tenant: &tenant,
                leg: &sip,
                named_route: Some(&missing),
                api_principal,
            })
            .await
            .unwrap()
            .is_none());
        let revised = NamedRouteBinding::new_with_profiles(
            "support",
            None,
            vec![NamedProfileBinding::new(
                NamedProfileRole::Ingress,
                NamedProfileKind::VapiIngress,
                "vapi-public",
                OTHER_REVISION,
            )
            .unwrap()],
        )
        .unwrap();
        assert!(resolver
            .resolve_authenticated_principal(AttachmentPrincipalRequest {
                tenant: &tenant,
                leg: &sip,
                named_route: Some(&revised),
                api_principal,
            })
            .await
            .unwrap()
            .is_none());
        assert!(resolver
            .resolve_authenticated_principal(AttachmentPrincipalRequest {
                tenant: &other_tenant,
                leg: &sip,
                named_route: Some(&exact),
                api_principal,
            })
            .await
            .unwrap()
            .is_none());

        let web_binding = NamedProfileBinding::new(
            NamedProfileRole::Ingress,
            NamedProfileKind::WebRtc,
            "browser-public",
            OTHER_REVISION,
        )
        .unwrap();
        let mixed = NamedRouteBinding::new_with_profiles(
            "support",
            None,
            vec![vapi_binding.clone(), web_binding.clone()],
        )
        .unwrap();
        assert!(resolver
            .resolve_authenticated_principal(AttachmentPrincipalRequest {
                tenant: &tenant,
                leg: &sip,
                named_route: Some(&mixed),
                api_principal,
            })
            .await
            .unwrap()
            .is_none());
        assert!(NamedRouteBinding::new_with_profiles(
            "support",
            None,
            vec![vapi_binding.clone(), vapi_binding],
        )
        .is_err());

        let direct =
            NamedRouteBinding::new_with_profiles("direct", None, vec![web_binding]).unwrap();
        assert_eq!(
            resolver
                .resolve_principal(AttachmentPrincipalRequest {
                    tenant: &tenant,
                    leg: &web,
                    named_route: Some(&direct),
                    api_principal,
                })
                .await
                .unwrap(),
            Some(api_principal)
        );
        assert_eq!(
            resolver
                .resolve_principal(AttachmentPrincipalRequest {
                    tenant: &tenant,
                    leg: &sip,
                    named_route: None,
                    api_principal,
                })
                .await
                .unwrap(),
            Some(api_principal)
        );
    }

    #[tokio::test]
    async fn named_vapi_sip_token_rejects_api_owner_and_accepts_configured_listener_identity_once()
    {
        const REVISION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let repository = Arc::new(MemoryRepository::new());
        let clock = Arc::new(TestClock::new(at(0)));
        let worker = repository
            .register_worker(RegisterWorker {
                worker_id: WorkerId::new(),
                max_calls: 4,
                capabilities: test_worker_capabilities(),
                at: at(0),
                lease_ttl: std::time::Duration::from_secs(300),
            })
            .await
            .unwrap()
            .lease;
        let mut vapi = authenticated_principal("tenant-a", "vapi-edge", None);
        vapi.issuer = Some("vapi-managed".into());
        let resolver = ConfiguredAttachmentPrincipalResolver::new().with_vapi_ingress(
            "vapi-public",
            REVISION,
            vapi.clone(),
        );
        let service = CallService::new(
            repository,
            Arc::new(FixedWorkerPlacement::new(worker)),
            Arc::new(resolver),
            CallServiceCrypto::new(vec![0x61; 32]).unwrap(),
            clock.clone(),
            CallTimeoutPolicy::default(),
        );
        let owner = principal("tenant-a");
        let stale_route = NamedRouteBinding::new_with_profiles(
            "support",
            None,
            vec![NamedProfileBinding::new(
                NamedProfileRole::Ingress,
                NamedProfileKind::VapiIngress,
                "vapi-public",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )
            .unwrap()],
        )
        .unwrap();
        assert!(matches!(
            service
                .create_named_route_call(
                    &owner,
                    &IdempotencyKey::parse("named-vapi-stale-revision").unwrap(),
                    generic_input(),
                    stale_route,
                )
                .await,
            Err(CallServiceError::AttachmentPrincipalUnresolved)
        ));
        assert!(matches!(
            service
                .create_named_route_call(
                    &owner,
                    &IdempotencyKey::parse("named-vapi-missing-profile").unwrap(),
                    generic_input(),
                    NamedRouteBinding::new("support", None).unwrap(),
                )
                .await,
            Err(CallServiceError::AttachmentPrincipalUnresolved)
        ));
        let route = NamedRouteBinding::new_with_profiles(
            "support",
            None,
            vec![NamedProfileBinding::new(
                NamedProfileRole::Ingress,
                NamedProfileKind::VapiIngress,
                "vapi-public",
                REVISION,
            )
            .unwrap()],
        )
        .unwrap();
        let mut created = service
            .create_named_route_call(
                &owner,
                &IdempotencyKey::parse("named-vapi-identity").unwrap(),
                generic_input(),
                route,
            )
            .await
            .unwrap();
        let (call_id, _, token, _) = take_first_attachment(&mut created);
        clock.set(at(1));

        assert_eq!(
            service
                .consume_inbound_attachment(InboundAttachmentRequest::new(
                    owner.authenticated().clone(),
                    Some(token.clone()),
                    AttachmentTransport::Sip,
                    worker,
                    ConnectionId::new(),
                ))
                .await,
            Err(InboundAttachmentError::ProofRejected)
        );
        let consumed = service
            .consume_inbound_attachment(InboundAttachmentRequest::new(
                vapi.clone(),
                Some(token.clone()),
                AttachmentTransport::Sip,
                worker,
                ConnectionId::new(),
            ))
            .await
            .unwrap();
        assert_eq!(consumed.commit.call.aggregate.id(), call_id);
        assert_eq!(
            service
                .consume_inbound_attachment(InboundAttachmentRequest::new(
                    vapi,
                    Some(token),
                    AttachmentTransport::Sip,
                    worker,
                    ConnectionId::new(),
                ))
                .await,
            Err(InboundAttachmentError::ProofRejected)
        );
    }

    #[tokio::test]
    async fn inbound_attachment_service_duplicate_connection_rolls_back_second_proof() {
        let (_repository, service, clock, worker) = harness(4).await;
        let owner = principal("tenant-a");
        let mut first = service
            .create_call(
                &owner,
                &IdempotencyKey::parse("service-attachment-connection-first").unwrap(),
                generic_input(),
            )
            .await
            .unwrap();
        let mut second = service
            .create_call(
                &owner,
                &IdempotencyKey::parse("service-attachment-connection-second").unwrap(),
                generic_input(),
            )
            .await
            .unwrap();
        let (_, _, first_token, _) = take_first_attachment(&mut first);
        let (second_call_id, _, second_token, _) = take_first_attachment(&mut second);
        let retry_token = second_token.clone();
        let duplicate = ConnectionId::new();
        clock.set(at(1));
        service
            .consume_inbound_attachment(inbound_request(
                "tenant-a",
                "subject-tenant-a",
                None,
                Some(first_token),
                AttachmentTransport::Sip,
                worker,
                duplicate.clone(),
            ))
            .await
            .unwrap();
        assert_eq!(
            service
                .consume_inbound_attachment(inbound_request(
                    "tenant-a",
                    "subject-tenant-a",
                    None,
                    Some(second_token),
                    AttachmentTransport::Sip,
                    worker,
                    duplicate,
                ))
                .await,
            Err(InboundAttachmentError::ProofRejected)
        );

        let recovered = service
            .consume_inbound_attachment(inbound_request(
                "tenant-a",
                "subject-tenant-a",
                None,
                Some(retry_token),
                AttachmentTransport::Sip,
                worker,
                ConnectionId::new(),
            ))
            .await
            .unwrap();
        assert_eq!(recovered.commit.call.aggregate.id(), second_call_id);
    }

    #[tokio::test]
    async fn interleaved_inbound_attachment_proofs_cannot_cross_bind_calls() {
        let (_repository, service, clock, worker) = harness(4).await;
        let owner = principal("tenant-a");
        let mut first = service
            .create_call(
                &owner,
                &IdempotencyKey::parse("service-attachment-interleaved-first").unwrap(),
                generic_input(),
            )
            .await
            .unwrap();
        let mut second = service
            .create_call(
                &owner,
                &IdempotencyKey::parse("service-attachment-interleaved-second").unwrap(),
                generic_input(),
            )
            .await
            .unwrap();
        let (first_call_id, first_leg_id, first_token, _) = take_first_attachment(&mut first);
        let (second_call_id, second_leg_id, second_token, _) = take_first_attachment(&mut second);
        clock.set(at(1));
        let first_future = service.consume_inbound_attachment(inbound_request(
            "tenant-a",
            "subject-tenant-a",
            None,
            Some(first_token),
            AttachmentTransport::Sip,
            worker,
            ConnectionId::new(),
        ));
        let second_future = service.consume_inbound_attachment(inbound_request(
            "tenant-a",
            "subject-tenant-a",
            None,
            Some(second_token),
            AttachmentTransport::Sip,
            worker,
            ConnectionId::new(),
        ));
        let (first_result, second_result) = tokio::join!(first_future, second_future);
        let first_result = first_result.unwrap();
        let second_result = second_result.unwrap();
        assert_eq!(first_result.commit.call.aggregate.id(), first_call_id);
        assert_eq!(first_result.binding.leg_id, first_leg_id);
        assert_eq!(second_result.commit.call.aggregate.id(), second_call_id);
        assert_eq!(second_result.binding.leg_id, second_leg_id);
        assert_ne!(
            first_result.binding.connection_id,
            second_result.binding.connection_id
        );
    }

    #[tokio::test]
    async fn concurrent_legs_of_one_call_retry_the_optimistic_attachment_race() {
        let repository = Arc::new(MemoryRepository::new());
        let clock = Arc::new(TestClock::new(at(0)));
        let worker = repository
            .register_worker(RegisterWorker {
                worker_id: WorkerId::new(),
                max_calls: 2,
                capabilities: test_worker_capabilities(),
                at: at(0),
                lease_ttl: Duration::from_secs(300),
            })
            .await
            .unwrap()
            .lease;
        let creator = CallService::new(
            repository.clone(),
            Arc::new(FixedWorkerPlacement::new(worker)),
            Arc::new(SamePrincipalAttachmentResolver),
            CallServiceCrypto::new(vec![0x79; 32]).unwrap(),
            clock.clone(),
            CallTimeoutPolicy::default(),
        );
        let owner = principal("tenant-a");
        let mut created = creator
            .create_call(
                &owner,
                &IdempotencyKey::parse("same-call-concurrent-attachments").unwrap(),
                two_inbound_input(),
            )
            .await
            .unwrap();
        let blocking = Arc::new(BlockingAttachmentRepository::new(
            repository.clone(),
            clock.clone(),
        ));
        let service = Arc::new(CallService::new(
            blocking.clone(),
            Arc::new(FixedWorkerPlacement::new(worker)),
            Arc::new(SamePrincipalAttachmentResolver),
            CallServiceCrypto::new(vec![0x79; 32]).unwrap(),
            clock.clone(),
            CallTimeoutPolicy::default(),
        ));
        let call_id = created.value.call.call_id;
        let first_leg_id = created.value.call.legs[0].leg_id;
        let second_leg_id = created.value.call.legs[1].leg_id;
        let first_token = std::mem::take(
            &mut created.value.call.legs[0]
                .attachment
                .as_mut()
                .unwrap()
                .token,
        );
        let second_token = std::mem::take(
            &mut created.value.call.legs[1]
                .attachment
                .as_mut()
                .unwrap()
                .token,
        );
        let first_connection = ConnectionId::new();
        let second_connection = ConnectionId::new();

        clock.set(at(1));
        blocking.synchronize_next_two_inspections();
        let first = {
            let service = service.clone();
            let connection_id = first_connection.clone();
            tokio::spawn(async move {
                service
                    .consume_inbound_attachment(inbound_request(
                        "tenant-a",
                        "subject-tenant-a",
                        None,
                        Some(first_token),
                        AttachmentTransport::Sip,
                        worker,
                        connection_id,
                    ))
                    .await
            })
        };
        let second = {
            let service = service.clone();
            let connection_id = second_connection.clone();
            tokio::spawn(async move {
                service
                    .consume_inbound_attachment(inbound_request(
                        "tenant-a",
                        "subject-tenant-a",
                        None,
                        Some(second_token),
                        AttachmentTransport::WebRtc,
                        worker,
                        connection_id,
                    ))
                    .await
            })
        };
        let first = first.await.unwrap().unwrap();
        let second = second.await.unwrap().unwrap();

        assert_eq!(first.commit.call.aggregate.id(), call_id);
        assert_eq!(second.commit.call.aggregate.id(), call_id);
        assert_eq!(first.binding.leg_id, first_leg_id);
        assert_eq!(second.binding.leg_id, second_leg_id);
        assert_eq!(first.binding.connection_id, first_connection);
        assert_eq!(second.binding.connection_id, second_connection);
        let stored = repository
            .load_service_call(&TenantId::parse("tenant-a").unwrap(), call_id)
            .await
            .unwrap();
        assert_eq!(stored.call.bindings.len(), 2);
        assert!(stored
            .call
            .aggregate
            .legs()
            .iter()
            .all(|leg| leg.state() == LegState::Signaling));
    }

    #[tokio::test]
    async fn attachment_is_principal_worker_expiry_and_single_use_bound() {
        let (repository, service, clock, worker) = harness(4).await;
        let owner = principal("tenant-a");
        let created = service
            .create_call(
                &owner,
                &IdempotencyKey::parse("attach-1").unwrap(),
                generic_input(),
            )
            .await
            .unwrap();
        let call_id = created.value.call.call_id;
        let leg = &created.value.call.legs[0];
        let attachment = leg.attachment.as_ref().unwrap();
        let lookup = AttachmentLookup {
            token_digest: token_digest(&attachment.token),
            tenant_id: TenantId::parse("tenant-a").unwrap(),
            transport: AttachmentTransport::Sip,
            principal_fingerprint: service.crypto.principal_fingerprint(&owner),
            worker,
            at: at(1),
        };
        let candidate = repository.inspect_attachment(lookup.clone()).await.unwrap();
        repository
            .consume_attachment(AttachmentConsume {
                candidate,
                command_id: CommandId::new(),
                command: CallCommand::SetLegState {
                    at: at(1),
                    leg_id: leg.leg_id,
                    binding_generation: BindingGeneration::INITIAL,
                    state: LegState::Signaling,
                    failure: None,
                },
                connection_id: ConnectionId::new(),
                principal_fingerprint: service.crypto.principal_fingerprint(&owner),
                principal_expires_at: None,
                at: at(1),
            })
            .await
            .unwrap();
        assert_eq!(
            repository.inspect_attachment(lookup).await.unwrap_err(),
            RepositoryError::AttachmentRejected
        );

        clock.set(at(2));
        let second = service
            .create_call(
                &owner,
                &IdempotencyKey::parse("attach-2").unwrap(),
                generic_input(),
            )
            .await
            .unwrap();
        let second_leg = &second.value.call.legs[0];
        let second_attachment = second_leg.attachment.as_ref().unwrap();
        assert_eq!(
            repository
                .inspect_attachment(AttachmentLookup {
                    token_digest: token_digest(&second_attachment.token),
                    tenant_id: TenantId::parse("tenant-a").unwrap(),
                    transport: AttachmentTransport::Sip,
                    principal_fingerprint: service.crypto.principal_fingerprint(&owner),
                    worker,
                    at: second_attachment.expires_at,
                })
                .await
                .unwrap_err(),
            RepositoryError::AttachmentRejected
        );
        assert_ne!(call_id, second.value.call.call_id);
    }

    #[tokio::test]
    async fn provider_media_attachment_is_hidden_reconstructible_and_principal_bound() {
        let repository = Arc::new(MemoryRepository::new());
        let clock = Arc::new(TestClock::new(at(0)));
        let worker = repository
            .register_worker(RegisterWorker {
                worker_id: WorkerId::new(),
                max_calls: 1,
                capabilities: BTreeSet::from(["sip".into(), "telnyx".into()]),
                at: at(0),
                lease_ttl: Duration::from_secs(300),
            })
            .await
            .unwrap()
            .lease;
        let provider_principal = AuthenticatedPrincipal {
            subject: "telnyx-media".into(),
            tenant: Some("tenant-a".into()),
            scopes: Vec::new(),
            issuer: Some("sip-digest:bridgefu".into()),
            expires_at: None,
            method: AuthenticationMethod::SipDigest,
            assurance: IdentityAssurance::Identified {
                credential_kind: CredentialKind::SipDigest,
            },
        };
        let service = CallService::new(
            repository.clone(),
            Arc::new(FixedWorkerPlacement::new(worker)),
            Arc::new(ConfiguredAttachmentPrincipalResolver::new().with_provider(
                ProviderKind::Telnyx,
                "telnyx-test",
                provider_principal.clone(),
            )),
            CallServiceCrypto::new(vec![0x79; 32]).unwrap(),
            clock,
            CallTimeoutPolicy::default(),
        );
        let owner = principal("tenant-a");
        let created = service
            .create_call(
                &owner,
                &IdempotencyKey::parse("provider-media-hidden").unwrap(),
                CreateCallInput {
                    tenant_id: None,
                    legs: [
                        RequestedLeg {
                            direction: LegDirection::Inbound,
                            signaling_initiator: None,
                            media_flow: MediaFlow::SendReceive,
                            endpoint: LegEndpointConfig::Sip(SipEndpointConfig {
                                uri: None,
                                initial_context: Default::default(),
                            }),
                            amazon_connect_start: None,
                        },
                        RequestedLeg {
                            direction: LegDirection::Outbound,
                            signaling_initiator: None,
                            media_flow: MediaFlow::SendReceive,
                            endpoint: LegEndpointConfig::Provider(ProviderEndpointConfig {
                                provider: ProviderKind::Telnyx,
                                account_profile: "telnyx-test".into(),
                                destination: Some("+15551234567".into()),
                            }),
                            amazon_connect_start: None,
                        },
                    ],
                },
            )
            .await
            .unwrap();
        let provider_leg = created
            .value
            .call
            .legs
            .iter()
            .find(|leg| leg.kind == crate::call_engine::LegKind::Telnyx)
            .expect("provider leg");
        assert!(provider_leg.attachment.is_none());
        let public_json = serde_json::to_value(&created.value).unwrap();
        assert!(public_json["legs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|leg| leg["kind"] == "telnyx")
            .unwrap()
            .get("attachment")
            .is_none());

        let stored = repository
            .load_service_call(
                &TenantId::parse("tenant-a").unwrap(),
                created.value.call.call_id,
            )
            .await
            .unwrap();
        let provider_descriptor = stored
            .attachments
            .iter()
            .find(|attachment| attachment.leg_id == provider_leg.leg_id)
            .expect("hidden provider descriptor");
        assert_eq!(
            provider_descriptor.purpose,
            AttachmentPurpose::ProviderMedia
        );
        let reconstructed = service
            .provider_media_attachment_token(&stored, provider_leg.leg_id)
            .unwrap();
        let raw_token = reconstructed.expose_secret().to_owned();
        assert!(!format!("{reconstructed:?}").contains(&raw_token));

        assert_eq!(
            service
                .consume_inbound_attachment(InboundAttachmentRequest::new(
                    authenticated_principal("tenant-a", "wrong-provider", None),
                    Some(raw_token.clone()),
                    AttachmentTransport::Sip,
                    worker,
                    ConnectionId::from_string("wrong-provider-media"),
                ))
                .await,
            Err(InboundAttachmentError::ProofRejected)
        );
        let attached = service
            .consume_inbound_attachment(InboundAttachmentRequest::new(
                provider_principal,
                Some(raw_token),
                AttachmentTransport::Sip,
                worker,
                ConnectionId::from_string("telnyx-provider-media"),
            ))
            .await
            .unwrap();
        assert_eq!(attached.binding.leg_id, provider_leg.leg_id);
    }

    #[tokio::test]
    async fn remote_initiated_provider_leg_fails_before_profile_resolution() {
        let (repository, service, _, _) = harness(2).await;
        let input = CreateCallInput {
            tenant_id: None,
            legs: [
                RequestedLeg {
                    direction: LegDirection::Inbound,
                    signaling_initiator: None,
                    media_flow: MediaFlow::SendReceive,
                    endpoint: LegEndpointConfig::Provider(ProviderEndpointConfig {
                        provider: ProviderKind::Telnyx,
                        account_profile: "telnyx-test".into(),
                        destination: None,
                    }),
                    amazon_connect_start: None,
                },
                generic_input().legs[1].clone(),
            ],
        };
        assert_eq!(
            service
                .create_call(
                    &principal("tenant-a"),
                    &IdempotencyKey::parse("provider-inbound").unwrap(),
                    input,
                )
                .await
                .unwrap_err(),
            CallServiceError::Repository(RepositoryError::InvalidInput(
                "provider-controlled legs require Bridgefu signaling initiation"
            ))
        );
        assert_eq!(repository.counts().unwrap().calls, 0);
    }

    #[tokio::test]
    async fn new_twilio_and_vonage_work_fails_with_deferred_capability() {
        let (repository, service, _, _) = harness(4).await;
        let owner = principal("tenant-a");

        for (provider, suffix) in [
            (ProviderKind::Twilio, "twilio"),
            (ProviderKind::Vonage, "vonage"),
        ] {
            let mut input = generic_input();
            input.legs[1] = RequestedLeg {
                direction: LegDirection::Outbound,
                signaling_initiator: None,
                media_flow: MediaFlow::SendReceive,
                endpoint: LegEndpointConfig::Provider(ProviderEndpointConfig {
                    provider,
                    account_profile: format!("{suffix}-test"),
                    destination: Some("+15551234567".into()),
                }),
                amazon_connect_start: None,
            };
            assert_eq!(
                service
                    .create_call(
                        &owner,
                        &IdempotencyKey::parse(format!("deferred-{suffix}")).unwrap(),
                        input,
                    )
                    .await
                    .unwrap_err(),
                CallServiceError::ProviderDeferred
            );
        }
        assert_eq!(repository.counts().unwrap().calls, 0);

        let created = service
            .create_call(
                &owner,
                &IdempotencyKey::parse("deferred-transfer-call").unwrap(),
                generic_input(),
            )
            .await
            .unwrap();
        for (provider, suffix) in [
            (ProviderKind::Twilio, "twilio"),
            (ProviderKind::Vonage, "vonage"),
        ] {
            assert_eq!(
                service
                    .transfer_call(
                        &owner,
                        created.value.call.call_id,
                        &IdempotencyKey::parse(format!("deferred-transfer-{suffix}")).unwrap(),
                        TransferCallInput {
                            tenant_id: None,
                            target_leg_id: created.value.call.legs[0].leg_id,
                            target: TransferTarget::Provider {
                                provider,
                                account_profile: format!("{suffix}-test"),
                                destination: "+15557654321".into(),
                            },
                        },
                    )
                    .await
                    .unwrap_err(),
                CallServiceError::ProviderDeferred
            );
        }
    }

    #[tokio::test]
    async fn deferred_provider_transfer_replays_an_existing_exact_receipt() {
        let (repository, service, clock, worker) = harness(2).await;
        let owner = principal("tenant-a");
        let created = service
            .create_call(
                &owner,
                &IdempotencyKey::parse("deferred-replay-create").unwrap(),
                two_inbound_input(),
            )
            .await
            .unwrap();
        connect_created_call(&repository, &service, &owner, worker, &created.value).await;
        clock.set(at(5));

        let input = TransferCallInput {
            tenant_id: None,
            target_leg_id: created.value.call.legs[0].leg_id,
            target: TransferTarget::Provider {
                provider: ProviderKind::Twilio,
                account_profile: "legacy-twilio".into(),
                destination: "+15551234567".into(),
            },
        };
        let key = IdempotencyKey::parse("legacy-twilio-transfer").unwrap();
        let tenant = TenantId::parse("tenant-a").unwrap();
        let stored = repository
            .load_service_call(&tenant, created.value.call.call_id)
            .await
            .unwrap();
        let target_leg = stored
            .call
            .aggregate
            .leg(input.target_leg_id)
            .expect("connected target leg");
        let mut transcript = CanonicalRequestTranscript::new();
        transcript.push_bytes(input.target_leg_id.as_uuid().as_bytes());
        push_transfer_target(&mut transcript, &input.target);
        let operation = service.operation(
            &tenant,
            service.crypto.principal_fingerprint(&owner),
            &key,
            ServiceOperationKind::TransferCall,
            created.value.call.call_id,
            transcript,
        );
        let committed = repository
            .commit_with_effect_payloads(ServiceCommandTransaction {
                command: crate::call_engine::CommandCommit {
                    tenant_id: tenant,
                    call_id: created.value.call.call_id,
                    expected_version: stored.call.aggregate.version(),
                    command_id: CommandId::new(),
                    command: CallCommand::BeginTransfer {
                        at: at(5),
                        transfer_deadline: at(35),
                    },
                    worker: stored.call.assignment.lease,
                    attachments: Vec::new(),
                    deadline_claim: None,
                    at: at(5),
                },
                effect_payloads: vec![ServiceEffectPayloadInput {
                    ordinal: 1,
                    payload: ServiceEffectPayload::Transfer {
                        target_leg_id: input.target_leg_id,
                        target_binding_generation: target_leg.binding_generation(),
                        target: input.target.clone(),
                    },
                }],
                operation_idempotency: Some(operation),
                bound_connection: None,
                media_activity: None,
                replacement_connection: None,
            })
            .await
            .unwrap();
        let ServiceCommandOutcome::Committed(committed) = committed else {
            panic!("legacy transfer must commit once")
        };

        let replayed = service
            .transfer_call(&owner, created.value.call.call_id, &key, input)
            .await
            .unwrap();
        assert!(replayed.replayed);
        assert_eq!(
            replayed.value,
            CallView::from_aggregate(&committed.command.call.aggregate)
        );
    }

    #[tokio::test]
    async fn hangup_replays_original_result_even_after_call_becomes_terminal() {
        let (repository, service, clock, worker) = harness(2).await;
        let owner = principal("tenant-a");
        let created = service
            .create_call(
                &owner,
                &IdempotencyKey::parse("create-ending").unwrap(),
                generic_input(),
            )
            .await
            .unwrap();
        let call_id = created.value.call.call_id;
        clock.set(at(1));
        let key = IdempotencyKey::parse("hangup-1").unwrap();
        let ending = service
            .hangup_call(&owner, call_id, &key, CallMutationInput::default())
            .await
            .unwrap();
        assert_eq!(ending.value.state, CallState::Ending);

        for second in [2, 3] {
            let current = repository
                .load_call(&TenantId::parse("tenant-a").unwrap(), call_id)
                .await
                .unwrap();
            let leg = current
                .aggregate
                .legs()
                .iter()
                .find(|leg| !leg.state().is_terminal())
                .unwrap();
            repository
                .commit_with_effect_payloads(ServiceCommandTransaction {
                    command: CommandCommit {
                        tenant_id: TenantId::parse("tenant-a").unwrap(),
                        call_id,
                        expected_version: current.aggregate.version(),
                        command_id: CommandId::new(),
                        command: CallCommand::SetLegState {
                            at: at(second),
                            leg_id: leg.id(),
                            binding_generation: leg.binding_generation(),
                            state: LegState::Ended,
                            failure: None,
                        },
                        worker,
                        attachments: Vec::new(),
                        deadline_claim: None,
                        at: at(second),
                    },
                    effect_payloads: Vec::new(),
                    operation_idempotency: None,
                    bound_connection: None,
                    media_activity: None,
                    replacement_connection: None,
                })
                .await
                .unwrap();
        }
        clock.set(at(4));
        let replayed = service
            .hangup_call(&owner, call_id, &key, CallMutationInput::default())
            .await
            .unwrap();
        assert!(replayed.replayed);
        assert_eq!(replayed.value, ending.value);
    }

    #[tokio::test]
    async fn dtmf_and_transfer_are_durable_replayable_and_share_one_key_namespace() {
        let (repository, service, clock, worker) = harness(2).await;
        let owner = principal("tenant-a");
        let created = service
            .create_call(
                &owner,
                &IdempotencyKey::parse("create-active").unwrap(),
                two_inbound_input(),
            )
            .await
            .unwrap();
        connect_created_call(&repository, &service, &owner, worker, &created.value).await;
        clock.set(at(5));

        let dtmf_key = IdempotencyKey::parse("control-1").unwrap();
        let dtmf_input = DtmfCallInput {
            tenant_id: None,
            leg_id: created.value.call.legs[0].leg_id,
            digits: "12#A".into(),
            duration_ms: 120,
            gap_ms: 70,
        };
        let accepted = service
            .send_dtmf(
                &owner,
                created.value.call.call_id,
                &dtmf_key,
                dtmf_input.clone(),
            )
            .await
            .unwrap();
        assert!(!accepted.replayed);
        let replayed = service
            .send_dtmf(
                &owner,
                created.value.call.call_id,
                &dtmf_key,
                dtmf_input.clone(),
            )
            .await
            .unwrap();
        assert!(replayed.replayed);
        assert_eq!(replayed.value, accepted.value);

        let mut changed = dtmf_input;
        changed.digits = "9".into();
        assert!(matches!(
            service
                .send_dtmf(&owner, created.value.call.call_id, &dtmf_key, changed,)
                .await,
            Err(CallServiceError::Repository(
                RepositoryError::IdempotencyConflict
            ))
        ));
        assert!(matches!(
            service
                .hangup_call(
                    &owner,
                    created.value.call.call_id,
                    &dtmf_key,
                    CallMutationInput::default(),
                )
                .await,
            Err(CallServiceError::Repository(
                RepositoryError::IdempotencyConflict
            ))
        ));

        let transfer_key = IdempotencyKey::parse("transfer-1").unwrap();
        let transfer_input = TransferCallInput {
            tenant_id: None,
            target_leg_id: created.value.call.legs[0].leg_id,
            target: TransferTarget::Sip {
                uri: "sip:queue@sip.example.test".into(),
            },
        };
        let transferred = service
            .transfer_call(
                &owner,
                created.value.call.call_id,
                &transfer_key,
                transfer_input.clone(),
            )
            .await
            .unwrap();
        assert_eq!(transferred.value.state, CallState::Transferring);
        let mut changed_leg = transfer_input.clone();
        changed_leg.target_leg_id = created.value.call.legs[1].leg_id;
        assert!(matches!(
            service
                .transfer_call(
                    &owner,
                    created.value.call.call_id,
                    &transfer_key,
                    changed_leg,
                )
                .await,
            Err(CallServiceError::Repository(
                RepositoryError::IdempotencyConflict
            ))
        ));
        let replayed_transfer = service
            .transfer_call(
                &owner,
                created.value.call.call_id,
                &transfer_key,
                transfer_input,
            )
            .await
            .unwrap();
        assert!(replayed_transfer.replayed);
        assert_eq!(replayed_transfer.value, transferred.value);
    }

    #[tokio::test]
    async fn unsupported_transfer_capability_is_rejected_before_durable_state_changes() {
        let (repository, service, clock, worker) = harness(2).await;
        let owner = principal("tenant-a");
        let created = service
            .create_call(
                &owner,
                &IdempotencyKey::parse("unsupported-transfer-create").unwrap(),
                two_inbound_input(),
            )
            .await
            .unwrap();
        connect_created_call(&repository, &service, &owner, worker, &created.value).await;
        clock.set(at(5));
        let web_rtc_leg = created
            .value
            .call
            .legs
            .iter()
            .find(|leg| leg.kind == crate::call_engine::LegKind::InteractiveWebRtc)
            .expect("WebRTC leg");
        let before = repository.counts().unwrap();

        assert_eq!(
            service
                .transfer_call(
                    &owner,
                    created.value.call.call_id,
                    &IdempotencyKey::parse("unsupported-transfer").unwrap(),
                    TransferCallInput {
                        tenant_id: None,
                        target_leg_id: web_rtc_leg.leg_id,
                        target: TransferTarget::WebRtc {
                            uri: "https://webrtc.example.test/transfer".into(),
                        },
                    },
                )
                .await,
            Err(CallServiceError::UnsupportedCapability)
        );

        let stored = repository
            .load_service_call(
                &TenantId::parse("tenant-a").unwrap(),
                created.value.call.call_id,
            )
            .await
            .unwrap();
        assert_eq!(stored.call.aggregate.state(), CallState::Active);
        assert_eq!(
            stored
                .call
                .aggregate
                .deadlines()
                .get(DeadlineKind::Transfer)
                .due_at(),
            None
        );
        assert_eq!(repository.counts().unwrap(), before);
    }

    #[tokio::test]
    async fn service_applies_media_idle_policy_to_exact_activity_generation() {
        let (repository, service, _, worker) = harness(1).await;
        let owner = principal("tenant-a");
        let created = service
            .create_call(
                &owner,
                &IdempotencyKey::parse("create-media-idle").unwrap(),
                two_inbound_input(),
            )
            .await
            .unwrap();
        connect_created_call(&repository, &service, &owner, worker, &created.value).await;
        let tenant = TenantId::parse("tenant-a").unwrap();
        let stored = repository
            .load_service_call(&tenant, created.value.call.call_id)
            .await
            .unwrap();
        let leg_id = stored.call.aggregate.legs()[0].id();
        let binding = stored.call.bindings.get(&leg_id).unwrap();
        let observation = MediaActivityObservation {
            tenant_id: tenant,
            call_id: stored.call.aggregate.id(),
            expected_version: stored.call.aggregate.version(),
            command_id: CommandId::new(),
            leg_id,
            binding_generation: binding.binding_generation,
            connection_id: binding.connection_id.clone(),
            activity_generation: MediaActivityGeneration::INITIAL,
            worker,
            at: at(5),
        };
        let ServiceCommandOutcome::Committed(view) = service
            .record_media_activity(observation.clone())
            .await
            .unwrap()
        else {
            panic!("fresh media activity replayed")
        };
        assert_eq!(
            view.command
                .call
                .aggregate
                .deadlines()
                .get(crate::call_engine::DeadlineKind::Media)
                .due_at(),
            Some(at(35))
        );
        assert_eq!(
            service.record_media_activity(observation).await.unwrap(),
            ServiceCommandOutcome::Replayed(view)
        );
    }

    #[tokio::test]
    async fn capacity_and_scope_fail_without_partial_call() {
        let (repository, service, _, _) = harness(1).await;
        service
            .create_call(
                &principal("tenant-a"),
                &IdempotencyKey::parse("capacity-1").unwrap(),
                generic_input(),
            )
            .await
            .unwrap();
        assert!(matches!(
            service
                .create_call(
                    &principal("tenant-a"),
                    &IdempotencyKey::parse("capacity-2").unwrap(),
                    generic_input(),
                )
                .await,
            Err(CallServiceError::Repository(
                RepositoryError::CapacityExceeded
            ))
        ));
        assert_eq!(repository.counts().unwrap().calls, 1);

        let read_only = ApiPrincipal::new(
            AuthenticatedPrincipal {
                subject: "read-only".into(),
                tenant: Some("tenant-a".into()),
                scopes: vec![CallScope::Read.as_str().into()],
                issuer: Some("test".into()),
                expires_at: None,
                method: AuthenticationMethod::Jwt,
                assurance: IdentityAssurance::Pseudonymous {
                    ephemeral_key: Jwk(serde_json::json!({"kty":"test"})),
                },
            },
            at(0),
        )
        .unwrap();
        assert!(matches!(
            service
                .create_call(
                    &read_only,
                    &IdempotencyKey::parse("forbidden").unwrap(),
                    generic_input(),
                )
                .await,
            Err(CallServiceError::Principal(
                ApiPrincipalError::MissingScope("calls:create")
            ))
        ));
    }

    #[test]
    fn worker_fence_changes_attachment_token() {
        let crypto = CallServiceCrypto::new(vec![0x71; 32]).unwrap();
        let tenant = TenantId::parse("tenant-a").unwrap();
        let call_id = CallId::new();
        let leg_id = LegId::new();
        let fingerprint = crypto.principal_fingerprint(&principal("tenant-a"));
        let worker_id = WorkerId::new();
        let first = crypto
            .attachment_token(AttachmentTokenContext {
                tenant: &tenant,
                call_id,
                leg_id,
                generation: BindingGeneration::INITIAL,
                transport: AttachmentTransport::Sip,
                purpose: AttachmentPurpose::PublicInbound,
                worker: WorkerLease {
                    worker_id,
                    fence: crate::call_engine::WorkerFence::INITIAL,
                },
                principal: fingerprint,
                created_at: at(0),
            })
            .unwrap();
        let second_fence: crate::call_engine::WorkerFence = serde_json::from_str("2").unwrap();
        let second = crypto
            .attachment_token(AttachmentTokenContext {
                tenant: &tenant,
                call_id,
                leg_id,
                generation: BindingGeneration::INITIAL,
                transport: AttachmentTransport::Sip,
                purpose: AttachmentPurpose::PublicInbound,
                worker: WorkerLease {
                    worker_id,
                    fence: second_fence,
                },
                principal: fingerprint,
                created_at: at(0),
            })
            .unwrap();
        assert_ne!(first.digest, second.digest);
        assert_ne!(first.expose_secret(), second.expose_secret());
    }

    #[test]
    fn replacement_profile_revision_is_canonical_idempotency_authority() {
        let crypto = CallServiceCrypto::new(vec![0x72; 32]).unwrap();
        let tenant = TenantId::parse("tenant-a").unwrap();
        let principal = crypto.principal_fingerprint(&principal("tenant-a"));
        let key = IdempotencyKey::parse("replacement-profile-digest").unwrap();
        let call_id = CallId::new();
        let operation = |route: &NamedRouteBinding| {
            let mut transcript = CanonicalRequestTranscript::new();
            transcript.push_str("bridgefu.leg-replacement.v2");
            push_replacement_route(&mut transcript, route);
            crypto.operation_idempotency(
                &tenant,
                principal,
                &key,
                ServiceOperationKind::TransferCall,
                Some(call_id),
                &transcript,
            )
        };
        let ingress = NamedProfileBinding::new(
            NamedProfileRole::Ingress,
            NamedProfileKind::WebRtc,
            "browser",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap();
        let destination = |revision: &str| {
            NamedProfileBinding::new(
                NamedProfileRole::Destination,
                NamedProfileKind::Sip,
                "support",
                revision,
            )
            .unwrap()
        };
        let first = NamedRouteBinding::new_with_profiles(
            "support",
            None,
            vec![
                ingress.clone(),
                destination("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            ],
        )
        .unwrap();
        let reordered = NamedRouteBinding::new_with_profiles(
            "support",
            None,
            vec![
                destination("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
                ingress.clone(),
            ],
        )
        .unwrap();
        let revised = NamedRouteBinding::new_with_profiles(
            "support",
            None,
            vec![
                ingress,
                destination("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
            ],
        )
        .unwrap();
        assert_eq!(
            operation(&first).request_digest,
            operation(&reordered).request_digest
        );
        assert_ne!(
            operation(&first).request_digest,
            operation(&revised).request_digest
        );
    }

    #[test]
    fn dtmf_input_debug_redacts_digits() {
        let input = DtmfCallInput {
            tenant_id: Some("tenant-a".into()),
            leg_id: LegId::new(),
            digits: "1234#A".into(),
            duration_ms: 120,
            gap_ms: 70,
        };
        let rendered = format!("{input:?}");
        assert!(rendered.contains("[redacted]"));
        assert!(!rendered.contains("1234#A"));
    }
}
