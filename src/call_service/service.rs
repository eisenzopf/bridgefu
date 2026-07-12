//! Authenticated transactional application service for the versioned call API.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::api_principal::{ApiPrincipal, ApiPrincipalError, CallScope};
use crate::call_engine::{
    AttachmentId, AttachmentIssue, AttachmentTransport, CallAggregate, CallCommand, CallId,
    CommandId, LegDirection, LegId, LegSpec, PrincipalFingerprint, RepositoryError, StopLegReason,
    TenantId, WorkerLease,
};

use super::{
    AmazonConnectEndpointConfig, AttachmentTokenContext, AttachmentView, CallExecutionPlan,
    CallOperationResult, CallServiceCrypto, CallServiceRepository, CallView,
    CanonicalRequestTranscript, ControlCommandOutcome, ControlCommandTransaction, ControlIntent,
    CreateCallView, DtmfAcceptedView, DtmfSequence, IdempotencyKey, LegEndpointConfig,
    LegExecutionSpec, OperationIdempotency, ProviderEndpointConfig, ProviderKind,
    ServiceCommandOutcome, ServiceCommandTransaction, ServiceCreateOutcome,
    ServiceCreateTransaction, ServiceEffectPayload, ServiceEffectPayloadInput,
    ServiceOperationKind, SipEndpointConfig, StoredServiceCall, TransferTarget,
    WebRtcEndpointConfig, WhepEndpointConfig, WhipEndpointConfig,
};

/// One API-requested logical leg.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedLeg {
    /// Direction relative to Bridgefu.
    pub direction: LegDirection,
    /// Typed, credential-free endpoint configuration.
    pub endpoint: LegEndpointConfig,
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
    /// Typed transfer destination.
    pub target: TransferTarget,
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
    /// Selects a current worker fence for a validated two-leg execution plan.
    async fn select_worker(
        &self,
        tenant: &TenantId,
        plan: &CallExecutionPlan,
        at: DateTime<Utc>,
    ) -> Result<WorkerLease, PlacementError>;
}

/// Safe worker-placement failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PlacementError {
    /// No worker currently has capacity.
    #[error("worker capacity exhausted")]
    CapacityExceeded,
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
    async fn select_worker(
        &self,
        _tenant: &TenantId,
        _plan: &CallExecutionPlan,
        _at: DateTime<Utc>,
    ) -> Result<WorkerLease, PlacementError> {
        Ok(self.worker)
    }
}

/// Validated inbound leg passed to signaling-principal policy.
pub struct AttachmentPrincipalRequest<'a> {
    /// Authenticated call owner tenant.
    pub tenant: &'a TenantId,
    /// Validated execution spec; profiles are configured names, not credentials.
    pub leg: &'a LegExecutionSpec,
    /// Ownership fingerprint of the API principal that created the call.
    pub api_principal: PrincipalFingerprint,
}

impl fmt::Debug for AttachmentPrincipalRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AttachmentPrincipalRequest")
            .field("tenant", self.tenant)
            .field("leg", self.leg)
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

/// Lifecycle deadline policy retained by the transactional service.
#[derive(Clone, Copy, Debug)]
pub struct CallTimeoutPolicy {
    /// Maximum setup time.
    pub setup: Duration,
    /// Maximum native/signaling transfer time.
    pub transfer: Duration,
    /// Maximum peer teardown time.
    pub ending: Duration,
}

impl Default for CallTimeoutPolicy {
    fn default() -> Self {
        Self {
            setup: Duration::from_secs(30),
            transfer: Duration::from_secs(30),
            ending: Duration::from_secs(30),
        }
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
    /// Request violated a service boundary invariant.
    #[error("invalid call request: {0}")]
    InvalidInput(&'static str),
    /// Current durable state cannot perform the requested operation.
    #[error("call state does not allow this operation")]
    InvalidTransition,
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

    /// Authenticates ownership, reserves a worker, and creates both legs atomically.
    pub async fn create_call(
        &self,
        principal: &ApiPrincipal,
        key: &IdempotencyKey,
        input: CreateCallInput,
    ) -> Result<CallOperationResult<CreateCallView>, CallServiceError> {
        let at = self.clock.now();
        let tenant = principal.resolve_tenant(input.tenant_id.as_deref(), CallScope::Create, at)?;
        let owner_fingerprint = self.crypto.principal_fingerprint(principal);
        let transcript = create_transcript(&input.legs);
        let operation = self.crypto.operation_idempotency(
            &tenant,
            owner_fingerprint,
            key,
            ServiceOperationKind::CreateCall,
            None,
            &transcript,
        );
        if let Some(stored) = self
            .repository
            .load_create_replay(&tenant, operation.key_digest, operation.request_digest, at)
            .await?
        {
            return self.create_view(stored, true);
        }
        let aggregate = CallAggregate::new(
            tenant.clone(),
            input.legs.clone().map(|leg| LegSpec {
                direction: leg.direction,
                kind: leg.endpoint.kind(),
            }),
            at,
        );
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
        )?;

        let resolved_principals = match self
            .resolve_attachment_principals(&tenant, &aggregate, &plan, owner_fingerprint)
            .await
        {
            Ok(principals) => principals,
            Err(error) => {
                // A concurrent request may commit while profile resolution is
                // blocked or failing. Its durable receipt outranks dependency
                // health and contains the original attachment descriptors.
                if let Some(stored) = self
                    .repository
                    .load_create_replay(&tenant, operation.key_digest, operation.request_digest, at)
                    .await?
                {
                    return self.create_view(stored, true);
                }
                return Err(error);
            }
        };
        let worker = match self.placement.select_worker(&tenant, &plan, at).await {
            Ok(worker) => worker,
            Err(error) => {
                // A concurrent request may have won after the preflight. Exact
                // retained results outrank current placement health/capacity.
                if let Some(stored) = self
                    .repository
                    .load_create_replay(&tenant, operation.key_digest, operation.request_digest, at)
                    .await?
                {
                    return self.create_view(stored, true);
                }
                return Err(map_placement_error(error));
            }
        };
        let setup_deadline = checked_deadline(at, self.timeouts.setup)?;
        let command = CallCommand::StartConnecting { at, setup_deadline };
        let decided = aggregate
            .decide(command.clone())
            .map_err(|_| CallServiceError::InvalidTransition)?;
        let attachments = self.attachment_issues(
            &tenant,
            decided.aggregate(),
            &resolved_principals,
            worker,
            at,
        )?;
        let outcome = self
            .repository
            .create_with_plan(ServiceCreateTransaction {
                create: crate::call_engine::CreateCall {
                    initial: aggregate,
                    command_id: CommandId::new(),
                    command,
                    worker,
                    idempotency_key: operation.key_digest,
                    request_digest: operation.request_digest,
                    attachments,
                    at,
                },
                plan,
            })
            .await?;
        let (stored, replayed) = match outcome {
            ServiceCreateOutcome::Created(stored) => (stored, false),
            ServiceCreateOutcome::Replayed(stored) => (stored, true),
        };
        self.create_view(stored, replayed)
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
        input.target.validate()?;
        let stored = self.repository.load_service_call(&tenant, call_id).await?;
        let command = CallCommand::BeginTransfer {
            at,
            transfer_deadline: checked_deadline(at, self.timeouts.transfer)?,
        };
        let mut transcript = CanonicalRequestTranscript::new();
        push_transfer_target(&mut transcript, &input.target);
        let operation = self.operation(
            &tenant,
            self.crypto.principal_fingerprint(principal),
            key,
            ServiceOperationKind::TransferCall,
            call_id,
            transcript,
        );
        self.commit_state_command(
            stored,
            command,
            vec![ServiceEffectPayloadInput {
                // `BeginTransfer` emits ScheduleDeadline followed by ExecuteTransfer.
                // The repository validates this semantic mapping before persistence.
                ordinal: 1,
                payload: ServiceEffectPayload::Transfer {
                    target: input.target,
                },
            }],
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
        let at = command.at();
        let outcome = self
            .repository
            .commit_with_effect_payloads(ServiceCommandTransaction {
                command: crate::call_engine::CommandCommit {
                    tenant_id: stored.call.aggregate.tenant_id().clone(),
                    call_id: stored.call.aggregate.id(),
                    expected_version: stored.call.aggregate.version(),
                    command_id: CommandId::new(),
                    command,
                    worker: stored.call.assignment.lease,
                    attachments: Vec::new(),
                    deadline_claim: None,
                    at,
                },
                effect_payloads,
                operation_idempotency: Some(operation),
            })
            .await?;
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
            if leg.direction() != LegDirection::Inbound {
                continue;
            }
            resolved[index] = self
                .attachment_principals
                .resolve_principal(AttachmentPrincipalRequest {
                    tenant,
                    leg: spec,
                    api_principal,
                })
                .await
                .map_err(|_| CallServiceError::DependencyUnavailable)?;
            if resolved[index].is_none() {
                return Err(CallServiceError::AttachmentPrincipalUnresolved);
            }
        }
        Ok(resolved)
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
            let token = self.crypto.attachment_token(AttachmentTokenContext {
                tenant,
                call_id: aggregate.id(),
                leg_id: leg.id(),
                generation: leg.binding_generation(),
                transport,
                worker,
                principal,
                created_at,
            })?;
            attachments.push(AttachmentIssue {
                attachment_id: AttachmentId::new(),
                token_digest: token.digest,
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
            .filter(|leg| leg.direction() == LegDirection::Inbound)
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
            if leg.direction() != LegDirection::Inbound
                || descriptor.binding_generation != leg.binding_generation()
                || descriptor.transport != transport
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
                worker: stored.call.assignment.lease,
                principal: descriptor.expected_principal,
                created_at: stored.call.aggregate.created_at(),
            })?;
            if token.digest != descriptor.token_digest || token.expires_at != descriptor.expires_at
            {
                return Err(CallServiceError::DependencyUnavailable);
            }
            view.attach(leg.id(), AttachmentView::from_token(token, transport));
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
        PlacementError::Unavailable => CallServiceError::DependencyUnavailable,
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

fn create_transcript(legs: &[RequestedLeg; 2]) -> CanonicalRequestTranscript {
    let mut transcript = CanonicalRequestTranscript::new();
    for leg in legs {
        transcript.push_str(match leg.direction {
            LegDirection::Inbound => "inbound",
            LegDirection::Outbound => "outbound",
        });
        push_endpoint(&mut transcript, &leg.endpoint);
    }
    transcript
}

fn push_endpoint(transcript: &mut CanonicalRequestTranscript, endpoint: &LegEndpointConfig) {
    match endpoint {
        LegEndpointConfig::Sip(SipEndpointConfig { uri }) => {
            transcript.push_str("sip");
            transcript.push_optional_str(uri.as_deref());
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
    use std::sync::Mutex;

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use chrono::TimeZone;
    use rvoip_auth_core::{AuthenticatedPrincipal, AuthenticationMethod};
    use rvoip_core::ids::ConnectionId;
    use rvoip_core::{IdentityAssurance, Jwk};
    use sha2::{Digest, Sha256};

    use crate::call_engine::{
        AttachmentConsume, AttachmentLookup, AttachmentTokenDigest, BindingGeneration,
        CallRepository, CallState, CommandCommit, LegState, RegisterWorker, WorkerId,
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
        async fn select_worker(
            &self,
            _tenant: &TenantId,
            _plan: &CallExecutionPlan,
            _at: DateTime<Utc>,
        ) -> Result<WorkerLease, PlacementError> {
            match *self.failure.lock().unwrap() {
                Some(error) => Err(error),
                None => Ok(self.worker),
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

    fn at(second: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_900_000_000 + second, 0).unwrap()
    }

    fn principal(tenant: &str) -> ApiPrincipal {
        ApiPrincipal::new(
            AuthenticatedPrincipal {
                subject: format!("subject-{tenant}"),
                tenant: Some(tenant.into()),
                scopes: vec!["*".into()],
                issuer: Some("test-issuer".into()),
                expires_at: None,
                method: AuthenticationMethod::Jwt,
                assurance: IdentityAssurance::Pseudonymous {
                    ephemeral_key: Jwk(serde_json::json!({"kty": "test"})),
                },
            },
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
                capabilities: BTreeSet::new(),
                at: at(0),
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
                    endpoint: LegEndpointConfig::Sip(SipEndpointConfig { uri: None }),
                },
                RequestedLeg {
                    direction: LegDirection::Outbound,
                    endpoint: LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
                        signaling_uri: Some("wss://signal.example.test/session".into()),
                    }),
                },
            ],
        }
    }

    fn two_inbound_input() -> CreateCallInput {
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

    fn token_digest(token: &str) -> AttachmentTokenDigest {
        let raw = URL_SAFE_NO_PAD.decode(token).unwrap();
        assert_eq!(raw.len(), 32);
        AttachmentTokenDigest::new(Sha256::digest(raw).into())
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
                })
                .await
                .unwrap();
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
    async fn create_replay_precedes_resolver_and_placement_health_or_capacity() {
        let repository = Arc::new(MemoryRepository::new());
        let worker = repository
            .register_worker(RegisterWorker {
                worker_id: WorkerId::new(),
                max_calls: 4,
                capabilities: BTreeSet::new(),
                at: at(0),
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
    async fn concurrent_winner_outranks_inflight_resolver_failure() {
        let repository = Arc::new(MemoryRepository::new());
        let worker = repository
            .register_worker(RegisterWorker {
                worker_id: WorkerId::new(),
                max_calls: 4,
                capabilities: BTreeSet::new(),
                at: at(0),
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
    async fn provider_inbound_leg_fails_closed_without_profile_principal() {
        let (repository, service, _, _) = harness(2).await;
        let input = CreateCallInput {
            tenant_id: None,
            legs: [
                RequestedLeg {
                    direction: LegDirection::Inbound,
                    endpoint: LegEndpointConfig::Provider(ProviderEndpointConfig {
                        provider: ProviderKind::Twilio,
                        account_profile: "twilio-test".into(),
                        destination: None,
                    }),
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
            CallServiceError::AttachmentPrincipalUnresolved
        );
        assert_eq!(repository.counts().unwrap().calls, 0);
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
