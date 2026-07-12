//! One-lock transactional in-memory call repository.
//!
//! Every mutable index lives in one [`Mutex`]. Mutations clone the complete
//! development-sized state, apply all validation to that draft, and swap it
//! into place only on success. This deliberately favors exact database-like
//! rollback semantics over throughput; clustered deployments use the SQL
//! implementations added by the next roadmap item.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rvoip_core::ids::ConnectionId;

use crate::call_engine::{
    chrono_ttl, idempotency_expiry, validate_attachment_issue, validate_provider_event,
    validate_register_worker, AggregateVersion, AttachmentCandidate, AttachmentConsume,
    AttachmentId, AttachmentIssue, AttachmentLookup, AttachmentTokenDigest, AttachmentTransport,
    BindProviderReference, BindingGeneration, CallCommand, CallId, CallRepository, ClaimGeneration,
    ClaimedDeadline, ClaimedOutbox, CommandCommit, CommandCommitOutcome, CommandCommitView,
    CommandDisposition, CommandId, ConnectionBinding, ConsumedAttachment, CreateCall,
    CreateCallOutcome, DeadlineClaimGuard, DeadlineGeneration, DeadlineKind, DeadlineRecord,
    DeadlineState, EffectId, EffectIntent, IdempotencyKeyDigest, LegId, LegState, OutboxCompletion,
    OutboxRecord, OutboxState, ProviderAccountKey, ProviderCallId, ProviderEventDigest,
    ProviderEventEnvelope, ProviderEventInput, ProviderEventOutcome, ProviderEventState,
    ProviderEventTarget, RegisterWorker, RepositoryError, RestartClaim, StoredCall, StoredCommand,
    TenantId, WorkerAssignment, WorkerFence, WorkerId, WorkerLease, WorkerSnapshot,
};

type BindingKey = (CallId, LegId, BindingGeneration);
type DeadlineKey = (CallId, DeadlineKind, DeadlineGeneration);
type ProviderEventKey = (ProviderAccountKey, ProviderEventDigest);
type ProviderReferenceKey = (ProviderAccountKey, ProviderCallId);

/// Aggregate-safe diagnostic counts. No token, provider, or payload material is exposed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MemoryRepositoryCounts {
    /// Persisted calls, including terminal calls.
    pub calls: usize,
    /// Persisted commands.
    pub commands: usize,
    /// Persisted outbox rows.
    pub outbox: usize,
    /// Persisted attachment digests.
    pub attachments: usize,
    /// Persisted provider events.
    pub provider_events: usize,
    /// Persisted deadline rows.
    pub deadlines: usize,
    /// Unexpired idempotency claims currently retained.
    pub idempotency: usize,
}

#[derive(Clone)]
struct IdempotencyRow {
    request_digest: crate::call_engine::RequestDigest,
    call_id: CallId,
    expires_at: DateTime<Utc>,
}

#[derive(Clone)]
struct AttachmentRow {
    attachment_id: AttachmentId,
    token_digest: AttachmentTokenDigest,
    tenant_id: TenantId,
    call_id: CallId,
    leg_id: LegId,
    binding_generation: BindingGeneration,
    transport: AttachmentTransport,
    worker: WorkerLease,
    expires_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
    binding: Option<ConnectionBinding>,
}

#[derive(Clone)]
struct ProviderReferenceRow {
    target: ProviderEventTarget,
    #[allow(dead_code)]
    bound_at: DateTime<Utc>,
}

#[derive(Clone, Default)]
struct MemoryState {
    workers: HashMap<WorkerId, WorkerSnapshot>,
    calls: HashMap<CallId, StoredCall>,
    leg_owners: HashMap<LegId, CallId>,
    commands: HashMap<CommandId, StoredCommand>,
    command_outbox: HashMap<CommandId, Vec<EffectId>>,
    idempotency: HashMap<(TenantId, IdempotencyKeyDigest), IdempotencyRow>,
    attachments: HashMap<AttachmentTokenDigest, AttachmentRow>,
    attachment_ids: HashMap<AttachmentId, AttachmentTokenDigest>,
    active_attachments: HashMap<BindingKey, AttachmentTokenDigest>,
    connection_owners: HashMap<ConnectionId, BindingKey>,
    provider_events: HashMap<ProviderEventKey, ProviderEventEnvelope>,
    provider_references: HashMap<ProviderReferenceKey, ProviderReferenceRow>,
    outbox: HashMap<EffectId, OutboxRecord>,
    deadlines: HashMap<DeadlineKey, DeadlineRecord>,
}

/// Standalone/test repository with database-equivalent atomic visibility.
#[derive(Default)]
pub struct MemoryRepository {
    state: Mutex<MemoryState>,
}

impl std::fmt::Debug for MemoryRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.state.lock() {
            Ok(state) => formatter
                .debug_struct("MemoryRepository")
                .field("workers", &state.workers.len())
                .field("calls", &state.calls.len())
                .field("commands", &state.commands.len())
                .field("outbox", &state.outbox.len())
                .field("attachments", &state.attachments.len())
                .field("provider_events", &state.provider_events.len())
                .field("deadlines", &state.deadlines.len())
                .finish(),
            Err(_) => formatter
                .debug_struct("MemoryRepository")
                .field("state", &"[unavailable]")
                .finish(),
        }
    }
}

impl MemoryRepository {
    /// Creates an empty repository.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns safe aggregate counts for tests and diagnostics.
    pub fn counts(&self) -> Result<MemoryRepositoryCounts, RepositoryError> {
        let state = self.lock()?;
        Ok(MemoryRepositoryCounts {
            calls: state.calls.len(),
            commands: state.commands.len(),
            outbox: state.outbox.len(),
            attachments: state.attachments.len(),
            provider_events: state.provider_events.len(),
            deadlines: state.deadlines.len(),
            idempotency: state.idempotency.len(),
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, MemoryState>, RepositoryError> {
        self.state.lock().map_err(|_| RepositoryError::Unavailable)
    }

    fn read<T>(
        &self,
        operation: impl FnOnce(&MemoryState) -> Result<T, RepositoryError>,
    ) -> Result<T, RepositoryError> {
        let state = self.lock()?;
        operation(&state)
    }

    fn transaction<T>(
        &self,
        operation: impl FnOnce(&mut MemoryState) -> Result<T, RepositoryError>,
    ) -> Result<T, RepositoryError> {
        let mut state = self.lock()?;
        let mut draft = state.clone();
        let result = operation(&mut draft)?;
        *state = draft;
        Ok(result)
    }
}

#[async_trait]
impl CallRepository for MemoryRepository {
    async fn register_worker(
        &self,
        request: RegisterWorker,
    ) -> Result<WorkerSnapshot, RepositoryError> {
        validate_register_worker(&request)?;
        self.transaction(|state| {
            let snapshot = match state.workers.get(&request.worker_id) {
                Some(existing) => {
                    if request.max_calls < existing.reserved_calls {
                        return Err(RepositoryError::InvalidInput(
                            "worker capacity is below existing reservations",
                        ));
                    }
                    WorkerSnapshot {
                        lease: WorkerLease {
                            worker_id: request.worker_id,
                            fence: existing.lease.fence.next()?,
                        },
                        max_calls: request.max_calls,
                        reserved_calls: existing.reserved_calls,
                        draining: false,
                        capabilities: request.capabilities.clone(),
                        updated_at: request.at,
                    }
                }
                None => WorkerSnapshot {
                    lease: WorkerLease {
                        worker_id: request.worker_id,
                        fence: WorkerFence::INITIAL,
                    },
                    max_calls: request.max_calls,
                    reserved_calls: 0,
                    draining: false,
                    capabilities: request.capabilities.clone(),
                    updated_at: request.at,
                },
            };
            state.workers.insert(request.worker_id, snapshot.clone());
            Ok(snapshot)
        })
    }

    async fn set_worker_draining(
        &self,
        worker: WorkerLease,
        draining: bool,
        at: DateTime<Utc>,
    ) -> Result<WorkerSnapshot, RepositoryError> {
        self.transaction(|state| {
            let snapshot = state
                .workers
                .get_mut(&worker.worker_id)
                .filter(|snapshot| snapshot.lease == worker)
                .ok_or(RepositoryError::StaleWorkerFence)?;
            snapshot.draining = draining;
            snapshot.updated_at = at;
            Ok(snapshot.clone())
        })
    }

    async fn worker_snapshot(
        &self,
        worker_id: WorkerId,
    ) -> Result<WorkerSnapshot, RepositoryError> {
        self.read(|state| {
            state
                .workers
                .get(&worker_id)
                .cloned()
                .ok_or(RepositoryError::NotFound)
        })
    }

    async fn create_call(&self, request: CreateCall) -> Result<CreateCallOutcome, RepositoryError> {
        request
            .initial
            .validate()
            .map_err(|_| RepositoryError::DomainRejected)?;
        if request.initial.version().value() != 0
            || request.initial.state() != crate::call_engine::CallState::Pending
        {
            return Err(RepositoryError::InvalidInput(
                "initial call must be pending at version zero",
            ));
        }
        let decision = request
            .initial
            .decide(request.command.clone())
            .map_err(|_| RepositoryError::DomainRejected)?;
        if decision.disposition() != CommandDisposition::Applied {
            return Err(RepositoryError::InvalidInput(
                "initial call command must change durable state",
            ));
        }
        let expires_at = idempotency_expiry(request.at)?;

        self.transaction(|state| {
            state
                .idempotency
                .retain(|_, existing| existing.expires_at > request.at);
            let tenant_id = request.initial.tenant_id().clone();
            let idempotency_key = (tenant_id.clone(), request.idempotency_key);
            if let Some(existing) = state.idempotency.get(&idempotency_key) {
                if existing.expires_at > request.at {
                    if existing.request_digest != request.request_digest {
                        return Err(RepositoryError::IdempotencyConflict);
                    }
                    let call = tenant_call(state, &tenant_id, existing.call_id)?;
                    return Ok(CreateCallOutcome::Replayed(call));
                }
            }
            state.idempotency.remove(&idempotency_key);

            if state.commands.contains_key(&request.command_id) {
                return Err(RepositoryError::CommandConflict);
            }
            let call_id = request.initial.id();
            if state.calls.contains_key(&call_id)
                || request
                    .initial
                    .legs()
                    .iter()
                    .any(|leg| state.leg_owners.contains_key(&leg.id()))
            {
                return Err(RepositoryError::InvalidInput(
                    "call or leg identifier already exists",
                ));
            }
            ensure_worker(state, request.worker, false)?;
            let worker = state
                .workers
                .get(&request.worker.worker_id)
                .ok_or(RepositoryError::StaleWorkerFence)?;
            if worker.reserved_calls >= worker.max_calls {
                return Err(RepositoryError::CapacityExceeded);
            }

            let (aggregate, effects, disposition) = decision.into_parts();
            for issue in &request.attachments {
                validate_attachment_issue(&aggregate, issue, request.at)?;
                validate_attachment_effect(&effects, issue)?;
                validate_new_attachment(state, call_id, issue)?;
            }

            let assignment = WorkerAssignment {
                lease: request.worker,
                assigned_at: request.at,
                released_at: None,
            };
            let stored = StoredCall {
                aggregate: aggregate.clone(),
                assignment,
                bindings: BTreeMap::new(),
            };
            state.calls.insert(call_id, stored.clone());
            for leg in aggregate.legs() {
                state.leg_owners.insert(leg.id(), call_id);
            }
            let worker = state
                .workers
                .get_mut(&request.worker.worker_id)
                .ok_or(RepositoryError::StaleWorkerFence)?;
            worker.reserved_calls += 1;
            worker.updated_at = request.at;

            let command = StoredCommand {
                command_id: request.command_id,
                tenant_id: tenant_id.clone(),
                call_id,
                observed_version: request.initial.version(),
                result_version: aggregate.version(),
                command: request.command.clone(),
                worker: request.worker,
                attachments: request.attachments.clone(),
                deadline_claim: None,
                disposition,
                recorded_at: request.at,
            };
            state.commands.insert(request.command_id, command);
            insert_attachments(
                state,
                &tenant_id,
                call_id,
                request.worker,
                request.at,
                &request.attachments,
            )?;
            let outbox = persist_effects(
                state,
                EffectBatch {
                    tenant_id: &tenant_id,
                    call_id,
                    worker: request.worker,
                    command_id: request.command_id,
                    aggregate_version: aggregate.version(),
                    at: request.at,
                    effects,
                },
            )?;
            state.command_outbox.insert(
                request.command_id,
                outbox.iter().map(|record| record.effect_id).collect(),
            );
            state.idempotency.insert(
                idempotency_key,
                IdempotencyRow {
                    request_digest: request.request_digest,
                    call_id,
                    expires_at,
                },
            );
            Ok(CreateCallOutcome::Created(stored))
        })
    }

    async fn load_call(
        &self,
        tenant_id: &TenantId,
        call_id: CallId,
    ) -> Result<StoredCall, RepositoryError> {
        self.read(|state| tenant_call(state, tenant_id, call_id))
    }

    async fn commit_command(
        &self,
        request: CommandCommit,
    ) -> Result<CommandCommitOutcome, RepositoryError> {
        self.transaction(|state| commit_command_in_state(state, request))
    }

    async fn release_assignment(
        &self,
        tenant_id: &TenantId,
        call_id: CallId,
        worker: WorkerLease,
        at: DateTime<Utc>,
    ) -> Result<bool, RepositoryError> {
        self.transaction(|state| release_assignment_in_state(state, tenant_id, call_id, worker, at))
    }

    async fn inspect_attachment(
        &self,
        request: AttachmentLookup,
    ) -> Result<AttachmentCandidate, RepositoryError> {
        self.read(|state| {
            ensure_worker(state, request.worker, true)
                .map_err(|_| RepositoryError::AttachmentRejected)?;
            let row = state
                .attachments
                .get(&request.token_digest)
                .ok_or(RepositoryError::AttachmentRejected)?;
            if row.token_digest != request.token_digest
                || row.tenant_id != request.tenant_id
                || row.transport != request.transport
                || row.worker != request.worker
                || row.expires_at <= request.at
                || row.consumed_at.is_some()
                || row.revoked_at.is_some()
            {
                return Err(RepositoryError::AttachmentRejected);
            }
            let call = tenant_call(state, &request.tenant_id, row.call_id)
                .map_err(|_| RepositoryError::AttachmentRejected)?;
            if call.assignment.released_at.is_some()
                || call.assignment.lease != request.worker
                || call.aggregate.leg(row.leg_id).is_none_or(|leg| {
                    leg.binding_generation() != row.binding_generation
                        || leg.state() != LegState::AwaitingAttach
                })
            {
                return Err(RepositoryError::AttachmentRejected);
            }
            Ok(AttachmentCandidate {
                attachment_id: row.attachment_id,
                token_digest: row.token_digest,
                tenant_id: row.tenant_id.clone(),
                call_id: row.call_id,
                leg_id: row.leg_id,
                binding_generation: row.binding_generation,
                transport: row.transport,
                worker: row.worker,
                expires_at: row.expires_at,
                call,
            })
        })
    }

    async fn consume_attachment(
        &self,
        request: AttachmentConsume,
    ) -> Result<ConsumedAttachment, RepositoryError> {
        self.transaction(|state| {
            ensure_worker(state, request.candidate.worker, true)
                .map_err(|_| RepositoryError::AttachmentRejected)?;
            validate_attachment_consume_command(&request)?;
            if state.commands.contains_key(&request.command_id) {
                return Err(RepositoryError::AttachmentRejected);
            }
            let row = state
                .attachments
                .get(&request.candidate.token_digest)
                .ok_or(RepositoryError::AttachmentRejected)?;
            if row.attachment_id != request.candidate.attachment_id
                || row.tenant_id != request.candidate.tenant_id
                || row.call_id != request.candidate.call_id
                || row.leg_id != request.candidate.leg_id
                || row.binding_generation != request.candidate.binding_generation
                || row.transport != request.candidate.transport
                || row.worker != request.candidate.worker
                || row.expires_at <= request.at
                || row.consumed_at.is_some()
                || row.revoked_at.is_some()
            {
                return Err(RepositoryError::AttachmentRejected);
            }
            if state.connection_owners.contains_key(&request.connection_id) {
                return Err(RepositoryError::AttachmentConflict);
            }

            let binding_key = (
                request.candidate.call_id,
                request.candidate.leg_id,
                request.candidate.binding_generation,
            );
            let binding = ConnectionBinding {
                connection_id: request.connection_id.clone(),
                leg_id: request.candidate.leg_id,
                binding_generation: request.candidate.binding_generation,
                transport: request.candidate.transport,
                principal_fingerprint: request.principal_fingerprint,
                bound_at: request.at,
            };
            let call = state
                .calls
                .get_mut(&request.candidate.call_id)
                .filter(|call| call.aggregate.tenant_id() == &request.candidate.tenant_id)
                .ok_or(RepositoryError::AttachmentRejected)?;
            if call.bindings.contains_key(&request.candidate.leg_id) {
                return Err(RepositoryError::AttachmentConflict);
            }
            call.bindings
                .insert(request.candidate.leg_id, binding.clone());
            state
                .connection_owners
                .insert(request.connection_id.clone(), binding_key);
            let row = state
                .attachments
                .get_mut(&request.candidate.token_digest)
                .ok_or(RepositoryError::AttachmentRejected)?;
            row.consumed_at = Some(request.at);
            row.binding = Some(binding.clone());

            let outcome = commit_command_in_state(
                state,
                CommandCommit {
                    tenant_id: request.candidate.tenant_id.clone(),
                    call_id: request.candidate.call_id,
                    expected_version: request.candidate.call.aggregate.version(),
                    command_id: request.command_id,
                    command: request.command.clone(),
                    worker: request.candidate.worker,
                    attachments: Vec::new(),
                    deadline_claim: None,
                    at: request.at,
                },
            )?;
            let CommandCommitOutcome::Committed(commit) = outcome else {
                return Err(RepositoryError::AttachmentRejected);
            };
            Ok(ConsumedAttachment { binding, commit })
        })
    }

    async fn ingest_provider_event(
        &self,
        request: ProviderEventInput,
    ) -> Result<ProviderEventOutcome, RepositoryError> {
        validate_provider_event(&request)?;
        self.transaction(|state| {
            let key = (request.account.clone(), request.event_digest);
            if let Some(existing) = state.provider_events.get(&key) {
                if existing.payload_digest == request.payload_digest
                    && existing.provider_call_id == request.provider_call_id
                    && existing.kind == request.kind
                    && existing.payload == request.payload
                {
                    return Ok(ProviderEventOutcome::Duplicate(existing.clone()));
                }
                return Err(RepositoryError::ProviderEventConflict);
            }
            let reference_key = (request.account.clone(), request.provider_call_id.clone());
            let target = state
                .provider_references
                .get(&reference_key)
                .map(|reference| reference.target.clone());
            let state_kind = if target.is_some() {
                ProviderEventState::Ready
            } else {
                ProviderEventState::PendingReference
            };
            let event = ProviderEventEnvelope {
                account: request.account,
                event_digest: request.event_digest,
                payload_digest: request.payload_digest,
                provider_call_id: request.provider_call_id,
                kind: request.kind,
                payload: request.payload,
                occurred_at: request.occurred_at,
                received_at: request.received_at,
                target,
                state: state_kind,
                applied_at: None,
            };
            state.provider_events.insert(key, event.clone());
            Ok(ProviderEventOutcome::Accepted(event))
        })
    }

    async fn bind_provider_reference(
        &self,
        request: BindProviderReference,
    ) -> Result<Vec<ProviderEventEnvelope>, RepositoryError> {
        self.transaction(|state| {
            ensure_call_worker(state, &request.tenant_id, request.call_id, request.worker)?;
            let call = tenant_call(state, &request.tenant_id, request.call_id)?;
            if call.aggregate.leg(request.leg_id).is_none() {
                return Err(RepositoryError::NotFound);
            }
            let target = ProviderEventTarget {
                tenant_id: request.tenant_id.clone(),
                call_id: request.call_id,
                leg_id: request.leg_id,
            };
            let key = (request.account.clone(), request.provider_call_id.clone());
            if let Some(existing) = state.provider_references.get(&key) {
                if existing.target != target {
                    return Err(RepositoryError::ProviderReferenceConflict);
                }
            } else {
                state.provider_references.insert(
                    key,
                    ProviderReferenceRow {
                        target: target.clone(),
                        bound_at: request.at,
                    },
                );
            }

            let mut ready = Vec::new();
            for event in state.provider_events.values_mut() {
                if event.account == request.account
                    && event.provider_call_id == request.provider_call_id
                    && event.state != ProviderEventState::Applied
                {
                    event.target = Some(target.clone());
                    event.state = ProviderEventState::Ready;
                    ready.push(event.clone());
                }
            }
            ready.sort_by(|left, right| {
                left.received_at.cmp(&right.received_at).then_with(|| {
                    left.event_digest
                        .expose_bytes()
                        .cmp(right.event_digest.expose_bytes())
                })
            });
            Ok(ready)
        })
    }

    async fn mark_provider_event_applied(
        &self,
        account: &ProviderAccountKey,
        event_digest: ProviderEventDigest,
        target: &ProviderEventTarget,
        at: DateTime<Utc>,
    ) -> Result<ProviderEventEnvelope, RepositoryError> {
        self.transaction(|state| {
            let event = state
                .provider_events
                .get_mut(&(account.clone(), event_digest))
                .ok_or(RepositoryError::NotFound)?;
            if event.target.as_ref() != Some(target)
                || !matches!(
                    event.state,
                    ProviderEventState::Ready | ProviderEventState::Applied
                )
            {
                return Err(RepositoryError::ProviderReferenceConflict);
            }
            if event.state == ProviderEventState::Ready {
                if at < event.received_at {
                    return Err(RepositoryError::InvalidInput(
                        "provider event application predates receipt",
                    ));
                }
                event.state = ProviderEventState::Applied;
                event.applied_at = Some(at);
            }
            Ok(event.clone())
        })
    }

    async fn claim_outbox(
        &self,
        worker: WorkerLease,
        at: DateTime<Utc>,
        claim_ttl: Duration,
        limit: usize,
    ) -> Result<Vec<ClaimedOutbox>, RepositoryError> {
        let expires_at = chrono_ttl(at, claim_ttl)?;
        if limit == 0 {
            return Ok(Vec::new());
        }
        self.transaction(|state| {
            ensure_worker(state, worker, true)?;
            let mut eligible = state
                .outbox
                .values()
                .filter(|record| {
                    record.worker == worker
                        && record.available_at <= at
                        && match &record.state {
                            OutboxState::Ready => true,
                            OutboxState::Claimed { expires_at, .. } => *expires_at <= at,
                            OutboxState::Succeeded { .. } | OutboxState::Failed { .. } => false,
                        }
                        && state
                            .calls
                            .get(&record.call_id)
                            .is_some_and(|call| call.assignment.lease == worker)
                })
                .map(|record| {
                    (
                        record.available_at,
                        record.call_id,
                        record.aggregate_version,
                        record.ordinal,
                        record.effect_id,
                    )
                })
                .collect::<Vec<_>>();
            eligible.sort();
            eligible.truncate(limit);

            let mut claimed = Vec::with_capacity(eligible.len());
            for (_, _, _, _, effect_id) in eligible {
                let record = state
                    .outbox
                    .get_mut(&effect_id)
                    .ok_or(RepositoryError::NotFound)?;
                let previous = match record.state {
                    OutboxState::Claimed { generation, .. } => generation,
                    OutboxState::Ready => ClaimGeneration::default(),
                    OutboxState::Succeeded { .. } | OutboxState::Failed { .. } => continue,
                };
                let generation = previous.next()?;
                record.state = OutboxState::Claimed {
                    worker,
                    generation,
                    expires_at,
                };
                claimed.push(ClaimedOutbox {
                    record: record.clone(),
                    claim_generation: generation,
                });
            }
            Ok(claimed)
        })
    }

    async fn complete_outbox(
        &self,
        effect_id: EffectId,
        worker: WorkerLease,
        claim_generation: ClaimGeneration,
        completion: OutboxCompletion,
        at: DateTime<Utc>,
    ) -> Result<OutboxRecord, RepositoryError> {
        self.transaction(|state| {
            ensure_worker(state, worker, true)?;
            let record = state
                .outbox
                .get_mut(&effect_id)
                .ok_or(RepositoryError::NotFound)?;
            match record.state {
                OutboxState::Claimed {
                    worker: owner,
                    generation,
                    expires_at,
                } if owner == worker && generation == claim_generation && expires_at > at => {}
                _ => return Err(RepositoryError::StaleClaim),
            }
            record.state = match completion {
                OutboxCompletion::Succeeded => OutboxState::Succeeded { at },
                OutboxCompletion::Failed(failure) => OutboxState::Failed { at, failure },
            };
            Ok(record.clone())
        })
    }

    async fn claim_due_deadlines(
        &self,
        worker: WorkerLease,
        at: DateTime<Utc>,
        claim_ttl: Duration,
        limit: usize,
    ) -> Result<Vec<ClaimedDeadline>, RepositoryError> {
        let expires_at = chrono_ttl(at, claim_ttl)?;
        if limit == 0 {
            return Ok(Vec::new());
        }
        self.transaction(|state| {
            ensure_worker(state, worker, true)?;
            let mut eligible = state
                .deadlines
                .values()
                .filter(|record| {
                    record.due_at <= at
                        && match &record.state {
                            DeadlineState::Pending => true,
                            DeadlineState::Claimed { expires_at, .. } => *expires_at <= at,
                            DeadlineState::Cancelled { .. } | DeadlineState::Completed { .. } => {
                                false
                            }
                        }
                        && state.calls.get(&record.call_id).is_some_and(|call| {
                            call.assignment.released_at.is_none() && call.assignment.lease == worker
                        })
                })
                .map(|record| {
                    (
                        record.due_at,
                        record.call_id,
                        deadline_rank(record.kind),
                        record.kind,
                        record.generation,
                    )
                })
                .collect::<Vec<_>>();
            eligible.sort_by(|left, right| {
                left.0
                    .cmp(&right.0)
                    .then(left.1.cmp(&right.1))
                    .then(left.2.cmp(&right.2))
                    .then(left.4.cmp(&right.4))
            });
            eligible.truncate(limit);

            let mut claimed = Vec::with_capacity(eligible.len());
            for (_, call_id, _, kind, generation) in eligible {
                let key = (call_id, kind, generation);
                let record = state
                    .deadlines
                    .get_mut(&key)
                    .ok_or(RepositoryError::NotFound)?;
                let previous = match record.state {
                    DeadlineState::Claimed { generation, .. } => generation,
                    DeadlineState::Pending => ClaimGeneration::default(),
                    DeadlineState::Cancelled { .. } | DeadlineState::Completed { .. } => continue,
                };
                let claim_generation = previous.next()?;
                record.state = DeadlineState::Claimed {
                    worker,
                    generation: claim_generation,
                    expires_at,
                };
                claimed.push(ClaimedDeadline {
                    record: record.clone(),
                    claim_generation,
                });
            }
            Ok(claimed)
        })
    }

    async fn claim_restart_calls(
        &self,
        worker: WorkerLease,
        at: DateTime<Utc>,
        limit: usize,
    ) -> Result<Vec<RestartClaim>, RepositoryError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        self.transaction(|state| {
            ensure_worker(state, worker, true)?;
            let mut call_ids = state
                .calls
                .iter()
                .filter(|(_, call)| {
                    call.assignment.released_at.is_none()
                        && call.assignment.lease.worker_id == worker.worker_id
                        && call.assignment.lease.fence < worker.fence
                })
                .map(|(call_id, _)| *call_id)
                .collect::<Vec<_>>();
            call_ids.sort();
            call_ids.truncate(limit);

            let mut claims = Vec::with_capacity(call_ids.len());
            for call_id in call_ids {
                let call = state
                    .calls
                    .get_mut(&call_id)
                    .ok_or(RepositoryError::NotFound)?;
                let previous_fence = call.assignment.lease.fence;
                call.assignment.lease = worker;
                for record in state
                    .outbox
                    .values_mut()
                    .filter(|row| row.call_id == call_id)
                {
                    record.worker = worker;
                    if matches!(record.state, OutboxState::Claimed { .. }) {
                        record.state = OutboxState::Ready;
                    }
                }
                for record in state
                    .deadlines
                    .values_mut()
                    .filter(|row| row.call_id == call_id)
                {
                    if matches!(record.state, DeadlineState::Claimed { .. }) {
                        record.state = DeadlineState::Pending;
                    }
                }
                for attachment in state
                    .attachments
                    .values_mut()
                    .filter(|row| row.call_id == call_id && row.consumed_at.is_none())
                {
                    attachment.revoked_at = Some(at);
                }
                claims.push(RestartClaim {
                    call: call.clone(),
                    previous_fence,
                });
            }
            Ok(claims)
        })
    }
}

fn ensure_worker(
    state: &MemoryState,
    lease: WorkerLease,
    allow_draining: bool,
) -> Result<(), RepositoryError> {
    let worker = state
        .workers
        .get(&lease.worker_id)
        .filter(|worker| worker.lease == lease)
        .ok_or(RepositoryError::StaleWorkerFence)?;
    if worker.draining && !allow_draining {
        return Err(RepositoryError::StaleWorkerFence);
    }
    Ok(())
}

fn ensure_call_worker(
    state: &MemoryState,
    tenant_id: &TenantId,
    call_id: CallId,
    worker: WorkerLease,
) -> Result<(), RepositoryError> {
    ensure_worker(state, worker, true)?;
    let call = state
        .calls
        .get(&call_id)
        .filter(|call| call.aggregate.tenant_id() == tenant_id)
        .ok_or(RepositoryError::NotFound)?;
    if call.assignment.released_at.is_some() || call.assignment.lease != worker {
        return Err(RepositoryError::StaleWorkerFence);
    }
    Ok(())
}

fn tenant_call(
    state: &MemoryState,
    tenant_id: &TenantId,
    call_id: CallId,
) -> Result<StoredCall, RepositoryError> {
    state
        .calls
        .get(&call_id)
        .filter(|call| call.aggregate.tenant_id() == tenant_id)
        .cloned()
        .ok_or(RepositoryError::NotFound)
}

fn validate_new_attachment(
    state: &MemoryState,
    call_id: CallId,
    issue: &AttachmentIssue,
) -> Result<(), RepositoryError> {
    if state.attachments.contains_key(&issue.token_digest)
        || state.attachment_ids.contains_key(&issue.attachment_id)
        || state
            .active_attachments
            .contains_key(&(call_id, issue.leg_id, issue.binding_generation))
    {
        return Err(RepositoryError::AttachmentConflict);
    }
    Ok(())
}

fn insert_attachments(
    state: &mut MemoryState,
    tenant_id: &TenantId,
    call_id: CallId,
    worker: WorkerLease,
    at: DateTime<Utc>,
    issues: &[AttachmentIssue],
) -> Result<(), RepositoryError> {
    let call = state.calls.get(&call_id).ok_or(RepositoryError::NotFound)?;
    for issue in issues {
        validate_attachment_issue(&call.aggregate, issue, at)?;
    }
    for issue in issues {
        validate_new_attachment(state, call_id, issue)?;
        let row = AttachmentRow {
            attachment_id: issue.attachment_id,
            token_digest: issue.token_digest,
            tenant_id: tenant_id.clone(),
            call_id,
            leg_id: issue.leg_id,
            binding_generation: issue.binding_generation,
            transport: issue.transport,
            worker,
            expires_at: issue.expires_at,
            consumed_at: None,
            revoked_at: None,
            binding: None,
        };
        state
            .attachment_ids
            .insert(issue.attachment_id, issue.token_digest);
        state.active_attachments.insert(
            (call_id, issue.leg_id, issue.binding_generation),
            issue.token_digest,
        );
        state.attachments.insert(issue.token_digest, row);
    }
    Ok(())
}

fn commit_command_in_state(
    state: &mut MemoryState,
    request: CommandCommit,
) -> Result<CommandCommitOutcome, RepositoryError> {
    if let Some(existing) = state.commands.get(&request.command_id) {
        ensure_worker(state, request.worker, true)?;
        let call = tenant_call(state, &request.tenant_id, request.call_id)?;
        if call.assignment.lease != request.worker {
            return Err(RepositoryError::StaleWorkerFence);
        }
        if existing.tenant_id != request.tenant_id
            || existing.call_id != request.call_id
            || existing.observed_version != request.expected_version
            || existing.command != request.command
            || existing.worker != request.worker
            || existing.attachments != request.attachments
            || existing.deadline_claim != request.deadline_claim
            || existing.recorded_at != request.at
        {
            return Err(RepositoryError::CommandConflict);
        }
        return Ok(CommandCommitOutcome::Replayed(command_view(
            state,
            existing.clone(),
        )?));
    }
    ensure_call_worker(state, &request.tenant_id, request.call_id, request.worker)?;
    let current = tenant_call(state, &request.tenant_id, request.call_id)?;
    if current.aggregate.version() != request.expected_version {
        return Err(RepositoryError::VersionConflict);
    }
    validate_command_deadline_claim(&request)?;
    validate_deadline_claim(state, request.deadline_claim.as_ref(), request.at)?;
    let decision = current
        .aggregate
        .decide(request.command.clone())
        .map_err(|_| RepositoryError::DomainRejected)?;
    for issue in &request.attachments {
        validate_attachment_issue(decision.aggregate(), issue, request.at)?;
        validate_attachment_effect(decision.effects(), issue)?;
        validate_new_attachment(state, request.call_id, issue)?;
    }

    let observed_version = current.aggregate.version();
    let (aggregate, effects, disposition) = decision.into_parts();
    let call = state
        .calls
        .get_mut(&request.call_id)
        .ok_or(RepositoryError::NotFound)?;
    call.aggregate = aggregate.clone();
    let command = StoredCommand {
        command_id: request.command_id,
        tenant_id: request.tenant_id.clone(),
        call_id: request.call_id,
        observed_version,
        result_version: aggregate.version(),
        command: request.command,
        worker: request.worker,
        attachments: request.attachments.clone(),
        deadline_claim: request.deadline_claim.clone(),
        disposition,
        recorded_at: request.at,
    };
    state.commands.insert(request.command_id, command.clone());
    insert_attachments(
        state,
        &request.tenant_id,
        request.call_id,
        request.worker,
        request.at,
        &request.attachments,
    )?;
    let outbox = persist_effects(
        state,
        EffectBatch {
            tenant_id: &request.tenant_id,
            call_id: request.call_id,
            worker: request.worker,
            command_id: request.command_id,
            aggregate_version: aggregate.version(),
            at: request.at,
            effects,
        },
    )?;
    state.command_outbox.insert(
        request.command_id,
        outbox.iter().map(|record| record.effect_id).collect(),
    );
    if let Some(claim) = request.deadline_claim {
        let record = state
            .deadlines
            .get_mut(&(claim.call_id, claim.kind, claim.generation))
            .ok_or(RepositoryError::StaleClaim)?;
        record.state = DeadlineState::Completed { at: request.at };
    }
    if aggregate.state().is_terminal() {
        release_assignment_in_state(
            state,
            &request.tenant_id,
            request.call_id,
            request.worker,
            request.at,
        )?;
    }
    let call = tenant_call(state, &request.tenant_id, request.call_id)?;
    Ok(CommandCommitOutcome::Committed(CommandCommitView {
        command,
        call,
        outbox,
    }))
}

fn command_view(
    state: &MemoryState,
    command: StoredCommand,
) -> Result<CommandCommitView, RepositoryError> {
    let call = tenant_call(state, &command.tenant_id, command.call_id)?;
    let outbox = state
        .command_outbox
        .get(&command.command_id)
        .into_iter()
        .flatten()
        .map(|effect_id| {
            state
                .outbox
                .get(effect_id)
                .cloned()
                .ok_or(RepositoryError::Unavailable)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CommandCommitView {
        command,
        call,
        outbox,
    })
}

struct EffectBatch<'a> {
    tenant_id: &'a TenantId,
    call_id: CallId,
    worker: WorkerLease,
    command_id: CommandId,
    aggregate_version: AggregateVersion,
    at: DateTime<Utc>,
    effects: Vec<EffectIntent>,
}

fn persist_effects(
    state: &mut MemoryState,
    batch: EffectBatch<'_>,
) -> Result<Vec<OutboxRecord>, RepositoryError> {
    let mut outbox = Vec::with_capacity(batch.effects.len());
    for (index, intent) in batch.effects.into_iter().enumerate() {
        let ordinal = u32::try_from(index)
            .map_err(|_| RepositoryError::InvalidInput("too many command effects"))?;
        match &intent {
            EffectIntent::ScheduleDeadline {
                kind,
                generation,
                due_at,
            } => {
                let key = (batch.call_id, *kind, *generation);
                if state.deadlines.contains_key(&key) {
                    return Err(RepositoryError::InvalidInput(
                        "deadline generation already exists",
                    ));
                }
                state.deadlines.insert(
                    key,
                    DeadlineRecord {
                        tenant_id: batch.tenant_id.clone(),
                        call_id: batch.call_id,
                        kind: *kind,
                        generation: *generation,
                        due_at: *due_at,
                        state: DeadlineState::Pending,
                    },
                );
            }
            EffectIntent::CancelDeadline { kind, generation } => {
                let record = state
                    .deadlines
                    .get_mut(&(batch.call_id, *kind, *generation))
                    .ok_or(RepositoryError::InvalidInput(
                        "cancelled deadline does not exist",
                    ))?;
                if !matches!(record.state, DeadlineState::Completed { .. }) {
                    record.state = DeadlineState::Cancelled { at: batch.at };
                }
            }
            _ => {}
        }
        let record = OutboxRecord {
            effect_id: EffectId::new(),
            command_id: batch.command_id,
            ordinal,
            tenant_id: batch.tenant_id.clone(),
            call_id: batch.call_id,
            aggregate_version: batch.aggregate_version,
            worker: batch.worker,
            intent,
            available_at: batch.at,
            state: OutboxState::Ready,
        };
        state.outbox.insert(record.effect_id, record.clone());
        outbox.push(record);
    }
    Ok(outbox)
}

fn validate_deadline_claim(
    state: &MemoryState,
    claim: Option<&DeadlineClaimGuard>,
    at: DateTime<Utc>,
) -> Result<(), RepositoryError> {
    let Some(claim) = claim else {
        return Ok(());
    };
    let record = state
        .deadlines
        .get(&(claim.call_id, claim.kind, claim.generation))
        .ok_or(RepositoryError::StaleClaim)?;
    match record.state {
        DeadlineState::Claimed {
            worker,
            generation,
            expires_at,
        } if worker == claim.worker && generation == claim.claim_generation && expires_at > at => {
            Ok(())
        }
        _ => Err(RepositoryError::StaleClaim),
    }
}

fn validate_command_deadline_claim(request: &CommandCommit) -> Result<(), RepositoryError> {
    match (&request.command, &request.deadline_claim) {
        (
            CallCommand::DeadlineElapsed {
                kind, generation, ..
            },
            Some(claim),
        ) if claim.call_id == request.call_id
            && claim.kind == *kind
            && claim.generation == *generation
            && claim.worker == request.worker =>
        {
            Ok(())
        }
        (CallCommand::DeadlineElapsed { .. }, None) => Err(RepositoryError::InvalidInput(
            "deadline command requires an exact claim",
        )),
        (CallCommand::DeadlineElapsed { .. }, Some(_)) | (_, Some(_)) => {
            Err(RepositoryError::StaleClaim)
        }
        (_, None) => Ok(()),
    }
}

fn validate_attachment_effect(
    effects: &[EffectIntent],
    issue: &AttachmentIssue,
) -> Result<(), RepositoryError> {
    if effects.iter().any(|effect| {
        matches!(
            effect,
            EffectIntent::AwaitLegAttachment {
                leg_id,
                binding_generation,
            } if *leg_id == issue.leg_id && *binding_generation == issue.binding_generation
        )
    }) {
        Ok(())
    } else {
        Err(RepositoryError::InvalidInput(
            "attachment is not backed by an await-attachment effect",
        ))
    }
}

fn release_assignment_in_state(
    state: &mut MemoryState,
    tenant_id: &TenantId,
    call_id: CallId,
    worker: WorkerLease,
    at: DateTime<Utc>,
) -> Result<bool, RepositoryError> {
    ensure_worker(state, worker, true)?;
    let call = state
        .calls
        .get_mut(&call_id)
        .filter(|call| call.aggregate.tenant_id() == tenant_id)
        .ok_or(RepositoryError::NotFound)?;
    if call.assignment.lease != worker {
        return Err(RepositoryError::StaleWorkerFence);
    }
    if !call.aggregate.state().is_terminal() {
        return Err(RepositoryError::InvalidInput(
            "capacity release requires a terminal call",
        ));
    }
    if call.assignment.released_at.is_some() {
        return Ok(false);
    }
    call.assignment.released_at = Some(at);
    let worker = state
        .workers
        .get_mut(&worker.worker_id)
        .ok_or(RepositoryError::StaleWorkerFence)?;
    worker.reserved_calls = worker
        .reserved_calls
        .checked_sub(1)
        .ok_or(RepositoryError::Unavailable)?;
    worker.updated_at = at;
    Ok(true)
}

fn validate_attachment_consume_command(request: &AttachmentConsume) -> Result<(), RepositoryError> {
    match &request.command {
        CallCommand::SetLegState {
            leg_id,
            binding_generation,
            state: LegState::Signaling,
            failure: None,
            ..
        } if *leg_id == request.candidate.leg_id
            && *binding_generation == request.candidate.binding_generation =>
        {
            Ok(())
        }
        _ => Err(RepositoryError::InvalidInput(
            "attachment command must signal its exact leg generation",
        )),
    }
}

fn deadline_rank(kind: DeadlineKind) -> u8 {
    match kind {
        DeadlineKind::Setup => 0,
        DeadlineKind::Media => 1,
        DeadlineKind::Transfer => 2,
        DeadlineKind::Ending => 3,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use chrono::TimeZone;
    use serde_json::json;

    use super::*;
    use crate::call_engine::{
        CallAggregate, CallState, LegDirection, LegKind, LegSpec, StopLegReason,
    };

    fn at(second: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_800_000_000 + second, 0).unwrap()
    }

    fn tenant(name: &str) -> TenantId {
        TenantId::parse(name).unwrap()
    }

    fn digest(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    async fn worker(repo: &MemoryRepository, max_calls: usize) -> WorkerSnapshot {
        repo.register_worker(RegisterWorker {
            worker_id: WorkerId::new(),
            max_calls,
            capabilities: BTreeSet::from(["sip".into(), "webrtc".into()]),
            at: at(0),
        })
        .await
        .unwrap()
    }

    fn new_call(owner: TenantId) -> CallAggregate {
        CallAggregate::new(
            owner,
            [
                LegSpec {
                    direction: LegDirection::Inbound,
                    kind: LegKind::Sip,
                },
                LegSpec {
                    direction: LegDirection::Outbound,
                    kind: LegKind::InteractiveWebRtc,
                },
            ],
            at(1),
        )
    }

    fn attachment_for(call: &CallAggregate, byte: u8) -> AttachmentIssue {
        let leg = &call.legs()[0];
        AttachmentIssue {
            attachment_id: AttachmentId::new(),
            token_digest: AttachmentTokenDigest::new(digest(byte)),
            leg_id: leg.id(),
            binding_generation: leg.binding_generation(),
            transport: AttachmentTransport::Sip,
            expires_at: at(121),
        }
    }

    fn create_request(call: CallAggregate, lease: WorkerLease, key: u8, request: u8) -> CreateCall {
        create_request_at(call, lease, key, request, at(2))
    }

    fn create_request_at(
        call: CallAggregate,
        lease: WorkerLease,
        key: u8,
        request: u8,
        now: DateTime<Utc>,
    ) -> CreateCall {
        let initial_decision = call
            .decide(CallCommand::StartConnecting {
                at: now,
                setup_deadline: now + chrono::Duration::seconds(30),
            })
            .unwrap();
        let issue = AttachmentIssue {
            expires_at: now + chrono::Duration::seconds(120),
            ..attachment_for(initial_decision.aggregate(), key.wrapping_add(100))
        };
        CreateCall {
            initial: call,
            command_id: CommandId::new(),
            command: CallCommand::StartConnecting {
                at: now,
                setup_deadline: now + chrono::Duration::seconds(30),
            },
            worker: lease,
            idempotency_key: IdempotencyKeyDigest::new(digest(key)),
            request_digest: crate::call_engine::RequestDigest::new(digest(request)),
            attachments: vec![issue],
            at: now,
        }
    }

    fn created(outcome: CreateCallOutcome) -> StoredCall {
        match outcome {
            CreateCallOutcome::Created(call) => call,
            CreateCallOutcome::Replayed(_) => panic!("expected created call"),
        }
    }

    #[tokio::test]
    async fn tenant_scoped_create_and_load() {
        let repo = MemoryRepository::new();
        let worker = worker(&repo, 2).await;
        let owner = tenant("tenant-a");
        let call = created(
            repo.create_call(create_request(new_call(owner.clone()), worker.lease, 1, 2))
                .await
                .unwrap(),
        );
        assert_eq!(
            repo.load_call(&owner, call.aggregate.id()).await.unwrap(),
            call
        );
        assert_eq!(
            repo.load_call(&tenant("tenant-b"), call.aggregate.id())
                .await,
            Err(RepositoryError::NotFound)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn identical_idempotency_digests_are_isolated_by_tenant() {
        let repo = Arc::new(MemoryRepository::new());
        let worker = worker(&repo, 2).await;
        let mut left = create_request(new_call(tenant("tenant-a")), worker.lease, 1, 1);
        let mut right = create_request(new_call(tenant("tenant-b")), worker.lease, 1, 1);
        left.attachments[0].token_digest = AttachmentTokenDigest::new(digest(201));
        right.attachments[0].token_digest = AttachmentTokenDigest::new(digest(202));
        let left_task = {
            let repo = Arc::clone(&repo);
            tokio::spawn(async move { repo.create_call(left).await })
        };
        let right_task = {
            let repo = Arc::clone(&repo);
            tokio::spawn(async move { repo.create_call(right).await })
        };
        let left = created(left_task.await.unwrap().unwrap());
        let right = created(right_task.await.unwrap().unwrap());
        assert_ne!(left.aggregate.id(), right.aggregate.id());
        assert_eq!(repo.counts().unwrap().calls, 2);
        assert_eq!(repo.counts().unwrap().idempotency, 2);
        assert_eq!(
            repo.load_call(&tenant("tenant-a"), right.aggregate.id())
                .await,
            Err(RepositoryError::NotFound)
        );
        assert_eq!(
            repo.load_call(&tenant("tenant-b"), left.aggregate.id())
                .await,
            Err(RepositoryError::NotFound)
        );
    }

    #[tokio::test]
    async fn create_rejects_forged_nonzero_pending_snapshot() {
        let repo = MemoryRepository::new();
        let worker = worker(&repo, 2).await;
        let mut wire = serde_json::to_value(new_call(tenant("tenant-a"))).unwrap();
        wire["version"] = json!(7);
        let forged: CallAggregate = serde_json::from_value(wire).unwrap();
        assert_eq!(forged.state(), CallState::Pending);
        assert_eq!(forged.version().value(), 7);
        assert_eq!(
            repo.create_call(create_request(forged, worker.lease, 2, 3))
                .await,
            Err(RepositoryError::InvalidInput(
                "initial call must be pending at version zero"
            ))
        );
        assert_eq!(repo.counts().unwrap().calls, 0);
        assert_eq!(
            repo.worker_snapshot(worker.lease.worker_id)
                .await
                .unwrap()
                .reserved_calls,
            0
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn sixty_four_way_idempotency_reserves_once() {
        let repo = Arc::new(MemoryRepository::new());
        let worker = worker(&repo, 4).await;
        let mut tasks = Vec::new();
        for _ in 0..64 {
            let repo = Arc::clone(&repo);
            let lease = worker.lease;
            tasks.push(tokio::spawn(async move {
                repo.create_call(create_request(new_call(tenant("tenant-a")), lease, 3, 4))
                    .await
                    .unwrap()
            }));
        }
        let mut created_count = 0;
        let mut ids = BTreeSet::new();
        for task in tasks {
            match task.await.unwrap() {
                CreateCallOutcome::Created(call) => {
                    created_count += 1;
                    ids.insert(call.aggregate.id());
                }
                CreateCallOutcome::Replayed(call) => {
                    ids.insert(call.aggregate.id());
                }
            }
        }
        assert_eq!(created_count, 1);
        assert_eq!(ids.len(), 1);
        assert_eq!(repo.counts().unwrap().calls, 1);
        assert_eq!(
            repo.worker_snapshot(worker.lease.worker_id)
                .await
                .unwrap()
                .reserved_calls,
            1
        );
    }

    #[tokio::test]
    async fn idempotency_conflict_and_expiry_are_atomic() {
        let repo = MemoryRepository::new();
        let worker = worker(&repo, 3).await;
        repo.create_call(create_request(
            new_call(tenant("tenant-a")),
            worker.lease,
            5,
            6,
        ))
        .await
        .unwrap();
        let conflict = repo
            .create_call(create_request(
                new_call(tenant("tenant-a")),
                worker.lease,
                5,
                7,
            ))
            .await;
        assert_eq!(conflict, Err(RepositoryError::IdempotencyConflict));
        assert_eq!(repo.counts().unwrap().calls, 1);

        let mut after_expiry = create_request_at(
            new_call(tenant("tenant-a")),
            worker.lease,
            5,
            7,
            at(2 + 24 * 60 * 60 + 1),
        );
        // Production attachment digests are derived from the new attachment
        // identity, not from the HTTP idempotency key. Reusing an expired
        // HTTP key therefore still produces an independent attachment.
        after_expiry.attachments[0].token_digest = AttachmentTokenDigest::new(digest(212));
        assert!(matches!(
            repo.create_call(after_expiry).await.unwrap(),
            CreateCallOutcome::Created(_)
        ));
        assert_eq!(repo.counts().unwrap().calls, 2);
        assert_eq!(repo.counts().unwrap().idempotency, 1);
    }

    #[tokio::test]
    async fn create_purges_every_expired_idempotency_key() {
        let repo = MemoryRepository::new();
        let worker = worker(&repo, 4).await;
        for key in [8u8, 9] {
            repo.create_call(create_request(
                new_call(tenant("tenant-a")),
                worker.lease,
                key,
                key,
            ))
            .await
            .unwrap();
        }
        assert_eq!(repo.counts().unwrap().idempotency, 2);
        repo.create_call(create_request_at(
            new_call(tenant("tenant-a")),
            worker.lease,
            10,
            10,
            at(2 + 24 * 60 * 60 + 1),
        ))
        .await
        .unwrap();
        assert_eq!(repo.counts().unwrap().calls, 3);
        assert_eq!(repo.counts().unwrap().idempotency, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn capacity_n_plus_one_has_exactly_n_successes() {
        let repo = Arc::new(MemoryRepository::new());
        let worker = worker(&repo, 8).await;
        let mut tasks = Vec::new();
        for index in 0..9u8 {
            let repo = Arc::clone(&repo);
            let lease = worker.lease;
            tasks.push(tokio::spawn(async move {
                repo.create_call(create_request(
                    new_call(tenant("tenant-a")),
                    lease,
                    20 + index,
                    40 + index,
                ))
                .await
            }));
        }
        let results = futures_for_tests(tasks).await;
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 8);
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Err(RepositoryError::CapacityExceeded))
                .count(),
            1
        );
        assert_eq!(repo.counts().unwrap().calls, 8);
    }

    async fn futures_for_tests(
        tasks: Vec<tokio::task::JoinHandle<Result<CreateCallOutcome, RepositoryError>>>,
    ) -> Vec<Result<CreateCallOutcome, RepositoryError>> {
        let mut results = Vec::new();
        for task in tasks {
            results.push(task.await.unwrap());
        }
        results
    }

    #[tokio::test]
    async fn command_cas_dedupe_and_late_attachment_failure_roll_back() {
        let repo = MemoryRepository::new();
        let worker = worker(&repo, 2).await;
        let owner = tenant("tenant-a");
        let call = created(
            repo.create_call(create_request(
                new_call(owner.clone()),
                worker.lease,
                60,
                61,
            ))
            .await
            .unwrap(),
        );
        let command_id = CommandId::new();
        let command = CallCommand::SetLegState {
            at: at(3),
            leg_id: call.aggregate.legs()[1].id(),
            binding_generation: call.aggregate.legs()[1].binding_generation(),
            state: LegState::Signaling,
            failure: None,
        };
        let request = CommandCommit {
            tenant_id: owner.clone(),
            call_id: call.aggregate.id(),
            expected_version: call.aggregate.version(),
            command_id,
            command: command.clone(),
            worker: worker.lease,
            attachments: Vec::new(),
            deadline_claim: None,
            at: at(3),
        };
        let first = repo.commit_command(request.clone()).await.unwrap();
        assert!(matches!(first, CommandCommitOutcome::Committed(_)));
        assert!(matches!(
            repo.commit_command(request).await.unwrap(),
            CommandCommitOutcome::Replayed(_)
        ));
        assert_eq!(
            repo.commit_command(CommandCommit {
                command_id: CommandId::new(),
                expected_version: call.aggregate.version(),
                ..CommandCommit {
                    tenant_id: owner.clone(),
                    call_id: call.aggregate.id(),
                    expected_version: call.aggregate.version(),
                    command_id,
                    command: command.clone(),
                    worker: worker.lease,
                    attachments: Vec::new(),
                    deadline_claim: None,
                    at: at(3),
                }
            })
            .await,
            Err(RepositoryError::VersionConflict)
        );

        let current = repo.load_call(&owner, call.aggregate.id()).await.unwrap();
        let bad_issue = AttachmentIssue {
            attachment_id: AttachmentId::new(),
            token_digest: AttachmentTokenDigest::new(digest(60 + 100)),
            leg_id: current.aggregate.legs()[1].id(),
            binding_generation: current.aggregate.legs()[1].binding_generation(),
            transport: AttachmentTransport::WebRtc,
            expires_at: at(120),
        };
        let counts = repo.counts().unwrap();
        let rejected = repo
            .commit_command(CommandCommit {
                tenant_id: owner.clone(),
                call_id: current.aggregate.id(),
                expected_version: current.aggregate.version(),
                command_id: CommandId::new(),
                command: CallCommand::SetLegState {
                    at: at(4),
                    leg_id: current.aggregate.legs()[1].id(),
                    binding_generation: current.aggregate.legs()[1].binding_generation(),
                    state: LegState::Connected,
                    failure: None,
                },
                worker: worker.lease,
                attachments: vec![bad_issue],
                deadline_claim: None,
                at: at(4),
            })
            .await;
        assert_eq!(
            rejected,
            Err(RepositoryError::InvalidInput(
                "attachment does not match an awaiting leg generation"
            ))
        );
        assert_eq!(repo.counts().unwrap(), counts);
        assert_eq!(
            repo.load_call(&owner, current.aggregate.id())
                .await
                .unwrap(),
            current
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_cas_allows_one_version_winner() {
        let repo = Arc::new(MemoryRepository::new());
        let worker = worker(&repo, 2).await;
        let owner = tenant("tenant-a");
        let call = created(
            repo.create_call(create_request(
                new_call(owner.clone()),
                worker.lease,
                62,
                63,
            ))
            .await
            .unwrap(),
        );
        let mut tasks = Vec::new();
        for (index, leg) in call.aggregate.legs().iter().enumerate() {
            let repo = Arc::clone(&repo);
            let request = CommandCommit {
                tenant_id: owner.clone(),
                call_id: call.aggregate.id(),
                expected_version: call.aggregate.version(),
                command_id: CommandId::new(),
                command: CallCommand::SetLegState {
                    at: at(3),
                    leg_id: leg.id(),
                    binding_generation: leg.binding_generation(),
                    state: LegState::Signaling,
                    failure: None,
                },
                worker: worker.lease,
                attachments: Vec::new(),
                deadline_claim: None,
                at: at(3),
            };
            tasks.push(tokio::spawn(async move {
                (index, repo.commit_command(request).await)
            }));
        }
        let mut committed = 0;
        let mut conflicts = 0;
        for task in tasks {
            match task.await.unwrap().1 {
                Ok(CommandCommitOutcome::Committed(_)) => committed += 1,
                Err(RepositoryError::VersionConflict) => conflicts += 1,
                other => panic!("unexpected CAS outcome: {other:?}"),
            }
        }
        assert_eq!((committed, conflicts), (1, 1));
    }

    #[tokio::test]
    async fn command_replay_requires_every_immutable_input_and_current_fence() {
        let repo = MemoryRepository::new();
        let worker = worker(&repo, 2).await;
        let owner = tenant("tenant-a");
        let call = created(
            repo.create_call(create_request(
                new_call(owner.clone()),
                worker.lease,
                120,
                121,
            ))
            .await
            .unwrap(),
        );
        let leg = &call.aggregate.legs()[0];
        let command = CallCommand::RotateLegBinding {
            at: at(3),
            leg_id: leg.id(),
            binding_generation: leg.binding_generation(),
        };
        let decision = call.aggregate.decide(command.clone()).unwrap();
        let rotated_leg = decision.aggregate().leg(leg.id()).unwrap();
        let issue = AttachmentIssue {
            attachment_id: AttachmentId::new(),
            token_digest: AttachmentTokenDigest::new(digest(221)),
            leg_id: rotated_leg.id(),
            binding_generation: rotated_leg.binding_generation(),
            transport: AttachmentTransport::Sip,
            expires_at: at(123),
        };
        let request = CommandCommit {
            tenant_id: owner,
            call_id: call.aggregate.id(),
            expected_version: call.aggregate.version(),
            command_id: CommandId::new(),
            command,
            worker: worker.lease,
            attachments: vec![issue],
            deadline_claim: None,
            at: at(3),
        };
        assert!(matches!(
            repo.commit_command(request.clone()).await.unwrap(),
            CommandCommitOutcome::Committed(_)
        ));
        assert!(matches!(
            repo.commit_command(request.clone()).await.unwrap(),
            CommandCommitOutcome::Replayed(_)
        ));

        let mut different_attachment = request.clone();
        different_attachment.attachments[0].attachment_id = AttachmentId::new();
        different_attachment.attachments[0].token_digest = AttachmentTokenDigest::new(digest(222));
        assert_eq!(
            repo.commit_command(different_attachment).await,
            Err(RepositoryError::CommandConflict)
        );

        repo.register_worker(RegisterWorker {
            worker_id: worker.lease.worker_id,
            max_calls: 2,
            capabilities: BTreeSet::from(["sip".into()]),
            at: at(4),
        })
        .await
        .unwrap();
        assert_eq!(
            repo.commit_command(request).await,
            Err(RepositoryError::StaleWorkerFence)
        );
    }

    #[tokio::test]
    async fn attachment_is_single_use_and_fully_isolated() {
        let repo = MemoryRepository::new();
        let worker = worker(&repo, 3).await;
        let owner = tenant("tenant-a");
        let request = create_request(new_call(owner.clone()), worker.lease, 70, 71);
        let token = request.attachments[0].token_digest;
        let call = created(repo.create_call(request).await.unwrap());
        let lookup = AttachmentLookup {
            token_digest: token,
            tenant_id: owner.clone(),
            transport: AttachmentTransport::Sip,
            worker: worker.lease,
            at: at(3),
        };
        assert!(matches!(
            repo.inspect_attachment(AttachmentLookup {
                tenant_id: tenant("tenant-b"),
                ..lookup.clone()
            })
            .await,
            Err(RepositoryError::AttachmentRejected)
        ));
        assert!(matches!(
            repo.inspect_attachment(AttachmentLookup {
                transport: AttachmentTransport::WebRtc,
                ..lookup.clone()
            })
            .await,
            Err(RepositoryError::AttachmentRejected)
        ));
        let candidate = repo.inspect_attachment(lookup.clone()).await.unwrap();
        let connection_id = ConnectionId::new();
        let consumed = repo
            .consume_attachment(AttachmentConsume {
                candidate: candidate.clone(),
                command_id: CommandId::new(),
                command: CallCommand::SetLegState {
                    at: at(4),
                    leg_id: candidate.leg_id(),
                    binding_generation: candidate.binding_generation(),
                    state: LegState::Signaling,
                    failure: None,
                },
                connection_id: connection_id.clone(),
                principal_fingerprint: crate::call_engine::PrincipalFingerprint::new(digest(72)),
                at: at(4),
            })
            .await
            .unwrap();
        assert_eq!(consumed.binding.connection_id, connection_id);
        assert_eq!(
            consumed
                .commit
                .call
                .bindings
                .get(&call.aggregate.legs()[0].id())
                .unwrap()
                .connection_id,
            connection_id
        );
        assert!(matches!(
            repo.inspect_attachment(lookup).await,
            Err(RepositoryError::AttachmentRejected)
        ));
        assert_eq!(
            repo.consume_attachment(AttachmentConsume {
                candidate,
                command_id: CommandId::new(),
                command: CallCommand::SetLegState {
                    at: at(5),
                    leg_id: call.aggregate.legs()[0].id(),
                    binding_generation: call.aggregate.legs()[0].binding_generation(),
                    state: LegState::Signaling,
                    failure: None,
                },
                connection_id: ConnectionId::new(),
                principal_fingerprint: crate::call_engine::PrincipalFingerprint::new(digest(73)),
                at: at(5),
            })
            .await,
            Err(RepositoryError::AttachmentRejected)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn interleaved_attachments_never_cross_connect_calls() {
        let repo = Arc::new(MemoryRepository::new());
        let worker = worker(&repo, 16).await;
        let owner = tenant("tenant-a");
        let mut candidates = Vec::new();
        let mut tokens = Vec::new();
        for index in 0..16u8 {
            let request = create_request(new_call(owner.clone()), worker.lease, index, 20 + index);
            let token = request.attachments[0].token_digest;
            repo.create_call(request).await.unwrap();
            let candidate = repo
                .inspect_attachment(AttachmentLookup {
                    token_digest: token,
                    tenant_id: owner.clone(),
                    transport: AttachmentTransport::Sip,
                    worker: worker.lease,
                    at: at(3),
                })
                .await
                .unwrap();
            tokens.push(token);
            candidates.push(candidate);
        }
        candidates.reverse();
        let mut tasks = Vec::new();
        for (index, candidate) in candidates.into_iter().enumerate() {
            let repo = Arc::clone(&repo);
            tasks.push(tokio::spawn(async move {
                let connection_id = ConnectionId::new();
                let consumed = repo
                    .consume_attachment(AttachmentConsume {
                        command_id: CommandId::new(),
                        command: CallCommand::SetLegState {
                            at: at(4),
                            leg_id: candidate.leg_id(),
                            binding_generation: candidate.binding_generation(),
                            state: LegState::Signaling,
                            failure: None,
                        },
                        candidate,
                        connection_id: connection_id.clone(),
                        principal_fingerprint: crate::call_engine::PrincipalFingerprint::new(
                            digest(150 + u8::try_from(index).unwrap()),
                        ),
                        at: at(4),
                    })
                    .await
                    .unwrap();
                (connection_id, consumed)
            }));
        }
        let mut call_ids = BTreeSet::new();
        let mut connection_ids = BTreeSet::new();
        for task in tasks {
            let (connection_id, consumed) = task.await.unwrap();
            assert_eq!(consumed.binding.connection_id, connection_id);
            let stored = consumed
                .commit
                .call
                .bindings
                .get(&consumed.binding.leg_id)
                .unwrap();
            assert_eq!(stored.connection_id, connection_id);
            call_ids.insert(consumed.commit.call.aggregate.id());
            connection_ids.insert(connection_id);
        }
        assert_eq!(call_ids.len(), 16);
        assert_eq!(connection_ids.len(), 16);
        for token in tokens {
            assert!(matches!(
                repo.inspect_attachment(AttachmentLookup {
                    token_digest: token,
                    tenant_id: owner.clone(),
                    transport: AttachmentTransport::Sip,
                    worker: worker.lease,
                    at: at(5),
                })
                .await,
                Err(RepositoryError::AttachmentRejected)
            ));
        }
    }

    #[tokio::test]
    async fn provider_callbacks_wait_for_reference_in_receipt_order() {
        let repo = MemoryRepository::new();
        let worker = worker(&repo, 2).await;
        let owner = tenant("tenant-a");
        let call = created(
            repo.create_call(create_request(
                new_call(owner.clone()),
                worker.lease,
                80,
                81,
            ))
            .await
            .unwrap(),
        );
        let account = ProviderAccountKey::parse("twilio-account").unwrap();
        let provider_call_id = ProviderCallId::parse("provider-call-1").unwrap();
        for (event, received) in [(1u8, 6i64), (2, 5)] {
            let outcome = repo
                .ingest_provider_event(ProviderEventInput {
                    account: account.clone(),
                    event_digest: ProviderEventDigest::new(digest(event)),
                    payload_digest: crate::call_engine::ProviderPayloadDigest::new(digest(event)),
                    provider_call_id: provider_call_id.clone(),
                    kind: "call_state".into(),
                    payload: json!({"sequence": event}),
                    occurred_at: None,
                    received_at: at(received),
                })
                .await
                .unwrap();
            assert!(matches!(
                outcome,
                ProviderEventOutcome::Accepted(ProviderEventEnvelope {
                    state: ProviderEventState::PendingReference,
                    ..
                })
            ));
        }
        let duplicate = repo
            .ingest_provider_event(ProviderEventInput {
                account: account.clone(),
                event_digest: ProviderEventDigest::new(digest(1)),
                payload_digest: crate::call_engine::ProviderPayloadDigest::new(digest(1)),
                provider_call_id: provider_call_id.clone(),
                kind: "call_state".into(),
                payload: json!({"sequence": 1}),
                occurred_at: None,
                received_at: at(6),
            })
            .await
            .unwrap();
        assert!(matches!(duplicate, ProviderEventOutcome::Duplicate(_)));
        assert_eq!(
            repo.ingest_provider_event(ProviderEventInput {
                account: account.clone(),
                event_digest: ProviderEventDigest::new(digest(1)),
                payload_digest: crate::call_engine::ProviderPayloadDigest::new(digest(9)),
                provider_call_id: provider_call_id.clone(),
                kind: "call_state".into(),
                payload: json!({"sequence": 9}),
                occurred_at: None,
                received_at: at(7),
            })
            .await,
            Err(RepositoryError::ProviderEventConflict)
        );
        let ready = repo
            .bind_provider_reference(BindProviderReference {
                tenant_id: owner.clone(),
                call_id: call.aggregate.id(),
                leg_id: call.aggregate.legs()[1].id(),
                account: account.clone(),
                provider_call_id,
                worker: worker.lease,
                at: at(8),
            })
            .await
            .unwrap();
        assert_eq!(ready.len(), 2);
        assert_eq!(ready[0].received_at, at(5));
        assert_eq!(ready[1].received_at, at(6));
        assert!(ready
            .iter()
            .all(|event| event.state == ProviderEventState::Ready));
    }

    #[tokio::test]
    async fn outbox_claims_are_fenced_expiring_and_ordered() {
        let repo = MemoryRepository::new();
        let worker = worker(&repo, 2).await;
        let call = created(
            repo.create_call(create_request(
                new_call(tenant("tenant-a")),
                worker.lease,
                90,
                91,
            ))
            .await
            .unwrap(),
        );
        let first = repo
            .claim_outbox(worker.lease, at(3), Duration::from_secs(5), 1)
            .await
            .unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].record.call_id, call.aggregate.id());
        assert_eq!(
            repo.complete_outbox(
                first[0].record.effect_id,
                worker.lease,
                ClaimGeneration::default(),
                OutboxCompletion::Succeeded,
                at(4),
            )
            .await,
            Err(RepositoryError::StaleClaim)
        );
        let reclaimed = repo
            .claim_outbox(worker.lease, at(9), Duration::from_secs(5), 1)
            .await
            .unwrap();
        assert_eq!(reclaimed[0].record.effect_id, first[0].record.effect_id);
        assert!(reclaimed[0].claim_generation > first[0].claim_generation);
        let completed = repo
            .complete_outbox(
                reclaimed[0].record.effect_id,
                worker.lease,
                reclaimed[0].claim_generation,
                OutboxCompletion::Succeeded,
                at(10),
            )
            .await
            .unwrap();
        assert!(matches!(completed.state, OutboxState::Succeeded { .. }));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_outbox_claimers_never_share_an_effect() {
        let repo = Arc::new(MemoryRepository::new());
        let worker = worker(&repo, 2).await;
        repo.create_call(create_request(
            new_call(tenant("tenant-a")),
            worker.lease,
            94,
            95,
        ))
        .await
        .unwrap();
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let repo = Arc::clone(&repo);
            tasks.push(tokio::spawn(async move {
                repo.claim_outbox(worker.lease, at(3), Duration::from_secs(10), 2)
                    .await
                    .unwrap()
            }));
        }
        let mut effect_ids = BTreeSet::new();
        let mut count = 0;
        for task in tasks {
            for claim in task.await.unwrap() {
                count += 1;
                assert!(effect_ids.insert(claim.record.effect_id));
            }
        }
        assert_eq!(count, 3);
    }

    #[tokio::test]
    async fn deadline_claim_keeps_kind_when_generations_collide() {
        let repo = MemoryRepository::new();
        let worker = worker(&repo, 2).await;
        let owner = tenant("tenant-a");
        let call = created(
            repo.create_call(create_request(
                new_call(owner.clone()),
                worker.lease,
                130,
                131,
            ))
            .await
            .unwrap(),
        );
        repo.transaction(|state| {
            let setup = state
                .deadlines
                .get(&(
                    call.aggregate.id(),
                    DeadlineKind::Setup,
                    call.aggregate
                        .deadlines()
                        .get(DeadlineKind::Setup)
                        .generation(),
                ))
                .cloned()
                .ok_or(RepositoryError::NotFound)?;
            let media = DeadlineRecord {
                tenant_id: owner,
                call_id: setup.call_id,
                kind: DeadlineKind::Media,
                generation: setup.generation,
                due_at: setup.due_at,
                state: DeadlineState::Pending,
            };
            state
                .deadlines
                .insert((media.call_id, media.kind, media.generation), media);
            Ok(())
        })
        .unwrap();

        let claimed = repo
            .claim_due_deadlines(worker.lease, at(33), Duration::from_secs(10), 2)
            .await
            .unwrap();
        assert_eq!(claimed.len(), 2);
        assert!(claimed
            .iter()
            .any(|claim| claim.record.kind == DeadlineKind::Setup));
        assert!(claimed
            .iter()
            .any(|claim| claim.record.kind == DeadlineKind::Media));
        assert_eq!(claimed[0].record.generation, claimed[1].record.generation);
    }

    #[tokio::test]
    async fn due_deadline_claim_completes_with_command_and_restart_refences_work() {
        let repo = MemoryRepository::new();
        let worker = worker(&repo, 2).await;
        let owner = tenant("tenant-a");
        let call = created(
            repo.create_call(create_request(
                new_call(owner.clone()),
                worker.lease,
                100,
                101,
            ))
            .await
            .unwrap(),
        );
        let claimed = repo
            .claim_due_deadlines(worker.lease, at(33), Duration::from_secs(10), 10)
            .await
            .unwrap();
        assert_eq!(claimed.len(), 1);
        let timer = &claimed[0];
        let current = repo.load_call(&owner, call.aggregate.id()).await.unwrap();
        let committed = repo
            .commit_command(CommandCommit {
                tenant_id: owner.clone(),
                call_id: call.aggregate.id(),
                expected_version: current.aggregate.version(),
                command_id: CommandId::new(),
                command: CallCommand::DeadlineElapsed {
                    at: at(33),
                    kind: timer.record.kind,
                    generation: timer.record.generation,
                    ending_deadline: Some(at(43)),
                },
                worker: worker.lease,
                attachments: Vec::new(),
                deadline_claim: Some(timer.guard(worker.lease)),
                at: at(33),
            })
            .await
            .unwrap();
        assert!(matches!(committed, CommandCommitOutcome::Committed(_)));

        let newer = repo
            .register_worker(RegisterWorker {
                worker_id: worker.lease.worker_id,
                max_calls: 2,
                capabilities: BTreeSet::from(["sip".into()]),
                at: at(34),
            })
            .await
            .unwrap();
        assert_eq!(
            repo.commit_command(CommandCommit {
                tenant_id: owner.clone(),
                call_id: call.aggregate.id(),
                expected_version: repo
                    .load_call(&owner, call.aggregate.id())
                    .await
                    .unwrap()
                    .aggregate
                    .version(),
                command_id: CommandId::new(),
                command: CallCommand::BeginEnding {
                    at: at(35),
                    ending_deadline: Some(at(45)),
                    reason: StopLegReason::Requested,
                },
                worker: worker.lease,
                attachments: Vec::new(),
                deadline_claim: None,
                at: at(35),
            })
            .await,
            Err(RepositoryError::StaleWorkerFence)
        );
        let restart = repo
            .claim_restart_calls(newer.lease, at(35), 10)
            .await
            .unwrap();
        assert_eq!(restart.len(), 1);
        assert_eq!(restart[0].previous_fence, worker.lease.fence);
        assert_eq!(restart[0].call.assignment.lease, newer.lease);
    }

    #[tokio::test]
    async fn terminal_capacity_release_is_exactly_once() {
        let repo = MemoryRepository::new();
        let worker = worker(&repo, 1).await;
        let owner = tenant("tenant-a");
        let call = created(
            repo.create_call(create_request(
                new_call(owner.clone()),
                worker.lease,
                110,
                111,
            ))
            .await
            .unwrap(),
        );
        let mut current = call;
        for (offset, leg_index) in [(3, 0usize), (4, 1usize)] {
            let outcome = repo
                .commit_command(CommandCommit {
                    tenant_id: owner.clone(),
                    call_id: current.aggregate.id(),
                    expected_version: current.aggregate.version(),
                    command_id: CommandId::new(),
                    command: CallCommand::SetLegState {
                        at: at(offset),
                        leg_id: current.aggregate.legs()[leg_index].id(),
                        binding_generation: current.aggregate.legs()[leg_index]
                            .binding_generation(),
                        state: LegState::Signaling,
                        failure: None,
                    },
                    worker: worker.lease,
                    attachments: Vec::new(),
                    deadline_claim: None,
                    at: at(offset),
                })
                .await
                .unwrap();
            let CommandCommitOutcome::Committed(view) = outcome else {
                unreachable!()
            };
            current = view.call;
        }
        for (offset, leg_index) in [(5, 0usize), (6, 1usize)] {
            let outcome = repo
                .commit_command(CommandCommit {
                    tenant_id: owner.clone(),
                    call_id: current.aggregate.id(),
                    expected_version: current.aggregate.version(),
                    command_id: CommandId::new(),
                    command: CallCommand::SetLegState {
                        at: at(offset),
                        leg_id: current.aggregate.legs()[leg_index].id(),
                        binding_generation: current.aggregate.legs()[leg_index]
                            .binding_generation(),
                        state: LegState::Connected,
                        failure: None,
                    },
                    worker: worker.lease,
                    attachments: Vec::new(),
                    deadline_claim: None,
                    at: at(offset),
                })
                .await
                .unwrap();
            let CommandCommitOutcome::Committed(view) = outcome else {
                unreachable!()
            };
            current = view.call;
        }
        assert_eq!(current.aggregate.state(), CallState::Active);
        let outcome = repo
            .commit_command(CommandCommit {
                tenant_id: owner.clone(),
                call_id: current.aggregate.id(),
                expected_version: current.aggregate.version(),
                command_id: CommandId::new(),
                command: CallCommand::BeginEnding {
                    at: at(7),
                    ending_deadline: Some(at(17)),
                    reason: StopLegReason::Requested,
                },
                worker: worker.lease,
                attachments: Vec::new(),
                deadline_claim: None,
                at: at(7),
            })
            .await
            .unwrap();
        let CommandCommitOutcome::Committed(view) = outcome else {
            unreachable!()
        };
        current = view.call;
        for (offset, leg_index) in [(8, 0usize), (9, 1usize)] {
            let outcome = repo
                .commit_command(CommandCommit {
                    tenant_id: owner.clone(),
                    call_id: current.aggregate.id(),
                    expected_version: current.aggregate.version(),
                    command_id: CommandId::new(),
                    command: CallCommand::SetLegState {
                        at: at(offset),
                        leg_id: current.aggregate.legs()[leg_index].id(),
                        binding_generation: current.aggregate.legs()[leg_index]
                            .binding_generation(),
                        state: LegState::Ended,
                        failure: None,
                    },
                    worker: worker.lease,
                    attachments: Vec::new(),
                    deadline_claim: None,
                    at: at(offset),
                })
                .await
                .unwrap();
            let CommandCommitOutcome::Committed(view) = outcome else {
                unreachable!()
            };
            current = view.call;
        }
        assert_eq!(current.aggregate.state(), CallState::Ended);
        assert_eq!(
            repo.worker_snapshot(worker.lease.worker_id)
                .await
                .unwrap()
                .reserved_calls,
            0
        );
        assert!(!repo
            .release_assignment(&owner, current.aggregate.id(), worker.lease, at(10))
            .await
            .unwrap());
        assert_eq!(
            repo.worker_snapshot(worker.lease.worker_id)
                .await
                .unwrap()
                .reserved_calls,
            0
        );
    }
}
