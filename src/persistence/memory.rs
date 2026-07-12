//! One-lock transactional in-memory call repository.
//!
//! Every mutable index lives in one [`Mutex`]. Mutations clone the complete
//! development-sized state, apply all validation to that draft, and swap it
//! into place only on success. This deliberately favors exact database-like
//! rollback semantics over throughput; clustered deployments use the SQL
//! implementations added by the next roadmap item.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rvoip_core::ids::ConnectionId;
use serde::{Deserialize, Serialize};

use crate::call_engine::{
    chrono_ttl, idempotency_expiry, validate_attachment_issue, validate_provider_event,
    validate_register_worker, AggregateVersion, AttachmentCandidate, AttachmentConsume,
    AttachmentId, AttachmentIssue, AttachmentLookup, AttachmentTokenDigest, AttachmentTransport,
    BindProviderReference, BindingGeneration, CallAggregate, CallCommand, CallId, CallRepository,
    ClaimGeneration, ClaimedDeadline, ClaimedOutbox, ClaimedProviderEvent, CommandCommit,
    CommandCommitOutcome, CommandCommitView, CommandDisposition, CommandId, ConnectionBinding,
    ConsumedAttachment, CreateCall, CreateCallOutcome, DeadlineClaimGuard, DeadlineGeneration,
    DeadlineKind, DeadlineRecord, DeadlineState, EffectId, EffectIntent, FailureDetails,
    IdempotencyKeyDigest, LegId, LegState, OutboxCompletion, OutboxRecord, OutboxState,
    PrincipalFingerprint, ProviderAccountKey, ProviderCallId, ProviderEventCommit,
    ProviderEventCommitOutcome, ProviderEventDigest, ProviderEventEnvelope, ProviderEventInput,
    ProviderEventOutcome, ProviderEventState, ProviderEventTarget, ProviderReceiptSequence,
    RegisterWorker, RepositoryError, RestartClaim, StoredCall, StoredCommand, TenantId,
    TerminalProviderEventAcknowledge, TerminalProviderEventAcknowledgeOutcome, TransferResult,
    WorkerAssignment, WorkerFence, WorkerId, WorkerLease, WorkerSnapshot,
};
use crate::call_service::{
    CallExecutionPlan, CallServiceRepository, ClaimedControlEffect, CompletedServiceEffect,
    ControlCommandOutcome, ControlCommandTransaction, ControlCommandView, ControlOutboxRecord,
    ControlSequence, EffectResultOutcome, EffectResultReconciliation, EffectResultView,
    ExternalReferenceBinding, ExternalReferenceValue, OutboundConnectionBind,
    OutboundConnectionBindOutcome, ServiceCommandOutcome, ServiceCommandTransaction,
    ServiceCommandView, ServiceCreateOutcome, ServiceCreateTransaction, ServiceEffectPayload,
    ServiceEffectPayloadInput, ServiceEffectResult, StoredControlCommand, StoredExternalReference,
    StoredServiceCall, StoredServiceEffectPayload,
};

type BindingKey = (CallId, LegId, BindingGeneration);
type PrincipalBindingKey = (PrincipalFingerprint, BindingKey);
type DeadlineKey = (CallId, DeadlineKind, DeadlineGeneration);
type ProviderEventKey = (ProviderAccountKey, ProviderEventDigest);
type ProviderReferenceKey = (ProviderAccountKey, ProviderCallId);
type ExternalBindingKey = (CallId, LegId, BindingGeneration);

#[derive(Clone, Eq, Hash, PartialEq)]
enum ExternalReferenceKey {
    Provider(ProviderAccountKey, ProviderCallId),
    Signaling(String, String),
}

#[derive(Clone)]
struct StoredServiceCommandResult {
    request: ServiceCommandTransaction,
    view: ServiceCommandView,
}

#[derive(Clone)]
struct StoredControlCommandResult {
    request: ControlCommandTransaction,
    view: ControlCommandView,
}

#[derive(Clone)]
struct StoredOutboundBindingResult {
    request: OutboundConnectionBind,
    binding: ConnectionBinding,
}

#[derive(Clone)]
struct StoredReconciliationResult {
    request: EffectResultReconciliation,
    view: EffectResultView,
}

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

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct IdempotencyRow {
    pub(super) request_digest: crate::call_engine::RequestDigest,
    pub(super) call_id: CallId,
    pub(super) expires_at: DateTime<Utc>,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct AttachmentRow {
    pub(super) attachment_id: AttachmentId,
    pub(super) token_digest: AttachmentTokenDigest,
    pub(super) tenant_id: TenantId,
    pub(super) call_id: CallId,
    pub(super) leg_id: LegId,
    pub(super) binding_generation: BindingGeneration,
    pub(super) transport: AttachmentTransport,
    pub(super) expected_principal: PrincipalFingerprint,
    pub(super) worker: WorkerLease,
    pub(super) expires_at: DateTime<Utc>,
    pub(super) consumed_at: Option<DateTime<Utc>>,
    pub(super) revoked_at: Option<DateTime<Utc>>,
    pub(super) binding: Option<ConnectionBinding>,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct ProviderReferenceRow {
    pub(super) target: ProviderEventTarget,
    pub(super) bound_at: DateTime<Utc>,
}

/// One command and its immutable replay result in a durable snapshot.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct PersistedCommandRow {
    pub(super) command: StoredCommand,
    pub(super) result: CommandCommitView,
}

/// Tenant-scoped idempotency row in a durable snapshot.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct PersistedIdempotencyRow {
    pub(super) tenant_id: TenantId,
    pub(super) key_digest: IdempotencyKeyDigest,
    pub(super) row: IdempotencyRow,
}

/// Provider reference key and target in a durable snapshot.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct PersistedProviderReferenceRow {
    pub(super) account: ProviderAccountKey,
    pub(super) provider_call_id: ProviderCallId,
    pub(super) row: ProviderReferenceRow,
}

/// Provider completion key and immutable replay guard in a durable snapshot.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct PersistedProviderCompletionRow {
    pub(super) account: ProviderAccountKey,
    pub(super) event_digest: ProviderEventDigest,
    pub(super) row: ProviderCompletionRow,
}

/// Authoritative, backend-neutral primary rows persisted by SQL repositories.
///
/// Secondary indexes are deliberately omitted and rebuilt with uniqueness
/// validation on load, preventing stale derived indexes from surviving a
/// process restart.
#[derive(Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct MemoryStateSnapshot {
    pub(super) workers: Vec<WorkerSnapshot>,
    pub(super) calls: Vec<StoredCall>,
    pub(super) commands: Vec<PersistedCommandRow>,
    pub(super) idempotency: Vec<PersistedIdempotencyRow>,
    pub(super) attachments: Vec<AttachmentRow>,
    pub(super) provider_events: Vec<ProviderEventEnvelope>,
    pub(super) provider_references: Vec<PersistedProviderReferenceRow>,
    pub(super) provider_completions: Vec<PersistedProviderCompletionRow>,
    pub(super) provider_receipt_sequence: Option<ProviderReceiptSequence>,
    pub(super) used_connection_ids: Vec<ConnectionId>,
    pub(super) outbox: Vec<OutboxRecord>,
    pub(super) deadlines: Vec<DeadlineRecord>,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub(super) enum ProviderCompletionRow {
    Command {
        request: Box<ProviderEventCommit>,
        view: Box<CommandCommitView>,
    },
    TerminalAcknowledgement {
        request: TerminalProviderEventAcknowledge,
    },
}

#[derive(Clone, Default)]
struct MemoryState {
    workers: HashMap<WorkerId, WorkerSnapshot>,
    calls: HashMap<CallId, StoredCall>,
    leg_owners: HashMap<LegId, CallId>,
    commands: HashMap<CommandId, StoredCommand>,
    command_results: HashMap<CommandId, CommandCommitView>,
    idempotency: HashMap<(TenantId, IdempotencyKeyDigest), IdempotencyRow>,
    attachments: HashMap<AttachmentTokenDigest, AttachmentRow>,
    attachment_ids: HashMap<AttachmentId, AttachmentTokenDigest>,
    active_attachments: HashMap<BindingKey, AttachmentTokenDigest>,
    connection_owners: HashMap<ConnectionId, BindingKey>,
    used_connection_ids: HashSet<ConnectionId>,
    principal_bindings: HashMap<PrincipalBindingKey, ConnectionId>,
    provider_events: HashMap<ProviderEventKey, ProviderEventEnvelope>,
    provider_references: HashMap<ProviderReferenceKey, ProviderReferenceRow>,
    provider_completions: HashMap<ProviderEventKey, ProviderCompletionRow>,
    provider_receipt_sequence: Option<ProviderReceiptSequence>,
    outbox: HashMap<EffectId, OutboxRecord>,
    deadlines: HashMap<DeadlineKey, DeadlineRecord>,
    execution_plans: HashMap<CallId, CallExecutionPlan>,
    service_effect_payloads: HashMap<EffectId, StoredServiceEffectPayload>,
    service_command_results: HashMap<CommandId, StoredServiceCommandResult>,
    control_commands: HashMap<CommandId, StoredControlCommand>,
    control_command_results: HashMap<CommandId, StoredControlCommandResult>,
    control_outbox: HashMap<EffectId, ControlOutboxRecord>,
    control_sequences: HashMap<ExternalBindingKey, ControlSequence>,
    outbound_binding_results: HashMap<CommandId, StoredOutboundBindingResult>,
    external_references: HashMap<ExternalReferenceKey, StoredExternalReference>,
    external_reference_bindings: HashMap<ExternalBindingKey, ExternalReferenceKey>,
    reconciliation_results: HashMap<EffectId, StoredReconciliationResult>,
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

    pub(super) fn snapshot(&self) -> Result<MemoryStateSnapshot, RepositoryError> {
        let state = self.lock()?;
        let mut commands = Vec::with_capacity(state.commands.len());
        for command in state.commands.values() {
            let result = state
                .command_results
                .get(&command.command_id)
                .filter(|result| result.command == *command)
                .cloned()
                .ok_or(RepositoryError::Unavailable)?;
            commands.push(PersistedCommandRow {
                command: command.clone(),
                result,
            });
        }

        Ok(MemoryStateSnapshot {
            workers: state.workers.values().cloned().collect(),
            calls: state.calls.values().cloned().collect(),
            commands,
            idempotency: state
                .idempotency
                .iter()
                .map(|((tenant_id, key_digest), row)| PersistedIdempotencyRow {
                    tenant_id: tenant_id.clone(),
                    key_digest: *key_digest,
                    row: row.clone(),
                })
                .collect(),
            attachments: state.attachments.values().cloned().collect(),
            provider_events: state.provider_events.values().cloned().collect(),
            provider_references: state
                .provider_references
                .iter()
                .map(
                    |((account, provider_call_id), row)| PersistedProviderReferenceRow {
                        account: account.clone(),
                        provider_call_id: provider_call_id.clone(),
                        row: row.clone(),
                    },
                )
                .collect(),
            provider_completions: state
                .provider_completions
                .iter()
                .map(
                    |((account, event_digest), row)| PersistedProviderCompletionRow {
                        account: account.clone(),
                        event_digest: *event_digest,
                        row: row.clone(),
                    },
                )
                .collect(),
            provider_receipt_sequence: state.provider_receipt_sequence,
            used_connection_ids: state.used_connection_ids.iter().cloned().collect(),
            outbox: state.outbox.values().cloned().collect(),
            deadlines: state.deadlines.values().cloned().collect(),
        })
    }

    pub(super) fn from_snapshot(snapshot: MemoryStateSnapshot) -> Result<Self, RepositoryError> {
        let mut state = MemoryState::default();

        for worker in snapshot.workers {
            if state
                .workers
                .insert(worker.lease.worker_id, worker)
                .is_some()
            {
                return Err(RepositoryError::Unavailable);
            }
        }
        for call in snapshot.calls {
            call.aggregate
                .validate()
                .map_err(|_| RepositoryError::Unavailable)?;
            let call_id = call.aggregate.id();
            for leg in call.aggregate.legs() {
                if state.leg_owners.insert(leg.id(), call_id).is_some() {
                    return Err(RepositoryError::Unavailable);
                }
            }
            for (leg_id, binding) in &call.bindings {
                let leg = call
                    .aggregate
                    .leg(*leg_id)
                    .ok_or(RepositoryError::Unavailable)?;
                if binding.leg_id != *leg_id
                    || binding.binding_generation != leg.binding_generation()
                {
                    return Err(RepositoryError::Unavailable);
                }
                let key = (call_id, *leg_id, binding.binding_generation);
                if state
                    .connection_owners
                    .insert(binding.connection_id.clone(), key)
                    .is_some()
                    || state
                        .principal_bindings
                        .insert(
                            (binding.principal_fingerprint, key),
                            binding.connection_id.clone(),
                        )
                        .is_some()
                {
                    return Err(RepositoryError::Unavailable);
                }
            }
            if state.calls.insert(call_id, call).is_some() {
                return Err(RepositoryError::Unavailable);
            }
        }
        for persisted in snapshot.commands {
            let command_id = persisted.command.command_id;
            if persisted.result.command != persisted.command
                || state
                    .commands
                    .insert(command_id, persisted.command)
                    .is_some()
                || state
                    .command_results
                    .insert(command_id, persisted.result)
                    .is_some()
            {
                return Err(RepositoryError::Unavailable);
            }
        }
        for persisted in snapshot.idempotency {
            if state
                .idempotency
                .insert((persisted.tenant_id, persisted.key_digest), persisted.row)
                .is_some()
            {
                return Err(RepositoryError::Unavailable);
            }
        }
        for attachment in snapshot.attachments {
            let token_digest = attachment.token_digest;
            let binding_key = (
                attachment.call_id,
                attachment.leg_id,
                attachment.binding_generation,
            );
            if state
                .attachment_ids
                .insert(attachment.attachment_id, token_digest)
                .is_some()
                || state
                    .active_attachments
                    .insert(binding_key, token_digest)
                    .is_some()
                || state.attachments.insert(token_digest, attachment).is_some()
            {
                return Err(RepositoryError::Unavailable);
            }
        }
        for event in snapshot.provider_events {
            let key = (event.account.clone(), event.event_digest);
            if state.provider_events.insert(key, event).is_some() {
                return Err(RepositoryError::Unavailable);
            }
        }
        for persisted in snapshot.provider_references {
            if state
                .provider_references
                .insert(
                    (persisted.account, persisted.provider_call_id),
                    persisted.row,
                )
                .is_some()
            {
                return Err(RepositoryError::Unavailable);
            }
        }
        for persisted in snapshot.provider_completions {
            if state
                .provider_completions
                .insert((persisted.account, persisted.event_digest), persisted.row)
                .is_some()
            {
                return Err(RepositoryError::Unavailable);
            }
        }
        for connection_id in snapshot.used_connection_ids {
            if !state.used_connection_ids.insert(connection_id) {
                return Err(RepositoryError::Unavailable);
            }
        }
        if state
            .connection_owners
            .keys()
            .any(|connection_id| !state.used_connection_ids.contains(connection_id))
            || state.provider_completions.keys().any(|key| {
                !state
                    .provider_events
                    .get(key)
                    .is_some_and(|event| matches!(event.state, ProviderEventState::Applied))
            })
            || state.provider_events.iter().any(|(key, event)| {
                matches!(event.state, ProviderEventState::Applied)
                    && !state.provider_completions.contains_key(key)
            })
        {
            return Err(RepositoryError::Unavailable);
        }
        state.provider_receipt_sequence = snapshot.provider_receipt_sequence;
        if state
            .provider_events
            .values()
            .map(|event| event.receipt_sequence)
            .max()
            != state.provider_receipt_sequence
        {
            return Err(RepositoryError::Unavailable);
        }
        for record in snapshot.outbox {
            if state.outbox.insert(record.effect_id, record).is_some() {
                return Err(RepositoryError::Unavailable);
            }
        }
        for record in snapshot.deadlines {
            let key = (record.call_id, record.kind, record.generation);
            if state.deadlines.insert(key, record).is_some() {
                return Err(RepositoryError::Unavailable);
            }
        }

        for call in state.calls.values() {
            let worker = state
                .workers
                .get(&call.assignment.lease.worker_id)
                .ok_or(RepositoryError::Unavailable)?;
            if worker.lease.fence < call.assignment.lease.fence {
                return Err(RepositoryError::Unavailable);
            }
        }

        Ok(Self {
            state: Mutex::new(state),
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
        self.transaction(|state| create_call_in_state(state, request))
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
        self.transaction(|state| {
            reject_service_managed_call(
                state,
                &request.tenant_id,
                request.call_id,
                request.worker,
            )?;
            commit_command_in_state(state, request)
        })
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
                || row.expected_principal != request.principal_fingerprint
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
                expected_principal: row.expected_principal,
                expected_version: call.aggregate.version(),
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
            if state.commands.contains_key(&request.command_id)
                || command_id_conflicts_with_service_namespace(state, request.command_id)
            {
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
                || row.expected_principal != request.candidate.expected_principal
                || row.expected_principal != request.principal_fingerprint
                || row.worker != request.candidate.worker
                || row.expires_at <= request.at
                || row.consumed_at.is_some()
                || row.revoked_at.is_some()
            {
                return Err(RepositoryError::AttachmentRejected);
            }
            let binding_key = (
                request.candidate.call_id,
                request.candidate.leg_id,
                request.candidate.binding_generation,
            );
            let principal_binding_key = (request.principal_fingerprint, binding_key);
            if state.used_connection_ids.contains(&request.connection_id)
                || state
                    .principal_bindings
                    .contains_key(&principal_binding_key)
            {
                return Err(RepositoryError::AttachmentConflict);
            }
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
            state
                .used_connection_ids
                .insert(request.connection_id.clone());
            state
                .principal_bindings
                .insert(principal_binding_key, request.connection_id.clone());
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
                    expected_version: request.candidate.expected_version(),
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
            let receipt_sequence = match state.provider_receipt_sequence {
                Some(last) => last.next()?,
                None => ProviderReceiptSequence::INITIAL,
            };
            state.provider_receipt_sequence = Some(receipt_sequence);
            let event = ProviderEventEnvelope {
                account: request.account,
                event_digest: request.event_digest,
                payload_digest: request.payload_digest,
                provider_call_id: request.provider_call_id,
                kind: request.kind,
                payload: request.payload,
                occurred_at: request.occurred_at,
                received_at: request.received_at,
                receipt_sequence,
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
            reject_service_managed_call(
                state,
                &request.tenant_id,
                request.call_id,
                request.worker,
            )?;
            bind_provider_reference_in_state(state, request)
        })
    }

    async fn claim_provider_events(
        &self,
        worker: WorkerLease,
        at: DateTime<Utc>,
        claim_ttl: Duration,
        limit: usize,
    ) -> Result<Vec<ClaimedProviderEvent>, RepositoryError> {
        let expires_at = chrono_ttl(at, claim_ttl)?;
        if limit == 0 {
            return Ok(Vec::new());
        }
        self.transaction(|state| {
            ensure_worker(state, worker, true)?;
            let mut eligible = state
                .provider_events
                .iter()
                .filter(|(_, event)| provider_event_claimable(state, event, worker, at))
                .map(|(key, event)| (event.receipt_sequence, key.clone()))
                .collect::<Vec<_>>();
            eligible.sort_by_key(|(sequence, _)| *sequence);

            let mut claimed = Vec::new();
            for (_, key) in eligible {
                if claimed.len() >= limit {
                    break;
                }
                let event = state
                    .provider_events
                    .get(&key)
                    .ok_or(RepositoryError::NotFound)?;
                if !provider_event_claimable(state, event, worker, at) {
                    continue;
                }
                let previous = match &event.state {
                    ProviderEventState::Ready => ClaimGeneration::default(),
                    ProviderEventState::Claimed { generation, .. } => *generation,
                    ProviderEventState::PendingReference | ProviderEventState::Applied => continue,
                };
                let generation = previous.next()?;
                let event = state
                    .provider_events
                    .get_mut(&key)
                    .ok_or(RepositoryError::NotFound)?;
                event.state = ProviderEventState::Claimed {
                    worker,
                    generation,
                    claimed_at: at,
                    expires_at,
                };
                claimed.push(ClaimedProviderEvent {
                    event: event.clone(),
                    claim_generation: generation,
                });
            }
            Ok(claimed)
        })
    }

    async fn complete_provider_event(
        &self,
        request: ProviderEventCommit,
    ) -> Result<ProviderEventCommitOutcome, RepositoryError> {
        self.transaction(|state| {
            if request.at != request.command.at
                || request.worker != request.command.worker
                || request.command.command.at() != request.at
            {
                return Err(RepositoryError::InvalidInput(
                    "provider completion and command times or workers differ",
                ));
            }
            ensure_worker(state, request.worker, true)?;
            let key = (request.account.clone(), request.event_digest);
            let event = state
                .provider_events
                .get(&key)
                .cloned()
                .ok_or(RepositoryError::NotFound)?;
            if let Some(target) = event.target.as_ref() {
                if target.tenant_id != request.command.tenant_id
                    || target.call_id != request.command.call_id
                {
                    return Err(RepositoryError::ProviderReferenceConflict);
                }
                if state.execution_plans.contains_key(&target.call_id) {
                    return Err(RepositoryError::InvalidInput(
                        "service-managed provider event requires service reconciliation",
                    ));
                }
            }
            if event.state == ProviderEventState::Applied {
                return match state.provider_completions.get(&key) {
                    Some(ProviderCompletionRow::Command {
                        request: recorded,
                        view,
                    }) if recorded.as_ref() == &request => Ok(ProviderEventCommitOutcome {
                        event,
                        command: CommandCommitOutcome::Replayed(view.as_ref().clone()),
                    }),
                    _ => Err(RepositoryError::StaleClaim),
                };
            }
            let target = event
                .target
                .clone()
                .ok_or(RepositoryError::ProviderReferenceConflict)?;
            match &event.state {
                ProviderEventState::Claimed {
                    worker,
                    generation,
                    claimed_at,
                    expires_at,
                } if *worker == request.worker
                    && *generation == request.claim_generation
                    && event.received_at <= request.at
                    && *claimed_at <= request.at
                    && *expires_at > request.at => {}
                _ => return Err(RepositoryError::StaleClaim),
            }
            if target.tenant_id != request.command.tenant_id
                || target.call_id != request.command.call_id
            {
                return Err(RepositoryError::ProviderReferenceConflict);
            }
            validate_provider_command_target(&target, &request.command.command)?;

            let recorded_request = request.clone();
            let command = commit_command_in_state(state, request.command)?;
            let view = match &command {
                CommandCommitOutcome::Committed(view) | CommandCommitOutcome::Replayed(view) => {
                    view.clone()
                }
            };
            let event = state
                .provider_events
                .get_mut(&key)
                .ok_or(RepositoryError::NotFound)?;
            event.state = ProviderEventState::Applied;
            event.applied_at = Some(request.at);
            let event = event.clone();
            state.provider_completions.insert(
                key,
                ProviderCompletionRow::Command {
                    request: Box::new(recorded_request),
                    view: Box::new(view),
                },
            );
            Ok(ProviderEventCommitOutcome { event, command })
        })
    }

    async fn acknowledge_terminal_provider_event(
        &self,
        request: TerminalProviderEventAcknowledge,
    ) -> Result<TerminalProviderEventAcknowledgeOutcome, RepositoryError> {
        self.transaction(|state| {
            ensure_worker(state, request.worker, true)?;
            let key = (request.account.clone(), request.event_digest);
            let event = state
                .provider_events
                .get(&key)
                .cloned()
                .ok_or(RepositoryError::NotFound)?;
            if event.state == ProviderEventState::Applied {
                return match state.provider_completions.get(&key) {
                    Some(ProviderCompletionRow::TerminalAcknowledgement { request: recorded })
                        if recorded == &request =>
                    {
                        Ok(TerminalProviderEventAcknowledgeOutcome::Replayed(event))
                    }
                    _ => Err(RepositoryError::StaleClaim),
                };
            }
            if event.target.as_ref() != Some(&request.target) {
                return Err(RepositoryError::ProviderReferenceConflict);
            }
            ensure_terminal_call_worker(state, &request.target, request.worker)?;
            match &event.state {
                ProviderEventState::Claimed {
                    worker,
                    generation,
                    claimed_at,
                    expires_at,
                } if *worker == request.worker
                    && *generation == request.claim_generation
                    && event.received_at <= request.at
                    && *claimed_at <= request.at
                    && *expires_at > request.at => {}
                _ => return Err(RepositoryError::StaleClaim),
            }
            let event = state
                .provider_events
                .get_mut(&key)
                .ok_or(RepositoryError::NotFound)?;
            event.state = ProviderEventState::Applied;
            event.applied_at = Some(request.at);
            let event = event.clone();
            state.provider_completions.insert(
                key,
                ProviderCompletionRow::TerminalAcknowledgement {
                    request: request.clone(),
                },
            );
            Ok(TerminalProviderEventAcknowledgeOutcome::Acknowledged(event))
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
                .filter(|record| outbox_claimable(state, record, worker, at))
                .map(|record| (outbox_order_key(record), record.effect_id))
                .collect::<Vec<_>>();
            eligible.sort_by_key(|(key, _)| *key);

            let mut claimed = Vec::new();
            for (_, effect_id) in eligible {
                if claimed.len() >= limit {
                    break;
                }
                let record = state
                    .outbox
                    .get(&effect_id)
                    .ok_or(RepositoryError::NotFound)?;
                if !outbox_claimable(state, record, worker, at) {
                    continue;
                }
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
            if state
                .outbox
                .get(&effect_id)
                .is_some_and(|record| state.execution_plans.contains_key(&record.call_id))
            {
                return Err(RepositoryError::InvalidInput(
                    "service-managed effect requires service reconciliation",
                ));
            }
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
                    call.assignment.lease.worker_id == worker.worker_id
                        && call.assignment.lease.fence < worker.fence
                        && (call.assignment.released_at.is_none()
                            || (call.aggregate.state().is_terminal()
                                && (has_unfinished_outbox(state, call.aggregate.id())
                                    || has_unfinished_control_outbox(state, call.aggregate.id())
                                    || has_unfinished_provider_events(state, call.aggregate.id()))))
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
                    .filter(|row| row.call_id == call_id && outbox_is_unfinished(row))
                {
                    record.worker = worker;
                    if matches!(record.state, OutboxState::Claimed { .. }) {
                        record.state = OutboxState::Ready;
                    }
                }
                for record in state
                    .control_outbox
                    .values_mut()
                    .filter(|row| row.call_id == call_id && control_outbox_is_unfinished(row))
                {
                    record.worker = worker;
                    if matches!(record.state, OutboxState::Claimed { .. }) {
                        record.state = OutboxState::Ready;
                        record.claimed_at = None;
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
                for event in state.provider_events.values_mut().filter(|event| {
                    event
                        .target
                        .as_ref()
                        .is_some_and(|target| target.call_id == call_id)
                }) {
                    if matches!(event.state, ProviderEventState::Claimed { .. }) {
                        event.state = ProviderEventState::Ready;
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

#[async_trait]
impl CallServiceRepository for MemoryRepository {
    async fn create_with_plan(
        &self,
        request: ServiceCreateTransaction,
    ) -> Result<ServiceCreateOutcome, RepositoryError> {
        request.plan.validate_against(&request.create.initial)?;
        self.transaction(|state| {
            let plan = request.plan;
            match create_call_in_state(state, request.create)? {
                CreateCallOutcome::Created(call) => {
                    if state
                        .execution_plans
                        .insert(call.aggregate.id(), plan.clone())
                        .is_some()
                    {
                        return Err(RepositoryError::Unavailable);
                    }
                    Ok(ServiceCreateOutcome::Created(StoredServiceCall {
                        call,
                        plan,
                    }))
                }
                CreateCallOutcome::Replayed(call) => {
                    let call_id = call.aggregate.id();
                    let original = state
                        .execution_plans
                        .get(&call_id)
                        .cloned()
                        .ok_or(RepositoryError::Unavailable)?;
                    Ok(ServiceCreateOutcome::Replayed(StoredServiceCall {
                        call: original_create_snapshot(state, call_id)?,
                        plan: original,
                    }))
                }
            }
        })
    }

    async fn load_service_call(
        &self,
        tenant_id: &TenantId,
        call_id: CallId,
    ) -> Result<StoredServiceCall, RepositoryError> {
        self.read(|state| {
            let call = tenant_call(state, tenant_id, call_id)?;
            let plan = state
                .execution_plans
                .get(&call_id)
                .cloned()
                .ok_or(RepositoryError::NotFound)?;
            Ok(StoredServiceCall { call, plan })
        })
    }

    async fn commit_with_effect_payloads(
        &self,
        request: ServiceCommandTransaction,
    ) -> Result<ServiceCommandOutcome, RepositoryError> {
        let request = normalize_service_command(request)?;
        self.transaction(|state| commit_service_command_in_state(state, request))
    }

    async fn load_effect_payload(
        &self,
        tenant_id: &TenantId,
        effect_id: EffectId,
    ) -> Result<Option<StoredServiceEffectPayload>, RepositoryError> {
        self.read(|state| {
            let record = state
                .outbox
                .get(&effect_id)
                .filter(|record| &record.tenant_id == tenant_id)
                .ok_or(RepositoryError::NotFound)?;
            let payload = state.service_effect_payloads.get(&effect_id).cloned();
            if payload
                .as_ref()
                .is_some_and(|payload| payload.command_id != record.command_id)
            {
                return Err(RepositoryError::Unavailable);
            }
            Ok(payload)
        })
    }

    async fn enqueue_control(
        &self,
        request: ControlCommandTransaction,
    ) -> Result<ControlCommandOutcome, RepositoryError> {
        request.intent.validate()?;
        self.transaction(|state| enqueue_control_in_state(state, request))
    }

    async fn claim_control_effects(
        &self,
        worker: WorkerLease,
        at: DateTime<Utc>,
        claim_ttl: Duration,
        limit: usize,
    ) -> Result<Vec<ClaimedControlEffect>, RepositoryError> {
        let expires_at = chrono_ttl(at, claim_ttl)?;
        if limit == 0 {
            return Ok(Vec::new());
        }
        self.transaction(|state| {
            ensure_worker(state, worker, true)?;
            let mut eligible = state
                .control_outbox
                .values()
                .filter(|record| control_outbox_claimable(state, record, worker, at))
                .map(|record| {
                    (
                        record.call_id,
                        record.leg_id,
                        record.binding_generation,
                        record.sequence,
                        record.effect_id,
                    )
                })
                .collect::<Vec<_>>();
            eligible.sort();
            eligible.truncate(limit);

            let mut claimed = Vec::with_capacity(eligible.len());
            for (_, _, _, _, effect_id) in eligible {
                let record = state
                    .control_outbox
                    .get(&effect_id)
                    .ok_or(RepositoryError::NotFound)?;
                if !control_outbox_claimable(state, record, worker, at) {
                    continue;
                }
                let record = state
                    .control_outbox
                    .get_mut(&effect_id)
                    .ok_or(RepositoryError::NotFound)?;
                let previous = match record.state {
                    OutboxState::Ready => ClaimGeneration::default(),
                    OutboxState::Claimed { generation, .. } => generation,
                    OutboxState::Succeeded { .. } | OutboxState::Failed { .. } => continue,
                };
                let generation = previous.next()?;
                record.state = OutboxState::Claimed {
                    worker,
                    generation,
                    expires_at,
                };
                record.claimed_at = Some(at);
                claimed.push(ClaimedControlEffect {
                    record: record.clone(),
                    claim_generation: generation,
                });
            }
            Ok(claimed)
        })
    }

    async fn bind_outbound_connection(
        &self,
        request: OutboundConnectionBind,
    ) -> Result<OutboundConnectionBindOutcome, RepositoryError> {
        self.transaction(|state| bind_outbound_connection_in_state(state, request))
    }

    async fn load_external_reference(
        &self,
        tenant_id: &TenantId,
        call_id: CallId,
        leg_id: LegId,
    ) -> Result<Option<StoredExternalReference>, RepositoryError> {
        self.read(|state| {
            let call = tenant_call(state, tenant_id, call_id)?;
            let leg = call
                .aggregate
                .leg(leg_id)
                .ok_or(RepositoryError::NotFound)?;
            let binding_key = (call_id, leg_id, leg.binding_generation());
            let Some(reference_key) = state.external_reference_bindings.get(&binding_key) else {
                return Ok(None);
            };
            let reference = state
                .external_references
                .get(reference_key)
                .cloned()
                .ok_or(RepositoryError::Unavailable)?;
            if &reference.tenant_id != tenant_id {
                return Err(RepositoryError::Unavailable);
            }
            Ok(Some(reference))
        })
    }

    async fn reconcile_effect_result(
        &self,
        request: EffectResultReconciliation,
    ) -> Result<EffectResultOutcome, RepositoryError> {
        let request = normalize_reconciliation(request)?;
        self.transaction(|state| reconcile_effect_result_in_state(state, request))
    }
}

fn original_create_snapshot(
    state: &MemoryState,
    call_id: CallId,
) -> Result<StoredCall, RepositoryError> {
    let mut matching = state.command_results.values().filter(|result| {
        result.command.call_id == call_id && result.command.observed_version.value() == 0
    });
    let call = matching
        .next()
        .map(|result| result.call.clone())
        .ok_or(RepositoryError::Unavailable)?;
    if matching.next().is_some() {
        return Err(RepositoryError::Unavailable);
    }
    Ok(call)
}

fn normalize_service_command(
    mut request: ServiceCommandTransaction,
) -> Result<ServiceCommandTransaction, RepositoryError> {
    request
        .effect_payloads
        .sort_by_key(|payload| payload.ordinal);
    if request
        .effect_payloads
        .windows(2)
        .any(|pair| pair[0].ordinal == pair[1].ordinal)
    {
        return Err(RepositoryError::InvalidInput(
            "duplicate service effect payload ordinal",
        ));
    }
    for input in &request.effect_payloads {
        input.payload.validate()?;
    }
    Ok(request)
}

fn commit_service_command_in_state(
    state: &mut MemoryState,
    request: ServiceCommandTransaction,
) -> Result<ServiceCommandOutcome, RepositoryError> {
    if let Some(existing) = state
        .service_command_results
        .get(&request.command.command_id)
    {
        return if existing.request == request {
            Ok(ServiceCommandOutcome::Replayed(existing.view.clone()))
        } else {
            Err(RepositoryError::CommandConflict)
        };
    }
    if state.commands.contains_key(&request.command.command_id)
        || state
            .control_commands
            .contains_key(&request.command.command_id)
        || state
            .outbound_binding_results
            .contains_key(&request.command.command_id)
    {
        return Err(RepositoryError::CommandConflict);
    }
    if !state.execution_plans.contains_key(&request.command.call_id) {
        return Err(RepositoryError::NotFound);
    }

    let core_request = request.command.clone();
    let core = match commit_command_in_state(state, core_request)? {
        CommandCommitOutcome::Committed(view) => view,
        CommandCommitOutcome::Replayed(_) => return Err(RepositoryError::CommandConflict),
    };
    let mut stored_payloads = Vec::with_capacity(request.effect_payloads.len());
    for effect in &core.outbox {
        let supplied = request
            .effect_payloads
            .iter()
            .find(|input| input.ordinal == effect.ordinal);
        match (&effect.intent, supplied) {
            (
                EffectIntent::ExecuteTransfer { .. },
                Some(ServiceEffectPayloadInput {
                    payload: ServiceEffectPayload::Transfer { .. },
                    ..
                }),
            ) => {}
            (EffectIntent::ExecuteTransfer { .. }, None) => {
                return Err(RepositoryError::InvalidInput(
                    "transfer effect requires a service payload",
                ));
            }
            (_, Some(_)) => {
                return Err(RepositoryError::InvalidInput(
                    "service payload ordinal does not target a compatible effect",
                ));
            }
            (_, None) => continue,
        }
        let supplied = supplied.ok_or(RepositoryError::Unavailable)?;
        stored_payloads.push(StoredServiceEffectPayload {
            effect_id: effect.effect_id,
            command_id: effect.command_id,
            ordinal: effect.ordinal,
            payload: supplied.payload.clone(),
        });
    }
    if stored_payloads.len() != request.effect_payloads.len() {
        return Err(RepositoryError::InvalidInput(
            "service payload ordinal does not exist",
        ));
    }
    for payload in &stored_payloads {
        if state
            .service_effect_payloads
            .insert(payload.effect_id, payload.clone())
            .is_some()
        {
            return Err(RepositoryError::Unavailable);
        }
    }
    let view = ServiceCommandView {
        command: core,
        effect_payloads: stored_payloads,
    };
    state.service_command_results.insert(
        request.command.command_id,
        StoredServiceCommandResult {
            request,
            view: view.clone(),
        },
    );
    Ok(ServiceCommandOutcome::Committed(view))
}

fn enqueue_control_in_state(
    state: &mut MemoryState,
    request: ControlCommandTransaction,
) -> Result<ControlCommandOutcome, RepositoryError> {
    if let Some(existing) = state.control_command_results.get(&request.command_id) {
        return if existing.request == request {
            Ok(ControlCommandOutcome::Replayed(existing.view.clone()))
        } else {
            Err(RepositoryError::CommandConflict)
        };
    }
    if state.commands.contains_key(&request.command_id)
        || state
            .service_command_results
            .contains_key(&request.command_id)
        || state
            .outbound_binding_results
            .contains_key(&request.command_id)
    {
        return Err(RepositoryError::CommandConflict);
    }
    ensure_call_worker(state, &request.tenant_id, request.call_id, request.worker)?;
    if !state.execution_plans.contains_key(&request.call_id) {
        return Err(RepositoryError::NotFound);
    }
    let call = state
        .calls
        .get(&request.call_id)
        .ok_or(RepositoryError::NotFound)?;
    let leg = call
        .aggregate
        .leg(request.leg_id)
        .ok_or(RepositoryError::NotFound)?;
    if leg.binding_generation() != request.binding_generation {
        return Err(RepositoryError::StaleClaim);
    }
    if !matches!(leg.state(), LegState::Connected | LegState::Held) {
        return Err(RepositoryError::DomainRejected);
    }
    let binding = call
        .bindings
        .get(&request.leg_id)
        .filter(|binding| binding.binding_generation == request.binding_generation)
        .ok_or(RepositoryError::StaleClaim)?;
    if binding.leg_id != request.leg_id {
        return Err(RepositoryError::Unavailable);
    }
    if request.at < call.aggregate.updated_at() || request.at < binding.bound_at {
        return Err(RepositoryError::InvalidInput(
            "control time predates its current binding",
        ));
    }

    let binding_key = (request.call_id, request.leg_id, request.binding_generation);
    let sequence = match state.control_sequences.get(&binding_key) {
        Some(previous) => previous.next()?,
        None => ControlSequence::INITIAL,
    };

    let effect_id = EffectId::new();
    if state.outbox.contains_key(&effect_id) || state.control_outbox.contains_key(&effect_id) {
        return Err(RepositoryError::Unavailable);
    }
    let command = StoredControlCommand {
        command_id: request.command_id,
        tenant_id: request.tenant_id.clone(),
        call_id: request.call_id,
        leg_id: request.leg_id,
        binding_generation: request.binding_generation,
        worker: request.worker,
        intent: request.intent.clone(),
        recorded_at: request.at,
    };
    let effect = ControlOutboxRecord {
        effect_id,
        command_id: request.command_id,
        tenant_id: request.tenant_id.clone(),
        call_id: request.call_id,
        leg_id: request.leg_id,
        binding_generation: request.binding_generation,
        worker: request.worker,
        sequence,
        intent: request.intent.clone(),
        available_at: request.at,
        claimed_at: None,
        state: OutboxState::Ready,
    };
    let view = ControlCommandView {
        command: command.clone(),
        effect: effect.clone(),
    };
    state.control_commands.insert(request.command_id, command);
    state.control_outbox.insert(effect_id, effect);
    state.control_sequences.insert(binding_key, sequence);
    state.control_command_results.insert(
        request.command_id,
        StoredControlCommandResult {
            request,
            view: view.clone(),
        },
    );
    Ok(ControlCommandOutcome::Enqueued(view))
}

fn bind_outbound_connection_in_state(
    state: &mut MemoryState,
    request: OutboundConnectionBind,
) -> Result<OutboundConnectionBindOutcome, RepositoryError> {
    if let Some(existing) = state.outbound_binding_results.get(&request.operation_id) {
        return if existing.request == request {
            Ok(OutboundConnectionBindOutcome::Replayed(
                existing.binding.clone(),
            ))
        } else {
            Err(RepositoryError::CommandConflict)
        };
    }
    if state.commands.contains_key(&request.operation_id)
        || state.control_commands.contains_key(&request.operation_id)
        || state
            .service_command_results
            .contains_key(&request.operation_id)
    {
        return Err(RepositoryError::CommandConflict);
    }
    ensure_call_worker(state, &request.tenant_id, request.call_id, request.worker)?;
    let plan = state
        .execution_plans
        .get(&request.call_id)
        .ok_or(RepositoryError::NotFound)?;
    let spec = plan
        .legs
        .iter()
        .find(|spec| spec.leg_id == request.leg_id)
        .ok_or(RepositoryError::NotFound)?;
    validate_endpoint_transport(&spec.endpoint, request.transport)?;

    let call = state
        .calls
        .get(&request.call_id)
        .ok_or(RepositoryError::NotFound)?;
    let leg = call
        .aggregate
        .leg(request.leg_id)
        .ok_or(RepositoryError::NotFound)?;
    if leg.direction() != crate::call_engine::LegDirection::Outbound {
        return Err(RepositoryError::InvalidInput(
            "outbound binding requires an outbound leg",
        ));
    }
    if leg.binding_generation() != request.binding_generation {
        return Err(RepositoryError::StaleClaim);
    }
    if request.at < call.aggregate.updated_at() {
        return Err(RepositoryError::InvalidInput(
            "outbound binding time predates call state",
        ));
    }
    if leg.state().is_terminal() || call.bindings.contains_key(&request.leg_id) {
        return Err(RepositoryError::AttachmentConflict);
    }
    let binding_key = (request.call_id, request.leg_id, request.binding_generation);
    let principal_binding_key = (request.principal_fingerprint, binding_key);
    if state.used_connection_ids.contains(&request.connection_id)
        || state.connection_owners.contains_key(&request.connection_id)
        || state
            .principal_bindings
            .contains_key(&principal_binding_key)
    {
        return Err(RepositoryError::AttachmentConflict);
    }

    let binding = ConnectionBinding {
        connection_id: request.connection_id.clone(),
        leg_id: request.leg_id,
        binding_generation: request.binding_generation,
        transport: request.transport,
        principal_fingerprint: request.principal_fingerprint,
        bound_at: request.at,
    };
    let call = state
        .calls
        .get_mut(&request.call_id)
        .ok_or(RepositoryError::NotFound)?;
    call.bindings.insert(request.leg_id, binding.clone());
    state
        .connection_owners
        .insert(request.connection_id.clone(), binding_key);
    state
        .used_connection_ids
        .insert(request.connection_id.clone());
    state
        .principal_bindings
        .insert(principal_binding_key, request.connection_id.clone());
    state.outbound_binding_results.insert(
        request.operation_id,
        StoredOutboundBindingResult {
            request,
            binding: binding.clone(),
        },
    );
    Ok(OutboundConnectionBindOutcome::Bound(binding))
}

fn validate_endpoint_transport(
    endpoint: &crate::call_service::LegEndpointConfig,
    transport: AttachmentTransport,
) -> Result<(), RepositoryError> {
    let expected = match endpoint {
        crate::call_service::LegEndpointConfig::Sip(_)
        | crate::call_service::LegEndpointConfig::Provider(_) => AttachmentTransport::Sip,
        crate::call_service::LegEndpointConfig::WebRtc(_)
        | crate::call_service::LegEndpointConfig::Whip(_)
        | crate::call_service::LegEndpointConfig::Whep(_)
        | crate::call_service::LegEndpointConfig::AmazonConnect(_) => AttachmentTransport::WebRtc,
    };
    if expected == transport {
        Ok(())
    } else {
        Err(RepositoryError::InvalidInput(
            "outbound binding transport does not match execution endpoint",
        ))
    }
}

fn normalize_reconciliation(
    mut request: EffectResultReconciliation,
) -> Result<EffectResultReconciliation, RepositoryError> {
    if let Some(follow_up) = request.follow_up.take() {
        request.follow_up = Some(normalize_service_command(follow_up)?);
    }
    if let Some(reference) = &request.external_reference {
        reference.value.validate()?;
    }
    if request.external_reference.is_some()
        && !matches!(request.result, ServiceEffectResult::Succeeded)
    {
        return Err(RepositoryError::InvalidInput(
            "failed effect cannot bind an external reference",
        ));
    }
    Ok(request)
}

#[derive(Clone)]
enum ServiceEffectSnapshot {
    Call(OutboxRecord),
    Control(ControlOutboxRecord),
}

fn reconcile_effect_result_in_state(
    state: &mut MemoryState,
    request: EffectResultReconciliation,
) -> Result<EffectResultOutcome, RepositoryError> {
    if let Some(existing) = state.reconciliation_results.get(&request.effect_id) {
        return if existing.request == request {
            Ok(EffectResultOutcome::Replayed(existing.view.clone()))
        } else {
            Err(RepositoryError::StaleClaim)
        };
    }
    ensure_worker(state, request.worker, true)?;
    let core = state.outbox.get(&request.effect_id).cloned();
    let control = state.control_outbox.get(&request.effect_id).cloned();
    let effect = match (core, control) {
        (Some(record), None) => ServiceEffectSnapshot::Call(record),
        (None, Some(record)) => ServiceEffectSnapshot::Control(record),
        (None, None) => return Err(RepositoryError::NotFound),
        (Some(_), Some(_)) => return Err(RepositoryError::Unavailable),
    };
    let (tenant_id, call_id, owner, state_view) = match &effect {
        ServiceEffectSnapshot::Call(record) => (
            &record.tenant_id,
            record.call_id,
            record.worker,
            &record.state,
        ),
        ServiceEffectSnapshot::Control(record) => (
            &record.tenant_id,
            record.call_id,
            record.worker,
            &record.state,
        ),
    };
    if tenant_id != &request.tenant_id || call_id != request.call_id || owner != request.worker {
        return Err(RepositoryError::StaleClaim);
    }
    validate_effect_claim(
        state_view,
        request.worker,
        request.claim_generation,
        request.at,
    )?;
    let available_at = match &effect {
        ServiceEffectSnapshot::Call(record) => record.available_at,
        ServiceEffectSnapshot::Control(record) => record.available_at,
    };
    if request.at < available_at {
        return Err(RepositoryError::InvalidInput(
            "effect completion predates effect availability",
        ));
    }
    if let ServiceEffectSnapshot::Control(record) = &effect {
        if record
            .claimed_at
            .is_none_or(|claimed_at| claimed_at > request.at)
        {
            return Err(RepositoryError::StaleClaim);
        }
    }
    let call = state
        .calls
        .get(&request.call_id)
        .filter(|call| call.aggregate.tenant_id() == &request.tenant_id)
        .ok_or(RepositoryError::NotFound)?;
    if call.assignment.lease != request.worker {
        return Err(RepositoryError::StaleWorkerFence);
    }
    if let ServiceEffectSnapshot::Control(record) = &effect {
        validate_control_effect_target(call, record)?;
    }
    if !state.execution_plans.contains_key(&request.call_id) {
        return Err(RepositoryError::NotFound);
    }

    let mut released_provider_events = Vec::new();
    let external_reference = match (&effect, &request.external_reference) {
        (ServiceEffectSnapshot::Control(_), Some(_)) => {
            return Err(RepositoryError::InvalidInput(
                "control effect cannot bind an external reference",
            ));
        }
        (ServiceEffectSnapshot::Control(_), None) => None,
        (ServiceEffectSnapshot::Call(record), Some(binding)) => {
            validate_external_reference_effect(record, binding)?;
            let (stored, released) =
                store_external_reference_in_state(state, &request, binding.clone())?;
            released_provider_events = released;
            Some(stored)
        }
        (ServiceEffectSnapshot::Call(_), None) => None,
    };

    let follow_up = match (&effect, request.follow_up.clone()) {
        (ServiceEffectSnapshot::Control(_), Some(_)) => {
            return Err(RepositoryError::InvalidInput(
                "control effect cannot commit a call follow-up",
            ));
        }
        (_, None) => None,
        (ServiceEffectSnapshot::Call(record), Some(follow_up)) => {
            if follow_up.command.tenant_id != request.tenant_id
                || follow_up.command.call_id != request.call_id
                || follow_up.command.worker != request.worker
                || follow_up.command.at != request.at
                || follow_up.command.command.at() != request.at
            {
                return Err(RepositoryError::InvalidInput(
                    "effect follow-up ownership or timestamp differs",
                ));
            }
            validate_effect_follow_up(&record.intent, &request.result, &follow_up.command.command)?;
            match commit_service_command_in_state(state, follow_up)? {
                ServiceCommandOutcome::Committed(view) => Some(view),
                ServiceCommandOutcome::Replayed(_) => {
                    return Err(RepositoryError::CommandConflict);
                }
            }
        }
    };

    let completed_state = match &request.result {
        ServiceEffectResult::Succeeded => OutboxState::Succeeded { at: request.at },
        ServiceEffectResult::Failed(failure) => OutboxState::Failed {
            at: request.at,
            failure: failure.clone(),
        },
    };
    let completed = match effect {
        ServiceEffectSnapshot::Call(_) => {
            let record = state
                .outbox
                .get_mut(&request.effect_id)
                .ok_or(RepositoryError::NotFound)?;
            record.state = completed_state;
            CompletedServiceEffect::Call(record.clone())
        }
        ServiceEffectSnapshot::Control(_) => {
            let record = state
                .control_outbox
                .get_mut(&request.effect_id)
                .ok_or(RepositoryError::NotFound)?;
            record.state = completed_state;
            record.claimed_at = None;
            CompletedServiceEffect::Control(record.clone())
        }
    };
    let view = EffectResultView {
        effect: completed,
        external_reference,
        released_provider_events,
        follow_up,
    };
    state.reconciliation_results.insert(
        request.effect_id,
        StoredReconciliationResult {
            request,
            view: view.clone(),
        },
    );
    Ok(EffectResultOutcome::Reconciled(view))
}

fn validate_effect_follow_up(
    intent: &EffectIntent,
    result: &ServiceEffectResult,
    command: &CallCommand,
) -> Result<(), RepositoryError> {
    let valid = match (intent, result, command) {
        (
            EffectIntent::StartLeg {
                leg_id,
                binding_generation,
                ..
            },
            ServiceEffectResult::Succeeded,
            CallCommand::SetLegState {
                leg_id: command_leg,
                binding_generation: command_generation,
                state: LegState::Signaling | LegState::Connected,
                failure: None,
                ..
            },
        ) => leg_id == command_leg && binding_generation == command_generation,
        (
            EffectIntent::StartLeg {
                leg_id,
                binding_generation,
                ..
            }
            | EffectIntent::StopLeg {
                leg_id,
                binding_generation,
                ..
            },
            ServiceEffectResult::Failed(expected),
            CallCommand::SetLegState {
                leg_id: command_leg,
                binding_generation: command_generation,
                state: LegState::Failed,
                failure: Some(actual),
                ..
            },
        ) => {
            leg_id == command_leg && binding_generation == command_generation && expected == actual
        }
        (
            EffectIntent::StopLeg {
                leg_id,
                binding_generation,
                ..
            },
            ServiceEffectResult::Succeeded,
            CallCommand::SetLegState {
                leg_id: command_leg,
                binding_generation: command_generation,
                state: LegState::Ended,
                failure: None,
                ..
            },
        ) => leg_id == command_leg && binding_generation == command_generation,
        (
            EffectIntent::ExecuteTransfer {
                deadline_generation,
            },
            ServiceEffectResult::Succeeded,
            CallCommand::FinishTransfer {
                deadline_generation: command_generation,
                result: TransferResult::Completed,
                ..
            },
        ) => deadline_generation == command_generation,
        (
            EffectIntent::ExecuteTransfer {
                deadline_generation,
            },
            ServiceEffectResult::Failed(expected),
            CallCommand::FinishTransfer {
                deadline_generation: command_generation,
                result: TransferResult::Rejected(actual),
                ..
            },
        ) => deadline_generation == command_generation && expected == actual,
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(RepositoryError::InvalidInput(
            "effect follow-up does not match claimed intent or result",
        ))
    }
}

fn validate_control_effect_target(
    call: &StoredCall,
    record: &ControlOutboxRecord,
) -> Result<(), RepositoryError> {
    let leg = call
        .aggregate
        .leg(record.leg_id)
        .filter(|leg| {
            leg.binding_generation() == record.binding_generation
                && matches!(leg.state(), LegState::Connected | LegState::Held)
        })
        .ok_or(RepositoryError::StaleClaim)?;
    let binding = call
        .bindings
        .get(&record.leg_id)
        .filter(|binding| {
            binding.leg_id == leg.id() && binding.binding_generation == record.binding_generation
        })
        .ok_or(RepositoryError::StaleClaim)?;
    if record.available_at < binding.bound_at || call.assignment.released_at.is_some() {
        return Err(RepositoryError::StaleClaim);
    }
    Ok(())
}

fn validate_effect_claim(
    state: &OutboxState,
    worker: WorkerLease,
    claim_generation: ClaimGeneration,
    at: DateTime<Utc>,
) -> Result<(), RepositoryError> {
    match state {
        OutboxState::Claimed {
            worker: owner,
            generation,
            expires_at,
        } if *owner == worker && *generation == claim_generation && *expires_at > at => Ok(()),
        _ => Err(RepositoryError::StaleClaim),
    }
}

fn validate_external_reference_effect(
    record: &OutboxRecord,
    binding: &ExternalReferenceBinding,
) -> Result<(), RepositoryError> {
    match record.intent {
        EffectIntent::StartLeg {
            leg_id,
            binding_generation,
            ..
        } if leg_id == binding.leg_id && binding_generation == binding.binding_generation => Ok(()),
        _ => Err(RepositoryError::InvalidInput(
            "external reference does not match a start-leg effect",
        )),
    }
}

fn store_external_reference_in_state(
    state: &mut MemoryState,
    request: &EffectResultReconciliation,
    binding: ExternalReferenceBinding,
) -> Result<(StoredExternalReference, Vec<ProviderEventEnvelope>), RepositoryError> {
    validate_external_reference_plan(state, request.call_id, binding.leg_id, &binding.value)?;
    let call = state
        .calls
        .get(&request.call_id)
        .filter(|call| call.aggregate.tenant_id() == &request.tenant_id)
        .ok_or(RepositoryError::NotFound)?;
    let leg = call
        .aggregate
        .leg(binding.leg_id)
        .ok_or(RepositoryError::NotFound)?;
    if leg.binding_generation() != binding.binding_generation {
        return Err(RepositoryError::StaleClaim);
    }
    let binding_key = (request.call_id, binding.leg_id, binding.binding_generation);
    let reference_key = external_reference_key(&binding.value);
    if state.external_references.contains_key(&reference_key)
        || state.external_reference_bindings.contains_key(&binding_key)
    {
        return Err(RepositoryError::ProviderReferenceConflict);
    }
    let stored = StoredExternalReference {
        tenant_id: request.tenant_id.clone(),
        call_id: request.call_id,
        leg_id: binding.leg_id,
        binding_generation: binding.binding_generation,
        effect_id: request.effect_id,
        value: binding.value.clone(),
        bound_at: request.at,
    };
    state
        .external_reference_bindings
        .insert(binding_key, reference_key.clone());
    state
        .external_references
        .insert(reference_key, stored.clone());

    let released = match binding.value {
        ExternalReferenceValue::ProviderCall {
            account,
            provider_call_id,
        } => bind_provider_reference_in_state(
            state,
            BindProviderReference {
                tenant_id: request.tenant_id.clone(),
                call_id: request.call_id,
                leg_id: binding.leg_id,
                account,
                provider_call_id,
                worker: request.worker,
                at: request.at,
            },
        )?,
        ExternalReferenceValue::Signaling { .. } => Vec::new(),
    };
    Ok((stored, released))
}

fn validate_external_reference_plan(
    state: &MemoryState,
    call_id: CallId,
    leg_id: LegId,
    value: &ExternalReferenceValue,
) -> Result<(), RepositoryError> {
    let plan = state
        .execution_plans
        .get(&call_id)
        .ok_or(RepositoryError::NotFound)?;
    let spec = plan
        .legs
        .iter()
        .find(|spec| spec.leg_id == leg_id)
        .ok_or(RepositoryError::ProviderReferenceConflict)?;
    match (&spec.endpoint, value) {
        (
            crate::call_service::LegEndpointConfig::Provider(config),
            ExternalReferenceValue::ProviderCall { account, .. },
        ) if account.as_str() == config.account_profile => Ok(()),
        (
            crate::call_service::LegEndpointConfig::Provider(_),
            ExternalReferenceValue::ProviderCall { .. },
        )
        | (
            crate::call_service::LegEndpointConfig::Provider(_),
            ExternalReferenceValue::Signaling { .. },
        )
        | (_, ExternalReferenceValue::ProviderCall { .. }) => {
            Err(RepositoryError::ProviderReferenceConflict)
        }
        (_, ExternalReferenceValue::Signaling { .. }) => Ok(()),
    }
}

fn external_reference_key(value: &ExternalReferenceValue) -> ExternalReferenceKey {
    match value {
        ExternalReferenceValue::ProviderCall {
            account,
            provider_call_id,
        } => ExternalReferenceKey::Provider(account.clone(), provider_call_id.clone()),
        ExternalReferenceValue::Signaling { namespace, value } => {
            ExternalReferenceKey::Signaling(namespace.clone(), value.clone())
        }
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

fn reject_service_managed_call(
    state: &MemoryState,
    tenant_id: &TenantId,
    call_id: CallId,
    worker: WorkerLease,
) -> Result<(), RepositoryError> {
    if state.execution_plans.contains_key(&call_id) {
        ensure_call_worker(state, tenant_id, call_id, worker)?;
        Err(RepositoryError::InvalidInput(
            "service-managed call requires service repository transaction",
        ))
    } else {
        Ok(())
    }
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

fn ensure_terminal_call_worker(
    state: &MemoryState,
    target: &ProviderEventTarget,
    worker: WorkerLease,
) -> Result<(), RepositoryError> {
    ensure_worker(state, worker, true)?;
    let call = state
        .calls
        .get(&target.call_id)
        .filter(|call| call.aggregate.tenant_id() == &target.tenant_id)
        .ok_or(RepositoryError::NotFound)?;
    if call.assignment.lease != worker {
        return Err(RepositoryError::StaleWorkerFence);
    }
    if call.assignment.released_at.is_none() || !call.aggregate.state().is_terminal() {
        return Err(RepositoryError::InvalidInput(
            "terminal provider acknowledgement requires a released terminal call",
        ));
    }
    if call.aggregate.leg(target.leg_id).is_none() {
        return Err(RepositoryError::ProviderReferenceConflict);
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

fn bind_provider_reference_in_state(
    state: &mut MemoryState,
    request: BindProviderReference,
) -> Result<Vec<ProviderEventEnvelope>, RepositoryError> {
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
            && !matches!(event.state, ProviderEventState::Applied)
        {
            if matches!(event.state, ProviderEventState::PendingReference) {
                event.target = Some(target.clone());
                event.state = ProviderEventState::Ready;
            }
            ready.push(event.clone());
        }
    }
    ready.sort_by_key(|event| event.receipt_sequence);
    Ok(ready)
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
            expected_principal: issue.expected_principal,
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

fn create_call_in_state(
    state: &mut MemoryState,
    request: CreateCall,
) -> Result<CreateCallOutcome, RepositoryError> {
    validate_command_timestamp(&request.command, request.at)?;
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

    if state.commands.contains_key(&request.command_id)
        || state.control_commands.contains_key(&request.command_id)
        || state
            .outbound_binding_results
            .contains_key(&request.command_id)
    {
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
    state.commands.insert(request.command_id, command.clone());
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
    state.idempotency.insert(
        idempotency_key,
        IdempotencyRow {
            request_digest: request.request_digest,
            call_id,
            expires_at,
        },
    );
    state.command_results.insert(
        request.command_id,
        CommandCommitView {
            command,
            call: stored.clone(),
            outbox: outbox.clone(),
        },
    );
    Ok(CreateCallOutcome::Created(stored))
}

fn commit_command_in_state(
    state: &mut MemoryState,
    request: CommandCommit,
) -> Result<CommandCommitOutcome, RepositoryError> {
    validate_command_timestamp(&request.command, request.at)?;
    if command_id_conflicts_with_service_namespace(state, request.command_id) {
        return Err(RepositoryError::CommandConflict);
    }
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
    if disposition == CommandDisposition::Applied {
        retire_inactive_bindings(state, request.call_id, &aggregate)?;
    }
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
    let view = CommandCommitView {
        command,
        call,
        outbox,
    };
    state
        .command_results
        .insert(request.command_id, view.clone());
    Ok(CommandCommitOutcome::Committed(view))
}

fn command_id_conflicts_with_service_namespace(state: &MemoryState, command_id: CommandId) -> bool {
    state.control_commands.contains_key(&command_id)
        || state.outbound_binding_results.contains_key(&command_id)
}

fn retire_inactive_bindings(
    state: &mut MemoryState,
    call_id: CallId,
    next: &CallAggregate,
) -> Result<(), RepositoryError> {
    for record in state.control_outbox.values_mut().filter(|record| {
        record.call_id == call_id
            && control_outbox_is_unfinished(record)
            && next.leg(record.leg_id).is_none_or(|leg| {
                leg.binding_generation() != record.binding_generation
                    || !matches!(leg.state(), LegState::Connected | LegState::Held)
            })
    }) {
        record.state = OutboxState::Failed {
            at: next.updated_at(),
            failure: FailureDetails::sanitized(
                "binding_retired",
                "control target binding retired",
                false,
            ),
        };
        record.claimed_at = None;
    }

    let retired = state
        .calls
        .get(&call_id)
        .ok_or(RepositoryError::NotFound)?
        .bindings
        .iter()
        .filter(|(leg_id, binding)| {
            next.leg(**leg_id).is_none_or(|leg| {
                leg.binding_generation() != binding.binding_generation
                    || !matches!(
                        leg.state(),
                        LegState::Signaling
                            | LegState::Connected
                            | LegState::Held
                            | LegState::Ending
                    )
            })
        })
        .map(|(leg_id, binding)| (*leg_id, binding.clone()))
        .collect::<Vec<_>>();

    for (leg_id, binding) in retired {
        let binding_key = (call_id, leg_id, binding.binding_generation);
        let call = state
            .calls
            .get_mut(&call_id)
            .ok_or(RepositoryError::NotFound)?;
        call.bindings.remove(&leg_id);
        if state.connection_owners.get(&binding.connection_id) == Some(&binding_key) {
            state.connection_owners.remove(&binding.connection_id);
        }
        let principal_binding_key = (binding.principal_fingerprint, binding_key);
        if state.principal_bindings.get(&principal_binding_key) == Some(&binding.connection_id) {
            state.principal_bindings.remove(&principal_binding_key);
        }
        for record in state.control_outbox.values_mut().filter(|record| {
            record.call_id == call_id
                && record.leg_id == leg_id
                && record.binding_generation == binding.binding_generation
                && control_outbox_is_unfinished(record)
        }) {
            record.state = OutboxState::Failed {
                at: next.updated_at(),
                failure: FailureDetails::sanitized(
                    "binding_retired",
                    "control target binding retired",
                    false,
                ),
            };
        }
    }
    Ok(())
}

fn provider_event_claimable(
    state: &MemoryState,
    event: &ProviderEventEnvelope,
    worker: WorkerLease,
    at: DateTime<Utc>,
) -> bool {
    let lifecycle_is_claimable = match &event.state {
        ProviderEventState::Ready => true,
        ProviderEventState::Claimed { expires_at, .. } => *expires_at <= at,
        ProviderEventState::PendingReference | ProviderEventState::Applied => false,
    };
    if !lifecycle_is_claimable || event.received_at > at {
        return false;
    }
    let Some(target) = event.target.as_ref() else {
        return false;
    };
    if !state.calls.get(&target.call_id).is_some_and(|call| {
        call.aggregate.tenant_id() == &target.tenant_id && call.assignment.lease == worker
    }) {
        return false;
    }
    !state.provider_events.values().any(|predecessor| {
        predecessor.account == event.account
            && predecessor.provider_call_id == event.provider_call_id
            && predecessor.receipt_sequence < event.receipt_sequence
            && !matches!(predecessor.state, ProviderEventState::Applied)
    })
}

fn validate_provider_command_target(
    target: &ProviderEventTarget,
    command: &CallCommand,
) -> Result<(), RepositoryError> {
    let leg_id = match command {
        CallCommand::SetLegState { leg_id, .. } | CallCommand::RotateLegBinding { leg_id, .. } => {
            Some(*leg_id)
        }
        _ => None,
    };
    if leg_id.is_some_and(|leg_id| leg_id != target.leg_id) {
        Err(RepositoryError::ProviderReferenceConflict)
    } else {
        Ok(())
    }
}

fn has_unfinished_provider_events(state: &MemoryState, call_id: CallId) -> bool {
    state.provider_events.values().any(|event| {
        event
            .target
            .as_ref()
            .is_some_and(|target| target.call_id == call_id)
            && matches!(
                event.state,
                ProviderEventState::Ready | ProviderEventState::Claimed { .. }
            )
    })
}

type OutboxOrderKey = (CallId, AggregateVersion, CommandId, u32, EffectId);

fn outbox_order_key(record: &OutboxRecord) -> OutboxOrderKey {
    (
        record.call_id,
        record.aggregate_version,
        record.command_id,
        record.ordinal,
        record.effect_id,
    )
}

fn outbox_is_unfinished(record: &OutboxRecord) -> bool {
    matches!(
        record.state,
        OutboxState::Ready | OutboxState::Claimed { .. }
    )
}

fn has_unfinished_outbox(state: &MemoryState, call_id: CallId) -> bool {
    state
        .outbox
        .values()
        .any(|record| record.call_id == call_id && outbox_is_unfinished(record))
}

fn control_outbox_is_unfinished(record: &ControlOutboxRecord) -> bool {
    matches!(
        record.state,
        OutboxState::Ready | OutboxState::Claimed { .. }
    )
}

fn has_unfinished_control_outbox(state: &MemoryState, call_id: CallId) -> bool {
    state
        .control_outbox
        .values()
        .any(|record| record.call_id == call_id && control_outbox_is_unfinished(record))
}

fn control_outbox_claimable(
    state: &MemoryState,
    record: &ControlOutboxRecord,
    worker: WorkerLease,
    at: DateTime<Utc>,
) -> bool {
    let individually_claimable = record.worker == worker
        && record.available_at <= at
        && match &record.state {
            OutboxState::Ready => record.claimed_at.is_none(),
            OutboxState::Claimed { expires_at, .. } => {
                record.claimed_at.is_some_and(|claimed_at| claimed_at <= at) && *expires_at <= at
            }
            OutboxState::Succeeded { .. } | OutboxState::Failed { .. } => false,
        }
        && state.calls.get(&record.call_id).is_some_and(|call| {
            call.assignment.lease == worker
                && call.assignment.released_at.is_none()
                && call.aggregate.leg(record.leg_id).is_some_and(|leg| {
                    leg.binding_generation() == record.binding_generation
                        && matches!(leg.state(), LegState::Connected | LegState::Held)
                })
        });
    individually_claimable
        && !state.control_outbox.values().any(|predecessor| {
            predecessor.call_id == record.call_id
                && predecessor.leg_id == record.leg_id
                && predecessor.binding_generation == record.binding_generation
                && predecessor.sequence < record.sequence
                && control_outbox_is_unfinished(predecessor)
        })
}

fn outbox_claimable(
    state: &MemoryState,
    record: &OutboxRecord,
    worker: WorkerLease,
    at: DateTime<Utc>,
) -> bool {
    if record.worker != worker
        || record.available_at > at
        || !match &record.state {
            OutboxState::Ready => true,
            OutboxState::Claimed { expires_at, .. } => *expires_at <= at,
            OutboxState::Succeeded { .. } | OutboxState::Failed { .. } => false,
        }
        || !state
            .calls
            .get(&record.call_id)
            .is_some_and(|call| call.assignment.lease == worker)
    {
        return false;
    }
    let key = outbox_order_key(record);
    !state.outbox.values().any(|predecessor| {
        predecessor.call_id == record.call_id
            && outbox_order_key(predecessor) < key
            && outbox_is_unfinished(predecessor)
    })
}

fn validate_command_timestamp(
    command: &CallCommand,
    at: DateTime<Utc>,
) -> Result<(), RepositoryError> {
    if command.at() == at {
        Ok(())
    } else {
        Err(RepositoryError::InvalidInput(
            "command time must equal repository transaction time",
        ))
    }
}

fn command_view(
    state: &MemoryState,
    command: StoredCommand,
) -> Result<CommandCommitView, RepositoryError> {
    state
        .command_results
        .get(&command.command_id)
        .filter(|result| result.command == command)
        .cloned()
        .ok_or(RepositoryError::Unavailable)
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
    validate_command_timestamp(&request.command, request.at)?;
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

    fn service_principal() -> PrincipalFingerprint {
        PrincipalFingerprint::new(digest(0xa5))
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
            expected_principal: service_principal(),
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

    async fn apply_command(
        repo: &MemoryRepository,
        owner: &TenantId,
        worker: WorkerLease,
        current: &StoredCall,
        command: CallCommand,
    ) -> CommandCommitView {
        let outcome = repo
            .commit_command(CommandCommit {
                tenant_id: owner.clone(),
                call_id: current.aggregate.id(),
                expected_version: current.aggregate.version(),
                command_id: CommandId::new(),
                at: command.at(),
                command,
                worker,
                attachments: Vec::new(),
                deadline_claim: None,
            })
            .await
            .unwrap();
        match outcome {
            CommandCommitOutcome::Committed(view) => view,
            CommandCommitOutcome::Replayed(_) => panic!("fresh command unexpectedly replayed"),
        }
    }

    async fn move_leg(
        repo: &MemoryRepository,
        owner: &TenantId,
        worker: WorkerLease,
        current: &StoredCall,
        leg_index: usize,
        state: LegState,
        second: i64,
    ) -> StoredCall {
        apply_command(
            repo,
            owner,
            worker,
            current,
            CallCommand::SetLegState {
                at: at(second),
                leg_id: current.aggregate.legs()[leg_index].id(),
                binding_generation: current.aggregate.legs()[leg_index].binding_generation(),
                state,
                failure: None,
            },
        )
        .await
        .call
    }

    async fn end_call(
        repo: &MemoryRepository,
        owner: &TenantId,
        worker: WorkerLease,
        mut current: StoredCall,
    ) -> StoredCall {
        current = move_leg(repo, owner, worker, &current, 0, LegState::Signaling, 3).await;
        current = move_leg(repo, owner, worker, &current, 1, LegState::Signaling, 4).await;
        current = move_leg(repo, owner, worker, &current, 0, LegState::Connected, 5).await;
        current = move_leg(repo, owner, worker, &current, 1, LegState::Connected, 6).await;
        current = apply_command(
            repo,
            owner,
            worker,
            &current,
            CallCommand::BeginEnding {
                at: at(7),
                ending_deadline: Some(at(17)),
                reason: StopLegReason::Requested,
            },
        )
        .await
        .call;
        current = move_leg(repo, owner, worker, &current, 0, LegState::Ended, 8).await;
        move_leg(repo, owner, worker, &current, 1, LegState::Ended, 9).await
    }

    async fn drain_outbox(repo: &MemoryRepository, worker: WorkerLease, now: DateTime<Utc>) {
        loop {
            let claimed = repo
                .claim_outbox(worker, now, Duration::from_secs(5), 1)
                .await
                .unwrap();
            let Some(claimed) = claimed.into_iter().next() else {
                break;
            };
            repo.complete_outbox(
                claimed.record.effect_id,
                worker,
                claimed.claim_generation,
                OutboxCompletion::Succeeded,
                now,
            )
            .await
            .unwrap();
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
            expected_principal: service_principal(),
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
            expected_principal: service_principal(),
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
    async fn command_replay_returns_its_original_result_after_later_commands() {
        let repo = MemoryRepository::new();
        let worker = worker(&repo, 2).await;
        let owner = tenant("tenant-a");
        let created = created(
            repo.create_call(create_request(
                new_call(owner.clone()),
                worker.lease,
                140,
                141,
            ))
            .await
            .unwrap(),
        );
        let command_a = CommandCommit {
            tenant_id: owner.clone(),
            call_id: created.aggregate.id(),
            expected_version: created.aggregate.version(),
            command_id: CommandId::new(),
            command: CallCommand::SetLegState {
                at: at(3),
                leg_id: created.aggregate.legs()[0].id(),
                binding_generation: created.aggregate.legs()[0].binding_generation(),
                state: LegState::Signaling,
                failure: None,
            },
            worker: worker.lease,
            attachments: Vec::new(),
            deadline_claim: None,
            at: at(3),
        };
        let CommandCommitOutcome::Committed(result_a) =
            repo.commit_command(command_a.clone()).await.unwrap()
        else {
            unreachable!()
        };
        let result_b = move_leg(
            &repo,
            &owner,
            worker.lease,
            &result_a.call,
            1,
            LegState::Signaling,
            4,
        )
        .await;
        assert!(result_b.aggregate.version() > result_a.call.aggregate.version());

        let CommandCommitOutcome::Replayed(replayed_a) =
            repo.commit_command(command_a).await.unwrap()
        else {
            unreachable!()
        };
        assert_eq!(replayed_a, result_a);
        assert!(replayed_a.call.aggregate.version() < result_b.aggregate.version());
    }

    #[tokio::test]
    async fn repository_rejects_create_command_and_attachment_time_skew_atomically() {
        let repo = MemoryRepository::new();
        let worker = worker(&repo, 2).await;
        let owner = tenant("tenant-a");
        let mut skewed_create = create_request(new_call(owner.clone()), worker.lease, 142, 143);
        skewed_create.at = at(3);
        assert_eq!(
            repo.create_call(skewed_create).await,
            Err(RepositoryError::InvalidInput(
                "command time must equal repository transaction time"
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

        let request = create_request(new_call(owner.clone()), worker.lease, 144, 145);
        let token = request.attachments[0].token_digest;
        let call = created(repo.create_call(request).await.unwrap());
        let skewed_command = CommandCommit {
            tenant_id: owner.clone(),
            call_id: call.aggregate.id(),
            expected_version: call.aggregate.version(),
            command_id: CommandId::new(),
            command: CallCommand::SetLegState {
                at: at(4),
                leg_id: call.aggregate.legs()[1].id(),
                binding_generation: call.aggregate.legs()[1].binding_generation(),
                state: LegState::Signaling,
                failure: None,
            },
            worker: worker.lease,
            attachments: Vec::new(),
            deadline_claim: None,
            at: at(3),
        };
        assert_eq!(
            repo.commit_command(skewed_command).await,
            Err(RepositoryError::InvalidInput(
                "command time must equal repository transaction time"
            ))
        );
        assert_eq!(
            repo.load_call(&owner, call.aggregate.id()).await.unwrap(),
            call
        );

        let lookup = AttachmentLookup {
            token_digest: token,
            tenant_id: owner,
            transport: AttachmentTransport::Sip,
            principal_fingerprint: service_principal(),
            worker: worker.lease,
            at: at(3),
        };
        let candidate = repo.inspect_attachment(lookup.clone()).await.unwrap();
        assert_eq!(
            repo.consume_attachment(AttachmentConsume {
                candidate,
                command_id: CommandId::new(),
                command: CallCommand::SetLegState {
                    at: at(4),
                    leg_id: call.aggregate.legs()[0].id(),
                    binding_generation: call.aggregate.legs()[0].binding_generation(),
                    state: LegState::Signaling,
                    failure: None,
                },
                connection_id: ConnectionId::new(),
                principal_fingerprint: service_principal(),
                at: at(5),
            })
            .await,
            Err(RepositoryError::InvalidInput(
                "command time must equal repository transaction time"
            ))
        );
        assert!(repo
            .inspect_attachment(AttachmentLookup {
                at: at(6),
                ..lookup
            })
            .await
            .is_ok());
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
            principal_fingerprint: service_principal(),
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
        assert!(matches!(
            repo.inspect_attachment(AttachmentLookup {
                principal_fingerprint: PrincipalFingerprint::new(digest(72)),
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
                principal_fingerprint: service_principal(),
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

    #[tokio::test]
    async fn stale_attachment_candidate_cannot_overwrite_a_newer_call_version() {
        let repo = MemoryRepository::new();
        let worker = worker(&repo, 2).await;
        let owner = tenant("tenant-a");
        let request = create_request(new_call(owner.clone()), worker.lease, 146, 147);
        let token = request.attachments[0].token_digest;
        let call = created(repo.create_call(request).await.unwrap());
        let lookup = AttachmentLookup {
            token_digest: token,
            tenant_id: owner.clone(),
            transport: AttachmentTransport::Sip,
            principal_fingerprint: service_principal(),
            worker: worker.lease,
            at: at(3),
        };
        let candidate = repo.inspect_attachment(lookup.clone()).await.unwrap();
        let newer = move_leg(
            &repo,
            &owner,
            worker.lease,
            &call,
            1,
            LegState::Signaling,
            4,
        )
        .await;

        assert_eq!(
            repo.consume_attachment(AttachmentConsume {
                command_id: CommandId::new(),
                command: CallCommand::SetLegState {
                    at: at(5),
                    leg_id: candidate.leg_id(),
                    binding_generation: candidate.binding_generation(),
                    state: LegState::Signaling,
                    failure: None,
                },
                candidate,
                connection_id: ConnectionId::new(),
                principal_fingerprint: service_principal(),
                at: at(5),
            })
            .await,
            Err(RepositoryError::VersionConflict)
        );
        assert_eq!(
            repo.load_call(&owner, call.aggregate.id()).await.unwrap(),
            newer
        );
        assert!(repo
            .inspect_attachment(AttachmentLookup {
                at: at(6),
                ..lookup
            })
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn connection_ids_are_unique_while_service_principals_span_calls() {
        let repo = MemoryRepository::new();
        let worker = worker(&repo, 2).await;
        let owner = tenant("tenant-a");
        let mut candidates = Vec::new();
        let mut lookups = Vec::new();
        for (key, request_digest) in [(148, 149), (150, 151)] {
            let request =
                create_request(new_call(owner.clone()), worker.lease, key, request_digest);
            let lookup = AttachmentLookup {
                token_digest: request.attachments[0].token_digest,
                tenant_id: owner.clone(),
                transport: AttachmentTransport::Sip,
                principal_fingerprint: service_principal(),
                worker: worker.lease,
                at: at(3),
            };
            repo.create_call(request).await.unwrap();
            candidates.push(repo.inspect_attachment(lookup.clone()).await.unwrap());
            lookups.push(lookup);
        }
        let shared_connection = ConnectionId::new();
        let first = candidates.remove(0);
        repo.consume_attachment(AttachmentConsume {
            command_id: CommandId::new(),
            command: CallCommand::SetLegState {
                at: at(4),
                leg_id: first.leg_id(),
                binding_generation: first.binding_generation(),
                state: LegState::Signaling,
                failure: None,
            },
            candidate: first,
            connection_id: shared_connection.clone(),
            principal_fingerprint: service_principal(),
            at: at(4),
        })
        .await
        .unwrap();

        let second = candidates.remove(0);
        assert_eq!(
            repo.consume_attachment(AttachmentConsume {
                command_id: CommandId::new(),
                command: CallCommand::SetLegState {
                    at: at(4),
                    leg_id: second.leg_id(),
                    binding_generation: second.binding_generation(),
                    state: LegState::Signaling,
                    failure: None,
                },
                candidate: second.clone(),
                connection_id: shared_connection,
                principal_fingerprint: service_principal(),
                at: at(4),
            })
            .await,
            Err(RepositoryError::AttachmentConflict)
        );
        assert!(repo
            .inspect_attachment(AttachmentLookup {
                at: at(5),
                ..lookups.remove(1)
            })
            .await
            .is_ok());
        assert!(repo
            .consume_attachment(AttachmentConsume {
                command_id: CommandId::new(),
                command: CallCommand::SetLegState {
                    at: at(5),
                    leg_id: second.leg_id(),
                    binding_generation: second.binding_generation(),
                    state: LegState::Signaling,
                    failure: None,
                },
                candidate: second,
                connection_id: ConnectionId::new(),
                principal_fingerprint: service_principal(),
                at: at(5),
            })
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn rotating_a_binding_retires_old_ownership_and_accepts_generation_two() {
        let repo = MemoryRepository::new();
        let worker = worker(&repo, 2).await;
        let owner = tenant("tenant-a");
        let request = create_request(new_call(owner.clone()), worker.lease, 152, 153);
        let initial_token = request.attachments[0].token_digest;
        let created = created(repo.create_call(request).await.unwrap());
        let candidate = repo
            .inspect_attachment(AttachmentLookup {
                token_digest: initial_token,
                tenant_id: owner.clone(),
                transport: AttachmentTransport::Sip,
                principal_fingerprint: service_principal(),
                worker: worker.lease,
                at: at(3),
            })
            .await
            .unwrap();
        let old_generation = candidate.binding_generation();
        let old_connection = ConnectionId::new();
        let connected = repo
            .consume_attachment(AttachmentConsume {
                command_id: CommandId::new(),
                command: CallCommand::SetLegState {
                    at: at(4),
                    leg_id: candidate.leg_id(),
                    binding_generation: old_generation,
                    state: LegState::Signaling,
                    failure: None,
                },
                candidate,
                connection_id: old_connection.clone(),
                principal_fingerprint: service_principal(),
                at: at(4),
            })
            .await
            .unwrap()
            .commit
            .call;
        let leg_id = created.aggregate.legs()[0].id();
        let rotate = CallCommand::RotateLegBinding {
            at: at(5),
            leg_id,
            binding_generation: old_generation,
        };
        let decision = connected.aggregate.decide(rotate.clone()).unwrap();
        let generation_two = decision
            .aggregate()
            .leg(leg_id)
            .unwrap()
            .binding_generation();
        let new_token = AttachmentTokenDigest::new(digest(254));
        let CommandCommitOutcome::Committed(rotated) = repo
            .commit_command(CommandCommit {
                tenant_id: owner.clone(),
                call_id: connected.aggregate.id(),
                expected_version: connected.aggregate.version(),
                command_id: CommandId::new(),
                command: rotate,
                worker: worker.lease,
                attachments: vec![AttachmentIssue {
                    attachment_id: AttachmentId::new(),
                    token_digest: new_token,
                    leg_id,
                    binding_generation: generation_two,
                    transport: AttachmentTransport::Sip,
                    expected_principal: service_principal(),
                    expires_at: at(125),
                }],
                deadline_claim: None,
                at: at(5),
            })
            .await
            .unwrap()
        else {
            unreachable!()
        };
        assert!(!rotated.call.bindings.contains_key(&leg_id));
        repo.read(|state| {
            assert!(!state.connection_owners.contains_key(&old_connection));
            assert!(!state.principal_bindings.contains_key(&(
                service_principal(),
                (created.aggregate.id(), leg_id, old_generation)
            )));
            Ok(())
        })
        .unwrap();

        let candidate = repo
            .inspect_attachment(AttachmentLookup {
                token_digest: new_token,
                tenant_id: owner.clone(),
                transport: AttachmentTransport::Sip,
                principal_fingerprint: service_principal(),
                worker: worker.lease,
                at: at(6),
            })
            .await
            .unwrap();
        assert_eq!(candidate.binding_generation(), generation_two);
        assert_eq!(
            repo.consume_attachment(AttachmentConsume {
                command_id: CommandId::new(),
                command: CallCommand::SetLegState {
                    at: at(7),
                    leg_id,
                    binding_generation: generation_two,
                    state: LegState::Signaling,
                    failure: None,
                },
                candidate: candidate.clone(),
                connection_id: old_connection,
                principal_fingerprint: service_principal(),
                at: at(7),
            })
            .await,
            Err(RepositoryError::AttachmentConflict)
        );
        assert!(repo
            .inspect_attachment(AttachmentLookup {
                token_digest: new_token,
                tenant_id: owner.clone(),
                transport: AttachmentTransport::Sip,
                principal_fingerprint: service_principal(),
                worker: worker.lease,
                at: at(7),
            })
            .await
            .is_ok());
        let new_connection = ConnectionId::new();
        let current = repo
            .consume_attachment(AttachmentConsume {
                command_id: CommandId::new(),
                command: CallCommand::SetLegState {
                    at: at(7),
                    leg_id,
                    binding_generation: generation_two,
                    state: LegState::Signaling,
                    failure: None,
                },
                candidate,
                connection_id: new_connection.clone(),
                principal_fingerprint: service_principal(),
                at: at(7),
            })
            .await
            .unwrap()
            .commit
            .call;
        assert_eq!(
            current.bindings.get(&leg_id).unwrap().connection_id,
            new_connection
        );

        let stale = apply_command(
            &repo,
            &owner,
            worker.lease,
            &current,
            CallCommand::SetLegState {
                at: at(8),
                leg_id,
                binding_generation: old_generation,
                state: LegState::Connected,
                failure: None,
            },
        )
        .await;
        assert_eq!(
            stale.command.disposition,
            CommandDisposition::IgnoredStaleGeneration
        );
        assert_eq!(stale.call, current);
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
                    principal_fingerprint: service_principal(),
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
        for candidate in candidates {
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
                        principal_fingerprint: service_principal(),
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
                    principal_fingerprint: service_principal(),
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
        for (event, received) in [(1u8, 6i64), (2, 5), (3, 5)] {
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
        assert_eq!(ready.len(), 3);
        assert_eq!(ready[0].receipt_sequence, ProviderReceiptSequence::INITIAL);
        assert_eq!(ready[0].received_at, at(6));
        assert_eq!(ready[1].received_at, at(5));
        assert_eq!(ready[2].received_at, at(5));
        assert_eq!(ready[0].event_digest, ProviderEventDigest::new(digest(1)));
        assert_eq!(ready[1].event_digest, ProviderEventDigest::new(digest(2)));
        assert_eq!(ready[2].event_digest, ProviderEventDigest::new(digest(3)));
        assert!(ready
            .windows(2)
            .all(|events| events[0].receipt_sequence < events[1].receipt_sequence));
        assert!(ready
            .iter()
            .all(|event| event.state == ProviderEventState::Ready));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn provider_claims_are_exclusive_expiring_and_atomically_applied() {
        let repo = Arc::new(MemoryRepository::new());
        let worker = worker(&repo, 2).await;
        let owner = tenant("tenant-a");
        let call = created(
            repo.create_call(create_request(
                new_call(owner.clone()),
                worker.lease,
                154,
                155,
            ))
            .await
            .unwrap(),
        );
        let account = ProviderAccountKey::parse("telnyx-account").unwrap();
        let provider_call_id = ProviderCallId::parse("provider-call-claims").unwrap();
        let event_digest = ProviderEventDigest::new(digest(156));
        repo.ingest_provider_event(ProviderEventInput {
            account: account.clone(),
            event_digest,
            payload_digest: crate::call_engine::ProviderPayloadDigest::new(digest(157)),
            provider_call_id: provider_call_id.clone(),
            kind: "answered".into(),
            payload: json!({"state": "answered"}),
            occurred_at: Some(at(7)),
            received_at: at(8),
        })
        .await
        .unwrap();
        repo.bind_provider_reference(BindProviderReference {
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

        let mut tasks = Vec::new();
        for _ in 0..2 {
            let repo = Arc::clone(&repo);
            tasks.push(tokio::spawn(async move {
                repo.claim_provider_events(worker.lease, at(9), Duration::from_secs(5), 1)
                    .await
                    .unwrap()
            }));
        }
        let mut claims = Vec::new();
        for task in tasks {
            claims.extend(task.await.unwrap());
        }
        assert_eq!(claims.len(), 1);
        let first_claim = claims.remove(0);

        let invalid_command = CommandCommit {
            tenant_id: owner.clone(),
            call_id: call.aggregate.id(),
            expected_version: AggregateVersion::default(),
            command_id: CommandId::new(),
            command: CallCommand::SetLegState {
                at: at(10),
                leg_id: call.aggregate.legs()[1].id(),
                binding_generation: call.aggregate.legs()[1].binding_generation(),
                state: LegState::Signaling,
                failure: None,
            },
            worker: worker.lease,
            attachments: Vec::new(),
            deadline_claim: None,
            at: at(10),
        };
        assert_eq!(
            repo.complete_provider_event(ProviderEventCommit {
                account: account.clone(),
                event_digest,
                claim_generation: first_claim.claim_generation,
                worker: worker.lease,
                command: invalid_command,
                at: at(10),
            })
            .await,
            Err(RepositoryError::VersionConflict)
        );
        assert!(repo
            .claim_provider_events(worker.lease, at(13), Duration::from_secs(5), 1)
            .await
            .unwrap()
            .is_empty());
        let reclaimed = repo
            .claim_provider_events(worker.lease, at(14), Duration::from_secs(5), 1)
            .await
            .unwrap();
        assert_eq!(reclaimed.len(), 1);
        assert!(reclaimed[0].claim_generation > first_claim.claim_generation);

        let stale_command = CommandCommit {
            tenant_id: owner.clone(),
            call_id: call.aggregate.id(),
            expected_version: call.aggregate.version(),
            command_id: CommandId::new(),
            command: CallCommand::SetLegState {
                at: at(15),
                leg_id: call.aggregate.legs()[1].id(),
                binding_generation: call.aggregate.legs()[1].binding_generation(),
                state: LegState::Signaling,
                failure: None,
            },
            worker: worker.lease,
            attachments: Vec::new(),
            deadline_claim: None,
            at: at(15),
        };
        assert_eq!(
            repo.complete_provider_event(ProviderEventCommit {
                account: account.clone(),
                event_digest,
                claim_generation: first_claim.claim_generation,
                worker: worker.lease,
                command: stale_command,
                at: at(15),
            })
            .await,
            Err(RepositoryError::StaleClaim)
        );

        let command = CommandCommit {
            tenant_id: owner.clone(),
            call_id: call.aggregate.id(),
            expected_version: call.aggregate.version(),
            command_id: CommandId::new(),
            command: CallCommand::SetLegState {
                at: at(16),
                leg_id: call.aggregate.legs()[1].id(),
                binding_generation: call.aggregate.legs()[1].binding_generation(),
                state: LegState::Signaling,
                failure: None,
            },
            worker: worker.lease,
            attachments: Vec::new(),
            deadline_claim: None,
            at: at(16),
        };
        let completed = repo
            .complete_provider_event(ProviderEventCommit {
                account,
                event_digest,
                claim_generation: reclaimed[0].claim_generation,
                worker: worker.lease,
                command,
                at: at(16),
            })
            .await
            .unwrap();
        assert_eq!(completed.event.state, ProviderEventState::Applied);
        assert_eq!(completed.event.applied_at, Some(at(16)));
        assert!(matches!(
            completed.command,
            CommandCommitOutcome::Committed(_)
        ));
        assert_eq!(
            repo.load_call(&owner, call.aggregate.id())
                .await
                .unwrap()
                .aggregate
                .leg(call.aggregate.legs()[1].id())
                .unwrap()
                .state(),
            LegState::Signaling
        );
    }

    #[tokio::test]
    async fn provider_completion_is_time_leg_and_exact_replay_bound_with_rollback() {
        let repo = MemoryRepository::new();
        let worker = worker(&repo, 2).await;
        let owner = tenant("tenant-a");
        let call = created(
            repo.create_call(create_request(
                new_call(owner.clone()),
                worker.lease,
                164,
                165,
            ))
            .await
            .unwrap(),
        );
        let account = ProviderAccountKey::parse("telnyx-replay-account").unwrap();
        let provider_call_id = ProviderCallId::parse("provider-call-replay").unwrap();
        let event_digest = ProviderEventDigest::new(digest(166));
        let target_leg = call.aggregate.legs()[1].id();
        repo.ingest_provider_event(ProviderEventInput {
            account: account.clone(),
            event_digest,
            payload_digest: crate::call_engine::ProviderPayloadDigest::new(digest(167)),
            provider_call_id: provider_call_id.clone(),
            kind: "answered".into(),
            payload: json!({"state": "answered"}),
            occurred_at: None,
            received_at: at(8),
        })
        .await
        .unwrap();
        repo.bind_provider_reference(BindProviderReference {
            tenant_id: owner.clone(),
            call_id: call.aggregate.id(),
            leg_id: target_leg,
            account: account.clone(),
            provider_call_id,
            worker: worker.lease,
            at: at(8),
        })
        .await
        .unwrap();
        let claim = repo
            .claim_provider_events(worker.lease, at(9), Duration::from_secs(5), 1)
            .await
            .unwrap()
            .remove(0);

        let backdated_command = CommandCommit {
            tenant_id: owner.clone(),
            call_id: call.aggregate.id(),
            expected_version: call.aggregate.version(),
            command_id: CommandId::new(),
            command: CallCommand::SetLegState {
                at: at(7),
                leg_id: target_leg,
                binding_generation: call.aggregate.legs()[1].binding_generation(),
                state: LegState::Signaling,
                failure: None,
            },
            worker: worker.lease,
            attachments: Vec::new(),
            deadline_claim: None,
            at: at(7),
        };
        assert_eq!(
            repo.complete_provider_event(ProviderEventCommit {
                account: account.clone(),
                event_digest,
                claim_generation: claim.claim_generation,
                worker: worker.lease,
                command: backdated_command,
                at: at(7),
            })
            .await,
            Err(RepositoryError::StaleClaim)
        );
        assert_eq!(
            repo.load_call(&owner, call.aggregate.id()).await.unwrap(),
            call
        );

        let wrong_leg_command = CommandCommit {
            tenant_id: owner.clone(),
            call_id: call.aggregate.id(),
            expected_version: call.aggregate.version(),
            command_id: CommandId::new(),
            command: CallCommand::SetLegState {
                at: at(10),
                leg_id: call.aggregate.legs()[0].id(),
                binding_generation: call.aggregate.legs()[0].binding_generation(),
                state: LegState::Signaling,
                failure: None,
            },
            worker: worker.lease,
            attachments: Vec::new(),
            deadline_claim: None,
            at: at(10),
        };
        assert_eq!(
            repo.complete_provider_event(ProviderEventCommit {
                account: account.clone(),
                event_digest,
                claim_generation: claim.claim_generation,
                worker: worker.lease,
                command: wrong_leg_command,
                at: at(10),
            })
            .await,
            Err(RepositoryError::ProviderReferenceConflict)
        );
        assert_eq!(
            repo.load_call(&owner, call.aggregate.id()).await.unwrap(),
            call
        );

        let command_id = CommandId::new();
        let command = CommandCommit {
            tenant_id: owner.clone(),
            call_id: call.aggregate.id(),
            expected_version: call.aggregate.version(),
            command_id,
            command: CallCommand::SetLegState {
                at: at(10),
                leg_id: target_leg,
                binding_generation: call.aggregate.legs()[1].binding_generation(),
                state: LegState::Signaling,
                failure: None,
            },
            worker: worker.lease,
            attachments: Vec::new(),
            deadline_claim: None,
            at: at(10),
        };
        let completion = ProviderEventCommit {
            account: account.clone(),
            event_digest,
            claim_generation: claim.claim_generation,
            worker: worker.lease,
            command,
            at: at(10),
        };
        let first = repo
            .complete_provider_event(completion.clone())
            .await
            .unwrap();
        assert!(matches!(first.command, CommandCommitOutcome::Committed(_)));
        let replay = repo
            .complete_provider_event(completion.clone())
            .await
            .unwrap();
        assert!(matches!(replay.command, CommandCommitOutcome::Replayed(_)));
        assert_eq!(replay.event, first.event);

        let mut mismatched = completion;
        mismatched.at = at(11);
        mismatched.command.at = at(11);
        mismatched.command.command = CallCommand::SetLegState {
            at: at(11),
            leg_id: target_leg,
            binding_generation: call.aggregate.legs()[1].binding_generation(),
            state: LegState::Signaling,
            failure: None,
        };
        assert_eq!(
            repo.complete_provider_event(mismatched).await,
            Err(RepositoryError::StaleClaim)
        );
    }

    #[tokio::test]
    async fn provider_claims_recover_on_worker_restart_and_reject_stale_fences() {
        let repo = MemoryRepository::new();
        let worker = worker(&repo, 2).await;
        let owner = tenant("tenant-a");
        let call = created(
            repo.create_call(create_request(
                new_call(owner.clone()),
                worker.lease,
                158,
                159,
            ))
            .await
            .unwrap(),
        );
        let account = ProviderAccountKey::parse("vonage-account").unwrap();
        let provider_call_id = ProviderCallId::parse("provider-call-restart").unwrap();
        let event_digest = ProviderEventDigest::new(digest(160));
        repo.ingest_provider_event(ProviderEventInput {
            account: account.clone(),
            event_digest,
            payload_digest: crate::call_engine::ProviderPayloadDigest::new(digest(161)),
            provider_call_id: provider_call_id.clone(),
            kind: "answered".into(),
            payload: json!({"state": "answered"}),
            occurred_at: None,
            received_at: at(8),
        })
        .await
        .unwrap();
        repo.bind_provider_reference(BindProviderReference {
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
        let old_claim = repo
            .claim_provider_events(worker.lease, at(9), Duration::from_secs(30), 1)
            .await
            .unwrap()
            .remove(0);
        let newer = repo
            .register_worker(RegisterWorker {
                worker_id: worker.lease.worker_id,
                max_calls: 2,
                capabilities: BTreeSet::from(["sip".into()]),
                at: at(10),
            })
            .await
            .unwrap();
        assert_eq!(
            repo.claim_restart_calls(newer.lease, at(11), 1)
                .await
                .unwrap()
                .len(),
            1
        );
        let stale_command = CommandCommit {
            tenant_id: owner.clone(),
            call_id: call.aggregate.id(),
            expected_version: call.aggregate.version(),
            command_id: CommandId::new(),
            command: CallCommand::SetLegState {
                at: at(12),
                leg_id: call.aggregate.legs()[1].id(),
                binding_generation: call.aggregate.legs()[1].binding_generation(),
                state: LegState::Signaling,
                failure: None,
            },
            worker: worker.lease,
            attachments: Vec::new(),
            deadline_claim: None,
            at: at(12),
        };
        assert_eq!(
            repo.complete_provider_event(ProviderEventCommit {
                account: account.clone(),
                event_digest,
                claim_generation: old_claim.claim_generation,
                worker: worker.lease,
                command: stale_command,
                at: at(12),
            })
            .await,
            Err(RepositoryError::StaleWorkerFence)
        );

        let recovered = repo
            .claim_provider_events(newer.lease, at(12), Duration::from_secs(5), 1)
            .await
            .unwrap();
        assert_eq!(recovered.len(), 1);
        let command = CommandCommit {
            tenant_id: owner.clone(),
            call_id: call.aggregate.id(),
            expected_version: call.aggregate.version(),
            command_id: CommandId::new(),
            command: CallCommand::SetLegState {
                at: at(13),
                leg_id: call.aggregate.legs()[1].id(),
                binding_generation: call.aggregate.legs()[1].binding_generation(),
                state: LegState::Signaling,
                failure: None,
            },
            worker: newer.lease,
            attachments: Vec::new(),
            deadline_claim: None,
            at: at(13),
        };
        let completed = repo
            .complete_provider_event(ProviderEventCommit {
                account,
                event_digest,
                claim_generation: recovered[0].claim_generation,
                worker: newer.lease,
                command,
                at: at(13),
            })
            .await
            .unwrap();
        assert_eq!(completed.event.state, ProviderEventState::Applied);
    }

    #[tokio::test]
    async fn terminal_provider_acknowledgement_recovers_without_outbox_or_capacity() {
        let repo = MemoryRepository::new();
        let worker = worker(&repo, 1).await;
        let owner = tenant("tenant-a");
        let call = created(
            repo.create_call(create_request(
                new_call(owner.clone()),
                worker.lease,
                168,
                169,
            ))
            .await
            .unwrap(),
        );
        let account = ProviderAccountKey::parse("vonage-terminal-account").unwrap();
        let provider_call_id = ProviderCallId::parse("provider-call-terminal").unwrap();
        let target = ProviderEventTarget {
            tenant_id: owner.clone(),
            call_id: call.aggregate.id(),
            leg_id: call.aggregate.legs()[1].id(),
        };
        repo.bind_provider_reference(BindProviderReference {
            tenant_id: owner.clone(),
            call_id: call.aggregate.id(),
            leg_id: target.leg_id,
            account: account.clone(),
            provider_call_id: provider_call_id.clone(),
            worker: worker.lease,
            at: at(2),
        })
        .await
        .unwrap();
        let terminal = end_call(&repo, &owner, worker.lease, call).await;
        assert!(terminal.aggregate.state().is_terminal());
        assert!(terminal.assignment.released_at.is_some());
        drain_outbox(&repo, worker.lease, at(10)).await;
        assert!(!repo
            .read(|state| Ok(has_unfinished_outbox(state, terminal.aggregate.id())))
            .unwrap());

        let event_digest = ProviderEventDigest::new(digest(170));
        repo.ingest_provider_event(ProviderEventInput {
            account: account.clone(),
            event_digest,
            payload_digest: crate::call_engine::ProviderPayloadDigest::new(digest(171)),
            provider_call_id,
            kind: "hangup".into(),
            payload: json!({"state": "completed"}),
            occurred_at: Some(at(10)),
            received_at: at(11),
        })
        .await
        .unwrap();

        let newer = repo
            .register_worker(RegisterWorker {
                worker_id: worker.lease.worker_id,
                max_calls: 1,
                capabilities: BTreeSet::from(["sip".into()]),
                at: at(12),
            })
            .await
            .unwrap();
        let recovered = repo
            .claim_restart_calls(newer.lease, at(13), 1)
            .await
            .unwrap();
        assert_eq!(recovered.len(), 1);
        assert!(recovered[0].call.assignment.released_at.is_some());
        assert_eq!(
            repo.worker_snapshot(newer.lease.worker_id)
                .await
                .unwrap()
                .reserved_calls,
            0
        );
        let claim = repo
            .claim_provider_events(newer.lease, at(14), Duration::from_secs(5), 1)
            .await
            .unwrap()
            .remove(0);
        let acknowledgement = TerminalProviderEventAcknowledge {
            account,
            event_digest,
            claim_generation: claim.claim_generation,
            worker: newer.lease,
            target,
            at: at(15),
        };
        let first = repo
            .acknowledge_terminal_provider_event(acknowledgement.clone())
            .await
            .unwrap();
        assert!(matches!(
            first,
            TerminalProviderEventAcknowledgeOutcome::Acknowledged(_)
        ));
        let replay = repo
            .acknowledge_terminal_provider_event(acknowledgement.clone())
            .await
            .unwrap();
        assert!(matches!(
            replay,
            TerminalProviderEventAcknowledgeOutcome::Replayed(_)
        ));
        let mut mismatch = acknowledgement;
        mismatch.at = at(16);
        assert_eq!(
            repo.acknowledge_terminal_provider_event(mismatch).await,
            Err(RepositoryError::StaleClaim)
        );
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
    async fn concurrent_outbox_claimers_preserve_predecessor_order() {
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
                repo.claim_outbox(worker.lease, at(3), Duration::from_secs(10), 1)
                    .await
                    .unwrap()
            }));
        }
        let mut effect_ids = BTreeSet::new();
        let mut claims = Vec::new();
        for task in tasks {
            for claim in task.await.unwrap() {
                assert!(effect_ids.insert(claim.record.effect_id));
                claims.push(claim);
            }
        }
        assert_eq!(claims.len(), 1);
        let first = claims.remove(0);
        repo.complete_outbox(
            first.record.effect_id,
            worker.lease,
            first.claim_generation,
            OutboxCompletion::Succeeded,
            at(4),
        )
        .await
        .unwrap();
        let next = repo
            .claim_outbox(worker.lease, at(5), Duration::from_secs(10), 1)
            .await
            .unwrap();
        assert_eq!(next.len(), 1);
        assert!(outbox_order_key(&first.record) < outbox_order_key(&next[0].record));
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
    async fn restart_migrates_terminal_cleanup_without_reserving_capacity_again() {
        let repo = MemoryRepository::new();
        let worker = worker(&repo, 1).await;
        let owner = tenant("tenant-a");
        let call = created(
            repo.create_call(create_request(
                new_call(owner.clone()),
                worker.lease,
                162,
                163,
            ))
            .await
            .unwrap(),
        );
        let terminal = end_call(&repo, &owner, worker.lease, call).await;
        assert_eq!(terminal.aggregate.state(), CallState::Ended);
        assert!(terminal.assignment.released_at.is_some());
        assert_eq!(
            repo.worker_snapshot(worker.lease.worker_id)
                .await
                .unwrap()
                .reserved_calls,
            0
        );
        assert!(repo
            .read(|state| Ok(has_unfinished_outbox(state, terminal.aggregate.id())))
            .unwrap());

        let newer = repo
            .register_worker(RegisterWorker {
                worker_id: worker.lease.worker_id,
                max_calls: 1,
                capabilities: BTreeSet::from(["sip".into()]),
                at: at(10),
            })
            .await
            .unwrap();
        let recovered = repo
            .claim_restart_calls(newer.lease, at(11), 1)
            .await
            .unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].call.aggregate.state(), CallState::Ended);
        assert!(recovered[0].call.assignment.released_at.is_some());
        assert_eq!(recovered[0].call.assignment.lease, newer.lease);
        assert_eq!(
            repo.worker_snapshot(newer.lease.worker_id)
                .await
                .unwrap()
                .reserved_calls,
            0
        );
        assert_eq!(
            repo.claim_outbox(worker.lease, at(12), Duration::from_secs(5), 1)
                .await,
            Err(RepositoryError::StaleWorkerFence)
        );
        let cleanup = repo
            .claim_outbox(newer.lease, at(12), Duration::from_secs(5), 1)
            .await
            .unwrap();
        assert_eq!(cleanup.len(), 1);
        assert_eq!(cleanup[0].record.worker, newer.lease);
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
