//! Durable gateway-to-worker broadcast commands.
//!
//! PostgreSQL is authoritative. Redis receives only the existing payload-free
//! worker wakeup through the transactional coordination outbox; workers also
//! poll this table on the same bounded fallback cadence used by call effects.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::{Postgres, Row, Transaction};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::call_engine::{BindingGeneration, CallId, LegId, TenantId, WorkerId, WorkerLease};
use crate::coordination::{
    CoordinationPayload, DeploymentId, PostgresCoordinationOutbox, WakeupReason,
};

const MAX_CLAIM_TTL: Duration = Duration::from_secs(5 * 60);
const MAX_BATCH: usize = 64;

/// Transport selected by the public broadcast request.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DurableBroadcastTransport {
    Moqt,
    UctpQuic,
}

impl DurableBroadcastTransport {
    const fn database_value(self) -> &'static str {
        match self {
            Self::Moqt => "moqt",
            Self::UctpQuic => "uctp_quic",
        }
    }
}

/// Immutable worker command payload. It contains identifiers and media policy,
/// never subscriber credentials or provider secrets.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DurableBroadcastSpec {
    pub broadcast_id: String,
    pub tenant_id: TenantId,
    pub call_id: CallId,
    pub source_leg_id: LegId,
    pub source_binding_generation: BindingGeneration,
    pub worker: WorkerLease,
    pub transport: DurableBroadcastTransport,
    pub language: Option<String>,
    pub sanitized_events: bool,
    pub expires_at: DateTime<Utc>,
}

/// Safe descriptor returned by a worker after the graph route is live.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DurableBroadcastRuntime {
    pub endpoint: Value,
    pub protocol: Value,
    pub lifecycle: Value,
    pub health: Value,
    pub sanitized_events: bool,
    /// Exact shared-authority lease installed by the worker. It is not
    /// returned by the public API, but lets crash and terminal cleanup revoke
    /// only the generation owned by this durable runtime.
    #[serde(default)]
    pub grant_generation: Option<Uuid>,
}

/// Durable lifecycle visible to gateway GET/token/delete handlers.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableBroadcastState {
    Pending,
    Active,
    Deleting,
    Deleted,
    Failed,
}

impl DurableBroadcastState {
    fn parse(value: &str) -> Result<Self, BroadcastCommandError> {
        match value {
            "pending" => Ok(Self::Pending),
            "active" => Ok(Self::Active),
            "deleting" => Ok(Self::Deleting),
            "deleted" => Ok(Self::Deleted),
            "failed" => Ok(Self::Failed),
            _ => Err(BroadcastCommandError::InvalidData),
        }
    }
}

/// One persisted broadcast and its latest reconciled runtime result.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DurableBroadcastRecord {
    pub specification: DurableBroadcastSpec,
    pub state: DurableBroadcastState,
    pub runtime: Option<DurableBroadcastRuntime>,
    pub failure_code: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Derived operation identities. Raw `Idempotency-Key` values never enter the
/// repository.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BroadcastOperationIdentity {
    pub idempotency_digest: [u8; 32],
    pub request_digest: [u8; 32],
}

impl fmt::Debug for BroadcastOperationIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BroadcastOperationIdentity([redacted])")
    }
}

/// Whether an enqueue created work or replayed the exact retained receipt.
#[derive(Clone, Debug, PartialEq)]
pub struct BroadcastEnqueueOutcome {
    pub record: DurableBroadcastRecord,
    pub replayed: bool,
}

/// Command kind claimed by the pinned worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableBroadcastCommandKind {
    Start,
    Stop,
}

impl DurableBroadcastCommandKind {
    fn parse(value: &str) -> Result<Self, BroadcastCommandError> {
        match value {
            "start" => Ok(Self::Start),
            "stop" => Ok(Self::Stop),
            _ => Err(BroadcastCommandError::InvalidData),
        }
    }
}

/// Exact expiring claim delivered to one worker incarnation.
#[derive(Clone, Debug, PartialEq)]
pub struct ClaimedBroadcastCommand {
    pub command_id: Uuid,
    pub kind: DurableBroadcastCommandKind,
    pub claim_generation: u64,
    pub record: DurableBroadcastRecord,
}

/// Worker reconciliation result.
#[derive(Clone, Debug, PartialEq)]
pub enum BroadcastCommandResult {
    Started(Box<DurableBroadcastRuntime>),
    Stopped,
    Failed(&'static str),
}

/// Safe durable-command failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BroadcastCommandError {
    #[error("broadcast command repository unavailable")]
    Unavailable,
    #[error("broadcast command data is invalid")]
    InvalidData,
    #[error("broadcast not found")]
    NotFound,
    #[error("broadcast operation conflicts with a retained idempotency receipt")]
    IdempotencyConflict,
    #[error("broadcast capacity is exhausted")]
    CapacityExceeded,
    #[error("broadcast state does not allow this operation")]
    InvalidTransition,
    #[error("broadcast command claim is stale")]
    StaleClaim,
}

/// Authoritative queue shared by gateway and worker roles.
#[async_trait]
pub trait BroadcastCommandRepository: Send + Sync {
    async fn enqueue_start(
        &self,
        specification: DurableBroadcastSpec,
        identity: BroadcastOperationIdentity,
        max_active: usize,
    ) -> Result<BroadcastEnqueueOutcome, BroadcastCommandError>;

    async fn enqueue_stop(
        &self,
        tenant_id: &TenantId,
        broadcast_id: &str,
        identity: BroadcastOperationIdentity,
    ) -> Result<BroadcastEnqueueOutcome, BroadcastCommandError>;

    async fn get(
        &self,
        tenant_id: &TenantId,
        broadcast_id: &str,
    ) -> Result<Option<DurableBroadcastRecord>, BroadcastCommandError>;

    async fn claim(
        &self,
        worker: WorkerLease,
        claim_ttl: Duration,
        limit: usize,
    ) -> Result<Vec<ClaimedBroadcastCommand>, BroadcastCommandError>;

    async fn complete(
        &self,
        claim: &ClaimedBroadcastCommand,
        result: BroadcastCommandResult,
    ) -> Result<DurableBroadcastRecord, BroadcastCommandError>;

    /// Fails every retained broadcast for an older incarnation of this stable
    /// worker ID and returns those rows so the executor can revoke shared
    /// transport grants. The current fence is never adopted by those rows.
    async fn fail_stale_worker_broadcasts(
        &self,
        current: WorkerLease,
    ) -> Result<Vec<DurableBroadcastRecord>, BroadcastCommandError>;

    /// Reconciles a worker-observed terminal route only while the durable row
    /// still names the exact source binding and worker incarnation that
    /// created it. A concurrent delete or replacement therefore wins without
    /// an older monitor overwriting newer state.
    async fn reconcile_terminal(
        &self,
        broadcast_id: &str,
        worker: WorkerLease,
        source_binding_generation: BindingGeneration,
        grant_generation: Option<Uuid>,
        failure_code: &'static str,
    ) -> Result<bool, BroadcastCommandError>;

    /// Clears retained cleanup metadata only after the exact shared grant was
    /// revoked. This is the gate that makes failed-row DELETE safe.
    async fn finalize_failed_cleanup(
        &self,
        broadcast_id: &str,
        worker: WorkerLease,
        grant_generation: Option<Uuid>,
    ) -> Result<bool, BroadcastCommandError>;

    async fn fail_worker_broadcasts(
        &self,
        worker: WorkerLease,
        failure_code: &'static str,
    ) -> Result<(), BroadcastCommandError>;
}

/// Deterministic standalone repository used by hermetic conformance tests and
/// embedders that deliberately choose ephemeral coordination.
#[derive(Debug, Default)]
pub struct MemoryBroadcastCommandRepository {
    state: tokio::sync::Mutex<MemoryBroadcastState>,
}

#[derive(Debug, Default)]
struct MemoryBroadcastState {
    records: HashMap<String, DurableBroadcastRecord>,
    create_receipts: HashMap<(TenantId, [u8; 32]), ([u8; 32], String)>,
    delete_receipts: HashMap<(TenantId, [u8; 32]), ([u8; 32], String)>,
    commands: HashMap<Uuid, MemoryBroadcastCommand>,
}

#[derive(Clone, Debug)]
struct MemoryBroadcastCommand {
    command_id: Uuid,
    broadcast_id: String,
    worker: WorkerLease,
    kind: DurableBroadcastCommandKind,
    available_at: DateTime<Utc>,
    claim_generation: u64,
    claim_expires_at: Option<DateTime<Utc>>,
    state: MemoryCommandState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MemoryCommandState {
    Pending,
    Claimed,
    Succeeded,
    Failed,
}

impl MemoryBroadcastCommandRepository {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
}

#[async_trait]
impl BroadcastCommandRepository for MemoryBroadcastCommandRepository {
    async fn enqueue_start(
        &self,
        specification: DurableBroadcastSpec,
        identity: BroadcastOperationIdentity,
        max_active: usize,
    ) -> Result<BroadcastEnqueueOutcome, BroadcastCommandError> {
        validate_specification(&specification)?;
        let mut state = self.state.lock().await;
        let receipt_key = (specification.tenant_id.clone(), identity.idempotency_digest);
        if let Some((request_digest, broadcast_id)) = state.create_receipts.get(&receipt_key) {
            if *request_digest != identity.request_digest {
                return Err(BroadcastCommandError::IdempotencyConflict);
            }
            return Ok(BroadcastEnqueueOutcome {
                record: state
                    .records
                    .get(broadcast_id)
                    .cloned()
                    .ok_or(BroadcastCommandError::InvalidData)?,
                replayed: true,
            });
        }
        let active = state
            .records
            .values()
            .filter(|record| {
                record.specification.worker == specification.worker
                    && matches!(
                        record.state,
                        DurableBroadcastState::Pending
                            | DurableBroadcastState::Active
                            | DurableBroadcastState::Deleting
                    )
            })
            .count();
        if max_active == 0 || active >= max_active {
            return Err(BroadcastCommandError::CapacityExceeded);
        }
        let now = Utc::now();
        let record = DurableBroadcastRecord {
            specification: specification.clone(),
            state: DurableBroadcastState::Pending,
            runtime: None,
            failure_code: None,
            created_at: now,
            updated_at: now,
        };
        state.create_receipts.insert(
            receipt_key,
            (identity.request_digest, specification.broadcast_id.clone()),
        );
        state
            .records
            .insert(specification.broadcast_id.clone(), record.clone());
        let command_id = Uuid::new_v4();
        state.commands.insert(
            command_id,
            MemoryBroadcastCommand {
                command_id,
                broadcast_id: specification.broadcast_id,
                worker: specification.worker,
                kind: DurableBroadcastCommandKind::Start,
                available_at: now,
                claim_generation: 0,
                claim_expires_at: None,
                state: MemoryCommandState::Pending,
            },
        );
        Ok(BroadcastEnqueueOutcome {
            record,
            replayed: false,
        })
    }

    async fn enqueue_stop(
        &self,
        tenant_id: &TenantId,
        broadcast_id: &str,
        identity: BroadcastOperationIdentity,
    ) -> Result<BroadcastEnqueueOutcome, BroadcastCommandError> {
        validate_broadcast_id(broadcast_id)?;
        let mut state = self.state.lock().await;
        let receipt_key = (tenant_id.clone(), identity.idempotency_digest);
        if let Some((request_digest, retained_id)) =
            state.delete_receipts.get(&receipt_key).cloned()
        {
            if request_digest != identity.request_digest {
                return Err(BroadcastCommandError::IdempotencyConflict);
            }
            let record = state
                .records
                .get_mut(&retained_id)
                .ok_or(BroadcastCommandError::InvalidData)?;
            if record.state == DurableBroadcastState::Failed {
                if record.runtime.is_some() {
                    return Err(BroadcastCommandError::InvalidTransition);
                }
                record.state = DurableBroadcastState::Deleted;
                record.updated_at = Utc::now();
            }
            return Ok(BroadcastEnqueueOutcome {
                record: record.clone(),
                replayed: true,
            });
        }
        let record = state
            .records
            .get_mut(broadcast_id)
            .filter(|record| &record.specification.tenant_id == tenant_id)
            .ok_or(BroadcastCommandError::NotFound)?;
        let worker = record.specification.worker;
        if record.state == DurableBroadcastState::Failed {
            if record.runtime.is_some() {
                return Err(BroadcastCommandError::InvalidTransition);
            }
            record.state = DurableBroadcastState::Deleted;
            record.updated_at = Utc::now();
        } else if record.state != DurableBroadcastState::Deleted {
            record.state = DurableBroadcastState::Deleting;
            record.updated_at = Utc::now();
            if !state.commands.values().any(|command| {
                command.broadcast_id == broadcast_id
                    && command.kind == DurableBroadcastCommandKind::Stop
            }) {
                let command_id = Uuid::new_v4();
                state.commands.insert(
                    command_id,
                    MemoryBroadcastCommand {
                        command_id,
                        broadcast_id: broadcast_id.to_owned(),
                        worker,
                        kind: DurableBroadcastCommandKind::Stop,
                        available_at: Utc::now(),
                        claim_generation: 0,
                        claim_expires_at: None,
                        state: MemoryCommandState::Pending,
                    },
                );
            }
        }
        state.delete_receipts.insert(
            receipt_key,
            (identity.request_digest, broadcast_id.to_owned()),
        );
        Ok(BroadcastEnqueueOutcome {
            record: state
                .records
                .get(broadcast_id)
                .cloned()
                .ok_or(BroadcastCommandError::InvalidData)?,
            replayed: false,
        })
    }

    async fn get(
        &self,
        tenant_id: &TenantId,
        broadcast_id: &str,
    ) -> Result<Option<DurableBroadcastRecord>, BroadcastCommandError> {
        validate_broadcast_id(broadcast_id)?;
        Ok(self
            .state
            .lock()
            .await
            .records
            .get(broadcast_id)
            .filter(|record| &record.specification.tenant_id == tenant_id)
            .cloned())
    }

    async fn claim(
        &self,
        worker: WorkerLease,
        claim_ttl: Duration,
        limit: usize,
    ) -> Result<Vec<ClaimedBroadcastCommand>, BroadcastCommandError> {
        if claim_ttl.is_zero() || claim_ttl > MAX_CLAIM_TTL || limit == 0 || limit > MAX_BATCH {
            return Err(BroadcastCommandError::InvalidData);
        }
        let now = Utc::now();
        let expires_at = now
            .checked_add_signed(
                TimeDelta::from_std(claim_ttl).map_err(|_| BroadcastCommandError::InvalidData)?,
            )
            .ok_or(BroadcastCommandError::InvalidData)?;
        let mut state = self.state.lock().await;
        let mut ids = state
            .commands
            .values()
            .filter(|command| {
                command.worker == worker
                    && command.available_at <= now
                    && (command.state == MemoryCommandState::Pending
                        || (command.state == MemoryCommandState::Claimed
                            && command.claim_expires_at.is_some_and(|expiry| expiry <= now)))
            })
            .map(|command| (command.available_at, command.command_id))
            .collect::<Vec<_>>();
        ids.sort_unstable();
        ids.truncate(limit);
        let mut claims = Vec::with_capacity(ids.len());
        for (_, command_id) in ids {
            let (broadcast_id, kind, generation) = {
                let command = state
                    .commands
                    .get_mut(&command_id)
                    .ok_or(BroadcastCommandError::InvalidData)?;
                command.claim_generation = command
                    .claim_generation
                    .checked_add(1)
                    .ok_or(BroadcastCommandError::InvalidData)?;
                command.claim_expires_at = Some(expires_at);
                command.state = MemoryCommandState::Claimed;
                (
                    command.broadcast_id.clone(),
                    command.kind,
                    command.claim_generation,
                )
            };
            claims.push(ClaimedBroadcastCommand {
                command_id,
                kind,
                claim_generation: generation,
                record: state
                    .records
                    .get(&broadcast_id)
                    .cloned()
                    .ok_or(BroadcastCommandError::InvalidData)?,
            });
        }
        Ok(claims)
    }

    async fn complete(
        &self,
        claim: &ClaimedBroadcastCommand,
        result: BroadcastCommandResult,
    ) -> Result<DurableBroadcastRecord, BroadcastCommandError> {
        let mut state = self.state.lock().await;
        let command = state
            .commands
            .get_mut(&claim.command_id)
            .ok_or(BroadcastCommandError::StaleClaim)?;
        if command.state != MemoryCommandState::Claimed
            || command.claim_generation != claim.claim_generation
            || command.kind != claim.kind
        {
            return Err(BroadcastCommandError::StaleClaim);
        }
        let (command_state, record_state, runtime, failure_code) = match result {
            BroadcastCommandResult::Started(runtime)
                if claim.kind == DurableBroadcastCommandKind::Start =>
            {
                (
                    MemoryCommandState::Succeeded,
                    DurableBroadcastState::Active,
                    Some(*runtime),
                    None,
                )
            }
            BroadcastCommandResult::Stopped if claim.kind == DurableBroadcastCommandKind::Stop => (
                MemoryCommandState::Succeeded,
                DurableBroadcastState::Deleted,
                None,
                None,
            ),
            BroadcastCommandResult::Failed(code) => (
                MemoryCommandState::Failed,
                DurableBroadcastState::Failed,
                None,
                Some(code.to_owned()),
            ),
            _ => return Err(BroadcastCommandError::InvalidTransition),
        };
        command.state = command_state;
        command.claim_expires_at = None;
        let broadcast_id = command.broadcast_id.clone();
        let record = state
            .records
            .get_mut(&broadcast_id)
            .ok_or(BroadcastCommandError::InvalidData)?;
        record.state = record_state;
        record.runtime = runtime;
        record.failure_code = failure_code;
        record.updated_at = Utc::now();
        Ok(record.clone())
    }

    async fn fail_worker_broadcasts(
        &self,
        worker: WorkerLease,
        failure_code: &'static str,
    ) -> Result<(), BroadcastCommandError> {
        let mut state = self.state.lock().await;
        for command in state.commands.values_mut().filter(|command| {
            command.worker == worker
                && matches!(
                    command.state,
                    MemoryCommandState::Pending | MemoryCommandState::Claimed
                )
        }) {
            command.state = MemoryCommandState::Failed;
            command.claim_expires_at = None;
        }
        for record in state.records.values_mut().filter(|record| {
            record.specification.worker == worker
                && matches!(
                    record.state,
                    DurableBroadcastState::Pending
                        | DurableBroadcastState::Active
                        | DurableBroadcastState::Deleting
                )
        }) {
            record.state = DurableBroadcastState::Failed;
            record.failure_code = Some(failure_code.to_owned());
            record.updated_at = Utc::now();
        }
        Ok(())
    }

    async fn fail_stale_worker_broadcasts(
        &self,
        current: WorkerLease,
    ) -> Result<Vec<DurableBroadcastRecord>, BroadcastCommandError> {
        let mut state = self.state.lock().await;
        let stale_ids = state
            .records
            .values()
            .filter(|record| {
                record.specification.worker.worker_id == current.worker_id
                    && record.specification.worker.fence != current.fence
                    && (matches!(
                        record.state,
                        DurableBroadcastState::Pending
                            | DurableBroadcastState::Active
                            | DurableBroadcastState::Deleting
                    ) || (record.failure_code.as_deref() == Some("stale_worker_fence")
                        && record.runtime.is_some()))
            })
            .map(|record| record.specification.broadcast_id.clone())
            .collect::<Vec<_>>();
        for command in state.commands.values_mut().filter(|command| {
            command.worker.worker_id == current.worker_id
                && command.worker.fence != current.fence
                && matches!(
                    command.state,
                    MemoryCommandState::Pending | MemoryCommandState::Claimed
                )
        }) {
            command.state = MemoryCommandState::Failed;
            command.claim_expires_at = None;
        }
        for broadcast_id in &stale_ids {
            let record = state
                .records
                .get_mut(broadcast_id)
                .ok_or(BroadcastCommandError::InvalidData)?;
            record.state = DurableBroadcastState::Failed;
            record.failure_code = Some("stale_worker_fence".to_owned());
            record.updated_at = Utc::now();
        }
        stale_ids
            .iter()
            .map(|broadcast_id| {
                state
                    .records
                    .get(broadcast_id)
                    .cloned()
                    .ok_or(BroadcastCommandError::InvalidData)
            })
            .collect()
    }

    async fn reconcile_terminal(
        &self,
        broadcast_id: &str,
        worker: WorkerLease,
        source_binding_generation: BindingGeneration,
        grant_generation: Option<Uuid>,
        failure_code: &'static str,
    ) -> Result<bool, BroadcastCommandError> {
        validate_broadcast_id(broadcast_id)?;
        let mut state = self.state.lock().await;
        let Some(record) = state.records.get_mut(broadcast_id) else {
            return Ok(false);
        };
        if record.state != DurableBroadcastState::Active
            || record.specification.worker != worker
            || record.specification.source_binding_generation != source_binding_generation
            || record
                .runtime
                .as_ref()
                .and_then(|runtime| runtime.grant_generation)
                != grant_generation
        {
            return Ok(false);
        }
        record.state = DurableBroadcastState::Failed;
        record.runtime = None;
        record.failure_code = Some(failure_code.to_owned());
        record.updated_at = Utc::now();
        Ok(true)
    }

    async fn finalize_failed_cleanup(
        &self,
        broadcast_id: &str,
        worker: WorkerLease,
        grant_generation: Option<Uuid>,
    ) -> Result<bool, BroadcastCommandError> {
        validate_broadcast_id(broadcast_id)?;
        let mut state = self.state.lock().await;
        let Some(record) = state.records.get_mut(broadcast_id) else {
            return Ok(false);
        };
        if record.state != DurableBroadcastState::Failed
            || record.specification.worker != worker
            || record
                .runtime
                .as_ref()
                .and_then(|runtime| runtime.grant_generation)
                != grant_generation
        {
            return Ok(false);
        }
        record.runtime = None;
        record.updated_at = Utc::now();
        Ok(true)
    }
}

/// PostgreSQL queue used by split gateway/worker deployments.
#[derive(Clone)]
pub struct PostgresBroadcastCommandRepository {
    pool: PgPool,
    outbox: PostgresCoordinationOutbox,
}

impl fmt::Debug for PostgresBroadcastCommandRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresBroadcastCommandRepository")
            .finish_non_exhaustive()
    }
}

impl PostgresBroadcastCommandRepository {
    /// Connects after the call repository has applied embedded migrations.
    pub async fn connect(
        mut database_url: String,
        deployment: DeploymentId,
    ) -> Result<Arc<Self>, BroadcastCommandError> {
        let result = PgPoolOptions::new()
            .max_connections(8)
            .connect(&database_url)
            .await;
        database_url.zeroize();
        let pool = result.map_err(|_| BroadcastCommandError::Unavailable)?;
        sqlx::query("SELECT 1 FROM broadcasts LIMIT 1")
            .execute(&pool)
            .await
            .map_err(|_| BroadcastCommandError::Unavailable)?;
        Ok(Arc::new(Self {
            outbox: PostgresCoordinationOutbox::from_pool(pool.clone(), deployment),
            pool,
        }))
    }

    async fn lock_operation(
        transaction: &mut Transaction<'_, Postgres>,
        identity: BroadcastOperationIdentity,
    ) -> Result<(), BroadcastCommandError> {
        let advisory_key = i64::from_be_bytes(
            identity.idempotency_digest[..8]
                .try_into()
                .expect("digest prefix has a fixed length"),
        );
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(advisory_key)
            .execute(&mut **transaction)
            .await
            .map_err(|_| BroadcastCommandError::Unavailable)?;
        Ok(())
    }

    async fn lock_worker(
        transaction: &mut Transaction<'_, Postgres>,
        worker: WorkerLease,
    ) -> Result<(), BroadcastCommandError> {
        let row = sqlx::query(
            "SELECT fence, draining, lease_expires_at > clock_timestamp() AS lease_active \
             FROM workers WHERE worker_id = $1::uuid FOR UPDATE",
        )
        .bind(worker.worker_id.to_string())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| BroadcastCommandError::Unavailable)?;
        let Some(row) = row else {
            return Err(BroadcastCommandError::InvalidTransition);
        };
        let fence: i64 = row
            .try_get("fence")
            .map_err(|_| BroadcastCommandError::InvalidData)?;
        let draining: bool = row
            .try_get("draining")
            .map_err(|_| BroadcastCommandError::InvalidData)?;
        let lease_active: bool = row
            .try_get("lease_active")
            .map_err(|_| BroadcastCommandError::InvalidData)?;
        if fence != worker.fence.as_i64() || draining || !lease_active {
            return Err(BroadcastCommandError::InvalidTransition);
        }
        Ok(())
    }

    async fn append_wakeup(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        worker_id: WorkerId,
    ) -> Result<(), BroadcastCommandError> {
        self.outbox
            .append_in_transaction(
                transaction,
                CoordinationPayload::WakeWorker {
                    worker_id,
                    reason: WakeupReason::Broadcasts,
                },
            )
            .await
            .map(|_| ())
            .map_err(|_| BroadcastCommandError::Unavailable)
    }
}

#[async_trait]
impl BroadcastCommandRepository for PostgresBroadcastCommandRepository {
    async fn enqueue_start(
        &self,
        specification: DurableBroadcastSpec,
        identity: BroadcastOperationIdentity,
        max_active: usize,
    ) -> Result<BroadcastEnqueueOutcome, BroadcastCommandError> {
        validate_specification(&specification)?;
        if max_active == 0 {
            return Err(BroadcastCommandError::CapacityExceeded);
        }
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| BroadcastCommandError::Unavailable)?;
        Self::lock_operation(&mut transaction, identity).await?;
        if let Some(row) = sqlx::query(
            "SELECT specification::text AS specification, state, runtime::text AS runtime, \
                    failure_code, created_at, updated_at, create_request_digest \
             FROM broadcasts WHERE tenant_id = $1 AND create_idempotency_digest = $2 FOR UPDATE",
        )
        .bind(specification.tenant_id.as_str())
        .bind(identity.idempotency_digest.as_slice())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| BroadcastCommandError::Unavailable)?
        {
            let retained: Vec<u8> = row
                .try_get("create_request_digest")
                .map_err(|_| BroadcastCommandError::InvalidData)?;
            if retained.as_slice() != identity.request_digest {
                return Err(BroadcastCommandError::IdempotencyConflict);
            }
            let record = decode_record(&row)?;
            transaction
                .commit()
                .await
                .map_err(|_| BroadcastCommandError::Unavailable)?;
            return Ok(BroadcastEnqueueOutcome {
                record,
                replayed: true,
            });
        }

        // Worker registration is the authoritative admission row. Holding it
        // through count-and-insert makes max_active exact under concurrent
        // gateway requests and rejects an obsolete worker fence.
        Self::lock_worker(&mut transaction, specification.worker).await?;

        let active: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM broadcasts \
             WHERE worker_id = $1::uuid AND worker_fence = $2 \
               AND state IN ('pending', 'active', 'deleting')",
        )
        .bind(specification.worker.worker_id.to_string())
        .bind(specification.worker.fence.as_i64())
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| BroadcastCommandError::Unavailable)?;
        if usize::try_from(active).unwrap_or(usize::MAX) >= max_active {
            return Err(BroadcastCommandError::CapacityExceeded);
        }

        let now = postgres_now(&mut transaction).await?;
        let body =
            serde_json::to_value(&specification).map_err(|_| BroadcastCommandError::InvalidData)?;
        sqlx::query(
            "INSERT INTO broadcasts \
             (broadcast_id, tenant_id, call_id, source_leg_id, worker_id, worker_fence, \
              transport, state, specification, expires_at, created_at, updated_at, \
              create_idempotency_digest, create_request_digest) \
             VALUES ($1::uuid, $2, $3::uuid, $4::uuid, $5::uuid, $6, $7, 'pending', \
                     $8::jsonb, $9, $10, $10, $11, $12)",
        )
        .bind(&specification.broadcast_id)
        .bind(specification.tenant_id.as_str())
        .bind(specification.call_id.to_string())
        .bind(specification.source_leg_id.to_string())
        .bind(specification.worker.worker_id.to_string())
        .bind(specification.worker.fence.as_i64())
        .bind(specification.transport.database_value())
        .bind(body)
        .bind(specification.expires_at)
        .bind(now)
        .bind(identity.idempotency_digest.as_slice())
        .bind(identity.request_digest.as_slice())
        .execute(&mut *transaction)
        .await
        .map_err(|_| BroadcastCommandError::Unavailable)?;
        sqlx::query(
            "INSERT INTO broadcast_commands \
             (command_id, broadcast_id, worker_id, worker_fence, kind, state, available_at) \
             VALUES ($1, $2::uuid, $3::uuid, $4, 'start', 'pending', $5)",
        )
        .bind(Uuid::new_v4())
        .bind(&specification.broadcast_id)
        .bind(specification.worker.worker_id.to_string())
        .bind(specification.worker.fence.as_i64())
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(|_| BroadcastCommandError::Unavailable)?;
        self.append_wakeup(&mut transaction, specification.worker.worker_id)
            .await?;
        transaction
            .commit()
            .await
            .map_err(|_| BroadcastCommandError::Unavailable)?;
        Ok(BroadcastEnqueueOutcome {
            record: DurableBroadcastRecord {
                specification,
                state: DurableBroadcastState::Pending,
                runtime: None,
                failure_code: None,
                created_at: now,
                updated_at: now,
            },
            replayed: false,
        })
    }

    async fn enqueue_stop(
        &self,
        tenant_id: &TenantId,
        broadcast_id: &str,
        identity: BroadcastOperationIdentity,
    ) -> Result<BroadcastEnqueueOutcome, BroadcastCommandError> {
        validate_broadcast_id(broadcast_id)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| BroadcastCommandError::Unavailable)?;
        Self::lock_operation(&mut transaction, identity).await?;
        if let Some(row) = sqlx::query(
            "SELECT b.specification::text AS specification, b.state, b.runtime::text AS runtime, \
                    b.failure_code, b.created_at, b.updated_at, r.request_digest \
             FROM broadcast_operation_receipts r JOIN broadcasts b USING (broadcast_id) \
             WHERE r.tenant_id = $1 AND r.operation = 'delete' AND r.idempotency_digest = $2 \
             FOR UPDATE OF b, r",
        )
        .bind(tenant_id.as_str())
        .bind(identity.idempotency_digest.as_slice())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| BroadcastCommandError::Unavailable)?
        {
            let retained: Vec<u8> = row
                .try_get("request_digest")
                .map_err(|_| BroadcastCommandError::InvalidData)?;
            if retained.as_slice() != identity.request_digest {
                return Err(BroadcastCommandError::IdempotencyConflict);
            }
            let mut record = decode_record(&row)?;
            if record.state == DurableBroadcastState::Failed {
                if record.runtime.is_some() {
                    return Err(BroadcastCommandError::InvalidTransition);
                }
                let now = postgres_now(&mut transaction).await?;
                sqlx::query(
                    "UPDATE broadcasts SET state = 'deleted', updated_at = $1 \
                     WHERE broadcast_id = $2::uuid",
                )
                .bind(now)
                .bind(&record.specification.broadcast_id)
                .execute(&mut *transaction)
                .await
                .map_err(|_| BroadcastCommandError::Unavailable)?;
                record.state = DurableBroadcastState::Deleted;
                record.updated_at = now;
            }
            transaction
                .commit()
                .await
                .map_err(|_| BroadcastCommandError::Unavailable)?;
            return Ok(BroadcastEnqueueOutcome {
                record,
                replayed: true,
            });
        }
        let row = sqlx::query(
            "SELECT specification::text AS specification, state, runtime::text AS runtime, \
                    failure_code, created_at, updated_at \
             FROM broadcasts WHERE tenant_id = $1 AND broadcast_id = $2::uuid FOR UPDATE",
        )
        .bind(tenant_id.as_str())
        .bind(broadcast_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| BroadcastCommandError::Unavailable)?
        .ok_or(BroadcastCommandError::NotFound)?;
        let mut record = decode_record(&row)?;
        let now = postgres_now(&mut transaction).await?;
        if record.state == DurableBroadcastState::Failed {
            if record.runtime.is_some() {
                return Err(BroadcastCommandError::InvalidTransition);
            }
            sqlx::query(
                "UPDATE broadcasts SET state = 'deleted', updated_at = $1 \
                 WHERE broadcast_id = $2::uuid",
            )
            .bind(now)
            .bind(broadcast_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| BroadcastCommandError::Unavailable)?;
            record.state = DurableBroadcastState::Deleted;
            record.updated_at = now;
        } else if record.state != DurableBroadcastState::Deleted {
            sqlx::query(
                "UPDATE broadcasts SET state = 'deleting', updated_at = $1 \
                 WHERE broadcast_id = $2::uuid",
            )
            .bind(now)
            .bind(broadcast_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| BroadcastCommandError::Unavailable)?;
            sqlx::query(
                "INSERT INTO broadcast_commands \
                 (command_id, broadcast_id, worker_id, worker_fence, kind, state, available_at) \
                 VALUES ($1, $2::uuid, $3::uuid, $4, 'stop', 'pending', $5) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(Uuid::new_v4())
            .bind(broadcast_id)
            .bind(record.specification.worker.worker_id.to_string())
            .bind(record.specification.worker.fence.as_i64())
            .bind(now)
            .execute(&mut *transaction)
            .await
            .map_err(|_| BroadcastCommandError::Unavailable)?;
            self.append_wakeup(&mut transaction, record.specification.worker.worker_id)
                .await?;
            record.state = DurableBroadcastState::Deleting;
            record.updated_at = now;
        }
        sqlx::query(
            "INSERT INTO broadcast_operation_receipts \
             (tenant_id, operation, idempotency_digest, request_digest, broadcast_id, recorded_at) \
             VALUES ($1, 'delete', $2, $3, $4::uuid, $5)",
        )
        .bind(tenant_id.as_str())
        .bind(identity.idempotency_digest.as_slice())
        .bind(identity.request_digest.as_slice())
        .bind(broadcast_id)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(|_| BroadcastCommandError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| BroadcastCommandError::Unavailable)?;
        Ok(BroadcastEnqueueOutcome {
            record,
            replayed: false,
        })
    }

    async fn get(
        &self,
        tenant_id: &TenantId,
        broadcast_id: &str,
    ) -> Result<Option<DurableBroadcastRecord>, BroadcastCommandError> {
        validate_broadcast_id(broadcast_id)?;
        sqlx::query(
            "SELECT specification::text AS specification, state, runtime::text AS runtime, \
                    failure_code, created_at, updated_at \
             FROM broadcasts WHERE tenant_id = $1 AND broadcast_id = $2::uuid",
        )
        .bind(tenant_id.as_str())
        .bind(broadcast_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| BroadcastCommandError::Unavailable)?
        .map(|row| decode_record(&row))
        .transpose()
    }

    async fn claim(
        &self,
        worker: WorkerLease,
        claim_ttl: Duration,
        limit: usize,
    ) -> Result<Vec<ClaimedBroadcastCommand>, BroadcastCommandError> {
        if claim_ttl.is_zero() || claim_ttl > MAX_CLAIM_TTL || limit == 0 || limit > MAX_BATCH {
            return Err(BroadcastCommandError::InvalidData);
        }
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| BroadcastCommandError::Unavailable)?;
        let now = postgres_now(&mut transaction).await?;
        let expires = now
            .checked_add_signed(
                TimeDelta::from_std(claim_ttl).map_err(|_| BroadcastCommandError::InvalidData)?,
            )
            .ok_or(BroadcastCommandError::InvalidData)?;
        let rows = sqlx::query(
            "SELECT c.command_id, c.kind, c.claim_generation, \
                    b.specification::text AS specification, b.state, b.runtime::text AS runtime, \
                    b.failure_code, b.created_at, b.updated_at \
             FROM broadcast_commands c JOIN broadcasts b USING (broadcast_id) \
             WHERE c.worker_id = $1::uuid AND c.worker_fence = $2 \
               AND c.available_at <= $3 \
               AND (c.state = 'pending' OR (c.state = 'claimed' AND c.claim_expires_at <= $3)) \
             ORDER BY c.available_at, c.command_id LIMIT $4 FOR UPDATE OF c SKIP LOCKED",
        )
        .bind(worker.worker_id.to_string())
        .bind(worker.fence.as_i64())
        .bind(now)
        .bind(limit as i64)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| BroadcastCommandError::Unavailable)?;
        let mut claims = Vec::with_capacity(rows.len());
        for row in rows {
            let command_id: Uuid = row
                .try_get("command_id")
                .map_err(|_| BroadcastCommandError::InvalidData)?;
            let previous: i64 = row
                .try_get("claim_generation")
                .map_err(|_| BroadcastCommandError::InvalidData)?;
            let generation = previous
                .checked_add(1)
                .filter(|value| *value > 0)
                .ok_or(BroadcastCommandError::InvalidData)?;
            sqlx::query(
                "UPDATE broadcast_commands SET state = 'claimed', claim_generation = $1, \
                        claimed_at = $2, claim_expires_at = $3 \
                 WHERE command_id = $4",
            )
            .bind(generation)
            .bind(now)
            .bind(expires)
            .bind(command_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| BroadcastCommandError::Unavailable)?;
            claims.push(ClaimedBroadcastCommand {
                command_id,
                kind: DurableBroadcastCommandKind::parse(
                    row.try_get("kind")
                        .map_err(|_| BroadcastCommandError::InvalidData)?,
                )?,
                claim_generation: generation as u64,
                record: decode_record(&row)?,
            });
        }
        transaction
            .commit()
            .await
            .map_err(|_| BroadcastCommandError::Unavailable)?;
        Ok(claims)
    }

    async fn complete(
        &self,
        claim: &ClaimedBroadcastCommand,
        result: BroadcastCommandResult,
    ) -> Result<DurableBroadcastRecord, BroadcastCommandError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| BroadcastCommandError::Unavailable)?;
        let row = sqlx::query(
            "SELECT c.kind, c.state AS command_state, c.claim_generation, \
                    b.specification::text AS specification, b.state, b.runtime::text AS runtime, \
                    b.failure_code, b.created_at, b.updated_at \
             FROM broadcast_commands c JOIN broadcasts b USING (broadcast_id) \
             WHERE c.command_id = $1 FOR UPDATE OF c, b",
        )
        .bind(claim.command_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| BroadcastCommandError::Unavailable)?
        .ok_or(BroadcastCommandError::StaleClaim)?;
        let command_state: &str = row
            .try_get("command_state")
            .map_err(|_| BroadcastCommandError::InvalidData)?;
        let generation: i64 = row
            .try_get("claim_generation")
            .map_err(|_| BroadcastCommandError::InvalidData)?;
        if command_state != "claimed" || generation != claim.claim_generation as i64 {
            return Err(BroadcastCommandError::StaleClaim);
        }
        let kind = DurableBroadcastCommandKind::parse(
            row.try_get("kind")
                .map_err(|_| BroadcastCommandError::InvalidData)?,
        )?;
        if kind != claim.kind {
            return Err(BroadcastCommandError::StaleClaim);
        }
        let now = postgres_now(&mut transaction).await?;
        let (command_state, broadcast_state, runtime, failure_code) = match result {
            BroadcastCommandResult::Started(runtime)
                if kind == DurableBroadcastCommandKind::Start =>
            {
                (
                    "succeeded",
                    "active",
                    Some(
                        serde_json::to_value(runtime)
                            .map_err(|_| BroadcastCommandError::InvalidData)?,
                    ),
                    None,
                )
            }
            BroadcastCommandResult::Stopped if kind == DurableBroadcastCommandKind::Stop => {
                ("succeeded", "deleted", None, None)
            }
            BroadcastCommandResult::Failed(code) => ("failed", "failed", None, Some(code)),
            _ => return Err(BroadcastCommandError::InvalidTransition),
        };
        sqlx::query(
            "UPDATE broadcast_commands SET state = $1, claimed_at = NULL, claim_expires_at = NULL, \
                    completed_at = $2, failure_code = $3 WHERE command_id = $4",
        )
        .bind(command_state)
        .bind(now)
        .bind(failure_code)
        .bind(claim.command_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| BroadcastCommandError::Unavailable)?;
        sqlx::query(
            "UPDATE broadcasts SET state = $1, runtime = $2::jsonb, failure_code = $3, \
                    updated_at = $4 WHERE broadcast_id = $5::uuid",
        )
        .bind(broadcast_state)
        .bind(&runtime)
        .bind(failure_code)
        .bind(now)
        .bind(&claim.record.specification.broadcast_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| BroadcastCommandError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| BroadcastCommandError::Unavailable)?;
        let mut record = claim.record.clone();
        record.state = DurableBroadcastState::parse(broadcast_state)?;
        record.runtime = runtime
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| BroadcastCommandError::InvalidData)?;
        record.failure_code = failure_code.map(str::to_owned);
        record.updated_at = now;
        Ok(record)
    }

    async fn fail_worker_broadcasts(
        &self,
        worker: WorkerLease,
        failure_code: &'static str,
    ) -> Result<(), BroadcastCommandError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| BroadcastCommandError::Unavailable)?;
        let now = postgres_now(&mut transaction).await?;
        sqlx::query(
            "UPDATE broadcast_commands SET state = 'failed', claimed_at = NULL, \
                    claim_expires_at = NULL, completed_at = $1, failure_code = $2 \
             WHERE worker_id = $3::uuid AND worker_fence = $4 \
               AND state IN ('pending', 'claimed')",
        )
        .bind(now)
        .bind(failure_code)
        .bind(worker.worker_id.to_string())
        .bind(worker.fence.as_i64())
        .execute(&mut *transaction)
        .await
        .map_err(|_| BroadcastCommandError::Unavailable)?;
        sqlx::query(
            "UPDATE broadcasts SET state = 'failed', failure_code = $1, \
                    updated_at = $2 WHERE worker_id = $3::uuid AND worker_fence = $4 \
                    AND state IN ('pending', 'active', 'deleting')",
        )
        .bind(failure_code)
        .bind(now)
        .bind(worker.worker_id.to_string())
        .bind(worker.fence.as_i64())
        .execute(&mut *transaction)
        .await
        .map_err(|_| BroadcastCommandError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| BroadcastCommandError::Unavailable)
    }

    async fn fail_stale_worker_broadcasts(
        &self,
        current: WorkerLease,
    ) -> Result<Vec<DurableBroadcastRecord>, BroadcastCommandError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| BroadcastCommandError::Unavailable)?;
        let now = postgres_now(&mut transaction).await?;
        // The worker registration that produced `current` is authoritative;
        // commands for the same stable ID but any older fence can no longer be
        // claimed and must not migrate.
        sqlx::query(
            "UPDATE broadcast_commands SET state = 'failed', claimed_at = NULL, \
                    claim_expires_at = NULL, completed_at = $1, failure_code = 'stale_worker_fence' \
             WHERE worker_id = $2::uuid AND worker_fence <> $3 \
               AND state IN ('pending', 'claimed')",
        )
        .bind(now)
        .bind(current.worker_id.to_string())
        .bind(current.fence.as_i64())
        .execute(&mut *transaction)
        .await
        .map_err(|_| BroadcastCommandError::Unavailable)?;
        sqlx::query(
            "UPDATE broadcasts SET state = 'failed', \
                    failure_code = 'stale_worker_fence', updated_at = $1 \
             WHERE worker_id = $2::uuid AND worker_fence <> $3 \
               AND state IN ('pending', 'active', 'deleting')",
        )
        .bind(now)
        .bind(current.worker_id.to_string())
        .bind(current.fence.as_i64())
        .execute(&mut *transaction)
        .await
        .map_err(|_| BroadcastCommandError::Unavailable)?;
        let rows = sqlx::query(
            "SELECT specification::text AS specification, state, runtime::text AS runtime, \
                    failure_code, created_at, updated_at FROM broadcasts \
             WHERE worker_id = $1::uuid AND worker_fence <> $2 \
               AND failure_code = 'stale_worker_fence' AND runtime IS NOT NULL",
        )
        .bind(current.worker_id.to_string())
        .bind(current.fence.as_i64())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| BroadcastCommandError::Unavailable)?;
        let records = rows
            .iter()
            .map(decode_record)
            .collect::<Result<Vec<_>, _>>()?;
        transaction
            .commit()
            .await
            .map_err(|_| BroadcastCommandError::Unavailable)?;
        Ok(records)
    }

    async fn reconcile_terminal(
        &self,
        broadcast_id: &str,
        worker: WorkerLease,
        source_binding_generation: BindingGeneration,
        grant_generation: Option<Uuid>,
        failure_code: &'static str,
    ) -> Result<bool, BroadcastCommandError> {
        validate_broadcast_id(broadcast_id)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| BroadcastCommandError::Unavailable)?;
        let row = sqlx::query(
            "SELECT specification::text AS specification, state, runtime::text AS runtime, \
                    failure_code, created_at, updated_at FROM broadcasts \
             WHERE broadcast_id = $1::uuid FOR UPDATE",
        )
        .bind(broadcast_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| BroadcastCommandError::Unavailable)?;
        let Some(row) = row else {
            transaction
                .commit()
                .await
                .map_err(|_| BroadcastCommandError::Unavailable)?;
            return Ok(false);
        };
        let record = decode_record(&row)?;
        if record.state != DurableBroadcastState::Active
            || record.specification.worker != worker
            || record.specification.source_binding_generation != source_binding_generation
            || record
                .runtime
                .as_ref()
                .and_then(|runtime| runtime.grant_generation)
                != grant_generation
        {
            transaction
                .commit()
                .await
                .map_err(|_| BroadcastCommandError::Unavailable)?;
            return Ok(false);
        }
        let now = postgres_now(&mut transaction).await?;
        sqlx::query(
            "UPDATE broadcasts SET state = 'failed', runtime = NULL, failure_code = $1, \
                    updated_at = $2 WHERE broadcast_id = $3::uuid",
        )
        .bind(failure_code)
        .bind(now)
        .bind(broadcast_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| BroadcastCommandError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| BroadcastCommandError::Unavailable)?;
        Ok(true)
    }

    async fn finalize_failed_cleanup(
        &self,
        broadcast_id: &str,
        worker: WorkerLease,
        grant_generation: Option<Uuid>,
    ) -> Result<bool, BroadcastCommandError> {
        validate_broadcast_id(broadcast_id)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| BroadcastCommandError::Unavailable)?;
        let row = sqlx::query(
            "SELECT specification::text AS specification, state, runtime::text AS runtime, \
                    failure_code, created_at, updated_at FROM broadcasts \
             WHERE broadcast_id = $1::uuid FOR UPDATE",
        )
        .bind(broadcast_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| BroadcastCommandError::Unavailable)?;
        let Some(row) = row else {
            transaction
                .commit()
                .await
                .map_err(|_| BroadcastCommandError::Unavailable)?;
            return Ok(false);
        };
        let record = decode_record(&row)?;
        if record.state != DurableBroadcastState::Failed
            || record.specification.worker != worker
            || record
                .runtime
                .as_ref()
                .and_then(|runtime| runtime.grant_generation)
                != grant_generation
        {
            transaction
                .commit()
                .await
                .map_err(|_| BroadcastCommandError::Unavailable)?;
            return Ok(false);
        }
        let now = postgres_now(&mut transaction).await?;
        sqlx::query(
            "UPDATE broadcasts SET runtime = NULL, updated_at = $1 \
             WHERE broadcast_id = $2::uuid",
        )
        .bind(now)
        .bind(broadcast_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| BroadcastCommandError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| BroadcastCommandError::Unavailable)?;
        Ok(true)
    }
}

fn validate_specification(
    specification: &DurableBroadcastSpec,
) -> Result<(), BroadcastCommandError> {
    validate_broadcast_id(&specification.broadcast_id)?;
    if specification.expires_at <= Utc::now()
        || specification
            .language
            .as_ref()
            .is_some_and(|language| language.len() > 64 || language.chars().any(char::is_control))
    {
        return Err(BroadcastCommandError::InvalidData);
    }
    Ok(())
}

fn validate_broadcast_id(value: &str) -> Result<(), BroadcastCommandError> {
    match Uuid::parse_str(value) {
        Ok(id) if !id.is_nil() => Ok(()),
        _ => Err(BroadcastCommandError::InvalidData),
    }
}

async fn postgres_now(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<DateTime<Utc>, BroadcastCommandError> {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **transaction)
        .await
        .map_err(|_| BroadcastCommandError::Unavailable)
}

fn decode_record(
    row: &sqlx::postgres::PgRow,
) -> Result<DurableBroadcastRecord, BroadcastCommandError> {
    let specification: String = row
        .try_get("specification")
        .map_err(|_| BroadcastCommandError::InvalidData)?;
    let runtime: Option<String> = row
        .try_get("runtime")
        .map_err(|_| BroadcastCommandError::InvalidData)?;
    Ok(DurableBroadcastRecord {
        specification: serde_json::from_str(&specification)
            .map_err(|_| BroadcastCommandError::InvalidData)?,
        state: DurableBroadcastState::parse(
            row.try_get("state")
                .map_err(|_| BroadcastCommandError::InvalidData)?,
        )?,
        runtime: runtime
            .map(|value| serde_json::from_str(&value))
            .transpose()
            .map_err(|_| BroadcastCommandError::InvalidData)?,
        failure_code: row
            .try_get("failure_code")
            .map_err(|_| BroadcastCommandError::InvalidData)?,
        created_at: row
            .try_get("created_at")
            .map_err(|_| BroadcastCommandError::InvalidData)?,
        updated_at: row
            .try_get("updated_at")
            .map_err(|_| BroadcastCommandError::InvalidData)?,
    })
}
