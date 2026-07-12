//! Transactional SQLite and PostgreSQL call repositories.
//!
//! SQL rows are authoritative. Each database transaction locks a durable
//! repository epoch, reconstructs the backend-neutral primary-row snapshot,
//! applies one deterministic [`MemoryRepository`] transition, and writes the
//! resulting normalized rows before advancing the epoch. SQLite uses
//! `BEGIN IMMEDIATE`; PostgreSQL uses `SELECT .. FOR UPDATE`. Consequently,
//! independent processes cannot race capacity, idempotency, attachment, or
//! work claims even though transition validation is shared with the memory
//! backend. Mutations diff the before/after primary-row snapshots and issue
//! targeted upserts or expiry deletes; retained history is never rewritten.
//! The global mutation lock is a Gate 11 concurrency optimization seam, not a
//! correctness dependency outside the database. Read methods use consistent
//! read-only transactions and never acquire the epoch write lock, rewrite
//! rows, or advance the epoch.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rvoip_core::ids::ConnectionId;
use sqlx::migrate::Migrator;
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use sqlx::{Executor, Row};

use crate::call_engine::{
    AggregateVersion, AttachmentCandidate, AttachmentConsume, AttachmentLookup,
    BindProviderReference, CallAggregate, CallId, CallRepository, ClaimGeneration, ClaimedDeadline,
    ClaimedOutbox, ClaimedProviderEvent, CommandCommit, CommandCommitOutcome, ConnectionBinding,
    ConsumedAttachment, CreateCall, CreateCallOutcome, DeadlineState, EffectId, LegId,
    OutboxCompletion, OutboxRecord, OutboxState, ProviderEventCommit, ProviderEventCommitOutcome,
    ProviderEventEnvelope, ProviderEventInput, ProviderEventOutcome, ProviderEventState,
    RegisterWorker, RepositoryError, RestartClaim, StoredCall, TenantId,
    TerminalProviderEventAcknowledge, TerminalProviderEventAcknowledgeOutcome, WorkerAssignment,
    WorkerId, WorkerLease, WorkerSnapshot,
};
use crate::call_service::{
    CallServiceRepository, ClaimedControlEffect, CompletedServiceEffect, ControlCommandOutcome,
    ControlCommandTransaction, ControlIntent, ControlOutboxRecord, EffectResultOutcome,
    EffectResultReconciliation, ExternalReferenceValue, LegEndpointConfig,
    OperationIdempotencyReceipt, OutboundConnectionBind, OutboundConnectionBindOutcome,
    ServiceCommandOutcome, ServiceCommandTransaction, ServiceCreateOutcome,
    ServiceCreateTransaction, ServiceEffectPayload, ServiceEffectResult, ServiceOperationKind,
    StoredExternalReference, StoredServiceCall, StoredServiceEffectPayload,
};

use super::memory::{
    AttachmentRow, ControlRetirementReceipt, MemoryRepository, MemoryStateSnapshot,
    PersistedCommandRow, PersistedControlCommandRow, PersistedControlSequenceRow,
    PersistedExecutionPlanRow, PersistedIdempotencyRow, PersistedOutboundBindingRow,
    PersistedProviderCompletionRow, PersistedProviderReferenceRow, PersistedReconciliationRow,
    PersistedServiceCommandRow, ProviderCompletionRow, RetiredOperationClaim,
    RetiredOperationReceiptKind,
};

static SQLITE_MIGRATOR: Migrator = sqlx::migrate!("./migrations/sqlite");
static POSTGRES_MIGRATOR: Migrator = sqlx::migrate!("./migrations/postgres");

type RepositoryFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, RepositoryError>> + Send + 'a>>;

#[derive(Clone)]
enum SqlBackend {
    Sqlite(SqlitePool),
    Postgres(PgPool),
}

#[derive(Clone)]
struct SqlRepository {
    backend: SqlBackend,
}

#[derive(Default)]
struct ServiceSnapshotRows {
    execution_plans: Vec<PersistedExecutionPlanRow>,
    service_effect_payloads: Vec<StoredServiceEffectPayload>,
    service_command_results: Vec<PersistedServiceCommandRow>,
    control_sequences: Vec<PersistedControlSequenceRow>,
    control_commands: Vec<PersistedControlCommandRow>,
    control_outbox: Vec<ControlOutboxRecord>,
    outbound_binding_results: Vec<PersistedOutboundBindingRow>,
    external_references: Vec<StoredExternalReference>,
    reconciliation_results: Vec<PersistedReconciliationRow>,
    retired_operation_claims: Vec<RetiredOperationClaim>,
    control_retirements: Vec<ControlRetirementReceipt>,
}

/// Safe retention threshold for terminal call history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqlRetentionPolicy {
    /// Minimum age of a released terminal aggregate before archival eligibility.
    pub terminal_history_age: Duration,
}

impl SqlRetentionPolicy {
    /// Constructs a policy. A zero age is useful only for deterministic tests.
    #[must_use]
    pub const fn new(terminal_history_age: Duration) -> Self {
        Self {
            terminal_history_age,
        }
    }
}

/// Fenced terminal history that is safe to hand to an external archive sink.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalHistoryCandidate {
    /// Tenant owning the history.
    pub tenant_id: TenantId,
    /// Terminal call identity.
    pub call_id: CallId,
    /// Exact aggregate version used as an archive/purge guard.
    pub aggregate_version: AggregateVersion,
    /// Last aggregate update.
    pub terminal_at: DateTime<Utc>,
    /// Commands retained for this call.
    pub command_count: usize,
    /// Completed effects retained for this call.
    pub outbox_count: usize,
    /// Applied provider events retained for this call.
    pub provider_event_count: usize,
}

/// Durable standalone repository backed by SQLite.
#[derive(Clone)]
pub struct SqliteRepository {
    inner: SqlRepository,
}

impl std::fmt::Debug for SqliteRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqliteRepository")
            .finish_non_exhaustive()
    }
}

impl SqliteRepository {
    /// Opens (and creates when absent) a SQLite database and applies embedded migrations.
    pub async fn connect(database_url: &str) -> Result<Self, RepositoryError> {
        let options = SqliteConnectOptions::from_str(database_url)
            .map_err(|_| RepositoryError::Unavailable)?
            .create_if_missing(true)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(30));
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .after_connect(|connection, _| {
                Box::pin(async move {
                    connection.execute("PRAGMA foreign_keys = ON").await?;
                    Ok(())
                })
            })
            .connect_with(options)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        SQLITE_MIGRATOR
            .run(&pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        Ok(Self {
            inner: SqlRepository {
                backend: SqlBackend::Sqlite(pool),
            },
        })
    }

    /// Exposes the pool for health checks and migration-drift diagnostics.
    #[must_use]
    pub fn pool(&self) -> &SqlitePool {
        let SqlBackend::Sqlite(pool) = &self.inner.backend else {
            unreachable!("sqlite repository always owns a sqlite pool")
        };
        pool
    }

    /// Lists released terminal histories whose durable work is fully settled.
    pub async fn retention_candidates(
        &self,
        policy: SqlRetentionPolicy,
        now: DateTime<Utc>,
        limit: usize,
    ) -> Result<Vec<TerminalHistoryCandidate>, RepositoryError> {
        self.inner.retention_candidates(policy, now, limit).await
    }
}

/// Durable clustered repository backed by PostgreSQL.
#[derive(Clone)]
pub struct PostgresRepository {
    inner: SqlRepository,
}

impl std::fmt::Debug for PostgresRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresRepository")
            .finish_non_exhaustive()
    }
}

impl PostgresRepository {
    /// Connects to PostgreSQL and applies embedded migrations.
    ///
    /// The URL must name a Bridgefu-owned database; migrations and repository
    /// tables are intentionally not schema-qualified.
    pub async fn connect(database_url: &str) -> Result<Self, RepositoryError> {
        let pool = PgPoolOptions::new()
            .max_connections(16)
            .connect(database_url)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        POSTGRES_MIGRATOR
            .run(&pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        Ok(Self {
            inner: SqlRepository {
                backend: SqlBackend::Postgres(pool),
            },
        })
    }

    /// Exposes the pool for health checks and migration-drift diagnostics.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        let SqlBackend::Postgres(pool) = &self.inner.backend else {
            unreachable!("postgres repository always owns a postgres pool")
        };
        pool
    }

    /// Lists released terminal histories whose durable work is fully settled.
    pub async fn retention_candidates(
        &self,
        policy: SqlRetentionPolicy,
        now: DateTime<Utc>,
        limit: usize,
    ) -> Result<Vec<TerminalHistoryCandidate>, RepositoryError> {
        self.inner.retention_candidates(policy, now, limit).await
    }
}

impl SqlRepository {
    async fn transaction<T, F>(&self, operation: F) -> Result<T, RepositoryError>
    where
        T: Send,
        F: for<'a> FnOnce(&'a MemoryRepository) -> RepositoryFuture<'a, T> + Send,
    {
        match &self.backend {
            SqlBackend::Sqlite(pool) => sqlite_transaction(pool, operation).await,
            SqlBackend::Postgres(pool) => postgres_transaction(pool, operation).await,
        }
    }

    async fn read<T, F>(&self, operation: F) -> Result<T, RepositoryError>
    where
        T: Send,
        F: for<'a> FnOnce(&'a MemoryRepository) -> RepositoryFuture<'a, T> + Send,
    {
        match &self.backend {
            SqlBackend::Sqlite(pool) => sqlite_read(pool, operation).await,
            SqlBackend::Postgres(pool) => postgres_read(pool, operation).await,
        }
    }

    async fn retention_candidates(
        &self,
        policy: SqlRetentionPolicy,
        now: DateTime<Utc>,
        limit: usize,
    ) -> Result<Vec<TerminalHistoryCandidate>, RepositoryError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let snapshot = self
            .read(|repository| Box::pin(async move { repository.snapshot() }))
            .await?;
        retention_candidates_from_snapshot(&snapshot, policy, now, limit)
    }
}

fn retention_candidates_from_snapshot(
    snapshot: &MemoryStateSnapshot,
    policy: SqlRetentionPolicy,
    now: DateTime<Utc>,
    limit: usize,
) -> Result<Vec<TerminalHistoryCandidate>, RepositoryError> {
    let age = chrono::Duration::from_std(policy.terminal_history_age)
        .map_err(|_| RepositoryError::InvalidInput("terminal retention age is too large"))?;
    let cutoff = now
        .checked_sub_signed(age)
        .ok_or(RepositoryError::InvalidInput(
            "terminal retention cutoff overflow",
        ))?;
    let mut candidates = Vec::new();
    for call in &snapshot.calls {
        let call_id = call.aggregate.id();
        if !call.aggregate.state().is_terminal()
            || call.assignment.released_at.is_none()
            || call.aggregate.updated_at() > cutoff
            || snapshot
                .idempotency
                .iter()
                .any(|row| row.row.call_id == call_id && row.row.expires_at > now)
            || snapshot.attachments.iter().any(|row| {
                row.call_id == call_id
                    && row.consumed_at.is_none()
                    && row.revoked_at.is_none()
                    && row.expires_at > now
            })
            || snapshot.outbox.iter().any(|row| {
                row.call_id == call_id
                    && !matches!(
                        row.state,
                        OutboxState::Succeeded { .. } | OutboxState::Failed { .. }
                    )
            })
            || snapshot.control_outbox.iter().any(|row| {
                row.call_id == call_id
                    && !matches!(
                        row.state,
                        OutboxState::Succeeded { .. } | OutboxState::Failed { .. }
                    )
            })
            || snapshot.deadlines.iter().any(|row| {
                row.call_id == call_id
                    && !matches!(
                        row.state,
                        DeadlineState::Cancelled { .. } | DeadlineState::Completed { .. }
                    )
            })
            || snapshot.provider_events.iter().any(|event| {
                event
                    .target
                    .as_ref()
                    .is_some_and(|target| target.call_id == call_id)
                    && !matches!(event.state, ProviderEventState::Applied)
            })
        {
            continue;
        }
        candidates.push(TerminalHistoryCandidate {
            tenant_id: call.aggregate.tenant_id().clone(),
            call_id,
            aggregate_version: call.aggregate.version(),
            terminal_at: call.aggregate.updated_at(),
            command_count: snapshot
                .commands
                .iter()
                .filter(|row| row.command.call_id == call_id)
                .count(),
            outbox_count: snapshot
                .outbox
                .iter()
                .filter(|row| row.call_id == call_id)
                .count(),
            provider_event_count: snapshot
                .provider_events
                .iter()
                .filter(|event| {
                    event
                        .target
                        .as_ref()
                        .is_some_and(|target| target.call_id == call_id)
                })
                .count(),
        });
    }
    candidates.sort_by_key(|candidate| (candidate.terminal_at, candidate.call_id));
    candidates.truncate(limit);
    Ok(candidates)
}

async fn sqlite_read<T, F>(pool: &SqlitePool, operation: F) -> Result<T, RepositoryError>
where
    T: Send,
    F: for<'a> FnOnce(&'a MemoryRepository) -> RepositoryFuture<'a, T> + Send,
{
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| RepositoryError::Unavailable)?;
    let result = async {
        let snapshot = load_sqlite_snapshot(&mut transaction).await?;
        let memory = MemoryRepository::from_snapshot(snapshot)?;
        operation(&memory).await
    }
    .await;
    match result {
        Ok(value) => {
            transaction
                .commit()
                .await
                .map_err(|_| RepositoryError::Unavailable)?;
            Ok(value)
        }
        Err(error) => {
            let _ = transaction.rollback().await;
            Err(error)
        }
    }
}

async fn postgres_read<T, F>(pool: &PgPool, operation: F) -> Result<T, RepositoryError>
where
    T: Send,
    F: for<'a> FnOnce(&'a MemoryRepository) -> RepositoryFuture<'a, T> + Send,
{
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| RepositoryError::Unavailable)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await
        .map_err(database_error)?;
    let snapshot = load_postgres_snapshot(&mut transaction).await?;
    let memory = MemoryRepository::from_snapshot(snapshot)?;
    let result = operation(&memory).await;
    match result {
        Ok(value) => {
            transaction
                .commit()
                .await
                .map_err(|_| RepositoryError::Unavailable)?;
            Ok(value)
        }
        Err(error) => {
            transaction
                .rollback()
                .await
                .map_err(|_| RepositoryError::Unavailable)?;
            Err(error)
        }
    }
}

async fn sqlite_transaction<T, F>(pool: &SqlitePool, operation: F) -> Result<T, RepositoryError>
where
    T: Send,
    F: for<'a> FnOnce(&'a MemoryRepository) -> RepositoryFuture<'a, T> + Send,
{
    let mut transaction = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| RepositoryError::Unavailable)?;

    let result = async {
        let before = load_sqlite_snapshot(&mut transaction).await?;
        let memory = MemoryRepository::from_snapshot(before.clone())?;
        let result = operation(&memory).await?;
        let after = memory.snapshot()?;
        persist_sqlite_delta(&mut transaction, &before, &after).await?;
        sqlx::query(
            "UPDATE repository_metadata SET epoch = epoch + 1, provider_receipt_sequence = ? WHERE singleton = 1",
        )
        .bind(
            after
                .provider_receipt_sequence
                .map(|sequence| sequence.as_i64()),
        )
        .execute(&mut *transaction)
        .await
        .map_err(database_error)?;
        Ok(result)
    }
    .await;

    match result {
        Ok(value) => {
            transaction
                .commit()
                .await
                .map_err(|_| RepositoryError::Unavailable)?;
            Ok(value)
        }
        Err(error) => {
            let _ = transaction.rollback().await;
            Err(error)
        }
    }
}

async fn postgres_transaction<T, F>(pool: &PgPool, operation: F) -> Result<T, RepositoryError>
where
    T: Send,
    F: for<'a> FnOnce(&'a MemoryRepository) -> RepositoryFuture<'a, T> + Send,
{
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| RepositoryError::Unavailable)?;
    sqlx::query("SELECT epoch FROM repository_metadata WHERE singleton = TRUE FOR UPDATE")
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| RepositoryError::Unavailable)?;
    let before = load_postgres_snapshot(&mut transaction).await?;
    let memory = MemoryRepository::from_snapshot(before.clone())?;
    let result = operation(&memory).await?;
    let after = memory.snapshot()?;
    persist_postgres_delta(&mut transaction, &before, &after).await?;
    sqlx::query(
        "UPDATE repository_metadata SET epoch = epoch + 1, provider_receipt_sequence = $1 WHERE singleton = TRUE",
    )
    .bind(
        after
            .provider_receipt_sequence
            .map(|sequence| sequence.as_i64()),
    )
    .execute(&mut *transaction)
    .await
    .map_err(database_error)?;
    transaction
        .commit()
        .await
        .map_err(|_| RepositoryError::Unavailable)?;
    Ok(result)
}

fn database_error(_error: sqlx::Error) -> RepositoryError {
    RepositoryError::Unavailable
}

fn encode<T: serde::Serialize>(value: &T) -> Result<String, RepositoryError> {
    serde_json::to_string(value).map_err(|_| RepositoryError::Unavailable)
}

fn decode<T: serde::de::DeserializeOwned>(value: &str) -> Result<T, RepositoryError> {
    serde_json::from_str(value).map_err(|_| RepositoryError::Unavailable)
}

fn parse_call_id(value: &str) -> Result<CallId, RepositoryError> {
    CallId::from_str(value).map_err(|_| RepositoryError::Unavailable)
}

fn parse_sqlite_time(value: &str) -> Result<DateTime<Utc>, RepositoryError> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| RepositoryError::Unavailable)
}

fn state_name<T: serde::Serialize>(value: &T) -> Result<String, RepositoryError> {
    let value = serde_json::to_value(value).map_err(|_| RepositoryError::Unavailable)?;
    value
        .as_str()
        .or_else(|| value.get("state").and_then(serde_json::Value::as_str))
        .map(ToOwned::to_owned)
        .ok_or(RepositoryError::Unavailable)
}

async fn load_sqlite_snapshot(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<MemoryStateSnapshot, RepositoryError> {
    let metadata = sqlx::query(
        "SELECT provider_receipt_sequence FROM repository_metadata WHERE singleton = 1",
    )
    .fetch_one(&mut **transaction)
    .await
    .map_err(database_error)?;
    let receipt_sequence = metadata
        .try_get::<Option<i64>, _>("provider_receipt_sequence")
        .map_err(database_error)?;
    let provider_receipt_sequence = decode_optional_receipt(receipt_sequence)?;

    let workers = load_sqlite_workers(transaction).await?;
    let calls = load_sqlite_calls(transaction).await?;
    let service_managed_calls = load_sqlite_service_managed_calls(transaction).await?;
    let commands = load_sqlite_commands(transaction).await?;
    let idempotency = load_sqlite_idempotency(transaction).await?;
    let attachments = load_sqlite_attachments(transaction).await?;
    let provider_events = load_sqlite_provider_events(transaction).await?;
    let provider_references = load_sqlite_provider_references(transaction).await?;
    let provider_completions = load_sqlite_provider_completions(transaction).await?;
    let used_connection_ids =
        sqlx::query("SELECT connection_id FROM used_connection_ids ORDER BY connection_id")
            .fetch_all(&mut **transaction)
            .await
            .map_err(database_error)?
            .into_iter()
            .map(|row| {
                row.try_get::<String, _>("connection_id")
                    .map(ConnectionId::from_string)
                    .map_err(database_error)
            })
            .collect::<Result<Vec<_>, RepositoryError>>()?;
    let outbox = load_sqlite_outbox(transaction).await?;
    let deadlines = load_sqlite_deadlines(transaction).await?;
    let service = load_sqlite_service_rows(transaction).await?;

    Ok(MemoryStateSnapshot {
        workers,
        calls,
        commands,
        idempotency,
        attachments,
        provider_events,
        provider_references,
        provider_completions,
        provider_receipt_sequence,
        used_connection_ids,
        outbox,
        deadlines,
        service_managed_calls,
        execution_plans: service.execution_plans,
        service_effect_payloads: service.service_effect_payloads,
        service_command_results: service.service_command_results,
        control_sequences: service.control_sequences,
        control_commands: service.control_commands,
        control_outbox: service.control_outbox,
        outbound_binding_results: service.outbound_binding_results,
        external_references: service.external_references,
        reconciliation_results: service.reconciliation_results,
        retired_operation_claims: service.retired_operation_claims,
        control_retirements: service.control_retirements,
    })
}

async fn load_postgres_snapshot(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<MemoryStateSnapshot, RepositoryError> {
    let metadata = sqlx::query(
        "SELECT provider_receipt_sequence FROM repository_metadata WHERE singleton = TRUE",
    )
    .fetch_one(&mut **transaction)
    .await
    .map_err(database_error)?;
    let receipt_sequence = metadata
        .try_get::<Option<i64>, _>("provider_receipt_sequence")
        .map_err(database_error)?;
    let provider_receipt_sequence = decode_optional_receipt(receipt_sequence)?;

    let workers = load_postgres_workers(transaction).await?;
    let calls = load_postgres_calls(transaction).await?;
    let service_managed_calls = load_postgres_service_managed_calls(transaction).await?;
    let commands = load_postgres_commands(transaction).await?;
    let idempotency = load_postgres_idempotency(transaction).await?;
    let attachments = load_postgres_attachments(transaction).await?;
    let provider_events = load_postgres_provider_events(transaction).await?;
    let provider_references = load_postgres_provider_references(transaction).await?;
    let provider_completions = load_postgres_provider_completions(transaction).await?;
    let used_connection_ids =
        sqlx::query("SELECT connection_id FROM used_connection_ids ORDER BY connection_id")
            .fetch_all(&mut **transaction)
            .await
            .map_err(database_error)?
            .into_iter()
            .map(|row| {
                row.try_get::<String, _>("connection_id")
                    .map(ConnectionId::from_string)
                    .map_err(database_error)
            })
            .collect::<Result<Vec<_>, RepositoryError>>()?;
    let outbox = load_postgres_outbox(transaction).await?;
    let deadlines = load_postgres_deadlines(transaction).await?;
    let service = load_postgres_service_rows(transaction).await?;

    Ok(MemoryStateSnapshot {
        workers,
        calls,
        commands,
        idempotency,
        attachments,
        provider_events,
        provider_references,
        provider_completions,
        provider_receipt_sequence,
        used_connection_ids,
        outbox,
        deadlines,
        service_managed_calls,
        execution_plans: service.execution_plans,
        service_effect_payloads: service.service_effect_payloads,
        service_command_results: service.service_command_results,
        control_sequences: service.control_sequences,
        control_commands: service.control_commands,
        control_outbox: service.control_outbox,
        outbound_binding_results: service.outbound_binding_results,
        external_references: service.external_references,
        reconciliation_results: service.reconciliation_results,
        retired_operation_claims: service.retired_operation_claims,
        control_retirements: service.control_retirements,
    })
}

async fn load_sqlite_service_managed_calls(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<Vec<CallId>, RepositoryError> {
    sqlx::query("SELECT call_id FROM calls WHERE service_managed = 1 ORDER BY call_id")
        .fetch_all(&mut **transaction)
        .await
        .map_err(database_error)?
        .into_iter()
        .map(|row| {
            parse_call_id(
                &row.try_get::<String, _>("call_id")
                    .map_err(database_error)?,
            )
        })
        .collect()
}

async fn load_postgres_service_managed_calls(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<Vec<CallId>, RepositoryError> {
    sqlx::query(
        "SELECT call_id::text AS call_id FROM calls WHERE service_managed = TRUE ORDER BY call_id",
    )
    .fetch_all(&mut **transaction)
    .await
    .map_err(database_error)?
    .into_iter()
    .map(|row| {
        parse_call_id(
            &row.try_get::<String, _>("call_id")
                .map_err(database_error)?,
        )
    })
    .collect()
}

fn decode_optional_receipt(
    value: Option<i64>,
) -> Result<Option<crate::call_engine::ProviderReceiptSequence>, RepositoryError> {
    value
        .map(|value| {
            serde_json::from_value(serde_json::json!(value))
                .map_err(|_| RepositoryError::Unavailable)
        })
        .transpose()
}

fn invalid_if(condition: bool) -> Result<(), RepositoryError> {
    if condition {
        Err(RepositoryError::Unavailable)
    } else {
        Ok(())
    }
}

fn validate_worker_columns(
    worker: &WorkerSnapshot,
    worker_id: &str,
    fence: i64,
    max_calls: i64,
    reserved_calls: i64,
    draining: bool,
    updated_at: DateTime<Utc>,
) -> Result<(), RepositoryError> {
    invalid_if(
        worker.lease.worker_id.to_string() != worker_id
            || worker.lease.fence.as_i64() != fence
            || i64::try_from(worker.max_calls).ok() != Some(max_calls)
            || i64::try_from(worker.reserved_calls).ok() != Some(reserved_calls)
            || worker.draining != draining
            || worker.updated_at != updated_at,
    )
}

fn validate_command_columns(
    row: &PersistedCommandRow,
    command_id: &str,
    tenant_id: &str,
    call_id: &str,
    observed_version: i64,
    result_version: i64,
    recorded_at: DateTime<Utc>,
) -> Result<(), RepositoryError> {
    let command = &row.command;
    invalid_if(
        command.command_id.to_string() != command_id
            || command.tenant_id.as_str() != tenant_id
            || command.call_id.to_string() != call_id
            || command.observed_version.as_i64() != observed_version
            || command.result_version.as_i64() != result_version
            || command.recorded_at != recorded_at,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_idempotency_columns(
    persisted: &PersistedIdempotencyRow,
    tenant_id: &str,
    key_digest: &[u8],
    request_digest: &[u8],
    call_id: &str,
    expires_at: DateTime<Utc>,
    receipt_kind: &str,
    operation_kind: &str,
) -> Result<(), RepositoryError> {
    let expected = idempotency_receipt_columns(&persisted.row.receipt);
    invalid_if(
        persisted.tenant_id.as_str() != tenant_id
            || persisted.key_digest.expose_bytes().as_slice() != key_digest
            || persisted.row.request_digest.expose_bytes().as_slice() != request_digest
            || persisted.row.call_id.to_string() != call_id
            || persisted.row.expires_at != expires_at
            || expected != (receipt_kind, operation_kind),
    )
}

fn service_operation_kind(operation: ServiceOperationKind) -> &'static str {
    match operation {
        ServiceOperationKind::CreateCall => "create_call",
        ServiceOperationKind::HangupCall => "hangup_call",
        ServiceOperationKind::TransferCall => "transfer_call",
        ServiceOperationKind::DtmfCall => "dtmf_call",
    }
}

fn idempotency_receipt_columns(
    receipt: &OperationIdempotencyReceipt,
) -> (&'static str, &'static str) {
    match receipt {
        OperationIdempotencyReceipt::CreateCall => ("create_call", "create_call"),
        OperationIdempotencyReceipt::ServiceCommand { operation, .. } => {
            ("service_command", service_operation_kind(*operation))
        }
        OperationIdempotencyReceipt::ControlCommand { operation, .. } => {
            ("control_command", service_operation_kind(*operation))
        }
    }
}

fn retired_receipt_kind(kind: RetiredOperationReceiptKind) -> &'static str {
    match kind {
        RetiredOperationReceiptKind::ServiceCommand => "service_command",
        RetiredOperationReceiptKind::ControlCommand => "control_command",
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_retired_operation_claim_columns(
    retired: &RetiredOperationClaim,
    command_id: &str,
    receipt_kind: &str,
    tenant_id: &str,
    key_digest: &[u8],
    request_digest: &[u8],
    call_id: &str,
    operation_kind: &str,
    expires_at: DateTime<Utc>,
    retired_at: DateTime<Utc>,
) -> Result<(), RepositoryError> {
    invalid_if(
        retired.command_id.to_string() != command_id
            || retired_receipt_kind(retired.receipt_kind) != receipt_kind
            || retired.tenant_id.as_str() != tenant_id
            || retired.key_digest.expose_bytes().as_slice() != key_digest
            || retired.request_digest.expose_bytes().as_slice() != request_digest
            || retired.call_id.to_string() != call_id
            || service_operation_kind(retired.operation) != operation_kind
            || retired.expires_at != expires_at
            || retired.retired_at != retired_at,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_control_retirement_columns(
    receipt: &ControlRetirementReceipt,
    effect_id: &str,
    command_id: &str,
    tenant_id: &str,
    call_id: &str,
    leg_id: &str,
    binding_generation: i64,
    retired_at: DateTime<Utc>,
    failure_code: &str,
) -> Result<(), RepositoryError> {
    invalid_if(
        receipt.effect_id.to_string() != effect_id
            || receipt.command_id.to_string() != command_id
            || receipt.tenant_id.as_str() != tenant_id
            || receipt.call_id.to_string() != call_id
            || receipt.leg_id.to_string() != leg_id
            || receipt.binding_generation.as_i64() != binding_generation
            || receipt.retired_at != retired_at
            || receipt.failure.code() != failure_code,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_attachment_columns(
    row: &AttachmentRow,
    token_digest: &[u8],
    attachment_id: &str,
    tenant_id: &str,
    call_id: &str,
    leg_id: &str,
    binding_generation: i64,
    worker_id: &str,
    worker_fence: i64,
    expires_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
) -> Result<(), RepositoryError> {
    invalid_if(
        row.token_digest.expose_bytes().as_slice() != token_digest
            || row.attachment_id.to_string() != attachment_id
            || row.tenant_id.as_str() != tenant_id
            || row.call_id.to_string() != call_id
            || row.leg_id.to_string() != leg_id
            || row.binding_generation.as_i64() != binding_generation
            || row.worker.worker_id.to_string() != worker_id
            || row.worker.fence.as_i64() != worker_fence
            || row.expires_at != expires_at
            || row.consumed_at != consumed_at
            || row.revoked_at != revoked_at,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_provider_event_columns(
    event: &ProviderEventEnvelope,
    account: &str,
    event_digest: &[u8],
    payload_digest: &[u8],
    provider_call_id: &str,
    receipt_sequence: i64,
    received_at: DateTime<Utc>,
    state: &str,
) -> Result<(), RepositoryError> {
    invalid_if(
        event.account.as_str() != account
            || event.event_digest.expose_bytes().as_slice() != event_digest
            || event.payload_digest.expose_bytes().as_slice() != payload_digest
            || event.provider_call_id.expose_secret() != provider_call_id
            || event.receipt_sequence.as_i64() != receipt_sequence
            || event.received_at != received_at
            || state_name(&event.state)? != state,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_provider_reference_columns(
    persisted: &PersistedProviderReferenceRow,
    account: &str,
    provider_call_id: &str,
    tenant_id: &str,
    call_id: &str,
    leg_id: &str,
    bound_at: DateTime<Utc>,
) -> Result<(), RepositoryError> {
    invalid_if(
        persisted.account.as_str() != account
            || persisted.provider_call_id.expose_secret() != provider_call_id
            || persisted.row.target.tenant_id.as_str() != tenant_id
            || persisted.row.target.call_id.to_string() != call_id
            || persisted.row.target.leg_id.to_string() != leg_id
            || persisted.row.bound_at != bound_at,
    )
}

fn provider_completion_kind(row: &ProviderCompletionRow) -> &'static str {
    match row {
        ProviderCompletionRow::Command { .. } => "command",
        ProviderCompletionRow::TerminalAcknowledgement { .. } => "terminal_acknowledgement",
    }
}

fn validate_provider_completion_columns(
    persisted: &PersistedProviderCompletionRow,
    account: &str,
    event_digest: &[u8],
    completion_kind: &str,
) -> Result<(), RepositoryError> {
    invalid_if(
        persisted.account.as_str() != account
            || persisted.event_digest.expose_bytes().as_slice() != event_digest
            || provider_completion_kind(&persisted.row) != completion_kind,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_outbox_columns(
    record: &OutboxRecord,
    effect_id: &str,
    command_id: &str,
    ordinal: i64,
    tenant_id: &str,
    call_id: &str,
    aggregate_version: i64,
    worker_id: &str,
    worker_fence: i64,
    available_at: DateTime<Utc>,
    state: &str,
) -> Result<(), RepositoryError> {
    invalid_if(
        record.effect_id.to_string() != effect_id
            || record.command_id.to_string() != command_id
            || i64::from(record.ordinal) != ordinal
            || record.tenant_id.as_str() != tenant_id
            || record.call_id.to_string() != call_id
            || record.aggregate_version.as_i64() != aggregate_version
            || record.worker.worker_id.to_string() != worker_id
            || record.worker.fence.as_i64() != worker_fence
            || record.available_at != available_at
            || state_name(&record.state)? != state,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_deadline_columns(
    record: &crate::call_engine::DeadlineRecord,
    call_id: &str,
    kind: &str,
    generation: i64,
    tenant_id: &str,
    due_at: DateTime<Utc>,
    state: &str,
) -> Result<(), RepositoryError> {
    invalid_if(
        record.call_id.to_string() != call_id
            || state_name(&record.kind)? != kind
            || record.generation.as_i64() != generation
            || record.tenant_id.as_str() != tenant_id
            || record.due_at != due_at
            || state_name(&record.state)? != state,
    )
}

fn endpoint_kind(endpoint: &LegEndpointConfig) -> &'static str {
    match endpoint {
        LegEndpointConfig::Sip(_) => "sip",
        LegEndpointConfig::WebRtc(_) => "web_rtc",
        LegEndpointConfig::Whip(_) => "whip",
        LegEndpointConfig::Whep(_) => "whep",
        LegEndpointConfig::AmazonConnect(_) => "amazon_connect",
        LegEndpointConfig::Provider(_) => "provider",
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_execution_plan_columns(
    persisted: &PersistedExecutionPlanRow,
    call_id: &str,
    plan_version: i64,
    first_leg_id: &str,
    first_endpoint_kind: &str,
    second_leg_id: &str,
    second_endpoint_kind: &str,
) -> Result<(), RepositoryError> {
    invalid_if(
        persisted.call_id.to_string() != call_id
            || i64::from(persisted.plan.version) != plan_version
            || persisted.plan.legs[0].leg_id.to_string() != first_leg_id
            || endpoint_kind(&persisted.plan.legs[0].endpoint) != first_endpoint_kind
            || persisted.plan.legs[1].leg_id.to_string() != second_leg_id
            || endpoint_kind(&persisted.plan.legs[1].endpoint) != second_endpoint_kind,
    )
}

fn validate_service_command_columns(
    persisted: &PersistedServiceCommandRow,
    command_id: &str,
    tenant_id: &str,
    call_id: &str,
    recorded_at: DateTime<Utc>,
) -> Result<(), RepositoryError> {
    let command = &persisted.result.view.command.command;
    invalid_if(
        persisted.command_id.to_string() != command_id
            || command.command_id != persisted.command_id
            || command.tenant_id.as_str() != tenant_id
            || command.call_id.to_string() != call_id
            || command.recorded_at != recorded_at,
    )
}

fn service_payload_kind(payload: &ServiceEffectPayload) -> &'static str {
    match payload {
        ServiceEffectPayload::Transfer { .. } => "transfer",
    }
}

fn validate_service_payload_columns(
    payload: &StoredServiceEffectPayload,
    effect_id: &str,
    command_id: &str,
    ordinal: i64,
    payload_kind: &str,
) -> Result<(), RepositoryError> {
    invalid_if(
        payload.effect_id.to_string() != effect_id
            || payload.command_id.to_string() != command_id
            || i64::from(payload.ordinal) != ordinal
            || service_payload_kind(&payload.payload) != payload_kind,
    )
}

fn validate_control_sequence_columns(
    persisted: &PersistedControlSequenceRow,
    call_id: &str,
    leg_id: &str,
    binding_generation: i64,
    sequence: i64,
) -> Result<(), RepositoryError> {
    invalid_if(
        persisted.call_id.to_string() != call_id
            || persisted.leg_id.to_string() != leg_id
            || persisted.binding_generation.as_i64() != binding_generation
            || persisted.sequence.as_i64() != sequence,
    )
}

fn control_kind(intent: &ControlIntent) -> &'static str {
    match intent {
        ControlIntent::Dtmf { .. } => "dtmf",
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_control_command_columns(
    persisted: &PersistedControlCommandRow,
    command_id: &str,
    tenant_id: &str,
    call_id: &str,
    leg_id: &str,
    binding_generation: i64,
    worker_id: &str,
    worker_fence: i64,
    kind: &str,
    recorded_at: DateTime<Utc>,
    effect_id: &str,
) -> Result<(), RepositoryError> {
    let command = &persisted.result.view.command;
    invalid_if(
        persisted.command_id.to_string() != command_id
            || command.command_id != persisted.command_id
            || command.tenant_id.as_str() != tenant_id
            || command.call_id.to_string() != call_id
            || command.leg_id.to_string() != leg_id
            || command.binding_generation.as_i64() != binding_generation
            || command.worker.worker_id.to_string() != worker_id
            || command.worker.fence.as_i64() != worker_fence
            || control_kind(&command.intent) != kind
            || command.recorded_at != recorded_at
            || persisted.result.view.effect.effect_id.to_string() != effect_id,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_control_outbox_columns(
    record: &ControlOutboxRecord,
    effect_id: &str,
    command_id: &str,
    tenant_id: &str,
    call_id: &str,
    leg_id: &str,
    binding_generation: i64,
    worker_id: &str,
    worker_fence: i64,
    sequence: i64,
    available_at: DateTime<Utc>,
    state: &str,
) -> Result<(), RepositoryError> {
    invalid_if(
        record.effect_id.to_string() != effect_id
            || record.command_id.to_string() != command_id
            || record.tenant_id.as_str() != tenant_id
            || record.call_id.to_string() != call_id
            || record.leg_id.to_string() != leg_id
            || record.binding_generation.as_i64() != binding_generation
            || record.worker.worker_id.to_string() != worker_id
            || record.worker.fence.as_i64() != worker_fence
            || record.sequence.as_i64() != sequence
            || record.available_at != available_at
            || state_name(&record.state)? != state,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_outbound_binding_columns(
    persisted: &PersistedOutboundBindingRow,
    operation_id: &str,
    tenant_id: &str,
    call_id: &str,
    leg_id: &str,
    binding_generation: i64,
    worker_id: &str,
    worker_fence: i64,
    connection_id: &str,
    transport: &str,
    bound_at: DateTime<Utc>,
) -> Result<(), RepositoryError> {
    let request = &persisted.result.request;
    invalid_if(
        persisted.operation_id.to_string() != operation_id
            || request.operation_id != persisted.operation_id
            || request.tenant_id.as_str() != tenant_id
            || request.call_id.to_string() != call_id
            || request.leg_id.to_string() != leg_id
            || request.binding_generation.as_i64() != binding_generation
            || request.worker.worker_id.to_string() != worker_id
            || request.worker.fence.as_i64() != worker_fence
            || request.connection_id.as_str() != connection_id
            || state_name(&request.transport)? != transport
            || request.at != bound_at,
    )
}

fn external_reference_columns(value: &ExternalReferenceValue) -> (&'static str, &str, &str) {
    match value {
        ExternalReferenceValue::ProviderCall {
            account,
            provider_call_id,
        } => (
            "provider_call",
            account.as_str(),
            provider_call_id.expose_secret(),
        ),
        ExternalReferenceValue::Signaling { namespace, value } => {
            ("signaling", namespace.as_str(), value.as_str())
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_external_reference_columns(
    reference: &StoredExternalReference,
    kind: &str,
    namespace: &str,
    value: &str,
    tenant_id: &str,
    call_id: &str,
    leg_id: &str,
    binding_generation: i64,
    effect_id: &str,
    bound_at: DateTime<Utc>,
) -> Result<(), RepositoryError> {
    let expected = external_reference_columns(&reference.value);
    invalid_if(
        expected != (kind, namespace, value)
            || reference.tenant_id.as_str() != tenant_id
            || reference.call_id.to_string() != call_id
            || reference.leg_id.to_string() != leg_id
            || reference.binding_generation.as_i64() != binding_generation
            || reference.effect_id.to_string() != effect_id
            || reference.bound_at != bound_at,
    )
}

fn completed_effect_source(effect: &CompletedServiceEffect) -> &'static str {
    match effect {
        CompletedServiceEffect::Call(_) => "call",
        CompletedServiceEffect::Control(_) => "control",
    }
}

fn service_result_kind(result: &ServiceEffectResult) -> &'static str {
    match result {
        ServiceEffectResult::Succeeded => "succeeded",
        ServiceEffectResult::Failed(_) => "failed",
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_reconciliation_columns(
    persisted: &PersistedReconciliationRow,
    effect_id: &str,
    source: &str,
    tenant_id: &str,
    call_id: &str,
    worker_id: &str,
    worker_fence: i64,
    result_kind: &str,
    reconciled_at: DateTime<Utc>,
) -> Result<(), RepositoryError> {
    let request = &persisted.result.request;
    invalid_if(
        persisted.effect_id.to_string() != effect_id
            || request.effect_id != persisted.effect_id
            || completed_effect_source(&persisted.result.view.effect) != source
            || request.tenant_id.as_str() != tenant_id
            || request.call_id.to_string() != call_id
            || request.worker.worker_id.to_string() != worker_id
            || request.worker.fence.as_i64() != worker_fence
            || service_result_kind(&request.result) != result_kind
            || request.at != reconciled_at,
    )
}

fn sqlite_time(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<DateTime<Utc>, RepositoryError> {
    parse_sqlite_time(&row.try_get::<String, _>(column).map_err(database_error)?)
}

fn sqlite_optional_time(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<Option<DateTime<Utc>>, RepositoryError> {
    row.try_get::<Option<String>, _>(column)
        .map_err(database_error)?
        .map(|value| parse_sqlite_time(&value))
        .transpose()
}

async fn load_sqlite_workers(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<Vec<WorkerSnapshot>, RepositoryError> {
    sqlx::query("SELECT worker_id, fence, max_calls, reserved_calls, draining, updated_at, body FROM workers ORDER BY worker_id")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: WorkerSnapshot = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_worker_columns(&value, &row.try_get::<String, _>("worker_id").map_err(database_error)?, row.try_get("fence").map_err(database_error)?, row.try_get("max_calls").map_err(database_error)?, row.try_get("reserved_calls").map_err(database_error)?, row.try_get("draining").map_err(database_error)?, sqlite_time(&row, "updated_at")?)?;
            Ok(value)
        }).collect()
}

async fn load_sqlite_commands(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<Vec<PersistedCommandRow>, RepositoryError> {
    sqlx::query("SELECT command_id, tenant_id, call_id, observed_version, result_version, recorded_at, body FROM commands ORDER BY command_id")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: PersistedCommandRow = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_command_columns(&value, &row.try_get::<String, _>("command_id").map_err(database_error)?, &row.try_get::<String, _>("tenant_id").map_err(database_error)?, &row.try_get::<String, _>("call_id").map_err(database_error)?, row.try_get("observed_version").map_err(database_error)?, row.try_get("result_version").map_err(database_error)?, sqlite_time(&row, "recorded_at")?)?;
            Ok(value)
        }).collect()
}

async fn load_sqlite_idempotency(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<Vec<PersistedIdempotencyRow>, RepositoryError> {
    sqlx::query("SELECT tenant_id, key_digest, request_digest, call_id, expires_at, receipt_kind, operation_kind, body FROM idempotency ORDER BY tenant_id, key_digest")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: PersistedIdempotencyRow = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_idempotency_columns(&value, &row.try_get::<String, _>("tenant_id").map_err(database_error)?, &row.try_get::<Vec<u8>, _>("key_digest").map_err(database_error)?, &row.try_get::<Vec<u8>, _>("request_digest").map_err(database_error)?, &row.try_get::<String, _>("call_id").map_err(database_error)?, sqlite_time(&row, "expires_at")?, &row.try_get::<String, _>("receipt_kind").map_err(database_error)?, &row.try_get::<String, _>("operation_kind").map_err(database_error)?)?;
            Ok(value)
        }).collect()
}

async fn load_sqlite_attachments(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<Vec<AttachmentRow>, RepositoryError> {
    sqlx::query("SELECT token_digest, attachment_id, tenant_id, call_id, leg_id, binding_generation, worker_id, worker_fence, expires_at, consumed_at, revoked_at, body FROM attachments ORDER BY attachment_id")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: AttachmentRow = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_attachment_columns(&value, &row.try_get::<Vec<u8>, _>("token_digest").map_err(database_error)?, &row.try_get::<String, _>("attachment_id").map_err(database_error)?, &row.try_get::<String, _>("tenant_id").map_err(database_error)?, &row.try_get::<String, _>("call_id").map_err(database_error)?, &row.try_get::<String, _>("leg_id").map_err(database_error)?, row.try_get("binding_generation").map_err(database_error)?, &row.try_get::<String, _>("worker_id").map_err(database_error)?, row.try_get("worker_fence").map_err(database_error)?, sqlite_time(&row, "expires_at")?, sqlite_optional_time(&row, "consumed_at")?, sqlite_optional_time(&row, "revoked_at")?)?;
            Ok(value)
        }).collect()
}

async fn load_sqlite_provider_events(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<Vec<ProviderEventEnvelope>, RepositoryError> {
    sqlx::query("SELECT account_key, event_digest, payload_digest, provider_call_id, receipt_sequence, received_at, event_state, body FROM provider_events ORDER BY receipt_sequence")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: ProviderEventEnvelope = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_provider_event_columns(&value, &row.try_get::<String, _>("account_key").map_err(database_error)?, &row.try_get::<Vec<u8>, _>("event_digest").map_err(database_error)?, &row.try_get::<Vec<u8>, _>("payload_digest").map_err(database_error)?, &row.try_get::<String, _>("provider_call_id").map_err(database_error)?, row.try_get("receipt_sequence").map_err(database_error)?, sqlite_time(&row, "received_at")?, &row.try_get::<String, _>("event_state").map_err(database_error)?)?;
            Ok(value)
        }).collect()
}

async fn load_sqlite_provider_references(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<Vec<PersistedProviderReferenceRow>, RepositoryError> {
    sqlx::query("SELECT account_key, provider_call_id, tenant_id, call_id, leg_id, bound_at, body FROM provider_references ORDER BY account_key, provider_call_id")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: PersistedProviderReferenceRow = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_provider_reference_columns(&value, &row.try_get::<String, _>("account_key").map_err(database_error)?, &row.try_get::<String, _>("provider_call_id").map_err(database_error)?, &row.try_get::<String, _>("tenant_id").map_err(database_error)?, &row.try_get::<String, _>("call_id").map_err(database_error)?, &row.try_get::<String, _>("leg_id").map_err(database_error)?, sqlite_time(&row, "bound_at")?)?;
            Ok(value)
        }).collect()
}

async fn load_sqlite_provider_completions(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<Vec<PersistedProviderCompletionRow>, RepositoryError> {
    sqlx::query("SELECT account_key, event_digest, completion_kind, body FROM provider_completions ORDER BY account_key, event_digest")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: PersistedProviderCompletionRow = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_provider_completion_columns(&value, &row.try_get::<String, _>("account_key").map_err(database_error)?, &row.try_get::<Vec<u8>, _>("event_digest").map_err(database_error)?, &row.try_get::<String, _>("completion_kind").map_err(database_error)?)?;
            Ok(value)
        }).collect()
}

async fn load_sqlite_outbox(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<Vec<OutboxRecord>, RepositoryError> {
    sqlx::query("SELECT effect_id, command_id, ordinal, tenant_id, call_id, aggregate_version, worker_id, worker_fence, available_at, outbox_state, body FROM outbox ORDER BY effect_id")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: OutboxRecord = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_outbox_columns(&value, &row.try_get::<String, _>("effect_id").map_err(database_error)?, &row.try_get::<String, _>("command_id").map_err(database_error)?, row.try_get("ordinal").map_err(database_error)?, &row.try_get::<String, _>("tenant_id").map_err(database_error)?, &row.try_get::<String, _>("call_id").map_err(database_error)?, row.try_get("aggregate_version").map_err(database_error)?, &row.try_get::<String, _>("worker_id").map_err(database_error)?, row.try_get("worker_fence").map_err(database_error)?, sqlite_time(&row, "available_at")?, &row.try_get::<String, _>("outbox_state").map_err(database_error)?)?;
            Ok(value)
        }).collect()
}

async fn load_sqlite_deadlines(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<Vec<crate::call_engine::DeadlineRecord>, RepositoryError> {
    sqlx::query("SELECT call_id, deadline_kind, generation, tenant_id, due_at, deadline_state, body FROM deadlines ORDER BY call_id, deadline_kind, generation")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: crate::call_engine::DeadlineRecord = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_deadline_columns(&value, &row.try_get::<String, _>("call_id").map_err(database_error)?, &row.try_get::<String, _>("deadline_kind").map_err(database_error)?, row.try_get("generation").map_err(database_error)?, &row.try_get::<String, _>("tenant_id").map_err(database_error)?, sqlite_time(&row, "due_at")?, &row.try_get::<String, _>("deadline_state").map_err(database_error)?)?;
            Ok(value)
        }).collect()
}

async fn load_sqlite_service_rows(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<ServiceSnapshotRows, RepositoryError> {
    let execution_plans = sqlx::query("SELECT call_id, plan_version, first_leg_id, first_endpoint_kind, second_leg_id, second_endpoint_kind, body FROM call_execution_plans ORDER BY call_id")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: PersistedExecutionPlanRow = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_execution_plan_columns(&value, &row.try_get::<String, _>("call_id").map_err(database_error)?, row.try_get("plan_version").map_err(database_error)?, &row.try_get::<String, _>("first_leg_id").map_err(database_error)?, &row.try_get::<String, _>("first_endpoint_kind").map_err(database_error)?, &row.try_get::<String, _>("second_leg_id").map_err(database_error)?, &row.try_get::<String, _>("second_endpoint_kind").map_err(database_error)?)?;
            Ok(value)
        }).collect::<Result<Vec<_>, RepositoryError>>()?;
    let service_command_results = sqlx::query("SELECT command_id, tenant_id, call_id, recorded_at, body FROM service_command_results ORDER BY command_id")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: PersistedServiceCommandRow = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_service_command_columns(&value, &row.try_get::<String, _>("command_id").map_err(database_error)?, &row.try_get::<String, _>("tenant_id").map_err(database_error)?, &row.try_get::<String, _>("call_id").map_err(database_error)?, sqlite_time(&row, "recorded_at")?)?;
            Ok(value)
        }).collect::<Result<Vec<_>, RepositoryError>>()?;
    let service_effect_payloads = sqlx::query("SELECT effect_id, command_id, ordinal, payload_kind, body FROM service_effect_payloads ORDER BY effect_id")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: StoredServiceEffectPayload = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_service_payload_columns(&value, &row.try_get::<String, _>("effect_id").map_err(database_error)?, &row.try_get::<String, _>("command_id").map_err(database_error)?, row.try_get("ordinal").map_err(database_error)?, &row.try_get::<String, _>("payload_kind").map_err(database_error)?)?;
            Ok(value)
        }).collect::<Result<Vec<_>, RepositoryError>>()?;
    let control_sequences = sqlx::query("SELECT call_id, leg_id, binding_generation, last_sequence, body FROM control_sequences ORDER BY call_id, leg_id, binding_generation")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: PersistedControlSequenceRow = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_control_sequence_columns(&value, &row.try_get::<String, _>("call_id").map_err(database_error)?, &row.try_get::<String, _>("leg_id").map_err(database_error)?, row.try_get("binding_generation").map_err(database_error)?, row.try_get("last_sequence").map_err(database_error)?)?;
            Ok(value)
        }).collect::<Result<Vec<_>, RepositoryError>>()?;
    let control_commands = sqlx::query("SELECT command_id, tenant_id, call_id, leg_id, binding_generation, worker_id, worker_fence, control_kind, recorded_at, effect_id, body FROM control_commands ORDER BY command_id")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: PersistedControlCommandRow = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_control_command_columns(&value, &row.try_get::<String, _>("command_id").map_err(database_error)?, &row.try_get::<String, _>("tenant_id").map_err(database_error)?, &row.try_get::<String, _>("call_id").map_err(database_error)?, &row.try_get::<String, _>("leg_id").map_err(database_error)?, row.try_get("binding_generation").map_err(database_error)?, &row.try_get::<String, _>("worker_id").map_err(database_error)?, row.try_get("worker_fence").map_err(database_error)?, &row.try_get::<String, _>("control_kind").map_err(database_error)?, sqlite_time(&row, "recorded_at")?, &row.try_get::<String, _>("effect_id").map_err(database_error)?)?;
            Ok(value)
        }).collect::<Result<Vec<_>, RepositoryError>>()?;
    let control_outbox = sqlx::query("SELECT effect_id, command_id, tenant_id, call_id, leg_id, binding_generation, worker_id, worker_fence, sequence, available_at, outbox_state, body FROM control_outbox ORDER BY effect_id")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: ControlOutboxRecord = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_control_outbox_columns(&value, &row.try_get::<String, _>("effect_id").map_err(database_error)?, &row.try_get::<String, _>("command_id").map_err(database_error)?, &row.try_get::<String, _>("tenant_id").map_err(database_error)?, &row.try_get::<String, _>("call_id").map_err(database_error)?, &row.try_get::<String, _>("leg_id").map_err(database_error)?, row.try_get("binding_generation").map_err(database_error)?, &row.try_get::<String, _>("worker_id").map_err(database_error)?, row.try_get("worker_fence").map_err(database_error)?, row.try_get("sequence").map_err(database_error)?, sqlite_time(&row, "available_at")?, &row.try_get::<String, _>("outbox_state").map_err(database_error)?)?;
            Ok(value)
        }).collect::<Result<Vec<_>, RepositoryError>>()?;
    let outbound_binding_results = sqlx::query("SELECT operation_id, tenant_id, call_id, leg_id, binding_generation, worker_id, worker_fence, connection_id, transport_kind, bound_at, body FROM outbound_binding_results ORDER BY operation_id")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: PersistedOutboundBindingRow = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_outbound_binding_columns(&value, &row.try_get::<String, _>("operation_id").map_err(database_error)?, &row.try_get::<String, _>("tenant_id").map_err(database_error)?, &row.try_get::<String, _>("call_id").map_err(database_error)?, &row.try_get::<String, _>("leg_id").map_err(database_error)?, row.try_get("binding_generation").map_err(database_error)?, &row.try_get::<String, _>("worker_id").map_err(database_error)?, row.try_get("worker_fence").map_err(database_error)?, &row.try_get::<String, _>("connection_id").map_err(database_error)?, &row.try_get::<String, _>("transport_kind").map_err(database_error)?, sqlite_time(&row, "bound_at")?)?;
            Ok(value)
        }).collect::<Result<Vec<_>, RepositoryError>>()?;
    let external_references = sqlx::query("SELECT reference_kind, reference_namespace, reference_value, tenant_id, call_id, leg_id, binding_generation, effect_id, bound_at, body FROM external_references ORDER BY reference_kind, reference_namespace, reference_value")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: StoredExternalReference = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_external_reference_columns(&value, &row.try_get::<String, _>("reference_kind").map_err(database_error)?, &row.try_get::<String, _>("reference_namespace").map_err(database_error)?, &row.try_get::<String, _>("reference_value").map_err(database_error)?, &row.try_get::<String, _>("tenant_id").map_err(database_error)?, &row.try_get::<String, _>("call_id").map_err(database_error)?, &row.try_get::<String, _>("leg_id").map_err(database_error)?, row.try_get("binding_generation").map_err(database_error)?, &row.try_get::<String, _>("effect_id").map_err(database_error)?, sqlite_time(&row, "bound_at")?)?;
            Ok(value)
        }).collect::<Result<Vec<_>, RepositoryError>>()?;
    let reconciliation_results = sqlx::query("SELECT effect_id, effect_source, tenant_id, call_id, worker_id, worker_fence, result_kind, reconciled_at, body FROM reconciliation_results ORDER BY effect_id")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: PersistedReconciliationRow = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_reconciliation_columns(&value, &row.try_get::<String, _>("effect_id").map_err(database_error)?, &row.try_get::<String, _>("effect_source").map_err(database_error)?, &row.try_get::<String, _>("tenant_id").map_err(database_error)?, &row.try_get::<String, _>("call_id").map_err(database_error)?, &row.try_get::<String, _>("worker_id").map_err(database_error)?, row.try_get("worker_fence").map_err(database_error)?, &row.try_get::<String, _>("result_kind").map_err(database_error)?, sqlite_time(&row, "reconciled_at")?)?;
            Ok(value)
        }).collect::<Result<Vec<_>, RepositoryError>>()?;
    let retired_operation_claims = sqlx::query("SELECT command_id, receipt_kind, tenant_id, key_digest, request_digest, call_id, operation_kind, expires_at, retired_at, body FROM retired_operation_claims ORDER BY command_id")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: RetiredOperationClaim = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_retired_operation_claim_columns(&value, &row.try_get::<String, _>("command_id").map_err(database_error)?, &row.try_get::<String, _>("receipt_kind").map_err(database_error)?, &row.try_get::<String, _>("tenant_id").map_err(database_error)?, &row.try_get::<Vec<u8>, _>("key_digest").map_err(database_error)?, &row.try_get::<Vec<u8>, _>("request_digest").map_err(database_error)?, &row.try_get::<String, _>("call_id").map_err(database_error)?, &row.try_get::<String, _>("operation_kind").map_err(database_error)?, sqlite_time(&row, "expires_at")?, sqlite_time(&row, "retired_at")?)?;
            Ok(value)
        }).collect::<Result<Vec<_>, RepositoryError>>()?;
    let control_retirements = sqlx::query("SELECT effect_id, command_id, tenant_id, call_id, leg_id, binding_generation, retired_at, failure_code, body FROM control_outbox_retirements ORDER BY effect_id")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: ControlRetirementReceipt = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_control_retirement_columns(&value, &row.try_get::<String, _>("effect_id").map_err(database_error)?, &row.try_get::<String, _>("command_id").map_err(database_error)?, &row.try_get::<String, _>("tenant_id").map_err(database_error)?, &row.try_get::<String, _>("call_id").map_err(database_error)?, &row.try_get::<String, _>("leg_id").map_err(database_error)?, row.try_get("binding_generation").map_err(database_error)?, sqlite_time(&row, "retired_at")?, &row.try_get::<String, _>("failure_code").map_err(database_error)?)?;
            Ok(value)
        }).collect::<Result<Vec<_>, RepositoryError>>()?;
    Ok(ServiceSnapshotRows {
        execution_plans,
        service_effect_payloads,
        service_command_results,
        control_sequences,
        control_commands,
        control_outbox,
        outbound_binding_results,
        external_references,
        reconciliation_results,
        retired_operation_claims,
        control_retirements,
    })
}

async fn load_postgres_workers(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<Vec<WorkerSnapshot>, RepositoryError> {
    sqlx::query("SELECT worker_id::text AS worker_id, fence, max_calls, reserved_calls, draining, updated_at, body::text AS body FROM workers ORDER BY worker_id")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: WorkerSnapshot = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_worker_columns(&value, &row.try_get::<String, _>("worker_id").map_err(database_error)?, row.try_get("fence").map_err(database_error)?, row.try_get("max_calls").map_err(database_error)?, row.try_get("reserved_calls").map_err(database_error)?, row.try_get("draining").map_err(database_error)?, row.try_get("updated_at").map_err(database_error)?)?;
            Ok(value)
        }).collect()
}

async fn load_postgres_commands(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<Vec<PersistedCommandRow>, RepositoryError> {
    sqlx::query("SELECT command_id::text AS command_id, tenant_id, call_id::text AS call_id, observed_version, result_version, recorded_at, body::text AS body FROM commands ORDER BY command_id")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: PersistedCommandRow = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_command_columns(&value, &row.try_get::<String, _>("command_id").map_err(database_error)?, &row.try_get::<String, _>("tenant_id").map_err(database_error)?, &row.try_get::<String, _>("call_id").map_err(database_error)?, row.try_get("observed_version").map_err(database_error)?, row.try_get("result_version").map_err(database_error)?, row.try_get("recorded_at").map_err(database_error)?)?;
            Ok(value)
        }).collect()
}

async fn load_postgres_idempotency(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<Vec<PersistedIdempotencyRow>, RepositoryError> {
    sqlx::query("SELECT tenant_id, key_digest, request_digest, call_id::text AS call_id, expires_at, receipt_kind, operation_kind, body::text AS body FROM idempotency ORDER BY tenant_id, key_digest")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: PersistedIdempotencyRow = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_idempotency_columns(&value, &row.try_get::<String, _>("tenant_id").map_err(database_error)?, &row.try_get::<Vec<u8>, _>("key_digest").map_err(database_error)?, &row.try_get::<Vec<u8>, _>("request_digest").map_err(database_error)?, &row.try_get::<String, _>("call_id").map_err(database_error)?, row.try_get("expires_at").map_err(database_error)?, &row.try_get::<String, _>("receipt_kind").map_err(database_error)?, &row.try_get::<String, _>("operation_kind").map_err(database_error)?)?;
            Ok(value)
        }).collect()
}

async fn load_postgres_attachments(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<Vec<AttachmentRow>, RepositoryError> {
    sqlx::query("SELECT token_digest, attachment_id::text AS attachment_id, tenant_id, call_id::text AS call_id, leg_id::text AS leg_id, binding_generation, worker_id::text AS worker_id, worker_fence, expires_at, consumed_at, revoked_at, body::text AS body FROM attachments ORDER BY attachment_id")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: AttachmentRow = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_attachment_columns(&value, &row.try_get::<Vec<u8>, _>("token_digest").map_err(database_error)?, &row.try_get::<String, _>("attachment_id").map_err(database_error)?, &row.try_get::<String, _>("tenant_id").map_err(database_error)?, &row.try_get::<String, _>("call_id").map_err(database_error)?, &row.try_get::<String, _>("leg_id").map_err(database_error)?, row.try_get("binding_generation").map_err(database_error)?, &row.try_get::<String, _>("worker_id").map_err(database_error)?, row.try_get("worker_fence").map_err(database_error)?, row.try_get("expires_at").map_err(database_error)?, row.try_get("consumed_at").map_err(database_error)?, row.try_get("revoked_at").map_err(database_error)?)?;
            Ok(value)
        }).collect()
}

async fn load_postgres_provider_events(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<Vec<ProviderEventEnvelope>, RepositoryError> {
    sqlx::query("SELECT account_key, event_digest, payload_digest, provider_call_id, receipt_sequence, received_at, event_state, body::text AS body FROM provider_events ORDER BY receipt_sequence")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: ProviderEventEnvelope = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_provider_event_columns(&value, &row.try_get::<String, _>("account_key").map_err(database_error)?, &row.try_get::<Vec<u8>, _>("event_digest").map_err(database_error)?, &row.try_get::<Vec<u8>, _>("payload_digest").map_err(database_error)?, &row.try_get::<String, _>("provider_call_id").map_err(database_error)?, row.try_get("receipt_sequence").map_err(database_error)?, row.try_get("received_at").map_err(database_error)?, &row.try_get::<String, _>("event_state").map_err(database_error)?)?;
            Ok(value)
        }).collect()
}

async fn load_postgres_provider_references(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<Vec<PersistedProviderReferenceRow>, RepositoryError> {
    sqlx::query("SELECT account_key, provider_call_id, tenant_id, call_id::text AS call_id, leg_id::text AS leg_id, bound_at, body::text AS body FROM provider_references ORDER BY account_key, provider_call_id")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: PersistedProviderReferenceRow = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_provider_reference_columns(&value, &row.try_get::<String, _>("account_key").map_err(database_error)?, &row.try_get::<String, _>("provider_call_id").map_err(database_error)?, &row.try_get::<String, _>("tenant_id").map_err(database_error)?, &row.try_get::<String, _>("call_id").map_err(database_error)?, &row.try_get::<String, _>("leg_id").map_err(database_error)?, row.try_get("bound_at").map_err(database_error)?)?;
            Ok(value)
        }).collect()
}

async fn load_postgres_provider_completions(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<Vec<PersistedProviderCompletionRow>, RepositoryError> {
    sqlx::query("SELECT account_key, event_digest, completion_kind, body::text AS body FROM provider_completions ORDER BY account_key, event_digest")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: PersistedProviderCompletionRow = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_provider_completion_columns(&value, &row.try_get::<String, _>("account_key").map_err(database_error)?, &row.try_get::<Vec<u8>, _>("event_digest").map_err(database_error)?, &row.try_get::<String, _>("completion_kind").map_err(database_error)?)?;
            Ok(value)
        }).collect()
}

async fn load_postgres_outbox(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<Vec<OutboxRecord>, RepositoryError> {
    sqlx::query("SELECT effect_id::text AS effect_id, command_id::text AS command_id, ordinal, tenant_id, call_id::text AS call_id, aggregate_version, worker_id::text AS worker_id, worker_fence, available_at, outbox_state, body::text AS body FROM outbox ORDER BY effect_id")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: OutboxRecord = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_outbox_columns(&value, &row.try_get::<String, _>("effect_id").map_err(database_error)?, &row.try_get::<String, _>("command_id").map_err(database_error)?, row.try_get("ordinal").map_err(database_error)?, &row.try_get::<String, _>("tenant_id").map_err(database_error)?, &row.try_get::<String, _>("call_id").map_err(database_error)?, row.try_get("aggregate_version").map_err(database_error)?, &row.try_get::<String, _>("worker_id").map_err(database_error)?, row.try_get("worker_fence").map_err(database_error)?, row.try_get("available_at").map_err(database_error)?, &row.try_get::<String, _>("outbox_state").map_err(database_error)?)?;
            Ok(value)
        }).collect()
}

async fn load_postgres_deadlines(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<Vec<crate::call_engine::DeadlineRecord>, RepositoryError> {
    sqlx::query("SELECT call_id::text AS call_id, deadline_kind, generation, tenant_id, due_at, deadline_state, body::text AS body FROM deadlines ORDER BY call_id, deadline_kind, generation")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: crate::call_engine::DeadlineRecord = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_deadline_columns(&value, &row.try_get::<String, _>("call_id").map_err(database_error)?, &row.try_get::<String, _>("deadline_kind").map_err(database_error)?, row.try_get("generation").map_err(database_error)?, &row.try_get::<String, _>("tenant_id").map_err(database_error)?, row.try_get("due_at").map_err(database_error)?, &row.try_get::<String, _>("deadline_state").map_err(database_error)?)?;
            Ok(value)
        }).collect()
}

async fn load_postgres_service_rows(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<ServiceSnapshotRows, RepositoryError> {
    let execution_plans = sqlx::query("SELECT call_id::text AS call_id, plan_version, first_leg_id::text AS first_leg_id, first_endpoint_kind, second_leg_id::text AS second_leg_id, second_endpoint_kind, body::text AS body FROM call_execution_plans ORDER BY call_id")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: PersistedExecutionPlanRow = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_execution_plan_columns(&value, &row.try_get::<String, _>("call_id").map_err(database_error)?, row.try_get("plan_version").map_err(database_error)?, &row.try_get::<String, _>("first_leg_id").map_err(database_error)?, &row.try_get::<String, _>("first_endpoint_kind").map_err(database_error)?, &row.try_get::<String, _>("second_leg_id").map_err(database_error)?, &row.try_get::<String, _>("second_endpoint_kind").map_err(database_error)?)?;
            Ok(value)
        }).collect::<Result<Vec<_>, RepositoryError>>()?;
    let service_command_results = sqlx::query("SELECT command_id::text AS command_id, tenant_id, call_id::text AS call_id, recorded_at, body::text AS body FROM service_command_results ORDER BY command_id")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: PersistedServiceCommandRow = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_service_command_columns(&value, &row.try_get::<String, _>("command_id").map_err(database_error)?, &row.try_get::<String, _>("tenant_id").map_err(database_error)?, &row.try_get::<String, _>("call_id").map_err(database_error)?, row.try_get("recorded_at").map_err(database_error)?)?;
            Ok(value)
        }).collect::<Result<Vec<_>, RepositoryError>>()?;
    let service_effect_payloads = sqlx::query("SELECT effect_id::text AS effect_id, command_id::text AS command_id, ordinal, payload_kind, body::text AS body FROM service_effect_payloads ORDER BY effect_id")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: StoredServiceEffectPayload = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_service_payload_columns(&value, &row.try_get::<String, _>("effect_id").map_err(database_error)?, &row.try_get::<String, _>("command_id").map_err(database_error)?, row.try_get("ordinal").map_err(database_error)?, &row.try_get::<String, _>("payload_kind").map_err(database_error)?)?;
            Ok(value)
        }).collect::<Result<Vec<_>, RepositoryError>>()?;
    let control_sequences = sqlx::query("SELECT call_id::text AS call_id, leg_id::text AS leg_id, binding_generation, last_sequence, body::text AS body FROM control_sequences ORDER BY call_id, leg_id, binding_generation")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: PersistedControlSequenceRow = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_control_sequence_columns(&value, &row.try_get::<String, _>("call_id").map_err(database_error)?, &row.try_get::<String, _>("leg_id").map_err(database_error)?, row.try_get("binding_generation").map_err(database_error)?, row.try_get("last_sequence").map_err(database_error)?)?;
            Ok(value)
        }).collect::<Result<Vec<_>, RepositoryError>>()?;
    let control_commands = sqlx::query("SELECT command_id::text AS command_id, tenant_id, call_id::text AS call_id, leg_id::text AS leg_id, binding_generation, worker_id::text AS worker_id, worker_fence, control_kind, recorded_at, effect_id::text AS effect_id, body::text AS body FROM control_commands ORDER BY command_id")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: PersistedControlCommandRow = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_control_command_columns(&value, &row.try_get::<String, _>("command_id").map_err(database_error)?, &row.try_get::<String, _>("tenant_id").map_err(database_error)?, &row.try_get::<String, _>("call_id").map_err(database_error)?, &row.try_get::<String, _>("leg_id").map_err(database_error)?, row.try_get("binding_generation").map_err(database_error)?, &row.try_get::<String, _>("worker_id").map_err(database_error)?, row.try_get("worker_fence").map_err(database_error)?, &row.try_get::<String, _>("control_kind").map_err(database_error)?, row.try_get("recorded_at").map_err(database_error)?, &row.try_get::<String, _>("effect_id").map_err(database_error)?)?;
            Ok(value)
        }).collect::<Result<Vec<_>, RepositoryError>>()?;
    let control_outbox = sqlx::query("SELECT effect_id::text AS effect_id, command_id::text AS command_id, tenant_id, call_id::text AS call_id, leg_id::text AS leg_id, binding_generation, worker_id::text AS worker_id, worker_fence, sequence, available_at, outbox_state, body::text AS body FROM control_outbox ORDER BY effect_id")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: ControlOutboxRecord = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_control_outbox_columns(&value, &row.try_get::<String, _>("effect_id").map_err(database_error)?, &row.try_get::<String, _>("command_id").map_err(database_error)?, &row.try_get::<String, _>("tenant_id").map_err(database_error)?, &row.try_get::<String, _>("call_id").map_err(database_error)?, &row.try_get::<String, _>("leg_id").map_err(database_error)?, row.try_get("binding_generation").map_err(database_error)?, &row.try_get::<String, _>("worker_id").map_err(database_error)?, row.try_get("worker_fence").map_err(database_error)?, row.try_get("sequence").map_err(database_error)?, row.try_get("available_at").map_err(database_error)?, &row.try_get::<String, _>("outbox_state").map_err(database_error)?)?;
            Ok(value)
        }).collect::<Result<Vec<_>, RepositoryError>>()?;
    let outbound_binding_results = sqlx::query("SELECT operation_id::text AS operation_id, tenant_id, call_id::text AS call_id, leg_id::text AS leg_id, binding_generation, worker_id::text AS worker_id, worker_fence, connection_id, transport_kind, bound_at, body::text AS body FROM outbound_binding_results ORDER BY operation_id")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: PersistedOutboundBindingRow = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_outbound_binding_columns(&value, &row.try_get::<String, _>("operation_id").map_err(database_error)?, &row.try_get::<String, _>("tenant_id").map_err(database_error)?, &row.try_get::<String, _>("call_id").map_err(database_error)?, &row.try_get::<String, _>("leg_id").map_err(database_error)?, row.try_get("binding_generation").map_err(database_error)?, &row.try_get::<String, _>("worker_id").map_err(database_error)?, row.try_get("worker_fence").map_err(database_error)?, &row.try_get::<String, _>("connection_id").map_err(database_error)?, &row.try_get::<String, _>("transport_kind").map_err(database_error)?, row.try_get("bound_at").map_err(database_error)?)?;
            Ok(value)
        }).collect::<Result<Vec<_>, RepositoryError>>()?;
    let external_references = sqlx::query("SELECT reference_kind, reference_namespace, reference_value, tenant_id, call_id::text AS call_id, leg_id::text AS leg_id, binding_generation, effect_id::text AS effect_id, bound_at, body::text AS body FROM external_references ORDER BY reference_kind, reference_namespace, reference_value")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: StoredExternalReference = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_external_reference_columns(&value, &row.try_get::<String, _>("reference_kind").map_err(database_error)?, &row.try_get::<String, _>("reference_namespace").map_err(database_error)?, &row.try_get::<String, _>("reference_value").map_err(database_error)?, &row.try_get::<String, _>("tenant_id").map_err(database_error)?, &row.try_get::<String, _>("call_id").map_err(database_error)?, &row.try_get::<String, _>("leg_id").map_err(database_error)?, row.try_get("binding_generation").map_err(database_error)?, &row.try_get::<String, _>("effect_id").map_err(database_error)?, row.try_get("bound_at").map_err(database_error)?)?;
            Ok(value)
        }).collect::<Result<Vec<_>, RepositoryError>>()?;
    let reconciliation_results = sqlx::query("SELECT effect_id::text AS effect_id, effect_source, tenant_id, call_id::text AS call_id, worker_id::text AS worker_id, worker_fence, result_kind, reconciled_at, body::text AS body FROM reconciliation_results ORDER BY effect_id")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: PersistedReconciliationRow = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_reconciliation_columns(&value, &row.try_get::<String, _>("effect_id").map_err(database_error)?, &row.try_get::<String, _>("effect_source").map_err(database_error)?, &row.try_get::<String, _>("tenant_id").map_err(database_error)?, &row.try_get::<String, _>("call_id").map_err(database_error)?, &row.try_get::<String, _>("worker_id").map_err(database_error)?, row.try_get("worker_fence").map_err(database_error)?, &row.try_get::<String, _>("result_kind").map_err(database_error)?, row.try_get("reconciled_at").map_err(database_error)?)?;
            Ok(value)
        }).collect::<Result<Vec<_>, RepositoryError>>()?;
    let retired_operation_claims = sqlx::query("SELECT command_id::text AS command_id, receipt_kind, tenant_id, key_digest, request_digest, call_id::text AS call_id, operation_kind, expires_at, retired_at, body::text AS body FROM retired_operation_claims ORDER BY command_id")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: RetiredOperationClaim = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_retired_operation_claim_columns(&value, &row.try_get::<String, _>("command_id").map_err(database_error)?, &row.try_get::<String, _>("receipt_kind").map_err(database_error)?, &row.try_get::<String, _>("tenant_id").map_err(database_error)?, &row.try_get::<Vec<u8>, _>("key_digest").map_err(database_error)?, &row.try_get::<Vec<u8>, _>("request_digest").map_err(database_error)?, &row.try_get::<String, _>("call_id").map_err(database_error)?, &row.try_get::<String, _>("operation_kind").map_err(database_error)?, row.try_get("expires_at").map_err(database_error)?, row.try_get("retired_at").map_err(database_error)?)?;
            Ok(value)
        }).collect::<Result<Vec<_>, RepositoryError>>()?;
    let control_retirements = sqlx::query("SELECT effect_id::text AS effect_id, command_id::text AS command_id, tenant_id, call_id::text AS call_id, leg_id::text AS leg_id, binding_generation, retired_at, failure_code, body::text AS body FROM control_outbox_retirements ORDER BY effect_id")
        .fetch_all(&mut **transaction).await.map_err(database_error)?
        .into_iter().map(|row| {
            let value: ControlRetirementReceipt = decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            validate_control_retirement_columns(&value, &row.try_get::<String, _>("effect_id").map_err(database_error)?, &row.try_get::<String, _>("command_id").map_err(database_error)?, &row.try_get::<String, _>("tenant_id").map_err(database_error)?, &row.try_get::<String, _>("call_id").map_err(database_error)?, &row.try_get::<String, _>("leg_id").map_err(database_error)?, row.try_get("binding_generation").map_err(database_error)?, row.try_get("retired_at").map_err(database_error)?, &row.try_get::<String, _>("failure_code").map_err(database_error)?)?;
            Ok(value)
        }).collect::<Result<Vec<_>, RepositoryError>>()?;
    Ok(ServiceSnapshotRows {
        execution_plans,
        service_effect_payloads,
        service_command_results,
        control_sequences,
        control_commands,
        control_outbox,
        outbound_binding_results,
        external_references,
        reconciliation_results,
        retired_operation_claims,
        control_retirements,
    })
}

async fn load_sqlite_calls(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<Vec<StoredCall>, RepositoryError> {
    let aggregate_rows = sqlx::query(
        "SELECT call_id, tenant_id, aggregate_version, call_state, body FROM calls ORDER BY call_id",
    )
        .fetch_all(&mut **transaction)
        .await
        .map_err(database_error)?;
    let assignment_rows = sqlx::query(
        "SELECT call_id, worker_id, worker_fence, assigned_at, released_at, body FROM worker_assignments ORDER BY call_id",
    )
            .fetch_all(&mut **transaction)
            .await
            .map_err(database_error)?;
    let binding_rows = sqlx::query(
        "SELECT connection_id, call_id, leg_id, binding_generation, principal_fingerprint, body FROM connection_bindings ORDER BY connection_id",
    )
            .fetch_all(&mut **transaction)
            .await
            .map_err(database_error)?;
    let leg_rows = sqlx::query(
        "SELECT call_id, leg_id, tenant_id, binding_generation, leg_state, body FROM legs ORDER BY leg_id",
    )
    .fetch_all(&mut **transaction)
    .await
    .map_err(database_error)?;

    let aggregates = aggregate_rows
        .into_iter()
        .map(|row| {
            let call_id = parse_call_id(
                &row.try_get::<String, _>("call_id")
                    .map_err(database_error)?,
            )?;
            let aggregate: CallAggregate =
                decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            if aggregate.id() != call_id
                || aggregate.tenant_id().as_str()
                    != row
                        .try_get::<String, _>("tenant_id")
                        .map_err(database_error)?
                || aggregate.version().as_i64()
                    != row
                        .try_get::<i64, _>("aggregate_version")
                        .map_err(database_error)?
                || state_name(&aggregate.state())?
                    != row
                        .try_get::<String, _>("call_state")
                        .map_err(database_error)?
            {
                return Err(RepositoryError::Unavailable);
            }
            Ok((call_id, aggregate))
        })
        .collect::<Result<Vec<_>, RepositoryError>>()?;
    let assignments = assignment_rows
        .into_iter()
        .map(|row| {
            let call_id = parse_call_id(
                &row.try_get::<String, _>("call_id")
                    .map_err(database_error)?,
            )?;
            let assignment: WorkerAssignment =
                decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            let assigned_at = parse_sqlite_time(
                &row.try_get::<String, _>("assigned_at")
                    .map_err(database_error)?,
            )?;
            let released_at = row
                .try_get::<Option<String>, _>("released_at")
                .map_err(database_error)?
                .map(|value| parse_sqlite_time(&value))
                .transpose()?;
            if assignment.lease.worker_id.to_string()
                != row
                    .try_get::<String, _>("worker_id")
                    .map_err(database_error)?
                || assignment.lease.fence.as_i64()
                    != row
                        .try_get::<i64, _>("worker_fence")
                        .map_err(database_error)?
                || assignment.assigned_at != assigned_at
                || assignment.released_at != released_at
            {
                return Err(RepositoryError::Unavailable);
            }
            Ok((call_id, assignment))
        })
        .collect::<Result<Vec<_>, RepositoryError>>()?;
    let bindings = binding_rows
        .into_iter()
        .map(|row| {
            let call_id = parse_call_id(
                &row.try_get::<String, _>("call_id")
                    .map_err(database_error)?,
            )?;
            let binding: ConnectionBinding =
                decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            let principal = row
                .try_get::<Vec<u8>, _>("principal_fingerprint")
                .map_err(database_error)?;
            if binding.connection_id.as_str()
                != row
                    .try_get::<String, _>("connection_id")
                    .map_err(database_error)?
                || binding.leg_id.to_string()
                    != row.try_get::<String, _>("leg_id").map_err(database_error)?
                || binding.binding_generation.as_i64()
                    != row
                        .try_get::<i64, _>("binding_generation")
                        .map_err(database_error)?
                || binding.principal_fingerprint.expose_bytes().as_slice() != principal
            {
                return Err(RepositoryError::Unavailable);
            }
            Ok((call_id, binding))
        })
        .collect::<Result<Vec<_>, RepositoryError>>()?;
    let legs = leg_rows
        .into_iter()
        .map(|row| {
            let call_id = parse_call_id(
                &row.try_get::<String, _>("call_id")
                    .map_err(database_error)?,
            )?;
            let leg_id =
                LegId::from_str(&row.try_get::<String, _>("leg_id").map_err(database_error)?)
                    .map_err(|_| RepositoryError::Unavailable)?;
            let body = row.try_get::<String, _>("body").map_err(database_error)?;
            let leg: crate::call_engine::Leg = decode(&body)?;
            if leg.id() != leg_id
                || leg.binding_generation().as_i64()
                    != row
                        .try_get::<i64, _>("binding_generation")
                        .map_err(database_error)?
                || state_name(&leg.state())?
                    != row
                        .try_get::<String, _>("leg_state")
                        .map_err(database_error)?
            {
                return Err(RepositoryError::Unavailable);
            }
            Ok((
                (call_id, leg_id),
                (
                    row.try_get::<String, _>("tenant_id")
                        .map_err(database_error)?,
                    serde_json::to_value(leg).map_err(|_| RepositoryError::Unavailable)?,
                ),
            ))
        })
        .collect::<Result<Vec<_>, RepositoryError>>()?;
    assemble_calls(aggregates, assignments, bindings, legs)
}

async fn load_postgres_calls(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<Vec<StoredCall>, RepositoryError> {
    let aggregate_rows = sqlx::query(
        "SELECT call_id::text AS call_id, tenant_id, aggregate_version, call_state, body::text AS body FROM calls ORDER BY call_id",
    )
    .fetch_all(&mut **transaction)
    .await
    .map_err(database_error)?;
    let assignment_rows = sqlx::query(
        "SELECT call_id::text AS call_id, worker_id::text AS worker_id, worker_fence, assigned_at, released_at, body::text AS body FROM worker_assignments ORDER BY call_id",
    )
    .fetch_all(&mut **transaction)
    .await
    .map_err(database_error)?;
    let binding_rows = sqlx::query(
        "SELECT connection_id, call_id::text AS call_id, leg_id::text AS leg_id, binding_generation, principal_fingerprint, body::text AS body FROM connection_bindings ORDER BY connection_id",
    )
    .fetch_all(&mut **transaction)
    .await
    .map_err(database_error)?;
    let leg_rows = sqlx::query(
        "SELECT call_id::text AS call_id, leg_id::text AS leg_id, tenant_id, binding_generation, leg_state, body::text AS body FROM legs ORDER BY leg_id",
    )
    .fetch_all(&mut **transaction)
    .await
    .map_err(database_error)?;

    let aggregates = aggregate_rows
        .into_iter()
        .map(|row| {
            let call_id = parse_call_id(
                &row.try_get::<String, _>("call_id")
                    .map_err(database_error)?,
            )?;
            let aggregate: CallAggregate =
                decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            if aggregate.id() != call_id
                || aggregate.tenant_id().as_str()
                    != row
                        .try_get::<String, _>("tenant_id")
                        .map_err(database_error)?
                || aggregate.version().as_i64()
                    != row
                        .try_get::<i64, _>("aggregate_version")
                        .map_err(database_error)?
                || state_name(&aggregate.state())?
                    != row
                        .try_get::<String, _>("call_state")
                        .map_err(database_error)?
            {
                return Err(RepositoryError::Unavailable);
            }
            Ok((call_id, aggregate))
        })
        .collect::<Result<Vec<_>, RepositoryError>>()?;
    let assignments = assignment_rows
        .into_iter()
        .map(|row| {
            let call_id = parse_call_id(
                &row.try_get::<String, _>("call_id")
                    .map_err(database_error)?,
            )?;
            let assignment: WorkerAssignment =
                decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            if assignment.lease.worker_id.to_string()
                != row
                    .try_get::<String, _>("worker_id")
                    .map_err(database_error)?
                || assignment.lease.fence.as_i64()
                    != row
                        .try_get::<i64, _>("worker_fence")
                        .map_err(database_error)?
                || assignment.assigned_at
                    != row
                        .try_get::<DateTime<Utc>, _>("assigned_at")
                        .map_err(database_error)?
                || assignment.released_at
                    != row
                        .try_get::<Option<DateTime<Utc>>, _>("released_at")
                        .map_err(database_error)?
            {
                return Err(RepositoryError::Unavailable);
            }
            Ok((call_id, assignment))
        })
        .collect::<Result<Vec<_>, RepositoryError>>()?;
    let bindings = binding_rows
        .into_iter()
        .map(|row| {
            let call_id = parse_call_id(
                &row.try_get::<String, _>("call_id")
                    .map_err(database_error)?,
            )?;
            let binding: ConnectionBinding =
                decode(&row.try_get::<String, _>("body").map_err(database_error)?)?;
            let principal = row
                .try_get::<Vec<u8>, _>("principal_fingerprint")
                .map_err(database_error)?;
            if binding.connection_id.as_str()
                != row
                    .try_get::<String, _>("connection_id")
                    .map_err(database_error)?
                || binding.leg_id.to_string()
                    != row.try_get::<String, _>("leg_id").map_err(database_error)?
                || binding.binding_generation.as_i64()
                    != row
                        .try_get::<i64, _>("binding_generation")
                        .map_err(database_error)?
                || binding.principal_fingerprint.expose_bytes().as_slice() != principal
            {
                return Err(RepositoryError::Unavailable);
            }
            Ok((call_id, binding))
        })
        .collect::<Result<Vec<_>, RepositoryError>>()?;
    let legs = leg_rows
        .into_iter()
        .map(|row| {
            let call_id = parse_call_id(
                &row.try_get::<String, _>("call_id")
                    .map_err(database_error)?,
            )?;
            let leg_id =
                LegId::from_str(&row.try_get::<String, _>("leg_id").map_err(database_error)?)
                    .map_err(|_| RepositoryError::Unavailable)?;
            let body = row.try_get::<String, _>("body").map_err(database_error)?;
            let leg: crate::call_engine::Leg = decode(&body)?;
            if leg.id() != leg_id
                || leg.binding_generation().as_i64()
                    != row
                        .try_get::<i64, _>("binding_generation")
                        .map_err(database_error)?
                || state_name(&leg.state())?
                    != row
                        .try_get::<String, _>("leg_state")
                        .map_err(database_error)?
            {
                return Err(RepositoryError::Unavailable);
            }
            Ok((
                (call_id, leg_id),
                (
                    row.try_get::<String, _>("tenant_id")
                        .map_err(database_error)?,
                    serde_json::to_value(leg).map_err(|_| RepositoryError::Unavailable)?,
                ),
            ))
        })
        .collect::<Result<Vec<_>, RepositoryError>>()?;
    assemble_calls(aggregates, assignments, bindings, legs)
}

fn assemble_calls(
    aggregates: Vec<(CallId, CallAggregate)>,
    assignments: Vec<(CallId, WorkerAssignment)>,
    bindings: Vec<(CallId, ConnectionBinding)>,
    legs: Vec<((CallId, LegId), (String, serde_json::Value))>,
) -> Result<Vec<StoredCall>, RepositoryError> {
    let mut assignments = assignments.into_iter().collect::<HashMap<_, _>>();
    let mut bindings_by_call = HashMap::<CallId, BTreeMap<LegId, ConnectionBinding>>::new();
    for (call_id, binding) in bindings {
        if bindings_by_call
            .entry(call_id)
            .or_default()
            .insert(binding.leg_id, binding)
            .is_some()
        {
            return Err(RepositoryError::Unavailable);
        }
    }
    let mut materialized_legs = legs.into_iter().collect::<HashMap<_, _>>();
    let mut calls = Vec::with_capacity(aggregates.len());
    for (call_id, aggregate) in aggregates {
        if aggregate.id() != call_id {
            return Err(RepositoryError::Unavailable);
        }
        for leg in aggregate.legs() {
            let (persisted_tenant, persisted) = materialized_legs
                .remove(&(call_id, leg.id()))
                .ok_or(RepositoryError::Unavailable)?;
            let expected = serde_json::to_value(leg).map_err(|_| RepositoryError::Unavailable)?;
            if persisted_tenant != aggregate.tenant_id().as_str() || persisted != expected {
                return Err(RepositoryError::Unavailable);
            }
        }
        calls.push(StoredCall {
            aggregate,
            assignment: assignments
                .remove(&call_id)
                .ok_or(RepositoryError::Unavailable)?,
            bindings: bindings_by_call.remove(&call_id).unwrap_or_default(),
        });
    }
    if !assignments.is_empty() || !bindings_by_call.is_empty() || !materialized_legs.is_empty() {
        return Err(RepositoryError::Unavailable);
    }
    Ok(calls)
}

fn changed_rows<T: Clone + PartialEq>(
    before: &[T],
    after: &[T],
    same_key: impl Fn(&T, &T) -> bool,
) -> Vec<T> {
    after
        .iter()
        .filter(|candidate| {
            before.iter().find(|existing| same_key(existing, candidate)) != Some(candidate)
        })
        .cloned()
        .collect()
}

fn removed_rows<'a, T>(
    before: &'a [T],
    after: &[T],
    same_key: impl Fn(&T, &T) -> bool,
) -> Vec<&'a T> {
    before
        .iter()
        .filter(|candidate| !after.iter().any(|existing| same_key(existing, candidate)))
        .collect()
}

fn changed_snapshot(
    before: &MemoryStateSnapshot,
    after: &MemoryStateSnapshot,
) -> MemoryStateSnapshot {
    MemoryStateSnapshot {
        workers: changed_rows(&before.workers, &after.workers, |left, right| {
            left.lease.worker_id == right.lease.worker_id
        }),
        calls: changed_rows(&before.calls, &after.calls, |left, right| {
            left.aggregate.id() == right.aggregate.id()
        }),
        commands: changed_rows(&before.commands, &after.commands, |left, right| {
            left.command.command_id == right.command.command_id
        }),
        idempotency: changed_rows(&before.idempotency, &after.idempotency, |left, right| {
            left.tenant_id == right.tenant_id && left.key_digest == right.key_digest
        }),
        attachments: changed_rows(&before.attachments, &after.attachments, |left, right| {
            left.token_digest == right.token_digest
        }),
        provider_events: changed_rows(
            &before.provider_events,
            &after.provider_events,
            |left, right| left.account == right.account && left.event_digest == right.event_digest,
        ),
        provider_references: changed_rows(
            &before.provider_references,
            &after.provider_references,
            |left, right| {
                left.account == right.account && left.provider_call_id == right.provider_call_id
            },
        ),
        provider_completions: changed_rows(
            &before.provider_completions,
            &after.provider_completions,
            |left, right| left.account == right.account && left.event_digest == right.event_digest,
        ),
        provider_receipt_sequence: after.provider_receipt_sequence,
        used_connection_ids: changed_rows(
            &before.used_connection_ids,
            &after.used_connection_ids,
            PartialEq::eq,
        ),
        outbox: changed_rows(&before.outbox, &after.outbox, |left, right| {
            left.effect_id == right.effect_id
        }),
        deadlines: changed_rows(&before.deadlines, &after.deadlines, |left, right| {
            left.call_id == right.call_id
                && left.kind == right.kind
                && left.generation == right.generation
        }),
        service_managed_calls: changed_rows(
            &before.service_managed_calls,
            &after.service_managed_calls,
            PartialEq::eq,
        ),
        execution_plans: changed_rows(
            &before.execution_plans,
            &after.execution_plans,
            |left, right| left.call_id == right.call_id,
        ),
        service_effect_payloads: changed_rows(
            &before.service_effect_payloads,
            &after.service_effect_payloads,
            |left, right| left.effect_id == right.effect_id,
        ),
        service_command_results: changed_rows(
            &before.service_command_results,
            &after.service_command_results,
            |left, right| left.command_id == right.command_id,
        ),
        control_sequences: changed_rows(
            &before.control_sequences,
            &after.control_sequences,
            |left, right| {
                left.call_id == right.call_id
                    && left.leg_id == right.leg_id
                    && left.binding_generation == right.binding_generation
            },
        ),
        control_commands: changed_rows(
            &before.control_commands,
            &after.control_commands,
            |left, right| left.command_id == right.command_id,
        ),
        control_outbox: changed_rows(
            &before.control_outbox,
            &after.control_outbox,
            |left, right| left.effect_id == right.effect_id,
        ),
        outbound_binding_results: changed_rows(
            &before.outbound_binding_results,
            &after.outbound_binding_results,
            |left, right| left.operation_id == right.operation_id,
        ),
        external_references: changed_rows(
            &before.external_references,
            &after.external_references,
            |left, right| left.value == right.value,
        ),
        reconciliation_results: changed_rows(
            &before.reconciliation_results,
            &after.reconciliation_results,
            |left, right| left.effect_id == right.effect_id,
        ),
        retired_operation_claims: changed_rows(
            &before.retired_operation_claims,
            &after.retired_operation_claims,
            |left, right| left.command_id == right.command_id,
        ),
        control_retirements: changed_rows(
            &before.control_retirements,
            &after.control_retirements,
            |left, right| left.effect_id == right.effect_id,
        ),
    }
}

fn validate_supported_removals(
    before: &MemoryStateSnapshot,
    after: &MemoryStateSnapshot,
) -> Result<(), RepositoryError> {
    let unsupported = removed_rows(&before.workers, &after.workers, |left, right| {
        left.lease.worker_id == right.lease.worker_id
    })
    .len()
        + removed_rows(&before.calls, &after.calls, |left, right| {
            left.aggregate.id() == right.aggregate.id()
        })
        .len()
        + removed_rows(&before.commands, &after.commands, |left, right| {
            left.command.command_id == right.command.command_id
        })
        .len()
        + removed_rows(&before.attachments, &after.attachments, |left, right| {
            left.token_digest == right.token_digest
        })
        .len()
        + removed_rows(
            &before.provider_events,
            &after.provider_events,
            |left, right| left.account == right.account && left.event_digest == right.event_digest,
        )
        .len()
        + removed_rows(
            &before.provider_references,
            &after.provider_references,
            |left, right| {
                left.account == right.account && left.provider_call_id == right.provider_call_id
            },
        )
        .len()
        + removed_rows(
            &before.provider_completions,
            &after.provider_completions,
            |left, right| left.account == right.account && left.event_digest == right.event_digest,
        )
        .len()
        + removed_rows(
            &before.used_connection_ids,
            &after.used_connection_ids,
            PartialEq::eq,
        )
        .len()
        + removed_rows(&before.outbox, &after.outbox, |left, right| {
            left.effect_id == right.effect_id
        })
        .len()
        + removed_rows(&before.deadlines, &after.deadlines, |left, right| {
            left.call_id == right.call_id
                && left.kind == right.kind
                && left.generation == right.generation
        })
        .len()
        + removed_rows(
            &before.service_managed_calls,
            &after.service_managed_calls,
            PartialEq::eq,
        )
        .len()
        + removed_rows(
            &before.execution_plans,
            &after.execution_plans,
            |left, right| left.call_id == right.call_id,
        )
        .len()
        + removed_rows(
            &before.service_effect_payloads,
            &after.service_effect_payloads,
            |left, right| left.effect_id == right.effect_id,
        )
        .len()
        + removed_rows(
            &before.service_command_results,
            &after.service_command_results,
            |left, right| left.command_id == right.command_id,
        )
        .len()
        + removed_rows(
            &before.control_sequences,
            &after.control_sequences,
            |left, right| {
                left.call_id == right.call_id
                    && left.leg_id == right.leg_id
                    && left.binding_generation == right.binding_generation
            },
        )
        .len()
        + removed_rows(
            &before.control_commands,
            &after.control_commands,
            |left, right| left.command_id == right.command_id,
        )
        .len()
        + removed_rows(
            &before.control_outbox,
            &after.control_outbox,
            |left, right| left.effect_id == right.effect_id,
        )
        .len()
        + removed_rows(
            &before.outbound_binding_results,
            &after.outbound_binding_results,
            |left, right| left.operation_id == right.operation_id,
        )
        .len()
        + removed_rows(
            &before.external_references,
            &after.external_references,
            |left, right| left.value == right.value,
        )
        .len()
        + removed_rows(
            &before.reconciliation_results,
            &after.reconciliation_results,
            |left, right| left.effect_id == right.effect_id,
        )
        .len()
        + removed_rows(
            &before.retired_operation_claims,
            &after.retired_operation_claims,
            |left, right| left.command_id == right.command_id,
        )
        .len()
        + removed_rows(
            &before.control_retirements,
            &after.control_retirements,
            |left, right| left.effect_id == right.effect_id,
        )
        .len();
    if unsupported == 0 {
        Ok(())
    } else {
        Err(RepositoryError::Unavailable)
    }
}

async fn persist_sqlite_delta(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    before: &MemoryStateSnapshot,
    after: &MemoryStateSnapshot,
) -> Result<(), RepositoryError> {
    validate_supported_removals(before, after)?;
    for call in &before.calls {
        let current = after
            .calls
            .iter()
            .find(|candidate| candidate.aggregate.id() == call.aggregate.id());
        for binding in call.bindings.values() {
            let retained = current.is_some_and(|current| {
                current
                    .bindings
                    .values()
                    .any(|candidate| candidate.connection_id == binding.connection_id)
            });
            if !retained {
                sqlx::query("DELETE FROM connection_bindings WHERE connection_id = ?")
                    .bind(binding.connection_id.as_str())
                    .execute(&mut **transaction)
                    .await
                    .map_err(database_error)?;
            }
        }
    }
    for expired in removed_rows(&before.idempotency, &after.idempotency, |left, right| {
        left.tenant_id == right.tenant_id && left.key_digest == right.key_digest
    }) {
        sqlx::query("DELETE FROM idempotency WHERE tenant_id = ? AND key_digest = ?")
            .bind(expired.tenant_id.as_str())
            .bind(expired.key_digest.expose_bytes().as_slice())
            .execute(&mut **transaction)
            .await
            .map_err(database_error)?;
    }
    upsert_sqlite_rows(transaction, &changed_snapshot(before, after)).await
}

async fn persist_postgres_delta(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    before: &MemoryStateSnapshot,
    after: &MemoryStateSnapshot,
) -> Result<(), RepositoryError> {
    validate_supported_removals(before, after)?;
    for call in &before.calls {
        let current = after
            .calls
            .iter()
            .find(|candidate| candidate.aggregate.id() == call.aggregate.id());
        for binding in call.bindings.values() {
            let retained = current.is_some_and(|current| {
                current
                    .bindings
                    .values()
                    .any(|candidate| candidate.connection_id == binding.connection_id)
            });
            if !retained {
                sqlx::query("DELETE FROM connection_bindings WHERE connection_id = $1")
                    .bind(binding.connection_id.as_str())
                    .execute(&mut **transaction)
                    .await
                    .map_err(database_error)?;
            }
        }
    }
    for expired in removed_rows(&before.idempotency, &after.idempotency, |left, right| {
        left.tenant_id == right.tenant_id && left.key_digest == right.key_digest
    }) {
        sqlx::query("DELETE FROM idempotency WHERE tenant_id = $1 AND key_digest = $2")
            .bind(expired.tenant_id.as_str())
            .bind(expired.key_digest.expose_bytes().as_slice())
            .execute(&mut **transaction)
            .await
            .map_err(database_error)?;
    }
    upsert_postgres_rows(transaction, &changed_snapshot(before, after)).await
}

async fn upsert_sqlite_rows(
    connection: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    snapshot: &MemoryStateSnapshot,
) -> Result<(), RepositoryError> {
    for worker in &snapshot.workers {
        sqlx::query(
            "INSERT INTO workers(worker_id, fence, max_calls, reserved_calls, draining, updated_at, body) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(worker_id) DO UPDATE SET fence=excluded.fence, max_calls=excluded.max_calls, reserved_calls=excluded.reserved_calls, draining=excluded.draining, updated_at=excluded.updated_at, body=excluded.body",
        )
        .bind(worker.lease.worker_id.to_string())
        .bind(worker.lease.fence.as_i64())
        .bind(i64::try_from(worker.max_calls).map_err(|_| RepositoryError::Unavailable)?)
        .bind(i64::try_from(worker.reserved_calls).map_err(|_| RepositoryError::Unavailable)?)
        .bind(worker.draining)
        .bind(worker.updated_at.to_rfc3339())
        .bind(encode(worker)?)
        .execute(&mut **connection)
        .await
        .map_err(database_error)?;
    }

    for call in &snapshot.calls {
        let call_id = call.aggregate.id();
        let tenant_id = call.aggregate.tenant_id();
        sqlx::query(
            "INSERT INTO calls(call_id, tenant_id, aggregate_version, call_state, body) VALUES (?, ?, ?, ?, ?) ON CONFLICT(call_id) DO UPDATE SET tenant_id=excluded.tenant_id, aggregate_version=excluded.aggregate_version, call_state=excluded.call_state, body=excluded.body",
        )
        .bind(call_id.to_string())
        .bind(tenant_id.as_str())
        .bind(call.aggregate.version().as_i64())
        .bind(state_name(&call.aggregate.state())?)
        .bind(encode(&call.aggregate)?)
        .execute(&mut **connection)
        .await
        .map_err(database_error)?;

        for leg in call.aggregate.legs() {
            sqlx::query(
                "INSERT INTO legs(leg_id, call_id, tenant_id, binding_generation, leg_state, body) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(leg_id) DO UPDATE SET call_id=excluded.call_id, tenant_id=excluded.tenant_id, binding_generation=excluded.binding_generation, leg_state=excluded.leg_state, body=excluded.body",
            )
            .bind(leg.id().to_string())
            .bind(call_id.to_string())
            .bind(tenant_id.as_str())
            .bind(leg.binding_generation().as_i64())
            .bind(state_name(&leg.state())?)
            .bind(encode(leg)?)
            .execute(&mut **connection)
            .await
            .map_err(database_error)?;
        }

        sqlx::query(
            "INSERT INTO worker_assignments(call_id, worker_id, worker_fence, assigned_at, released_at, body) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(call_id) DO UPDATE SET worker_id=excluded.worker_id, worker_fence=excluded.worker_fence, assigned_at=excluded.assigned_at, released_at=excluded.released_at, body=excluded.body",
        )
        .bind(call_id.to_string())
        .bind(call.assignment.lease.worker_id.to_string())
        .bind(call.assignment.lease.fence.as_i64())
        .bind(call.assignment.assigned_at.to_rfc3339())
        .bind(call.assignment.released_at.map(|at| at.to_rfc3339()))
        .bind(encode(&call.assignment)?)
        .execute(&mut **connection)
        .await
        .map_err(database_error)?;

        for binding in call.bindings.values() {
            sqlx::query(
                "INSERT INTO connection_bindings(connection_id, call_id, leg_id, binding_generation, principal_fingerprint, body) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(connection_id) DO UPDATE SET call_id=excluded.call_id, leg_id=excluded.leg_id, binding_generation=excluded.binding_generation, principal_fingerprint=excluded.principal_fingerprint, body=excluded.body",
            )
            .bind(binding.connection_id.to_string())
            .bind(call_id.to_string())
            .bind(binding.leg_id.to_string())
            .bind(binding.binding_generation.as_i64())
            .bind(binding.principal_fingerprint.expose_bytes().as_slice())
            .bind(encode(binding)?)
            .execute(&mut **connection)
            .await
            .map_err(database_error)?;
        }
    }

    for call_id in &snapshot.service_managed_calls {
        let changed = sqlx::query("UPDATE calls SET service_managed = 1 WHERE call_id = ?")
            .bind(call_id.to_string())
            .execute(&mut **connection)
            .await
            .map_err(database_error)?;
        if changed.rows_affected() != 1 {
            return Err(RepositoryError::Unavailable);
        }
    }

    for persisted in &snapshot.commands {
        let command = &persisted.command;
        sqlx::query(
            "INSERT INTO commands(command_id, tenant_id, call_id, observed_version, result_version, recorded_at, body) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(command_id) DO UPDATE SET tenant_id=excluded.tenant_id, call_id=excluded.call_id, observed_version=excluded.observed_version, result_version=excluded.result_version, recorded_at=excluded.recorded_at, body=excluded.body",
        )
        .bind(command.command_id.to_string())
        .bind(command.tenant_id.as_str())
        .bind(command.call_id.to_string())
        .bind(command.observed_version.as_i64())
        .bind(command.result_version.as_i64())
        .bind(command.recorded_at.to_rfc3339())
        .bind(encode(persisted)?)
        .execute(&mut **connection)
        .await
        .map_err(database_error)?;
    }

    for persisted in &snapshot.idempotency {
        let (receipt_kind, operation_kind) = idempotency_receipt_columns(&persisted.row.receipt);
        sqlx::query(
            "INSERT INTO idempotency(tenant_id, key_digest, request_digest, call_id, expires_at, receipt_kind, operation_kind, body) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(tenant_id, key_digest) DO UPDATE SET request_digest=excluded.request_digest, call_id=excluded.call_id, expires_at=excluded.expires_at, receipt_kind=excluded.receipt_kind, operation_kind=excluded.operation_kind, body=excluded.body",
        )
        .bind(persisted.tenant_id.as_str())
        .bind(persisted.key_digest.expose_bytes().as_slice())
        .bind(persisted.row.request_digest.expose_bytes().as_slice())
        .bind(persisted.row.call_id.to_string())
        .bind(persisted.row.expires_at.to_rfc3339())
        .bind(receipt_kind)
        .bind(operation_kind)
        .bind(encode(persisted)?)
        .execute(&mut **connection)
        .await
        .map_err(database_error)?;
    }

    for attachment in &snapshot.attachments {
        sqlx::query(
            "INSERT INTO attachments(token_digest, attachment_id, tenant_id, call_id, leg_id, binding_generation, worker_id, worker_fence, expires_at, consumed_at, revoked_at, body) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(token_digest) DO UPDATE SET attachment_id=excluded.attachment_id, tenant_id=excluded.tenant_id, call_id=excluded.call_id, leg_id=excluded.leg_id, binding_generation=excluded.binding_generation, worker_id=excluded.worker_id, worker_fence=excluded.worker_fence, expires_at=excluded.expires_at, consumed_at=excluded.consumed_at, revoked_at=excluded.revoked_at, body=excluded.body",
        )
        .bind(attachment.token_digest.expose_bytes().as_slice())
        .bind(attachment.attachment_id.to_string())
        .bind(attachment.tenant_id.as_str())
        .bind(attachment.call_id.to_string())
        .bind(attachment.leg_id.to_string())
        .bind(attachment.binding_generation.as_i64())
        .bind(attachment.worker.worker_id.to_string())
        .bind(attachment.worker.fence.as_i64())
        .bind(attachment.expires_at.to_rfc3339())
        .bind(attachment.consumed_at.map(|at| at.to_rfc3339()))
        .bind(attachment.revoked_at.map(|at| at.to_rfc3339()))
        .bind(encode(attachment)?)
        .execute(&mut **connection)
        .await
        .map_err(database_error)?;
    }

    for persisted in &snapshot.provider_references {
        sqlx::query(
            "INSERT INTO provider_references(account_key, provider_call_id, tenant_id, call_id, leg_id, bound_at, body) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(account_key, provider_call_id) DO UPDATE SET tenant_id=excluded.tenant_id, call_id=excluded.call_id, leg_id=excluded.leg_id, bound_at=excluded.bound_at, body=excluded.body",
        )
        .bind(persisted.account.as_str())
        .bind(persisted.provider_call_id.expose_secret())
        .bind(persisted.row.target.tenant_id.as_str())
        .bind(persisted.row.target.call_id.to_string())
        .bind(persisted.row.target.leg_id.to_string())
        .bind(persisted.row.bound_at.to_rfc3339())
        .bind(encode(persisted)?)
        .execute(&mut **connection)
        .await
        .map_err(database_error)?;
    }

    for event in &snapshot.provider_events {
        sqlx::query(
            "INSERT INTO provider_events(account_key, event_digest, payload_digest, provider_call_id, receipt_sequence, received_at, event_state, body) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(account_key, event_digest) DO UPDATE SET payload_digest=excluded.payload_digest, provider_call_id=excluded.provider_call_id, receipt_sequence=excluded.receipt_sequence, received_at=excluded.received_at, event_state=excluded.event_state, body=excluded.body",
        )
        .bind(event.account.as_str())
        .bind(event.event_digest.expose_bytes().as_slice())
        .bind(event.payload_digest.expose_bytes().as_slice())
        .bind(event.provider_call_id.expose_secret())
        .bind(event.receipt_sequence.as_i64())
        .bind(event.received_at.to_rfc3339())
        .bind(state_name(&event.state)?)
        .bind(encode(event)?)
        .execute(&mut **connection)
        .await
        .map_err(database_error)?;
    }

    for completion in &snapshot.provider_completions {
        let completion_kind = match &completion.row {
            ProviderCompletionRow::Command { .. } => "command",
            ProviderCompletionRow::TerminalAcknowledgement { .. } => "terminal_acknowledgement",
        };
        sqlx::query(
            "INSERT INTO provider_completions(account_key, event_digest, completion_kind, body) VALUES (?, ?, ?, ?) ON CONFLICT(account_key, event_digest) DO UPDATE SET completion_kind=excluded.completion_kind, body=excluded.body",
        )
        .bind(completion.account.as_str())
        .bind(completion.event_digest.expose_bytes().as_slice())
        .bind(completion_kind)
        .bind(encode(completion)?)
        .execute(&mut **connection)
        .await
        .map_err(database_error)?;
    }

    for connection_id in &snapshot.used_connection_ids {
        sqlx::query("INSERT INTO used_connection_ids(connection_id) VALUES (?) ON CONFLICT(connection_id) DO NOTHING")
            .bind(connection_id.as_str())
            .execute(&mut **connection)
            .await
            .map_err(database_error)?;
    }

    for record in &snapshot.outbox {
        sqlx::query(
            "INSERT INTO outbox(effect_id, command_id, ordinal, tenant_id, call_id, aggregate_version, worker_id, worker_fence, available_at, outbox_state, body) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(effect_id) DO UPDATE SET command_id=excluded.command_id, ordinal=excluded.ordinal, tenant_id=excluded.tenant_id, call_id=excluded.call_id, aggregate_version=excluded.aggregate_version, worker_id=excluded.worker_id, worker_fence=excluded.worker_fence, available_at=excluded.available_at, outbox_state=excluded.outbox_state, body=excluded.body",
        )
        .bind(record.effect_id.to_string())
        .bind(record.command_id.to_string())
        .bind(i64::from(record.ordinal))
        .bind(record.tenant_id.as_str())
        .bind(record.call_id.to_string())
        .bind(record.aggregate_version.as_i64())
        .bind(record.worker.worker_id.to_string())
        .bind(record.worker.fence.as_i64())
        .bind(record.available_at.to_rfc3339())
        .bind(state_name(&record.state)?)
        .bind(encode(record)?)
        .execute(&mut **connection)
        .await
        .map_err(database_error)?;
    }

    for record in &snapshot.deadlines {
        sqlx::query(
            "INSERT INTO deadlines(call_id, deadline_kind, generation, tenant_id, due_at, deadline_state, body) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(call_id, deadline_kind, generation) DO UPDATE SET tenant_id=excluded.tenant_id, due_at=excluded.due_at, deadline_state=excluded.deadline_state, body=excluded.body",
        )
        .bind(record.call_id.to_string())
        .bind(state_name(&record.kind)?)
        .bind(record.generation.as_i64())
        .bind(record.tenant_id.as_str())
        .bind(record.due_at.to_rfc3339())
        .bind(state_name(&record.state)?)
        .bind(encode(record)?)
        .execute(&mut **connection)
        .await
        .map_err(database_error)?;
    }

    for persisted in &snapshot.execution_plans {
        let [first, second] = &persisted.plan.legs;
        sqlx::query(
            "INSERT INTO call_execution_plans(call_id, plan_version, first_leg_id, first_endpoint_kind, second_leg_id, second_endpoint_kind, body) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(call_id) DO UPDATE SET plan_version=excluded.plan_version, first_leg_id=excluded.first_leg_id, first_endpoint_kind=excluded.first_endpoint_kind, second_leg_id=excluded.second_leg_id, second_endpoint_kind=excluded.second_endpoint_kind, body=excluded.body",
        )
        .bind(persisted.call_id.to_string())
        .bind(i64::from(persisted.plan.version))
        .bind(first.leg_id.to_string())
        .bind(endpoint_kind(&first.endpoint))
        .bind(second.leg_id.to_string())
        .bind(endpoint_kind(&second.endpoint))
        .bind(encode(persisted)?)
        .execute(&mut **connection)
        .await
        .map_err(database_error)?;
    }

    for persisted in &snapshot.service_command_results {
        let command = &persisted.result.view.command.command;
        sqlx::query(
            "INSERT INTO service_command_results(command_id, tenant_id, call_id, recorded_at, body) VALUES (?, ?, ?, ?, ?) ON CONFLICT(command_id) DO UPDATE SET tenant_id=excluded.tenant_id, call_id=excluded.call_id, recorded_at=excluded.recorded_at, body=excluded.body",
        )
        .bind(persisted.command_id.to_string())
        .bind(command.tenant_id.as_str())
        .bind(command.call_id.to_string())
        .bind(command.recorded_at.to_rfc3339())
        .bind(encode(persisted)?)
        .execute(&mut **connection)
        .await
        .map_err(database_error)?;
    }

    for payload in &snapshot.service_effect_payloads {
        sqlx::query(
            "INSERT INTO service_effect_payloads(effect_id, command_id, ordinal, payload_kind, body) VALUES (?, ?, ?, ?, ?) ON CONFLICT(effect_id) DO UPDATE SET command_id=excluded.command_id, ordinal=excluded.ordinal, payload_kind=excluded.payload_kind, body=excluded.body",
        )
        .bind(payload.effect_id.to_string())
        .bind(payload.command_id.to_string())
        .bind(i64::from(payload.ordinal))
        .bind(service_payload_kind(&payload.payload))
        .bind(encode(payload)?)
        .execute(&mut **connection)
        .await
        .map_err(database_error)?;
    }

    for persisted in &snapshot.control_sequences {
        sqlx::query(
            "INSERT INTO control_sequences(call_id, leg_id, binding_generation, last_sequence, body) VALUES (?, ?, ?, ?, ?) ON CONFLICT(call_id, leg_id, binding_generation) DO UPDATE SET last_sequence=excluded.last_sequence, body=excluded.body",
        )
        .bind(persisted.call_id.to_string())
        .bind(persisted.leg_id.to_string())
        .bind(persisted.binding_generation.as_i64())
        .bind(persisted.sequence.as_i64())
        .bind(encode(persisted)?)
        .execute(&mut **connection)
        .await
        .map_err(database_error)?;
    }

    for persisted in &snapshot.control_commands {
        let command = &persisted.result.view.command;
        sqlx::query(
            "INSERT INTO control_commands(command_id, tenant_id, call_id, leg_id, binding_generation, worker_id, worker_fence, control_kind, recorded_at, effect_id, body) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(command_id) DO UPDATE SET tenant_id=excluded.tenant_id, call_id=excluded.call_id, leg_id=excluded.leg_id, binding_generation=excluded.binding_generation, worker_id=excluded.worker_id, worker_fence=excluded.worker_fence, control_kind=excluded.control_kind, recorded_at=excluded.recorded_at, effect_id=excluded.effect_id, body=excluded.body",
        )
        .bind(persisted.command_id.to_string())
        .bind(command.tenant_id.as_str())
        .bind(command.call_id.to_string())
        .bind(command.leg_id.to_string())
        .bind(command.binding_generation.as_i64())
        .bind(command.worker.worker_id.to_string())
        .bind(command.worker.fence.as_i64())
        .bind(control_kind(&command.intent))
        .bind(command.recorded_at.to_rfc3339())
        .bind(persisted.result.view.effect.effect_id.to_string())
        .bind(encode(persisted)?)
        .execute(&mut **connection)
        .await
        .map_err(database_error)?;
    }

    for record in &snapshot.control_outbox {
        sqlx::query(
            "INSERT INTO control_outbox(effect_id, command_id, tenant_id, call_id, leg_id, binding_generation, worker_id, worker_fence, sequence, available_at, outbox_state, body) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(effect_id) DO UPDATE SET command_id=excluded.command_id, tenant_id=excluded.tenant_id, call_id=excluded.call_id, leg_id=excluded.leg_id, binding_generation=excluded.binding_generation, worker_id=excluded.worker_id, worker_fence=excluded.worker_fence, sequence=excluded.sequence, available_at=excluded.available_at, outbox_state=excluded.outbox_state, body=excluded.body",
        )
        .bind(record.effect_id.to_string())
        .bind(record.command_id.to_string())
        .bind(record.tenant_id.as_str())
        .bind(record.call_id.to_string())
        .bind(record.leg_id.to_string())
        .bind(record.binding_generation.as_i64())
        .bind(record.worker.worker_id.to_string())
        .bind(record.worker.fence.as_i64())
        .bind(record.sequence.as_i64())
        .bind(record.available_at.to_rfc3339())
        .bind(state_name(&record.state)?)
        .bind(encode(record)?)
        .execute(&mut **connection)
        .await
        .map_err(database_error)?;
    }

    for persisted in &snapshot.outbound_binding_results {
        let request = &persisted.result.request;
        sqlx::query(
            "INSERT INTO outbound_binding_results(operation_id, tenant_id, call_id, leg_id, binding_generation, worker_id, worker_fence, connection_id, transport_kind, bound_at, body) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(operation_id) DO UPDATE SET tenant_id=excluded.tenant_id, call_id=excluded.call_id, leg_id=excluded.leg_id, binding_generation=excluded.binding_generation, worker_id=excluded.worker_id, worker_fence=excluded.worker_fence, connection_id=excluded.connection_id, transport_kind=excluded.transport_kind, bound_at=excluded.bound_at, body=excluded.body",
        )
        .bind(persisted.operation_id.to_string())
        .bind(request.tenant_id.as_str())
        .bind(request.call_id.to_string())
        .bind(request.leg_id.to_string())
        .bind(request.binding_generation.as_i64())
        .bind(request.worker.worker_id.to_string())
        .bind(request.worker.fence.as_i64())
        .bind(request.connection_id.as_str())
        .bind(state_name(&request.transport)?)
        .bind(request.at.to_rfc3339())
        .bind(encode(persisted)?)
        .execute(&mut **connection)
        .await
        .map_err(database_error)?;
    }

    for reference in &snapshot.external_references {
        let (kind, namespace, value) = external_reference_columns(&reference.value);
        sqlx::query(
            "INSERT INTO external_references(reference_kind, reference_namespace, reference_value, tenant_id, call_id, leg_id, binding_generation, effect_id, bound_at, body) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(reference_kind, reference_namespace, reference_value) DO UPDATE SET tenant_id=excluded.tenant_id, call_id=excluded.call_id, leg_id=excluded.leg_id, binding_generation=excluded.binding_generation, effect_id=excluded.effect_id, bound_at=excluded.bound_at, body=excluded.body",
        )
        .bind(kind)
        .bind(namespace)
        .bind(value)
        .bind(reference.tenant_id.as_str())
        .bind(reference.call_id.to_string())
        .bind(reference.leg_id.to_string())
        .bind(reference.binding_generation.as_i64())
        .bind(reference.effect_id.to_string())
        .bind(reference.bound_at.to_rfc3339())
        .bind(encode(reference)?)
        .execute(&mut **connection)
        .await
        .map_err(database_error)?;
    }

    for persisted in &snapshot.reconciliation_results {
        let request = &persisted.result.request;
        sqlx::query(
            "INSERT INTO reconciliation_results(effect_id, effect_source, tenant_id, call_id, worker_id, worker_fence, result_kind, reconciled_at, body) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(effect_id) DO UPDATE SET effect_source=excluded.effect_source, tenant_id=excluded.tenant_id, call_id=excluded.call_id, worker_id=excluded.worker_id, worker_fence=excluded.worker_fence, result_kind=excluded.result_kind, reconciled_at=excluded.reconciled_at, body=excluded.body",
        )
        .bind(persisted.effect_id.to_string())
        .bind(completed_effect_source(&persisted.result.view.effect))
        .bind(request.tenant_id.as_str())
        .bind(request.call_id.to_string())
        .bind(request.worker.worker_id.to_string())
        .bind(request.worker.fence.as_i64())
        .bind(service_result_kind(&request.result))
        .bind(request.at.to_rfc3339())
        .bind(encode(persisted)?)
        .execute(&mut **connection)
        .await
        .map_err(database_error)?;
    }
    for retired in &snapshot.retired_operation_claims {
        sqlx::query(
            "INSERT INTO retired_operation_claims(command_id, receipt_kind, tenant_id, key_digest, request_digest, call_id, operation_kind, expires_at, retired_at, body) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(command_id) DO UPDATE SET receipt_kind=excluded.receipt_kind, tenant_id=excluded.tenant_id, key_digest=excluded.key_digest, request_digest=excluded.request_digest, call_id=excluded.call_id, operation_kind=excluded.operation_kind, expires_at=excluded.expires_at, retired_at=excluded.retired_at, body=excluded.body",
        )
        .bind(retired.command_id.to_string())
        .bind(retired_receipt_kind(retired.receipt_kind))
        .bind(retired.tenant_id.as_str())
        .bind(retired.key_digest.expose_bytes().as_slice())
        .bind(retired.request_digest.expose_bytes().as_slice())
        .bind(retired.call_id.to_string())
        .bind(service_operation_kind(retired.operation))
        .bind(retired.expires_at.to_rfc3339())
        .bind(retired.retired_at.to_rfc3339())
        .bind(encode(retired)?)
        .execute(&mut **connection)
        .await
        .map_err(database_error)?;
    }
    for receipt in &snapshot.control_retirements {
        sqlx::query(
            "INSERT INTO control_outbox_retirements(effect_id, command_id, tenant_id, call_id, leg_id, binding_generation, retired_at, failure_code, body) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(effect_id) DO UPDATE SET command_id=excluded.command_id, tenant_id=excluded.tenant_id, call_id=excluded.call_id, leg_id=excluded.leg_id, binding_generation=excluded.binding_generation, retired_at=excluded.retired_at, failure_code=excluded.failure_code, body=excluded.body",
        )
        .bind(receipt.effect_id.to_string())
        .bind(receipt.command_id.to_string())
        .bind(receipt.tenant_id.as_str())
        .bind(receipt.call_id.to_string())
        .bind(receipt.leg_id.to_string())
        .bind(receipt.binding_generation.as_i64())
        .bind(receipt.retired_at.to_rfc3339())
        .bind(receipt.failure.code())
        .bind(encode(receipt)?)
        .execute(&mut **connection)
        .await
        .map_err(database_error)?;
    }
    Ok(())
}

async fn upsert_postgres_rows(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    snapshot: &MemoryStateSnapshot,
) -> Result<(), RepositoryError> {
    for worker in &snapshot.workers {
        sqlx::query(
            "INSERT INTO workers(worker_id, fence, max_calls, reserved_calls, draining, updated_at, body) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb) ON CONFLICT(worker_id) DO UPDATE SET fence=EXCLUDED.fence, max_calls=EXCLUDED.max_calls, reserved_calls=EXCLUDED.reserved_calls, draining=EXCLUDED.draining, updated_at=EXCLUDED.updated_at, body=EXCLUDED.body",
        )
        .bind(worker.lease.worker_id.as_uuid())
        .bind(worker.lease.fence.as_i64())
        .bind(i64::try_from(worker.max_calls).map_err(|_| RepositoryError::Unavailable)?)
        .bind(i64::try_from(worker.reserved_calls).map_err(|_| RepositoryError::Unavailable)?)
        .bind(worker.draining)
        .bind(worker.updated_at)
        .bind(encode(worker)?)
        .execute(&mut **transaction)
        .await
        .map_err(database_error)?;
    }

    for call in &snapshot.calls {
        let call_id = call.aggregate.id();
        let tenant_id = call.aggregate.tenant_id();
        sqlx::query(
            "INSERT INTO calls(call_id, tenant_id, aggregate_version, call_state, body) VALUES ($1, $2, $3, $4, $5::jsonb) ON CONFLICT(call_id) DO UPDATE SET tenant_id=EXCLUDED.tenant_id, aggregate_version=EXCLUDED.aggregate_version, call_state=EXCLUDED.call_state, body=EXCLUDED.body",
        )
        .bind(call_id.as_uuid())
        .bind(tenant_id.as_str())
        .bind(call.aggregate.version().as_i64())
        .bind(state_name(&call.aggregate.state())?)
        .bind(encode(&call.aggregate)?)
        .execute(&mut **transaction)
        .await
        .map_err(database_error)?;

        for leg in call.aggregate.legs() {
            sqlx::query(
                "INSERT INTO legs(leg_id, call_id, tenant_id, binding_generation, leg_state, body) VALUES ($1, $2, $3, $4, $5, $6::jsonb) ON CONFLICT(leg_id) DO UPDATE SET call_id=EXCLUDED.call_id, tenant_id=EXCLUDED.tenant_id, binding_generation=EXCLUDED.binding_generation, leg_state=EXCLUDED.leg_state, body=EXCLUDED.body",
            )
            .bind(leg.id().as_uuid())
            .bind(call_id.as_uuid())
            .bind(tenant_id.as_str())
            .bind(leg.binding_generation().as_i64())
            .bind(state_name(&leg.state())?)
            .bind(encode(leg)?)
            .execute(&mut **transaction)
            .await
            .map_err(database_error)?;
        }

        sqlx::query(
            "INSERT INTO worker_assignments(call_id, worker_id, worker_fence, assigned_at, released_at, body) VALUES ($1, $2, $3, $4, $5, $6::jsonb) ON CONFLICT(call_id) DO UPDATE SET worker_id=EXCLUDED.worker_id, worker_fence=EXCLUDED.worker_fence, assigned_at=EXCLUDED.assigned_at, released_at=EXCLUDED.released_at, body=EXCLUDED.body",
        )
        .bind(call_id.as_uuid())
        .bind(call.assignment.lease.worker_id.as_uuid())
        .bind(call.assignment.lease.fence.as_i64())
        .bind(call.assignment.assigned_at)
        .bind(call.assignment.released_at)
        .bind(encode(&call.assignment)?)
        .execute(&mut **transaction)
        .await
        .map_err(database_error)?;

        for binding in call.bindings.values() {
            sqlx::query(
                "INSERT INTO connection_bindings(connection_id, call_id, leg_id, binding_generation, principal_fingerprint, body) VALUES ($1, $2, $3, $4, $5, $6::jsonb) ON CONFLICT(connection_id) DO UPDATE SET call_id=EXCLUDED.call_id, leg_id=EXCLUDED.leg_id, binding_generation=EXCLUDED.binding_generation, principal_fingerprint=EXCLUDED.principal_fingerprint, body=EXCLUDED.body",
            )
            .bind(binding.connection_id.to_string())
            .bind(call_id.as_uuid())
            .bind(binding.leg_id.as_uuid())
            .bind(binding.binding_generation.as_i64())
            .bind(binding.principal_fingerprint.expose_bytes().as_slice())
            .bind(encode(binding)?)
            .execute(&mut **transaction)
            .await
            .map_err(database_error)?;
        }
    }

    for call_id in &snapshot.service_managed_calls {
        let changed = sqlx::query("UPDATE calls SET service_managed = TRUE WHERE call_id = $1")
            .bind(call_id.as_uuid())
            .execute(&mut **transaction)
            .await
            .map_err(database_error)?;
        if changed.rows_affected() != 1 {
            return Err(RepositoryError::Unavailable);
        }
    }

    for persisted in &snapshot.commands {
        let command = &persisted.command;
        sqlx::query(
            "INSERT INTO commands(command_id, tenant_id, call_id, observed_version, result_version, recorded_at, body) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb) ON CONFLICT(command_id) DO UPDATE SET tenant_id=EXCLUDED.tenant_id, call_id=EXCLUDED.call_id, observed_version=EXCLUDED.observed_version, result_version=EXCLUDED.result_version, recorded_at=EXCLUDED.recorded_at, body=EXCLUDED.body",
        )
        .bind(command.command_id.as_uuid())
        .bind(command.tenant_id.as_str())
        .bind(command.call_id.as_uuid())
        .bind(command.observed_version.as_i64())
        .bind(command.result_version.as_i64())
        .bind(command.recorded_at)
        .bind(encode(persisted)?)
        .execute(&mut **transaction)
        .await
        .map_err(database_error)?;
    }

    for persisted in &snapshot.idempotency {
        let (receipt_kind, operation_kind) = idempotency_receipt_columns(&persisted.row.receipt);
        sqlx::query(
            "INSERT INTO idempotency(tenant_id, key_digest, request_digest, call_id, expires_at, receipt_kind, operation_kind, body) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb) ON CONFLICT(tenant_id, key_digest) DO UPDATE SET request_digest=EXCLUDED.request_digest, call_id=EXCLUDED.call_id, expires_at=EXCLUDED.expires_at, receipt_kind=EXCLUDED.receipt_kind, operation_kind=EXCLUDED.operation_kind, body=EXCLUDED.body",
        )
        .bind(persisted.tenant_id.as_str())
        .bind(persisted.key_digest.expose_bytes().as_slice())
        .bind(persisted.row.request_digest.expose_bytes().as_slice())
        .bind(persisted.row.call_id.as_uuid())
        .bind(persisted.row.expires_at)
        .bind(receipt_kind)
        .bind(operation_kind)
        .bind(encode(persisted)?)
        .execute(&mut **transaction)
        .await
        .map_err(database_error)?;
    }

    for attachment in &snapshot.attachments {
        sqlx::query(
            "INSERT INTO attachments(token_digest, attachment_id, tenant_id, call_id, leg_id, binding_generation, worker_id, worker_fence, expires_at, consumed_at, revoked_at, body) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb) ON CONFLICT(token_digest) DO UPDATE SET attachment_id=EXCLUDED.attachment_id, tenant_id=EXCLUDED.tenant_id, call_id=EXCLUDED.call_id, leg_id=EXCLUDED.leg_id, binding_generation=EXCLUDED.binding_generation, worker_id=EXCLUDED.worker_id, worker_fence=EXCLUDED.worker_fence, expires_at=EXCLUDED.expires_at, consumed_at=EXCLUDED.consumed_at, revoked_at=EXCLUDED.revoked_at, body=EXCLUDED.body",
        )
        .bind(attachment.token_digest.expose_bytes().as_slice())
        .bind(attachment.attachment_id.as_uuid())
        .bind(attachment.tenant_id.as_str())
        .bind(attachment.call_id.as_uuid())
        .bind(attachment.leg_id.as_uuid())
        .bind(attachment.binding_generation.as_i64())
        .bind(attachment.worker.worker_id.as_uuid())
        .bind(attachment.worker.fence.as_i64())
        .bind(attachment.expires_at)
        .bind(attachment.consumed_at)
        .bind(attachment.revoked_at)
        .bind(encode(attachment)?)
        .execute(&mut **transaction)
        .await
        .map_err(database_error)?;
    }

    for persisted in &snapshot.provider_references {
        sqlx::query(
            "INSERT INTO provider_references(account_key, provider_call_id, tenant_id, call_id, leg_id, bound_at, body) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb) ON CONFLICT(account_key, provider_call_id) DO UPDATE SET tenant_id=EXCLUDED.tenant_id, call_id=EXCLUDED.call_id, leg_id=EXCLUDED.leg_id, bound_at=EXCLUDED.bound_at, body=EXCLUDED.body",
        )
        .bind(persisted.account.as_str())
        .bind(persisted.provider_call_id.expose_secret())
        .bind(persisted.row.target.tenant_id.as_str())
        .bind(persisted.row.target.call_id.as_uuid())
        .bind(persisted.row.target.leg_id.as_uuid())
        .bind(persisted.row.bound_at)
        .bind(encode(persisted)?)
        .execute(&mut **transaction)
        .await
        .map_err(database_error)?;
    }

    for event in &snapshot.provider_events {
        sqlx::query(
            "INSERT INTO provider_events(account_key, event_digest, payload_digest, provider_call_id, receipt_sequence, received_at, event_state, body) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb) ON CONFLICT(account_key, event_digest) DO UPDATE SET payload_digest=EXCLUDED.payload_digest, provider_call_id=EXCLUDED.provider_call_id, receipt_sequence=EXCLUDED.receipt_sequence, received_at=EXCLUDED.received_at, event_state=EXCLUDED.event_state, body=EXCLUDED.body",
        )
        .bind(event.account.as_str())
        .bind(event.event_digest.expose_bytes().as_slice())
        .bind(event.payload_digest.expose_bytes().as_slice())
        .bind(event.provider_call_id.expose_secret())
        .bind(event.receipt_sequence.as_i64())
        .bind(event.received_at)
        .bind(state_name(&event.state)?)
        .bind(encode(event)?)
        .execute(&mut **transaction)
        .await
        .map_err(database_error)?;
    }

    for completion in &snapshot.provider_completions {
        let completion_kind = match &completion.row {
            ProviderCompletionRow::Command { .. } => "command",
            ProviderCompletionRow::TerminalAcknowledgement { .. } => "terminal_acknowledgement",
        };
        sqlx::query(
            "INSERT INTO provider_completions(account_key, event_digest, completion_kind, body) VALUES ($1, $2, $3, $4::jsonb) ON CONFLICT(account_key, event_digest) DO UPDATE SET completion_kind=EXCLUDED.completion_kind, body=EXCLUDED.body",
        )
        .bind(completion.account.as_str())
        .bind(completion.event_digest.expose_bytes().as_slice())
        .bind(completion_kind)
        .bind(encode(completion)?)
        .execute(&mut **transaction)
        .await
        .map_err(database_error)?;
    }

    for connection_id in &snapshot.used_connection_ids {
        sqlx::query("INSERT INTO used_connection_ids(connection_id) VALUES ($1) ON CONFLICT(connection_id) DO NOTHING")
            .bind(connection_id.as_str())
            .execute(&mut **transaction)
            .await
            .map_err(database_error)?;
    }

    for record in &snapshot.outbox {
        sqlx::query(
            "INSERT INTO outbox(effect_id, command_id, ordinal, tenant_id, call_id, aggregate_version, worker_id, worker_fence, available_at, outbox_state, body) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb) ON CONFLICT(effect_id) DO UPDATE SET command_id=EXCLUDED.command_id, ordinal=EXCLUDED.ordinal, tenant_id=EXCLUDED.tenant_id, call_id=EXCLUDED.call_id, aggregate_version=EXCLUDED.aggregate_version, worker_id=EXCLUDED.worker_id, worker_fence=EXCLUDED.worker_fence, available_at=EXCLUDED.available_at, outbox_state=EXCLUDED.outbox_state, body=EXCLUDED.body",
        )
        .bind(record.effect_id.as_uuid())
        .bind(record.command_id.as_uuid())
        .bind(i64::from(record.ordinal))
        .bind(record.tenant_id.as_str())
        .bind(record.call_id.as_uuid())
        .bind(record.aggregate_version.as_i64())
        .bind(record.worker.worker_id.as_uuid())
        .bind(record.worker.fence.as_i64())
        .bind(record.available_at)
        .bind(state_name(&record.state)?)
        .bind(encode(record)?)
        .execute(&mut **transaction)
        .await
        .map_err(database_error)?;
    }

    for record in &snapshot.deadlines {
        sqlx::query(
            "INSERT INTO deadlines(call_id, deadline_kind, generation, tenant_id, due_at, deadline_state, body) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb) ON CONFLICT(call_id, deadline_kind, generation) DO UPDATE SET tenant_id=EXCLUDED.tenant_id, due_at=EXCLUDED.due_at, deadline_state=EXCLUDED.deadline_state, body=EXCLUDED.body",
        )
        .bind(record.call_id.as_uuid())
        .bind(state_name(&record.kind)?)
        .bind(record.generation.as_i64())
        .bind(record.tenant_id.as_str())
        .bind(record.due_at)
        .bind(state_name(&record.state)?)
        .bind(encode(record)?)
        .execute(&mut **transaction)
        .await
        .map_err(database_error)?;
    }

    for persisted in &snapshot.execution_plans {
        let [first, second] = &persisted.plan.legs;
        sqlx::query(
            "INSERT INTO call_execution_plans(call_id, plan_version, first_leg_id, first_endpoint_kind, second_leg_id, second_endpoint_kind, body) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb) ON CONFLICT(call_id) DO UPDATE SET plan_version=EXCLUDED.plan_version, first_leg_id=EXCLUDED.first_leg_id, first_endpoint_kind=EXCLUDED.first_endpoint_kind, second_leg_id=EXCLUDED.second_leg_id, second_endpoint_kind=EXCLUDED.second_endpoint_kind, body=EXCLUDED.body",
        )
        .bind(persisted.call_id.as_uuid())
        .bind(i64::from(persisted.plan.version))
        .bind(first.leg_id.as_uuid())
        .bind(endpoint_kind(&first.endpoint))
        .bind(second.leg_id.as_uuid())
        .bind(endpoint_kind(&second.endpoint))
        .bind(encode(persisted)?)
        .execute(&mut **transaction)
        .await
        .map_err(database_error)?;
    }

    for persisted in &snapshot.service_command_results {
        let command = &persisted.result.view.command.command;
        sqlx::query(
            "INSERT INTO service_command_results(command_id, tenant_id, call_id, recorded_at, body) VALUES ($1, $2, $3, $4, $5::jsonb) ON CONFLICT(command_id) DO UPDATE SET tenant_id=EXCLUDED.tenant_id, call_id=EXCLUDED.call_id, recorded_at=EXCLUDED.recorded_at, body=EXCLUDED.body",
        )
        .bind(persisted.command_id.as_uuid())
        .bind(command.tenant_id.as_str())
        .bind(command.call_id.as_uuid())
        .bind(command.recorded_at)
        .bind(encode(persisted)?)
        .execute(&mut **transaction)
        .await
        .map_err(database_error)?;
    }

    for payload in &snapshot.service_effect_payloads {
        sqlx::query(
            "INSERT INTO service_effect_payloads(effect_id, command_id, ordinal, payload_kind, body) VALUES ($1, $2, $3, $4, $5::jsonb) ON CONFLICT(effect_id) DO UPDATE SET command_id=EXCLUDED.command_id, ordinal=EXCLUDED.ordinal, payload_kind=EXCLUDED.payload_kind, body=EXCLUDED.body",
        )
        .bind(payload.effect_id.as_uuid())
        .bind(payload.command_id.as_uuid())
        .bind(i64::from(payload.ordinal))
        .bind(service_payload_kind(&payload.payload))
        .bind(encode(payload)?)
        .execute(&mut **transaction)
        .await
        .map_err(database_error)?;
    }

    for persisted in &snapshot.control_sequences {
        sqlx::query(
            "INSERT INTO control_sequences(call_id, leg_id, binding_generation, last_sequence, body) VALUES ($1, $2, $3, $4, $5::jsonb) ON CONFLICT(call_id, leg_id, binding_generation) DO UPDATE SET last_sequence=EXCLUDED.last_sequence, body=EXCLUDED.body",
        )
        .bind(persisted.call_id.as_uuid())
        .bind(persisted.leg_id.as_uuid())
        .bind(persisted.binding_generation.as_i64())
        .bind(persisted.sequence.as_i64())
        .bind(encode(persisted)?)
        .execute(&mut **transaction)
        .await
        .map_err(database_error)?;
    }

    for persisted in &snapshot.control_commands {
        let command = &persisted.result.view.command;
        sqlx::query(
            "INSERT INTO control_commands(command_id, tenant_id, call_id, leg_id, binding_generation, worker_id, worker_fence, control_kind, recorded_at, effect_id, body) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb) ON CONFLICT(command_id) DO UPDATE SET tenant_id=EXCLUDED.tenant_id, call_id=EXCLUDED.call_id, leg_id=EXCLUDED.leg_id, binding_generation=EXCLUDED.binding_generation, worker_id=EXCLUDED.worker_id, worker_fence=EXCLUDED.worker_fence, control_kind=EXCLUDED.control_kind, recorded_at=EXCLUDED.recorded_at, effect_id=EXCLUDED.effect_id, body=EXCLUDED.body",
        )
        .bind(persisted.command_id.as_uuid())
        .bind(command.tenant_id.as_str())
        .bind(command.call_id.as_uuid())
        .bind(command.leg_id.as_uuid())
        .bind(command.binding_generation.as_i64())
        .bind(command.worker.worker_id.as_uuid())
        .bind(command.worker.fence.as_i64())
        .bind(control_kind(&command.intent))
        .bind(command.recorded_at)
        .bind(persisted.result.view.effect.effect_id.as_uuid())
        .bind(encode(persisted)?)
        .execute(&mut **transaction)
        .await
        .map_err(database_error)?;
    }

    for record in &snapshot.control_outbox {
        sqlx::query(
            "INSERT INTO control_outbox(effect_id, command_id, tenant_id, call_id, leg_id, binding_generation, worker_id, worker_fence, sequence, available_at, outbox_state, body) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb) ON CONFLICT(effect_id) DO UPDATE SET command_id=EXCLUDED.command_id, tenant_id=EXCLUDED.tenant_id, call_id=EXCLUDED.call_id, leg_id=EXCLUDED.leg_id, binding_generation=EXCLUDED.binding_generation, worker_id=EXCLUDED.worker_id, worker_fence=EXCLUDED.worker_fence, sequence=EXCLUDED.sequence, available_at=EXCLUDED.available_at, outbox_state=EXCLUDED.outbox_state, body=EXCLUDED.body",
        )
        .bind(record.effect_id.as_uuid())
        .bind(record.command_id.as_uuid())
        .bind(record.tenant_id.as_str())
        .bind(record.call_id.as_uuid())
        .bind(record.leg_id.as_uuid())
        .bind(record.binding_generation.as_i64())
        .bind(record.worker.worker_id.as_uuid())
        .bind(record.worker.fence.as_i64())
        .bind(record.sequence.as_i64())
        .bind(record.available_at)
        .bind(state_name(&record.state)?)
        .bind(encode(record)?)
        .execute(&mut **transaction)
        .await
        .map_err(database_error)?;
    }

    for persisted in &snapshot.outbound_binding_results {
        let request = &persisted.result.request;
        sqlx::query(
            "INSERT INTO outbound_binding_results(operation_id, tenant_id, call_id, leg_id, binding_generation, worker_id, worker_fence, connection_id, transport_kind, bound_at, body) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb) ON CONFLICT(operation_id) DO UPDATE SET tenant_id=EXCLUDED.tenant_id, call_id=EXCLUDED.call_id, leg_id=EXCLUDED.leg_id, binding_generation=EXCLUDED.binding_generation, worker_id=EXCLUDED.worker_id, worker_fence=EXCLUDED.worker_fence, connection_id=EXCLUDED.connection_id, transport_kind=EXCLUDED.transport_kind, bound_at=EXCLUDED.bound_at, body=EXCLUDED.body",
        )
        .bind(persisted.operation_id.as_uuid())
        .bind(request.tenant_id.as_str())
        .bind(request.call_id.as_uuid())
        .bind(request.leg_id.as_uuid())
        .bind(request.binding_generation.as_i64())
        .bind(request.worker.worker_id.as_uuid())
        .bind(request.worker.fence.as_i64())
        .bind(request.connection_id.as_str())
        .bind(state_name(&request.transport)?)
        .bind(request.at)
        .bind(encode(persisted)?)
        .execute(&mut **transaction)
        .await
        .map_err(database_error)?;
    }

    for reference in &snapshot.external_references {
        let (kind, namespace, value) = external_reference_columns(&reference.value);
        sqlx::query(
            "INSERT INTO external_references(reference_kind, reference_namespace, reference_value, tenant_id, call_id, leg_id, binding_generation, effect_id, bound_at, body) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb) ON CONFLICT(reference_kind, reference_namespace, reference_value) DO UPDATE SET tenant_id=EXCLUDED.tenant_id, call_id=EXCLUDED.call_id, leg_id=EXCLUDED.leg_id, binding_generation=EXCLUDED.binding_generation, effect_id=EXCLUDED.effect_id, bound_at=EXCLUDED.bound_at, body=EXCLUDED.body",
        )
        .bind(kind)
        .bind(namespace)
        .bind(value)
        .bind(reference.tenant_id.as_str())
        .bind(reference.call_id.as_uuid())
        .bind(reference.leg_id.as_uuid())
        .bind(reference.binding_generation.as_i64())
        .bind(reference.effect_id.as_uuid())
        .bind(reference.bound_at)
        .bind(encode(reference)?)
        .execute(&mut **transaction)
        .await
        .map_err(database_error)?;
    }

    for persisted in &snapshot.reconciliation_results {
        let request = &persisted.result.request;
        sqlx::query(
            "INSERT INTO reconciliation_results(effect_id, effect_source, tenant_id, call_id, worker_id, worker_fence, result_kind, reconciled_at, body) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb) ON CONFLICT(effect_id) DO UPDATE SET effect_source=EXCLUDED.effect_source, tenant_id=EXCLUDED.tenant_id, call_id=EXCLUDED.call_id, worker_id=EXCLUDED.worker_id, worker_fence=EXCLUDED.worker_fence, result_kind=EXCLUDED.result_kind, reconciled_at=EXCLUDED.reconciled_at, body=EXCLUDED.body",
        )
        .bind(persisted.effect_id.as_uuid())
        .bind(completed_effect_source(&persisted.result.view.effect))
        .bind(request.tenant_id.as_str())
        .bind(request.call_id.as_uuid())
        .bind(request.worker.worker_id.as_uuid())
        .bind(request.worker.fence.as_i64())
        .bind(service_result_kind(&request.result))
        .bind(request.at)
        .bind(encode(persisted)?)
        .execute(&mut **transaction)
        .await
        .map_err(database_error)?;
    }
    for retired in &snapshot.retired_operation_claims {
        sqlx::query(
            "INSERT INTO retired_operation_claims(command_id, receipt_kind, tenant_id, key_digest, request_digest, call_id, operation_kind, expires_at, retired_at, body) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb) ON CONFLICT(command_id) DO UPDATE SET receipt_kind=EXCLUDED.receipt_kind, tenant_id=EXCLUDED.tenant_id, key_digest=EXCLUDED.key_digest, request_digest=EXCLUDED.request_digest, call_id=EXCLUDED.call_id, operation_kind=EXCLUDED.operation_kind, expires_at=EXCLUDED.expires_at, retired_at=EXCLUDED.retired_at, body=EXCLUDED.body",
        )
        .bind(retired.command_id.as_uuid())
        .bind(retired_receipt_kind(retired.receipt_kind))
        .bind(retired.tenant_id.as_str())
        .bind(retired.key_digest.expose_bytes().as_slice())
        .bind(retired.request_digest.expose_bytes().as_slice())
        .bind(retired.call_id.as_uuid())
        .bind(service_operation_kind(retired.operation))
        .bind(retired.expires_at)
        .bind(retired.retired_at)
        .bind(encode(retired)?)
        .execute(&mut **transaction)
        .await
        .map_err(database_error)?;
    }
    for receipt in &snapshot.control_retirements {
        sqlx::query(
            "INSERT INTO control_outbox_retirements(effect_id, command_id, tenant_id, call_id, leg_id, binding_generation, retired_at, failure_code, body) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb) ON CONFLICT(effect_id) DO UPDATE SET command_id=EXCLUDED.command_id, tenant_id=EXCLUDED.tenant_id, call_id=EXCLUDED.call_id, leg_id=EXCLUDED.leg_id, binding_generation=EXCLUDED.binding_generation, retired_at=EXCLUDED.retired_at, failure_code=EXCLUDED.failure_code, body=EXCLUDED.body",
        )
        .bind(receipt.effect_id.as_uuid())
        .bind(receipt.command_id.as_uuid())
        .bind(receipt.tenant_id.as_str())
        .bind(receipt.call_id.as_uuid())
        .bind(receipt.leg_id.as_uuid())
        .bind(receipt.binding_generation.as_i64())
        .bind(receipt.retired_at)
        .bind(receipt.failure.code())
        .bind(encode(receipt)?)
        .execute(&mut **transaction)
        .await
        .map_err(database_error)?;
    }
    Ok(())
}

macro_rules! impl_call_repository {
    ($repository:ty) => {
        #[async_trait]
        impl CallRepository for $repository {
            async fn register_worker(
                &self,
                request: RegisterWorker,
            ) -> Result<WorkerSnapshot, RepositoryError> {
                self.inner
                    .transaction(move |repository| {
                        Box::pin(async move { repository.register_worker(request).await })
                    })
                    .await
            }

            async fn set_worker_draining(
                &self,
                worker: WorkerLease,
                draining: bool,
                at: DateTime<Utc>,
            ) -> Result<WorkerSnapshot, RepositoryError> {
                self.inner
                    .transaction(move |repository| {
                        Box::pin(async move {
                            repository.set_worker_draining(worker, draining, at).await
                        })
                    })
                    .await
            }

            async fn worker_snapshot(
                &self,
                worker_id: WorkerId,
            ) -> Result<WorkerSnapshot, RepositoryError> {
                self.inner
                    .read(move |repository| {
                        Box::pin(async move { repository.worker_snapshot(worker_id).await })
                    })
                    .await
            }

            async fn create_call(
                &self,
                request: CreateCall,
            ) -> Result<CreateCallOutcome, RepositoryError> {
                self.inner
                    .transaction(move |repository| {
                        Box::pin(async move { repository.create_call(request).await })
                    })
                    .await
            }

            async fn load_call(
                &self,
                tenant_id: &TenantId,
                call_id: CallId,
            ) -> Result<StoredCall, RepositoryError> {
                let tenant_id = tenant_id.clone();
                self.inner
                    .read(move |repository| {
                        Box::pin(async move { repository.load_call(&tenant_id, call_id).await })
                    })
                    .await
            }

            async fn commit_command(
                &self,
                request: CommandCommit,
            ) -> Result<CommandCommitOutcome, RepositoryError> {
                self.inner
                    .transaction(move |repository| {
                        Box::pin(async move { repository.commit_command(request).await })
                    })
                    .await
            }

            async fn release_assignment(
                &self,
                tenant_id: &TenantId,
                call_id: CallId,
                worker: WorkerLease,
                at: DateTime<Utc>,
            ) -> Result<bool, RepositoryError> {
                let tenant_id = tenant_id.clone();
                self.inner
                    .transaction(move |repository| {
                        Box::pin(async move {
                            repository
                                .release_assignment(&tenant_id, call_id, worker, at)
                                .await
                        })
                    })
                    .await
            }

            async fn inspect_attachment(
                &self,
                request: AttachmentLookup,
            ) -> Result<AttachmentCandidate, RepositoryError> {
                self.inner
                    .read(move |repository| {
                        Box::pin(async move { repository.inspect_attachment(request).await })
                    })
                    .await
            }

            async fn consume_attachment(
                &self,
                request: AttachmentConsume,
            ) -> Result<ConsumedAttachment, RepositoryError> {
                self.inner
                    .transaction(move |repository| {
                        Box::pin(async move { repository.consume_attachment(request).await })
                    })
                    .await
            }

            async fn ingest_provider_event(
                &self,
                request: ProviderEventInput,
            ) -> Result<ProviderEventOutcome, RepositoryError> {
                self.inner
                    .transaction(move |repository| {
                        Box::pin(async move { repository.ingest_provider_event(request).await })
                    })
                    .await
            }

            async fn bind_provider_reference(
                &self,
                request: BindProviderReference,
            ) -> Result<Vec<ProviderEventEnvelope>, RepositoryError> {
                self.inner
                    .transaction(move |repository| {
                        Box::pin(async move { repository.bind_provider_reference(request).await })
                    })
                    .await
            }

            async fn claim_provider_events(
                &self,
                worker: WorkerLease,
                at: DateTime<Utc>,
                claim_ttl: Duration,
                limit: usize,
            ) -> Result<Vec<ClaimedProviderEvent>, RepositoryError> {
                self.inner
                    .transaction(move |repository| {
                        Box::pin(async move {
                            repository
                                .claim_provider_events(worker, at, claim_ttl, limit)
                                .await
                        })
                    })
                    .await
            }

            async fn complete_provider_event(
                &self,
                request: ProviderEventCommit,
            ) -> Result<ProviderEventCommitOutcome, RepositoryError> {
                self.inner
                    .transaction(move |repository| {
                        Box::pin(async move { repository.complete_provider_event(request).await })
                    })
                    .await
            }

            async fn acknowledge_terminal_provider_event(
                &self,
                request: TerminalProviderEventAcknowledge,
            ) -> Result<TerminalProviderEventAcknowledgeOutcome, RepositoryError> {
                self.inner
                    .transaction(move |repository| {
                        Box::pin(async move {
                            repository
                                .acknowledge_terminal_provider_event(request)
                                .await
                        })
                    })
                    .await
            }

            async fn claim_outbox(
                &self,
                worker: WorkerLease,
                at: DateTime<Utc>,
                claim_ttl: Duration,
                limit: usize,
            ) -> Result<Vec<ClaimedOutbox>, RepositoryError> {
                self.inner
                    .transaction(move |repository| {
                        Box::pin(async move {
                            repository.claim_outbox(worker, at, claim_ttl, limit).await
                        })
                    })
                    .await
            }

            async fn complete_outbox(
                &self,
                effect_id: EffectId,
                worker: WorkerLease,
                claim_generation: ClaimGeneration,
                completion: OutboxCompletion,
                at: DateTime<Utc>,
            ) -> Result<OutboxRecord, RepositoryError> {
                self.inner
                    .transaction(move |repository| {
                        Box::pin(async move {
                            repository
                                .complete_outbox(
                                    effect_id,
                                    worker,
                                    claim_generation,
                                    completion,
                                    at,
                                )
                                .await
                        })
                    })
                    .await
            }

            async fn claim_due_deadlines(
                &self,
                worker: WorkerLease,
                at: DateTime<Utc>,
                claim_ttl: Duration,
                limit: usize,
            ) -> Result<Vec<ClaimedDeadline>, RepositoryError> {
                self.inner
                    .transaction(move |repository| {
                        Box::pin(async move {
                            repository
                                .claim_due_deadlines(worker, at, claim_ttl, limit)
                                .await
                        })
                    })
                    .await
            }

            async fn claim_restart_calls(
                &self,
                worker: WorkerLease,
                at: DateTime<Utc>,
                limit: usize,
            ) -> Result<Vec<RestartClaim>, RepositoryError> {
                self.inner
                    .transaction(move |repository| {
                        Box::pin(
                            async move { repository.claim_restart_calls(worker, at, limit).await },
                        )
                    })
                    .await
            }
        }
    };
}

impl_call_repository!(SqliteRepository);
impl_call_repository!(PostgresRepository);

macro_rules! impl_call_service_repository {
    ($repository:ty) => {
        #[async_trait]
        impl CallServiceRepository for $repository {
            async fn create_with_plan(
                &self,
                request: ServiceCreateTransaction,
            ) -> Result<ServiceCreateOutcome, RepositoryError> {
                self.inner
                    .transaction(move |repository| {
                        Box::pin(async move { repository.create_with_plan(request).await })
                    })
                    .await
            }

            async fn load_service_call(
                &self,
                tenant_id: &TenantId,
                call_id: CallId,
            ) -> Result<StoredServiceCall, RepositoryError> {
                let tenant_id = tenant_id.clone();
                self.inner
                    .read(move |repository| {
                        Box::pin(
                            async move { repository.load_service_call(&tenant_id, call_id).await },
                        )
                    })
                    .await
            }

            async fn commit_with_effect_payloads(
                &self,
                request: ServiceCommandTransaction,
            ) -> Result<ServiceCommandOutcome, RepositoryError> {
                self.inner
                    .transaction(move |repository| {
                        Box::pin(
                            async move { repository.commit_with_effect_payloads(request).await },
                        )
                    })
                    .await
            }

            async fn load_effect_payload(
                &self,
                tenant_id: &TenantId,
                effect_id: EffectId,
            ) -> Result<Option<StoredServiceEffectPayload>, RepositoryError> {
                let tenant_id = tenant_id.clone();
                self.inner
                    .read(move |repository| {
                        Box::pin(async move {
                            repository.load_effect_payload(&tenant_id, effect_id).await
                        })
                    })
                    .await
            }

            async fn enqueue_control(
                &self,
                request: ControlCommandTransaction,
            ) -> Result<ControlCommandOutcome, RepositoryError> {
                self.inner
                    .transaction(move |repository| {
                        Box::pin(async move { repository.enqueue_control(request).await })
                    })
                    .await
            }

            async fn claim_control_effects(
                &self,
                worker: WorkerLease,
                at: DateTime<Utc>,
                claim_ttl: Duration,
                limit: usize,
            ) -> Result<Vec<ClaimedControlEffect>, RepositoryError> {
                self.inner
                    .transaction(move |repository| {
                        Box::pin(async move {
                            repository
                                .claim_control_effects(worker, at, claim_ttl, limit)
                                .await
                        })
                    })
                    .await
            }

            async fn bind_outbound_connection(
                &self,
                request: OutboundConnectionBind,
            ) -> Result<OutboundConnectionBindOutcome, RepositoryError> {
                self.inner
                    .transaction(move |repository| {
                        Box::pin(async move { repository.bind_outbound_connection(request).await })
                    })
                    .await
            }

            async fn load_external_reference(
                &self,
                tenant_id: &TenantId,
                call_id: CallId,
                leg_id: LegId,
            ) -> Result<Option<StoredExternalReference>, RepositoryError> {
                let tenant_id = tenant_id.clone();
                self.inner
                    .read(move |repository| {
                        Box::pin(async move {
                            repository
                                .load_external_reference(&tenant_id, call_id, leg_id)
                                .await
                        })
                    })
                    .await
            }

            async fn reconcile_effect_result(
                &self,
                request: EffectResultReconciliation,
            ) -> Result<EffectResultOutcome, RepositoryError> {
                self.inner
                    .transaction(move |repository| {
                        Box::pin(async move { repository.reconcile_effect_result(request).await })
                    })
                    .await
            }
        }
    };
}

impl_call_service_repository!(SqliteRepository);
impl_call_service_repository!(PostgresRepository);
