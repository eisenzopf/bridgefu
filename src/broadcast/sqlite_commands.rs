//! SQLite parity for the durable broadcast command repository.
//!
//! Split production roles require PostgreSQL. This implementation keeps the
//! standalone schema and repository contract executable in conformance tests
//! and small single-process deployments.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use sqlx::migrate::Migrator;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions, SqliteRow};
use sqlx::{Row, Sqlite, Transaction};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::call_engine::{BindingGeneration, TenantId, WorkerLease};
use crate::coordination::{
    CoordinationPayload, DeploymentId, SqliteCoordinationOutbox, WakeupReason,
};

use super::{
    BroadcastCommandError, BroadcastCommandRepository, BroadcastCommandResult,
    BroadcastEnqueueOutcome, BroadcastOperationIdentity, ClaimedBroadcastCommand,
    DurableBroadcastCommandKind, DurableBroadcastRecord, DurableBroadcastRuntime,
    DurableBroadcastSpec, DurableBroadcastState,
};

static MIGRATOR: Migrator = sqlx::migrate!("./migrations/sqlite");
const MAX_CLAIM_TTL: Duration = Duration::from_secs(5 * 60);
const MAX_BATCH: usize = 64;

#[derive(Clone)]
pub struct SqliteBroadcastCommandRepository {
    pool: SqlitePool,
    outbox: SqliteCoordinationOutbox,
    deployment: DeploymentId,
}

impl std::fmt::Debug for SqliteBroadcastCommandRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqliteBroadcastCommandRepository")
            .field("deployment", &self.deployment)
            .finish_non_exhaustive()
    }
}

impl SqliteBroadcastCommandRepository {
    pub async fn connect(
        mut database_url: String,
        deployment: DeploymentId,
    ) -> Result<Arc<Self>, BroadcastCommandError> {
        let options = SqliteConnectOptions::from_str(&database_url)
            .map_err(|_| BroadcastCommandError::Unavailable)?
            .create_if_missing(true)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(30));
        database_url.zeroize();
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .after_connect(|connection, _| {
                Box::pin(async move {
                    sqlx::query("PRAGMA foreign_keys = ON")
                        .execute(&mut *connection)
                        .await?;
                    Ok(())
                })
            })
            .connect_with(options)
            .await
            .map_err(|_| BroadcastCommandError::Unavailable)?;
        MIGRATOR
            .run(&pool)
            .await
            .map_err(|_| BroadcastCommandError::Unavailable)?;
        Ok(Arc::new(Self {
            outbox: SqliteCoordinationOutbox::from_pool(pool.clone(), deployment.clone()),
            pool,
            deployment,
        }))
    }

    async fn begin_write(&self) -> Result<Transaction<'_, Sqlite>, BroadcastCommandError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| BroadcastCommandError::Unavailable)?;
        sqlx::query(
            "INSERT INTO coordination_projection_locks(deployment_id, generation) VALUES (?1, 0) \
             ON CONFLICT(deployment_id) DO UPDATE SET generation = generation + 1",
        )
        .bind(self.deployment.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(|_| BroadcastCommandError::Unavailable)?;
        Ok(transaction)
    }

    async fn wake(
        &self,
        transaction: &mut Transaction<'_, Sqlite>,
        worker: WorkerLease,
    ) -> Result<(), BroadcastCommandError> {
        self.outbox
            .append_in_transaction(
                transaction,
                CoordinationPayload::WakeWorker {
                    worker_id: worker.worker_id,
                    reason: WakeupReason::Broadcasts,
                },
            )
            .await
            .map(|_| ())
            .map_err(|_| BroadcastCommandError::Unavailable)
    }
}

#[async_trait]
impl BroadcastCommandRepository for SqliteBroadcastCommandRepository {
    async fn enqueue_start(
        &self,
        specification: DurableBroadcastSpec,
        identity: BroadcastOperationIdentity,
        max_active: usize,
    ) -> Result<BroadcastEnqueueOutcome, BroadcastCommandError> {
        validate_spec(&specification)?;
        let mut transaction = self.begin_write().await?;
        if let Some(row) = sqlx::query(
            "SELECT specification, state, runtime, failure_code, created_at, updated_at, \
                    create_request_digest FROM broadcasts \
             WHERE tenant_id = ?1 AND create_idempotency_digest = ?2",
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
        let active: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM broadcasts WHERE worker_id = ?1 AND worker_fence = ?2 \
             AND state IN ('pending', 'active', 'deleting')",
        )
        .bind(specification.worker.worker_id.to_string())
        .bind(specification.worker.fence.as_i64())
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| BroadcastCommandError::Unavailable)?;
        if max_active == 0 || usize::try_from(active).unwrap_or(usize::MAX) >= max_active {
            return Err(BroadcastCommandError::CapacityExceeded);
        }
        let now = sqlite_now(&mut transaction).await?;
        let body = serde_json::to_string(&specification)
            .map_err(|_| BroadcastCommandError::InvalidData)?;
        sqlx::query(
            "INSERT INTO broadcasts \
             (broadcast_id, tenant_id, call_id, source_leg_id, worker_id, worker_fence, transport, \
              state, specification, expires_at, created_at, updated_at, \
              create_idempotency_digest, create_request_digest) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending', ?8, ?9, ?10, ?10, ?11, ?12)",
        )
        .bind(&specification.broadcast_id)
        .bind(specification.tenant_id.as_str())
        .bind(specification.call_id.to_string())
        .bind(specification.source_leg_id.to_string())
        .bind(specification.worker.worker_id.to_string())
        .bind(specification.worker.fence.as_i64())
        .bind(match specification.transport {
            super::DurableBroadcastTransport::Moqt => "moqt",
            super::DurableBroadcastTransport::UctpQuic => "uctp_quic",
        })
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
             VALUES (?1, ?2, ?3, ?4, 'start', 'pending', ?5)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&specification.broadcast_id)
        .bind(specification.worker.worker_id.to_string())
        .bind(specification.worker.fence.as_i64())
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(|_| BroadcastCommandError::Unavailable)?;
        self.wake(&mut transaction, specification.worker).await?;
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
        validate_id(broadcast_id)?;
        let mut transaction = self.begin_write().await?;
        if let Some(row) = sqlx::query(
            "SELECT b.specification, b.state, b.runtime, b.failure_code, b.created_at, b.updated_at, \
                    r.request_digest FROM broadcast_operation_receipts r \
             JOIN broadcasts b USING (broadcast_id) WHERE r.tenant_id = ?1 \
             AND r.operation = 'delete' AND r.idempotency_digest = ?2",
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
                let now = sqlite_now(&mut transaction).await?;
                sqlx::query(
                    "UPDATE broadcasts SET state = 'deleted', updated_at = ?1 \
                     WHERE broadcast_id = ?2",
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
            "SELECT specification, state, runtime, failure_code, created_at, updated_at \
             FROM broadcasts WHERE tenant_id = ?1 AND broadcast_id = ?2",
        )
        .bind(tenant_id.as_str())
        .bind(broadcast_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| BroadcastCommandError::Unavailable)?
        .ok_or(BroadcastCommandError::NotFound)?;
        let mut record = decode_record(&row)?;
        let now = sqlite_now(&mut transaction).await?;
        if record.state == DurableBroadcastState::Failed {
            if record.runtime.is_some() {
                return Err(BroadcastCommandError::InvalidTransition);
            }
            sqlx::query(
                "UPDATE broadcasts SET state = 'deleted', updated_at = ?1 WHERE broadcast_id = ?2",
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
                "UPDATE broadcasts SET state = 'deleting', updated_at = ?1 WHERE broadcast_id = ?2",
            )
            .bind(now)
            .bind(broadcast_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| BroadcastCommandError::Unavailable)?;
            sqlx::query(
                "INSERT OR IGNORE INTO broadcast_commands \
                 (command_id, broadcast_id, worker_id, worker_fence, kind, state, available_at) \
                 VALUES (?1, ?2, ?3, ?4, 'stop', 'pending', ?5)",
            )
            .bind(Uuid::new_v4().to_string())
            .bind(broadcast_id)
            .bind(record.specification.worker.worker_id.to_string())
            .bind(record.specification.worker.fence.as_i64())
            .bind(now)
            .execute(&mut *transaction)
            .await
            .map_err(|_| BroadcastCommandError::Unavailable)?;
            self.wake(&mut transaction, record.specification.worker)
                .await?;
            record.state = DurableBroadcastState::Deleting;
            record.updated_at = now;
        }
        sqlx::query(
            "INSERT INTO broadcast_operation_receipts \
             (tenant_id, operation, idempotency_digest, request_digest, broadcast_id, recorded_at) \
             VALUES (?1, 'delete', ?2, ?3, ?4, ?5)",
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
        validate_id(broadcast_id)?;
        sqlx::query(
            "SELECT specification, state, runtime, failure_code, created_at, updated_at \
             FROM broadcasts WHERE tenant_id = ?1 AND broadcast_id = ?2",
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
        let mut transaction = self.begin_write().await?;
        let now = sqlite_now(&mut transaction).await?;
        let expires = now
            .checked_add_signed(
                TimeDelta::from_std(claim_ttl).map_err(|_| BroadcastCommandError::InvalidData)?,
            )
            .ok_or(BroadcastCommandError::InvalidData)?;
        let rows = sqlx::query(
            "SELECT c.command_id, c.kind, c.claim_generation, b.specification, b.state, b.runtime, \
                    b.failure_code, b.created_at, b.updated_at FROM broadcast_commands c \
             JOIN broadcasts b USING (broadcast_id) WHERE c.worker_id = ?1 AND c.worker_fence = ?2 \
             AND c.available_at <= ?3 AND (c.state = 'pending' OR \
                 (c.state = 'claimed' AND c.claim_expires_at <= ?3)) \
             ORDER BY c.available_at, c.command_id LIMIT ?4",
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
            let command_id: String = row
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
                "UPDATE broadcast_commands SET state = 'claimed', claim_generation = ?1, \
                        claimed_at = ?2, claim_expires_at = ?3 WHERE command_id = ?4",
            )
            .bind(generation)
            .bind(now)
            .bind(expires)
            .bind(&command_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| BroadcastCommandError::Unavailable)?;
            claims.push(ClaimedBroadcastCommand {
                command_id: Uuid::parse_str(&command_id)
                    .map_err(|_| BroadcastCommandError::InvalidData)?,
                kind: parse_kind(
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
        let mut transaction = self.begin_write().await?;
        let row = sqlx::query(
            "SELECT c.kind, c.state AS command_state, c.claim_generation, b.specification, b.state, \
                    b.runtime, b.failure_code, b.created_at, b.updated_at FROM broadcast_commands c \
             JOIN broadcasts b USING (broadcast_id) WHERE c.command_id = ?1",
        )
        .bind(claim.command_id.to_string())
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
        let kind = parse_kind(
            row.try_get("kind")
                .map_err(|_| BroadcastCommandError::InvalidData)?,
        )?;
        if command_state != "claimed"
            || generation != claim.claim_generation as i64
            || kind != claim.kind
        {
            return Err(BroadcastCommandError::StaleClaim);
        }
        let now = sqlite_now(&mut transaction).await?;
        let (command_state, record_state, runtime, failure) = match result {
            BroadcastCommandResult::Started(runtime)
                if kind == DurableBroadcastCommandKind::Start =>
            {
                (
                    "succeeded",
                    "active",
                    Some(
                        serde_json::to_string(&runtime)
                            .map_err(|_| BroadcastCommandError::InvalidData)?,
                    ),
                    None,
                )
            }
            BroadcastCommandResult::Stopped if kind == DurableBroadcastCommandKind::Stop => {
                ("succeeded", "deleted", None, None)
            }
            BroadcastCommandResult::Failed(code) => {
                ("failed", "failed", None, Some(code.to_owned()))
            }
            _ => return Err(BroadcastCommandError::InvalidTransition),
        };
        sqlx::query(
            "UPDATE broadcast_commands SET state = ?1, claimed_at = NULL, claim_expires_at = NULL, \
                    completed_at = ?2, failure_code = ?3 WHERE command_id = ?4",
        )
        .bind(command_state)
        .bind(now)
        .bind(&failure)
        .bind(claim.command_id.to_string())
        .execute(&mut *transaction)
        .await
        .map_err(|_| BroadcastCommandError::Unavailable)?;
        sqlx::query(
            "UPDATE broadcasts SET state = ?1, runtime = ?2, failure_code = ?3, updated_at = ?4 \
             WHERE broadcast_id = ?5",
        )
        .bind(record_state)
        .bind(&runtime)
        .bind(&failure)
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
        record.state = parse_state(record_state)?;
        record.runtime = runtime
            .map(|runtime| serde_json::from_str::<DurableBroadcastRuntime>(&runtime))
            .transpose()
            .map_err(|_| BroadcastCommandError::InvalidData)?;
        record.failure_code = failure;
        record.updated_at = now;
        Ok(record)
    }

    async fn fail_worker_broadcasts(
        &self,
        worker: WorkerLease,
        failure_code: &'static str,
    ) -> Result<(), BroadcastCommandError> {
        let mut transaction = self.begin_write().await?;
        let now = sqlite_now(&mut transaction).await?;
        sqlx::query(
            "UPDATE broadcast_commands SET state = 'failed', claimed_at = NULL, \
                    claim_expires_at = NULL, completed_at = ?1, failure_code = ?2 \
             WHERE worker_id = ?3 AND worker_fence = ?4 AND state IN ('pending', 'claimed')",
        )
        .bind(now)
        .bind(failure_code)
        .bind(worker.worker_id.to_string())
        .bind(worker.fence.as_i64())
        .execute(&mut *transaction)
        .await
        .map_err(|_| BroadcastCommandError::Unavailable)?;
        sqlx::query(
            "UPDATE broadcasts SET state = 'failed', failure_code = ?1, \
                    updated_at = ?2 WHERE worker_id = ?3 AND worker_fence = ?4 \
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
        let mut transaction = self.begin_write().await?;
        let now = sqlite_now(&mut transaction).await?;
        sqlx::query(
            "UPDATE broadcast_commands SET state = 'failed', claimed_at = NULL, \
                    claim_expires_at = NULL, completed_at = ?1, failure_code = 'stale_worker_fence' \
             WHERE worker_id = ?2 AND worker_fence <> ?3 AND state IN ('pending', 'claimed')",
        )
        .bind(now)
        .bind(current.worker_id.to_string())
        .bind(current.fence.as_i64())
        .execute(&mut *transaction)
        .await
        .map_err(|_| BroadcastCommandError::Unavailable)?;
        sqlx::query(
            "UPDATE broadcasts SET state = 'failed', \
                    failure_code = 'stale_worker_fence', updated_at = ?1 \
             WHERE worker_id = ?2 AND worker_fence <> ?3 \
               AND state IN ('pending', 'active', 'deleting')",
        )
        .bind(now)
        .bind(current.worker_id.to_string())
        .bind(current.fence.as_i64())
        .execute(&mut *transaction)
        .await
        .map_err(|_| BroadcastCommandError::Unavailable)?;
        let rows = sqlx::query(
            "SELECT specification, state, runtime, failure_code, created_at, updated_at \
             FROM broadcasts WHERE worker_id = ?1 AND worker_fence <> ?2 \
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
        validate_id(broadcast_id)?;
        let mut transaction = self.begin_write().await?;
        let row = sqlx::query(
            "SELECT specification, state, runtime, failure_code, created_at, updated_at \
             FROM broadcasts WHERE broadcast_id = ?1",
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
        let now = sqlite_now(&mut transaction).await?;
        sqlx::query(
            "UPDATE broadcasts SET state = 'failed', runtime = NULL, failure_code = ?1, \
                    updated_at = ?2 WHERE broadcast_id = ?3",
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
        validate_id(broadcast_id)?;
        let mut transaction = self.begin_write().await?;
        let row = sqlx::query(
            "SELECT specification, state, runtime, failure_code, created_at, updated_at \
             FROM broadcasts WHERE broadcast_id = ?1",
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
        let now = sqlite_now(&mut transaction).await?;
        sqlx::query(
            "UPDATE broadcasts SET runtime = NULL, updated_at = ?1 WHERE broadcast_id = ?2",
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

async fn sqlite_now(
    transaction: &mut Transaction<'_, Sqlite>,
) -> Result<DateTime<Utc>, BroadcastCommandError> {
    let millis: i64 =
        sqlx::query_scalar("SELECT CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER)")
            .fetch_one(&mut **transaction)
            .await
            .map_err(|_| BroadcastCommandError::Unavailable)?;
    DateTime::from_timestamp_millis(millis).ok_or(BroadcastCommandError::InvalidData)
}

fn decode_record(row: &SqliteRow) -> Result<DurableBroadcastRecord, BroadcastCommandError> {
    let specification: String = row
        .try_get("specification")
        .map_err(|_| BroadcastCommandError::InvalidData)?;
    let runtime: Option<String> = row
        .try_get("runtime")
        .map_err(|_| BroadcastCommandError::InvalidData)?;
    Ok(DurableBroadcastRecord {
        specification: serde_json::from_str(&specification)
            .map_err(|_| BroadcastCommandError::InvalidData)?,
        state: parse_state(
            row.try_get("state")
                .map_err(|_| BroadcastCommandError::InvalidData)?,
        )?,
        runtime: runtime
            .map(|runtime| serde_json::from_str(&runtime))
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

fn parse_state(value: &str) -> Result<DurableBroadcastState, BroadcastCommandError> {
    match value {
        "pending" => Ok(DurableBroadcastState::Pending),
        "active" => Ok(DurableBroadcastState::Active),
        "deleting" => Ok(DurableBroadcastState::Deleting),
        "deleted" => Ok(DurableBroadcastState::Deleted),
        "failed" => Ok(DurableBroadcastState::Failed),
        _ => Err(BroadcastCommandError::InvalidData),
    }
}

fn parse_kind(value: &str) -> Result<DurableBroadcastCommandKind, BroadcastCommandError> {
    match value {
        "start" => Ok(DurableBroadcastCommandKind::Start),
        "stop" => Ok(DurableBroadcastCommandKind::Stop),
        _ => Err(BroadcastCommandError::InvalidData),
    }
}

fn validate_id(value: &str) -> Result<(), BroadcastCommandError> {
    match Uuid::parse_str(value) {
        Ok(id) if !id.is_nil() => Ok(()),
        _ => Err(BroadcastCommandError::InvalidData),
    }
}

fn validate_spec(specification: &DurableBroadcastSpec) -> Result<(), BroadcastCommandError> {
    validate_id(&specification.broadcast_id)?;
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
