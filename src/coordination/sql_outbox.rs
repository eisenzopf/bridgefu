//! Database-time, ordered coordination outboxes for clustered and standalone SQL.

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::postgres::PgPool;
use sqlx::sqlite::SqlitePool;
use sqlx::{PgConnection, Postgres, Row, Sqlite, SqliteConnection, Transaction};

use super::outbox::validate_projector;
use super::{
    checked_claim_expiry, CoordinationClaimGeneration, CoordinationError, CoordinationEvent,
    CoordinationOutbox, CoordinationOutboxClaim, CoordinationOutboxRecord, CoordinationOutboxState,
    CoordinationPayload, DeploymentId, ProjectionSequence,
};

const MAX_BATCH_SIZE: usize = 1_024;
const SQLITE_NOW_MS: &str = "CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER)";

/// PostgreSQL-authoritative ordered coordination outbox.
#[derive(Clone)]
pub struct PostgresCoordinationOutbox {
    pool: PgPool,
    deployment: DeploymentId,
}

impl std::fmt::Debug for PostgresCoordinationOutbox {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresCoordinationOutbox")
            .field("deployment", &self.deployment)
            .finish_non_exhaustive()
    }
}

impl PostgresCoordinationOutbox {
    /// Binds to a migrated Bridgefu pool. No connection URL is retained.
    #[must_use]
    pub fn from_pool(pool: PgPool, deployment: DeploymentId) -> Self {
        Self { pool, deployment }
    }

    /// Appends in a short standalone transaction. Request-path mutations should
    /// instead call [`Self::append_in_transaction`] in their authoritative transaction.
    pub async fn append(
        &self,
        payload: CoordinationPayload,
    ) -> Result<CoordinationOutboxRecord, CoordinationError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| CoordinationError::Unavailable)?;
        let record = self
            .append_in_transaction(&mut transaction, payload)
            .await?;
        transaction
            .commit()
            .await
            .map_err(|_| CoordinationError::Unavailable)?;
        Ok(record)
    }

    /// Atomically appends beside an authoritative PostgreSQL mutation. Callers
    /// commit once; Redis projection happens only after this transaction commits.
    pub async fn append_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        payload: CoordinationPayload,
    ) -> Result<CoordinationOutboxRecord, CoordinationError> {
        // Producer allocation and projector claiming share this lock. A
        // transaction cannot publish a later visible sequence while an
        // earlier producer for the same deployment is still uncommitted.
        postgres_deployment_lock(transaction, &self.deployment).await?;
        let now_ms = postgres_now_ms(transaction).await?;
        validate_payload_at(&self.deployment, &payload, now_ms)?;
        let payload_json =
            serde_json::to_string(&payload).map_err(|_| CoordinationError::InvalidData)?;
        let row = sqlx::query(
            "INSERT INTO coordination_outbox \
             (deployment_id, payload_json, recorded_at_ms) \
             VALUES ($1, $2::jsonb, $3) \
             RETURNING sequence",
        )
        .bind(self.deployment.as_str())
        .bind(payload_json)
        .bind(now_ms)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|_| CoordinationError::Unavailable)?;
        build_ready_record(
            self.deployment.clone(),
            row.try_get("sequence")
                .map_err(|_| CoordinationError::InvalidData)?,
            payload,
            now_ms,
        )
    }

    async fn claim_transaction(
        &self,
        projector: &str,
        claim_ttl: Duration,
        limit: usize,
    ) -> Result<Vec<CoordinationOutboxClaim>, CoordinationError> {
        validate_claim_request(projector, claim_ttl, limit)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| CoordinationError::Unavailable)?;
        postgres_deployment_lock(&mut transaction, &self.deployment).await?;
        let now_ms = postgres_now_ms(&mut transaction).await?;
        let expires_at_ms = claim_expiry_millis(now_ms, claim_ttl)?;
        let rows = sqlx::query(
            "SELECT sequence, payload_json::text AS payload_json, recorded_at_ms, \
                    claim_projector, claim_generation, claimed_at_ms, \
                    claim_expires_at_ms, applied_at_ms \
             FROM coordination_outbox \
             WHERE deployment_id = $1 AND applied_at_ms IS NULL \
             ORDER BY sequence \
             LIMIT $2 \
             FOR UPDATE",
        )
        .bind(self.deployment.as_str())
        .bind(limit as i64)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| CoordinationError::Unavailable)?;
        let mut claims = Vec::new();
        for row in rows {
            let pending = decode_pending_row(&self.deployment, &row)?;
            let previous_generation = match pending.record.state {
                CoordinationOutboxState::Ready => CoordinationClaimGeneration::default(),
                CoordinationOutboxState::Claimed {
                    generation,
                    expires_at,
                    ..
                } if expires_at.timestamp_millis() <= now_ms => generation,
                CoordinationOutboxState::Claimed { .. } => break,
                CoordinationOutboxState::Applied { .. } => {
                    return Err(CoordinationError::InvalidData)
                }
            };
            let generation = previous_generation.next()?;
            let result = sqlx::query(
                "UPDATE coordination_outbox \
                 SET claim_projector = $1, claim_generation = $2, \
                     claimed_at_ms = $3, claim_expires_at_ms = $4 \
                 WHERE deployment_id = $5 AND sequence = $6 AND applied_at_ms IS NULL",
            )
            .bind(projector)
            .bind(generation.as_i64())
            .bind(now_ms)
            .bind(expires_at_ms)
            .bind(self.deployment.as_str())
            .bind(pending.record.event.sequence.as_i64())
            .execute(&mut *transaction)
            .await
            .map_err(|_| CoordinationError::Unavailable)?;
            if result.rows_affected() != 1 {
                return Err(CoordinationError::InvalidData);
            }
            claims.push(claim_from_pending(
                pending.record,
                projector,
                generation,
                now_ms,
                expires_at_ms,
            )?);
        }
        transaction
            .commit()
            .await
            .map_err(|_| CoordinationError::Unavailable)?;
        Ok(claims)
    }
}

/// SQLite-authoritative ordered coordination outbox for standalone mode.
#[derive(Clone)]
pub struct SqliteCoordinationOutbox {
    pool: SqlitePool,
    deployment: DeploymentId,
}

impl std::fmt::Debug for SqliteCoordinationOutbox {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqliteCoordinationOutbox")
            .field("deployment", &self.deployment)
            .finish_non_exhaustive()
    }
}

impl SqliteCoordinationOutbox {
    /// Binds to a migrated Bridgefu pool.
    #[must_use]
    pub fn from_pool(pool: SqlitePool, deployment: DeploymentId) -> Self {
        Self { pool, deployment }
    }

    /// Appends in a short standalone transaction.
    pub async fn append(
        &self,
        payload: CoordinationPayload,
    ) -> Result<CoordinationOutboxRecord, CoordinationError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| CoordinationError::Unavailable)?;
        let record = self
            .append_in_transaction(&mut transaction, payload)
            .await?;
        transaction
            .commit()
            .await
            .map_err(|_| CoordinationError::Unavailable)?;
        Ok(record)
    }

    /// Atomically appends beside an authoritative SQLite mutation.
    pub async fn append_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Sqlite>,
        payload: CoordinationPayload,
    ) -> Result<CoordinationOutboxRecord, CoordinationError> {
        let now_ms = sqlite_now_ms(transaction).await?;
        validate_payload_at(&self.deployment, &payload, now_ms)?;
        let payload_json =
            serde_json::to_string(&payload).map_err(|_| CoordinationError::InvalidData)?;
        let result = sqlx::query(
            "INSERT INTO coordination_outbox \
             (deployment_id, payload_json, recorded_at_ms) VALUES (?, ?, ?)",
        )
        .bind(self.deployment.as_str())
        .bind(payload_json)
        .bind(now_ms)
        .execute(&mut **transaction)
        .await
        .map_err(|_| CoordinationError::Unavailable)?;
        build_ready_record(
            self.deployment.clone(),
            result.last_insert_rowid(),
            payload,
            now_ms,
        )
    }

    async fn claim_transaction(
        &self,
        projector: &str,
        claim_ttl: Duration,
        limit: usize,
    ) -> Result<Vec<CoordinationOutboxClaim>, CoordinationError> {
        validate_claim_request(projector, claim_ttl, limit)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| CoordinationError::Unavailable)?;
        sqlx::query(
            "INSERT INTO coordination_projection_locks (deployment_id, generation) \
             VALUES (?, 0) ON CONFLICT(deployment_id) DO NOTHING",
        )
        .bind(self.deployment.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(|_| CoordinationError::Unavailable)?;
        sqlx::query(
            "UPDATE coordination_projection_locks SET generation = generation + 1 \
             WHERE deployment_id = ?",
        )
        .bind(self.deployment.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(|_| CoordinationError::Unavailable)?;
        let now_ms = sqlite_now_ms(&mut transaction).await?;
        let expires_at_ms = claim_expiry_millis(now_ms, claim_ttl)?;
        let rows = sqlx::query(
            "SELECT sequence, payload_json, recorded_at_ms, claim_projector, \
                    claim_generation, claimed_at_ms, claim_expires_at_ms, applied_at_ms \
             FROM coordination_outbox \
             WHERE deployment_id = ? AND applied_at_ms IS NULL \
             ORDER BY sequence LIMIT ?",
        )
        .bind(self.deployment.as_str())
        .bind(limit as i64)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| CoordinationError::Unavailable)?;
        let mut claims = Vec::new();
        for row in rows {
            let pending = decode_pending_row(&self.deployment, &row)?;
            let previous_generation = match pending.record.state {
                CoordinationOutboxState::Ready => CoordinationClaimGeneration::default(),
                CoordinationOutboxState::Claimed {
                    generation,
                    expires_at,
                    ..
                } if expires_at.timestamp_millis() <= now_ms => generation,
                CoordinationOutboxState::Claimed { .. } => break,
                CoordinationOutboxState::Applied { .. } => {
                    return Err(CoordinationError::InvalidData)
                }
            };
            let generation = previous_generation.next()?;
            let result = sqlx::query(
                "UPDATE coordination_outbox \
                 SET claim_projector = ?, claim_generation = ?, \
                     claimed_at_ms = ?, claim_expires_at_ms = ? \
                 WHERE deployment_id = ? AND sequence = ? AND applied_at_ms IS NULL",
            )
            .bind(projector)
            .bind(generation.as_i64())
            .bind(now_ms)
            .bind(expires_at_ms)
            .bind(self.deployment.as_str())
            .bind(pending.record.event.sequence.as_i64())
            .execute(&mut *transaction)
            .await
            .map_err(|_| CoordinationError::Unavailable)?;
            if result.rows_affected() != 1 {
                return Err(CoordinationError::InvalidData);
            }
            claims.push(claim_from_pending(
                pending.record,
                projector,
                generation,
                now_ms,
                expires_at_ms,
            )?);
        }
        transaction
            .commit()
            .await
            .map_err(|_| CoordinationError::Unavailable)?;
        Ok(claims)
    }
}

#[async_trait]
impl CoordinationOutbox for PostgresCoordinationOutbox {
    async fn claim(
        &self,
        projector: &str,
        claim_ttl: Duration,
        limit: usize,
    ) -> Result<Vec<CoordinationOutboxClaim>, CoordinationError> {
        self.claim_transaction(projector, claim_ttl, limit).await
    }

    async fn acknowledge(
        &self,
        sequence: ProjectionSequence,
        projector: &str,
        claim_generation: CoordinationClaimGeneration,
    ) -> Result<(), CoordinationError> {
        validate_projector(projector)?;
        let result = sqlx::query(
            "WITH database_clock AS ( \
                 SELECT (extract(epoch from clock_timestamp()) * 1000)::bigint AS now_ms \
             ) \
             UPDATE coordination_outbox \
             SET applied_at_ms = database_clock.now_ms \
             FROM database_clock \
             WHERE deployment_id = $1 AND sequence = $2 AND claim_projector = $3 \
               AND claim_generation = $4 AND applied_at_ms IS NULL \
               AND claim_expires_at_ms > database_clock.now_ms",
        )
        .bind(self.deployment.as_str())
        .bind(sequence.as_i64())
        .bind(projector)
        .bind(claim_generation.as_i64())
        .execute(&self.pool)
        .await
        .map_err(|_| CoordinationError::Unavailable)?;
        if result.rows_affected() == 1 {
            Ok(())
        } else {
            Err(CoordinationError::StaleClaim)
        }
    }
}

#[async_trait]
impl CoordinationOutbox for SqliteCoordinationOutbox {
    async fn claim(
        &self,
        projector: &str,
        claim_ttl: Duration,
        limit: usize,
    ) -> Result<Vec<CoordinationOutboxClaim>, CoordinationError> {
        self.claim_transaction(projector, claim_ttl, limit).await
    }

    async fn acknowledge(
        &self,
        sequence: ProjectionSequence,
        projector: &str,
        claim_generation: CoordinationClaimGeneration,
    ) -> Result<(), CoordinationError> {
        validate_projector(projector)?;
        let statement = format!(
            "UPDATE coordination_outbox SET applied_at_ms = {SQLITE_NOW_MS} \
             WHERE deployment_id = ? AND sequence = ? AND claim_projector = ? \
               AND claim_generation = ? AND applied_at_ms IS NULL \
               AND claim_expires_at_ms > {SQLITE_NOW_MS}"
        );
        let result = sqlx::query(&statement)
            .bind(self.deployment.as_str())
            .bind(sequence.as_i64())
            .bind(projector)
            .bind(claim_generation.as_i64())
            .execute(&self.pool)
            .await
            .map_err(|_| CoordinationError::Unavailable)?;
        if result.rows_affected() == 1 {
            Ok(())
        } else {
            Err(CoordinationError::StaleClaim)
        }
    }
}

struct PendingRow {
    record: CoordinationOutboxRecord,
}

fn decode_pending_row<R>(
    deployment: &DeploymentId,
    row: &R,
) -> Result<PendingRow, CoordinationError>
where
    for<'column> &'column str: sqlx::ColumnIndex<R>,
    R: Row,
    i64: for<'value> sqlx::Decode<'value, R::Database> + sqlx::Type<R::Database>,
    String: for<'value> sqlx::Decode<'value, R::Database> + sqlx::Type<R::Database>,
{
    let sequence = ProjectionSequence::from_i64(
        row.try_get("sequence")
            .map_err(|_| CoordinationError::InvalidData)?,
    )?;
    let payload_json: String = row
        .try_get("payload_json")
        .map_err(|_| CoordinationError::InvalidData)?;
    let payload =
        serde_json::from_str(&payload_json).map_err(|_| CoordinationError::InvalidData)?;
    let recorded_at_ms: i64 = row
        .try_get("recorded_at_ms")
        .map_err(|_| CoordinationError::InvalidData)?;
    let projector: Option<String> = row
        .try_get("claim_projector")
        .map_err(|_| CoordinationError::InvalidData)?;
    let generation: i64 = row
        .try_get("claim_generation")
        .map_err(|_| CoordinationError::InvalidData)?;
    let claimed_at_ms: Option<i64> = row
        .try_get("claimed_at_ms")
        .map_err(|_| CoordinationError::InvalidData)?;
    let expires_at_ms: Option<i64> = row
        .try_get("claim_expires_at_ms")
        .map_err(|_| CoordinationError::InvalidData)?;
    let applied_at_ms: Option<i64> = row
        .try_get("applied_at_ms")
        .map_err(|_| CoordinationError::InvalidData)?;
    let event = CoordinationEvent {
        deployment: deployment.clone(),
        sequence,
        payload,
        recorded_at: datetime_from_millis(recorded_at_ms)?,
    };
    event.validate()?;
    let state = if let Some(applied_at_ms) = applied_at_ms {
        CoordinationOutboxState::Applied {
            at: datetime_from_millis(applied_at_ms)?,
        }
    } else {
        match (projector, claimed_at_ms, expires_at_ms) {
            (None, None, None) => CoordinationOutboxState::Ready,
            (Some(projector), Some(claimed_at_ms), Some(expires_at_ms)) => {
                CoordinationOutboxState::Claimed {
                    projector,
                    generation: CoordinationClaimGeneration::from_i64(generation)?,
                    claimed_at: datetime_from_millis(claimed_at_ms)?,
                    expires_at: datetime_from_millis(expires_at_ms)?,
                }
            }
            _ => return Err(CoordinationError::InvalidData),
        }
    };
    Ok(PendingRow {
        record: CoordinationOutboxRecord { event, state },
    })
}

fn claim_from_pending(
    mut record: CoordinationOutboxRecord,
    projector: &str,
    generation: CoordinationClaimGeneration,
    claimed_at_ms: i64,
    expires_at_ms: i64,
) -> Result<CoordinationOutboxClaim, CoordinationError> {
    record.state = CoordinationOutboxState::Claimed {
        projector: projector.to_owned(),
        generation,
        claimed_at: datetime_from_millis(claimed_at_ms)?,
        expires_at: datetime_from_millis(expires_at_ms)?,
    };
    Ok(CoordinationOutboxClaim {
        record,
        claim_generation: generation,
    })
}

fn build_ready_record(
    deployment: DeploymentId,
    sequence: i64,
    payload: CoordinationPayload,
    recorded_at_ms: i64,
) -> Result<CoordinationOutboxRecord, CoordinationError> {
    let event = CoordinationEvent {
        deployment,
        sequence: ProjectionSequence::from_i64(sequence)?,
        payload,
        recorded_at: datetime_from_millis(recorded_at_ms)?,
    };
    event.validate()?;
    Ok(CoordinationOutboxRecord {
        event,
        state: CoordinationOutboxState::Ready,
    })
}

fn validate_payload_at(
    deployment: &DeploymentId,
    payload: &CoordinationPayload,
    now_ms: i64,
) -> Result<(), CoordinationError> {
    CoordinationEvent {
        deployment: deployment.clone(),
        sequence: ProjectionSequence::INITIAL,
        payload: payload.clone(),
        recorded_at: datetime_from_millis(now_ms)?,
    }
    .validate()
}

fn validate_claim_request(
    projector: &str,
    claim_ttl: Duration,
    limit: usize,
) -> Result<(), CoordinationError> {
    validate_projector(projector)?;
    if limit == 0 || limit > MAX_BATCH_SIZE {
        return Err(CoordinationError::InvalidInput(
            "invalid coordination claim limit",
        ));
    }
    checked_claim_expiry(Utc::now(), claim_ttl).map(|_| ())
}

fn claim_expiry_millis(now_ms: i64, ttl: Duration) -> Result<i64, CoordinationError> {
    let now = datetime_from_millis(now_ms)?;
    Ok(checked_claim_expiry(now, ttl)?.timestamp_millis())
}

fn datetime_from_millis(value: i64) -> Result<DateTime<Utc>, CoordinationError> {
    DateTime::from_timestamp_millis(value).ok_or(CoordinationError::InvalidData)
}

async fn postgres_now_ms(connection: &mut PgConnection) -> Result<i64, CoordinationError> {
    sqlx::query_scalar("SELECT (extract(epoch from clock_timestamp()) * 1000)::bigint")
        .fetch_one(connection)
        .await
        .map_err(|_| CoordinationError::Unavailable)
}

async fn postgres_deployment_lock(
    transaction: &mut Transaction<'_, Postgres>,
    deployment: &DeploymentId,
) -> Result<(), CoordinationError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(deployment.as_str())
        .execute(&mut **transaction)
        .await
        .map_err(|_| CoordinationError::Unavailable)?;
    Ok(())
}

async fn sqlite_now_ms(connection: &mut SqliteConnection) -> Result<i64, CoordinationError> {
    let statement = format!("SELECT {SQLITE_NOW_MS}");
    sqlx::query_scalar(&statement)
        .fetch_one(connection)
        .await
        .map_err(|_| CoordinationError::Unavailable)
}
