//! Ordered coordination outbox contracts and deterministic memory source.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use super::{
    checked_claim_expiry, CoordinationClaimGeneration, CoordinationClock, CoordinationError,
    CoordinationEvent, CoordinationPayload, CoordinationProjection, DeploymentId,
    ProjectionApplyOutcome, ProjectionSequence,
};

/// Durable coordination-outbox lifecycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoordinationOutboxState {
    /// Ready for the ordered projector.
    Ready,
    /// Exclusively claimed until expiry.
    Claimed {
        /// Projector identity.
        projector: String,
        /// Claim incarnation.
        generation: CoordinationClaimGeneration,
        /// Claim start.
        claimed_at: DateTime<Utc>,
        /// Claim expiry.
        expires_at: DateTime<Utc>,
    },
    /// Applied to the projection and acknowledged in the authoritative store.
    Applied {
        /// Acknowledgement time.
        at: DateTime<Utc>,
    },
}

/// One durable coordination-outbox record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoordinationOutboxRecord {
    /// Safe typed event.
    pub event: CoordinationEvent,
    /// Durable lifecycle.
    pub state: CoordinationOutboxState,
}

/// Claimed event and exact acknowledgement guard.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoordinationOutboxClaim {
    /// Claimed record snapshot.
    pub record: CoordinationOutboxRecord,
    /// Exact claim incarnation.
    pub claim_generation: CoordinationClaimGeneration,
}

/// Authoritative ordered outbox consumed by a later projector.
#[async_trait]
pub trait CoordinationOutbox: Send + Sync {
    /// Claims a contiguous ordered prefix. PostgreSQL implementations use DB time.
    async fn claim(
        &self,
        projector: &str,
        claim_ttl: Duration,
        limit: usize,
    ) -> Result<Vec<CoordinationOutboxClaim>, CoordinationError>;

    /// Acknowledges an exact projected claim.
    async fn acknowledge(
        &self,
        sequence: ProjectionSequence,
        projector: &str,
        claim_generation: CoordinationClaimGeneration,
    ) -> Result<(), CoordinationError>;
}

#[derive(Default)]
struct MemoryOutboxState {
    last_sequence: Option<ProjectionSequence>,
    records: BTreeMap<ProjectionSequence, CoordinationOutboxRecord>,
}

/// Standalone authoritative coordination outbox with an injected clock.
pub struct MemoryCoordinationOutbox {
    deployment: DeploymentId,
    clock: Arc<dyn CoordinationClock>,
    state: Mutex<MemoryOutboxState>,
}

impl std::fmt::Debug for MemoryCoordinationOutbox {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MemoryCoordinationOutbox")
            .field("deployment", &self.deployment)
            .finish_non_exhaustive()
    }
}

impl MemoryCoordinationOutbox {
    /// Creates an empty standalone outbox.
    #[must_use]
    pub fn new(deployment: DeploymentId, clock: Arc<dyn CoordinationClock>) -> Self {
        Self {
            deployment,
            clock,
            state: Mutex::new(MemoryOutboxState::default()),
        }
    }

    /// Atomically appends a safe event in authoritative order.
    pub fn append(
        &self,
        payload: CoordinationPayload,
    ) -> Result<CoordinationOutboxRecord, CoordinationError> {
        let mut state = self.lock()?;
        let sequence = match state.last_sequence {
            Some(last) => last.next()?,
            None => ProjectionSequence::INITIAL,
        };
        let event = CoordinationEvent {
            deployment: self.deployment.clone(),
            sequence,
            payload,
            recorded_at: self.clock.now(),
        };
        event.validate()?;
        let record = CoordinationOutboxRecord {
            event,
            state: CoordinationOutboxState::Ready,
        };
        state.last_sequence = Some(sequence);
        state.records.insert(sequence, record.clone());
        Ok(record)
    }

    /// Returns one record for deterministic diagnostics/tests.
    pub fn record(
        &self,
        sequence: ProjectionSequence,
    ) -> Result<Option<CoordinationOutboxRecord>, CoordinationError> {
        Ok(self.lock()?.records.get(&sequence).cloned())
    }

    fn lock(&self) -> Result<MutexGuard<'_, MemoryOutboxState>, CoordinationError> {
        self.state
            .lock()
            .map_err(|_| CoordinationError::Unavailable)
    }
}

#[async_trait]
impl CoordinationOutbox for MemoryCoordinationOutbox {
    async fn claim(
        &self,
        projector: &str,
        claim_ttl: Duration,
        limit: usize,
    ) -> Result<Vec<CoordinationOutboxClaim>, CoordinationError> {
        validate_projector(projector)?;
        if limit == 0 || limit > 1_024 {
            return Err(CoordinationError::InvalidInput(
                "invalid coordination claim limit",
            ));
        }
        let now = self.clock.now();
        let expires_at = checked_claim_expiry(now, claim_ttl)?;
        let mut state = self.lock()?;
        let mut claims = Vec::new();
        for record in state.records.values_mut() {
            if claims.len() >= limit {
                break;
            }
            let previous = match &record.state {
                CoordinationOutboxState::Applied { .. } => continue,
                CoordinationOutboxState::Ready => CoordinationClaimGeneration::default(),
                CoordinationOutboxState::Claimed {
                    generation,
                    expires_at,
                    ..
                } if *expires_at <= now => *generation,
                CoordinationOutboxState::Claimed { .. } => break,
            };
            let generation = previous.next()?;
            record.state = CoordinationOutboxState::Claimed {
                projector: projector.to_owned(),
                generation,
                claimed_at: now,
                expires_at,
            };
            claims.push(CoordinationOutboxClaim {
                record: record.clone(),
                claim_generation: generation,
            });
        }
        Ok(claims)
    }

    async fn acknowledge(
        &self,
        sequence: ProjectionSequence,
        projector: &str,
        claim_generation: CoordinationClaimGeneration,
    ) -> Result<(), CoordinationError> {
        validate_projector(projector)?;
        let now = self.clock.now();
        let mut state = self.lock()?;
        let record = state
            .records
            .get_mut(&sequence)
            .ok_or(CoordinationError::StaleClaim)?;
        match &record.state {
            CoordinationOutboxState::Claimed {
                projector: owner,
                generation,
                claimed_at,
                expires_at,
            } if owner == projector
                && *generation == claim_generation
                && *claimed_at <= now
                && *expires_at > now => {}
            _ => return Err(CoordinationError::StaleClaim),
        }
        record.state = CoordinationOutboxState::Applied { at: now };
        Ok(())
    }
}

/// Projects durable events and acknowledges only after the cache/wakeup write succeeds.
pub struct CoordinationProjector<O, P> {
    outbox: Arc<O>,
    projection: Arc<P>,
    projector: String,
    claim_ttl: Duration,
    batch_size: usize,
}

impl<O, P> std::fmt::Debug for CoordinationProjector<O, P> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CoordinationProjector")
            .field("projector", &self.projector)
            .field("claim_ttl", &self.claim_ttl)
            .field("batch_size", &self.batch_size)
            .finish_non_exhaustive()
    }
}

impl<O, P> CoordinationProjector<O, P>
where
    O: CoordinationOutbox,
    P: CoordinationProjection,
{
    /// Creates an ordered projector. It never writes the authoritative call repository.
    pub fn new(
        outbox: Arc<O>,
        projection: Arc<P>,
        projector: impl Into<String>,
        claim_ttl: Duration,
        batch_size: usize,
    ) -> Result<Self, CoordinationError> {
        let projector = projector.into();
        validate_projector(&projector)?;
        if batch_size == 0 || batch_size > 1_024 {
            return Err(CoordinationError::InvalidInput(
                "invalid projector batch size",
            ));
        }
        checked_claim_expiry(Utc::now(), claim_ttl)?;
        Ok(Self {
            outbox,
            projection,
            projector,
            claim_ttl,
            batch_size,
        })
    }

    /// Projects one claimed ordered batch. A failed projection remains unacknowledged.
    pub async fn project_once(&self) -> Result<usize, CoordinationError> {
        let claims = self
            .outbox
            .claim(&self.projector, self.claim_ttl, self.batch_size)
            .await?;
        let mut applied = 0;
        for claim in claims {
            match self.projection.apply(&claim.record.event).await? {
                ProjectionApplyOutcome::Applied
                | ProjectionApplyOutcome::Duplicate
                | ProjectionApplyOutcome::Stale => {}
            }
            self.outbox
                .acknowledge(
                    claim.record.event.sequence,
                    &self.projector,
                    claim.claim_generation,
                )
                .await?;
            applied += 1;
        }
        Ok(applied)
    }
}

pub(crate) fn validate_projector(projector: &str) -> Result<(), CoordinationError> {
    if projector.is_empty()
        || projector.len() > 128
        || projector
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        Err(CoordinationError::InvalidInput(
            "invalid coordination projector ID",
        ))
    } else {
        Ok(())
    }
}
