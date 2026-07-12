//! Deterministic standalone coordination projection and wakeup broker.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::call_engine::{CallId, WorkerId};

use super::{
    validate_poll_interval, CallRouteHint, CoordinationClock, CoordinationError, CoordinationEvent,
    CoordinationPayload, CoordinationProjection, DatabasePollReason, DeploymentId,
    ProjectionApplyOutcome, ProjectionSequence, ReplayDigest, ReplayMarker, WakeupConsumer,
    WakeupMessage, WakeupPoll, WakeupPublisher, WakeupReason, WorkerCoordinationSnapshot,
    WorkerSelectionRequest,
};

#[derive(Clone)]
struct Versioned<T> {
    sequence: ProjectionSequence,
    value: T,
}

#[derive(Clone)]
struct MemoryWakeupEntry {
    id: u64,
    sequence: ProjectionSequence,
    reason: WakeupReason,
}

#[derive(Clone)]
struct PendingWakeup {
    consumer: String,
    delivered_at: DateTime<Utc>,
}

#[derive(Default)]
struct MemoryConsumerGroup {
    last_delivered: u64,
    pending: HashMap<u64, PendingWakeup>,
}

#[derive(Default)]
struct MemoryState {
    workers: HashMap<WorkerId, Versioned<WorkerCoordinationSnapshot>>,
    routes: HashMap<CallId, Versioned<CallRouteHint>>,
    replay: HashMap<ReplayDigest, Versioned<ReplayMarker>>,
    wakeup_sequences: HashMap<WorkerId, Versioned<WakeupReason>>,
    streams: HashMap<WorkerId, VecDeque<MemoryWakeupEntry>>,
    groups: HashMap<(WorkerId, String), MemoryConsumerGroup>,
    next_stream_id: u64,
}

/// One-lock deterministic coordination backend for standalone mode and tests.
pub struct MemoryCoordinator {
    deployment: DeploymentId,
    clock: Arc<dyn CoordinationClock>,
    max_stream_len: usize,
    state: Mutex<MemoryState>,
}

impl std::fmt::Debug for MemoryCoordinator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MemoryCoordinator")
            .field("deployment", &self.deployment)
            .field("max_stream_len", &self.max_stream_len)
            .finish_non_exhaustive()
    }
}

impl MemoryCoordinator {
    /// Creates an empty standalone projection.
    pub fn new(
        deployment: DeploymentId,
        clock: Arc<dyn CoordinationClock>,
        max_stream_len: usize,
    ) -> Result<Self, CoordinationError> {
        if max_stream_len == 0 || max_stream_len > 1_000_000 {
            return Err(CoordinationError::InvalidInput(
                "invalid wakeup stream bound",
            ));
        }
        Ok(Self {
            deployment,
            clock,
            max_stream_len,
            state: Mutex::new(MemoryState::default()),
        })
    }

    /// Creates a dedicated logical consumer for one worker stream.
    pub fn wakeup_consumer(
        self: &Arc<Self>,
        worker_id: WorkerId,
        group: impl Into<String>,
        consumer: impl Into<String>,
        poll_interval: Duration,
    ) -> Result<MemoryWakeupConsumer, CoordinationError> {
        validate_poll_interval(poll_interval)?;
        let group = validate_name(group.into())?;
        let consumer = validate_name(consumer.into())?;
        self.lock()?
            .groups
            .entry((worker_id, group.clone()))
            .or_default();
        Ok(MemoryWakeupConsumer {
            coordinator: Arc::clone(self),
            worker_id,
            group,
            consumer,
            poll_interval,
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, MemoryState>, CoordinationError> {
        self.state
            .lock()
            .map_err(|_| CoordinationError::Unavailable)
    }

    fn publish_locked(
        &self,
        state: &mut MemoryState,
        worker_id: WorkerId,
        sequence: ProjectionSequence,
        reason: WakeupReason,
    ) -> Result<(), CoordinationError> {
        state.next_stream_id = state
            .next_stream_id
            .checked_add(1)
            .ok_or(CoordinationError::CounterExhausted)?;
        let entry = MemoryWakeupEntry {
            id: state.next_stream_id,
            sequence,
            reason,
        };
        let stream = state.streams.entry(worker_id).or_default();
        stream.push_back(entry);
        while stream.len() > self.max_stream_len {
            if let Some(trimmed) = stream.pop_front() {
                for ((pending_worker, _), group) in &mut state.groups {
                    if *pending_worker == worker_id {
                        group.pending.remove(&trimmed.id);
                    }
                }
            }
        }
        Ok(())
    }

    fn apply_worker(
        &self,
        state: &mut MemoryState,
        sequence: ProjectionSequence,
        incoming: WorkerCoordinationSnapshot,
    ) -> Result<ProjectionApplyOutcome, CoordinationError> {
        incoming.validate()?;
        let now = self.clock.now();
        if let Some(existing) = state.workers.get(&incoming.lease.worker_id) {
            if sequence < existing.sequence {
                return Ok(ProjectionApplyOutcome::Stale);
            }
            if sequence == existing.sequence {
                return if incoming == existing.value {
                    Ok(ProjectionApplyOutcome::Duplicate)
                } else {
                    Err(CoordinationError::SequenceConflict)
                };
            }
            if incoming.lease.fence < existing.value.lease.fence {
                return Err(CoordinationError::StaleFence);
            }
            if incoming.lease.fence == existing.value.lease.fence {
                if existing.value.lease_expires_at <= now {
                    return Err(CoordinationError::LeaseExpired);
                }
                if existing.value.draining && !incoming.draining {
                    return Err(CoordinationError::DrainIsOneWay);
                }
            }
        }
        state.workers.insert(
            incoming.lease.worker_id,
            Versioned {
                sequence,
                value: incoming,
            },
        );
        Ok(ProjectionApplyOutcome::Applied)
    }

    fn apply_route(
        &self,
        state: &mut MemoryState,
        sequence: ProjectionSequence,
        incoming: CallRouteHint,
    ) -> Result<ProjectionApplyOutcome, CoordinationError> {
        if incoming.expires_at <= self.clock.now() {
            return Ok(ProjectionApplyOutcome::Stale);
        }
        apply_versioned(&mut state.routes, incoming.call_id, sequence, incoming)
    }

    fn apply_replay(
        &self,
        state: &mut MemoryState,
        sequence: ProjectionSequence,
        incoming: ReplayMarker,
    ) -> Result<ProjectionApplyOutcome, CoordinationError> {
        if incoming.expires_at <= self.clock.now() {
            return Ok(ProjectionApplyOutcome::Stale);
        }
        apply_versioned(&mut state.replay, incoming.digest, sequence, incoming)
    }

    fn apply_wakeup(
        &self,
        state: &mut MemoryState,
        sequence: ProjectionSequence,
        worker_id: WorkerId,
        reason: WakeupReason,
    ) -> Result<ProjectionApplyOutcome, CoordinationError> {
        let outcome = apply_versioned(&mut state.wakeup_sequences, worker_id, sequence, reason)?;
        if outcome == ProjectionApplyOutcome::Applied {
            self.publish_locked(state, worker_id, sequence, reason)?;
        }
        Ok(outcome)
    }
}

fn apply_versioned<K, V>(
    values: &mut HashMap<K, Versioned<V>>,
    key: K,
    sequence: ProjectionSequence,
    value: V,
) -> Result<ProjectionApplyOutcome, CoordinationError>
where
    K: Eq + std::hash::Hash,
    V: Eq,
{
    if let Some(existing) = values.get(&key) {
        if sequence < existing.sequence {
            return Ok(ProjectionApplyOutcome::Stale);
        }
        if sequence == existing.sequence {
            return if value == existing.value {
                Ok(ProjectionApplyOutcome::Duplicate)
            } else {
                Err(CoordinationError::SequenceConflict)
            };
        }
    }
    values.insert(key, Versioned { sequence, value });
    Ok(ProjectionApplyOutcome::Applied)
}

#[async_trait]
impl CoordinationProjection for MemoryCoordinator {
    async fn apply(
        &self,
        event: &CoordinationEvent,
    ) -> Result<ProjectionApplyOutcome, CoordinationError> {
        event.validate()?;
        if event.deployment != self.deployment {
            return Err(CoordinationError::InvalidInput(
                "coordination deployment mismatch",
            ));
        }
        let mut state = self.lock()?;
        match &event.payload {
            CoordinationPayload::Worker(worker) => {
                self.apply_worker(&mut state, event.sequence, worker.clone())
            }
            CoordinationPayload::Route(route) => {
                self.apply_route(&mut state, event.sequence, route.clone())
            }
            CoordinationPayload::Replay(marker) => {
                self.apply_replay(&mut state, event.sequence, marker.clone())
            }
            CoordinationPayload::WakeWorker { worker_id, reason } => {
                self.apply_wakeup(&mut state, event.sequence, *worker_id, *reason)
            }
        }
    }

    async fn worker_hints(
        &self,
        request: &WorkerSelectionRequest,
    ) -> Result<Vec<WorkerCoordinationSnapshot>, CoordinationError> {
        request.validate()?;
        let now = self.clock.now();
        let state = self.lock()?;
        let mut workers = state
            .workers
            .values()
            .filter(|entry| {
                entry.value.lease_expires_at > now
                    && !entry.value.draining
                    && entry.value.reserved_calls < entry.value.max_calls
                    && request
                        .required_capabilities
                        .is_subset(&entry.value.capabilities)
            })
            .map(|entry| entry.value.clone())
            .collect::<Vec<_>>();
        workers.sort_by(|left, right| {
            let left_load = (left.reserved_calls as u128) * (right.max_calls as u128);
            let right_load = (right.reserved_calls as u128) * (left.max_calls as u128);
            left_load
                .cmp(&right_load)
                .then(left.reserved_calls.cmp(&right.reserved_calls))
                .then(left.lease.worker_id.cmp(&right.lease.worker_id))
                .then(right.lease.fence.cmp(&left.lease.fence))
        });
        workers.truncate(request.limit);
        Ok(workers)
    }

    async fn route_hint(
        &self,
        call_id: CallId,
    ) -> Result<Option<CallRouteHint>, CoordinationError> {
        let now = self.clock.now();
        let state = self.lock()?;
        let Some(route) = state.routes.get(&call_id).map(|entry| &entry.value) else {
            return Ok(None);
        };
        if route.expires_at <= now {
            return Ok(None);
        }
        let worker_is_live = state
            .workers
            .get(&route.worker.worker_id)
            .is_some_and(|worker| {
                worker.value.lease == route.worker && worker.value.lease_expires_at > now
            });
        Ok(worker_is_live.then(|| route.clone()))
    }

    async fn replay_seen(&self, digest: ReplayDigest) -> Result<bool, CoordinationError> {
        let now = self.clock.now();
        Ok(self
            .lock()?
            .replay
            .get(&digest)
            .is_some_and(|entry| entry.value.expires_at > now))
    }
}

#[async_trait]
impl WakeupPublisher for MemoryCoordinator {
    async fn publish_wakeup(
        &self,
        worker_id: WorkerId,
        sequence: ProjectionSequence,
        reason: WakeupReason,
    ) -> Result<(), CoordinationError> {
        let mut state = self.lock()?;
        self.apply_wakeup(&mut state, sequence, worker_id, reason)
            .map(|_| ())
    }
}

/// Dedicated logical consumer for a memory wakeup stream.
pub struct MemoryWakeupConsumer {
    coordinator: Arc<MemoryCoordinator>,
    worker_id: WorkerId,
    group: String,
    consumer: String,
    poll_interval: Duration,
}

impl std::fmt::Debug for MemoryWakeupConsumer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MemoryWakeupConsumer")
            .field("worker_id", &self.worker_id)
            .field("group", &self.group)
            .field("consumer", &self.consumer)
            .field("poll_interval", &self.poll_interval)
            .finish()
    }
}

#[async_trait]
impl WakeupConsumer for MemoryWakeupConsumer {
    async fn poll(&mut self, count: usize) -> WakeupPoll {
        let count = count.clamp(1, 1_024);
        let now = self.coordinator.clock.now();
        let Ok(mut state) = self.coordinator.lock() else {
            return WakeupPoll {
                messages: Vec::new(),
                database_poll_reason: DatabasePollReason::CoordinationUnavailable,
            };
        };
        let key = (self.worker_id, self.group.clone());
        let last_delivered = state
            .groups
            .get(&key)
            .map_or(0, |group| group.last_delivered);
        let entries = state
            .streams
            .get(&self.worker_id)
            .into_iter()
            .flatten()
            .filter(|entry| entry.id > last_delivered)
            .take(count)
            .cloned()
            .collect::<Vec<_>>();
        let group = state.groups.entry(key).or_default();
        let mut messages = Vec::with_capacity(entries.len());
        for entry in entries {
            group.last_delivered = group.last_delivered.max(entry.id);
            group.pending.insert(
                entry.id,
                PendingWakeup {
                    consumer: self.consumer.clone(),
                    delivered_at: now,
                },
            );
            messages.push(memory_message(entry));
        }
        WakeupPoll {
            database_poll_reason: if messages.is_empty() {
                DatabasePollReason::IntervalElapsed
            } else {
                DatabasePollReason::Wakeup
            },
            messages,
        }
    }

    async fn auto_claim(
        &mut self,
        min_idle: Duration,
        count: usize,
    ) -> Result<Vec<WakeupMessage>, CoordinationError> {
        if min_idle.is_zero() || count == 0 || count > 1_024 {
            return Err(CoordinationError::InvalidInput(
                "invalid wakeup auto-claim request",
            ));
        }
        let min_idle = chrono::TimeDelta::from_std(min_idle)
            .map_err(|_| CoordinationError::InvalidInput("auto-claim idle is too large"))?;
        let now = self.coordinator.clock.now();
        let mut state = self.coordinator.lock()?;
        let key = (self.worker_id, self.group.clone());
        let eligible = state
            .groups
            .get(&key)
            .into_iter()
            .flat_map(|group| &group.pending)
            .filter(|(_, pending)| {
                pending.consumer != self.consumer && pending.delivered_at + min_idle <= now
            })
            .map(|(id, _)| *id)
            .take(count)
            .collect::<Vec<_>>();
        let entries = state
            .streams
            .get(&self.worker_id)
            .into_iter()
            .flatten()
            .filter(|entry| eligible.contains(&entry.id))
            .cloned()
            .collect::<Vec<_>>();
        let group = state.groups.entry(key).or_default();
        for entry in &entries {
            if let Some(pending) = group.pending.get_mut(&entry.id) {
                pending.consumer.clone_from(&self.consumer);
                pending.delivered_at = now;
            }
        }
        Ok(entries.into_iter().map(memory_message).collect())
    }

    async fn acknowledge(&mut self, entry_ids: &[String]) -> Result<usize, CoordinationError> {
        let ids = entry_ids
            .iter()
            .map(|id| {
                id.strip_suffix("-0")
                    .ok_or(CoordinationError::InvalidInput("invalid memory stream ID"))?
                    .parse::<u64>()
                    .map_err(|_| CoordinationError::InvalidInput("invalid memory stream ID"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut state = self.coordinator.lock()?;
        let group = state
            .groups
            .entry((self.worker_id, self.group.clone()))
            .or_default();
        Ok(ids
            .into_iter()
            .filter(|id| group.pending.remove(id).is_some())
            .count())
    }
}

fn memory_message(entry: MemoryWakeupEntry) -> WakeupMessage {
    WakeupMessage {
        entry_id: format!("{}-0", entry.id),
        sequence: entry.sequence,
        reason: entry.reason,
    }
}

fn validate_name(value: String) -> Result<String, CoordinationError> {
    if value.is_empty()
        || value.len() > 128
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        Err(CoordinationError::InvalidInput(
            "invalid consumer or group name",
        ))
    } else {
        Ok(value)
    }
}
