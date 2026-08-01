//! Durable state boundary for gateway private-egress command execution.
//!
//! The in-memory implementation is intentionally hermetic and explicitly
//! non-durable. Clustered process roles must install a durable implementation;
//! they may not claim restart safety by wrapping this store.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::call_engine::{BindingGeneration, CallId, LegId, TenantId, WorkerLease};
use crate::private_egress::{
    PrivateEgressError, PrivateEgressLifecycleEvent, PrivateEgressLifecycleKind,
    PrivateEgressLifecycleState, PrivateEgressResponse, PrivateEgressRouteAuthority,
    PrivateEgressSource, PrivateEgressTarget,
};

/// Process incarnation fenced by one stable gateway identity.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct PrivateEgressGatewayEpoch {
    pub gateway_id: String,
    pub instance_id: Uuid,
}

impl PrivateEgressGatewayEpoch {
    pub fn new(
        gateway_id: impl Into<String>,
        instance_id: Uuid,
    ) -> Result<Self, PrivateEgressError> {
        let gateway_id = gateway_id.into();
        if gateway_id.is_empty()
            || gateway_id.len() > 128
            || instance_id.is_nil()
            || !gateway_id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':')
            })
        {
            return Err(PrivateEgressError::InvalidCommand);
        }
        Ok(Self {
            gateway_id,
            instance_id,
        })
    }

    pub fn standalone() -> Self {
        Self {
            gateway_id: "standalone".into(),
            instance_id: Uuid::new_v4(),
        }
    }
}

/// Exact route generation persisted independently of process-local adapters.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct PrivateEgressRouteKey {
    pub worker: WorkerLease,
    pub tenant_id: TenantId,
    pub call_id: CallId,
    pub source_leg_id: LegId,
    pub source_binding_generation: BindingGeneration,
    pub target: PrivateEgressTarget,
}

impl PrivateEgressRouteKey {
    pub fn new(
        worker: WorkerLease,
        source: &PrivateEgressSource,
        target: PrivateEgressTarget,
    ) -> Self {
        Self {
            worker,
            tenant_id: source.tenant_id.clone(),
            call_id: source.call_id,
            source_leg_id: source.leg_id,
            source_binding_generation: source.binding_generation,
            target,
        }
    }

    pub fn authority(&self) -> PrivateEgressRouteAuthority {
        PrivateEgressRouteAuthority {
            worker: self.worker,
            source: PrivateEgressSource {
                tenant_id: self.tenant_id.clone(),
                call_id: self.call_id,
                leg_id: self.source_leg_id,
                binding_generation: self.source_binding_generation,
            },
        }
    }

    pub fn belongs_to(&self, authority: &PrivateEgressRouteAuthority) -> bool {
        self.worker == authority.worker
            && self.tenant_id == authority.source.tenant_id
            && self.call_id == authority.source.call_id
            && self.source_leg_id == authority.source.leg_id
            && self.source_binding_generation == authority.source.binding_generation
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrivateEgressCommandClaim {
    Acquired,
    InFlight,
    Completed(PrivateEgressResponse),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateEgressRecoveredRoute {
    pub dead_epoch: Uuid,
    pub key: PrivateEgressRouteKey,
}

/// Store contract required for restart-safe command and lifecycle execution.
#[async_trait]
pub trait PrivateEgressStateStore: Send + Sync {
    /// True only for a shared store whose writes survive this process.
    fn is_durable(&self) -> bool;

    /// Fence the previous instance and atomically tombstone every route or
    /// incomplete command owned by that dead epoch.
    async fn begin_epoch(
        &self,
        epoch: &PrivateEgressGatewayEpoch,
        at_ms: i64,
    ) -> Result<Vec<PrivateEgressRecoveredRoute>, PrivateEgressError>;

    async fn assert_epoch(
        &self,
        epoch: &PrivateEgressGatewayEpoch,
    ) -> Result<(), PrivateEgressError>;

    /// A dead-epoch route stays recovery-pending until adapter cleanup is
    /// explicitly acknowledged. Reconstructing a service cannot skip a failed
    /// cleanup attempt.
    async fn complete_route_recovery(
        &self,
        epoch: &PrivateEgressGatewayEpoch,
        key: &PrivateEgressRouteKey,
    ) -> Result<(), PrivateEgressError>;

    async fn claim_command(
        &self,
        epoch: &PrivateEgressGatewayEpoch,
        command_id: Uuid,
        digest: [u8; 32],
        at_ms: i64,
    ) -> Result<PrivateEgressCommandClaim, PrivateEgressError>;

    async fn complete_command(
        &self,
        epoch: &PrivateEgressGatewayEpoch,
        command_id: Uuid,
        digest: [u8; 32],
        response: &PrivateEgressResponse,
        at_ms: i64,
    ) -> Result<(), PrivateEgressError>;

    /// Claim one exact route transition before adapter I/O. `None` is the
    /// expected state only for a first Prepare.
    async fn claim_route_transition(
        &self,
        epoch: &PrivateEgressGatewayEpoch,
        key: &PrivateEgressRouteKey,
        command_id: Uuid,
        expected: Option<PrivateEgressLifecycleState>,
        next: PrivateEgressLifecycleState,
    ) -> Result<(), PrivateEgressError>;

    async fn complete_route_transition(
        &self,
        epoch: &PrivateEgressGatewayEpoch,
        key: &PrivateEgressRouteKey,
        command_id: Uuid,
        next: PrivateEgressLifecycleState,
        at_ms: i64,
    ) -> Result<(), PrivateEgressError>;

    async fn abort_route_transition(
        &self,
        epoch: &PrivateEgressGatewayEpoch,
        key: &PrivateEgressRouteKey,
        command_id: Uuid,
    ) -> Result<(), PrivateEgressError>;

    async fn fail_source(
        &self,
        epoch: &PrivateEgressGatewayEpoch,
        authority: &PrivateEgressRouteAuthority,
        at_ms: i64,
    ) -> Result<Vec<PrivateEgressRouteKey>, PrivateEgressError>;

    /// Apply the route transition and append one monotonic, unacked journal
    /// record atomically. The returned event is stamped with epoch/sequence.
    async fn append_lifecycle(
        &self,
        epoch: &PrivateEgressGatewayEpoch,
        key: &PrivateEgressRouteKey,
        event: &PrivateEgressLifecycleEvent,
        at_ms: i64,
    ) -> Result<PrivateEgressLifecycleEvent, PrivateEgressError>;

    async fn ack_lifecycle(
        &self,
        epoch: &PrivateEgressGatewayEpoch,
        key: &PrivateEgressRouteKey,
        event_id: Uuid,
        sequence: u64,
    ) -> Result<(), PrivateEgressError>;

    async fn unacked_lifecycle(
        &self,
        epoch: &PrivateEgressGatewayEpoch,
        key: &PrivateEgressRouteKey,
    ) -> Result<Vec<PrivateEgressLifecycleEvent>, PrivateEgressError>;
}

struct MemoryCommandRecord {
    epoch: Uuid,
    digest: [u8; 32],
    created_at_ms: i64,
    completed_at_ms: Option<i64>,
    response: Option<PrivateEgressResponse>,
}

struct MemoryRouteRecord {
    epoch: Uuid,
    state: Option<PrivateEgressLifecycleState>,
    pending: Option<(Uuid, PrivateEgressLifecycleState)>,
    next_lifecycle_sequence: u64,
    tombstoned_at_ms: Option<i64>,
    recovery_required: bool,
}

struct MemoryLifecycleRecord {
    epoch: Uuid,
    key: PrivateEgressRouteKey,
    event: PrivateEgressLifecycleEvent,
    acked: bool,
    created_at_ms: i64,
}

#[derive(Default)]
struct MemoryState {
    active_epochs: HashMap<String, Uuid>,
    commands: HashMap<(String, Uuid), MemoryCommandRecord>,
    routes: HashMap<(String, PrivateEgressRouteKey), MemoryRouteRecord>,
    lifecycle: HashMap<(String, Uuid), MemoryLifecycleRecord>,
}

/// Hermetic state store for standalone mode and deterministic tests.
pub struct MemoryPrivateEgressStateStore {
    max_entries: usize,
    ttl: Duration,
    state: Mutex<MemoryState>,
}

impl MemoryPrivateEgressStateStore {
    pub fn new(max_entries: usize, ttl: Duration) -> Result<Arc<Self>, PrivateEgressError> {
        if max_entries == 0 || ttl.is_zero() {
            return Err(PrivateEgressError::InvalidCommand);
        }
        Ok(Arc::new(Self {
            max_entries,
            ttl,
            state: Mutex::new(MemoryState::default()),
        }))
    }

    pub(crate) fn activate(
        &self,
        epoch: &PrivateEgressGatewayEpoch,
        at_ms: i64,
    ) -> Vec<PrivateEgressRecoveredRoute> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        begin_epoch_locked(&mut state, epoch, at_ms)
    }

    fn ttl_ms(&self) -> i64 {
        i64::try_from(self.ttl.as_millis()).unwrap_or(i64::MAX)
    }

    fn sweep_locked(&self, state: &mut MemoryState, at_ms: i64) {
        let ttl_ms = self.ttl_ms();
        state.commands.retain(|_, record| {
            let completed = record.completed_at_ms.unwrap_or(record.created_at_ms);
            at_ms.saturating_sub(completed) < ttl_ms || record.response.is_none()
        });
        let expired_routes = state
            .routes
            .iter()
            .filter(|(_, route)| {
                !route.recovery_required
                    && route
                        .tombstoned_at_ms
                        .is_some_and(|completed| at_ms.saturating_sub(completed) >= ttl_ms)
            })
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        for key in expired_routes {
            state.routes.remove(&key);
            state
                .lifecycle
                .retain(|(gateway, _), event| !(gateway == &key.0 && event.key == key.1));
        }
        state
            .lifecycle
            .retain(|_, event| !event.acked || at_ms.saturating_sub(event.created_at_ms) < ttl_ms);
    }
}

#[async_trait]
impl PrivateEgressStateStore for MemoryPrivateEgressStateStore {
    fn is_durable(&self) -> bool {
        false
    }

    async fn begin_epoch(
        &self,
        epoch: &PrivateEgressGatewayEpoch,
        at_ms: i64,
    ) -> Result<Vec<PrivateEgressRecoveredRoute>, PrivateEgressError> {
        Ok(self.activate(epoch, at_ms))
    }

    async fn assert_epoch(
        &self,
        epoch: &PrivateEgressGatewayEpoch,
    ) -> Result<(), PrivateEgressError> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.active_epochs.get(&epoch.gateway_id) == Some(&epoch.instance_id) {
            Ok(())
        } else {
            Err(PrivateEgressError::DeadEpoch)
        }
    }

    async fn complete_route_recovery(
        &self,
        epoch: &PrivateEgressGatewayEpoch,
        key: &PrivateEgressRouteKey,
    ) -> Result<(), PrivateEgressError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        ensure_epoch(&state, epoch)?;
        let route = state
            .routes
            .get_mut(&(epoch.gateway_id.clone(), key.clone()))
            .ok_or(PrivateEgressError::StateUnavailable)?;
        if !route.recovery_required
            || route.state != Some(PrivateEgressLifecycleState::Failed)
            || route.tombstoned_at_ms.is_none()
        {
            return Err(PrivateEgressError::InvalidTransition);
        }
        route.recovery_required = false;
        Ok(())
    }

    async fn claim_command(
        &self,
        epoch: &PrivateEgressGatewayEpoch,
        command_id: Uuid,
        digest: [u8; 32],
        at_ms: i64,
    ) -> Result<PrivateEgressCommandClaim, PrivateEgressError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        ensure_epoch(&state, epoch)?;
        self.sweep_locked(&mut state, at_ms);
        let key = (epoch.gateway_id.clone(), command_id);
        if let Some(record) = state.commands.get(&key) {
            if record.digest != digest {
                return Err(PrivateEgressError::ReplayConflict);
            }
            return Ok(match &record.response {
                Some(response) => PrivateEgressCommandClaim::Completed(response.clone()),
                None => PrivateEgressCommandClaim::InFlight,
            });
        }
        if state.commands.len() >= self.max_entries {
            return Err(PrivateEgressError::CapacityExceeded);
        }
        state.commands.insert(
            key,
            MemoryCommandRecord {
                epoch: epoch.instance_id,
                digest,
                created_at_ms: at_ms,
                completed_at_ms: None,
                response: None,
            },
        );
        Ok(PrivateEgressCommandClaim::Acquired)
    }

    async fn complete_command(
        &self,
        epoch: &PrivateEgressGatewayEpoch,
        command_id: Uuid,
        digest: [u8; 32],
        response: &PrivateEgressResponse,
        at_ms: i64,
    ) -> Result<(), PrivateEgressError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        ensure_epoch(&state, epoch)?;
        let record = state
            .commands
            .get_mut(&(epoch.gateway_id.clone(), command_id))
            .ok_or(PrivateEgressError::StateUnavailable)?;
        if record.epoch != epoch.instance_id || record.digest != digest {
            return Err(PrivateEgressError::ReplayConflict);
        }
        if let Some(existing) = &record.response {
            return if existing == response {
                Ok(())
            } else {
                Err(PrivateEgressError::ReplayConflict)
            };
        }
        record.response = Some(response.clone());
        record.completed_at_ms = Some(at_ms);
        Ok(())
    }

    async fn claim_route_transition(
        &self,
        epoch: &PrivateEgressGatewayEpoch,
        key: &PrivateEgressRouteKey,
        command_id: Uuid,
        expected: Option<PrivateEgressLifecycleState>,
        next: PrivateEgressLifecycleState,
    ) -> Result<(), PrivateEgressError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        ensure_epoch(&state, epoch)?;
        let route_key = (epoch.gateway_id.clone(), key.clone());
        match state.routes.get_mut(&route_key) {
            Some(route)
                if route.epoch == epoch.instance_id
                    && route.state == expected
                    && route.pending.is_none()
                    && route.tombstoned_at_ms.is_none() =>
            {
                route.pending = Some((command_id, next));
                Ok(())
            }
            None if expected.is_none() => {
                if state.routes.len() >= self.max_entries {
                    return Err(PrivateEgressError::CapacityExceeded);
                }
                state.routes.insert(
                    route_key,
                    MemoryRouteRecord {
                        epoch: epoch.instance_id,
                        state: None,
                        pending: Some((command_id, next)),
                        next_lifecycle_sequence: 0,
                        tombstoned_at_ms: None,
                        recovery_required: false,
                    },
                );
                Ok(())
            }
            _ => Err(PrivateEgressError::InvalidTransition),
        }
    }

    async fn complete_route_transition(
        &self,
        epoch: &PrivateEgressGatewayEpoch,
        key: &PrivateEgressRouteKey,
        command_id: Uuid,
        next: PrivateEgressLifecycleState,
        at_ms: i64,
    ) -> Result<(), PrivateEgressError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        ensure_epoch(&state, epoch)?;
        let route = state
            .routes
            .get_mut(&(epoch.gateway_id.clone(), key.clone()))
            .ok_or(PrivateEgressError::InvalidTransition)?;
        if route.epoch != epoch.instance_id || route.pending != Some((command_id, next)) {
            return Err(PrivateEgressError::InvalidTransition);
        }
        route.pending = None;
        route.state = Some(next);
        if is_terminal(next) {
            route.tombstoned_at_ms = Some(at_ms);
        }
        Ok(())
    }

    async fn abort_route_transition(
        &self,
        epoch: &PrivateEgressGatewayEpoch,
        key: &PrivateEgressRouteKey,
        command_id: Uuid,
    ) -> Result<(), PrivateEgressError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        ensure_epoch(&state, epoch)?;
        let route_key = (epoch.gateway_id.clone(), key.clone());
        let remove = {
            let route = state
                .routes
                .get_mut(&route_key)
                .ok_or(PrivateEgressError::InvalidTransition)?;
            if route.epoch != epoch.instance_id
                || route.pending.is_none_or(|pending| pending.0 != command_id)
            {
                return Err(PrivateEgressError::InvalidTransition);
            }
            route.pending = None;
            route.state.is_none()
        };
        if remove {
            state.routes.remove(&route_key);
        }
        Ok(())
    }

    async fn fail_source(
        &self,
        epoch: &PrivateEgressGatewayEpoch,
        authority: &PrivateEgressRouteAuthority,
        at_ms: i64,
    ) -> Result<Vec<PrivateEgressRouteKey>, PrivateEgressError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        ensure_epoch(&state, epoch)?;
        let keys = state
            .routes
            .iter()
            .filter(|((gateway, key), route)| {
                gateway == &epoch.gateway_id
                    && route.epoch == epoch.instance_id
                    && key.belongs_to(authority)
                    && (route.pending.is_some()
                        || route.state.is_some_and(|state| !is_terminal(state)))
            })
            .map(|((_, key), _)| key.clone())
            .collect::<Vec<_>>();
        for key in &keys {
            if let Some(route) = state
                .routes
                .get_mut(&(epoch.gateway_id.clone(), key.clone()))
            {
                route.pending = None;
                route.state = Some(PrivateEgressLifecycleState::Failed);
                route.tombstoned_at_ms = Some(at_ms);
            }
        }
        Ok(keys)
    }

    async fn append_lifecycle(
        &self,
        epoch: &PrivateEgressGatewayEpoch,
        key: &PrivateEgressRouteKey,
        event: &PrivateEgressLifecycleEvent,
        at_ms: i64,
    ) -> Result<PrivateEgressLifecycleEvent, PrivateEgressError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        ensure_epoch(&state, epoch)?;
        if event.worker != key.worker
            || event.source != key.authority().source
            || event.target != key.target
            || !event.gateway_epoch.is_nil()
            || event.sequence != 0
        {
            return Err(PrivateEgressError::OwnershipMismatch);
        }
        let journal_key = (epoch.gateway_id.clone(), event.event_id);
        if state.lifecycle.contains_key(&journal_key) {
            return Err(PrivateEgressError::ReplayConflict);
        }
        if state.lifecycle.len() >= self.max_entries {
            return Err(PrivateEgressError::CapacityExceeded);
        }
        let sequence = {
            let route = state
                .routes
                .get_mut(&(epoch.gateway_id.clone(), key.clone()))
                .ok_or(PrivateEgressError::InvalidTransition)?;
            if route.epoch != epoch.instance_id
                || route.recovery_required
                || route.tombstoned_at_ms.is_some()
            {
                return Err(PrivateEgressError::InvalidTransition);
            }
            let current = route.state.ok_or(PrivateEgressError::InvalidTransition)?;
            match &event.kind {
                PrivateEgressLifecycleKind::State { state: next, .. } => {
                    if route.pending.is_some() || !lifecycle_transition_allowed(current, *next) {
                        return Err(PrivateEgressError::InvalidTransition);
                    }
                    route.state = Some(*next);
                    if is_terminal(*next) {
                        route.tombstoned_at_ms = Some(at_ms);
                    }
                }
                PrivateEgressLifecycleKind::Progress { status_code, .. } => {
                    let pending_activate = route
                        .pending
                        .is_none_or(|(_, next)| next == PrivateEgressLifecycleState::Active);
                    if current != PrivateEgressLifecycleState::Prepared
                        || !pending_activate
                        || !(100..=199).contains(status_code)
                    {
                        return Err(PrivateEgressError::InvalidTransition);
                    }
                }
            }
            let sequence = route
                .next_lifecycle_sequence
                .checked_add(1)
                .ok_or(PrivateEgressError::StateUnavailable)?;
            route.next_lifecycle_sequence = sequence;
            sequence
        };
        let mut stamped = event.clone();
        stamped.gateway_epoch = epoch.instance_id;
        stamped.sequence = sequence;
        state.lifecycle.insert(
            journal_key,
            MemoryLifecycleRecord {
                epoch: epoch.instance_id,
                key: key.clone(),
                event: stamped.clone(),
                acked: false,
                created_at_ms: at_ms,
            },
        );
        Ok(stamped)
    }

    async fn ack_lifecycle(
        &self,
        epoch: &PrivateEgressGatewayEpoch,
        key: &PrivateEgressRouteKey,
        event_id: Uuid,
        sequence: u64,
    ) -> Result<(), PrivateEgressError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        ensure_epoch(&state, epoch)?;
        let record = state
            .lifecycle
            .get_mut(&(epoch.gateway_id.clone(), event_id))
            .ok_or(PrivateEgressError::InvalidResponse)?;
        if record.epoch != epoch.instance_id
            || record.key != *key
            || record.event.sequence != sequence
        {
            return Err(PrivateEgressError::OwnershipMismatch);
        }
        record.acked = true;
        Ok(())
    }

    async fn unacked_lifecycle(
        &self,
        epoch: &PrivateEgressGatewayEpoch,
        key: &PrivateEgressRouteKey,
    ) -> Result<Vec<PrivateEgressLifecycleEvent>, PrivateEgressError> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        ensure_epoch(&state, epoch)?;
        let mut events = state
            .lifecycle
            .iter()
            .filter(|((gateway, _), event)| {
                gateway == &epoch.gateway_id
                    && event.epoch == epoch.instance_id
                    && event.key == *key
                    && !event.acked
            })
            .map(|(_, event)| event.event.clone())
            .collect::<Vec<_>>();
        events.sort_by_key(|event| event.sequence);
        Ok(events)
    }
}

fn ensure_epoch(
    state: &MemoryState,
    epoch: &PrivateEgressGatewayEpoch,
) -> Result<(), PrivateEgressError> {
    if state.active_epochs.get(&epoch.gateway_id) == Some(&epoch.instance_id) {
        Ok(())
    } else {
        Err(PrivateEgressError::DeadEpoch)
    }
}

fn begin_epoch_locked(
    state: &mut MemoryState,
    epoch: &PrivateEgressGatewayEpoch,
    at_ms: i64,
) -> Vec<PrivateEgressRecoveredRoute> {
    let previous = state
        .active_epochs
        .insert(epoch.gateway_id.clone(), epoch.instance_id);
    if let Some(dead_epoch) = previous.filter(|previous| *previous != epoch.instance_id) {
        for ((gateway, command_id), command) in &mut state.commands {
            if gateway == &epoch.gateway_id && command.epoch != epoch.instance_id {
                command.epoch = epoch.instance_id;
                command.response = Some(PrivateEgressResponse::rejected(
                    *command_id,
                    PrivateEgressError::DeadEpoch,
                ));
                command.completed_at_ms = Some(at_ms);
            }
        }
        for ((gateway, _), route) in &mut state.routes {
            if gateway == &epoch.gateway_id
                && route.epoch == dead_epoch
                && (route.pending.is_some() || route.state.is_some_and(|state| !is_terminal(state)))
            {
                route.pending = None;
                route.state = Some(PrivateEgressLifecycleState::Failed);
                route.tombstoned_at_ms = Some(at_ms);
                route.recovery_required = true;
            }
        }
    }
    state
        .routes
        .iter()
        .filter(|((gateway, _), route)| gateway == &epoch.gateway_id && route.recovery_required)
        .map(|((_, key), route)| PrivateEgressRecoveredRoute {
            dead_epoch: route.epoch,
            key: key.clone(),
        })
        .collect()
}

fn is_terminal(state: PrivateEgressLifecycleState) -> bool {
    matches!(
        state,
        PrivateEgressLifecycleState::Ended | PrivateEgressLifecycleState::Failed
    )
}

fn lifecycle_transition_allowed(
    current: PrivateEgressLifecycleState,
    next: PrivateEgressLifecycleState,
) -> bool {
    matches!(
        (current, next),
        (
            PrivateEgressLifecycleState::Prepared,
            PrivateEgressLifecycleState::Prepared
                | PrivateEgressLifecycleState::Active
                | PrivateEgressLifecycleState::Ended
                | PrivateEgressLifecycleState::Failed
        ) | (
            PrivateEgressLifecycleState::Active,
            PrivateEgressLifecycleState::Active
                | PrivateEgressLifecycleState::Ended
                | PrivateEgressLifecycleState::Failed
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease() -> WorkerLease {
        serde_json::from_value(serde_json::json!({
            "worker_id": "00000000-0000-4000-8000-000000000151",
            "fence": 9
        }))
        .unwrap()
    }

    fn source() -> PrivateEgressSource {
        PrivateEgressSource {
            tenant_id: TenantId::parse("durable-tenant").unwrap(),
            call_id: "00000000-0000-4000-8000-000000000152".parse().unwrap(),
            leg_id: "00000000-0000-4000-8000-000000000153".parse().unwrap(),
            binding_generation: BindingGeneration::INITIAL,
        }
    }

    fn target() -> PrivateEgressTarget {
        PrivateEgressTarget {
            leg_id: "00000000-0000-4000-8000-000000000154".parse().unwrap(),
            binding_generation: BindingGeneration::INITIAL,
        }
    }

    fn epoch(instance_id: &str) -> PrivateEgressGatewayEpoch {
        PrivateEgressGatewayEpoch::new(
            "gateway-durable-test",
            Uuid::parse_str(instance_id).unwrap(),
        )
        .unwrap()
    }

    fn accepted(command_id: Uuid, state: PrivateEgressLifecycleState) -> PrivateEgressResponse {
        PrivateEgressResponse {
            version: 1,
            command_id,
            accepted: true,
            replayed: false,
            state: Some(state),
            failure_code: None,
            external_reference: None,
        }
    }

    #[tokio::test]
    async fn durable_epoch_journal_recovery_and_monotonic_ack_are_fail_closed() {
        let store = MemoryPrivateEgressStateStore::new(64, Duration::from_secs(60)).unwrap();
        assert!(!store.is_durable());
        let first = epoch("00000000-0000-4000-8000-000000000155");
        assert!(store.begin_epoch(&first, 1_000).await.unwrap().is_empty());

        let command_id = Uuid::parse_str("00000000-0000-4000-8000-000000000156").unwrap();
        let digest = [7; 32];
        assert_eq!(
            store
                .claim_command(&first, command_id, digest, 1_001)
                .await
                .unwrap(),
            PrivateEgressCommandClaim::Acquired
        );
        assert_eq!(
            store
                .claim_command(&first, command_id, digest, 1_002)
                .await
                .unwrap(),
            PrivateEgressCommandClaim::InFlight
        );
        assert_eq!(
            store
                .claim_command(&first, command_id, [8; 32], 1_002)
                .await,
            Err(PrivateEgressError::ReplayConflict)
        );
        let response = accepted(command_id, PrivateEgressLifecycleState::Prepared);
        store
            .complete_command(&first, command_id, digest, &response, 1_003)
            .await
            .unwrap();
        assert_eq!(
            store
                .claim_command(&first, command_id, digest, 1_004)
                .await
                .unwrap(),
            PrivateEgressCommandClaim::Completed(response)
        );

        let route = PrivateEgressRouteKey::new(lease(), &source(), target());
        let prepare_id = Uuid::new_v4();
        store
            .claim_route_transition(
                &first,
                &route,
                prepare_id,
                None,
                PrivateEgressLifecycleState::Prepared,
            )
            .await
            .unwrap();
        store
            .complete_route_transition(
                &first,
                &route,
                prepare_id,
                PrivateEgressLifecycleState::Prepared,
                1_005,
            )
            .await
            .unwrap();
        let activate_id = Uuid::new_v4();
        store
            .claim_route_transition(
                &first,
                &route,
                activate_id,
                Some(PrivateEgressLifecycleState::Prepared),
                PrivateEgressLifecycleState::Active,
            )
            .await
            .unwrap();
        let progress = PrivateEgressLifecycleEvent::progress(
            route.worker,
            route.authority().source,
            route.target,
            183,
            true,
        )
        .unwrap();
        let progress = store
            .append_lifecycle(&first, &route, &progress, 1_006)
            .await
            .unwrap();
        assert_eq!(progress.sequence, 1);
        assert_eq!(progress.progress_details(), Some((183, true)));
        store
            .complete_route_transition(
                &first,
                &route,
                activate_id,
                PrivateEgressLifecycleState::Active,
                1_007,
            )
            .await
            .unwrap();
        let ended = PrivateEgressLifecycleEvent::new(
            route.worker,
            route.authority().source,
            route.target,
            PrivateEgressLifecycleState::Ended,
            None,
        )
        .unwrap();
        let ended = store
            .append_lifecycle(&first, &route, &ended, 1_008)
            .await
            .unwrap();
        assert_eq!(ended.sequence, 2);

        assert_eq!(
            store
                .ack_lifecycle(&first, &route, progress.event_id, 2)
                .await,
            Err(PrivateEgressError::OwnershipMismatch)
        );
        let foreign_route = PrivateEgressRouteKey::new(
            route.worker,
            &route.authority().source,
            PrivateEgressTarget {
                binding_generation: route.target.binding_generation.next().unwrap(),
                ..route.target
            },
        );
        assert_eq!(
            store
                .ack_lifecycle(&first, &foreign_route, progress.event_id, 1)
                .await,
            Err(PrivateEgressError::OwnershipMismatch)
        );
        store
            .ack_lifecycle(&first, &route, progress.event_id, 1)
            .await
            .unwrap();
        store
            .ack_lifecycle(&first, &route, progress.event_id, 1)
            .await
            .expect("an exact duplicate acknowledgement is idempotent");
        assert_eq!(
            store
                .unacked_lifecycle(&first, &route)
                .await
                .unwrap()
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![2]
        );
        assert_eq!(
            store
                .claim_route_transition(
                    &first,
                    &route,
                    Uuid::new_v4(),
                    None,
                    PrivateEgressLifecycleState::Prepared,
                )
                .await,
            Err(PrivateEgressError::InvalidTransition),
            "a terminal generation remains tombstoned"
        );
    }

    #[tokio::test]
    async fn a_new_epoch_repeats_dead_route_recovery_until_cleanup_is_acknowledged() {
        let store = MemoryPrivateEgressStateStore::new(64, Duration::from_secs(60)).unwrap();
        let first = epoch("00000000-0000-4000-8000-000000000161");
        let second = epoch("00000000-0000-4000-8000-000000000162");
        store.begin_epoch(&first, 2_000).await.unwrap();
        let route = PrivateEgressRouteKey::new(lease(), &source(), target());
        let prepare_id = Uuid::new_v4();
        store
            .claim_route_transition(
                &first,
                &route,
                prepare_id,
                None,
                PrivateEgressLifecycleState::Prepared,
            )
            .await
            .unwrap();
        store
            .complete_route_transition(
                &first,
                &route,
                prepare_id,
                PrivateEgressLifecycleState::Prepared,
                2_001,
            )
            .await
            .unwrap();
        let incomplete_id = Uuid::new_v4();
        store
            .claim_command(&first, incomplete_id, [9; 32], 2_002)
            .await
            .unwrap();
        let completed_prepare_id = Uuid::new_v4();
        let completed_prepare_digest = [10; 32];
        store
            .claim_command(
                &first,
                completed_prepare_id,
                completed_prepare_digest,
                2_002,
            )
            .await
            .unwrap();
        store
            .complete_command(
                &first,
                completed_prepare_id,
                completed_prepare_digest,
                &PrivateEgressResponse {
                    version: 1,
                    command_id: completed_prepare_id,
                    accepted: true,
                    replayed: false,
                    state: Some(PrivateEgressLifecycleState::Prepared),
                    failure_code: None,
                    external_reference: None,
                },
                2_002,
            )
            .await
            .unwrap();

        let recovered = store.begin_epoch(&second, 2_003).await.unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].dead_epoch, first.instance_id);
        assert_eq!(recovered[0].key, route);
        assert_eq!(
            store.assert_epoch(&first).await,
            Err(PrivateEgressError::DeadEpoch)
        );
        assert!(matches!(
            store
                .claim_command(&second, incomplete_id, [9; 32], 2_004)
                .await
                .unwrap(),
            PrivateEgressCommandClaim::Completed(PrivateEgressResponse {
                accepted: false,
                failure_code: Some(code),
                ..
            }) if code == PrivateEgressError::DeadEpoch.code()
        ));
        assert!(
            matches!(
                store
                    .claim_command(
                        &second,
                        completed_prepare_id,
                        completed_prepare_digest,
                        2_004,
                    )
                    .await
                    .unwrap(),
                PrivateEgressCommandClaim::Completed(PrivateEgressResponse {
                    accepted: false,
                    failure_code: Some(code),
                    ..
                }) if code == PrivateEgressError::DeadEpoch.code()
            ),
            "a lost accepted Prepare response cannot be replayed after its route was recovered"
        );
        assert_eq!(
            store
                .claim_command(&second, completed_prepare_id, [11; 32], 2_004)
                .await,
            Err(PrivateEgressError::ReplayConflict),
            "epoch fencing must preserve the original command digest"
        );
        assert_eq!(
            store.begin_epoch(&second, 2_005).await.unwrap(),
            recovered,
            "a failed cleanup cannot disappear on service reconstruction"
        );
        store
            .complete_route_recovery(&second, &route)
            .await
            .unwrap();
        assert!(store.begin_epoch(&second, 2_006).await.unwrap().is_empty());
    }
}
