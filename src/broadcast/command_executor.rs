//! Worker-owned execution of durable broadcast commands.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use rvoip_core::broadcast::{BroadcastDrainReason, BroadcastLifecycleState};
use rvoip_moq::MoqPublisherConfig;
use serde_json::Value;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::call_engine::{CallState, LegState, RepositoryError};
use crate::call_engine::{TenantId, WorkerLease};
use crate::call_service::CallServiceRuntime;

use super::{
    BroadcastCommandRepository, BroadcastCommandResult, BroadcastGrantRegistry,
    ClaimedBroadcastCommand, DurableBroadcastCommandKind, DurableBroadcastRuntime,
    DurableBroadcastTransport, ManagedBroadcast, ManagedBroadcastService,
    ManagedBroadcastTransport, ManagedSanitizedEventBinding, MoqRelayTarget,
    RedisBroadcastGrantStore, SanitizedContextEventPolicy, MAX_DIRECT_UCTP_SUBSCRIBERS,
};

const CLAIM_TTL: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(250);
const TERMINAL_POLL_INTERVAL: Duration = Duration::from_secs(1);
const CLAIM_BATCH: usize = 16;

#[derive(Clone)]
struct WorkerBroadcastGrant {
    tenant_id: TenantId,
    worker: WorkerLease,
    grant_generation: uuid::Uuid,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct WorkerListenerBinding {
    broadcast_id: String,
    listener_id: uuid::Uuid,
}

/// Worker-local, exact-generation authority shared by the durable command
/// executor and the private UCTP subscription boundary. A gateway cannot
/// subscribe until the start result has committed durably, and revocation is
/// visible synchronously before another subscription command is accepted.
pub struct WorkerBroadcastSubscriptionAuthority {
    worker: WorkerLease,
    active: DashMap<String, WorkerBroadcastGrant>,
    listeners: DashMap<WorkerListenerBinding, uuid::Uuid>,
}

impl std::fmt::Debug for WorkerBroadcastSubscriptionAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WorkerBroadcastSubscriptionAuthority")
            .field("worker", &self.worker)
            .field("active", &self.active.len())
            .field("listeners", &self.listeners.len())
            .finish()
    }
}

impl WorkerBroadcastSubscriptionAuthority {
    pub fn new(worker: WorkerLease) -> Arc<Self> {
        Arc::new(Self {
            worker,
            active: DashMap::new(),
            listeners: DashMap::new(),
        })
    }

    pub fn authorize_and_bind(
        &self,
        tenant_id: &str,
        broadcast_id: &str,
        listener_id: uuid::Uuid,
        worker_fence: i64,
        grant_generation: uuid::Uuid,
    ) -> bool {
        if worker_fence != self.worker.fence.as_i64()
            || listener_id.is_nil()
            || grant_generation.is_nil()
        {
            return false;
        }
        let Some(grant) = self.active.get(broadcast_id) else {
            return false;
        };
        if grant.tenant_id.as_str() != tenant_id
            || grant.worker != self.worker
            || grant.grant_generation != grant_generation
        {
            return false;
        }
        let binding = WorkerListenerBinding {
            broadcast_id: broadcast_id.to_owned(),
            listener_id,
        };
        match self.listeners.entry(binding) {
            dashmap::mapref::entry::Entry::Occupied(entry) => *entry.get() == grant_generation,
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert(grant_generation);
                true
            }
        }
    }

    pub fn revalidate_listener(&self, broadcast_id: &str, listener_id: uuid::Uuid) -> bool {
        let binding = WorkerListenerBinding {
            broadcast_id: broadcast_id.to_owned(),
            listener_id,
        };
        let Some(generation) = self.listeners.get(&binding).map(|entry| *entry) else {
            return false;
        };
        self.active.get(broadcast_id).is_some_and(|grant| {
            grant.worker == self.worker && grant.grant_generation == generation
        })
    }

    pub fn active_for_tenant(&self, tenant_id: &str, broadcast_id: &str) -> bool {
        self.active.get(broadcast_id).is_some_and(|grant| {
            grant.tenant_id.as_str() == tenant_id && grant.worker == self.worker
        })
    }

    pub fn unbind_listener(&self, broadcast_id: &str, listener_id: uuid::Uuid) {
        self.listeners.remove(&WorkerListenerBinding {
            broadcast_id: broadcast_id.to_owned(),
            listener_id,
        });
    }

    fn activate(&self, record: &super::DurableBroadcastRecord) -> bool {
        let Some(runtime) = record.runtime.as_ref() else {
            return false;
        };
        let Some(grant_generation) = runtime.grant_generation else {
            return false;
        };
        if record.state != super::DurableBroadcastState::Active
            || record.specification.worker != self.worker
            || record.specification.transport != DurableBroadcastTransport::UctpQuic
        {
            return false;
        }
        self.active.insert(
            record.specification.broadcast_id.clone(),
            WorkerBroadcastGrant {
                tenant_id: record.specification.tenant_id.clone(),
                worker: record.specification.worker,
                grant_generation,
            },
        );
        true
    }

    fn revoke(&self, broadcast_id: &str) {
        self.active.remove(broadcast_id);
        self.listeners
            .retain(|binding, _| binding.broadcast_id != broadcast_id);
    }

    #[cfg(test)]
    pub(crate) fn activate_for_test(
        &self,
        tenant_id: TenantId,
        broadcast_id: String,
        grant_generation: uuid::Uuid,
    ) {
        self.active.insert(
            broadcast_id,
            WorkerBroadcastGrant {
                tenant_id,
                worker: self.worker,
                grant_generation,
            },
        );
    }

    #[cfg(test)]
    pub(crate) fn listener_count(&self) -> usize {
        self.listeners.len()
    }
}

struct ActiveDurableBroadcast {
    managed: Arc<ManagedBroadcast>,
    specification: super::DurableBroadcastSpec,
    grant_generation: Option<uuid::Uuid>,
}

/// Worker-local transport policy for durable commands.
pub struct BroadcastCommandExecutorConfig {
    pub public_uctp_endpoint: Url,
    pub moq_relay: Option<MoqRelayTarget>,
    pub sanitized_event_policies: BTreeMap<String, SanitizedContextEventPolicy>,
}

/// Bounded worker command owner. Dropping it cancels the task; callers should
/// use `shutdown` to close graph routes and reconcile durable state.
pub struct BroadcastCommandExecutor {
    repository: Arc<dyn BroadcastCommandRepository>,
    call_runtime: Arc<CallServiceRuntime>,
    managed: Arc<ManagedBroadcastService>,
    shared_grants: Option<Arc<RedisBroadcastGrantStore>>,
    config: Arc<BroadcastCommandExecutorConfig>,
    subscription_authority: Arc<WorkerBroadcastSubscriptionAuthority>,
    active: Arc<DashMap<String, Arc<ActiveDurableBroadcast>>>,
    cancel: CancellationToken,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for BroadcastCommandExecutor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BroadcastCommandExecutor")
            .field("worker", &self.call_runtime.worker().lease)
            .field("active", &self.active.len())
            .finish_non_exhaustive()
    }
}

impl BroadcastCommandExecutor {
    pub fn start(
        repository: Arc<dyn BroadcastCommandRepository>,
        call_runtime: Arc<CallServiceRuntime>,
        orchestrator: Arc<rvoip_core::Orchestrator>,
        shared_grants: Option<Arc<RedisBroadcastGrantStore>>,
        config: BroadcastCommandExecutorConfig,
    ) -> Result<Arc<Self>, super::ManagedBroadcastError> {
        let subscription_authority =
            WorkerBroadcastSubscriptionAuthority::new(call_runtime.worker().lease);
        Self::start_with_subscription_authority(
            repository,
            call_runtime,
            orchestrator,
            shared_grants,
            config,
            subscription_authority,
        )
    }

    pub fn start_with_subscription_authority(
        repository: Arc<dyn BroadcastCommandRepository>,
        call_runtime: Arc<CallServiceRuntime>,
        orchestrator: Arc<rvoip_core::Orchestrator>,
        shared_grants: Option<Arc<RedisBroadcastGrantStore>>,
        config: BroadcastCommandExecutorConfig,
        subscription_authority: Arc<WorkerBroadcastSubscriptionAuthority>,
    ) -> Result<Arc<Self>, super::ManagedBroadcastError> {
        if subscription_authority.worker != call_runtime.worker().lease {
            return Err(super::ManagedBroadcastError::InvalidConfiguration(
                "worker broadcast subscription authority fence mismatch",
            ));
        }
        let grants = BroadcastGrantRegistry::new();
        let managed = Arc::new(match &shared_grants {
            Some(shared) => ManagedBroadcastService::with_shared_grants(
                orchestrator,
                grants,
                Arc::clone(shared),
                MAX_DIRECT_UCTP_SUBSCRIBERS,
            )?,
            None => {
                ManagedBroadcastService::new(orchestrator, grants, MAX_DIRECT_UCTP_SUBSCRIBERS)?
            }
        });
        let executor = Arc::new(Self {
            repository,
            call_runtime,
            managed,
            shared_grants,
            config: Arc::new(config),
            subscription_authority,
            active: Arc::new(DashMap::new()),
            cancel: CancellationToken::new(),
            task: Mutex::new(None),
        });
        let task_owner = Arc::clone(&executor);
        let task = tokio::spawn(async move { task_owner.run().await });
        let mut slot = executor.task.try_lock().expect("executor task slot is new");
        *slot = Some(task);
        drop(slot);
        Ok(executor)
    }

    async fn run(self: Arc<Self>) {
        let mut wakeups = self.call_runtime.subscribe_work_wakeups();
        let mut fallback = tokio::time::interval(POLL_INTERVAL);
        fallback.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut terminals = tokio::time::interval(TERMINAL_POLL_INTERVAL);
        terminals.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut stale_fences_reconciled = false;
        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => break,
                changed = wakeups.changed() => {
                    if changed.is_err() { break; }
                    if !stale_fences_reconciled {
                        stale_fences_reconciled = self.reconcile_stale_fences().await;
                    }
                    if stale_fences_reconciled { self.claim_and_execute().await; }
                }
                _ = fallback.tick() => {
                    if !stale_fences_reconciled {
                        stale_fences_reconciled = self.reconcile_stale_fences().await;
                    }
                    if stale_fences_reconciled { self.claim_and_execute().await; }
                },
                _ = terminals.tick() => {
                    if stale_fences_reconciled { self.reconcile_active().await; }
                },
            }
        }
    }

    async fn reconcile_stale_fences(&self) -> bool {
        let records = match self
            .repository
            .fail_stale_worker_broadcasts(self.call_runtime.worker().lease)
            .await
        {
            Ok(records) => records,
            Err(error) => {
                tracing::warn!(%error, "stale broadcast fence reconciliation failed");
                return false;
            }
        };
        for record in records {
            let id = &record.specification.broadcast_id;
            let expected_generation = record
                .runtime
                .as_ref()
                .and_then(|runtime| runtime.grant_generation);
            match &self.shared_grants {
                Some(shared) => match shared.active_grant(id).await {
                    Ok(Some(grant))
                        if grant.tenant_id == record.specification.tenant_id.as_str()
                            && grant.broadcast_id == *id
                            && Some(grant.generation) == expected_generation =>
                    {
                        match shared.revoke_generation(id, grant.generation).await {
                            Ok(_) => {}
                            Err(error) => {
                                tracing::warn!(%error, "stale broadcast grant revocation failed");
                                return false;
                            }
                        }
                    }
                    Ok(None) => {}
                    Ok(Some(_)) => {
                        tracing::warn!(
                            broadcast_id = %id,
                            "stale broadcast grant generation does not match durable ownership"
                        );
                        return false;
                    }
                    Err(error) => {
                        tracing::warn!(%error, "stale broadcast grant lookup failed");
                        return false;
                    }
                },
                None if expected_generation.is_some() => {
                    tracing::warn!(broadcast_id = %id, "stale shared grant has no cleanup authority");
                    return false;
                }
                None => {}
            }
            if let Err(error) = self
                .repository
                .finalize_failed_cleanup(id, record.specification.worker, expected_generation)
                .await
            {
                tracing::warn!(%error, broadcast_id = %id, "stale broadcast cleanup finalization failed");
                return false;
            }
            let cleaned = match self
                .repository
                .get(&record.specification.tenant_id, id)
                .await
            {
                Ok(Some(cleaned)) => cleaned.runtime.is_none(),
                Ok(None) => true,
                Err(error) => {
                    tracing::warn!(%error, broadcast_id = %id, "stale broadcast cleanup verification failed");
                    return false;
                }
            };
            if !cleaned {
                tracing::warn!(broadcast_id = %id, "stale broadcast cleanup CAS did not match");
                return false;
            }
        }
        true
    }

    async fn claim_and_execute(&self) {
        let claims = match self
            .repository
            .claim(self.call_runtime.worker().lease, CLAIM_TTL, CLAIM_BATCH)
            .await
        {
            Ok(claims) => claims,
            Err(error) => {
                tracing::warn!(%error, "claiming durable broadcast commands failed");
                return;
            }
        };
        for claim in claims {
            self.execute(claim).await;
        }
    }

    async fn execute(&self, claim: ClaimedBroadcastCommand) {
        let result = match claim.kind {
            DurableBroadcastCommandKind::Start => self.start_broadcast(&claim).await,
            DurableBroadcastCommandKind::Stop => self.stop_broadcast(&claim).await,
        };
        let expected_result = result.clone();
        match self.complete_durably(&claim, result).await {
            Some(record) if !completion_is_visible(&claim, &expected_result, &record) => {
                tracing::warn!(
                    command_id = %claim.command_id,
                    broadcast_id = %claim.record.specification.broadcast_id,
                    "durable broadcast command resolved to a different authoritative result"
                );
                // A reclaimed command can complete on another worker while
                // this worker is still reconciling an ambiguous response.
                // Never activate or revoke that newer generation from this
                // stale execution. Only tear down the publication created by
                // this worker's uncommitted start attempt.
                if claim.kind == DurableBroadcastCommandKind::Start {
                    self.cleanup_uncommitted_start(&claim.record.specification.broadcast_id)
                        .await;
                }
            }
            Some(record) => match claim.kind {
                DurableBroadcastCommandKind::Start => {
                    let committed_uctp = record.state == super::DurableBroadcastState::Active
                        && record.specification.transport == DurableBroadcastTransport::UctpQuic;
                    if committed_uctp && !self.subscription_authority.activate(&record) {
                        tracing::error!(
                            command_id = %claim.command_id,
                            "durable UCTP broadcast committed without an exact worker grant"
                        );
                        if let Some((_, active)) =
                            self.active.remove(&record.specification.broadcast_id)
                        {
                            let _ = active
                                .managed
                                .close(BroadcastDrainReason::Reconfigure)
                                .await;
                            let _ = self
                                .revoke_shared_generation(
                                    &active.specification,
                                    active.grant_generation,
                                )
                                .await;
                        }
                    } else if record.state != super::DurableBroadcastState::Active {
                        self.cleanup_uncommitted_start(&record.specification.broadcast_id)
                            .await;
                    }
                }
                DurableBroadcastCommandKind::Stop => self
                    .subscription_authority
                    .revoke(&record.specification.broadcast_id),
            },
            None => {
                tracing::error!(
                    command_id = %claim.command_id,
                    "durable broadcast command reconciliation cancelled"
                );
                if claim.kind == DurableBroadcastCommandKind::Start {
                    self.cleanup_uncommitted_start(&claim.record.specification.broadcast_id)
                        .await;
                }
            }
        }
    }

    async fn complete_durably(
        &self,
        claim: &ClaimedBroadcastCommand,
        result: BroadcastCommandResult,
    ) -> Option<super::DurableBroadcastRecord> {
        complete_broadcast_command(self.repository.as_ref(), &self.cancel, claim, result).await
    }

    async fn cleanup_uncommitted_start(&self, broadcast_id: &str) {
        self.subscription_authority.revoke(broadcast_id);
        if let Some((_, active)) = self.active.remove(broadcast_id) {
            let _ = active
                .managed
                .close(BroadcastDrainReason::Reconfigure)
                .await;
            // Keep retrying while this worker is live. On cancellation the
            // durable old-fence recovery path owns any still-active exact
            // generation after restart.
            while !self
                .revoke_shared_generation(&active.specification, active.grant_generation)
                .await
            {
                tokio::select! {
                    _ = self.cancel.cancelled() => return,
                    _ = tokio::time::sleep(POLL_INTERVAL) => {}
                }
            }
        }
    }

    async fn start_broadcast(&self, claim: &ClaimedBroadcastCommand) -> BroadcastCommandResult {
        let specification = &claim.record.specification;
        if specification.worker != self.call_runtime.worker().lease {
            return BroadcastCommandResult::Failed("stale_worker_fence");
        }
        if specification.expires_at <= chrono::Utc::now() {
            return BroadcastCommandResult::Failed("broadcast_expired");
        }
        let stored = match self
            .call_runtime
            .repository()
            .load_call(&specification.tenant_id, specification.call_id)
            .await
        {
            Ok(stored) => stored,
            Err(_) => return BroadcastCommandResult::Failed("source_unavailable"),
        };
        if stored.assignment.released_at.is_some()
            || stored.assignment.lease != specification.worker
        {
            return BroadcastCommandResult::Failed("source_worker_changed");
        }
        let Some(leg) = stored.aggregate.leg(specification.source_leg_id) else {
            return BroadcastCommandResult::Failed("source_leg_missing");
        };
        if leg.state() != LegState::Connected
            || leg.binding_generation() != specification.source_binding_generation
        {
            return BroadcastCommandResult::Failed("source_not_connected");
        }
        let Some(binding) = stored.bindings.get(&specification.source_leg_id) else {
            return BroadcastCommandResult::Failed("source_binding_missing");
        };
        if binding.binding_generation != specification.source_binding_generation {
            return BroadcastCommandResult::Failed("source_binding_rotated");
        }
        let source_connection_id = binding.connection_id.clone();

        let transport = match specification.transport {
            DurableBroadcastTransport::Moqt => {
                let sanitized_events = if specification.sanitized_events {
                    let Some(policy) = self
                        .config
                        .sanitized_event_policies
                        .get(specification.tenant_id.as_str())
                        .cloned()
                    else {
                        return BroadcastCommandResult::Failed("sanitized_events_not_allowed");
                    };
                    match ManagedSanitizedEventBinding::new(
                        specification.call_id.to_string(),
                        specification.source_leg_id.to_string(),
                        policy,
                    ) {
                        Ok(binding) => Some(binding),
                        Err(_) => {
                            return BroadcastCommandResult::Failed("sanitized_events_invalid")
                        }
                    }
                } else {
                    None
                };
                ManagedBroadcastTransport::Moqt {
                    publisher: MoqPublisherConfig {
                        tenant_id: specification.tenant_id.as_str().to_owned(),
                        broadcast_id: specification.broadcast_id.clone(),
                        bitrate: 24_000,
                        language: specification.language.clone(),
                        queue_frames: 10,
                    },
                    relay: self.config.moq_relay.clone().map(Box::new),
                    sanitized_events,
                }
            }
            DurableBroadcastTransport::UctpQuic => ManagedBroadcastTransport::UctpQuic {
                endpoint: self.config.public_uctp_endpoint.clone(),
            },
        };
        let managed = match self
            .managed
            .start(
                specification.tenant_id.as_str(),
                specification.broadcast_id.clone(),
                source_connection_id.clone(),
                specification.expires_at,
                transport,
            )
            .await
        {
            Ok(managed) => managed,
            Err(_) => return BroadcastCommandResult::Failed("broadcast_runtime_unavailable"),
        };

        // Close the route if the authoritative source rotated while graph
        // installation was awaiting transport setup.
        let current = self
            .call_runtime
            .repository()
            .load_call(&specification.tenant_id, specification.call_id)
            .await;
        let still_current = current.is_ok_and(|stored| {
            stored.assignment.released_at.is_none()
                && stored.assignment.lease == specification.worker
                && stored
                    .bindings
                    .get(&specification.source_leg_id)
                    .is_some_and(|binding| {
                        binding.binding_generation == specification.source_binding_generation
                            && binding.connection_id == source_connection_id
                    })
        });
        if !still_current {
            let _ = managed.close(BroadcastDrainReason::Reconfigure).await;
            return BroadcastCommandResult::Failed("source_binding_rotated");
        }
        let grant_generation = match &self.shared_grants {
            Some(shared) => match shared.active_grant(&specification.broadcast_id).await {
                Ok(Some(grant))
                    if grant.tenant_id == specification.tenant_id.as_str()
                        && grant.broadcast_id == specification.broadcast_id =>
                {
                    Some(grant.generation)
                }
                _ => {
                    let _ = managed.close(BroadcastDrainReason::Reconfigure).await;
                    return BroadcastCommandResult::Failed("broadcast_authority_unavailable");
                }
            },
            None => None,
        };
        let runtime = DurableBroadcastRuntime {
            endpoint: serde_json::to_value(managed.endpoint()).unwrap_or(Value::Null),
            protocol: serde_json::to_value(managed.protocol()).unwrap_or(Value::Null),
            lifecycle: serde_json::to_value(managed.lifecycle()).unwrap_or(Value::Null),
            health: serde_json::to_value(managed.health()).unwrap_or(Value::Null),
            sanitized_events: managed.diagnostics().sanitized_events.enabled,
            grant_generation,
        };
        let active = Arc::new(ActiveDurableBroadcast {
            managed,
            specification: specification.clone(),
            grant_generation,
        });
        if let Some(previous) = self
            .active
            .insert(specification.broadcast_id.clone(), active)
        {
            let _ = previous
                .managed
                .close(BroadcastDrainReason::Reconfigure)
                .await;
            let _ = self
                .revoke_shared_generation(&previous.specification, previous.grant_generation)
                .await;
        }
        BroadcastCommandResult::Started(Box::new(runtime))
    }

    async fn stop_broadcast(&self, claim: &ClaimedBroadcastCommand) -> BroadcastCommandResult {
        let specification = &claim.record.specification;
        if specification.worker != self.call_runtime.worker().lease {
            return BroadcastCommandResult::Failed("stale_worker_fence");
        }
        self.subscription_authority
            .revoke(&specification.broadcast_id);
        if let Some((_, active)) = self.active.remove(&specification.broadcast_id) {
            if active
                .managed
                .close(BroadcastDrainReason::OperatorRequest)
                .await
                .is_err()
            {
                return BroadcastCommandResult::Failed("broadcast_runtime_unavailable");
            }
            if !self
                .revoke_shared_generation(specification, active.grant_generation)
                .await
            {
                return BroadcastCommandResult::Failed("broadcast_authority_unavailable");
            }
        } else if !self
            .revoke_shared_generation(
                specification,
                claim
                    .record
                    .runtime
                    .as_ref()
                    .and_then(|runtime| runtime.grant_generation),
            )
            .await
        {
            return BroadcastCommandResult::Failed("broadcast_authority_unavailable");
        }
        BroadcastCommandResult::Stopped
    }

    async fn reconcile_active(&self) {
        let active = self
            .active
            .iter()
            .map(|entry| Arc::clone(entry.value()))
            .collect::<Vec<_>>();
        for entry in active {
            let id = &entry.specification.broadcast_id;
            if !self
                .active
                .get(id)
                .is_some_and(|current| Arc::ptr_eq(current.value(), &entry))
            {
                continue;
            }
            let Some(failure_code) = self.terminal_reason(&entry).await else {
                continue;
            };
            self.subscription_authority.revoke(id);
            if let Err(error) = entry.managed.close(BroadcastDrainReason::Reconfigure).await {
                tracing::warn!(%error, broadcast_id = %id, "terminal broadcast close failed");
            }
            if !self
                .revoke_shared_generation(&entry.specification, entry.grant_generation)
                .await
            {
                continue;
            }
            match self
                .repository
                .reconcile_terminal(
                    id,
                    entry.specification.worker,
                    entry.specification.source_binding_generation,
                    entry.grant_generation,
                    failure_code,
                )
                .await
            {
                Ok(_) => {
                    self.active
                        .remove_if(id, |_, current| Arc::ptr_eq(current, &entry));
                }
                Err(error) => {
                    tracing::warn!(%error, broadcast_id = %id, "terminal broadcast reconciliation failed");
                }
            }
        }
    }

    async fn terminal_reason(&self, active: &ActiveDurableBroadcast) -> Option<&'static str> {
        let specification = &active.specification;
        if specification.expires_at <= chrono::Utc::now() {
            return Some("broadcast_expired");
        }
        if matches!(
            active.managed.lifecycle().state,
            BroadcastLifecycleState::Closed | BroadcastLifecycleState::Failed
        ) {
            return Some("broadcast_runtime_terminal");
        }
        let stored = match self
            .call_runtime
            .repository()
            .load_call(&specification.tenant_id, specification.call_id)
            .await
        {
            Ok(stored) => stored,
            Err(error) => return source_load_failure(&error),
        };
        if stored.assignment.released_at.is_some()
            || stored.assignment.lease != specification.worker
        {
            return Some("source_worker_changed");
        }
        if matches!(
            stored.aggregate.state(),
            CallState::Ending | CallState::Ended | CallState::Failed
        ) {
            return Some("source_terminal");
        }
        let Some(leg) = stored.aggregate.leg(specification.source_leg_id) else {
            return Some("source_terminal");
        };
        if leg.state() != LegState::Connected {
            return Some("source_terminal");
        }
        let Some(binding) = stored.bindings.get(&specification.source_leg_id) else {
            return Some("source_binding_rotated");
        };
        if binding.binding_generation != specification.source_binding_generation
            || &binding.connection_id != active.managed.source_connection_id()
        {
            return Some("source_binding_rotated");
        }
        None
    }

    async fn revoke_shared_generation(
        &self,
        specification: &super::DurableBroadcastSpec,
        generation: Option<uuid::Uuid>,
    ) -> bool {
        let Some(shared) = &self.shared_grants else {
            return true;
        };
        let Some(generation) = generation else {
            return match shared.active_grant(&specification.broadcast_id).await {
                Ok(None) => true,
                Ok(Some(_)) | Err(_) => false,
            };
        };
        match shared
            .revoke_generation(&specification.broadcast_id, generation)
            .await
        {
            Ok(_) => true,
            Err(error) => {
                tracing::warn!(%error, broadcast_id = %specification.broadcast_id, "broadcast grant revocation failed");
                false
            }
        }
    }

    pub async fn shutdown(&self, timeout: Duration) {
        self.cancel.cancel();
        if let Some(mut task) = self.task.lock().await.take() {
            if tokio::time::timeout(timeout, &mut task).await.is_err() {
                task.abort();
                let _ = task.await;
            }
        }
        let broadcasts: Vec<_> = self
            .active
            .iter()
            .map(|entry| entry.key().clone())
            .collect();
        let mut revoked = Vec::new();
        for broadcast_id in broadcasts {
            self.subscription_authority.revoke(&broadcast_id);
            if let Some((_, active)) = self.active.remove(&broadcast_id) {
                let _ = active.managed.close(BroadcastDrainReason::Shutdown).await;
                if self
                    .revoke_shared_generation(&active.specification, active.grant_generation)
                    .await
                {
                    revoked.push((active.specification.clone(), active.grant_generation));
                }
            }
        }
        match self
            .repository
            .fail_worker_broadcasts(self.call_runtime.worker().lease, "worker_drained")
            .await
        {
            Ok(()) => {
                for (specification, generation) in revoked {
                    if let Err(error) = self
                        .repository
                        .finalize_failed_cleanup(
                            &specification.broadcast_id,
                            specification.worker,
                            generation,
                        )
                        .await
                    {
                        tracing::warn!(%error, broadcast_id = %specification.broadcast_id, "finalizing drained broadcast cleanup failed");
                    }
                }
            }
            Err(error) => {
                tracing::warn!(%error, "marking drained worker broadcasts failed");
            }
        }
    }
}

async fn complete_broadcast_command(
    repository: &dyn BroadcastCommandRepository,
    cancel: &CancellationToken,
    claim: &ClaimedBroadcastCommand,
    result: BroadcastCommandResult,
) -> Option<super::DurableBroadcastRecord> {
    let specification = &claim.record.specification;
    loop {
        match repository.complete(claim, result.clone()).await {
            Ok(record) => return Some(record),
            Err(error) => {
                tracing::warn!(
                    %error,
                    command_id = %claim.command_id,
                    "broadcast completion ambiguous; verifying durable result"
                );
            }
        }
        match repository
            .get(&specification.tenant_id, &specification.broadcast_id)
            .await
        {
            Ok(Some(record)) if completion_is_visible(claim, &result, &record) => {
                return Some(record);
            }
            Ok(Some(record))
                if !matches!(
                    record.state,
                    super::DurableBroadcastState::Pending | super::DurableBroadcastState::Deleting
                ) =>
            {
                return Some(record);
            }
            Ok(None) => return None,
            Ok(Some(_)) | Err(_) => {}
        }
        tokio::select! {
            _ = cancel.cancelled() => return None,
            _ = tokio::time::sleep(POLL_INTERVAL) => {}
        }
    }
}

fn source_load_failure(error: &RepositoryError) -> Option<&'static str> {
    match error {
        RepositoryError::NotFound => Some("source_terminal"),
        _ => None,
    }
}

fn completion_is_visible(
    claim: &ClaimedBroadcastCommand,
    result: &BroadcastCommandResult,
    record: &super::DurableBroadcastRecord,
) -> bool {
    if record.specification != claim.record.specification {
        return false;
    }
    match result {
        BroadcastCommandResult::Started(expected) => {
            record.state == super::DurableBroadcastState::Active
                && record.runtime.as_ref().is_some_and(|runtime| {
                    runtime.grant_generation == expected.grant_generation
                        && runtime.endpoint == expected.endpoint
                        && runtime.protocol == expected.protocol
                })
        }
        BroadcastCommandResult::Stopped => {
            record.state == super::DurableBroadcastState::Deleted && record.runtime.is_none()
        }
        BroadcastCommandResult::Failed(code) => {
            record.state == super::DurableBroadcastState::Failed
                && record.failure_code.as_deref() == Some(*code)
        }
    }
}

impl Drop for BroadcastCommandExecutor {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Ok(mut task) = self.task.try_lock() {
            if let Some(task) = task.take() {
                task.abort();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CommitThenUnavailableRepository {
        record: tokio::sync::Mutex<crate::broadcast::DurableBroadcastRecord>,
        complete_calls: std::sync::atomic::AtomicUsize,
        get_calls: std::sync::atomic::AtomicUsize,
        commit_result: bool,
    }

    #[async_trait::async_trait]
    impl BroadcastCommandRepository for CommitThenUnavailableRepository {
        async fn enqueue_start(
            &self,
            _specification: crate::broadcast::DurableBroadcastSpec,
            _identity: crate::broadcast::BroadcastOperationIdentity,
            _max_active: usize,
        ) -> Result<
            crate::broadcast::BroadcastEnqueueOutcome,
            crate::broadcast::BroadcastCommandError,
        > {
            Err(crate::broadcast::BroadcastCommandError::Unavailable)
        }

        async fn enqueue_stop(
            &self,
            _tenant_id: &TenantId,
            _broadcast_id: &str,
            _identity: crate::broadcast::BroadcastOperationIdentity,
        ) -> Result<
            crate::broadcast::BroadcastEnqueueOutcome,
            crate::broadcast::BroadcastCommandError,
        > {
            Err(crate::broadcast::BroadcastCommandError::Unavailable)
        }

        async fn get(
            &self,
            tenant_id: &TenantId,
            broadcast_id: &str,
        ) -> Result<
            Option<crate::broadcast::DurableBroadcastRecord>,
            crate::broadcast::BroadcastCommandError,
        > {
            self.get_calls
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            let record = self.record.lock().await;
            Ok((record.specification.tenant_id == *tenant_id
                && record.specification.broadcast_id == broadcast_id)
                .then(|| record.clone()))
        }

        async fn claim(
            &self,
            _worker: WorkerLease,
            _claim_ttl: Duration,
            _limit: usize,
        ) -> Result<Vec<ClaimedBroadcastCommand>, crate::broadcast::BroadcastCommandError> {
            Err(crate::broadcast::BroadcastCommandError::Unavailable)
        }

        async fn complete(
            &self,
            claim: &ClaimedBroadcastCommand,
            result: BroadcastCommandResult,
        ) -> Result<crate::broadcast::DurableBroadcastRecord, crate::broadcast::BroadcastCommandError>
        {
            self.complete_calls
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            let mut record = self.record.lock().await;
            assert_eq!(record.specification, claim.record.specification);
            if self.commit_result {
                match result {
                    BroadcastCommandResult::Started(runtime) => {
                        record.state = crate::broadcast::DurableBroadcastState::Active;
                        record.runtime = Some(*runtime);
                        record.failure_code = None;
                    }
                    BroadcastCommandResult::Stopped => {
                        record.state = crate::broadcast::DurableBroadcastState::Deleted;
                        record.runtime = None;
                        record.failure_code = None;
                    }
                    BroadcastCommandResult::Failed(code) => {
                        record.state = crate::broadcast::DurableBroadcastState::Failed;
                        record.failure_code = Some(code.to_owned());
                    }
                }
            }
            // Simulate an error after COMMIT. The caller must inspect the
            // authoritative row rather than treating this as an uncommitted
            // start and tearing down the live publication.
            Err(crate::broadcast::BroadcastCommandError::Unavailable)
        }

        async fn fail_stale_worker_broadcasts(
            &self,
            _current: WorkerLease,
        ) -> Result<
            Vec<crate::broadcast::DurableBroadcastRecord>,
            crate::broadcast::BroadcastCommandError,
        > {
            Err(crate::broadcast::BroadcastCommandError::Unavailable)
        }

        async fn reconcile_terminal(
            &self,
            _broadcast_id: &str,
            _worker: WorkerLease,
            _source_binding_generation: crate::call_engine::BindingGeneration,
            _grant_generation: Option<uuid::Uuid>,
            _failure_code: &'static str,
        ) -> Result<bool, crate::broadcast::BroadcastCommandError> {
            Err(crate::broadcast::BroadcastCommandError::Unavailable)
        }

        async fn finalize_failed_cleanup(
            &self,
            _broadcast_id: &str,
            _worker: WorkerLease,
            _grant_generation: Option<uuid::Uuid>,
        ) -> Result<bool, crate::broadcast::BroadcastCommandError> {
            Err(crate::broadcast::BroadcastCommandError::Unavailable)
        }

        async fn fail_worker_broadcasts(
            &self,
            _worker: WorkerLease,
            _failure_code: &'static str,
        ) -> Result<(), crate::broadcast::BroadcastCommandError> {
            Err(crate::broadcast::BroadcastCommandError::Unavailable)
        }
    }

    #[tokio::test]
    async fn committed_but_ambiguous_start_completion_is_reconciled_as_active() {
        let worker = WorkerLease {
            worker_id: crate::call_engine::WorkerId::new(),
            fence: crate::call_engine::WorkerFence::INITIAL,
        };
        let now = chrono::Utc::now();
        let specification = crate::broadcast::DurableBroadcastSpec {
            broadcast_id: uuid::Uuid::new_v4().to_string(),
            tenant_id: TenantId::parse("tenant-ambiguous-completion").unwrap(),
            call_id: Default::default(),
            source_leg_id: Default::default(),
            source_binding_generation: crate::call_engine::BindingGeneration::INITIAL,
            worker,
            transport: DurableBroadcastTransport::UctpQuic,
            language: None,
            sanitized_events: false,
            expires_at: now + chrono::TimeDelta::minutes(5),
        };
        let pending = crate::broadcast::DurableBroadcastRecord {
            specification,
            state: crate::broadcast::DurableBroadcastState::Pending,
            runtime: None,
            failure_code: None,
            created_at: now,
            updated_at: now,
        };
        let claim = ClaimedBroadcastCommand {
            command_id: uuid::Uuid::new_v4(),
            kind: DurableBroadcastCommandKind::Start,
            claim_generation: 1,
            record: pending.clone(),
        };
        let runtime = DurableBroadcastRuntime {
            endpoint: serde_json::json!({"uri": "uctp+quic://broadcast.example.test:4444"}),
            protocol: serde_json::json!({"uctp": "0.2"}),
            lifecycle: serde_json::json!({"state": "active"}),
            health: serde_json::json!({"status": "healthy"}),
            sanitized_events: false,
            grant_generation: Some(uuid::Uuid::new_v4()),
        };
        let repository = CommitThenUnavailableRepository {
            record: tokio::sync::Mutex::new(pending),
            complete_calls: std::sync::atomic::AtomicUsize::new(0),
            get_calls: std::sync::atomic::AtomicUsize::new(0),
            commit_result: true,
        };

        let reconciled = complete_broadcast_command(
            &repository,
            &CancellationToken::new(),
            &claim,
            BroadcastCommandResult::Started(Box::new(runtime.clone())),
        )
        .await
        .expect("committed result remains visible after ambiguous completion");

        assert_eq!(
            reconciled.state,
            crate::broadcast::DurableBroadcastState::Active
        );
        assert_eq!(reconciled.runtime, Some(runtime));
        assert_eq!(
            repository
                .complete_calls
                .load(std::sync::atomic::Ordering::Acquire),
            1
        );
        assert_eq!(
            repository
                .get_calls
                .load(std::sync::atomic::Ordering::Acquire),
            1
        );
    }

    #[tokio::test]
    async fn stale_start_never_adopts_a_different_authoritative_generation() {
        let worker = WorkerLease {
            worker_id: crate::call_engine::WorkerId::new(),
            fence: crate::call_engine::WorkerFence::INITIAL,
        };
        let now = chrono::Utc::now();
        let specification = crate::broadcast::DurableBroadcastSpec {
            broadcast_id: uuid::Uuid::new_v4().to_string(),
            tenant_id: TenantId::parse("tenant-stale-completion").unwrap(),
            call_id: Default::default(),
            source_leg_id: Default::default(),
            source_binding_generation: crate::call_engine::BindingGeneration::INITIAL,
            worker,
            transport: DurableBroadcastTransport::UctpQuic,
            language: None,
            sanitized_events: false,
            expires_at: now + chrono::TimeDelta::minutes(5),
        };
        let pending = crate::broadcast::DurableBroadcastRecord {
            specification,
            state: crate::broadcast::DurableBroadcastState::Pending,
            runtime: None,
            failure_code: None,
            created_at: now,
            updated_at: now,
        };
        let claim = ClaimedBroadcastCommand {
            command_id: uuid::Uuid::new_v4(),
            kind: DurableBroadcastCommandKind::Start,
            claim_generation: 1,
            record: pending.clone(),
        };
        let expected = DurableBroadcastRuntime {
            endpoint: serde_json::json!({"uri": "uctp+quic://expected.example.test:4444"}),
            protocol: serde_json::json!({"uctp": "0.2"}),
            lifecycle: serde_json::json!({"state": "active"}),
            health: serde_json::json!({"status": "healthy"}),
            sanitized_events: false,
            grant_generation: Some(uuid::Uuid::new_v4()),
        };
        let successor = DurableBroadcastRuntime {
            endpoint: serde_json::json!({"uri": "uctp+quic://successor.example.test:4444"}),
            grant_generation: Some(uuid::Uuid::new_v4()),
            ..expected.clone()
        };
        let mut authoritative = pending;
        authoritative.state = crate::broadcast::DurableBroadcastState::Active;
        authoritative.runtime = Some(successor.clone());
        let repository = CommitThenUnavailableRepository {
            record: tokio::sync::Mutex::new(authoritative),
            complete_calls: std::sync::atomic::AtomicUsize::new(0),
            get_calls: std::sync::atomic::AtomicUsize::new(0),
            commit_result: false,
        };
        let cancel = CancellationToken::new();

        let reconciled = complete_broadcast_command(
            &repository,
            &cancel,
            &claim,
            BroadcastCommandResult::Started(Box::new(expected.clone())),
        )
        .await
        .expect("a different terminal generation is authoritative");

        assert_eq!(reconciled.runtime, Some(successor));
        assert!(!completion_is_visible(
            &claim,
            &BroadcastCommandResult::Started(Box::new(expected)),
            &reconciled,
        ));
        assert_eq!(
            repository
                .complete_calls
                .load(std::sync::atomic::Ordering::Acquire),
            1
        );
        assert_eq!(
            repository
                .get_calls
                .load(std::sync::atomic::Ordering::Acquire),
            1
        );
    }

    #[test]
    fn deleted_source_is_terminal_but_transient_store_loss_retries() {
        assert_eq!(
            source_load_failure(&RepositoryError::NotFound),
            Some("source_terminal")
        );
        assert_eq!(source_load_failure(&RepositoryError::Unavailable), None);
    }
}
