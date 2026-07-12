use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use uuid::Uuid;

use crate::call_engine::{CallId, WorkerFence, WorkerId, WorkerLease};

use super::*;

fn instant() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-07-12T12:00:00Z")
        .expect("test time")
        .with_timezone(&Utc)
}

fn worker_id(value: u128) -> WorkerId {
    WorkerId::from_uuid(Uuid::from_u128(value)).expect("non-nil worker ID")
}

fn call_id(value: u128) -> CallId {
    CallId::from_uuid(Uuid::from_u128(value)).expect("non-nil call ID")
}

fn fence(value: u64) -> WorkerFence {
    serde_json::from_value(serde_json::json!(value)).expect("valid worker fence")
}

fn sequence(value: i64) -> ProjectionSequence {
    ProjectionSequence::from_i64(value).expect("positive sequence")
}

fn worker_snapshot(
    id: WorkerId,
    fence_value: u64,
    expires_at: DateTime<Utc>,
) -> WorkerCoordinationSnapshot {
    WorkerCoordinationSnapshot {
        lease: WorkerLease {
            worker_id: id,
            fence: fence(fence_value),
        },
        max_calls: 10,
        reserved_calls: 2,
        draining: false,
        capabilities: BTreeSet::from(["sip".to_owned(), "webrtc".to_owned()]),
        lease_expires_at: expires_at,
    }
}

fn event(
    deployment: &DeploymentId,
    sequence_value: i64,
    payload: CoordinationPayload,
) -> CoordinationEvent {
    CoordinationEvent {
        deployment: deployment.clone(),
        sequence: sequence(sequence_value),
        payload,
        recorded_at: instant(),
    }
}

#[tokio::test]
async fn memory_worker_projection_enforces_sequence_fence_expiry_and_one_way_drain() {
    let deployment = DeploymentId::parse("test-a").expect("deployment");
    let clock = Arc::new(ManualCoordinationClock::new(instant()));
    let coordinator =
        MemoryCoordinator::new(deployment.clone(), clock.clone(), 8).expect("memory coordinator");
    let id = worker_id(1);
    let worker = worker_snapshot(id, 1, instant() + TimeDelta::seconds(30));

    assert_eq!(
        coordinator
            .apply(&event(
                &deployment,
                1,
                CoordinationPayload::Worker(worker.clone()),
            ))
            .await,
        Ok(ProjectionApplyOutcome::Applied)
    );
    assert_eq!(
        coordinator
            .apply(&event(
                &deployment,
                1,
                CoordinationPayload::Worker(worker.clone()),
            ))
            .await,
        Ok(ProjectionApplyOutcome::Duplicate)
    );
    let mut conflicting = worker.clone();
    conflicting.reserved_calls = 3;
    assert_eq!(
        coordinator
            .apply(&event(
                &deployment,
                1,
                CoordinationPayload::Worker(conflicting),
            ))
            .await,
        Err(CoordinationError::SequenceConflict)
    );

    let mut draining = worker.clone();
    draining.draining = true;
    assert_eq!(
        coordinator
            .apply(&event(
                &deployment,
                2,
                CoordinationPayload::Worker(draining),
            ))
            .await,
        Ok(ProjectionApplyOutcome::Applied)
    );
    assert_eq!(
        coordinator
            .apply(&event(
                &deployment,
                3,
                CoordinationPayload::Worker(worker.clone()),
            ))
            .await,
        Err(CoordinationError::DrainIsOneWay)
    );

    clock.advance(Duration::from_secs(31)).expect("advance");
    let mut renewed = worker.clone();
    renewed.lease_expires_at = instant() + TimeDelta::minutes(2);
    assert_eq!(
        coordinator
            .apply(&event(
                &deployment,
                4,
                CoordinationPayload::Worker(renewed.clone()),
            ))
            .await,
        Err(CoordinationError::LeaseExpired)
    );
    renewed.lease.fence = fence(2);
    assert_eq!(
        coordinator
            .apply(&event(
                &deployment,
                5,
                CoordinationPayload::Worker(renewed.clone()),
            ))
            .await,
        Ok(ProjectionApplyOutcome::Applied)
    );
    let mut stale_fence = renewed;
    stale_fence.lease.fence = WorkerFence::INITIAL;
    assert_eq!(
        coordinator
            .apply(&event(
                &deployment,
                6,
                CoordinationPayload::Worker(stale_fence),
            ))
            .await,
        Err(CoordinationError::StaleFence)
    );
}

#[tokio::test]
async fn memory_hints_are_capacity_filtered_and_routes_require_exact_live_fence() {
    let deployment = DeploymentId::parse("test-b").expect("deployment");
    let clock = Arc::new(ManualCoordinationClock::new(instant()));
    let coordinator =
        MemoryCoordinator::new(deployment.clone(), clock.clone(), 8).expect("coordinator");
    let first_id = worker_id(10);
    let second_id = worker_id(11);
    let mut first = worker_snapshot(first_id, 1, instant() + TimeDelta::minutes(1));
    first.reserved_calls = 8;
    let mut second = worker_snapshot(second_id, 1, instant() + TimeDelta::minutes(1));
    second.reserved_calls = 1;
    second.capabilities.remove("webrtc");
    coordinator
        .apply(&event(
            &deployment,
            1,
            CoordinationPayload::Worker(first.clone()),
        ))
        .await
        .expect("first worker");
    coordinator
        .apply(&event(&deployment, 2, CoordinationPayload::Worker(second)))
        .await
        .expect("second worker");

    let hints = coordinator
        .worker_hints(&WorkerSelectionRequest {
            required_capabilities: BTreeSet::from(["webrtc".to_owned()]),
            limit: 5,
        })
        .await
        .expect("worker hints");
    assert_eq!(hints, vec![first.clone()]);

    let call = call_id(20);
    let route = CallRouteHint {
        call_id: call,
        worker: first.lease,
        expires_at: instant() + TimeDelta::seconds(20),
    };
    coordinator
        .apply(&event(
            &deployment,
            3,
            CoordinationPayload::Route(route.clone()),
        ))
        .await
        .expect("route");
    assert_eq!(coordinator.route_hint(call).await, Ok(Some(route)));

    let digest = ReplayDigest::new([7; 32]);
    coordinator
        .apply(&event(
            &deployment,
            4,
            CoordinationPayload::Replay(ReplayMarker {
                digest,
                expires_at: instant() + TimeDelta::seconds(5),
            }),
        ))
        .await
        .expect("replay");
    assert_eq!(coordinator.replay_seen(digest).await, Ok(true));
    clock.advance(Duration::from_secs(21)).expect("advance");
    assert_eq!(coordinator.route_hint(call).await, Ok(None));
    assert_eq!(coordinator.replay_seen(digest).await, Ok(false));
}

#[tokio::test]
async fn memory_wakeup_groups_deduplicate_reclaim_ack_and_fall_back_to_database() {
    let deployment = DeploymentId::parse("test-c").expect("deployment");
    let clock = Arc::new(ManualCoordinationClock::new(instant()));
    let coordinator = Arc::new(
        MemoryCoordinator::new(deployment.clone(), clock.clone(), 8).expect("coordinator"),
    );
    let worker = worker_id(30);
    let mut first = coordinator
        .wakeup_consumer(worker, "workers", "consumer-a", Duration::from_millis(25))
        .expect("consumer");
    let mut second = coordinator
        .wakeup_consumer(worker, "workers", "consumer-b", Duration::from_millis(25))
        .expect("consumer");
    let wake = event(
        &deployment,
        1,
        CoordinationPayload::WakeWorker {
            worker_id: worker,
            reason: WakeupReason::Effects,
        },
    );
    assert_eq!(
        coordinator.apply(&wake).await,
        Ok(ProjectionApplyOutcome::Applied)
    );
    assert_eq!(
        coordinator.apply(&wake).await,
        Ok(ProjectionApplyOutcome::Duplicate)
    );
    coordinator
        .publish_wakeup(worker, sequence(1), WakeupReason::Effects)
        .await
        .expect("idempotent direct publisher");

    let poll = first.poll(10).await;
    assert_eq!(poll.database_poll_reason, DatabasePollReason::Wakeup);
    assert_eq!(poll.messages.len(), 1);
    clock.advance(Duration::from_secs(2)).expect("advance");
    let reclaimed = second
        .auto_claim(Duration::from_secs(1), 10)
        .await
        .expect("reclaim");
    assert_eq!(reclaimed, poll.messages);
    assert_eq!(
        second.acknowledge(&[reclaimed[0].entry_id.clone()]).await,
        Ok(1)
    );
    let empty = second.poll(10).await;
    assert!(empty.messages.is_empty());
    assert_eq!(
        empty.database_poll_reason,
        DatabasePollReason::IntervalElapsed
    );
}

struct FailOnceProjection {
    failed: AtomicBool,
    inner: Arc<MemoryCoordinator>,
}

#[async_trait]
impl CoordinationProjection for FailOnceProjection {
    async fn apply(
        &self,
        event: &CoordinationEvent,
    ) -> Result<ProjectionApplyOutcome, CoordinationError> {
        if !self.failed.swap(true, Ordering::SeqCst) {
            Err(CoordinationError::Unavailable)
        } else {
            self.inner.apply(event).await
        }
    }

    async fn worker_hints(
        &self,
        request: &WorkerSelectionRequest,
    ) -> Result<Vec<WorkerCoordinationSnapshot>, CoordinationError> {
        self.inner.worker_hints(request).await
    }

    async fn route_hint(
        &self,
        call_id: CallId,
    ) -> Result<Option<CallRouteHint>, CoordinationError> {
        self.inner.route_hint(call_id).await
    }

    async fn replay_seen(&self, digest: ReplayDigest) -> Result<bool, CoordinationError> {
        self.inner.replay_seen(digest).await
    }
}

#[tokio::test]
async fn projector_crash_leaves_claim_reclaimable_and_ack_is_exact() {
    let deployment = DeploymentId::parse("test-d").expect("deployment");
    let clock = Arc::new(ManualCoordinationClock::new(instant()));
    let outbox = Arc::new(MemoryCoordinationOutbox::new(
        deployment.clone(),
        clock.clone(),
    ));
    let record = outbox
        .append(CoordinationPayload::Replay(ReplayMarker {
            digest: ReplayDigest::new([9; 32]),
            expires_at: instant() + TimeDelta::minutes(5),
        }))
        .expect("append");
    let inner =
        Arc::new(MemoryCoordinator::new(deployment, clock.clone(), 8).expect("coordinator"));
    let projection = Arc::new(FailOnceProjection {
        failed: AtomicBool::new(false),
        inner,
    });
    let projector = CoordinationProjector::new(
        outbox.clone(),
        projection,
        "projector-a",
        Duration::from_secs(1),
        8,
    )
    .expect("projector");

    assert_eq!(
        projector.project_once().await,
        Err(CoordinationError::Unavailable)
    );
    assert_eq!(projector.project_once().await, Ok(0));
    clock.advance(Duration::from_secs(2)).expect("advance");
    assert_eq!(projector.project_once().await, Ok(1));
    assert!(matches!(
        outbox
            .record(record.event.sequence)
            .expect("record")
            .expect("present")
            .state,
        CoordinationOutboxState::Applied { .. }
    ));
    assert_eq!(
        outbox
            .acknowledge(
                record.event.sequence,
                "projector-a",
                CoordinationClaimGeneration::default(),
            )
            .await,
        Err(CoordinationError::StaleClaim)
    );
}

#[test]
fn secrets_are_not_representable_and_debug_output_is_redacted() {
    let digest = ReplayDigest::new([0xab; 32]);
    assert_eq!(format!("{digest:?}"), "ReplayDigest([redacted])");
    let config = RedisCoordinationConfig::new(
        "redis://user:super-secret@127.0.0.1/",
        DeploymentId::parse("redaction").expect("deployment"),
    )
    .expect("config");
    let rendered = format!("{config:?}");
    assert!(!rendered.contains("super-secret"));
    assert!(rendered.contains("[redacted]"));
}
