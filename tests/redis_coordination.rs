use std::collections::BTreeSet;
use std::time::Duration;

use bridgefu::call_engine::{CallId, WorkerFence, WorkerId, WorkerLease};
use bridgefu::coordination::{
    CallRouteHint, CoordinationError, CoordinationEvent, CoordinationPayload,
    CoordinationProjection, DatabasePollReason, DeploymentId, ProjectionApplyOutcome,
    ProjectionSequence, RedisCoordinationConfig, RedisCoordinator, ReplayDigest, ReplayMarker,
    WakeupConsumer, WakeupPublisher, WakeupReason, WorkerCoordinationSnapshot,
    WorkerSelectionRequest,
};
use chrono::{TimeDelta, Utc};
use uuid::Uuid;

fn fence(value: u64) -> WorkerFence {
    serde_json::from_value(serde_json::json!(value)).expect("valid fence")
}

fn sequence(value: i64) -> ProjectionSequence {
    ProjectionSequence::from_i64(value).expect("valid sequence")
}

fn event(deployment: &DeploymentId, value: i64, payload: CoordinationPayload) -> CoordinationEvent {
    CoordinationEvent {
        deployment: deployment.clone(),
        sequence: sequence(value),
        payload,
        recorded_at: Utc::now(),
    }
}

#[tokio::test]
#[ignore = "requires BRIDGEFU_TEST_REDIS_URL pointing at Redis 7.2"]
async fn redis_72_projection_streams_and_database_fallback_are_conformant() {
    let url =
        std::env::var("BRIDGEFU_TEST_REDIS_URL").expect("BRIDGEFU_TEST_REDIS_URL is required");
    let deployment =
        DeploymentId::parse(format!("redis-{}", Uuid::new_v4().simple())).expect("deployment");
    assert_redis_72(&url).await;
    let config = RedisCoordinationConfig::new(&url, deployment.clone())
        .expect("config")
        .with_lease_tombstone_ttl(Duration::from_secs(5))
        .expect("tombstone policy")
        .with_stream_policy(4, Duration::from_secs(5), Duration::from_millis(25))
        .expect("stream policy");
    let coordinator = RedisCoordinator::connect(config)
        .await
        .expect("Redis coordinator");
    let worker_id = WorkerId::from_uuid(Uuid::from_u128(100)).expect("worker");
    let now = Utc::now();
    let mut worker = WorkerCoordinationSnapshot {
        lease: WorkerLease {
            worker_id,
            fence: WorkerFence::INITIAL,
        },
        max_calls: 20,
        reserved_calls: 3,
        draining: false,
        capabilities: BTreeSet::from(["sip".to_owned(), "webrtc".to_owned()]),
        lease_expires_at: now + TimeDelta::milliseconds(100),
    };
    let first = event(&deployment, 1, CoordinationPayload::Worker(worker.clone()));
    assert_eq!(
        coordinator.apply(&first).await,
        Ok(ProjectionApplyOutcome::Applied)
    );
    assert_eq!(
        coordinator.apply(&first).await,
        Ok(ProjectionApplyOutcome::Duplicate)
    );
    let mut conflict = first.clone();
    if let CoordinationPayload::Worker(snapshot) = &mut conflict.payload {
        snapshot.reserved_calls = 4;
    }
    assert_eq!(
        coordinator.apply(&conflict).await,
        Err(CoordinationError::SequenceConflict)
    );
    worker.draining = true;
    assert_eq!(
        coordinator
            .apply(&event(
                &deployment,
                2,
                CoordinationPayload::Worker(worker.clone()),
            ))
            .await,
        Ok(ProjectionApplyOutcome::Applied)
    );
    worker.draining = false;
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
    tokio::time::sleep(Duration::from_millis(150)).await;
    worker.lease_expires_at = Utc::now() + TimeDelta::seconds(5);
    assert_eq!(
        coordinator
            .apply(&event(
                &deployment,
                4,
                CoordinationPayload::Worker(worker.clone()),
            ))
            .await,
        Err(CoordinationError::LeaseExpired)
    );
    worker.lease.fence = fence(2);
    assert_eq!(
        coordinator
            .apply(&event(
                &deployment,
                5,
                CoordinationPayload::Worker(worker.clone()),
            ))
            .await,
        Ok(ProjectionApplyOutcome::Applied)
    );
    assert_eq!(
        coordinator
            .worker_hints(&WorkerSelectionRequest {
                required_capabilities: BTreeSet::from(["webrtc".to_owned()]),
                limit: 1,
            })
            .await
            .expect("hints"),
        vec![worker.clone()]
    );

    let call_id = CallId::from_uuid(Uuid::from_u128(200)).expect("call");
    let route = CallRouteHint {
        call_id,
        worker: worker.lease,
        expires_at: Utc::now() + TimeDelta::seconds(3),
    };
    coordinator
        .apply(&event(
            &deployment,
            6,
            CoordinationPayload::Route(route.clone()),
        ))
        .await
        .expect("route projection");
    assert_eq!(coordinator.route_hint(call_id).await, Ok(Some(route)));
    let digest = ReplayDigest::new([0x33; 32]);
    coordinator
        .apply(&event(
            &deployment,
            7,
            CoordinationPayload::Replay(ReplayMarker {
                digest,
                expires_at: Utc::now() + TimeDelta::seconds(3),
            }),
        ))
        .await
        .expect("replay projection");
    assert_eq!(coordinator.replay_seen(digest).await, Ok(true));

    let above_lua_integer_precision = 9_007_199_254_740_992_i64;
    let precision_fence_worker =
        WorkerId::from_uuid(Uuid::from_u128(102)).expect("precision fence worker");
    let mut precision_fence_snapshot = worker.clone();
    precision_fence_snapshot.lease = WorkerLease {
        worker_id: precision_fence_worker,
        fence: fence(above_lua_integer_precision as u64),
    };
    coordinator
        .apply(&event(
            &deployment,
            8,
            CoordinationPayload::Worker(precision_fence_snapshot.clone()),
        ))
        .await
        .expect("first large fence");
    precision_fence_snapshot.lease.fence = fence((above_lua_integer_precision + 1) as u64);
    assert_eq!(
        coordinator
            .apply(&event(
                &deployment,
                9,
                CoordinationPayload::Worker(precision_fence_snapshot.clone()),
            ))
            .await,
        Ok(ProjectionApplyOutcome::Applied)
    );
    precision_fence_snapshot.lease.fence = fence(above_lua_integer_precision as u64);
    assert_eq!(
        coordinator
            .apply(&event(
                &deployment,
                10,
                CoordinationPayload::Worker(precision_fence_snapshot),
            ))
            .await,
        Err(CoordinationError::StaleFence)
    );

    let mut consumer_a = coordinator
        .wakeup_consumer(worker_id, "workers", "redis-a")
        .await
        .expect("consumer a");
    let mut consumer_b = coordinator
        .wakeup_consumer(worker_id, "workers", "redis-b")
        .await
        .expect("consumer b");
    coordinator
        .publish_wakeup(worker_id, sequence(10), WakeupReason::Effects)
        .await
        .expect("publish");
    let first_delivery = consumer_a.poll(1).await;
    assert_eq!(
        first_delivery.database_poll_reason,
        DatabasePollReason::Wakeup
    );
    assert_eq!(first_delivery.messages.len(), 1);
    tokio::time::sleep(Duration::from_millis(20)).await;
    let reclaimed = consumer_b
        .auto_claim(Duration::from_millis(10), 1)
        .await
        .expect("auto claim");
    assert_eq!(reclaimed, first_delivery.messages);
    assert_eq!(
        consumer_b
            .acknowledge(&[reclaimed[0].entry_id.clone()])
            .await,
        Ok(1)
    );
    let fallback = consumer_b.poll(1).await;
    assert!(fallback.messages.is_empty());
    assert_eq!(
        fallback.database_poll_reason,
        DatabasePollReason::IntervalElapsed
    );

    for value in 11..31 {
        coordinator
            .publish_wakeup(worker_id, sequence(value), WakeupReason::Assignment)
            .await
            .expect("bounded publish");
    }
    let mut raw = redis::Client::open(url.as_str())
        .expect("client")
        .get_multiplexed_async_connection()
        .await
        .expect("connection");
    let stream_key = format!(
        "bridgefu:{{{}}}:coord:wakeup:{}",
        deployment.as_str(),
        worker_id
    );
    let length: usize = redis::cmd("XLEN")
        .arg(&stream_key)
        .query_async(&mut raw)
        .await
        .expect("stream length");
    assert!(length <= 4, "stream must be strictly bounded");

    let precision_worker = WorkerId::from_uuid(Uuid::from_u128(101)).expect("precision worker");
    let mut precision_consumer = coordinator
        .wakeup_consumer(precision_worker, "workers", "precision")
        .await
        .expect("precision consumer");
    coordinator
        .publish_wakeup(
            precision_worker,
            sequence(above_lua_integer_precision),
            WakeupReason::Effects,
        )
        .await
        .expect("first large sequence");
    coordinator
        .publish_wakeup(
            precision_worker,
            sequence(above_lua_integer_precision + 1),
            WakeupReason::Controls,
        )
        .await
        .expect("adjacent large sequence");
    let precision_messages = precision_consumer.poll(2).await.messages;
    assert_eq!(precision_messages.len(), 2);
    assert_eq!(
        precision_messages[1].sequence,
        sequence(above_lua_integer_precision + 1)
    );
    cleanup_deployment(&mut raw, &deployment).await;
}

async fn assert_redis_72(url: &str) {
    let client = redis::Client::open(url).expect("Redis URL");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let info: String = redis::cmd("INFO")
        .arg("server")
        .query_async(&mut connection)
        .await
        .expect("INFO server");
    let version = info
        .lines()
        .find_map(|line| line.strip_prefix("redis_version:"))
        .map(str::trim)
        .expect("redis_version");
    assert!(
        version.starts_with("7.2."),
        "integration suite requires Redis 7.2, got {version}"
    );
}

async fn cleanup_deployment(
    connection: &mut redis::aio::MultiplexedConnection,
    deployment: &DeploymentId,
) {
    let pattern = format!("bridgefu:{{{}}}:coord:*", deployment.as_str());
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg(pattern)
        .query_async(connection)
        .await
        .expect("test key scan");
    if !keys.is_empty() {
        let _: usize = redis::cmd("DEL")
            .arg(keys)
            .query_async(connection)
            .await
            .expect("test cleanup");
    }
}
