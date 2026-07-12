use std::path::PathBuf;
use std::time::Duration;

use bridgefu::call_engine::WorkerId;
use bridgefu::coordination::{
    CoordinationError, CoordinationOutbox, CoordinationOutboxState, CoordinationPayload,
    DeploymentId, PostgresCoordinationOutbox, SqliteCoordinationOutbox, WakeupReason,
};
use bridgefu::persistence::{PostgresRepository, SqliteRepository};
use uuid::Uuid;

fn wake(worker_id: WorkerId, reason: WakeupReason) -> CoordinationPayload {
    CoordinationPayload::WakeWorker { worker_id, reason }
}

fn sqlite_path() -> PathBuf {
    std::env::temp_dir().join(format!("bridgefu-coordination-{}.sqlite", Uuid::new_v4()))
}

#[tokio::test]
async fn sqlite_outbox_is_atomic_ordered_and_reclaims_after_projector_crash() {
    let path = sqlite_path();
    let url = format!("sqlite://{}", path.display());
    let first_repository = SqliteRepository::connect(&url).await.expect("first repo");
    let second_repository = SqliteRepository::connect(&url).await.expect("second repo");
    let deployment = DeploymentId::parse("sqlite-race").expect("deployment");
    let first =
        SqliteCoordinationOutbox::from_pool(first_repository.pool().clone(), deployment.clone());
    let second =
        SqliteCoordinationOutbox::from_pool(second_repository.pool().clone(), deployment.clone());
    let worker = WorkerId::from_uuid(Uuid::from_u128(1)).expect("worker");

    let mut rolled_back = first_repository.pool().begin().await.expect("transaction");
    first
        .append_in_transaction(&mut rolled_back, wake(worker, WakeupReason::Assignment))
        .await
        .expect("append in transaction");
    rolled_back.rollback().await.expect("rollback");
    assert!(first
        .claim("empty-check", Duration::from_secs(1), 8)
        .await
        .expect("claim after rollback")
        .is_empty());

    let first_record = first
        .append(wake(worker, WakeupReason::Effects))
        .await
        .expect("first append");
    let second_record = first
        .append(wake(worker, WakeupReason::Controls))
        .await
        .expect("second append");
    assert!(first_record.event.sequence < second_record.event.sequence);

    let first_claim = {
        let outbox = first.clone();
        tokio::spawn(async move {
            outbox
                .claim("projector-a", Duration::from_millis(100), 8)
                .await
        })
    };
    let second_claim = {
        let outbox = second.clone();
        tokio::spawn(async move {
            outbox
                .claim("projector-b", Duration::from_millis(100), 8)
                .await
        })
    };
    let claims_a = first_claim.await.expect("task a").expect("claim a");
    let claims_b = second_claim.await.expect("task b").expect("claim b");
    assert_eq!(claims_a.len() + claims_b.len(), 2);
    assert!(claims_a.is_empty() || claims_b.is_empty());
    let crashed_claims = if claims_a.is_empty() {
        claims_b
    } else {
        claims_a
    };

    drop(first);
    drop(second);
    tokio::time::sleep(Duration::from_millis(175)).await;
    let restarted_repository = SqliteRepository::connect(&url).await.expect("restart repo");
    let restarted =
        SqliteCoordinationOutbox::from_pool(restarted_repository.pool().clone(), deployment);
    let reclaimed = restarted
        .claim("projector-after-restart", Duration::from_secs(1), 8)
        .await
        .expect("reclaim");
    assert_eq!(reclaimed.len(), 2);
    assert!(reclaimed
        .iter()
        .zip(&crashed_claims)
        .all(|(new, old)| new.claim_generation > old.claim_generation));
    assert_eq!(
        restarted
            .acknowledge(
                crashed_claims[0].record.event.sequence,
                "projector-a",
                crashed_claims[0].claim_generation,
            )
            .await,
        Err(CoordinationError::StaleClaim)
    );
    for claim in &reclaimed {
        restarted
            .acknowledge(
                claim.record.event.sequence,
                "projector-after-restart",
                claim.claim_generation,
            )
            .await
            .expect("exact acknowledgement");
    }
    assert!(restarted
        .claim("projector-after-restart", Duration::from_secs(1), 8)
        .await
        .expect("empty after acknowledgement")
        .is_empty());

    drop(restarted);
    drop(restarted_repository);
    drop(first_repository);
    drop(second_repository);
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
#[ignore = "requires BRIDGEFU_TEST_POSTGRES_URL pointing at disposable PostgreSQL"]
async fn postgres_two_instances_have_one_ordered_claim_winner() {
    let url = std::env::var("BRIDGEFU_TEST_POSTGRES_URL")
        .expect("BRIDGEFU_TEST_POSTGRES_URL is required");
    let first_repository = PostgresRepository::connect(&url).await.expect("first repo");
    let second_repository = PostgresRepository::connect(&url)
        .await
        .expect("second repo");
    let deployment =
        DeploymentId::parse(format!("pg-{}", Uuid::new_v4().simple())).expect("deployment");
    let first =
        PostgresCoordinationOutbox::from_pool(first_repository.pool().clone(), deployment.clone());
    let second =
        PostgresCoordinationOutbox::from_pool(second_repository.pool().clone(), deployment.clone());
    let worker = WorkerId::from_uuid(Uuid::from_u128(2)).expect("worker");
    let mut rolled_back = first_repository.pool().begin().await.expect("transaction");
    first
        .append_in_transaction(&mut rolled_back, wake(worker, WakeupReason::Assignment))
        .await
        .expect("append in transaction");
    rolled_back.rollback().await.expect("rollback");
    assert!(first
        .claim("pg-empty", Duration::from_secs(1), 8)
        .await
        .expect("claim after rollback")
        .is_empty());
    first
        .append(wake(worker, WakeupReason::Effects))
        .await
        .expect("append one");
    first
        .append(wake(worker, WakeupReason::Controls))
        .await
        .expect("append two");

    let task_a =
        tokio::spawn(async move { first.claim("pg-a", Duration::from_millis(100), 8).await });
    let task_b =
        tokio::spawn(async move { second.claim("pg-b", Duration::from_millis(100), 8).await });
    let claims_a = task_a.await.expect("task a").expect("claim a");
    let claims_b = task_b.await.expect("task b").expect("claim b");
    assert_eq!(claims_a.len() + claims_b.len(), 2);
    assert!(claims_a.is_empty() || claims_b.is_empty());
    let crashed_claims = if claims_a.is_empty() {
        claims_b
    } else {
        claims_a
    };
    let crashed_projector = match &crashed_claims[0].record.state {
        CoordinationOutboxState::Claimed { projector, .. } => projector.clone(),
        state => panic!("expected claimed record, got {state:?}"),
    };

    tokio::time::sleep(Duration::from_millis(175)).await;
    let restarted =
        PostgresCoordinationOutbox::from_pool(first_repository.pool().clone(), deployment.clone());
    let reclaimed = restarted
        .claim("pg-after-restart", Duration::from_secs(1), 8)
        .await
        .expect("reclaim");
    assert_eq!(reclaimed.len(), 2);
    assert!(reclaimed
        .iter()
        .zip(&crashed_claims)
        .all(|(new, old)| new.claim_generation > old.claim_generation));
    assert_eq!(
        restarted
            .acknowledge(
                crashed_claims[0].record.event.sequence,
                &crashed_projector,
                crashed_claims[0].claim_generation,
            )
            .await,
        Err(CoordinationError::StaleClaim)
    );
    for claim in reclaimed {
        restarted
            .acknowledge(
                claim.record.event.sequence,
                "pg-after-restart",
                claim.claim_generation,
            )
            .await
            .expect("exact acknowledgement");
    }

    sqlx::query("DELETE FROM coordination_outbox WHERE deployment_id = $1")
        .bind(deployment.as_str())
        .execute(first_repository.pool())
        .await
        .expect("cleanup");
}
