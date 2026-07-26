use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use std::time::Duration;

use bridgefu::call_engine::{
    AttachmentId, AttachmentIssue, AttachmentPurpose, AttachmentTokenDigest, AttachmentTransport,
    BindingGeneration, CallAggregate, CallCommand, CallRepository, CommandId, CreateCall,
    IdempotencyKeyDigest, LegDirection, LegKind, LegSpec, PrincipalFingerprint, RegisterWorker,
    RequestDigest, TenantId, WorkerId, WorkerLease,
};
use bridgefu::call_service::{
    AmazonConnectEndpointConfig, AmazonConnectStartSpec, CallExecutionPlan, CallServiceRepository,
    LegEndpointConfig, LegExecutionSpec, ServiceCreateOutcome, ServiceCreateTransaction,
    SipEndpointConfig, CALL_EXECUTION_PLAN_VERSION,
};
use bridgefu::persistence::{MemoryRepository, PostgresRepository, SqliteRepository};
use chrono::{DateTime, TimeZone, Utc};
use sqlx::Row;

fn at(second: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_960_000_000 + second, 0).unwrap()
}

fn digest(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn sqlite_database(label: &str) -> (String, std::path::PathBuf) {
    let path =
        std::env::temp_dir().join(format!("bridgefu-{label}-{}.sqlite", uuid::Uuid::new_v4()));
    (format!("sqlite://{}?mode=rwc", path.display()), path)
}

async fn register<R>(repository: &R) -> WorkerLease
where
    R: CallRepository + Sync,
{
    repository
        .register_worker(RegisterWorker {
            worker_id: WorkerId::new(),
            max_calls: 1,
            capabilities: BTreeSet::from(["sip".into(), "amazon_connect".into()]),
            at: at(0),
            lease_ttl: Duration::from_secs(300),
        })
        .await
        .unwrap()
        .lease
}

#[derive(Clone)]
struct AmazonEvidence {
    owner: TenantId,
    call_id: bridgefu::call_engine::CallId,
    amazon_leg_id: bridgefu::call_engine::LegId,
    spec: AmazonConnectStartSpec,
}

fn amazon_transaction(worker: WorkerLease) -> (ServiceCreateTransaction, AmazonEvidence) {
    let owner = TenantId::parse("amazon-spec-conformance").unwrap();
    let initial = CallAggregate::new(
        owner.clone(),
        [
            LegSpec {
                direction: LegDirection::Inbound,
                kind: LegKind::Sip,
            },
            LegSpec {
                direction: LegDirection::Outbound,
                kind: LegKind::AmazonConnect,
            },
        ],
        at(1),
    );
    let call_id = initial.id();
    let inbound_leg_id = initial.legs()[0].id();
    let amazon_leg_id = initial.legs()[1].id();
    let spec = AmazonConnectStartSpec::new(
        "tenant-profile-private",
        "instance-private",
        "flow-private",
        BTreeMap::from([
            ("correlation_id".into(), "correlation-private".into()),
            ("tenant_hint".into(), "tenant-private".into()),
        ]),
        "Caller Private",
        Some("Description Private".into()),
    )
    .unwrap();
    let plan = CallExecutionPlan::new_with_amazon_connect_starts(
        &initial,
        [
            LegExecutionSpec {
                leg_id: inbound_leg_id,
                endpoint: LegEndpointConfig::Sip(SipEndpointConfig {
                    uri: None,
                    initial_context: Default::default(),
                }),
            },
            LegExecutionSpec {
                leg_id: amazon_leg_id,
                endpoint: LegEndpointConfig::AmazonConnect(AmazonConnectEndpointConfig {
                    instance_id: "instance-private".into(),
                    contact_flow_id: "flow-private".into(),
                }),
            },
        ],
        PrincipalFingerprint::new(digest(0x41)),
        BTreeMap::from([(amazon_leg_id, spec.clone())]),
    )
    .unwrap();
    let command_at = at(2);
    let create = CreateCall {
        initial,
        command_id: CommandId::new(),
        command: CallCommand::StartConnecting {
            at: command_at,
            setup_deadline: command_at + chrono::Duration::seconds(30),
        },
        worker,
        idempotency_key: IdempotencyKeyDigest::new(digest(0x42)),
        request_digest: RequestDigest::new(digest(0x43)),
        attachments: vec![AttachmentIssue {
            attachment_id: AttachmentId::new(),
            token_digest: AttachmentTokenDigest::new(digest(0x44)),
            purpose: AttachmentPurpose::PublicInbound,
            leg_id: inbound_leg_id,
            binding_generation: BindingGeneration::INITIAL,
            transport: AttachmentTransport::Sip,
            expected_principal: PrincipalFingerprint::new(digest(0x45)),
            expires_at: command_at + chrono::Duration::seconds(120),
        }],
        at: command_at,
    };
    (
        ServiceCreateTransaction {
            create,
            plan,
            alternatives: Vec::new(),
        },
        AmazonEvidence {
            owner,
            call_id,
            amazon_leg_id,
            spec,
        },
    )
}

fn legacy_plan(current: &CallExecutionPlan) -> CallExecutionPlan {
    let mut value = serde_json::to_value(current).unwrap();
    value["version"] = serde_json::json!(2);
    value
        .as_object_mut()
        .unwrap()
        .remove("amazon_connect_starts");
    serde_json::from_value(value).unwrap()
}

async fn assert_amazon_repository_conformance<R>(repository: &R) -> AmazonEvidence
where
    R: CallRepository + CallServiceRepository + Sync,
{
    let worker = register(repository).await;
    let (transaction, evidence) = amazon_transaction(worker);

    let rejected = repository
        .create_with_plan(ServiceCreateTransaction {
            create: transaction.create.clone(),
            plan: legacy_plan(&transaction.plan),
            alternatives: Vec::new(),
        })
        .await;
    assert!(
        matches!(
            rejected,
            Err(bridgefu::call_engine::RepositoryError::InvalidInput(_))
        ),
        "a new version-two Amazon plan was accepted"
    );

    let created = repository
        .create_with_plan(ServiceCreateTransaction {
            create: transaction.create.clone(),
            plan: transaction.plan.clone(),
            alternatives: Vec::new(),
        })
        .await
        .unwrap();
    let created = match created {
        ServiceCreateOutcome::Created(value) => value,
        ServiceCreateOutcome::Replayed(_) => panic!("first current plan unexpectedly replayed"),
    };
    assert_eq!(created.plan.version, CALL_EXECUTION_PLAN_VERSION);
    assert_eq!(
        created
            .plan
            .amazon_connect_start_spec(evidence.amazon_leg_id)
            .unwrap(),
        &evidence.spec
    );

    let replay = repository
        .create_with_plan(ServiceCreateTransaction {
            create: transaction.create,
            plan: transaction.plan,
            alternatives: Vec::new(),
        })
        .await
        .unwrap();
    let replay = match replay {
        ServiceCreateOutcome::Replayed(value) => value,
        ServiceCreateOutcome::Created(_) => panic!("same create did not replay"),
    };
    assert_eq!(replay.plan, created.plan);

    let loaded = repository
        .load_service_call(&evidence.owner, evidence.call_id)
        .await
        .unwrap();
    assert_eq!(loaded.plan, created.plan);
    evidence
}

#[tokio::test]
async fn memory_preserves_current_amazon_spec_and_rejects_new_legacy_plan_atomically() {
    let repository = MemoryRepository::default();
    assert_amazon_repository_conformance(&repository).await;
}

#[tokio::test]
async fn sqlite_preserves_current_amazon_spec_across_restart_and_rejects_invalid_body() {
    let (url, path) = sqlite_database("amazon-spec");
    let repository = SqliteRepository::connect(&url).await.unwrap();
    let evidence = assert_amazon_repository_conformance(&repository).await;

    let row = sqlx::query("SELECT plan_version, body FROM call_execution_plans WHERE call_id = ?")
        .bind(evidence.call_id.to_string())
        .fetch_one(repository.pool())
        .await
        .unwrap();
    assert_eq!(row.get::<i64, _>("plan_version"), 3);
    let body = row.get::<String, _>("body");
    let lowered = body.to_ascii_lowercase();
    assert!(!lowered.contains("client_token"));
    assert!(!lowered.contains("credential"));
    repository.pool().close().await;

    let restarted = SqliteRepository::connect(&url).await.unwrap();
    let loaded = restarted
        .load_service_call(&evidence.owner, evidence.call_id)
        .await
        .unwrap();
    assert_eq!(
        loaded
            .plan
            .amazon_connect_start_spec(evidence.amazon_leg_id)
            .unwrap(),
        &evidence.spec
    );

    sqlx::query(
        "UPDATE call_execution_plans SET body = json_set(body, '$.plan.amazon_connect_starts[0].spec.profile', ?) WHERE call_id = ?",
    )
    .bind("p".repeat(129))
    .bind(evidence.call_id.to_string())
    .execute(restarted.pool())
    .await
    .unwrap();
    assert_eq!(
        restarted
            .load_service_call(&evidence.owner, evidence.call_id)
            .await,
        Err(bridgefu::call_engine::RepositoryError::Unavailable)
    );
    restarted.pool().close().await;
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn sqlite_v7_to_v8_does_not_promote_or_rewrite_legacy_amazon_plan() {
    let (url, path) = sqlite_database("amazon-spec-v7-upgrade");
    let migration_dir = std::env::temp_dir().join(format!(
        "bridgefu-amazon-spec-migrations-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir(&migration_dir).unwrap();
    for version in 1..=7 {
        let name = std::fs::read_dir("migrations/sqlite")
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .find(|name| name.starts_with(&format!("{version:04}_")))
            .unwrap();
        std::fs::copy(
            format!("migrations/sqlite/{name}"),
            migration_dir.join(name),
        )
        .unwrap();
    }
    let options = sqlx::sqlite::SqliteConnectOptions::from_str(&url)
        .unwrap()
        .create_if_missing(true)
        .foreign_keys(false);
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    sqlx::migrate::Migrator::new(migration_dir.clone())
        .await
        .unwrap()
        .run(&pool)
        .await
        .unwrap();
    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&pool)
        .await
        .unwrap();
    let call_id = uuid::Uuid::new_v4().to_string();
    let first_leg = uuid::Uuid::new_v4().to_string();
    let second_leg = uuid::Uuid::new_v4().to_string();
    let legacy_body = serde_json::json!({
        "call_id": call_id,
        "plan": {
            "version": 2,
            "authorization_principal_fingerprint": digest(0x51),
            "legs": [
                {
                    "leg_id": first_leg,
                    "endpoint": {"type": "sip", "config": {"uri": null}}
                },
                {
                    "leg_id": second_leg,
                    "endpoint": {
                        "type": "amazon_connect",
                        "config": {
                            "instance_id": "legacy-instance",
                            "contact_flow_id": "legacy-flow"
                        }
                    }
                }
            ]
        }
    })
    .to_string();
    sqlx::query(
        "INSERT INTO call_execution_plans(call_id, plan_version, first_leg_id, first_endpoint_kind, second_leg_id, second_endpoint_kind, authorization_principal_fingerprint, body) VALUES (?, 2, ?, 'sip', ?, 'amazon_connect', ?, ?)",
    )
    .bind(&call_id)
    .bind(&first_leg)
    .bind(&second_leg)
    .bind(digest(0x51).to_vec())
    .bind(&legacy_body)
    .execute(&pool)
    .await
    .unwrap();

    let migration_name = std::fs::read_dir("migrations/sqlite")
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .find(|name| name.starts_with("0008_"))
        .unwrap();
    std::fs::copy(
        format!("migrations/sqlite/{migration_name}"),
        migration_dir.join(migration_name),
    )
    .unwrap();
    sqlx::migrate::Migrator::new(migration_dir.clone())
        .await
        .unwrap()
        .run(&pool)
        .await
        .unwrap();

    let row = sqlx::query("SELECT plan_version, body FROM call_execution_plans WHERE call_id = ?")
        .bind(&call_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(row.get::<i64, _>("plan_version"), 2);
    assert_eq!(row.get::<String, _>("body"), legacy_body);
    let schema_version: i64 =
        sqlx::query_scalar("SELECT schema_version FROM repository_metadata WHERE singleton = 1")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(schema_version, 8);

    pool.close().await;
    std::fs::remove_file(path).unwrap();
    std::fs::remove_dir_all(migration_dir).unwrap();
}

#[tokio::test]
async fn postgres_v7_to_v8_does_not_promote_or_rewrite_legacy_amazon_plan() {
    let Some(url) = std::env::var("BRIDGEFU_TEST_POSTGRES_URL")
        .ok()
        .filter(|url| !url.trim().is_empty())
    else {
        eprintln!("BRIDGEFU_TEST_POSTGRES_URL is unset; Amazon migration test skipped");
        return;
    };
    let administration = sqlx::PgPool::connect(&url).await.unwrap();
    let schema = format!(
        "bridgefu_amazon_migration_{}",
        uuid::Uuid::new_v4().simple()
    );
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&administration)
        .await
        .unwrap();
    let mut scoped = url::Url::parse(&url).unwrap();
    scoped
        .query_pairs_mut()
        .append_pair("options", &format!("-csearch_path={schema}"));
    let scoped = scoped.to_string();
    let pool = sqlx::PgPool::connect(&scoped).await.unwrap();

    let migration_dir = std::env::temp_dir().join(format!(
        "bridgefu-amazon-postgres-migrations-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir(&migration_dir).unwrap();
    for version in 1..=7 {
        let name = std::fs::read_dir("migrations/postgres")
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .find(|name| name.starts_with(&format!("{version:04}_")))
            .unwrap();
        std::fs::copy(
            format!("migrations/postgres/{name}"),
            migration_dir.join(name),
        )
        .unwrap();
    }
    sqlx::migrate::Migrator::new(migration_dir.clone())
        .await
        .unwrap()
        .run(&pool)
        .await
        .unwrap();

    let call_id = uuid::Uuid::new_v4();
    let first_leg = uuid::Uuid::new_v4();
    let second_leg = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO calls(call_id, tenant_id, aggregate_version, call_state, body) \
         VALUES ($1, 'legacy-amazon', 0, 'pending', '{}'::jsonb)",
    )
    .bind(call_id)
    .execute(&pool)
    .await
    .unwrap();
    for leg_id in [first_leg, second_leg] {
        sqlx::query(
            "INSERT INTO legs(leg_id, call_id, tenant_id, binding_generation, leg_state, body) \
             VALUES ($1, $2, 'legacy-amazon', 1, 'pending', '{}'::jsonb)",
        )
        .bind(leg_id)
        .bind(call_id)
        .execute(&pool)
        .await
        .unwrap();
    }
    let legacy_body = serde_json::json!({
        "call_id": call_id,
        "plan": {
            "version": 2,
            "authorization_principal_fingerprint": digest(0x61),
            "legs": [
                {
                    "leg_id": first_leg,
                    "endpoint": {"type": "sip", "config": {"uri": null}}
                },
                {
                    "leg_id": second_leg,
                    "endpoint": {
                        "type": "amazon_connect",
                        "config": {
                            "instance_id": "legacy-instance",
                            "contact_flow_id": "legacy-flow"
                        }
                    }
                }
            ]
        }
    });
    sqlx::query(
        "INSERT INTO call_execution_plans(\
             call_id, plan_version, first_leg_id, first_endpoint_kind, second_leg_id, \
             second_endpoint_kind, authorization_principal_fingerprint, body\
         ) VALUES ($1, 2, $2, 'sip', $3, 'amazon_connect', $4, $5)",
    )
    .bind(call_id)
    .bind(first_leg)
    .bind(second_leg)
    .bind(digest(0x61).to_vec())
    .bind(&legacy_body)
    .execute(&pool)
    .await
    .unwrap();
    let before: String =
        sqlx::query_scalar("SELECT body::text FROM call_execution_plans WHERE call_id = $1")
            .bind(call_id)
            .fetch_one(&pool)
            .await
            .unwrap();

    let migration_name = std::fs::read_dir("migrations/postgres")
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .find(|name| name.starts_with("0008_"))
        .unwrap();
    std::fs::copy(
        format!("migrations/postgres/{migration_name}"),
        migration_dir.join(migration_name),
    )
    .unwrap();
    sqlx::migrate::Migrator::new(migration_dir.clone())
        .await
        .unwrap()
        .run(&pool)
        .await
        .unwrap();

    let row = sqlx::query(
        "SELECT plan_version, body::text AS body FROM call_execution_plans WHERE call_id = $1",
    )
    .bind(call_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.get::<i64, _>("plan_version"), 2);
    assert_eq!(row.get::<String, _>("body"), before);
    let schema_version: i64 =
        sqlx::query_scalar("SELECT schema_version FROM repository_metadata WHERE singleton = TRUE")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(schema_version, 8);

    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&administration)
        .await
        .unwrap();
    administration.close().await;
    std::fs::remove_dir_all(migration_dir).unwrap();
}

#[tokio::test]
async fn postgres_preserves_current_amazon_spec_across_restart() {
    let Some(url) = std::env::var("BRIDGEFU_TEST_POSTGRES_URL")
        .ok()
        .filter(|url| !url.trim().is_empty())
    else {
        eprintln!("BRIDGEFU_TEST_POSTGRES_URL is unset; Amazon spec PostgreSQL test skipped");
        return;
    };
    let administration = sqlx::PgPool::connect(&url).await.unwrap();
    let schema = format!("bridgefu_amazon_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&administration)
        .await
        .unwrap();
    let mut scoped = url::Url::parse(&url).unwrap();
    scoped
        .query_pairs_mut()
        .append_pair("options", &format!("-csearch_path={schema}"));
    let scoped = scoped.to_string();

    let first = PostgresRepository::connect(&scoped).await.unwrap();
    let evidence = assert_amazon_repository_conformance(&first).await;
    let row = sqlx::query(
        "SELECT plan_version, body::text AS body FROM call_execution_plans WHERE call_id = $1",
    )
    .bind(evidence.call_id.as_uuid())
    .fetch_one(first.pool())
    .await
    .unwrap();
    assert_eq!(row.get::<i64, _>("plan_version"), 3);
    let lowered = row.get::<String, _>("body").to_ascii_lowercase();
    assert!(!lowered.contains("client_token"));
    assert!(!lowered.contains("credential"));
    first.pool().close().await;

    let restarted = PostgresRepository::connect(&scoped).await.unwrap();
    let loaded = restarted
        .load_service_call(&evidence.owner, evidence.call_id)
        .await
        .unwrap();
    assert_eq!(
        loaded
            .plan
            .amazon_connect_start_spec(evidence.amazon_leg_id)
            .unwrap(),
        &evidence.spec
    );
    restarted.pool().close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&administration)
        .await
        .unwrap();
    administration.close().await;
}
