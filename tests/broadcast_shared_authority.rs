use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bridgefu::broadcast::{
    ActiveBroadcastGrant, BroadcastGrantRegistry, BroadcastGrantTransport, BroadcastGrantVerifier,
    BroadcastTokenError, BroadcastTokenService, RedisBroadcastGrantConfig,
    RedisBroadcastGrantStore,
};
use chrono::Utc;
use rvoip_auth_core::BearerValidator;
use uuid::Uuid;

struct FixedGrantAuthority {
    grant: Option<ActiveBroadcastGrant>,
    unavailable: bool,
}

#[async_trait]
impl BroadcastGrantVerifier for FixedGrantAuthority {
    async fn active(
        &self,
        _broadcast_id: &str,
    ) -> Result<Option<ActiveBroadcastGrant>, BroadcastTokenError> {
        if self.unavailable {
            Err(BroadcastTokenError::AuthorityUnavailable)
        } else {
            Ok(self.grant.clone())
        }
    }

    async fn health_check(&self) -> Result<(), BroadcastTokenError> {
        if self.unavailable {
            Err(BroadcastTokenError::AuthorityUnavailable)
        } else {
            Ok(())
        }
    }
}

#[tokio::test]
async fn standalone_token_validation_uses_shared_grants_and_fails_closed() {
    let secret = b"0123456789abcdef0123456789abcdef".to_vec();
    let grants = BroadcastGrantRegistry::new();
    let _lease = grants
        .register(
            "tenant-a",
            "broadcast-a",
            BroadcastGrantTransport::Moqt,
            Utc::now() + chrono::Duration::minutes(5),
        )
        .unwrap();
    let issuer =
        BroadcastTokenService::new(secret.clone(), grants.clone(), Duration::from_secs(300))
            .unwrap();
    let token = issuer
        .issue("tenant-a", "broadcast-a", Duration::from_secs(60))
        .unwrap()
        .token;

    let standalone = BroadcastTokenService::new(
        secret.clone(),
        BroadcastGrantRegistry::new(),
        Duration::from_secs(300),
    )
    .unwrap()
    .with_shared_verifier(Arc::new(FixedGrantAuthority {
        grant: grants.active("broadcast-a"),
        unavailable: false,
    }));
    assert!(standalone.validate_credential(&token).await.is_ok());

    let inactive = BroadcastTokenService::new(
        secret.clone(),
        BroadcastGrantRegistry::new(),
        Duration::from_secs(300),
    )
    .unwrap()
    .with_shared_verifier(Arc::new(FixedGrantAuthority {
        grant: None,
        unavailable: false,
    }));
    assert!(inactive.validate_credential(&token).await.is_err());

    let unavailable = BroadcastTokenService::new(
        secret,
        BroadcastGrantRegistry::new(),
        Duration::from_secs(300),
    )
    .unwrap()
    .with_shared_verifier(Arc::new(FixedGrantAuthority {
        grant: None,
        unavailable: true,
    }));
    assert!(unavailable.validate_credential(&token).await.is_err());
}

#[tokio::test]
#[ignore = "requires BRIDGEFU_TEST_REDIS_URL pointing at disposable Redis"]
async fn redis_shared_grant_lifecycle_authorizes_and_revokes_tokens() {
    let redis_url =
        std::env::var("BRIDGEFU_TEST_REDIS_URL").expect("BRIDGEFU_TEST_REDIS_URL is required");
    let namespace = format!("broadcast-shared-authority-{}", Uuid::new_v4());
    let tenant_id = format!("tenant-{}", Uuid::new_v4());
    let broadcast_id = Uuid::new_v4().to_string();
    let store =
        RedisBroadcastGrantStore::connect(RedisBroadcastGrantConfig::new(redis_url, namespace))
            .await
            .expect("connect shared broadcast grant authority");
    let lease = store
        .register(
            &tenant_id,
            &broadcast_id,
            BroadcastGrantTransport::Moqt,
            Utc::now() + chrono::Duration::minutes(2),
        )
        .await
        .expect("register shared grant");

    let grant = BroadcastGrantVerifier::active(store.as_ref(), &broadcast_id)
        .await
        .expect("read shared grant")
        .expect("grant is active");
    assert_eq!(grant.tenant_id, tenant_id);
    assert_eq!(grant.broadcast_id, broadcast_id);
    assert_eq!(grant.transport, BroadcastGrantTransport::Moqt);
    assert_eq!(
        store
            .register(
                &tenant_id,
                &broadcast_id,
                BroadcastGrantTransport::Moqt,
                Utc::now() + chrono::Duration::minutes(2),
            )
            .await
            .expect_err("duplicate grant must fail"),
        BroadcastTokenError::Conflict
    );

    let tokens = BroadcastTokenService::new(
        b"0123456789abcdef0123456789abcdef".to_vec(),
        BroadcastGrantRegistry::new(),
        Duration::from_secs(300),
    )
    .expect("token service")
    .with_shared_verifier(store.clone());
    let token = tokens
        .issue_authorized(&tenant_id, &broadcast_id, Duration::from_secs(60))
        .await
        .expect("shared grant authorizes issuance")
        .token;
    tokens
        .validate_credential(&token)
        .await
        .expect("shared grant authorizes validation");

    assert!(lease.revoke().await.expect("revoke exact grant generation"));
    assert!(
        BroadcastGrantVerifier::active(store.as_ref(), &broadcast_id)
            .await
            .expect("read revoked grant")
            .is_none()
    );
    assert!(tokens.validate_credential(&token).await.is_err());
}

#[tokio::test]
#[ignore = "requires BRIDGEFU_TEST_REDIS_URL pointing at disposable Redis"]
async fn redis_uctp_listener_refresh_replay_and_revocation_are_exact() {
    let redis_url =
        std::env::var("BRIDGEFU_TEST_REDIS_URL").expect("BRIDGEFU_TEST_REDIS_URL is required");
    let namespace = format!("broadcast-uctp-listener-{}", Uuid::new_v4());
    let tenant_id = format!("tenant-{}", Uuid::new_v4());
    let broadcast_id = Uuid::new_v4().to_string();
    let store =
        RedisBroadcastGrantStore::connect(RedisBroadcastGrantConfig::new(redis_url, namespace))
            .await
            .expect("connect shared broadcast grant authority");
    let grant = store
        .register(
            &tenant_id,
            &broadcast_id,
            BroadcastGrantTransport::UctpQuic,
            Utc::now() + chrono::Duration::minutes(2),
        )
        .await
        .expect("register UCTP grant");
    let tokens = BroadcastTokenService::new(
        b"0123456789abcdef0123456789abcdef".to_vec(),
        BroadcastGrantRegistry::new(),
        Duration::from_secs(300),
    )
    .expect("token service")
    .with_shared_verifier(store.clone());

    let original = tokens
        .issue_authorized(&tenant_id, &broadcast_id, Duration::from_secs(30))
        .await
        .expect("issue original listener token");
    let refreshed = tokens
        .refresh(&original.token, Duration::from_secs(90))
        .await
        .expect("refresh listener token with stable credential ownership");
    let original_principal = tokens
        .validate_principal(&original.token)
        .await
        .expect("validate original listener principal");
    let refreshed_principal = tokens
        .validate_principal(&refreshed.token)
        .await
        .expect("validate refreshed listener principal");
    assert_eq!(original_principal.subject, refreshed_principal.subject);
    assert!(refreshed_principal.expires_at > original_principal.expires_at);

    let mut listener = store
        .acquire_uctp_listener(&original_principal, &broadcast_id, "gateway-a")
        .await
        .expect("acquire exact listener lease");
    assert_eq!(
        store
            .acquire_uctp_listener(&refreshed_principal, &broadcast_id, "gateway-b")
            .await
            .expect_err("credential replay on a second gateway must fail"),
        BroadcastTokenError::Conflict
    );
    assert!(listener
        .renew(&refreshed_principal)
        .await
        .expect("renew exact listener lease"));
    assert!(listener
        .revalidate()
        .await
        .expect("revalidate renewed lease"));
    assert!(listener.close().await.expect("close exact listener lease"));

    let listener = store
        .acquire_uctp_listener(&refreshed_principal, &broadcast_id, "gateway-b")
        .await
        .expect("closed listener credential can be rebound");
    assert!(grant.revoke().await.expect("revoke exact grant generation"));
    assert!(!listener
        .revalidate()
        .await
        .expect("grant revocation invalidates listener"));
    assert!(listener
        .close()
        .await
        .expect("listener ownership remains exactly closable after grant revocation"));
}

#[tokio::test]
#[ignore = "requires BRIDGEFU_TEST_REDIS_URL pointing at disposable Redis"]
async fn redis_uctp_listener_ownership_uses_complete_principal_tuple() {
    let redis_url =
        std::env::var("BRIDGEFU_TEST_REDIS_URL").expect("BRIDGEFU_TEST_REDIS_URL is required");
    let namespace = format!("broadcast-uctp-owner-tuple-{}", Uuid::new_v4());
    let tenant_id = format!("tenant-{}", Uuid::new_v4());
    let broadcast_id = Uuid::new_v4().to_string();
    let store =
        RedisBroadcastGrantStore::connect(RedisBroadcastGrantConfig::new(redis_url, namespace))
            .await
            .expect("connect shared broadcast grant authority");
    let grant = store
        .register(
            &tenant_id,
            &broadcast_id,
            BroadcastGrantTransport::UctpQuic,
            Utc::now() + chrono::Duration::minutes(2),
        )
        .await
        .expect("register UCTP grant");
    let tokens = BroadcastTokenService::new(
        b"0123456789abcdef0123456789abcdef".to_vec(),
        BroadcastGrantRegistry::new(),
        Duration::from_secs(300),
    )
    .expect("token service")
    .with_shared_verifier(store.clone());
    let issued = tokens
        .issue_authorized(&tenant_id, &broadcast_id, Duration::from_secs(60))
        .await
        .expect("issue listener token");
    let template = tokens
        .validate_principal(&issued.token)
        .await
        .expect("validate listener principal");

    // The authorization boundary receives an already authenticated principal.
    // Hold tenant, subject, scopes, and expiry constant so this exercises the
    // issuer component of the canonical ownership tuple through the real Lua
    // acquire/revalidate/close path rather than only comparing local digests.
    let mut issuer_a = template.clone();
    issuer_a.issuer = Some("issuer-a".into());
    let mut issuer_b = template;
    issuer_b.issuer = Some("issuer-b".into());
    assert_eq!(issuer_a.tenant, issuer_b.tenant);
    assert_eq!(issuer_a.subject, issuer_b.subject);

    let listener_a = store
        .acquire_uctp_listener(&issuer_a, &broadcast_id, "gateway-a")
        .await
        .expect("first issuer acquires its listener lease");
    let listener_b = store
        .acquire_uctp_listener(&issuer_b, &broadcast_id, "gateway-b")
        .await
        .expect("second issuer with the same tenant and subject remains independent");
    assert!(listener_a.revalidate().await.expect("revalidate issuer A"));
    assert!(listener_b.revalidate().await.expect("revalidate issuer B"));

    assert!(listener_a.close().await.expect("close only issuer A"));
    assert!(listener_b
        .revalidate()
        .await
        .expect("closing issuer A must not revoke issuer B"));
    let rebound_a = store
        .acquire_uctp_listener(&issuer_a, &broadcast_id, "gateway-a-rebound")
        .await
        .expect("issuer A can rebind without colliding with issuer B");
    assert!(listener_b.close().await.expect("close only issuer B"));
    assert!(rebound_a.close().await.expect("close rebound issuer A"));
    assert!(grant.revoke().await.expect("revoke exact grant generation"));
}
