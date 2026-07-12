//! Authenticated control-API principal handling.
//!
//! This module is deliberately independent from Axum handlers. Gateways can
//! authenticate a request once, retain rvoip's complete principal, and apply
//! the same tenant/scope rules in HTTP, command-stream, or test transports.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use axum::http::{header::AUTHORIZATION, HeaderMap};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use rvoip_auth_core::{
    AuthenticatedPrincipal, AuthenticationMethod, BearerAuthError, BearerValidator,
    MAX_BEARER_ISSUER_BYTES, MAX_BEARER_SUBJECT_BYTES,
};
use rvoip_core::{IdentityAssurance, Jwk};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroize;

use crate::call_engine::{PrincipalFingerprint, TenantId};

/// Maximum accepted bytes in the credential after the `Bearer` scheme.
pub const MAX_API_BEARER_BYTES: usize = 16 * 1024;
/// Minimum key material for domain-separated principal fingerprints.
pub const MIN_FINGERPRINT_KEY_BYTES: usize = 32;
const MAX_FINGERPRINT_KEY_BYTES: usize = 4096;
const FINGERPRINT_DOMAIN: &[u8] = b"bridgefu.principal-fingerprint.v1\0";

/// Stable authorization scopes for Bridgefu call operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallScope {
    Create,
    Read,
    Hangup,
    Transfer,
    Dtmf,
    TenantOverride,
}

impl CallScope {
    /// Wire value used by rvoip principal scope checks.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "calls:create",
            Self::Read => "calls:read",
            Self::Hangup => "calls:hangup",
            Self::Transfer => "calls:transfer",
            Self::Dtmf => "calls:dtmf",
            Self::TenantOverride => "calls:tenant-override",
        }
    }
}

/// Credential and authorization failures safe for HTTP error mapping.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ApiPrincipalError {
    #[error("bearer credential is required")]
    MissingCredential,
    #[error("bearer credential is malformed")]
    MalformedCredential,
    #[error("bearer credential is invalid")]
    InvalidCredential,
    #[error("bearer credential is expired")]
    ExpiredCredential,
    #[error("authenticated principal has no tenant")]
    TenantRequired,
    #[error("authenticated principal is missing scope {0}")]
    MissingScope(&'static str),
    #[error("tenant override is not authorized")]
    TenantOverrideForbidden,
    #[error("tenant identifier is invalid")]
    InvalidTenant,
    #[error("static API-key authentication requires exactly one tenant")]
    AmbiguousStaticTenant,
    #[error("static API key is empty or too large")]
    InvalidStaticApiKey,
    #[error("principal fingerprint key must contain 32 to 4096 bytes")]
    InvalidFingerprintKey,
}

/// Complete rvoip principal retained at the control-plane boundary.
#[derive(Clone)]
pub struct ApiPrincipal {
    inner: AuthenticatedPrincipal,
    tenant: TenantId,
}

impl fmt::Debug for ApiPrincipal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiPrincipal")
            .field("subject", &"[redacted]")
            .field("issuer", &self.inner.issuer.as_ref().map(|_| "[redacted]"))
            .field("tenant", &self.tenant)
            .field("scope_count", &self.inner.scopes.len())
            .field("expires_at", &self.inner.expires_at)
            .field("method", &self.inner.method)
            .field("assurance", &self.inner.assurance.kind())
            .finish()
    }
}

impl ApiPrincipal {
    /// Validates and retains an authenticated rvoip principal.
    pub fn new(
        inner: AuthenticatedPrincipal,
        now: DateTime<Utc>,
    ) -> Result<Self, ApiPrincipalError> {
        let invalid_subject = inner.subject.trim().is_empty()
            || inner.subject.len() > MAX_BEARER_SUBJECT_BYTES
            || inner.subject.chars().any(char::is_control)
            || inner.issuer.as_ref().is_some_and(|issuer| {
                issuer.trim().is_empty()
                    || issuer.len() > MAX_BEARER_ISSUER_BYTES
                    || issuer.chars().any(char::is_control)
            });
        if invalid_subject {
            return Err(ApiPrincipalError::InvalidCredential);
        }
        if inner.is_expired_at(now) {
            return Err(ApiPrincipalError::ExpiredCredential);
        }
        let tenant = inner
            .tenant
            .as_deref()
            .ok_or(ApiPrincipalError::TenantRequired)
            .and_then(|tenant| {
                TenantId::parse(tenant).map_err(|_| ApiPrincipalError::InvalidTenant)
            })?;
        Ok(Self { inner, tenant })
    }

    /// Returns the complete transport-neutral authentication result.
    #[must_use]
    pub const fn authenticated(&self) -> &AuthenticatedPrincipal {
        &self.inner
    }

    /// Tenant established by the credential.
    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// Rechecks credential expiry and an operation scope at the handler boundary.
    pub fn authorize(&self, scope: CallScope, now: DateTime<Utc>) -> Result<(), ApiPrincipalError> {
        if self.inner.is_expired_at(now) {
            return Err(ApiPrincipalError::ExpiredCredential);
        }
        if !self.inner.has_scope(scope.as_str()) {
            return Err(ApiPrincipalError::MissingScope(scope.as_str()));
        }
        Ok(())
    }

    /// Resolves the tenant for an operation after checking both operation and
    /// administrative override scopes.
    pub fn resolve_tenant(
        &self,
        requested: Option<&str>,
        operation: CallScope,
        now: DateTime<Utc>,
    ) -> Result<TenantId, ApiPrincipalError> {
        self.authorize(operation, now)?;
        let Some(requested) = requested else {
            return Ok(self.tenant.clone());
        };
        let requested = TenantId::parse(requested).map_err(|_| ApiPrincipalError::InvalidTenant)?;
        if requested == self.tenant {
            return Ok(requested);
        }
        if !self.inner.has_scope(CallScope::TenantOverride.as_str()) {
            return Err(ApiPrincipalError::TenantOverrideForbidden);
        }
        Ok(requested)
    }
}

/// Validates HTTP Bearer credentials with a first-party rvoip validator.
#[derive(Clone)]
pub struct ApiBearerAuthenticator {
    validator: Arc<dyn BearerValidator>,
}

impl fmt::Debug for ApiBearerAuthenticator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiBearerAuthenticator")
            .field("validator", &"[configured]")
            .finish()
    }
}

impl ApiBearerAuthenticator {
    #[must_use]
    pub fn new(validator: Arc<dyn BearerValidator>) -> Self {
        Self { validator }
    }

    /// Parses one credential, validates it, and retains the complete principal.
    pub async fn authenticate(
        &self,
        headers: &HeaderMap,
        now: DateTime<Utc>,
    ) -> Result<ApiPrincipal, ApiPrincipalError> {
        let credential = parse_bearer(headers)?;
        let principal = self
            .validator
            .validate_principal(credential)
            .await
            .map_err(|_| ApiPrincipalError::InvalidCredential)?;
        ApiPrincipal::new(principal, now)
    }
}

fn parse_bearer(headers: &HeaderMap) -> Result<&str, ApiPrincipalError> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let value = values.next().ok_or(ApiPrincipalError::MissingCredential)?;
    if values.next().is_some() {
        return Err(ApiPrincipalError::MalformedCredential);
    }
    let value = value
        .to_str()
        .map_err(|_| ApiPrincipalError::MalformedCredential)?;
    if value.contains(',') {
        return Err(ApiPrincipalError::MalformedCredential);
    }
    let (scheme, credential) = value
        .split_once(' ')
        .ok_or(ApiPrincipalError::MalformedCredential)?;
    if !scheme.eq_ignore_ascii_case("Bearer")
        || credential.is_empty()
        || credential.len() > MAX_API_BEARER_BYTES
        || credential
            .bytes()
            .any(|byte| !(0x21..=0x7e).contains(&byte))
    {
        return Err(ApiPrincipalError::MalformedCredential);
    }
    Ok(credential)
}

/// Secret HMAC material used to derive non-reversible ownership fingerprints.
pub struct PrincipalFingerprintKey(Vec<u8>);

impl fmt::Debug for PrincipalFingerprintKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrincipalFingerprintKey([redacted])")
    }
}

impl Drop for PrincipalFingerprintKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl PrincipalFingerprintKey {
    pub fn new(bytes: Vec<u8>) -> Result<Self, ApiPrincipalError> {
        if !(MIN_FINGERPRINT_KEY_BYTES..=MAX_FINGERPRINT_KEY_BYTES).contains(&bytes.len()) {
            return Err(ApiPrincipalError::InvalidFingerprintKey);
        }
        Ok(Self(bytes))
    }

    /// Derives a stable fingerprint over issuer, tenant, and subject.
    pub fn derive(&self, principal: &ApiPrincipal) -> PrincipalFingerprint {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0)
            .expect("HMAC accepts keys within the validated bounds");
        mac.update(FINGERPRINT_DOMAIN);
        update_optional_field(&mut mac, principal.inner.issuer.as_deref());
        update_field(&mut mac, principal.tenant.as_str());
        update_field(&mut mac, &principal.inner.subject);
        let digest: [u8; 32] = mac.finalize().into_bytes().into();
        PrincipalFingerprint::new(digest)
    }
}

fn update_optional_field(mac: &mut Hmac<Sha256>, value: Option<&str>) {
    match value {
        Some(value) => {
            mac.update(&[1]);
            update_field(mac, value);
        }
        None => mac.update(&[0]),
    }
}

fn update_field(mac: &mut Hmac<Sha256>, value: &str) {
    let length = u32::try_from(value.len()).expect("validated principal fields fit u32");
    mac.update(&length.to_be_bytes());
    mac.update(value.as_bytes());
}

/// Source-compatible validator for the existing configured shared API key.
pub struct ConfiguredApiKeyValidator {
    key: Vec<u8>,
    principal: AuthenticatedPrincipal,
}

impl fmt::Debug for ConfiguredApiKeyValidator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfiguredApiKeyValidator")
            .field("key", &"[redacted]")
            .field("tenant", &self.principal.tenant)
            .finish()
    }
}

impl Drop for ConfiguredApiKeyValidator {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl ConfiguredApiKeyValidator {
    /// Creates a compatibility validator only when one tenant is unambiguous.
    pub fn new<I, S>(key: String, tenants: I) -> Result<Self, ApiPrincipalError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        if key.is_empty()
            || key.len() > MAX_API_BEARER_BYTES
            || key.contains(',')
            || key.bytes().any(|byte| !(0x21..=0x7e).contains(&byte))
        {
            return Err(ApiPrincipalError::InvalidStaticApiKey);
        }
        let tenants = tenants
            .into_iter()
            .map(|tenant| tenant.as_ref().to_owned())
            .collect::<BTreeSet<_>>();
        if tenants.len() != 1 {
            return Err(ApiPrincipalError::AmbiguousStaticTenant);
        }
        let tenant = tenants
            .into_iter()
            .next()
            .expect("one tenant was validated");
        TenantId::parse(&tenant).map_err(|_| ApiPrincipalError::InvalidTenant)?;
        let assurance = IdentityAssurance::Pseudonymous {
            ephemeral_key: Jwk(serde_json::json!({
                "kty": "oct",
                "kid": "bridgefu-static-api-key"
            })),
        };
        Ok(Self {
            key: key.into_bytes(),
            principal: AuthenticatedPrincipal {
                subject: "bridgefu-static-api-key".into(),
                tenant: Some(tenant),
                scopes: vec!["*".into()],
                issuer: Some("bridgefu:configured-api-key".into()),
                expires_at: None,
                method: AuthenticationMethod::ApiKey,
                assurance,
            },
        })
    }

    fn matches(&self, candidate: &str) -> bool {
        candidate.as_bytes().ct_eq(self.key.as_slice()).into()
    }
}

#[async_trait]
impl BearerValidator for ConfiguredApiKeyValidator {
    async fn validate(&self, token: &str) -> Result<IdentityAssurance, BearerAuthError> {
        if self.matches(token) {
            Ok(self.principal.assurance.clone())
        } else {
            Err(BearerAuthError::Invalid("invalid API key".into()))
        }
    }

    async fn validate_principal(
        &self,
        token: &str,
    ) -> Result<AuthenticatedPrincipal, BearerAuthError> {
        if self.matches(token) {
            Ok(self.principal.clone())
        } else {
            Err(BearerAuthError::Invalid("invalid API key".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use chrono::TimeZone;

    fn now() -> DateTime<Utc> {
        Utc.timestamp_opt(1_900_000_000, 0).unwrap()
    }

    fn principal(
        issuer: Option<&str>,
        tenant: Option<&str>,
        subject: &str,
        scopes: &[&str],
        expires_at: Option<DateTime<Utc>>,
    ) -> AuthenticatedPrincipal {
        AuthenticatedPrincipal {
            subject: subject.into(),
            tenant: tenant.map(str::to_owned),
            scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
            issuer: issuer.map(str::to_owned),
            expires_at,
            method: AuthenticationMethod::Jwt,
            assurance: IdentityAssurance::Pseudonymous {
                ephemeral_key: Jwk(serde_json::json!({"kty": "test"})),
            },
        }
    }

    struct FixedValidator(AuthenticatedPrincipal);

    #[async_trait]
    impl BearerValidator for FixedValidator {
        async fn validate(&self, token: &str) -> Result<IdentityAssurance, BearerAuthError> {
            if token == "valid-token" {
                Ok(self.0.assurance.clone())
            } else {
                Err(BearerAuthError::Invalid("invalid".into()))
            }
        }

        async fn validate_principal(
            &self,
            token: &str,
        ) -> Result<AuthenticatedPrincipal, BearerAuthError> {
            if token == "valid-token" {
                Ok(self.0.clone())
            } else {
                Err(BearerAuthError::Invalid("invalid".into()))
            }
        }
    }

    fn bearer(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        headers
    }

    #[tokio::test]
    async fn authenticator_retains_complete_principal_and_rechecks_expiry() {
        let expected = principal(
            Some("issuer-a"),
            Some("tenant-a"),
            "subject-a",
            &[CallScope::Read.as_str()],
            Some(now() + chrono::Duration::seconds(2)),
        );
        let authenticator = ApiBearerAuthenticator::new(Arc::new(FixedValidator(expected)));
        let authenticated = authenticator
            .authenticate(&bearer("bEaReR valid-token"), now())
            .await
            .unwrap();
        assert_eq!(authenticated.authenticated().subject, "subject-a");
        authenticated.authorize(CallScope::Read, now()).unwrap();
        assert_eq!(
            authenticated.authorize(CallScope::Read, now() + chrono::Duration::seconds(2)),
            Err(ApiPrincipalError::ExpiredCredential)
        );
    }

    #[tokio::test]
    async fn bearer_header_is_exactly_one_visible_unmerged_credential() {
        let authenticator = ApiBearerAuthenticator::new(Arc::new(FixedValidator(principal(
            Some("issuer"),
            Some("tenant"),
            "subject",
            &["*"],
            None,
        ))));
        assert!(matches!(
            authenticator.authenticate(&HeaderMap::new(), now()).await,
            Err(ApiPrincipalError::MissingCredential)
        ));
        for value in [
            "Basic value",
            "Bearer ",
            "Bearer two tokens",
            "Bearer one,two",
        ] {
            assert!(
                matches!(
                    authenticator.authenticate(&bearer(value), now()).await,
                    Err(ApiPrincipalError::MalformedCredential)
                ),
                "{value}"
            );
        }
        let mut duplicate = bearer("Bearer valid-token");
        duplicate.append(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer valid-token"),
        );
        assert!(matches!(
            authenticator.authenticate(&duplicate, now()).await,
            Err(ApiPrincipalError::MalformedCredential)
        ));
        assert!(matches!(
            authenticator
                .authenticate(&bearer("Bearer wrong-token"), now())
                .await,
            Err(ApiPrincipalError::InvalidCredential)
        ));
        let oversized = format!("Bearer {}", "x".repeat(MAX_API_BEARER_BYTES + 1));
        assert!(matches!(
            authenticator.authenticate(&bearer(&oversized), now()).await,
            Err(ApiPrincipalError::MalformedCredential)
        ));
        let mut non_utf8 = HeaderMap::new();
        non_utf8.insert(
            AUTHORIZATION,
            HeaderValue::from_bytes(b"Bearer \xff").unwrap(),
        );
        assert!(matches!(
            authenticator.authenticate(&non_utf8, now()).await,
            Err(ApiPrincipalError::MalformedCredential)
        ));
    }

    #[test]
    fn scopes_tenant_and_override_are_fail_closed() {
        let scoped = ApiPrincipal::new(
            principal(
                Some("issuer"),
                Some("tenant-a"),
                "subject",
                &[CallScope::Read.as_str()],
                None,
            ),
            now(),
        )
        .unwrap();
        assert_eq!(
            scoped.authorize(CallScope::Create, now()),
            Err(ApiPrincipalError::MissingScope("calls:create"))
        );
        assert_eq!(
            scoped.resolve_tenant(Some("tenant-b"), CallScope::Read, now()),
            Err(ApiPrincipalError::TenantOverrideForbidden)
        );
        assert_eq!(
            scoped.resolve_tenant(Some("tenant-a"), CallScope::Read, now()),
            Ok(TenantId::parse("tenant-a").unwrap())
        );

        let admin = ApiPrincipal::new(
            principal(
                Some("issuer"),
                Some("tenant-a"),
                "subject",
                &[CallScope::Read.as_str(), CallScope::TenantOverride.as_str()],
                None,
            ),
            now(),
        )
        .unwrap();
        assert_eq!(
            admin.resolve_tenant(Some("tenant-b"), CallScope::Read, now()),
            Ok(TenantId::parse("tenant-b").unwrap())
        );
        let wildcard = ApiPrincipal::new(
            principal(Some("issuer"), Some("tenant-a"), "subject", &["*"], None),
            now(),
        )
        .unwrap();
        for scope in [
            CallScope::Create,
            CallScope::Read,
            CallScope::Hangup,
            CallScope::Transfer,
            CallScope::Dtmf,
            CallScope::TenantOverride,
        ] {
            wildcard.authorize(scope, now()).unwrap();
        }
    }

    #[test]
    fn tenantless_expired_and_invalid_tenants_are_rejected() {
        assert_eq!(
            ApiPrincipal::new(
                principal(Some("issuer"), None, "subject", &["*"], None),
                now()
            )
            .unwrap_err(),
            ApiPrincipalError::TenantRequired
        );
        assert_eq!(
            ApiPrincipal::new(
                principal(
                    Some("issuer"),
                    Some("tenant"),
                    "subject",
                    &["*"],
                    Some(now())
                ),
                now()
            )
            .unwrap_err(),
            ApiPrincipalError::ExpiredCredential
        );
        assert_eq!(
            ApiPrincipal::new(
                principal(Some("issuer"), Some("bad tenant"), "subject", &["*"], None),
                now()
            )
            .unwrap_err(),
            ApiPrincipalError::InvalidTenant
        );
    }

    #[test]
    fn fingerprint_is_stable_domain_separated_and_debug_redacted() {
        let key = PrincipalFingerprintKey::new(vec![0x55; 32]).unwrap();
        let first = ApiPrincipal::new(
            principal(
                Some("issuer-a"),
                Some("tenant-a"),
                "subject-a",
                &["*"],
                None,
            ),
            now(),
        )
        .unwrap();
        let repeated = key.derive(&first);
        assert_eq!(key.derive(&first), repeated);
        for changed in [
            principal(
                Some("issuer-b"),
                Some("tenant-a"),
                "subject-a",
                &["*"],
                None,
            ),
            principal(
                Some("issuer-a"),
                Some("tenant-b"),
                "subject-a",
                &["*"],
                None,
            ),
            principal(
                Some("issuer-a"),
                Some("tenant-a"),
                "subject-b",
                &["*"],
                None,
            ),
        ] {
            assert_ne!(
                key.derive(&ApiPrincipal::new(changed, now()).unwrap()),
                repeated
            );
        }
        let debug = format!("{first:?} {key:?} {repeated:?}");
        assert!(!debug.contains("subject-a"));
        assert!(!debug.contains("issuer-a"));
        assert!(!debug.contains("555555"));
    }

    #[tokio::test]
    async fn configured_api_key_requires_one_tenant_and_never_debugs_key() {
        for invalid in [String::new(), "bad key".into(), "bad,key".into()] {
            assert_eq!(
                ConfiguredApiKeyValidator::new(invalid, ["tenant-a"]).unwrap_err(),
                ApiPrincipalError::InvalidStaticApiKey
            );
        }
        assert_eq!(
            ConfiguredApiKeyValidator::new("x".repeat(MAX_API_BEARER_BYTES + 1), ["tenant-a"])
                .unwrap_err(),
            ApiPrincipalError::InvalidStaticApiKey
        );
        assert_eq!(
            ConfiguredApiKeyValidator::new("key".into(), Vec::<String>::new()).unwrap_err(),
            ApiPrincipalError::AmbiguousStaticTenant
        );
        assert_eq!(
            ConfiguredApiKeyValidator::new("key".into(), ["a", "b"]).unwrap_err(),
            ApiPrincipalError::AmbiguousStaticTenant
        );
        let validator =
            ConfiguredApiKeyValidator::new("extremely-secret-key".into(), ["tenant-a", "tenant-a"])
                .unwrap();
        let debug = format!("{validator:?}");
        assert!(!debug.contains("extremely-secret-key"));
        assert_eq!(
            validator
                .validate_principal("extremely-secret-key")
                .await
                .unwrap()
                .tenant
                .as_deref(),
            Some("tenant-a")
        );
        assert!(validator.validate_principal("wrong").await.is_err());
    }
}
