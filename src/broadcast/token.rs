use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rvoip_auth_core::{
    AuthenticatedPrincipal, AuthenticationMethod, BearerAuthError, BearerValidator, ValidatedBearer,
};
use rvoip_core::identity::IdentityAssurance;
use rvoip_core::ids::{IdentityId, SessionId};
use rvoip_uctp::state::{
    ResourceBindingError, SessionBindingResolver, UCTP_RECEIVE_ONLY_SCOPE, UCTP_SESSION_SCOPE,
    UCTP_SUBSCRIBE_SCOPE,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroize;

pub const BRIDGEFU_BROADCAST_TOKEN_ISSUER: &str = "bridgefu";
pub const BRIDGEFU_BROADCAST_TOKEN_AUDIENCE: &str = "bridgefu-broadcast-subscriber";
pub const BRIDGEFU_BROADCAST_TOKEN_VERSION: u8 = 1;
pub const MAX_BROADCAST_TOKEN_BYTES: usize = 4 * 1024;
pub const DEFAULT_MAX_BROADCAST_TOKEN_TTL: Duration = Duration::from_secs(15 * 60);

const TOKEN_SUBJECT: &str = "bridgefu-broadcast-listener";
const MIN_HMAC_SECRET_BYTES: usize = 32;
const MAX_RESOURCE_ID_BYTES: usize = 256;
const SUBSCRIBE_SCOPE_PREFIX: &str = "broadcast:subscribe:";
const MAX_CREDENTIAL_ID_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BroadcastGrantTransport {
    Moqt,
    UctpQuic,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveBroadcastGrant {
    pub tenant_id: String,
    pub broadcast_id: String,
    pub transport: BroadcastGrantTransport,
    pub expires_at: DateTime<Utc>,
    pub(crate) generation: Uuid,
}

/// Cross-process active-grant authority used by standalone subscriber edges.
///
/// Token signature validation is not enough: a relay must also reject a
/// deleted, expired, wrong-tenant, or wrong-transport broadcast. Implementors
/// therefore fail closed on backend errors rather than returning `None`.
#[async_trait]
pub trait BroadcastGrantVerifier: Send + Sync {
    async fn active(
        &self,
        broadcast_id: &str,
    ) -> Result<Option<ActiveBroadcastGrant>, BroadcastTokenError>;

    async fn health_check(&self) -> Result<(), BroadcastTokenError>;
}

#[derive(Clone)]
pub struct BroadcastGrantRegistry {
    inner: Arc<GrantRegistryInner>,
}

struct GrantRegistryInner {
    active: DashMap<String, ActiveBroadcastGrant>,
    consumed_uctp_tokens: DashMap<String, ConsumedUctpToken>,
}

#[derive(Clone)]
struct ConsumedUctpToken {
    expires_at: DateTime<Utc>,
}

impl fmt::Debug for BroadcastGrantRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BroadcastGrantRegistry")
            .field("active_grants", &self.inner.active.len())
            .field(
                "consumed_uctp_tokens",
                &self.inner.consumed_uctp_tokens.len(),
            )
            .finish()
    }
}

impl Default for BroadcastGrantRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl BroadcastGrantRegistry {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(GrantRegistryInner {
                active: DashMap::new(),
                consumed_uctp_tokens: DashMap::new(),
            }),
        }
    }

    pub fn register(
        &self,
        tenant_id: impl Into<String>,
        broadcast_id: impl Into<String>,
        transport: BroadcastGrantTransport,
        expires_at: DateTime<Utc>,
    ) -> Result<BroadcastGrantLease, BroadcastTokenError> {
        let tenant_id = tenant_id.into();
        let broadcast_id = broadcast_id.into();
        validate_resource_id("tenant", &tenant_id)?;
        validate_resource_id("broadcast", &broadcast_id)?;
        if expires_at <= Utc::now() {
            return Err(BroadcastTokenError::Expired);
        }
        self.remove_expired();
        let generation = Uuid::new_v4();
        let grant = ActiveBroadcastGrant {
            tenant_id,
            broadcast_id: broadcast_id.clone(),
            transport,
            expires_at,
            generation,
        };
        match self.inner.active.entry(broadcast_id.clone()) {
            Entry::Occupied(_) => Err(BroadcastTokenError::Conflict),
            Entry::Vacant(entry) => {
                entry.insert(grant);
                Ok(BroadcastGrantLease {
                    registry: self.clone(),
                    broadcast_id,
                    generation,
                    active: true,
                })
            }
        }
    }

    pub fn active(&self, broadcast_id: &str) -> Option<ActiveBroadcastGrant> {
        let now = Utc::now();
        let grant = self.inner.active.get(broadcast_id)?.clone();
        if grant.expires_at <= now {
            self.revoke_generation(broadcast_id, grant.generation);
            return None;
        }
        Some(grant)
    }

    pub fn active_count(&self) -> usize {
        self.remove_expired();
        self.inner.active.len()
    }

    fn revoke_generation(&self, broadcast_id: &str, generation: Uuid) -> bool {
        self.inner
            .active
            .remove_if(broadcast_id, |_, grant| grant.generation == generation)
            .is_some()
    }

    fn remove_expired(&self) {
        let now = Utc::now();
        self.inner.active.retain(|_, grant| grant.expires_at > now);
        self.inner
            .consumed_uctp_tokens
            .retain(|_, binding| binding.expires_at > now);
    }

    fn authorize_uctp_session(
        &self,
        principal: &AuthenticatedPrincipal,
        wire_session: &SessionId,
    ) -> Result<SessionId, ResourceBindingError> {
        let canonical = SessionId::from_string(wire_session.as_str());
        self.authorize_bound_uctp_session(principal, wire_session, &canonical)?;

        let broadcast_id = canonical.as_str().to_owned();
        let grant = self
            .active(&broadcast_id)
            .ok_or_else(|| ResourceBindingError::forbidden("broadcast-inactive"))?;
        self.remove_expired();
        match self
            .inner
            .consumed_uctp_tokens
            .entry(principal.subject.clone())
        {
            Entry::Occupied(_) => Err(ResourceBindingError::forbidden("broadcast-token-replayed")),
            Entry::Vacant(entry) => {
                entry.insert(ConsumedUctpToken {
                    expires_at: principal.expires_at.unwrap_or(grant.expires_at),
                });
                Ok(canonical)
            }
        }
    }

    fn authorize_bound_uctp_session(
        &self,
        principal: &AuthenticatedPrincipal,
        wire_session: &SessionId,
        canonical_session: &SessionId,
    ) -> Result<(), ResourceBindingError> {
        if principal.is_expired() {
            return Err(ResourceBindingError::forbidden("principal-expired"));
        }
        let broadcast_id = exact_subscriber_broadcast(principal)?;
        if wire_session.as_str() != broadcast_id || canonical_session.as_str() != broadcast_id {
            return Err(ResourceBindingError::forbidden(
                "broadcast-session-mismatch",
            ));
        }
        let Some(grant) = self.active(&broadcast_id) else {
            return Err(ResourceBindingError::forbidden("broadcast-inactive"));
        };
        if grant.transport != BroadcastGrantTransport::UctpQuic {
            return Err(ResourceBindingError::forbidden(
                "broadcast-transport-mismatch",
            ));
        }
        if principal.tenant.as_deref() != Some(grant.tenant_id.as_str()) {
            return Err(ResourceBindingError::forbidden("broadcast-tenant-mismatch"));
        }
        if !principal
            .scopes
            .iter()
            .any(|scope| scope == UCTP_RECEIVE_ONLY_SCOPE)
        {
            return Err(ResourceBindingError::forbidden(
                "broadcast-receive-only-required",
            ));
        }
        Ok(())
    }

    fn extend_bound_uctp_session(
        &self,
        principal: &AuthenticatedPrincipal,
    ) -> Result<(), ResourceBindingError> {
        // A refreshed bearer retains the original listener subject while its
        // token ID and expiry rotate. Keep the single-use reservation alive
        // for the refreshed principal's full lifetime so a later refresh
        // credential cannot be replayed as a second physical peer after the
        // initial short-lived token expires.
        let Some(mut consumed) = self.inner.consumed_uctp_tokens.get_mut(&principal.subject) else {
            return Err(ResourceBindingError::forbidden(
                "broadcast-token-binding-missing",
            ));
        };
        if let Some(expires_at) = principal.expires_at {
            consumed.expires_at = consumed.expires_at.max(expires_at);
        }
        Ok(())
    }
}

pub(crate) fn exact_subscriber_broadcast(
    principal: &AuthenticatedPrincipal,
) -> Result<String, ResourceBindingError> {
    if principal.scopes.iter().any(|scope| {
        matches!(
            scope.as_str(),
            "*" | "broadcast:publish" | "broadcast:relay"
        )
    }) {
        return Err(ResourceBindingError::forbidden(
            "broadcast-subscriber-scope-required",
        ));
    }
    let mut matches = principal
        .scopes
        .iter()
        .filter_map(|scope| scope.strip_prefix(SUBSCRIBE_SCOPE_PREFIX));
    let Some(broadcast_id) = matches.next() else {
        return Err(ResourceBindingError::forbidden(
            "broadcast-subscriber-scope-required",
        ));
    };
    if matches.next().is_some() || validate_resource_id("broadcast", broadcast_id).is_err() {
        return Err(ResourceBindingError::forbidden(
            "broadcast-subscriber-scope-invalid",
        ));
    }
    Ok(broadcast_id.to_owned())
}

pub struct BroadcastGrantLease {
    registry: BroadcastGrantRegistry,
    broadcast_id: String,
    generation: Uuid,
    active: bool,
}

impl fmt::Debug for BroadcastGrantLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BroadcastGrantLease")
            .field("active", &self.active)
            .finish()
    }
}

impl BroadcastGrantLease {
    pub fn revoke(mut self) -> bool {
        let removed = self
            .registry
            .revoke_generation(&self.broadcast_id, self.generation);
        self.active = false;
        removed
    }
}

impl Drop for BroadcastGrantLease {
    fn drop(&mut self) {
        if self.active {
            self.registry
                .revoke_generation(&self.broadcast_id, self.generation);
            self.active = false;
        }
    }
}

#[derive(Clone)]
pub struct BroadcastSessionResolver {
    grants: BroadcastGrantRegistry,
}

impl BroadcastSessionResolver {
    pub fn new(grants: BroadcastGrantRegistry) -> Arc<Self> {
        Arc::new(Self { grants })
    }
}

impl SessionBindingResolver for BroadcastSessionResolver {
    fn resolve_session(
        &self,
        principal: &AuthenticatedPrincipal,
        wire_session: &SessionId,
    ) -> Result<SessionId, ResourceBindingError> {
        self.grants.authorize_uctp_session(principal, wire_session)
    }

    fn reauthorize_session(
        &self,
        principal: &AuthenticatedPrincipal,
        wire_session: &SessionId,
        canonical_session: &SessionId,
    ) -> Result<(), ResourceBindingError> {
        self.grants
            .authorize_bound_uctp_session(principal, wire_session, canonical_session)?;
        self.grants.extend_bound_uctp_session(principal)
    }
}

struct BroadcastTokenSecret(Vec<u8>);

impl fmt::Debug for BroadcastTokenSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BroadcastTokenSecret([redacted])")
    }
}

impl Drop for BroadcastTokenSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone)]
pub struct BroadcastTokenService {
    secret: Arc<BroadcastTokenSecret>,
    grants: BroadcastGrantRegistry,
    shared_verifier: Option<Arc<dyn BroadcastGrantVerifier>>,
    max_ttl: Duration,
}

impl fmt::Debug for BroadcastTokenService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BroadcastTokenService")
            .field("secret", &self.secret)
            .field("grants", &self.grants)
            .field("shared_verifier", &self.shared_verifier.is_some())
            .field("max_ttl", &self.max_ttl)
            .finish()
    }
}

impl BroadcastTokenService {
    pub fn new(
        secret: impl Into<Vec<u8>>,
        grants: BroadcastGrantRegistry,
        max_ttl: Duration,
    ) -> Result<Self, BroadcastTokenError> {
        let secret = secret.into();
        if secret.len() < MIN_HMAC_SECRET_BYTES {
            return Err(BroadcastTokenError::WeakSecret);
        }
        if max_ttl.is_zero() || max_ttl > DEFAULT_MAX_BROADCAST_TOKEN_TTL {
            return Err(BroadcastTokenError::InvalidTtl);
        }
        Ok(Self {
            secret: Arc::new(BroadcastTokenSecret(secret)),
            grants,
            shared_verifier: None,
            max_ttl,
        })
    }

    /// Validate against a cross-process active-grant authority.
    ///
    /// Issuance still uses this service's local exact-generation registry; the
    /// managed publisher projects an independently fenced grant before
    /// returning a usable broadcast. Relay-only processes use an empty local
    /// registry and this verifier.
    pub fn with_shared_verifier(mut self, verifier: Arc<dyn BroadcastGrantVerifier>) -> Self {
        self.shared_verifier = Some(verifier);
        self
    }

    pub fn grants(&self) -> BroadcastGrantRegistry {
        self.grants.clone()
    }

    pub fn issue(
        &self,
        tenant_id: &str,
        broadcast_id: &str,
        requested_ttl: Duration,
    ) -> Result<IssuedBroadcastToken, BroadcastTokenError> {
        self.issue_for_credential(
            tenant_id,
            broadcast_id,
            requested_ttl,
            Uuid::new_v4().to_string(),
        )
    }

    /// Issues against the configured cross-process grant authority. Split
    /// gateways have no process-local publisher registry, so this is the only
    /// safe issuance path for worker-created broadcasts.
    pub async fn issue_authorized(
        &self,
        tenant_id: &str,
        broadcast_id: &str,
        requested_ttl: Duration,
    ) -> Result<IssuedBroadcastToken, BroadcastTokenError> {
        self.issue_authorized_for_credential(
            tenant_id,
            broadcast_id,
            requested_ttl,
            Uuid::new_v4().to_string(),
        )
        .await
    }

    /// Rotate one still-valid subscriber bearer without changing the
    /// authenticated listener's ownership key.
    ///
    /// UCTP sessions use this with `auth.refresh`: every JWT gets a fresh
    /// replay identifier, while `credential_id` remains stable for that one
    /// listener. The original credential must still validate, and both the
    /// requested lifetime and active broadcast grant remain authoritative.
    pub async fn refresh(
        &self,
        current_token: &str,
        requested_ttl: Duration,
    ) -> Result<IssuedBroadcastToken, BroadcastTokenError> {
        let claims = self.validate_claims(current_token).await?;
        let credential_id = claims
            .credential_id
            .clone()
            .unwrap_or_else(|| claims.jti.clone());
        self.issue_authorized_for_credential(
            &claims.tenant_id,
            &claims.broadcast_id,
            requested_ttl,
            credential_id,
        )
        .await
    }

    async fn issue_authorized_for_credential(
        &self,
        tenant_id: &str,
        broadcast_id: &str,
        requested_ttl: Duration,
        credential_id: String,
    ) -> Result<IssuedBroadcastToken, BroadcastTokenError> {
        let grant = match &self.shared_verifier {
            Some(verifier) => verifier.active(broadcast_id).await?,
            None => self.grants.active(broadcast_id),
        }
        .ok_or(BroadcastTokenError::Inactive)?;
        self.issue_with_grant(tenant_id, broadcast_id, requested_ttl, credential_id, grant)
    }

    fn issue_for_credential(
        &self,
        tenant_id: &str,
        broadcast_id: &str,
        requested_ttl: Duration,
        credential_id: String,
    ) -> Result<IssuedBroadcastToken, BroadcastTokenError> {
        if requested_ttl.is_zero() {
            return Err(BroadcastTokenError::InvalidTtl);
        }
        validate_credential_id(&credential_id)?;
        let grant = self
            .grants
            .active(broadcast_id)
            .ok_or(BroadcastTokenError::Inactive)?;
        self.issue_with_grant(tenant_id, broadcast_id, requested_ttl, credential_id, grant)
    }

    fn issue_with_grant(
        &self,
        tenant_id: &str,
        broadcast_id: &str,
        requested_ttl: Duration,
        credential_id: String,
        grant: ActiveBroadcastGrant,
    ) -> Result<IssuedBroadcastToken, BroadcastTokenError> {
        if requested_ttl.is_zero() {
            return Err(BroadcastTokenError::InvalidTtl);
        }
        validate_credential_id(&credential_id)?;
        if grant.tenant_id != tenant_id {
            return Err(BroadcastTokenError::OwnershipMismatch);
        }
        let now = Utc::now();
        let requested_ttl = requested_ttl.min(self.max_ttl);
        let requested_expiry = now
            + chrono::Duration::from_std(requested_ttl)
                .map_err(|_| BroadcastTokenError::InvalidTtl)?;
        let expires_at = requested_expiry.min(grant.expires_at);
        if expires_at.timestamp() <= now.timestamp() {
            return Err(BroadcastTokenError::Expired);
        }
        let scope = format!("{SUBSCRIBE_SCOPE_PREFIX}{broadcast_id}");
        let claims = BroadcastTokenClaims {
            iss: BRIDGEFU_BROADCAST_TOKEN_ISSUER.to_owned(),
            aud: BRIDGEFU_BROADCAST_TOKEN_AUDIENCE.to_owned(),
            sub: TOKEN_SUBJECT.to_owned(),
            tenant_id: tenant_id.to_owned(),
            broadcast_id: broadcast_id.to_owned(),
            scope: scope.clone(),
            iat: now.timestamp(),
            nbf: now.timestamp(),
            exp: expires_at.timestamp(),
            jti: Uuid::new_v4().to_string(),
            credential_id: Some(credential_id),
            ver: BRIDGEFU_BROADCAST_TOKEN_VERSION,
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(&self.secret.0),
        )
        .map_err(|_| BroadcastTokenError::Signing)?;
        Ok(IssuedBroadcastToken {
            token,
            expires_at,
            scope,
        })
    }

    async fn validate_token(&self, token: &str) -> Result<ValidatedBearer, BroadcastTokenError> {
        let claims = self.validate_claims(token).await?;
        let expires_at =
            DateTime::from_timestamp(claims.exp, 0).ok_or(BroadcastTokenError::Invalid)?;
        let issued_at =
            DateTime::from_timestamp(claims.iat, 0).ok_or(BroadcastTokenError::Invalid)?;
        let scope = claims.scope;
        let scopes = vec![
            scope,
            UCTP_SESSION_SCOPE.to_owned(),
            UCTP_SUBSCRIBE_SCOPE.to_owned(),
            UCTP_RECEIVE_ONLY_SCOPE.to_owned(),
        ];
        let identity = IdentityId::from_string(TOKEN_SUBJECT);
        let assurance = IdentityAssurance::TaskScoped {
            identity,
            task_id: claims.broadcast_id,
            scopes: scopes.clone(),
            expires_at,
        };
        let stable_credential_id = claims.credential_id.as_deref().unwrap_or(&claims.jti);
        let subject_digest = Sha256::digest(stable_credential_id.as_bytes());
        let subject = format!("broadcast-listener:sha256:{subject_digest:x}");
        ValidatedBearer::new(
            AuthenticatedPrincipal {
                subject,
                tenant: Some(claims.tenant_id),
                scopes,
                issuer: Some(BRIDGEFU_BROADCAST_TOKEN_ISSUER.to_owned()),
                expires_at: Some(expires_at),
                method: AuthenticationMethod::Jwt,
                assurance,
            },
            Some(claims.jti),
            Some(SystemTime::from(issued_at)),
        )
        .map_err(|_| BroadcastTokenError::Invalid)
    }

    async fn validate_claims(
        &self,
        token: &str,
    ) -> Result<BroadcastTokenClaims, BroadcastTokenError> {
        if token.is_empty() {
            return Err(BroadcastTokenError::Empty);
        }
        if token.len() > MAX_BROADCAST_TOKEN_BYTES {
            return Err(BroadcastTokenError::Oversized);
        }
        let mut validation = Validation::new(Algorithm::HS256);
        validation.algorithms = vec![Algorithm::HS256];
        validation.set_issuer(&[BRIDGEFU_BROADCAST_TOKEN_ISSUER]);
        validation.set_audience(&[BRIDGEFU_BROADCAST_TOKEN_AUDIENCE]);
        validation.required_spec_claims = HashSet::from([
            "iss".to_owned(),
            "aud".to_owned(),
            "sub".to_owned(),
            "exp".to_owned(),
            "nbf".to_owned(),
            "iat".to_owned(),
        ]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.leeway = 0;
        let claims = decode::<BroadcastTokenClaims>(
            token,
            &DecodingKey::from_secret(&self.secret.0),
            &validation,
        )
        .map_err(|_| BroadcastTokenError::Invalid)?
        .claims;
        if claims.ver != BRIDGEFU_BROADCAST_TOKEN_VERSION || claims.sub != TOKEN_SUBJECT {
            return Err(BroadcastTokenError::Invalid);
        }
        validate_resource_id("tenant", &claims.tenant_id)?;
        validate_resource_id("broadcast", &claims.broadcast_id)?;
        if claims.scope != format!("{SUBSCRIBE_SCOPE_PREFIX}{}", claims.broadcast_id) {
            return Err(BroadcastTokenError::InvalidScope);
        }
        if claims.jti.is_empty()
            || claims.jti.len() > 128
            || claims.jti.chars().any(char::is_control)
        {
            return Err(BroadcastTokenError::Invalid);
        }
        if let Some(credential_id) = claims.credential_id.as_deref() {
            validate_credential_id(credential_id)?;
        }
        let now = Utc::now().timestamp();
        if claims.iat > now || claims.nbf > now || claims.exp <= now || claims.exp <= claims.iat {
            return Err(BroadcastTokenError::Expired);
        }
        let lifetime =
            u64::try_from(claims.exp - claims.iat).map_err(|_| BroadcastTokenError::InvalidTtl)?;
        if lifetime > self.max_ttl.as_secs() {
            return Err(BroadcastTokenError::InvalidTtl);
        }
        let expires_at =
            DateTime::from_timestamp(claims.exp, 0).ok_or(BroadcastTokenError::Invalid)?;
        DateTime::from_timestamp(claims.iat, 0).ok_or(BroadcastTokenError::Invalid)?;
        let grant = match &self.shared_verifier {
            Some(verifier) => verifier.active(&claims.broadcast_id).await?,
            None => self.grants.active(&claims.broadcast_id),
        }
        .ok_or(BroadcastTokenError::Inactive)?;
        if grant.tenant_id != claims.tenant_id || expires_at > grant.expires_at {
            return Err(BroadcastTokenError::OwnershipMismatch);
        }
        Ok(claims)
    }
}

#[async_trait]
impl BearerValidator for BroadcastTokenService {
    async fn validate(&self, token: &str) -> Result<IdentityAssurance, BearerAuthError> {
        Ok(self.validate_credential(token).await?.principal.assurance)
    }

    async fn validate_principal(
        &self,
        token: &str,
    ) -> Result<AuthenticatedPrincipal, BearerAuthError> {
        Ok(self.validate_credential(token).await?.principal)
    }

    async fn validate_credential(&self, token: &str) -> Result<ValidatedBearer, BearerAuthError> {
        self.validate_token(token).await.map_err(Into::into)
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct IssuedBroadcastToken {
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub scope: String,
}

impl fmt::Debug for IssuedBroadcastToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedBroadcastToken")
            .field("token", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .field("scope", &self.scope)
            .finish()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BroadcastTokenClaims {
    iss: String,
    aud: String,
    sub: String,
    tenant_id: String,
    broadcast_id: String,
    scope: String,
    iat: i64,
    nbf: i64,
    exp: i64,
    jti: String,
    /// Stable ownership lineage for one listener. Tokens issued before this
    /// field existed remain valid and fall back to their one-shot `jti`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    credential_id: Option<String>,
    ver: u8,
}

fn validate_credential_id(value: &str) -> Result<(), BroadcastTokenError> {
    if value.is_empty()
        || value.len() > MAX_CREDENTIAL_ID_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(BroadcastTokenError::Invalid);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BroadcastTokenError {
    #[error("broadcast token is empty")]
    Empty,
    #[error("broadcast token exceeds its size limit")]
    Oversized,
    #[error("broadcast token is invalid")]
    Invalid,
    #[error("broadcast token scope is invalid")]
    InvalidScope,
    #[error("broadcast token TTL is invalid")]
    InvalidTtl,
    #[error("broadcast token or grant is expired")]
    Expired,
    #[error("broadcast is inactive")]
    Inactive,
    #[error("broadcast ownership does not match")]
    OwnershipMismatch,
    #[error("broadcast identifier is invalid")]
    InvalidIdentifier,
    #[error("broadcast token secret is too short")]
    WeakSecret,
    #[error("broadcast token signing failed")]
    Signing,
    #[error("broadcast grant already exists")]
    Conflict,
    #[error("broadcast grant authority is unavailable")]
    AuthorityUnavailable,
}

impl From<BroadcastTokenError> for BearerAuthError {
    fn from(error: BroadcastTokenError) -> Self {
        match error {
            BroadcastTokenError::Empty => Self::Empty,
            _ => Self::Invalid(error.to_string()),
        }
    }
}

pub(super) fn validate_resource_id(_kind: &str, value: &str) -> Result<(), BroadcastTokenError> {
    if value.is_empty()
        || value.len() > MAX_RESOURCE_ID_BYTES
        || value.chars().any(char::is_control)
        || value.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'))
        })
    {
        return Err(BroadcastTokenError::InvalidIdentifier);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SharedVerifier {
        grant: Option<ActiveBroadcastGrant>,
        unavailable: bool,
    }

    #[async_trait]
    impl BroadcastGrantVerifier for SharedVerifier {
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

    fn service(
        transport: BroadcastGrantTransport,
    ) -> (BroadcastTokenService, BroadcastGrantLease, DateTime<Utc>) {
        let grants = BroadcastGrantRegistry::new();
        let expires_at = Utc::now() + chrono::Duration::minutes(10);
        let lease = grants
            .register("tenant-a", "broadcast-a", transport, expires_at)
            .unwrap();
        let service = BroadcastTokenService::new(
            b"0123456789abcdef0123456789abcdef".to_vec(),
            grants,
            Duration::from_secs(300),
        )
        .unwrap();
        (service, lease, expires_at)
    }

    #[tokio::test]
    async fn issued_token_retains_exact_receive_only_principal_and_metadata() {
        let (service, _lease, _) = service(BroadcastGrantTransport::UctpQuic);
        let issued = service
            .issue("tenant-a", "broadcast-a", Duration::from_secs(60))
            .unwrap();
        let validated = service.validate_credential(&issued.token).await.unwrap();
        assert_eq!(validated.principal.tenant.as_deref(), Some("tenant-a"));
        assert_eq!(
            validated.principal.issuer.as_deref(),
            Some(BRIDGEFU_BROADCAST_TOKEN_ISSUER)
        );
        assert!(validated
            .principal
            .scopes
            .contains(&"broadcast:subscribe:broadcast-a".to_owned()));
        assert!(validated
            .principal
            .scopes
            .contains(&UCTP_RECEIVE_ONLY_SCOPE.to_owned()));
        assert!(!validated.principal.has_scope("broadcast:publish"));
        assert!(!validated.principal.has_scope("broadcast:relay"));
        assert!(validated.token_id.is_some());
        assert!(validated.issued_at.is_some());
        assert!(format!("{service:?}").contains("[redacted]"));
        assert!(!format!("{service:?}").contains("0123456789abcdef"));
        let issued_debug = format!("{issued:?}");
        assert!(issued_debug.contains("[redacted]"));
        assert!(!issued_debug.contains(&issued.token));
    }

    #[tokio::test]
    async fn refreshed_uctp_token_rotates_replay_id_but_retains_listener_owner() {
        let (service, _lease, _) = service(BroadcastGrantTransport::UctpQuic);
        let issued = service
            .issue("tenant-a", "broadcast-a", Duration::from_secs(60))
            .unwrap();
        let original = service.validate_credential(&issued.token).await.unwrap();
        let refreshed = service
            .refresh(&issued.token, Duration::from_secs(120))
            .await
            .unwrap();
        let rotated = service.validate_credential(&refreshed.token).await.unwrap();

        assert_ne!(original.token_id, rotated.token_id);
        assert_eq!(
            original.principal.ownership_key(),
            rotated.principal.ownership_key()
        );
        assert!(rotated.principal.expires_at >= original.principal.expires_at);

        let resolver = BroadcastSessionResolver::new(service.grants());
        let session = SessionId::from_string("broadcast-a");
        resolver
            .resolve_session(&original.principal, &session)
            .expect("initial token binds the listener exactly once");
        resolver
            .reauthorize_session(&rotated.principal, &session, &session)
            .expect("rotated token extends the existing listener binding");
        assert_eq!(
            resolver
                .resolve_session(&rotated.principal, &session)
                .unwrap_err()
                .reason,
            "broadcast-token-replayed"
        );
    }

    #[tokio::test]
    async fn revocation_invalidates_an_already_issued_token() {
        let (service, lease, _) = service(BroadcastGrantTransport::Moqt);
        let issued = service
            .issue("tenant-a", "broadcast-a", Duration::from_secs(60))
            .unwrap();
        assert!(service.validate_credential(&issued.token).await.is_ok());
        assert!(lease.revoke());
        assert!(service.validate_credential(&issued.token).await.is_err());
    }

    #[tokio::test]
    async fn wrong_algorithm_and_oversized_tokens_are_rejected() {
        let (service, _lease, _) = service(BroadcastGrantTransport::Moqt);
        let now = Utc::now();
        let claims = BroadcastTokenClaims {
            iss: BRIDGEFU_BROADCAST_TOKEN_ISSUER.into(),
            aud: BRIDGEFU_BROADCAST_TOKEN_AUDIENCE.into(),
            sub: TOKEN_SUBJECT.into(),
            tenant_id: "tenant-a".into(),
            broadcast_id: "broadcast-a".into(),
            scope: "broadcast:subscribe:broadcast-a".into(),
            iat: now.timestamp(),
            nbf: now.timestamp(),
            exp: (now + chrono::Duration::seconds(60)).timestamp(),
            jti: Uuid::new_v4().to_string(),
            credential_id: Some(Uuid::new_v4().to_string()),
            ver: BRIDGEFU_BROADCAST_TOKEN_VERSION,
        };
        let token = encode(
            &Header::new(Algorithm::HS384),
            &claims,
            &EncodingKey::from_secret(&service.secret.0),
        )
        .unwrap();
        assert!(service.validate_credential(&token).await.is_err());
        assert!(service
            .validate_credential(&"x".repeat(MAX_BROADCAST_TOKEN_BYTES + 1))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn uctp_resolver_binds_exact_transport_tenant_and_single_use_token() {
        let (service, lease, _) = service(BroadcastGrantTransport::UctpQuic);
        let issued = service
            .issue("tenant-a", "broadcast-a", Duration::from_secs(60))
            .unwrap();
        let principal = service.validate_principal(&issued.token).await.unwrap();
        let resolver = BroadcastSessionResolver::new(service.grants());
        let wire = SessionId::from_string("broadcast-a");
        assert_eq!(
            resolver.resolve_session(&principal, &wire).unwrap(),
            SessionId::from_string("broadcast-a")
        );
        assert_eq!(
            resolver
                .resolve_session(&principal, &wire)
                .unwrap_err()
                .reason,
            "broadcast-token-replayed"
        );
        resolver
            .reauthorize_session(&principal, &wire, &SessionId::from_string("broadcast-a"))
            .expect("an active consumed token remains authorized for its bound Session");
        assert!(lease.revoke());
        assert_eq!(
            resolver
                .reauthorize_session(&principal, &wire, &SessionId::from_string("broadcast-a"))
                .unwrap_err()
                .reason,
            "broadcast-inactive"
        );
    }

    #[tokio::test]
    async fn uctp_resolver_rejects_moq_grant_and_cross_broadcast_session() {
        let (service, _lease, _) = service(BroadcastGrantTransport::Moqt);
        let issued = service
            .issue("tenant-a", "broadcast-a", Duration::from_secs(60))
            .unwrap();
        let principal = service.validate_principal(&issued.token).await.unwrap();
        let resolver = BroadcastSessionResolver::new(service.grants());
        assert_eq!(
            resolver
                .resolve_session(&principal, &SessionId::from_string("broadcast-b"))
                .unwrap_err()
                .reason,
            "broadcast-session-mismatch"
        );
        assert_eq!(
            resolver
                .resolve_session(&principal, &SessionId::from_string("broadcast-a"))
                .unwrap_err()
                .reason,
            "broadcast-transport-mismatch"
        );
    }

    #[tokio::test]
    async fn standalone_validator_uses_shared_grants_and_fails_closed_on_backend_loss() {
        let (issuer, _lease, _) = service(BroadcastGrantTransport::Moqt);
        let issued = issuer
            .issue("tenant-a", "broadcast-a", Duration::from_secs(60))
            .unwrap();
        let active = issuer.grants().active("broadcast-a").unwrap();
        let validator = BroadcastTokenService::new(
            b"0123456789abcdef0123456789abcdef".to_vec(),
            BroadcastGrantRegistry::new(),
            Duration::from_secs(300),
        )
        .unwrap()
        .with_shared_verifier(Arc::new(SharedVerifier {
            grant: Some(active),
            unavailable: false,
        }));
        assert!(validator.validate_credential(&issued.token).await.is_ok());

        let unavailable = BroadcastTokenService::new(
            b"0123456789abcdef0123456789abcdef".to_vec(),
            BroadcastGrantRegistry::new(),
            Duration::from_secs(300),
        )
        .unwrap()
        .with_shared_verifier(Arc::new(SharedVerifier {
            grant: None,
            unavailable: true,
        }));
        assert!(unavailable
            .validate_credential(&issued.token)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn gateway_issuer_uses_shared_authority_without_process_local_grant() {
        let (worker, _lease, _) = service(BroadcastGrantTransport::Moqt);
        let active = worker.grants().active("broadcast-a").unwrap();
        let gateway = BroadcastTokenService::new(
            b"0123456789abcdef0123456789abcdef".to_vec(),
            BroadcastGrantRegistry::new(),
            Duration::from_secs(300),
        )
        .unwrap()
        .with_shared_verifier(Arc::new(SharedVerifier {
            grant: Some(active),
            unavailable: false,
        }));
        assert!(gateway
            .issue("tenant-a", "broadcast-a", Duration::from_secs(60))
            .is_err());
        let issued = gateway
            .issue_authorized("tenant-a", "broadcast-a", Duration::from_secs(60))
            .await
            .unwrap();
        assert!(gateway.validate_credential(&issued.token).await.is_ok());
    }
}
