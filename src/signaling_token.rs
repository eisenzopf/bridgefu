//! Short-lived, attachment-bound credentials for browser WebRTC signaling.
//!
//! The public REST credential is deliberately not accepted as browser
//! material. A route call instead receives a domain-separated JWT that keeps
//! the creator's issuer/tenant/subject ownership identity, grants only
//! `webrtc:connect`, expires no later than the one-use attachment, and is
//! cryptographically bound to that exact attachment hint.

use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rvoip_auth_core::{
    AuthenticatedPrincipal, AuthenticationMethod, BearerAuthError, BearerValidator, ValidatedBearer,
};
use rvoip_core::identity::IdentityAssurance;
use rvoip_core::ids::IdentityId;
use rvoip_webrtc::signaling::auth::{AuthRejection, WsBearerSessionBinding};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::call_engine::{CallId, LegId, TenantId};

pub const SIGNALING_TOKEN_USAGE: &str = "bridgefu-webrtc-signaling";
pub const SIGNALING_TOKEN_SCOPE: &str = "webrtc:connect";
pub const SIGNALING_TOKEN_PREFIX: &str = "bfs1.";
pub const SIGNALING_TOKEN_ISSUER: &str = "bridgefu:webrtc-signaling";
pub const SIGNALING_TOKEN_AUDIENCE: &str = "bridgefu-webrtc";
pub const SIGNALING_TOKEN_VERSION: u8 = 1;
pub const MAX_SIGNALING_TOKEN_TTL: Duration = Duration::from_secs(2 * 60);

const KEY_DOMAIN: &[u8] = b"bridgefu.webrtc-signaling-key.v1\0";
const MIN_SECRET_BYTES: usize = 32;
const MAX_SECRET_BYTES: usize = 4_096;
const MAX_TOKEN_BYTES: usize = 8 * 1_024;
const MAX_IDENTITY_BYTES: usize = 1_024;

#[derive(Debug, Error)]
pub enum SignalingTokenError {
    #[error("signaling-token key must contain 32 to 4096 bytes")]
    InvalidSecret,
    #[error("signaling-token principal is not eligible")]
    InvalidPrincipal,
    #[error("signaling-token expiry is invalid")]
    InvalidExpiry,
    #[error("signaling-token could not be signed")]
    Signing,
    #[error("signaling-token is invalid")]
    Invalid,
}

struct SigningSecret([u8; 32]);

impl fmt::Debug for SigningSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SigningSecret([redacted])")
    }
}

impl Drop for SigningSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Stateless authority shared by route creation and WebSocket admission.
pub struct SignalingTokenService {
    secret: SigningSecret,
}

impl fmt::Debug for SignalingTokenService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignalingTokenService")
            .field("secret", &"[configured]")
            .finish()
    }
}

impl SignalingTokenService {
    pub fn new(mut control_key: Vec<u8>) -> Result<Self, SignalingTokenError> {
        if !(MIN_SECRET_BYTES..=MAX_SECRET_BYTES).contains(&control_key.len()) {
            control_key.zeroize();
            return Err(SignalingTokenError::InvalidSecret);
        }
        let mut derivation = Hmac::<Sha256>::new_from_slice(&control_key)
            .expect("HMAC accepts validated control keys");
        derivation.update(KEY_DOMAIN);
        let secret = SigningSecret(derivation.finalize().into_bytes().into());
        control_key.zeroize();
        Ok(Self { secret })
    }

    pub fn issue(
        &self,
        principal: &AuthenticatedPrincipal,
        call_id: CallId,
        leg_id: LegId,
        attachment_token: &str,
        attachment_expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<IssuedSignalingToken, SignalingTokenError> {
        validate_identity(principal)?;
        if attachment_token.is_empty() || attachment_token.len() > MAX_IDENTITY_BYTES {
            return Err(SignalingTokenError::Invalid);
        }
        let maximum_expiry = now
            + chrono::Duration::from_std(MAX_SIGNALING_TOKEN_TTL)
                .map_err(|_| SignalingTokenError::InvalidExpiry)?;
        let mut expires_at = attachment_expires_at.min(maximum_expiry);
        if let Some(principal_expiry) = principal.expires_at {
            expires_at = expires_at.min(principal_expiry);
        }
        if expires_at <= now {
            return Err(SignalingTokenError::InvalidExpiry);
        }
        let attachment_digest = format!("{:x}", Sha256::digest(attachment_token.as_bytes()));
        let claims = SignalingTokenClaims {
            iss: SIGNALING_TOKEN_ISSUER.to_owned(),
            aud: SIGNALING_TOKEN_AUDIENCE.to_owned(),
            sub: principal.subject.clone(),
            principal_issuer: principal.issuer.clone(),
            tenant_id: principal
                .tenant
                .clone()
                .ok_or(SignalingTokenError::InvalidPrincipal)?,
            call_id: call_id.to_string(),
            leg_id: leg_id.to_string(),
            attachment_digest,
            scope: SIGNALING_TOKEN_SCOPE.to_owned(),
            exp: expires_at.timestamp(),
            nbf: now.timestamp(),
            iat: now.timestamp(),
            jti: Uuid::new_v4().to_string(),
            ver: SIGNALING_TOKEN_VERSION,
        };
        let encoded = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(&self.secret.0),
        )
        .map_err(|_| SignalingTokenError::Signing)?;
        Ok(IssuedSignalingToken {
            token: format!("{SIGNALING_TOKEN_PREFIX}{encoded}"),
            expires_at,
        })
    }

    fn validate_claims(&self, token: &str) -> Result<SignalingTokenClaims, SignalingTokenError> {
        if token.len() > MAX_TOKEN_BYTES || token.chars().any(char::is_control) {
            return Err(SignalingTokenError::Invalid);
        }
        let encoded = token
            .strip_prefix(SIGNALING_TOKEN_PREFIX)
            .ok_or(SignalingTokenError::Invalid)?;
        let mut validation = Validation::new(Algorithm::HS256);
        validation.algorithms = vec![Algorithm::HS256];
        validation.set_issuer(&[SIGNALING_TOKEN_ISSUER]);
        validation.set_audience(&[SIGNALING_TOKEN_AUDIENCE]);
        validation.required_spec_claims = HashSet::from([
            "iss".to_owned(),
            "aud".to_owned(),
            "sub".to_owned(),
            "exp".to_owned(),
            "nbf".to_owned(),
            "iat".to_owned(),
            "jti".to_owned(),
        ]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.leeway = 0;
        let claims = decode::<SignalingTokenClaims>(
            encoded,
            &DecodingKey::from_secret(&self.secret.0),
            &validation,
        )
        .map_err(|_| SignalingTokenError::Invalid)?
        .claims;
        validate_claims_shape(&claims)?;
        Ok(claims)
    }

    fn principal_from_claims(
        claims: SignalingTokenClaims,
    ) -> Result<ValidatedBearer, SignalingTokenError> {
        let expires_at =
            DateTime::from_timestamp(claims.exp, 0).ok_or(SignalingTokenError::InvalidExpiry)?;
        let issued_at =
            DateTime::from_timestamp(claims.iat, 0).ok_or(SignalingTokenError::InvalidExpiry)?;
        let scopes = vec![SIGNALING_TOKEN_SCOPE.to_owned()];
        let assurance = IdentityAssurance::TaskScoped {
            identity: IdentityId::from_string(&claims.sub),
            task_id: claims.call_id.clone(),
            scopes: scopes.clone(),
            expires_at,
        };
        ValidatedBearer::new(
            AuthenticatedPrincipal {
                subject: claims.sub,
                tenant: Some(claims.tenant_id),
                scopes,
                // Preserve the API principal's ownership identity. The JWT's
                // own cryptographic issuer remains fixed in `iss` above.
                issuer: claims.principal_issuer,
                expires_at: Some(expires_at),
                method: AuthenticationMethod::Jwt,
                assurance,
            },
            Some(claims.jti),
            Some(SystemTime::from(issued_at)),
        )
        .map_err(|_| SignalingTokenError::Invalid)
    }
}

#[async_trait]
impl BearerValidator for SignalingTokenService {
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
        let claims = self
            .validate_claims(token)
            .map_err(|_| BearerAuthError::Invalid("invalid signaling credential".into()))?;
        Self::principal_from_claims(claims)
            .map_err(|_| BearerAuthError::Invalid("invalid signaling credential".into()))
    }
}

#[async_trait]
impl WsBearerSessionBinding for SignalingTokenService {
    async fn authorize(
        &self,
        bearer: &str,
        session_hint: &str,
        principal: &AuthenticatedPrincipal,
    ) -> Result<(), AuthRejection> {
        let claims = self
            .validate_claims(bearer)
            .map_err(|_| AuthRejection::Forbidden)?;
        let expected_digest = format!("{:x}", Sha256::digest(session_hint.as_bytes()));
        let exact_attachment = claims
            .attachment_digest
            .as_bytes()
            .ct_eq(expected_digest.as_bytes())
            .into();
        let exact_principal = claims.sub == principal.subject
            && claims.tenant_id.as_str() == principal.tenant.as_deref().unwrap_or_default()
            && claims.principal_issuer == principal.issuer
            && principal.scopes.len() == 1
            && principal.has_scope(SIGNALING_TOKEN_SCOPE);
        if exact_attachment && exact_principal {
            Ok(())
        } else {
            Err(AuthRejection::Forbidden)
        }
    }
}

/// Disjoint validator: signaling credentials are recognized only by their
/// version prefix and can never fall through to the control-plane validator.
pub struct WebRtcSignalingBearerValidator {
    control: Arc<dyn BearerValidator>,
    signaling: Arc<SignalingTokenService>,
}

impl fmt::Debug for WebRtcSignalingBearerValidator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebRtcSignalingBearerValidator")
            .field("control", &"[configured]")
            .field("signaling", &"[configured]")
            .finish()
    }
}

impl WebRtcSignalingBearerValidator {
    pub fn new(control: Arc<dyn BearerValidator>, signaling: Arc<SignalingTokenService>) -> Self {
        Self { control, signaling }
    }

    async fn selected(&self, token: &str) -> &dyn BearerValidator {
        if token.starts_with(SIGNALING_TOKEN_PREFIX) {
            self.signaling.as_ref()
        } else {
            self.control.as_ref()
        }
    }
}

#[async_trait]
impl BearerValidator for WebRtcSignalingBearerValidator {
    async fn validate(&self, token: &str) -> Result<IdentityAssurance, BearerAuthError> {
        self.selected(token).await.validate(token).await
    }

    async fn validate_principal(
        &self,
        token: &str,
    ) -> Result<AuthenticatedPrincipal, BearerAuthError> {
        self.selected(token).await.validate_principal(token).await
    }

    async fn validate_credential(&self, token: &str) -> Result<ValidatedBearer, BearerAuthError> {
        self.selected(token).await.validate_credential(token).await
    }
}

pub struct IssuedSignalingToken {
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

impl fmt::Debug for IssuedSignalingToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedSignalingToken")
            .field("token", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl Drop for IssuedSignalingToken {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct SignalingTokenClaims {
    iss: String,
    aud: String,
    sub: String,
    principal_issuer: Option<String>,
    tenant_id: String,
    call_id: String,
    leg_id: String,
    attachment_digest: String,
    scope: String,
    exp: i64,
    nbf: i64,
    iat: i64,
    jti: String,
    ver: u8,
}

fn validate_identity(principal: &AuthenticatedPrincipal) -> Result<(), SignalingTokenError> {
    let tenant = principal
        .tenant
        .as_deref()
        .ok_or(SignalingTokenError::InvalidPrincipal)?;
    if principal.subject.trim().is_empty()
        || principal.subject.len() > MAX_IDENTITY_BYTES
        || principal.subject.chars().any(char::is_control)
        || TenantId::parse(tenant).is_err()
        || principal.issuer.as_ref().is_some_and(|issuer| {
            issuer.trim().is_empty()
                || issuer.len() > MAX_IDENTITY_BYTES
                || issuer.chars().any(char::is_control)
        })
    {
        return Err(SignalingTokenError::InvalidPrincipal);
    }
    Ok(())
}

fn validate_claims_shape(claims: &SignalingTokenClaims) -> Result<(), SignalingTokenError> {
    if claims.ver != SIGNALING_TOKEN_VERSION
        || claims.iss != SIGNALING_TOKEN_ISSUER
        || claims.aud != SIGNALING_TOKEN_AUDIENCE
        || claims.scope != SIGNALING_TOKEN_SCOPE
        || claims.jti.len() > 128
        || Uuid::parse_str(&claims.jti).is_err()
        || CallId::from_str(&claims.call_id).is_err()
        || LegId::from_str(&claims.leg_id).is_err()
        || claims.attachment_digest.len() != 64
        || !claims
            .attachment_digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(SignalingTokenError::Invalid);
    }
    validate_identity(&AuthenticatedPrincipal {
        subject: claims.sub.clone(),
        tenant: Some(claims.tenant_id.clone()),
        scopes: vec![SIGNALING_TOKEN_SCOPE.to_owned()],
        issuer: claims.principal_issuer.clone(),
        expires_at: None,
        method: AuthenticationMethod::Jwt,
        assurance: IdentityAssurance::Anonymous,
    })?;
    let now = Utc::now().timestamp();
    if claims.iat > now
        || claims.nbf > now
        || claims.exp <= now
        || claims.exp <= claims.iat
        || claims.nbf < claims.iat
        || u64::try_from(claims.exp - claims.iat)
            .map_or(true, |ttl| ttl > MAX_SIGNALING_TOKEN_TTL.as_secs())
    {
        return Err(SignalingTokenError::InvalidExpiry);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvoip_core::Jwk;

    fn principal(tenant: &str, subject: &str) -> AuthenticatedPrincipal {
        AuthenticatedPrincipal {
            subject: subject.into(),
            tenant: Some(tenant.into()),
            scopes: vec!["calls:create".into()],
            issuer: Some("bridgefu:test-control".into()),
            expires_at: None,
            method: AuthenticationMethod::ApiKey,
            assurance: IdentityAssurance::Pseudonymous {
                ephemeral_key: Jwk(serde_json::json!({"kty": "test"})),
            },
        }
    }

    #[tokio::test]
    async fn credential_preserves_ownership_and_binds_exact_attachment() {
        let service = SignalingTokenService::new(vec![0x55; 32]).unwrap();
        let now = Utc::now();
        let owner = principal("tenant-a", "owner-a");
        let issued = service
            .issue(
                &owner,
                CallId::new(),
                LegId::new(),
                "attachment-token-a",
                now + chrono::Duration::minutes(2),
                now,
            )
            .unwrap();
        let validated = service.validate_principal(&issued.token).await.unwrap();
        assert_eq!(validated.subject, owner.subject);
        assert_eq!(validated.tenant, owner.tenant);
        assert_eq!(validated.issuer, owner.issuer);
        assert_eq!(validated.scopes, [SIGNALING_TOKEN_SCOPE]);
        service
            .authorize(&issued.token, "attachment-token-a", &validated)
            .await
            .unwrap();
        assert!(matches!(
            service
                .authorize(&issued.token, "attachment-token-b", &validated)
                .await,
            Err(AuthRejection::Forbidden)
        ));
    }

    #[tokio::test]
    async fn cross_principal_binding_fails_closed() {
        let service = SignalingTokenService::new(vec![0x66; 32]).unwrap();
        let now = Utc::now();
        let issued = service
            .issue(
                &principal("tenant-a", "owner-a"),
                CallId::new(),
                LegId::new(),
                "attachment-token-a",
                now + chrono::Duration::minutes(2),
                now,
            )
            .unwrap();
        let other = principal("tenant-b", "owner-b");
        assert!(matches!(
            service
                .authorize(&issued.token, "attachment-token-a", &other)
                .await,
            Err(AuthRejection::Forbidden)
        ));
    }

    #[tokio::test]
    async fn composite_never_falls_a_signaling_prefix_back_to_control_auth() {
        struct AcceptAnything;
        #[async_trait]
        impl BearerValidator for AcceptAnything {
            async fn validate(&self, _token: &str) -> Result<IdentityAssurance, BearerAuthError> {
                Ok(IdentityAssurance::Pseudonymous {
                    ephemeral_key: Jwk(serde_json::json!({"kty": "test"})),
                })
            }
        }

        let signaling = Arc::new(SignalingTokenService::new(vec![0x77; 32]).unwrap());
        let composite = WebRtcSignalingBearerValidator::new(Arc::new(AcceptAnything), signaling);
        assert!(composite
            .validate(&format!("{SIGNALING_TOKEN_PREFIX}not-a-jwt"))
            .await
            .is_err());
        assert!(composite.validate("ordinary-control-token").await.is_ok());
    }
}
