//! Domain-separated control-plane request and attachment-token cryptography.

use std::fmt;

use axum::http::{header::HeaderName, HeaderMap};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

use crate::api_principal::{ApiPrincipal, PrincipalFingerprintKey};
use crate::call_engine::{
    AttachmentTokenDigest, AttachmentTransport, BindingGeneration, CallId, IdempotencyKeyDigest,
    LegId, PrincipalFingerprint, RequestDigest, TenantId, WorkerLease,
};

use super::{OperationIdempotency, ServiceOperationKind};

/// HTTP header carrying the durable public-operation replay key.
pub static IDEMPOTENCY_KEY_HEADER: HeaderName = HeaderName::from_static("idempotency-key");
/// Required entropy for the shared control-plane HMAC secret.
pub const MIN_CONTROL_KEY_BYTES: usize = 32;
/// Maximum accepted HMAC secret size.
pub const MAX_CONTROL_KEY_BYTES: usize = 4_096;
/// Maximum public idempotency-key length.
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 255;
/// Attachment tokens are always valid for exactly two minutes from creation.
pub const ATTACHMENT_TOKEN_TTL_SECONDS: i64 = 120;

const IDEMPOTENCY_KEY_DOMAIN: &[u8] = b"bridgefu.idempotency-key.v1\0";
const REQUEST_DOMAIN: &[u8] = b"bridgefu.canonical-request.v1\0";
const ATTACHMENT_DOMAIN: &[u8] = b"bridgefu.attachment-token.v1\0";

/// Safe validation failures for public control cryptography.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ControlCryptoError {
    /// Secret material is outside the supported bounds.
    #[error("control HMAC key must contain 32 to 4096 bytes")]
    InvalidControlKey,
    /// The idempotency key is missing.
    #[error("Idempotency-Key header is required")]
    MissingIdempotencyKey,
    /// Multiple or merged idempotency keys were supplied.
    #[error("Idempotency-Key header must be a single field-line")]
    DuplicateIdempotencyKey,
    /// The idempotency key is not a bounded visible-ASCII token.
    #[error("Idempotency-Key must contain 1 to 255 visible ASCII characters")]
    MalformedIdempotencyKey,
    /// A timestamp calculation overflowed.
    #[error("attachment token expiry is outside the supported range")]
    TimestampOverflow,
}

/// Validated raw HTTP idempotency key. Debug never exposes the key.
#[derive(Eq, PartialEq)]
pub struct IdempotencyKey(String);

impl Drop for IdempotencyKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for IdempotencyKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IdempotencyKey([redacted])")
    }
}

impl IdempotencyKey {
    /// Extracts exactly one unmerged header field-line.
    pub fn from_headers(headers: &HeaderMap) -> Result<Self, ControlCryptoError> {
        let mut values = headers.get_all(&IDEMPOTENCY_KEY_HEADER).iter();
        let value = values
            .next()
            .ok_or(ControlCryptoError::MissingIdempotencyKey)?;
        if values.next().is_some() {
            return Err(ControlCryptoError::DuplicateIdempotencyKey);
        }
        let value = value
            .to_str()
            .map_err(|_| ControlCryptoError::MalformedIdempotencyKey)?;
        Self::parse(value)
    }

    /// Validates a raw key received through a non-HTTP service boundary.
    pub fn parse(value: impl Into<String>) -> Result<Self, ControlCryptoError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_IDEMPOTENCY_KEY_BYTES
            || value.contains(',')
            || value.bytes().any(|byte| !(0x21..=0x7e).contains(&byte))
        {
            return Err(ControlCryptoError::MalformedIdempotencyKey);
        }
        Ok(Self(value))
    }

    fn expose(&self) -> &str {
        &self.0
    }
}

/// Manual length-prefixed request transcript, independent of JSON ordering.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct CanonicalRequestTranscript(Vec<u8>);

impl Drop for CanonicalRequestTranscript {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for CanonicalRequestTranscript {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalRequestTranscript")
            .field("bytes", &"[redacted]")
            .field("length", &self.0.len())
            .finish()
    }
}

impl CanonicalRequestTranscript {
    /// Starts an empty transcript.
    #[must_use]
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// Appends a required UTF-8 field.
    pub fn push_str(&mut self, value: &str) {
        push_bytes(&mut self.0, value.as_bytes());
    }

    /// Appends an optional UTF-8 field with an explicit presence marker.
    pub fn push_optional_str(&mut self, value: Option<&str>) {
        match value {
            Some(value) => {
                self.0.push(1);
                self.push_str(value);
            }
            None => self.0.push(0),
        }
    }

    /// Appends a fixed byte field, normally a redacted ownership digest.
    pub fn push_bytes(&mut self, value: &[u8]) {
        push_bytes(&mut self.0, value);
    }

    /// Appends an unsigned integer in canonical network byte order.
    pub fn push_u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }
}

/// Public attachment token and the digest stored by repositories.
#[derive(Eq, PartialEq)]
pub struct DerivedAttachmentToken {
    token: String,
    /// SHA-256 digest of the raw 32-byte HMAC token.
    pub digest: AttachmentTokenDigest,
    /// Fixed absolute expiry encoded into the token.
    pub expires_at: DateTime<Utc>,
}

/// Complete immutable context bound into one attachment bearer token.
#[derive(Clone, Copy)]
pub struct AttachmentTokenContext<'a> {
    /// Authenticated tenant.
    pub tenant: &'a TenantId,
    /// Owning call.
    pub call_id: CallId,
    /// Exact inbound leg.
    pub leg_id: LegId,
    /// Exact binding incarnation.
    pub generation: BindingGeneration,
    /// Accepted signaling transport.
    pub transport: AttachmentTransport,
    /// Exact assigned worker incarnation.
    pub worker: WorkerLease,
    /// Expected signaling principal.
    pub principal: PrincipalFingerprint,
    /// Original persisted call creation time.
    pub created_at: DateTime<Utc>,
}

impl fmt::Debug for AttachmentTokenContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AttachmentTokenContext")
            .field("tenant", self.tenant)
            .field("call_id", &self.call_id)
            .field("leg_id", &self.leg_id)
            .field("generation", &self.generation)
            .field("transport", &self.transport)
            .field("worker", &self.worker)
            .field("principal", &"[redacted]")
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl Drop for DerivedAttachmentToken {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

impl fmt::Debug for DerivedAttachmentToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DerivedAttachmentToken")
            .field("token", &"[redacted]")
            .field("digest", &self.digest)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl DerivedAttachmentToken {
    /// Explicitly reveals the bearer token only at the response boundary.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.token
    }
}

/// Zeroizing, domain-separated cryptographic policy for the call service.
pub struct CallServiceCrypto {
    key: Vec<u8>,
    fingerprint_key: PrincipalFingerprintKey,
}

impl fmt::Debug for CallServiceCrypto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CallServiceCrypto([configured])")
    }
}

impl Drop for CallServiceCrypto {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl CallServiceCrypto {
    /// Retains validated HMAC material. Invalid input is zeroized before return.
    pub fn new(mut key: Vec<u8>) -> Result<Self, ControlCryptoError> {
        if !(MIN_CONTROL_KEY_BYTES..=MAX_CONTROL_KEY_BYTES).contains(&key.len()) {
            key.zeroize();
            return Err(ControlCryptoError::InvalidControlKey);
        }
        let fingerprint_key = PrincipalFingerprintKey::new(key.clone())
            .map_err(|_| ControlCryptoError::InvalidControlKey)?;
        Ok(Self {
            key,
            fingerprint_key,
        })
    }

    /// Derives issuer/tenant/subject ownership without exposing those values.
    #[must_use]
    pub fn principal_fingerprint(&self, principal: &ApiPrincipal) -> PrincipalFingerprint {
        self.fingerprint_key.derive(principal)
    }

    /// Builds the tenant-wide 24-hour replay claim for one public operation.
    #[must_use]
    pub fn operation_idempotency(
        &self,
        tenant: &TenantId,
        principal: PrincipalFingerprint,
        key: &IdempotencyKey,
        operation: ServiceOperationKind,
        call_id: Option<CallId>,
        transcript: &CanonicalRequestTranscript,
    ) -> OperationIdempotency {
        let mut key_mac = new_mac(&self.key);
        key_mac.update(IDEMPOTENCY_KEY_DOMAIN);
        update_field(&mut key_mac, tenant.as_str().as_bytes());
        update_field(&mut key_mac, key.expose().as_bytes());
        let key_digest = IdempotencyKeyDigest::new(key_mac.finalize().into_bytes().into());

        let mut request_mac = new_mac(&self.key);
        request_mac.update(REQUEST_DOMAIN);
        update_field(&mut request_mac, tenant.as_str().as_bytes());
        update_field(&mut request_mac, principal.expose_bytes());
        update_field(&mut request_mac, operation_label(operation));
        match call_id {
            Some(call_id) => {
                request_mac.update(&[1]);
                update_field(&mut request_mac, call_id.as_uuid().as_bytes());
            }
            None => request_mac.update(&[0]),
        }
        update_field(&mut request_mac, &transcript.0);
        let request_digest = RequestDigest::new(request_mac.finalize().into_bytes().into());

        OperationIdempotency {
            key_digest,
            request_digest,
            operation,
        }
    }

    /// Deterministically derives a 256-bit, tenant/binding/principal-bound token.
    pub fn attachment_token(
        &self,
        context: AttachmentTokenContext<'_>,
    ) -> Result<DerivedAttachmentToken, ControlCryptoError> {
        let expires_at = context
            .created_at
            .checked_add_signed(chrono::Duration::seconds(ATTACHMENT_TOKEN_TTL_SECONDS))
            .ok_or(ControlCryptoError::TimestampOverflow)?;
        let mut mac = new_mac(&self.key);
        mac.update(ATTACHMENT_DOMAIN);
        update_field(&mut mac, context.tenant.as_str().as_bytes());
        update_field(&mut mac, context.call_id.as_uuid().as_bytes());
        update_field(&mut mac, context.leg_id.as_uuid().as_bytes());
        mac.update(&context.generation.as_i64().to_be_bytes());
        mac.update(&[match context.transport {
            AttachmentTransport::Sip => 1,
            AttachmentTransport::WebRtc => 2,
        }]);
        update_field(&mut mac, context.worker.worker_id.as_uuid().as_bytes());
        mac.update(&context.worker.fence.as_i64().to_be_bytes());
        update_field(&mut mac, context.principal.expose_bytes());
        mac.update(&expires_at.timestamp().to_be_bytes());
        mac.update(&expires_at.timestamp_subsec_nanos().to_be_bytes());
        let mut raw: [u8; 32] = mac.finalize().into_bytes().into();
        let digest = AttachmentTokenDigest::new(Sha256::digest(raw).into());
        let token = URL_SAFE_NO_PAD.encode(raw);
        raw.zeroize();
        Ok(DerivedAttachmentToken {
            token,
            digest,
            expires_at,
        })
    }
}

fn operation_label(operation: ServiceOperationKind) -> &'static [u8] {
    match operation {
        ServiceOperationKind::CreateCall => b"create_call",
        ServiceOperationKind::HangupCall => b"hangup_call",
        ServiceOperationKind::TransferCall => b"transfer_call",
        ServiceOperationKind::DtmfCall => b"dtmf_call",
    }
}

fn new_mac(key: &[u8]) -> Hmac<Sha256> {
    Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts validated key material")
}

fn update_field(mac: &mut Hmac<Sha256>, value: &[u8]) {
    let length = u64::try_from(value.len()).expect("in-memory field length fits u64");
    mac.update(&length.to_be_bytes());
    mac.update(value);
}

fn push_bytes(target: &mut Vec<u8>, value: &[u8]) {
    let length = u64::try_from(value.len()).expect("in-memory field length fits u64");
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use chrono::TimeZone;
    use rvoip_auth_core::{AuthenticatedPrincipal, AuthenticationMethod};
    use rvoip_core::{IdentityAssurance, Jwk};

    fn principal() -> ApiPrincipal {
        ApiPrincipal::new(
            AuthenticatedPrincipal {
                subject: "subject-a".into(),
                tenant: Some("tenant-a".into()),
                scopes: vec!["*".into()],
                issuer: Some("issuer-a".into()),
                expires_at: None,
                method: AuthenticationMethod::Jwt,
                assurance: IdentityAssurance::Pseudonymous {
                    ephemeral_key: Jwk(serde_json::json!({"kty": "test"})),
                },
            },
            Utc.timestamp_opt(1_900_000_000, 0).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn header_parser_rejects_missing_duplicate_merged_and_whitespace() {
        assert_eq!(
            IdempotencyKey::from_headers(&HeaderMap::new()),
            Err(ControlCryptoError::MissingIdempotencyKey)
        );
        for raw in ["", "two keys", "two,keys", " leading", "trailing "] {
            let mut headers = HeaderMap::new();
            if let Ok(value) = HeaderValue::from_str(raw) {
                headers.insert(&IDEMPOTENCY_KEY_HEADER, value);
                assert_eq!(
                    IdempotencyKey::from_headers(&headers),
                    Err(ControlCryptoError::MalformedIdempotencyKey),
                    "accepted {raw:?}"
                );
            }
        }
        let mut duplicate = HeaderMap::new();
        duplicate.append(&IDEMPOTENCY_KEY_HEADER, HeaderValue::from_static("one"));
        duplicate.append(&IDEMPOTENCY_KEY_HEADER, HeaderValue::from_static("two"));
        assert_eq!(
            IdempotencyKey::from_headers(&duplicate),
            Err(ControlCryptoError::DuplicateIdempotencyKey)
        );
    }

    #[test]
    fn operation_digests_are_domain_tenant_principal_and_body_bound() {
        let crypto = CallServiceCrypto::new(vec![0x41; 32]).unwrap();
        let principal = principal();
        let fingerprint = crypto.principal_fingerprint(&principal);
        let tenant = TenantId::parse("tenant-a").unwrap();
        let key = IdempotencyKey::parse("request-1").unwrap();
        let mut body = CanonicalRequestTranscript::new();
        body.push_str("first");
        let original = crypto.operation_idempotency(
            &tenant,
            fingerprint,
            &key,
            ServiceOperationKind::CreateCall,
            None,
            &body,
        );
        assert_eq!(
            original,
            crypto.operation_idempotency(
                &tenant,
                fingerprint,
                &key,
                ServiceOperationKind::CreateCall,
                None,
                &body,
            )
        );
        let mut changed = CanonicalRequestTranscript::new();
        changed.push_str("second");
        assert_ne!(
            original.request_digest,
            crypto
                .operation_idempotency(
                    &tenant,
                    fingerprint,
                    &key,
                    ServiceOperationKind::CreateCall,
                    None,
                    &changed,
                )
                .request_digest
        );
        assert!(!format!("{original:?} {key:?}").contains("request-1"));
    }

    #[test]
    fn attachment_token_is_url_safe_fixed_length_and_exactly_two_minutes() {
        let crypto = CallServiceCrypto::new(vec![0x51; 32]).unwrap();
        let tenant = TenantId::parse("tenant-a").unwrap();
        let created = Utc.timestamp_opt(1_900_000_000, 0).unwrap();
        let token = crypto
            .attachment_token(AttachmentTokenContext {
                tenant: &tenant,
                call_id: CallId::new(),
                leg_id: LegId::new(),
                generation: BindingGeneration::INITIAL,
                transport: AttachmentTransport::Sip,
                worker: WorkerLease {
                    worker_id: crate::call_engine::WorkerId::new(),
                    fence: crate::call_engine::WorkerFence::INITIAL,
                },
                principal: crypto.principal_fingerprint(&principal()),
                created_at: created,
            })
            .unwrap();
        assert_eq!(token.expose_secret().len(), 43);
        assert!(token
            .expose_secret()
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')));
        assert_eq!(token.expires_at, created + chrono::Duration::minutes(2));
        assert!(!format!("{token:?}").contains(token.expose_secret()));
    }
}
