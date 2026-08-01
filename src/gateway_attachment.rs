//! Exact-worker attachment routing and private admission protocol.
//!
//! Public attachment bearers remain opaque to gateways. A gateway hashes the
//! presented bearer, verifies its authenticated owner against a short-lived
//! Redis projection, and opens exactly one provisional mTLS UCTP connection
//! to the projected worker incarnation. The worker still performs the only
//! authoritative proof consume and durable connection bind. It acknowledges
//! exact tenant/call/leg identities only after that transaction succeeds.

use std::fmt;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use rvoip_auth_core::{AuthenticatedPrincipal, AuthenticationMethod};
use rvoip_core::{DataMessage, DataReliability, IdentityAssurance};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::api_principal::{ApiPrincipal, PrincipalFingerprintKey};
use crate::call_engine::{
    AttachmentTransport, BindingGeneration, CallId, LegId, RouteCatalogFingerprint, TenantId,
    WorkerLease,
};
use crate::call_service::{parse_presented_attachment_token, PresentedAttachmentToken};
use crate::coordination::{
    AttachmentRouteHint, AttachmentRouteLookup, CoordinationError, CoordinationProjection,
};

/// Reliable private DataMessage carrying a single attachment proof.
pub const PRIVATE_ATTACHMENT_ADMISSION_REQUEST_LABEL: &str = "bridgefu.private.attachment.admit.v1";
/// Reliable private DataMessage carrying a redacted admission outcome.
pub const PRIVATE_ATTACHMENT_ADMISSION_RESPONSE_LABEL: &str =
    "bridgefu.private.attachment.result.v1";
/// Content type for both private attachment messages.
pub const PRIVATE_ATTACHMENT_CONTENT_TYPE: &str = "application/json";
/// Protocol discriminator retained inside the JSON body.
pub const PRIVATE_ATTACHMENT_PROTOCOL_VERSION: u16 = 1;

const MAX_PRIVATE_ATTACHMENT_MESSAGE_BYTES: usize = 16 * 1024;

/// Aggregate-safe gateway routing failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GatewayAttachmentError {
    #[error("attachment proof rejected")]
    ProofRejected,
    #[error("attachment routing dependency unavailable")]
    RoutingUnavailable,
    #[error("private attachment protocol message is invalid")]
    InvalidProtocol,
    #[error("private attachment admission was rejected")]
    AdmissionRejected,
}

/// Minimum public-principal claim needed to reproduce the existing keyed
/// issuer/tenant/subject binding and expiry check at the worker.
///
/// Scopes, assurance evidence, and the original credential never cross the
/// private edge. mTLS and the gateway's UCTP principal attest this claim; the
/// opaque attachment token independently binds the same ownership tuple.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct AttachmentPrincipalClaim {
    subject: String,
    tenant: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at: Option<DateTime<Utc>>,
}

impl AttachmentPrincipalClaim {
    pub fn from_authenticated(
        principal: &AuthenticatedPrincipal,
        now: DateTime<Utc>,
    ) -> Result<Self, GatewayAttachmentError> {
        let validated = ApiPrincipal::new(principal.clone(), now)
            .map_err(|_| GatewayAttachmentError::ProofRejected)?;
        Ok(Self {
            subject: principal.subject.clone(),
            tenant: validated.tenant().as_str().to_owned(),
            issuer: principal.issuer.clone(),
            expires_at: principal.expires_at,
        })
    }

    /// Reconstructs the ownership/expiry principal consumed by the worker's
    /// existing `CallService` proof path. The assurance describes the trusted
    /// private gateway assertion, not the original public credential.
    pub fn into_authenticated(
        self,
        now: DateTime<Utc>,
    ) -> Result<AuthenticatedPrincipal, GatewayAttachmentError> {
        let principal = AuthenticatedPrincipal {
            subject: self.subject,
            tenant: Some(self.tenant),
            scopes: Vec::new(),
            issuer: self.issuer,
            expires_at: self.expires_at,
            method: AuthenticationMethod::MutualTls,
            assurance: IdentityAssurance::Anonymous,
        };
        ApiPrincipal::new(principal.clone(), now)
            .map(|_| principal)
            .map_err(|_| GatewayAttachmentError::ProofRejected)
    }
}

impl fmt::Debug for AttachmentPrincipalClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AttachmentPrincipalClaim")
            .field("subject", &"[redacted]")
            .field("tenant", &"[redacted]")
            .field("issuer_present", &self.issuer.is_some())
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Gateway-side authorization returned only after the exact-worker Redis
/// projection matches the token digest, transport, and principal binding.
pub struct GatewayAttachmentAuthorization {
    route: AttachmentRouteHint,
    principal: AttachmentPrincipalClaim,
    token: PresentedAttachmentToken,
}

impl fmt::Debug for GatewayAttachmentAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayAttachmentAuthorization")
            .field("worker", &self.route.worker)
            .field("transport", &self.route.transport)
            .field("expires_at", &self.route.expires_at)
            .field("principal", &self.principal)
            .field("token", &"[redacted]")
            .finish()
    }
}

impl GatewayAttachmentAuthorization {
    #[must_use]
    pub const fn worker(&self) -> WorkerLease {
        self.route.worker
    }

    #[must_use]
    pub const fn transport(&self) -> AttachmentTransport {
        self.route.transport
    }

    pub fn tenant_id(&self) -> Result<TenantId, GatewayAttachmentError> {
        TenantId::parse(self.principal.tenant.clone())
            .map_err(|_| GatewayAttachmentError::ProofRejected)
    }

    #[must_use]
    pub fn into_request(self, request_id: Uuid) -> WorkerAttachmentAdmissionRequest {
        WorkerAttachmentAdmissionRequest {
            version: PRIVATE_ATTACHMENT_PROTOCOL_VERSION,
            request_id,
            expected_worker: self.route.worker,
            transport: self.route.transport,
            principal: self.principal,
            routing_token: self.token.into_secret(),
        }
    }
}

/// Resolves one bearer to one exact live worker without inspecting or deriving
/// call/leg identity at the gateway.
pub struct GatewayAttachmentResolver {
    projection: Arc<dyn CoordinationProjection>,
    fingerprint_key: PrincipalFingerprintKey,
    route_catalog_fingerprint: Option<RouteCatalogFingerprint>,
}

impl fmt::Debug for GatewayAttachmentResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayAttachmentResolver")
            .field("projection", &"[configured]")
            .field("fingerprint_key", &"[configured]")
            .field("route_catalog_fingerprint", &self.route_catalog_fingerprint)
            .finish()
    }
}

impl GatewayAttachmentResolver {
    pub fn new(
        projection: Arc<dyn CoordinationProjection>,
        fingerprint_key: Vec<u8>,
    ) -> Result<Self, GatewayAttachmentError> {
        let fingerprint_key = PrincipalFingerprintKey::new(fingerprint_key)
            .map_err(|_| GatewayAttachmentError::RoutingUnavailable)?;
        Ok(Self {
            projection,
            fingerprint_key,
            route_catalog_fingerprint: None,
        })
    }

    /// Requires projected attachment assignments to match this gateway's
    /// exact route/capability catalog before any private worker dial occurs.
    #[must_use]
    pub fn with_route_catalog_fingerprint(mut self, fingerprint: RouteCatalogFingerprint) -> Self {
        self.route_catalog_fingerprint = Some(fingerprint);
        self
    }

    pub async fn resolve(
        &self,
        principal: AuthenticatedPrincipal,
        routing_token: String,
        transport: AttachmentTransport,
        now: DateTime<Utc>,
    ) -> Result<GatewayAttachmentAuthorization, GatewayAttachmentError> {
        let principal =
            ApiPrincipal::new(principal, now).map_err(|_| GatewayAttachmentError::ProofRejected)?;
        let token = parse_presented_attachment_token(routing_token)
            .map_err(|_| GatewayAttachmentError::ProofRejected)?;
        let lookup = AttachmentRouteLookup {
            token_digest: token.digest(),
            transport,
            tenant_binding: self.fingerprint_key.derive(&principal),
        };
        let route = self
            .projection
            .attachment_route_hint(lookup)
            .await
            .map_err(map_projection_error)?
            .ok_or(GatewayAttachmentError::ProofRejected)?;
        if route.token_digest != lookup.token_digest
            || route.transport != transport
            || route.tenant_binding != lookup.tenant_binding
            || route.expires_at <= now
            || self
                .route_catalog_fingerprint
                .is_some_and(|expected| route.route_catalog_fingerprint != Some(expected))
        {
            return Err(GatewayAttachmentError::ProofRejected);
        }
        let principal =
            AttachmentPrincipalClaim::from_authenticated(principal.authenticated(), now)?;
        Ok(GatewayAttachmentAuthorization {
            route,
            principal,
            token,
        })
    }
}

fn map_projection_error(_error: CoordinationError) -> GatewayAttachmentError {
    GatewayAttachmentError::RoutingUnavailable
}

/// Secret-bearing request sent only over the selected mutually-authenticated
/// UCTP connection. Debug output and errors never expose the bearer or owner.
#[derive(Serialize, Deserialize)]
pub struct WorkerAttachmentAdmissionRequest {
    version: u16,
    request_id: Uuid,
    expected_worker: WorkerLease,
    transport: AttachmentTransport,
    principal: AttachmentPrincipalClaim,
    routing_token: String,
}

impl WorkerAttachmentAdmissionRequest {
    #[must_use]
    pub const fn request_id(&self) -> Uuid {
        self.request_id
    }

    #[must_use]
    pub const fn expected_worker(&self) -> WorkerLease {
        self.expected_worker
    }

    #[must_use]
    pub const fn transport(&self) -> AttachmentTransport {
        self.transport
    }

    pub fn into_worker_parts(
        mut self,
        actual_worker: WorkerLease,
        now: DateTime<Utc>,
    ) -> Result<WorkerAttachmentAdmissionParts, GatewayAttachmentError> {
        if self.version != PRIVATE_ATTACHMENT_PROTOCOL_VERSION
            || self.request_id.is_nil()
            || self.expected_worker != actual_worker
        {
            return Err(GatewayAttachmentError::AdmissionRejected);
        }
        let token = parse_presented_attachment_token(std::mem::take(&mut self.routing_token))
            .map_err(|_| GatewayAttachmentError::AdmissionRejected)?;
        let principal = std::mem::replace(
            &mut self.principal,
            AttachmentPrincipalClaim {
                subject: String::new(),
                tenant: String::new(),
                issuer: None,
                expires_at: None,
            },
        )
        .into_authenticated(now)
        .map_err(|_| GatewayAttachmentError::AdmissionRejected)?;
        Ok(WorkerAttachmentAdmissionParts {
            request_id: self.request_id,
            transport: self.transport,
            principal,
            routing_token: token.into_secret(),
        })
    }

    pub fn to_data_message(&self) -> Result<DataMessage, GatewayAttachmentError> {
        let bytes =
            serde_json::to_vec(self).map_err(|_| GatewayAttachmentError::InvalidProtocol)?;
        if bytes.len() > MAX_PRIVATE_ATTACHMENT_MESSAGE_BYTES {
            return Err(GatewayAttachmentError::InvalidProtocol);
        }
        Ok(DataMessage::reliable(
            PRIVATE_ATTACHMENT_ADMISSION_REQUEST_LABEL,
            PRIVATE_ATTACHMENT_CONTENT_TYPE,
            bytes,
        ))
    }

    /// Encodes the same admission body as a bounded pre-admission UCTP
    /// routing hint. Retained owners must zeroize the returned string after
    /// constructing the encrypted private Session offer.
    pub fn to_routing_hint(&self) -> Result<String, GatewayAttachmentError> {
        let encoded =
            serde_json::to_string(self).map_err(|_| GatewayAttachmentError::InvalidProtocol)?;
        if encoded.is_empty()
            || encoded.len() > rvoip_core::adapter::MAX_INBOUND_ROUTING_HINT_BYTES
            || encoded.chars().any(char::is_control)
        {
            return Err(GatewayAttachmentError::InvalidProtocol);
        }
        Ok(encoded)
    }

    /// Decodes and clears a pre-admission routing hint immediately after the
    /// strongly typed, secret-owning request has been reconstructed.
    pub fn from_routing_hint(mut routing_hint: String) -> Result<Self, GatewayAttachmentError> {
        let decoded = if routing_hint.is_empty()
            || routing_hint.len() > rvoip_core::adapter::MAX_INBOUND_ROUTING_HINT_BYTES
        {
            Err(GatewayAttachmentError::InvalidProtocol)
        } else {
            serde_json::from_str(&routing_hint).map_err(|_| GatewayAttachmentError::InvalidProtocol)
        };
        routing_hint.zeroize();
        decoded
    }

    pub fn from_data_message(message: DataMessage) -> Result<Self, GatewayAttachmentError> {
        validate_private_message(&message, PRIVATE_ATTACHMENT_ADMISSION_REQUEST_LABEL)?;
        serde_json::from_slice(&message.bytes).map_err(|_| GatewayAttachmentError::InvalidProtocol)
    }
}

impl Drop for WorkerAttachmentAdmissionRequest {
    fn drop(&mut self) {
        self.routing_token.zeroize();
    }
}

impl fmt::Debug for WorkerAttachmentAdmissionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkerAttachmentAdmissionRequest")
            .field("version", &self.version)
            .field("request_id_present", &!self.request_id.is_nil())
            .field("expected_worker", &self.expected_worker)
            .field("transport", &self.transport)
            .field("principal", &self.principal)
            .field("routing_token", &"[redacted]")
            .finish()
    }
}

/// Worker-owned parts ready for the existing authoritative attachment consume.
pub struct WorkerAttachmentAdmissionParts {
    pub request_id: Uuid,
    pub transport: AttachmentTransport,
    pub principal: AuthenticatedPrincipal,
    pub routing_token: String,
}

impl Drop for WorkerAttachmentAdmissionParts {
    fn drop(&mut self) {
        self.routing_token.zeroize();
    }
}

impl fmt::Debug for WorkerAttachmentAdmissionParts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkerAttachmentAdmissionParts")
            .field("request_id_present", &!self.request_id.is_nil())
            .field("transport", &self.transport)
            .field("principal", &self.principal)
            .field("routing_token", &"[redacted]")
            .finish()
    }
}

/// Exact identities disclosed only after the worker has consumed the bearer
/// and durably bound the same private UCTP connection.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorkerAttachmentAdmissionReceipt {
    pub tenant_id: TenantId,
    pub call_id: CallId,
    pub leg_id: LegId,
    pub binding_generation: BindingGeneration,
    pub worker: WorkerLease,
}

impl fmt::Debug for WorkerAttachmentAdmissionReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkerAttachmentAdmissionReceipt")
            .field("tenant_present", &true)
            .field("call_id_present", &true)
            .field("leg_id_present", &true)
            .field("binding_generation", &self.binding_generation)
            .field("worker", &self.worker)
            .finish()
    }
}

/// Redaction-safe worker response. All proof failures deliberately collapse
/// to `Rejected`; only dependency failure is separately retryable.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerAttachmentAdmissionOutcome {
    Admitted,
    Rejected,
    Unavailable,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorkerAttachmentAdmissionResponse {
    version: u16,
    request_id: Uuid,
    outcome: WorkerAttachmentAdmissionOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt: Option<WorkerAttachmentAdmissionReceipt>,
}

impl WorkerAttachmentAdmissionResponse {
    #[must_use]
    pub const fn request_id(&self) -> Uuid {
        self.request_id
    }
    #[must_use]
    pub fn admitted(request_id: Uuid, receipt: WorkerAttachmentAdmissionReceipt) -> Self {
        Self {
            version: PRIVATE_ATTACHMENT_PROTOCOL_VERSION,
            request_id,
            outcome: WorkerAttachmentAdmissionOutcome::Admitted,
            receipt: Some(receipt),
        }
    }

    #[must_use]
    pub fn rejected(request_id: Uuid) -> Self {
        Self {
            version: PRIVATE_ATTACHMENT_PROTOCOL_VERSION,
            request_id,
            outcome: WorkerAttachmentAdmissionOutcome::Rejected,
            receipt: None,
        }
    }

    #[must_use]
    pub fn unavailable(request_id: Uuid) -> Self {
        Self {
            version: PRIVATE_ATTACHMENT_PROTOCOL_VERSION,
            request_id,
            outcome: WorkerAttachmentAdmissionOutcome::Unavailable,
            receipt: None,
        }
    }

    pub fn into_receipt(
        self,
        expected_request_id: Uuid,
        expected_worker: WorkerLease,
    ) -> Result<WorkerAttachmentAdmissionReceipt, GatewayAttachmentError> {
        if self.version != PRIVATE_ATTACHMENT_PROTOCOL_VERSION
            || self.request_id != expected_request_id
            || expected_request_id.is_nil()
        {
            return Err(GatewayAttachmentError::InvalidProtocol);
        }
        match (self.outcome, self.receipt) {
            (WorkerAttachmentAdmissionOutcome::Admitted, Some(receipt))
                if receipt.worker == expected_worker =>
            {
                Ok(receipt)
            }
            (WorkerAttachmentAdmissionOutcome::Rejected, None) => {
                Err(GatewayAttachmentError::AdmissionRejected)
            }
            (WorkerAttachmentAdmissionOutcome::Unavailable, None) => {
                Err(GatewayAttachmentError::RoutingUnavailable)
            }
            _ => Err(GatewayAttachmentError::InvalidProtocol),
        }
    }

    pub fn to_data_message(&self) -> Result<DataMessage, GatewayAttachmentError> {
        let bytes =
            serde_json::to_vec(self).map_err(|_| GatewayAttachmentError::InvalidProtocol)?;
        if bytes.len() > MAX_PRIVATE_ATTACHMENT_MESSAGE_BYTES {
            return Err(GatewayAttachmentError::InvalidProtocol);
        }
        Ok(DataMessage::reliable(
            PRIVATE_ATTACHMENT_ADMISSION_RESPONSE_LABEL,
            PRIVATE_ATTACHMENT_CONTENT_TYPE,
            bytes,
        ))
    }

    pub fn from_data_message(message: DataMessage) -> Result<Self, GatewayAttachmentError> {
        validate_private_message(&message, PRIVATE_ATTACHMENT_ADMISSION_RESPONSE_LABEL)?;
        serde_json::from_slice(&message.bytes).map_err(|_| GatewayAttachmentError::InvalidProtocol)
    }
}

impl fmt::Debug for WorkerAttachmentAdmissionResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkerAttachmentAdmissionResponse")
            .field("version", &self.version)
            .field("request_id_present", &!self.request_id.is_nil())
            .field("outcome", &self.outcome)
            .field("receipt_present", &self.receipt.is_some())
            .finish()
    }
}

fn validate_private_message(
    message: &DataMessage,
    expected_label: &str,
) -> Result<(), GatewayAttachmentError> {
    message
        .validate()
        .map_err(|_| GatewayAttachmentError::InvalidProtocol)?;
    if message.label != expected_label
        || message.content_type != PRIVATE_ATTACHMENT_CONTENT_TYPE
        || message.reliability != DataReliability::ReliableOrdered
        || message.bytes.is_empty()
        || message.bytes.len() > MAX_PRIVATE_ATTACHMENT_MESSAGE_BYTES
    {
        return Err(GatewayAttachmentError::InvalidProtocol);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use chrono::TimeDelta;

    use super::*;
    use crate::call_engine::{AttachmentTokenDigest, PrincipalFingerprint, WorkerId};
    use crate::coordination::{
        CoordinationEvent, CoordinationPayload, DeploymentId, ManualCoordinationClock,
        MemoryCoordinator, ProjectionSequence, WorkerCoordinationSnapshot,
    };

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-07-14T12:00:00Z")
            .expect("time")
            .with_timezone(&Utc)
    }

    fn worker_lease(fence: u64) -> WorkerLease {
        WorkerLease {
            worker_id: WorkerId::from_uuid(Uuid::from_u128(91)).expect("worker"),
            fence: serde_json::from_value(serde_json::json!(fence)).expect("fence"),
        }
    }

    fn principal(tenant: &str, subject: &str) -> AuthenticatedPrincipal {
        AuthenticatedPrincipal {
            subject: subject.to_owned(),
            tenant: Some(tenant.to_owned()),
            scopes: vec!["sip:connect".into()],
            issuer: Some("https://issuer.example".into()),
            expires_at: Some(now() + TimeDelta::minutes(5)),
            method: AuthenticationMethod::Jwt,
            assurance: IdentityAssurance::Anonymous,
        }
    }

    fn event(
        deployment: &DeploymentId,
        sequence: i64,
        payload: CoordinationPayload,
    ) -> CoordinationEvent {
        CoordinationEvent {
            deployment: deployment.clone(),
            sequence: ProjectionSequence::from_i64(sequence).expect("sequence"),
            payload,
            recorded_at: now(),
        }
    }

    async fn routed_resolver() -> (
        GatewayAttachmentResolver,
        Arc<MemoryCoordinator>,
        DeploymentId,
        AuthenticatedPrincipal,
        String,
        WorkerLease,
    ) {
        let deployment = DeploymentId::parse("gateway-attachment-test").expect("deployment");
        let clock = Arc::new(ManualCoordinationClock::new(now()));
        let coordinator =
            Arc::new(MemoryCoordinator::new(deployment.clone(), clock, 8).expect("coordinator"));
        let worker = worker_lease(1);
        coordinator
            .apply(&event(
                &deployment,
                1,
                CoordinationPayload::Worker(WorkerCoordinationSnapshot {
                    lease: worker,
                    max_calls: 10,
                    reserved_calls: 0,
                    draining: false,
                    capabilities: BTreeSet::from(["sip".into(), "webrtc".into()]),
                    lease_expires_at: now() + TimeDelta::minutes(2),
                }),
            ))
            .await
            .expect("worker projection");
        let key = b"gateway-attachment-fingerprint-key-32-bytes".to_vec();
        let public_principal = principal("tenant-a", "alice");
        let api_principal = ApiPrincipal::new(public_principal.clone(), now()).expect("principal");
        let tenant_binding = PrincipalFingerprintKey::new(key.clone())
            .expect("key")
            .derive(&api_principal);
        let token = URL_SAFE_NO_PAD.encode([0x5a; 32]);
        let token_digest = parse_presented_attachment_token(token.clone())
            .expect("token")
            .digest();
        let route_catalog_fingerprint = RouteCatalogFingerprint::new([0x71; 32]);
        coordinator
            .apply(&event(
                &deployment,
                2,
                CoordinationPayload::AttachmentRoute(AttachmentRouteHint {
                    token_digest,
                    worker,
                    route_catalog_fingerprint: Some(route_catalog_fingerprint),
                    transport: AttachmentTransport::Sip,
                    tenant_binding,
                    expires_at: now() + TimeDelta::minutes(1),
                }),
            ))
            .await
            .expect("attachment projection");
        let resolver = GatewayAttachmentResolver::new(coordinator.clone(), key)
            .expect("resolver")
            .with_route_catalog_fingerprint(route_catalog_fingerprint);
        (
            resolver,
            coordinator,
            deployment,
            public_principal,
            token,
            worker,
        )
    }

    #[tokio::test]
    async fn exact_projection_selects_one_worker_and_round_trips_private_request() {
        let (resolver, _, _, public_principal, token, worker) = routed_resolver().await;
        let authorization = resolver
            .resolve(
                public_principal,
                token.clone(),
                AttachmentTransport::Sip,
                now(),
            )
            .await
            .expect("resolved");
        assert_eq!(authorization.worker(), worker);
        let request_id = Uuid::new_v4();
        let request = authorization.into_request(request_id);
        let debug = format!("{request:?}");
        assert!(!debug.contains(&token));
        assert!(!debug.contains("alice"));
        assert!(!debug.contains("tenant-a"));

        let message = request.to_data_message().expect("message");
        assert_eq!(message.reliability, DataReliability::ReliableOrdered);
        let decoded =
            WorkerAttachmentAdmissionRequest::from_data_message(message).expect("decoded");
        let mut parts = decoded
            .into_worker_parts(worker, now())
            .expect("worker proof inputs");
        assert_eq!(parts.request_id, request_id);
        assert_eq!(parts.transport, AttachmentTransport::Sip);
        assert_eq!(
            parts.principal.ownership_key(),
            principal("tenant-a", "alice").ownership_key()
        );
        assert_eq!(parts.routing_token, token);
        parts.routing_token.zeroize();
    }

    #[tokio::test]
    async fn restarted_gateway_rejects_old_catalog_attachment_before_private_dial() {
        let (_, coordinator, _, public_principal, token, _) = routed_resolver().await;
        let changed = RouteCatalogFingerprint::new([0x72; 32]);
        let resolver = GatewayAttachmentResolver::new(
            coordinator,
            b"gateway-attachment-fingerprint-key-32-bytes".to_vec(),
        )
        .expect("resolver")
        .with_route_catalog_fingerprint(changed);

        assert!(matches!(
            resolver
                .resolve(public_principal, token, AttachmentTransport::Sip, now(),)
                .await,
            Err(GatewayAttachmentError::ProofRejected)
        ));
    }

    #[tokio::test]
    async fn owner_transport_and_stale_worker_fence_fail_before_private_dial() {
        let (resolver, coordinator, deployment, _, token, first_worker) = routed_resolver().await;
        assert_eq!(
            resolver
                .resolve(
                    principal("tenant-b", "alice"),
                    token.clone(),
                    AttachmentTransport::Sip,
                    now(),
                )
                .await
                .unwrap_err(),
            GatewayAttachmentError::ProofRejected
        );
        assert_eq!(
            resolver
                .resolve(
                    principal("tenant-a", "alice"),
                    token.clone(),
                    AttachmentTransport::WebRtc,
                    now(),
                )
                .await
                .unwrap_err(),
            GatewayAttachmentError::ProofRejected
        );

        let restarted = worker_lease(2);
        coordinator
            .apply(&event(
                &deployment,
                3,
                CoordinationPayload::Worker(WorkerCoordinationSnapshot {
                    lease: restarted,
                    max_calls: 10,
                    reserved_calls: 0,
                    draining: false,
                    capabilities: BTreeSet::from(["sip".into(), "webrtc".into()]),
                    lease_expires_at: now() + TimeDelta::minutes(2),
                }),
            ))
            .await
            .expect("restart projection");
        assert_ne!(first_worker, restarted);
        assert_eq!(
            resolver
                .resolve(
                    principal("tenant-a", "alice"),
                    token,
                    AttachmentTransport::Sip,
                    now(),
                )
                .await
                .unwrap_err(),
            GatewayAttachmentError::ProofRejected
        );
    }

    #[test]
    fn worker_rejects_stale_fence_and_gateway_rejects_mismatched_receipts() {
        let token = URL_SAFE_NO_PAD.encode([0x33; 32]);
        let request = WorkerAttachmentAdmissionRequest {
            version: PRIVATE_ATTACHMENT_PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            expected_worker: worker_lease(1),
            transport: AttachmentTransport::Sip,
            principal: AttachmentPrincipalClaim::from_authenticated(
                &principal("tenant-a", "a"),
                now(),
            )
            .expect("claim"),
            routing_token: token.clone(),
        };
        assert_eq!(
            request
                .into_worker_parts(worker_lease(2), now())
                .unwrap_err(),
            GatewayAttachmentError::AdmissionRejected
        );

        let request_id = Uuid::new_v4();
        let receipt = WorkerAttachmentAdmissionReceipt {
            tenant_id: TenantId::parse("tenant-a").expect("tenant"),
            call_id: CallId::from_uuid(Uuid::from_u128(92)).expect("call"),
            leg_id: LegId::from_uuid(Uuid::from_u128(93)).expect("leg"),
            binding_generation: serde_json::from_value(serde_json::json!(1)).expect("generation"),
            worker: worker_lease(1),
        };
        let response = WorkerAttachmentAdmissionResponse::admitted(request_id, receipt.clone());
        let message = response.to_data_message().expect("response message");
        let decoded =
            WorkerAttachmentAdmissionResponse::from_data_message(message).expect("decoded");
        assert_eq!(
            decoded
                .clone()
                .into_receipt(request_id, worker_lease(1))
                .expect("receipt"),
            receipt
        );
        assert_eq!(
            decoded
                .clone()
                .into_receipt(Uuid::new_v4(), worker_lease(1))
                .unwrap_err(),
            GatewayAttachmentError::InvalidProtocol
        );
        assert_eq!(
            decoded
                .into_receipt(request_id, worker_lease(2))
                .unwrap_err(),
            GatewayAttachmentError::InvalidProtocol
        );

        // Keep these imports exercised as redaction sentinels for the strong
        // digest types used by the public protocol surface.
        assert_eq!(
            format!("{:?}", AttachmentTokenDigest::new([1; 32])),
            "AttachmentTokenDigest([redacted])"
        );
        assert_eq!(
            format!("{:?}", PrincipalFingerprint::new([1; 32])),
            "PrincipalFingerprint([redacted])"
        );
    }
}
