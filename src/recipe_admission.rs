//! Generic, recipe-owned stable SIP URI admission into the durable call engine.
//!
//! Managed recipe attachments remain the production default. This catalog is
//! the explicit compatibility path for fixed SIP endpoints: an exact,
//! configured Request-URI user is converted into an ordinary one-use durable
//! attachment and then consumed by the same admission transaction as every
//! other named-route call.

use std::collections::BTreeMap;
use std::fmt;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rvoip_auth_core::AuthenticatedPrincipal;
use rvoip_core::ids::ConnectionId;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::api_principal::ApiPrincipal;
use crate::call_engine::{
    AttachmentTransport, CallId, LegDirection, MediaFlow, SignalingInitiator, TenantId,
};
use crate::call_service::{
    CallServiceError, CallServiceRuntime, CreateCallInput, IdempotencyKey, LegEndpointConfig,
    NamedProfileBinding, NamedRouteBinding, NamedRouteCallContext, RequestedLeg, SipEndpointConfig,
    SipInitialContextMode,
};

const IDEMPOTENCY_DOMAIN: &[u8] = b"bridgefu.recipe-stable-sip-admission.v1\0";
const REQUIRED_SCOPE: &str = "sip:connect";
const MAX_ROUTES: usize = 64;
const MAX_URI_USER_BYTES: usize = 128;

/// One fully resolved stable URI route. Endpoint selection and profile
/// revisions are server-owned and contain no secret material.
#[derive(Clone)]
pub struct RecipeSipAdmissionRoute {
    pub uri_user: String,
    pub recipe_instance: String,
    pub route_id: String,
    pub expected_principal: AuthenticatedPrincipal,
    pub profiles: Vec<NamedProfileBinding>,
    pub required_correlation_header: Option<String>,
    pub destination: RequestedLeg,
}

impl fmt::Debug for RecipeSipAdmissionRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecipeSipAdmissionRoute")
            .field("uri_user", &self.uri_user)
            .field("recipe_instance", &self.recipe_instance)
            .field("route_id", &self.route_id)
            .field("expected_principal", &"[redacted]")
            .field("profile_count", &self.profiles.len())
            .field(
                "required_correlation_header",
                &self.required_correlation_header,
            )
            .field("destination", &self.destination)
            .finish()
    }
}

/// Immutable exact-match catalog installed before the SIP listener opens.
#[derive(Clone, Default)]
pub struct RecipeSipAdmissionCatalog {
    routes: BTreeMap<String, RecipeSipAdmissionRoute>,
}

impl fmt::Debug for RecipeSipAdmissionCatalog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecipeSipAdmissionCatalog")
            .field("route_count", &self.routes.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RecipeSipAdmissionError {
    #[error("invalid recipe SIP admission configuration")]
    InvalidConfiguration,
    #[error("recipe SIP admission rejected")]
    Rejected,
    #[error("recipe SIP admission authority is unavailable")]
    Unavailable,
}

#[derive(Eq, PartialEq)]
pub enum RecipeSipAdmissionDecision {
    NotApplicable,
    Attachment(RecipeSipAdmissionAttachment),
}

impl fmt::Debug for RecipeSipAdmissionDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotApplicable => formatter.write_str("NotApplicable"),
            Self::Attachment(_) => formatter.write_str("Attachment([redacted])"),
        }
    }
}

#[derive(Eq, PartialEq)]
pub struct RecipeSipAdmissionAttachment {
    call_id: CallId,
    secret: String,
}

impl RecipeSipAdmissionAttachment {
    #[must_use]
    pub const fn call_id(&self) -> CallId {
        self.call_id
    }

    #[must_use]
    pub fn into_secret(mut self) -> String {
        std::mem::take(&mut self.secret)
    }
}

impl fmt::Debug for RecipeSipAdmissionAttachment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecipeSipAdmissionAttachment([redacted])")
    }
}

impl Drop for RecipeSipAdmissionAttachment {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl RecipeSipAdmissionCatalog {
    pub fn new(
        routes: impl IntoIterator<Item = RecipeSipAdmissionRoute>,
    ) -> Result<Self, RecipeSipAdmissionError> {
        let mut catalog = BTreeMap::new();
        for route in routes {
            validate_route(&route)?;
            if catalog.insert(route.uri_user.clone(), route).is_some() || catalog.len() > MAX_ROUTES
            {
                return Err(RecipeSipAdmissionError::InvalidConfiguration);
            }
        }
        Ok(Self { routes: catalog })
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Converts only an exact configured URI user into a durable named-route
    /// call. Nonmatches fall through to managed attachment processing.
    pub async fn admit(
        &self,
        principal: &AuthenticatedPrincipal,
        routing_hint: &str,
        signaling_metadata: &[(String, String)],
        connection_id: &ConnectionId,
        runtime: &CallServiceRuntime,
    ) -> Result<RecipeSipAdmissionDecision, RecipeSipAdmissionError> {
        let Some(route) = self.routes.get(routing_hint) else {
            return Ok(RecipeSipAdmissionDecision::NotApplicable);
        };
        authorize(route, principal, runtime)?;

        let correlation = route
            .required_correlation_header
            .as_deref()
            .map(|header| {
                exact_header(signaling_metadata, header).ok_or(RecipeSipAdmissionError::Rejected)
            })
            .transpose()?;
        let context = correlation
            .map(|correlation_id| NamedRouteCallContext {
                correlation_id: correlation_id.to_owned(),
                metadata: BTreeMap::new(),
            })
            .map(|context| {
                context
                    .validate()
                    .map(|_| context)
                    .map_err(|_| RecipeSipAdmissionError::Rejected)
            })
            .transpose()?;
        let mut binding = NamedRouteBinding::new_with_profiles(
            route.route_id.clone(),
            context,
            route.profiles.clone(),
        )
        .map_err(|_| RecipeSipAdmissionError::InvalidConfiguration)?;
        if let Some(header) = &route.required_correlation_header {
            binding = binding
                .with_required_sip_correlation_header(header.clone())
                .map_err(|_| RecipeSipAdmissionError::InvalidConfiguration)?;
        }

        let api_principal = ApiPrincipal::new(principal.clone(), runtime.observation_time())
            .map_err(|_| RecipeSipAdmissionError::Rejected)?;
        let idempotency = stable_idempotency_key(route, connection_id, correlation)?;
        let created = runtime
            .service()
            .create_named_route_call(
                &api_principal,
                &idempotency,
                CreateCallInput {
                    tenant_id: None,
                    legs: [
                        RequestedLeg {
                            direction: LegDirection::Inbound,
                            signaling_initiator: Some(SignalingInitiator::Remote),
                            media_flow: MediaFlow::SendReceive,
                            endpoint: LegEndpointConfig::Sip(SipEndpointConfig {
                                uri: None,
                                initial_context: SipInitialContextMode::None,
                            }),
                            amazon_connect_start: None,
                        },
                        route.destination.clone(),
                    ],
                },
                binding,
            )
            .await
            .map_err(classify_service_error)?;

        let mut tokens = created
            .value
            .call
            .legs
            .into_iter()
            .filter_map(|leg| leg.attachment)
            .filter(|attachment| attachment.transport == AttachmentTransport::Sip);
        let token = tokens.next().ok_or(RecipeSipAdmissionError::Unavailable)?;
        if tokens.next().is_some() {
            return Err(RecipeSipAdmissionError::Unavailable);
        }
        Ok(RecipeSipAdmissionDecision::Attachment(
            RecipeSipAdmissionAttachment {
                call_id: created.value.call.call_id,
                secret: token.into_token(),
            },
        ))
    }
}

fn validate_route(route: &RecipeSipAdmissionRoute) -> Result<(), RecipeSipAdmissionError> {
    let tenant = TenantId::parse(&route.recipe_instance)
        .map_err(|_| RecipeSipAdmissionError::InvalidConfiguration)?;
    let valid_uri_user = !route.uri_user.is_empty()
        && route.uri_user.len() <= MAX_URI_USER_BYTES
        && route.uri_user.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        });
    if !valid_uri_user
        || route.recipe_instance.is_empty()
        || route.expected_principal.expires_at.is_some()
        || route.expected_principal.tenant.as_deref() != Some(tenant.as_str())
        || !route.expected_principal.has_scope("calls:create")
        || !route.expected_principal.has_scope(REQUIRED_SCOPE)
        || route.destination.direction != LegDirection::Outbound
        || route.destination.resolved_signaling_initiator() != SignalingInitiator::Bridgefu
        || route.destination.media_flow != MediaFlow::SendReceive
        || route
            .destination
            .validate_named_route_destination()
            .is_err()
    {
        return Err(RecipeSipAdmissionError::InvalidConfiguration);
    }
    let mut ingress = route
        .profiles
        .iter()
        .filter(|profile| profile.role() == crate::call_service::NamedProfileRole::Ingress);
    if !ingress.next().is_some_and(|profile| {
        matches!(
            profile.kind(),
            crate::call_service::NamedProfileKind::SipIngress
                | crate::call_service::NamedProfileKind::VapiIngress
        )
    }) || ingress.next().is_some()
    {
        return Err(RecipeSipAdmissionError::InvalidConfiguration);
    }
    let context = route
        .required_correlation_header
        .as_ref()
        .map(|_| NamedRouteCallContext {
            correlation_id: "bridgefu-stable-admission-validation".to_owned(),
            metadata: BTreeMap::new(),
        });
    let mut binding = NamedRouteBinding::new_with_profiles(
        route.route_id.clone(),
        context,
        route.profiles.clone(),
    )
    .map_err(|_| RecipeSipAdmissionError::InvalidConfiguration)?;
    if let Some(header) = &route.required_correlation_header {
        binding = binding
            .with_required_sip_correlation_header(header.clone())
            .map_err(|_| RecipeSipAdmissionError::InvalidConfiguration)?;
    }
    let _ = binding;
    Ok(())
}

fn authorize(
    route: &RecipeSipAdmissionRoute,
    principal: &AuthenticatedPrincipal,
    runtime: &CallServiceRuntime,
) -> Result<(), RecipeSipAdmissionError> {
    if principal.is_expired_at(runtime.observation_time())
        || principal.ownership_key() != route.expected_principal.ownership_key()
        || principal.tenant != route.expected_principal.tenant
        || !principal.has_scope("calls:create")
        || !principal.has_scope(REQUIRED_SCOPE)
    {
        return Err(RecipeSipAdmissionError::Rejected);
    }
    Ok(())
}

fn exact_header<'a>(metadata: &'a [(String, String)], expected: &str) -> Option<&'a str> {
    let mut values = metadata
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(expected))
        .map(|(_, value)| value.as_str());
    let first = values.next()?;
    values.next().is_none().then_some(first)
}

fn stable_idempotency_key(
    route: &RecipeSipAdmissionRoute,
    connection_id: &ConnectionId,
    correlation: Option<&str>,
) -> Result<IdempotencyKey, RecipeSipAdmissionError> {
    let mut digest = Sha256::new();
    digest.update(IDEMPOTENCY_DOMAIN);
    let connection_id = connection_id.to_string();
    for value in [
        route
            .expected_principal
            .tenant
            .as_deref()
            .unwrap_or_default(),
        route.recipe_instance.as_str(),
        route.route_id.as_str(),
        connection_id.as_str(),
        correlation.unwrap_or_default(),
    ] {
        digest.update((value.len() as u32).to_be_bytes());
        digest.update(value.as_bytes());
    }
    IdempotencyKey::parse(format!(
        "recipe-sip-v1.{}",
        URL_SAFE_NO_PAD.encode(digest.finalize())
    ))
    .map_err(|_| RecipeSipAdmissionError::InvalidConfiguration)
}

fn classify_service_error(error: CallServiceError) -> RecipeSipAdmissionError {
    match error {
        CallServiceError::CapacityExceeded
        | CallServiceError::DependencyUnavailable
        | CallServiceError::Repository(_) => RecipeSipAdmissionError::Unavailable,
        _ => RecipeSipAdmissionError::Rejected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::time::Duration;

    use crate::call_engine::WorkerId;
    use crate::call_service::{
        build_call_service_runtime, CallRepositoryBackendConfig, CallServiceCoordinationConfig,
        CallServiceRuntimeConfig, CallTimeoutPolicy, ConfiguredAttachmentPrincipalResolver,
        InboundAttachmentRequest, SystemCallServiceClock,
    };
    use crate::coordination::DeploymentId;
    use rvoip_auth_core::AuthenticationMethod;
    use rvoip_core::{IdentityAssurance, Jwk};

    fn principal(tenant: &str) -> AuthenticatedPrincipal {
        AuthenticatedPrincipal {
            subject: "fixed-sbc".to_owned(),
            tenant: Some(tenant.to_owned()),
            scopes: vec!["calls:create".to_owned(), "sip:connect".to_owned()],
            issuer: Some("bridgefu:recipe-catalog".to_owned()),
            expires_at: None,
            method: AuthenticationMethod::ApiKey,
            assurance: IdentityAssurance::Pseudonymous {
                ephemeral_key: Jwk(serde_json::json!({"kty": "test"})),
            },
        }
    }

    fn route(uri_user: &str) -> RecipeSipAdmissionRoute {
        RecipeSipAdmissionRoute {
            uri_user: uri_user.to_owned(),
            recipe_instance: "support".to_owned(),
            route_id: "support".to_owned(),
            expected_principal: principal("support"),
            profiles: vec![NamedProfileBinding::new(
                crate::call_service::NamedProfileRole::Ingress,
                crate::call_service::NamedProfileKind::SipIngress,
                "recipe-support-sip-ingress",
                "a".repeat(64),
            )
            .unwrap()],
            required_correlation_header: None,
            destination: RequestedLeg {
                direction: LegDirection::Outbound,
                signaling_initiator: Some(SignalingInitiator::Bridgefu),
                media_flow: MediaFlow::SendReceive,
                endpoint: LegEndpointConfig::WebRtc(crate::call_service::WebRtcEndpointConfig {
                    signaling_uri: Some("wss://agent.example.test/session".to_owned()),
                }),
                amazon_connect_start: None,
            },
        }
    }

    #[test]
    fn catalog_is_exact_bounded_and_redacted() {
        let catalog = RecipeSipAdmissionCatalog::new([route("support")]).unwrap();
        assert_eq!(catalog.len(), 1);
        assert!(!format!("{catalog:?}").contains("fixed-sbc"));
        assert_eq!(
            RecipeSipAdmissionCatalog::new([route("support"), route("support")]).unwrap_err(),
            RecipeSipAdmissionError::InvalidConfiguration
        );
        assert_eq!(
            RecipeSipAdmissionCatalog::new([route("Support")]).unwrap_err(),
            RecipeSipAdmissionError::InvalidConfiguration
        );
    }

    #[test]
    fn exact_correlation_header_rejects_duplicates() {
        assert_eq!(
            exact_header(
                &[("x-correlation-id".to_owned(), "one".to_owned())],
                "X-Correlation-Id"
            ),
            Some("one")
        );
        assert_eq!(
            exact_header(
                &[
                    ("X-Correlation-Id".to_owned(), "one".to_owned()),
                    ("x-correlation-id".to_owned(), "two".to_owned()),
                ],
                "X-Correlation-Id",
            ),
            None
        );
    }

    #[test]
    fn idempotency_is_route_operation_and_context_bound() {
        let route = route("support");
        let connection = ConnectionId::from_string("stable-operation-a");
        let left = stable_idempotency_key(&route, &connection, Some("corr-a")).unwrap();
        let same = stable_idempotency_key(&route, &connection, Some("corr-a")).unwrap();
        let other = stable_idempotency_key(
            &route,
            &ConnectionId::from_string("stable-operation-b"),
            Some("corr-a"),
        )
        .unwrap();
        assert_eq!(format!("{left:?}"), format!("{same:?}"));
        assert_eq!(format!("{left:?}"), "IdempotencyKey([redacted])");
        assert_eq!(format!("{other:?}"), "IdempotencyKey([redacted])");
    }

    #[test]
    fn wrong_principal_is_rejected_before_runtime_use() {
        let route = route("support");
        let mut wrong = principal("support");
        wrong.subject = "other".to_owned();
        assert_ne!(
            wrong.ownership_key(),
            route.expected_principal.ownership_key()
        );
    }

    #[tokio::test]
    async fn stable_uri_creates_a_named_route_and_preserves_one_use_proof() {
        let route = route("support");
        let expected = route.expected_principal.clone();
        let resolver = ConfiguredAttachmentPrincipalResolver::new().with_sip_ingress(
            crate::call_service::NamedProfileKind::SipIngress,
            "recipe-support-sip-ingress",
            "a".repeat(64),
            expected.clone(),
        );
        let mut coordination = CallServiceCoordinationConfig::new(
            DeploymentId::parse("stable-recipe-admission-test").unwrap(),
        );
        coordination.worker_lease_ttl = Duration::from_secs(300);
        coordination.worker_renew_interval = Duration::from_secs(100);
        let runtime = build_call_service_runtime(
            CallServiceRuntimeConfig {
                backend: CallRepositoryBackendConfig::Memory,
                worker_id: WorkerId::new(),
                max_calls: 4,
                worker_capabilities: BTreeSet::from([
                    "sip".into(),
                    "webrtc".into(),
                    "webrtc_egress".into(),
                ]),
                control_key: vec![0x72; 32],
                timeouts: CallTimeoutPolicy {
                    setup: Duration::from_secs(30),
                    media_idle: Duration::from_secs(30),
                    transfer: Duration::from_secs(30),
                    ending: Duration::from_secs(30),
                },
                coordination,
            },
            Arc::new(resolver),
            Arc::new(SystemCallServiceClock),
        )
        .await
        .unwrap();
        let catalog = RecipeSipAdmissionCatalog::new([route]).unwrap();
        let connection = ConnectionId::from_string("stable-recipe-connection");
        assert_eq!(
            catalog
                .admit(&expected, "unconfigured", &[], &connection, &runtime)
                .await
                .unwrap(),
            RecipeSipAdmissionDecision::NotApplicable
        );
        let mut wrong = expected.clone();
        wrong.subject = "other-sbc".to_owned();
        assert_eq!(
            catalog
                .admit(&wrong, "support", &[], &connection, &runtime)
                .await
                .unwrap_err(),
            RecipeSipAdmissionError::Rejected
        );
        let first = catalog
            .admit(&expected, "support", &[], &connection, &runtime)
            .await
            .unwrap();
        let second = catalog
            .admit(&expected, "support", &[], &connection, &runtime)
            .await
            .unwrap();
        let (
            RecipeSipAdmissionDecision::Attachment(first),
            RecipeSipAdmissionDecision::Attachment(second),
        ) = (first, second)
        else {
            panic!("exact stable URI must create a durable attachment")
        };
        assert_eq!(first.call_id(), second.call_id());
        let first = first.into_secret();
        let second = second.into_secret();
        runtime
            .service()
            .consume_inbound_attachment(InboundAttachmentRequest::new(
                expected.clone(),
                Some(first),
                AttachmentTransport::Sip,
                runtime.worker().lease,
                connection,
            ))
            .await
            .unwrap();
        assert!(runtime
            .service()
            .consume_inbound_attachment(InboundAttachmentRequest::new(
                expected,
                Some(second),
                AttachmentTransport::Sip,
                runtime.worker().lease,
                ConnectionId::from_string("stable-recipe-replay"),
            ))
            .await
            .is_err());
    }
}
