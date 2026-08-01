//! Protected, false-by-default StandardCharter admission into the durable engine.
//!
//! The legacy Vapi-to-Amazon listener remains independent. This module only
//! turns an authenticated `sip:<tenant>` admission into the same single-use
//! attachment proof used by every other durable inbound leg.

use std::collections::BTreeMap;
use std::fmt;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rvoip_amazon_connect::AttributeMapping;
use rvoip_auth_core::{AuthenticatedPrincipal, MAX_BEARER_ISSUER_BYTES, MAX_BEARER_SUBJECT_BYTES};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::api_principal::ApiPrincipal;
use crate::call_engine::{
    AttachmentTransport, CallId, LegDirection, MediaFlow, SignalingInitiator, TenantId,
};
use crate::call_service::{
    AmazonConnectEndpointConfig, AmazonConnectStartSpec, CallServiceError, CallServiceRuntime,
    CreateCallInput, IdempotencyKey, LegEndpointConfig, RequestedLeg, SipEndpointConfig,
    SipInitialContextMode,
};

const CANARY_IDEMPOTENCY_DOMAIN: &[u8] = b"bridgefu.standardcharter-canary.v1\0";
const REQUIRED_SCOPE: &str = "sip:connect";
const MAX_CANARY_PROFILE_BYTES: usize = 128;
const MAX_CANARY_DISPLAY_BYTES: usize = 256;
const MAX_CORRELATION_BYTES: usize = 256;

/// A protected route that can create one durable SIP-to-Amazon call.
#[derive(Clone)]
pub struct StandardCharterCanaryPolicy {
    tenant: TenantId,
    trusted_subject: String,
    trusted_issuer: String,
    correlation_header: String,
    profile: String,
    instance_id: String,
    contact_flow_id: String,
    default_display_name: String,
    attribute_mapping: AttributeMapping,
}

impl fmt::Debug for StandardCharterCanaryPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StandardCharterCanaryPolicy")
            .field("tenant", &self.tenant)
            .field("trusted_subject", &"[redacted]")
            .field("trusted_issuer", &"[redacted]")
            .field("correlation_header", &self.correlation_header)
            .field("profile", &"[redacted]")
            .field("instance_id", &"[redacted]")
            .field("contact_flow_id", &"[redacted]")
            .field("attribute_mapping", &self.attribute_mapping)
            .finish()
    }
}

/// Safe configuration/admission failure. No signaling or credential value is retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum StandardCharterCanaryError {
    #[error("invalid StandardCharter canary configuration")]
    InvalidConfiguration,
    #[error("StandardCharter canary admission rejected")]
    Rejected,
    #[error("StandardCharter canary durable authority is unavailable")]
    Unavailable,
}

/// Result of inspecting an inbound routing hint.
#[derive(Eq, PartialEq)]
pub enum StandardCharterCanaryDecision {
    /// The hint is not the explicitly configured canary tenant. Ordinary
    /// single-use attachment-token processing must continue.
    NotApplicable,
    /// A durable call was created (or replayed byte-for-byte) and this is its
    /// derived single-use SIP attachment bearer.
    Attachment(StandardCharterCanaryAttachment),
}

impl fmt::Debug for StandardCharterCanaryDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotApplicable => formatter.write_str("NotApplicable"),
            Self::Attachment(_) => formatter.write_str("Attachment([redacted])"),
        }
    }
}

/// Zeroizing owner for the derived two-minute attachment bearer.
#[derive(Eq, PartialEq)]
pub struct StandardCharterCanaryAttachment {
    call_id: CallId,
    secret: String,
}

impl StandardCharterCanaryAttachment {
    /// Durable call selected by the correlation-bound idempotency decision.
    ///
    /// Exposing the opaque call identifier lets diagnostics and tests join the
    /// canary admission to the ordinary call lifecycle without exposing the
    /// single-use attachment bearer.
    #[must_use]
    pub const fn call_id(&self) -> CallId {
        self.call_id
    }

    #[must_use]
    pub fn into_secret(mut self) -> String {
        std::mem::take(&mut self.secret)
    }
}

impl fmt::Debug for StandardCharterCanaryAttachment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StandardCharterCanaryAttachment([redacted])")
    }
}

impl Drop for StandardCharterCanaryAttachment {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Validated construction inputs kept separate from YAML representation.
pub struct StandardCharterCanaryConfig {
    pub tenant: String,
    pub trusted_subject: String,
    pub trusted_issuer: String,
    pub correlation_header: String,
    pub profile: String,
    pub instance_id: String,
    pub contact_flow_id: String,
    pub default_display_name: String,
    pub attribute_mapping: AttributeMapping,
}

impl StandardCharterCanaryPolicy {
    pub fn new(config: StandardCharterCanaryConfig) -> Result<Self, StandardCharterCanaryError> {
        let tenant = TenantId::parse(&config.tenant)
            .map_err(|_| StandardCharterCanaryError::InvalidConfiguration)?;
        if !bounded_identity(&config.trusted_subject, MAX_BEARER_SUBJECT_BYTES)
            || !bounded_identity(&config.trusted_issuer, MAX_BEARER_ISSUER_BYTES)
            || !bounded_text(&config.profile, MAX_CANARY_PROFILE_BYTES)
            || !bounded_text(&config.instance_id, 512)
            || !bounded_text(&config.contact_flow_id, 512)
            || !bounded_text(&config.default_display_name, MAX_CANARY_DISPLAY_BYTES)
            || !valid_extension_header(&config.correlation_header)
        {
            return Err(StandardCharterCanaryError::InvalidConfiguration);
        }
        // Construction exercises the exact reusable Amazon boundary before a
        // listener can bind. Runtime calls create the same spec with attributes.
        AmazonConnectStartSpec::new(
            config.profile.clone(),
            config.instance_id.clone(),
            config.contact_flow_id.clone(),
            BTreeMap::new(),
            config.default_display_name.clone(),
            None,
        )
        .map_err(|_| StandardCharterCanaryError::InvalidConfiguration)?;
        Ok(Self {
            tenant,
            trusted_subject: config.trusted_subject,
            trusted_issuer: config.trusted_issuer,
            correlation_header: config.correlation_header,
            profile: config.profile,
            instance_id: config.instance_id,
            contact_flow_id: config.contact_flow_id,
            default_display_name: config.default_display_name,
            attribute_mapping: config.attribute_mapping,
        })
    }

    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// Inspect a SIP routing hint and, only for the configured canary tenant,
    /// create/replay the durable call before deriving its normal attachment.
    pub async fn admit(
        &self,
        principal: &AuthenticatedPrincipal,
        routing_hint: &str,
        signaling_metadata: &[(String, String)],
        runtime: &CallServiceRuntime,
    ) -> Result<StandardCharterCanaryDecision, StandardCharterCanaryError> {
        if routing_hint != self.tenant.as_str() {
            return Ok(StandardCharterCanaryDecision::NotApplicable);
        }
        self.authorize(principal, runtime)?;
        let correlation = exact_header(signaling_metadata, &self.correlation_header)
            .ok_or(StandardCharterCanaryError::Rejected)?;
        if !bounded_text(correlation, MAX_CORRELATION_BYTES) {
            return Err(StandardCharterCanaryError::Rejected);
        }

        let mapped = self.attribute_mapping.translate(
            signaling_metadata
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
        );
        if mapped.dropped_for_size != 0
            || mapped.attributes.get("correlation_id").map(String::as_str) != Some(correlation)
        {
            return Err(StandardCharterCanaryError::Rejected);
        }
        let amazon_start = AmazonConnectStartSpec::new(
            self.profile.clone(),
            self.instance_id.clone(),
            self.contact_flow_id.clone(),
            mapped.attributes,
            self.default_display_name.clone(),
            None,
        )
        .map_err(|_| StandardCharterCanaryError::Rejected)?;
        let api_principal = ApiPrincipal::new(principal.clone(), runtime.observation_time())
            .map_err(|_| StandardCharterCanaryError::Rejected)?;
        let idempotency = canary_idempotency_key(self.tenant.as_str(), correlation)?;
        let created = runtime
            .service()
            .create_call(
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
                        RequestedLeg {
                            direction: LegDirection::Outbound,
                            signaling_initiator: Some(SignalingInitiator::Bridgefu),
                            media_flow: MediaFlow::SendReceive,
                            endpoint: LegEndpointConfig::AmazonConnect(
                                AmazonConnectEndpointConfig {
                                    instance_id: self.instance_id.clone(),
                                    contact_flow_id: self.contact_flow_id.clone(),
                                },
                            ),
                            amazon_connect_start: Some(amazon_start),
                        },
                    ],
                },
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
        let token = tokens
            .next()
            .ok_or(StandardCharterCanaryError::Unavailable)?;
        if tokens.next().is_some() {
            return Err(StandardCharterCanaryError::Unavailable);
        }
        Ok(StandardCharterCanaryDecision::Attachment(
            StandardCharterCanaryAttachment {
                call_id: created.value.call.call_id,
                secret: token.into_token(),
            },
        ))
    }

    fn authorize(
        &self,
        principal: &AuthenticatedPrincipal,
        runtime: &CallServiceRuntime,
    ) -> Result<(), StandardCharterCanaryError> {
        if principal.is_expired_at(runtime.observation_time())
            || principal.tenant.as_deref() != Some(self.tenant.as_str())
            || principal.subject != self.trusted_subject
            || principal.issuer.as_deref() != Some(self.trusted_issuer.as_str())
            || !principal.has_scope(REQUIRED_SCOPE)
            || !principal.has_scope("calls:create")
        {
            return Err(StandardCharterCanaryError::Rejected);
        }
        Ok(())
    }
}

fn exact_header<'a>(metadata: &'a [(String, String)], expected: &str) -> Option<&'a str> {
    let mut values = metadata
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(expected))
        .map(|(_, value)| value.as_str());
    let first = values.next()?;
    values.next().is_none().then_some(first)
}

fn canary_idempotency_key(
    tenant: &str,
    correlation: &str,
) -> Result<IdempotencyKey, StandardCharterCanaryError> {
    let mut digest = Sha256::new();
    digest.update(CANARY_IDEMPOTENCY_DOMAIN);
    digest.update((tenant.len() as u32).to_be_bytes());
    digest.update(tenant.as_bytes());
    digest.update((correlation.len() as u32).to_be_bytes());
    digest.update(correlation.as_bytes());
    IdempotencyKey::parse(format!(
        "sc-canary-v1.{}",
        URL_SAFE_NO_PAD.encode(digest.finalize())
    ))
    .map_err(|_| StandardCharterCanaryError::InvalidConfiguration)
}

fn classify_service_error(error: CallServiceError) -> StandardCharterCanaryError {
    match error {
        CallServiceError::CapacityExceeded
        | CallServiceError::DependencyUnavailable
        | CallServiceError::Repository(_) => StandardCharterCanaryError::Unavailable,
        _ => StandardCharterCanaryError::Rejected,
    }
}

fn bounded_identity(value: &str, maximum: usize) -> bool {
    bounded_text(value, maximum) && value.trim() == value
}

fn bounded_text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}

fn valid_extension_header(value: &str) -> bool {
    value.len() > 2
        && value.len() <= 128
        && value[..2].eq_ignore_ascii_case("x-")
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'+' | b'!')
        })
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
        CallServiceRuntimeConfig, CallTimeoutPolicy, InboundAttachmentRequest,
        SamePrincipalAttachmentResolver, SystemCallServiceClock,
    };
    use crate::coordination::DeploymentId;
    use chrono::Utc;
    use rvoip_auth_core::{AuthenticatedPrincipal, AuthenticationMethod};
    use rvoip_core::{ids::ConnectionId, IdentityAssurance, Jwk};

    #[test]
    fn idempotency_is_stable_and_tenant_bound_without_retaining_correlation() {
        let left = format!(
            "{:?}",
            canary_idempotency_key("tenant-a", "private-corr").unwrap()
        );
        let same = format!(
            "{:?}",
            canary_idempotency_key("tenant-a", "private-corr").unwrap()
        );
        let other = format!(
            "{:?}",
            canary_idempotency_key("tenant-b", "private-corr").unwrap()
        );
        assert_eq!(left, same);
        assert_eq!(left, "IdempotencyKey([redacted])");
        assert_eq!(other, "IdempotencyKey([redacted])");
        assert!(!left.contains("private-corr"));
    }

    #[test]
    fn correlation_requires_exactly_one_case_insensitive_field_line() {
        let one = vec![("x-correlation-id".into(), "corr".into())];
        assert_eq!(exact_header(&one, "X-Correlation-Id"), Some("corr"));
        let duplicate = vec![
            ("X-Correlation-Id".into(), "one".into()),
            ("x-correlation-id".into(), "two".into()),
        ];
        assert_eq!(exact_header(&duplicate, "X-Correlation-Id"), None);
    }

    #[tokio::test]
    async fn durable_canary_replays_exactly_and_attachment_is_single_use() {
        let mut coordination = CallServiceCoordinationConfig::new(
            DeploymentId::parse("standardcharter-canary-test").unwrap(),
        );
        coordination.worker_lease_ttl = Duration::from_secs(300);
        coordination.worker_renew_interval = Duration::from_secs(100);
        let runtime = build_call_service_runtime(
            CallServiceRuntimeConfig {
                backend: CallRepositoryBackendConfig::Memory,
                worker_id: WorkerId::new(),
                max_calls: 4,
                worker_capabilities: BTreeSet::from(["sip".into(), "amazon_connect".into()]),
                control_key: vec![0x73; 32],
                timeouts: CallTimeoutPolicy {
                    setup: Duration::from_secs(30),
                    media_idle: Duration::from_secs(30),
                    transfer: Duration::from_secs(30),
                    ending: Duration::from_secs(30),
                },
                coordination,
            },
            Arc::new(SamePrincipalAttachmentResolver),
            Arc::new(SystemCallServiceClock),
        )
        .await
        .unwrap();
        let principal = AuthenticatedPrincipal {
            subject: "trusted-vapi".into(),
            tenant: Some("banking".into()),
            // The protected compatibility route currently enters through the
            // configured static API principal, whose explicit advanced scope
            // authorizes the fixed Amazon endpoint submitted to `create_call`.
            scopes: vec![
                "calls:create".into(),
                "calls:destinations:arbitrary".into(),
                "sip:connect".into(),
            ],
            issuer: Some("vapi-test".into()),
            expires_at: None,
            method: AuthenticationMethod::Jwt,
            assurance: IdentityAssurance::Pseudonymous {
                ephemeral_key: Jwk(serde_json::json!({"kty": "test"})),
            },
        };
        let policy = StandardCharterCanaryPolicy::new(StandardCharterCanaryConfig {
            tenant: "banking".into(),
            trusted_subject: "trusted-vapi".into(),
            trusted_issuer: "vapi-test".into(),
            correlation_header: "X-Correlation-Id".into(),
            profile: "default".into(),
            instance_id: "instance-test".into(),
            contact_flow_id: "flow-test".into(),
            default_display_name: "Vapi caller".into(),
            attribute_mapping: AttributeMapping::default()
                .with_unmapped(rvoip_amazon_connect::UnmappedPolicy::Drop)
                .rename("X-Correlation-Id", "correlation_id")
                .rename("X-Vapi-Call-Id", "HostedWidget-vapiCallId"),
        })
        .unwrap();
        let metadata = vec![
            ("X-Correlation-Id".into(), "+14155550199".into()),
            ("X-Vapi-Call-Id".into(), "vapi-call-77".into()),
        ];
        let first = policy
            .admit(&principal, "banking", &metadata, &runtime)
            .await
            .unwrap();
        let second = policy
            .admit(&principal, "banking", &metadata, &runtime)
            .await
            .unwrap();
        let (
            StandardCharterCanaryDecision::Attachment(first),
            StandardCharterCanaryDecision::Attachment(second),
        ) = (first, second)
        else {
            panic!("configured route must return an attachment")
        };
        assert_eq!(first, second, "exact replay derives the same bearer");
        assert_eq!(
            format!("{first:?}"),
            "StandardCharterCanaryAttachment([redacted])"
        );
        let first = first.into_secret();
        let second = second.into_secret();

        let consumed = runtime
            .service()
            .consume_inbound_attachment(InboundAttachmentRequest::new(
                principal.clone(),
                Some(first),
                AttachmentTransport::Sip,
                runtime.worker().lease,
                ConnectionId::new(),
            ))
            .await;
        assert!(consumed.is_ok());
        let replay = runtime
            .service()
            .consume_inbound_attachment(InboundAttachmentRequest::new(
                principal.clone(),
                Some(second),
                AttachmentTransport::Sip,
                runtime.worker().lease,
                ConnectionId::new(),
            ))
            .await;
        assert!(replay.is_err(), "the canary cannot bypass token single use");

        let mut foreign = principal;
        foreign.tenant = Some("retail".into());
        assert_eq!(
            policy
                .admit(&foreign, "banking", &metadata, &runtime)
                .await
                .unwrap_err(),
            StandardCharterCanaryError::Rejected
        );
        assert_eq!(
            policy
                .admit(
                    &AuthenticatedPrincipal {
                        subject: "trusted-vapi".into(),
                        tenant: Some("banking".into()),
                        scopes: vec!["calls:create".into(), "sip:connect".into()],
                        issuer: Some("vapi-test".into()),
                        expires_at: Some(Utc::now() - chrono::Duration::seconds(1)),
                        method: AuthenticationMethod::Jwt,
                        assurance: IdentityAssurance::Pseudonymous {
                            ephemeral_key: Jwk(serde_json::json!({"kty": "test"})),
                        },
                    },
                    "banking",
                    &metadata,
                    &runtime,
                )
                .await
                .unwrap_err(),
            StandardCharterCanaryError::Rejected
        );
    }
}
