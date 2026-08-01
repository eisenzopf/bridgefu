//! Versioned SIP header ↔ WebRTC/UCTP data contract.

use std::collections::{BTreeMap, HashMap};
use std::fmt;

use anyhow::{anyhow, Result};
use rvoip_core::ids::ConnectionId;
use rvoip_core::stream::{BridgedDataMessageDecision, DataMessageBridgePolicy};
use rvoip_core::{DataMessage, DataReliability};
use serde::{Deserialize, Serialize};

use crate::handoff_status::HANDOFF_STATUS_LABEL;
use crate::private_egress::is_private_egress_label;

pub const CONTEXT_LABEL: &str = "bridgefu.context.v1";
pub const CONTEXT_CONTENT_TYPE: &str = "application/vnd.bridgefu.context.v1+json";
pub const MAX_CONTEXT_BYTES: usize = 16 * 1024;
pub const MAX_CONTEXT_METADATA_ENTRIES: usize = 64;
const RESERVED_KEYS: &[&str] = &["tenant_id", "call_id", "source_leg_id", "version"];
const HOP_BY_HOP_HEADERS: &[&str] = &[
    "via",
    "route",
    "record-route",
    "contact",
    "content-length",
    "authorization",
    "proxy-authorization",
    "www-authenticate",
    "proxy-authenticate",
];

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ContextEnvelope {
    pub version: u8,
    pub correlation_id: String,
    pub tenant_id: String,
    pub call_id: String,
    pub source_leg_id: String,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

impl fmt::Debug for ContextEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContextEnvelope")
            .field("version", &self.version)
            .field("correlation_id_present", &!self.correlation_id.is_empty())
            .field("tenant_id_present", &!self.tenant_id.is_empty())
            .field("call_id_present", &!self.call_id.is_empty())
            .field("source_leg_id_present", &!self.source_leg_id.is_empty())
            .field("metadata_entries", &self.metadata.len())
            .finish()
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ContextPolicy {
    /// SIP header name → canonical metadata key.
    #[serde(default)]
    pub allow_headers: BTreeMap<String, String>,
}

impl ContextPolicy {
    /// Validate the configured SIP-header allowlist before any signaling
    /// listener is bound. This is the same policy used for every message at
    /// the translation boundary, with an aggregate cap matching config v1.
    pub fn validate(&self) -> Result<()> {
        if self.allow_headers.len() > MAX_CONTEXT_METADATA_ENTRIES {
            return Err(anyhow!(
                "context allowlist exceeds {MAX_CONTEXT_METADATA_ENTRIES} entries"
            ));
        }
        normalized_policy(self).map(|_| ())
    }

    /// Whether an exact metadata key is reachable through the configured SIP
    /// header allowlist. Broadcast sanitizers use this to prevent a hidden,
    /// non-auditable context field from becoming an event trigger.
    pub fn allows_metadata_key(&self, key: &str) -> Result<bool> {
        self.validate()?;
        validate_metadata_key_or_correlation(key)?;
        Ok(normalized_policy(self)?.values().any(|value| value == key))
    }
}

/// Durable call-route identity associated with one exact rvoip connection.
///
/// Values are deliberately private and redacted from diagnostics. They are
/// used only to authenticate the assertions in a context envelope; they never
/// select a route.
#[derive(Clone)]
pub struct ContextSourceBinding {
    connection_id: ConnectionId,
    tenant_id: String,
    call_id: String,
    source_leg_id: String,
}

impl ContextSourceBinding {
    pub fn new(
        connection_id: ConnectionId,
        tenant_id: impl Into<String>,
        call_id: impl Into<String>,
        source_leg_id: impl Into<String>,
    ) -> Self {
        Self {
            connection_id,
            tenant_id: tenant_id.into(),
            call_id: call_id.into(),
            source_leg_id: source_leg_id.into(),
        }
    }
}

impl fmt::Debug for ContextSourceBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContextSourceBinding")
            .field(
                "connection_id_present",
                &!self.connection_id.as_str().is_empty(),
            )
            .field("tenant_id_present", &!self.tenant_id.is_empty())
            .field("call_id_present", &!self.call_id.is_empty())
            .field("source_leg_id_present", &!self.source_leg_id.is_empty())
            .finish()
    }
}

struct BoundContextSource {
    expected_target: ConnectionId,
    tenant_id: String,
    call_id: String,
    source_leg_id: String,
}

/// Bridge policy that passes arbitrary application DataChannels unchanged and
/// authenticates only the `bridgefu.context.v1` envelope against the durable
/// source binding.
pub struct BridgefuContextBridgePolicy {
    sources: HashMap<ConnectionId, BoundContextSource>,
}

impl BridgefuContextBridgePolicy {
    pub fn new(left: ContextSourceBinding, right: ContextSourceBinding) -> Self {
        let mut sources = HashMap::with_capacity(2);
        sources.insert(
            left.connection_id.clone(),
            BoundContextSource {
                expected_target: right.connection_id.clone(),
                tenant_id: left.tenant_id,
                call_id: left.call_id,
                source_leg_id: left.source_leg_id,
            },
        );
        sources.insert(
            right.connection_id,
            BoundContextSource {
                expected_target: left.connection_id,
                tenant_id: right.tenant_id,
                call_id: right.call_id,
                source_leg_id: right.source_leg_id,
            },
        );
        Self { sources }
    }

    fn drop_context(reason: &'static str) -> BridgedDataMessageDecision {
        metrics::counter!(
            "bridgefu_context_data_messages_total",
            "result" => "dropped",
            "reason" => reason
        )
        .increment(1);
        BridgedDataMessageDecision::Drop
    }
}

impl fmt::Debug for BridgefuContextBridgePolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BridgefuContextBridgePolicy")
            .field("source_bindings", &self.sources.len())
            .finish()
    }
}

impl DataMessageBridgePolicy for BridgefuContextBridgePolicy {
    fn decide(
        &self,
        source: &ConnectionId,
        target: &ConnectionId,
        message: DataMessage,
    ) -> BridgedDataMessageDecision {
        if message.label == HANDOFF_STATUS_LABEL || is_private_egress_label(&message.label) {
            return Self::drop_context("private_control_label");
        }
        if message.label != CONTEXT_LABEL {
            return BridgedDataMessageDecision::Forward(message);
        }
        let Some(binding) = self.sources.get(source) else {
            return Self::drop_context("unbound_source");
        };
        if &binding.expected_target != target {
            return Self::drop_context("target_mismatch");
        }
        let envelope = match ContextEnvelope::from_data_message(&message) {
            Ok(envelope) => envelope,
            Err(_) => return Self::drop_context("invalid_envelope"),
        };
        if envelope
            .validate_binding(&binding.tenant_id, &binding.call_id, &binding.source_leg_id)
            .is_err()
        {
            return Self::drop_context("ownership_mismatch");
        }
        metrics::counter!(
            "bridgefu_context_data_messages_total",
            "result" => "forwarded",
            "reason" => "valid"
        )
        .increment(1);
        BridgedDataMessageDecision::Forward(message)
    }
}

impl ContextEnvelope {
    pub fn new(
        correlation_id: impl Into<String>,
        tenant_id: impl Into<String>,
        call_id: impl Into<String>,
        source_leg_id: impl Into<String>,
    ) -> Self {
        Self {
            version: 1,
            correlation_id: correlation_id.into(),
            tenant_id: tenant_id.into(),
            call_id: call_id.into(),
            source_leg_id: source_leg_id.into(),
            metadata: BTreeMap::new(),
        }
    }

    pub fn from_sip_headers<'a>(
        mut envelope: Self,
        headers: impl IntoIterator<Item = (&'a str, &'a str)>,
        policy: &ContextPolicy,
    ) -> Result<Self> {
        let allow = normalized_policy(policy)?;
        for (name, value) in headers {
            let normalized = name.to_ascii_lowercase();
            let Some(key) = allow.get(&normalized) else {
                continue;
            };
            validate_value(value)?;
            if key == "correlation_id" {
                envelope.correlation_id = value.to_string();
            } else {
                validate_metadata_key(key)?;
                envelope.metadata.insert(key.clone(), value.to_string());
            }
        }
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn to_sip_headers(&self, policy: &ContextPolicy) -> Result<BTreeMap<String, String>> {
        self.validate()?;
        let mut result = BTreeMap::new();
        for (header, key) in &policy.allow_headers {
            validate_header_name(header)?;
            let value = if key == "correlation_id" {
                Some(&self.correlation_id)
            } else {
                self.metadata.get(key)
            };
            if let Some(value) = value {
                validate_value(value)?;
                result.insert(header.clone(), value.clone());
            }
        }
        Ok(result)
    }

    pub fn to_data_message(&self) -> Result<DataMessage> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_CONTEXT_BYTES {
            return Err(anyhow!(
                "context envelope exceeds {MAX_CONTEXT_BYTES} bytes"
            ));
        }
        Ok(DataMessage {
            label: CONTEXT_LABEL.into(),
            content_type: CONTEXT_CONTENT_TYPE.into(),
            bytes: bytes.into(),
            reliability: DataReliability::ReliableOrdered,
            message_id: rvoip_core::MessageId::new(),
        })
    }

    pub fn from_data_message(message: &DataMessage) -> Result<Self> {
        if message.label != CONTEXT_LABEL || message.content_type != CONTEXT_CONTENT_TYPE {
            return Err(anyhow!("unsupported bridgefu data message"));
        }
        if message.bytes.len() > MAX_CONTEXT_BYTES {
            return Err(anyhow!(
                "context envelope exceeds {MAX_CONTEXT_BYTES} bytes"
            ));
        }
        let envelope: Self = serde_json::from_slice(&message.bytes)?;
        envelope.validate()?;
        Ok(envelope)
    }

    /// Parses context and binds the untrusted envelope to the authenticated
    /// call route that delivered it.
    ///
    /// Callers must use this boundary for inbound DataChannel or UCTP context;
    /// the identifiers inside the envelope are assertions, not routing input.
    pub fn from_data_message_for(
        message: &DataMessage,
        tenant_id: &str,
        call_id: &str,
        source_leg_id: &str,
    ) -> Result<Self> {
        let envelope = Self::from_data_message(message)?;
        envelope.validate_binding(tenant_id, call_id, source_leg_id)?;
        Ok(envelope)
    }

    /// Verifies that context cannot override its authenticated owner or route.
    pub fn validate_binding(
        &self,
        tenant_id: &str,
        call_id: &str,
        source_leg_id: &str,
    ) -> Result<()> {
        if self.tenant_id != tenant_id
            || self.call_id != call_id
            || self.source_leg_id != source_leg_id
        {
            return Err(anyhow!("context ownership mismatch"));
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(anyhow!("unsupported context version {}", self.version));
        }
        for required in [
            &self.correlation_id,
            &self.tenant_id,
            &self.call_id,
            &self.source_leg_id,
        ] {
            if required.is_empty() || required.len() > 512 || required.contains(['\r', '\n', '\0'])
            {
                return Err(anyhow!("invalid context identifier"));
            }
        }
        if self.metadata.len() > MAX_CONTEXT_METADATA_ENTRIES {
            return Err(anyhow!(
                "context envelope exceeds {MAX_CONTEXT_METADATA_ENTRIES} metadata entries"
            ));
        }
        for (key, value) in &self.metadata {
            validate_metadata_key(key)?;
            validate_value(value)?;
        }
        Ok(())
    }
}

fn normalized_policy(policy: &ContextPolicy) -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    for (header, key) in &policy.allow_headers {
        validate_header_name(header)?;
        validate_metadata_key_or_correlation(key)?;
        result.insert(header.to_ascii_lowercase(), key.clone());
    }
    Ok(result)
}

fn validate_header_name(header: &str) -> Result<()> {
    let normalized = header.to_ascii_lowercase();
    if !header.starts_with("X-") && !header.starts_with("x-") {
        return Err(anyhow!("context SIP headers must start with X-"));
    }
    if HOP_BY_HOP_HEADERS.contains(&normalized.as_str())
        || header.len() > 128
        || !header
            .bytes()
            // RFC 3261 `token` permits `_`. Vapi uses underscores in custom
            // X-headers to create Liquid-safe template variable names, so keep
            // that one additional character while still rejecting whitespace,
            // separators, controls, and arbitrary header injection.
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(anyhow!("invalid or unsafe SIP header {header}"));
    }
    Ok(())
}

fn validate_metadata_key_or_correlation(key: &str) -> Result<()> {
    if key == "correlation_id" {
        Ok(())
    } else {
        validate_metadata_key(key)
    }
}

fn validate_metadata_key(key: &str) -> Result<()> {
    if key.is_empty()
        || key.len() > 128
        || RESERVED_KEYS.contains(&key)
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(anyhow!("invalid or reserved context metadata key {key}"));
    }
    Ok(())
}

fn validate_value(value: &str) -> Result<()> {
    if value.len() > 2048 || value.contains(['\r', '\n', '\0']) {
        Err(anyhow!("invalid or oversized context value"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ContextPolicy {
        ContextPolicy {
            allow_headers: BTreeMap::from([
                ("X-Correlation-Id".into(), "correlation_id".into()),
                ("X-Account-Tier".into(), "account_tier".into()),
            ]),
        }
    }

    #[test]
    fn configured_policy_is_validated_before_signaling_starts() {
        policy().validate().unwrap();

        let vapi_template_header = ContextPolicy {
            allow_headers: BTreeMap::from([(
                "X-Bridgefu_Handoff_Token".into(),
                "handoff_token".into(),
            )]),
        };
        vapi_template_header.validate().unwrap();

        let oversized = ContextPolicy {
            allow_headers: (0..=MAX_CONTEXT_METADATA_ENTRIES)
                .map(|index| (format!("X-Test-{index}"), format!("test_{index}")))
                .collect(),
        };
        assert!(oversized
            .validate()
            .unwrap_err()
            .to_string()
            .contains("allowlist exceeds"));

        let unsafe_header = ContextPolicy {
            allow_headers: BTreeMap::from([("Authorization".into(), "credential".into())]),
        };
        assert!(unsafe_header.validate().is_err());
        let injected_header = ContextPolicy {
            allow_headers: BTreeMap::from([("X-Safe: X-Injected".into(), "handoff_token".into())]),
        };
        assert!(injected_header.validate().is_err());
    }

    #[test]
    fn only_allowlisted_sip_headers_cross_the_boundary() {
        let envelope = ContextEnvelope::from_sip_headers(
            ContextEnvelope::new("old", "tenant", "call", "leg"),
            [
                ("X-Correlation-Id", "corr"),
                ("X-Account-Tier", "gold"),
                ("Authorization", "secret"),
            ],
            &policy(),
        )
        .unwrap();
        assert_eq!(envelope.correlation_id, "corr");
        assert_eq!(envelope.metadata.get("account_tier").unwrap(), "gold");
        assert!(!envelope.metadata.values().any(|value| value == "secret"));
    }

    #[test]
    fn data_message_roundtrip_is_versioned() {
        let mut envelope = ContextEnvelope::new("corr", "tenant", "call", "leg");
        envelope
            .metadata
            .insert("account_tier".into(), "gold".into());
        let message = envelope.to_data_message().unwrap();
        assert_eq!(
            ContextEnvelope::from_data_message(&message).unwrap(),
            envelope
        );
        assert_eq!(message.label, "bridgefu.context.v1");
        assert_eq!(
            ContextEnvelope::from_data_message_for(&message, "tenant", "call", "leg").unwrap(),
            envelope
        );
    }

    #[test]
    fn inbound_context_is_bound_to_authenticated_tenant_call_and_leg() {
        let message = ContextEnvelope::new("corr", "tenant", "call", "leg")
            .to_data_message()
            .unwrap();

        for (tenant, call, leg) in [
            ("other", "call", "leg"),
            ("tenant", "other", "leg"),
            ("tenant", "call", "other"),
        ] {
            let error =
                ContextEnvelope::from_data_message_for(&message, tenant, call, leg).unwrap_err();
            assert_eq!(error.to_string(), "context ownership mismatch");
        }
    }

    #[test]
    fn bridge_policy_passes_arbitrary_channels_and_valid_bound_context_unchanged() {
        let left = ConnectionId::from_string("left-connection");
        let right = ConnectionId::from_string("right-connection");
        let policy = BridgefuContextBridgePolicy::new(
            ContextSourceBinding::new(left.clone(), "tenant", "call", "left-leg"),
            ContextSourceBinding::new(right.clone(), "tenant", "call", "right-leg"),
        );
        let arbitrary = DataMessage {
            label: "customer.binary/v7".to_string(),
            content_type: "application/octet-stream".to_string(),
            bytes: vec![0, 0xff, 7].into(),
            reliability: DataReliability::ReliableUnordered,
            message_id: rvoip_core::MessageId::from_string("arbitrary-message"),
        };
        assert!(matches!(
            policy.decide(&left, &right, arbitrary.clone()),
            BridgedDataMessageDecision::Forward(forwarded) if forwarded == arbitrary
        ));

        let context = ContextEnvelope::new("corr", "tenant", "call", "left-leg")
            .to_data_message()
            .unwrap();
        assert!(matches!(
            policy.decide(&left, &right, context.clone()),
            BridgedDataMessageDecision::Forward(forwarded) if forwarded == context
        ));
    }

    #[test]
    fn bridge_policy_drops_context_that_does_not_match_exact_durable_source_binding() {
        let left = ConnectionId::from_string("left-connection");
        let right = ConnectionId::from_string("right-connection");
        let policy = BridgefuContextBridgePolicy::new(
            ContextSourceBinding::new(left.clone(), "tenant", "call", "left-leg"),
            ContextSourceBinding::new(right.clone(), "tenant", "call", "right-leg"),
        );
        for message in [
            ContextEnvelope::new("corr", "other", "call", "left-leg")
                .to_data_message()
                .unwrap(),
            ContextEnvelope::new("corr", "tenant", "other", "left-leg")
                .to_data_message()
                .unwrap(),
            ContextEnvelope::new("corr", "tenant", "call", "other-leg")
                .to_data_message()
                .unwrap(),
            DataMessage::reliable(CONTEXT_LABEL, CONTEXT_CONTENT_TYPE, b"not-json".as_slice()),
        ] {
            assert!(matches!(
                policy.decide(&left, &right, message),
                BridgedDataMessageDecision::Drop
            ));
        }
        let valid = ContextEnvelope::new("corr", "tenant", "call", "left-leg")
            .to_data_message()
            .unwrap();
        assert!(matches!(
            policy.decide(&left, &ConnectionId::new(), valid),
            BridgedDataMessageDecision::Drop
        ));
    }

    #[test]
    fn bridge_policy_never_forwards_server_control_labels() {
        let left = ConnectionId::from_string("left-connection");
        let right = ConnectionId::from_string("right-connection");
        let policy = BridgefuContextBridgePolicy::new(
            ContextSourceBinding::new(left.clone(), "tenant", "call", "left-leg"),
            ContextSourceBinding::new(right.clone(), "tenant", "call", "right-leg"),
        );
        for label in [
            HANDOFF_STATUS_LABEL,
            "bridgefu.private-egress.command.v1",
            "bridgefu.private-egress.response.v1",
            "bridgefu.private-egress.lifecycle.v1",
        ] {
            assert!(matches!(
                policy.decide(
                    &left,
                    &right,
                    DataMessage::reliable(label, "application/json", b"{}".as_slice()),
                ),
                BridgedDataMessageDecision::Drop
            ));
        }
    }

    #[test]
    fn context_diagnostics_never_include_envelope_or_binding_values() {
        const CANARY: &str = "context-canary\r\nAuthorization: exposed";
        let envelope = ContextEnvelope::new(CANARY, CANARY, CANARY, CANARY);
        let binding =
            ContextSourceBinding::new(ConnectionId::from_string(CANARY), CANARY, CANARY, CANARY);
        let policy = BridgefuContextBridgePolicy::new(
            binding,
            ContextSourceBinding::new(ConnectionId::new(), "tenant", "call", "leg"),
        );
        for debug in [
            format!("{envelope:?}"),
            format!("{policy:?}"),
            format!(
                "{:?}",
                BridgedDataMessageDecision::Forward(DataMessage::reliable(
                    "canary-label",
                    "text/plain",
                    CANARY
                ))
            ),
        ] {
            assert!(!debug.contains(CANARY));
            assert!(!debug.contains("Authorization: exposed"));
        }
    }

    #[test]
    fn context_metadata_count_is_bounded() {
        let mut envelope = ContextEnvelope::new("corr", "tenant", "call", "leg");
        for index in 0..=MAX_CONTEXT_METADATA_ENTRIES {
            envelope
                .metadata
                .insert(format!("key-{index}"), "value".into());
        }
        assert!(envelope.validate().is_err());
    }

    #[test]
    fn rejects_crlf_and_reserved_overrides() {
        let mut envelope = ContextEnvelope::new("corr", "tenant", "call", "leg");
        envelope.metadata.insert("tenant_id".into(), "other".into());
        assert!(envelope.validate().is_err());
        assert!(validate_value("safe\r\nVia: evil").is_err());

        let nul_identifier = ContextEnvelope::new("corr\0hidden", "tenant", "call", "leg");
        assert!(nul_identifier.validate().is_err());
    }
}
