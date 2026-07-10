//! Versioned SIP header ↔ WebRTC/UCTP data contract.

use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use rvoip_core::{DataMessage, DataReliability};
use serde::{Deserialize, Serialize};

pub const CONTEXT_LABEL: &str = "bridgefu.control.v1";
pub const CONTEXT_CONTENT_TYPE: &str = "application/vnd.bridgefu.context.v1+json";
pub const MAX_CONTEXT_BYTES: usize = 16 * 1024;
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContextEnvelope {
    pub version: u8,
    pub correlation_id: String,
    pub tenant_id: String,
    pub call_id: String,
    pub source_leg_id: String,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ContextPolicy {
    /// SIP header name → canonical metadata key.
    #[serde(default)]
    pub allow_headers: BTreeMap<String, String>,
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
            if required.is_empty() || required.len() > 512 || required.contains(['\r', '\n']) {
                return Err(anyhow!("invalid context identifier"));
            }
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
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
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
    }

    #[test]
    fn rejects_crlf_and_reserved_overrides() {
        let mut envelope = ContextEnvelope::new("corr", "tenant", "call", "leg");
        envelope.metadata.insert("tenant_id".into(), "other".into());
        assert!(envelope.validate().is_err());
        assert!(validate_value("safe\r\nVia: evil").is_err());
    }
}
