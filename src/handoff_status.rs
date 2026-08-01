//! Authenticated server-to-browser handoff status contract.
//!
//! The message is delivered only by Bridgefu on the browser's DTLS-protected
//! WebRTC connection. [`HANDOFF_STATUS_LABEL`] is reserved by the bridge data
//! policy, so neither the held assistant nor a replacement destination can
//! spoof lifecycle state through ordinary bridged DataChannels.

use std::fmt;

use anyhow::{anyhow, Result};
use rvoip_core::{DataMessage, DataReliability, MessageId};
use serde::{Deserialize, Serialize};

use crate::call_engine::{BindingGeneration, CallId, LegId};

pub const HANDOFF_STATUS_LABEL: &str = "bridgefu.handoff.v1";
pub const HANDOFF_STATUS_CONTENT_TYPE: &str = "application/vnd.bridgefu.handoff.v1+json";
pub const MAX_HANDOFF_STATUS_BYTES: usize = 2 * 1024;
const MAX_DETAIL_CODE_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HandoffStatusKind {
    Preparing,
    Ringing,
    Attaching,
    Connected,
    Resumed,
    Failed,
    Ended,
}

/// One status for one exact append-only replacement generation.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffStatusEnvelope {
    pub version: u8,
    pub call_id: CallId,
    pub replacement_leg_id: LegId,
    pub binding_generation: BindingGeneration,
    pub status: HandoffStatusKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail_code: Option<String>,
}

impl fmt::Debug for HandoffStatusEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HandoffStatusEnvelope")
            .field("version", &self.version)
            .field("call_id_present", &true)
            .field("replacement_leg_id_present", &true)
            .field("binding_generation", &self.binding_generation)
            .field("status", &self.status)
            .field("detail_code", &self.detail_code)
            .finish()
    }
}

impl HandoffStatusEnvelope {
    #[must_use]
    pub fn new(
        call_id: CallId,
        replacement_leg_id: LegId,
        binding_generation: BindingGeneration,
        status: HandoffStatusKind,
        detail_code: Option<String>,
    ) -> Self {
        Self {
            version: 1,
            call_id,
            replacement_leg_id,
            binding_generation,
            status,
            detail_code,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(anyhow!("unsupported handoff status version"));
        }
        if self.detail_code.as_ref().is_some_and(|value| {
            value.is_empty()
                || value.len() > MAX_DETAIL_CODE_BYTES
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        }) {
            return Err(anyhow!("invalid handoff status detail code"));
        }
        Ok(())
    }

    pub fn to_data_message(&self) -> Result<DataMessage> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_HANDOFF_STATUS_BYTES {
            return Err(anyhow!("handoff status exceeds its wire bound"));
        }
        DataMessage::try_new(
            HANDOFF_STATUS_LABEL,
            HANDOFF_STATUS_CONTENT_TYPE,
            bytes,
            DataReliability::ReliableOrdered,
            MessageId::new(),
        )
        .map_err(|_| anyhow!("handoff status is not a valid data message"))
    }

    pub fn from_data_message(message: &DataMessage) -> Result<Self> {
        if message.label != HANDOFF_STATUS_LABEL
            || message.content_type != HANDOFF_STATUS_CONTENT_TYPE
            || message.reliability != DataReliability::ReliableOrdered
            || message.bytes.len() > MAX_HANDOFF_STATUS_BYTES
        {
            return Err(anyhow!("invalid handoff status data message"));
        }
        let envelope: Self = serde_json::from_slice(&message.bytes)?;
        envelope.validate()?;
        Ok(envelope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_round_trip_is_bounded_and_debug_redacts_route_ids() {
        let call_id = CallId::new();
        let leg_id = LegId::new();
        let envelope = HandoffStatusEnvelope::new(
            call_id,
            leg_id,
            BindingGeneration::INITIAL,
            HandoffStatusKind::Ringing,
            Some("destination_ringing".into()),
        );
        let message = envelope.to_data_message().unwrap();
        assert_eq!(message.label, HANDOFF_STATUS_LABEL);
        assert_eq!(message.reliability, DataReliability::ReliableOrdered);
        assert_eq!(
            HandoffStatusEnvelope::from_data_message(&message).unwrap(),
            envelope
        );
        let debug = format!("{envelope:?}");
        assert!(!debug.contains(&call_id.to_string()));
        assert!(!debug.contains(&leg_id.to_string()));
    }

    #[test]
    fn malformed_or_unbounded_status_is_rejected() {
        let mut envelope = HandoffStatusEnvelope::new(
            CallId::new(),
            LegId::new(),
            BindingGeneration::INITIAL,
            HandoffStatusKind::Failed,
            Some("bad detail".into()),
        );
        assert!(envelope.to_data_message().is_err());
        envelope.detail_code = Some("safe_failure".into());
        let mut message = envelope.to_data_message().unwrap();
        message.reliability = DataReliability::ReliableUnordered;
        assert!(HandoffStatusEnvelope::from_data_message(&message).is_err());
    }
}
