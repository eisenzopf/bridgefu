//! Bridgefu's fail-closed context-to-MOQT event sanitization boundary.
//!
//! A peer-controlled `bridgefu.context.v1` message is never published as-is.
//! The authenticated source binding is checked first, then exactly one
//! allowlisted metadata value is reduced to rvoip's fixed event-kind enum. The
//! MOQT object therefore cannot contain call IDs, tenant IDs, SIP headers,
//! provider metadata, correlation IDs, or arbitrary application values.

use chrono::{DateTime, Utc};
use rvoip_core::{
    BroadcastSanitizedEvent, BroadcastSanitizedEventKind, DataMessage, DataReliability,
};

use crate::context::{ContextEnvelope, ContextPolicy};

/// Maximum peer-originated sanitized events admitted per broadcast per second.
pub const MAX_SANITIZED_EVENTS_PER_SECOND: u32 = 100;

/// One tenant's explicit context-to-event disclosure policy.
///
/// This type intentionally has no `Default`: an event track exists only after
/// configuration validation and a per-broadcast API opt-in.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SanitizedContextEventPolicy {
    metadata_key: String,
    queue_events: usize,
    history_events: usize,
    max_events_per_second: u32,
}

impl SanitizedContextEventPolicy {
    pub fn new(
        metadata_key: impl Into<String>,
        queue_events: usize,
        history_events: usize,
        max_events_per_second: u32,
        context_policy: &ContextPolicy,
    ) -> Result<Self, SanitizedContextEventPolicyError> {
        let metadata_key = metadata_key.into();
        let is_allowlisted = context_policy
            .allows_metadata_key(&metadata_key)
            .map_err(|_| SanitizedContextEventPolicyError::InvalidContextPolicy)?;
        if !is_allowlisted || metadata_key == "correlation_id" {
            return Err(SanitizedContextEventPolicyError::MetadataKeyNotAllowlisted);
        }
        rvoip_moq::MoqSanitizedEventsConfig::new(queue_events, history_events)
            .map_err(|_| SanitizedContextEventPolicyError::InvalidMoqLimits)?;
        if !(1..=MAX_SANITIZED_EVENTS_PER_SECOND).contains(&max_events_per_second) {
            return Err(SanitizedContextEventPolicyError::InvalidRateLimit {
                maximum: MAX_SANITIZED_EVENTS_PER_SECOND,
            });
        }
        Ok(Self {
            metadata_key,
            queue_events,
            history_events,
            max_events_per_second,
        })
    }

    pub fn moq_config(
        &self,
    ) -> Result<rvoip_moq::MoqSanitizedEventsConfig, SanitizedContextEventPolicyError> {
        rvoip_moq::MoqSanitizedEventsConfig::new(self.queue_events, self.history_events)
            .map_err(|_| SanitizedContextEventPolicyError::InvalidMoqLimits)
    }

    pub const fn max_events_per_second(&self) -> u32 {
        self.max_events_per_second
    }

    /// Reduce one authenticated context message to the fixed public event
    /// model. The timestamp is the trusted local receive time, never a peer
    /// field from the JSON envelope.
    pub fn sanitize(
        &self,
        message: &DataMessage,
        tenant_id: &str,
        call_id: &str,
        source_leg_id: &str,
        received_at: DateTime<Utc>,
    ) -> Result<BroadcastSanitizedEvent, SanitizedContextEventError> {
        message
            .validate()
            .map_err(|_| SanitizedContextEventError::InvalidOrUnauthorizedContext)?;
        if message.reliability != DataReliability::ReliableOrdered {
            return Err(SanitizedContextEventError::UnorderedOrUnreliable);
        }
        let envelope =
            ContextEnvelope::from_data_message_for(message, tenant_id, call_id, source_leg_id)
                .map_err(|_| SanitizedContextEventError::InvalidOrUnauthorizedContext)?;
        let kind = envelope
            .metadata
            .get(&self.metadata_key)
            .ok_or(SanitizedContextEventError::EventKindMissing)
            .and_then(|value| parse_event_kind(value))?;
        let timestamp = u64::try_from(received_at.timestamp_millis())
            .map_err(|_| SanitizedContextEventError::InvalidReceiveTime)?;
        BroadcastSanitizedEvent::at_unix_millis(kind, timestamp)
            .map_err(|_| SanitizedContextEventError::InvalidReceiveTime)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum SanitizedContextEventPolicyError {
    #[error("sanitized event metadata key is not mapped by context.allow_headers")]
    MetadataKeyNotAllowlisted,
    #[error("context allowlist is invalid")]
    InvalidContextPolicy,
    #[error("sanitized MOQT event queue or history limit is invalid")]
    InvalidMoqLimits,
    #[error("sanitized event rate must be between 1 and {maximum} events per second")]
    InvalidRateLimit { maximum: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum SanitizedContextEventError {
    #[error("context event must be reliable and ordered")]
    UnorderedOrUnreliable,
    #[error("context event is invalid or does not match its authenticated source")]
    InvalidOrUnauthorizedContext,
    #[error("context event kind is absent")]
    EventKindMissing,
    #[error("context event kind is unsupported")]
    UnsupportedEventKind,
    #[error("context event receive time is invalid")]
    InvalidReceiveTime,
}

fn parse_event_kind(
    value: &str,
) -> Result<BroadcastSanitizedEventKind, SanitizedContextEventError> {
    match value {
        "call-connecting" => Ok(BroadcastSanitizedEventKind::CallConnecting),
        "call-connected" => Ok(BroadcastSanitizedEventKind::CallConnected),
        "call-held" => Ok(BroadcastSanitizedEventKind::CallHeld),
        "call-resumed" => Ok(BroadcastSanitizedEventKind::CallResumed),
        "transfer-started" => Ok(BroadcastSanitizedEventKind::TransferStarted),
        "transfer-completed" => Ok(BroadcastSanitizedEventKind::TransferCompleted),
        "transfer-failed" => Ok(BroadcastSanitizedEventKind::TransferFailed),
        "call-ending" => Ok(BroadcastSanitizedEventKind::CallEnding),
        "call-ended" => Ok(BroadcastSanitizedEventKind::CallEnded),
        _ => Err(SanitizedContextEventError::UnsupportedEventKind),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use rvoip_core::{DataReliability, MessageId};

    use super::*;

    fn context_policy() -> ContextPolicy {
        ContextPolicy {
            allow_headers: BTreeMap::from([
                ("X-Bridgefu-Event".into(), "broadcast_event".into()),
                ("X-Correlation-Id".into(), "correlation_id".into()),
            ]),
        }
    }

    fn policy() -> SanitizedContextEventPolicy {
        SanitizedContextEventPolicy::new("broadcast_event", 8, 8, 4, &context_policy()).unwrap()
    }

    fn message(kind: &str) -> DataMessage {
        let mut envelope =
            ContextEnvelope::new("secret-correlation", "tenant-a", "call-a", "leg-a");
        envelope
            .metadata
            .insert("broadcast_event".into(), kind.into());
        envelope
            .metadata
            .insert("provider_secret".into(), "never-publish-me".into());
        envelope.to_data_message().unwrap()
    }

    #[test]
    fn policy_requires_an_allowlisted_non_identifier_metadata_key_and_bounded_limits() {
        assert!(
            SanitizedContextEventPolicy::new("broadcast_event", 1, 1, 1, &context_policy()).is_ok()
        );
        assert!(matches!(
            SanitizedContextEventPolicy::new("other", 1, 1, 1, &context_policy()),
            Err(SanitizedContextEventPolicyError::MetadataKeyNotAllowlisted)
        ));
        assert!(matches!(
            SanitizedContextEventPolicy::new("correlation_id", 1, 1, 1, &context_policy()),
            Err(SanitizedContextEventPolicyError::MetadataKeyNotAllowlisted)
        ));
        assert!(
            SanitizedContextEventPolicy::new("broadcast_event", 0, 1, 1, &context_policy())
                .is_err()
        );
        assert!(SanitizedContextEventPolicy::new(
            "broadcast_event",
            1,
            1,
            MAX_SANITIZED_EVENTS_PER_SECOND + 1,
            &context_policy()
        )
        .is_err());
    }

    #[test]
    fn fixed_kind_and_trusted_receive_time_are_the_only_outputs() {
        let event = policy()
            .sanitize(
                &message("call-connected"),
                "tenant-a",
                "call-a",
                "leg-a",
                DateTime::from_timestamp_millis(1_234).unwrap(),
            )
            .unwrap();
        assert_eq!(event.kind(), BroadcastSanitizedEventKind::CallConnected);
        assert_eq!(event.occurred_at_unix_millis(), 1_234);
        let serialized = serde_json::to_string(&event).unwrap();
        for forbidden in [
            "tenant-a",
            "call-a",
            "leg-a",
            "secret-correlation",
            "never-publish-me",
            "provider_secret",
            "X-Bridgefu-Event",
        ] {
            assert!(!serialized.contains(forbidden), "leaked {forbidden}");
        }
    }

    #[test]
    fn ownership_schema_reliability_and_kind_fail_closed() {
        let received_at = Utc::now();
        for (tenant, call, leg) in [
            ("tenant-b", "call-a", "leg-a"),
            ("tenant-a", "call-b", "leg-a"),
            ("tenant-a", "call-a", "leg-b"),
        ] {
            assert!(matches!(
                policy().sanitize(&message("call-connected"), tenant, call, leg, received_at),
                Err(SanitizedContextEventError::InvalidOrUnauthorizedContext)
            ));
        }
        assert!(matches!(
            policy().sanitize(
                &message("custom-sensitive-event"),
                "tenant-a",
                "call-a",
                "leg-a",
                received_at
            ),
            Err(SanitizedContextEventError::UnsupportedEventKind)
        ));

        let mut unreliable = message("call-connected");
        unreliable.reliability = DataReliability::MaxRetransmits {
            ordered: true,
            count: 1,
        };
        unreliable.message_id = MessageId::new();
        assert!(matches!(
            policy().sanitize(&unreliable, "tenant-a", "call-a", "leg-a", received_at),
            Err(SanitizedContextEventError::UnorderedOrUnreliable)
        ));

        let mut invalid_message_id = message("call-connected");
        invalid_message_id.message_id = MessageId::from_string("");
        assert!(matches!(
            policy().sanitize(
                &invalid_message_id,
                "tenant-a",
                "call-a",
                "leg-a",
                received_at
            ),
            Err(SanitizedContextEventError::InvalidOrUnauthorizedContext)
        ));

        let mut unknown_schema = message("call-connected");
        let mut json = serde_json::from_slice::<serde_json::Value>(&unknown_schema.bytes).unwrap();
        json["authorization"] = serde_json::json!("secret");
        unknown_schema.bytes = serde_json::to_vec(&json).unwrap().into();
        assert!(matches!(
            policy().sanitize(&unknown_schema, "tenant-a", "call-a", "leg-a", received_at),
            Err(SanitizedContextEventError::InvalidOrUnauthorizedContext)
        ));
    }
}
