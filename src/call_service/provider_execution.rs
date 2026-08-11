//! Library-neutral execution boundary for native provider call legs.
//!
//! Durable call actors own invocation and reconciliation. Implementations may
//! use any provider SDK, but SDK request/response types and credentials never
//! cross this module. Every mutating request carries the exact durable effect
//! identifier that an implementation must use as the provider command ID.

use std::collections::BTreeMap;
use std::fmt;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

use crate::call_engine::{
    BindingGeneration, CallId, DeadlineGeneration, EffectId, LegId, ProviderAccountKey,
    ProviderCallId, TenantId,
};
use crate::context::{ContextEnvelope, ContextPolicy};

use super::{DtmfSequence, ProviderEndpointConfig, TransferTarget};

/// Maximum canonical JSON size of provider dial state before the provider
/// transport applies its wire encoding. Base64 expands this exact limit to at
/// most [`MAX_PROVIDER_DIAL_CLIENT_STATE_BYTES`].
const MAX_PROVIDER_DIAL_CLIENT_STATE_JSON_BYTES: usize = 3 * 1_024;

/// Hard provider-wire cap for an encoded dial `client_state` value.
pub const MAX_PROVIDER_DIAL_CLIENT_STATE_BYTES: usize = 4 * 1_024;

/// Opaque, short-lived SIP attachment token passed only to a provider executor.
///
/// The executor places this bearer in a configured SIP Request-URI user part.
/// Its `Debug` representation is redacted and its owned bytes are cleared on
/// drop.
#[derive(Eq, PartialEq)]
pub struct ProviderMediaAttachmentToken(String);

impl ProviderMediaAttachmentToken {
    /// Retains a token reconstructed by the call service.
    pub(crate) fn new(token: String) -> Self {
        Self(token)
    }

    /// Reveals the URI only at the provider SDK boundary.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ProviderMediaAttachmentToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderMediaAttachmentToken([redacted])")
    }
}

impl Drop for ProviderMediaAttachmentToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Durable ownership guard shared by all provider mutations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderExecutionContext {
    /// Authenticated tenant owning the logical call.
    pub tenant_id: TenantId,
    /// Exact durable call.
    pub call_id: CallId,
    /// Exact logical provider leg.
    pub leg_id: LegId,
    /// Current logical-leg incarnation.
    pub binding_generation: BindingGeneration,
    /// Exact durable effect; implementations use its string form verbatim as
    /// the provider command ID.
    pub effect_id: EffectId,
}

impl ProviderExecutionContext {
    /// Provider command ID that must be reused for every ambiguous retry.
    #[must_use]
    pub fn command_id(&self) -> String {
        self.effect_id.to_string()
    }

    /// Deterministic command ID for the second originate in a compound
    /// provider replacement effect.
    ///
    /// The media and destination dials must not share Telnyx deduplication
    /// authority even though one durable effect owns both operations. The
    /// derived UUID is stable across ambiguous retries and remains
    /// credential-free.
    #[must_use]
    pub fn destination_command_id(&self) -> String {
        // Telnyx requires `command_id` to be a UUID. Derive a second UUID by
        // changing only low payload bits: this preserves the version/variant
        // bits of ordinary generated effect IDs, is deterministic for retry,
        // can never equal the source, and cannot turn a non-nil ID into nil.
        let value = self.effect_id.as_uuid().as_u128();
        let destination = if value & 1 == 0 { value | 1 } else { value ^ 2 };
        uuid::Uuid::from_u128(destination).to_string()
    }
}

/// Which half of a provider-controlled two-dial call owns one client-state
/// envelope.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderDialRole {
    /// Provider call whose SIP media terminates at Bridgefu.
    Media,
    /// Provider call to the configured call-center destination.
    Destination,
}

/// Safe validation failure for provider dial client state.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderDialClientStateError {
    /// The context envelope did not belong to this exact durable call.
    #[error("provider dial context ownership does not match")]
    OwnershipMismatch,
    /// The context or projection policy was invalid.
    #[error("provider dial context is invalid")]
    InvalidContext,
    /// The projected state exceeded the provider-safe bound.
    #[error("provider dial context exceeds its size limit")]
    TooLarge,
}

/// Versioned state sent only through a provider's opaque per-call state field.
///
/// Ownership fields are generated from durable call state, while business
/// context is projected through the server's context allowlist. This value is
/// not a routing token: verified provider-call references remain authoritative
/// when callbacks are reconciled.
#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderDialClientState {
    version: u8,
    role: ProviderDialRole,
    tenant_id: TenantId,
    call_id: CallId,
    leg_id: LegId,
    binding_generation: BindingGeneration,
    effect_id: EffectId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    correlation_id: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    metadata: BTreeMap<String, String>,
}

impl ProviderDialClientState {
    const VERSION: u8 = 1;

    /// Bind one dial to exact durable ownership and project only context fields
    /// admitted by the configured server policy.
    pub fn new(
        context: &ProviderExecutionContext,
        role: ProviderDialRole,
        envelope: Option<&ContextEnvelope>,
        policy: &ContextPolicy,
    ) -> Result<Self, ProviderDialClientStateError> {
        policy
            .validate()
            .map_err(|_| ProviderDialClientStateError::InvalidContext)?;
        let (correlation_id, metadata) = if let Some(envelope) = envelope {
            envelope
                .validate()
                .map_err(|_| ProviderDialClientStateError::InvalidContext)?;
            if envelope.tenant_id != context.tenant_id.as_str()
                || envelope.call_id != context.call_id.to_string()
            {
                return Err(ProviderDialClientStateError::OwnershipMismatch);
            }
            let correlation_id = policy
                .allows_metadata_key("correlation_id")
                .map_err(|_| ProviderDialClientStateError::InvalidContext)?
                .then(|| envelope.correlation_id.clone());
            let mut metadata = BTreeMap::new();
            for (key, value) in &envelope.metadata {
                if policy
                    .allows_metadata_key(key)
                    .map_err(|_| ProviderDialClientStateError::InvalidContext)?
                {
                    metadata.insert(key.clone(), value.clone());
                }
            }
            (correlation_id, metadata)
        } else {
            (None, BTreeMap::new())
        };
        let state = Self {
            version: Self::VERSION,
            role,
            tenant_id: context.tenant_id.clone(),
            call_id: context.call_id,
            leg_id: context.leg_id,
            binding_generation: context.binding_generation,
            effect_id: context.effect_id,
            correlation_id,
            metadata,
        };
        state.validate()?;
        Ok(state)
    }

    /// Validate a decoded state before using it as callback corroboration.
    pub fn validate(&self) -> Result<(), ProviderDialClientStateError> {
        if self.version != Self::VERSION {
            return Err(ProviderDialClientStateError::InvalidContext);
        }
        if self.correlation_id.is_some() || !self.metadata.is_empty() {
            let mut envelope = ContextEnvelope::new(
                self.correlation_id
                    .clone()
                    .unwrap_or_else(|| "provider-context".into()),
                self.tenant_id.as_str(),
                self.call_id.to_string(),
                self.leg_id.to_string(),
            );
            envelope.metadata.clone_from(&self.metadata);
            envelope
                .validate()
                .map_err(|_| ProviderDialClientStateError::InvalidContext)?;
        }
        let encoded =
            serde_json::to_vec(self).map_err(|_| ProviderDialClientStateError::InvalidContext)?;
        if encoded.len() > MAX_PROVIDER_DIAL_CLIENT_STATE_JSON_BYTES {
            return Err(ProviderDialClientStateError::TooLarge);
        }
        Ok(())
    }

    /// Whether decoded state corroborates the exact provider reference already
    /// selected by account and provider-call ID.
    #[must_use]
    pub fn matches(&self, context: &ProviderExecutionContext, role: ProviderDialRole) -> bool {
        self.validate().is_ok()
            && self.role == role
            && self.tenant_id == context.tenant_id
            && self.call_id == context.call_id
            && self.leg_id == context.leg_id
            && self.binding_generation == context.binding_generation
            && self.effect_id == context.effect_id
    }

    #[must_use]
    pub const fn role(&self) -> ProviderDialRole {
        self.role
    }

    #[must_use]
    pub fn correlation_id(&self) -> Option<&str> {
        self.correlation_id.as_deref()
    }

    #[must_use]
    pub const fn metadata(&self) -> &BTreeMap<String, String> {
        &self.metadata
    }
}

impl fmt::Debug for ProviderDialClientState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderDialClientState")
            .field("version", &self.version)
            .field("role", &self.role)
            .field("binding_generation", &self.binding_generation)
            .field("correlation_present", &self.correlation_id.is_some())
            .field("metadata_entries", &self.metadata.len())
            .field("ownership", &"[redacted]")
            .finish()
    }
}

/// Versioned ownership proof echoed by Telnyx in signed transfer callbacks.
///
/// The serialized value is carried only in provider `client_state`; public
/// APIs and diagnostics never expose it. Webhook signature verification plus
/// exact account, call, leg, binding, and deadline matching make a delayed or
/// unrelated provider event incapable of completing another transfer.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderTransferCorrelation {
    version: u8,
    tenant_id: TenantId,
    call_id: CallId,
    leg_id: LegId,
    binding_generation: BindingGeneration,
    deadline_generation: DeadlineGeneration,
    effect_id: EffectId,
}

impl ProviderTransferCorrelation {
    const VERSION: u8 = 1;

    /// Bind one provider command to its exact durable transfer generation.
    #[must_use]
    pub fn new(
        context: &ProviderExecutionContext,
        deadline_generation: DeadlineGeneration,
    ) -> Self {
        Self {
            version: Self::VERSION,
            tenant_id: context.tenant_id.clone(),
            call_id: context.call_id,
            leg_id: context.leg_id,
            binding_generation: context.binding_generation,
            deadline_generation,
            effect_id: context.effect_id,
        }
    }

    /// Whether a verified callback belongs to the exact live transfer.
    #[must_use]
    pub fn matches(
        &self,
        tenant_id: &TenantId,
        call_id: CallId,
        leg_id: LegId,
        binding_generation: BindingGeneration,
        deadline_generation: DeadlineGeneration,
    ) -> bool {
        self.version == Self::VERSION
            && &self.tenant_id == tenant_id
            && self.call_id == call_id
            && self.leg_id == leg_id
            && self.binding_generation == binding_generation
            && self.deadline_generation == deadline_generation
    }

    /// Whether a previously verified transfer state still belongs to the same
    /// provider leg after the transfer deadline itself has been cleared.
    #[must_use]
    pub fn matches_owner(
        &self,
        tenant_id: &TenantId,
        call_id: CallId,
        leg_id: LegId,
        binding_generation: BindingGeneration,
    ) -> bool {
        self.version == Self::VERSION
            && &self.tenant_id == tenant_id
            && self.call_id == call_id
            && self.leg_id == leg_id
            && self.binding_generation == binding_generation
    }
}

impl fmt::Debug for ProviderTransferCorrelation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderTransferCorrelation")
            .field("version", &self.version)
            .field("binding_generation", &self.binding_generation)
            .field("deadline_generation", &self.deadline_generation)
            .field("ownership", &"[redacted]")
            .finish()
    }
}

/// Successful provider mutation returning one provider-owned call reference.
#[derive(Clone, Eq, PartialEq)]
pub struct ProviderExecutionReference {
    /// Configured credential/account namespace.
    pub account: ProviderAccountKey,
    /// Opaque provider call-control identifier.
    pub provider_call_id: ProviderCallId,
}

impl fmt::Debug for ProviderExecutionReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderExecutionReference")
            .field("account", &"[redacted]")
            .field("provider_call_id", &"[redacted]")
            .finish()
    }
}

/// Start the provider leg whose media terminates at a one-time Bridgefu SIP
/// attachment.
pub struct ProviderStartMediaRequest {
    /// Durable ownership and command-id guard.
    pub context: ProviderExecutionContext,
    /// Versioned, redacted ownership and allowlisted business context.
    pub client_state: ProviderDialClientState,
    /// Credential-free endpoint/profile selection from the immutable plan.
    pub endpoint: ProviderEndpointConfig,
    /// One-use, two-minute bearer for the configured SIP attachment URI.
    pub attachment_token: ProviderMediaAttachmentToken,
}

impl fmt::Debug for ProviderStartMediaRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderStartMediaRequest")
            .field("context", &self.context)
            .field("client_state", &self.client_state)
            .field("endpoint", &self.endpoint)
            .field("attachment_token", &self.attachment_token)
            .finish()
    }
}

/// Dial the configured provider destination and link it to the established
/// provider media call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderConnectDestinationRequest {
    /// Durable ownership and command-id guard.
    pub context: ProviderExecutionContext,
    /// Versioned, redacted ownership and allowlisted business context.
    pub client_state: ProviderDialClientState,
    /// Credential-free endpoint/profile selection and destination.
    pub endpoint: ProviderEndpointConfig,
    /// Primary provider media call created by `start_media`.
    pub media_call: ProviderExecutionReference,
}

/// Transfer one current provider media call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderTransferRequest {
    /// Durable ownership and command-id guard.
    pub context: ProviderExecutionContext,
    /// Credential-free endpoint/profile selection.
    pub endpoint: ProviderEndpointConfig,
    /// Primary provider media call.
    pub media_call: ProviderExecutionReference,
    /// Validated typed transfer destination.
    pub target: TransferTarget,
    /// Exact transfer generation echoed through authenticated provider events.
    pub correlation: ProviderTransferCorrelation,
}

/// Terminate one current provider media call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderHangupRequest {
    /// Durable ownership and command-id guard.
    pub context: ProviderExecutionContext,
    /// Credential-free endpoint/profile selection.
    pub endpoint: ProviderEndpointConfig,
    /// Primary provider media call.
    pub media_call: ProviderExecutionReference,
}

/// Send DTMF through one current provider media call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderDtmfRequest {
    /// Durable ownership and command-id guard.
    pub context: ProviderExecutionContext,
    /// Credential-free endpoint/profile selection.
    pub endpoint: ProviderEndpointConfig,
    /// Primary provider media call.
    pub media_call: ProviderExecutionReference,
    /// Validated digit/timing request. Its `Debug` output redacts digits.
    pub sequence: DtmfSequence,
}

/// Safe provider execution failure. No SDK response body, credential, target,
/// phone number, or attachment URI is retained.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderExecutionError {
    /// No provider executor was installed for this process.
    #[error("provider execution is disabled")]
    Disabled,
    /// The selected provider or operation is intentionally unsupported.
    #[error("provider operation is unsupported")]
    Unsupported,
    /// The plan's provider/profile does not match configured credentials.
    #[error("provider account profile does not match")]
    AccountProfileMismatch,
    /// A bounded provider request failed local validation.
    #[error("provider request is invalid")]
    InvalidRequest,
    /// A provider or transport operation failed.
    #[error("provider operation failed (retryable: {retryable})")]
    Remote {
        /// Whether retrying the exact effect and command ID may succeed.
        retryable: bool,
    },
}

impl ProviderExecutionError {
    /// Whether retrying the exact effect with its original command ID is safe.
    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(self, Self::Remote { retryable: true })
    }
}

/// Provider SDK abstraction owned by durable call actors.
#[async_trait]
pub trait ProviderLegExecutor: Send + Sync {
    /// Originate the provider media leg to a one-time Bridgefu SIP attachment.
    async fn start_media(
        &self,
        request: ProviderStartMediaRequest,
    ) -> Result<ProviderExecutionReference, ProviderExecutionError>;

    /// Originate and link the configured remote destination.
    async fn connect_destination(
        &self,
        request: ProviderConnectDestinationRequest,
    ) -> Result<ProviderExecutionReference, ProviderExecutionError>;

    /// Transfer the primary media call.
    async fn transfer(
        &self,
        request: ProviderTransferRequest,
    ) -> Result<(), ProviderExecutionError>;

    /// Hang up the primary media call.
    async fn hangup(&self, request: ProviderHangupRequest) -> Result<(), ProviderExecutionError>;

    /// Send DTMF through the primary media call.
    async fn send_dtmf(&self, request: ProviderDtmfRequest) -> Result<(), ProviderExecutionError>;
}

/// Fail-closed compatibility executor installed by the legacy supervisor
/// constructor and by runtimes with no native provider configuration.
#[derive(Clone, Copy, Debug, Default)]
pub struct DisabledProviderLegExecutor;

#[async_trait]
impl ProviderLegExecutor for DisabledProviderLegExecutor {
    async fn start_media(
        &self,
        _request: ProviderStartMediaRequest,
    ) -> Result<ProviderExecutionReference, ProviderExecutionError> {
        Err(ProviderExecutionError::Disabled)
    }

    async fn connect_destination(
        &self,
        _request: ProviderConnectDestinationRequest,
    ) -> Result<ProviderExecutionReference, ProviderExecutionError> {
        Err(ProviderExecutionError::Disabled)
    }

    async fn transfer(
        &self,
        _request: ProviderTransferRequest,
    ) -> Result<(), ProviderExecutionError> {
        Err(ProviderExecutionError::Disabled)
    }

    async fn hangup(&self, _request: ProviderHangupRequest) -> Result<(), ProviderExecutionError> {
        Err(ProviderExecutionError::Disabled)
    }

    async fn send_dtmf(&self, _request: ProviderDtmfRequest) -> Result<(), ProviderExecutionError> {
        Err(ProviderExecutionError::Disabled)
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    #[test]
    fn durable_effect_id_is_the_exact_provider_command_id() {
        let effect_id =
            EffectId::from_uuid(Uuid::parse_str("891510ac-f3e4-11e8-af5b-de00688a4901").unwrap())
                .unwrap();
        let context = ProviderExecutionContext {
            tenant_id: TenantId::parse("tenant-a").unwrap(),
            call_id: CallId::new(),
            leg_id: LegId::new(),
            binding_generation: BindingGeneration::INITIAL,
            effect_id,
        };

        assert_eq!(context.command_id(), effect_id.to_string());
        assert_eq!(context.command_id(), "891510ac-f3e4-11e8-af5b-de00688a4901");
        assert_eq!(
            context.destination_command_id(),
            "891510ac-f3e4-11e8-af5b-de00688a4903"
        );
        assert_ne!(context.destination_command_id(), context.command_id());
        assert!(!Uuid::parse_str(&context.destination_command_id())
            .unwrap()
            .is_nil());
    }

    #[test]
    fn attachment_token_debug_never_exposes_the_bearer() {
        let token = ProviderMediaAttachmentToken::new("diagnostic-attachment-secret".into());
        let debug = format!("{token:?}");
        assert!(!debug.contains("diagnostic-attachment-secret"));
        assert_eq!(debug, "ProviderMediaAttachmentToken([redacted])");
    }

    fn dial_context() -> ProviderExecutionContext {
        ProviderExecutionContext {
            tenant_id: TenantId::parse("diagnostic-secret-tenant").unwrap(),
            call_id: CallId::from_uuid(Uuid::from_u128(41)).unwrap(),
            leg_id: LegId::from_uuid(Uuid::from_u128(42)).unwrap(),
            binding_generation: BindingGeneration::INITIAL,
            effect_id: EffectId::from_uuid(Uuid::from_u128(43)).unwrap(),
        }
    }

    fn dial_policy() -> ContextPolicy {
        ContextPolicy {
            allow_headers: BTreeMap::from([
                ("X-Correlation-Id".into(), "correlation_id".into()),
                ("X-Account-Tier".into(), "account_tier".into()),
            ]),
            ..ContextPolicy::default()
        }
    }

    #[test]
    fn provider_dial_state_projects_policy_and_round_trips_without_debug_leaks() {
        let context = dial_context();
        let mut envelope = ContextEnvelope::new(
            "diagnostic-secret-correlation",
            context.tenant_id.as_str(),
            context.call_id.to_string(),
            Uuid::from_u128(44).to_string(),
        );
        envelope
            .metadata
            .insert("account_tier".into(), "diagnostic-secret-gold".into());
        envelope.metadata.insert(
            "must_not_forward".into(),
            "diagnostic-secret-private".into(),
        );
        let state = ProviderDialClientState::new(
            &context,
            ProviderDialRole::Media,
            Some(&envelope),
            &dial_policy(),
        )
        .unwrap();

        assert_eq!(
            state.correlation_id(),
            Some("diagnostic-secret-correlation")
        );
        assert_eq!(
            state.metadata().get("account_tier").map(String::as_str),
            Some("diagnostic-secret-gold")
        );
        assert!(!state.metadata().contains_key("must_not_forward"));
        assert!(state.matches(&context, ProviderDialRole::Media));
        assert!(!state.matches(&context, ProviderDialRole::Destination));

        let encoded = telnyx::calls::client_state::encode_json(&state).unwrap();
        assert!(encoded.len() <= MAX_PROVIDER_DIAL_CLIENT_STATE_BYTES);
        let decoded =
            telnyx::calls::client_state::decode_json::<ProviderDialClientState>(&encoded).unwrap();
        assert_eq!(decoded, state);

        let debug = format!("{state:?}");
        for secret in [
            "diagnostic-secret-tenant",
            "diagnostic-secret-correlation",
            "diagnostic-secret-gold",
            "diagnostic-secret-private",
            &context.call_id.to_string(),
            &context.leg_id.to_string(),
            &context.effect_id.to_string(),
        ] {
            assert!(
                !debug.contains(secret),
                "client-state debug leaked {secret}"
            );
        }
    }

    #[test]
    fn provider_dial_state_rejects_wrong_owner_version_and_oversize_projection() {
        let context = dial_context();
        let mut wrong_owner = ContextEnvelope::new(
            "correlation",
            context.tenant_id.as_str(),
            CallId::new().to_string(),
            LegId::new().to_string(),
        );
        wrong_owner
            .metadata
            .insert("account_tier".into(), "gold".into());
        assert_eq!(
            ProviderDialClientState::new(
                &context,
                ProviderDialRole::Media,
                Some(&wrong_owner),
                &dial_policy(),
            ),
            Err(ProviderDialClientStateError::OwnershipMismatch)
        );

        let mut valid =
            ProviderDialClientState::new(&context, ProviderDialRole::Media, None, &dial_policy())
                .unwrap();
        valid.version = 2;
        assert_eq!(
            valid.validate(),
            Err(ProviderDialClientStateError::InvalidContext)
        );

        let mut oversized = ContextEnvelope::new(
            "correlation",
            context.tenant_id.as_str(),
            context.call_id.to_string(),
            LegId::new().to_string(),
        );
        oversized
            .metadata
            .insert("large_a".into(), "a".repeat(1_800));
        oversized
            .metadata
            .insert("large_b".into(), "b".repeat(1_800));
        let policy = ContextPolicy {
            allow_headers: BTreeMap::from([
                ("X-Large-A".into(), "large_a".into()),
                ("X-Large-B".into(), "large_b".into()),
            ]),
            ..ContextPolicy::default()
        };
        assert_eq!(
            ProviderDialClientState::new(
                &context,
                ProviderDialRole::Destination,
                Some(&oversized),
                &policy,
            ),
            Err(ProviderDialClientStateError::TooLarge)
        );
    }
}
