//! Deliberately credential-free public call and operation views.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::Serialize;
use zeroize::Zeroize;

use crate::call_engine::{
    AttachmentTransport, CallAggregate, CallId, CallState, CommandId, EffectId, FailureDetails,
    Leg, LegDirection, LegId, LegKind, LegState, TenantId,
};

use super::{ControlCommandView, DerivedAttachmentToken, StoredServiceCall};

/// Sanitized terminal failure exposed by the REST API.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FailureView {
    /// Stable safe failure code.
    pub code: String,
    /// Bounded single-line safe message.
    pub message: String,
    /// Whether policy may retry the operation.
    pub retryable: bool,
}

impl From<&FailureDetails> for FailureView {
    fn from(value: &FailureDetails) -> Self {
        Self {
            code: value.code().to_owned(),
            message: value.message().to_owned(),
            retryable: value.retryable(),
        }
    }
}

/// One single-use inbound signaling attachment returned only at creation.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct AttachmentView {
    /// URL-safe, unpadded 256-bit bearer token.
    pub token: String,
    /// Exact accepted signaling transport.
    pub transport: AttachmentTransport,
    /// Absolute two-minute expiry.
    pub expires_at: DateTime<Utc>,
}

impl fmt::Debug for AttachmentView {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AttachmentView")
            .field("token", &"[redacted]")
            .field("transport", &self.transport)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl Drop for AttachmentView {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

impl AttachmentView {
    pub(crate) fn from_token(
        token: DerivedAttachmentToken,
        transport: AttachmentTransport,
    ) -> Self {
        Self {
            token: token.expose_secret().to_owned(),
            transport,
            expires_at: token.expires_at,
        }
    }
}

/// Safe public state for one logical leg.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LegView {
    /// Generated logical leg ID.
    pub leg_id: LegId,
    /// Direction relative to Bridgefu.
    pub direction: LegDirection,
    /// Signaling/provider family.
    pub kind: LegKind,
    /// Current typed lifecycle state.
    pub state: LegState,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Latest state transition.
    pub state_changed_at: DateTime<Utc>,
    /// First connected time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connected_at: Option<DateTime<Utc>>,
    /// Terminal time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<DateTime<Utc>>,
    /// Sanitized failure details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<FailureView>,
    /// Initial inbound attachment. Omitted from later reads and mutations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachment: Option<AttachmentView>,
}

impl LegView {
    fn from_leg(leg: &Leg) -> Self {
        Self {
            leg_id: leg.id(),
            direction: leg.direction(),
            kind: leg.kind(),
            state: leg.state(),
            created_at: leg.created_at(),
            state_changed_at: leg.state_changed_at(),
            connected_at: leg.connected_at(),
            ended_at: leg.ended_at(),
            failure: leg.failure().map(FailureView::from),
            attachment: None,
        }
    }
}

/// Credential- and endpoint-free call representation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CallView {
    /// Generated call ID.
    pub call_id: CallId,
    /// Authenticated owner tenant.
    pub tenant_id: TenantId,
    /// Current typed lifecycle state.
    pub state: CallState,
    /// The two explicitly bridged legs.
    pub legs: [LegView; 2],
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Latest applied command time.
    pub updated_at: DateTime<Utc>,
    /// Latest call-state transition time.
    pub state_changed_at: DateTime<Utc>,
}

impl CallView {
    /// Builds a safe view without endpoint configuration or attachment tokens.
    #[must_use]
    pub fn from_aggregate(aggregate: &CallAggregate) -> Self {
        Self {
            call_id: aggregate.id(),
            tenant_id: aggregate.tenant_id().clone(),
            state: aggregate.state(),
            legs: [
                LegView::from_leg(&aggregate.legs()[0]),
                LegView::from_leg(&aggregate.legs()[1]),
            ],
            created_at: aggregate.created_at(),
            updated_at: aggregate.updated_at(),
            state_changed_at: aggregate.state_changed_at(),
        }
    }

    pub(crate) fn from_stored(call: &StoredServiceCall) -> Self {
        Self::from_aggregate(&call.call.aggregate)
    }

    pub(crate) fn attach(&mut self, leg_id: LegId, attachment: AttachmentView) {
        if let Some(leg) = self.legs.iter_mut().find(|leg| leg.leg_id == leg_id) {
            leg.attachment = Some(attachment);
        }
    }
}

/// Call-creation result. Exact retries return the same serialized value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CreateCallView {
    /// Safe call snapshot produced by the initial transaction.
    #[serde(flatten)]
    pub call: CallView,
}

/// Service result with replay disposition kept outside the public JSON value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallOperationResult<T> {
    /// Original operation value.
    pub value: T,
    /// Whether the tenant-wide receipt supplied that value.
    pub replayed: bool,
}

/// Durable DTMF acceptance receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DtmfAcceptedView {
    /// Owning call.
    pub call_id: CallId,
    /// Exact bound leg.
    pub leg_id: LegId,
    /// Stable command receipt ID.
    pub command_id: CommandId,
    /// Stable control-effect ID.
    pub effect_id: EffectId,
    /// Repository acceptance time.
    pub accepted_at: DateTime<Utc>,
}

impl DtmfAcceptedView {
    pub(crate) fn from_control(value: &ControlCommandView) -> Self {
        Self {
            call_id: value.command.call_id,
            leg_id: value.command.leg_id,
            command_id: value.command.command_id,
            effect_id: value.effect.effect_id,
            accepted_at: value.command.recorded_at,
        }
    }
}
