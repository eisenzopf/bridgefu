//! Durable service-layer models and repository contracts.
//!
//! The call engine remains a transport-neutral state machine. This module adds
//! the immutable execution plan and transactional records needed by a worker
//! without changing the existing call-engine public API.

mod execution;
mod idempotency;
mod model;
mod outbound_profiles;
mod provider_execution;
mod repository;
mod runtime;
mod service;
mod view;

pub use execution::*;
pub use idempotency::*;
pub use model::*;
#[doc(hidden)]
pub use outbound_profiles::{
    ConfiguredIceServer, ConfiguredSipOutboundProfile, ConfiguredSipProfileAuth,
    ConfiguredWebRtcOutboundProfile, StaticOutboundProfileResolver,
};
pub use outbound_profiles::{
    DisabledOutboundProfileResolver, OutboundProfileError, OutboundProfileResolver,
};
pub use provider_execution::*;
pub use repository::*;
pub use runtime::*;
pub use service::*;
pub use view::*;
