//! Durable service-layer models and repository contracts.
//!
//! The call engine remains a transport-neutral state machine. This module adds
//! the immutable execution plan and transactional records needed by a worker
//! without changing the existing call-engine public API.

mod idempotency;
mod model;
mod repository;
mod service;
mod view;

pub use idempotency::*;
pub use model::*;
pub use repository::*;
pub use service::*;
pub use view::*;
