//! Durable service-layer models and repository contracts.
//!
//! The call engine remains a transport-neutral state machine. This module adds
//! the immutable execution plan and transactional records needed by a worker
//! without changing the existing call-engine public API.

mod model;
mod repository;

pub use model::*;
pub use repository::*;
