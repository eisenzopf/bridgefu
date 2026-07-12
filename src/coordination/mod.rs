//! Worker coordination projections and payload-free wakeups.
//!
//! PostgreSQL (or the standalone repository) remains authoritative for worker
//! capacity, assignments, idempotency, and work claims. Redis is only a
//! sequence-checked projection and latency hint. Request paths never write both
//! the database and Redis; a durable coordination outbox is projected later.

mod memory;
mod model;
mod outbox;
mod redis;
mod sql_outbox;

#[cfg(test)]
mod tests;

pub use memory::{MemoryCoordinator, MemoryWakeupConsumer};
pub use model::*;
pub use outbox::{
    CoordinationOutbox, CoordinationOutboxClaim, CoordinationOutboxRecord, CoordinationOutboxState,
    CoordinationProjector, MemoryCoordinationOutbox,
};
pub use redis::{RedisCoordinationConfig, RedisCoordinator, RedisWakeupConsumer};
pub use sql_outbox::{PostgresCoordinationOutbox, SqliteCoordinationOutbox};
