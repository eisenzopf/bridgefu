//! Managed broadcast integration for real rvoip Connection media sources.
//!
//! This module owns the Bridgefu policy boundary around rvoip's transport
//! implementations. It deliberately does not know how a REST leg ID maps to a
//! Connection ID; the durable call engine supplies that mapping before calling
//! [`ManagedBroadcastService`].

mod command_executor;
mod commands;
mod context_events;
mod managed;
mod redis_grants;
mod sqlite_commands;
mod token;
mod uctp_listener;

pub use command_executor::{
    BroadcastCommandExecutor, BroadcastCommandExecutorConfig, WorkerBroadcastSubscriptionAuthority,
};
pub use commands::{
    BroadcastCommandError, BroadcastCommandRepository, BroadcastCommandResult,
    BroadcastEnqueueOutcome, BroadcastOperationIdentity, ClaimedBroadcastCommand,
    DurableBroadcastCommandKind, DurableBroadcastRecord, DurableBroadcastRuntime,
    DurableBroadcastSpec, DurableBroadcastState, DurableBroadcastTransport,
    MemoryBroadcastCommandRepository, PostgresBroadcastCommandRepository,
};
pub use context_events::{
    SanitizedContextEventError, SanitizedContextEventPolicy, SanitizedContextEventPolicyError,
    MAX_SANITIZED_EVENTS_PER_SECOND,
};
pub use managed::{
    ManagedBroadcast, ManagedBroadcastDiagnostics, ManagedBroadcastError, ManagedBroadcastService,
    ManagedBroadcastTransport, ManagedSanitizedEventBinding, ManagedSanitizedEventDiagnostics,
    MoqRelayTarget, MAX_DIRECT_UCTP_SUBSCRIBERS,
};
pub use redis_grants::{
    RedisBroadcastGrantConfig, RedisBroadcastGrantLease, RedisBroadcastGrantRevocationChecker,
    RedisBroadcastGrantStore, RedisUctpListenerLease,
};
pub use sqlite_commands::SqliteBroadcastCommandRepository;
pub(crate) use token::exact_subscriber_broadcast;
pub use token::{
    ActiveBroadcastGrant, BroadcastGrantLease, BroadcastGrantRegistry, BroadcastGrantTransport,
    BroadcastGrantVerifier, BroadcastSessionResolver, BroadcastTokenError, BroadcastTokenService,
    IssuedBroadcastToken, BRIDGEFU_BROADCAST_TOKEN_AUDIENCE, BRIDGEFU_BROADCAST_TOKEN_ISSUER,
    BRIDGEFU_BROADCAST_TOKEN_VERSION, DEFAULT_MAX_BROADCAST_TOKEN_TTL, MAX_BROADCAST_TOKEN_BYTES,
};
pub use uctp_listener::{
    PublicUctpBindConfig, PublicUctpBroadcastListener, PublicUctpListenerError,
};
