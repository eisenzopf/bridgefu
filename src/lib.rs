//! Reusable Bridgefu control-plane building blocks.
//!
//! The production binary remains in `main.rs`.  Library modules are deliberately
//! free of process-global state so they can also be used by workers, gateways,
//! tests, and administrative tools.

// A small number of modules are also compiled into the historical binary
// crate, where they refer to this library by package name. Keep the same
// absolute path valid when those modules are reused from the library itself.
extern crate self as bridgefu;

pub mod amazon_cleanup;
pub mod api_principal;
pub mod broadcast;
pub mod call_engine;
pub mod call_service;
pub mod context;
pub mod coordination;
pub mod gateway_attachment;
pub mod gateway_forwarding;
pub mod gateway_native_ingress;
pub mod gateway_uctp_ingress;
pub mod handoff_status;
pub mod persistence;
pub mod private_egress;
pub mod private_egress_redis;
pub mod private_egress_state;
pub mod private_egress_stream;
pub mod providers;
pub mod secret_ref;
pub mod signaling_token;
pub mod standardcharter_canary;
