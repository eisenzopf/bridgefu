//! Reusable Bridgefu control-plane building blocks.
//!
//! The production binary remains in `main.rs`.  Library modules are deliberately
//! free of process-global state so they can also be used by workers, gateways,
//! tests, and administrative tools.

pub mod api_principal;
pub mod call_engine;
pub mod persistence;
