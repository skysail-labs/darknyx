//! HTTP + WS surface. Wire contract: `docs/tee-api-openapi.yaml`.
//!
//! Phase 1: just module stubs so the binary compiles. The actual
//! axum routers + WS handlers come after we've wired the matcher
//! + indexer to in-memory state.

pub mod account;
pub mod attestation;
pub mod auth;
pub mod info;
pub mod orders;
pub mod settlement;
pub mod transparency;
pub mod tree;
pub mod ws;
