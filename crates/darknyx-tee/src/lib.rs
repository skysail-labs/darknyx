//! `darknyx-tee` library surface. Exists so integration tests can
//! exercise the internal modules without going through the
//! binary's `main.rs` boot path. Re-exports the public APIs that
//! external consumers (today: test code; later: PR-5+ admin tools
//! and observability glue) need.
//!
//! The binary in `main.rs` is the production entry point. It
//! pulls these same modules into its own scope and threads them
//! together. Either side compiles independently.

pub mod api;
pub mod boot;
pub mod config;
pub mod keys;
pub mod matcher;
pub mod merkle;
pub mod oracle;
pub mod prover;
pub mod settle;
pub mod solana_rpc;
pub mod verify;

// Supplies the `__rust_probestack` symbol that wasmer 4.4 (via
// ark-circom, in `prover`) references but Rust 1.91 no longer exports.
// No Rust items — just a `global_asm!` definition, x86_64-linux only.
// See the module doc comment for the full story.
mod probestack;

// Phase 1b — best-effort auth-state persistence (accounts.db).
pub mod persistence;
