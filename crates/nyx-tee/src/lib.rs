//! `nyx-tee` library surface. Exists so integration tests can
//! exercise the internal modules without going through the
//! binary's `main.rs` boot path. Re-exports the public APIs that
//! external consumers (today: test code; later: PR-5+ admin tools
//! and observability glue) need.
//!
//! The binary in `main.rs` is the production entry point. It
//! pulls these same modules into its own scope and threads them
//! together. Either side compiles independently.

pub mod boot;
pub mod config;
pub mod keys;
pub mod oracle;

// The remaining modules are scaffolds that haven't grown
// public-facing APIs yet — they'll get re-exports here as the
// later PRs land.
// pub mod api;
// pub mod matcher;
// pub mod merkle;
// pub mod persistence;
// pub mod prover;
// pub mod settle;
