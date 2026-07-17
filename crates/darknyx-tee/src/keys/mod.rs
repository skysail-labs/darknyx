//! dstack-derived keypair management. See
//! `docs/tee-architecture.md` §4 + `docs/tee-attestation-flow.md` §1.
//!
//! Phase 1: stub. Phase 2 will:
//!   - call `dstack.get_key("darknyx/ed25519-signer/v2")` at boot
//!   - construct an Ed25519 signing key from the returned seed
//!   - expose the pubkey via `/info`
//!   - use the dstack SDK's `solana.to_keypair()` helper if/when
//!     dstack-sdk publishes it for Rust (Python ships it today)

pub mod ed25519;
pub mod solana;
