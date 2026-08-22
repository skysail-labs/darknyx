//! dstack-derived keypair management.
//!
//! See `docs/tee-architecture.md` §4 and `docs/tee-attestation-flow.md` §1.
//!
//! At boot the enclave calls `dstack.get_key("darknyx/ed25519-signer/v2")` and,
//! under tree sharding, derives K per-shard signers at
//! `darknyx/ed25519-signer/v2/{0..K-1}`. Each shard's signer is the Solana
//! fee-payer for that shard's settle transaction, which is what lets settles for
//! one batch be sent concurrently and co-included in a single block.
//!
//!   - [`ed25519::DerivedSigner`] builds the signing key from the returned seed.
//!   - [`ed25519::DerivedSigner::solana_keypair`] converts it to the Solana
//!     fee-payer keypair. The dstack SDK's own `solana.to_keypair()` helper is
//!     Python-only, so this conversion is ours to maintain.
//!
//! `/info` exposes only the primary (shard 0) signer. The full K-shard set appears
//! in the boot log, and **all K must be registered in `vault_config.tee_pubkeys` in
//! shard order and funded** — `keys[j]` settles shard `j`, so a missing or
//! unfunded key silently disables that shard rather than failing at boot.
//!
//! Keys are deterministic per `app_id`, so registration and funding are one-time
//! per CVM and survive restarts.

pub mod ed25519;
pub mod solana;
