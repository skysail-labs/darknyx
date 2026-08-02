//! dstack-derived keypair management. See
//! `docs/tee-architecture.md` §4 + `docs/tee-attestation-flow.md` §1.
//!
//! All of this is IMPLEMENTED in [`ed25519`] and [`solana`] (SW-30 — this
//! header described it as a stub with the work still ahead, which is the kind
//! of line a reader trusts when deciding whether a boundary exists yet):
//!   - `dstack.get_key("darknyx/ed25519-signer/v2")` is called at boot, and
//!     under tree-sharding derives the K per-shard signers
//!     (`darknyx/ed25519-signer/v2/{0..K-1}`)
//!   - the Ed25519 signing key is constructed from the returned seed
//!     ([`ed25519::DerivedSigner`])
//!   - the pubkey — and the whole K-shard set — is exposed via `/info`
//!   - [`ed25519::DerivedSigner::solana_keypair`] converts to the Solana
//!     fee-payer keypair; the dstack SDK's `solana.to_keypair()` helper is
//!     still Python-only, so that conversion stays ours

pub mod ed25519;
pub mod solana;
