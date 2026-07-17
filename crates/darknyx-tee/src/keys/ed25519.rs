//! Ed25519 signer derivation from a dstack-supplied seed.
//!
//! The single load-bearing constant in this module is the path PREFIX
//! `"darknyx/ed25519-signer/v2"`. **Bumping it triggers the full
//! multisig rotation ceremony** documented in
//! `docs/tee-attestation-flow.md` §5. Same seed → same signing
//! key, deterministically, for the lifetime of the compose-hash.
//!
//! Tree-sharding (Phase 2) derives **K** signers — one per shard —
//! at the indexed sub-paths `"darknyx/ed25519-signer/v2/{i}"` for
//! `i ∈ 0..K`. Each key is simultaneously a shard fee-payer +
//! `tee_authority` + Ed25519 settle-signer, so the K concurrent
//! settle Tx D's (one per shard) share NO writable account: distinct
//! `merkle_tree[i]` + distinct fee-payer `key[i]` → the leader has no
//! reason to serialize them across blocks. All K are registered in
//! `vault_config.tee_pubkeys` via `set_tee_pubkey` at the ceremony.

use anyhow::{Context, Result};
use dstack_sdk::dstack_client::DstackClient;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use solana_keypair::Keypair;

/// The canonical derivation-path PREFIX. The K per-shard signers live at
/// `"{SIGNER_PATH}/{i}"`. Clients do NOT re-derive these (they can't — the seed
/// is dstack-sealed); instead the enclave advertises the derived set on `/info`
/// (`tee_pubkeys`), which `packages/sdk/src/tee/attestation.ts` reads and a
/// client reconciles against on-chain `vault_config.tee_pubkeys`.
pub const SIGNER_PATH: &str = "darknyx/ed25519-signer/v2";

/// The dstack derivation path for shard `index`'s signer.
pub fn signer_path(index: u8) -> String {
    format!("{SIGNER_PATH}/{index}")
}

/// Derived Ed25519 signing key + display-ready encodings.
///
/// One keypair, two type views: `key` for `canonical_payload_hash`
/// signing (settle pipeline payload auth); [`Self::solana_keypair`]
/// for Solana tx signing (the same key acts as `tee_authority` AND
/// the tx fee-payer for every settle-pipeline tx — see PR 4g.3 for
/// the walk-back rationale).
pub struct DerivedSigner {
    /// The full Ed25519 keypair. **Private**: never serialise,
    /// never log, never leave this struct's owning scope. Used to
    /// sign `canonical_payload_hash(payload)` for
    /// `tee_forced_settle_batched`.
    pub key: SigningKey,
    /// Base58 encoding of the public key. Matches the Solana
    /// wire format; this is what `vault_config.tee_pubkey` holds
    /// AND the address that needs to hold SOL on whichever cluster
    /// the TEE points at.
    pub pubkey_base58: String,
    /// Hex encoding of the same public key. Useful for the
    /// `report_data` binding when calling `get_quote(SHA-256(pubkey))`.
    pub pubkey_hex: String,
}

impl DerivedSigner {
    /// Construct a fresh Solana `Keypair` from the same 32-byte
    /// Ed25519 seed `self.key` was built from. Cheap (one Ed25519
    /// pubkey-derivation step); the caller takes ownership so it
    /// can be moved into a settle-stage worker without keeping a
    /// reference back to this struct.
    ///
    /// **Property**: the returned `Keypair::pubkey()` equals the
    /// pubkey in `self.pubkey_base58`. This is what makes the
    /// "TEE signer == Solana fee-payer == `vault_config.tee_pubkey`"
    /// unification work — one funded address satisfies every
    /// signer constraint in the settle pipeline.
    pub fn solana_keypair(&self) -> Keypair {
        // `SigningKey::to_bytes()` returns the 32-byte secret seed.
        // `Keypair::new_from_array` constructs the matching Solana
        // keypair byte-for-byte the same way `solders.Keypair.from_seed`
        // does in the Python tooling — so an airdrop to one is an
        // airdrop to both.
        Keypair::new_from_array(self.key.to_bytes())
    }

    /// The raw 32-byte Ed25519 public key.
    pub fn pubkey_bytes(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
}

/// SHA-256 over the K shard signer pubkeys, concatenated in shard order
/// (`pk_0 ‖ pk_1 ‖ … ‖ pk_{K-1}`, raw 32-byte each). This is the value the
/// attestation `report_data` right-half commits to, so a client can bind the
/// ENTIRE settle-authorizing key set to the DCAP-verified quote — not just the
/// primary. For a single-shard TEE this is exactly `SHA-256(pk_0)`, so the
/// binding is backward-compatible with the shard-0-only scheme.
pub fn signer_set_hash(signers: &[DerivedSigner]) -> [u8; 32] {
    let mut h = Sha256::new();
    for s in signers {
        h.update(s.pubkey_bytes());
    }
    h.finalize().into()
}

/// Derive shard `index`'s signer from dstack's KDF.
///
/// Stages:
///   1. Call `dstack.get_key("darknyx/ed25519-signer/v2/{index}")` —
///      returns hex-encoded 32-byte seed material.
///   2. `decode_key()` to bytes; assert length == 32.
///   3. Construct `SigningKey::from_bytes(&seed)`. The same 32-byte
///      seed is what Python's `solders.Keypair.from_seed(...)` uses
///      (which is what we validated end-to-end against a real
///      Phala Cloud CVM in the Phase-1 smoke test), so the Solana
///      pubkey produced here is byte-identical to that path.
pub async fn derive(client: &DstackClient, index: u8) -> Result<DerivedSigner> {
    let path = signer_path(index);
    let resp = client
        .get_key(Some(path.clone()), None)
        .await
        .with_context(|| format!("dstack.get_key('{path}') failed"))?;

    let seed_bytes = resp
        .decode_key()
        .with_context(|| "dstack.get_key returned undecodable key material")?;
    let seed_array: [u8; 32] = seed_bytes
        .as_slice()
        .try_into()
        .context("dstack.get_key returned non-32-byte material")?;

    let key = SigningKey::from_bytes(&seed_array);
    let pubkey_bytes = key.verifying_key().to_bytes();

    Ok(DerivedSigner {
        key,
        pubkey_base58: bs58::encode(pubkey_bytes).into_string(),
        pubkey_hex: hex::encode(pubkey_bytes),
    })
}

/// Derive the full K-signer set (`count` keys, one per shard), at the
/// indexed sub-paths `0..count`. `count` must be in `1..=MAX` (the vault's
/// `MAX_TEE_KEYS = 16`); the caller passes `num_trees`. Returns the signers
/// in shard order, so `signers[i]` is shard `i`'s fee-payer/authority.
pub async fn derive_set(client: &DstackClient, count: u8) -> Result<Vec<DerivedSigner>> {
    anyhow::ensure!(
        (1..=16).contains(&count),
        "tee signer count {count} out of range (1..=16)"
    );
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count {
        out.push(derive(client, i).await?);
    }
    Ok(out)
}
