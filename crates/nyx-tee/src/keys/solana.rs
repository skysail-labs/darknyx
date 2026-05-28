//! Solana fee-payer keypair derivation from dstack.
//!
//! Same shape as `keys::ed25519::derive` — `Some(path), None` for
//! purpose — but a DIFFERENT path so the two key materials are
//! independent. Compromise of the TEE's settle-signing Ed25519
//! key (which signs `MatchResultPayload` over canonical bytes)
//! shouldn't leak the fee-payer keypair, and vice versa.
//!
//! Funding: the derived pubkey needs SOL on whichever cluster the
//! TEE points at. First-time CVM boots need a manual airdrop
//! (devnet: `solana airdrop 5 <pubkey>`); production deployments
//! pre-fund the address out of band. The pubkey is logged at boot
//! and surfaced via `/info` (added in 4g.5 — for now operators
//! read it from the boot log).

use anyhow::{Context, Result};
use dstack_sdk::dstack_client::DstackClient;
use solana_keypair::Keypair;
use solana_signer::Signer;

use crate::solana_rpc::RpcError;

/// dstack key derivation path. **Changing this triggers a multisig
/// rotation ceremony** (same rules as the Ed25519 signer path —
/// see `docs/tee-attestation-flow.md` §5).
pub const FEE_PAYER_PATH: &str = "nyx/solana-fee-payer/v1";

/// Derived fee-payer + display-ready encodings. Same shape as
/// `keys::ed25519::DerivedSigner` — kept similar so future
/// refactors can unify the two derivations behind a generic
/// keypair-derivation helper if it pays off.
pub struct FeePayer {
    /// The Solana Keypair (64 bytes = 32-byte secret + 32-byte
    /// public). Used to sign all settle-pipeline txs. **Private**:
    /// never log, never serialise.
    pub keypair: Keypair,
    /// Base58 encoding of the public key. The address that needs
    /// to hold SOL on the target cluster.
    pub pubkey_base58: String,
}

/// Derive the fee-payer.
///
/// Stages:
///   1. `dstack.get_key(FEE_PAYER_PATH, None)` → 32-byte seed.
///   2. `Keypair::new_from_array(seed)` constructs the Ed25519
///      keypair byte-for-byte the same way as
///      `solders.Keypair.from_seed(seed)` (the Python settle
///      tooling), so a manually-airdropped balance on the derived
///      pubkey is retained across CVM restarts on the same
///      `app_id`.
pub async fn derive(client: &DstackClient) -> Result<FeePayer> {
    let resp = client
        .get_key(Some(FEE_PAYER_PATH.to_string()), None)
        .await
        .with_context(|| format!("dstack.get_key('{FEE_PAYER_PATH}') failed"))?;
    let seed_bytes = resp
        .decode_key()
        .with_context(|| "dstack.get_key returned undecodable fee-payer key")?;
    let seed_array: [u8; 32] = seed_bytes
        .as_slice()
        .try_into()
        .context("dstack.get_key returned non-32-byte material for fee-payer")?;

    let keypair = Keypair::new_from_array(seed_array);
    let pubkey_base58 = keypair.pubkey().to_string();
    Ok(FeePayer {
        keypair,
        pubkey_base58,
    })
}

/// Helper for the `solana_rpc` layer: surface a deterministic
/// `RpcError::KeyMaterial` when caller code wants to fail with the
/// same error type used by the RPC client. The `derive` fn above
/// returns `anyhow::Result` because main.rs's boot path is
/// `anyhow` — this conversion is the boundary for callers that
/// want typed errors.
pub fn into_rpc_error(e: anyhow::Error) -> RpcError {
    RpcError::KeyMaterial(format!("{e:#}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fee_payer_path_constant_documented() {
        // Pinned at "/v1" — any bump requires a multisig rotation.
        // This test exists so a careless rename of the path
        // constant trips a unit failure before deploy.
        assert_eq!(FEE_PAYER_PATH, "nyx/solana-fee-payer/v1");
    }

    #[test]
    fn keypair_from_seed_round_trips() {
        // Sanity: same seed → same pubkey. The deterministic
        // derivation is the invariant that lets us pre-fund the
        // address on devnet and retain the balance across reboots.
        let seed = [0x42u8; 32];
        let kp1 = Keypair::new_from_array(seed);
        let kp2 = Keypair::new_from_array(seed);
        assert_eq!(kp1.pubkey(), kp2.pubkey());
    }
}
