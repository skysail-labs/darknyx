//! `verify_match_batch` instruction builder (Tx B of the v3
//! settle pipeline).
//!
//! Submits the TEE's VALID_MATCH_BATCH Groth16 proof + the batch
//! Merkle root. On success the on-chain handler allocates the
//! `BatchValidityMarker` PDA (seeded by the merkle root, 1:N — one
//! per batch) that Tx D consumes per match.
//!
//! On-chain reference:
//! `programs/vault/src/instructions/verify_match_batch.rs`.
//!
//! Args (Borsh, declaration order):
//!   1. `merkle_root: [u8; 32]`  — the batch root (first public input)
//!   2. `proof: Groth16Proof`    — 256 bytes (pi_a 64 + pi_b 128 +
//!      pi_c 64), produced by the prover
//!   3. `fee_key_epoch: u64`
//!   4. `fee_recovery_ciphertext: [u8; 272]`
//!
//! **The marker TTL is not an argument — the program derives it.** A
//! caller-supplied TTL, even one bounded to
//! `(current_slot, current_slot + MAX_BATCH_VALIDITY_MARKER_TTL_SLOTS]`, lets
//! anyone replaying this proof pick a 1-slot TTL, win the `init`, and kill every
//! settle in the batch while the locks are already down (audit S-04).
//!
//! Accounts (positional, mirror `VerifyMatchBatch<'info>`):
//!   `[0]` payer            — signer + writable; must be one of the finalized
//!                            authorized TEE keys and pays rent + fee
//!   `[1]` vault_config     — readonly; supplies fee + owner digest preimage
//!   `[2]` market_config    — readonly; supplies mint/scale digest preimage
//!   `[3]` marker           — writable PDA (init), seeds
//!                            `[b"batch_validity", merkle_root]`
//!   `[4]` system_program   — readonly

use std::sync::LazyLock;

use borsh::BorshSerialize;
use sha2::{Digest, Sha256};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};

use super::lock_note::Groth16ProofBytes;
use super::vault::{
    batch_validity_marker_pda, market_config_pda, vault_config_pda, vault_program_id,
    SYSTEM_PROGRAM_ID,
};

/// Anchor discriminator for `verify_match_batch`:
/// `sha256("global:verify_match_batch")[..8]`.
pub static VERIFY_MATCH_BATCH_DISCRIMINATOR: LazyLock<[u8; 8]> = LazyLock::new(|| {
    let h = Sha256::digest(b"global:verify_match_batch");
    let mut out = [0u8; 8];
    out.copy_from_slice(&h[..8]);
    out
});

/// Args to `verify_match_batch`, in the handler's declaration order.
#[derive(Clone, Debug, BorshSerialize)]
pub struct VerifyMatchBatchArgs {
    pub merkle_root: [u8; 32],
    pub proof: Groth16ProofBytes,
    pub fee_key_epoch: u64,
    pub fee_recovery_ciphertext: [u8; 272],
}

impl VerifyMatchBatchArgs {
    /// Borsh-encoded width: 32 + 256 + 8 + 272 = 568 bytes.
    pub const WIRE_LEN: usize = 32 + Groth16ProofBytes::WIRE_LEN + 8 + 272;
}

/// Build the `verify_match_batch` instruction. `payer` is the TEE
/// pubkey (signer + fee-payer). The marker PDA is derived from the
/// merkle root.
pub fn build_verify_match_batch_ix(
    payer: &Address,
    base_mint: &[u8; 32],
    quote_mint: &[u8; 32],
    args: VerifyMatchBatchArgs,
) -> Instruction {
    let program_id = vault_program_id();
    let (marker_pda, _) = batch_validity_marker_pda(&args.merkle_root);

    let (vault_config, _) = vault_config_pda();
    let (market_config, _) = market_config_pda(base_mint, quote_mint);
    // Order MUST match: payer, vault_config, market_config, marker, system.
    let accounts = vec![
        AccountMeta::new(*payer, true), // payer: signer + writable
        AccountMeta::new_readonly(vault_config, false), // config-digest preimage
        AccountMeta::new_readonly(market_config, false),
        AccountMeta::new(marker_pda, false), // marker: writable (init)
        AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
    ];

    let mut data = Vec::with_capacity(8 + VerifyMatchBatchArgs::WIRE_LEN);
    data.extend_from_slice(&*VERIFY_MATCH_BATCH_DISCRIMINATOR);
    borsh::to_writer(&mut data, &args).expect("Borsh write to Vec cannot fail");

    Instruction {
        program_id,
        accounts,
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use solana_hash::Hash;
    use solana_keypair::Keypair;
    use solana_signer::Signer;

    fn dummy_proof() -> Groth16ProofBytes {
        Groth16ProofBytes {
            pi_a: [0x11; 64],
            pi_b: [0x22; 128],
            pi_c: [0x33; 64],
        }
    }

    fn dummy_args() -> VerifyMatchBatchArgs {
        VerifyMatchBatchArgs {
            merkle_root: [0xAB; 32],
            proof: dummy_proof(),
            fee_key_epoch: 7,
            fee_recovery_ciphertext: [0x44; 272],
        }
    }

    fn dummy_payer() -> Address {
        bs58::encode([0xEEu8; 32]).into_string().parse().unwrap()
    }

    fn mints() -> ([u8; 32], [u8; 32]) {
        ([0x44; 32], [0x55; 32])
    }

    #[test]
    fn discriminator_pins_to_anchor_global() {
        // sha256("global:verify_match_batch")[..8]. Pinned so a
        // refactor of the discriminator input string surfaces here
        // rather than as on-chain InvalidIxData.
        let expected = "717208eec60cdf29";
        let got = hex::encode(*VERIFY_MATCH_BATCH_DISCRIMINATOR);
        assert_eq!(got, expected, "verify_match_batch discriminator drifted");
    }

    #[test]
    fn ix_data_starts_with_discriminator_and_has_right_len() {
        let (base, quote) = mints();
        let ix = build_verify_match_batch_ix(&dummy_payer(), &base, &quote, dummy_args());
        assert_eq!(&ix.data[..8], &*VERIFY_MATCH_BATCH_DISCRIMINATOR);
        // 8 disc + 32 root + 256 proof = 296. S-04 removed the 8-byte
        // caller-supplied expiry; a regression that re-adds it grows this.
        assert_eq!(ix.data.len(), 8 + VerifyMatchBatchArgs::WIRE_LEN);
        assert_eq!(ix.data.len(), 576);
    }

    #[test]
    fn ix_data_field_order() {
        let (base, quote) = mints();
        let ix = build_verify_match_batch_ix(&dummy_payer(), &base, &quote, dummy_args());
        let body = &ix.data[8..];
        assert_eq!(&body[0..32], &[0xAB; 32]); // merkle_root
                                               // S-04: no expiry_slot on the wire — the program derives the TTL.
        assert_eq!(&body[32..96], &[0x11; 64]); // pi_a
        assert_eq!(&body[96..224], &[0x22; 128]); // pi_b
        assert_eq!(&body[224..288], &[0x33; 64]); // pi_c
        assert_eq!(&body[288..296], &7u64.to_le_bytes());
        assert_eq!(&body[296..568], &[0x44; 272]);
        assert_eq!(body.len(), 568);
    }

    #[test]
    fn account_layout_matches_anchor_struct() {
        let payer = dummy_payer();
        let (base, quote) = mints();
        let ix = build_verify_match_batch_ix(&payer, &base, &quote, dummy_args());
        assert_eq!(ix.accounts.len(), 5);

        // [0] payer: signer + writable
        assert_eq!(ix.accounts[0].pubkey, payer);
        assert!(ix.accounts[0].is_signer);
        assert!(ix.accounts[0].is_writable);

        // [1] vault_config: readonly (config-digest preimage)
        assert_eq!(ix.accounts[1].pubkey, vault_config_pda().0);
        assert!(!ix.accounts[1].is_signer);
        assert!(!ix.accounts[1].is_writable);

        // [2] market config: readonly and mint-pair bound
        assert_eq!(ix.accounts[2].pubkey, market_config_pda(&base, &quote).0);
        assert!(!ix.accounts[2].is_signer);
        assert!(!ix.accounts[2].is_writable);

        // [3] marker: writable PDA (init), not signer
        let (marker, _) = batch_validity_marker_pda(&[0xAB; 32]);
        assert_eq!(ix.accounts[3].pubkey, marker);
        assert!(!ix.accounts[3].is_signer);
        assert!(ix.accounts[3].is_writable);

        // [4] system_program: readonly
        assert_eq!(ix.accounts[4].pubkey, SYSTEM_PROGRAM_ID);
        assert!(!ix.accounts[4].is_signer);
        assert!(!ix.accounts[4].is_writable);
    }

    #[test]
    fn marker_pda_varies_with_root() {
        let mut args2 = dummy_args();
        args2.merkle_root = [0x01; 32];
        let (base, quote) = mints();
        let ix1 = build_verify_match_batch_ix(&dummy_payer(), &base, &quote, dummy_args());
        let ix2 = build_verify_match_batch_ix(&dummy_payer(), &base, &quote, args2);
        assert_ne!(ix1.accounts[3].pubkey, ix2.accounts[3].pubkey);
    }

    #[test]
    fn worst_case_tx_b_retains_packet_headroom() {
        use crate::settle::pipeline::{budget_ixs, VERIFY_COMPUTE_UNIT_LIMIT};
        use crate::settle::submit::build_tx_b64;

        let payer = Keypair::new_from_array([0x42; 32]);
        let (base, quote) = mints();
        let verify = build_verify_match_batch_ix(&payer.pubkey(), &base, &quote, dummy_args());
        let mut ixs = budget_ixs(VERIFY_COMPUTE_UNIT_LIMIT, 10_000);
        ixs.push(verify);
        let encoded =
            build_tx_b64(&payer, &ixs, Hash::new_from_array([0x11; 32])).expect("Tx B compiles");
        let wire = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .expect("base64 transaction");

        const SOLANA_CAP: usize = 1232;
        const MIN_HEADROOM: usize = 250;
        eprintln!(
            "TX_B_WIRE_SIZE_V2 bytes={} headroom={}",
            wire.len(),
            SOLANA_CAP - wire.len()
        );
        assert!(wire.len() <= SOLANA_CAP);
        assert!(SOLANA_CAP - wire.len() >= MIN_HEADROOM);
    }
}
