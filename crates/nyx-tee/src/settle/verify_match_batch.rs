//! `verify_match_batch` instruction builder (Tx B of the v3.5
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
//!   1. `merkle_root: [u8; 32]`  — the batch root (single public
//!      input to the Groth16 proof)
//!   2. `expiry_slot: u64`       — marker TTL; must be in
//!      `(current_slot, current_slot + MAX_BATCH_VALIDITY_MARKER_TTL_SLOTS]`
//!   3. `proof: Groth16Proof`    — 256 bytes (pi_a 64 + pi_b 128 +
//!      pi_c 64), produced by the 4g.4b prover
//!
//! Accounts (positional, mirror `VerifyMatchBatch<'info>`):
//!   `[0]` payer            — signer + writable (the TEE keypair;
//!                            authorization is implicit in the proof,
//!                            but the TEE pays rent + fee)
//!   `[1]` marker           — writable PDA (init), seeds
//!                            `[b"batch_validity", merkle_root]`
//!   `[2]` system_program   — readonly

use std::sync::LazyLock;

use borsh::BorshSerialize;
use sha2::{Digest, Sha256};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};

use super::lock_note::Groth16ProofBytes;
use super::vault::{batch_validity_marker_pda, vault_program_id, SYSTEM_PROGRAM_ID};

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
    pub expiry_slot: u64,
    pub proof: Groth16ProofBytes,
}

impl VerifyMatchBatchArgs {
    /// Borsh-encoded width: 32 + 8 + 256 = 296 bytes.
    pub const WIRE_LEN: usize = 32 + 8 + Groth16ProofBytes::WIRE_LEN;
}

/// Build the `verify_match_batch` instruction. `payer` is the TEE
/// pubkey (signer + fee-payer). The marker PDA is derived from the
/// merkle root.
pub fn build_verify_match_batch_ix(payer: &Address, args: VerifyMatchBatchArgs) -> Instruction {
    let program_id = vault_program_id();
    let (marker_pda, _) = batch_validity_marker_pda(&args.merkle_root);

    let accounts = vec![
        AccountMeta::new(*payer, true),      // payer: signer + writable
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
            expiry_slot: 1_000_000,
            proof: dummy_proof(),
        }
    }

    fn dummy_payer() -> Address {
        bs58::encode([0xEEu8; 32]).into_string().parse().unwrap()
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
        let ix = build_verify_match_batch_ix(&dummy_payer(), dummy_args());
        assert_eq!(&ix.data[..8], &*VERIFY_MATCH_BATCH_DISCRIMINATOR);
        // 8 disc + 32 root + 8 expiry + 256 proof = 304.
        assert_eq!(ix.data.len(), 8 + VerifyMatchBatchArgs::WIRE_LEN);
        assert_eq!(ix.data.len(), 304);
    }

    #[test]
    fn ix_data_field_order() {
        let ix = build_verify_match_batch_ix(&dummy_payer(), dummy_args());
        let body = &ix.data[8..];
        assert_eq!(&body[0..32], &[0xAB; 32]); // merkle_root
        assert_eq!(&body[32..40], &1_000_000u64.to_le_bytes()); // expiry_slot
        assert_eq!(&body[40..104], &[0x11; 64]); // pi_a
        assert_eq!(&body[104..232], &[0x22; 128]); // pi_b
        assert_eq!(&body[232..296], &[0x33; 64]); // pi_c
        assert_eq!(body.len(), 296);
    }

    #[test]
    fn account_layout_matches_anchor_struct() {
        let payer = dummy_payer();
        let ix = build_verify_match_batch_ix(&payer, dummy_args());
        assert_eq!(ix.accounts.len(), 3);

        // [0] payer: signer + writable
        assert_eq!(ix.accounts[0].pubkey, payer);
        assert!(ix.accounts[0].is_signer);
        assert!(ix.accounts[0].is_writable);

        // [1] marker: writable PDA (init), not signer
        let (marker, _) = batch_validity_marker_pda(&[0xAB; 32]);
        assert_eq!(ix.accounts[1].pubkey, marker);
        assert!(!ix.accounts[1].is_signer);
        assert!(ix.accounts[1].is_writable);

        // [2] system_program: readonly
        assert_eq!(ix.accounts[2].pubkey, SYSTEM_PROGRAM_ID);
        assert!(!ix.accounts[2].is_signer);
        assert!(!ix.accounts[2].is_writable);
    }

    #[test]
    fn marker_pda_varies_with_root() {
        let mut args2 = dummy_args();
        args2.merkle_root = [0x01; 32];
        let ix1 = build_verify_match_batch_ix(&dummy_payer(), dummy_args());
        let ix2 = build_verify_match_batch_ix(&dummy_payer(), args2);
        assert_ne!(ix1.accounts[1].pubkey, ix2.accounts[1].pubkey);
    }
}
