//! `close_batch_validity_marker` instruction builder (Tx E).
//!
//! Reclaims the rent locked in the `BatchValidityMarker` PDA after
//! ALL matches in a batch have settled. Separate from Tx D because
//! the marker is 1:N (one per batch) — closing it during a per-match
//! settle would brick every subsequent match in the same batch
//! (CLAUDE.md §7.4). The matcher's fast path closes it once, after
//! the last settle, with `authority == payer == the TEE keypair`.
//!
//! On-chain reference:
//! `programs/vault/src/instructions/close_batch_validity_marker.rs`.
//!
//! Args: `merkle_root: [u8; 32]` (seeds the marker PDA).
//!
//! Accounts (mirror `CloseBatchValidityMarker<'info>`):
//!   `[0]` authority  — signer (readonly). Must equal `marker.payer`
//!                      for the close-anytime path; any signer after
//!                      `expiry_slot` for the GC path.
//!   `[1]` payer      — writable, non-signer. Refund target; the
//!                      marker's `has_one = payer` enforces it equals
//!                      `marker.payer`.
//!   `[2]` marker     — writable PDA (close = payer), seeds
//!                      `[b"batch_validity", merkle_root]`.

use std::sync::LazyLock;

use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};

use super::vault::{batch_validity_marker_pda, vault_program_id};

/// Anchor discriminator: `sha256("global:close_batch_validity_marker")[..8]`.
pub static CLOSE_MARKER_DISCRIMINATOR: LazyLock<[u8; 8]> = LazyLock::new(|| {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(b"global:close_batch_validity_marker");
    let mut out = [0u8; 8];
    out.copy_from_slice(&h[..8]);
    out
});

/// Build the close ix. For the matcher fast-path, `authority` and
/// `payer` are both the TEE pubkey (it paid the marker rent in Tx
/// B and reclaims it here).
pub fn build_close_marker_ix(
    authority: &Address,
    payer: &Address,
    merkle_root: &[u8; 32],
) -> Instruction {
    let program_id = vault_program_id();
    let (marker, _) = batch_validity_marker_pda(merkle_root);

    let accounts = vec![
        AccountMeta::new_readonly(*authority, true), // 0 authority: signer, readonly
        AccountMeta::new(*payer, false),             // 1 payer: writable, non-signer
        AccountMeta::new(marker, false),             // 2 marker: writable (close)
    ];

    // ix data: disc + merkle_root (32). No length prefix (fixed array).
    let mut data = Vec::with_capacity(8 + 32);
    data.extend_from_slice(&*CLOSE_MARKER_DISCRIMINATOR);
    data.extend_from_slice(merkle_root);

    Instruction {
        program_id,
        accounts,
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_addr(b: u8) -> Address {
        bs58::encode([b; 32]).into_string().parse().unwrap()
    }

    #[test]
    fn discriminator_pins() {
        // sha256("global:close_batch_validity_marker")[..8].
        assert_eq!(hex::encode(*CLOSE_MARKER_DISCRIMINATOR), "d5fda34390c33c03");
    }

    #[test]
    fn ix_data_layout() {
        let ix = build_close_marker_ix(&dummy_addr(0xEE), &dummy_addr(0xEE), &[0xAB; 32]);
        assert_eq!(&ix.data[..8], &*CLOSE_MARKER_DISCRIMINATOR);
        assert_eq!(&ix.data[8..40], &[0xAB; 32]);
        assert_eq!(ix.data.len(), 40);
    }

    #[test]
    fn account_layout_matches_anchor_struct() {
        let auth = dummy_addr(0xEE);
        let payer = dummy_addr(0xEE);
        let ix = build_close_marker_ix(&auth, &payer, &[0xAB; 32]);
        assert_eq!(ix.accounts.len(), 3);

        // [0] authority: signer, readonly.
        assert_eq!(ix.accounts[0].pubkey, auth);
        assert!(ix.accounts[0].is_signer);
        assert!(!ix.accounts[0].is_writable);

        // [1] payer: writable, non-signer.
        assert!(!ix.accounts[1].is_signer);
        assert!(ix.accounts[1].is_writable);

        // [2] marker: writable PDA, non-signer.
        let (marker, _) = batch_validity_marker_pda(&[0xAB; 32]);
        assert_eq!(ix.accounts[2].pubkey, marker);
        assert!(!ix.accounts[2].is_signer);
        assert!(ix.accounts[2].is_writable);
    }

    #[test]
    fn marker_pda_tracks_root() {
        let a = build_close_marker_ix(&dummy_addr(1), &dummy_addr(1), &[0x01; 32]);
        let b = build_close_marker_ix(&dummy_addr(1), &dummy_addr(1), &[0x02; 32]);
        assert_ne!(a.accounts[2].pubkey, b.accounts[2].pubkey);
    }
}
