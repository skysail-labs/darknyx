//! `close_batch_validity_marker` instruction builder (Tx E).
//!
//! Reclaims the rent locked in the `BatchValidityMarker` PDA after
//! its expiry has been reached. Separate from Tx D because
//! the marker is 1:N (one per batch) — closing it during a per-match
//! settle would brick every subsequent match in the same batch
//! (CLAUDE.md §8.2). The background sweeper waits until expiry, then
//! closes with `authority == payer == the primary TEE keypair`.
//!
//! On-chain reference:
//! `programs/vault/src/instructions/close_batch_validity_marker.rs`.
//!
//! Args: `merkle_root: [u8; 32]` (seeds the marker PDA).
//!
//! Accounts (mirror `CloseBatchValidityMarker<'info>`):
//!   `[0]` authority  — signer AND refund target, writable. Must equal
//!                      `marker.payer`, enforced on-chain by an explicit
//!                      constraint (v2 deprecated `has_one`).
//!   `[1]` marker     — writable PDA (close = authority), seeds
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

/// Build the expiry-only close ix. The in-TEE sweeper uses the primary TEE
/// pubkey for both authority and payer because it funded Tx B.
/// `authority` is BOTH the signer and the rent refund target. v2 collapsed the
/// old separate `payer` slot into this one: passing the same address twice —
/// which this sweeper always did — trips v2's duplicate-mutable-account check
/// and is rejected before the handler runs. The on-chain constraint still pins
/// it to `marker.payer`, so the caller must be that payer.
pub fn build_close_marker_ix(authority: &Address, merkle_root: &[u8; 32]) -> Instruction {
    let program_id = vault_program_id();
    let (marker, _) = batch_validity_marker_pda(merkle_root);

    let accounts = vec![
        // 0 authority: signer AND refund target — writable, since the marker
        //   closes into it.
        AccountMeta::new(*authority, true),
        // 1 marker: writable (close = authority)
        AccountMeta::new(marker, false),
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
        let ix = build_close_marker_ix(&dummy_addr(0xEE), &[0xAB; 32]);
        assert_eq!(&ix.data[..8], &*CLOSE_MARKER_DISCRIMINATOR);
        assert_eq!(&ix.data[8..40], &[0xAB; 32]);
        assert_eq!(ix.data.len(), 40);
    }

    #[test]
    fn account_layout_matches_anchor_struct() {
        // TWO accounts under v2, not three. The old separate `payer` refund
        // slot aliased with `authority` — this sweeper always passed the same
        // address for both — and v2 rejects a duplicate mutable account before
        // the handler runs. The slots are collapsed; `authority` is now the
        // refund target and must equal `marker.payer` (enforced on-chain).
        let auth = dummy_addr(0xEE);
        let ix = build_close_marker_ix(&auth, &[0xAB; 32]);
        assert_eq!(ix.accounts.len(), 2);

        // [0] authority: signer AND refund target, so writable.
        assert_eq!(ix.accounts[0].pubkey, auth);
        assert!(ix.accounts[0].is_signer);
        assert!(
            ix.accounts[0].is_writable,
            "authority receives the marker rent, so it must be writable"
        );

        // [1] marker: writable PDA, non-signer.
        let (marker, _) = batch_validity_marker_pda(&[0xAB; 32]);
        assert_eq!(ix.accounts[1].pubkey, marker);
        assert!(!ix.accounts[1].is_signer);
        assert!(ix.accounts[1].is_writable);
    }

    #[test]
    fn marker_pda_tracks_root() {
        let a = build_close_marker_ix(&dummy_addr(1), &[0x01; 32]);
        let b = build_close_marker_ix(&dummy_addr(1), &[0x02; 32]);
        assert_ne!(a.accounts[1].pubkey, b.accounts[1].pubkey);
    }
}
