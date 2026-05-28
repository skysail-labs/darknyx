//! `lock_note` instruction builder (Tx A of the v3.5 settle pipeline).
//!
//! Constructs the Solana `Instruction` the on-chain `vault::lock_note`
//! handler expects. The on-chain side
//! (`programs/vault/src/instructions/lock_note.rs`) takes:
//!
//!   - 4 accounts: `tee_authority` (signer, writable), `vault_config`
//!     (PDA, read-only), `note_lock` (PDA, writable — init), `system_program`.
//!   - 7 instruction-data args, Anchor-style (8-byte discriminator
//!     + Borsh-encoded args in declaration order):
//!       1. `note_commitment: [u8; 32]`
//!       2. `order_id: [u8; 16]`
//!       3. `expiry_slot: u64`
//!       4. `amount: u64`
//!       5. `token_mint: Pubkey` (32 bytes)
//!       6. `merkle_root: [u8; 32]`
//!       7. `proof: Groth16Proof` (256 bytes — pi_a 64 + pi_b 128 + pi_c 64)
//!
//! The handler enforces `tee_authority == vault_config.tee_pubkey`
//! and verifies the VALID_INPUT Groth16 proof against the merkle
//! root. **The proof is user-supplied** — the TEE just relays it.
//! 4g.3 takes the proof bytes as a builder input; integrating it
//! with `POST /orders` (so the TEE actually has a proof to relay)
//! is its own follow-up — for now the LockingNotes stage worker
//! fails the job with a clear "missing valid_input_proof" reason
//! when no proof is attached.
//!
//! Wire spec for the discriminator is the same as Anchor's:
//! `sha256("global:lock_note")[..8]`. We compute it at runtime
//! once and cache via `LazyLock` — same constant the SDK's
//! `idl/vault-client.ts::anchorDiscriminator("lock_note")` produces.

use std::sync::LazyLock;

use borsh::BorshSerialize;
use sha2::{Digest, Sha256};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};

use crate::settle::vault::{note_lock_pda, vault_config_pda, vault_program_id, SYSTEM_PROGRAM_ID};

/// Anchor discriminator for the `lock_note` instruction. Computed
/// at first access; the result is `sha256("global:lock_note")[..8]`.
pub static LOCK_NOTE_DISCRIMINATOR: LazyLock<[u8; 8]> = LazyLock::new(|| {
    let h = Sha256::digest(b"global:lock_note");
    let mut out = [0u8; 8];
    out.copy_from_slice(&h[..8]);
    out
});

/// Raw Groth16 proof bytes — must match the on-chain
/// `vault::zk::verifier::Groth16Proof` layout exactly. 256 bytes
/// total. The order matches snarkjs' / ark-circom's output so the
/// SDK's `groth16-format.ts` produces bytes the TEE can pass
/// through verbatim.
#[derive(Clone, Debug, BorshSerialize)]
pub struct Groth16ProofBytes {
    pub pi_a: [u8; 64],
    pub pi_b: [u8; 128],
    pub pi_c: [u8; 64],
}

impl Groth16ProofBytes {
    /// Borsh-encoded width — pinned by the on-chain Anchor type.
    pub const WIRE_LEN: usize = 64 + 128 + 64;
}

/// All args to `lock_note`, in the declaration order the on-chain
/// handler expects. The builder takes this whole struct + the
/// `tee_authority` pubkey, then derives the two PDAs internally.
#[derive(Clone, Debug, BorshSerialize)]
pub struct LockNoteArgs {
    pub note_commitment: [u8; 32],
    pub order_id: [u8; 16],
    pub expiry_slot: u64,
    pub amount: u64,
    /// `token_mint` is the 32-byte Solana mint pubkey, NOT the
    /// `(lo, hi)` Fr-pair the VALID_INPUT circuit uses internally.
    /// The handler does the split itself.
    pub token_mint: [u8; 32],
    pub merkle_root: [u8; 32],
    pub proof: Groth16ProofBytes,
}

impl LockNoteArgs {
    /// Total Borsh-encoded width: 32 + 16 + 8 + 8 + 32 + 32 + 256 = 384 bytes.
    pub const WIRE_LEN: usize = 32 + 16 + 8 + 8 + 32 + 32 + Groth16ProofBytes::WIRE_LEN;
}

/// Build the full `Instruction`. Caller composes this into a
/// `Message`, signs with the TEE keypair (which is BOTH the
/// `tee_authority` Signer AND the tx fee-payer — see PR 4g.3 doc),
/// and submits via `SolanaRpcClient::send_transaction`.
///
/// Accounts (positional, in the order the on-chain `LockNote<'info>`
/// struct declares them):
///
///   - `[0]` `tee_authority`: signer, writable (pays rent for the
///     new note_lock PDA AND the tx fee).
///   - `[1]` `vault_config`: read-only PDA, seeds=[b"vault_config"].
///   - `[2]` `note_lock`: writable PDA (init), seeds=[b"note_lock",
///     note_commitment].
///   - `[3]` `system_program`: read-only.
pub fn build_lock_note_ix(tee_authority: &Address, args: LockNoteArgs) -> Instruction {
    let program_id = vault_program_id();
    let (vault_cfg_pda, _) = vault_config_pda();
    let (note_lock_pda_addr, _) = note_lock_pda(&args.note_commitment);

    let accounts = vec![
        AccountMeta::new(*tee_authority, true), // signer + writable
        AccountMeta::new_readonly(vault_cfg_pda, false),
        AccountMeta::new(note_lock_pda_addr, false), // writable (init)
        AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
    ];

    // Anchor ix data layout: 8-byte discriminator || Borsh(args).
    let mut data = Vec::with_capacity(8 + LockNoteArgs::WIRE_LEN);
    data.extend_from_slice(&*LOCK_NOTE_DISCRIMINATOR);
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

    fn dummy_args() -> LockNoteArgs {
        LockNoteArgs {
            note_commitment: [0xAA; 32],
            order_id: [0xBB; 16],
            expiry_slot: 1_000_000,
            amount: 5_000_000_000,
            token_mint: [0xCC; 32],
            merkle_root: [0xDD; 32],
            proof: Groth16ProofBytes {
                pi_a: [0x11; 64],
                pi_b: [0x22; 128],
                pi_c: [0x33; 64],
            },
        }
    }

    fn dummy_tee_authority() -> Address {
        // Deterministic non-zero address for testing.
        let bytes = [0xEEu8; 32];
        bs58::encode(bytes)
            .into_string()
            .parse()
            .expect("valid base58 pubkey")
    }

    #[test]
    fn discriminator_pins_to_anchor_global_lock_note() {
        // sha256("global:lock_note")[..8] — Anchor's canonical
        // discriminator formula, mirrored by
        // `packages/sdk/src/idl/vault-client.ts::anchorDiscriminator("lock_note")`.
        // Pinned so a refactor that touches `LOCK_NOTE_DISCRIMINATOR`'s
        // input string surfaces here rather than as `InvalidIxData`
        // on-chain.
        let expected = "e75b0f220c3fecca";
        let got = hex::encode(*LOCK_NOTE_DISCRIMINATOR);
        assert_eq!(got, expected, "lock_note discriminator drifted");
    }

    #[test]
    fn ix_data_starts_with_discriminator() {
        let ix = build_lock_note_ix(&dummy_tee_authority(), dummy_args());
        assert_eq!(&ix.data[..8], &*LOCK_NOTE_DISCRIMINATOR);
    }

    #[test]
    fn ix_data_total_length_matches_wire_spec() {
        let ix = build_lock_note_ix(&dummy_tee_authority(), dummy_args());
        // 8 disc + 32 + 16 + 8 + 8 + 32 + 32 + 256 = 392 bytes.
        assert_eq!(ix.data.len(), 8 + LockNoteArgs::WIRE_LEN);
        assert_eq!(ix.data.len(), 392);
    }

    #[test]
    fn ix_data_fields_appear_in_declaration_order() {
        // Pin the Borsh layout: each field's bytes appear at the
        // expected offset. A reordering would silently break the
        // on-chain Borsh deserialiser; we want this to fail at the
        // test stage, not at runtime against a confirmed tx.
        let ix = build_lock_note_ix(&dummy_tee_authority(), dummy_args());
        let body = &ix.data[8..]; // skip discriminator

        let mut off = 0;
        // note_commitment
        assert_eq!(&body[off..off + 32], &[0xAA; 32]);
        off += 32;
        // order_id
        assert_eq!(&body[off..off + 16], &[0xBB; 16]);
        off += 16;
        // expiry_slot (u64 LE)
        assert_eq!(&body[off..off + 8], &1_000_000u64.to_le_bytes());
        off += 8;
        // amount (u64 LE)
        assert_eq!(&body[off..off + 8], &5_000_000_000u64.to_le_bytes());
        off += 8;
        // token_mint
        assert_eq!(&body[off..off + 32], &[0xCC; 32]);
        off += 32;
        // merkle_root
        assert_eq!(&body[off..off + 32], &[0xDD; 32]);
        off += 32;
        // proof: pi_a then pi_b then pi_c (Borsh follows struct
        // declaration order).
        assert_eq!(&body[off..off + 64], &[0x11; 64]);
        off += 64;
        assert_eq!(&body[off..off + 128], &[0x22; 128]);
        off += 128;
        assert_eq!(&body[off..off + 64], &[0x33; 64]);
        off += 64;
        assert_eq!(off, body.len(), "consumed every byte exactly");
    }

    #[test]
    fn account_list_matches_anchor_struct_order() {
        // Mirror of programs/vault/src/instructions/lock_note.rs
        // LockNote<'info>: tee_authority, vault_config, note_lock,
        // system_program.
        let tee = dummy_tee_authority();
        let ix = build_lock_note_ix(&tee, dummy_args());
        assert_eq!(ix.accounts.len(), 4);

        // [0] tee_authority: signer + writable
        assert_eq!(ix.accounts[0].pubkey, tee);
        assert!(ix.accounts[0].is_signer);
        assert!(ix.accounts[0].is_writable);

        // [1] vault_config: readonly
        assert!(!ix.accounts[1].is_signer);
        assert!(!ix.accounts[1].is_writable);

        // [2] note_lock: writable (init)
        assert!(!ix.accounts[2].is_signer);
        assert!(ix.accounts[2].is_writable);

        // [3] system_program: readonly
        assert_eq!(ix.accounts[3].pubkey, SYSTEM_PROGRAM_ID);
        assert!(!ix.accounts[3].is_signer);
        assert!(!ix.accounts[3].is_writable);
    }

    #[test]
    fn note_lock_pda_varies_with_note_commitment() {
        // Different note → different note_lock PDA. The on-chain
        // ix init constraint relies on this; a builder bug that
        // hashed a constant seed would collide at runtime with
        // a confusing `AccountAlreadyInitialized` error.
        let tee = dummy_tee_authority();
        let mut args2 = dummy_args();
        args2.note_commitment = [0x11; 32];
        let ix1 = build_lock_note_ix(&tee, dummy_args());
        let ix2 = build_lock_note_ix(&tee, args2);
        assert_ne!(ix1.accounts[2].pubkey, ix2.accounts[2].pubkey);
    }

    #[test]
    fn program_id_is_consistent_across_calls() {
        let ix1 = build_lock_note_ix(&dummy_tee_authority(), dummy_args());
        let ix2 = build_lock_note_ix(&dummy_tee_authority(), dummy_args());
        assert_eq!(ix1.program_id, ix2.program_id);
        assert_eq!(ix1.program_id, vault_program_id());
    }
}
