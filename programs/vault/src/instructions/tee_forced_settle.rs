//! Shared settlement infrastructure. The v3.1 per-match
//! `tee_forced_settle` handler + its `TeeForcedSettle<'info>` Accounts
//! struct used to live here; both were deleted in Phase 1c-hard once
//! `verify_match_batch` + `tee_forced_settle_batched` took over every
//! settle path on-chain and every test was migrated to the batched
//! flow.
//!
//! What stays here is the SHARED settlement infrastructure that the
//! v3.5 batched handler depends on:
//! * `MatchResultPayload` (the Borsh struct the TEE signs and every
//!   settle ix carries),
//! * `canonical_payload_hash` (the SHA-256 over the payload that the
//!   TEE actually signs; cross-language byte-identical with the TS
//!   `canonicalPayloadHash`),
//! * `verify_tee_signature` (the Ed25519-precompile-inspection helper
//!   the batched handler reuses verbatim),
//! * `create_relock_pda` (allocates a fresh `NoteLock` for a
//!   continuing-order change note — used during atomic re-lock by
//!   `tee_forced_settle_batched`),
//! * `TradeSettled` (the event the batched handler emits).
//!
//! When this file empties out further (e.g. the TradeSettled event
//! moves elsewhere), rename it to something like `settlement_shared.rs`.

use crate::errors::VaultError;
use crate::state::*;
use anchor_lang::prelude::*;

/// Phase-5 MatchResultPayload — extended with change-note commitments and
/// input-note values so the vault can verify the conservation law before
/// writing any state.
///
/// Conservation law (spec `change_note_implementation.md`):
///   note_A.amount == quote_amount + buyer_change_amt   (buyer pays quote)
///   note_B.amount == base_amount  + seller_change_amt  (seller pays base)
///
/// `note_e_commitment` / `note_f_commitment` carry the Poseidon-hashed
/// change note commitments for buyer and seller respectively. They are
/// encoded as `[0u8; 32]` when the corresponding `change_amt` is zero
/// (exact-fill) to keep the payload fixed-size and Borsh-stable; the
/// handler skips the tree insertion for zero commitments.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct MatchResultPayload {
    pub match_id: [u8; 16],
    pub note_a_commitment: [u8; 32],
    pub note_b_commitment: [u8; 32],
    pub note_c_commitment: [u8; 32],
    pub note_d_commitment: [u8; 32],
    pub note_e_commitment: [u8; 32],
    pub note_f_commitment: [u8; 32],
    pub nullifier_a: [u8; 32],
    pub nullifier_b: [u8; 32],
    pub order_id_a: [u8; 16],
    pub order_id_b: [u8; 16],
    pub base_amount: u64,
    pub quote_amount: u64,
    pub buyer_change_amt: u64,
    pub seller_change_amt: u64,
    /// Buyer-side protocol fee (quote units). Subtracted from note_A at
    /// conservation-law check time. Already rolled into the batch fee
    /// accumulator by `run_batch`.
    pub buyer_fee_amt: u64,
    /// Seller-side protocol fee (base units).
    pub seller_fee_amt: u64,
    /// Batch-level protocol fee notes — ONE PER MINT. `[0u8;32]` = no fee
    /// note for that mint. Populated by the TEE only on the settlement
    /// chosen to carry the batch flush — the first settlement in the batch
    /// (see `partial_fill_and_fee_notes.md §2.4`). Both come straight from
    /// the matcher's per-batch `flush_fee_notes`:
    ///   - `note_fee_base_commitment`  — seller-side fees (base mint/units)
    ///   - `note_fee_quote_commitment` — buyer-side fees (quote mint/units)
    ///
    /// Carrying base separately is what mints the seller-side fee as a real
    /// protocol note instead of charging it in conservation but never
    /// crediting it (the v1 single-slot, quote-only gap).
    pub note_fee_base_commitment: [u8; 32],
    pub note_fee_quote_commitment: [u8; 32],
    /// If non-zero, re-lock note_e_commitment against `buyer_relock_order_id`
    /// for `buyer_relock_expiry`. The continuing order keeps trading in
    /// the next batch without the user doing anything.
    pub buyer_relock_order_id: [u8; 16],
    pub buyer_relock_expiry: u64,
    pub seller_relock_order_id: [u8; 16],
    pub seller_relock_expiry: u64,
    pub clearing_price: u64,
    pub batch_slot: u64,
    // v3.1 note: `price_proof` and `price_commitment` previously lived
    // here. They have been factored out into a preceding `verify_valid_price`
    // ix that writes a `ValidPriceMarker` PDA. This handler recomputes
    // `Poseidon3(DOMAIN_PRICE, clearing_price, batch_slot)` from the two
    // u64 fields above and asserts the marker PDA exists at that address.
    // The v3.1 price factor-out did NOT change canonical_payload_hash.
    // The base/quote fee-note split (this PR) DID — the single
    // `note_fee_commitment` became `note_fee_base_commitment` +
    // `note_fee_quote_commitment`, and the domain tag bumped
    // `nyx-match-v5` → `nyx-match-v6`.
}

// ---------------------------------------------------------------------------
// v3.1 per-match handler + its Accounts struct lived here. Deleted in
// Phase 1c-hard (see `docs/v3.5-migration.md`). The on-chain settle
// path is now `tee_forced_settle_batched` — one Groth16 covers the
// whole batch via `verify_match_batch`, then a single ix consumes the
// matched locks + appends leaves + re-locks change notes against a
// Merkle inclusion proof rooted at the batched marker. See
// `programs/vault/src/instructions/tee_forced_settle_batched.rs`.
//
// What stays in THIS file is the shared infrastructure the batched
// handler depends on: `MatchResultPayload` + `canonical_payload_hash`
// + `create_relock_pda` + `verify_tee_signature` + `TradeSettled`.
// When this file shrinks further we can rename it
// `settlement_shared.rs`.
// ---------------------------------------------------------------------------

/// Manually create a NoteLock PDA so the settlement tx can atomically
/// re-lock a change note against the continuing order. The seeds MUST be
/// `[NoteLock::SEED, note_commitment]` — this is what `cancel_order` /
/// `release_lock` will look up. Returns an error if the account is
/// non-empty (a prior lock still exists for this commitment).
#[allow(clippy::too_many_arguments)]
pub(crate) fn create_relock_pda<'info>(
    note_lock_ai: &UncheckedAccount<'info>,
    payer: &Signer<'info>,
    system_program: &Program<'info, System>,
    note_commitment: &[u8; 32],
    order_id: &[u8; 16],
    expiry_slot: u64,
    amount: u64,
) -> Result<()> {
    use anchor_lang::system_program;
    use core::mem::size_of;

    let (expected_pda, bump) =
        Pubkey::find_program_address(&[NoteLock::SEED, note_commitment.as_ref()], &crate::ID);
    require_keys_eq!(note_lock_ai.key(), expected_pda, VaultError::Unauthorized);
    require!(
        note_lock_ai.data_is_empty() && note_lock_ai.lamports() == 0,
        VaultError::NoteAlreadyLocked
    );

    let space = 8 + size_of::<NoteLock>();
    let lamports = Rent::get()?.minimum_balance(space);
    let bump_arr = [bump];
    let seeds: &[&[u8]] = &[NoteLock::SEED, note_commitment.as_ref(), &bump_arr];
    let signer_seeds = &[seeds];

    let cpi_ctx = CpiContext::new_with_signer(
        system_program.to_account_info(),
        system_program::CreateAccount {
            from: payer.to_account_info(),
            to: note_lock_ai.to_account_info(),
        },
        signer_seeds,
    );
    system_program::create_account(cpi_ctx, lamports, space as u64, &crate::ID)?;

    // Populate. Discriminator for zero_copy is the first 8 bytes of
    // anchor_lang::solana_program::hash::hash("account:NoteLock").
    {
        let mut data = note_lock_ai.try_borrow_mut_data()?;
        let disc = NoteLock::DISCRIMINATOR;
        data[..8].copy_from_slice(disc);
        let (_head, body) = data.split_at_mut(8);
        let lock: &mut NoteLock = bytemuck::from_bytes_mut(body);
        lock.note_commitment = *note_commitment;
        lock.order_id = *order_id;
        lock.expiry_slot = expiry_slot;
        lock.locked_by = payer.key();
        lock.amount = amount;
        lock.bump = bump;
        lock._padding = [0u8; 7];
    }
    Ok(())
}

#[event]
pub struct TradeSettled {
    pub match_id: [u8; 16],
    pub clearing_price: u64,
    pub base_amount: u64,
    pub quote_amount: u64,
    pub buyer_change_amt: u64,
    pub seller_change_amt: u64,
    pub buyer_fee_amt: u64,
    pub seller_fee_amt: u64,
    pub note_c_leaf: u64,
    pub note_d_leaf: u64,
    /// `u64::MAX` means no buyer-change leaf was inserted (exact fill).
    pub note_e_leaf: u64,
    /// `u64::MAX` means no seller-change leaf was inserted (exact fill).
    pub note_f_leaf: u64,
    /// `u64::MAX` means no base/quote batch fee note was flushed on this
    /// settlement (only the first settlement in a batch carries them).
    pub note_fee_base_leaf: u64,
    pub note_fee_quote_leaf: u64,
    pub buyer_relock_active: bool,
    pub seller_relock_active: bool,
    pub new_root: [u8; 32],
}

/// Canonical 32-byte hash of a [`MatchResultPayload`] used as the TEE's
/// signed message. Fields are concatenated in struct order and hashed via
/// SHA-256 so that a cross-environment signer (Rust TEE, TS client) can
/// produce byte-identical output.
pub fn canonical_payload_hash(p: &MatchResultPayload) -> [u8; 32] {
    use solana_program::hash::hashv;
    let base = p.base_amount.to_le_bytes();
    let quote = p.quote_amount.to_le_bytes();
    let buyer_change = p.buyer_change_amt.to_le_bytes();
    let seller_change = p.seller_change_amt.to_le_bytes();
    let buyer_fee = p.buyer_fee_amt.to_le_bytes();
    let seller_fee = p.seller_fee_amt.to_le_bytes();
    let buyer_relock_exp = p.buyer_relock_expiry.to_le_bytes();
    let seller_relock_exp = p.seller_relock_expiry.to_le_bytes();
    let price = p.clearing_price.to_le_bytes();
    let slot = p.batch_slot.to_le_bytes();
    hashv(&[
        // v6: the single fee-note slot was split into base + quote (the
        // per-batch base-mint protocol fee note is new). Bumping the domain
        // tag invalidates v5 signatures over the old single-slot layout.
        b"nyx-match-v6",
        p.match_id.as_ref(),
        p.note_a_commitment.as_ref(),
        p.note_b_commitment.as_ref(),
        p.note_c_commitment.as_ref(),
        p.note_d_commitment.as_ref(),
        p.note_e_commitment.as_ref(),
        p.note_f_commitment.as_ref(),
        p.note_fee_base_commitment.as_ref(),
        p.note_fee_quote_commitment.as_ref(),
        p.nullifier_a.as_ref(),
        p.nullifier_b.as_ref(),
        p.order_id_a.as_ref(),
        p.order_id_b.as_ref(),
        &base,
        &quote,
        &buyer_change,
        &seller_change,
        &buyer_fee,
        &seller_fee,
        p.buyer_relock_order_id.as_ref(),
        &buyer_relock_exp,
        p.seller_relock_order_id.as_ref(),
        &seller_relock_exp,
        &price,
        &slot,
    ])
    .to_bytes()
}

/// The Solana Ed25519Program precompile id.
fn ed25519_program_id() -> Pubkey {
    solana_program::ed25519_program::ID
}

/// Scan the tx's instructions list for an Ed25519Program precompile ix
/// whose (pubkey, msg) matches our expectations. Fails with
/// `InvalidTeeSignature` otherwise.
///
/// Precompile ix data layout (per Solana docs):
///   offset 0     : u8  num_signatures (we require exactly 1)
///   offset 1     : u8  padding
///   offset 2..4  : u16 signature_offset
///   offset 4..6  : u16 signature_instruction_index
///   offset 6..8  : u16 public_key_offset
///   offset 8..10 : u16 public_key_instruction_index
///   offset 10..12: u16 message_data_offset
///   offset 12..14: u16 message_data_size
///   offset 14..16: u16 message_instruction_index
///
/// `*_instruction_index == 0xFFFF` means "same instruction" (data inlined).
/// We only accept the inlined form — cross-ix lookups are not worth the
/// complexity and a well-behaved relayer always inlines.
pub fn verify_tee_signature(
    instructions_sysvar: &UncheckedAccount<'_>,
    expected_pubkey: &Pubkey,
    expected_msg: &[u8; 32],
) -> Result<()> {
    use solana_program::sysvar::instructions::load_instruction_at_checked;

    let ai = instructions_sysvar.to_account_info();
    // The sysvar data starts with a u16 instruction count at offset 0.
    // Use it as the upper bound so we scan every instruction in the tx
    // regardless of where the Ed25519 precompile is placed relative to us.
    // Previous code used `current_ix_idx + 8` which silently skipped the
    // precompile if it was placed > 8 slots after the settle ix.
    let total_ix_count: usize = {
        let data = ai
            .try_borrow_data()
            .map_err(|_| error!(VaultError::InvalidTeeSignature))?;
        if data.len() < 2 {
            return Err(error!(VaultError::InvalidTeeSignature));
        }
        u16::from_le_bytes([data[0], data[1]]) as usize
    };

    // Walk every instruction in the tx looking for a single Ed25519Program
    // precompile entry with matching (pk, msg).
    for i in 0..total_ix_count {
        let ix = match load_instruction_at_checked(i, &ai) {
            Ok(v) => v,
            Err(_) => break,
        };
        if ix.program_id != ed25519_program_id() {
            continue;
        }
        if ix.data.len() < 16 {
            continue;
        }
        let num_sigs = ix.data[0];
        if num_sigs != 1 {
            continue;
        }
        let pk_off = u16::from_le_bytes([ix.data[6], ix.data[7]]) as usize;
        let pk_ix_idx = u16::from_le_bytes([ix.data[8], ix.data[9]]);
        let msg_off = u16::from_le_bytes([ix.data[10], ix.data[11]]) as usize;
        let msg_len = u16::from_le_bytes([ix.data[12], ix.data[13]]) as usize;
        let msg_ix_idx = u16::from_le_bytes([ix.data[14], ix.data[15]]);
        // We only accept inlined pk/msg (index == u16::MAX).
        if pk_ix_idx != u16::MAX || msg_ix_idx != u16::MAX {
            continue;
        }
        if pk_off + 32 > ix.data.len() || msg_off + msg_len > ix.data.len() {
            continue;
        }
        let pk_bytes = &ix.data[pk_off..pk_off + 32];
        let msg_bytes = &ix.data[msg_off..msg_off + msg_len];
        if pk_bytes != expected_pubkey.as_ref() {
            continue;
        }
        if msg_len != 32 || msg_bytes != expected_msg {
            continue;
        }
        // Precompile already verified the signature bytes against this
        // (pk, msg) pair or the tx would have failed before reaching us.
        return Ok(());
    }
    Err(error!(VaultError::InvalidTeeSignature))
}

#[cfg(test)]
#[cfg(not(target_os = "solana"))]
mod tests {
    use super::*;

    /// Fixed-input canonical hash. Any byte drift here means the TS
    /// `canonicalPayloadHash` + the in-TEE signer diverged from the
    /// on-chain verifier and every settlement would start failing —
    /// catch it at compile time.
    #[test]
    fn canonical_payload_hash_fixed_vector() {
        let p = MatchResultPayload {
            match_id: [0x11u8; 16],
            note_a_commitment: [0xA1u8; 32],
            note_b_commitment: [0xB1u8; 32],
            note_c_commitment: [0xC1u8; 32],
            note_d_commitment: [0xD1u8; 32],
            note_e_commitment: [0u8; 32],
            note_f_commitment: [0u8; 32],
            nullifier_a: [0xEAu8; 32],
            nullifier_b: [0xEBu8; 32],
            order_id_a: [0x01u8; 16],
            order_id_b: [0x02u8; 16],
            base_amount: 100,
            quote_amount: 5_000,
            buyer_change_amt: 0,
            seller_change_amt: 0,
            buyer_fee_amt: 0,
            seller_fee_amt: 0,
            note_fee_base_commitment: [0u8; 32],
            note_fee_quote_commitment: [0u8; 32],
            buyer_relock_order_id: [0u8; 16],
            buyer_relock_expiry: 0,
            seller_relock_order_id: [0u8; 16],
            seller_relock_expiry: 0,
            clearing_price: 0,
            batch_slot: 0,
        };
        let hash = canonical_payload_hash(&p);
        // Keep in sync with packages/sdk/tests/settle-builder.test.ts
        // `[hash_cross_env_parity]`. When the payload shape changes, update
        // BOTH sides — any divergence breaks the TEE signature verification.
        let expected: [u8; 32] = [
            0x98, 0xF6, 0xF0, 0x18, 0x48, 0x80, 0x02, 0x61, 0x5E, 0x03, 0xD0, 0x22, 0xF9, 0xCF,
            0xAC, 0x17, 0x27, 0x9A, 0xB3, 0xE5, 0xAB, 0x15, 0x5F, 0xA2, 0xCF, 0x71, 0xAD, 0x4D,
            0x08, 0x84, 0x6B, 0x47,
        ];
        if hash != expected {
            panic!("canonical_payload_hash drifted — got {:02X?}", hash);
        }
    }
}
