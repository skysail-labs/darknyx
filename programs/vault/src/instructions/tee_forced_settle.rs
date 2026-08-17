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

/// Phase-5 MatchResultPayload — carries the commitments + relock plumbing
/// the on-chain settle handler needs.
///
/// **Amount-privacy (P3b).** The plaintext amounts (`base_amount`,
/// `quote_amount`, `buyer/seller_change_amt`, `buyer/seller_fee_amt`,
/// `clearing_price`) USED to live here so the chain could re-check the
/// conservation law + fee. They have been REMOVED: VALID_MATCH_BATCH now proves
/// conservation + the exact governed fee in-circuit over PRIVATE amounts
/// (range-checked), and the note commitments bind the amounts transitively.
/// Putting them in the settle ix (which lands on-chain in plaintext) was a
/// public leak — competitors could read every trade size + execution price.
/// The payload now carries ONLY commitments, order ids, relock fields, and the
/// batch slot. Each client reconstructs its own amounts from
/// the per-account FillMemo.
///
/// `note_e_commitment` / `note_f_commitment` carry the Poseidon-hashed
/// change note commitments for buyer and seller respectively. They are
/// encoded as `[0u8; 32]` when the corresponding change is zero
/// (exact-fill) to keep the payload fixed-size and Borsh-stable; the
/// handler skips the tree insertion for zero commitments.
#[derive(SchemaWrite, SchemaRead, Clone, Debug)]
pub struct MatchResultPayload {
    pub match_id: [u8; 16],
    /// The CONSUMED inputs, as note-use TAGS rather than commitments. These key
    /// the `NoteLock` and `ConsumedNoteEntry` PDAs, and republishing the
    /// commitments here would relink both inputs to their Merkle leaves —
    /// undoing the unlinkability for every note that ever trades.
    pub note_a_use_tag: [u8; 32],
    pub note_b_use_tag: [u8; 32],
    /// The OUTPUTS stay commitments: they are appended to the tree as new
    /// leaves, so the handler needs the leaf value itself.
    pub note_c_commitment: [u8; 32],
    pub note_d_commitment: [u8; 32],
    pub note_e_commitment: [u8; 32],
    pub note_f_commitment: [u8; 32],
    pub order_id_a: [u8; 16],
    pub order_id_b: [u8; 16],
    /// This match's protocol fee notes — one per input leg. `[0u8;32]` means
    /// that leg's exact fee is zero. VALID_MATCH_BATCH derives each inner from
    /// the consumed input commitment, and this match's Tx D appends the note
    /// atomically with consuming that input:
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
    /// Use tags for the change notes this settle creates and immediately
    /// RE-LOCKS. Needed in addition to `note_e/f_commitment` — the commitment is
    /// the leaf value, the tag is the `NoteLock` PDA seed, and the handler has
    /// no way to derive one from the other (that needs the private inner hash).
    ///
    /// These are the +64 bytes the tag migration costs on this payload. They are
    /// bound by the batch leaf via `relock_digest`, because the in-settle relock
    /// takes no proof of its own: an unconstrained tag here would let the
    /// enclave lock an arbitrary note, bounded only by MAX_LOCK_TTL_SLOTS.
    ///
    /// `[0u8; 32]` when that side has no change, mirroring the commitment.
    pub note_e_use_tag: [u8; 32],
    pub note_f_use_tag: [u8; 32],
    pub batch_slot: u64,
    /// Recovery v3: the per-fill X25519-ECIES bundle
    /// `ephemeral_pubkey(32) ‖ buyer_enc(44) ‖ seller_enc(44) ‖ "DNYXREC3"`.
    /// The TEE encrypts each side's `(trade, change)` tuple to that order's
    /// viewing key. Opaque to the program — it never reads these bytes;
    /// they ride the (signed) payload only to be persisted on-chain. All-zero
    /// only when neither side supplies a viewing key.
    ///
    /// U-04 — recovery integrity is a TEE-HONESTY assumption, not a
    /// cryptographic guarantee. The program never validates this blob, and the
    /// AEAD protects only confidentiality (a third party can't read it), NOT
    /// correctness: a compromised TEE could sign a fully-conserved settle whose
    /// `fill_recovery` is garbage, stranding a client that relies ONLY on
    /// on-chain recovery (it would fail to decrypt or fail the commitment
    /// recompute). The redundancy against that is the live `/v1/stream` fills
    /// channel + trade-history backfill — chain recovery is the last-resort
    /// path, not the sole one. (Ops follow-up: alert on recovery-decrypt
    /// failure. No on-chain fix — it's inside the accepted TEE-honesty boundary.)
    pub fill_recovery: [u8; 128],
    // Amount-privacy (P3b): `clearing_price` was removed alongside the other
    // plaintext amounts — the price is proven in-circuit
    // (`quote === floor(base*price/price_scale)`) and bound inside the note commitments, so it no
    // longer needs to ride in the (public) settle ix. The domain tag bumped
    // settlement-domain v6 → v7 for this layout change, then v7 → v8 when
    // encrypted output recovery
    // appended the `fill_recovery` field above. Settlement payload v9 then
    // removed the two vestigial nullifiers. The Darknyx namespace cutover
    // retained that layout and bumped the signed domain to v10. v11 makes
    // tag-keyed `ConsumedNoteEntry` PDAs the sole settle/withdraw replay guard,
    // replaces the two consumed commitments with note-use
    // TAGS and appends `note_e_use_tag` / `note_f_use_tag` for the relock PDAs
    // (488 -> 552 bytes).
    //
    // v3.1 note: `price_proof` and `price_commitment` had previously been
    // factored out into a preceding `verify_valid_price` ix; that path was
    // since subsumed by the batched VALID_MATCH_BATCH proof.
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
/// `[NoteLock::SEED, note_use_tag]` — this is what `cancel_order` /
/// `release_lock` will look up. Returns an error if the account is
/// non-empty (a prior lock still exists for this commitment).
#[allow(clippy::too_many_arguments)]
// v2: mutable receivers — CreateAccount's slots are CpiHandleMut, and the
// post-create discriminator write needs a mutable data borrow.
pub(crate) fn create_relock_pda(
    note_lock_ai: &mut UncheckedAccount,
    payer: &mut Signer,
    system_program: &Program<System>,
    note_use_tag: &[u8; 32],
    token_mint: &Address,
    order_id: &[u8; 16],
    expiry_slot: u64,
) -> Result<()> {
    use anchor_lang::system_program;
    use core::mem::size_of;

    let (expected_pda, bump) =
        Address::find_program_address(&[NoteLock::SEED, note_use_tag.as_ref()], &crate::ID);
    require_keys_eq!(
        *note_lock_ai.address(),
        expected_pda,
        VaultError::Unauthorized
    );
    require!(
        note_lock_ai.data_len() == 0 && note_lock_ai.lamports() == 0,
        VaultError::NoteAlreadyLocked
    );

    // C-02: cap the relock expiry exactly as `lock_note` caps a fresh lock.
    // `withdraw` rejects while ANY NoteLock exists — even an expired one — so
    // the lock window IS the censorship window. `lock_note.rs` enforces this
    // bound on the initial lock, but the re-lock path (used for partial-fill
    // continuations) previously set `expiry_slot` unchecked, letting a
    // malicious TEE stamp an arbitrarily distant expiry and freeze the note
    // indefinitely. The settler stamps the relock with the order's expiry,
    // which intake already caps to `current + MAX_LOCK_TTL_SLOTS` at
    // `prepare_order`, so this is on-chain defense-in-depth (a legit relock is
    // always within cap: its expiry was bounded at an earlier slot).
    let clock = Clock::get()?;
    require!(expiry_slot > clock.slot, VaultError::InvalidExpirySlot);
    require!(
        expiry_slot <= clock.slot.saturating_add(MAX_LOCK_TTL_SLOTS),
        VaultError::InvalidExpirySlot
    );

    let space = 8 + size_of::<NoteLock>();
    // v2: `minimum_balance` is deprecated (it panics past MAX_PERMITTED_DATA_LENGTH);
    // the fallible form returns InvalidArgument instead.
    let lamports = Rent::get()?.try_minimum_balance(space)?;
    let bump_arr = [bump];
    let seeds: &[&[u8]] = &[NoteLock::SEED, note_use_tag.as_ref(), &bump_arr];
    let signer_seeds = &[seeds];

    let cpi_ctx = CpiContext::new_with_signer(
        system_program.address(),
        system_program::CreateAccount {
            from: payer.to_cpi_handle_mut(),
            to: note_lock_ai.to_cpi_handle_mut(),
        },
        signer_seeds,
    );
    system_program::create_account(cpi_ctx, lamports, space as u64, &crate::ID)?;

    // Populate. Discriminator for zero_copy is the first 8 bytes of
    // anchor_lang::solana_program::hash::hash("account:NoteLock").
    {
        // v2: `UncheckedAccount` exposes the view by `account()` and does not
        // implement DerefMut, so take a copy of the (Copy) AccountView to get
        // the mutable data borrow. Writes go through to the same buffer.
        let mut view = *note_lock_ai.account();
        let mut data = view.try_borrow_mut()?;
        let disc = NoteLock::DISCRIMINATOR;
        data[..8].copy_from_slice(disc);
        let (_head, body) = data.split_at_mut(8);
        let lock: &mut NoteLock = bytemuck::from_bytes_mut(body);
        lock.note_use_tag = *note_use_tag;
        // CRITICAL: populate token_mint. A later batch that consumes this
        // relocked note reads `note_lock.token_mint` to recompute the
        // batch-binding leaf (`compute_match_leaf`); a zero mint there →
        // wrong leaf → InvalidBatchBinding. lock_note sets this too — the
        // relock is a lock and must be byte-identical in the fields the
        // settle reads back.
        lock.token_mint = *token_mint;
        lock.order_id = *order_id;
        lock.expiry_slot = (expiry_slot).into();
        lock.locked_by = *payer.address();
        lock.bump = bump;
        lock._padding = [0u8; 7];
    }
    Ok(())
}

#[event]
pub struct TradeSettled {
    /// The Merkle-tree shard the output notes were appended to. The mirror /
    /// indexer routes the (note_*_leaf) indices into this shard.
    pub tree_id: u8,
    pub match_id: [u8; 16],
    // Amount-privacy (P3b): the trade amounts / change / fees / clearing price
    // were dropped from this event — they were a public leak (events are
    // on-chain). The event now carries only the leaf INDICES + relock flags +
    // root; a client reconstructs its own amounts from the per-account FillMemo.
    pub note_c_leaf: u64,
    pub note_d_leaf: u64,
    /// `u64::MAX` means no buyer-change leaf was inserted (exact fill).
    pub note_e_leaf: u64,
    /// `u64::MAX` means no seller-change leaf was inserted (exact fill).
    pub note_f_leaf: u64,
    /// `u64::MAX` means this match's exact base-side fee was zero (no fee leaf
    /// appended). Fees are per-match, not a batch-slot-0 aggregate flush.
    pub note_fee_base_leaf: u64,
    /// `u64::MAX` means this match's exact quote-side fee was zero.
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
    use solana_sha256_hasher::hashv;
    let buyer_relock_exp = p.buyer_relock_expiry.to_le_bytes();
    let seller_relock_exp = p.seller_relock_expiry.to_le_bytes();
    let slot = p.batch_slot.to_le_bytes();
    hashv(&[
        // v7: amount-privacy (P3b) dropped the seven plaintext amount fields
        // (base/quote/buyer_change/seller_change/buyer_fee/seller_fee/price)
        // from the payload — they're proven in-circuit + bound by the note
        // commitments. v8: encrypted output recovery appended the
        // 128-byte `fill_recovery` ciphertext bundle. v9 removed the two
        // vestigial nullifiers. v10 is the clean Darknyx namespace cutover.
        // v11 swaps the consumed commitments for note-use TAGS and appends the
        // two relock tags. Bumping the tag invalidates every signature over an
        // older domain.
        b"darknyx-match-v11",
        p.match_id.as_ref(),
        p.note_a_use_tag.as_ref(),
        p.note_b_use_tag.as_ref(),
        p.note_c_commitment.as_ref(),
        p.note_d_commitment.as_ref(),
        p.note_e_commitment.as_ref(),
        p.note_f_commitment.as_ref(),
        p.note_fee_base_commitment.as_ref(),
        p.note_fee_quote_commitment.as_ref(),
        p.order_id_a.as_ref(),
        p.order_id_b.as_ref(),
        p.buyer_relock_order_id.as_ref(),
        &buyer_relock_exp,
        p.seller_relock_order_id.as_ref(),
        &seller_relock_exp,
        p.note_e_use_tag.as_ref(),
        p.note_f_use_tag.as_ref(),
        &slot,
        p.fill_recovery.as_ref(), // v8: encrypted output-recovery bundle
    ])
    .to_bytes()
}

/// The Solana Ed25519Program precompile id.
fn ed25519_program_id() -> Address {
    solana_sdk_ids::ed25519_program::ID
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
    instructions_sysvar: &UncheckedAccount,
    expected_pubkey: &Address,
    expected_msg: &[u8; 32],
) -> Result<()> {
    // v2: `solana_instructions_sysvar::load_instruction_at_checked` takes the
    // old `AccountInfo`, which no longer exists — introspection moves to
    // pinocchio's `Instructions` reader over the same sysvar bytes. The parsing
    // below is byte-for-byte the same Ed25519 precompile layout; only the
    // accessor changed.
    use pinocchio::sysvars::instructions::Instructions;

    let ai = instructions_sysvar.account();
    let data = ai
        .try_borrow()
        .map_err(|_| Error::from(VaultError::InvalidTeeSignature))?;
    if data.len() < 2 {
        return Err(Error::from(VaultError::InvalidTeeSignature));
    }
    // SAFETY: the caller constrains this account to the instructions sysvar
    // address via `address = solana_sdk_ids::sysvar::instructions::ID`, so the
    // bytes are the runtime's own sysvar data.
    let ixs = unsafe { Instructions::new_unchecked(&data[..]) };
    let total_ix_count = ixs.num_instructions();

    // Walk every instruction in the tx looking for a single Ed25519Program
    // precompile entry with matching (pk, msg).
    for i in 0..total_ix_count {
        let ix = match ixs.load_instruction_at(i) {
            Ok(v) => v,
            Err(_) => break,
        };
        if ix.get_program_id() != &ed25519_program_id() {
            continue;
        }
        let ix_data = ix.get_instruction_data();
        if ix_data.len() < 16 {
            continue;
        }
        let num_sigs = ix_data[0];
        if num_sigs != 1 {
            continue;
        }
        let pk_off = u16::from_le_bytes([ix_data[6], ix_data[7]]) as usize;
        let pk_ix_idx = u16::from_le_bytes([ix_data[8], ix_data[9]]);
        let msg_off = u16::from_le_bytes([ix_data[10], ix_data[11]]) as usize;
        let msg_len = u16::from_le_bytes([ix_data[12], ix_data[13]]) as usize;
        let msg_ix_idx = u16::from_le_bytes([ix_data[14], ix_data[15]]);
        // We only accept inlined pk/msg (index == u16::MAX).
        if pk_ix_idx != u16::MAX || msg_ix_idx != u16::MAX {
            continue;
        }
        if pk_off + 32 > ix_data.len() || msg_off + msg_len > ix_data.len() {
            continue;
        }
        let pk_bytes = &ix_data[pk_off..pk_off + 32];
        let msg_bytes = &ix_data[msg_off..msg_off + msg_len];
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
    Err(Error::from(VaultError::InvalidTeeSignature))
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
        // A WITH-CHANGE payload, so the vector binds note_e/f and their relock
        // tags. The previous fixture zeroed them (an exact fill), which meant a
        // regression that dropped a field from the hash could not move it.
        let p = MatchResultPayload {
            match_id: [0x11u8; 16],
            note_a_use_tag: [0xA1u8; 32],
            note_b_use_tag: [0xB1u8; 32],
            note_c_commitment: [0xC1u8; 32],
            note_d_commitment: [0xD1u8; 32],
            note_e_commitment: [0xE1u8; 32],
            note_f_commitment: [0xF1u8; 32],
            order_id_a: [0x01u8; 16],
            order_id_b: [0x02u8; 16],
            note_fee_base_commitment: [0u8; 32],
            note_fee_quote_commitment: [0u8; 32],
            buyer_relock_order_id: [0u8; 16],
            buyer_relock_expiry: 0,
            seller_relock_order_id: [0u8; 16],
            seller_relock_expiry: 0,
            note_e_use_tag: [0xEAu8; 32],
            note_f_use_tag: [0xFAu8; 32],
            batch_slot: 0,
            fill_recovery: [0u8; 128],
        };
        let hash = canonical_payload_hash(&p);
        // Keep in sync with packages/sdk/tests/settle-builder.test.ts
        // `[hash_cross_env_parity]`. When the payload shape changes, update
        // BOTH sides — any divergence breaks the TEE signature verification.
        let expected: [u8; 32] = [
            0xC7, 0xFF, 0x67, 0xAC, 0xDA, 0x24, 0x5D, 0x16, 0x4C, 0x12, 0x48, 0xDC, 0x51, 0xDC,
            0x2D, 0x97, 0x05, 0x2C, 0x3A, 0xBE, 0x76, 0x96, 0x41, 0x3D, 0x54, 0xE6, 0x53, 0x6E,
            0xD0, 0x15, 0x6D, 0x45,
        ];
        if hash != expected {
            panic!("canonical_payload_hash drifted — got {:02X?}", hash);
        }
    }
}
