//! TEE-forced atomic settlement.
//!
//! The TEE produces a signed `match_result` authorising:
//!   - consumption of note_a and note_b (input notes)
//!   - creation of note_c and note_d (output notes, commitments supplied)
//!
//! The vault program executes all state transitions atomically. User
//! participation is NOT required (fair exchange via TEE-forced settlement;
//! Section 19 of the spec).
//!
//! NOTE: Ed25519 signature verification on Solana happens via the
//! `ed25519_program` precompile, which must be added to the transaction by
//! the caller. Here we check that the TEE-signed match payload hash matches
//! the `match_hash` the caller provides and trust the precompile instruction
//! to have validated the signature. A full implementation would also verify
//! the Ed25519Program instruction in the tx sysvar.
//!
//! For Phase 1 we implement the ATOMIC STATE TRANSITION correctly; Ed25519
//! sysvar verification of the TEE signature is marked as a TODO and enforced
//! via a simple bytes check against `vault_config.tee_pubkey` placed in an
//! ed25519 precompile ix. This is the standard Solana pattern.

use crate::errors::VaultError;
use crate::merkle::append_leaf;
use crate::state::*;
use anchor_lang::prelude::*;
use core::mem::size_of;

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
    /// v6: SPL mint of the QUOTE side (the mint of `note_a` / `note_e`).
    /// Cross-checked against `note_lock_a.token_mint`, which itself is bound
    /// via the VALID_INPUT proof at lock time — so the TEE cannot misrepresent
    /// which mint `note_a` carries.
    pub quote_mint: Pubkey,
    /// v6: SPL mint of the BASE side (the mint of `note_b` / `note_f`).
    pub base_mint: Pubkey,
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
    /// Batch-level fee note commitment for one mint. `[0u8;32]` = no fee
    /// note to flush on this call (normal case when settlement of a batch
    /// spans multiple txs). Populated by the TEE only on the settlement
    /// chosen to carry the flush — typically the first settlement in the
    /// batch (see `partial_fill_and_fee_notes.md §2.4`).
    pub note_fee_commitment: [u8; 32],
    /// If non-zero, re-lock note_e_commitment against `buyer_relock_order_id`
    /// for `buyer_relock_expiry`. The continuing order keeps trading in
    /// the next batch without the user doing anything.
    pub buyer_relock_order_id: [u8; 16],
    pub buyer_relock_expiry: u64,
    pub seller_relock_order_id: [u8; 16],
    pub seller_relock_expiry: u64,
    pub clearing_price: u64,
    pub batch_slot: u64,
}

#[derive(Accounts)]
#[instruction(payload: MatchResultPayload)]
pub struct TeeForcedSettle<'info> {
    #[account(mut)]
    pub tee_authority: Signer<'info>,

    #[account(
        mut,
        seeds = [VaultConfig::SEED],
        bump,
    )]
    pub vault_config: AccountLoader<'info, VaultConfig>,

    // --- locks for input notes ---
    #[account(
        mut,
        seeds = [NoteLock::SEED, payload.note_a_commitment.as_ref()],
        bump,
        close = tee_authority,
    )]
    pub note_lock_a: AccountLoader<'info, NoteLock>,

    #[account(
        mut,
        seeds = [NoteLock::SEED, payload.note_b_commitment.as_ref()],
        bump,
        close = tee_authority,
    )]
    pub note_lock_b: AccountLoader<'info, NoteLock>,

    // --- consumed-note markers (must NOT already exist -> init) ---
    #[account(
        init,
        payer = tee_authority,
        space = 8 + size_of::<ConsumedNoteEntry>(),
        seeds = [ConsumedNoteEntry::SEED, payload.note_a_commitment.as_ref()],
        bump,
    )]
    pub consumed_a: AccountLoader<'info, ConsumedNoteEntry>,

    #[account(
        init,
        payer = tee_authority,
        space = 8 + size_of::<ConsumedNoteEntry>(),
        seeds = [ConsumedNoteEntry::SEED, payload.note_b_commitment.as_ref()],
        bump,
    )]
    pub consumed_b: AccountLoader<'info, ConsumedNoteEntry>,

    // --- nullifier entries (must NOT already exist -> init) ---
    #[account(
        init,
        payer = tee_authority,
        space = 8 + size_of::<NullifierEntry>(),
        seeds = [NullifierEntry::SEED, payload.nullifier_a.as_ref()],
        bump,
    )]
    pub nullifier_a_entry: AccountLoader<'info, NullifierEntry>,

    #[account(
        init,
        payer = tee_authority,
        space = 8 + size_of::<NullifierEntry>(),
        seeds = [NullifierEntry::SEED, payload.nullifier_b.as_ref()],
        bump,
    )]
    pub nullifier_b_entry: AccountLoader<'info, NullifierEntry>,

    /// Phase-5 re-lock PDA for the buyer's change note. Created manually
    /// by the handler iff `payload.buyer_relock_order_id != NONE`; else
    /// the caller may pass any dummy writable account — the handler
    /// never touches it. The handler enforces the seed derivation
    /// `[NoteLock::SEED, payload.note_e_commitment]` when it *does* use
    /// this account.
    /// CHECK: Seeds validated in handler when re-lock is requested.
    #[account(mut)]
    pub note_lock_e: UncheckedAccount<'info>,

    /// Same as `note_lock_e`, for the seller.
    /// CHECK: Seeds validated in handler when re-lock is requested.
    #[account(mut)]
    pub note_lock_f: UncheckedAccount<'info>,

    /// Phase-5: Instructions sysvar. The handler inspects this account to
    /// prove the tx includes a valid Ed25519Program precompile ix signed
    /// by `vault_config.tee_pubkey` over `SHA-256(MatchResultPayload)`.
    /// The sysvar address is hard-coded — Anchor enforces it.
    /// CHECK: Address validated via `address = sysvar_id()`.
    #[account(address = solana_program::sysvar::instructions::ID)]
    pub instructions_sysvar: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

pub fn tee_forced_settle_handler(
    ctx: Context<TeeForcedSettle>,
    payload: MatchResultPayload,
) -> Result<()> {
    let clock = Clock::get()?;
    let tee_pubkey = {
        let cfg = ctx.accounts.vault_config.load()?;
        require!(
            ctx.accounts.tee_authority.key() == cfg.tee_pubkey,
            VaultError::Unauthorized
        );
        cfg.tee_pubkey
    };

    // Phase-5: verify the TEE's Ed25519 signature over the canonical
    // payload hash via the Solana Ed25519Program precompile. We search
    // the transaction's instructions for a matching precompile ix and
    // assert its (pubkey, msg) tuple. The precompile already checked the
    // signature bytes for us — our job is to bind that check to our
    // expected key + message.
    verify_tee_signature(
        &ctx.accounts.instructions_sysvar,
        &tee_pubkey,
        &canonical_payload_hash(&payload),
    )?;
    // Capture the mints of the two input locks. Needed below to (a) propagate
    // into change-note relock PDAs (note_e inherits lock_a's mint, note_f
    // inherits lock_b's mint), and (b) — once per-mint conservation lands in
    // v6 of MatchResultPayload — assert lock.token_mint matches the
    // payload's declared quote_mint / base_mint.
    let (lock_a_mint, lock_b_mint) = {
        let lock_a = ctx.accounts.note_lock_a.load()?;
        let lock_b = ctx.accounts.note_lock_b.load()?;
        require!(
            lock_a.order_id == payload.order_id_a,
            VaultError::NoteNotLockedForOrder
        );
        require!(
            lock_b.order_id == payload.order_id_b,
            VaultError::NoteNotLockedForOrder
        );
        // v6: input-mint binding. The locks' mints are bound to real Merkle
        // leaves via VALID_INPUT, so this assertion makes the payload's
        // declared quote_mint / base_mint provably honest for the input side.
        // (Output-side note_c/d/e/f mints still rely on TEE honesty until
        // VALID_CREATE ships — see spec §7.5.)
        require_keys_eq!(
            lock_a.token_mint,
            payload.quote_mint,
            VaultError::MintMismatch
        );
        require_keys_eq!(
            lock_b.token_mint,
            payload.base_mint,
            VaultError::MintMismatch
        );
        (lock_a.token_mint, lock_b.token_mint)
    };
    {
        let lock_a = ctx.accounts.note_lock_a.load()?;
        let lock_b = ctx.accounts.note_lock_b.load()?;

        // Phase-5 conservation law (with fees): the value escrowed under
        // each NoteLock MUST equal trade_leg + change_leg + fee_leg. This
        // check runs BEFORE any state mutation so a malicious TEE cannot
        // settle an inconsistent payload.
        //   buyer  (note_a is quote): lock_a.amount == quote_amount + buyer_change_amt + buyer_fee_amt
        //   seller (note_b is base):  lock_b.amount == base_amount  + seller_change_amt + seller_fee_amt
        let expected_a = payload
            .quote_amount
            .checked_add(payload.buyer_change_amt)
            .and_then(|v| v.checked_add(payload.buyer_fee_amt))
            .ok_or(error!(VaultError::ArithmeticOverflow))?;
        require!(
            lock_a.amount == expected_a,
            VaultError::ConservationViolation
        );
        let expected_b = payload
            .base_amount
            .checked_add(payload.seller_change_amt)
            .and_then(|v| v.checked_add(payload.seller_fee_amt))
            .ok_or(error!(VaultError::ArithmeticOverflow))?;
        require!(
            lock_b.amount == expected_b,
            VaultError::ConservationViolation
        );

        // A non-zero change amount MUST be accompanied by a non-zero
        // commitment, and vice-versa — otherwise the TEE could steal funds
        // by declaring change but never appending the leaf, or append a
        // commitment out of thin air.
        let has_e = payload.note_e_commitment != [0u8; 32];
        let has_f = payload.note_f_commitment != [0u8; 32];
        require!(
            has_e == (payload.buyer_change_amt > 0),
            VaultError::ChangeNoteInconsistent
        );
        require!(
            has_f == (payload.seller_change_amt > 0),
            VaultError::ChangeNoteInconsistent
        );

        // Re-lock requires a change note. You can't relock a note that
        // doesn't exist — the TEE would be conjuring collateral from air.
        if payload.buyer_relock_order_id != [0u8; 16] {
            require!(has_e, VaultError::RelockRequiresChangeNote);
        }
        if payload.seller_relock_order_id != [0u8; 16] {
            require!(has_f, VaultError::RelockRequiresChangeNote);
        }
    }

    // Lock sanity — already enforced by the Accounts constraints (order_id match).
    // Both lock PDAs are closed via `close = tee_authority` automatically.

    // Mark consumed notes.
    let ca = &mut ctx.accounts.consumed_a.load_init()?;
    ca.note_commitment = payload.note_a_commitment;
    ca.match_id = payload.match_id;
    ca.consumed_slot = clock.slot;
    ca.bump = ctx.bumps.consumed_a;
    ca._padding = [0u8; 7];

    let cb = &mut ctx.accounts.consumed_b.load_init()?;
    cb.note_commitment = payload.note_b_commitment;
    cb.match_id = payload.match_id;
    cb.consumed_slot = clock.slot;
    cb.bump = ctx.bumps.consumed_b;
    cb._padding = [0u8; 7];

    // Mark nullifiers spent.
    let na = &mut ctx.accounts.nullifier_a_entry.load_init()?;
    na.nullifier = payload.nullifier_a;
    na.spent_slot = clock.slot;
    na.bump = ctx.bumps.nullifier_a_entry;
    na._padding = [0u8; 7];

    let nb = &mut ctx.accounts.nullifier_b_entry.load_init()?;
    nb.nullifier = payload.nullifier_b;
    nb.spent_slot = clock.slot;
    nb.bump = ctx.bumps.nullifier_b_entry;
    nb._padding = [0u8; 7];

    // Append output note commitments to Merkle tree. Order:
    //   note_c (trade leg to buyer), note_d (trade leg to seller),
    //   note_e (buyer change, if any), note_f (seller change, if any),
    //   note_fee (batch fee note, if any).
    // The `u64::MAX` sentinel means "no leaf was inserted for this slot".
    let cfg = &mut ctx.accounts.vault_config.load_mut()?;
    let leaf_c = cfg.leaf_count;
    let _ = append_leaf(cfg, payload.note_c_commitment)?;
    let leaf_d = cfg.leaf_count;
    let mut new_root = append_leaf(cfg, payload.note_d_commitment)?;

    let leaf_e = if payload.note_e_commitment != [0u8; 32] {
        let idx = cfg.leaf_count;
        new_root = append_leaf(cfg, payload.note_e_commitment)?;
        idx
    } else {
        u64::MAX
    };
    let leaf_f = if payload.note_f_commitment != [0u8; 32] {
        let idx = cfg.leaf_count;
        new_root = append_leaf(cfg, payload.note_f_commitment)?;
        idx
    } else {
        u64::MAX
    };

    // Phase-5: flush the per-batch protocol fee note, if any. Distinct
    // from the change notes because it's owned by the protocol_owner —
    // the same append machinery applies. Consistency check: caller must
    // actually have set `protocol_owner_commitment` — else fee accrual
    // was paused upstream and we should reject a supplied fee note.
    let leaf_fee = if payload.note_fee_commitment != [0u8; 32] {
        require!(
            cfg.protocol_owner_commitment != [0u8; 32],
            VaultError::ProtocolOwnerUnset
        );
        let idx = cfg.leaf_count;
        new_root = append_leaf(cfg, payload.note_fee_commitment)?;
        idx
    } else {
        u64::MAX
    };

    // Phase-5: atomic re-lock of change notes against continuing orders.
    // Done LAST so a re-lock failure (e.g., insufficient lamports on
    // `tee_authority`) rolls back every preceding state change.
    if payload.buyer_relock_order_id != [0u8; 16] {
        create_relock_pda(
            &ctx.accounts.note_lock_e,
            &ctx.accounts.tee_authority,
            &ctx.accounts.system_program,
            &payload.note_e_commitment,
            &lock_a_mint,
            &payload.buyer_relock_order_id,
            payload.buyer_relock_expiry,
            payload.buyer_change_amt,
        )?;
    }
    if payload.seller_relock_order_id != [0u8; 16] {
        create_relock_pda(
            &ctx.accounts.note_lock_f,
            &ctx.accounts.tee_authority,
            &ctx.accounts.system_program,
            &payload.note_f_commitment,
            &lock_b_mint,
            &payload.seller_relock_order_id,
            payload.seller_relock_expiry,
            payload.seller_change_amt,
        )?;
    }

    emit!(TradeSettled {
        match_id: payload.match_id,
        clearing_price: payload.clearing_price,
        base_amount: payload.base_amount,
        quote_amount: payload.quote_amount,
        buyer_change_amt: payload.buyer_change_amt,
        seller_change_amt: payload.seller_change_amt,
        buyer_fee_amt: payload.buyer_fee_amt,
        seller_fee_amt: payload.seller_fee_amt,
        note_c_leaf: leaf_c,
        note_d_leaf: leaf_d,
        note_e_leaf: leaf_e,
        note_f_leaf: leaf_f,
        note_fee_leaf: leaf_fee,
        buyer_relock_active: payload.buyer_relock_order_id != [0u8; 16],
        seller_relock_active: payload.seller_relock_order_id != [0u8; 16],
        new_root,
    });
    Ok(())
}

/// Manually create a NoteLock PDA so the settlement tx can atomically
/// re-lock a change note against the continuing order. The seeds MUST be
/// `[NoteLock::SEED, note_commitment]` — this is what `cancel_order` /
/// `release_lock` will look up. Returns an error if the account is
/// non-empty (a prior lock still exists for this commitment).
#[allow(clippy::too_many_arguments)]
fn create_relock_pda<'info>(
    note_lock_ai: &UncheckedAccount<'info>,
    payer: &Signer<'info>,
    system_program: &Program<'info, System>,
    note_commitment: &[u8; 32],
    token_mint: &Pubkey,
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
        lock.token_mint = *token_mint;
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
    /// `u64::MAX` means no batch fee note was flushed on this settlement.
    pub note_fee_leaf: u64,
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
    let quote_mint = p.quote_mint.to_bytes();
    let base_mint = p.base_mint.to_bytes();
    // v6 tag — bumped from v5 because the payload now carries
    // `quote_mint` + `base_mint`. The SDK's settle-builder.ts must match.
    hashv(&[
        b"nyx-match-v6",
        p.match_id.as_ref(),
        p.note_a_commitment.as_ref(),
        p.note_b_commitment.as_ref(),
        p.note_c_commitment.as_ref(),
        p.note_d_commitment.as_ref(),
        p.note_e_commitment.as_ref(),
        p.note_f_commitment.as_ref(),
        p.note_fee_commitment.as_ref(),
        p.nullifier_a.as_ref(),
        p.nullifier_b.as_ref(),
        p.order_id_a.as_ref(),
        p.order_id_b.as_ref(),
        &quote_mint,
        &base_mint,
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
    use solana_program::sysvar::instructions::{
        load_current_index_checked, load_instruction_at_checked,
    };

    let ai = instructions_sysvar.to_account_info();
    let current_ix_idx = load_current_index_checked(&ai)
        .map_err(|_| error!(VaultError::InvalidTeeSignature))?;

    // Walk every instruction in the tx except ourselves, looking for a
    // single Ed25519Program precompile entry with matching (pk, msg).
    for i in 0..current_ix_idx as usize + 8 {
        // Ceiling: `load_instruction_at_checked` returns Err past the
        // last ix; break when we go OOB.
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
        // v6 fixture. Two new pubkey-shaped fields (`quote_mint`, `base_mint`)
        // hashed between order_id_b and base_amount. Domain tag bumped to
        // `b"nyx-match-v6"`. Keep in sync with the SDK side
        // (packages/sdk/tests/settle-builder.test.ts).
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
            quote_mint: Pubkey::new_from_array([0xC4u8; 32]),
            base_mint: Pubkey::new_from_array([0xC5u8; 32]),
            base_amount: 100,
            quote_amount: 5_000,
            buyer_change_amt: 0,
            seller_change_amt: 0,
            buyer_fee_amt: 0,
            seller_fee_amt: 0,
            note_fee_commitment: [0u8; 32],
            buyer_relock_order_id: [0u8; 16],
            buyer_relock_expiry: 0,
            seller_relock_order_id: [0u8; 16],
            seller_relock_expiry: 0,
            clearing_price: 0,
            batch_slot: 0,
        };
        let hash = canonical_payload_hash(&p);
        // The v6 expected hash is filled in after first compile — run
        //   cargo test -p vault canonical_payload_hash_fixed_vector
        // and copy the printed value here.
        let expected: [u8; 32] = [
            0x8E, 0x53, 0xB8, 0x36, 0x62, 0xB1, 0x8B, 0xEA, 0x73, 0x77, 0x48, 0x2C, 0xC1, 0xA7,
            0xD1, 0x82, 0x2F, 0xFB, 0x8C, 0x7C, 0xD8, 0x32, 0xB8, 0x21, 0xB1, 0x8D, 0xB0, 0x36,
            0x8B, 0x31, 0x5F, 0x31,
        ];
        if hash != expected {
            panic!(
                "canonical_payload_hash drifted — got {:02X?}",
                hash
            );
        }
    }
}
