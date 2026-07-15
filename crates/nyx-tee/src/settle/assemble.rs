//! `MatchPair` + input-note openings → (`MatchSlotWitness`,
//! `MatchResultPayload`).
//!
//! This is the byte-critical bridge between the matcher's output and
//! the settle pipeline. For one real match it produces:
//!
//!   - the **proof witness** the VALID_MATCH_BATCH circuit consumes
//!     (input-note openings + derived output-note openings +
//!     conservation fields), and
//!   - the **settle payload** the TEE signs + the on-chain handler
//!     verifies (commitments + nullifiers + amounts + re-lock + fee).
//!
//! Every derivation here mirrors the canonical TS reference
//! (`packages/sdk/tests/helpers/e2e-helpers.ts` +
//! `change-note-flow.test.ts`), because the user must be able to
//! re-derive the output notes' openings later to spend them:
//!
//!   - note_c/e (buyer outputs): owner = buyer input's owner commitment;
//!     inner = Poseidon3(24, buyer_input_inner, output_role).
//!   - note_d/f (seller outputs): owner = seller input's owner commitment;
//!     inner = Poseidon3(24, seller_input_inner, output_role).
//!   - note_fee (protocol cut): owner = protocol_owner_commitment;
//!     inner = Poseidon3(25, consumed_input_commitment, fee_role).
//!
//! Conservation is enforced up front (the same equalities the circuit
//! constrains), so a malformed match fails here with a named error
//! rather than as an opaque `InvalidProof` on-chain.
//!
//! The input-note openings come from [`crate::matcher::openings`]
//! (captured + verified at order intake, 4g.7a). The `order_id_a/b`
//! and the MatchPair→orders linkage are supplied by the caller
//! (4g.7c live wiring); this function is pure so it's exhaustively
//! unit-testable without a matcher tick or a real proof.

use darkpool_crypto::note::commitment_from_fields_v2;
use darkpool_crypto::{match_fee_inner_hash, match_output_inner_hash};
use darkpool_matcher::change_note::{
    CHANGE_ROLE_BUYER, CHANGE_ROLE_SELLER, FEE_ROLE_BASE, FEE_ROLE_QUOTE, TRADE_ROLE_BUYER,
    TRADE_ROLE_SELLER,
};
use darkpool_matcher::match_result::{MatchPair, RunBatchOutput};
use sha2::{Digest, Sha256};

use crate::matcher::openings::{NoteOpening, OpeningStore};
use crate::prover::{pad_batch, MatchSlotWitness};
use crate::settle::payload::MatchResultPayload;
use crate::settle::submit_lock::LockSideInputs;
use crate::settle::worker::{BatchSettleInputs, MatchSettleInputs};

/// Inputs to assemble one match. References are borrowed; the result
/// owns its bytes.
pub struct MatchAssemblyInputs<'a> {
    pub match_pair: &'a MatchPair,
    /// Opening of the buyer's input note (note_a, QUOTE collateral).
    pub buyer_opening: &'a NoteOpening,
    /// Opening of the seller's input note (note_b, BASE collateral).
    pub seller_opening: &'a NoteOpening,
    /// 16-byte ids of the two matched orders (payload fields).
    pub order_id_a: [u8; 16],
    pub order_id_b: [u8; 16],
    /// Domain-separated 16-byte settlement identifier derived from the boot
    /// session, the match counter, and both order ids.
    pub settlement_id: [u8; 16],
    /// Market mints.
    pub base_mint: [u8; 32],
    pub quote_mint: [u8; 32],
    /// Owner commitment the protocol's fee notes pay to.
    pub protocol_owner_commitment: [u8; 32],
    /// Protocol fee rate (bps) — the circuit's fee-floor public input
    /// (`VaultConfig.fee_rate_bps`). Stamped into every slot's witness.
    pub fee_rate_bps: u64,
    /// Governed fixed-point price denominator.
    pub price_scale: u64,
    /// This match's **position within the batch** (0..N-1). C-08:
    /// VALID_MATCH_BATCH binds `batch_slot[i] === i`, and the on-chain settle
    /// asserts `payload.batch_slot == match_index`, so the leaf/payload
    /// `batch_slot` MUST be the slot index — NOT the matcher's `now_slot`
    /// Mixing
    /// these up is the bug the live CVM caught: the matcher sets
    /// `MatchPair.batch_slot = now_slot`, so feeding that into the leaf makes
    /// witness generation abort on `batch_slot[i] === i`.
    pub slot_index: u64,
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum AssembleError {
    #[error("note commitment derivation failed (Fr-safety): {0}")]
    Crypto(String),
    #[error("conservation violated: {0}")]
    Conservation(String),
    #[error("buyer opening mint does not match the market quote mint")]
    BuyerMint,
    #[error("seller opening mint does not match the market base mint")]
    SellerMint,
    /// A match references a collateral note with no opening in the
    /// store — the order's opening was never captured (or was already
    /// evicted). Cannot settle without it.
    #[error("no opening in store for {side} note {commitment}")]
    MissingOpening {
        side: &'static str,
        commitment: String,
    },
    /// The batch has more real matches than the circuit's N.
    #[error("batch has {got} matches but circuit N = {n}")]
    BatchTooLarge { got: usize, n: usize },
}

const ZERO32: [u8; 32] = [0u8; 32];
const SETTLEMENT_ID_DOMAIN: &[u8] = b"nyx-settlement-id-v1";

/// Derive the transport/event settlement id. Output-note safety does not rely
/// on uniqueness: VALID_MATCH_BATCH derives every output inner exclusively
/// from a consumed input commitment/inner plus a role tag.
pub fn derive_settlement_id(
    boot_session_id: &[u8; 32],
    counter: u64,
    order_id_a: &[u8; 16],
    order_id_b: &[u8; 16],
) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(SETTLEMENT_ID_DOMAIN);
    h.update(boot_session_id);
    h.update(counter.to_le_bytes());
    h.update(order_id_a);
    h.update(order_id_b);
    let digest = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

fn commit(
    mint: &[u8; 32],
    amount: u64,
    owner: &[u8; 32],
    inner: &[u8; 32],
) -> Result<[u8; 32], AssembleError> {
    commitment_from_fields_v2(mint, amount, owner, inner)
        .map_err(|e| AssembleError::Crypto(e.to_string()))
}

/// Assemble one match into its proof witness + settle payload.
pub fn assemble_match(
    inp: MatchAssemblyInputs,
) -> Result<(MatchSlotWitness, MatchResultPayload), AssembleError> {
    let m = inp.match_pair;

    // ── 0. The openings must be for the correct collateral mints.
    // A bid locks QUOTE (note_a); an ask locks BASE (note_b).
    if inp.buyer_opening.token_mint != inp.quote_mint {
        return Err(AssembleError::BuyerMint);
    }
    if inp.seller_opening.token_mint != inp.base_mint {
        return Err(AssembleError::SellerMint);
    }

    let a_amount = inp.buyer_opening.amount;
    let b_amount = inp.seller_opening.amount;

    // ── 1. Conservation — the exact equalities the circuit constrains.
    //   a_amount === quote_amount + buyer_change + buyer_fee
    //   b_amount === base_amount  + seller_change + seller_fee
    let buyer_out = m
        .quote_amt
        .checked_add(m.buyer_change_amt)
        .and_then(|x| x.checked_add(m.buyer_fee_amt))
        .ok_or_else(|| AssembleError::Conservation("buyer-side sum overflows u64".into()))?;
    if a_amount != buyer_out {
        return Err(AssembleError::Conservation(format!(
            "a_amount ({a_amount}) != quote ({}) + buyer_change ({}) + buyer_fee ({})",
            m.quote_amt, m.buyer_change_amt, m.buyer_fee_amt
        )));
    }
    let seller_out = m
        .base_amt
        .checked_add(m.seller_change_amt)
        .and_then(|x| x.checked_add(m.seller_fee_amt))
        .ok_or_else(|| AssembleError::Conservation("seller-side sum overflows u64".into()))?;
    if b_amount != seller_out {
        return Err(AssembleError::Conservation(format!(
            "b_amount ({b_amount}) != base ({}) + seller_change ({}) + seller_fee ({})",
            m.base_amt, m.seller_change_amt, m.seller_fee_amt
        )));
    }

    // ── 2. Scaled floor pricing.
    if m.base_amt == 0 || m.price == 0 || inp.price_scale == 0 {
        return Err(AssembleError::Conservation("base_amount is zero".into()));
    }
    let clearing_price = m.price;
    let numerator = (m.base_amt as u128)
        .checked_mul(clearing_price as u128)
        .ok_or_else(|| AssembleError::Conservation("scaled price product overflow".into()))?;
    let expected_quote = numerator / inp.price_scale as u128;
    let price_remainder = numerator % inp.price_scale as u128;
    if expected_quote != m.quote_amt as u128 {
        return Err(AssembleError::Conservation(format!(
            "quote ({}) != floor(base ({}) * price ({}) / scale ({}))",
            m.quote_amt, m.base_amt, clearing_price, inp.price_scale
        )));
    }

    // ── 3. Output notes c (buyer, BASE) + d (seller, QUOTE).
    let c_inner = match_output_inner_hash(&inp.buyer_opening.inner_hash, TRADE_ROLE_BUYER)
        .map_err(|e| AssembleError::Crypto(e.to_string()))?;
    let note_c = commit(
        &inp.base_mint,
        m.base_amt,
        &inp.buyer_opening.owner_commitment,
        &c_inner,
    )?;

    let d_inner = match_output_inner_hash(&inp.seller_opening.inner_hash, TRADE_ROLE_SELLER)
        .map_err(|e| AssembleError::Crypto(e.to_string()))?;
    let note_d = commit(
        &inp.quote_mint,
        m.quote_amt,
        &inp.seller_opening.owner_commitment,
        &d_inner,
    )?;

    // ── 4. Change notes e (buyer, QUOTE) + f (seller, BASE),
    // conditional on a non-zero change amount. When there's no
    // change, the commitment AND the inner_hash are all-zero — the
    // circuit's IsZero gate bypasses the reconstruction constraint,
    // matching the TS exact-fill witness.
    //
    // The inner is derived from the consumed input inner for both final and
    // continuing outputs; relocking no longer depends on an anchor pool.
    let (note_e, e_inner) = if m.buyer_change_amt > 0 {
        let inner = match_output_inner_hash(&inp.buyer_opening.inner_hash, CHANGE_ROLE_BUYER)
            .map_err(|e| AssembleError::Crypto(e.to_string()))?;
        let c = commit(
            &inp.quote_mint,
            m.buyer_change_amt,
            &inp.buyer_opening.owner_commitment,
            &inner,
        )?;
        (c, inner)
    } else {
        (ZERO32, ZERO32)
    };

    let (note_f, f_inner) = if m.seller_change_amt > 0 {
        let inner = match_output_inner_hash(&inp.seller_opening.inner_hash, CHANGE_ROLE_SELLER)
            .map_err(|e| AssembleError::Crypto(e.to_string()))?;
        let c = commit(
            &inp.base_mint,
            m.seller_change_amt,
            &inp.seller_opening.owner_commitment,
            &inner,
        )?;
        (c, inner)
    } else {
        (ZERO32, ZERO32)
    };

    // ── 5. Per-match fee notes, atomically appended by this match's Tx D.
    let fee_base_inner = match_fee_inner_hash(&m.note_seller, FEE_ROLE_BASE)
        .map_err(|e| AssembleError::Crypto(e.to_string()))?;
    let fee_quote_inner = match_fee_inner_hash(&m.note_buyer, FEE_ROLE_QUOTE)
        .map_err(|e| AssembleError::Crypto(e.to_string()))?;
    let note_fee_base_commitment = if m.seller_fee_amt == 0 {
        ZERO32
    } else {
        commit(
            &inp.base_mint,
            m.seller_fee_amt,
            &inp.protocol_owner_commitment,
            &fee_base_inner,
        )?
    };
    let note_fee_quote_commitment = if m.buyer_fee_amt == 0 {
        ZERO32
    } else {
        commit(
            &inp.quote_mint,
            m.buyer_fee_amt,
            &inp.protocol_owner_commitment,
            &fee_quote_inner,
        )?
    };

    let witness = MatchSlotWitness {
        note_a_commitment: m.note_buyer,
        note_b_commitment: m.note_seller,
        note_c_commitment: note_c,
        note_d_commitment: note_d,
        note_e_commitment: note_e,
        note_f_commitment: note_f,
        quote_mint: inp.quote_mint,
        base_mint: inp.base_mint,
        base_amount: m.base_amt,
        quote_amount: m.quote_amt,
        buyer_change_amt: m.buyer_change_amt,
        seller_change_amt: m.seller_change_amt,
        buyer_fee_amt: m.buyer_fee_amt,
        seller_fee_amt: m.seller_fee_amt,
        // C-08: the leaf's slot field is the batch INDEX, not `m.batch_slot`
        // (= now_slot). The circuit binds `batch_slot[i] === i`.
        batch_slot: inp.slot_index,
        is_active: true,
        a_owner_commit: inp.buyer_opening.owner_commitment,
        b_owner_commit: inp.seller_opening.owner_commitment,
        a_amount,
        b_amount,
        a_inner: inp.buyer_opening.inner_hash,
        b_inner: inp.seller_opening.inner_hash,
        c_inner,
        d_inner,
        e_inner,
        f_inner,
        clearing_price,
        price_remainder: price_remainder as u64,
        note_fee_base_commitment,
        note_fee_quote_commitment,
        fee_rate_bps: inp.fee_rate_bps,
        protocol_owner_commitment: inp.protocol_owner_commitment,
        price_scale: inp.price_scale,
        fee_base_inner,
        fee_quote_inner,
    };

    let payload = MatchResultPayload {
        match_id: inp.settlement_id,
        note_a_commitment: m.note_buyer,
        note_b_commitment: m.note_seller,
        note_c_commitment: note_c,
        note_d_commitment: note_d,
        note_e_commitment: note_e,
        note_f_commitment: note_f,
        order_id_a: inp.order_id_a,
        order_id_b: inp.order_id_b,
        // Amount-privacy (P3b): the amounts (base/quote/change/fee/price) stay
        // in the WITNESS (private prover inputs) but no longer ride the payload
        // — VALID_MATCH_BATCH proves conservation + the fee floor over them and
        // the note commitments bind them, so the on-chain settle ix carries no
        // plaintext amounts.
        //
        note_fee_base_commitment,
        note_fee_quote_commitment,
        buyer_relock_order_id: m.buyer_relock_order_id,
        buyer_relock_expiry: m.buyer_relock_expiry,
        seller_relock_order_id: m.seller_relock_order_id,
        seller_relock_expiry: m.seller_relock_expiry,
        // C-08: on-chain settle asserts `payload.batch_slot == match_index`,
        // so this MUST be the batch index (matches the leaf witness above).
        batch_slot: inp.slot_index,
        // Change-amount recovery (Proposal B): zero here; `assemble_batch`
        // fills it from the openings' viewing keys (it has the OrderOpenings;
        // this per-match fn only sees the NoteOpenings). Zero = no ciphertext.
        fill_recovery: [0u8; 128],
    };

    Ok((witness, payload))
}

/// Parameters for assembling a whole batch (market + protocol context
/// the per-match openings don't carry).
pub struct BatchAssemblyParams {
    /// Scheduler-local batch id (keys the per-match jobs).
    pub batch_id: u64,
    pub boot_session_id: [u8; 32],
    pub base_mint: [u8; 32],
    pub quote_mint: [u8; 32],
    pub protocol_owner_commitment: [u8; 32],
    // Fee identifier is intentionally absent: `assemble_batch` must copy the
    // value recorded on `RunBatchOutput`, so callers cannot re-sample it.
    /// Protocol fee rate (bps) — the circuit fee-floor public input
    /// (`VaultConfig.fee_rate_bps`).
    pub fee_rate_bps: u64,
    pub price_scale: u64,
    /// Circuit instantiation N (production = 16) — the witness set is
    /// padded with dummy slots up to this.
    pub circuit_n: usize,
}

/// Turn one matcher `RunBatchOutput` into the settle worker's
/// [`BatchSettleInputs`], resolving each match's two input-note
/// openings from the in-enclave store (keyed by collateral note
/// commitment — the matcher's `MatchPair` carries `note_buyer` /
/// `note_seller`).
///
/// For each real match it produces the proof witness + signed payload
/// (via [`assemble_match`]) AND the buyer/seller `lock_note` inputs
/// (from the stored VALID_INPUT proof relay). The witness set is then
/// padded to `circuit_n`.
pub fn assemble_batch(
    output: &RunBatchOutput,
    store: &OpeningStore,
    params: BatchAssemblyParams,
) -> Result<BatchSettleInputs, AssembleError> {
    if output.matches.len() > params.circuit_n {
        return Err(AssembleError::BatchTooLarge {
            got: output.matches.len(),
            n: params.circuit_n,
        });
    }

    let mut matches = Vec::with_capacity(output.matches.len());
    let mut witnesses = Vec::with_capacity(output.matches.len());

    for (idx, m) in output.matches.iter().enumerate() {
        let buyer = store
            .get(&m.note_buyer)
            .ok_or_else(|| AssembleError::MissingOpening {
                side: "buyer",
                commitment: hex::encode(m.note_buyer),
            })?;
        let seller = store
            .get(&m.note_seller)
            .ok_or_else(|| AssembleError::MissingOpening {
                side: "seller",
                commitment: hex::encode(m.note_seller),
            })?;

        let settlement_id = derive_settlement_id(
            &params.boot_session_id,
            m.match_id,
            &buyer.order_id,
            &seller.order_id,
        );
        let (witness, mut payload) = assemble_match(MatchAssemblyInputs {
            match_pair: m,
            buyer_opening: &buyer.opening,
            seller_opening: &seller.opening,
            order_id_a: buyer.order_id,
            order_id_b: seller.order_id,
            settlement_id,
            base_mint: params.base_mint,
            quote_mint: params.quote_mint,
            protocol_owner_commitment: params.protocol_owner_commitment,
            // C-08: the leaf/payload batch_slot is this match's index in the
            // batch (0..N-1), which the circuit + on-chain settle both require.
            slot_index: idx as u64,
            fee_rate_bps: params.fee_rate_bps,
            price_scale: params.price_scale,
        })?;

        let buyer_lock = lock_inputs(m.note_buyer, &buyer);
        let seller_lock = lock_inputs(m.note_seller, &seller);

        // Change-amount recovery (Proposal B): encrypt each side's change_amount
        // to its order's viewing key so the change note stays recoverable after
        // a CVM redeploy. The change note returns to the same owner, so the
        // input note's opening is the right recipient. The ciphertext rides the
        // SIGNED payload (so the TEE signature binds it on-chain).
        let fill_ciphertext = crate::settle::fill_recovery::build_fill_ciphertext(
            buyer.viewing_pubkey,
            seller.viewing_pubkey,
            m.buyer_change_amt,
            m.seller_change_amt,
        );
        payload.fill_recovery = fill_ciphertext.to_payload_bytes();

        matches.push(MatchSettleInputs {
            payload,
            buyer_lock,
            seller_lock,
            match_index: idx as u8,
        });
        witnesses.push(witness);
    }

    // Pad the witness set to the circuit's N with dummy slots.
    let witnesses =
        pad_batch(&witnesses, params.circuit_n).map_err(|_| AssembleError::BatchTooLarge {
            got: output.matches.len(),
            n: params.circuit_n,
        })?;

    Ok(BatchSettleInputs {
        batch_id: params.batch_id,
        matches,
        witnesses,
    })
}

/// Build the `lock_note` (Tx A) inputs for one input note from its
/// stored record — the VALID_INPUT proof + root the client relayed.
fn lock_inputs(
    note_commitment: [u8; 32],
    rec: &crate::matcher::openings::OrderOpening,
) -> LockSideInputs {
    LockSideInputs {
        // The shard the input note lives in (from the order's `tree_id`,
        // recorded at intake) — so lock_note checks `merkle_root` recency
        // against the right `merkle_tree` shard and a batch's inputs can span
        // shards. Irrelevant for a relocked continuation (`already_locked`
        // below skips lock_note entirely).
        tree_id: rec.tree_id,
        note_commitment,
        order_id: rec.order_id,
        expiry_slot: rec.expiry_slot,
        token_mint: rec.opening.token_mint,
        merkle_root: rec.merkle_root,
        proof: rec.valid_input_proof.clone(),
        // A relocked continuation note is already locked by the prior batch's
        // re-lock PDA — skip lock_note for it (re-init would collide).
        already_locked: rec.from_relock,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::compute_batch_leaf;
    use darkpool_matcher::book::{Order, OrderBook, OrderSide, OrderStatus, OrderType};
    use darkpool_matcher::config::{MatchConfig, OracleSnapshot};
    use darkpool_matcher::match_result::MatchStatus;
    use darkpool_matcher::run_batch;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    fn fr_safe(b: u8) -> [u8; 32] {
        let mut v = [b; 32];
        v[0] = 0;
        v
    }
    fn base_mint() -> [u8; 32] {
        let mut m = [0u8; 32];
        m[0] = 1;
        m[31] = 0xb1;
        m
    }
    fn quote_mint() -> [u8; 32] {
        let mut m = [0u8; 32];
        m[0] = 1;
        m[31] = 0x9e;
        m
    }

    fn fr_safe_pair(domain: u8, salt: u8) -> [u8; 32] {
        let mut value = [0u8; 32];
        value[30] = domain;
        value[31] = salt;
        value
    }

    /// Build a self-consistent match: the input-note commitments equal
    /// `commitment_from_fields_v2(opening)`, so the resulting witness is
    /// provable (note_a/b reconstruct).
    fn scenario(
        base_amt: u64,
        quote_amt: u64,
        buyer_change: u64,
        seller_change: u64,
        buyer_fee: u64,
        seller_fee: u64,
    ) -> (MatchPair, NoteOpening, NoteOpening) {
        let buyer_owner = fr_safe(0x44);
        let seller_owner = fr_safe(0x55);
        let a_amount = quote_amt + buyer_change + buyer_fee;
        let b_amount = base_amt + seller_change + seller_fee;

        let buyer_opening = NoteOpening {
            token_mint: quote_mint(),
            amount: a_amount,
            owner_commitment: buyer_owner,
            inner_hash: fr_safe(0x11),
            nullifier: [0xAA; 32],
        };
        let seller_opening = NoteOpening {
            token_mint: base_mint(),
            amount: b_amount,
            owner_commitment: seller_owner,
            inner_hash: fr_safe(0x33),
            nullifier: [0xBB; 32],
        };
        let note_buyer = buyer_opening.commitment().unwrap();
        let note_seller = seller_opening.commitment().unwrap();

        let m = MatchPair {
            note_buyer,
            note_seller,
            note_e_commitment: [0; 32],
            note_f_commitment: [0; 32],
            owner_buyer: [0x77; 32],
            owner_seller: [0x88; 32],
            user_commitment_buyer: [0x99; 32],
            user_commitment_seller: [0xAA; 32],
            buyer_note_value: a_amount,
            seller_note_value: b_amount,
            base_amt,
            quote_amt,
            buyer_change_amt: buyer_change,
            seller_change_amt: seller_change,
            buyer_fee_amt: buyer_fee,
            seller_fee_amt: seller_fee,
            buyer_relock_order_id: [0; 16],
            buyer_relock_expiry: 0,
            seller_relock_order_id: [0; 16],
            seller_relock_expiry: 0,
            price: quote_amt / base_amt,
            pyth_at_match: quote_amt / base_amt,
            batch_slot: 7,
            match_id: 42,
            status: MatchStatus::Filled,
        };
        (m, buyer_opening, seller_opening)
    }

    fn inputs<'a>(
        m: &'a MatchPair,
        buyer: &'a NoteOpening,
        seller: &'a NoteOpening,
    ) -> MatchAssemblyInputs<'a> {
        MatchAssemblyInputs {
            match_pair: m,
            buyer_opening: buyer,
            seller_opening: seller,
            order_id_a: [0x01; 16],
            order_id_b: [0x02; 16],
            settlement_id: derive_settlement_id(&[0x5A; 32], m.match_id, &[0x01; 16], &[0x02; 16]),
            base_mint: base_mint(),
            quote_mint: quote_mint(),
            protocol_owner_commitment: fr_safe(0x07),
            price_scale: 1,
            // Default to index 0 (single-match). The scenario's MatchPair
            // carries batch_slot=7 (a now_slot stand-in) on purpose, so tests
            // that assert on the leaf/payload batch_slot prove it tracks
            // slot_index, not m.batch_slot (see the C-08 regression test).
            slot_index: 0,
            fee_rate_bps: 0,
        }
    }

    #[test]
    fn exact_fill_has_zero_change_and_fee_notes() {
        let (m, buyer, seller) = scenario(10, 1000, 0, 0, 0, 0);
        let (w, p) = assemble_match(inputs(&m, &buyer, &seller)).unwrap();

        // No change → note_e/f + their openings are all-zero.
        assert_eq!(w.note_e_commitment, [0u8; 32]);
        assert_eq!(w.note_f_commitment, [0u8; 32]);
        assert_eq!(w.e_inner, [0u8; 32]);
        assert_eq!(w.f_inner, [0u8; 32]);
        // This zero-fee match has canonical zero fee commitments.
        assert_eq!(p.note_fee_base_commitment, [0u8; 32]);
        assert_eq!(p.note_fee_quote_commitment, [0u8; 32]);
        // clearing = quote/base. Amount-privacy (P3b): the clearing price lives
        // only in the witness now (the payload no longer carries it).
        assert_eq!(w.clearing_price, 100);
    }

    #[test]
    fn batch_slot_tracks_slot_index_not_matcher_now_slot() {
        // Regression for the C-08 gap the live CVM caught. The matcher stamps
        // `MatchPair.batch_slot` with the on-chain `now_slot` (scenario uses 7),
        // but VALID_MATCH_BATCH binds `batch_slot[i] === i` and the on-chain
        // settle asserts `payload.batch_slot == match_index`. So the assembled
        // leaf + payload MUST carry the slot INDEX, never `m.batch_slot`.
        // Before the fix, feeding `m.batch_slot` here made live witness
        // generation abort on `batch_slot[i] === i`.
        let (m, buyer, seller) = scenario(10, 1000, 0, 0, 0, 0);
        assert_eq!(m.batch_slot, 7, "scenario stamps a now_slot-like value");

        let mut inp = inputs(&m, &buyer, &seller);
        inp.slot_index = 3; // deliberately != m.batch_slot
        let (w, p) = assemble_match(inp).unwrap();

        assert_eq!(
            w.batch_slot, 3,
            "witness leaf batch_slot must be slot_index"
        );
        assert_eq!(p.batch_slot, 3, "payload batch_slot must be slot_index");
        assert_eq!(
            w.fee_base_inner,
            match_fee_inner_hash(&m.note_seller, FEE_ROLE_BASE).unwrap()
        );
    }

    #[test]
    fn note_a_and_b_reconstruct_from_openings() {
        // The whole point: the witness must be PROVABLE, i.e.
        // note_a_commitment == Poseidon7(opening). scenario() builds
        // the MatchPair commitments from the openings, so they must
        // round-trip through commitment_from_fields.
        let (m, buyer, seller) = scenario(10, 1000, 0, 0, 0, 0);
        let (w, _) = assemble_match(inputs(&m, &buyer, &seller)).unwrap();
        assert_eq!(w.note_a_commitment, buyer.commitment().unwrap());
        assert_eq!(w.note_b_commitment, seller.commitment().unwrap());
    }

    #[test]
    fn note_c_d_match_trade_role_derivation() {
        let (m, buyer, seller) = scenario(10, 1000, 0, 0, 0, 0);
        let (w, p) = assemble_match(inputs(&m, &buyer, &seller)).unwrap();

        // note_c: buyer receives BASE, owner = buyer's note owner,
        let ci = match_output_inner_hash(&buyer.inner_hash, TRADE_ROLE_BUYER).unwrap();
        let expected_c =
            commitment_from_fields_v2(&base_mint(), 10, &buyer.owner_commitment, &ci).unwrap();
        assert_eq!(w.note_c_commitment, expected_c);
        assert_eq!(p.note_c_commitment, expected_c);
        assert_eq!(w.c_inner, ci);

        // note_d: seller receives QUOTE, owner = seller's note owner.
        let di = match_output_inner_hash(&seller.inner_hash, TRADE_ROLE_SELLER).unwrap();
        let expected_d =
            commitment_from_fields_v2(&quote_mint(), 1000, &seller.owner_commitment, &di).unwrap();
        assert_eq!(w.note_d_commitment, expected_d);
    }

    #[test]
    fn with_change_derives_e_and_per_match_quote_fee_note() {
        // base=10, quote=1000, buyer keeps 150 change + pays 50 fee
        // (a_amount = 1000 + 150 + 50 = 1200); seller exact.
        let (m, buyer, seller) = scenario(10, 1000, 150, 0, 50, 0);
        let (w, p) = assemble_match(inputs(&m, &buyer, &seller)).unwrap();

        let ei = match_output_inner_hash(&buyer.inner_hash, CHANGE_ROLE_BUYER).unwrap();
        let expected_e =
            commitment_from_fields_v2(&quote_mint(), 150, &buyer.owner_commitment, &ei).unwrap();
        assert_eq!(w.note_e_commitment, expected_e);
        assert_eq!(w.e_inner, ei);
        assert_eq!(w.buyer_change_amt, 150);

        // Fee notes are per-match and circuit-bound to the consumed input.
        assert_eq!(w.buyer_fee_amt, 50);
        assert_eq!(p.note_fee_base_commitment, [0u8; 32]);
        assert_ne!(p.note_fee_quote_commitment, [0u8; 32]);
    }

    #[test]
    fn randomized_assembler_outputs_use_consumed_openings() {
        let mut rng = StdRng::seed_from_u64(0x004e_5958_2d4e_3037);

        for case in 0u64..256 {
            let price = rng.gen_range(1u64..10_000);
            let amount = rng.gen_range(1u64..10_000);
            let buyer_change = rng.gen_range(1u64..1_000_000);
            let seller_change = rng.gen_range(1u64..1_000_000);
            let salt = rng.gen::<u8>();

            let buyer_owner = fr_safe_pair(0x20, salt);
            let seller_owner = fr_safe_pair(0x40, salt);
            let buyer_opening = NoteOpening {
                token_mint: quote_mint(),
                amount: amount * price + buyer_change,
                owner_commitment: buyer_owner,
                inner_hash: fr_safe_pair(0x51, salt),
                nullifier: fr_safe_pair(0x61, salt),
            };
            let seller_opening = NoteOpening {
                token_mint: base_mint(),
                amount: amount + seller_change,
                owner_commitment: seller_owner,
                inner_hash: fr_safe_pair(0x52, salt),
                nullifier: fr_safe_pair(0x62, salt),
            };

            let bid = Order {
                trading_key: fr_safe_pair(0x71, salt),
                side: OrderSide::Bid,
                order_type: OrderType::Limit,
                status: OrderStatus::Pending,
                arrival_slot: 1,
                expiry_slot: 1_000_000,
                price_limit: price,
                amount,
                total_quantity: amount,
                filled_quantity: 0,
                min_fill_qty: 0,
                note_amount: buyer_opening.amount,
                collateral_note: buyer_opening.commitment().unwrap(),
                user_commitment: fr_safe_pair(0x10, salt),
                owner_commitment: buyer_owner,
                order_id: [0x01; 16],
                order_inclusion_commitment: fr_safe_pair(0x81, salt),
            };
            let ask = Order {
                trading_key: fr_safe_pair(0x72, salt),
                side: OrderSide::Ask,
                order_type: OrderType::Limit,
                status: OrderStatus::Pending,
                arrival_slot: 2,
                expiry_slot: 1_000_000,
                price_limit: price,
                amount,
                total_quantity: amount,
                filled_quantity: 0,
                min_fill_qty: 0,
                note_amount: seller_opening.amount,
                collateral_note: seller_opening.commitment().unwrap(),
                user_commitment: fr_safe_pair(0x30, salt),
                owner_commitment: seller_owner,
                order_id: [0x02; 16],
                order_inclusion_commitment: fr_safe_pair(0x82, salt),
            };
            let config = MatchConfig {
                base_mint: base_mint(),
                quote_mint: quote_mint(),
                tick_size: 1,
                min_order_size: 0,
                circuit_breaker_bps: 100_000,
                batch_ms: 2_000,
                fee_rate_bps: 0,
                protocol_owner_commitment: [0u8; 32],
                price_scale: 1,
            };
            let oracle = OracleSnapshot {
                twap: price,
                confidence: 0,
                exponent: 0,
                publish_slot: 1,
            };
            let output = run_batch(
                &OrderBook {
                    orders: vec![bid, ask],
                },
                &oracle,
                &config,
                1,
                case,
            )
            .unwrap();
            assert_eq!(output.matches.len(), 1, "case {case}");
            let matched = &output.matches[0];

            let (witness, payload) = assemble_match(MatchAssemblyInputs {
                match_pair: matched,
                buyer_opening: &buyer_opening,
                seller_opening: &seller_opening,
                order_id_a: [0x01; 16],
                order_id_b: [0x02; 16],
                settlement_id: derive_settlement_id(
                    &[0x5A; 32],
                    matched.match_id,
                    &[0x01; 16],
                    &[0x02; 16],
                ),
                base_mint: base_mint(),
                quote_mint: quote_mint(),
                protocol_owner_commitment: [0u8; 32],
                fee_rate_bps: 0,
                price_scale: 1,
                slot_index: 0,
            })
            .unwrap();

            assert_eq!(payload.note_e_commitment, witness.note_e_commitment);
            assert_eq!(payload.note_f_commitment, witness.note_f_commitment);
        }
    }

    #[test]
    fn relocking_buyer_change_uses_consumed_input_inner() {
        let (mut m, buyer, seller) = scenario(10, 1000, 150, 0, 50, 0);
        m.buyer_relock_order_id = [0xAB; 16];

        let (w, _) = assemble_match(inputs(&m, &buyer, &seller)).unwrap();
        let derived = match_output_inner_hash(&buyer.inner_hash, CHANGE_ROLE_BUYER).unwrap();

        let expected_e =
            commitment_from_fields_v2(&quote_mint(), 150, &buyer.owner_commitment, &derived)
                .unwrap();
        assert_eq!(w.note_e_commitment, expected_e);
        assert_eq!(w.e_inner, derived);
    }

    #[test]
    fn relocking_buyer_needs_no_anchor() {
        let (mut m, buyer, seller) = scenario(10, 1000, 150, 0, 50, 0);
        m.buyer_relock_order_id = [0xAB; 16];
        assert!(assemble_match(inputs(&m, &buyer, &seller)).is_ok());
    }

    #[test]
    fn settlement_id_binds_session_counter_and_order_ids() {
        let (m, buyer, seller) = scenario(10, 1000, 0, 0, 0, 0);
        let (_, p) = assemble_match(inputs(&m, &buyer, &seller)).unwrap();
        let expected = derive_settlement_id(&[0x5A; 32], 42, &[0x01; 16], &[0x02; 16]);
        assert_eq!(p.match_id, expected);
        assert_eq!(
            expected,
            derive_settlement_id(&[0x5A; 32], 42, &[0x01; 16], &[0x02; 16]),
            "same boot/counter/order tuple is deterministic"
        );
        assert_ne!(
            expected,
            derive_settlement_id(&[0x5B; 32], 42, &[0x01; 16], &[0x02; 16]),
            "a reboot session prevents cross-boot collisions"
        );
        assert_ne!(
            expected,
            derive_settlement_id(&[0x5A; 32], 43, &[0x01; 16], &[0x02; 16]),
            "a new matcher counter prevents page collisions"
        );
        assert_ne!(
            expected,
            derive_settlement_id(&[0x5A; 32], 42, &[0x03; 16], &[0x02; 16]),
            "the matched order pair is bound"
        );
    }

    #[test]
    fn output_safety_is_independent_of_settlement_id_uniqueness() {
        let (m, buyer, seller) = scenario(10, 1000, 150, 0, 50, 0);
        let mut first = inputs(&m, &buyer, &seller);
        first.settlement_id = [0x11; 16];
        let (w1, p1) = assemble_match(first).unwrap();

        let mut second = inputs(&m, &buyer, &seller);
        second.settlement_id = [0x22; 16];
        let (w2, p2) = assemble_match(second).unwrap();

        assert_ne!(p1.match_id, p2.match_id);
        assert_eq!(
            compute_batch_leaf(&w1).unwrap(),
            compute_batch_leaf(&w2).unwrap()
        );
        assert_eq!(w1.c_inner, w2.c_inner);
        assert_eq!(w1.d_inner, w2.d_inner);
        assert_eq!(w1.e_inner, w2.e_inner);
        assert_eq!(w1.f_inner, w2.f_inner);
        assert_eq!(p1.note_c_commitment, p2.note_c_commitment);
        assert_eq!(p1.note_d_commitment, p2.note_d_commitment);
        assert_eq!(p1.note_e_commitment, p2.note_e_commitment);
        assert_eq!(p1.note_f_commitment, p2.note_f_commitment);
    }

    #[test]
    fn assembled_witness_leaf_and_payload_hash_compute() {
        // End-to-end smoke: the witness hashes to a leaf (so it can
        // sit in the batch tree) and the payload produces a canonical
        // hash (so the TEE can sign it). Neither should error.
        let (m, buyer, seller) = scenario(10, 1000, 150, 0, 50, 0);
        let (w, p) = assemble_match(inputs(&m, &buyer, &seller)).unwrap();
        assert!(compute_batch_leaf(&w).is_ok());
        let h = p.canonical_hash();
        assert_ne!(h, [0u8; 32]);
    }

    #[test]
    fn conservation_violation_is_rejected() {
        let (mut m, buyer, seller) = scenario(10, 1000, 0, 0, 0, 0);
        // Bump quote so a_amount (1000) no longer equals quote+0+0.
        m.quote_amt = 1001;
        let err = assemble_match(inputs(&m, &buyer, &seller)).unwrap_err();
        assert!(matches!(err, AssembleError::Conservation(_)));
    }

    #[test]
    fn inconsistent_scaled_floor_price_is_rejected() {
        // Changing base without changing quote/price breaks the governed
        // floor equation (scale=1 in this fixture).
        let (mut m, buyer, seller) = scenario(10, 1000, 0, 0, 0, 0);
        m.base_amt = 7; // 1000 / 7 is not exact
        m.buyer_note_value = 1000;
        // keep b_amount consistent so we hit the price check, not
        // the seller conservation check.
        let mut seller2 = seller.clone();
        seller2.amount = 7;
        let s = seller2.commitment().unwrap();
        m.note_seller = s;
        let err = assemble_match(inputs(&m, &buyer, &seller2)).unwrap_err();
        assert!(matches!(err, AssembleError::Conservation(_)));
    }

    #[test]
    fn wrong_collateral_mint_is_rejected() {
        let (m, mut buyer, seller) = scenario(10, 1000, 0, 0, 0, 0);
        // Buyer opening claims the BASE mint instead of QUOTE.
        buyer.token_mint = base_mint();
        let err = assemble_match(inputs(&m, &buyer, &seller)).unwrap_err();
        assert_eq!(err, AssembleError::BuyerMint);
    }

    // ─── assemble_batch ───────────────────────────────────────────

    use crate::matcher::openings::OrderOpening;
    use crate::settle::lock_note::Groth16ProofBytes;
    use darkpool_crypto::fill_encryption::{decrypt_change_amount, ephemeral_public};

    fn order_rec(opening: NoteOpening, order_id: [u8; 16]) -> OrderOpening {
        OrderOpening {
            opening,
            order_id,
            expiry_slot: 999,
            merkle_root: [0xDD; 32],
            tree_id: 0,
            valid_input_proof: Groth16ProofBytes {
                pi_a: [1u8; 64],
                pi_b: [2u8; 128],
                pi_c: [3u8; 64],
            },
            from_relock: false,
            viewing_pubkey: None,
        }
    }

    fn batch_params() -> BatchAssemblyParams {
        BatchAssemblyParams {
            batch_id: 5,
            boot_session_id: [0x5A; 32],
            base_mint: base_mint(),
            quote_mint: quote_mint(),
            protocol_owner_commitment: fr_safe(0x07),
            fee_rate_bps: 0,
            price_scale: 1,
            circuit_n: 16,
        }
    }

    #[test]
    fn assemble_batch_resolves_openings_and_pads_to_n() {
        let (m, buyer, seller) = scenario(10, 1000, 0, 0, 0, 0);
        let mut store = OpeningStore::new();
        // Keyed by collateral commitment = note_buyer / note_seller.
        store.insert(m.note_buyer, order_rec(buyer, [0x01; 16]));
        store.insert(m.note_seller, order_rec(seller, [0x02; 16]));

        let mut output = RunBatchOutput::empty(7, 100, 0);
        output.matches = vec![m.clone()];

        let bsi = assemble_batch(&output, &store, batch_params()).unwrap();
        assert_eq!(bsi.batch_id, 5);
        assert_eq!(bsi.matches.len(), 1);
        // Witnesses padded to the circuit N.
        assert_eq!(bsi.witnesses.len(), 16);

        let ms = &bsi.matches[0];
        assert_eq!(ms.match_index, 0);
        // Lock inputs resolved from the stored records.
        assert_eq!(ms.buyer_lock.note_commitment, m.note_buyer);
        assert_eq!(ms.buyer_lock.order_id, [0x01; 16]);
        assert_eq!(ms.buyer_lock.token_mint, quote_mint());
        assert_eq!(ms.buyer_lock.expiry_slot, 999);
        assert_eq!(ms.seller_lock.note_commitment, m.note_seller);
        assert_eq!(ms.seller_lock.token_mint, base_mint());
        // Payload carries the resolved order ids.
        assert_eq!(ms.payload.order_id_a, [0x01; 16]);
        assert_eq!(ms.payload.order_id_b, [0x02; 16]);
    }

    #[test]
    fn assemble_batch_derives_per_match_fee_from_consumed_commitments() {
        let recorded = 476_000_000u64;
        let protocol_owner = fr_safe(0x07);
        let (m, buyer, seller) = scenario(1_000, 100_000, 0, 0, 300, 3);
        let mut store = OpeningStore::new();
        store.insert(m.note_buyer, order_rec(buyer, [0x01; 16]));
        store.insert(m.note_seller, order_rec(seller, [0x02; 16]));

        let base_inner = match_fee_inner_hash(&m.note_seller, FEE_ROLE_BASE).unwrap();
        let quote_inner = match_fee_inner_hash(&m.note_buyer, FEE_ROLE_QUOTE).unwrap();
        let base_fee_commitment =
            commitment_from_fields_v2(&base_mint(), 3, &protocol_owner, &base_inner).unwrap();
        let quote_fee_commitment =
            commitment_from_fields_v2(&quote_mint(), 300, &protocol_owner, &quote_inner).unwrap();

        let mut output = RunBatchOutput::empty(recorded, 100, 0);
        output.matches = vec![m];

        let mut params = batch_params();
        params.fee_rate_bps = 30;
        let assembled = assemble_batch(&output, &store, params).unwrap();
        let witness = &assembled.witnesses[0];
        let payload = &assembled.matches[0].payload;

        assert_eq!(witness.fee_base_inner, base_inner);
        assert_eq!(witness.fee_quote_inner, quote_inner);
        assert_eq!(witness.note_fee_base_commitment, base_fee_commitment);
        assert_eq!(witness.note_fee_quote_commitment, quote_fee_commitment);
        assert_eq!(payload.note_fee_base_commitment, base_fee_commitment);
        assert_eq!(payload.note_fee_quote_commitment, quote_fee_commitment);
    }

    #[test]
    fn assemble_batch_encrypts_change_to_the_viewing_key() {
        // A buyer partial fill (change 250) with a viewing key on its opening:
        // assemble_batch must produce a recovery ciphertext the buyer decrypts.
        let buyer_sk = [0x31u8; 32];
        let buyer_pub = ephemeral_public(&buyer_sk);
        let (m, buyer, seller) = scenario(10, 1000, 250, 0, 0, 0);

        let mut buyer_rec = order_rec(buyer, [0x01; 16]);
        buyer_rec.viewing_pubkey = Some(buyer_pub);
        let mut store = OpeningStore::new();
        store.insert(m.note_buyer, buyer_rec);
        store.insert(m.note_seller, order_rec(seller, [0x02; 16])); // no viewing key

        let mut output = RunBatchOutput::empty(7, 100, 0);
        output.matches = vec![m];

        let bsi = assemble_batch(&output, &store, batch_params()).unwrap();
        // The ciphertext rides the signed payload's fill_recovery field.
        let ct = crate::settle::fill_recovery::FillCiphertext::from_payload_bytes(
            &bsi.matches[0].payload.fill_recovery,
        );
        assert!(
            !ct.is_empty(),
            "buyer change + viewing key → ciphertext present"
        );
        assert_eq!(
            decrypt_change_amount(&buyer_sk, &ct.ephemeral_pubkey, &ct.buyer_enc),
            Some(250),
            "buyer recovers its change_amount from the on-chain-bound ciphertext"
        );
        // Seller had no viewing key → its blob stays zeroed.
        assert_eq!(ct.seller_enc, [0u8; 36]);
    }

    #[test]
    fn assemble_batch_no_viewing_key_means_empty_ciphertext() {
        // Default openings (viewing_pubkey: None) → no recovery ciphertext.
        let (m, buyer, seller) = scenario(10, 1000, 250, 0, 0, 0);
        let mut store = OpeningStore::new();
        store.insert(m.note_buyer, order_rec(buyer, [0x01; 16]));
        store.insert(m.note_seller, order_rec(seller, [0x02; 16]));
        let mut output = RunBatchOutput::empty(7, 100, 0);
        output.matches = vec![m];

        let bsi = assemble_batch(&output, &store, batch_params()).unwrap();
        assert!(
            crate::settle::fill_recovery::FillCiphertext::from_payload_bytes(
                &bsi.matches[0].payload.fill_recovery
            )
            .is_empty()
        );
    }

    #[test]
    fn assemble_batch_missing_opening_errors() {
        let (m, _buyer, seller) = scenario(10, 1000, 0, 0, 0, 0);
        let mut store = OpeningStore::new();
        // Only the seller's opening is present.
        store.insert(m.note_seller, order_rec(seller, [0x02; 16]));
        let mut output = RunBatchOutput::empty(7, 100, 0);
        output.matches = vec![m];

        let res = assemble_batch(&output, &store, batch_params());
        assert!(matches!(
            res,
            Err(AssembleError::MissingOpening { side: "buyer", .. })
        ));
    }

    #[test]
    fn assemble_batch_rejects_oversize_batch() {
        // circuit_n = 1 but two matches → too large.
        let (m, buyer, seller) = scenario(10, 1000, 0, 0, 0, 0);
        let mut store = OpeningStore::new();
        store.insert(m.note_buyer, order_rec(buyer, [0x01; 16]));
        store.insert(m.note_seller, order_rec(seller, [0x02; 16]));
        let mut output = RunBatchOutput::empty(7, 100, 0);
        output.matches = vec![m.clone(), m];
        let mut params = batch_params();
        params.circuit_n = 1;
        let res = assemble_batch(&output, &store, params);
        assert!(matches!(
            res,
            Err(AssembleError::BatchTooLarge { got: 2, n: 1 })
        ));
    }
}
