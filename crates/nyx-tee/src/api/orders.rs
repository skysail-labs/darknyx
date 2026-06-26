//! Layer B — per-order cryptographic auth.
//!
//! Handlers:
//!
//!   - `POST /orders` — accepts a `PlaceOrderRequest`, verifies the
//!     trading-key Ed25519 signature over the canonical body bytes
//!     from PR 4e.1, and inserts the resulting `Order` into the
//!     matcher's in-memory book.
//!   - `DELETE /orders/{order_id}` — accepts a `CancelOrderRequest`
//!     body, verifies a fresh signature from the SAME trading_key
//!     that owns the order, removes it from the book.
//!   - `GET /orders/{order_id}` — read-only status lookup.
//!
//! Auth model: the bearer middleware (PR 4e.2) gates these routes
//! at the account level; this module adds the per-order signature
//! check that the on-chain settlement relies on. The `account_id`
//! from the bearer is NOT required to match the order's
//! `trading_key` — one account may operate many trading keys
//! (different sub-portfolios, market-maker fleets). This is the
//! same separation-of-concerns godarkdex documented. The
//! `trading_key` IS the cryptographic identity; the JWT only
//! enables rate-limiting + audit.
//!
//! See `docs/tee-architecture.md` §11 for the full design.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use darkpool_matcher::book::{Order, OrderSide, OrderStatus, OrderType};
use darkpool_matcher::order_canonical::{
    anchor_pool_hash, Anchor, AnchorTopUpCanonical, CancelCanonical, CanonicalError,
    OrderCanonical, ANCHOR_POOL_SIZE, ANCHOR_TOPUP_SIZE, SYMBOL_MAX_LEN,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::auth::Authorized;
use super::error::ApiError;
use super::state::{ApiState, OrderUpdateMsg};
use crate::matcher::book::BookError;

// ─────────────────────────────────────────────────────────────────────────────
// Wire shapes — pinned by docs/tee-api-openapi.yaml.
// All byte-vector fields are hex-encoded strings; all integer fields
// (including u64s) are JSON numbers — caller bigints must fit in
// 2^53 - 1 which covers every market value we expect to see.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PlaceOrderRequest {
    pub symbol: String,
    pub side: SideTag,
    pub order_type: OrderTypeTag,
    pub amount: u64,
    pub price_limit: u64,
    #[serde(default)]
    pub min_fill_size: u64,
    pub expiry_slot: u64,
    /// 16-byte client UUID, hex.
    pub order_id: String,
    /// 32-byte Poseidon6 commitment of the collateral note, hex.
    pub note_commitment: String,
    /// 32-byte Poseidon2(spending_key, r_owner), hex. Top byte must
    /// be zero (BN254 Fr safety — the matcher Poseidon-hashes this
    /// during change-note construction).
    pub user_commitment: String,
    pub arrival_nonce: u64,
    /// 32-byte Ed25519 pubkey of the submitter, hex.
    pub trading_key: String,
    /// 64-byte Ed25519 signature over
    /// `sha256(order_canonical_bytes)`, hex.
    pub trading_key_signature: String,

    // ─── Input-note opening (4g.7a) ──────────────────────────────
    // The TEE prover opens this note inside VALID_MATCH_BATCH, so it
    // needs the secret opening fields the `note_commitment` hides.
    // They're verified at intake against the signed commitment (so
    // they're cryptographically pinned without expanding the signed
    // canonical body) and held in enclave memory only. See
    // `crate::matcher::openings`.
    /// 32-byte note owner commitment `Poseidon3(1, spending_key,
    /// r_owner)`, hex. NOT the same as `user_commitment`.
    pub owner_commitment: String,
    /// 32-byte v2 note `inner_hash`, hex (replaces the old note_nonce +
    /// note_blinding pair). Anchors both the commitment and the nullifier.
    pub note_inner_hash: String,
    /// 32-byte nullifier `Poseidon3(3, spending_key, inner_hash)`,
    /// hex. Precomputed by the client (needs the spending key, which
    /// never enters the TEE); opaque to the matcher.
    pub nullifier: String,

    // ─── VALID_INPUT proof relay (4g.7c) ─────────────────────────
    // `lock_note` (settle Tx A) requires a per-note VALID_INPUT
    // Groth16 proof. The TEE cannot generate it (it needs the user's
    // spending key + merkle witness), so the client generates it and
    // relays it here. The matcher does NOT verify it (on-chain
    // `lock_note` does, against the vault's 64-root ring buffer); it
    // holds it in enclave memory until settle.
    /// 32-byte merkle root the VALID_INPUT proof was generated
    /// against, hex. Must still be in the vault's root history at
    /// lock time (64-root window).
    pub merkle_root: String,
    /// 256-byte VALID_INPUT Groth16 proof (`pi_a ‖ pi_b ‖ pi_c`), hex.
    pub valid_input_proof: String,

    /// OPTIONAL over-collateralization: the actual amount the collateral note
    /// carries, when it exceeds the order's nominal locked amount
    /// (`amount*price_limit + fee` for a bid, `amount + fee` for an ask). Lets a
    /// user point a large note (e.g. a 500-USDC deposit) at a small order and
    /// get the surplus back as a change note. A plaintext opening field — it is
    /// NOT in the signed canonical body, because the signed `note_commitment`
    /// already commits the amount; intake re-derives the commitment from this
    /// value and rejects a mismatch (same mechanism as `owner_commitment` /
    /// `note_inner_hash`). Absent ⇒ exact collateral (`note == nominal + fee`),
    /// unchanged behaviour.
    #[serde(default)]
    pub collateral_amount: Option<u64>,

    /// Which Merkle-tree shard the collateral note lives in (the shard it was
    /// deposited/merged into). Selects the `merkle_tree[tree_id]` account the
    /// settle's `lock_note` checks the proof's `merkle_root` recency against, so
    /// a batch's input notes can span shards. NOT in the signed canonical body —
    /// the proof's `merkle_root` + the shard's recent-roots ring already bind the
    /// note; a wrong `tree_id` only self-harms (lock fails). `#[serde(default)]`
    /// ⇒ shard 0, back-compatible with pre-sharding clients.
    #[serde(default)]
    pub tree_id: u8,

    /// OPTIONAL 32-byte X25519 viewing-encryption public key, hex
    /// (`deriveViewingEncKeypair().publicKey`). When present, the settle
    /// assembler encrypts each of this order's change_amounts to it and writes
    /// the ciphertext on-chain, so the change note stays recoverable after a CVM
    /// redeploy wipes the live fill memo (change-amount recovery, Proposal B).
    /// NOT in the signed canonical body — it pins nothing the signature must
    /// cover; a wrong key only makes the owner's OWN change unrecoverable
    /// (self-harm), and the ciphertext is self-verifying client-side. Absent ⇒
    /// no on-chain ciphertext (back-compatible). Any 32 bytes are accepted (an
    /// X25519 point, not a Poseidon input — no Fr check).
    #[serde(default)]
    pub viewing_pubkey: Option<String>,

    /// The order's continuation anchor pool — exactly
    /// `ANCHOR_POOL_SIZE` `(inner_hash, nullifier)` pairs the client
    /// pre-supplied so the matcher can settle partial-fill
    /// continuations without a per-fill roundtrip. The SHA-256 over
    /// these (`anchor_pool_hash`) is bound into the signed canonical
    /// body, so the matcher checks the pool against the signature.
    pub anchors: Vec<AnchorJson>,
}

/// One `(inner_hash, nullifier)` continuation anchor, hex-encoded.
#[derive(Debug, Deserialize)]
pub struct AnchorJson {
    pub inner_hash: String,
    pub nullifier: String,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SideTag {
    Bid,
    Ask,
}

impl From<SideTag> for OrderSide {
    fn from(s: SideTag) -> Self {
        match s {
            SideTag::Bid => OrderSide::Bid,
            SideTag::Ask => OrderSide::Ask,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OrderTypeTag {
    Limit,
    Ioc,
    Fok,
}

impl From<OrderTypeTag> for OrderType {
    fn from(t: OrderTypeTag) -> Self {
        match t {
            OrderTypeTag::Limit => OrderType::Limit,
            OrderTypeTag::Ioc => OrderType::Ioc,
            OrderTypeTag::Fok => OrderType::Fok,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct PlaceOrderResponse {
    pub order_id: String,
    pub status: &'static str,
    pub arrival_slot: u64,
}

#[derive(Debug, Deserialize)]
pub struct CancelOrderRequest {
    /// 32-byte Ed25519 pubkey (must match the original order's
    /// trading_key), hex.
    pub trading_key: String,
    pub cancel_nonce: u64,
    /// 64-byte Ed25519 signature over
    /// `sha256(cancel_canonical_bytes)`, hex.
    pub trading_key_signature: String,
}

#[derive(Debug, Serialize)]
pub struct CancelOrderResponse {
    pub order_id: String,
    pub status: &'static str,
}

#[derive(Debug, Serialize)]
pub struct OrderStatusResponse {
    pub order_id: String,
    pub side: &'static str,
    pub order_type: &'static str,
    pub status: &'static str,
    pub amount: u64,
    pub filled_quantity: u64,
    pub price_limit: u64,
    pub expiry_slot: u64,
    pub arrival_slot: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn decode_hex<const N: usize>(s: &str, label: &str) -> Result<[u8; N], (StatusCode, String)> {
    let bytes = hex::decode(s).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("{label} is not valid hex: {e}"),
        )
    })?;
    bytes.as_slice().try_into().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            format!("{label} must be {N} bytes; got {}", bytes.len()),
        )
    })
}

fn verify_sig(
    digest: &[u8; 32],
    trading_key: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), ApiError> {
    let vk = VerifyingKey::from_bytes(trading_key).map_err(|e| {
        ApiError::sig_invalid(format!("trading_key is not a valid Ed25519 pubkey: {e}"))
    })?;
    let sig = Signature::from_bytes(signature);
    vk.verify_strict(digest, &sig).map_err(|_| {
        ApiError::sig_invalid("trading_key_signature does not verify against the canonical body")
    })
}

fn matcher_or_503(
    state: &ApiState,
) -> Result<&Arc<tokio::sync::RwLock<crate::matcher::MatcherState>>, (StatusCode, String)> {
    state.matcher.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "matcher state not initialised on this instance".to_string(),
    ))
}

/// Compute the order's inclusion commitment exactly as the matcher
/// will expect: `SHA-256(arrival_slot_le || collateral_note ||
/// trading_key)`. Frozen at submit time; never rotates across
/// partial-fills.
fn order_inclusion_commitment(
    arrival_slot: u64,
    collateral_note: &[u8; 32],
    trading_key: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(arrival_slot.to_le_bytes());
    h.update(collateral_note);
    h.update(trading_key);
    h.finalize().into()
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /orders
// ─────────────────────────────────────────────────────────────────────────────

/// Everything an order needs to be committed to the book, after all
/// (lock-free) verification has passed. Built by [`prepare_order`]; consumed by
/// [`commit_order`] under the matcher write lock.
struct PreparedOrder {
    order: Order,
    note_commitment: [u8; 32],
    opening: crate::matcher::openings::NoteOpening,
    order_id: [u8; 16],
    lock_merkle_root: [u8; 32],
    /// Merkle-tree shard the collateral note lives in (selects the lock_note
    /// `merkle_tree` account). From `PlaceOrderRequest::tree_id`.
    tree_id: u8,
    /// The owner's X25519 viewing-encryption pubkey, if supplied — recipient for
    /// the on-chain change_amount ciphertext (Proposal B). Stored on the opening.
    viewing_pubkey: Option<[u8; 32]>,
    valid_input_proof: crate::settle::lock_note::Groth16ProofBytes,
    anchors: Vec<Anchor>,
    arrival_slot: u64,
    /// SHA-256 of the signed canonical body. Identifies "the same order" for
    /// idempotent-retry detection on a duplicate `order_id` (see `place_core`).
    canonical_digest: [u8; 32],
}

/// Verify + build an order WITHOUT touching the book (decode, Fr-checks,
/// canonical-signature verify, collateral/fee derivation, opening verify, Order
/// construction). Lock-free so the Poseidon work doesn't block a matcher tick;
/// the caller commits the result under the write lock. Shared by `place_order`
/// and `modify_order`.
async fn prepare_order(
    state: &ApiState,
    matcher: &Arc<tokio::sync::RwLock<crate::matcher::MatcherState>>,
    req: &PlaceOrderRequest,
) -> Result<PreparedOrder, ApiError> {
    // 1. Decode hex inputs.
    let order_id: [u8; 16] = decode_hex(&req.order_id, "order_id")?;
    let note_commitment: [u8; 32] = decode_hex(&req.note_commitment, "note_commitment")?;
    let user_commitment: [u8; 32] = decode_hex(&req.user_commitment, "user_commitment")?;
    let trading_key: [u8; 32] = decode_hex(&req.trading_key, "trading_key")?;
    let signature: [u8; 64] = decode_hex(&req.trading_key_signature, "trading_key_signature")?;
    let owner_commitment: [u8; 32] = decode_hex(&req.owner_commitment, "owner_commitment")?;
    let note_inner_hash: [u8; 32] = decode_hex(&req.note_inner_hash, "note_inner_hash")?;
    let nullifier: [u8; 32] = decode_hex(&req.nullifier, "nullifier")?;
    // Optional X25519 viewing-encryption pubkey (Proposal B). Length-checked
    // only — it's an X25519 point, not a Poseidon input, so no Fr safety check.
    let viewing_pubkey: Option<[u8; 32]> = match req.viewing_pubkey.as_deref() {
        Some(h) => Some(decode_hex(h, "viewing_pubkey")?),
        None => None,
    };

    // Anchor pool: exactly ANCHOR_POOL_SIZE (inner_hash, nullifier) pairs.
    // Each inner_hash is Poseidon-hashed into a future change-note
    // commitment, so it MUST be a canonical BN254 Fr (fail fast here, like
    // the order's own note_inner_hash). The nullifier is opaque to the TEE
    // (it can't verify it without the spending key) — only length-checked.
    if req.anchors.len() != ANCHOR_POOL_SIZE {
        return Err(ApiError::malformed(format!(
            "anchors: expected exactly {ANCHOR_POOL_SIZE} continuation anchors, got {}",
            req.anchors.len()
        )));
    }
    let mut anchors: Vec<Anchor> = Vec::with_capacity(ANCHOR_POOL_SIZE);
    for (i, a) in req.anchors.iter().enumerate() {
        let inner_hash: [u8; 32] = decode_hex(&a.inner_hash, "anchor.inner_hash")?;
        let null: [u8; 32] = decode_hex(&a.nullifier, "anchor.nullifier")?;
        darkpool_crypto::fr_from_be_bytes(&inner_hash).map_err(|_| {
            ApiError::fr_unsafe(format!(
                "anchors[{i}].inner_hash is not a canonical BN254 field element"
            ))
        })?;
        anchors.push(Anchor {
            inner_hash,
            nullifier: null,
        });
    }
    let pool_hash = anchor_pool_hash(&anchors);
    let lock_merkle_root: [u8; 32] = decode_hex(&req.merkle_root, "merkle_root")?;
    let valid_input_proof_bytes: [u8; 256] =
        decode_hex(&req.valid_input_proof, "valid_input_proof")?;
    let valid_input_proof =
        crate::settle::lock_note::Groth16ProofBytes::from_concat(&valid_input_proof_bytes);

    // 2. Field-level validation. Cheap; runs before the expensive
    //    Ed25519 verify.
    if order_id == [0u8; 16] {
        return Err(ApiError::malformed(
            "order_id must not be all-zero (sentinel reserved for matcher RELOCK_ORDER_ID_NONE)",
        ));
    }
    if req.symbol.len() > SYMBOL_MAX_LEN {
        return Err(ApiError::malformed(format!(
            "symbol length {} exceeds SYMBOL_MAX_LEN ({SYMBOL_MAX_LEN})",
            req.symbol.len()
        )));
    }
    if user_commitment[0] != 0 {
        // BN254 Fr-safety. Matcher Poseidon-hashes this during
        // change-note construction; non-zero top byte means
        // light-poseidon's `hash_bytes_be` will fail at tick time.
        // Reject early at intake.
        return Err(ApiError::fr_unsafe(
            "user_commitment top byte must be zero (BN254 Fr safety)",
        ));
    }
    // Minimum order size (dust floor). The market's `min_order_size` is static
    // instrument metadata; reject a sub-minimum order here, before the expensive
    // Ed25519 verify. An unlisted symbol has no floor (min 0) — the canonical
    // verify below still binds the symbol, and the matcher rejects unknown
    // markets downstream.
    let min_order_size = state
        .instruments
        .iter()
        .find(|i| i.symbol == req.symbol)
        .map_or(0, |i| i.min_order_size);
    if req.amount < min_order_size {
        return Err(ApiError::min_notional(format!(
            "amount {} is below the market minimum {min_order_size}",
            req.amount
        )));
    }

    // 3. Reconstruct the canonical bytes and verify the trading-key
    //    signature. CanonicalError can't fire here — we already
    //    bounded symbol length above. Map it through anyway so any
    //    future invariant change doesn't silently miscompile.
    let side: OrderSide = req.side.into();
    let order_type: OrderType = req.order_type.into();
    let canonical = OrderCanonical {
        symbol: req.symbol.as_bytes(),
        side,
        order_type,
        amount: req.amount,
        price_limit: req.price_limit,
        min_fill_size: req.min_fill_size,
        expiry_slot: req.expiry_slot,
        order_id,
        note_commitment,
        user_commitment,
        arrival_nonce: req.arrival_nonce,
        anchor_pool_hash: pool_hash,
    };
    let digest = canonical
        .digest()
        .map_err(|e: CanonicalError| (StatusCode::BAD_REQUEST, format!("canonical encode: {e}")))?;
    verify_sig(&digest, &trading_key, &signature)?;

    // 4. Construct the on-book Order. `note_amount` equals the full
    //    value the collateral note carries, which for a bid is
    //    amount * price_limit (quote units) and for an ask is
    //    `amount` (base units). The .max guards collapse the
    //    pathological "zero" case the matcher never sees in
    //    practice.
    let arrival_slot = state.current_slot.load(Ordering::Relaxed);
    // A bid's collateral is `amount * price_limit` (quote units). A
    // zero price_limit is economically meaningless (buy at price 0)
    // and would collapse to the base-unit `amount` fallback below —
    // a silent unit confusion. Reject it. (An ask may legitimately
    // use price_limit == 0 as a market sell, so this is bid-only.)
    if matches!(side, OrderSide::Bid) && req.price_limit == 0 {
        return Err(ApiError::zero_price_bid(
            "price_limit must be > 0 for a bid",
        ));
    }
    // Collateral mints + the protocol fee rate, read together under one
    // lock. (Done before deriving note_amount so the fee can be folded
    // into the required collateral.)
    let (base_mint, quote_mint, fee_rate_bps) = {
        let st = matcher.read().await;
        let (b, q) = st.market_mints();
        (b, q, st.fee_rate_bps())
    };

    // Nominal collateral: a bid locks `amount * price_limit` quote, an
    // ask locks `amount` base. Reject a bid whose `amount * price_limit`
    // overflows u64 (mirrors the price_limit == 0 reject above) rather
    // than saturating to a nonsense collateral the deposit can never
    // match. price_limit > 0 is already enforced for bids, so the
    // product is >= amount — no `.max` fallback needed.
    let nominal = match side {
        OrderSide::Bid => req
            .amount
            .checked_mul(req.price_limit)
            .ok_or_else(|| ApiError::malformed("amount * price_limit overflows u64"))?,
        OrderSide::Ask => req.amount,
    };
    // ...PLUS the order's own protocol fee. The matcher charges each leg
    // `charge = trade + fee` (additive); so an order must lock enough to
    // pay its OWN fee, else run_batch rejects the match as
    // conservation-breaking. We over-collateralize on the NOMINAL/limit
    // amount (the worst case — the matcher charges the fee on the lower
    // clearing-based amount and returns the surplus as a change note).
    // Floor division matches the matcher's fee math + the client's
    // deposit, so the re-derived commitment lines up exactly. fee=0 when
    // fee_rate_bps=0 → collateral == nominal (unchanged dev behaviour).
    let fee = ((nominal as u128) * (fee_rate_bps as u128) / 10_000u128) as u64;
    // The minimum the collateral note must carry so the order can pay its own
    // worst-case fee. With exact collateral this IS the note amount; with
    // over-collateralization it's the floor.
    let required = nominal.saturating_add(fee).max(1);

    // Over-collateralization: if the client declares a `collateral_amount`, the
    // note may be LARGER than `required` and the matcher returns the surplus as
    // a change note (the same path price-improvement surplus already takes —
    // `algorithm.rs` computes `change = note_amount - charge`). The declared
    // amount must still be >= the floor (so the fee is covered), and it is
    // pinned to the signed `note_commitment` by `verify_commitment` below.
    let note_amount = match req.collateral_amount {
        Some(c) if c >= required => c,
        Some(c) => {
            return Err(ApiError::below_collateral(format!(
                "collateral_amount {c} is below the required {required} \
                 (nominal {nominal} + fee {fee}) for this order"
            )));
        }
        None => required,
    };

    // 4b. Build + verify the input-note opening. The collateral mint
    //     is the quote mint for a bid (quote locked) and the base
    //     mint for an ask. `verify_commitment` re-derives the note
    //     commitment from (mint, note_amount, owner_commitment,
    //     inner_hash) and asserts it equals the signed `note_commitment`
    //     — pinning the opening (incl. the possibly over-collateralized
    //     `note_amount`) to the signature. Done outside the matcher lock
    //     so the Poseidon work doesn't block a tick.
    let token_mint = match side {
        OrderSide::Bid => quote_mint,
        OrderSide::Ask => base_mint,
    };
    let opening = crate::matcher::openings::NoteOpening {
        token_mint,
        amount: note_amount,
        owner_commitment,
        inner_hash: note_inner_hash,
        nullifier,
    };
    opening.verify_commitment(&note_commitment).map_err(|e| {
        ApiError::bad_opening(format!("note opening does not match note_commitment: {e}"))
    })?;

    let order = Order {
        trading_key,
        side,
        order_type,
        status: OrderStatus::Pending,
        arrival_slot,
        expiry_slot: req.expiry_slot,
        price_limit: req.price_limit,
        amount: req.amount,
        total_quantity: req.amount,
        filled_quantity: 0,
        min_fill_qty: req.min_fill_size,
        note_amount,
        collateral_note: note_commitment,
        user_commitment,
        // The owner_commitment was just pinned to `note_commitment` by
        // `verify_commitment` above, so the matcher's self-trade check keys on a
        // value the caller cannot spoof for a note they don't own.
        owner_commitment,
        order_id,
        order_inclusion_commitment: order_inclusion_commitment(
            arrival_slot,
            &note_commitment,
            &trading_key,
        ),
    };

    Ok(PreparedOrder {
        order,
        note_commitment,
        opening,
        order_id,
        lock_merkle_root,
        tree_id: req.tree_id,
        viewing_pubkey,
        valid_input_proof,
        anchors,
        arrival_slot,
        canonical_digest: digest,
    })
}

/// Commit a prepared order to the book under the matcher write lock: submit it,
/// store the opening (keyed by note commitment so the settle assembler resolves
/// both sides of a match), and stash the continuation anchor pool. Both
/// mutations happen under the same lock the caller holds, so an observer never
/// sees a booked order without its opening.
fn commit_order(
    st: &mut crate::matcher::MatcherState,
    p: PreparedOrder,
    expiry_slot: u64,
) -> Result<(), ApiError> {
    st.book_mut().submit(p.order).map_err(|e| match e {
        BookError::Duplicate(_, _) => ApiError::duplicate(e.to_string()),
        BookError::ZeroOrderId => ApiError::malformed(e.to_string()),
        e => ApiError::internal(e.to_string()),
    })?;
    st.openings_mut().insert(
        p.note_commitment,
        crate::matcher::openings::OrderOpening {
            opening: p.opening,
            order_id: p.order_id,
            expiry_slot,
            merkle_root: p.lock_merkle_root,
            tree_id: p.tree_id,
            valid_input_proof: p.valid_input_proof,
            // A fresh deposit: lock_note must run for it (no prior re-lock).
            from_relock: false,
            viewing_pubkey: p.viewing_pubkey,
        },
    );
    st.openings_mut().insert_anchor_pool(
        p.order_id,
        crate::matcher::openings::AnchorPool::new(p.anchors),
    );
    Ok(())
}

/// Remove an order + its opening + anchor pool from the book under the matcher
/// write lock (the lock-held half of `cancel_order`, reused by `modify_order`).
fn cancel_in_book(
    st: &mut crate::matcher::MatcherState,
    trading_key: [u8; 32],
    order_id: [u8; 16],
) -> Result<(), ApiError> {
    // Resolve the collateral note BEFORE cancelling (the store is keyed by note
    // commitment, not order_id).
    let collateral_note = st.book().get(&order_id).map(|o| o.collateral_note);
    st.book_mut()
        .cancel(trading_key, order_id)
        .map_err(|e| match e {
            BookError::NotFound(_) => ApiError::not_found(e.to_string()),
            BookError::NotOwner(_, _) => ApiError::not_owner(e.to_string()),
            e => ApiError::internal(e.to_string()),
        })?;
    if let Some(note) = collateral_note {
        st.openings_mut().remove(&note);
    }
    st.openings_mut().remove_anchor_pool(&order_id);
    Ok(())
}

/// Place an order: verify + build (lock-free) then commit it under the matcher
/// write lock + record its owner for per-account routing. The transport-agnostic
/// core shared by `POST /orders` (`place_order`) and the `/ws/trading`
/// `order.place` frame — both already hold the authenticated `account_id`.
pub async fn place_core(
    state: &ApiState,
    matcher: &Arc<tokio::sync::RwLock<crate::matcher::MatcherState>>,
    req: &PlaceOrderRequest,
    account_id: &str,
) -> Result<PlaceOrderResponse, ApiError> {
    let prepared = prepare_order(state, matcher, req).await?;
    let order_id = prepared.order_id;
    let arrival_slot = prepared.arrival_slot;
    let digest = prepared.canonical_digest;
    let order_id_hex = hex::encode(order_id);

    // Idempotency: if this order_id was accepted before, a retry of the SAME
    // signed body returns the original acceptance (not a 409); a DIFFERENT body
    // reusing the id is a real conflict. Checked before the write lock; the rare
    // concurrent-double-submit race still resolves to one acceptance + one 409
    // (the book's `submit` is the hard dedup).
    if let Some((prev_digest, prev_slot)) = state.idempotency_lookup(&order_id_hex).await {
        if prev_digest == digest {
            return Ok(PlaceOrderResponse {
                order_id: order_id_hex,
                status: "accepted",
                arrival_slot: prev_slot,
            });
        }
        return Err(ApiError::duplicate(
            "order_id already used with a different order",
        ));
    }

    {
        let mut st = matcher.write().await;
        commit_order(&mut st, prepared, req.expiry_slot)?;
    }

    // Record the acceptance for idempotent retries, then the order→account
    // mapping for per-account routing. After dropping the matcher lock so we
    // never hold it across the other map locks.
    state
        .idempotency_record(order_id_hex.clone(), digest, arrival_slot)
        .await;
    state
        .record_order_owner(order_id_hex.clone(), account_id.to_string())
        .await;

    Ok(PlaceOrderResponse {
        order_id: order_id_hex,
        status: "accepted",
        arrival_slot,
    })
}

pub async fn place_order(
    State(state): State<Arc<ApiState>>,
    Extension(auth): Extension<Authorized>,
    Json(req): Json<PlaceOrderRequest>,
) -> Result<(StatusCode, Json<PlaceOrderResponse>), ApiError> {
    let matcher = matcher_or_503(&state)?;
    let resp = place_core(&state, matcher, &req, &auth.account_id).await?;
    Ok((StatusCode::ACCEPTED, Json(resp)))
}

// ─────────────────────────────────────────────────────────────────────────────
// DELETE /orders/{order_id}
// ─────────────────────────────────────────────────────────────────────────────

/// Route a synthetic `Cancelled` onto `/ws/orders` then drop the order's
/// routing entry. Explicit/server cancels bypass the matcher tick (so they
/// never reach the `order_updates` broadcast); this mirrors them so
/// `/ws/orders` subscribers still see the order leave, and bounds the
/// `order_owner` map. Shared by every cancel path.
async fn announce_cancel(state: &ApiState, order_id_hex: &str) {
    state
        .route_order_update(
            order_id_hex,
            &OrderUpdateMsg {
                order_id: order_id_hex.to_string(),
                kind: "cancelled",
                filled_quantity: None,
                new_amount: None,
                new_note_amount: None,
            },
        )
        .await;
    state.forget_order(order_id_hex).await;
}

/// Cancel an order after verifying a fresh trading-key signature over its id.
/// The transport-agnostic core shared by `DELETE /orders/{id}` (`cancel_order`)
/// and the `/ws/trading` `order.cancel` frame.
pub async fn cancel_core(
    state: &ApiState,
    matcher: &Arc<tokio::sync::RwLock<crate::matcher::MatcherState>>,
    order_id_hex: &str,
    req: &CancelOrderRequest,
) -> Result<CancelOrderResponse, ApiError> {
    let order_id: [u8; 16] = decode_hex(order_id_hex, "order_id (path)")?;
    let trading_key: [u8; 32] = decode_hex(&req.trading_key, "trading_key")?;
    let signature: [u8; 64] = decode_hex(&req.trading_key_signature, "trading_key_signature")?;

    let cancel = CancelCanonical {
        order_id,
        trading_key,
        cancel_nonce: req.cancel_nonce,
    };
    verify_sig(&cancel.digest(), &trading_key, &signature)?;

    {
        let mut st = matcher.write().await;
        cancel_in_book(&mut st, trading_key, order_id)?;
    }
    announce_cancel(state, order_id_hex).await;

    Ok(CancelOrderResponse {
        order_id: hex::encode(order_id),
        status: "cancelled",
    })
}

/// Server-initiated cancel of a still-resting order — the cancel-on-disconnect
/// path. Cancels using the order's OWN booked `trading_key` (no client
/// signature): the order was placed on an authenticated `/ws/trading` session,
/// so the session's authority covers tearing it down when the socket closes.
/// A no-op (returns `false`) if the order already left the book
/// (filled/expired/already cancelled). Cancelling only removes a resting order
/// — it never moves funds or settles — so requiring no fresh signature is safe.
pub async fn cancel_resting_unchecked(
    state: &ApiState,
    matcher: &Arc<tokio::sync::RwLock<crate::matcher::MatcherState>>,
    order_id_hex: &str,
) -> bool {
    let Ok(order_id) = decode_hex::<16>(order_id_hex, "order_id") else {
        return false;
    };
    {
        let mut st = matcher.write().await;
        let Some(trading_key) = st.book().get(&order_id).map(|o| o.trading_key) else {
            return false; // already gone
        };
        if cancel_in_book(&mut st, trading_key, order_id).is_err() {
            return false;
        }
    }
    announce_cancel(state, order_id_hex).await;
    true
}

pub async fn cancel_order(
    State(state): State<Arc<ApiState>>,
    Extension(_auth): Extension<Authorized>,
    Path(order_id_hex): Path<String>,
    Json(req): Json<CancelOrderRequest>,
) -> Result<Json<CancelOrderResponse>, ApiError> {
    let matcher = matcher_or_503(&state)?;
    let resp = cancel_core(&state, matcher, &order_id_hex, &req).await?;
    Ok(Json(resp))
}

// ─────────────────────────────────────────────────────────────────────────────
// PUT /orders/{order_id}  — atomic cancel + replace (modify)
// ─────────────────────────────────────────────────────────────────────────────

/// Body for `PUT /orders/{order_id}`. A modify is "the same owner replaces their
/// resting order with a new one." It carries a signed cancel of the OLD order
/// (over its id) plus a full new order (`replacement`, a normal signed
/// `PlaceOrderRequest`). The trading key that signs the cancel MUST be the one
/// that signs the replacement — the swap happens atomically under one matcher
/// lock, so there is no window where the caller has neither order.
#[derive(Debug, Deserialize)]
pub struct ModifyOrderRequest {
    /// 64-byte Ed25519 signature over `CancelCanonical{old_order_id, trading_key,
    /// cancel_nonce}`, hex — proves ownership of the OLD order.
    pub cancel_signature: String,
    pub cancel_nonce: u64,
    /// The replacement order — a full, independently-signed `PlaceOrderRequest`
    /// (its own note + `VALID_INPUT` proof; may reuse the old order's note while
    /// the root is still in the 64-root window).
    pub replacement: PlaceOrderRequest,
}

#[derive(Debug, Serialize)]
pub struct ModifyOrderResponse {
    /// The cancelled order's id (hex).
    pub old_order_id: String,
    /// The new order's id (hex; may equal `old_order_id` on a reprice-in-place).
    pub order_id: String,
    pub status: &'static str,
    pub arrival_slot: u64,
}

/// Atomic cancel + replace. The transport-agnostic core shared by
/// `PUT /orders/{id}` (`modify_order`) and the `/ws/trading` `order.modify`
/// frame.
pub async fn modify_core(
    state: &ApiState,
    matcher: &Arc<tokio::sync::RwLock<crate::matcher::MatcherState>>,
    old_order_id_hex: &str,
    req: &ModifyOrderRequest,
    account_id: &str,
) -> Result<ModifyOrderResponse, ApiError> {
    let old_order_id: [u8; 16] = decode_hex(old_order_id_hex, "order_id (path)")?;
    // The cancel is authorized by the SAME trading_key that signs the
    // replacement. Verify the cancel sig over the OLD id with that key.
    let trading_key: [u8; 32] =
        decode_hex(&req.replacement.trading_key, "replacement.trading_key")?;
    let cancel_signature: [u8; 64] = decode_hex(&req.cancel_signature, "cancel_signature")?;
    let cancel = CancelCanonical {
        order_id: old_order_id,
        trading_key,
        cancel_nonce: req.cancel_nonce,
    };
    verify_sig(&cancel.digest(), &trading_key, &cancel_signature)?;

    // Verify + build the replacement (its own canonical sig, collateral, opening)
    // OUTSIDE the lock — the Poseidon/Ed25519 work doesn't block a tick.
    let prepared = prepare_order(state, matcher, &req.replacement).await?;
    let new_order_id = prepared.order_id;
    let arrival_slot = prepared.arrival_slot;

    // Atomic swap under ONE write lock. Check BOTH preconditions before mutating
    // so neither side partially applies (no "user has neither order" window):
    //   - the old order exists and is owned by this trading_key, and
    //   - the new order_id isn't already booked (unless it's the same id — a
    //     reprice in place, where cancelling the old frees the id first).
    {
        let mut st = matcher.write().await;
        match st.book().get(&old_order_id) {
            None => {
                return Err(ApiError::not_found(format!(
                    "order {old_order_id_hex} not found"
                )))
            }
            Some(o) if o.trading_key != trading_key => {
                return Err(ApiError::not_owner("not the order owner"))
            }
            Some(_) => {}
        }
        if new_order_id != old_order_id && st.book().get(&new_order_id).is_some() {
            return Err(ApiError::id_in_use(format!(
                "replacement order_id {} already exists",
                hex::encode(new_order_id)
            )));
        }
        // Preconditions hold → both mutations succeed.
        cancel_in_book(&mut st, trading_key, old_order_id)?;
        commit_order(&mut st, prepared, req.replacement.expiry_slot)?;
    }

    // The old order left the book → emit a Cancelled on `/ws/orders` + drop its
    // owner mapping, UNLESS the id is reused (a reprice keeps the logical order).
    if new_order_id != old_order_id {
        announce_cancel(state, old_order_id_hex).await;
    }
    state
        .record_order_owner(hex::encode(new_order_id), account_id.to_string())
        .await;

    Ok(ModifyOrderResponse {
        old_order_id: old_order_id_hex.to_string(),
        order_id: hex::encode(new_order_id),
        status: "modified",
        arrival_slot,
    })
}

pub async fn modify_order(
    State(state): State<Arc<ApiState>>,
    Extension(auth): Extension<Authorized>,
    Path(old_order_id_hex): Path<String>,
    Json(req): Json<ModifyOrderRequest>,
) -> Result<Json<ModifyOrderResponse>, ApiError> {
    let matcher = matcher_or_503(&state)?;
    let resp = modify_core(&state, matcher, &old_order_id_hex, &req, &auth.account_id).await?;
    Ok(Json(resp))
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /orders/{order_id}/anchors  — anchor-pool top-up (Phase 7)
// ─────────────────────────────────────────────────────────────────────────────

/// Body for `POST /orders/{order_id}/anchors`. Appends a fresh batch of
/// continuation anchors to a live order whose pool drained (the matcher
/// paused it). The trading key signs over the new pool's hash + a
/// per-order monotonic `topup_nonce`.
#[derive(Debug, Deserialize)]
pub struct AnchorTopUpRequest {
    /// Exactly `ANCHOR_TOPUP_SIZE` new `(inner_hash, nullifier)` anchors.
    pub anchors: Vec<AnchorJson>,
    /// Strictly-increasing per-order counter (replay protection).
    pub topup_nonce: u64,
    /// 32-byte trading key (must own the order), hex.
    pub trading_key: String,
    /// 64-byte Ed25519 signature over the top-up canonical digest, hex.
    pub trading_key_signature: String,
}

#[derive(Debug, Serialize)]
pub struct AnchorTopUpResponse {
    pub order_id: String,
    pub status: &'static str,
    /// Anchors not yet consumed after the append.
    pub remaining: usize,
}

pub async fn topup_anchors(
    State(state): State<Arc<ApiState>>,
    Extension(_auth): Extension<Authorized>,
    Path(order_id_hex): Path<String>,
    Json(req): Json<AnchorTopUpRequest>,
) -> Result<(StatusCode, Json<AnchorTopUpResponse>), ApiError> {
    let matcher = matcher_or_503(&state)?;

    let order_id: [u8; 16] = decode_hex(&order_id_hex, "order_id (path)")?;
    let trading_key: [u8; 32] = decode_hex(&req.trading_key, "trading_key")?;
    let signature: [u8; 64] = decode_hex(&req.trading_key_signature, "trading_key_signature")?;

    // Validate + decode the new anchors (same rules as intake).
    if req.anchors.len() != ANCHOR_TOPUP_SIZE {
        return Err(ApiError::malformed(format!(
            "anchors: expected exactly {ANCHOR_TOPUP_SIZE} top-up anchors, got {}",
            req.anchors.len()
        )));
    }
    let mut anchors: Vec<Anchor> = Vec::with_capacity(ANCHOR_TOPUP_SIZE);
    for (i, a) in req.anchors.iter().enumerate() {
        let inner_hash: [u8; 32] = decode_hex(&a.inner_hash, "anchor.inner_hash")?;
        let null: [u8; 32] = decode_hex(&a.nullifier, "anchor.nullifier")?;
        darkpool_crypto::fr_from_be_bytes(&inner_hash).map_err(|_| {
            ApiError::fr_unsafe(format!(
                "anchors[{i}].inner_hash is not a canonical BN254 field element"
            ))
        })?;
        anchors.push(Anchor {
            inner_hash,
            nullifier: null,
        });
    }

    // Verify the trading-key signature over (order_id, new-pool hash, nonce).
    let canonical = AnchorTopUpCanonical {
        order_id,
        anchor_pool_hash: anchor_pool_hash(&anchors),
        topup_nonce: req.topup_nonce,
    };
    verify_sig(&canonical.digest(), &trading_key, &signature)?;

    let mut st = matcher.write().await;
    // Authorize: the top-up's trading key must own the order. (A missing
    // order → 404: it filled / cancelled / expired, so its pool is gone.)
    match st.book().get(&order_id) {
        None => {
            return Err(ApiError::not_found(
                "order not found (filled / cancelled / expired)",
            ))
        }
        Some(o) if o.trading_key != trading_key => {
            return Err(ApiError::not_owner("trading key does not own this order"))
        }
        Some(_) => {}
    }

    let pool = st
        .openings_mut()
        .anchor_pool_mut(&order_id)
        .ok_or_else(|| ApiError::not_found("order has no anchor pool"))?;
    // Replay protection: the nonce must strictly increase.
    if req.topup_nonce <= pool.last_topup_nonce {
        return Err(ApiError::stale_nonce(format!(
            "topup_nonce {} not greater than last accepted {}",
            req.topup_nonce, pool.last_topup_nonce
        )));
    }
    pool.last_topup_nonce = req.topup_nonce;
    pool.append(anchors); // also clears `paused` → the matcher resumes it
    let remaining = pool.remaining();

    Ok((
        StatusCode::OK,
        Json(AnchorTopUpResponse {
            order_id: hex::encode(order_id),
            status: "topped_up",
            remaining,
        }),
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /orders/{order_id}
// ─────────────────────────────────────────────────────────────────────────────

pub async fn get_order(
    State(state): State<Arc<ApiState>>,
    Extension(_auth): Extension<Authorized>,
    Path(order_id_hex): Path<String>,
) -> Result<Json<OrderStatusResponse>, ApiError> {
    let matcher = matcher_or_503(&state)?;
    let order_id: [u8; 16] = decode_hex(&order_id_hex, "order_id (path)")?;

    let st = matcher.read().await;
    let order = st
        .book()
        .get(&order_id)
        .ok_or_else(|| ApiError::not_found(format!("no order with id {order_id_hex}")))?;

    Ok(Json(OrderStatusResponse {
        order_id: order_id_hex,
        side: match order.side {
            OrderSide::Bid => "bid",
            OrderSide::Ask => "ask",
        },
        order_type: match order.order_type {
            OrderType::Limit => "limit",
            OrderType::Ioc => "ioc",
            OrderType::Fok => "fok",
        },
        status: match order.status {
            OrderStatus::Empty => "empty",
            OrderStatus::Pending => "pending",
            OrderStatus::Matched => "matched",
            OrderStatus::Expired => "expired",
            OrderStatus::Cancelled => "cancelled",
        },
        amount: order.amount,
        filled_quantity: order.filled_quantity,
        price_limit: order.price_limit,
        expiry_slot: order.expiry_slot,
        arrival_slot: order.arrival_slot,
    }))
}
