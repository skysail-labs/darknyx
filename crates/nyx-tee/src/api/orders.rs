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

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
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
) -> Result<(), (StatusCode, String)> {
    let vk = VerifyingKey::from_bytes(trading_key).map_err(|e| {
        (
            StatusCode::FORBIDDEN,
            format!("trading_key is not a valid Ed25519 pubkey: {e}"),
        )
    })?;
    let sig = Signature::from_bytes(signature);
    vk.verify_strict(digest, &sig).map_err(|_| {
        (
            StatusCode::FORBIDDEN,
            "trading_key_signature does not verify against the canonical body".to_string(),
        )
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

pub async fn place_order(
    State(state): State<Arc<ApiState>>,
    Extension(auth): Extension<Authorized>,
    Json(req): Json<PlaceOrderRequest>,
) -> Result<(StatusCode, Json<PlaceOrderResponse>), (StatusCode, String)> {
    let matcher = matcher_or_503(&state)?;

    // 1. Decode hex inputs.
    let order_id: [u8; 16] = decode_hex(&req.order_id, "order_id")?;
    let note_commitment: [u8; 32] = decode_hex(&req.note_commitment, "note_commitment")?;
    let user_commitment: [u8; 32] = decode_hex(&req.user_commitment, "user_commitment")?;
    let trading_key: [u8; 32] = decode_hex(&req.trading_key, "trading_key")?;
    let signature: [u8; 64] = decode_hex(&req.trading_key_signature, "trading_key_signature")?;
    let owner_commitment: [u8; 32] = decode_hex(&req.owner_commitment, "owner_commitment")?;
    let note_inner_hash: [u8; 32] = decode_hex(&req.note_inner_hash, "note_inner_hash")?;
    let nullifier: [u8; 32] = decode_hex(&req.nullifier, "nullifier")?;

    // Anchor pool: exactly ANCHOR_POOL_SIZE (inner_hash, nullifier) pairs.
    // Each inner_hash is Poseidon-hashed into a future change-note
    // commitment, so it MUST be a canonical BN254 Fr (fail fast here, like
    // the order's own note_inner_hash). The nullifier is opaque to the TEE
    // (it can't verify it without the spending key) — only length-checked.
    if req.anchors.len() != ANCHOR_POOL_SIZE {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "anchors: expected exactly {ANCHOR_POOL_SIZE} continuation anchors, got {}",
                req.anchors.len()
            ),
        ));
    }
    let mut anchors: Vec<Anchor> = Vec::with_capacity(ANCHOR_POOL_SIZE);
    for (i, a) in req.anchors.iter().enumerate() {
        let inner_hash: [u8; 32] = decode_hex(&a.inner_hash, "anchor.inner_hash")?;
        let null: [u8; 32] = decode_hex(&a.nullifier, "anchor.nullifier")?;
        darkpool_crypto::fr_from_be_bytes(&inner_hash).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                format!("anchors[{i}].inner_hash is not a canonical BN254 field element"),
            )
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
        return Err((
            StatusCode::BAD_REQUEST,
            "order_id must not be all-zero (sentinel reserved for matcher RELOCK_ORDER_ID_NONE)"
                .to_string(),
        ));
    }
    if req.symbol.len() > SYMBOL_MAX_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "symbol length {} exceeds SYMBOL_MAX_LEN ({SYMBOL_MAX_LEN})",
                req.symbol.len()
            ),
        ));
    }
    if user_commitment[0] != 0 {
        // BN254 Fr-safety. Matcher Poseidon-hashes this during
        // change-note construction; non-zero top byte means
        // light-poseidon's `hash_bytes_be` will fail at tick time.
        // Reject early at intake.
        return Err((
            StatusCode::BAD_REQUEST,
            "user_commitment top byte must be zero (BN254 Fr safety)".to_string(),
        ));
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
        return Err((
            StatusCode::BAD_REQUEST,
            "price_limit must be > 0 for a bid".to_string(),
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
        OrderSide::Bid => req.amount.checked_mul(req.price_limit).ok_or((
            StatusCode::BAD_REQUEST,
            "amount * price_limit overflows u64".to_string(),
        ))?,
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
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "collateral_amount {c} is below the required {required} \
                     (nominal {nominal} + fee {fee}) for this order"
                ),
            ));
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
        (
            StatusCode::BAD_REQUEST,
            format!("note opening does not match note_commitment: {e}"),
        )
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
        order_id,
        order_inclusion_commitment: order_inclusion_commitment(
            arrival_slot,
            &note_commitment,
            &trading_key,
        ),
    };

    // 5. Insert. Book may reject for duplicate order_id; map to 409.
    //    On success, record the verified opening keyed by order_id so
    //    the settle assembler can build the proof witness. Both
    //    mutations happen under the same write lock so an observer
    //    never sees a booked order without its opening.
    let mut st = matcher.write().await;
    st.book_mut().submit(order).map_err(|e| match e {
        BookError::Duplicate(_, _) => (StatusCode::CONFLICT, e.to_string()),
        BookError::ZeroOrderId => (StatusCode::BAD_REQUEST, e.to_string()),
        // The matcher's other BookError variants belong to cancel
        // / status paths and shouldn't surface here. If they do,
        // it's a bug — surface as 500.
        e => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    })?;
    // Keyed by collateral note commitment so the settle assembler can
    // resolve both sides of a match from MatchPair.note_buyer/seller.
    st.openings_mut().insert(
        note_commitment,
        crate::matcher::openings::OrderOpening {
            opening,
            order_id,
            expiry_slot: req.expiry_slot,
            merkle_root: lock_merkle_root,
            valid_input_proof,
            // A fresh deposit: lock_note must run for it (no prior re-lock).
            from_relock: false,
        },
    );
    // Stash the continuation anchor pool, keyed by order_id (stable
    // across the collateral rotation a partial-fill continuation does).
    st.openings_mut()
        .insert_anchor_pool(order_id, crate::matcher::openings::AnchorPool::new(anchors));
    drop(st);

    // Record order→account for per-account fills routing — this is the one
    // moment the bearer (account) and the order_id are both in hand. Done after
    // dropping the matcher lock so we never hold it across the routing-map lock.
    state
        .record_order_owner(hex::encode(order_id), auth.account_id.clone())
        .await;

    Ok((
        StatusCode::ACCEPTED,
        Json(PlaceOrderResponse {
            order_id: hex::encode(order_id),
            status: "accepted",
            arrival_slot,
        }),
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// DELETE /orders/{order_id}
// ─────────────────────────────────────────────────────────────────────────────

pub async fn cancel_order(
    State(state): State<Arc<ApiState>>,
    Extension(_auth): Extension<Authorized>,
    Path(order_id_hex): Path<String>,
    Json(req): Json<CancelOrderRequest>,
) -> Result<Json<CancelOrderResponse>, (StatusCode, String)> {
    let matcher = matcher_or_503(&state)?;

    let order_id: [u8; 16] = decode_hex(&order_id_hex, "order_id (path)")?;
    let trading_key: [u8; 32] = decode_hex(&req.trading_key, "trading_key")?;
    let signature: [u8; 64] = decode_hex(&req.trading_key_signature, "trading_key_signature")?;

    let cancel = CancelCanonical {
        order_id,
        trading_key,
        cancel_nonce: req.cancel_nonce,
    };
    let digest = cancel.digest();
    verify_sig(&digest, &trading_key, &signature)?;

    let mut st = matcher.write().await;
    // Resolve the collateral note BEFORE cancelling (the store is
    // keyed by note commitment, not order_id), so we can drop the
    // opening after the book removes the order.
    let collateral_note = st.book().get(&order_id).map(|o| o.collateral_note);
    st.book_mut()
        .cancel(trading_key, order_id)
        .map_err(|e| match e {
            BookError::NotFound(_) => (StatusCode::NOT_FOUND, e.to_string()),
            BookError::NotOwner(_, _) => (StatusCode::FORBIDDEN, e.to_string()),
            e => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        })?;
    // Cancelled order can never settle — drop its in-enclave opening
    // AND its order_id-keyed continuation anchor pool (the cancel path
    // removes the order directly, bypassing the tick's apply_updates
    // pool eviction, so do it here too).
    if let Some(note) = collateral_note {
        st.openings_mut().remove(&note);
    }
    st.openings_mut().remove_anchor_pool(&order_id);
    drop(st);

    // Mirror the cancel onto the order-lifecycle stream BEFORE forgetting the
    // owner mapping (explicit cancels bypass the matcher tick, so they don't go
    // through the order_updates broadcast — route a synthetic Cancelled here so
    // `/ws/orders` subscribers see it).
    state
        .route_order_update(
            &order_id_hex,
            &OrderUpdateMsg {
                order_id: order_id_hex.clone(),
                kind: "cancelled",
                filled_quantity: None,
                new_amount: None,
                new_note_amount: None,
            },
        )
        .await;

    // Cancelled order can never produce a fill — drop its fills-routing entry.
    state.forget_order(&order_id_hex).await;

    Ok(Json(CancelOrderResponse {
        order_id: hex::encode(order_id),
        status: "cancelled",
    }))
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
) -> Result<(StatusCode, Json<AnchorTopUpResponse>), (StatusCode, String)> {
    let matcher = matcher_or_503(&state)?;

    let order_id: [u8; 16] = decode_hex(&order_id_hex, "order_id (path)")?;
    let trading_key: [u8; 32] = decode_hex(&req.trading_key, "trading_key")?;
    let signature: [u8; 64] = decode_hex(&req.trading_key_signature, "trading_key_signature")?;

    // Validate + decode the new anchors (same rules as intake).
    if req.anchors.len() != ANCHOR_TOPUP_SIZE {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "anchors: expected exactly {ANCHOR_TOPUP_SIZE} top-up anchors, got {}",
                req.anchors.len()
            ),
        ));
    }
    let mut anchors: Vec<Anchor> = Vec::with_capacity(ANCHOR_TOPUP_SIZE);
    for (i, a) in req.anchors.iter().enumerate() {
        let inner_hash: [u8; 32] = decode_hex(&a.inner_hash, "anchor.inner_hash")?;
        let null: [u8; 32] = decode_hex(&a.nullifier, "anchor.nullifier")?;
        darkpool_crypto::fr_from_be_bytes(&inner_hash).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                format!("anchors[{i}].inner_hash is not a canonical BN254 field element"),
            )
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
            return Err((
                StatusCode::NOT_FOUND,
                "order not found (filled / cancelled / expired)".to_string(),
            ))
        }
        Some(o) if o.trading_key != trading_key => {
            return Err((
                StatusCode::FORBIDDEN,
                "trading key does not own this order".to_string(),
            ))
        }
        Some(_) => {}
    }

    let pool = st.openings_mut().anchor_pool_mut(&order_id).ok_or((
        StatusCode::NOT_FOUND,
        "order has no anchor pool".to_string(),
    ))?;
    // Replay protection: the nonce must strictly increase.
    if req.topup_nonce <= pool.last_topup_nonce {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "topup_nonce {} not greater than last accepted {}",
                req.topup_nonce, pool.last_topup_nonce
            ),
        ));
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
) -> Result<Json<OrderStatusResponse>, (StatusCode, String)> {
    let matcher = matcher_or_503(&state)?;
    let order_id: [u8; 16] = decode_hex(&order_id_hex, "order_id (path)")?;

    let st = matcher.read().await;
    let order = st.book().get(&order_id).ok_or((
        StatusCode::NOT_FOUND,
        format!("no order with id {order_id_hex}"),
    ))?;

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
