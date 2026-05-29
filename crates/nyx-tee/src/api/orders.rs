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
    CancelCanonical, CanonicalError, OrderCanonical, SYMBOL_MAX_LEN,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::auth::Authorized;
use super::state::ApiState;
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
    /// 32-byte per-note nonce, hex.
    pub note_nonce: String,
    /// 32-byte per-note blinding factor, hex.
    pub note_blinding: String,
    /// 32-byte nullifier `Poseidon3(3, spending_key, note_commitment)`,
    /// hex. Precomputed by the client (needs the spending key, which
    /// never enters the TEE); opaque to the matcher.
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
    Extension(_auth): Extension<Authorized>,
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
    let note_nonce: [u8; 32] = decode_hex(&req.note_nonce, "note_nonce")?;
    let note_blinding: [u8; 32] = decode_hex(&req.note_blinding, "note_blinding")?;
    let nullifier: [u8; 32] = decode_hex(&req.nullifier, "nullifier")?;

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
    let note_amount = match side {
        OrderSide::Bid => req
            .amount
            .saturating_mul(req.price_limit)
            .max(req.amount)
            .max(1),
        OrderSide::Ask => req.amount.max(1),
    };

    // 4b. Build + verify the input-note opening. The collateral mint
    //     is the quote mint for a bid (quote locked) and the base
    //     mint for an ask. `verify_commitment` re-derives the note
    //     commitment from (mint, note_amount, owner_commitment,
    //     nonce, blinding) and asserts it equals the signed
    //     `note_commitment` — pinning the opening to the signature
    //     and enforcing `note_amount == committed amount` (the
    //     conservation invariant the circuit needs). Done outside the
    //     matcher lock so the Poseidon work doesn't block a tick.
    let (base_mint, quote_mint) = {
        let st = matcher.read().await;
        st.market_mints()
    };
    let token_mint = match side {
        OrderSide::Bid => quote_mint,
        OrderSide::Ask => base_mint,
    };
    let opening = crate::matcher::openings::NoteOpening {
        token_mint,
        amount: note_amount,
        owner_commitment,
        nonce: note_nonce,
        blinding: note_blinding,
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
    st.openings_mut().insert(order_id, opening);

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
    st.book_mut()
        .cancel(trading_key, order_id)
        .map_err(|e| match e {
            BookError::NotFound(_) => (StatusCode::NOT_FOUND, e.to_string()),
            BookError::NotOwner(_, _) => (StatusCode::FORBIDDEN, e.to_string()),
            e => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        })?;
    // Cancelled order can never settle — drop its in-enclave opening.
    st.openings_mut().remove(&order_id);

    Ok(Json(CancelOrderResponse {
        order_id: hex::encode(order_id),
        status: "cancelled",
    }))
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
