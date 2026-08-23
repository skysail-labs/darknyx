//! Order intake — the per-order cryptographic tier ("Layer B").
//!
//! This is the auth that matters. The bearer middleware in [`super::auth`] gates
//! these routes at the account level, but the trading-key Ed25519 signature checked
//! here is what on-chain settlement relies on.
//!
//! Handlers:
//!
//!   - `POST /orders` — verifies the trading-key signature over the canonical body
//!     bytes, then inserts the `Order` into the matcher's book.
//!   - `PUT /orders/{order_id}` — atomic cancel and replace.
//!   - `DELETE /orders/{order_id}` — verifies a fresh signature from the *same*
//!     trading key that owns the order, then removes it.
//!   - `GET /orders/{order_id}` — read-only status.
//!
//! **The bearer's `account_id` is deliberately not required to match the order's
//! `trading_key`.** One account may operate many trading keys — separate
//! sub-portfolios, or a market-maker fleet. The trading key is the cryptographic
//! identity; the JWT only enables metering and audit. Tightening this to an
//! equality check would break fleet operation while adding no custody guarantee,
//! since the signature is already the thing that authorises the order.
//!
//! Canonical signing bytes are produced by `darkpool-matcher`'s `order_canonical`,
//! the single source of truth shared with the SDK. A divergence here rejects every
//! well-formed order rather than accepting a malformed one, which is the safe
//! direction but presents as a total intake outage.
//!
//! See `docs/tee-architecture.md` §11.

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
    pub arrival_nonce: u64,
    /// 32-byte Ed25519 pubkey of the submitter, hex.
    pub trading_key: String,
    /// 64-byte Ed25519 signature over
    /// `sha256(order_canonical_bytes)`, hex.
    pub trading_key_signature: String,

    // ─── Input-note opening ──────────────────────────────────────
    // The TEE prover opens this note inside VALID_MATCH_BATCH, so it
    // needs the secret opening fields the `note_commitment` hides.
    // They're verified at intake against the signed commitment (so
    // they're cryptographically pinned without expanding the signed
    // canonical body) and held in enclave memory only. See
    // `crate::matcher::openings`.
    /// 32-byte note owner commitment `Poseidon3(1, spending_key, r_owner)`,
    /// hex. Intake re-derives `note_commitment` from it, so it is the only
    /// note-bound owner identity an order carries — the only one intake
    /// verifies, and the one output notes derive back to. A separate,
    /// unverified `user_commitment` also rode the wire until audit 2026-07-25
    /// (T-07 / PF-10); nothing read it.
    pub owner_commitment: String,
    /// 32-byte v2 note `inner_hash`, hex (replaces the old note_nonce +
    /// note_blinding pair). Anchors both the commitment and the nullifier.
    pub note_inner_hash: String,

    // ─── VALID_INPUT proof relay ─────────────────────────────────
    // `lock_note` (settle Tx A) requires a per-note VALID_INPUT
    // Groth16 proof. The TEE cannot generate it (it needs the user's
    // spending key + merkle witness), so the client generates it and
    // relays it here, and holds it in enclave memory until settle.
    //
    // Intake DOES verify it (audit 2026-07-25, S-02) — against the same
    // verifying key the on-chain `lock_note` uses, plus a recency check
    // of `merkle_root` against the shard mirror's window. Storing it
    // unverified would let any credentialed client book an order backed by a
    // fabricated note and freeze a real counterparty's collateral when the
    // resulting batch died. On-chain verification
    // remains authoritative; this is an early reject, not a replacement.
    /// 32-byte merkle root the VALID_INPUT proof was generated
    /// against, hex. Must still be in the vault's root history at
    /// lock time (64-root window), and in the mirror's window at intake.
    pub merkle_root: String,
    /// 256-byte VALID_INPUT Groth16 proof (`pi_a ‖ pi_b ‖ pi_c`), hex.
    pub valid_input_proof: String,

    /// OPTIONAL over-collateralization: the actual amount the collateral note
    /// carries, when it exceeds the order's nominal locked amount
    /// (`floor(amount*price_limit/price_scale) + fee` for a bid,
    /// `amount + fee` for an ask). Lets a
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

    /// Required 32-byte contributory X25519 viewing-encryption public key, hex
    /// (`deriveViewingEncKeypair().publicKey`). The settle assembler encrypts
    /// this order's `(trade, change)` output amounts to it and writes the
    /// recovery-v3 ciphertext on-chain. It is bound into the canonical
    /// signature; low-order points are rejected.
    pub viewing_pubkey: String,

    /// 32-byte boot session id from `/info`, hex, bound into the signature.
    pub session_id: String,
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
    #[serde(deserialize_with = "deserialize_wire_u64")]
    pub cancel_nonce: u64,
    /// 32-byte boot session id from `/info`, hex, bound into the signature
    /// (S-07). Scopes the cancel to one CVM boot so a captured body cannot
    /// kill a re-placed order after a restart.
    pub session_id: String,
    /// 64-byte Ed25519 signature over
    /// `sha256(cancel_canonical_bytes)`, hex.
    pub trading_key_signature: String,
}

/// Accept the canonical decimal-string form used by JavaScript clients. The
/// integer arm keeps existing Rust/native clients compatible during devnet.
fn deserialize_wire_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum WireU64 {
        Decimal(String),
        Integer(u64),
    }

    match WireU64::deserialize(deserializer)? {
        WireU64::Integer(value) => Ok(value),
        WireU64::Decimal(value) => {
            if value.is_empty()
                || (value.len() > 1 && value.starts_with('0'))
                || !value.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(serde::de::Error::custom(
                    "u64 must be a canonical decimal string",
                ));
            }
            value.parse::<u64>().map_err(serde::de::Error::custom)
        }
    }
}

#[derive(Debug, Serialize)]
pub struct CancelOrderResponse {
    pub order_id: String,
    pub status: &'static str,
}

#[derive(Debug, Serialize)]
pub struct OrderStatusResponse {
    pub order_id: String,
    pub symbol: String,
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

fn matcher_for_symbol_or_503(
    state: &ApiState,
    symbol: &str,
) -> Result<Arc<tokio::sync::RwLock<crate::matcher::MatcherState>>, ApiError> {
    state.matcher_for_symbol(symbol).ok_or_else(|| {
        if state.all_matchers().is_empty() {
            ApiError::degraded("matcher state not initialised on this instance")
        } else {
            ApiError::malformed(format!("unknown market symbol {symbol:?}"))
        }
    })
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
    /// The owner's required X25519 viewing-encryption pubkey — recipient for
    /// the on-chain recovery-v3 output ciphertext. Stored on the opening.
    viewing_pubkey: [u8; 32],
    valid_input_proof: crate::settle::lock_note::Groth16ProofBytes,
    arrival_slot: u64,
    /// SHA-256 of the signed canonical body. Identifies "the same order" for
    /// idempotent-retry detection on a duplicate `order_id` (see `place_core`).
    canonical_digest: [u8; 32],
}

/// Hand-mirror of `vault::state::MAX_LOCK_TTL_SLOTS` (F-05) — the TEE doesn't
/// depend on the vault BPF crate, so keep this in lockstep with
/// `programs/vault/src/state.rs`. The settler stamps each note lock with the
/// order's `expiry_slot`, and the vault's `lock_note` caps that at
/// `current_slot + MAX_LOCK_TTL_SLOTS`; intake rejects orders beyond it up front
/// (see `prepare_order`) so the cap is a clean placement error, not a
/// settle-time failure. 4_500 ≈ 30 min at 400 ms slots (→ ~15 min post-Alpenglow).
pub(crate) const MAX_LOCK_TTL_SLOTS: u64 = 4_500;

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
    if !state
        .trading_gate_for_symbol(&req.symbol)
        .is_some_and(|gate| gate.is_open())
    {
        return Err(ApiError::degraded(
            "new trading is paused for this market while oracle or finalized governance \
             readiness is unavailable",
        ));
    }

    // 1. Decode hex inputs.
    let order_id: [u8; 16] = decode_hex(&req.order_id, "order_id")?;
    let note_commitment: [u8; 32] = decode_hex(&req.note_commitment, "note_commitment")?;
    let trading_key: [u8; 32] = decode_hex(&req.trading_key, "trading_key")?;
    let signature: [u8; 64] = decode_hex(&req.trading_key_signature, "trading_key_signature")?;
    let owner_commitment: [u8; 32] = decode_hex(&req.owner_commitment, "owner_commitment")?;
    let note_inner_hash: [u8; 32] = decode_hex(&req.note_inner_hash, "note_inner_hash")?;
    let viewing_pubkey: [u8; 32] = decode_hex(&req.viewing_pubkey, "viewing_pubkey")?;
    if !darkpool_crypto::is_contributory_x25519_public_key(&viewing_pubkey) {
        return Err(ApiError::invalid_viewing_key(
            "viewing_pubkey is a non-contributory X25519 point",
        ));
    }
    let session_id: [u8; 32] = decode_hex(&req.session_id, "session_id")?;
    if session_id != state.boot_session_id {
        return Err(ApiError::stale_session(
            "session_id does not match the current CVM boot session",
        ));
    }
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
    // Governed intake policy. Resolve the symbol once, then enforce its minimum
    // size and tick before the expensive Ed25519 verify. Accepting an unlisted
    // symbol would bypass the boot-static market/gate registry.
    let instrument = state
        .instruments
        .iter()
        .find(|i| i.symbol == req.symbol)
        .ok_or_else(|| ApiError::malformed(format!("unknown market symbol {:?}", req.symbol)))?;
    if req.amount < instrument.min_order_size {
        return Err(ApiError::min_notional(format!(
            "amount {} is below the market minimum {}",
            req.amount, instrument.min_order_size
        )));
    }
    if instrument.tick_size == 0 {
        return Err(ApiError::degraded(
            "market tick_size is zero; refusing new trading",
        ));
    }
    if !req.price_limit.is_multiple_of(instrument.tick_size) {
        return Err(ApiError::off_tick(format!(
            "price_limit {} is not aligned to market tick_size {}",
            req.price_limit, instrument.tick_size
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
        arrival_nonce: req.arrival_nonce,
        viewing_pubkey,
        session_id,
    };
    let digest = canonical
        .digest()
        .map_err(|e: CanonicalError| (StatusCode::BAD_REQUEST, format!("canonical encode: {e}")))?;
    verify_sig(&digest, &trading_key, &signature)?;

    // 4. Construct the on-book Order. `note_amount` equals the full
    //    value the collateral note carries, which for a bid is
    //    floor(amount * price_limit / price_scale) (quote units) and for an ask is
    //    `amount` (base units). The .max guards collapse the
    //    pathological "zero" case the matcher never sees in
    //    practice.
    let arrival_slot = state.current_slot.load(Ordering::Relaxed);
    // F-05: the settler stamps the note lock with THIS order's `expiry_slot`,
    // and the vault caps the lock window at `MAX_LOCK_TTL_SLOTS`. An order valid
    // beyond that could never settle (the settle-time `lock_note` would revert),
    // so reject it here for a clean placement error. Expired or near-expiry
    // orders are also rejected here: returning 202 only to sweep them on the
    // next matcher tick gives clients a false accepted/open transition.
    if req.expiry_slot > arrival_slot.saturating_add(MAX_LOCK_TTL_SLOTS) {
        return Err(ApiError::expiry_too_far(format!(
            "expiry_slot {} exceeds current_slot {} + MAX_LOCK_TTL_SLOTS {} (~30 min)",
            req.expiry_slot, arrival_slot, MAX_LOCK_TTL_SLOTS
        )));
    }
    // A bid's collateral is scaled floor quote collateral. A
    // zero price_limit is economically meaningless (buy at price 0)
    // and would collapse to the base-unit `amount` fallback below —
    // a silent unit confusion. Reject it. (An ask may legitimately
    // use price_limit == 0 as a market sell, so this is bid-only.)
    if matches!(side, OrderSide::Bid) && req.price_limit == 0 {
        return Err(ApiError::zero_price_bid(
            "price_limit must be > 0 for a bid",
        ));
    }
    let minimum_expiry = arrival_slot.saturating_add(darkpool_matcher::SETTLEMENT_BUFFER_SLOTS);
    if req.expiry_slot <= minimum_expiry {
        return Err(ApiError::expiry_too_soon(format!(
            "expiry_slot {} must exceed current_slot {} + settlement buffer {}",
            req.expiry_slot,
            arrival_slot,
            darkpool_matcher::SETTLEMENT_BUFFER_SLOTS
        )));
    }
    // Collateral mints + the protocol fee rate, read together under one
    // lock. (Done before deriving note_amount so the fee can be folded
    // into the required collateral.)
    let (base_mint, quote_mint, fee_rate_bps, price_scale) = {
        let st = matcher.read().await;
        let (b, q) = st.market_mints();
        (b, q, st.fee_rate_bps(), st.price_scale())
    };

    // Nominal collateral: a bid locks
    // `floor(amount * price_limit / price_scale)` quote, while an ask locks
    // `amount` base. The u128 intermediate makes the scaled product exact;
    // reject only if the final quote amount cannot fit u64.
    let nominal = match side {
        OrderSide::Bid => u64::try_from(
            (req.amount as u128)
                .checked_mul(req.price_limit as u128)
                .ok_or_else(|| ApiError::malformed("amount * price_limit overflows u128"))?
                / price_scale as u128,
        )
        .map_err(|_| ApiError::malformed("scaled bid collateral overflows u64"))?,
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
    };
    opening.verify_commitment(&note_commitment).map_err(|e| {
        ApiError::bad_opening(format!("note opening does not match note_commitment: {e}"))
    })?;

    // The public consume handle, needed only to check the relayed VALID_INPUT
    // proof against the value `lock_note` will use as its PDA seed. Derived
    // AFTER `verify_commitment`, so the opening is already known
    // self-consistent — a tag is only meaningful for a commitment that really
    // is this opening's.
    //
    // Deliberately NOT carried on `PreparedOrder`: the settle assembler
    // re-derives tags from each opening it resolves, and the `OpeningStore`
    // stays commitment-keyed because it never leaves the enclave. Storing a
    // second copy of a derived value is how the two drift.
    let note_use_tag = darkpool_crypto::note_use_tag(&note_commitment, &note_inner_hash)
        .map_err(|e| ApiError::bad_opening(format!("note-use tag not field-safe: {e}")))?;

    // 4d. Verify the RELAYED VALID_INPUT proof (audit 2026-07-25, S-02).
    //
    //     `verify_commitment` above only proves the opening is self-consistent
    //     with a commitment the client signed — a client can invent an opening
    //     from nothing, sign its Poseidon6, and attach 256 bytes of noise.
    //     Everything up to here passes. The matcher then crosses that phantom
    //     against a real resting order, both `lock_note` transactions fire
    //     concurrently, the HONEST side's lock lands, the fake side's is
    //     rejected on-chain, and the batch dies — leaving an innocent user's
    //     note pinned by an on-chain NoteLock for up to MAX_LOCK_TTL_SLOTS at
    //     zero cost to the attacker. Verifying here turns that into a 400.
    //
    //     Deliberately placed at the END of the lock-free prepare phase:
    //     `place_core` takes the global `submission_replay` mutex and then the
    //     matcher WRITE lock, so a pairing check performed there would
    //     serialise behind — and stall — every matcher tick. Here it costs
    //     nothing but the caller's own latency.
    //
    //     Root recency is checked FIRST: it is a hash-window lookup versus a
    //     pairing, so the cheap reject runs before the expensive one.
    //
    //     Gated on `settle_enabled`, which is the same switch that decides
    //     whether these proofs ever reach the chain at all. A boot without a
    //     live settle driver (placeholder/loadgen mode per U-09, or the
    //     simulator) is enqueue-only: its orders can never produce a
    //     `lock_note`, and the loadgen deliberately sends stub proofs against
    //     synthetic roots. Verifying there would reject traffic that is
    //     harmless by construction. Every configuration that CAN settle
    //     verifies — which is the direction that matters, since S-02's harm is
    //     entirely on-chain.
    if state.settle_enabled {
        // Range-check the shard (SW-21). `tree_id` is deliberately outside the
        // signed canonical body on the grounds that a wrong shard only
        // self-harms — the proof's root is checked against that shard's ring
        // and misses. That holds for an IN-RANGE wrong shard. It does not hold
        // out of range: `merkle_mirror` CLAMPS to shard 0, so an out-of-range
        // id silently validates the root against a shard the caller did not
        // name, and the order is booked carrying a `tree_id` the settle path
        // cannot use.
        let shards = state.num_mirror_shards();
        if usize::from(req.tree_id) >= shards {
            return Err(ApiError::malformed(format!(
                "tree_id {} is out of range; this venue has {} shard(s)",
                req.tree_id, shards
            )));
        }
        let mirror = state.merkle_mirror(req.tree_id as usize);
        let known_root = mirror.read().await.contains_root(&lock_merkle_root);
        if !known_root {
            return Err(ApiError::stale_merkle_root(format!(
                "valid_input proof references merkle_root {} which is not in shard \
                 {}'s recent-root window; re-prove against a current root",
                hex::encode(lock_merkle_root),
                req.tree_id
            )));
        }

        crate::verify::verify_valid_input(
            &valid_input_proof,
            &lock_merkle_root,
            &note_use_tag,
            &token_mint,
        )
        .map_err(|e| ApiError::invalid_input_proof(e.to_string()))?;
    }

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
        arrival_slot,
        canonical_digest: digest,
    })
}

/// Commit a prepared order to the book under the matcher write lock: submit it,
/// store the opening (keyed by note commitment so the settle assembler resolves
/// both sides of a match). Both
/// mutations happen under the same lock the caller holds, so an observer never
/// sees a booked order without its opening.
fn commit_order(
    st: &mut crate::matcher::MatcherState,
    p: PreparedOrder,
    expiry_slot: u64,
) -> Result<(), ApiError> {
    st.release_failed_reservations(p.arrival_slot);
    // Check every conflict before mutating the book. In particular, a note
    // opening is a reservation that survives while settlement is pending; a
    // second order may not overwrite it and double-book the same collateral.
    if st.book().get(&p.order_id).is_some() {
        return Err(ApiError::duplicate(format!(
            "order {} already exists",
            hex::encode(p.order_id)
        )));
    }
    if st.openings().is_reserved(&p.note_commitment) {
        return Err(ApiError::collateral_in_use(
            "collateral note is already reserved",
        ));
    }

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
            viewing_pubkey: Some(p.viewing_pubkey),
        },
    );
    Ok(())
}

/// Remove an order + its opening from the book under the matcher
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
            BookError::PendingSettlement(_) => ApiError::collateral_in_use(e.to_string()),
            e => ApiError::internal(e.to_string()),
        })?;
    if let Some(note) = collateral_note {
        st.openings_mut().remove(&note);
    }
    Ok(())
}

/// Place an order: verify + build (lock-free) then commit it under the matcher
/// write lock + record its owner for per-account routing. The transport-agnostic
/// core shared by `POST /orders` (`place_order`) and the `/v1/stream`
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
    let trading_key = prepared.order.trading_key;
    let arrival_nonce = req.arrival_nonce;
    let order_id_hex = hex::encode(order_id);

    // Exact-idempotency and nonce advancement share one lock, held through the
    // matcher commit. Concurrent submissions therefore have one deterministic
    // order: an exact retry wins before nonce validation; every new body must
    // strictly advance the per-trading-key high-water mark.
    let mut replay = state.submission_replay.lock().await;
    if let Some((prev_digest, prev_slot)) = replay.idempotency.get(&order_id_hex).copied() {
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
    if let Some((last, _last_slot)) = replay.last_arrival_nonce.get(&trading_key).copied() {
        if arrival_nonce <= last {
            return Err(ApiError::stale_nonce(format!(
                "arrival_nonce {arrival_nonce} is not greater than last accepted {last}"
            )));
        }
    }
    if !state
        .trading_gate_for_symbol(&req.symbol)
        .is_some_and(|gate| gate.is_open())
    {
        return Err(ApiError::degraded(
            "new trading paused for this market while the order was being verified; \
             retry after readiness recovers",
        ));
    }

    {
        let mut st = matcher.write().await;
        commit_order(&mut st, prepared, req.expiry_slot)?;
    }

    ApiState::record_submission_locked(
        &mut replay,
        order_id_hex.clone(),
        digest,
        arrival_slot,
        trading_key,
        arrival_nonce,
    );
    drop(replay);
    state
        .record_order_route(
            order_id_hex.clone(),
            account_id.to_string(),
            req.symbol.clone(),
        )
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
    let matcher = matcher_for_symbol_or_503(&state, &req.symbol)?;
    let resp = place_core(&state, &matcher, &req, &auth.account_id).await?;
    Ok((StatusCode::ACCEPTED, Json(resp)))
}

// ─────────────────────────────────────────────────────────────────────────────
// DELETE /orders/{order_id}
// ─────────────────────────────────────────────────────────────────────────────

/// Route a synthetic `Cancelled` onto the `/v1/stream` orders channel then drop the order's
/// routing entry. Explicit/server cancels bypass the matcher tick (so they
/// never reach the `order_updates` broadcast); this mirrors them so
/// orders-channel subscribers still see the order leave, and bounds the
/// `order_owner` map. Shared by every cancel path.
async fn announce_cancel(state: &ApiState, order_id_hex: &str) {
    let market_id = match state.matcher_for_order(order_id_hex).await {
        Some(matcher) => matcher.read().await.market_id(),
        None => "unconfigured".to_string(),
    };
    state
        .route_order_update(
            order_id_hex,
            &OrderUpdateMsg {
                order_id: order_id_hex.to_string(),
                market_id,
                match_id: None,
                server_time_ms: crate::settle::metrics::unix_ms(),
                kind: "cancelled",
                filled_quantity: None,
                new_amount: None,
                new_note_amount: None,
                reason: None,
                lock_expiry_slot: None,
            },
        )
        .await;
    state.forget_order(order_id_hex).await;
}

/// Cancel an order after verifying a fresh trading-key signature over its id.
/// The transport-agnostic core shared by `DELETE /orders/{id}` (`cancel_order`)
/// and the `/v1/stream` `order.cancel` frame.
pub async fn cancel_core(
    state: &ApiState,
    matcher: &Arc<tokio::sync::RwLock<crate::matcher::MatcherState>>,
    order_id_hex: &str,
    req: &CancelOrderRequest,
) -> Result<CancelOrderResponse, ApiError> {
    let order_id: [u8; 16] = decode_hex(order_id_hex, "order_id (path)")?;
    let trading_key: [u8; 32] = decode_hex(&req.trading_key, "trading_key")?;
    let signature: [u8; 64] = decode_hex(&req.trading_key_signature, "trading_key_signature")?;

    let session_id: [u8; 32] = decode_hex(&req.session_id, "session_id")?;
    if session_id != state.boot_session_id {
        return Err(ApiError::stale_session(
            "session_id does not match the current CVM boot session",
        ));
    }

    let cancel = CancelCanonical {
        order_id,
        trading_key,
        cancel_nonce: req.cancel_nonce,
        session_id,
    };
    verify_sig(&cancel.digest(), &trading_key, &signature)?;

    // S-07: strictly increasing per trading key, mirroring the placement
    // path's `arrival_nonce`. Session binding alone bounds a captured
    // signature to one boot; this closes in-session replay as well, so the two
    // sides of the order lifecycle now have the same replay posture.
    let now_slot = state.current_slot.load(Ordering::Relaxed);
    {
        let mut replay = state.submission_replay.lock().await;
        if let Some((last, _)) = replay.last_cancel_nonce.get(&trading_key).copied() {
            if req.cancel_nonce <= last {
                return Err(ApiError::stale_nonce(format!(
                    "cancel_nonce {} is not greater than last accepted {last}",
                    req.cancel_nonce
                )));
            }
        }
        replay
            .last_cancel_nonce
            .insert(trading_key, (req.cancel_nonce, now_slot));
    }

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
/// signature): the order was placed on an authenticated `/v1/stream` session,
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
    Extension(auth): Extension<Authorized>,
    Path(order_id_hex): Path<String>,
    Json(req): Json<CancelOrderRequest>,
) -> Result<Json<CancelOrderResponse>, ApiError> {
    if !state
        .account_owns_order(&order_id_hex, &auth.account_id)
        .await
    {
        return Err(ApiError::not_found("order not found"));
    }
    let matcher = state
        .matcher_for_order(&order_id_hex)
        .await
        .ok_or_else(|| ApiError::not_found("order not found"))?;
    let resp = cancel_core(&state, &matcher, &order_id_hex, &req).await?;
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
    #[serde(deserialize_with = "deserialize_wire_u64")]
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
/// `PUT /orders/{id}` (`modify_order`) and the `/v1/stream` `order.modify`
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
    // The embedded cancel is scoped to the same boot session as the
    // replacement it accompanies (S-07). `prepare_order` below independently
    // rejects a replacement whose session is stale, so a modify cannot smuggle
    // a cross-boot cancel in either half.
    let session_id: [u8; 32] = decode_hex(&req.replacement.session_id, "replacement.session_id")?;
    let cancel = CancelCanonical {
        order_id: old_order_id,
        trading_key,
        cancel_nonce: req.cancel_nonce,
        session_id,
    };
    verify_sig(&cancel.digest(), &trading_key, &cancel_signature)?;

    if let Some(old_symbol) = state.order_market_symbol(old_order_id_hex).await {
        if old_symbol != req.replacement.symbol {
            return Err(ApiError::malformed(
                "modify cannot move an order between markets; cancel and place a fresh order",
            ));
        }
    }

    // Verify + build the replacement (its own canonical sig, collateral, opening)
    // OUTSIDE the lock — the Poseidon/Ed25519 work doesn't block a tick.
    let prepared = prepare_order(state, matcher, &req.replacement).await?;
    let new_order_id = prepared.order_id;
    let arrival_slot = prepared.arrival_slot;
    let digest = prepared.canonical_digest;
    let arrival_nonce = req.replacement.arrival_nonce;
    let new_order_id_hex = hex::encode(new_order_id);

    let mut replay = state.submission_replay.lock().await;
    if let Some((prev_digest, prev_slot)) = replay.idempotency.get(&new_order_id_hex).copied() {
        if prev_digest == digest {
            return Ok(ModifyOrderResponse {
                old_order_id: old_order_id_hex.to_string(),
                order_id: new_order_id_hex,
                status: "modified",
                arrival_slot: prev_slot,
            });
        }
        // Reprice-in-place deliberately reuses the old id; a different new id
        // may never overwrite an earlier accepted canonical body.
        if new_order_id != old_order_id {
            return Err(ApiError::duplicate(
                "replacement order_id already used with a different order",
            ));
        }
    }
    if let Some((last, _last_slot)) = replay.last_arrival_nonce.get(&trading_key).copied() {
        if arrival_nonce <= last {
            return Err(ApiError::stale_nonce(format!(
                "arrival_nonce {arrival_nonce} is not greater than last accepted {last}"
            )));
        }
    }
    if !state
        .trading_gate_for_symbol(&req.replacement.symbol)
        .is_some_and(|gate| gate.is_open())
    {
        return Err(ApiError::degraded(
            "new trading paused for this market while the replacement was being verified; \
             original order unchanged",
        ));
    }

    // Atomic swap under ONE write lock. Check BOTH preconditions before mutating
    // so neither side partially applies (no "user has neither order" window):
    //   - the old order exists and is owned by this trading_key, and
    //   - the new order_id isn't already booked (unless it's the same id — a
    //     reprice in place, where cancelling the old frees the id first).
    {
        let mut st = matcher.write().await;
        let old_collateral = match st.book().get(&old_order_id) {
            None => {
                return Err(ApiError::not_found(format!(
                    "order {old_order_id_hex} not found"
                )))
            }
            Some(o) if o.trading_key != trading_key => {
                return Err(ApiError::not_owner("not the order owner"))
            }
            Some(o) => o.collateral_note,
        };
        if new_order_id != old_order_id && st.book().get(&new_order_id).is_some() {
            return Err(ApiError::id_in_use(format!(
                "replacement order_id {} already exists",
                hex::encode(new_order_id)
            )));
        }
        // Reusing the old order's current collateral is safe because the
        // cancel below releases that exact reservation. Any other existing
        // reservation—including an earlier input still pending settlement—is
        // a hard conflict. Check before cancelling to keep modify atomic.
        if prepared.note_commitment != old_collateral
            && st.openings().is_reserved(&prepared.note_commitment)
        {
            return Err(ApiError::collateral_in_use(
                "replacement collateral is already reserved",
            ));
        }
        // Preconditions hold → both mutations succeed.
        cancel_in_book(&mut st, trading_key, old_order_id)?;
        commit_order(&mut st, prepared, req.replacement.expiry_slot)?;
    }

    ApiState::record_submission_locked(
        &mut replay,
        new_order_id_hex.clone(),
        digest,
        arrival_slot,
        trading_key,
        arrival_nonce,
    );
    drop(replay);

    // The old order left the book → emit a Cancelled on the orders channel + drop its
    // owner mapping, UNLESS the id is reused (a reprice keeps the logical order).
    if new_order_id != old_order_id {
        announce_cancel(state, old_order_id_hex).await;
    }
    state
        .record_order_route(
            new_order_id_hex.clone(),
            account_id.to_string(),
            req.replacement.symbol.clone(),
        )
        .await;

    Ok(ModifyOrderResponse {
        old_order_id: old_order_id_hex.to_string(),
        order_id: new_order_id_hex,
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
    if !state
        .account_owns_order(&old_order_id_hex, &auth.account_id)
        .await
    {
        return Err(ApiError::not_found("order not found"));
    }
    let matcher = state
        .matcher_for_order(&old_order_id_hex)
        .await
        .ok_or_else(|| ApiError::not_found("order not found"))?;
    let resp = modify_core(&state, &matcher, &old_order_id_hex, &req, &auth.account_id).await?;
    Ok(Json(resp))
}

// ─────────────────────────────────────────────────────────────────────────────
// Retired in canonical-order v2: continuation anchors/top-ups no longer exist.
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// GET /orders/{order_id}
// ─────────────────────────────────────────────────────────────────────────────

pub async fn get_order(
    State(state): State<Arc<ApiState>>,
    Extension(auth): Extension<Authorized>,
    Path(order_id_hex): Path<String>,
) -> Result<Json<OrderStatusResponse>, ApiError> {
    let order_id: [u8; 16] = decode_hex(&order_id_hex, "order_id (path)")?;
    let canonical_order_id = hex::encode(order_id);

    // Do not reveal whether a well-formed id belongs to another account. The
    // owner map is populated only after accepted intake and removed when the
    // order becomes terminal, so both foreign and absent ids take this exact
    // response path.
    if !state
        .account_owns_order(&canonical_order_id, &auth.account_id)
        .await
    {
        return Err(ApiError::not_found("order not found"));
    }
    let symbol = state
        .order_market_symbol(&canonical_order_id)
        .await
        .ok_or_else(|| ApiError::not_found("order not found"))?;
    let matcher = state
        .matcher_for_symbol(&symbol)
        .ok_or_else(|| ApiError::not_found("order not found"))?;

    let st = matcher.read().await;
    let order = st
        .book()
        .get(&order_id)
        .ok_or_else(|| ApiError::not_found("order not found"))?;

    Ok(Json(OrderStatusResponse {
        order_id: canonical_order_id,
        symbol,
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
            OrderStatus::Matched => "pending_settlement",
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

#[cfg(test)]
mod wire_tests {
    use super::CancelOrderRequest;

    #[test]
    fn cancel_nonce_accepts_lossless_decimal_u64() {
        let request: CancelOrderRequest = serde_json::from_value(serde_json::json!({
            "trading_key": "00".repeat(32),
            "cancel_nonce": u64::MAX.to_string(),
            "session_id": "11".repeat(32),
            "trading_key_signature": "22".repeat(64),
        }))
        .expect("canonical decimal u64");
        assert_eq!(request.cancel_nonce, u64::MAX);

        for invalid in ["01", "-1", "18446744073709551616"] {
            let parsed = serde_json::from_value::<CancelOrderRequest>(serde_json::json!({
                "trading_key": "00".repeat(32),
                "cancel_nonce": invalid,
                "session_id": "11".repeat(32),
                "trading_key_signature": "22".repeat(64),
            }));
            assert!(parsed.is_err(), "accepted invalid u64 {invalid}");
        }
    }
}
