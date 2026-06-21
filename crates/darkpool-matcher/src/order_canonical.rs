//! Canonical byte encoding of an order intent for signing.
//!
//! The trading-key signature in `POST /orders` is computed over
//! `sha256(order_canonical_bytes)`. The bytes are fully fixed-length
//! per field so that re-encoding from JSON / Borsh / any wire form
//! produces the same digest — no canonicalisation attacks possible
//! via field-reordering, whitespace, or leading-zero ambiguity.
//!
//! Wire spec: `docs/tee-architecture.md` §11.2.
//!
//! Cross-language byte equality with the TS encoder in
//! `packages/sdk/src/orders/canonical.ts` is pinned by
//! `packages/sdk/tests/order-canonical-parity.test.ts`. CLAUDE.md §6
//! lists the byte-equality contracts this is now part of.

use crate::book::{OrderSide, OrderType};
use sha2::{Digest, Sha256};

/// Domain-separation tag for order submit. Bound into the front of
/// the canonical bytes so an `OrderCanonical` and a `CancelCanonical`
/// with the same `order_id` can never collide on digest.
///
/// `v2` (was `v1`): the canonical body now binds a 32-byte
/// `anchor_pool_hash` — a SHA-256 over the order's pre-supplied
/// anchor pool (the `(inner_hash, nullifier)` pairs the in-TEE matcher
/// uses to settle partial-fill continuations). Signing the hash (not
/// the 640-byte pool inline) keeps the signed body compact while still
/// cryptographically pinning the pool to the trading-key signature.
pub const ORDER_DOMAIN: &[u8] = b"nyx-order-v2";

/// Domain-separation tag for order cancel. See [`ORDER_DOMAIN`].
pub const CANCEL_DOMAIN: &[u8] = b"nyx-cancel-v1";

/// Domain-separation tag for an anchor-pool top-up (Phase 7 WS). A
/// top-up appends [`ANCHOR_TOPUP_SIZE`] fresh anchors to a live order's
/// pool when it drains; the trading key signs over the new pool's hash
/// so the matcher can't be fed forged anchors. Distinct domain so a
/// top-up can never be replayed as an order submit or cancel.
pub const ANCHOR_TOPUP_DOMAIN: &[u8] = b"nyx-anchor-topup-v1";

/// Cap on symbol length. 32 bytes covers every market identifier
/// we expect to ever ship (`SOL-USDC`, `SOL-USDC-PERP-A`, etc.) and
/// fits cleanly in a `u8` length prefix.
pub const SYMBOL_MAX_LEN: usize = 32;

/// Fixed number of continuation anchors a client supplies with each
/// order. Bounds the per-order memory the CVM holds and the signed
/// pool size. When exhausted (a 10th partial fill) the matcher pauses
/// the order and requests a [`ANCHOR_TOPUP_SIZE`]-anchor top-up over WS.
pub const ANCHOR_POOL_SIZE: usize = 10;

/// Number of anchors added per WebSocket top-up when a pool is drained.
pub const ANCHOR_TOPUP_SIZE: usize = 5;

/// One pre-supplied continuation anchor: the `inner_hash` a future
/// change note will be built with, plus the `nullifier =
/// Poseidon3(DOMAIN_NULL, spending_key, inner_hash)` the client
/// precomputed for when that change note is later spent. Both are
/// 32-byte BE field elements. The CVM cannot forge either (it lacks
/// the spending key); it only consumes them in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub inner_hash: [u8; 32],
    pub nullifier: [u8; 32],
}

/// SHA-256 over the ordered anchor pool: `H(a0.inner ‖ a0.null ‖ a1.inner
/// ‖ a1.null ‖ …)`. This is the value bound into [`OrderCanonical`] and
/// re-checked at intake against the full pool in the request body.
/// Mirrored in TS by `anchorPoolHash` (`packages/sdk/src/orders/canonical.ts`).
pub fn anchor_pool_hash(anchors: &[Anchor]) -> [u8; 32] {
    let mut h = Sha256::new();
    for a in anchors {
        h.update(a.inner_hash);
        h.update(a.nullifier);
    }
    h.finalize().into()
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum CanonicalError {
    #[error("symbol length {0} exceeds SYMBOL_MAX_LEN ({})", SYMBOL_MAX_LEN)]
    SymbolTooLong(usize),
}

/// Submit-order canonical view. Fields mirror the JSON shape in
/// `docs/tee-api-openapi.yaml`'s `PlaceOrderRequest`. `trading_key`
/// is intentionally NOT in the canonical bytes — the signature
/// attests to it implicitly (an Ed25519 signature verifies against
/// the public key, and `verify_strict` rejects key-substitution),
/// and leaving it out keeps the canonical body proof-of-intent only.
#[derive(Clone, Debug)]
pub struct OrderCanonical<'a> {
    /// ASCII market symbol, e.g. `b"SOL-USDC"`. Variable-length with
    /// a `u8` length prefix in the encoding; capped at
    /// [`SYMBOL_MAX_LEN`].
    pub symbol: &'a [u8],
    pub side: OrderSide,
    pub order_type: OrderType,
    pub amount: u64,
    /// 0 for market orders. Always included in the canonical bytes
    /// (no conditional fields — keeps the encoder a straight-line
    /// concat with no branch on `order_type`).
    pub price_limit: u64,
    /// 0 = any partial fill allowed.
    pub min_fill_size: u64,
    pub expiry_slot: u64,
    /// 16-byte client-chosen identifier. Same width as
    /// [`crate::book::Order::order_id`].
    pub order_id: [u8; 16],
    pub note_commitment: [u8; 32],
    pub user_commitment: [u8; 32],
    /// Client-supplied monotonic counter, scoped per trading key.
    /// Used by the TEE to reject submit-replay.
    pub arrival_nonce: u64,
    /// SHA-256 over the order's anchor pool (the ordered
    /// `(inner_hash ‖ nullifier)` pairs). Binds the pre-supplied
    /// continuation anchors to the signature without inlining the
    /// 640-byte pool in the signed body. The intake handler verifies
    /// the full pool in the request body hashes to this value.
    pub anchor_pool_hash: [u8; 32],
}

impl<'a> OrderCanonical<'a> {
    /// Serialise to the canonical byte layout. Layout (offsets are
    /// running totals; `S` = symbol bytes length):
    ///
    /// ```text
    ///   0..12        ORDER_DOMAIN              ("nyx-order-v2")
    ///   12..13       symbol_len : u8
    ///   13..13+S     symbol bytes
    ///   +0..+1       side       : u8           (0 = bid, 1 = ask)
    ///   +1..+2       order_type : u8           (0 = limit, 1 = ioc, 2 = fok)
    ///   +2..+10      amount        : u64 LE
    ///   +10..+18     price_limit   : u64 LE
    ///   +18..+26     min_fill_size : u64 LE
    ///   +26..+34     expiry_slot   : u64 LE
    ///   +34..+50     order_id        : [u8; 16]
    ///   +50..+82     note_commitment : [u8; 32]
    ///   +82..+114    user_commitment : [u8; 32]
    ///   +114..+122   arrival_nonce : u64 LE
    ///   +122..+154   anchor_pool_hash : [u8; 32]
    /// ```
    ///
    /// Total length: `12 + 1 + S + 1 + 1 + 32 + 16 + 32 + 32 + 8 + 32`
    /// = `167 + S` bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        if self.symbol.len() > SYMBOL_MAX_LEN {
            return Err(CanonicalError::SymbolTooLong(self.symbol.len()));
        }
        let symbol_len = self.symbol.len() as u8;

        let mut buf = Vec::with_capacity(ORDER_DOMAIN.len() + 1 + self.symbol.len() + 154);
        buf.extend_from_slice(ORDER_DOMAIN);
        buf.push(symbol_len);
        buf.extend_from_slice(self.symbol);
        buf.push(self.side as u8);
        buf.push(self.order_type as u8);
        buf.extend_from_slice(&self.amount.to_le_bytes());
        buf.extend_from_slice(&self.price_limit.to_le_bytes());
        buf.extend_from_slice(&self.min_fill_size.to_le_bytes());
        buf.extend_from_slice(&self.expiry_slot.to_le_bytes());
        buf.extend_from_slice(&self.order_id);
        buf.extend_from_slice(&self.note_commitment);
        buf.extend_from_slice(&self.user_commitment);
        buf.extend_from_slice(&self.arrival_nonce.to_le_bytes());
        buf.extend_from_slice(&self.anchor_pool_hash);
        Ok(buf)
    }

    /// SHA-256 over [`Self::to_bytes`] — the message the trading-key
    /// signature is computed over.
    pub fn digest(&self) -> Result<[u8; 32], CanonicalError> {
        Ok(Sha256::digest(self.to_bytes()?).into())
    }
}

/// Cancel-order canonical view. Layout:
///
/// ```text
///   0..13       CANCEL_DOMAIN  ("nyx-cancel-v1")
///   13..29      order_id      : [u8; 16]
///   29..61      trading_key   : [u8; 32]
///   61..69      cancel_nonce  : u64 LE
/// ```
///
/// `trading_key` is included here (unlike `OrderCanonical`) because
/// a cancel must bind to the same trading key that owns the
/// original order — including it in the signed bytes makes the
/// binding explicit + audit-friendly.
#[derive(Clone, Debug)]
pub struct CancelCanonical {
    pub order_id: [u8; 16],
    pub trading_key: [u8; 32],
    pub cancel_nonce: u64,
}

impl CancelCanonical {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(CANCEL_DOMAIN.len() + 16 + 32 + 8);
        buf.extend_from_slice(CANCEL_DOMAIN);
        buf.extend_from_slice(&self.order_id);
        buf.extend_from_slice(&self.trading_key);
        buf.extend_from_slice(&self.cancel_nonce.to_le_bytes());
        buf
    }

    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.to_bytes()).into()
    }
}

/// Anchor-pool top-up canonical view. Layout:
///
/// ```text
///   0..19       ANCHOR_TOPUP_DOMAIN  ("nyx-anchor-topup-v1")
///   19..35      order_id      : [u8; 16]
///   35..67      anchor_pool_hash : [u8; 32]   (SHA-256 over the NEW anchors)
///   67..75      topup_nonce   : u64 LE
/// ```
///
/// `anchor_pool_hash` is [`anchor_pool_hash`] over ONLY the newly-added
/// anchors (not the whole pool) — the handler appends them after the
/// signature verifies. `topup_nonce` is a per-order monotonic counter so
/// a top-up can't be replayed (the matcher tracks the last accepted
/// nonce per order). `trading_key` is attested implicitly by the Ed25519
/// signature, as in [`OrderCanonical`].
#[derive(Clone, Debug)]
pub struct AnchorTopUpCanonical {
    pub order_id: [u8; 16],
    pub anchor_pool_hash: [u8; 32],
    pub topup_nonce: u64,
}

impl AnchorTopUpCanonical {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(ANCHOR_TOPUP_DOMAIN.len() + 16 + 32 + 8);
        buf.extend_from_slice(ANCHOR_TOPUP_DOMAIN);
        buf.extend_from_slice(&self.order_id);
        buf.extend_from_slice(&self.anchor_pool_hash);
        buf.extend_from_slice(&self.topup_nonce.to_le_bytes());
        buf
    }

    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.to_bytes()).into()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinned fixture digest. Must stay byte-identical with the TS
    /// encoder in `packages/sdk/src/orders/canonical.ts`; the parity
    /// is pinned by `packages/sdk/tests/order-canonical-parity.test.ts`.
    ///
    /// If you intentionally change the layout, regenerate this hex
    /// AND the TS-side fixture in the same commit.
    const FIXTURE_DIGEST_HEX: &str =
        "03c9cb7db15bd91461dc5f21788ff975adb11351cb77e386ea5ca66ff07235ae";

    /// Pinned cancel-fixture digest. Same parity rule applies.
    const CANCEL_FIXTURE_DIGEST_HEX: &str =
        "da322b3d5d025a9dade32876d05798346e0ebbe69e391d274daa3bd34fcf7962";

    fn fixture() -> OrderCanonical<'static> {
        OrderCanonical {
            symbol: b"SOL-USDC",
            side: OrderSide::Bid,
            order_type: OrderType::Limit,
            amount: 10_000_000,
            price_limit: 150_000_000,
            min_fill_size: 1_000_000,
            expiry_slot: 320_145_000,
            order_id: [0x11; 16],
            note_commitment: [0x22; 32],
            user_commitment: [0x33; 32],
            arrival_nonce: 42,
            anchor_pool_hash: [0x44; 32],
        }
    }

    fn cancel_fixture() -> CancelCanonical {
        CancelCanonical {
            order_id: [0x11; 16],
            trading_key: [0x55; 32],
            cancel_nonce: 7,
        }
    }

    #[test]
    fn fixture_digest_is_pinned() {
        // If this fails after an intentional layout change,
        // regenerate FIXTURE_DIGEST_HEX (above) and the TS fixture
        // in packages/sdk/tests/order-canonical-parity.test.ts in
        // the SAME commit.
        let actual = hex::encode(fixture().digest().unwrap());
        assert_eq!(actual, FIXTURE_DIGEST_HEX);
    }

    #[test]
    fn fixture_length_is_167_plus_symbol() {
        let bytes = fixture().to_bytes().unwrap();
        assert_eq!(bytes.len(), 167 + 8); // SOL-USDC = 8 bytes
    }

    #[test]
    fn cancel_fixture_digest_is_pinned() {
        let actual = hex::encode(cancel_fixture().digest());
        assert_eq!(actual, CANCEL_FIXTURE_DIGEST_HEX);
    }

    #[test]
    fn order_and_cancel_domains_distinct() {
        // Same order_id; different domain tag must yield different
        // digests so a signed submit cannot be replayed as a cancel
        // (and vice versa).
        let order = fixture();
        let cancel = CancelCanonical {
            order_id: order.order_id,
            trading_key: [0; 32],
            cancel_nonce: 0,
        };
        assert_ne!(order.digest().unwrap(), cancel.digest());
    }

    #[test]
    fn each_field_perturbation_changes_digest() {
        let base = fixture().digest().unwrap();

        // Macro-style: clone, perturb one field, assert ne.
        macro_rules! perturb {
            ($field:ident = $val:expr) => {{
                let mut v = fixture();
                v.$field = $val;
                assert_ne!(
                    v.digest().unwrap(),
                    base,
                    "field `{}` did not affect the digest",
                    stringify!($field),
                );
            }};
        }

        perturb!(symbol = b"SOL-USDT");
        perturb!(side = OrderSide::Ask);
        perturb!(order_type = OrderType::Ioc);
        perturb!(amount = 10_000_001);
        perturb!(price_limit = 150_000_001);
        perturb!(min_fill_size = 1_000_001);
        perturb!(expiry_slot = 320_145_001);
        perturb!(order_id = [0x12; 16]);
        perturb!(note_commitment = [0x23; 32]);
        perturb!(user_commitment = [0x34; 32]);
        perturb!(arrival_nonce = 43);
        perturb!(anchor_pool_hash = [0x45; 32]);
    }

    #[test]
    fn anchor_topup_canonical_is_deterministic_and_domain_separated() {
        let t = AnchorTopUpCanonical {
            order_id: [0x11; 16],
            anchor_pool_hash: [0x44; 32],
            topup_nonce: 7,
        };
        // Deterministic.
        assert_eq!(t.digest(), t.digest());
        // Layout length: 19 (domain) + 16 + 32 + 8.
        assert_eq!(t.to_bytes().len(), 19 + 16 + 32 + 8);
        // Domain-separated from an order submit + a cancel with the same id.
        let order = OrderCanonical {
            order_id: t.order_id,
            anchor_pool_hash: t.anchor_pool_hash,
            ..fixture()
        };
        assert_ne!(t.digest(), order.digest().unwrap());
        let cancel = CancelCanonical {
            order_id: t.order_id,
            trading_key: [0; 32],
            cancel_nonce: 7,
        };
        assert_ne!(t.digest(), cancel.digest());
        // nonce + pool-hash both affect the digest.
        let mut t2 = t.clone();
        t2.topup_nonce = 8;
        assert_ne!(t.digest(), t2.digest());
        let mut t3 = t.clone();
        t3.anchor_pool_hash = [0x45; 32];
        assert_ne!(t.digest(), t3.digest());
    }

    #[test]
    fn anchor_pool_hash_is_order_sensitive() {
        let a = Anchor {
            inner_hash: [1u8; 32],
            nullifier: [2u8; 32],
        };
        let b = Anchor {
            inner_hash: [3u8; 32],
            nullifier: [4u8; 32],
        };
        // Swapping the order of two distinct anchors changes the hash.
        assert_ne!(anchor_pool_hash(&[a, b]), anchor_pool_hash(&[b, a]));
        // Deterministic.
        assert_eq!(anchor_pool_hash(&[a, b]), anchor_pool_hash(&[a, b]));
    }

    #[test]
    fn symbol_too_long_rejected() {
        let long = vec![b'X'; SYMBOL_MAX_LEN + 1];
        let v = OrderCanonical {
            symbol: &long,
            ..fixture()
        };
        assert_eq!(
            v.to_bytes().unwrap_err(),
            CanonicalError::SymbolTooLong(SYMBOL_MAX_LEN + 1),
        );
    }

    #[test]
    fn empty_symbol_is_allowed_but_distinct() {
        // Zero-length symbol is a corner case — explicitly allowed
        // by the encoder (the u8 length prefix makes it
        // unambiguous). API layer can additionally reject it; this
        // is the encoder contract.
        let v = OrderCanonical {
            symbol: b"",
            ..fixture()
        };
        let with_symbol = fixture().digest().unwrap();
        let without_symbol = v.digest().unwrap();
        assert_ne!(with_symbol, without_symbol);
    }

    #[test]
    fn side_bit_perturbations_each_distinct() {
        let bid = OrderCanonical {
            side: OrderSide::Bid,
            ..fixture()
        }
        .digest()
        .unwrap();
        let ask = OrderCanonical {
            side: OrderSide::Ask,
            ..fixture()
        }
        .digest()
        .unwrap();
        assert_ne!(bid, ask);
    }

    #[test]
    fn order_type_variants_each_distinct() {
        let limit = OrderCanonical {
            order_type: OrderType::Limit,
            ..fixture()
        }
        .digest()
        .unwrap();
        let ioc = OrderCanonical {
            order_type: OrderType::Ioc,
            ..fixture()
        }
        .digest()
        .unwrap();
        let fok = OrderCanonical {
            order_type: OrderType::Fok,
            ..fixture()
        }
        .digest()
        .unwrap();
        assert_ne!(limit, ioc);
        assert_ne!(ioc, fok);
        assert_ne!(limit, fok);
    }
}
