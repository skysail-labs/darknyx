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
/// `v3` is the clean canonical-order-v2 cutover: continuation anchors were
/// removed after VALID_MATCH_BATCH began deriving every output inner from the
/// consumed input inner. The signed body now binds the required X25519 viewing
/// key and the CVM's 32-byte boot session id. Old v2 signatures are therefore
/// invalid by construction.
pub const ORDER_DOMAIN: &[u8] = b"nyx-order-v3";

/// Domain-separation tag for order cancel. See [`ORDER_DOMAIN`].
pub const CANCEL_DOMAIN: &[u8] = b"nyx-cancel-v1";

/// Cap on symbol length. 32 bytes covers every market identifier
/// we expect to ever ship (`SOL-USDC`, `SOL-USDC-PERP-A`, etc.) and
/// fits cleanly in a `u8` length prefix.
pub const SYMBOL_MAX_LEN: usize = 32;

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
    /// Required X25519 viewing-encryption public key. Signing it prevents an
    /// intermediary from redirecting the durable fill-recovery ciphertext.
    pub viewing_pubkey: [u8; 32],
    /// Random 32-byte id generated once per CVM boot and advertised by `/info`.
    /// Binding it makes every pre-reboot order signature stale after restart.
    pub session_id: [u8; 32],
}

impl<'a> OrderCanonical<'a> {
    /// Serialise to the canonical byte layout. Layout (offsets are
    /// running totals; `S` = symbol bytes length):
    ///
    /// ```text
    ///   0..12        ORDER_DOMAIN              ("nyx-order-v3")
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
    ///   +122..+154   viewing_pubkey : [u8; 32]
    ///   +154..+186   session_id : [u8; 32]
    /// ```
    ///
    /// Total length: `199 + S` bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        if self.symbol.len() > SYMBOL_MAX_LEN {
            return Err(CanonicalError::SymbolTooLong(self.symbol.len()));
        }
        let symbol_len = self.symbol.len() as u8;

        let mut buf = Vec::with_capacity(ORDER_DOMAIN.len() + 1 + self.symbol.len() + 186);
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
        buf.extend_from_slice(&self.viewing_pubkey);
        buf.extend_from_slice(&self.session_id);
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
        "86e585b1c0f2229e61ebbd9d724714577c78359539b6662a5b88b90ec543942a";

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
            viewing_pubkey: [0x44; 32],
            session_id: [0x66; 32],
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
    fn fixture_length_is_199_plus_symbol() {
        let bytes = fixture().to_bytes().unwrap();
        assert_eq!(bytes.len(), 199 + 8); // SOL-USDC = 8 bytes
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
        perturb!(viewing_pubkey = [0x45; 32]);
        perturb!(session_id = [0x67; 32]);
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
