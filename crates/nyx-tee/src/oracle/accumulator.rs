//! Pyth accumulator (PNAU) parser + Keccak160 Merkle-inclusion verifier.
//!
//! This is the C-05 / A-2 fix. `vaa.rs` proves the Wormhole guardians signed a
//! VAA; this module proves the *price we actually use* is the one committed
//! under that VAA's Merkle root — closing the gap where the price was read from
//! Hermes's untrusted JSON `parsed[]` instead of the guardian-signed binary.
//!
//! The wire format + hashing here are pinned against `pythnet-sdk`
//! (`pyth-network/pyth-crosschain`) AND validated byte-for-byte against a real
//! Hermes fixture. The full confirmed spec (with source line refs) lives in
//! `docs/oracle-accumulator-notes.md` — read it before touching any offset,
//! length-prefix width, endianness, or the Merkle hashing. Those are exactly
//! where a silent false-accept hides.
//!
//! Layout summary (all big-endian; sequences/enum-variants are u8-prefixed —
//! Pyth's custom serde format):
//!
//! ```text
//! AccumulatorUpdateData:
//!   "PNAU"(4) major(1) minor(1) trailing(u8 len + bytes)
//!   proof_disc(1)=0  vaa(u16-BE len + bytes)  num_updates(u8)
//!   updates[]: { msg(u16-BE len + bytes)  proof(u8 count + count×20B) }
//! VAA payload (WormholeMessage):
//!   "AUWV"(4) payload_disc(1)=0  slot(u64-BE) ring_size(u32-BE) root([u8;20])
//! Merkle:  leaf=K160(0x00‖msg)  node=K160(0x01‖min(l,r)‖max(l,r))  (sorted)
//! ```

use sha3::{Digest, Keccak256};

/// `AccumulatorUpdateData` magic ("PNAU").
pub const ACCUM_MAGIC: &[u8; 4] = b"PNAU";
/// `WormholeMessage` magic ("AUWV") — the VAA payload envelope.
pub const WORMHOLE_MSG_MAGIC: &[u8; 4] = b"AUWV";
/// `Message` enum discriminant for `PriceFeedMessage`.
pub const PRICE_FEED_MESSAGE_DISCRIMINATOR: u8 = 0;
/// `Proof` enum discriminant for `WormholeMerkle`.
pub const PROOF_TYPE_WORMHOLE_MERKLE: u8 = 0;
/// `WormholePayload` enum discriminant for `Merkle`.
pub const PAYLOAD_TYPE_MERKLE: u8 = 0;

const MERKLE_LEAF_PREFIX: u8 = 0;
const MERKLE_NODE_PREFIX: u8 = 1;

#[derive(Debug, thiserror::Error)]
pub enum AccumulatorError {
    #[error("buffer truncated at {section}: needed {needed} more bytes, only {available} left")]
    Truncated {
        section: &'static str,
        needed: usize,
        available: usize,
    },
    #[error("bad {what} magic: expected {expected:x?}, got {got:x?}")]
    BadMagic {
        what: &'static str,
        expected: [u8; 4],
        got: [u8; 4],
    },
    #[error("unsupported AccumulatorUpdateData major_version {0} (expected 1)")]
    UnsupportedVersion(u8),
    #[error("unsupported proof_type {got} (expected {expected} = WormholeMerkle)")]
    UnsupportedProofType { expected: u8, got: u8 },
    #[error("unsupported wormhole payload_type {got} (expected {expected} = Merkle)")]
    UnsupportedPayloadType { expected: u8, got: u8 },
    #[error("PriceFeedMessage discriminant {got} is not {expected}")]
    NotPriceFeedMessage { expected: u8, got: u8 },
    #[error("no price message for feed {feed_id} in the accumulator update")]
    FeedNotFound { feed_id: String },
    #[error("Merkle inclusion proof failed for feed {feed_id}: recomputed root {recomputed:x?} != attested {attested:x?}")]
    InclusionFailed {
        feed_id: String,
        recomputed: [u8; 20],
        attested: [u8; 20],
    },
}

// ─────── bounds-checked big-endian cursor ───────────────────────────────────

/// A forward-only reader that never panics on a short buffer — every read is
/// length-checked and returns [`AccumulatorError::Truncated`] on underflow.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize, section: &'static str) -> Result<&'a [u8], AccumulatorError> {
        let end = self.pos.checked_add(n).ok_or(AccumulatorError::Truncated {
            section,
            needed: n,
            available: 0,
        })?;
        if end > self.bytes.len() {
            return Err(AccumulatorError::Truncated {
                section,
                needed: n,
                available: self.bytes.len().saturating_sub(self.pos),
            });
        }
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u8(&mut self, section: &'static str) -> Result<u8, AccumulatorError> {
        Ok(self.take(1, section)?[0])
    }

    fn u16_be(&mut self, section: &'static str) -> Result<u16, AccumulatorError> {
        let b = self.take(2, section)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn magic4(&mut self, section: &'static str) -> Result<[u8; 4], AccumulatorError> {
        let b = self.take(4, section)?;
        Ok([b[0], b[1], b[2], b[3]])
    }
}

// ─────── parsed views ───────────────────────────────────────────────────────

/// One `MerklePriceUpdate`: a serialized price message + its Merkle path.
/// Both borrow from the source accumulator buffer.
#[derive(Debug, Clone)]
pub struct PriceUpdate<'a> {
    /// Raw serialized `Message` bytes — this is the Merkle *leaf* preimage
    /// (hashed as-is; do NOT decode before hashing).
    pub message: &'a [u8],
    /// Merkle proof: sibling hashes leaf→root. Order-agnostic (pairs are
    /// sorted when hashing), so no left/right bit is carried.
    pub proof: Vec<[u8; 20]>,
}

/// A parsed `AccumulatorUpdateData` (borrows the source buffer).
#[derive(Debug, Clone)]
pub struct AccumulatorUpdate<'a> {
    /// The Wormhole VAA bytes — pass to [`crate::oracle::vaa::verify`].
    pub vaa: &'a [u8],
    /// Price updates (one per feed in the query; single-feed → one entry).
    pub updates: Vec<PriceUpdate<'a>>,
}

/// A decoded Pyth `PriceFeedMessage` (the 85-byte `Message::PriceFeedMessage`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PriceFeedMessage {
    pub feed_id: [u8; 32],
    pub price: i64,
    pub conf: u64,
    pub exponent: i32,
    pub publish_time: i64,
    pub prev_publish_time: i64,
    pub ema_price: i64,
    pub ema_conf: u64,
}

// ─────── parsing ─────────────────────────────────────────────────────────────

/// Parse the `AccumulatorUpdateData` envelope (Hermes `binary.data[0]`).
///
/// Validates the "PNAU" magic, major version, and proof type, then splits out
/// the VAA and each `(message, proof)` update. Does NOT verify anything
/// cryptographic — call [`verify_inclusion`] + `vaa::verify` for that.
pub fn parse(bytes: &[u8]) -> Result<AccumulatorUpdate<'_>, AccumulatorError> {
    let mut c = Cursor::new(bytes);

    let magic = c.magic4("magic")?;
    if &magic != ACCUM_MAGIC {
        return Err(AccumulatorError::BadMagic {
            what: "PNAU",
            expected: *ACCUM_MAGIC,
            got: magic,
        });
    }
    let major = c.u8("major_version")?;
    if major != 1 {
        return Err(AccumulatorError::UnsupportedVersion(major));
    }
    let _minor = c.u8("minor_version")?; // forward-compatible: accept any minor

    // `trailing: Vec<u8>` — u8 length prefix, then that many bytes (skip).
    let trailing_len = c.u8("trailing_len")? as usize;
    let _ = c.take(trailing_len, "trailing")?;

    // `proof: Proof` enum — u8 variant discriminant.
    let proof_type = c.u8("proof_type")?;
    if proof_type != PROOF_TYPE_WORMHOLE_MERKLE {
        return Err(AccumulatorError::UnsupportedProofType {
            expected: PROOF_TYPE_WORMHOLE_MERKLE,
            got: proof_type,
        });
    }

    // `vaa: PrefixedVec<u16, u8>` — u16-BE length prefix.
    let vaa_len = c.u16_be("vaa_len")? as usize;
    let vaa = c.take(vaa_len, "vaa")?;

    // `updates: Vec<MerklePriceUpdate>` — u8 count.
    let num_updates = c.u8("num_updates")? as usize;
    let mut updates = Vec::with_capacity(num_updates);
    for _ in 0..num_updates {
        // `message: PrefixedVec<u16, u8>` — u16-BE length prefix.
        let msg_len = c.u16_be("update.msg_len")? as usize;
        let message = c.take(msg_len, "update.message")?;
        // `proof: MerklePath<Keccak160>` = Vec<[u8;20]> — u8 count, 20B nodes.
        let proof_count = c.u8("update.proof_count")? as usize;
        let mut proof = Vec::with_capacity(proof_count);
        for _ in 0..proof_count {
            let node = c.take(20, "update.proof_node")?;
            let mut arr = [0u8; 20];
            arr.copy_from_slice(node);
            proof.push(arr);
        }
        updates.push(PriceUpdate { message, proof });
    }

    Ok(AccumulatorUpdate { vaa, updates })
}

/// Extract the 20-byte Merkle root from a **guardian-verified** VAA payload
/// (`WormholeMessage`). Call this ONLY on the payload of a VAA that already
/// passed [`crate::oracle::vaa::verify`] — the root is the sole anchor the
/// guardian signatures bind.
pub fn merkle_root_from_vaa_payload(payload: &[u8]) -> Result<[u8; 20], AccumulatorError> {
    let mut c = Cursor::new(payload);
    let magic = c.magic4("AUWV magic")?;
    if &magic != WORMHOLE_MSG_MAGIC {
        return Err(AccumulatorError::BadMagic {
            what: "AUWV",
            expected: *WORMHOLE_MSG_MAGIC,
            got: magic,
        });
    }
    // `payload: WormholePayload` enum — u8 variant discriminant.
    let payload_type = c.u8("payload_type")?;
    if payload_type != PAYLOAD_TYPE_MERKLE {
        return Err(AccumulatorError::UnsupportedPayloadType {
            expected: PAYLOAD_TYPE_MERKLE,
            got: payload_type,
        });
    }
    let _slot = c.take(8, "slot")?; // u64-BE, unused
    let _ring_size = c.take(4, "ring_size")?; // u32-BE, unused
    let root = c.take(20, "root")?;
    let mut out = [0u8; 20];
    out.copy_from_slice(root);
    Ok(out)
}

/// Decode a `PriceFeedMessage`. Rejects any other `Message` discriminant.
/// Forward-compatible: extra trailing bytes (future fields) are ignored.
pub fn parse_price_feed_message(msg: &[u8]) -> Result<PriceFeedMessage, AccumulatorError> {
    let mut c = Cursor::new(msg);
    let disc = c.u8("message_disc")?;
    if disc != PRICE_FEED_MESSAGE_DISCRIMINATOR {
        return Err(AccumulatorError::NotPriceFeedMessage {
            expected: PRICE_FEED_MESSAGE_DISCRIMINATOR,
            got: disc,
        });
    }
    let feed_id: [u8; 32] = c.take(32, "feed_id")?.try_into().unwrap();
    let price = i64::from_be_bytes(c.take(8, "price")?.try_into().unwrap());
    let conf = u64::from_be_bytes(c.take(8, "conf")?.try_into().unwrap());
    let exponent = i32::from_be_bytes(c.take(4, "exponent")?.try_into().unwrap());
    let publish_time = i64::from_be_bytes(c.take(8, "publish_time")?.try_into().unwrap());
    let prev_publish_time = i64::from_be_bytes(c.take(8, "prev_publish_time")?.try_into().unwrap());
    let ema_price = i64::from_be_bytes(c.take(8, "ema_price")?.try_into().unwrap());
    let ema_conf = u64::from_be_bytes(c.take(8, "ema_conf")?.try_into().unwrap());
    Ok(PriceFeedMessage {
        feed_id,
        price,
        conf,
        exponent,
        publish_time,
        prev_publish_time,
        ema_price,
        ema_conf,
    })
}

// ─────── Keccak160 Merkle verification ───────────────────────────────────────

/// Keccak160 = the **first** 20 bytes of Keccak256 (matches
/// `pythnet_sdk::hashers::keccak256_160`). Note `sha3::Keccak256` is the
/// original Keccak (Ethereum's), NOT FIPS-202 SHA3-256.
fn keccak160(parts: &[&[u8]]) -> [u8; 20] {
    let mut hasher = Keccak256::new();
    for p in parts {
        hasher.update(p);
    }
    let full = hasher.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&full[..20]);
    out
}

fn hash_leaf(message: &[u8]) -> [u8; 20] {
    keccak160(&[&[MERKLE_LEAF_PREFIX], message])
}

/// Hash a node from its two children, sorting the pair (min‖max) exactly as
/// `pythnet_sdk`'s `hash_node` does. The sort makes the fold order-agnostic.
fn hash_node(a: &[u8; 20], b: &[u8; 20]) -> [u8; 20] {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    keccak160(&[&[MERKLE_NODE_PREFIX], lo, hi])
}

/// Recompute the Merkle root from a leaf message + proof path.
pub fn compute_root(message: &[u8], proof: &[[u8; 20]]) -> [u8; 20] {
    let mut current = hash_leaf(message);
    for node in proof {
        current = hash_node(&current, node);
    }
    current
}

/// Verify that `message` is included under `root` via `proof`.
pub fn verify_inclusion(message: &[u8], proof: &[[u8; 20]], root: &[u8; 20]) -> bool {
    compute_root(message, proof) == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The full-fixture end-to-end test lives in
    /// `tests/oracle_accumulator.rs` (it needs the committed fixture). These
    /// cover the parsing/hashing units + malformed-input safety.

    #[test]
    fn keccak160_is_first_20_bytes() {
        // keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        // first 20 bytes = c5d2460186f7233c927e7db2dcc703c0e500b653
        let h = keccak160(&[b""]);
        assert_eq!(hex::encode(h), "c5d2460186f7233c927e7db2dcc703c0e500b653");
    }

    #[test]
    fn hash_node_is_sorted() {
        let a = [0x11u8; 20];
        let b = [0x22u8; 20];
        // sorted → identical regardless of argument order
        assert_eq!(hash_node(&a, &b), hash_node(&b, &a));
        // and equals the explicit min‖max form
        assert_eq!(hash_node(&a, &b), keccak160(&[&[1], &a, &b]));
    }

    #[test]
    fn single_leaf_tree_root_is_leaf_hash() {
        let msg = b"hello";
        assert_eq!(compute_root(msg, &[]), hash_leaf(msg));
    }

    #[test]
    fn parse_rejects_bad_magic() {
        let bad = [0xde, 0xad, 0xbe, 0xef, 1, 0, 0, 0];
        assert!(matches!(
            parse(&bad),
            Err(AccumulatorError::BadMagic { what: "PNAU", .. })
        ));
    }

    #[test]
    fn parse_rejects_truncated() {
        // "PNAU" + major=1 but nothing after → truncated on minor.
        let bad = [b'P', b'N', b'A', b'U', 1];
        assert!(matches!(
            parse(&bad),
            Err(AccumulatorError::Truncated { .. })
        ));
    }

    #[test]
    fn merkle_root_rejects_bad_magic() {
        let bad = [0u8; 37];
        assert!(matches!(
            merkle_root_from_vaa_payload(&bad),
            Err(AccumulatorError::BadMagic { what: "AUWV", .. })
        ));
    }

    #[test]
    fn price_feed_message_rejects_wrong_discriminant() {
        let mut msg = vec![9u8]; // not PriceFeedMessage
        msg.extend_from_slice(&[0u8; 84]);
        assert!(matches!(
            parse_price_feed_message(&msg),
            Err(AccumulatorError::NotPriceFeedMessage { got: 9, .. })
        ));
    }
}
