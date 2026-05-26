//! Wormhole VAA (Verifiable Action Approval) parser + guardian
//! signature verification.
//!
//! A VAA is the cryptographic primitive Pyth uses to sign price
//! attestations. Structure:
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────┐
//! │ header                                                   │
//! │   version              (1 byte)   — must be 1            │
//! │   guardian_set_index   (4 bytes BE) — currently 4 mainnet│
//! │   signatures_count     (1 byte)                          │
//! │ signatures[]                                             │
//! │   guardian_index       (1 byte)                          │
//! │   signature            (65 bytes — r||s||recovery_id)    │
//! │ body                                                     │
//! │   timestamp            (4 bytes BE)                      │
//! │   nonce                (4 bytes BE)                      │
//! │   emitter_chain_id     (2 bytes BE)                      │
//! │   emitter_address      (32 bytes)                        │
//! │   sequence             (8 bytes BE)                      │
//! │   consistency_level    (1 byte)                          │
//! │   payload              (rest — Pyth accumulator update)  │
//! └──────────────────────────────────────────────────────────┘
//! ```
//!
//! Verification: the body bytes (post-signature section) are
//! double-keccak256'd (Wormhole's signing scheme is keccak256 of
//! the body, then ECDSA-signed); for each signature, recover the
//! 20-byte Ethereum-style address via ecrecover and check it
//! matches the guardian at the given index. Quorum is 13/19 for
//! mainnet set 4.
//!
//! **NOT verified at this layer**: the Pyth-internal Merkle-proof
//! inclusion of a specific price feed in the attested Merkle
//! root. That's a Pyth-Wormhole-Accumulator-protocol concern; we
//! treat the Hermes-supplied `parsed[]` price as the truth bound
//! to the attested VAA root in v2. See
//! `docs/tee-architecture.md` §5.6 "What a malicious TEE could
//! actually do" — the trade-off is documented and closed in v3
//! when on-chain Pyth verification lands.

use anyhow::{Context, Result};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use sha3::{Digest, Keccak256};

// ─────── Wormhole mainnet guardian set 6 ───────────────────────────────────
//
// 19 guardians; quorum = ceil(2 * 19 / 3) + 1 = 13.
//
// Source: https://raw.githubusercontent.com/wormhole-foundation/wormhole/main/guardianset/mainnetv2/canonical_sets/v6.prototxt
// Capture date: 2026-05-27 (live Hermes VAA was signed against
// this set — confirmed by the captured `sol_usd_vaa.bin` fixture
// in tests/fixtures/).
//
// When Wormhole next rotates: bump MAINNET_GUARDIAN_SET_INDEX +
// replace this table.

/// The guardian-set index this binary trusts. VAAs signed against a
/// different set are rejected.
pub const MAINNET_GUARDIAN_SET_INDEX: u32 = 6;

/// Number of valid signatures required for a VAA to be accepted.
pub const QUORUM: usize = 13;

/// 20-byte Ethereum-style addresses (keccak256(pubkey)[12..]) of
/// the 19 guardians in mainnet set 6.
#[rustfmt::skip]
pub const MAINNET_GUARDIANS: [[u8; 20]; 19] = [
    hex_lit!("5893B5A76c3f739645648885bDCcC06cd70a3Cd3"),
    hex_lit!("fF6CB952589BDE862c25Ef4392132fb9D4A42157"),
    hex_lit!("114De8460193bdf3A2fCf81f86a09765F4762fD1"),
    hex_lit!("107A0086b32d7A0977926A205131d8731D39cbEB"),
    hex_lit!("8C82B2fd82FaeD2711d59AF0F2499D16e726f6b2"),
    hex_lit!("42579bFFbCF4276E290aB8E4C162bd4052b97970"),
    hex_lit!("938f104AEb5581293216ce97d771e0CB721221B1"),
    hex_lit!("18e41674CcF26329cD111406C1D05C6c80b23EdC"),
    hex_lit!("9D16870160e703324D057c3361c34C5beFBa2c34"),
    hex_lit!("000aC0076727b35FBea2dAc28fEE5cCB0fEA768e"),
    hex_lit!("AF45Ced136b9D9e24903464AE889F5C8a723FC14"),
    hex_lit!("f93124b7c738843CBB89E864c862c38cddCccF95"),
    hex_lit!("D2CC37A4dc036a8D232b48f62cDD4731412f4890"),
    hex_lit!("DA798F6896A3331F64b48c12D1D57Fd9cbe70811"),
    hex_lit!("D1F64e26238811de5553C40f64af41eE1B6057Cc"),
    hex_lit!("3F851Ad586A47ceF8d04748f33ab0D71395f06b4"),
    hex_lit!("178e21ad2E77AE06711549CFBB1f9c7a9d8096e8"),
    hex_lit!("7899cEAB1DC961Dae9defDB7A4f521269a5448FC"),
    hex_lit!("6FbEBc898F403E4773E95feB15E80C9A99c8348d"),
];

// Compile-time hex literal helper. Avoids a runtime hex::decode
// allocation per entry.
macro_rules! hex_lit {
    ($s:literal) => {{
        const BYTES: [u8; $s.len() / 2] = {
            let s = $s.as_bytes();
            let mut out = [0u8; $s.len() / 2];
            let mut i = 0;
            while i < out.len() {
                out[i] = (hex_nibble(s[i * 2]) << 4) | hex_nibble(s[i * 2 + 1]);
                i += 1;
            }
            out
        };
        BYTES
    }};
}
pub(crate) use hex_lit;

/// const-fn hex digit decoder. Panics at compile time on bad input.
const fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => 10 + b - b'a',
        b'A'..=b'F' => 10 + b - b'A',
        _ => panic!("non-hex character in hex_lit!"),
    }
}

// ─────── VAA parsing ───────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum VaaError {
    #[error("VAA shorter than minimum header (6 bytes), got {0}")]
    TooShort(usize),
    #[error("unsupported VAA version {0} (expected 1)")]
    UnsupportedVersion(u8),
    #[error("VAA was signed against guardian set {actual} but this binary trusts set {expected}")]
    WrongGuardianSet { expected: u32, actual: u32 },
    #[error("VAA truncated at {section}: expected {needed} bytes, only {available} left")]
    Truncated {
        section: &'static str,
        needed: usize,
        available: usize,
    },
    #[error("signature {sig_idx} references guardian {guardian_idx} which is out of range [0, {set_size})")]
    GuardianIndexOutOfRange {
        sig_idx: usize,
        guardian_idx: u8,
        set_size: usize,
    },
    #[error("invalid recovery_id {0} in signature (must be 0 or 1)")]
    InvalidRecoveryId(u8),
    #[error("ecrecover failed for signature {sig_idx}: {reason}")]
    EcrecoverFailed { sig_idx: usize, reason: String },
    #[error("recovered address for sig {sig_idx} ({recovered:x?}) does not match guardian {guardian_idx} ({expected:x?})")]
    SignatureMismatch {
        sig_idx: usize,
        guardian_idx: u8,
        recovered: [u8; 20],
        expected: [u8; 20],
    },
    #[error("only {valid}/{required} valid signatures (need quorum = {required} of {set_size})")]
    BelowQuorum {
        valid: usize,
        required: usize,
        set_size: usize,
    },
    #[error("duplicate guardian_index {0} in signature list")]
    DuplicateGuardian(u8),
    #[error("signature_indices not strictly increasing — got {prev} then {next}")]
    SignaturesUnordered { prev: u8, next: u8 },
}

#[derive(Debug, Clone)]
pub struct ParsedVaa<'a> {
    pub guardian_set_index: u32,
    pub signature_count: u8,
    /// Borrowed slice into the source VAA bytes covering the body
    /// section (everything after signatures). Hashed during
    /// verification.
    pub body: &'a [u8],
    pub timestamp: u32,
    pub nonce: u32,
    pub emitter_chain_id: u16,
    pub emitter_address: [u8; 32],
    pub sequence: u64,
    pub consistency_level: u8,
    /// Borrowed slice covering the body's payload (Pyth
    /// accumulator update bytes, for downstream Merkle parsing).
    pub payload: &'a [u8],
    /// Parsed signatures, each ((guardian_idx, recovery_id), r||s bytes).
    /// `signatures[i] = (guardian_idx, recovery_id, [u8; 64])`.
    pub signatures: Vec<(u8, u8, [u8; 64])>,
}

/// Parse the byte layout of a VAA. Does NOT verify guardian sigs;
/// call [`verify_signatures`] for that.
pub fn parse(bytes: &[u8]) -> Result<ParsedVaa<'_>, VaaError> {
    let mut cursor = 0usize;
    let need = |cur: usize, n: usize, section: &'static str| -> Result<(), VaaError> {
        if cur + n > bytes.len() {
            return Err(VaaError::Truncated {
                section,
                needed: n,
                available: bytes.len() - cur,
            });
        }
        Ok(())
    };

    need(cursor, 6, "header")?;
    let version = bytes[cursor];
    cursor += 1;
    if version != 1 {
        return Err(VaaError::UnsupportedVersion(version));
    }
    let guardian_set_index = u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
    cursor += 4;
    let signature_count = bytes[cursor];
    cursor += 1;

    // Parse signatures.
    let sigs_len = (signature_count as usize) * 66; // 1 byte index + 65 byte sig
    need(cursor, sigs_len, "signatures")?;
    let mut signatures = Vec::with_capacity(signature_count as usize);
    let mut prev_idx: Option<u8> = None;
    for _ in 0..signature_count {
        let guardian_idx = bytes[cursor];
        cursor += 1;
        // Wormhole requires signatures to be in strictly-increasing
        // guardian_index order; this prevents duplicate-counting.
        if let Some(prev) = prev_idx {
            if guardian_idx <= prev {
                return Err(VaaError::SignaturesUnordered {
                    prev,
                    next: guardian_idx,
                });
            }
        }
        prev_idx = Some(guardian_idx);

        let mut rs = [0u8; 64];
        rs.copy_from_slice(&bytes[cursor..cursor + 64]);
        cursor += 64;
        let recovery_id = bytes[cursor];
        cursor += 1;
        signatures.push((guardian_idx, recovery_id, rs));
    }

    // Everything from here on is the "body".
    let body_start = cursor;
    let body = &bytes[body_start..];

    need(cursor, 4 + 4 + 2 + 32 + 8 + 1, "body header")?;
    let timestamp = u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
    cursor += 4;
    let nonce = u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
    cursor += 4;
    let emitter_chain_id = u16::from_be_bytes(bytes[cursor..cursor + 2].try_into().unwrap());
    cursor += 2;
    let mut emitter_address = [0u8; 32];
    emitter_address.copy_from_slice(&bytes[cursor..cursor + 32]);
    cursor += 32;
    let sequence = u64::from_be_bytes(bytes[cursor..cursor + 8].try_into().unwrap());
    cursor += 8;
    let consistency_level = bytes[cursor];
    cursor += 1;
    let payload = &bytes[cursor..];

    Ok(ParsedVaa {
        guardian_set_index,
        signature_count,
        body,
        timestamp,
        nonce,
        emitter_chain_id,
        emitter_address,
        sequence,
        consistency_level,
        payload,
        signatures,
    })
}

// ─────── Signature verification ─────────────────────────────────────────────

/// Verify the VAA's guardian signatures against the trusted set.
///
/// 1. Reject if the VAA's `guardian_set_index` isn't the trusted
///    set index.
/// 2. Compute `digest = keccak256(keccak256(body))` — Wormhole's
///    double-hash signing scheme.
/// 3. For each signature: ecrecover the public key, derive the
///    20-byte Ethereum-style address, compare to
///    `guardians[guardian_idx]`. Reject duplicate guardian_idx.
/// 4. Accept iff at least `QUORUM` signatures verified against
///    distinct guardians.
pub fn verify_signatures(
    vaa: &ParsedVaa<'_>,
    guardians: &[[u8; 20]],
    trusted_set_index: u32,
) -> Result<(), VaaError> {
    if vaa.guardian_set_index != trusted_set_index {
        return Err(VaaError::WrongGuardianSet {
            expected: trusted_set_index,
            actual: vaa.guardian_set_index,
        });
    }

    // Wormhole signs keccak256(keccak256(body)). See
    // wormhole-foundation/wormhole/sdk/vaa/structs.go::SigningDigest.
    let inner = Keccak256::digest(vaa.body);
    let digest = Keccak256::digest(inner);

    let mut seen = [false; 256];
    let mut valid: usize = 0;

    for (sig_idx, (guardian_idx, recovery_id, rs)) in vaa.signatures.iter().enumerate() {
        if seen[*guardian_idx as usize] {
            return Err(VaaError::DuplicateGuardian(*guardian_idx));
        }
        seen[*guardian_idx as usize] = true;

        if *guardian_idx as usize >= guardians.len() {
            return Err(VaaError::GuardianIndexOutOfRange {
                sig_idx,
                guardian_idx: *guardian_idx,
                set_size: guardians.len(),
            });
        }
        let expected_addr = guardians[*guardian_idx as usize];

        if *recovery_id > 1 {
            return Err(VaaError::InvalidRecoveryId(*recovery_id));
        }
        let recid =
            RecoveryId::from_byte(*recovery_id).ok_or(VaaError::InvalidRecoveryId(*recovery_id))?;

        let signature = Signature::from_slice(rs).map_err(|e| VaaError::EcrecoverFailed {
            sig_idx,
            reason: format!("invalid r||s: {e}"),
        })?;

        let vk = VerifyingKey::recover_from_prehash(&digest, &signature, recid).map_err(|e| {
            VaaError::EcrecoverFailed {
                sig_idx,
                reason: format!("recover_from_prehash: {e}"),
            }
        })?;

        // Wormhole guardian addresses = keccak256(uncompressed pubkey
        // sans the 0x04 prefix)[12..32]. Same as Ethereum addresses.
        let pubkey_bytes = vk.to_encoded_point(false);
        let pubkey_slice = &pubkey_bytes.as_bytes()[1..]; // strip 0x04
        let recovered_addr_full = Keccak256::digest(pubkey_slice);
        let mut recovered_addr = [0u8; 20];
        recovered_addr.copy_from_slice(&recovered_addr_full[12..32]);

        if recovered_addr != expected_addr {
            return Err(VaaError::SignatureMismatch {
                sig_idx,
                guardian_idx: *guardian_idx,
                recovered: recovered_addr,
                expected: expected_addr,
            });
        }
        valid += 1;
    }

    if valid < QUORUM {
        return Err(VaaError::BelowQuorum {
            valid,
            required: QUORUM,
            set_size: guardians.len(),
        });
    }
    Ok(())
}

/// Convenience wrapper: parse + verify against the trusted mainnet
/// set. Returns the parsed VAA on success.
pub fn verify(bytes: &[u8]) -> Result<ParsedVaa<'_>> {
    let vaa = parse(bytes).context("VAA parse failed")?;
    verify_signatures(&vaa, &MAINNET_GUARDIANS, MAINNET_GUARDIAN_SET_INDEX)
        .context("VAA guardian signature verification failed")?;
    Ok(vaa)
}

// ─────── Self-tests (no fixtures needed) ────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quorum_is_thirteen_of_nineteen() {
        // Documented as constants but worth pinning by test: if
        // anyone changes one without the other, this catches it.
        assert_eq!(MAINNET_GUARDIANS.len(), 19);
        assert_eq!(QUORUM, 13);
        // floor(2 * 19 / 3) + 1 = 13
        assert_eq!(QUORUM, (2 * MAINNET_GUARDIANS.len() / 3) + 1);
    }

    #[test]
    fn hex_lit_decodes_correctly() {
        // Sanity-check the const-fn hex helper.
        const X: [u8; 4] = hex_lit!("DeAdBeEf");
        assert_eq!(X, [0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn parse_rejects_short_input() {
        let err = parse(&[1u8; 3]).unwrap_err();
        assert!(matches!(err, VaaError::Truncated { .. }));
    }

    #[test]
    fn parse_rejects_wrong_version() {
        let bytes = vec![2u8, 0, 0, 0, 4, 0]; // version=2
        let err = parse(&bytes).unwrap_err();
        assert!(matches!(err, VaaError::UnsupportedVersion(2)));
    }

    #[test]
    fn parse_rejects_unordered_signatures() {
        // version=1, set=4, count=2, then sig0 idx=5, sig1 idx=3.
        let mut bytes = vec![1u8];
        bytes.extend_from_slice(&4u32.to_be_bytes());
        bytes.push(2); // 2 signatures
                       // sig 0: guardian 5
        bytes.push(5);
        bytes.extend_from_slice(&[0u8; 65]);
        // sig 1: guardian 3 (out of order)
        bytes.push(3);
        bytes.extend_from_slice(&[0u8; 65]);
        // body bytes (timestamp..) — won't be reached because parse
        // bails on ordering.
        let err = parse(&bytes).unwrap_err();
        assert!(matches!(
            err,
            VaaError::SignaturesUnordered { prev: 5, next: 3 }
        ));
    }
}
