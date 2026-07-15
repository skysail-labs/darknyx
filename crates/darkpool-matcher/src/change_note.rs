//! Deterministic note-inner derivation used by the matcher and settler.
//!
//! # Cross-language byte-equality contract
//!
//! These functions must produce byte-identical output to the TypeScript SDK:
//!
//! * **TypeScript** —
//!   `packages/sdk/tests/helpers/e2e-helpers.ts::deriveNonce` /
//!   `deriveBlinding`, which uses Node's `crypto.createHash("sha256")`.
//!   Pinned by fixed vectors in the Rust and SDK parity tests.
//!
//! All three implementations:
//!   1. SHA-256 over: `domain_tag ‖ match_id_le ‖ role_byte`
//!   2. Set output byte 0 = 0, output byte 1 &= 0x0f (BN254 Fr safety
//!      — keeps the 32-byte value strictly below the Fr modulus).
//!
//! `tests/change_note_parity.rs` also checks an independent Solana SHA-256
//! backend so backend changes cannot silently alter the bytes.
//!
//! ## v2 (inner_hash)
//!
//! The v2 note construction collapses the per-note (nonce, blinding_r) pair
//! into a SINGLE `inner_hash` (see `darkpool_crypto::note::commitment_from_fields_v2`).
//! So there is now ONE derivation per (match_id, role): [`derive_inner`]. It uses
//! a single domain tag — the nonce/blinding domain split is gone because there is
//! only one field to derive.

use sha2::{Digest, Sha256};

// ─────── Role tags ──────────────────────────────────────────────────────────
//
// These constants MUST equal the TS constants at
// `packages/sdk/tests/helpers/e2e-helpers.ts`.
//
// CLAUDE.md §6 lists this as a cross-language byte-equality contract;
// changing any of these requires touching all three sites + bumping
// the parity tests.

/// Role tag for the buyer's change note (`note_e`).
pub const CHANGE_ROLE_BUYER: u8 = 0xB1;
/// Role tag for the seller's change note (`note_f`).
pub const CHANGE_ROLE_SELLER: u8 = 0x5E;

// ─── Trade-output + fee note roles (4g.7) ─────────────────────────────────────
//
// These role bytes are also consumed by VALID_MATCH_BATCH v3's Poseidon
// derivations. User outputs use Poseidon3(24, consumed_input_inner, role), and
// fee outputs use Poseidon3(25, consumed_input_commitment, role). The legacy
// `derive_inner(match_id, role)` helper remains for pre-cutover note families.

/// Role tag for the buyer's full-fill output note (`note_c`).
pub const TRADE_ROLE_BUYER: u8 = 0xC1;
/// Role tag for the seller's full-fill output note (`note_d`).
pub const TRADE_ROLE_SELLER: u8 = 0xD1;
/// Role tag for a base-asset protocol fee note.
pub const FEE_ROLE_BASE: u8 = 0xFB;
/// Role tag for a quote-asset protocol fee note.
pub const FEE_ROLE_QUOTE: u8 = 0xFC;

// ─────── Domain tag ──────────────────────────────────────────────────────────
//
// The single domain tag for the v2 inner_hash derivation. (The v1 split into
// `nyx-change-nonce` / `nyx-change-blind` is gone — there is now one field per
// note.)

const DOMAIN_INNER: &[u8] = b"nyx-change-inner";

// ─────── Derivation primitive ────────────────────────────────────────────────

/// Derive the v2 note `inner_hash` (32 bytes) from `(match_id, role)`.
///
/// Output is masked to be a valid BN254 Fr element:
/// `out[0] = 0`, `out[1] &= 0x0f`. SHA-256 alone could produce a
/// 32-byte value ≥ p (the Fr modulus); the mask drops it into a
/// strict subset that's guaranteed < p without rejection sampling.
///
/// This is the single per-note randomness field in the v2 construction
/// (`commitment_from_fields_v2`). The `role` byte distinguishes the six note
/// roles (buyer/seller change, buyer/seller trade output, base/quote fee).
pub fn derive_inner(match_id: u64, role: u8) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_INNER);
    hasher.update(match_id.to_le_bytes());
    hasher.update([role]);
    let mut out: [u8; 32] = hasher.finalize().into();
    // BN254 Fr safety — same mask as the on-chain and TS sides.
    out[0] = 0;
    out[1] &= 0x0f;
    out
}

// ─────── Self-tests (algorithm-level only) ──────────────────────────────────
//
// Cross-language parity tests live in tests/change_note_parity.rs.
// These #[cfg(test)] sanity checks just verify shape + determinism
// of THIS implementation.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inner_is_deterministic() {
        assert_eq!(
            derive_inner(42, CHANGE_ROLE_BUYER),
            derive_inner(42, CHANGE_ROLE_BUYER)
        );
    }

    #[test]
    fn buyer_and_seller_differ() {
        assert_ne!(
            derive_inner(42, CHANGE_ROLE_BUYER),
            derive_inner(42, CHANGE_ROLE_SELLER),
            "different role bytes must yield different outputs"
        );
    }

    #[test]
    fn match_id_changes_output() {
        assert_ne!(
            derive_inner(42, CHANGE_ROLE_BUYER),
            derive_inner(43, CHANGE_ROLE_BUYER),
            "different match_id must yield different outputs"
        );
    }

    #[test]
    fn all_six_roles_are_distinct() {
        // For one match_id, every role must produce a distinct inner_hash —
        // a collision would alias two notes onto the same opening.
        let mid = 42u64;
        let roles = [
            CHANGE_ROLE_BUYER,
            CHANGE_ROLE_SELLER,
            TRADE_ROLE_BUYER,
            TRADE_ROLE_SELLER,
            FEE_ROLE_BASE,
            FEE_ROLE_QUOTE,
        ];
        let inners: Vec<[u8; 32]> = roles.iter().map(|&r| derive_inner(mid, r)).collect();
        for i in 0..inners.len() {
            for j in (i + 1)..inners.len() {
                assert_ne!(
                    inners[i], inners[j],
                    "role {:#x} and {:#x} produced colliding inner_hashes",
                    roles[i], roles[j]
                );
            }
        }
    }

    #[test]
    fn output_is_bn254_fr_safe() {
        for &mid in &[0u64, 1, 42, u64::MAX] {
            for &role in &[
                CHANGE_ROLE_BUYER,
                CHANGE_ROLE_SELLER,
                TRADE_ROLE_BUYER,
                TRADE_ROLE_SELLER,
                FEE_ROLE_BASE,
                FEE_ROLE_QUOTE,
            ] {
                let n = derive_inner(mid, role);
                assert_eq!(n[0], 0, "inner byte 0 must be zero");
                assert_eq!(n[1] & 0xf0, 0, "inner byte 1 high nibble must be zero");
            }
        }
    }
}
