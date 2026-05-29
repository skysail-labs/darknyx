//! Deterministic change-note derivation. Anchor-free port of
//! `programs/matching_engine/src/state/change_note.rs`.
//!
//! # Cross-language byte-equality contract
//!
//! These functions must produce byte-identical output to:
//!
//! * **The on-chain Rust** —
//!   `programs/matching_engine/src/state/change_note.rs::derive_nonce`
//!   / `derive_blinding`, which uses `solana_program::hash::hashv`.
//!   Pinned by `tests/change_note_parity.rs`.
//!
//! * **The TypeScript SDK** —
//!   `packages/sdk/tests/helpers/e2e-helpers.ts::deriveNonce` /
//!   `deriveBlinding`, which uses Node's `crypto.createHash("sha256")`.
//!   Pinned by ad-hoc fixtures in `change-note-flow.test.ts` and
//!   `devnet-trade-flow.test.ts`.
//!
//! All three implementations:
//!   1. SHA-256 over: `domain_tag ‖ match_id_le ‖ role_byte`
//!   2. Set output byte 0 = 0, output byte 1 &= 0x0f (BN254 Fr safety
//!      — keeps the 32-byte value strictly below the Fr modulus).
//!
//! The matcher port uses `sha2::Sha256` rather than
//! `solana_program::hash::hashv` because the latter is a Solana-only
//! crate. SHA-256 is the same algorithm under both backends, so the
//! output is byte-identical — but we GATE that with the parity test,
//! we don't ASSUME it.

use sha2::{Digest, Sha256};

// ─────── Role tags ──────────────────────────────────────────────────────────
//
// These constants MUST equal the on-chain consts at
// `programs/matching_engine/src/state/change_note.rs` AND the TS
// consts at `packages/sdk/tests/helpers/e2e-helpers.ts`.
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
// note_c / note_d are the full-fill output notes the buyer / seller
// receive; the fee notes hold the protocol's cut. Their (nonce,
// blinding) are derived the SAME way as the change notes — only the
// role byte differs — so the user (and the protocol, for fee notes)
// can re-derive the opening to spend the note later. Mirror of the TS
// SDK's `TRADE_ROLE_*` / `FEE_ROLE_*` in
// `packages/sdk/tests/helpers/e2e-helpers.ts`. Cross-language equality
// follows from the shared `derive_inner` body (already parity-pinned
// for the CHANGE roles by `tests/change_note_parity.rs`): same
// SHA-256(domain ‖ match_id_le ‖ role), only the role byte changes.

/// Role tag for the buyer's full-fill output note (`note_c`),
/// derived against `match_id`.
pub const TRADE_ROLE_BUYER: u8 = 0xC1;
/// Role tag for the seller's full-fill output note (`note_d`).
pub const TRADE_ROLE_SELLER: u8 = 0xD1;
/// Role tag for a base-asset protocol fee note, derived against the
/// settle slot (NOT match_id — fees flush per slot).
pub const FEE_ROLE_BASE: u8 = 0xFB;
/// Role tag for a quote-asset protocol fee note.
pub const FEE_ROLE_QUOTE: u8 = 0xFC;

// ─────── Domain tags ────────────────────────────────────────────────────────
//
// These bytes are the FIRST input to SHA-256 — they domain-separate
// nonce derivation from blinding derivation so the same `(match_id,
// role)` pair never produces colliding outputs across the two.

const DOMAIN_NONCE: &[u8] = b"nyx-change-nonce";
const DOMAIN_BLIND: &[u8] = b"nyx-change-blind";

// ─────── Derivation primitives ──────────────────────────────────────────────

/// Derive the change-note `nonce` (32 bytes) from `(match_id, role)`.
///
/// Output is masked to be a valid BN254 Fr element:
/// `out[0] = 0`, `out[1] &= 0x0f`. SHA-256 alone could produce a
/// 32-byte value ≥ p (the Fr modulus); the mask drops it into a
/// strict subset that's guaranteed < p without rejection sampling.
pub fn derive_nonce(match_id: u64, role: u8) -> [u8; 32] {
    derive_inner(DOMAIN_NONCE, match_id, role)
}

/// Derive the change-note blinding factor `r` from `(match_id, role)`.
/// Same shape as [`derive_nonce`] but with a distinct domain tag.
pub fn derive_blinding(match_id: u64, role: u8) -> [u8; 32] {
    derive_inner(DOMAIN_BLIND, match_id, role)
}

/// Shared body for both derivations. Kept private so callers must
/// go through the named entrypoints (which encode the domain tag).
fn derive_inner(domain: &[u8], match_id: u64, role: u8) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
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
    fn nonce_is_deterministic() {
        assert_eq!(
            derive_nonce(42, CHANGE_ROLE_BUYER),
            derive_nonce(42, CHANGE_ROLE_BUYER)
        );
    }

    #[test]
    fn blinding_is_deterministic() {
        assert_eq!(
            derive_blinding(42, CHANGE_ROLE_BUYER),
            derive_blinding(42, CHANGE_ROLE_BUYER)
        );
    }

    #[test]
    fn nonce_and_blinding_differ() {
        assert_ne!(
            derive_nonce(42, CHANGE_ROLE_BUYER),
            derive_blinding(42, CHANGE_ROLE_BUYER),
            "different domain tags must yield different outputs"
        );
    }

    #[test]
    fn buyer_and_seller_differ() {
        assert_ne!(
            derive_nonce(42, CHANGE_ROLE_BUYER),
            derive_nonce(42, CHANGE_ROLE_SELLER),
            "different role bytes must yield different outputs"
        );
    }

    #[test]
    fn all_six_roles_are_distinct() {
        // For one match_id, every role must produce a distinct nonce —
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
        let nonces: Vec<[u8; 32]> = roles.iter().map(|&r| derive_nonce(mid, r)).collect();
        for i in 0..nonces.len() {
            for j in (i + 1)..nonces.len() {
                assert_ne!(
                    nonces[i], nonces[j],
                    "role {:#x} and {:#x} produced colliding nonces",
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
                let n = derive_nonce(mid, role);
                let r = derive_blinding(mid, role);
                assert_eq!(n[0], 0, "nonce byte 0 must be zero");
                assert_eq!(r[0], 0, "blinding byte 0 must be zero");
                assert_eq!(n[1] & 0xf0, 0, "nonce byte 1 high nibble must be zero");
                assert_eq!(r[1] & 0xf0, 0, "blinding byte 1 high nibble must be zero");
            }
        }
    }
}
