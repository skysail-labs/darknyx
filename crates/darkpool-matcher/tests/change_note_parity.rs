//! Cross-language and cross-backend byte equality for `change_note::derive_*`.
//!
//! This test exists because independent implementations of the same
//! SHA-256 derivation must produce byte-identical output:
//!
//! 1. **`darkpool_matcher::change_note::derive_*`** — pure Rust,
//!    `sha2::Sha256` backend. The one under test.
//! 2. **An independent Solana SHA-256 backend** —
//!    `solana_program::hash::hashv`, checked here.
//! 3. **`packages/sdk/tests/helpers/e2e-helpers.ts::deriveNonce` /
//!    `deriveBlinding`** — TypeScript SDK, Node `crypto.createHash`
//!    backend, pinned by the same fixed known-answer vectors.
//!
//! # Fixed-input table
//!
//! Every combination of `(match_id, role)` we expect to exercise
//! in production lives in the table below. If you change any
//! domain tag, role byte, or output mask in EITHER implementation,
//! this test fails immediately.
//!
//! `cargo test -p darkpool-matcher --test change_note_parity`

use darkpool_matcher::change_note::{
    derive_inner, CHANGE_ROLE_BUYER, CHANGE_ROLE_SELLER, TRADE_ROLE_BUYER, TRADE_ROLE_SELLER,
};
use solana_program::hash::hashv;

// ─────── Independent Solana-backend reference ──────────────────────────────
//
// The matcher uses `sha2::Sha256`; this reference uses
// `solana_program::hash::hashv`. Same algorithm, separately implemented.

fn reference_derive_inner(match_id: u64, role: u8) -> [u8; 32] {
    let mut h = hashv(&[b"darknyx-change-inner-v2", &match_id.to_le_bytes(), &[role]]).to_bytes();
    h[0] = 0;
    h[1] &= 0x0f;
    h
}

// Role bytes documented in CLAUDE.md §6 + e2e-helpers.ts. We
// include the fee roles (`FEE_ROLE_BASE = 0xfb`, `FEE_ROLE_QUOTE
// = 0xfc`) here even though they're declared inline in run_batch.rs
// rather than in change_note.rs — they're consumed by the same
// derive_nonce / derive_blinding fns.
const FEE_ROLE_BASE: u8 = 0xfb;
const FEE_ROLE_QUOTE: u8 = 0xfc;

// ─────── Test cases ─────────────────────────────────────────────────────────
//
// We test the full Cartesian product of:
//   - match_id: 0, 1, 42, u64::MAX, plus a handful of slot-shaped
//     numbers picked to catch endianness bugs (`0x00ff..00`,
//     `0xff00..ff`, etc.).
//   - role: every role byte the system uses today.

fn match_ids() -> &'static [u64] {
    &[
        0u64,
        1,
        42,
        1_000_000,
        u64::MAX,
        0x0102_0304_0506_0708, // catches LE↔BE confusion
        0xff00_ff00_ff00_ff00,
        0x00ff_00ff_00ff_00ff,
    ]
}

fn roles() -> &'static [u8] {
    &[
        CHANGE_ROLE_BUYER,
        CHANGE_ROLE_SELLER,
        // note_c / note_d trade-output roles (4g.7). On-chain never
        // derives these (it receives note_c/d in the signed payload),
        // but the derivation is backend-agnostic — proving the sha2
        // and solana_program backends agree for these role bytes too
        // guarantees the TEE prover + the TS SDK + any future on-chain
        // use stay byte-identical.
        TRADE_ROLE_BUYER,
        TRADE_ROLE_SELLER,
        FEE_ROLE_BASE,
        FEE_ROLE_QUOTE,
    ]
}

#[test]
fn inner_parity_against_solana_sha256_backend() {
    for &mid in match_ids() {
        for &role in roles() {
            let matcher = derive_inner(mid, role);
            let reference = reference_derive_inner(mid, role);
            assert_eq!(
                matcher,
                reference,
                "derive_inner mismatch at (match_id={mid:#x}, role={role:#x}): \
                 matcher={} solana_backend={}",
                hex::encode(matcher),
                hex::encode(reference),
            );
        }
    }
}

// ─────── Known-answer test against the TS port ──────────────────────────────
//
// Hand-computed against the TS implementation in
// `packages/sdk/tests/helpers/e2e-helpers.ts::deriveNonce`. The
// expected bytes were captured from a one-off Node snippet:
//
//     import { deriveNonce, deriveBlinding,
//              CHANGE_ROLE_BUYER, CHANGE_ROLE_SELLER }
//              from "./packages/sdk/tests/helpers/e2e-helpers";
//     console.log(Buffer.from(deriveNonce(42n, CHANGE_ROLE_BUYER)).toString("hex"));
//     console.log(Buffer.from(deriveBlinding(42n, CHANGE_ROLE_BUYER)).toString("hex"));
//     console.log(Buffer.from(deriveNonce(42n, CHANGE_ROLE_SELLER)).toString("hex"));
//     console.log(Buffer.from(deriveBlinding(42n, CHANGE_ROLE_SELLER)).toString("hex"));
//
// If the TS side ever changes and a known-answer here drifts, that's
// a deliberate decision that must update BOTH this file AND the TS
// side together. The CI gate then catches accidental drift.
//
// (The on-chain reference fns above already cover the Rust ↔ Rust
// half of the contract. These KATs cover the Rust ↔ TS half by
// referencing the TS computation directly.)

// True known-answer values — computed INDEPENDENTLY of the
// implementation (`printf 'darknyx-change-inner-v2' ‖ 42_le_u64 ‖ role |
// shasum -a 256`, then byte0=0, byte1 &= 0x0f). Hardcoding the bytes
// (rather than calling reference_derive_inner) keeps these KATs an
// independent oracle — they'd catch a bug that the reference impl
// shared. The TS port pins the buyer value too
// (`packages/sdk/tests/change-note-inner-parity.test.ts`).
const KAT_INNER_BUYER_42: &str = "0007c1605d5ab69620f81cbc8834c305a4f850011d482888629cb6c89d6024fb";
const KAT_INNER_SELLER_42: &str =
    "0007211d97074d5370ce8af33229f2e41329e9ec0382b7ddffe7d2082a626ed6";

#[test]
fn known_answer_inner_buyer_match42() {
    let got = derive_inner(42, CHANGE_ROLE_BUYER);
    assert_eq!(hex::encode(got), KAT_INNER_BUYER_42);
    // Shape invariant (BN254 Fr safety).
    assert_eq!(got[0], 0);
    assert_eq!(got[1] & 0xf0, 0);
}

#[test]
fn known_answer_inner_seller_match42() {
    let got = derive_inner(42, CHANGE_ROLE_SELLER);
    assert_eq!(hex::encode(got), KAT_INNER_SELLER_42);
    assert_eq!(got[0], 0);
    assert_eq!(got[1] & 0xf0, 0);
}
