//! Cross-language byte-equality parity for `change_note::derive_*`.
//!
//! This test exists because three independent implementations of the
//! same SHA-256 derivation must produce byte-identical output:
//!
//! 1. **`darkpool_matcher::change_note::derive_*`** — pure Rust,
//!    `sha2::Sha256` backend. The one under test.
//! 2. **`programs/matching_engine/src/state/change_note.rs::derive_*`**
//!    — on-chain Rust, `solana_program::hash::hashv` backend. Until
//!    PR 3 cuts the on-chain ix over to call us, this is the active
//!    on-chain implementation. We assert byte-equality against it
//!    HERE so PR 3's caller swap is provably safe.
//! 3. **`packages/sdk/tests/helpers/e2e-helpers.ts::deriveNonce` /
//!    `deriveBlinding`** — TypeScript SDK, Node `crypto.createHash`
//!    backend. Already gated by SDK tests (`change-note-flow.test.ts`)
//!    against the on-chain output; by virtue of transitivity, when
//!    THIS test passes, the matcher port is also byte-identical to
//!    the TS port.
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

// ─────── Reference (on-chain) implementation ────────────────────────────────
//
// Copy of the body in
// `programs/matching_engine/src/state/change_note.rs::derive_inner` so this
// test is dependency-free w.r.t. the matching_engine crate (we don't want to
// depend on Anchor here). It uses the `solana_program::hash::hashv` backend;
// the matcher port uses `sha2::Sha256`. Same algorithm → byte-identical, GATED
// here rather than assumed.

fn reference_derive_inner(match_id: u64, role: u8) -> [u8; 32] {
    let mut h = hashv(&[b"nyx-change-inner", &match_id.to_le_bytes(), &[role]]).to_bytes();
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
fn inner_parity_against_on_chain() {
    for &mid in match_ids() {
        for &role in roles() {
            let matcher = derive_inner(mid, role);
            let reference = reference_derive_inner(mid, role);
            assert_eq!(
                matcher,
                reference,
                "derive_inner mismatch at (match_id={mid:#x}, role={role:#x}): \
                 matcher={} on-chain={}",
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
// implementation (`printf 'nyx-change-inner' ‖ 42_le_u64 ‖ role |
// shasum -a 256`, then byte0=0, byte1 &= 0x0f). Hardcoding the bytes
// (rather than calling reference_derive_inner) keeps these KATs an
// independent oracle — they'd catch a bug that the reference impl
// shared. The TS port pins the buyer value too
// (`packages/sdk/tests/change-note-inner-parity.test.ts`).
const KAT_INNER_BUYER_42: &str = "0003e743eb441d6b6f5363d7ad169cf3b8dd6621303ed9d47cb14ddf05de286b";
const KAT_INNER_SELLER_42: &str =
    "000e6d1cff8251e672fb9b1f84257ea0884095de985dadb2b8b6d2616cf90179";

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
