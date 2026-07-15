//! Settle-tx assembly — the v0 (versioned) transaction that
//! carries Tx D.
//!
//! `tee_forced_settle_batched` is the one tx in the pipeline that
//! must be a v0 transaction stacking Address Lookup Tables to fit
//! under the 1232-byte cap (CLAUDE.md §5). It bundles TWO
//! instructions:
//!   1. the Ed25519 precompile ix (the TEE signature over the
//!      canonical payload hash — [`super::ed25519`]);
//!   2. the settle ix itself ([`super::settle_batched`]).
//!
//! Both are compiled into a `v0::Message` referencing the static
//! settle ALT (created once at devnet-setup: vault_config,
//! instructions_sysvar, system_program) + the per-batch ALT
//! (created by Tx C: note_lock_a/b/e/f + batch_validity_marker).
//! The result is signed by the TEE keypair (fee-payer +
//! tee_authority) and base64-encoded for `sendTransaction`.
//!
//! Mirrors `packages/sdk/tests/helpers/batched-settle.ts`'s v0 tx
//! assembly.

use base64::Engine as _;
use solana_address::Address;
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::{v0, AddressLookupTableAccount, VersionedMessage};
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;

use crate::solana_rpc::RpcError;

/// Solana ComputeBudget program id
/// (`ComputeBudget111111111111111111111111111111`).
const COMPUTE_BUDGET_PROGRAM_ID: Address = Address::new_from_array([
    0x03, 0x06, 0x46, 0x6f, 0xe5, 0x21, 0x17, 0x32, 0xff, 0xec, 0xad, 0xba, 0x72, 0xc3, 0x9b, 0xe7,
    0xbc, 0x8c, 0xe5, 0xbb, 0xc5, 0xf7, 0x12, 0x6b, 0x2c, 0x43, 0x9b, 0x3a, 0x40, 0x00, 0x00, 0x00,
]);

// ── Per-tx CU limits (right-sized from measured `unitsConsumed`) ──
//
// Every settle-path tx requests an explicit ComputeUnitLimit sized to its
// measured worst-case consumption + 15% headroom (×1.15), replacing the old
// blanket 1.4M on the settle tx (and the implicit 200k/ix default on the rest).
// A tight limit is the prerequisite for priority fees: the prioritization fee
// is `compute_unit_price × requested_limit`, so an over-requested limit
// overpays for the same per-CU bid AND packs worse into a block's CU budget.
//
// 15% is enough because every settle-path ix's CU is DETERMINISTIC:
//   - verify/lock/close are fixed work (N=16 groth16; a fixed 26-level Merkle
//     inclusion check; a PDA close).
//   - settle's `append_leaf` (merkle.rs) does exactly MERKLE_DEPTH (26)
//     poseidon2 hashes PER LEAF unconditionally — constant per leaf, no
//     index/tree-fill dependence — so the only variable is leaf count, which
//     tops out at 5 (note_c/d + buyer change + base/quote fee). The 5-leaf
//     worst case is a hard, stable ceiling (162,145), not a moving target.
//
// Measured 2026-06-08 (image tee-v3-hardening-20):
//   lock_note               117,943 CU (devnet, fixed 26-level Merkle path)
//   tee_forced_settle_batched 162,145 CU (devnet, WORST case: 5 leaves appended
//                                          = note_c/d + buyer change + 2 fee notes;
//                                          litesvm 2-leaf path is ~100k)
//   close_batch_validity_marker 3,546 CU (litesvm)
//
// Re-measured 2026-06-23 (image tee-v3-hardening-40, post amount-privacy +
// change-amount-recovery):
//   verify_match_batch       100,533 CU (litesvm) — up from 87,224: amount-privacy
//     (P1b) added fee-binding + more public inputs to VALID_MATCH_BATCH, so the
//     on-chain groth16 verify got heavier. DEVNET runs the alt_bn128 syscalls
//     HOTTER than litesvm (a -39 deploy with a 101,000 limit died
//     `ComputationalBudgetExceeded` at ~100,850), so the on-chain limit carries
//     a generous margin over the litesvm figure — NOT the usual ×1.15.
//   tee_forced_settle_batched 93,542 CU (litesvm 2-leaf) — v8's +128B fill_recovery
//     adds only one extra SHA-256 block to the on-chain canonical-hash recompute;
//     the devnet 5-leaf worst case stays well under SETTLE_COMPUTE_UNIT_LIMIT.
//
// Re-measured 2026-06-28 (audit_1 "CU-1" batch-append + "CU-2" load dedupe,
// vault commits 959c500 + 3d84c8c):
//   tee_forced_settle_batched is no longer linear in leaf count. `merkle.rs`
//   now appends the up-to-6 output leaves in ONE bottom-up pass
//   (`append_leaves`) that shares the Merkle-path recomputation, so a full
//   settle costs roughly a single leaf-walk instead of 6×20 poseidon2. Litesvm
//   (== devnet for this poseidon-syscall-bound ix; the old 162,145 figure
//   matched the litesvm extrapolation):
//     2-leaf settle                 93,112 → 77,033
//     6-leaf settle (no relock)    165,355 → 80,129
//     6-leaf + 2 relock (TRUE worst) ~175,600 → 90,381
//   The true worst case (all 6 output notes + both continuation re-lock CPIs)
//   is now 90,381 — guarded by `cu_profile_worst_case_settle` in
//   programs/vault/tests/tee_forced_settle_batched.rs.
//
// Re-measured 2026-07-15 after settlement payload v9 removed 64 signed/wire
// bytes (current branch, devnet-admin SBF consumed by litesvm):
//   2-leaf settle                 63,172 CU
//   6-leaf + 2 relock worst case 78,388 CU
// The 115k ceiling therefore retains >31% margin against its own limit and
// >46% margin over measured consumption.
// (Stale-comment fix: MERKLE_DEPTH is 20, not 26 as the 2026-06-08 notes said.)
// Regression-guarded by the `CU_PROFILE`/assert lines in
// programs/vault/tests/{match_batch_verify,tee_forced_settle_batched}.rs.

/// CU ceiling for the settle tx (Tx D). Post-CU-1 the true worst case (6
/// output leaves + both continuation re-locks) is 78,388 after payload v9;
/// 115k leaves a deliberately conservative >46% margin over that measurement.
/// Lowering it cuts the settle priority fee (= price × requested_limit) by
/// ~38%. NOTE: must be confirmed by a `cvm-settle-e2e` run on a redeployed CVM
/// image before the reduced fee is relied on — a too-low limit fails the
/// settle tx loud-and-safe with `ComputationalBudgetExceeded` (no fund risk).
const SETTLE_COMPUTE_UNIT_LIMIT: u32 = 115_000;
/// CU ceiling for each lock_note tx (Tx A). 117,943 × 1.15.
pub(crate) const LOCK_COMPUTE_UNIT_LIMIT: u32 = 136_000;
/// CU ceiling for the verify_match_batch tx (Tx B). litesvm measures 100,533;
/// devnet's groth16 runs hotter (a 101,000 limit exceeded budget on devnet), so
/// this carries ~1.4× headroom over the litesvm figure rather than the usual ×1.15.
// VALID_MATCH_BATCH v3 verifies eight public inputs (up from three). LiteSVM
// measures ~132.5k CU; 180k preserves >20% headroom and leaves room for the
// modest devnet/runtime delta observed in prior verifier measurements.
pub(crate) const VERIFY_COMPUTE_UNIT_LIMIT: u32 = 180_000;
// (The close_batch_validity_marker tx (Tx E) no longer rides the settle worker's
// budgeted path — it's closed asynchronously by `marker_sweep`, which packs
// several closes per tx under the default CU budget. The old per-close
// CLOSE_COMPUTE_UNIT_LIMIT const was removed with the inline close.)

/// Build a `ComputeBudget::SetComputeUnitLimit` ix (variant tag 2,
/// then the u32 limit LE).
pub(crate) fn set_compute_unit_limit_ix(units: u32) -> Instruction {
    let mut data = Vec::with_capacity(5);
    data.push(2u8);
    data.extend_from_slice(&units.to_le_bytes());
    Instruction {
        program_id: COMPUTE_BUDGET_PROGRAM_ID,
        accounts: vec![],
        data,
    }
}

/// Build a `ComputeBudget::SetComputeUnitPrice` ix (variant tag 3,
/// then the u64 micro-lamports-per-CU price LE). The priority fee paid is
/// `price × requested_compute_unit_limit / 1_000_000` lamports — which is why
/// the per-tx limits are right-sized (see the CU-limit block above).
pub(crate) fn set_compute_unit_price_ix(micro_lamports_per_cu: u64) -> Instruction {
    let mut data = Vec::with_capacity(9);
    data.push(3u8);
    data.extend_from_slice(&micro_lamports_per_cu.to_le_bytes());
    Instruction {
        program_id: COMPUTE_BUDGET_PROGRAM_ID,
        accounts: vec![],
        data,
    }
}

/// The ComputeBudget ixs every settle-path tx prepends: the right-sized CU
/// `limit`, plus a `SetComputeUnitPrice` at `priority_fee` when non-zero (a
/// quiet network bids 0 → no price ix, identical to the pre-priority-fee shape).
pub(crate) fn budget_ixs(limit: u32, priority_fee: u64) -> Vec<Instruction> {
    let mut v = Vec::with_capacity(2);
    v.push(set_compute_unit_limit_ix(limit));
    if priority_fee > 0 {
        v.push(set_compute_unit_price_ix(priority_fee));
    }
    v
}

/// Compile + sign the settle v0 transaction. `alts` is the static
/// settle ALT followed by the per-batch ALT (order doesn't matter
/// for resolution, but convention is static-first).
///
/// Returns the base64-encoded wire bytes ready for
/// `SolanaRpcClient::send_transaction`.
pub fn build_settle_v0_tx_b64(
    tee_keypair: &Keypair,
    ed25519_ix: Instruction,
    settle_ix: Instruction,
    alts: &[AddressLookupTableAccount],
    blockhash: Hash,
) -> Result<String, RpcError> {
    // Delegate compile/sign to `build_settle_v0_tx` (single source) +
    // serialise to the base64 wire form.
    let tx = build_settle_v0_tx(tee_keypair, ed25519_ix, settle_ix, alts, blockhash)?;
    let wire = bincode::serialize(&tx)
        .map_err(|e| RpcError::Schema(format!("v0 tx bincode serialise failed: {e}")))?;

    // Pre-send size guard. The settle tx rides near the 1232-byte cap; if an
    // account that SHOULD be ALT-referenced fell inline (e.g. a per-batch ALT
    // that didn't cover this batch's PDAs), the RPC rejects it post-send with an
    // opaque -32602. Catch it here + log WHICH accounts are inline (static keys)
    // vs ALT-looked-up, so the failure names its cause instead of a byte count.
    if wire.len() > SOLANA_TX_SIZE_CAP {
        if let VersionedMessage::V0(m) = &tx.message {
            let inline: Vec<String> = m.account_keys.iter().map(|k| k.to_string()).collect();
            let alt_lookups: usize = m
                .address_table_lookups
                .iter()
                .map(|l| l.writable_indexes.len() + l.readonly_indexes.len())
                .sum();
            tracing::error!(
                raw_bytes = wire.len(),
                cap = SOLANA_TX_SIZE_CAP,
                inline_accounts = m.account_keys.len(),
                alt_lookups,
                alts_passed = alts.len(),
                inline = ?inline,
                "settle Tx D over the 1232-byte cap — accounts that should be \
                 ALT-referenced are inline; check the per-batch ALT covers this \
                 batch's locks/consumed PDAs",
            );
        }
        return Err(RpcError::Schema(format!(
            "settle Tx D is {} raw bytes (cap {SOLANA_TX_SIZE_CAP}); too many inline accounts \
             — per-batch ALT likely missing this batch's PDAs",
            wire.len()
        )));
    }

    Ok(base64::engine::general_purpose::STANDARD.encode(&wire))
}

/// Solana's hard transaction-size cap (raw wire bytes).
const SOLANA_TX_SIZE_CAP: usize = 1232;

/// Same as [`build_settle_v0_tx_b64`] but returns the raw
/// `VersionedTransaction` (for tests that want to inspect the
/// compiled message — account count, ALT lookups, wire size).
///
/// NOTE: the settle tx (Tx D) deliberately carries only the right-sized
/// `SetComputeUnitLimit` ix. Payload v9 restores at least 112 bytes of wire
/// headroom; keeping the price ix off Tx D preserves that regression margin.
/// Tx D confirmation latency is bound by per-batch ALT activation, not by
/// priority (a fee cannot make a leader load an ALT that is not rooted yet).
/// Priority fees remain on the other settle-path transactions.
pub fn build_settle_v0_tx(
    tee_keypair: &Keypair,
    ed25519_ix: Instruction,
    settle_ix: Instruction,
    alts: &[AddressLookupTableAccount],
    blockhash: Hash,
) -> Result<VersionedTransaction, RpcError> {
    let payer = tee_keypair.pubkey();
    // ComputeBudget limit ix first so the right-sized CU limit applies to the
    // whole tx; then the ed25519 precompile + the settle ix. No price ix — see
    // the doc comment (1232-byte cap).
    let cu_ix = set_compute_unit_limit_ix(SETTLE_COMPUTE_UNIT_LIMIT);
    let message =
        v0::Message::try_compile(&payer, &[cu_ix, ed25519_ix, settle_ix], alts, blockhash)
            .map_err(|e| RpcError::Schema(format!("v0 message compile failed: {e}")))?;
    VersionedTransaction::try_new(VersionedMessage::V0(message), &[tee_keypair])
        .map_err(|e| RpcError::Schema(format!("v0 tx sign failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settle::alt::alt_account;
    use crate::settle::ed25519::build_ed25519_verify_ix;
    use crate::settle::payload::MatchResultPayload;
    use crate::settle::settle_batched::{
        build_settle_batched_ix, per_batch_alt_addresses, static_alt_addresses,
    };
    use solana_address::Address;

    fn payload() -> MatchResultPayload {
        MatchResultPayload {
            match_id: [0x11; 16],
            note_a_commitment: [0xA1; 32],
            note_b_commitment: [0xB1; 32],
            note_c_commitment: [0xC1; 32],
            note_d_commitment: [0xD1; 32],
            note_e_commitment: [0xE1; 32],
            note_f_commitment: [0xF1; 32],
            order_id_a: [0x01; 16],
            order_id_b: [0x02; 16],
            note_fee_base_commitment: [0; 32],
            note_fee_quote_commitment: [0; 32],
            buyer_relock_order_id: [0; 16],
            buyer_relock_expiry: 0,
            seller_relock_order_id: [0; 16],
            seller_relock_expiry: 0,
            batch_slot: 7,
            // Worst case for the size guard below: a full 128-byte recovery
            // bundle (Borsh encodes [u8;128] as 128 bytes regardless of content,
            // so zeros measure the same wire size as a real ciphertext).
            fill_recovery: [0u8; 128],
        }
    }

    #[test]
    fn settle_v0_tx_compiles_and_fits_under_cap() {
        let kp = Keypair::new_from_array([0x42; 32]);
        let p = payload();
        let root = [0xAB; 32];
        let proof = [[0x01; 32], [0x02; 32], [0x03; 32], [0x04; 32]];

        let ed_ix = build_ed25519_verify_ix(&[0xAA; 32], &[0xBB; 64], &p.canonical_hash());
        let settle_ix = build_settle_batched_ix(&kp.pubkey(), 0, &p, 5, &proof, &root);

        // Production stacks BOTH ALTs (worker.rs): the static settle ALT
        // (vault_config + sysvar + system program + K merkle_tree shards) under
        // the per-batch ALT (the 5 derivable PDAs). Both are needed to keep the
        // worst-case (change-note, no PDA dedup) settle tx under 1120 bytes.
        let static_alt = alt_account(Address::new_from_array([0x44; 32]), static_alt_addresses(4));
        let alt = alt_account(
            Address::new_from_array([0x55; 32]),
            per_batch_alt_addresses(&p, &root),
        );

        let tx = build_settle_v0_tx(
            &kp,
            ed_ix,
            settle_ix,
            &[static_alt, alt],
            Hash::new_from_array([0x01; 32]),
        )
        .expect("v0 compile + sign");

        // This is the worst case: distinct change notes, all accounts present,
        // a full recovery bundle, four tree shards in the static ALT, and both
        // production ALTs. Payload v9 removes 64 vestigial nullifier bytes.
        // Pin both the target size and the resulting Solana packet headroom.
        let wire = bincode::serialize(&tx).unwrap();
        const MAX_TX_D_WIRE_LEN: usize = 1120;
        const MIN_TX_D_HEADROOM: usize = 112;
        eprintln!(
            "TX_D_WIRE_SIZE_V9 bytes={} headroom={}",
            wire.len(),
            SOLANA_TX_SIZE_CAP - wire.len()
        );
        assert!(
            wire.len() <= MAX_TX_D_WIRE_LEN,
            "settle v0 tx is {} bytes (max {MAX_TX_D_WIRE_LEN}) — payload or ALT headroom regressed",
            wire.len()
        );
        assert!(
            SOLANA_TX_SIZE_CAP - wire.len() >= MIN_TX_D_HEADROOM,
            "settle v0 tx has only {} bytes of headroom (min {MIN_TX_D_HEADROOM})",
            SOLANA_TX_SIZE_CAP - wire.len()
        );

        // It's a v0 message with one signature (the TEE keypair).
        assert!(matches!(tx.message, VersionedMessage::V0(_)));
        assert_eq!(tx.signatures.len(), 1);
    }

    #[test]
    fn b64_variant_produces_valid_base64() {
        let kp = Keypair::new_from_array([0x42; 32]);
        let p = payload();
        let root = [0xAB; 32];
        let proof = [[0x01; 32]; 4];
        let ed_ix = build_ed25519_verify_ix(&[0xAA; 32], &[0xBB; 64], &p.canonical_hash());
        let settle_ix = build_settle_batched_ix(&kp.pubkey(), 0, &p, 0, &proof, &root);
        // Both ALTs (as production stacks them) — see the worst-case test above.
        // With the v8 +128 recovery bundle the per-batch ALT alone overflows the
        // 1232 cap, so the static ALT is required here too.
        let static_alt = alt_account(Address::new_from_array([0x44; 32]), static_alt_addresses(4));
        let alt = alt_account(
            Address::new_from_array([0x55; 32]),
            per_batch_alt_addresses(&p, &root),
        );
        let b64 = build_settle_v0_tx_b64(
            &kp,
            ed_ix,
            settle_ix,
            &[static_alt, alt],
            Hash::new_from_array([0x01; 32]),
        )
        .unwrap();
        assert!(b64
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c)));
        // Decodes back to the same tx bytes.
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .unwrap();
        assert!(!decoded.is_empty());
    }
}
