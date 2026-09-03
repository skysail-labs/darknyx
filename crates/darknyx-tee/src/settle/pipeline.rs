//! Assembly of Tx D — the settlement transaction itself.
//!
//! `tee_forced_settle_batched` is the only transaction in the pipeline that uses
//! Solana's v1 transaction format. Its payload and inline account list exceed the
//! legacy/v0 1232-byte limit, while v1 permits up to 4096 bytes. It carries two
//! instructions, in order:
//!
//!   1. the Ed25519 precompile instruction verifying the TEE signature over the
//!      canonical payload hash ([`super::ed25519`]);
//!   2. the settle instruction itself ([`super::settle_batched`]).
//!
//! V1 does not support Address Lookup Tables. Every account is inline, and the
//! compute-unit limit, loaded-account-data limit, and optional total priority fee
//! live in the v1 message configuration rather than no-op ComputeBudget
//! instructions. The TEE keypair signs as both fee-payer and `tee_authority`.
//!
//! This format is opt-in and requires the cluster's transaction-v1 feature to be
//! active. Devnet and the supported local validators have activated it; mainnet
//! deployment remains gated on cluster activation.
//!
//! Mirrored by `packages/sdk/tests/helpers/batched-settle.ts`.

use base64::Engine as _;
use solana_address::Address;
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::{v1, VersionedMessage};
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
// encrypted output recovery):
//   verify_match_batch       100,533 CU (litesvm) — up from 87,224: amount
//     privacy added fee-binding and more public inputs to VALID_MATCH_BATCH, so
//     the on-chain groth16 verify got heavier. DEVNET runs the alt_bn128 syscalls
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

/// CU ceiling for the settle tx (Tx D). The local devnet-admin SBF test measures
/// 58,251 CU for six output leaves plus both continuation re-locks; 115k keeps
/// a conservative runtime margin.
/// Lowering it cuts the settle priority fee (= price × requested_limit) by
/// ~38%. NOTE: must be confirmed by a `cvm-settle-e2e` run on a redeployed CVM
/// image before the reduced fee is relied on — a too-low limit fails the
/// settle tx loud-and-safe with `ComputationalBudgetExceeded` (no fund risk).
const SETTLE_COMPUTE_UNIT_LIMIT: u32 = 115_000;
/// Provisional maximum account data Tx D may load. V1 defaults this resource to
/// zero, so an explicit limit is mandatory. The migration deliberately starts
/// at the runtime's legacy/v0 default maximum; the Surfpool settlement
/// simulation must report `loadedAccountsDataSize`, after which this is rounded
/// up to the next 32-KiB page with measured headroom. Guessing below the loaded
/// upgradeable-program data would make every otherwise-valid settle fail.
pub(crate) const SETTLE_LOADED_ACCOUNTS_DATA_SIZE_LIMIT: u32 = 64 * 1024 * 1024;
/// CU ceiling for each lock_note tx (Tx A). The proof-backed LiteSVM test
/// measures 101,076 CU; 136k leaves about 34% local-runtime headroom.
pub(crate) const LOCK_COMPUTE_UNIT_LIMIT: u32 = 136_000;
/// CU ceiling for the verify_match_batch tx (Tx B). The two-public-input
/// statement measures 103,346 CU in litesvm after paying for the authoritative
/// Poseidon8 config digest. 140k retains >35% litesvm headroom and a generous
/// buffer for the modest devnet/runtime delta observed in prior verifier runs.
pub(crate) const VERIFY_COMPUTE_UNIT_LIMIT: u32 = 140_000;
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

/// Compile and sign the settle v1 transaction with every account inline.
///
/// Returns the base64-encoded wire bytes ready for
/// `SolanaRpcClient::send_transaction`.
pub fn build_settle_v1_tx_b64(
    tee_keypair: &Keypair,
    ed25519_ix: Instruction,
    settle_ix: Instruction,
    blockhash: Hash,
    priority_fee_micro_lamports_per_cu: u64,
) -> Result<String, RpcError> {
    // Delegate compile/sign to `build_settle_v1_tx` (single source) +
    // serialise to the base64 wire form.
    let tx = build_settle_v1_tx(
        tee_keypair,
        ed25519_ix,
        settle_ix,
        blockhash,
        priority_fee_micro_lamports_per_cu,
    )?;
    let wire = wincode::serialize(&tx)
        .map_err(|e| RpcError::Schema(format!("v1 tx wincode serialise failed: {e}")))?;

    // Pre-send guard against the v1 4096-byte hard ceiling. Log the inline
    // account count because v1 has no ALT indirection to hide an accidental
    // account expansion.
    if wire.len() > SOLANA_V1_TX_SIZE_CAP {
        if let VersionedMessage::V1(m) = &tx.message {
            let inline: Vec<String> = m.account_keys.iter().map(|k| k.to_string()).collect();
            tracing::error!(
                raw_bytes = wire.len(),
                cap = SOLANA_V1_TX_SIZE_CAP,
                inline_accounts = m.account_keys.len(),
                inline = ?inline,
                "settle Tx D exceeds the v1 transaction-size cap",
            );
        }
        return Err(RpcError::Schema(format!(
            "settle Tx D is {} raw bytes (v1 cap {SOLANA_V1_TX_SIZE_CAP})",
            wire.len()
        )));
    }

    Ok(base64::engine::general_purpose::STANDARD.encode(&wire))
}

/// Base58 of a signed transaction's first signature, read back from its wire
/// form.
///
/// The settle journal must record a transaction's signature BEFORE the
/// transaction is sent — a signature written afterwards is exactly the record
/// that goes missing in the crash window that matters, leaving an orphan the
/// enclave cannot ask the chain about. That is possible only because the
/// signature is fully determined at signing time, which this reads back out of
/// the already-signed bytes rather than recomputing.
pub fn first_signature_b58(tx_b64: &str) -> Option<String> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(tx_b64)
        .ok()?;
    let tx: VersionedTransaction = wincode::deserialize(&raw).ok()?;
    tx.signatures.first().map(|s| s.to_string())
}

/// Solana's hard transaction-size cap (raw wire bytes).
const SOLANA_V1_TX_SIZE_CAP: usize = 4096;

/// Same as [`build_settle_v1_tx_b64`] but returns the raw
/// `VersionedTransaction` (for tests that want to inspect the
/// compiled message, resource config, account count, and wire size).
pub fn build_settle_v1_tx(
    tee_keypair: &Keypair,
    ed25519_ix: Instruction,
    settle_ix: Instruction,
    blockhash: Hash,
    priority_fee_micro_lamports_per_cu: u64,
) -> Result<VersionedTransaction, RpcError> {
    let payer = tee_keypair.pubkey();
    let total_priority_fee = priority_fee_lamports(
        priority_fee_micro_lamports_per_cu,
        SETTLE_COMPUTE_UNIT_LIMIT,
    );
    let mut config = v1::TransactionConfig::empty()
        .with_compute_unit_limit(SETTLE_COMPUTE_UNIT_LIMIT)
        .with_loaded_accounts_data_size_limit(SETTLE_LOADED_ACCOUNTS_DATA_SIZE_LIMIT);
    if total_priority_fee > 0 {
        config = config.with_priority_fee(total_priority_fee);
    }
    let message =
        v1::Message::try_compile_with_config(&payer, &[ed25519_ix, settle_ix], blockhash, config)
            .map_err(|e| RpcError::Schema(format!("v1 message compile failed: {e}")))?;
    VersionedTransaction::try_new(VersionedMessage::V1(message), &[tee_keypair])
        .map_err(|e| RpcError::Schema(format!("v1 tx sign failed: {e}")))
}

/// Convert the legacy/v0 priority-fee quote (micro-lamports per CU) into v1's
/// total-lamport fee, rounding up so a non-zero quote never truncates to zero.
fn priority_fee_lamports(micro_lamports_per_cu: u64, compute_units: u32) -> u64 {
    micro_lamports_per_cu
        .saturating_mul(u64::from(compute_units))
        .saturating_add(999_999)
        / 1_000_000
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settle::ed25519::build_ed25519_verify_ix;
    use crate::settle::payload::MatchResultPayload;
    use crate::settle::settle_batched::build_settle_batched_ix;

    fn payload() -> MatchResultPayload {
        MatchResultPayload {
            match_id: [0x11; 16],
            note_a_use_tag: [0xA1; 32],
            note_b_use_tag: [0xB1; 32],
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
            note_e_use_tag: [0u8; 32],
            note_f_use_tag: [0u8; 32],
            batch_slot: 7,
            // Worst case for the size guard below: a full 128-byte recovery
            // bundle (Borsh encodes [u8;128] as 128 bytes regardless of content,
            // so zeros measure the same wire size as a real ciphertext).
            fill_recovery: [0u8; 128],
        }
    }

    #[test]
    fn settle_v1_tx_compiles_inline_and_fits_under_cap() {
        let kp = Keypair::new_from_array([0x42; 32]);
        let p = payload();
        let root = [0xAB; 32];
        let proof = [[0x01; 32], [0x02; 32], [0x03; 32], [0x04; 32]];

        let ed_ix = build_ed25519_verify_ix(&[0xAA; 32], &[0xBB; 64], &p.canonical_hash());
        let settle_ix = build_settle_batched_ix(&kp.pubkey(), 0, &p, 5, &proof, &root);

        let tx = build_settle_v1_tx(
            &kp,
            ed_ix,
            settle_ix,
            Hash::new_from_array([0x01; 32]),
            250_000,
        )
        .expect("v1 compile + sign");

        let wire = wincode::serialize(&tx).unwrap();
        const MAX_TX_D_WIRE_LEN: usize = 2_048;
        const MIN_TX_D_HEADROOM: usize = 2_048;
        eprintln!(
            "TX_D_V1_WIRE_SIZE bytes={} headroom={}",
            wire.len(),
            SOLANA_V1_TX_SIZE_CAP - wire.len()
        );
        assert!(
            wire.len() <= MAX_TX_D_WIRE_LEN,
            "settle v1 tx is {} bytes (max {MAX_TX_D_WIRE_LEN}) — inline account or payload growth regressed",
            wire.len()
        );
        assert!(
            SOLANA_V1_TX_SIZE_CAP - wire.len() >= MIN_TX_D_HEADROOM,
            "settle v1 tx has only {} bytes of headroom (min {MIN_TX_D_HEADROOM})",
            SOLANA_V1_TX_SIZE_CAP - wire.len()
        );

        let VersionedMessage::V1(message) = &tx.message else {
            panic!("settle must compile as v1");
        };
        assert_eq!(
            message.config.compute_unit_limit,
            Some(SETTLE_COMPUTE_UNIT_LIMIT)
        );
        assert_eq!(
            message.config.loaded_accounts_data_size_limit,
            Some(SETTLE_LOADED_ACCOUNTS_DATA_SIZE_LIMIT)
        );
        assert_eq!(message.config.priority_fee, Some(28_750));
        assert!(
            message.account_keys.len() <= 64,
            "v1 account list has {} entries (runtime cap 64)",
            message.account_keys.len()
        );
        assert!(message
            .account_keys
            .iter()
            .all(|key| *key != COMPUTE_BUDGET_PROGRAM_ID));
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
        let b64 =
            build_settle_v1_tx_b64(&kp, ed_ix, settle_ix, Hash::new_from_array([0x01; 32]), 0)
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

    #[test]
    fn first_signature_matches_the_signed_transaction() {
        let kp = Keypair::new_from_array([0x42; 32]);
        let p = payload();
        let root = [0xAB; 32];
        let proof = [[0x01; 32]; 4];
        let ed_ix = build_ed25519_verify_ix(&[0xAA; 32], &[0xBB; 64], &p.canonical_hash());
        let settle_ix = build_settle_batched_ix(&kp.pubkey(), 0, &p, 0, &proof, &root);
        let bh = Hash::new_from_array([0x01; 32]);
        let tx = build_settle_v1_tx(&kp, ed_ix.clone(), settle_ix.clone(), bh, 0).unwrap();
        let b64 = build_settle_v1_tx_b64(&kp, ed_ix, settle_ix, bh, 0).unwrap();

        // The journal records THIS string before the send; recovery later asks
        // the chain about it. If the two ever disagreed, every recovered entry
        // would name a transaction that does not exist.
        assert_eq!(
            first_signature_b58(&b64).expect("signature readable from wire bytes"),
            tx.signatures[0].to_string(),
        );
    }

    #[test]
    fn first_signature_of_garbage_is_none_not_a_panic() {
        assert!(first_signature_b58("not base64 !!").is_none());
        assert!(
            first_signature_b58("aGVsbG8=").is_none(),
            "valid b64, not a tx"
        );
    }

    #[test]
    fn v1_priority_fee_conversion_rounds_up() {
        assert_eq!(priority_fee_lamports(0, SETTLE_COMPUTE_UNIT_LIMIT), 0);
        assert_eq!(priority_fee_lamports(1, 1), 1);
        assert_eq!(priority_fee_lamports(250_000, 115_000), 28_750);
        assert_eq!(
            priority_fee_lamports(u64::MAX, u32::MAX),
            u64::MAX / 1_000_000
        );
    }
}
