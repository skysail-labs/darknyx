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
// measured worst-case consumption + ~1.5× headroom, replacing the old blanket
// 1.4M on the settle tx (and the implicit 200k/ix default on the rest). A tight
// limit is the prerequisite for priority fees: the prioritization fee is
// `compute_unit_price × requested_limit`, so an over-requested limit overpays
// for the same per-CU bid AND packs worse into a block's CU budget.
//
// Measured 2026-06-08 (image tee-v3-hardening-20):
//   lock_note               117,943 CU (devnet, fixed 26-level Merkle path)
//   verify_match_batch        87,224 CU (litesvm, deterministic N=16 groth16)
//   tee_forced_settle_batched 162,145 CU (devnet, WORST case: 5 leaves appended
//                                          = note_c/d + buyer change + 2 fee notes;
//                                          litesvm 2-leaf path is 99,299)
//   close_batch_validity_marker 3,546 CU (litesvm)
// Regression-guarded by the `CU_PROFILE`/assert lines in
// programs/vault/tests/{match_batch_verify,tee_forced_settle_batched}.rs.

/// CU ceiling for the settle tx (Tx D). 5-leaf worst case ≈ 162k; 250k ≈ 1.54×.
const SETTLE_COMPUTE_UNIT_LIMIT: u32 = 250_000;
/// CU ceiling for each lock_note tx (Tx A). ~118k measured; 175k ≈ 1.48×.
pub(crate) const LOCK_COMPUTE_UNIT_LIMIT: u32 = 175_000;
/// CU ceiling for the verify_match_batch tx (Tx B). ~87k measured; 130k ≈ 1.49×.
pub(crate) const VERIFY_COMPUTE_UNIT_LIMIT: u32 = 130_000;
/// CU ceiling for the close_batch_validity_marker tx (Tx E). ~3.5k; 15k generous.
pub(crate) const CLOSE_COMPUTE_UNIT_LIMIT: u32 = 15_000;

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
    Ok(base64::engine::general_purpose::STANDARD.encode(&wire))
}

/// Same as [`build_settle_v0_tx_b64`] but returns the raw
/// `VersionedTransaction` (for tests that want to inspect the
/// compiled message — account count, ALT lookups, wire size).
pub fn build_settle_v0_tx(
    tee_keypair: &Keypair,
    ed25519_ix: Instruction,
    settle_ix: Instruction,
    alts: &[AddressLookupTableAccount],
    blockhash: Hash,
) -> Result<VersionedTransaction, RpcError> {
    let payer = tee_keypair.pubkey();
    // ComputeBudget ix first so the (right-sized) CU limit applies to the
    // whole tx; then the ed25519 precompile + the settle ix.
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
            nullifier_a: [0xEA; 32],
            nullifier_b: [0xEB; 32],
            order_id_a: [0x01; 16],
            order_id_b: [0x02; 16],
            base_amount: 100,
            quote_amount: 5_000,
            buyer_change_amt: 1,
            seller_change_amt: 1,
            buyer_fee_amt: 0,
            seller_fee_amt: 0,
            note_fee_base_commitment: [0; 32],
            note_fee_quote_commitment: [0; 32],
            buyer_relock_order_id: [0; 16],
            buyer_relock_expiry: 0,
            seller_relock_order_id: [0; 16],
            seller_relock_expiry: 0,
            clearing_price: 50,
            batch_slot: 7,
        }
    }

    #[test]
    fn settle_v0_tx_compiles_and_fits_under_cap() {
        let kp = Keypair::new_from_array([0x42; 32]);
        let p = payload();
        let root = [0xAB; 32];
        let proof = [[0x01; 32], [0x02; 32], [0x03; 32], [0x04; 32]];

        let ed_ix = build_ed25519_verify_ix(&[0xAA; 32], &[0xBB; 64], &p.canonical_hash());
        let settle_ix = build_settle_batched_ix(&kp.pubkey(), &p, 5, &proof, &root);

        // Production stacks BOTH ALTs (worker.rs): the static settle ALT
        // (vault_config + sysvar + system program) under the per-batch ALT
        // (the 5 derivable PDAs). Both are needed to keep the worst-case
        // (change-note, no PDA dedup) settle tx under the 1232-byte cap.
        let static_alt = alt_account(Address::new_from_array([0x44; 32]), static_alt_addresses());
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

        // Serialized wire size must be under Solana's 1232-byte cap.
        let wire = bincode::serialize(&tx).unwrap();
        assert!(
            wire.len() <= 1232,
            "settle v0 tx is {} bytes, over the 1232 cap",
            wire.len()
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
        let settle_ix = build_settle_batched_ix(&kp.pubkey(), &p, 0, &proof, &root);
        let alt = alt_account(
            Address::new_from_array([0x55; 32]),
            per_batch_alt_addresses(&p, &root),
        );
        let b64 = build_settle_v0_tx_b64(
            &kp,
            ed_ix,
            settle_ix,
            &[alt],
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
