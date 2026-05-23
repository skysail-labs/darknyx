/**
 * v3.5 — one-shot helper that:
 *   1. Pads the supplied real matches with `dummySlot()` up to N=16.
 *   2. Generates a single batched VALID_CREATE + VALID_PRICE proof.
 *   3. Lands `verify_match_batch` on L1, creating the BatchValidityMarker
 *      PDA whose seed is the Merkle root over all 16 leaves.
 *   4. Returns the leaves + root so the caller can compute Merkle
 *      inclusion proofs for the per-match `tee_forced_settle_batched`
 *      txs that follow.
 *
 * Mirrors the existing `landVerifyValidPrice` + `proveValidPrice`
 * pattern, just for the batched flow.
 */

import {
  ComputeBudgetProgram,
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";

import { buildVerifyMatchBatchInstruction } from "../../src/idl/vault-client.js";
import {
  proveMatchBatch,
  padBatch,
  type MatchSlotWitness,
} from "./match-batch-prover.js";

export interface LandVerifyMatchBatchParams {
  connection: Connection;
  vaultProgramId: PublicKey;
  /** The TEE authority — also doubles as the payer of the marker rent. */
  teeKeypair: Keypair;
  /** Real per-slot witnesses. Will be padded with dummy slots up to N=16. */
  realSlots: MatchSlotWitness[];
  repoRoot: string;
  /** Optional override of the on-chain expiry-slot window (default 200). */
  expirySlotWindow?: number;
}

export interface LandVerifyMatchBatchResult {
  /** All 16 per-slot leaves (real first, dummies appended). */
  leaves: Uint8Array[];
  /** Merkle root over the 16 leaves — the proof's public input and the
   *  BatchValidityMarker PDA's seed. */
  merkleRoot: Uint8Array;
  /** Padded slot witnesses (real + dummies) — useful when the caller needs
   *  to drive `tee_forced_settle_batched` for individual real slots and
   *  wants to know their final batch indices. */
  paddedSlots: MatchSlotWitness[];
  /** Tx signature of the landed verify_match_batch tx. */
  txSig: string;
}

export async function landVerifyMatchBatch(
  p: LandVerifyMatchBatchParams,
): Promise<LandVerifyMatchBatchResult> {
  // On-chain handler accepts N=16 only; pad the real matches up.
  const paddedSlots = await padBatch(p.realSlots, 16);

  const proveResult = await proveMatchBatch({
    repoRoot: p.repoRoot,
    slots: paddedSlots,
  });

  const currentSlot = await p.connection.getSlot("confirmed");
  const expirySlot = BigInt(currentSlot + (p.expirySlotWindow ?? 200));

  const tx = new Transaction().add(
    // Bigger compute budget than verify_valid_create / verify_valid_price
    // because we're verifying a single proof that bundles 16 matches'
    // worth of constraints. ~1.4M CU is the practical ceiling on devnet.
    ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
    buildVerifyMatchBatchInstruction({
      programId: p.vaultProgramId,
      payer: p.teeKeypair.publicKey,
      merkleRoot: proveResult.merkleRoot,
      expirySlot,
      proof: proveResult.proof,
    }),
  );

  const txSig = await sendAndConfirmTransaction(
    p.connection,
    tx,
    [p.teeKeypair],
    { commitment: "confirmed" },
  );

  return {
    leaves: proveResult.leaves,
    merkleRoot: proveResult.merkleRoot,
    paddedSlots,
    txSig,
  };
}
