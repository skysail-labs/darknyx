/**
 * v3.5 — batched match-validity prover validation across N ∈ {2, 4, 16}.
 *
 * Three things this suite is gating:
 *   1. **Architecture works**: every supported N (2 / 4 / 16) generates a
 *      proof that snarkjs accepts. If snarkjs's internal verifier accepts
 *      it, every constraint in the circuit body is satisfied.
 *   2. **Leaf hash + Merkle root parity**: TS-computed leaves + root agree
 *      with the circuit's internally-derived values. This is the property
 *      the on-chain Merkle-inclusion check will rely on.
 *   3. **Negative paths reject**: malformed witnesses (bad VALID_PRICE math,
 *      corrupted note commitment) are rejected — either at the prover's
 *      precondition check (readable error) or at witness generation
 *      (opaque snarkjs error).
 *
 * Cross-validation against the per-match `valid_create` + `valid_price`
 * circuits comes via integration tests once the on-chain
 * `verify_match_batch` ix lands; this suite is the upstream sanity gate.
 */

import { describe, expect, it } from "vitest";
import { resolve } from "node:path";
import { existsSync } from "node:fs";

import { noteCommitmentV2 } from "../src/utxo/note.js";
import {
  proveMatchBatch,
  computeBatchLeaf,
  computeBatchRoot,
  type MatchSlotWitness,
  type BatchSize,
} from "./helpers/match-batch-prover.js";

const REPO_ROOT = resolve(__dirname, "../../..");

function circuitPaths(N: BatchSize) {
  const dir = `circuits/build/match_batch_n${N}`;
  return {
    wasm: resolve(REPO_ROOT, `${dir}/circuit_js/circuit.wasm`),
    zkey: resolve(REPO_ROOT, `${dir}/circuit_final.zkey`),
    vk: resolve(REPO_ROOT, `${dir}/verification_key.json`),
  };
}

function artefactsReady(N: BatchSize): boolean {
  const { wasm, zkey, vk } = circuitPaths(N);
  return existsSync(wasm) && existsSync(zkey) && existsSync(vk);
}

/**
 * Build a fully-valid match-slot witness. Note commitments are computed
 * from the witness so the per-slot VALID_CREATE openings hold by
 * construction.
 */
async function buildSlot(args: {
  quoteMint: Uint8Array;
  baseMint: Uint8Array;
  buyerOwnerCommit: bigint;
  sellerOwnerCommit: bigint;
  baseAmount: bigint;
  clearingPrice: bigint;
  buyerChange: bigint;
  sellerChange: bigint;
  buyerFee: bigint;
  sellerFee: bigint;
  batchSlot: bigint;
  /** Salt the inner_hashes so multiple slots in the same batch
   *  don't accidentally collide commitments. */
  slotIdx: number;
}): Promise<MatchSlotWitness> {
  const quoteAmount = args.baseAmount * args.clearingPrice;
  const aAmount = quoteAmount + args.buyerChange + args.buyerFee;
  const bAmount = args.baseAmount + args.sellerChange + args.sellerFee;

  // One inner_hash per note (v2). Salt by slot so leaves stay distinct.
  const I = (idx: number) => BigInt(0xA0A0 + args.slotIdx * 100 + idx);
  const aInner = I(1);
  const bInner = I(2);
  const cInner = I(3);
  const dInner = I(4);
  const eInner = I(5);
  const fInner = I(6);

  const noteA = await noteCommitmentV2({
    tokenMint: args.quoteMint, amount: aAmount,
    ownerCommitment: args.buyerOwnerCommit, innerHash: aInner,
  });
  const noteB = await noteCommitmentV2({
    tokenMint: args.baseMint, amount: bAmount,
    ownerCommitment: args.sellerOwnerCommit, innerHash: bInner,
  });
  const noteC = await noteCommitmentV2({
    tokenMint: args.baseMint, amount: args.baseAmount,
    ownerCommitment: args.buyerOwnerCommit, innerHash: cInner,
  });
  const noteD = await noteCommitmentV2({
    tokenMint: args.quoteMint, amount: quoteAmount,
    ownerCommitment: args.sellerOwnerCommit, innerHash: dInner,
  });
  const zero = new Uint8Array(32);
  const noteE = args.buyerChange === 0n ? zero : await noteCommitmentV2({
    tokenMint: args.quoteMint, amount: args.buyerChange,
    ownerCommitment: args.buyerOwnerCommit, innerHash: eInner,
  });
  const noteF = args.sellerChange === 0n ? zero : await noteCommitmentV2({
    tokenMint: args.baseMint, amount: args.sellerChange,
    ownerCommitment: args.sellerOwnerCommit, innerHash: fInner,
  });

  return {
    noteAcommitment: noteA, noteBcommitment: noteB,
    noteCcommitment: noteC, noteDcommitment: noteD,
    noteEcommitment: noteE, noteFcommitment: noteF,
    quoteMint: args.quoteMint, baseMint: args.baseMint,
    baseAmount: args.baseAmount, quoteAmount,
    buyerChangeAmt: args.buyerChange, sellerChangeAmt: args.sellerChange,
    buyerFeeAmt: args.buyerFee, sellerFeeAmt: args.sellerFee,
    batchSlot: args.batchSlot,
    aOwnerCommit: args.buyerOwnerCommit, bOwnerCommit: args.sellerOwnerCommit,
    aAmount, bAmount,
    aInner, bInner, cInner, dInner, eInner, fInner,
    clearingPrice: args.clearingPrice,
  };
}

function rand32(seed: number): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = (seed + i * 37) & 0xff;
  out[0] &= 0x0f;   // Keep within the BN254 scalar field.
  return out;
}

/** Default exact-fill scenario reused across N. */
async function defaultBatch(N: BatchSize): Promise<MatchSlotWitness[]> {
  const quoteMint = rand32(0xAA);
  const baseMint = rand32(0xBB);
  const buyerCommit = 0x1234567890ABCDEFn;
  const sellerCommit = 0xFEDCBA0987654321n;
  const slots: MatchSlotWitness[] = [];
  for (let i = 0; i < N; i++) {
    slots.push(await buildSlot({
      quoteMint, baseMint,
      buyerOwnerCommit: buyerCommit,
      sellerOwnerCommit: sellerCommit,
      // Different base amounts per slot so the leaves are distinct.
      baseAmount: 10n + BigInt(i) * 5n,
      clearingPrice: 100n,
      buyerChange: 0n, sellerChange: 0n,
      buyerFee: 0n, sellerFee: 0n,
      batchSlot: 1_000_000n,
      slotIdx: i,
    }));
  }
  return slots;
}

// ---------------------------------------------------------------------------
// Positive scenarios per N
// ---------------------------------------------------------------------------

for (const N of [2, 4, 16] as const) {
  const ready = artefactsReady(N);
  const d = ready ? describe : describe.skip;

  d(`v3.5 batched validity — N=${N}`, () => {
    it(`[exact_fill_no_change] all-slot proof verifies + leaves match TS`, async () => {
      const slots = await defaultBatch(N);
      const result = await proveMatchBatch({ repoRoot: REPO_ROOT, slots });

      expect(result.publicInputsBE.length).toBe(1);
      expect(result.publicInputsBE[0]).toEqual(result.merkleRoot);

      // TS-side leaf + root reproduce the circuit's internal computation.
      for (let i = 0; i < N; i++) {
        const tsLeaf = await computeBatchLeaf(slots[i]);
        expect(result.leaves[i]).toEqual(tsLeaf);
      }
      const tsRoot = await computeBatchRoot(result.leaves);
      expect(result.merkleRoot).toEqual(tsRoot);

      // Proof byte layout sanity.
      expect(result.proof.piA.length).toBe(64);
      expect(result.proof.piB.length).toBe(128);
      expect(result.proof.piC.length).toBe(64);
    }, 240_000);   // N=16 proof gen can be ~30-60s on M1.
  });
}

// ---------------------------------------------------------------------------
// Mixed-shape scenarios — change-note slots interleaved with exact-fill
// ---------------------------------------------------------------------------

const ready2 = artefactsReady(2);
(ready2 ? describe : describe.skip)("v3.5 — N=2 mixed-shape coverage", () => {
  it("[with_change_notes] one exact-fill + one over-collateralised with buyer change + fee", async () => {
    const quoteMint = rand32(0xCC);
    const baseMint = rand32(0xDD);
    const buyerCommit = 0xAAAAAAAA00000001n;
    const sellerCommit = 0xBBBBBBBB00000002n;

    const slots: MatchSlotWitness[] = [
      await buildSlot({
        quoteMint, baseMint,
        buyerOwnerCommit: buyerCommit, sellerOwnerCommit: sellerCommit,
        baseAmount: 25n, clearingPrice: 200n,
        buyerChange: 0n, sellerChange: 0n,
        buyerFee: 0n, sellerFee: 0n,
        batchSlot: 1_000_001n, slotIdx: 0,
      }),
      await buildSlot({
        quoteMint, baseMint,
        buyerOwnerCommit: buyerCommit, sellerOwnerCommit: sellerCommit,
        baseAmount: 25n, clearingPrice: 200n,
        buyerChange: 1_000n, sellerChange: 0n,
        buyerFee: 15n, sellerFee: 0n,
        batchSlot: 1_000_001n, slotIdx: 1,
      }),
    ];

    const result = await proveMatchBatch({ repoRoot: REPO_ROOT, slots });

    expect(result.publicInputsBE.length).toBe(1);
    expect(result.leaves[0]).not.toEqual(result.leaves[1]);   // distinct shapes → distinct leaves.

    const tsRoot = await computeBatchRoot(result.leaves);
    expect(result.merkleRoot).toEqual(tsRoot);
  }, 120_000);
});

// ---------------------------------------------------------------------------
// Negative paths — what's supposed to be rejected, IS rejected.
// ---------------------------------------------------------------------------

(ready2 ? describe : describe.skip)("v3.5 — N=2 negative paths", () => {
  it("[bad_price_math] prover precondition rejects quote != base × price", async () => {
    const slots = await defaultBatch(2);
    // Deliberately corrupt slot[0] so the headline VALID_PRICE constraint
    // would fail. Bumping quoteAmount up by 1 breaks `quote = base × price`
    // without affecting any other constraint precheck.
    slots[0] = { ...slots[0], quoteAmount: slots[0].quoteAmount + 1n };

    await expect(
      proveMatchBatch({ repoRoot: REPO_ROOT, slots }),
    ).rejects.toThrow(/quote .* !== base .* \* price/);
  }, 30_000);

  it("[bad_conservation] prover precondition rejects a_amount != quote + change + fee", async () => {
    const slots = await defaultBatch(2);
    // Bump aAmount by 1 — breaks `a_amount = quote_amount + buyer_change + buyer_fee`.
    slots[1] = { ...slots[1], aAmount: slots[1].aAmount + 1n };

    await expect(
      proveMatchBatch({ repoRoot: REPO_ROOT, slots }),
    ).rejects.toThrow(/a_amount conservation/);
  }, 30_000);

  it("[bad_note_commitment] snarkjs rejects when noteA doesn't open to its commitment", async () => {
    const slots = await defaultBatch(2);
    // Corrupt noteA's commitment AFTER the witness is built. This bypasses
    // the prover's quick-checks (which only verify the high-level
    // VALID_PRICE / conservation arithmetic, not the per-note Poseidon
    // openings). snarkjs's witness generator should fail because the
    // constraint `note_a_commitment === Poseidon6(2, qm_lo, qm_hi,
    // a_amount, a_owner_commit, a_inner)` no longer holds.
    const corrupted = new Uint8Array(slots[0].noteAcommitment);
    corrupted[31] ^= 0x01;
    slots[0] = { ...slots[0], noteAcommitment: corrupted };

    await expect(
      proveMatchBatch({ repoRoot: REPO_ROOT, slots }),
    ).rejects.toThrow();
  }, 60_000);
});
