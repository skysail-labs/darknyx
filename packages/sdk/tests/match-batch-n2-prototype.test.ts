/**
 * v3.5 prototype validation — N=2 batched match-validity proof.
 *
 * Goal: prove the new batched-circuit architecture works end-to-end before
 * scaling up to N=4 / N=16. Two assertions matter here:
 *
 *   1. The N=2 circuit accepts the same witness shape that the per-match
 *      `valid_create` + `valid_price` circuits expected — translated into
 *      batched-slot form. If this proof verifies via snarkjs, the constraint
 *      logic is at least self-consistent for that witness.
 *
 *   2. The TS-side leaf-hash + Merkle-root computation matches what the
 *      circuit derives internally (and what the on-chain Rust handler will
 *      eventually re-derive). This is the property the on-chain
 *      Merkle-inclusion check relies on.
 *
 *   Cross-validation against the per-match circuits comes once we wire the
 *   batch VK into the Rust verifier; this test is the upstream sanity gate.
 */

import { describe, expect, it } from "vitest";
import { resolve } from "node:path";
import { existsSync } from "node:fs";

import { noteCommitment } from "../src/utxo/note.js";
import {
  proveMatchBatch2,
  computeBatchLeaf,
  computeBatchRoot2,
  type MatchSlotWitness,
} from "./helpers/match-batch-prover.js";

const REPO_ROOT = resolve(__dirname, "../../..");

const WASM = resolve(REPO_ROOT, "circuits/build/match_batch_n2/circuit_js/circuit.wasm");
const ZKEY = resolve(REPO_ROOT, "circuits/build/match_batch_n2/circuit_final.zkey");
const VK = resolve(REPO_ROOT, "circuits/build/match_batch_n2/verification_key.json");

// Skip the suite gracefully if the artefacts aren't built yet (e.g.
// fresh checkout pre-`bash scripts/build-circuits.sh`).
const READY = existsSync(WASM) && existsSync(ZKEY) && existsSync(VK);
const dCircuits = READY ? describe : describe.skip;

/**
 * Build a fully-valid match-slot witness given (baseAmount, clearingPrice)
 * and the owner identities. The note commitments are computed from the
 * witness so the VALID_CREATE openings (`note_a_commitment === Poseidon7(...)`)
 * are satisfied by construction.
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
  /** Salt the nonces / blindings so the two slots don't collide. */
  slotIdx: number;
}): Promise<MatchSlotWitness> {
  const quoteAmount = args.baseAmount * args.clearingPrice;
  const aAmount = quoteAmount + args.buyerChange + args.buyerFee;
  const bAmount = args.baseAmount + args.sellerChange + args.sellerFee;

  const aNonce = BigInt(0xA1A1 + args.slotIdx);
  const aBlinding = BigInt(0xB1B1 + args.slotIdx);
  const bNonce = BigInt(0xA2A2 + args.slotIdx);
  const bBlinding = BigInt(0xB2B2 + args.slotIdx);
  const cNonce = BigInt(0xA3A3 + args.slotIdx);
  const cBlinding = BigInt(0xB3B3 + args.slotIdx);
  const dNonce = BigInt(0xA4A4 + args.slotIdx);
  const dBlinding = BigInt(0xB4B4 + args.slotIdx);
  const eNonce = BigInt(0xA5A5 + args.slotIdx);
  const eBlinding = BigInt(0xB5B5 + args.slotIdx);
  const fNonce = BigInt(0xA6A6 + args.slotIdx);
  const fBlinding = BigInt(0xB6B6 + args.slotIdx);

  const noteA = await noteCommitment({
    tokenMint: args.quoteMint,
    amount: aAmount,
    ownerCommitment: args.buyerOwnerCommit,
    nonce: aNonce,
    blindingR: aBlinding,
  });
  const noteB = await noteCommitment({
    tokenMint: args.baseMint,
    amount: bAmount,
    ownerCommitment: args.sellerOwnerCommit,
    nonce: bNonce,
    blindingR: bBlinding,
  });
  const noteC = await noteCommitment({
    tokenMint: args.baseMint,
    amount: args.baseAmount,
    ownerCommitment: args.buyerOwnerCommit,
    nonce: cNonce,
    blindingR: cBlinding,
  });
  const noteD = await noteCommitment({
    tokenMint: args.quoteMint,
    amount: quoteAmount,
    ownerCommitment: args.sellerOwnerCommit,
    nonce: dNonce,
    blindingR: dBlinding,
  });
  const zero = new Uint8Array(32);
  const noteE =
    args.buyerChange === 0n
      ? zero
      : await noteCommitment({
          tokenMint: args.quoteMint,
          amount: args.buyerChange,
          ownerCommitment: args.buyerOwnerCommit,
          nonce: eNonce,
          blindingR: eBlinding,
        });
  const noteF =
    args.sellerChange === 0n
      ? zero
      : await noteCommitment({
          tokenMint: args.baseMint,
          amount: args.sellerChange,
          ownerCommitment: args.sellerOwnerCommit,
          nonce: fNonce,
          blindingR: fBlinding,
        });

  return {
    noteAcommitment: noteA,
    noteBcommitment: noteB,
    noteCcommitment: noteC,
    noteDcommitment: noteD,
    noteEcommitment: noteE,
    noteFcommitment: noteF,
    quoteMint: args.quoteMint,
    baseMint: args.baseMint,
    baseAmount: args.baseAmount,
    quoteAmount,
    buyerChangeAmt: args.buyerChange,
    sellerChangeAmt: args.sellerChange,
    buyerFeeAmt: args.buyerFee,
    sellerFeeAmt: args.sellerFee,
    batchSlot: args.batchSlot,
    aOwnerCommit: args.buyerOwnerCommit,
    bOwnerCommit: args.sellerOwnerCommit,
    aAmount,
    bAmount,
    aNonce,
    aBlinding,
    bNonce,
    bBlinding,
    cNonce,
    cBlinding,
    dNonce,
    dBlinding,
    eNonce,
    eBlinding,
    fNonce,
    fBlinding,
    clearingPrice: args.clearingPrice,
  };
}

function rand32(seed: number): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = (seed + i * 37) & 0xff;
  // Mask the top byte so the value stays inside the BN254 scalar field.
  out[0] &= 0x0f;
  return out;
}

dCircuits("v3.5 prototype — match_batch_n2", () => {
  it("[exact_fill_no_change] proves both slots simultaneously", async () => {
    const quoteMint = rand32(0xAA);
    const baseMint = rand32(0xBB);
    const buyerCommit = 0x1234567890ABCDEFn;
    const sellerCommit = 0xFEDCBA0987654321n;

    const slot0 = await buildSlot({
      quoteMint, baseMint,
      buyerOwnerCommit: buyerCommit,
      sellerOwnerCommit: sellerCommit,
      baseAmount: 50n,
      clearingPrice: 100n,    // quote = 5_000
      buyerChange: 0n,
      sellerChange: 0n,
      buyerFee: 0n,
      sellerFee: 0n,
      batchSlot: 1_000_000n,
      slotIdx: 0,
    });
    const slot1 = await buildSlot({
      quoteMint, baseMint,
      buyerOwnerCommit: buyerCommit,
      sellerOwnerCommit: sellerCommit,
      baseAmount: 30n,
      clearingPrice: 100n,    // quote = 3_000
      buyerChange: 0n,
      sellerChange: 0n,
      buyerFee: 0n,
      sellerFee: 0n,
      batchSlot: 1_000_000n,
      slotIdx: 1,
    });

    const result = await proveMatchBatch2({ repoRoot: REPO_ROOT, slot0, slot1 });

    // The proof should have exactly one public input — the merkleRoot.
    expect(result.publicInputsBE.length).toBe(1);
    expect(result.publicInputsBE[0]).toEqual(result.merkleRoot);

    // TS-side leaf + root computation MUST agree with what the circuit
    // re-derived internally. If they didn't, snarkjs would have already
    // failed the proof — but we double-check here for the test's
    // diagnostic value.
    const leaf0Recompute = await computeBatchLeaf(slot0);
    const leaf1Recompute = await computeBatchLeaf(slot1);
    expect(result.leaves[0]).toEqual(leaf0Recompute);
    expect(result.leaves[1]).toEqual(leaf1Recompute);
    const rootRecompute = await computeBatchRoot2(leaf0Recompute, leaf1Recompute);
    expect(result.merkleRoot).toEqual(rootRecompute);

    // Sanity-check the proof byte layout.
    expect(result.proof.piA.length).toBe(64);
    expect(result.proof.piB.length).toBe(128);
    expect(result.proof.piC.length).toBe(64);

    // Note: `snarkjsFullProve` shells out to `snarkjs groth16 fullprove`
    // which itself generates the witness + verifies internal consistency
    // before returning. If it returned, the witness satisfied every
    // constraint (R1CS check is implicit in proof construction). The
    // on-chain `verify_match_batch` ix (not yet wired) is the eventual
    // production gate.
  }, 120_000);

  it("[with_change_notes] proves a slot pair with non-zero change legs", async () => {
    const quoteMint = rand32(0xCC);
    const baseMint = rand32(0xDD);
    const buyerCommit = 0xAAAAAAAA00000001n;
    const sellerCommit = 0xBBBBBBBB00000002n;

    // Slot 0: exact fill. Slot 1: buyer over-collateralised, has change.
    const slot0 = await buildSlot({
      quoteMint, baseMint,
      buyerOwnerCommit: buyerCommit,
      sellerOwnerCommit: sellerCommit,
      baseAmount: 25n, clearingPrice: 200n,
      buyerChange: 0n, sellerChange: 0n,
      buyerFee: 0n, sellerFee: 0n,
      batchSlot: 1_000_001n,
      slotIdx: 0,
    });
    const slot1 = await buildSlot({
      quoteMint, baseMint,
      buyerOwnerCommit: buyerCommit,
      sellerOwnerCommit: sellerCommit,
      baseAmount: 25n, clearingPrice: 200n,    // quote = 5_000
      buyerChange: 1_000n,                      // a_amount = 5_000+1_000+15 = 6_015
      sellerChange: 0n,
      buyerFee: 15n,
      sellerFee: 0n,
      batchSlot: 1_000_001n,
      slotIdx: 1,
    });

    const result = await proveMatchBatch2({ repoRoot: REPO_ROOT, slot0, slot1 });

    expect(result.publicInputsBE.length).toBe(1);
    expect(result.leaves[0]).not.toEqual(result.leaves[1]);
    expect(result.merkleRoot).toEqual(
      await computeBatchRoot2(result.leaves[0], result.leaves[1]),
    );
  }, 120_000);
});

