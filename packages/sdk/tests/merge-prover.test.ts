/**
 * VALID_MERGE(K) circuit round-trip. A successful snarkjs `fullprove` means the
 * witness satisfied EVERY constraint — K membership proofs, K nullifier
 * derivations, the active-only sum, and the range checks — so this pins the
 * circuit's correctness. We additionally assert the public signals
 * (outputCommitment, merkleRoot) match an independent recomputation.
 *
 * Needs the built artifacts (`bash scripts/build-circuits.sh`); auto-skips otherwise.
 */

import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

import { describe, it, expect } from "vitest";
import { ownerCommitment, noteCommitmentV2 } from "../src/utxo/note.js";
import { MerkleShadow } from "./helpers/merkle-shadow.js";
import { be32ToBigInt } from "./helpers/e2e-helpers.js";
import { proveValidMerge, type MergeSlot } from "./helpers/merge-prover.js";

const here = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(here, "..", "..", "..");
const HAVE_ARTIFACTS =
  existsSync(
    resolve(REPO_ROOT, "circuits/build/valid_merge_k2/circuit_final.zkey"),
  ) &&
  existsSync(
    resolve(REPO_ROOT, "circuits/build/valid_merge_k4/circuit_final.zkey"),
  );

const maybe = HAVE_ARTIFACTS ? describe : describe.skip;

const SK = 0x1234_5678n;
const BLINDING = 0xfeedn;
const MINT = new Uint8Array(32).fill(0x07);
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

/** Build a note set in a fresh tree; return the shared root + per-note slots. */
async function buildTree(notes: { amount: bigint; innerHash: bigint }[]) {
  const owner = await ownerCommitment(SK, BLINDING);
  const tree = await MerkleShadow.create();
  for (const n of notes) {
    const c = await noteCommitmentV2({
      tokenMint: MINT,
      amount: n.amount,
      ownerCommitment: owner,
      innerHash: n.innerHash,
    });
    await tree.append(c); // leaf index = append order
  }
  const slots: MergeSlot[] = [];
  for (let i = 0; i < notes.length; i++) {
    const w = await tree.witness(i);
    slots.push({
      amount: notes[i].amount,
      innerHash: notes[i].innerHash,
      pathElements: w.siblings.map(be32ToBigInt),
      pathIndices: w.indices,
    });
  }
  const root = await tree.computeRoot();
  return { slots, root, owner };
}

maybe("VALID_MERGE circuit", () => {
  it("K=2 merges two notes into one of their sum", async () => {
    const notes = [
      { amount: 300n, innerHash: 0x11n },
      { amount: 200n, innerHash: 0x22n },
    ];
    const { slots, root } = await buildTree(notes);
    const outputInnerHash = 0xabcn;

    const r = await proveValidMerge({
      repoRoot: REPO_ROOT,
      k: 2,
      spendingKey: SK,
      ownerCommitmentBlinding: BLINDING,
      outputInnerHash,
      tokenMint: MINT,
      merkleRootBE: root,
      slots,
    });

    expect(r.outputAmount).toBe(500n);
    expect(hex(r.publicInputsBE[0])).toBe(hex(r.outputCommitmentBE)); // output (signal 0)
    expect(hex(r.publicInputsBE[1])).toBe(hex(root)); // merkleRoot
  }, 120_000);

  it("K=4 merges two real notes with two dummy-padded slots", async () => {
    const notes = [
      { amount: 100n, innerHash: 0x33n },
      { amount: 250n, innerHash: 0x44n },
    ];
    const { slots, root } = await buildTree(notes);

    const r = await proveValidMerge({
      repoRoot: REPO_ROOT,
      k: 4,
      spendingKey: SK,
      ownerCommitmentBlinding: BLINDING,
      outputInnerHash: 0xdefn,
      tokenMint: MINT,
      merkleRootBE: root,
      slots, // only 2 real → 2 dummy slots padded
    });

    expect(r.outputAmount).toBe(350n);
    expect(hex(r.publicInputsBE[0])).toBe(hex(r.outputCommitmentBE));
    // The two dummy slots' public nullifiers (signals 6,7) are zero.
    expect(be32ToBigInt(r.publicInputsBE[6])).toBe(0n);
    expect(be32ToBigInt(r.publicInputsBE[7])).toBe(0n);
  }, 120_000);

  it("rejects an input note that is not in the tree (membership constraint)", async () => {
    const notes = [
      { amount: 300n, innerHash: 0x11n },
      { amount: 200n, innerHash: 0x22n },
    ];
    const { slots, root } = await buildTree(notes);
    // Tamper: claim a different inner_hash for slot 0 → its commitment is no
    // longer the tree leaf the path traverses to, so membership must fail.
    slots[0] = { ...slots[0], innerHash: 0x99n };

    await expect(
      proveValidMerge({
        repoRoot: REPO_ROOT,
        k: 2,
        spendingKey: SK,
        ownerCommitmentBlinding: BLINDING,
        outputInnerHash: 0xabcn,
        tokenMint: MINT,
        merkleRootBE: root,
        slots,
      }),
    ).rejects.toThrow();
  }, 120_000);
});
