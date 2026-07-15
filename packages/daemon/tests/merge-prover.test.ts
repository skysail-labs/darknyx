/**
 * nodeMergeProver integration test — proves a REAL k=2 VALID_MERGE in-process.
 *
 * Builds two same-owner/same-mint notes, places them in a LocalMerkleTree,
 * assembles MergeInputs exactly as the SDK getMergeFunction would, and proves.
 * snarkjs succeeding means the witness satisfies the circuit — i.e. the
 * commitment / nullifier / Merkle-membership / conservation all line up, which
 * validates both the prover's field mapping AND the local tree. Skipped if the
 * merge circuit artifacts aren't built.
 */

import { describe, expect, it } from "vitest";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { nodeMergeProver } from "../src/merge-prover.js";
import { LocalMerkleTree } from "../src/merkle-tree.js";
import {
  noteCommitmentV2,
  ownerCommitment,
  pubkeyToFrPair,
  type MergeInputs,
} from "@nyx/sdk";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", "..", "..");
const k2 = {
  wasmPath: resolve(
    repoRoot,
    "circuits/build/valid_merge_k2/circuit_js/circuit.wasm",
  ),
  zkeyPath: resolve(
    repoRoot,
    "circuits/build/valid_merge_k2/circuit_final.zkey",
  ),
};
const k4 = {
  wasmPath: resolve(
    repoRoot,
    "circuits/build/valid_merge_k4/circuit_js/circuit.wasm",
  ),
  zkeyPath: resolve(
    repoRoot,
    "circuits/build/valid_merge_k4/circuit_final.zkey",
  ),
};
const available = existsSync(k2.wasmPath) && existsSync(k2.zkeyPath);
const ait = (name: string, fn: () => Promise<void>) =>
  available ? it(name, fn, 60_000) : it.skip(name, fn);

const beToBig = (x: Uint8Array): bigint => {
  let h = "0x";
  for (const b of x) h += b.toString(16).padStart(2, "0");
  return BigInt(h);
};

describe("nodeMergeProver (real VALID_MERGE k=2)", () => {
  ait("proves a 2-note merge whose witness satisfies the circuit", async () => {
    const spendingKey = 12345678901234567890n;
    const ownerBlinding = 42n;
    const tokenMint = new Uint8Array(32);
    tokenMint.set([1, 2, 3, 4]);
    const owner = await ownerCommitment(spendingKey, ownerBlinding);

    // Two input notes (same owner + mint).
    const notes = [
      { amount: 100n, innerHash: 7n },
      { amount: 250n, innerHash: 9n },
    ];
    const commits = await Promise.all(
      notes.map((n) =>
        noteCommitmentV2({
          tokenMint,
          amount: n.amount,
          ownerCommitment: owner,
          innerHash: n.innerHash,
        }),
      ),
    );

    const tree = await LocalMerkleTree.fromLeaves(commits);
    const witnesses = [await tree.witness(0), await tree.witness(1)];
    const root = witnesses[0].root;

    const [mintLo, mintHi] = pubkeyToFrPair(tokenMint);
    const inputs: MergeInputs = {
      k: 2,
      merkleRoot: beToBig(root),
      tokenMint: [mintLo, mintHi],
      spendingKey,
      ownerCommitmentBlinding: ownerBlinding,
      isActive: [1, 1],
      amount: notes.map((n) => n.amount),
      innerHash: notes.map((n) => n.innerHash),
      merklePath: witnesses.map((w) => w.siblings.map(beToBig)),
      merkleIndices: witnesses.map((w) => w.indices),
    };

    const proof = await nodeMergeProver({ k2, k4 }).merge.prove(inputs);

    expect(proof.piA).toHaveLength(64);
    expect(proof.piB).toHaveLength(128);
    expect(proof.piC).toHaveLength(64);
    // public signals: outputCommitment, merkleRoot, mint_lo, mint_hi, k nullifiers
    expect(proof.publicInputs.length).toBe(4 + 2);
  });

  it("stubs walletCreate + spend", async () => {
    const suite = nodeMergeProver({ k2, k4 });
    await expect(suite.spend.prove({} as never)).rejects.toThrow(/merge-only/);
    await expect(suite.walletCreate.prove({} as never)).rejects.toThrow(
      /merge-only/,
    );
  });
});
