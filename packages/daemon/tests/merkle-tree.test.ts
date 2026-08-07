/**
 * LocalMerkleTree tests — a witness must recompute the tree's root. Verifies the
 * by-leaf-index proof construction (the merge path's merkle provider relies on it).
 */

import { describe, expect, it } from "vitest";

import { LocalMerkleTree, TREE_DEPTH } from "../src/merkle-tree.js";
import { poseidonHashBytesBE } from "@darknyx/sdk";

const bytesToBigInt = (x: Uint8Array): bigint => {
  let hex = "0x";
  for (const b of x) hex += b.toString(16).padStart(2, "0");
  return BigInt(hex);
};

/** Recompute the root from a leaf + its witness (the on-chain verify direction). */
async function rootFromWitness(
  leaf: Uint8Array,
  siblings: Uint8Array[],
  indices: number[],
): Promise<Uint8Array> {
  let cur = leaf;
  for (let d = 0; d < TREE_DEPTH; d++) {
    const sib = siblings[d];
    const [l, r] = indices[d] === 0 ? [cur, sib] : [sib, cur];
    cur = await poseidonHashBytesBE([bytesToBigInt(l), bytesToBigInt(r)]);
  }
  return cur;
}

const leaf = (n: number): Uint8Array => {
  const b = new Uint8Array(32);
  b[31] = n;
  return b;
};

describe("LocalMerkleTree", () => {
  it("a single-leaf witness recomputes the root", async () => {
    const t = await LocalMerkleTree.fromLeaves([leaf(1)]);
    const w = await t.witness(0);
    expect(w.siblings).toHaveLength(TREE_DEPTH);
    const recomputed = await rootFromWitness(leaf(1), w.siblings, w.indices);
    expect(Buffer.from(recomputed)).toEqual(Buffer.from(w.root));
    expect(Buffer.from(await t.root())).toEqual(Buffer.from(w.root));
  });

  it("every leaf's witness recomputes the same root (5 leaves)", async () => {
    const leaves = [leaf(10), leaf(20), leaf(30), leaf(40), leaf(50)];
    const t = await LocalMerkleTree.fromLeaves(leaves);
    const root = await t.root();
    const buildHashes = t.internalHashCount();
    for (let i = 0; i < leaves.length; i++) {
      const w = await t.witness(i);
      expect(Buffer.from(w.root)).toEqual(Buffer.from(root));
      const recomputed = await rootFromWitness(
        leaves[i],
        w.siblings,
        w.indices,
      );
      expect(Buffer.from(recomputed)).toEqual(Buffer.from(root));
    }
    // Five witnesses plus root reuse the one immutable build. The exact count
    // is 3+2+1 for the populated levels, then 17 right-zero extensions.
    expect(buildHashes).toBe(23);
    expect(t.internalHashCount()).toBe(buildHashes);
  });

  it("path bits reflect the leaf's position", async () => {
    const t = await LocalMerkleTree.fromLeaves([leaf(1), leaf(2), leaf(3)]);
    expect((await t.witness(0)).indices[0]).toBe(0); // left child
    expect((await t.witness(1)).indices[0]).toBe(1); // right child
  });

  it("rejects an out-of-range leaf", async () => {
    const t = await LocalMerkleTree.fromLeaves([leaf(1)]);
    await expect(t.witness(5)).rejects.toThrow(/out of range/);
  });

  it("owns its snapshot and does not expose mutable cached nodes", async () => {
    const input = [leaf(1), leaf(2)];
    const t = await LocalMerkleTree.fromLeaves(input);
    const expected = await t.root();
    input[0].fill(0xff);
    const witness = await t.witness(0);
    witness.root.fill(0xaa);
    witness.siblings[0].fill(0xbb);
    expect(Buffer.from(await t.root())).toEqual(Buffer.from(expected));
    expect(Buffer.from((await t.witness(0)).root)).toEqual(
      Buffer.from(expected),
    );
  });

  it("returns the precomputed empty root without internal build hashes", async () => {
    const empty = await LocalMerkleTree.fromLeaves([]);
    expect(await empty.root()).toHaveLength(32);
    expect(empty.internalHashCount()).toBe(0);
  });
});
