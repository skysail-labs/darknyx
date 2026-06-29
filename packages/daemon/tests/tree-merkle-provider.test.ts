/**
 * TreeLeavesMerkleProvider tests — pages a snapshot + serves by-leaf proofs that
 * recompute the snapshot root, no gateway (the fetcher is a fake).
 */

import { describe, expect, it, vi } from "vitest";

import {
  TreeLeavesMerkleProvider,
  type LeavesFetcher,
} from "../src/tree-merkle-provider.js";
import { LocalMerkleTree, TREE_DEPTH } from "../src/merkle-tree.js";
import { poseidonHashBytesBE } from "@nyx/sdk";

const bytesToBigInt = (x: Uint8Array): bigint => {
  let hex = "0x";
  for (const b of x) hex += b.toString(16).padStart(2, "0");
  return BigInt(hex);
};
async function rootFromWitness(
  leaf: Uint8Array,
  siblings: Uint8Array[],
  indices: number[],
): Promise<Uint8Array> {
  let cur = leaf;
  for (let d = 0; d < TREE_DEPTH; d++) {
    const [l, r] = indices[d] === 0 ? [cur, siblings[d]] : [siblings[d], cur];
    cur = await poseidonHashBytesBE([bytesToBigInt(l), bytesToBigInt(r)]);
  }
  return cur;
}

const leafHex = (n: number) =>
  Buffer.from([...new Array(31).fill(0), n]).toString("hex");

/** A fake /tree/leaves over an in-memory leaf set, paginated. */
function fakeFetcher(leaves: string[], pageSize: number): LeavesFetcher {
  return vi.fn(async (from: number, to: number) => {
    const slice = leaves
      .slice(from, Math.min(to, leaves.length))
      .map((value, i) => ({ leaf_index: from + i, value }));
    void pageSize;
    return { leaves: slice, merkle_root: "00".repeat(32) };
  });
}

describe("TreeLeavesMerkleProvider", () => {
  it("serves a by-leaf proof that recomputes the snapshot root", async () => {
    const leaves = [leafHex(11), leafHex(22), leafHex(33)];
    const provider = new TreeLeavesMerkleProvider({
      fetcher: fakeFetcher(leaves, 500),
      pageSize: 500,
    });
    const expectRoot = await (
      await LocalMerkleTree.fromLeaves(
        leaves.map((h) => Uint8Array.from(Buffer.from(h, "hex"))),
      )
    ).root();

    const proof = await provider.getInclusionProof(1n);
    expect(Buffer.from(proof.root)).toEqual(Buffer.from(expectRoot));
    const recomputed = await rootFromWitness(
      Uint8Array.from(Buffer.from(leaves[1], "hex")),
      proof.siblings,
      proof.pathIndices,
    );
    expect(Buffer.from(recomputed)).toEqual(Buffer.from(expectRoot));
  });

  it("all inputs share one root (the merge same-root requirement)", async () => {
    const leaves = [leafHex(1), leafHex(2), leafHex(3), leafHex(4)];
    const provider = new TreeLeavesMerkleProvider({
      fetcher: fakeFetcher(leaves, 500),
    });
    const a = await provider.getInclusionProof(0n);
    const b = await provider.getInclusionProof(3n);
    expect(Buffer.from(a.root)).toEqual(Buffer.from(b.root));
  });

  it("pages a snapshot larger than one page", async () => {
    const leaves = Array.from({ length: 7 }, (_, i) => leafHex(i + 1));
    const fetcher = fakeFetcher(leaves, 3);
    const provider = new TreeLeavesMerkleProvider({ fetcher, pageSize: 3 });
    await provider.refresh();
    // 7 leaves / page 3 → pages [0,3) [3,6) [6,9) = 3 fetches
    expect((fetcher as ReturnType<typeof vi.fn>).mock.calls.length).toBe(3);
    const proof = await provider.getInclusionProof(6n);
    expect(proof.siblings).toHaveLength(TREE_DEPTH);
  });
});
