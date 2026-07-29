/**
 * TreeLeavesMerkleProvider tests — pages a snapshot + serves by-leaf proofs that
 * recompute the snapshot root, no gateway (the fetcher is a fake).
 */

import { describe, expect, it, vi } from "vitest";
import type { RootVerifier } from "@darknyx/sdk";

import {
  TreeLeavesMerkleProvider,
  type LeavesFetcher,
} from "../src/tree-merkle-provider.js";
import { LocalMerkleTree, TREE_DEPTH } from "../src/merkle-tree.js";
import { poseidonHashBytesBE } from "@darknyx/sdk";

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
  const root = LocalMerkleTree.fromLeaves(
    leaves.map((h) => Uint8Array.from(Buffer.from(h, "hex"))),
  ).then((tree) => tree.root());
  return vi.fn(async (from: number, to: number) => {
    const slice = leaves
      .slice(from, Math.min(to, leaves.length))
      .map((value, i) => ({ leaf_index: from + i, value }));
    void pageSize;
    return {
      leaves: slice,
      merkle_root: Buffer.from(await root).toString("hex"),
    };
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

  it("verifies the reconstructed snapshot root against the on-chain ring", async () => {
    const leaves = [leafHex(7), leafHex(8)];
    const verifyRoot = vi.fn<RootVerifier>(async () => {});
    const provider = new TreeLeavesMerkleProvider({
      fetcher: fakeFetcher(leaves, 500),
      verifyRoot,
      treeId: 3,
    });
    await provider.refresh();
    expect(verifyRoot).toHaveBeenCalledOnce();
    expect(verifyRoot.mock.calls[0][1]).toBe(3);
  });

  it("rejects a snapshot whose advertised root changes between pages", async () => {
    const leaves = [leafHex(1), leafHex(2), leafHex(3)];
    const good = fakeFetcher(leaves, 2);
    const fetcher: LeavesFetcher = vi.fn(async (from, to, treeId) => {
      const page = await good(from, to, treeId);
      return from === 0 ? page : { ...page, merkle_root: "ff".repeat(32) };
    });
    const provider = new TreeLeavesMerkleProvider({
      fetcher,
      pageSize: 2,
    });
    await expect(provider.refresh()).rejects.toThrow(/root changed/);
  });

  it("rejects fabricated leaves that do not reconstruct the advertised root", async () => {
    const fetcher: LeavesFetcher = vi.fn(async () => ({
      leaves: [{ leaf_index: 0, value: leafHex(1) }],
      merkle_root: "ee".repeat(32),
    }));
    const provider = new TreeLeavesMerkleProvider({ fetcher });
    await expect(provider.refresh()).rejects.toThrow(/does not match/);
  });

  it("rejects gapped leaf indices and invalid pagination parameters", async () => {
    const fetcher: LeavesFetcher = vi.fn(async () => ({
      leaves: [{ leaf_index: 1, value: leafHex(1) }],
      merkle_root: "ee".repeat(32),
    }));
    const provider = new TreeLeavesMerkleProvider({ fetcher });
    await expect(provider.refresh()).rejects.toThrow(
      /expected leaf_index 0, got 1/,
    );
    expect(
      () => new TreeLeavesMerkleProvider({ fetcher, pageSize: 0 }),
    ).toThrow(/page size must be a positive integer/);
  });
});
