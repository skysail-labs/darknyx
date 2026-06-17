/**
 * Unit test for the shadow Merkle tree — verifies parity with the on-chain
 * incremental Merkle tree by (a) checking the empty root and (b) confirming
 * that witness(i).root reconstructs to the same root after N appends.
 */

import { describe, expect, it } from "vitest";

import { poseidonHashBytesBE } from "../../src/utxo/note.js";

import { MerkleShadow, TREE_DEPTH } from "./merkle-shadow.js";

describe("Phase 5 — MerkleShadow parity with on-chain incremental tree", () => {
  it("[empty_tree_root_matches] empty root survives 20 levels of poseidon2(0,0)", async () => {
    const t = await MerkleShadow.create();
    const root = await t.computeRoot();

    // Brute-force: z_{i+1} = poseidon2(z_i, z_i), starting from z_0 = 0.
    // on-chain `empty_root` = poseidon2^TREE_DEPTH(0) = z_{TREE_DEPTH}.
    let cur: Uint8Array = new Uint8Array(32);
    for (let i = 0; i < TREE_DEPTH; i++) {
      cur = await poseidonHashBytesBE([bytesToBigInt(cur), bytesToBigInt(cur)]);
    }
    expect(root).toEqual(cur);
  });

  it("[witness_roundtrip] replaying siblings + indices recovers the root", async () => {
    const t = await MerkleShadow.create();
    const leaves = [
      bytes32(0x10),
      bytes32(0x20),
      bytes32(0x30),
      bytes32(0x40),
    ];
    for (const l of leaves) await t.append(l);
    const root = await t.computeRoot();

    for (let i = 0; i < leaves.length; i++) {
      const w = await t.witness(i);
      expect(w.root).toEqual(root);
      // Replay up the path.
      let cur = leaves[i];
      for (let d = 0; d < TREE_DEPTH; d++) {
        const s = w.siblings[d];
        cur = w.indices[d] === 0
          ? await poseidonHashBytesBE([bytesToBigInt(cur), bytesToBigInt(s)])
          : await poseidonHashBytesBE([bytesToBigInt(s), bytesToBigInt(cur)]);
      }
      expect(cur).toEqual(root);
    }
  });
});

function bytes32(v: number): Uint8Array {
  const o = new Uint8Array(32);
  o[31] = v & 0xff;
  return o;
}

function bytesToBigInt(x: Uint8Array): bigint {
  let hex = "0x";
  for (const b of x) hex += b.toString(16).padStart(2, "0");
  return BigInt(hex);
}
