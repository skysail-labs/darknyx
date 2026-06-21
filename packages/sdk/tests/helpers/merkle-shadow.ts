/**
 * Phase-5 devnet E2E helper — a shadow incremental Merkle tree.
 *
 * The on-chain `vault_config` keeps only the `right_path` + rightmost
 * leaf index; it does NOT store the full set of leaves (too expensive).
 * To produce a VALID_SPEND inclusion proof off-chain, the SDK must keep
 * its own full copy of the leaves and replay the insertion order.
 *
 * This class does exactly that, in memory, using Poseidon2 parity with
 * `programs/vault/src/merkle.rs`:
 *   - TREE_DEPTH = 20.
 *   - Internal hash = poseidon2(left, right).
 *   - zero_subtree_roots[i] = poseidon2^i(0).
 *
 * Usage:
 *   const t = await MerkleShadow.create();
 *   await t.append(leaf);        // call after every deposit / run_batch append
 *   const w = await t.witness(i); // { root, siblings[20], indices[20] }
 */

import { poseidonHashBytesBE } from "../../src/utxo/note.js";

export const TREE_DEPTH = 20;

export interface MerkleWitness {
  root: Uint8Array; // 32B BE
  siblings: Uint8Array[]; // 20 × 32B BE
  indices: number[]; // 20 × {0,1}
}

export class MerkleShadow {
  public leafCount = 0;
  public leaves: Uint8Array[] = [];
  public zeroSubtreeRoots: Uint8Array[] = [];

  private constructor() {}

  static async create(): Promise<MerkleShadow> {
    const t = new MerkleShadow();
    await t.initZero();
    return t;
  }

  private async initZero() {
    const z: Uint8Array[] = [];
    let cur: Uint8Array = new Uint8Array(32);
    for (let i = 0; i < TREE_DEPTH; i++) {
      z.push(cur);
      cur = await this.poseidon2(cur, cur);
    }
    this.zeroSubtreeRoots = z;
  }

  private async poseidon2(a: Uint8Array, b: Uint8Array): Promise<Uint8Array> {
    return poseidonHashBytesBE([bytesToBigInt(a), bytesToBigInt(b)]);
  }

  async append(leaf: Uint8Array): Promise<Uint8Array> {
    this.leaves.push(leaf);
    this.leafCount += 1;
    return this.computeRoot();
  }

  /** O(n*depth) but fine for ≤ 2^20 leaves — the test never gets near that. */
  async computeRoot(): Promise<Uint8Array> {
    let level: Uint8Array[] = this.leaves.slice();
    for (let d = 0; d < TREE_DEPTH; d++) {
      const next: Uint8Array[] = [];
      for (let i = 0; i < level.length; i += 2) {
        const l = level[i];
        const r = i + 1 < level.length ? level[i + 1] : this.zeroSubtreeRoots[d];
        next.push(await this.poseidon2(l, r));
      }
      if (next.length === 0) {
        // Empty tree root = zero_subtree[d] upwards
        let z = this.zeroSubtreeRoots[d];
        for (let e = d; e < TREE_DEPTH; e++) z = await this.poseidon2(z, z);
        return z;
      }
      level = next;
    }
    return level[0];
  }

  /**
   * Build a Merkle-inclusion witness for the leaf at `targetIndex`.
   * Mirrors `merkle_witness` in programs/vault/tests/zk_spend_roundtrip.rs.
   */
  async witness(targetIndex: number): Promise<MerkleWitness> {
    if (targetIndex < 0 || targetIndex >= this.leaves.length) {
      throw new Error(`leaf ${targetIndex} out of range (have ${this.leaves.length})`);
    }
    const siblings: Uint8Array[] = new Array(TREE_DEPTH);
    const indices: number[] = new Array(TREE_DEPTH);

    // Small tree over just the leaves we've seen so far.
    const n = this.leaves.length;
    let small = 1;
    let smallDepth = 0;
    while (small < n) {
      small <<= 1;
      smallDepth += 1;
    }
    if (smallDepth === 0) smallDepth = 1; // min depth = 1 so there's always a sibling

    // Pad level to the next power of two with zero leaves.
    const padded = 1 << smallDepth;
    let level: Uint8Array[] = this.leaves.slice();
    while (level.length < padded) level.push(new Uint8Array(32));

    let idx = targetIndex;
    for (let d = 0; d < smallDepth; d++) {
      const siblingIdx = idx ^ 1;
      siblings[d] = level[siblingIdx];
      indices[d] = idx & 1;
      idx >>= 1;
      const next: Uint8Array[] = [];
      for (let i = 0; i < level.length; i += 2) {
        next.push(await this.poseidon2(level[i], level[i + 1]));
      }
      level = next;
    }

    // Fill the remaining depth with empty-subtree roots; the path always goes
    // left (we're extending a growing tree on its right edge).
    let current = level[0];
    for (let d = smallDepth; d < TREE_DEPTH; d++) {
      siblings[d] = this.zeroSubtreeRoots[d];
      indices[d] = 0;
      current = await this.poseidon2(current, this.zeroSubtreeRoots[d]);
    }

    return { root: current, siblings, indices };
  }
}

function bytesToBigInt(x: Uint8Array): bigint {
  let hex = "0x";
  for (const b of x) hex += b.toString(16).padStart(2, "0");
  return BigInt(hex);
}
