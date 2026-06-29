/**
 * LocalMerkleTree — an in-memory snapshot of the vault's incremental Merkle
 * tree, for producing by-LEAF-INDEX inclusion proofs the SDK merge path needs.
 *
 * The TEE's `GET /tree/inclusion` is keyed by COMMITMENT and returns the CURRENT
 * root — so fetching k proofs one-by-one for a merge would see a moving root (the
 * TEE settles constantly) and the proofs wouldn't share a root. Instead we pull
 * ONE `/tree/leaves` snapshot and compute every proof locally against that single
 * root — race-free. The construction is byte-identical to
 * `programs/vault/src/merkle.rs` (depth 20, `poseidon2(left,right)`,
 * `zero_subtree_roots[i] = poseidon2^i(0)`), ported from the SDK's
 * parity-validated `MerkleShadow`.
 */

import { poseidonHashBytesBE } from "@nyx/sdk";

export const TREE_DEPTH = 20;

export interface LocalMerkleWitness {
  root: Uint8Array; // 32B BE
  siblings: Uint8Array[]; // 20 × 32B BE
  indices: number[]; // 20 × {0,1}
}

const bytesToBigInt = (x: Uint8Array): bigint => {
  let hex = "0x";
  for (const b of x) hex += b.toString(16).padStart(2, "0");
  return BigInt(hex);
};

export class LocalMerkleTree {
  private zeroSubtreeRoots: Uint8Array[] = [];

  private constructor(private readonly leaves: Uint8Array[]) {}

  /** Build a tree from an ordered leaf list (index 0 = first appended). */
  static async fromLeaves(leaves: Uint8Array[]): Promise<LocalMerkleTree> {
    const t = new LocalMerkleTree(leaves.slice());
    await t.initZero();
    return t;
  }

  get leafCount(): number {
    return this.leaves.length;
  }

  private async initZero(): Promise<void> {
    const z: Uint8Array[] = [];
    let cur: Uint8Array = new Uint8Array(32);
    for (let i = 0; i < TREE_DEPTH; i++) {
      z.push(cur);
      cur = await this.poseidon2(cur, cur);
    }
    this.zeroSubtreeRoots = z;
  }

  private poseidon2(a: Uint8Array, b: Uint8Array): Promise<Uint8Array> {
    return poseidonHashBytesBE([bytesToBigInt(a), bytesToBigInt(b)]);
  }

  /** The full-depth root of the current leaf set. */
  async root(): Promise<Uint8Array> {
    let level: Uint8Array[] = this.leaves.slice();
    for (let d = 0; d < TREE_DEPTH; d++) {
      if (level.length === 0) {
        let z = this.zeroSubtreeRoots[d];
        for (let e = d; e < TREE_DEPTH; e++) z = await this.poseidon2(z, z);
        return z;
      }
      const next: Uint8Array[] = [];
      for (let i = 0; i < level.length; i += 2) {
        const l = level[i];
        const r =
          i + 1 < level.length ? level[i + 1] : this.zeroSubtreeRoots[d];
        next.push(await this.poseidon2(l, r));
      }
      level = next;
    }
    return level[0];
  }

  /**
   * Inclusion witness for the leaf at `targetIndex` (mirrors `merkle_witness`
   * in the vault's spend-roundtrip test): siblings + path bits + the root.
   */
  async witness(targetIndex: number): Promise<LocalMerkleWitness> {
    if (targetIndex < 0 || targetIndex >= this.leaves.length) {
      throw new Error(
        `leaf ${targetIndex} out of range (have ${this.leaves.length})`,
      );
    }
    const siblings: Uint8Array[] = new Array(TREE_DEPTH);
    const indices: number[] = new Array(TREE_DEPTH);

    const n = this.leaves.length;
    let small = 1;
    let smallDepth = 0;
    while (small < n) {
      small <<= 1;
      smallDepth += 1;
    }
    if (smallDepth === 0) smallDepth = 1; // always at least one sibling

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

    // The growing tree extends on its right edge → remaining path goes left.
    let current = level[0];
    for (let d = smallDepth; d < TREE_DEPTH; d++) {
      siblings[d] = this.zeroSubtreeRoots[d];
      indices[d] = 0;
      current = await this.poseidon2(current, this.zeroSubtreeRoots[d]);
    }

    return { root: current, siblings, indices };
  }
}
