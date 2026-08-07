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

import { poseidonHashBytesBE } from "@darknyx/sdk";

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
  /** Level 0 is leaves; level TREE_DEPTH contains the single root. */
  private levels: Uint8Array[][] = [];
  private buildHashCount = 0;

  private constructor(private readonly leaves: Uint8Array[]) {}

  /** Build a tree from an ordered leaf list (index 0 = first appended). */
  static async fromLeaves(leaves: Uint8Array[]): Promise<LocalMerkleTree> {
    const owned = leaves.map((leaf, index) => {
      if (leaf.length !== 32) {
        throw new Error(`leaf ${index} must be 32 bytes`);
      }
      return leaf.slice();
    });
    const t = new LocalMerkleTree(owned);
    await t.initZero();
    await t.buildLevels();
    return t;
  }

  get leafCount(): number {
    return this.leaves.length;
  }

  private async initZero(): Promise<void> {
    const z: Uint8Array[] = [];
    let cur: Uint8Array = new Uint8Array(32);
    for (let i = 0; i <= TREE_DEPTH; i++) {
      z.push(cur);
      if (i < TREE_DEPTH) cur = await this.poseidon2(cur, cur);
    }
    this.zeroSubtreeRoots = z;
  }

  /** Build the immutable snapshot once; root/witness only read these levels. */
  private async buildLevels(): Promise<void> {
    this.levels = [this.leaves];
    if (this.leaves.length === 0) return;

    let level = this.leaves;
    for (let depth = 0; depth < TREE_DEPTH; depth++) {
      const next: Uint8Array[] = [];
      for (let i = 0; i < level.length; i += 2) {
        const right =
          i + 1 < level.length ? level[i + 1] : this.zeroSubtreeRoots[depth];
        next.push(await this.poseidon2(level[i], right));
        this.buildHashCount += 1;
      }
      this.levels.push(next);
      level = next;
    }
  }

  private poseidon2(a: Uint8Array, b: Uint8Array): Promise<Uint8Array> {
    return poseidonHashBytesBE([bytesToBigInt(a), bytesToBigInt(b)]);
  }

  /** The full-depth root of the current leaf set. */
  async root(): Promise<Uint8Array> {
    const root =
      this.leaves.length === 0
        ? this.zeroSubtreeRoots[TREE_DEPTH]
        : this.levels[TREE_DEPTH][0];
    return root.slice();
  }

  /** Test-visible construction cost; reads must never increase it. */
  internalHashCount(): number {
    return this.buildHashCount;
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

    let idx = targetIndex;
    for (let d = 0; d < TREE_DEPTH; d++) {
      const siblingIdx = idx ^ 1;
      const sibling =
        siblingIdx < this.levels[d].length
          ? this.levels[d][siblingIdx]
          : this.zeroSubtreeRoots[d];
      siblings[d] = sibling.slice();
      indices[d] = idx & 1;
      idx >>= 1;
    }

    return { root: await this.root(), siblings, indices };
  }
}
