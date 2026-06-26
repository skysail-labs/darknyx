/**
 * Shadow incremental Merkle tree for VALID_SPEND witnesses — mirrors
 * `packages/sdk/tests/helpers/merkle-shadow.ts` (Poseidon2 parity with on-chain vault).
 */
import { poseidonHashBytesBE } from "@nyx/sdk";

export const TREE_DEPTH = 20;

export interface MerkleWitness {
  root: Uint8Array;
  siblings: Uint8Array[];
  indices: number[];
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
    let cur = new Uint8Array(32);
    for (let i = 0; i < TREE_DEPTH; i++) {
      z.push(cur);
      const nxt = await this.poseidon2(cur, cur);
      cur = new Uint8Array(nxt);
    }
    this.zeroSubtreeRoots = z;
  }

  private async poseidon2(a: Uint8Array, b: Uint8Array): Promise<Uint8Array> {
    const out = await poseidonHashBytesBE([bytesToBigInt(a), bytesToBigInt(b)]);
    return new Uint8Array(out);
  }

  async append(leaf: Uint8Array): Promise<Uint8Array> {
    this.leaves.push(new Uint8Array(leaf));
    this.leafCount += 1;
    return this.computeRoot();
  }

  async computeRoot(): Promise<Uint8Array> {
    let level: Uint8Array[] = this.leaves.slice();
    for (let d = 0; d < TREE_DEPTH; d++) {
      const next: Uint8Array[] = [];
      for (let i = 0; i < level.length; i += 2) {
        const l = level[i];
        const r =
          i + 1 < level.length ? level[i + 1] : this.zeroSubtreeRoots[d];
        next.push(await this.poseidon2(l, r));
      }
      if (next.length === 0) {
        let z = this.zeroSubtreeRoots[d];
        for (let e = d; e < TREE_DEPTH; e++) z = await this.poseidon2(z, z);
        return z;
      }
      level = next;
    }
    return level[0];
  }

  async witness(targetIndex: number): Promise<MerkleWitness> {
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
    if (smallDepth === 0) smallDepth = 1;

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
