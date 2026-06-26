/**
 * Compute a VALID_SPEND inclusion witness for a leaf that we just appended
 * to the on-chain vault Merkle tree, using the `right_path` snapshot we
 * captured BEFORE the append.
 *
 * Why this works
 * --------------
 * The on-chain `programs/vault/src/merkle.rs::append_leaf` walks levels
 * 0..MERKLE_DEPTH and at each level chooses the sibling like so:
 *   - bit `d` of `leafIndex` is `0` (left child)  → sibling = zero_subtree[d]
 *   - bit `d` of `leafIndex` is `1` (right child) → sibling = right_path[d]
 *     **as it was BEFORE the append** (because that level's right_path slot
 *     gets overwritten as we walk up).
 *
 * So if we snapshot `right_path` BEFORE the deposit ix executes (which is
 * what `/api/dapp/private-deposit` does by reading `vault_config`), then we
 * can reconstruct the exact siblings + indices the circuit needs.
 *
 * Limitation: this only works when the leaf we're proving inclusion for is
 * the LATEST appended leaf at the time of withdraw — i.e. nothing else got
 * appended between the user's deposit and the user's withdraw on the same
 * vault. The demo uses a dedicated `e2e-config.json` market, so there is no
 * concurrent activity in practice. If a third-party append slips in, the
 * server's leaf-count check rejects with a clear error.
 */

import { poseidonHashBytesBE } from "@nyx/sdk";

export const MERKLE_DEPTH = 20;

let cachedZeros: Uint8Array[] | null = null;

/** Compute `zero_subtree_roots[0..MERKLE_DEPTH]` matching the on-chain vault. */
export async function computeZeroSubtreeRoots(): Promise<Uint8Array[]> {
  if (cachedZeros) return cachedZeros;
  const out: Uint8Array[] = new Array(MERKLE_DEPTH);
  let cur: Uint8Array = new Uint8Array(32);
  for (let i = 0; i < MERKLE_DEPTH; i++) {
    out[i] = cur;
    cur = (await poseidonPair(cur, cur)) as Uint8Array;
  }
  cachedZeros = out;
  return out;
}

async function poseidonPair(a: Uint8Array, b: Uint8Array): Promise<Uint8Array> {
  return (await poseidonHashBytesBE([
    beToBigInt(a),
    beToBigInt(b),
  ])) as Uint8Array;
}

function beToBigInt(x: Uint8Array): bigint {
  let acc = 0n;
  for (const b of x) acc = (acc << 8n) | BigInt(b);
  return acc;
}

export interface LatestLeafWitness {
  /** Merkle root after the leaf was appended (32B BE). */
  root: Uint8Array;
  /** Length-20 array of 32B BE sibling values, level 0 (leaf) → 19. */
  siblings: Uint8Array[];
  /** Length-20 array of {0,1} indicating whether the leaf path is on the right. */
  indices: number[];
}

/**
 * Build the inclusion witness for a leaf at `leafIndex` (which must be
 * `priorLeafCount`, i.e. exactly one past the snapshotted leaf count).
 *
 * @param leaf            32B BE leaf commitment
 * @param leafIndex       index where the leaf landed
 * @param priorRightPath  20 entries × 32B BE — `right_path` BEFORE the append
 */
export async function witnessFromPriorRightPath(
  leaf: Uint8Array,
  leafIndex: bigint,
  priorRightPath: Uint8Array[],
): Promise<LatestLeafWitness> {
  if (leaf.length !== 32) throw new Error("leaf must be 32 bytes");
  if (priorRightPath.length !== MERKLE_DEPTH) {
    throw new Error(`priorRightPath must have ${MERKLE_DEPTH} entries`);
  }

  const zeros = await computeZeroSubtreeRoots();
  const siblings: Uint8Array[] = new Array(MERKLE_DEPTH);
  const indices: number[] = new Array(MERKLE_DEPTH);

  let cur: Uint8Array = leaf;
  for (let d = 0; d < MERKLE_DEPTH; d++) {
    const bit = Number((leafIndex >> BigInt(d)) & 1n);
    indices[d] = bit;
    if (bit === 0) {
      siblings[d] = zeros[d];
      cur = (await poseidonPair(cur, zeros[d])) as Uint8Array;
    } else {
      siblings[d] = priorRightPath[d];
      cur = (await poseidonPair(priorRightPath[d], cur)) as Uint8Array;
    }
  }

  return { root: cur, siblings, indices };
}
