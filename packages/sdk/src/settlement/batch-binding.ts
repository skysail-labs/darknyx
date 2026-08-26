/** Reconstruct the MATCH_BATCH leaf/root published by a finalized Tx D.
 *
 * The fee collector uses this to pair each successful settlement with its Tx B
 * encrypted fee record without trusting transaction adjacency or an online
 * journal. The formulas mirror `prover/leaf.rs` and the N=16 circuit.
 */

import { poseidonHashBytesBE } from "../utxo/note.js";
import type { MatchResultPayload } from "./settle-builder.js";

export const DOMAIN_BATCH_ROOT = 22n;
export const DOMAIN_RELOCK_DIGEST = 30n;
export const DOMAIN_MATCH_LEAF_V3 = 31n;
export const MATCH_BATCH_DEPTH = 4;
export const MATCH_BATCH_SLOTS = 16;

function bytesToBigIntBE(value: Uint8Array, name: string): bigint {
  if (value.length !== 32) throw new Error(`${name} must be 32 bytes`);
  let out = 0n;
  for (const byte of value) out = (out << 8n) | BigInt(byte);
  return out;
}

/** Compute the active-slot leaf from public Tx D payload fields. */
export async function computeSettlementBatchLeaf(
  payload: MatchResultPayload,
): Promise<Uint8Array> {
  if (payload.batchSlot < 0n || payload.batchSlot >= 16n) {
    throw new Error("settlement batch slot must be in [0, 15]");
  }
  const relockDigest = await poseidonHashBytesBE([
    DOMAIN_RELOCK_DIGEST,
    bytesToBigIntBE(payload.noteEuseTag, "note E use tag"),
    bytesToBigIntBE(payload.noteFuseTag, "note F use tag"),
  ]);
  return poseidonHashBytesBE([
    DOMAIN_MATCH_LEAF_V3,
    1n,
    bytesToBigIntBE(payload.noteAuseTag, "note A use tag"),
    bytesToBigIntBE(payload.noteBuseTag, "note B use tag"),
    bytesToBigIntBE(payload.noteCcommitment, "note C commitment"),
    bytesToBigIntBE(payload.noteDcommitment, "note D commitment"),
    bytesToBigIntBE(payload.noteEcommitment, "note E commitment"),
    bytesToBigIntBE(payload.noteFcommitment, "note F commitment"),
    bytesToBigIntBE(payload.noteFeeBaseCommitment, "base fee commitment"),
    bytesToBigIntBE(payload.noteFeeQuoteCommitment, "quote fee commitment"),
    payload.batchSlot,
    bytesToBigIntBE(relockDigest, "relock digest"),
  ]);
}

/** Fold the exact four Tx D siblings into the N=16 batch root. */
export async function computeSettlementBatchRoot(params: {
  leaf: Uint8Array;
  matchIndex: number;
  siblings: readonly Uint8Array[];
}): Promise<Uint8Array> {
  if (
    !Number.isInteger(params.matchIndex) ||
    params.matchIndex < 0 ||
    params.matchIndex >= MATCH_BATCH_SLOTS
  ) {
    throw new Error("match index must be in [0, 15]");
  }
  if (params.siblings.length !== MATCH_BATCH_DEPTH) {
    throw new Error(`batch proof must contain ${MATCH_BATCH_DEPTH} siblings`);
  }
  let node: Uint8Array = Uint8Array.from(params.leaf);
  let index = params.matchIndex;
  for (const [level, sibling] of params.siblings.entries()) {
    const siblingValue = bytesToBigIntBE(sibling, `sibling ${level}`);
    const nodeValue = bytesToBigIntBE(node, `node ${level}`);
    node = await poseidonHashBytesBE(
      index & 1
        ? [DOMAIN_BATCH_ROOT, siblingValue, nodeValue]
        : [DOMAIN_BATCH_ROOT, nodeValue, siblingValue],
    );
    index >>= 1;
  }
  return node;
}
