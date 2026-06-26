/**
 * Client-side continuation anchor pool (Phase 8).
 *
 * A client derives its anchor pool DETERMINISTICALLY from its master seed
 * + order id, so it never has to persist the pool: it can regenerate every
 * `(inner_hash, nullifier)` pair — and therefore recover every change note —
 * from `(masterSeed, orderId)` alone. Each anchor is:
 *
 *   inner_hash[j] = deriveInnerHash(masterSeed, orderId, j)
 *   nullifier[j]  = nullifierV2(spendingKey, inner_hash[j])
 *
 * The pool's SHA-256 (`anchorPoolHash`) is bound into the signed order
 * canonical body (v2); a WebSocket top-up signs over the hash of just the
 * NEW anchors (continuing the index sequence).
 */

import {
  ANCHOR_POOL_SIZE,
  ANCHOR_TOPUP_SIZE,
  anchorPoolHash,
  anchorTopUpCanonicalDigest,
  type Anchor,
} from "./canonical.js";
import { deriveInnerHash, bn254ToBE32 } from "../keys/key-generators.js";
import { nullifierV2 } from "../utxo/note.js";

/** A pool entry with its index — the index is what a `FillMemo` reports. */
export interface IndexedAnchor extends Anchor {
  index: number;
}

/**
 * Derive `count` anchors starting at `startIndex` for `orderId`. Async
 * because the nullifier is a Poseidon hash.
 */
export async function deriveAnchors(
  masterSeed: Uint8Array,
  spendingKey: bigint,
  orderId: Uint8Array,
  count: number,
  startIndex = 0,
): Promise<IndexedAnchor[]> {
  if (orderId.length !== 16) throw new Error("orderId must be 16 bytes");
  const out: IndexedAnchor[] = [];
  for (let k = 0; k < count; k++) {
    const index = startIndex + k;
    const innerBig = deriveInnerHash(masterSeed, orderId, index);
    out.push({
      index,
      innerHash: bn254ToBE32(innerBig),
      nullifier: await nullifierV2(spendingKey, innerBig),
    });
  }
  return out;
}

export interface BuiltAnchorPool {
  anchors: IndexedAnchor[];
  /** SHA-256 over the pool — fold into the v2 order canonical digest. */
  poolHash: Uint8Array;
}

/** Build the full initial pool (`ANCHOR_POOL_SIZE` anchors, indices 0..N-1). */
export async function buildAnchorPool(
  masterSeed: Uint8Array,
  spendingKey: bigint,
  orderId: Uint8Array,
): Promise<BuiltAnchorPool> {
  const anchors = await deriveAnchors(
    masterSeed,
    spendingKey,
    orderId,
    ANCHOR_POOL_SIZE,
    0,
  );
  return { anchors, poolHash: anchorPoolHash(anchors) };
}

/** JSON-shaped anchor for the request body (`{ inner_hash, nullifier }` hex). */
export function anchorsToJson(
  anchors: Anchor[],
): { inner_hash: string; nullifier: string }[] {
  const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
  return anchors.map((a) => ({
    inner_hash: hex(a.innerHash),
    nullifier: hex(a.nullifier),
  }));
}

export interface AnchorTopUpBody {
  anchors: { inner_hash: string; nullifier: string }[];
  topup_nonce: number;
  trading_key: string;
  trading_key_signature: string;
}

/**
 * Build a signed `POST /orders/{id}/anchors` body. `startIndex` continues
 * the pool's index sequence (so the new inner_hashes don't collide with the
 * already-consumed ones); `sign` is the trading-key Ed25519 signer.
 */
export async function buildAnchorTopUp(args: {
  masterSeed: Uint8Array;
  spendingKey: bigint;
  orderId: Uint8Array;
  startIndex: number;
  topupNonce: bigint;
  tradingKey: Uint8Array; // 32-byte pubkey
  sign: (digest: Uint8Array) => Promise<Uint8Array> | Uint8Array;
  count?: number;
}): Promise<AnchorTopUpBody> {
  const count = args.count ?? ANCHOR_TOPUP_SIZE;
  // topup_nonce goes on the wire as a JSON number; the signature is over the
  // exact bigint. Reject values that wouldn't round-trip through a JS number
  // (would silently desync the wire value from the signed digest → 403).
  if (
    args.topupNonce < 0n ||
    args.topupNonce > BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    throw new Error(
      `topupNonce out of safe range [0, 2^53): ${args.topupNonce}`,
    );
  }
  const anchors = await deriveAnchors(
    args.masterSeed,
    args.spendingKey,
    args.orderId,
    count,
    args.startIndex,
  );
  const poolHash = anchorPoolHash(anchors);
  const digest = anchorTopUpCanonicalDigest({
    orderId: args.orderId,
    anchorPoolHash: poolHash,
    topupNonce: args.topupNonce,
  });
  const signature = await args.sign(digest);
  const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
  return {
    anchors: anchorsToJson(anchors),
    topup_nonce: Number(args.topupNonce),
    trading_key: hex(args.tradingKey),
    trading_key_signature: hex(signature),
  };
}
