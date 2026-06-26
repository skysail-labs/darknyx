/**
 * Client-side anchor pool derivation + top-up signing (Phase 8).
 */

import { describe, expect, it } from "vitest";

import {
  buildAnchorPool,
  deriveAnchors,
  buildAnchorTopUp,
} from "../src/orders/anchor-pool.js";
import {
  ANCHOR_POOL_SIZE,
  ANCHOR_TOPUP_SIZE,
  anchorPoolHash,
  anchorTopUpCanonicalDigest,
} from "../src/orders/canonical.js";
import { deriveInnerHash, bn254ToBE32 } from "../src/keys/key-generators.js";
import { nullifierV2 } from "../src/utxo/note.js";

const SEED = new Uint8Array(64).map((_, i) => i);
const SK = 12345678901234567890n;
const ORDER_ID = new Uint8Array(16).fill(0xab);

describe("anchor pool — client derivation", () => {
  it("builds a deterministic ANCHOR_POOL_SIZE pool whose hash matches the canonical", async () => {
    const a = await buildAnchorPool(SEED, SK, ORDER_ID);
    const b = await buildAnchorPool(SEED, SK, ORDER_ID);
    expect(a.anchors.length).toBe(ANCHOR_POOL_SIZE);
    // Deterministic from (seed, orderId).
    expect(Buffer.from(a.poolHash)).toEqual(Buffer.from(b.poolHash));
    // The reported poolHash matches anchorPoolHash over the anchors.
    expect(Buffer.from(a.poolHash)).toEqual(
      Buffer.from(anchorPoolHash(a.anchors)),
    );
    // Indices are 0..N-1.
    expect(a.anchors.map((x) => x.index)).toEqual([
      ...Array(ANCHOR_POOL_SIZE).keys(),
    ]);
  });

  it("each anchor's (inner_hash, nullifier) matches direct derivation", async () => {
    const pool = await buildAnchorPool(SEED, SK, ORDER_ID);
    for (const anc of pool.anchors) {
      const innerBig = deriveInnerHash(SEED, ORDER_ID, anc.index);
      expect(Buffer.from(anc.innerHash)).toEqual(
        Buffer.from(bn254ToBE32(innerBig)),
      );
      expect(Buffer.from(anc.nullifier)).toEqual(
        Buffer.from(await nullifierV2(SK, innerBig)),
      );
    }
  });

  it("a different order id yields a disjoint pool", async () => {
    const a = await buildAnchorPool(SEED, SK, ORDER_ID);
    const b = await buildAnchorPool(SEED, SK, new Uint8Array(16).fill(0xcd));
    expect(Buffer.from(a.poolHash)).not.toEqual(Buffer.from(b.poolHash));
  });

  it("top-up continues the index sequence + signs the right digest", async () => {
    let signed: Uint8Array | undefined;
    const body = await buildAnchorTopUp({
      masterSeed: SEED,
      spendingKey: SK,
      orderId: ORDER_ID,
      startIndex: ANCHOR_POOL_SIZE, // continue after the initial pool
      topupNonce: 1n,
      tradingKey: new Uint8Array(32).fill(0x55),
      sign: (digest) => {
        signed = digest;
        return new Uint8Array(64).fill(0x11);
      },
    });
    expect(body.anchors.length).toBe(ANCHOR_TOPUP_SIZE);
    expect(body.topup_nonce).toBe(1);

    // The signed digest is anchorTopUpCanonicalDigest over the new pool.
    const newAnchors = await deriveAnchors(
      SEED,
      SK,
      ORDER_ID,
      ANCHOR_TOPUP_SIZE,
      ANCHOR_POOL_SIZE,
    );
    const expectedDigest = anchorTopUpCanonicalDigest({
      orderId: ORDER_ID,
      anchorPoolHash: anchorPoolHash(newAnchors),
      topupNonce: 1n,
    });
    expect(signed).toBeDefined();
    expect(Buffer.from(signed!)).toEqual(Buffer.from(expectedDigest));

    // The new inner_hashes don't collide with the initial pool's.
    const initial = await buildAnchorPool(SEED, SK, ORDER_ID);
    const initialInners = new Set(
      initial.anchors.map((a) => Buffer.from(a.innerHash).toString("hex")),
    );
    for (const a of body.anchors) {
      expect(initialInners.has(a.inner_hash)).toBe(false);
    }
  });
});
