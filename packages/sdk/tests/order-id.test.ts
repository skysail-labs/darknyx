/**
 * Deterministic order-id derivation.
 *
 * `order_id[n] = HKDF-SHA256-expand(seed, "darknyx-order-id-v2" || n_u32_le)[:16]`
 *
 * order_id is client-only (the TEE just echoes it back in the settle payload),
 * so there is no Rust parity vector — but determinism is load-bearing: a fresh
 * device rebuilds full trade history by re-deriving order_id[0..] and gap-scanning
 * the indexer, so the bytes MUST be stable across versions. These fixed vectors
 * pin them. (Sibling: the formula check re-derives via the documented HKDF path.)
 */

import { describe, it, expect } from "vitest";
import { deriveOrderId, __testing } from "../src/keys/key-generators.js";

const SEED = new Uint8Array(64);
for (let i = 0; i < 64; i++) SEED[i] = i;

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

// Pinned regression vectors (seed = [0,1,…,63]). If these change, every
// client's history gap-scan breaks — treat a diff here as a breaking change.
const VECTORS: Record<number, string> = {
  0: "49e01ba74836cd2b89d17d19cfccb97f",
  1: "d0e5e691ee849284b541c1a02c9d3d95",
  2: "40cf0cee6293e65dd422958ed8e67403",
  255: "906449c71d0b836ab19d0e6c824abd7d",
};

describe("deriveOrderId", () => {
  it("matches the pinned fixed vectors", () => {
    for (const [n, expected] of Object.entries(VECTORS)) {
      expect(hex(deriveOrderId(SEED, Number(n)))).toBe(expected);
    }
  });

  it("is 16 bytes", () => {
    expect(deriveOrderId(SEED, 0).length).toBe(16);
  });

  it("is deterministic for a given (seed, n)", () => {
    expect(hex(deriveOrderId(SEED, 7))).toBe(hex(deriveOrderId(SEED, 7)));
  });

  it("is distinct per n and per seed", () => {
    const a = hex(deriveOrderId(SEED, 0));
    const b = hex(deriveOrderId(SEED, 1));
    expect(a).not.toBe(b);
    const other = new Uint8Array(64).fill(9);
    expect(hex(deriveOrderId(other, 0))).not.toBe(a);
  });

  it("re-derives via the documented HKDF construction", () => {
    const INFO = new TextEncoder().encode("darknyx-order-id-v2");
    const n = 42;
    const nBuf = new ArrayBuffer(4);
    new DataView(nBuf).setUint32(0, n, true);
    const info = new Uint8Array(INFO.length + 4);
    info.set(INFO, 0);
    info.set(new Uint8Array(nBuf), INFO.length);
    const expected = __testing.hkdfExpand(SEED, info, 16);
    expect(hex(deriveOrderId(SEED, n))).toBe(hex(expected));
  });

  it("rejects out-of-range n", () => {
    expect(() => deriveOrderId(SEED, -1)).toThrow();
    expect(() => deriveOrderId(SEED, 1.5)).toThrow();
    expect(() => deriveOrderId(SEED, 0x1_0000_0000)).toThrow();
  });
});
