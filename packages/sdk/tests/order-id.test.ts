/**
 * Deterministic order-id derivation.
 *
 * `order_id[n] = HKDF-SHA256-expand(seed, "nyx-order-id-v1" || n_u32_le)[:16]`
 *
 * order_id is client-only (the TEE just echoes it back in the settle payload),
 * so there is no Rust parity vector — but determinism is load-bearing: a fresh
 * device rebuilds full trade history by re-deriving order_id[0..] and gap-scanning
 * the indexer, so the bytes MUST be stable across versions. These fixed vectors
 * pin them. (Sibling: the formula check re-derives via the documented HKDF path.)
 */

import { describe, it, expect } from "vitest";
import { deriveOrderId, deriveMergeInnerHash, BN254_R, __testing } from "../src/keys/key-generators.js";

const SEED = new Uint8Array(64);
for (let i = 0; i < 64; i++) SEED[i] = i;

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

// Pinned regression vectors (seed = [0,1,…,63]). If these change, every
// client's history gap-scan breaks — treat a diff here as a breaking change.
const VECTORS: Record<number, string> = {
  0: "ea59c471259380fae2de21114aa5b994",
  1: "c2362c3aef579b5ec5491873e7bb4402",
  2: "7ae5f5782178d9427cbf463b6e2e266b",
  255: "e070278900719ce9cd7480e62e1ca508",
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
    const INFO = new TextEncoder().encode("nyx-order-id-v1");
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

describe("deriveMergeInnerHash", () => {
  it("is a deterministic, distinct, in-range Fr per (seed, n)", () => {
    expect(deriveMergeInnerHash(SEED, 0)).toBe(deriveMergeInnerHash(SEED, 0));
    expect(deriveMergeInnerHash(SEED, 0)).not.toBe(deriveMergeInnerHash(SEED, 1));
    expect(deriveMergeInnerHash(SEED, 5)).toBeLessThan(BN254_R);
    expect(deriveMergeInnerHash(SEED, 5)).toBeGreaterThanOrEqual(0n);
  });

  it("rejects out-of-range n", () => {
    expect(() => deriveMergeInnerHash(SEED, -1)).toThrow();
    expect(() => deriveMergeInnerHash(SEED, 0x1_0000_0000)).toThrow();
  });
});
