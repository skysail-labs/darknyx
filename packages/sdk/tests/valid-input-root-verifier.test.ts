/**
 * C-09 — `onchainRootVerifier` cross-checks a TEE-supplied inclusion root
 * against the on-chain shard root ring before the client proves against it.
 * These tests mock the on-chain `MerkleTree` account bytes (no RPC).
 */

import { describe, it, expect } from "vitest";
import { PublicKey } from "@solana/web3.js";

import { onchainRootVerifier } from "../src/zk/valid-input-prover.js";

const PROGRAM_ID = new PublicKey(
  "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
);

const ROOT_HISTORY_SIZE = 64;
const CURRENT_ROOT_OFFSET = 16;
const ROOTS_RING_OFFSET = 48;

/** Build a `MerkleTree` account buffer with `current` at current_root and each
 *  of `ring` at successive ring slots (mirrors the Rust struct layout). */
function mtAccount(current: Uint8Array, ring: Uint8Array[]): Buffer {
  const size = 8 + 8 + 32 + ROOT_HISTORY_SIZE * 32 + 20 * 32 + 8;
  const buf = Buffer.alloc(size);
  Buffer.from(current).copy(buf, CURRENT_ROOT_OFFSET);
  ring.forEach((r, i) => Buffer.from(r).copy(buf, ROOTS_RING_OFFSET + i * 32));
  return buf;
}

// Minimal Connection stub — only getAccountInfo is used.
function mockConn(data: Buffer | null) {
  return {
    getAccountInfo: async () => (data ? { data } : null),
  } as unknown as import("@solana/web3.js").Connection;
}

const r = (b: number) => new Uint8Array(32).fill(b);

describe("onchainRootVerifier (C-09)", () => {
  it("accepts the current_root", async () => {
    const verify = onchainRootVerifier({
      connection: mockConn(mtAccount(r(0xab), [])),
      programId: PROGRAM_ID,
    });
    await expect(verify(r(0xab), 0)).resolves.toBeUndefined();
  });

  it("accepts a root present in the ring", async () => {
    const verify = onchainRootVerifier({
      connection: mockConn(mtAccount(r(0x11), [r(0x22), r(0x33)])),
      programId: PROGRAM_ID,
    });
    await expect(verify(r(0x33), 0)).resolves.toBeUndefined();
  });

  it("rejects a root that is in neither current nor the ring", async () => {
    const verify = onchainRootVerifier({
      connection: mockConn(mtAccount(r(0x11), [r(0x22)])),
      programId: PROGRAM_ID,
    });
    await expect(verify(r(0x99), 0)).rejects.toThrow(/not in shard/);
  });

  it("rejects an all-zero root (must not match empty ring slots)", async () => {
    const verify = onchainRootVerifier({
      connection: mockConn(mtAccount(r(0x11), [r(0x22)])),
      programId: PROGRAM_ID,
    });
    await expect(verify(new Uint8Array(32), 0)).rejects.toThrow(/not in shard/);
  });

  it("throws when the shard account is missing on-chain", async () => {
    const verify = onchainRootVerifier({
      connection: mockConn(null),
      programId: PROGRAM_ID,
    });
    await expect(verify(r(0x01), 0)).rejects.toThrow(/not found/);
  });
});
