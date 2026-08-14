/**
 * C-09 — `onchainRootVerifier` cross-checks a TEE-supplied inclusion root
 * against the on-chain shard root ring before the client proves against it.
 * These tests mock the on-chain `MerkleTree` account bytes (no RPC).
 */

import { createHash } from "node:crypto";
import { describe, it, expect, vi } from "vitest";
import { Keypair, PublicKey } from "@solana/web3.js";

import {
  onchainRootVerifier,
  parseMerkleRootRing,
} from "../src/zk/valid-input-prover.js";

const PROGRAM_ID = new PublicKey(
  "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
);

const ROOT_HISTORY_SIZE = 64;
const MERKLE_TREE_ACCOUNT_LEN = 2_744;
const CURRENT_ROOT_OFFSET = 16;
const ROOTS_RING_OFFSET = 48;
const ROOTS_HEAD_OFFSET = 2_736;
const TREE_ID_OFFSET = 2_737;
const DISCRIMINATOR = createHash("sha256")
  .update("account:MerkleTree")
  .digest()
  .subarray(0, 8);

/** Build a `MerkleTree` account buffer with `current` at current_root and each
 *  of `ring` at successive ring slots (mirrors the Rust struct layout). */
function mtAccount(
  current: Uint8Array,
  ring: Uint8Array[],
  treeId = 0,
): Buffer {
  const buf = Buffer.alloc(MERKLE_TREE_ACCOUNT_LEN);
  DISCRIMINATOR.copy(buf, 0);
  Buffer.from(current).copy(buf, CURRENT_ROOT_OFFSET);
  ring.forEach((r, i) => Buffer.from(r).copy(buf, ROOTS_RING_OFFSET + i * 32));
  buf[ROOTS_HEAD_OFFSET] = ring.length;
  buf[TREE_ID_OFFSET] = treeId;
  return buf;
}

// Minimal Connection stub — only getAccountInfo is used.
function mockConn(
  data: Buffer | null,
  owner: PublicKey = PROGRAM_ID,
): {
  connection: import("@solana/web3.js").Connection;
  getAccountInfo: ReturnType<typeof vi.fn>;
} {
  const getAccountInfo = vi.fn(async () =>
    data ? { data, owner, executable: false, lamports: 1, rentEpoch: 0 } : null,
  );
  return {
    connection: {
      getAccountInfo,
    } as unknown as import("@solana/web3.js").Connection,
    getAccountInfo,
  };
}

const r = (b: number) => new Uint8Array(32).fill(b);

describe("onchainRootVerifier (C-09)", () => {
  it("orders the current and historical roots newest first", () => {
    const parsed = parseMerkleRootRing(
      mtAccount(r(0x44), [r(0x11), r(0x22), r(0x33)]),
      0,
    );
    expect(parsed.acceptedRoots.map((root) => root[0])).toEqual([
      0x44, 0x33, 0x22, 0x11,
    ]);
  });

  it("accepts the current_root", async () => {
    const rpc = mockConn(mtAccount(r(0xab), []));
    const verify = onchainRootVerifier({
      connection: rpc.connection,
      programId: PROGRAM_ID,
    });
    await expect(verify(r(0xab), 0)).resolves.toBeUndefined();
    expect(rpc.getAccountInfo).toHaveBeenCalledWith(
      expect.any(PublicKey),
      "finalized",
    );
  });

  it("accepts a root present in the ring", async () => {
    const verify = onchainRootVerifier({
      connection: mockConn(mtAccount(r(0x11), [r(0x22), r(0x33)])).connection,
      programId: PROGRAM_ID,
    });
    await expect(verify(r(0x33), 0)).resolves.toBeUndefined();
  });

  it("rejects a root that is in neither current nor the ring", async () => {
    const verify = onchainRootVerifier({
      connection: mockConn(mtAccount(r(0x11), [r(0x22)])).connection,
      programId: PROGRAM_ID,
    });
    await expect(verify(r(0x99), 0)).rejects.toThrow(/not in shard/);
  });

  it("rejects an all-zero root (must not match empty ring slots)", async () => {
    const verify = onchainRootVerifier({
      connection: mockConn(mtAccount(r(0x11), [r(0x22)])).connection,
      programId: PROGRAM_ID,
    });
    await expect(verify(new Uint8Array(32), 0)).rejects.toThrow(/all-zero/);
  });

  it("throws when the shard account is missing on-chain", async () => {
    const verify = onchainRootVerifier({
      connection: mockConn(null).connection,
      programId: PROGRAM_ID,
    });
    await expect(verify(r(0x01), 0)).rejects.toThrow(/not found/);
  });

  it("rejects an account owned by a different program", async () => {
    const verify = onchainRootVerifier({
      connection: mockConn(mtAccount(r(0x11), []), Keypair.generate().publicKey)
        .connection,
      programId: PROGRAM_ID,
    });
    await expect(verify(r(0x11), 0)).rejects.toThrow(/owned by/);
  });

  it("rejects a wrong account length or discriminator", async () => {
    const short = mtAccount(r(0x11), []).subarray(0, 100);
    const verifyShort = onchainRootVerifier({
      connection: mockConn(short).connection,
      programId: PROGRAM_ID,
    });
    await expect(verifyShort(r(0x11), 0)).rejects.toThrow(/length must be/);

    const badDiscriminator = mtAccount(r(0x11), []);
    badDiscriminator[0] ^= 0xff;
    const verifyDiscriminator = onchainRootVerifier({
      connection: mockConn(badDiscriminator).connection,
      programId: PROGRAM_ID,
    });
    await expect(verifyDiscriminator(r(0x11), 0)).rejects.toThrow(
      /discriminator/,
    );
  });

  it("rejects a shard account whose embedded tree_id disagrees", async () => {
    const verify = onchainRootVerifier({
      connection: mockConn(mtAccount(r(0x11), [], 1)).connection,
      programId: PROGRAM_ID,
    });
    await expect(verify(r(0x11), 0)).rejects.toThrow(/contains tree_id 1/);
  });
});
