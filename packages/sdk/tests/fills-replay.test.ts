/**
 * Durable memo replay (P7c) — `replayFills` fetches `GET /fills/replay`, runs
 * each memo through the Vuln-4 `verifyFillMemo` guard, stores the recovered
 * change note, and advances the cursor. This is the amount-recovery the off-TEE
 * indexer can no longer provide after amount-privacy (P4).
 */

import { describe, it, expect } from "vitest";
import { deriveOrderId, deriveInnerHash, bn254ToBE32 } from "../src/keys/key-generators.js";
import { noteCommitmentV2 } from "../src/utxo/note.js";
import { InMemoryNoteStore } from "../src/utxo/note-store.js";
import { replayFills } from "../src/fills/replay.js";
import type { FillMemo } from "../src/orders/fill-memo.js";

const SEED = new Uint8Array(64).map((_, i) => (i * 7 + 1) & 0xff);
const OWNER =
  12345678901234567890n % 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const QUOTE_MINT = new Uint8Array(32).fill(0x22);
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

/** Build a valid memo (the TEE would emit) for order n, anchor k. */
async function buildMemo(n: number, k: number, amount: number, seq: number): Promise<FillMemo> {
  const orderId = deriveOrderId(SEED, n);
  const inner = deriveInnerHash(SEED, orderId, k);
  const commitment = await noteCommitmentV2({
    tokenMint: QUOTE_MINT,
    amount: BigInt(amount),
    ownerCommitment: OWNER,
    innerHash: inner,
  });
  return {
    seq,
    order_id: hex(orderId),
    anchor_index: k,
    change_amount: amount,
    change_note_commitment: hex(commitment),
    mint: hex(QUOTE_MINT),
    inner_hash: hex(bn254ToBE32(inner)),
  };
}

/** A fake fetch serving a fixed `/fills/replay` body, asserting the `since` arg. */
function fakeReplay(
  memos: FillMemo[],
  nextCursor: number,
  expectAuth = "Bearer tok",
): typeof fetch {
  return (async (input: string, init?: RequestInit) => {
    expect(new URL(input).pathname).toBe("/fills/replay");
    expect((init?.headers as Record<string, string>)?.authorization).toBe(expectAuth);
    return {
      ok: true,
      status: 200,
      json: async () => ({ memos, next_cursor: nextCursor }),
      text: async () => "",
    };
  }) as unknown as typeof fetch;
}

describe("replayFills", () => {
  it("verifies + stores each replayed memo and returns the cursor", async () => {
    const m1 = await buildMemo(1, 0, 500, 1);
    const m2 = await buildMemo(1, 1, 250, 2);
    const store = new InMemoryNoteStore();

    const res = await replayFills({
      gatewayHttpUrl: "https://gw.test",
      token: "tok",
      masterSeed: SEED,
      ownerCommitment: OWNER,
      store,
      since: 0,
      fetchImpl: fakeReplay([m1, m2], 2),
    });

    expect(res.records).toHaveLength(2);
    expect(res.nextCursor).toBe(2);
    // Both notes recovered into the store with their amounts + anchor indices.
    const a = await store.get(m1.change_note_commitment);
    expect(a?.amount).toBe(500n);
    expect(a?.anchorIndex).toBe(0);
    const b = await store.get(m2.change_note_commitment);
    expect(b?.amount).toBe(250n);
    expect(b?.anchorIndex).toBe(1);
  });

  it("passes the since cursor through to the query", async () => {
    const store = new InMemoryNoteStore();
    const fetchImpl = (async (input: string) => {
      expect(new URL(input).searchParams.get("since")).toBe("7");
      return { ok: true, status: 200, json: async () => ({ memos: [], next_cursor: 7 }), text: async () => "" };
    }) as unknown as typeof fetch;

    const res = await replayFills({
      gatewayHttpUrl: "https://gw.test",
      token: "tok",
      masterSeed: SEED,
      ownerCommitment: OWNER,
      store,
      since: 7,
      fetchImpl,
    });
    expect(res.records).toHaveLength(0);
    expect(res.nextCursor).toBe(7);
  });

  it("skips a memo that fails the Vuln-4 guard but recovers the rest", async () => {
    const good = await buildMemo(2, 0, 1000, 1);
    // A tampered memo: the TEE reported a different amount than the commitment
    // was built with → verifyFillMemo's commitment check fails.
    const tampered = await buildMemo(2, 1, 2000, 2);
    tampered.change_amount = 9999; // commitment no longer reproduces

    const store = new InMemoryNoteStore();
    const errors: Error[] = [];
    const res = await replayFills({
      gatewayHttpUrl: "https://gw.test",
      token: "tok",
      masterSeed: SEED,
      ownerCommitment: OWNER,
      store,
      fetchImpl: fakeReplay([good, tampered], 2),
      onError: (e) => errors.push(e),
    });

    // The good memo is recovered; the tampered one is skipped (not fatal).
    expect(res.records).toHaveLength(1);
    expect(res.records[0].commitment).toBe(good.change_note_commitment);
    expect(errors).toHaveLength(1);
    expect(await store.get(tampered.change_note_commitment)).toBeUndefined();
  });

  it("throws on a non-OK HTTP status", async () => {
    const store = new InMemoryNoteStore();
    const fetchImpl = (async () => ({
      ok: false,
      status: 401,
      json: async () => ({}),
      text: async () => "unauthorized",
    })) as unknown as typeof fetch;

    await expect(
      replayFills({
        gatewayHttpUrl: "https://gw.test",
        token: "bad",
        masterSeed: SEED,
        ownerCommitment: OWNER,
        store,
        fetchImpl,
      }),
    ).rejects.toThrow(/fills\/replay 401/);
  });
});
