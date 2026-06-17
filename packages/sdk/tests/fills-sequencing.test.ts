/**
 * "Backfill then tail" — the durable (indexer) + live (WS) fills paths must
 * recover the same change notes and dedup cleanly across the handoff.
 *
 * The indexer row carries no secrets, so `backfillHistory` recovers the opening
 * by searching anchor indices; the WS `FillMemo` carries `inner_hash`/
 * `anchor_index` directly. Both end in the commitment-keyed NoteStore, so a note
 * seen on both paths is stored once.
 */

import { describe, it, expect } from "vitest";
import { deriveOrderId, deriveInnerHash, bn254ToBE32 } from "../src/keys/key-generators.js";
import { noteCommitmentV2 } from "../src/utxo/note.js";
import { InMemoryNoteStore } from "../src/utxo/note-store.js";
import { backfillHistory, type IndexerFill } from "../src/fills/history.js";
import { subscribeFills, type WebSocketLike } from "../src/fills/ws-client.js";
import type { FillMemo } from "../src/orders/fill-memo.js";

const SEED = new Uint8Array(64).map((_, i) => (i * 7 + 1) & 0xff);
const OWNER = 12345678901234567890n % 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const QUOTE_MINT = new Uint8Array(32).fill(0x22);
const BASE_MINT = new Uint8Array(32).fill(0x33);
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

/** Build the buyer (quote-side) change-note commitment for order n, anchor k. */
async function buyerCommitment(n: number, k: number, amount: bigint): Promise<{ orderId: string; commitment: string; inner: bigint }> {
  const orderId = deriveOrderId(SEED, n);
  const inner = deriveInnerHash(SEED, orderId, k);
  const c = await noteCommitmentV2({ tokenMint: QUOTE_MINT, amount, ownerCommitment: OWNER, innerHash: inner });
  return { orderId: hex(orderId), commitment: hex(c), inner };
}

/** A fake fetch that serves a single order's fills by order_id query param. */
function fakeIndexer(rows: Record<string, IndexerFill[]>): typeof fetch {
  return (async (input: string) => {
    const u = new URL(input);
    const id = u.searchParams.get("order_id") ?? "";
    return {
      ok: true,
      status: 200,
      json: async () => ({ fills: rows[id] ?? [] }),
      text: async () => "",
    };
  }) as unknown as typeof fetch;
}

class FakeWs implements WebSocketLike {
  private handlers: Record<string, Array<(ev?: unknown) => void>> = {};
  // `any` callback param: a single mock signature can't satisfy the interface's
  // four typed addEventListener overloads otherwise (callback contravariance).
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  addEventListener(type: string, cb: (ev: any) => void): void {
    (this.handlers[type] ??= []).push(cb as (ev?: unknown) => void);
  }
  close(): void {
    this.emit("close", { code: 1000 });
  }
  emit(type: string, ev?: unknown): void {
    for (const h of this.handlers[type] ?? []) h(ev);
  }
}

describe("backfill then tail", () => {
  it("backfillHistory gap-scans, recovers the opening, and stores the note", async () => {
    const amount = 500n;
    const n = 3;
    const k = 2;
    const { orderId, commitment } = await buyerCommitment(n, k, amount);

    const rows: Record<string, IndexerFill[]> = {
      [orderId]: [
        {
          orderId,
          side: "buyer",
          matchId: "ab".repeat(8),
          signature: "sig1",
          changeAmount: amount.toString(),
          changeNoteCommitment: commitment,
          clearingPrice: "1500",
          batchSlot: "100",
        },
      ],
    };

    const store = new InMemoryNoteStore();
    const res = await backfillHistory({
      baseUrl: "http://indexer.test",
      masterSeed: SEED,
      ownerCommitment: OWNER,
      baseMint: BASE_MINT,
      quoteMint: QUOTE_MINT,
      store,
      gapLimit: 5,
      fetchImpl: fakeIndexer(rows),
    });

    expect(res.notes).toHaveLength(1);
    expect(res.highestUsedIndex).toBe(n);
    expect(res.cursorSlot).toBe(100);
    const stored = await store.get(commitment);
    expect(stored?.anchorIndex).toBe(k);
    expect(stored?.amount).toBe(amount);
  });

  it("subscribeFills verifies + stores a live memo, then dedups against backfill", async () => {
    const store = new InMemoryNoteStore();
    const n = 1;

    // Pre-store a backfilled note (anchor 0).
    const a = await buyerCommitment(n, 0, 200n);
    await store.put({
      commitment: a.commitment,
      tokenMint: QUOTE_MINT,
      amount: 200n,
      ownerCommitment: OWNER,
      innerHash: a.inner,
      orderId: a.orderId,
      anchorIndex: 0,
    });

    // A NEW live continuation fill (anchor 1) over the WS.
    const b = await buyerCommitment(n, 1, 150n);
    const memo: FillMemo = {
      order_id: b.orderId,
      anchor_index: 1,
      change_amount: 150,
      change_note_commitment: b.commitment,
      mint: hex(QUOTE_MINT),
      inner_hash: hex(bn254ToBE32(b.inner)),
    };

    const ws = new FakeWs();
    const fills: string[] = [];
    const done = new Promise<void>((resolve) => {
      subscribeFills({
        gatewayWsUrl: "wss://gw.test",
        token: "tok",
        masterSeed: SEED,
        ownerCommitment: OWNER,
        store,
        webSocketFactory: () => ws,
        onFill: (rec) => {
          fills.push(rec.commitment);
          resolve();
        },
        onError: (e) => {
          throw e;
        },
      });
    });

    ws.emit("message", { data: JSON.stringify(memo) });
    await done;

    expect(fills).toEqual([b.commitment]);
    const all = await store.list();
    expect(all).toHaveLength(2); // backfilled + live, no dup

    // Re-delivering the backfilled note over WS does not duplicate it.
    const aMemo: FillMemo = {
      order_id: a.orderId,
      anchor_index: 0,
      change_amount: 200,
      change_note_commitment: a.commitment,
      mint: hex(QUOTE_MINT),
      inner_hash: hex(bn254ToBE32(a.inner)),
    };
    // A re-subscribe is a NEW connection — use a fresh FakeWs so the first
    // subscription's still-registered message handler doesn't also fire on this
    // emit (same-instance reuse double-processes aMemo).
    const ws2 = new FakeWs();
    const done2 = new Promise<void>((resolve) => {
      subscribeFills({
        gatewayWsUrl: "wss://gw.test",
        token: "tok",
        masterSeed: SEED,
        ownerCommitment: OWNER,
        store,
        webSocketFactory: () => ws2,
        onFill: () => resolve(),
      });
    });
    ws2.emit("message", { data: JSON.stringify(aMemo) });
    await done2;
    expect(await store.list()).toHaveLength(2); // still 2 — commitment-keyed
  });

  it("surfaces a 1011 resync close to the caller", () => {
    const ws = new FakeWs();
    let resync: string | undefined;
    subscribeFills({
      gatewayWsUrl: "wss://gw.test",
      token: "tok",
      masterSeed: SEED,
      ownerCommitment: OWNER,
      store: new InMemoryNoteStore(),
      webSocketFactory: () => ws,
      onResync: (reason) => {
        resync = reason;
      },
    });
    ws.emit("close", { code: 1011, reason: "lagged: 5 memos skipped" });
    expect(resync).toContain("lagged");
  });
});
