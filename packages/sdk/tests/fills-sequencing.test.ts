/**
 * "Backfill then tail" — the durable (indexer) + live (WS) fills paths.
 *
 * Amount-privacy: the indexer is a COMMITMENT LOCATOR (no amounts), so
 * `backfillHistory` locates exact and partial fills (input/output commitments,
 * ciphertext, and finalized Solana slot) but does not reconstruct openings by
 * itself. Recovery v3 or the low-latency WS `FillMemo` verifies outputs against
 * the named consumed input in the commitment-keyed NoteStore.
 */

import { describe, it, expect } from "vitest";
import { deriveOrderId, bn254ToBE32 } from "../src/keys/key-generators.js";
import {
  deriveMatchOutputInner,
  MATCH_ROLE_CHANGE_BUYER,
} from "../src/utxo/match-output.js";
import { noteCommitmentV2 } from "../src/utxo/note.js";
import { InMemoryNoteStore } from "../src/utxo/note-store.js";
import { backfillHistory, type IndexerFill } from "../src/fills/history.js";
import { subscribeFills, type WebSocketLike } from "../src/fills/ws-client.js";
import type { FillMemo } from "../src/orders/fill-memo.js";

const SEED = new Uint8Array(64).map((_, i) => (i * 7 + 1) & 0xff);
const OWNER =
  12345678901234567890n %
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const QUOTE_MINT = new Uint8Array(32).fill(0x22);
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

const be32ToBig = (b: Uint8Array): bigint => {
  let n = 0n;
  for (const x of b) n = (n << 8n) | BigInt(x);
  return n;
};

/** Build a buyer change output from one consumed quote note. */
async function buyerCommitment(
  n: number,
  amount: bigint,
): Promise<{
  orderId: string;
  commitment: string;
  inner: bigint;
  inputCommitment: string;
  inputInner: bigint;
}> {
  const orderId = deriveOrderId(SEED, n);
  const inputInner = BigInt(100 + n);
  const inputCommitment = await noteCommitmentV2({
    tokenMint: QUOTE_MINT,
    amount: 1_000n,
    ownerCommitment: OWNER,
    innerHash: inputInner,
  });
  const inner = be32ToBig(
    await deriveMatchOutputInner(
      bn254ToBE32(inputInner),
      MATCH_ROLE_CHANGE_BUYER,
    ),
  );
  const c = await noteCommitmentV2({
    tokenMint: QUOTE_MINT,
    amount,
    ownerCommitment: OWNER,
    innerHash: inner,
  });
  return {
    orderId: hex(orderId),
    commitment: hex(c),
    inner,
    inputCommitment: hex(inputCommitment),
    inputInner,
  };
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
  private serverSeq = 0;
  sent: string[] = [];
  // `any` callback param: a single mock signature can't satisfy the interface's
  // four typed addEventListener overloads otherwise (callback contravariance).
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  addEventListener(type: string, cb: (ev: any) => void): void {
    (this.handlers[type] ??= []).push(cb as (ev?: unknown) => void);
  }
  send(data: string): void {
    this.sent.push(data);
    const frame = JSON.parse(data) as {
      op: string;
      request_id?: string;
      channels?: string[];
    };
    if (frame.op === "login") {
      this.server({
        op: "login",
        request_id: frame.request_id,
        account_id: "acct",
      });
    } else if (frame.op === "subscribe") {
      this.server({
        op: "subscribed",
        request_id: frame.request_id,
        channels: frame.channels,
      });
    }
  }
  close(): void {
    this.emit("close", { code: 1000 });
  }
  server(frame: Record<string, unknown>): void {
    this.emit("message", {
      data: JSON.stringify({ ...frame, seq: ++this.serverSeq }),
    });
  }
  emit(type: string, ev?: unknown): void {
    for (const h of this.handlers[type] ?? []) h(ev);
  }
}

describe("backfill then tail", () => {
  it("backfillHistory gap-scans and locates fills (no amounts)", async () => {
    const amount = 500n;
    const n = 3;
    const { orderId, commitment } = await buyerCommitment(n, amount);

    const rows: Record<string, IndexerFill[]> = {
      [orderId]: [
        {
          orderId,
          side: "buyer",
          matchId: "ab".repeat(8),
          signature: "sig1",
          slot: 500,
          inputNoteUseTag: "11".repeat(32),
          tradeNoteCommitment: "22".repeat(32),
          isPartialFill: true,
          changeNoteCommitment: commitment,
          batchSlot: "3",
        },
      ],
    };

    const res = await backfillHistory({
      baseUrl: "http://indexer.test",
      masterSeed: SEED,
      gapLimit: 5,
      fetchImpl: fakeIndexer(rows),
    });

    // Locator only: the fill + its commitments are found, but no opening is
    // reconstructed until the recovery-v3 ciphertext is decrypted.
    expect(res.located).toHaveLength(1);
    expect(res.located[0].changeNoteCommitment).toBe(commitment);
    expect(res.located[0].orderId).toBe(orderId);
    expect(res.highestUsedIndex).toBe(n);
    expect(res.cursorSlot).toBe(500);
  });

  it("subscribeFills verifies + stores a live memo, then dedups against backfill", async () => {
    const store = new InMemoryNoteStore();
    const n = 1;

    // The consumed input opening is already in the wallet's local UTXO set.
    const b = await buyerCommitment(n, 150n);
    await store.put({
      commitment: b.inputCommitment,
      tokenMint: QUOTE_MINT,
      amount: 1_000n,
      ownerCommitment: OWNER,
      innerHash: b.inputInner,
      leafIndex: 1n,
    });

    // A live continuation fill names that exact input and the v3 change role.
    const memo: FillMemo = {
      order_id: b.orderId,
      consumed_note_commitment: b.inputCommitment,
      output_role: MATCH_ROLE_CHANGE_BUYER,
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

    ws.emit("open");
    await Promise.resolve();
    ws.server({ ...memo, channel: "fills" });
    await done;

    expect(fills).toEqual([b.commitment]);
    const all = await store.list();
    expect(all).toHaveLength(2); // backfilled + live, no dup

    // Re-delivering the same verified output does not duplicate it.
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
    ws2.emit("open");
    await Promise.resolve();
    ws2.server({ ...memo, channel: "fills" });
    await done2;
    expect(await store.list()).toHaveLength(2); // still 2 — commitment-keyed
  });

  it("surfaces a 1011 resync close to the caller", async () => {
    const ws = new FakeWs();
    let resync: string | undefined;
    const sub = subscribeFills({
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
    ws.emit("open");
    await Promise.resolve();
    ws.emit("close", { code: 1011, reason: "lagged: 5 memos skipped" });
    expect(resync).toContain("lagged");
    sub.close();
  });
});
