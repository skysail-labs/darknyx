/**
 * Phase-5 — settlement-watcher: TradeSettled event decoder + projection
 * into MatchNotification.
 */

import { describe, expect, it } from "vitest";

import {
  U64_MAX,
  buyerNotification,
  decodeTradeSettled,
  sellerNotification,
  type TradeSettledEvent,
} from "../src/settlement/settlement-watcher.js";

function u64LE(v: bigint): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, v, true);
  return b;
}

function encodeEvent(ev: TradeSettledEvent): Uint8Array {
  const parts: Uint8Array[] = [
    ev.matchId,
    u64LE(ev.clearingPrice),
    u64LE(ev.baseAmount),
    u64LE(ev.quoteAmount),
    u64LE(ev.buyerChangeAmt),
    u64LE(ev.sellerChangeAmt),
    u64LE(ev.buyerFeeAmt),
    u64LE(ev.sellerFeeAmt),
    u64LE(ev.noteCleaf),
    u64LE(ev.noteDleaf),
    u64LE(ev.noteEleaf),
    u64LE(ev.noteFleaf),
    u64LE(ev.noteFeeBaseLeaf),
    u64LE(ev.noteFeeQuoteLeaf),
    new Uint8Array([ev.buyerRelockActive ? 1 : 0]),
    new Uint8Array([ev.sellerRelockActive ? 1 : 0]),
    ev.newRoot,
  ];
  const total = parts.reduce((s, b) => s + b.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function baseEvent(): TradeSettledEvent {
  return {
    matchId: new Uint8Array(16).fill(0x11),
    clearingPrice: 100n,
    baseAmount: 50n,
    quoteAmount: 5_000n,
    buyerChangeAmt: 0n,
    sellerChangeAmt: 0n,
    buyerFeeAmt: 0n,
    sellerFeeAmt: 0n,
    noteCleaf: 0n,
    noteDleaf: 1n,
    noteEleaf: U64_MAX,
    noteFleaf: U64_MAX,
    noteFeeBaseLeaf: U64_MAX,
    noteFeeQuoteLeaf: U64_MAX,
    buyerRelockActive: false,
    sellerRelockActive: false,
    newRoot: new Uint8Array(32).fill(0x77),
  };
}

describe("Phase 5 — settlement-watcher: decodeTradeSettled", () => {
  it("[decode_roundtrip_exact_fill] encoded event roundtrips cleanly", () => {
    const ev = baseEvent();
    const bytes = encodeEvent(ev);
    const back = decodeTradeSettled(bytes);
    expect(back.matchId).toEqual(ev.matchId);
    expect(back.clearingPrice).toBe(100n);
    expect(back.baseAmount).toBe(50n);
    expect(back.quoteAmount).toBe(5_000n);
    expect(back.noteEleaf).toBe(U64_MAX);
    expect(back.buyerRelockActive).toBe(false);
    expect(back.newRoot).toEqual(ev.newRoot);
  });

  it("[decode_partial_fill] with change + relock + fee flush", () => {
    const ev: TradeSettledEvent = {
      ...baseEvent(),
      buyerChangeAmt: 50n,
      noteEleaf: 7n,
      buyerRelockActive: true,
      buyerFeeAmt: 3n,
      noteFeeBaseLeaf: 8n,
      noteFeeQuoteLeaf: 9n,
    };
    const back = decodeTradeSettled(encodeEvent(ev));
    expect(back.buyerChangeAmt).toBe(50n);
    expect(back.noteEleaf).toBe(7n);
    expect(back.buyerRelockActive).toBe(true);
    expect(back.noteFeeBaseLeaf).toBe(8n);
    expect(back.noteFeeQuoteLeaf).toBe(9n);
  });

  it("[decode_rejects_wrong_length] throws when buffer is too short", () => {
    expect(() => decodeTradeSettled(new Uint8Array(10))).toThrow(
      /TradeSettled event length mismatch/,
    );
  });
});

describe("Phase 5 — settlement-watcher: buyer/seller notifications", () => {
  it("[buyer_exact_fill] isPartialFill=false, changeLeaf=null, feeLeaf=null", () => {
    const ev = baseEvent();
    const n = buyerNotification(ev);
    expect(n.side).toBe("buyer");
    expect(n.isPartialFill).toBe(false);
    expect(n.changeLeaf).toBe(null);
    expect(n.feeLeaf).toBe(null);
    expect(n.relockActive).toBe(false);
    expect(n.tradeLeaf).toBe(0n); // noteCleaf
  });

  it("[buyer_partial_fill_with_relock] exposes change + relock to client", () => {
    const ev: TradeSettledEvent = {
      ...baseEvent(),
      buyerChangeAmt: 50n,
      noteEleaf: 7n,
      buyerRelockActive: true,
    };
    const n = buyerNotification(ev);
    expect(n.isPartialFill).toBe(true);
    expect(n.changeLeaf).toBe(7n);
    expect(n.relockActive).toBe(true);
  });

  it("[seller_exact_fill_reads_d_leaf] tradeLeaf == noteDleaf", () => {
    const ev: TradeSettledEvent = { ...baseEvent(), noteDleaf: 42n };
    const n = sellerNotification(ev);
    expect(n.side).toBe("seller");
    expect(n.tradeLeaf).toBe(42n);
    expect(n.changeLeaf).toBe(null);
  });

  it("[fee_leaves_per_side] buyer sees the quote fee leaf, seller the base fee leaf", () => {
    const ev: TradeSettledEvent = {
      ...baseEvent(),
      buyerFeeAmt: 3n,
      sellerFeeAmt: 1n,
      noteFeeBaseLeaf: 88n, // seller-side (base mint)
      noteFeeQuoteLeaf: 99n, // buyer-side (quote mint)
    };
    expect(buyerNotification(ev).feeLeaf).toBe(99n);
    expect(sellerNotification(ev).feeLeaf).toBe(88n);
    expect(buyerNotification(ev).feePaid).toBe(3n);
    expect(sellerNotification(ev).feePaid).toBe(1n);
  });

  it("[relayer_should_not_resubmit_when_relockActive] is a contract invariant", () => {
    // A partial-fill with relock means the relayer must NOT construct a
    // follow-up submit_order — the continuing order is already re-locked
    // against the change note and will be picked up by run_batch next slot.
    const ev: TradeSettledEvent = {
      ...baseEvent(),
      buyerChangeAmt: 50n,
      noteEleaf: 5n,
      buyerRelockActive: true,
    };
    const n = buyerNotification(ev);
    expect(n.relockActive).toBe(true);
    expect(n.isPartialFill).toBe(true);
    // Anti-regression: if ever these two diverge, relayer logic must be audited.
  });
});
