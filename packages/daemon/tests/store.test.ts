/**
 * DaemonStore unit tests — note UTXO set (NoteStore contract) + managed-order
 * crash-recovery CRUD. In-memory sqlite (`:memory:`), no infra. Requires Node
 * 22+ for `node:sqlite`.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { DaemonStore } from "../src/store.js";
import { newManagedOrder, type ManagedOrder } from "../src/types.js";
import type { StoredNote } from "@nyx/sdk";

let store: DaemonStore;

beforeEach(() => {
  store = new DaemonStore(":memory:");
});
afterEach(() => {
  store.close();
});

const depositNote = (suffix: string): StoredNote => ({
  commitment: `dep${suffix}`,
  tokenMint: Uint8Array.from([1, 2, 3, 4]),
  amount: 1_000_000n,
  ownerCommitment: 123456789012345678901234567890n,
  innerHash: 7n,
  leafIndex: 42n,
});

const fillNote = (
  suffix: string,
  orderId: string,
  idx: number,
): StoredNote => ({
  commitment: `fill${suffix}`,
  tokenMint: Uint8Array.from([9, 9]),
  amount: 250n,
  ownerCommitment: 99n,
  innerHash: 555n,
  orderId,
  anchorIndex: idx,
});

describe("DaemonStore — NoteStore", () => {
  it("round-trips a deposit note (bigints + bytes)", () => {
    const n = depositNote("A");
    store.put(n);
    const got = store.get(n.commitment);
    expect(got).toBeDefined();
    expect(got!.amount).toBe(1_000_000n);
    expect(got!.ownerCommitment).toBe(123456789012345678901234567890n);
    expect(got!.innerHash).toBe(7n);
    expect(got!.leafIndex).toBe(42n);
    expect(Buffer.from(got!.tokenMint)).toEqual(Buffer.from(n.tokenMint));
    expect(got!.orderId).toBeUndefined();
    expect(got!.anchorIndex).toBeUndefined();
  });

  it("round-trips a fill (continuation) note with provenance", () => {
    const oid = "ab".repeat(8);
    const n = fillNote("B", oid, 3);
    store.put(n);
    const got = store.get(n.commitment)!;
    expect(got.orderId).toBe(oid);
    expect(got.anchorIndex).toBe(3);
    expect(got.leafIndex).toBeUndefined();
  });

  it("upserts on the same commitment (idempotent re-write)", () => {
    const n = depositNote("C");
    store.put(n);
    store.put({ ...n, amount: 2n });
    expect(store.list()).toHaveLength(1);
    expect(store.get(n.commitment)!.amount).toBe(2n);
  });

  it("lists + deletes", () => {
    store.put(depositNote("D"));
    store.put(depositNote("E"));
    expect(store.list()).toHaveLength(2);
    store.delete("depD");
    expect(store.list()).toHaveLength(1);
    expect(store.get("depD")).toBeUndefined();
  });

  it("queries notes by originating order", () => {
    const oid = "cd".repeat(8);
    store.put(fillNote("1", oid, 0));
    store.put(fillNote("2", oid, 1));
    store.put(fillNote("3", "ef".repeat(8), 0));
    const byOrder = store.notesByOrder(oid);
    expect(byOrder).toHaveLength(2);
    expect(byOrder.map((n) => n.anchorIndex).sort()).toEqual([0, 1]);
  });
});

describe("DaemonStore — managed orders", () => {
  const mk = (id: string, idx: number): ManagedOrder =>
    newManagedOrder({
      orderId: id,
      seedIndex: idx,
      side: "bid",
      priceRaw: 100n,
      sizeRaw: 5000n,
      anchorPoolSize: 10,
      now: 1000 + idx,
    });

  it("round-trips a managed order including flags + bigints", () => {
    const o: ManagedOrder = {
      ...mk("11".repeat(8), 0),
      phase: "open",
      anchorsConsumed: 4,
      topupNonce: 1,
      topupInFlight: true,
      mergeInFlight: false,
      pendingChangeNotes: 2,
    };
    store.putOrder(o);
    const got = store.getOrder(o.orderId)!;
    expect(got).toEqual(o);
  });

  it("upserts an order (phase advance)", () => {
    const o = mk("22".repeat(8), 1);
    store.putOrder(o);
    store.putOrder({ ...o, phase: "filled", updatedAt: 2000 });
    expect(store.getOrder(o.orderId)!.phase).toBe("filled");
    expect(store.listOrders()).toHaveLength(1);
  });

  it("listActiveOrders excludes terminal phases", () => {
    store.putOrder({ ...mk("33".repeat(8), 2), phase: "open" });
    store.putOrder({ ...mk("44".repeat(8), 3), phase: "closed" });
    store.putOrder({ ...mk("55".repeat(8), 4), phase: "rejected" });
    store.putOrder({ ...mk("66".repeat(8), 5), phase: "pending" });
    const active = store.listActiveOrders();
    expect(active.map((o) => o.phase).sort()).toEqual(["open", "pending"]);
  });

  it("maxSeedIndex returns -1 when empty, else the high-water mark", () => {
    expect(store.maxSeedIndex()).toBe(-1);
    store.putOrder(mk("77".repeat(8), 3));
    store.putOrder(mk("88".repeat(8), 9));
    store.putOrder(mk("99".repeat(8), 5));
    expect(store.maxSeedIndex()).toBe(9);
  });
});
