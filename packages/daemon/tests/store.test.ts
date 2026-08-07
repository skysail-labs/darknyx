/**
 * DaemonStore unit tests — note UTXO set (NoteStore contract) + managed-order
 * crash-recovery CRUD. In-memory sqlite (`:memory:`), no infra. Requires Node
 * 22+ for `node:sqlite`.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DatabaseSync } from "node:sqlite";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { DaemonStore } from "../src/store.js";
import {
  newManagedOrder,
  TERMINAL_PHASES,
  type ManagedOrder,
} from "../src/types.js";
import type { StoredNote } from "@darknyx/sdk";

let store: DaemonStore;

beforeEach(() => {
  store = new DaemonStore(":memory:");
});
afterEach(() => {
  store.close();
  vi.restoreAllMocks();
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
  consumedCommitment: string,
): StoredNote => ({
  commitment: `fill${suffix}`,
  tokenMint: Uint8Array.from([9, 9]),
  amount: 250n,
  ownerCommitment: 99n,
  innerHash: 555n,
  orderId,
  consumedCommitment,
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
    expect(got!.consumedCommitment).toBeUndefined();
  });

  it("round-trips a fill (continuation) note with provenance", () => {
    const oid = "ab".repeat(8);
    const n = fillNote("B", oid, "aa".repeat(32));
    store.put(n);
    const got = store.get(n.commitment)!;
    expect(got.orderId).toBe(oid);
    expect(got.consumedCommitment).toBe("aa".repeat(32));
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
    store.put(fillNote("1", oid, "01".repeat(32)));
    store.put(fillNote("2", oid, "02".repeat(32)));
    store.put(fillNote("3", "ef".repeat(8), "03".repeat(32)));
    const byOrder = store.notesByOrder(oid);
    expect(byOrder).toHaveLength(2);
    expect(byOrder.map((n) => n.consumedCommitment).sort()).toEqual([
      "01".repeat(32),
      "02".repeat(32),
    ]);
  });

  it("selects exact u64 best-fit in SQL and preserves FIFO ties", () => {
    const mint = Uint8Array.from([1, 2, 3, 4]);
    const mk = (commitment: string, amount: bigint): StoredNote => ({
      ...depositNote(commitment),
      commitment,
      tokenMint: mint,
      amount,
    });
    store.put(mk("first", 9_007_199_254_740_994n));
    store.put(mk("second", 9_007_199_254_740_993n));
    store.put(mk("tie", 9_007_199_254_740_993n));
    expect(
      store.selectCollateral(mint, 9_007_199_254_740_993n)?.commitment,
    ).toBe("second");
  });

  it("excludes original collateral and rolling residuals of live orders", () => {
    const oid = "aa".repeat(8);
    const original = depositNote("original");
    const residual = { ...depositNote("residual"), orderId: oid };
    store.put(original);
    store.put(residual);
    store.putOrder({
      ...newManagedOrder({
        orderId: oid,
        seedIndex: 1,
        side: "bid",
        priceRaw: 1n,
        sizeRaw: 1n,
        collateralCommitment: original.commitment,
      }),
      phase: "open",
    });
    expect(store.selectCollateral(original.tokenMint, 1n)).toBeUndefined();
  });
});

describe("DaemonStore — migration and durability profile", () => {
  it("prepares hot statements once per store lifetime", () => {
    const prepare = vi.spyOn(DatabaseSync.prototype, "prepare");
    const local = new DaemonStore(":memory:");
    const preparedAtBoot = prepare.mock.calls.length;
    const note = depositNote("prepared");
    local.put(note);
    local.get(note.commitment);
    local.list();
    local.notesByOrder("none");
    local.listPendingLeafNotes();
    local.selectCollateral(note.tokenMint, 1n);
    local.delete(note.commitment);
    expect(prepare).toHaveBeenCalledTimes(preparedAtBoot);
    local.close();
    prepare.mockRestore();
  });

  it("backfills the sortable amount key on a legacy database and reopens", () => {
    store.close();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "darknyx-store-"));
    const dbPath = path.join(dir, "legacy.sqlite");
    try {
      const legacy = new DatabaseSync(dbPath);
      legacy.exec(`
        CREATE TABLE notes (
          commitment TEXT PRIMARY KEY, token_mint TEXT NOT NULL,
          amount TEXT NOT NULL, owner_commitment TEXT NOT NULL,
          inner_hash TEXT NOT NULL, leaf_index TEXT, order_id TEXT,
          consumed_commitment TEXT
        );
        CREATE TABLE orders (
          order_id TEXT PRIMARY KEY, seed_index INTEGER NOT NULL,
          symbol TEXT NOT NULL, side TEXT NOT NULL, price_raw TEXT NOT NULL,
          size_raw TEXT NOT NULL, phase TEXT NOT NULL,
          merge_in_flight INTEGER NOT NULL, pending_change_notes INTEGER NOT NULL,
          collateral_commitment TEXT, settlement_failure_reason TEXT,
          settlement_unlock_slot INTEGER, created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL
        );
        INSERT INTO notes VALUES
          ('legacy', '01020304', '9007199254740993', '1', '2', '3', NULL, NULL);
      `);
      legacy.close();
      store = new DaemonStore(dbPath);
      expect(
        store.selectCollateral(
          Uint8Array.from([1, 2, 3, 4]),
          9_007_199_254_740_993n,
        )?.commitment,
      ).toBe("legacy");
      const db = (store as unknown as { db: DatabaseSync }).db;
      expect(
        (db.prepare("PRAGMA synchronous").get() as { synchronous: number })
          .synchronous,
      ).toBe(1); // NORMAL
    } finally {
      store.close();
      fs.rmSync(dir, { recursive: true });
      // afterEach expects an open object; replace with an ephemeral one.
      store = new DaemonStore(":memory:");
    }
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
      now: 1000 + idx,
    });

  it("round-trips a managed order including flags + bigints", () => {
    const o: ManagedOrder = {
      ...mk("11".repeat(8), 0),
      phase: "open",
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

  it("listActiveOrders excludes EVERY terminal phase", () => {
    // Widened deliberately. This previously exercised only `closed` and
    // `rejected`, so it passed while the SQL omitted `'expired'` — the query
    // resumed expired orders as live and nothing noticed (SW-11). Driving the
    // fixture off TERMINAL_PHASES means a newly added phase fails here rather
    // than silently becoming resumable.
    let seed = 2;
    for (const phase of TERMINAL_PHASES) {
      store.putOrder({
        ...mk(String(seed).padStart(2, "0").repeat(8), seed),
        phase,
      });
      seed += 1;
    }
    store.putOrder({ ...mk("aa".repeat(8), 90), phase: "open" });
    store.putOrder({ ...mk("bb".repeat(8), 91), phase: "pending" });

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
