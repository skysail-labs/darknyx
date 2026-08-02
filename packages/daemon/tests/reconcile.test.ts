/**
 * SW-11 — the daemon must reconcile after a stream gap or a restart.
 *
 * The `orders`/`fills` channels are notifiers, not durable logs; a client that
 * falls behind the server's buffer is closed with 1011, which the SDK raises as
 * `onResync`. Nothing consumed it, so the daemon carried on as though the stream
 * were complete: notes minted during the gap never entered the store, filled
 * orders stayed `open` (keeping their collateral locked out of selection), and a
 * crash mid-merge left `mergeInFlight` set forever.
 */

import { describe, expect, it } from "vitest";

import { DaemonStore } from "../src/store.js";
import { newManagedOrder, type ManagedOrder } from "../src/types.js";
import { phaseFromServerStatus, reconcile } from "../src/reconcile.js";
import type { TeeReadClient } from "../src/tee-read.js";

function store(): DaemonStore {
  return new DaemonStore(":memory:");
}

function order(id: string, over: Partial<ManagedOrder> = {}): ManagedOrder {
  return {
    ...newManagedOrder({
      orderId: id,
      seedIndex: 1,
      symbol: "SOL-USDC",
      side: "bid",
      priceRaw: 100n,
      sizeRaw: 10n,
      collateralCommitment: `c${id}`,
    }),
    ...over,
  };
}

/** A `TeeReadClient` stub exposing only what the reconciler calls. */
function reads(byId: Record<string, unknown>): TeeReadClient {
  return {
    order: async (id: string) => (id in byId ? byId[id] : null),
  } as unknown as TeeReadClient;
}

/** Deps with the chain half stubbed out — overridden per test. */
function deps(s: DaemonStore, r: TeeReadClient, notes: unknown[] = []) {
  return {
    store: s,
    reads: r,
    rpcUrl: "http://stub",
    programId: "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
    masterSeed: new Uint8Array(32).fill(7),
    baseMint: new Uint8Array(32).fill(1),
    quoteMint: new Uint8Array(32).fill(2),
    // The chain scan is exercised through its own SDK tests; here we only need
    // the orchestration to feed what it returns into the store.
    connectionFactory: () => ({}) as never,
    __notes: notes,
  };
}

describe("phaseFromServerStatus", () => {
  it("maps the server's book vocabulary onto the client lifecycle", () => {
    // `empty` is the one that matters: the book has no remaining quantity, which
    // client-side is `filled`. A stale daemon keeps `open` and therefore keeps
    // excluding that collateral from selection.
    expect(phaseFromServerStatus("empty")).toBe("filled");
    expect(phaseFromServerStatus("pending")).toBe("open");
    expect(phaseFromServerStatus("pending_settlement")).toBe(
      "pending_settlement",
    );
    expect(phaseFromServerStatus("expired")).toBe("expired");
    expect(phaseFromServerStatus("cancelled")).toBe("cancelled");
  });

  it("leaves the local phase alone on an unrecognised status", () => {
    // A newer CVM than this daemon. Guessing a transition could free collateral
    // that is still committed, so `null` means "do not touch".
    expect(phaseFromServerStatus("some_future_state")).toBeNull();
  });
});

describe("reconcile", () => {
  it("corrects a phase that went stale inside the gap", async () => {
    const s = store();
    s.putOrder(order("aa", { phase: "open" }));
    const r = reads({ aa: { order_id: "aa", status: "empty" } });

    const out = await reconcile({ ...deps(s, r), connectionFactory: undefined });

    expect(out.ordersRephased).toBe(1);
    expect(s.getOrder("aa")!.phase).toBe("filled");
  });

  it("does not invent a terminal phase for an order the CVM has forgotten", async () => {
    // "The server dropped it" and "it never landed" are indistinguishable from
    // here, and guessing `cancelled` would release collateral that may still be
    // committed on-chain.
    const s = store();
    s.putOrder(order("bb", { phase: "open" }));

    const out = await reconcile({
      ...deps(s, reads({})),
      connectionFactory: undefined,
    });

    expect(out.ordersUnknown).toBe(1);
    expect(s.getOrder("bb")!.phase).toBe("open");
  });

  it("clears a mergeInFlight latch stranded by a crash", async () => {
    // `mergeInFlight` is persisted and cleared only by a merge-confirmed/failed
    // event. Crash mid-merge and the flag is what survives, and `reduceOrder`
    // gates every future intent on `!mergeInFlight` — so that order would never
    // auto-merge again for the life of the database.
    const s = store();
    s.putOrder(order("cc", { phase: "open", mergeInFlight: true }));

    const out = await reconcile({
      ...deps(s, reads({ cc: { order_id: "cc", status: "pending" } })),
      connectionFactory: undefined,
    });

    expect(out.mergeLatchesCleared).toBe(1);
    expect(s.getOrder("cc")!.mergeInFlight).toBe(false);
  });

  it("keeps going when one order cannot be read", async () => {
    // Best-effort per item: a partially reconciled daemon beats one that gave
    // up on the first transport error.
    const s = store();
    s.putOrder(order("dd", { phase: "open" }));
    s.putOrder(order("ee", { phase: "open", seedIndex: 2 }));
    const r = {
      order: async (id: string) => {
        if (id === "dd") throw new Error("boom");
        return { order_id: id, status: "cancelled" };
      },
    } as unknown as TeeReadClient;

    const out = await reconcile({
      ...deps(s, r),
      connectionFactory: undefined,
    });

    // The note scan also fails here (no RPC), so assert on the ORDER error
    // specifically rather than the total count.
    expect(out.errors.some((e) => e.startsWith("order dd"))).toBe(true);
    expect(s.getOrder("ee")!.phase).toBe("cancelled");
  });

  it("records a chain-recovery failure instead of throwing", async () => {
    // The note scan is the half most likely to fail (RPC). It must not abandon
    // the order reconciliation that already succeeded.
    const s = store();
    s.putOrder(order("ff", { phase: "open" }));

    const out = await reconcile({
      ...deps(s, reads({ ff: { order_id: "ff", status: "empty" } })),
      connectionFactory: () => {
        throw new Error("rpc down");
      },
    });

    expect(out.ordersRephased).toBe(1);
    expect(out.errors.some((e) => e.startsWith("note recovery"))).toBe(true);
  });
});
