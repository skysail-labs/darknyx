/**
 * SettlementTracker tests — leaf-index resolution, no gateway.
 * `fetchInclusion` is injected; asserts change notes get their leaf written back
 * (which unblocks the MergeRunner) and that non-change / already-resolved /
 * not-yet-settled notes are handled correctly.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  SettlementTracker,
  type FetchInclusionFn,
} from "../src/settlement-tracker.js";
import { DaemonStore } from "../src/store.js";
import type { StoredNote } from "@darknyx/sdk";

let store: DaemonStore;
beforeEach(() => {
  store = new DaemonStore(":memory:");
});
afterEach(() => store.close());

const changeNote = (commitment: string, leafIndex?: bigint): StoredNote => ({
  commitment,
  tokenMint: new Uint8Array(32).fill(1),
  amount: 100n,
  ownerCommitment: 9n,
  innerHash: 7n,
  orderId: "ab".repeat(8),
  consumedCommitment: "cd".repeat(32),
  leafIndex,
});

const depositNote = (commitment: string): StoredNote => ({
  commitment,
  tokenMint: new Uint8Array(32).fill(2),
  amount: 1000n,
  ownerCommitment: 9n,
  innerHash: 7n,
  leafIndex: 3n, // deposits already know their leaf
});

/** A fake inclusion fetch: returns a leaf index for commitments in `known`. */
function fakeInclusion(known: Record<string, number>): FetchInclusionFn {
  return vi.fn(async (_opts, commitment: string) => {
    if (!(commitment in known)) throw new Error("/tree/inclusion 404");
    return {
      leafIndex: known[commitment],
      merkleRoot: new Uint8Array(32),
      siblings: [],
      pathIndices: [],
    };
  }) as unknown as FetchInclusionFn;
}

function tracker(
  fetchInclusion: FetchInclusionFn,
  onResolved?: (c: string, l: bigint) => void,
): SettlementTracker {
  return new SettlementTracker({
    store,
    gatewayUrl: "https://gw",
    token: "t",
    fetchInclusion,
    onResolved,
  });
}

describe("SettlementTracker", () => {
  it("resolves a change note's leaf index and writes it back", async () => {
    store.put(changeNote("aa".repeat(32)));
    const resolved: Array<[string, bigint]> = [];
    const t = tracker(fakeInclusion({ ["aa".repeat(32)]: 12 }), (c, l) =>
      resolved.push([c, l]),
    );

    const count = await t.resolvePending();
    expect(count).toBe(1);
    expect(store.get("aa".repeat(32))!.leafIndex).toBe(12n);
    expect(resolved).toEqual([["aa".repeat(32), 12n]]);
  });

  it("leaves a not-yet-settled note pending (no leaf on-chain)", async () => {
    store.put(changeNote("bb".repeat(32)));
    const t = tracker(fakeInclusion({})); // nothing known
    const count = await t.resolvePending();
    expect(count).toBe(0);
    expect(store.get("bb".repeat(32))!.leafIndex).toBeUndefined();
  });

  it("skips notes that already have a leaf index", async () => {
    store.put(changeNote("cc".repeat(32), 5n));
    const fetch = fakeInclusion({ ["cc".repeat(32)]: 99 });
    await tracker(fetch).resolvePending();
    expect(fetch).not.toHaveBeenCalled();
    expect(store.get("cc".repeat(32))!.leafIndex).toBe(5n); // unchanged
  });

  it("skips deposit notes (no orderId)", async () => {
    store.put(depositNote("dd".repeat(32)));
    const fetch = fakeInclusion({ ["dd".repeat(32)]: 1 });
    await tracker(fetch).resolvePending();
    expect(fetch).not.toHaveBeenCalled();
  });

  it("resolves a mix across multiple passes", async () => {
    store.put(changeNote("a1".repeat(32)));
    store.put(changeNote("a2".repeat(32)));
    // first pass: only a1 is settled
    const known: Record<string, number> = { ["a1".repeat(32)]: 7 };
    let now = 1_000;
    const t = new SettlementTracker({
      store,
      gatewayUrl: "https://gw",
      token: "t",
      fetchInclusion: fakeInclusion(known),
      pollMs: 100,
      now: () => now,
    });
    expect(await t.resolvePending()).toBe(1);
    expect(store.get("a1".repeat(32))!.leafIndex).toBe(7n);
    expect(store.get("a2".repeat(32))!.leafIndex).toBeUndefined();
    // a2 settles → next pass resolves it
    known["a2".repeat(32)] = 8;
    now += 100;
    expect(await t.resolvePending()).toBe(1);
    expect(store.get("a2".repeat(32))!.leafIndex).toBe(8n);
  });

  it("caps concurrent inclusion reads at eight", async () => {
    for (let i = 0; i < 20; i++) {
      store.put(changeNote(i.toString(16).padStart(2, "0").repeat(32)));
    }
    let active = 0;
    let peak = 0;
    const fetch = vi.fn(async () => {
      active += 1;
      peak = Math.max(peak, active);
      await new Promise((resolve) => setTimeout(resolve, 2));
      active -= 1;
      throw new Error("not settled");
    }) as unknown as FetchInclusionFn;
    const fullScan = vi.spyOn(store, "list");
    await tracker(fetch).resolvePending();
    expect(fetch).toHaveBeenCalledTimes(20);
    expect(peak).toBe(8);
    expect(fullScan).not.toHaveBeenCalled();
  });

  it("backs off, quarantines, and re-admits only after reconciliation", async () => {
    const commitment = "ee".repeat(32);
    store.put(changeNote(commitment));
    let now = 0;
    const quarantined: string[] = [];
    const fetch = fakeInclusion({});
    const t = new SettlementTracker({
      store,
      gatewayUrl: "https://gw",
      token: "t",
      fetchInclusion: fetch,
      pollMs: 10,
      maxAttempts: 3,
      now: () => now,
      onQuarantined: (c) => quarantined.push(c),
    });

    expect(await t.resolvePending()).toBe(0); // attempt 1, next at 10
    await t.resolvePending();
    expect(fetch).toHaveBeenCalledTimes(1); // no hot-loop before backoff
    now = 10;
    await t.resolvePending(); // attempt 2, next at 30
    now = 30;
    await t.resolvePending(); // attempt 3 -> quarantine
    now = 10_000;
    await t.resolvePending();
    expect(fetch).toHaveBeenCalledTimes(3);
    expect(quarantined).toEqual([commitment]);

    t.retryQuarantined();
    await t.resolvePending();
    expect(fetch).toHaveBeenCalledTimes(4);
  });

  it("drops retry state when reconciliation removes a pending note", async () => {
    const commitment = "f1".repeat(32);
    const fetch = fakeInclusion({});
    store.put(changeNote(commitment));
    const t = new SettlementTracker({
      store,
      gatewayUrl: "https://gw",
      token: "t",
      fetchInclusion: fetch,
      pollMs: 10_000,
      now: () => 0,
    });
    await t.resolvePending(); // enters long backoff
    store.delete(commitment);
    await t.resolvePending(); // prunes orphan retry state
    store.put(changeNote(commitment));
    await t.resolvePending(); // immediately eligible again
    expect(fetch).toHaveBeenCalledTimes(2);
  });
});
