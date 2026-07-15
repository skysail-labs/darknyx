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
import type { StoredNote } from "@nyx/sdk";

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
    const t = tracker(fakeInclusion(known));
    expect(await t.resolvePending()).toBe(1);
    expect(store.get("a1".repeat(32))!.leafIndex).toBe(7n);
    expect(store.get("a2".repeat(32))!.leafIndex).toBeUndefined();
    // a2 settles → next pass resolves it
    known["a2".repeat(32)] = 8;
    expect(await t.resolvePending()).toBe(1);
    expect(store.get("a2".repeat(32))!.leafIndex).toBe(8n);
  });
});
