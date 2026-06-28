/**
 * DaemonMergeRunner tests — note selection + store update, no devnet.
 * `mergeFn` is a fake returning a canned MergeReceipt.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PublicKey } from "@solana/web3.js";

import {
  DaemonMergeRunner,
  createMergeRunner,
  type MergeFn,
} from "../src/merge-runner.js";
import { DaemonStore } from "../src/store.js";
import { newManagedOrder, type ManagedOrder } from "../src/types.js";
import type { MergeParams, MergeReceipt, StoredNote } from "@nyx/sdk";

const ORDER_ID = "ab".repeat(8);
const MINT_A = new Uint8Array(32).fill(1);
const MINT_B = new Uint8Array(32).fill(2);

let store: DaemonStore;
beforeEach(() => {
  store = new DaemonStore(":memory:");
});
afterEach(() => store.close());

const order = (): ManagedOrder => ({
  ...newManagedOrder({
    orderId: ORDER_ID,
    seedIndex: 0,
    side: "bid",
    priceRaw: 1n,
    sizeRaw: 1n,
    anchorPoolSize: 10,
  }),
  phase: "filled",
});

function changeNote(
  suffix: string,
  mint: Uint8Array,
  amount: bigint,
  leafIndex?: bigint,
): StoredNote {
  return {
    commitment: suffix.repeat(64).slice(0, 64),
    tokenMint: mint,
    amount,
    ownerCommitment: 99n,
    innerHash: 7n,
    orderId: ORDER_ID,
    anchorIndex: 0,
    leafIndex,
  };
}

/** A mergeFn that records its params and returns a merged-note receipt. */
function fakeMerge(): { fn: MergeFn; calls: MergeParams[] } {
  const calls: MergeParams[] = [];
  const fn: MergeFn = async (params) => {
    calls.push(params);
    const sum = params.inputs.reduce((s, i) => s + i.amount, 0n);
    const outputCommitment = new Uint8Array(32).fill(0xee);
    const receipt: MergeReceipt = {
      signature: "sig",
      outputCommitment,
      outputLeafIndex: 100n,
      outputNote: {
        commitment: Buffer.from(outputCommitment).toString("hex"),
        tokenMint: params.tokenMint,
        amount: sum,
        ownerCommitment: params.ownerCommitment,
        innerHash: 123n,
        leafIndex: 100n,
      },
      spentCommitments: params.inputs.map((i) =>
        Buffer.from(i.commitment).toString("hex"),
      ),
    };
    return receipt;
  };
  return { fn, calls };
}

function runner(fn: MergeFn, nextMergeIndex = () => 0): DaemonMergeRunner {
  return new DaemonMergeRunner({
    store,
    payer: PublicKey.default,
    ownerCommitment: 99n,
    mergeFn: fn,
    nextMergeIndex,
  });
}

describe("DaemonMergeRunner", () => {
  it("merges a same-mint batch, prunes inputs, stores the output", async () => {
    const c1 = changeNote("a", MINT_A, 10n, 0n);
    const c2 = changeNote("b", MINT_A, 20n, 1n);
    const c3 = changeNote("c", MINT_A, 30n, 2n);
    store.put(c1);
    store.put(c2);
    store.put(c3);

    const { fn, calls } = fakeMerge();
    const consumed = await runner(fn).run(order(), 3);

    expect(consumed).toBe(3);
    expect(calls).toHaveLength(1);
    expect(calls[0].inputs).toHaveLength(3);
    expect(calls[0].mergeIndex).toBe(0);
    // inputs pruned, merged output present
    expect(store.get(c1.commitment)).toBeUndefined();
    expect(store.get(c2.commitment)).toBeUndefined();
    const out = store.list().filter((n) => n.amount === 60n);
    expect(out).toHaveLength(1);
  });

  it("caps a batch at K=4", async () => {
    for (let i = 0; i < 6; i++) {
      store.put(changeNote(String.fromCharCode(97 + i), MINT_A, 1n, BigInt(i)));
    }
    const { fn, calls } = fakeMerge();
    const consumed = await runner(fn).run(order(), 6);
    expect(consumed).toBe(4);
    expect(calls[0].inputs).toHaveLength(4);
  });

  it("skips notes without a resolved leaf index", async () => {
    store.put(changeNote("a", MINT_A, 10n, 0n));
    store.put(changeNote("b", MINT_A, 20n)); // no leafIndex
    const { fn, calls } = fakeMerge();
    const consumed = await runner(fn).run(order(), 2);
    expect(consumed).toBe(0); // only 1 mergeable → no-op
    expect(calls).toHaveLength(0);
  });

  it("groups by mint (won't merge across mints)", async () => {
    store.put(changeNote("a", MINT_A, 10n, 0n));
    store.put(changeNote("b", MINT_B, 20n, 1n));
    const { fn, calls } = fakeMerge();
    const consumed = await runner(fn).run(order(), 2);
    expect(consumed).toBe(0); // 1 of each mint → nothing to merge
    expect(calls).toHaveLength(0);
  });

  it("merges the mint that has a quorum", async () => {
    store.put(changeNote("a", MINT_A, 10n, 0n));
    store.put(changeNote("b", MINT_B, 20n, 1n));
    store.put(changeNote("c", MINT_B, 30n, 2n));
    const { fn, calls } = fakeMerge();
    const consumed = await runner(fn).run(order(), 3);
    expect(consumed).toBe(2);
    expect(Buffer.from(calls[0].tokenMint)).toEqual(Buffer.from(MINT_B));
  });
});

describe("createMergeRunner", () => {
  it("advances the merge index monotonically across runs", async () => {
    store.put(changeNote("a", MINT_A, 10n, 0n));
    store.put(changeNote("b", MINT_A, 20n, 1n));
    const { fn, calls } = fakeMerge();
    const r = createMergeRunner({
      store,
      payer: PublicKey.default,
      ownerCommitment: 99n,
      mergeFn: fn,
      startMergeIndex: 5,
    });
    await r.run(order(), 2);
    // a fresh pair to merge again
    store.put(changeNote("d", MINT_A, 1n, 3n));
    store.put(changeNote("e", MINT_A, 2n, 4n));
    await r.run(order(), 2);
    expect(calls[0].mergeIndex).toBe(5);
    expect(calls[1].mergeIndex).toBe(6);
  });
});
