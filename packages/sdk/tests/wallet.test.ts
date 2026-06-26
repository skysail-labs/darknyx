/**
 * Client-side UTXO wallet: balance = Σ unspent notes, status filtering, and the
 * over-collateral coin-selection (smallest single note that covers the order;
 * `merge-needed` when no single note does but the set would).
 */

import { describe, it, expect } from "vitest";
import { InMemoryNoteStore, type StoredNote } from "../src/utxo/note-store.js";
import { Wallet, type NoteStatus, type MergeFn } from "../src/wallet/wallet.js";

const MINT_A = new Uint8Array(32).fill(0xaa);
const MINT_B = new Uint8Array(32).fill(0xbb);

function deposit(
  commitment: string,
  mint: Uint8Array,
  amount: bigint,
): StoredNote {
  return {
    commitment,
    tokenMint: mint,
    amount,
    ownerCommitment: 1n,
    innerHash: 2n,
    leafIndex: 0n,
  };
}
function fill(
  commitment: string,
  mint: Uint8Array,
  amount: bigint,
): StoredNote {
  return {
    commitment,
    tokenMint: mint,
    amount,
    ownerCommitment: 1n,
    innerHash: 2n,
    orderId: "ab".repeat(8),
    anchorIndex: 0,
  };
}

/** A wallet over a store + an explicit per-commitment status map (default active). */
function walletWith(
  notes: StoredNote[],
  status: Record<string, NoteStatus> = {},
): Wallet {
  const store = new InMemoryNoteStore();
  for (const n of notes) store.put(n);
  return new Wallet({ store, noteStatus: (c) => status[c] ?? "active" });
}

describe("Wallet", () => {
  it("getBalance sums only spendable (active) notes, per mint and across mints", async () => {
    const w = walletWith(
      [
        deposit("a1", MINT_A, 500n),
        fill("a2", MINT_A, 50n),
        fill("a3", MINT_A, 100n), // consumed → excluded
        fill("a4", MINT_A, 30n), // locked → excluded
        deposit("b1", MINT_B, 200n),
      ],
      { a3: "consumed", a4: "locked" },
    );

    expect(await w.getBalance(MINT_A)).toBe(550n); // 500 + 50
    expect(await w.getBalance(MINT_B)).toBe(200n);
    expect(await w.getBalance()).toBe(750n); // all mints
  });

  it("listNotes reports source + status and can filter to spendable", async () => {
    const w = walletWith(
      [deposit("a1", MINT_A, 500n), fill("a2", MINT_A, 50n)],
      { a2: "consumed" },
    );

    const all = await w.listNotes({ mint: MINT_A });
    expect(all).toHaveLength(2);
    expect(all.find((n) => n.commitment === "a1")!.source).toBe("deposit");
    expect(all.find((n) => n.commitment === "a2")!.source).toBe("fill");
    expect(all.find((n) => n.commitment === "a2")!.status).toBe("consumed");

    const spendable = await w.listNotes({ mint: MINT_A, spendableOnly: true });
    expect(spendable.map((n) => n.commitment)).toEqual(["a1"]);
  });

  it("selectCollateral picks the smallest single note that covers the order", async () => {
    const w = walletWith([
      deposit("big", MINT_A, 500n),
      fill("small", MINT_A, 50n),
    ]);

    // 40 fits in the 50 note (smaller) — over-collateralize it, surplus returns.
    const r1 = await w.selectCollateral(40n, MINT_A);
    expect(r1).toEqual({
      ok: true,
      note: expect.objectContaining({ commitment: "small" }),
    });

    // 60 needs the 500 note (the 50 is too small).
    const r2 = await w.selectCollateral(60n, MINT_A);
    expect(r2.ok && r2.note.commitment).toBe("big");
  });

  it("signals merge-needed when no single note covers it but the set does", async () => {
    const w = walletWith([
      deposit("n500", MINT_A, 500n),
      fill("n50", MINT_A, 50n),
    ]);

    const r = await w.selectCollateral(550n, MINT_A);
    expect(r).toMatchObject({ ok: false, reason: "merge-needed", total: 550n });
    if (!r.ok && r.reason === "merge-needed") {
      // candidates are largest-first (the natural merge input order).
      expect(r.candidates.map((c) => c.commitment)).toEqual(["n500", "n50"]);
    }
  });

  it("signals insufficient-funds when even the spendable set is short", async () => {
    const w = walletWith([deposit("n500", MINT_A, 500n)], {});
    const r = await w.selectCollateral(600n, MINT_A);
    expect(r).toEqual({ ok: false, reason: "insufficient-funds", total: 500n });
  });

  it("excludes spent/locked notes from coin-selection", async () => {
    const w = walletWith(
      [deposit("spent", MINT_A, 1000n), fill("ok", MINT_A, 100n)],
      { spent: "consumed" },
    );
    // The big note is spent → only the 100 note is selectable.
    const r = await w.selectCollateral(80n, MINT_A);
    expect(r.ok && r.note.commitment).toBe("ok");
    // 200 can't be covered (spent note ignored) and total spendable is 100.
    expect(await w.selectCollateral(200n, MINT_A)).toEqual({
      ok: false,
      reason: "insufficient-funds",
      total: 100n,
    });
  });
});

/** A wallet + its store (so tests can drive a real `mergeFn`). */
function walletAndStore(notes: StoredNote[]): {
  wallet: Wallet;
  store: InMemoryNoteStore;
  merges: () => number;
} {
  const store = new InMemoryNoteStore();
  for (const n of notes) store.put(n);
  const wallet = new Wallet({ store, noteStatus: () => "active" });
  let count = 0;
  // A mergeFn that mirrors the real one: sum the inputs, prune them, store the
  // merged note (always active by default).
  (wallet as unknown as { _mockMerge: MergeFn })._mockMerge = async (
    toMerge,
  ) => {
    count += 1;
    const sum = toMerge.reduce((s, n) => s + n.amount, 0n);
    for (const n of toMerge) store.delete(n.commitment);
    const merged: StoredNote = {
      commitment: `merged${count}`,
      tokenMint: toMerge[0].tokenMint,
      amount: sum,
      ownerCommitment: 1n,
      innerHash: 2n,
      leafIndex: 0n,
    };
    store.put(merged);
    return merged;
  };
  return { wallet, store, merges: () => count };
}
const mockMerge = (w: Wallet): MergeFn =>
  (w as unknown as { _mockMerge: MergeFn })._mockMerge;

describe("Wallet merge selection + consolidation", () => {
  it("selectForMerge greedily picks the fewest largest notes that cover it", async () => {
    const w = walletWith([
      deposit("n300", MINT_A, 300n),
      fill("n200", MINT_A, 200n),
      fill("n100", MINT_A, 100n),
    ]);
    const sel = await w.selectForMerge(450n, MINT_A);
    expect(sel.ok).toBe(true);
    if (sel.ok) expect(sel.notes.map((n) => n.amount)).toEqual([300n, 200n]); // not the 100
  });

  it("selectForMerge signals chain-needed when the 4 largest fall short", async () => {
    const notes = [1, 2, 3, 4, 5].map((i) => deposit(`n${i}`, MINT_A, 100n));
    const w = walletWith(notes);
    const sel = await w.selectForMerge(450n, MINT_A); // 4×100=400 < 450, total 500
    expect(sel).toMatchObject({
      ok: false,
      reason: "chain-needed",
      total: 500n,
    });
    if (!sel.ok && sel.reason === "chain-needed")
      expect(sel.notes).toHaveLength(4);
  });

  it("selectForMerge reports insufficient-funds when even the set is short", async () => {
    const w = walletWith([
      deposit("a", MINT_A, 100n),
      deposit("b", MINT_A, 100n),
    ]);
    expect(await w.selectForMerge(500n, MINT_A)).toEqual({
      ok: false,
      reason: "insufficient-funds",
      total: 200n,
    });
  });

  it("consolidate merges in one step when ≤4 notes cover the order", async () => {
    const { wallet, merges } = walletAndStore([
      deposit("n300", MINT_A, 300n),
      deposit("n200", MINT_A, 200n),
      deposit("n100", MINT_A, 100n),
    ]);
    const note = await wallet.consolidate(450n, MINT_A, mockMerge(wallet));
    expect(note.amount).toBe(500n); // 300 + 200
    expect(merges()).toBe(1);
  });

  it("consolidate CHAINS merges when more than 4 notes are needed", async () => {
    // 5 × 100; need 450. 4 largest = 400 < 450 → must chain.
    const { wallet, merges } = walletAndStore(
      [1, 2, 3, 4, 5].map((i) => deposit(`n${i}`, MINT_A, 100n)),
    );
    const note = await wallet.consolidate(450n, MINT_A, mockMerge(wallet));
    expect(note.amount).toBeGreaterThanOrEqual(450n);
    expect(merges()).toBe(2); // merge 4→400, then 400+100→500
  });

  it("consolidate returns an existing note without merging when one already covers it", async () => {
    const { wallet, merges } = walletAndStore([
      deposit("big", MINT_A, 1000n),
      deposit("s", MINT_A, 50n),
    ]);
    const note = await wallet.consolidate(450n, MINT_A, mockMerge(wallet));
    expect(note.commitment).toBe("big");
    expect(merges()).toBe(0);
  });

  it("consolidate throws on insufficient funds", async () => {
    const { wallet } = walletAndStore([deposit("a", MINT_A, 100n)]);
    await expect(
      wallet.consolidate(500n, MINT_A, mockMerge(wallet)),
    ).rejects.toThrow(/insufficient/);
  });
});
