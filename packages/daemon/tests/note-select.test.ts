/**
 * Collateral selection tests — pure best-fit picker.
 */

import { describe, expect, it } from "vitest";

import { selectCollateralNote, isSpendable } from "../src/note-select.js";
import type { StoredNote } from "@nyx/sdk";

const MINT_A = new Uint8Array(32).fill(1);
const MINT_B = new Uint8Array(32).fill(2);

const note = (
  commitment: string,
  mint: Uint8Array,
  amount: bigint,
  leafIndex?: bigint,
): StoredNote => ({
  commitment,
  tokenMint: mint,
  amount,
  ownerCommitment: 9n,
  innerHash: 7n,
  leafIndex,
});

describe("isSpendable", () => {
  it("requires a resolved leaf index", () => {
    expect(isSpendable(note("a", MINT_A, 1n, 0n))).toBe(true);
    expect(isSpendable(note("a", MINT_A, 1n))).toBe(false);
  });
});

describe("selectCollateralNote", () => {
  const notes = [
    note("big", MINT_A, 1000n, 0n),
    note("mid", MINT_A, 500n, 1n),
    note("small", MINT_A, 100n, 2n),
    note("otherMint", MINT_B, 999n, 3n),
    note("unresolved", MINT_A, 800n), // no leaf
  ];

  it("best-fit: smallest note that covers the requirement", () => {
    const got = selectCollateralNote(notes, { mint: MINT_A, minAmount: 300n });
    expect(got?.commitment).toBe("mid"); // 500 is the smallest >= 300
  });

  it("returns the exact-fit note when present", () => {
    const got = selectCollateralNote(notes, { mint: MINT_A, minAmount: 100n });
    expect(got?.commitment).toBe("small");
  });

  it("never returns an unresolved (leaf-less) note", () => {
    // 800 would match 'unresolved' by amount, but it isn't spendable → 'big'.
    const got = selectCollateralNote(notes, { mint: MINT_A, minAmount: 600n });
    expect(got?.commitment).toBe("big");
  });

  it("respects the mint", () => {
    const got = selectCollateralNote(notes, { mint: MINT_B, minAmount: 1n });
    expect(got?.commitment).toBe("otherMint");
  });

  it("excludes locked commitments", () => {
    const got = selectCollateralNote(
      notes,
      { mint: MINT_A, minAmount: 100n },
      new Set(["small", "mid"]),
    );
    expect(got?.commitment).toBe("big"); // small + mid locked
  });

  it("returns undefined when nothing covers", () => {
    expect(
      selectCollateralNote(notes, { mint: MINT_A, minAmount: 5000n }),
    ).toBeUndefined();
  });
});
