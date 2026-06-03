/**
 * Settle-memo integrity check (Phase 8) — the client's guard against a
 * misbehaving TEE (design-doc Vulnerability 4).
 */

import { describe, expect, it } from "vitest";

import {
  verifyFillMemo,
  receiveFillMemo,
  FillMemoError,
  type FillMemo,
} from "../src/orders/fill-memo.js";
import { InMemoryNoteStore } from "../src/utxo/note-store.js";
import { deriveInnerHash, bn254ToBE32 } from "../src/keys/key-generators.js";
import { noteCommitmentV2 } from "../src/utxo/note.js";

const SEED = new Uint8Array(64).map((_, i) => (i * 7) & 0xff);
const ORDER_ID = new Uint8Array(16).fill(0xab);
const OWNER = 0x1234567890abcdefn;
const MINT = new Uint8Array(32).fill(0x01);

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

/** Build a well-formed memo for anchor `index` + `amount`. */
async function goodMemo(index: number, amount: bigint): Promise<FillMemo> {
  const innerBig = deriveInnerHash(SEED, ORDER_ID, index);
  const commitment = await noteCommitmentV2({
    tokenMint: MINT,
    amount,
    ownerCommitment: OWNER,
    innerHash: innerBig,
  });
  return {
    order_id: hex(ORDER_ID),
    anchor_index: index,
    change_amount: Number(amount),
    change_note_commitment: hex(commitment),
    mint: hex(MINT),
    inner_hash: hex(bn254ToBE32(innerBig)),
  };
}

describe("fill-memo integrity", () => {
  it("accepts a well-formed memo and builds the change-note record", async () => {
    const memo = await goodMemo(3, 1500n);
    const rec = await verifyFillMemo(memo, SEED, OWNER);
    expect(rec.commitment).toBe(memo.change_note_commitment);
    expect(rec.amount).toBe(1500n);
    expect(rec.anchorIndex).toBe(3);
    expect(rec.ownerCommitment).toBe(OWNER);
    // The stored inner_hash matches the client's own derivation.
    expect(rec.innerHash).toBe(deriveInnerHash(SEED, ORDER_ID, 3));
  });

  it("rejects a tampered commitment (commitment_mismatch)", async () => {
    const memo = await goodMemo(0, 100n);
    // Flip a byte of the commitment.
    const c = Buffer.from(memo.change_note_commitment, "hex");
    c[31] ^= 0x01;
    memo.change_note_commitment = c.toString("hex");
    await expect(verifyFillMemo(memo, SEED, OWNER)).rejects.toThrow(FillMemoError);
    await expect(verifyFillMemo(memo, SEED, OWNER)).rejects.toMatchObject({
      kind: "commitment_mismatch",
    });
  });

  it("rejects a substituted inner_hash even if its commitment is self-consistent", async () => {
    // A malicious TEE uses a DIFFERENT inner_hash (one it can forge a
    // nullifier for) + a commitment that matches THAT inner_hash. The
    // commitment check alone would pass; the inner_hash binding catches it.
    const index = 5;
    const evilInner = deriveInnerHash(SEED, ORDER_ID, 9999); // not anchor 5
    const amount = 250n;
    const evilCommitment = await noteCommitmentV2({
      tokenMint: MINT,
      amount,
      ownerCommitment: OWNER,
      innerHash: evilInner,
    });
    const memo: FillMemo = {
      order_id: hex(ORDER_ID),
      anchor_index: index,
      change_amount: Number(amount),
      change_note_commitment: hex(evilCommitment),
      mint: hex(MINT),
      inner_hash: hex(bn254ToBE32(evilInner)),
    };
    await expect(verifyFillMemo(memo, SEED, OWNER)).rejects.toMatchObject({
      kind: "inner_hash_mismatch",
    });
  });

  it("receiveFillMemo persists a verified note into the store", async () => {
    const store = new InMemoryNoteStore();
    const memo = await goodMemo(1, 777n);
    const rec = await receiveFillMemo(memo, SEED, OWNER, store);
    expect(store.get(rec.commitment)).toEqual(rec);
    expect(store.list()).toHaveLength(1);
  });
});
