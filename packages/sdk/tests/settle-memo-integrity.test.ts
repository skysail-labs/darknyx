/** Anchor-free fill-memo integrity checks for VALID_MATCH_BATCH v3 outputs. */

import { describe, expect, it } from "vitest";

import {
  verifyFillMemo,
  receiveFillMemo,
  FillMemoError,
  type FillMemo,
} from "../src/orders/fill-memo.js";
import { InMemoryNoteStore } from "../src/utxo/note-store.js";
import { bn254ToBE32 } from "../src/keys/key-generators.js";
import {
  deriveMatchOutputInner,
  MATCH_ROLE_CHANGE_BUYER,
  MATCH_ROLE_CHANGE_SELLER,
} from "../src/utxo/match-output.js";
import { noteCommitmentV2 } from "../src/utxo/note.js";

const ORDER_ID = new Uint8Array(16).fill(0xab);
const OWNER = 0x1234567890abcdefn;
const MINT = new Uint8Array(32).fill(0x01);
const INPUT_INNER = 0x1234n;
const INPUT_AMOUNT = 4_000n;

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const be32ToBig = (b: Uint8Array): bigint => {
  let n = 0n;
  for (const x of b) n = (n << 8n) | BigInt(x);
  return n;
};

async function fixture(
  amount: bigint,
  role = MATCH_ROLE_CHANGE_BUYER,
): Promise<{ memo: FillMemo; store: InMemoryNoteStore; consumed: string }> {
  const store = new InMemoryNoteStore();
  const inputCommitment = await noteCommitmentV2({
    tokenMint: MINT,
    amount: INPUT_AMOUNT,
    ownerCommitment: OWNER,
    innerHash: INPUT_INNER,
  });
  const consumed = hex(inputCommitment);
  store.put({
    commitment: consumed,
    tokenMint: MINT,
    amount: INPUT_AMOUNT,
    ownerCommitment: OWNER,
    innerHash: INPUT_INNER,
    leafIndex: 7n,
  });

  const innerBytes = await deriveMatchOutputInner(
    bn254ToBE32(INPUT_INNER),
    role,
  );
  const innerHash = be32ToBig(innerBytes);
  const commitment = await noteCommitmentV2({
    tokenMint: MINT,
    amount,
    ownerCommitment: OWNER,
    innerHash,
  });
  return {
    store,
    consumed,
    memo: {
      order_id: hex(ORDER_ID),
      consumed_note_commitment: consumed,
      output_role: role,
      change_amount: Number(amount),
      change_note_commitment: hex(commitment),
      mint: hex(MINT),
      inner_hash: hex(innerBytes),
    },
  };
}

describe("fill-memo integrity", () => {
  it("derives the output from the exact consumed input opening", async () => {
    const { memo, store, consumed } = await fixture(1_500n);
    const rec = await verifyFillMemo(memo, store);
    expect(rec.commitment).toBe(memo.change_note_commitment);
    expect(rec.amount).toBe(1_500n);
    expect(rec.consumedCommitment).toBe(consumed);
    expect(rec.ownerCommitment).toBe(OWNER);
    expect(rec.innerHash).toBe(be32ToBig(Buffer.from(memo.inner_hash, "hex")));
  });

  it("compares commitments as bytes and returns canonical hex", async () => {
    const { memo, store } = await fixture(1_500n);
    const canonical = memo.change_note_commitment;
    memo.change_note_commitment = canonical.toUpperCase();
    memo.consumed_note_commitment = memo.consumed_note_commitment.toUpperCase();

    const rec = await verifyFillMemo(memo, store);
    expect(rec.commitment).toBe(canonical);
  });

  it("rejects a tampered output commitment", async () => {
    const { memo, store } = await fixture(100n);
    const c = Buffer.from(memo.change_note_commitment, "hex");
    c[31] ^= 0x01;
    memo.change_note_commitment = c.toString("hex");
    await expect(verifyFillMemo(memo, store)).rejects.toBeInstanceOf(
      FillMemoError,
    );
    await expect(verifyFillMemo(memo, store)).rejects.toMatchObject({
      kind: "commitment_mismatch",
    });
  });

  it("rejects a substituted inner even with a self-consistent commitment", async () => {
    const { memo, store } = await fixture(250n);
    const evilInnerBytes = await deriveMatchOutputInner(
      bn254ToBE32(INPUT_INNER),
      MATCH_ROLE_CHANGE_SELLER,
    );
    const evilInner = be32ToBig(evilInnerBytes);
    memo.inner_hash = hex(evilInnerBytes);
    memo.change_note_commitment = hex(
      await noteCommitmentV2({
        tokenMint: MINT,
        amount: 250n,
        ownerCommitment: OWNER,
        innerHash: evilInner,
      }),
    );
    await expect(verifyFillMemo(memo, store)).rejects.toMatchObject({
      kind: "inner_hash_mismatch",
    });
  });

  it("rejects a memo whose consumed input is unavailable", async () => {
    const { memo } = await fixture(100n);
    await expect(
      verifyFillMemo(memo, new InMemoryNoteStore()),
    ).rejects.toMatchObject({ kind: "input_note_missing" });
  });

  it("rejects malformed fields with FillMemoError", async () => {
    const { memo, store } = await fixture(100n);
    await expect(
      verifyFillMemo({ ...memo, inner_hash: "zz".repeat(32) }, store),
    ).rejects.toMatchObject({ kind: "malformed" });
    await expect(
      verifyFillMemo({ ...memo, change_note_commitment: "00" }, store),
    ).rejects.toMatchObject({ kind: "malformed" });
    await expect(
      verifyFillMemo({ ...memo, change_amount: -1 }, store),
    ).rejects.toMatchObject({ kind: "malformed" });
    await expect(
      verifyFillMemo({ ...memo, change_amount: 1.5 }, store),
    ).rejects.toMatchObject({ kind: "malformed" });
    await expect(
      verifyFillMemo({ ...memo, output_role: 0xff }, store),
    ).rejects.toMatchObject({ kind: "malformed" });
  });

  it("persists a verified note into the store", async () => {
    const { memo, store } = await fixture(777n);
    const rec = await receiveFillMemo(memo, store);
    expect(store.get(rec.commitment)).toEqual(rec);
    expect(store.list()).toHaveLength(2);
  });
});
