/**
 * Anchor-free fill-memo reception + integrity verification.
 *
 * VALID_MATCH_BATCH v3 derives a change output as
 * `Poseidon3(24, consumed_input_inner, role)`. The live memo therefore names
 * the exact consumed commitment and role. The client resolves that opening
 * from its NoteStore, derives the expected inner itself, and recomputes both
 * the consumed and output commitments before storing anything.
 */

import { bn254ToBE32 } from "../keys/key-generators.js";
import {
  deriveMatchOutputInner,
  MATCH_ROLE_CHANGE_BUYER,
  MATCH_ROLE_CHANGE_SELLER,
} from "../utxo/match-output.js";
import { noteCommitmentV2 } from "../utxo/note.js";
import type { ChangeNoteRecord, NoteStore } from "../utxo/note-store.js";

/** Wire shape of a fill memo (mirrors `darknyx_tee::matcher::FillMemo`). */
export interface FillMemo {
  order_id: string; // 16-byte hex
  consumed_note_commitment: string; // 32-byte hex
  output_role: number; // buyer/seller change role byte
  change_amount: number;
  change_note_commitment: string; // 32-byte hex
  mint: string; // 32-byte hex
  inner_hash: string; // 32-byte hex
}

export class FillMemoError extends Error {
  constructor(
    message: string,
    readonly kind:
      | "input_note_missing"
      | "input_note_mismatch"
      | "inner_hash_mismatch"
      | "commitment_mismatch"
      | "malformed",
  ) {
    super(message);
    this.name = "FillMemoError";
  }
}

function fromHex(hex: string, label: string, len: number): Uint8Array {
  // Buffer.from(hex, "hex") silently truncates at the first non-hex byte.
  if (
    typeof hex !== "string" ||
    hex.length !== len * 2 ||
    !/^[0-9a-fA-F]*$/.test(hex)
  ) {
    throw new FillMemoError(`${label}: expected ${len}-byte hex`, "malformed");
  }
  return Uint8Array.from(Buffer.from(hex, "hex"));
}

function requireAmount(n: number): bigint {
  if (!Number.isSafeInteger(n) || n < 0) {
    throw new FillMemoError(
      `change_amount must be a non-negative safe integer; got ${n}`,
      "malformed",
    );
  }
  return BigInt(n);
}

function requireOutputRole(role: number): number {
  if (
    role !== MATCH_ROLE_CHANGE_BUYER &&
    role !== MATCH_ROLE_CHANGE_SELLER
  ) {
    throw new FillMemoError(
      `output_role must be a change role; got ${role}`,
      "malformed",
    );
  }
  return role;
}

function be32ToBig(b: Uint8Array): bigint {
  let n = 0n;
  for (const x of b) n = (n << 8n) | BigInt(x);
  return n;
}

const sameBytes = (a: Uint8Array, b: Uint8Array): boolean =>
  Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;

/** Verify a JSON-number memo. Use `verifyFillMemoExact` for amounts above 2^53. */
export async function verifyFillMemo(
  memo: FillMemo,
  store: NoteStore,
): Promise<ChangeNoteRecord> {
  return verifyFillMemoExact(memo, store, requireAmount(memo.change_amount));
}

/** Verify a memo with an exact bigint amount supplied by the caller. */
export async function verifyFillMemoExact(
  memo: FillMemo,
  store: NoteStore,
  changeAmount: bigint,
): Promise<ChangeNoteRecord> {
  fromHex(memo.order_id, "order_id", 16);
  const consumed = fromHex(
    memo.consumed_note_commitment,
    "consumed_note_commitment",
    32,
  );
  const mint = fromHex(memo.mint, "mint", 32);
  const memoInner = fromHex(memo.inner_hash, "inner_hash", 32);
  const memoCommitment = fromHex(
    memo.change_note_commitment,
    "change_note_commitment",
    32,
  );
  const outputRole = requireOutputRole(memo.output_role);
  if (changeAmount < 0n || changeAmount > 0xffff_ffff_ffff_ffffn) {
    throw new FillMemoError("change_amount must fit u64", "malformed");
  }

  const consumedHex = Buffer.from(consumed).toString("hex");
  const input = await store.get(consumedHex);
  if (!input) {
    throw new FillMemoError(
      `consumed input ${consumedHex} is not present in the NoteStore`,
      "input_note_missing",
    );
  }

  // Reject corrupted or mismatched local openings before using one as the
  // derivation authority for the output.
  const recomputedInput = await noteCommitmentV2({
    tokenMint: input.tokenMint,
    amount: input.amount,
    ownerCommitment: input.ownerCommitment,
    innerHash: input.innerHash,
  });
  if (!sameBytes(recomputedInput, consumed) || !sameBytes(input.tokenMint, mint)) {
    throw new FillMemoError(
      "consumed input opening or change mint does not match the memo",
      "input_note_mismatch",
    );
  }

  const expectedInner = await deriveMatchOutputInner(
    bn254ToBE32(input.innerHash),
    outputRole,
  );
  if (!sameBytes(expectedInner, memoInner)) {
    throw new FillMemoError(
      `inner_hash mismatch: TEE used ${memo.inner_hash}, client derived ${Buffer.from(expectedInner).toString("hex")}`,
      "inner_hash_mismatch",
    );
  }

  const innerHash = be32ToBig(memoInner);
  const recomputedOutput = await noteCommitmentV2({
    tokenMint: mint,
    amount: changeAmount,
    ownerCommitment: input.ownerCommitment,
    innerHash,
  });
  if (!sameBytes(recomputedOutput, memoCommitment)) {
    throw new FillMemoError(
      `commitment mismatch: recomputed ${Buffer.from(recomputedOutput).toString("hex")} != reported ${memo.change_note_commitment}`,
      "commitment_mismatch",
    );
  }

  return {
    commitment: Buffer.from(recomputedOutput).toString("hex"),
    tokenMint: mint,
    amount: changeAmount,
    ownerCommitment: input.ownerCommitment,
    innerHash,
    orderId: memo.order_id.toLowerCase(),
    consumedCommitment: consumedHex,
  };
}

/** Verify a memo and, on success, persist the change note. */
export async function receiveFillMemo(
  memo: FillMemo,
  store: NoteStore,
): Promise<ChangeNoteRecord> {
  const rec = await verifyFillMemo(memo, store);
  await store.put(rec);
  return rec;
}
