/**
 * Fill-memo reception + settle-memo integrity check (Phase 8).
 *
 * The CVM streams a `FillMemo` per continuation fill over `GET /ws/fills`.
 * Before storing the change note the client MUST verify the memo — this is
 * the guard against a misbehaving TEE (design-doc Vulnerability 4):
 *
 *   1. inner_hash binding: the memo's `inner_hash` must equal the client's
 *      OWN deterministically-derived `deriveInnerHash(seed, orderId,
 *      anchor_index)`. A TEE that substituted a different inner_hash (so it
 *      could later forge a nullifier it controls) is caught here.
 *   2. commitment binding: Poseidon6(mint, change_amount, owner, inner_hash)
 *      must equal the reported `change_note_commitment`.
 *
 * Only a memo that passes BOTH becomes a `ChangeNoteRecord`.
 */

import { deriveInnerHash, bn254ToBE32 } from "../keys/key-generators.js";
import { noteCommitmentV2 } from "../utxo/note.js";
import type { ChangeNoteRecord, NoteStore } from "../utxo/note-store.js";

/** Wire shape of a fill memo (mirrors `nyx_tee::matcher::FillMemo`). */
export interface FillMemo {
  /** Per-connection monotonic sequence. A gap means missed memos — recover via
   *  the indexer backfill ("backfill then tail"). Present on the live stream. */
  seq?: number;
  order_id: string; // 16-byte hex
  anchor_index: number;
  change_amount: number; // u64 fits a JS number for realistic amounts; see note below
  change_note_commitment: string; // 32-byte hex
  mint: string; // 32-byte hex
  inner_hash: string; // 32-byte hex
}

export class FillMemoError extends Error {
  constructor(
    message: string,
    readonly kind: "inner_hash_mismatch" | "commitment_mismatch" | "malformed",
  ) {
    super(message);
    this.name = "FillMemoError";
  }
}

function fromHex(hex: string, label: string, len: number): Uint8Array {
  // Validate FULLY: Buffer.from(hex,"hex") silently truncates at the first
  // non-hex char, so length-only checks let malformed input through.
  if (
    typeof hex !== "string" ||
    hex.length !== len * 2 ||
    !/^[0-9a-fA-F]*$/.test(hex)
  ) {
    throw new FillMemoError(`${label}: expected ${len}-byte hex`, "malformed");
  }
  const bytes = Uint8Array.from(Buffer.from(hex, "hex"));
  if (bytes.length !== len)
    throw new FillMemoError(`${label}: expected ${len} bytes`, "malformed");
  return bytes;
}

/** A non-negative safe-integer field; throws FillMemoError otherwise. */
function requireU32Index(n: number): number {
  if (!Number.isInteger(n) || n < 0 || n > 0xffff_ffff) {
    throw new FillMemoError(
      `anchor_index must be a u32; got ${n}`,
      "malformed",
    );
  }
  return n;
}

function requireAmount(n: number): bigint {
  if (!Number.isInteger(n) || n < 0) {
    throw new FillMemoError(
      `change_amount must be a non-negative integer; got ${n}`,
      "malformed",
    );
  }
  return BigInt(n);
}

function be32ToBig(b: Uint8Array): bigint {
  let n = 0n;
  for (const x of b) n = (n << 8n) | BigInt(x);
  return n;
}

/**
 * Verify a fill memo against the client's own keys + build the change-note
 * record. `masterSeed` + `orderId` (in the memo) reproduce the expected
 * inner_hash; `ownerCommitment` is the order's note owner. Throws
 * `FillMemoError` on any mismatch.
 *
 * `change_amount` arrives as a JSON number — exact for amounts below 2^53.
 * For larger amounts pass the memo through a bigint-preserving JSON parser
 * and call `verifyFillMemoExact` with an explicit `changeAmount` instead.
 */
export async function verifyFillMemo(
  memo: FillMemo,
  masterSeed: Uint8Array,
  ownerCommitment: bigint,
): Promise<ChangeNoteRecord> {
  return verifyFillMemoExact(
    memo,
    masterSeed,
    ownerCommitment,
    requireAmount(memo.change_amount),
  );
}

export async function verifyFillMemoExact(
  memo: FillMemo,
  masterSeed: Uint8Array,
  ownerCommitment: bigint,
  changeAmount: bigint,
): Promise<ChangeNoteRecord> {
  const orderId = fromHex(memo.order_id, "order_id", 16);
  const mint = fromHex(memo.mint, "mint", 32);
  const memoInner = fromHex(memo.inner_hash, "inner_hash", 32);
  const memoCommitment = fromHex(
    memo.change_note_commitment,
    "change_note_commitment",
    32,
  );
  const anchorIndex = requireU32Index(memo.anchor_index);

  // (1) inner_hash binding — the TEE must have used OUR derived inner_hash.
  const expectedInner = bn254ToBE32(
    deriveInnerHash(masterSeed, orderId, anchorIndex),
  );
  if (
    Buffer.compare(Buffer.from(expectedInner), Buffer.from(memoInner)) !== 0
  ) {
    throw new FillMemoError(
      `inner_hash mismatch at anchor_index ${anchorIndex}: ` +
        `TEE used ${memo.inner_hash}, client derived ${Buffer.from(expectedInner).toString("hex")}`,
      "inner_hash_mismatch",
    );
  }

  // (2) commitment binding — recompute + compare.
  const innerBig = be32ToBig(memoInner);
  const recomputed = await noteCommitmentV2({
    tokenMint: mint,
    amount: changeAmount,
    ownerCommitment,
    innerHash: innerBig,
  });
  const recomputedHex = Buffer.from(recomputed).toString("hex");
  if (
    Buffer.compare(Buffer.from(recomputed), Buffer.from(memoCommitment)) !== 0
  ) {
    throw new FillMemoError(
      `commitment mismatch: recomputed ${recomputedHex} != reported ${memo.change_note_commitment}`,
      "commitment_mismatch",
    );
  }

  return {
    commitment: recomputedHex,
    tokenMint: mint,
    amount: changeAmount,
    ownerCommitment,
    innerHash: innerBig,
    orderId: memo.order_id,
    anchorIndex,
  };
}

/** Verify a memo and, on success, persist the change note. */
export async function receiveFillMemo(
  memo: FillMemo,
  masterSeed: Uint8Array,
  ownerCommitment: bigint,
  store: NoteStore,
): Promise<ChangeNoteRecord> {
  const rec = await verifyFillMemo(memo, masterSeed, ownerCommitment);
  await store.put(rec);
  return rec;
}
