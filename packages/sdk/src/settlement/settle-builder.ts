/**
 * Phase-5 settlement tx builder.
 *
 * Mirrors `programs/vault/src/instructions/tee_forced_settle.rs`:
 *   - Canonical SHA-256 payload hash (byte-identical across TS + Rust + TEE).
 *   - Ed25519Program precompile ix with inlined (pubkey, signature, msg).
 *   - `tee_forced_settle` ix — Anchor-discriminator + Borsh-serialised
 *     `MatchResultPayload` + full accounts list.
 *
 * Typical call site (relayer):
 *   ```ts
 *   const payload = buildSettlementPayloadFromMatch(match, ...);
 *   const msgHash = canonicalPayloadHash(payload);
 *   const sig = teeSignEd25519(msgHash); // inside TEE
 *   const tx = buildSettleTx({ programId, teePubkey, payload, signature: sig });
 *   ```
 */

import { createHash } from "node:crypto";
import {
  PublicKey,
  SystemProgram,
  TransactionInstruction,
  SYSVAR_INSTRUCTIONS_PUBKEY,
} from "@solana/web3.js";

import {
  anchorDiscriminator,
  consumedNotePda,
  noteLockPda,
  nullifierEntryPda,
  vaultConfigPda,
} from "../idl/vault-client.js";

/** Canonical on-chain Ed25519 precompile program id. */
export const ED25519_PROGRAM_ID = new PublicKey(
  "Ed25519SigVerify111111111111111111111111111",
);

import { RELOCK_ORDER_ID_NONE } from "../batch/inclusion-proof.js";
export { RELOCK_ORDER_ID_NONE };

/** All-zero 32-byte commitment (= "field not used" e.g. no change note). */
export const ZERO_COMMITMENT = new Uint8Array(32);

/** Byte-for-byte shape of `tee_forced_settle::MatchResultPayload`. */
export interface MatchResultPayload {
  matchId: Uint8Array;              // [u8; 16]
  noteAcommitment: Uint8Array;      // [u8; 32]
  noteBcommitment: Uint8Array;
  noteCcommitment: Uint8Array;
  noteDcommitment: Uint8Array;
  noteEcommitment: Uint8Array;      // [0;32] when no buyer change
  noteFcommitment: Uint8Array;      // [0;32] when no seller change
  nullifierA: Uint8Array;
  nullifierB: Uint8Array;
  orderIdA: Uint8Array;             // [u8; 16]
  orderIdB: Uint8Array;
  baseAmount: bigint;
  quoteAmount: bigint;
  buyerChangeAmt: bigint;
  sellerChangeAmt: bigint;
  buyerFeeAmt: bigint;
  sellerFeeAmt: bigint;
  noteFeeCommitment: Uint8Array;    // [0;32] = no fee flush on this settlement
  buyerRelockOrderId: Uint8Array;   // RELOCK_ORDER_ID_NONE when no re-lock
  buyerRelockExpiry: bigint;
  sellerRelockOrderId: Uint8Array;
  sellerRelockExpiry: bigint;
  clearingPrice: bigint;
  batchSlot: bigint;
}

// ---------- Borsh serialisation ----------

function u64LE(v: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, v, true);
  return out;
}

function fixed(x: Uint8Array, len: number): Uint8Array {
  if (x.length !== len) {
    throw new Error(`expected ${len} bytes, got ${x.length}`);
  }
  return x;
}

function cat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((s, b) => s + b.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** Serialise [`MatchResultPayload`] with the on-chain field order. */
export function serializePayload(p: MatchResultPayload): Uint8Array {
  return cat(
    fixed(p.matchId, 16),
    fixed(p.noteAcommitment, 32),
    fixed(p.noteBcommitment, 32),
    fixed(p.noteCcommitment, 32),
    fixed(p.noteDcommitment, 32),
    fixed(p.noteEcommitment, 32),
    fixed(p.noteFcommitment, 32),
    fixed(p.nullifierA, 32),
    fixed(p.nullifierB, 32),
    fixed(p.orderIdA, 16),
    fixed(p.orderIdB, 16),
    u64LE(p.baseAmount),
    u64LE(p.quoteAmount),
    u64LE(p.buyerChangeAmt),
    u64LE(p.sellerChangeAmt),
    u64LE(p.buyerFeeAmt),
    u64LE(p.sellerFeeAmt),
    fixed(p.noteFeeCommitment, 32),
    fixed(p.buyerRelockOrderId, 16),
    u64LE(p.buyerRelockExpiry),
    fixed(p.sellerRelockOrderId, 16),
    u64LE(p.sellerRelockExpiry),
    u64LE(p.clearingPrice),
    u64LE(p.batchSlot),
  );
}

// ---------- Canonical payload hash ----------

/**
 * Canonical 32-byte SHA-256 of the match payload used as the TEE's signed
 * message. Byte-identical to `tee_forced_settle::canonical_payload_hash`.
 *
 * DO NOT change the field order or domain tag — on-chain verification will
 * reject any hash computed with a different layout.
 */
export function canonicalPayloadHash(p: MatchResultPayload): Uint8Array {
  const h = createHash("sha256");
  h.update(Buffer.from("nyx-match-v5"));
  h.update(fixed(p.matchId, 16));
  h.update(fixed(p.noteAcommitment, 32));
  h.update(fixed(p.noteBcommitment, 32));
  h.update(fixed(p.noteCcommitment, 32));
  h.update(fixed(p.noteDcommitment, 32));
  h.update(fixed(p.noteEcommitment, 32));
  h.update(fixed(p.noteFcommitment, 32));
  h.update(fixed(p.noteFeeCommitment, 32));
  h.update(fixed(p.nullifierA, 32));
  h.update(fixed(p.nullifierB, 32));
  h.update(fixed(p.orderIdA, 16));
  h.update(fixed(p.orderIdB, 16));
  h.update(u64LE(p.baseAmount));
  h.update(u64LE(p.quoteAmount));
  h.update(u64LE(p.buyerChangeAmt));
  h.update(u64LE(p.sellerChangeAmt));
  h.update(u64LE(p.buyerFeeAmt));
  h.update(u64LE(p.sellerFeeAmt));
  h.update(fixed(p.buyerRelockOrderId, 16));
  h.update(u64LE(p.buyerRelockExpiry));
  h.update(fixed(p.sellerRelockOrderId, 16));
  h.update(u64LE(p.sellerRelockExpiry));
  h.update(u64LE(p.clearingPrice));
  h.update(u64LE(p.batchSlot));
  return new Uint8Array(h.digest());
}

// ---------- Ed25519 precompile ix builder ----------

/**
 * Build an Ed25519Program precompile instruction with inlined pubkey,
 * signature, and message. Matches the layout expected by
 * `tee_forced_settle::verify_tee_signature`.
 *
 * Header layout (16 bytes, LE):
 *   u8   num_signatures = 1
 *   u8   padding        = 0
 *   u16  signature_offset
 *   u16  signature_instruction_index = 0xFFFF (inlined)
 *   u16  public_key_offset
 *   u16  public_key_instruction_index = 0xFFFF
 *   u16  message_data_offset
 *   u16  message_data_size
 *   u16  message_instruction_index = 0xFFFF
 *
 * Followed by pubkey (32B) || signature (64B) || message (N).
 */
export function buildEd25519VerifyIx(params: {
  teePubkey: Uint8Array;   // 32
  signature: Uint8Array;   // 64
  message: Uint8Array;
}): TransactionInstruction {
  const pk = fixed(params.teePubkey, 32);
  const sig = fixed(params.signature, 64);
  const msg = params.message;
  const headerLen = 16;
  const pkOff = headerLen;
  const sigOff = pkOff + 32;
  const msgOff = sigOff + 64;

  const header = new Uint8Array(headerLen);
  const dv = new DataView(header.buffer);
  header[0] = 1;       // num_signatures
  header[1] = 0;       // padding
  dv.setUint16(2, sigOff, true);
  dv.setUint16(4, 0xffff, true); // sig_ix_idx
  dv.setUint16(6, pkOff, true);
  dv.setUint16(8, 0xffff, true); // pk_ix_idx
  dv.setUint16(10, msgOff, true);
  dv.setUint16(12, msg.length, true);
  dv.setUint16(14, 0xffff, true); // msg_ix_idx

  const data = cat(header, pk, sig, msg);
  return new TransactionInstruction({
    programId: ED25519_PROGRAM_ID,
    keys: [],
    data: Buffer.from(data),
  });
}

// ---------- tee_forced_settle ix builder ----------

export interface BuildSettleIxParams {
  /** vault program id. */
  programId: PublicKey;
  /** The TEE authority (signer — must equal vault_config.tee_pubkey). */
  teeAuthority: PublicKey;
  payload: MatchResultPayload;
}

/**
 * Build the `tee_forced_settle` Anchor ix. The caller must also prepend a
 * valid Ed25519Program precompile ix signing
 * `canonicalPayloadHash(payload)` with `teeAuthority` for the on-chain
 * verification to succeed.
 *
 * Accounts order MUST match `TeeForcedSettle<'info>`:
 *   0  tee_authority     (mut, signer)
 *   1  vault_config      (mut)
 *   2  note_lock_a       (mut, close)
 *   3  note_lock_b       (mut, close)
 *   4  consumed_a        (init)
 *   5  consumed_b        (init)
 *   6  nullifier_a_entry (init)
 *   7  nullifier_b_entry (init)
 *   8  note_lock_e       (mut — may be unused when no re-lock; seed derived from note_e_commitment)
 *   9  note_lock_f       (mut — same for seller)
 *  10  instructions_sysvar
 *  11  system_program
 */
export function buildSettleIx(p: BuildSettleIxParams): TransactionInstruction {
  const [vaultConfig] = vaultConfigPda(p.programId);
  const [lockA] = noteLockPda(p.programId, p.payload.noteAcommitment);
  const [lockB] = noteLockPda(p.programId, p.payload.noteBcommitment);
  const [consumedA] = consumedNotePda(p.programId, p.payload.noteAcommitment);
  const [consumedB] = consumedNotePda(p.programId, p.payload.noteBcommitment);
  const [nullA] = nullifierEntryPda(p.programId, p.payload.nullifierA);
  const [nullB] = nullifierEntryPda(p.programId, p.payload.nullifierB);
  // The note-lock accounts for note_e/note_f are always required; the
  // handler inspects them only when the corresponding relock is active.
  // We always seed them from the change-note commitments so the seeds
  // line up when relock IS active; when not, the handler ignores them.
  const [lockE] = noteLockPda(p.programId, p.payload.noteEcommitment);
  const [lockF] = noteLockPda(p.programId, p.payload.noteFcommitment);

  const data = cat(
    anchorDiscriminator("tee_forced_settle"),
    serializePayload(p.payload),
  );

  return new TransactionInstruction({
    programId: p.programId,
    keys: [
      { pubkey: p.teeAuthority, isSigner: true, isWritable: true },
      { pubkey: vaultConfig, isSigner: false, isWritable: true },
      { pubkey: lockA, isSigner: false, isWritable: true },
      { pubkey: lockB, isSigner: false, isWritable: true },
      { pubkey: consumedA, isSigner: false, isWritable: true },
      { pubkey: consumedB, isSigner: false, isWritable: true },
      { pubkey: nullA, isSigner: false, isWritable: true },
      { pubkey: nullB, isSigner: false, isWritable: true },
      { pubkey: lockE, isSigner: false, isWritable: true },
      { pubkey: lockF, isSigner: false, isWritable: true },
      { pubkey: SYSVAR_INSTRUCTIONS_PUBKEY, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.from(data),
  });
}

// ---------- Convenience helpers ----------

/** Construct an exact-fill payload with sensible zero defaults for the
 *  Phase-5 fields. Callers can mutate the returned object for partial
 *  fills / fees / re-locks. */
export function exactFillPayload(args: {
  matchId: Uint8Array;
  noteAcommitment: Uint8Array;
  noteBcommitment: Uint8Array;
  noteCcommitment: Uint8Array;
  noteDcommitment: Uint8Array;
  nullifierA: Uint8Array;
  nullifierB: Uint8Array;
  orderIdA: Uint8Array;
  orderIdB: Uint8Array;
  baseAmount: bigint;
  quoteAmount: bigint;
  clearingPrice?: bigint;
  batchSlot?: bigint;
}): MatchResultPayload {
  return {
    matchId: args.matchId,
    noteAcommitment: args.noteAcommitment,
    noteBcommitment: args.noteBcommitment,
    noteCcommitment: args.noteCcommitment,
    noteDcommitment: args.noteDcommitment,
    noteEcommitment: ZERO_COMMITMENT,
    noteFcommitment: ZERO_COMMITMENT,
    nullifierA: args.nullifierA,
    nullifierB: args.nullifierB,
    orderIdA: args.orderIdA,
    orderIdB: args.orderIdB,
    baseAmount: args.baseAmount,
    quoteAmount: args.quoteAmount,
    buyerChangeAmt: 0n,
    sellerChangeAmt: 0n,
    buyerFeeAmt: 0n,
    sellerFeeAmt: 0n,
    noteFeeCommitment: ZERO_COMMITMENT,
    buyerRelockOrderId: RELOCK_ORDER_ID_NONE,
    buyerRelockExpiry: 0n,
    sellerRelockOrderId: RELOCK_ORDER_ID_NONE,
    sellerRelockExpiry: 0n,
    clearingPrice: args.clearingPrice ?? 0n,
    batchSlot: args.batchSlot ?? 0n,
  };
}
