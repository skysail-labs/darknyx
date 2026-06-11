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
  batchValidityMarkerPda,
  consumedNotePda,
  merkleTreePda,
  noteLockPda,
  nullifierEntryPda,
  vaultConfigPda,
} from "../idl/vault-client.js";

/** Canonical on-chain Ed25519 precompile program id. */
export const ED25519_PROGRAM_ID = new PublicKey(
  "Ed25519SigVerify111111111111111111111111111",
);

/** 16 zero bytes — the "no relock" sentinel for an order id
 *  (relocated here when batch/inclusion-proof.ts was removed). */
const RELOCK_ORDER_ID_NONE = new Uint8Array(16);
export { RELOCK_ORDER_ID_NONE };

/** All-zero 32-byte commitment (= "field not used" e.g. no change note). */
export const ZERO_COMMITMENT = new Uint8Array(32);

/** Groth16 proof bytes in the flat layout the on-chain verifier expects. */
export interface Groth16Proof {
  piA: Uint8Array;   // 64 bytes
  piB: Uint8Array;   // 128 bytes
  piC: Uint8Array;   // 64 bytes
}

/** All-zero Groth16 proof. Kept as a public export for callers (tests) that
 *  build placeholder proof structures; the settle ix no longer carries a
 *  proof inline (v3.1 split it into the `verify_valid_price` ix). */
export const ZERO_PROOF: Groth16Proof = {
  piA: new Uint8Array(64),
  piB: new Uint8Array(128),
  piC: new Uint8Array(64),
};

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
  // Per-batch protocol fee notes, one per mint ([0;32] = none). Both set
  // only on the first settlement in a batch. base = seller-side (base
  // mint), quote = buyer-side (quote mint).
  noteFeeBaseCommitment: Uint8Array;
  noteFeeQuoteCommitment: Uint8Array;
  buyerRelockOrderId: Uint8Array;   // RELOCK_ORDER_ID_NONE when no re-lock
  buyerRelockExpiry: bigint;
  sellerRelockOrderId: Uint8Array;
  sellerRelockExpiry: bigint;
  clearingPrice: bigint;
  batchSlot: bigint;
  // v3.1: `priceProof` and `priceCommitment` are no longer in the settle
  // payload. The VALID_PRICE Groth16 proof now lives in a preceding
  // `verify_valid_price` ix that writes a marker PDA at
  // `[b"valid_price", priceCommitment]`. The on-chain settle handler
  // recomputes the commitment from (clearingPrice, batchSlot) and
  // asserts the marker PDA exists. Build the prep ix via
  // `buildVerifyValidPriceIx` and submit it before the settle tx.
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
    fixed(p.noteFeeBaseCommitment, 32),
    fixed(p.noteFeeQuoteCommitment, 32),
    fixed(p.buyerRelockOrderId, 16),
    u64LE(p.buyerRelockExpiry),
    fixed(p.sellerRelockOrderId, 16),
    u64LE(p.sellerRelockExpiry),
    u64LE(p.clearingPrice),
    u64LE(p.batchSlot),
    // v3.1: priceProof + priceCommitment removed from the payload (the
    // Groth16 proof is verified by a preceding `verify_valid_price` ix
    // that writes a marker PDA; the settle handler recomputes
    // priceCommitment from clearingPrice + batchSlot and reads the marker).
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
  // v6: the single fee-note slot was split into base + quote.
  h.update(Buffer.from("nyx-match-v6"));
  h.update(fixed(p.matchId, 16));
  h.update(fixed(p.noteAcommitment, 32));
  h.update(fixed(p.noteBcommitment, 32));
  h.update(fixed(p.noteCcommitment, 32));
  h.update(fixed(p.noteDcommitment, 32));
  h.update(fixed(p.noteEcommitment, 32));
  h.update(fixed(p.noteFcommitment, 32));
  h.update(fixed(p.noteFeeBaseCommitment, 32));
  h.update(fixed(p.noteFeeQuoteCommitment, 32));
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


// ---------------------------------------------------------------------------
// v3.5 — tee_forced_settle_batched
// ---------------------------------------------------------------------------

export interface BuildSettleBatchedIxParams {
  programId: PublicKey;
  /** Which Merkle-tree shard the output notes append to. */
  treeId: number;
  /** TEE authority — signer, must be one of vault_config.tee_pubkeys. */
  teeAuthority: PublicKey;
  payload: MatchResultPayload;
  /** Match's position in the batch (0..15). Bits select left/right at each
   *  Merkle level (bit 0 = leaf-level direction, bit 3 = level-3). */
  matchIndex: number;
  /** Sibling hashes at each of the 4 levels (leaf-level → root-level pair). */
  merkleProof: [Uint8Array, Uint8Array, Uint8Array, Uint8Array];
  /** Merkle root the batch committed to. Used to derive the
   *  BatchValidityMarker PDA address; the on-chain handler re-derives the
   *  same root from leaf + proof and asserts the PDA is at that address. */
  merkleRoot: Uint8Array;
}

/**
 * Build the `tee_forced_settle_batched` Anchor ix. The caller must also
 * prepend a valid Ed25519Program precompile ix signing
 * `canonicalPayloadHash(payload)` with `teeAuthority` for the on-chain
 * verification to succeed.
 *
 * Accounts order MUST match `TeeForcedSettleBatched<'info>` (post-sharding:
 * vault_config is read-only, the writable tree state is merkle_tree at slot 2):
 *   0  tee_authority           (mut, signer)
 *   1  vault_config            (ro)
 *   2  merkle_tree[treeId]     (mut — the output-shard append)
 *   3  note_lock_a             (mut, close)
 *   4  note_lock_b             (mut, close)
 *   5  consumed_a              (init)
 *   6  consumed_b              (init)
 *   7  nullifier_a_entry       (init)
 *   8  nullifier_b_entry       (init)
 *   9  note_lock_e             (mut — relock; dummy when no buyer change)
 *  10  note_lock_f             (mut — relock; dummy when no seller change)
 *  11  instructions_sysvar
 *  12  batch_validity_marker   (mut — left open; closed by a separate ix)
 *  13  system_program
 *
 * ix data = disc(8) || tree_id(1) || payload(Borsh) || match_index(1) || 4×32 siblings.
 */
export function buildSettleBatchedIx(
  p: BuildSettleBatchedIxParams,
): TransactionInstruction {
  if (!Number.isInteger(p.treeId) || p.treeId < 0 || p.treeId > 255) {
    // treeId is a u8 shard id (PDA seed byte + first ix-data byte). A negative
    // or non-integer value would silently mask to a bogus shard via `& 0xff`.
    throw new Error(`buildSettleBatchedIx: treeId (${p.treeId}) must be an integer in [0,255]`);
  }
  if (p.matchIndex < 0 || p.matchIndex > 15) {
    throw new Error(`buildSettleBatchedIx: matchIndex (${p.matchIndex}) out of range [0,15]`);
  }
  if (p.merkleProof.length !== 4) {
    throw new Error("buildSettleBatchedIx: merkleProof must have exactly 4 siblings");
  }
  for (let i = 0; i < 4; i++) {
    if (p.merkleProof[i].length !== 32) {
      throw new Error(`buildSettleBatchedIx: merkleProof[${i}] must be 32 bytes`);
    }
  }
  if (p.merkleRoot.length !== 32) {
    throw new Error("buildSettleBatchedIx: merkleRoot must be 32 bytes");
  }

  const [vaultConfig] = vaultConfigPda(p.programId);
  const [merkleTree] = merkleTreePda(p.programId, p.treeId);
  const [lockA] = noteLockPda(p.programId, p.payload.noteAcommitment);
  const [lockB] = noteLockPda(p.programId, p.payload.noteBcommitment);
  const [consumedA] = consumedNotePda(p.programId, p.payload.noteAcommitment);
  const [consumedB] = consumedNotePda(p.programId, p.payload.noteBcommitment);
  const [nullA] = nullifierEntryPda(p.programId, p.payload.nullifierA);
  const [nullB] = nullifierEntryPda(p.programId, p.payload.nullifierB);
  const [lockE] = noteLockPda(p.programId, p.payload.noteEcommitment);
  const [lockF] = noteLockPda(p.programId, p.payload.noteFcommitment);
  const [batchMarker] = batchValidityMarkerPda(p.programId, p.merkleRoot);

  // ix data = anchor disc + payload (Borsh) + match_index (u8) + 4 × 32 sibling bytes.
  // Anchor's [[u8; 32]; 4] is encoded as 128 contiguous bytes (no length prefix).
  const siblingsConcat = cat(...p.merkleProof);
  const matchIndexByte = new Uint8Array([p.matchIndex & 0xff]);

  const data = cat(
    anchorDiscriminator("tee_forced_settle_batched"),
    new Uint8Array([p.treeId & 0xff]),
    serializePayload(p.payload),
    matchIndexByte,
    siblingsConcat,
  );

  return new TransactionInstruction({
    programId: p.programId,
    keys: [
      { pubkey: p.teeAuthority, isSigner: true, isWritable: true },
      { pubkey: vaultConfig, isSigner: false, isWritable: false },
      { pubkey: merkleTree, isSigner: false, isWritable: true },
      { pubkey: lockA, isSigner: false, isWritable: true },
      { pubkey: lockB, isSigner: false, isWritable: true },
      { pubkey: consumedA, isSigner: false, isWritable: true },
      { pubkey: consumedB, isSigner: false, isWritable: true },
      { pubkey: nullA, isSigner: false, isWritable: true },
      { pubkey: nullB, isSigner: false, isWritable: true },
      { pubkey: lockE, isSigner: false, isWritable: true },
      { pubkey: lockF, isSigner: false, isWritable: true },
      { pubkey: SYSVAR_INSTRUCTIONS_PUBKEY, isSigner: false, isWritable: false },
      { pubkey: batchMarker, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.from(data),
  });
}

// ---------------------------------------------------------------------------
// v3.5 — close_batch_validity_marker
// ---------------------------------------------------------------------------

export interface BuildCloseBatchValidityMarkerIxParams {
  programId: PublicKey;
  /** Caller. Either equals `marker.payer` (close-anytime) or any
   *  signer if the marker has already passed `expiry_slot`. */
  authority: PublicKey;
  /** Refund target — MUST equal `marker.payer` recorded by
   *  `verify_match_batch`. Anchor's `has_one = payer` check on the
   *  marker enforces this. For the matcher's standard fast-path
   *  (close immediately after the last settle in the batch), pass
   *  the same key as `authority`. */
  payer: PublicKey;
  /** The batch's Merkle root — seeds the marker PDA. */
  merkleRoot: Uint8Array;
}

/**
 * Build the `close_batch_validity_marker` Anchor ix. Caller should
 * land this once per batch, after the last `tee_forced_settle_batched`
 * succeeds; the ix refunds the marker's rent (~49 bytes worth) to
 * `marker.payer`.
 *
 * Accounts order MUST match `CloseBatchValidityMarker<'info>`:
 *   0  authority   (signer)
 *   1  payer       (mut — refund recipient; must equal marker.payer)
 *   2  marker      (mut, close = payer)
 */
export function buildCloseBatchValidityMarkerIx(
  p: BuildCloseBatchValidityMarkerIxParams,
): TransactionInstruction {
  if (p.merkleRoot.length !== 32) {
    throw new Error(
      "buildCloseBatchValidityMarkerIx: merkleRoot must be 32 bytes",
    );
  }
  const [marker] = batchValidityMarkerPda(p.programId, p.merkleRoot);

  // Anchor ix data: 8-byte discriminator + 32-byte merkle_root arg.
  const data = cat(
    anchorDiscriminator("close_batch_validity_marker"),
    p.merkleRoot,
  );

  return new TransactionInstruction({
    programId: p.programId,
    keys: [
      { pubkey: p.authority, isSigner: true, isWritable: false },
      { pubkey: p.payer, isSigner: false, isWritable: true },
      { pubkey: marker, isSigner: false, isWritable: true },
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
    noteFeeBaseCommitment: ZERO_COMMITMENT,
    noteFeeQuoteCommitment: ZERO_COMMITMENT,
    buyerRelockOrderId: RELOCK_ORDER_ID_NONE,
    buyerRelockExpiry: 0n,
    sellerRelockOrderId: RELOCK_ORDER_ID_NONE,
    sellerRelockExpiry: 0n,
    // v3.1: default clearingPrice from the leg ratio. The VALID_PRICE
    // circuit asserts `quoteAmount === baseAmount * clearingPrice` exactly,
    // so for any explicit-fill match this is forced. Tests that need a
    // different price (e.g. asserting the circuit catches mismatches)
    // pass `clearingPrice` explicitly.
    clearingPrice: args.clearingPrice ?? (
      args.baseAmount === 0n
        ? 0n
        : args.quoteAmount % args.baseAmount === 0n
          ? args.quoteAmount / args.baseAmount
          : (() => {
              throw new Error(
                `exactFillPayload: quoteAmount (${args.quoteAmount}) ` +
                  `is not an exact multiple of baseAmount (${args.baseAmount}); ` +
                  `pass an explicit clearingPrice to override`,
              );
            })()
    ),
    batchSlot: args.batchSlot ?? 0n,
  };
}
