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
  piA: Uint8Array; // 64 bytes
  piB: Uint8Array; // 128 bytes
  piC: Uint8Array; // 64 bytes
}

/** All-zero Groth16 proof. Kept as a public export for callers (tests) that
 *  build placeholder proof structures; the settle ix no longer carries a
 *  proof inline (v3.1 split it into the `verify_valid_price` ix). */
export const ZERO_PROOF: Groth16Proof = {
  piA: new Uint8Array(64),
  piB: new Uint8Array(128),
  piC: new Uint8Array(64),
};

/** Byte-for-byte shape of `tee_forced_settle::MatchResultPayload`.
 *
 *  Amount-privacy (P3b): the seven plaintext amount fields (baseAmount,
 *  quoteAmount, buyer/sellerChangeAmt, buyer/sellerFeeAmt, clearingPrice) were
 *  removed — they're proven in-circuit + bound by the note commitments, and
 *  putting them in the (public, on-chain) settle ix leaked every trade size.
 *  The canonical-hash domain bumped `v6`→`v7`. Settlement payload v9 removed
 *  the two unused nullifiers; commitment-keyed consumed-note PDAs are the
 *  replay guard shared by settlement and withdrawal. The Darknyx namespace
 *  cutover retains the 488-byte layout and signs it under v10. v11 replaces the
 *  two consumed commitments with note-use TAGS and appends the two relock tags
 *  (488 -> 552 bytes, domain v11).
 *
 *  The payload is deliberately MIXED: inputs are handles, outputs are
 *  identities. Republishing a consumed commitment here would relink both inputs
 *  to their Merkle leaves and undo the unlinkability for every note that ever
 *  trades; the outputs must be commitments because the handler appends them as
 *  leaves. */
export interface MatchResultPayload {
  matchId: Uint8Array; // [u8; 16]
  /** CONSUMED inputs — note-use tags, not commitments. */
  noteAuseTag: Uint8Array; // [u8; 32]
  noteBuseTag: Uint8Array;
  /** OUTPUTS — commitments; these become Merkle leaves. */
  noteCcommitment: Uint8Array;
  noteDcommitment: Uint8Array;
  noteEcommitment: Uint8Array; // [0;32] when no buyer change
  noteFcommitment: Uint8Array; // [0;32] when no seller change
  orderIdA: Uint8Array; // [u8; 16]
  orderIdB: Uint8Array;
  // Per-batch protocol fee notes, one per mint ([0;32] = none). Both set
  // only on the first settlement in a batch. base = seller-side (base
  // mint), quote = buyer-side (quote mint).
  noteFeeBaseCommitment: Uint8Array;
  noteFeeQuoteCommitment: Uint8Array;
  buyerRelockOrderId: Uint8Array; // RELOCK_ORDER_ID_NONE when no re-lock
  buyerRelockExpiry: bigint;
  sellerRelockOrderId: Uint8Array;
  sellerRelockExpiry: bigint;
  /**
   * Tags for the change notes this settle creates and immediately RE-LOCKS.
   * Needed *in addition to* `noteE/Fcommitment`: the commitment is the leaf
   * value, the tag is the NoteLock PDA seed, and neither derives from the
   * other without the private inner hash. `[0;32]` when that side has no
   * change, mirroring the commitment.
   */
  noteEuseTag: Uint8Array;
  noteFuseTag: Uint8Array;
  batchSlot: bigint;
  /** Durable output recovery v3: `ephemeral_pubkey(32) ‖ buyer_enc(44) ‖
   * seller_enc(44) ‖ "DNYXREC3"`. Each side encrypts `(trade, change)`; an
   * absent viewing key zeroes only that side's blob. */
  fillRecovery: Uint8Array; // [u8; 128]
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
    fixed(p.noteAuseTag, 32),
    fixed(p.noteBuseTag, 32),
    fixed(p.noteCcommitment, 32),
    fixed(p.noteDcommitment, 32),
    fixed(p.noteEcommitment, 32),
    fixed(p.noteFcommitment, 32),
    fixed(p.orderIdA, 16),
    fixed(p.orderIdB, 16),
    fixed(p.noteFeeBaseCommitment, 32),
    fixed(p.noteFeeQuoteCommitment, 32),
    fixed(p.buyerRelockOrderId, 16),
    u64LE(p.buyerRelockExpiry),
    fixed(p.sellerRelockOrderId, 16),
    u64LE(p.sellerRelockExpiry),
    fixed(p.noteEuseTag, 32),
    fixed(p.noteFuseTag, 32),
    u64LE(p.batchSlot),
    // Amount-privacy (P3b): the seven plaintext amount fields were removed
    // from the payload (proven in-circuit + bound by the note commitments).
    // v8 added the fixed 128-byte recovery bundle; recovery v3 repacks it.
    fixed(p.fillRecovery, 128),
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
  // v7: amount-privacy (P3b) dropped the seven plaintext amount fields.
  // v8 appended the 128-byte fill_recovery field (repacked internally in v2).
  // v9: removed the two vestigial nullifiers.
  // v10: clean Darknyx namespace cutover; wire fields remain unchanged.
  // v11: consumed commitments become note-use tags and the two relock tags are
  // appended. The hash order is NOT the Borsh order — the fee commitments sit
  // ahead of the order ids here — so both were changed independently against
  // `tee_forced_settle::canonical_payload_hash`.
  h.update(Buffer.from("darknyx-match-v11"));
  h.update(fixed(p.matchId, 16));
  h.update(fixed(p.noteAuseTag, 32));
  h.update(fixed(p.noteBuseTag, 32));
  h.update(fixed(p.noteCcommitment, 32));
  h.update(fixed(p.noteDcommitment, 32));
  h.update(fixed(p.noteEcommitment, 32));
  h.update(fixed(p.noteFcommitment, 32));
  h.update(fixed(p.noteFeeBaseCommitment, 32));
  h.update(fixed(p.noteFeeQuoteCommitment, 32));
  h.update(fixed(p.orderIdA, 16));
  h.update(fixed(p.orderIdB, 16));
  h.update(fixed(p.buyerRelockOrderId, 16));
  h.update(u64LE(p.buyerRelockExpiry));
  h.update(fixed(p.sellerRelockOrderId, 16));
  h.update(u64LE(p.sellerRelockExpiry));
  h.update(fixed(p.noteEuseTag, 32));
  h.update(fixed(p.noteFuseTag, 32));
  h.update(u64LE(p.batchSlot));
  h.update(fixed(p.fillRecovery, 128)); // v8: encrypted output-recovery bundle
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
  teePubkey: Uint8Array; // 32
  signature: Uint8Array; // 64
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
  header[0] = 1; // num_signatures
  header[1] = 0; // padding
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
 *   5  consumed_a              (init — the consume-once guard, shared w/ withdraw)
 *   6  consumed_b              (init)
 *   7  note_lock_e             (mut only when buyer relock is requested)
 *   8  note_lock_f             (mut only when seller relock is requested)
 *   9  instructions_sysvar
 *  10  batch_validity_marker   (ro — left open; swept after expiry)
 *  11  system_program
 *
 * The two per-match `nullifier_entry` accounts and their payload fields are
 * removed. The commitment-keyed `consumed_a/b` PDAs are the replay guard shared
 * with withdrawal.
 *
 * ix data = disc(8) || tree_id(1) || payload(Borsh) || match_index(1) || 4×32 siblings.
 */
export function buildSettleBatchedIx(
  p: BuildSettleBatchedIxParams,
): TransactionInstruction {
  if (!Number.isInteger(p.treeId) || p.treeId < 0 || p.treeId > 255) {
    // treeId is a u8 shard id (PDA seed byte + first ix-data byte). A negative
    // or non-integer value would silently mask to a bogus shard via `& 0xff`.
    throw new Error(
      `buildSettleBatchedIx: treeId (${p.treeId}) must be an integer in [0,255]`,
    );
  }
  if (p.matchIndex < 0 || p.matchIndex > 15) {
    throw new Error(
      `buildSettleBatchedIx: matchIndex (${p.matchIndex}) out of range [0,15]`,
    );
  }
  if (p.merkleProof.length !== 4) {
    throw new Error(
      "buildSettleBatchedIx: merkleProof must have exactly 4 siblings",
    );
  }
  for (let i = 0; i < 4; i++) {
    if (p.merkleProof[i].length !== 32) {
      throw new Error(
        `buildSettleBatchedIx: merkleProof[${i}] must be 32 bytes`,
      );
    }
  }
  if (p.merkleRoot.length !== 32) {
    throw new Error("buildSettleBatchedIx: merkleRoot must be 32 bytes");
  }

  const [vaultConfig] = vaultConfigPda(p.programId);
  const [merkleTree] = merkleTreePda(p.programId, p.treeId);
  const [lockA] = noteLockPda(p.programId, p.payload.noteAuseTag);
  const [lockB] = noteLockPda(p.programId, p.payload.noteBuseTag);
  const [consumedA] = consumedNotePda(p.programId, p.payload.noteAuseTag);
  const [consumedB] = consumedNotePda(p.programId, p.payload.noteBuseTag);
  // The relock locks are seeded on the TAGS, not the change commitments the
  // adjacent fields carry. An exact fill leaves both zero, and the encoder
  // dedups the two identical PDAs into one account slot (CLAUDE.md §6).
  const [lockE] = noteLockPda(p.programId, p.payload.noteEuseTag);
  const [lockF] = noteLockPda(p.programId, p.payload.noteFuseTag);
  const [batchMarker] = batchValidityMarkerPda(p.programId, p.merkleRoot);
  const buyerRelock = p.payload.buyerRelockOrderId.some((x) => x !== 0);
  const sellerRelock = p.payload.sellerRelockOrderId.some((x) => x !== 0);

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
      { pubkey: lockE, isSigner: false, isWritable: buyerRelock },
      { pubkey: lockF, isSigner: false, isWritable: sellerRelock },
      {
        pubkey: SYSVAR_INSTRUCTIONS_PUBKEY,
        isSigner: false,
        isWritable: false,
      },
      { pubkey: batchMarker, isSigner: false, isWritable: false },
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
  /** Any signer may sweep once the marker reaches `expiry_slot`. */
  authority: PublicKey;
  /** Refund target — MUST equal `marker.payer` recorded by
   *  `verify_match_batch`. Anchor's `has_one = payer` check on the
   *  marker enforces this. */
  payer: PublicKey;
  /** The batch's Merkle root — seeds the marker PDA. */
  merkleRoot: Uint8Array;
}

/**
 * Build the `close_batch_validity_marker` Anchor ix. Caller should
 * land this once per batch at or after marker expiry; the ix refunds the
 * marker's rent (~49 bytes worth) to `marker.payer`.
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
 *  fills / fees / re-locks.
 *
 *  Amount-privacy (P3b): `baseAmount` / `quoteAmount` / `clearingPrice` no
 *  longer ride the payload. They're accepted as optional args for call-site
 *  back-compat (and to read as "this is a 100-base/5000-quote fill") but are
 *  not written anywhere. */
export function exactFillPayload(args: {
  matchId: Uint8Array;
  noteAuseTag: Uint8Array;
  noteBuseTag: Uint8Array;
  noteCcommitment: Uint8Array;
  noteDcommitment: Uint8Array;
  orderIdA: Uint8Array;
  orderIdB: Uint8Array;
  baseAmount?: bigint;
  quoteAmount?: bigint;
  clearingPrice?: bigint;
  batchSlot?: bigint;
}): MatchResultPayload {
  return {
    matchId: args.matchId,
    noteAuseTag: args.noteAuseTag,
    noteBuseTag: args.noteBuseTag,
    noteCcommitment: args.noteCcommitment,
    noteDcommitment: args.noteDcommitment,
    noteEcommitment: ZERO_COMMITMENT,
    noteFcommitment: ZERO_COMMITMENT,
    noteEuseTag: ZERO_COMMITMENT,
    noteFuseTag: ZERO_COMMITMENT,
    orderIdA: args.orderIdA,
    orderIdB: args.orderIdB,
    noteFeeBaseCommitment: ZERO_COMMITMENT,
    noteFeeQuoteCommitment: ZERO_COMMITMENT,
    buyerRelockOrderId: RELOCK_ORDER_ID_NONE,
    buyerRelockExpiry: 0n,
    sellerRelockOrderId: RELOCK_ORDER_ID_NONE,
    sellerRelockExpiry: 0n,
    batchSlot: args.batchSlot ?? 0n,
    // Recovery is TEE-populated at settle after both output amounts are known.
    fillRecovery: new Uint8Array(128),
  };
}
