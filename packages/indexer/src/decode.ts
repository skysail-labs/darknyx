/**
 * Decode the vault's `tee_forced_settle_batched` instruction data into per-order
 * fill records.
 *
 * WHY the ix data (not the `TradeSettled` event): the event is keyed by
 * `match_id` and carries leaf indices but NOT `order_id` or note commitments.
 * Only the instruction's `MatchResultPayload` carries `order_id_a/b` +
 * `note_e/f_commitment` — exactly what a by-order_id index needs. So we decode
 * the ix data.
 *
 * Amount-privacy (P3b): the settle ix no longer carries any plaintext amounts
 * (trade size / change / fees / clearing price). The off-TEE indexer is
 * UNTRUSTED, so this is by design — it sees only commitments + order ids and
 * acts as a by-order_id COMMITMENT LOCATOR. Each client reconstructs its own
 * trade + change amounts from the encrypted recovery tuple; partial-fill is
 * signalled by change-note presence.
 *
 * BYTE-LAYOUT CONTRACT: the 488-byte payload mirrors
 * `programs/vault/src/instructions/tee_forced_settle.rs::MatchResultPayload`
 * and the TS encoder `@nyx/sdk` `settle-builder.ts::serializePayload`. The
 * `decode.test.ts` round-trips against that encoder so the two can't drift.
 *
 * One settle ix = ONE match (one payload). A batch is N such ixs sharing a
 * marker. ix data = disc(8) ‖ tree_id(1) ‖ payload(488) ‖ match_index(1) ‖
 * siblings(128).
 */

import { createHash } from "node:crypto";

/** Anchor discriminator: `sha256("global:<name>")[..8]`. Mirrors `@nyx/sdk` `anchorDiscriminator`. */
export function anchorDiscriminator(name: string): Uint8Array {
  return new Uint8Array(
    createHash("sha256").update(`global:${name}`).digest().subarray(0, 8),
  );
}

export const SETTLE_IX_NAME = "tee_forced_settle_batched";
export const SETTLE_DISCRIMINATOR = anchorDiscriminator(SETTLE_IX_NAME);

/** Borsh-serialized `MatchResultPayload` is exactly this many bytes.
 *  v9 removed two vestigial nullifiers from v8's 552-byte layout → 488. */
export const PAYLOAD_LEN = 488;

const ZERO32 = "0".repeat(64);

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const u64 = (v: DataView, off: number) => v.getBigUint64(off, true);

/** Field-level decode of a `MatchResultPayload` (PAYLOAD_LEN bytes).
 *
 *  Amount-privacy (P3b): commitments + order ids only — no plaintext amounts.
 *  Recovery v2: plus the opaque 128-byte `fill_recovery` bundle
 *  (`ephemeral_pubkey(32) ‖ buyer_enc(44) ‖ seller_enc(44) ‖ "NYXREC02"`),
 *  which the indexer stores but cannot decrypt. */
export interface MatchPayload {
  matchId: string;
  noteAcommitment: string; // buyer input (quote)
  noteBcommitment: string; // seller input (base)
  noteCcommitment: string; // buyer trade output (base)
  noteDcommitment: string; // seller trade output (quote)
  orderIdA: string;
  orderIdB: string;
  noteEcommitment: string; // buyer change note ([0;32] = exact fill)
  noteFcommitment: string; // seller change note ([0;32] = exact fill)
  batchSlot: bigint;
  /** Shared ephemeral X25519 pubkey, hex — `null` when there's no recovery
   *  ciphertext (all-zero bundle). */
  ephemeralPubkey: string | null;
  /** Buyer-side 44-byte encrypted `(trade_base, change_quote)`, hex. */
  buyerEnc: string | null;
  /** Seller-side 44-byte encrypted `(trade_quote, change_base)`, hex. */
  sellerEnc: string | null;
}

/** Offsets into the 128-byte fill_recovery bundle (which itself starts at 360). */
const FILL_RECOVERY_OFFSET = 360;
const RECOVERY_V2_TRAILER = Buffer.from("NYXREC02", "ascii");
const isZero = (b: Uint8Array) => b.every((x) => x === 0);
const hexOrNull = (b: Uint8Array) => (isZero(b) ? null : hex(b));

export function decodeMatchPayload(payload: Uint8Array): MatchPayload {
  if (payload.length !== PAYLOAD_LEN) {
    throw new Error(
      `payload must be ${PAYLOAD_LEN} bytes; got ${payload.length}`,
    );
  }
  const v = new DataView(
    payload.buffer,
    payload.byteOffset,
    payload.byteLength,
  );
  const r = FILL_RECOVERY_OFFSET;
  // Recovery v2: eph[0,32) buyer_enc[32,76) seller_enc[76,120) trailer[120,128).
  const eph = payload.subarray(r, r + 32);
  const trailer = payload.subarray(r + 120, r + 128);
  const recoveryV2 = Buffer.from(trailer).equals(RECOVERY_V2_TRAILER);
  return {
    matchId: hex(payload.subarray(0, 16)),
    // Six 32-byte note commitments precede the order ids in payload v9.
    noteAcommitment: hex(payload.subarray(16, 48)),
    noteBcommitment: hex(payload.subarray(48, 80)),
    noteCcommitment: hex(payload.subarray(80, 112)),
    noteDcommitment: hex(payload.subarray(112, 144)),
    noteEcommitment: hex(payload.subarray(144, 176)),
    noteFcommitment: hex(payload.subarray(176, 208)),
    orderIdA: hex(payload.subarray(208, 224)),
    orderIdB: hex(payload.subarray(224, 240)),
    // After order_id_b: note_fee_base (240..272) + note_fee_quote (272..304) +
    // buyer_relock_order_id (304..320) + buyer_relock_expiry (320..328) +
    // seller_relock_order_id (328..344) + seller_relock_expiry (344..352) +
    // batch_slot (352..360) + fill_recovery (360..488).
    batchSlot: u64(v, 352),
    ephemeralPubkey: recoveryV2 ? hexOrNull(eph) : null,
    buyerEnc: recoveryV2 ? hexOrNull(payload.subarray(r + 32, r + 76)) : null,
    sellerEnc: recoveryV2 ? hexOrNull(payload.subarray(r + 76, r + 120)) : null,
  };
}

/** One settled fill, keyed by the order that produced it.
 *
 *  Amount-privacy (P3b): the indexer is a commitment LOCATOR — it carries the
 *  change-note commitment (and whether the side filled exactly) but NOT the
 *  amount. The client reads the amount from its per-account FillMemo. */
export interface SettleFill {
  orderId: string;
  side: "buyer" | "seller";
  matchId: string;
  /** Consumed input and always-present trade output commitments. */
  inputNoteCommitment: string;
  tradeNoteCommitment: string;
  /** `true` when this side received a change note (partial fill). */
  isPartialFill: boolean;
  /** 32-byte hex of the minted change note, or `null` when the side filled exactly. */
  changeNoteCommitment: string | null;
  batchSlot: string;
  /** Recovery v2: shared ephemeral X25519 pubkey and THIS side's 44-byte
   * encrypted output tuple. Opaque to the indexer. */
  ephemeralPubkey: string | null;
  outputEnc: string | null;
}

/** Project a decoded payload into one fill row per order side. */
export function payloadToFills(p: MatchPayload): SettleFill[] {
  const buyerExact = p.noteEcommitment === ZERO32;
  const sellerExact = p.noteFcommitment === ZERO32;
  return [
    {
      orderId: p.orderIdA,
      side: "buyer",
      matchId: p.matchId,
      inputNoteCommitment: p.noteAcommitment,
      tradeNoteCommitment: p.noteCcommitment,
      isPartialFill: !buyerExact,
      changeNoteCommitment: buyerExact ? null : p.noteEcommitment,
      batchSlot: p.batchSlot.toString(),
      ephemeralPubkey: p.ephemeralPubkey,
      outputEnc: p.buyerEnc,
    },
    {
      orderId: p.orderIdB,
      side: "seller",
      matchId: p.matchId,
      inputNoteCommitment: p.noteBcommitment,
      tradeNoteCommitment: p.noteDcommitment,
      isPartialFill: !sellerExact,
      changeNoteCommitment: sellerExact ? null : p.noteFcommitment,
      batchSlot: p.batchSlot.toString(),
      ephemeralPubkey: p.ephemeralPubkey,
      outputEnc: p.sellerEnc,
    },
  ];
}

/**
 * Decode a vault instruction's raw data. Returns the two fill rows when it is a
 * `tee_forced_settle_batched` ix, or `null` for any other ix (wrong
 * discriminator / too short) so the watcher can skip it.
 */
export function decodeSettleIxData(data: Uint8Array): SettleFill[] | null {
  // ix data layout: 8-byte Anchor discriminator, then the Borsh args in
  // declaration order — `tree_id: u8` (the cross-shard output-shard id), THEN
  // the MatchResultPayload, then match_index + merkle_proof. The payload starts
  // AFTER the discriminator AND that leading `tree_id` byte; reading at offset 8
  // (discriminator only) shifts every field 1 byte and corrupts the decoded
  // order_ids — see `tee_forced_settle_batched`'s signature in programs/vault.
  const PAYLOAD_OFFSET = 8 + 1; // discriminator (8) + tree_id (u8)
  if (data.length < PAYLOAD_OFFSET + PAYLOAD_LEN) return null;
  for (let i = 0; i < 8; i++) {
    if (data[i] !== SETTLE_DISCRIMINATOR[i]) return null;
  }
  const payload = data.subarray(PAYLOAD_OFFSET, PAYLOAD_OFFSET + PAYLOAD_LEN);
  return payloadToFills(decodeMatchPayload(payload));
}
