/**
 * Decode the vault's `tee_forced_settle_batched` instruction data into per-order
 * fill records.
 *
 * WHY the ix data (not the `TradeSettled` event): the event is keyed by
 * `match_id` and carries change amounts + leaf indices but NOT `order_id` or note
 * commitments. Only the instruction's `MatchResultPayload` carries `order_id_a/b`
 * + `note_e/f_commitment` + the change amounts — exactly what a by-order_id index
 * needs. So we decode the ix data.
 *
 * BYTE-LAYOUT CONTRACT: the 480-byte payload mirrors
 * `programs/vault/src/instructions/tee_forced_settle.rs::MatchResultPayload`
 * and the TS encoder `@nyx/sdk` `settle-builder.ts::serializePayload`. The
 * `decode.test.ts` round-trips against that encoder so the two can't drift.
 *
 * One settle ix = ONE match (one payload). A batch is N such ixs sharing a
 * marker. ix data = disc(8) ‖ payload(480) ‖ match_index(1) ‖ siblings(128).
 */

import { createHash } from "node:crypto";

/** Anchor discriminator: `sha256("global:<name>")[..8]`. Mirrors `@nyx/sdk` `anchorDiscriminator`. */
export function anchorDiscriminator(name: string): Uint8Array {
  return new Uint8Array(createHash("sha256").update(`global:${name}`).digest().subarray(0, 8));
}

export const SETTLE_IX_NAME = "tee_forced_settle_batched";
export const SETTLE_DISCRIMINATOR = anchorDiscriminator(SETTLE_IX_NAME);

/** Borsh-serialized `MatchResultPayload` is exactly this many bytes. */
export const PAYLOAD_LEN = 480;

const ZERO32 = "0".repeat(64);

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const u64 = (v: DataView, off: number) => v.getBigUint64(off, true);

/** Field-level decode of a 480-byte `MatchResultPayload`. */
export interface MatchPayload {
  matchId: string;
  orderIdA: string;
  orderIdB: string;
  noteEcommitment: string; // buyer change note ([0;32] = exact fill)
  noteFcommitment: string; // seller change note ([0;32] = exact fill)
  baseAmount: bigint;
  quoteAmount: bigint;
  buyerChangeAmt: bigint;
  sellerChangeAmt: bigint;
  clearingPrice: bigint;
  batchSlot: bigint;
}

export function decodeMatchPayload(payload: Uint8Array): MatchPayload {
  if (payload.length !== PAYLOAD_LEN) {
    throw new Error(`payload must be ${PAYLOAD_LEN} bytes; got ${payload.length}`);
  }
  const v = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  return {
    matchId: hex(payload.subarray(0, 16)),
    // 6 × 32-byte commitments + 2 × 32-byte nullifiers precede the order ids.
    noteEcommitment: hex(payload.subarray(144, 176)),
    noteFcommitment: hex(payload.subarray(176, 208)),
    orderIdA: hex(payload.subarray(272, 288)),
    orderIdB: hex(payload.subarray(288, 304)),
    baseAmount: u64(v, 304),
    quoteAmount: u64(v, 312),
    buyerChangeAmt: u64(v, 320),
    sellerChangeAmt: u64(v, 328),
    clearingPrice: u64(v, 464),
    batchSlot: u64(v, 472),
  };
}

/** One settled fill, keyed by the order that produced it. */
export interface SettleFill {
  orderId: string;
  side: "buyer" | "seller";
  matchId: string;
  /** Change amount in base units (decimal string — u64-safe). `"0"` on exact fill. */
  changeAmount: string;
  /** 32-byte hex of the minted change note, or `null` when the side filled exactly. */
  changeNoteCommitment: string | null;
  clearingPrice: string;
  batchSlot: string;
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
      changeAmount: p.buyerChangeAmt.toString(),
      changeNoteCommitment: buyerExact ? null : p.noteEcommitment,
      clearingPrice: p.clearingPrice.toString(),
      batchSlot: p.batchSlot.toString(),
    },
    {
      orderId: p.orderIdB,
      side: "seller",
      matchId: p.matchId,
      changeAmount: p.sellerChangeAmt.toString(),
      changeNoteCommitment: sellerExact ? null : p.noteFcommitment,
      clearingPrice: p.clearingPrice.toString(),
      batchSlot: p.batchSlot.toString(),
    },
  ];
}

/**
 * Decode a vault instruction's raw data. Returns the two fill rows when it is a
 * `tee_forced_settle_batched` ix, or `null` for any other ix (wrong
 * discriminator / too short) so the watcher can skip it.
 */
export function decodeSettleIxData(data: Uint8Array): SettleFill[] | null {
  if (data.length < 8 + PAYLOAD_LEN) return null;
  for (let i = 0; i < 8; i++) {
    if (data[i] !== SETTLE_DISCRIMINATOR[i]) return null;
  }
  const payload = data.subarray(8, 8 + PAYLOAD_LEN);
  return payloadToFills(decodeMatchPayload(payload));
}
