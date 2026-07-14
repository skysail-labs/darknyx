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
 * amounts from the per-account FillMemo (delivered over the authenticated
 * `/v1/stream` fills channel); partial-fill is signalled by change-note presence.
 *
 * BYTE-LAYOUT CONTRACT: the 552-byte payload mirrors
 * `programs/vault/src/instructions/tee_forced_settle.rs::MatchResultPayload`
 * and the TS encoder `@nyx/sdk` `settle-builder.ts::serializePayload`. The
 * `decode.test.ts` round-trips against that encoder so the two can't drift.
 *
 * One settle ix = ONE match (one payload). A batch is N such ixs sharing a
 * marker. ix data = disc(8) ‖ payload(552) ‖ match_index(1) ‖ siblings(128).
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
 *  v8 (change-amount recovery, Proposal B) appended the 128-byte `fill_recovery`
 *  field to the v7 424-byte layout → 552. The locator fields this indexer reads
 *  all precede it, so their offsets are unchanged. */
export const PAYLOAD_LEN = 552;

const ZERO32 = "0".repeat(64);

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const u64 = (v: DataView, off: number) => v.getBigUint64(off, true);

/** Field-level decode of a `MatchResultPayload` (PAYLOAD_LEN bytes).
 *
 *  Amount-privacy (P3b): commitments + order ids only — no plaintext amounts.
 *  Change-amount recovery (Proposal B, v8): plus the opaque 128-byte
 *  `fill_recovery` bundle (`ephemeral_pubkey(32) ‖ buyer_enc(36) ‖
 *  seller_enc(36) ‖ pad(24)`), which the indexer stores but cannot decrypt. */
export interface MatchPayload {
  matchId: string;
  orderIdA: string;
  orderIdB: string;
  noteEcommitment: string; // buyer change note ([0;32] = exact fill)
  noteFcommitment: string; // seller change note ([0;32] = exact fill)
  batchSlot: bigint;
  /** Shared ephemeral X25519 pubkey, hex — `null` when there's no recovery
   *  ciphertext (all-zero bundle). */
  ephemeralPubkey: string | null;
  /** Buyer-side 36-byte encrypted change_amount, hex — `null` when zeroed. */
  buyerEnc: string | null;
  /** Seller-side 36-byte encrypted change_amount, hex — `null` when zeroed. */
  sellerEnc: string | null;
}

/** Offsets into the 128-byte fill_recovery bundle (which itself starts at 424). */
const FILL_RECOVERY_OFFSET = 424;
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
  // fill_recovery internal layout: eph[0,32) buyer_enc[32,68) seller_enc[68,104).
  const eph = payload.subarray(r, r + 32);
  return {
    matchId: hex(payload.subarray(0, 16)),
    // 6 × 32-byte commitments + 2 × 32-byte nullifiers precede the order ids.
    noteEcommitment: hex(payload.subarray(144, 176)),
    noteFcommitment: hex(payload.subarray(176, 208)),
    orderIdA: hex(payload.subarray(272, 288)),
    orderIdB: hex(payload.subarray(288, 304)),
    // After order_id_b: note_fee_base (304..336) + note_fee_quote (336..368) +
    // buyer_relock_order_id (368..384) + buyer_relock_expiry (384..392) +
    // seller_relock_order_id (392..408) + seller_relock_expiry (408..416) +
    // batch_slot (416..424) + fill_recovery (424..552).
    batchSlot: u64(v, 416),
    ephemeralPubkey: hexOrNull(eph),
    buyerEnc: hexOrNull(payload.subarray(r + 32, r + 68)),
    sellerEnc: hexOrNull(payload.subarray(r + 68, r + 104)),
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
  /** `true` when this side received a change note (partial fill). */
  isPartialFill: boolean;
  /** 32-byte hex of the minted change note, or `null` when the side filled exactly. */
  changeNoteCommitment: string | null;
  batchSlot: string;
  /** Change-amount recovery (Proposal B): the shared ephemeral X25519 pubkey
   *  (hex) and THIS side's 36-byte encrypted change_amount (hex). Opaque to the
   *  indexer; the client decrypts with its viewing secret + self-verifies against
   *  `changeNoteCommitment`. `null` when this side carries no recovery ciphertext. */
  ephemeralPubkey: string | null;
  changeEnc: string | null;
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
      isPartialFill: !buyerExact,
      changeNoteCommitment: buyerExact ? null : p.noteEcommitment,
      batchSlot: p.batchSlot.toString(),
      ephemeralPubkey: p.ephemeralPubkey,
      changeEnc: p.buyerEnc,
    },
    {
      orderId: p.orderIdB,
      side: "seller",
      matchId: p.matchId,
      isPartialFill: !sellerExact,
      changeNoteCommitment: sellerExact ? null : p.noteFcommitment,
      batchSlot: p.batchSlot.toString(),
      ephemeralPubkey: p.ephemeralPubkey,
      changeEnc: p.sellerEnc,
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
