/**
 * Settlement watcher + `MatchNotification` shape.
 *
 * A relayer subscribes to the vault program's `TradeSettled` event (emitted
 * by `tee_forced_settle`) and converts each occurrence into a
 * user-friendly `MatchNotification` the client / UI consumes.
 *
 * Key Phase-5 details:
 *   - `isPartialFill` is derived from `buyerChangeAmt` / `sellerChangeAmt`.
 *   - `relockActive` tells the relayer whether the client still has an
 *     active order — if true, DO NOT resubmit; the continuing order's
 *     residual is already re-locked against the change note.
 *   - `feeNoteLeaf` is set when the batch's fee note was flushed on this
 *     settlement (= `noteFeeLeaf !== U64_MAX`).
 */

/** Matches the on-chain `TradeSettled` event (Borsh order). */
export interface TradeSettledEvent {
  matchId: Uint8Array;
  clearingPrice: bigint;
  baseAmount: bigint;
  quoteAmount: bigint;
  buyerChangeAmt: bigint;
  sellerChangeAmt: bigint;
  buyerFeeAmt: bigint;
  sellerFeeAmt: bigint;
  noteCleaf: bigint;
  noteDleaf: bigint;
  /** `U64_MAX` means no buyer change leaf was inserted. */
  noteEleaf: bigint;
  /** `U64_MAX` means no seller change leaf was inserted. */
  noteFleaf: bigint;
  /** Per-batch protocol fee note leaves (base + quote). `U64_MAX` means
   *  that mint had no fee note on this settlement — only the first
   *  settlement in a batch carries them. */
  noteFeeBaseLeaf: bigint;
  noteFeeQuoteLeaf: bigint;
  buyerRelockActive: boolean;
  sellerRelockActive: boolean;
  newRoot: Uint8Array;
}

export const U64_MAX = 0xffff_ffff_ffff_ffffn;

/** High-level client-facing summary of one settlement. */
export interface MatchNotification {
  matchId: Uint8Array;
  side: "buyer" | "seller";
  isPartialFill: boolean;
  tradeLeaf: bigint;          // buyer=noteCleaf, seller=noteDleaf
  changeLeaf: bigint | null;  // buyer=noteEleaf, seller=noteFleaf (null if exact fill)
  feeLeaf: bigint | null;     // protocol fee-note leaf for this side's mint (buyer=quote, seller=base), batch-level, or null
  /** The side's protocol fee deducted from its input note. */
  feePaid: bigint;
  /** `true` when the continuing order was re-locked against the change
   *  note — relayer must NOT resubmit; the next batch continues trading. */
  relockActive: boolean;
  baseAmount: bigint;
  quoteAmount: bigint;
  clearingPrice: bigint;
  newRoot: Uint8Array;
}

/** Project the on-chain event into the buyer-side client view. */
export function buyerNotification(ev: TradeSettledEvent): MatchNotification {
  const isPartial = ev.buyerChangeAmt > 0n;
  return {
    matchId: ev.matchId,
    side: "buyer",
    isPartialFill: isPartial,
    tradeLeaf: ev.noteCleaf,
    changeLeaf: ev.noteEleaf === U64_MAX ? null : ev.noteEleaf,
    // Buyer pays the quote-side fee → the quote fee note (batch-level).
    feeLeaf: ev.noteFeeQuoteLeaf === U64_MAX ? null : ev.noteFeeQuoteLeaf,
    feePaid: ev.buyerFeeAmt,
    relockActive: ev.buyerRelockActive,
    baseAmount: ev.baseAmount,
    quoteAmount: ev.quoteAmount,
    clearingPrice: ev.clearingPrice,
    newRoot: ev.newRoot,
  };
}

/** Project the on-chain event into the seller-side client view. */
export function sellerNotification(ev: TradeSettledEvent): MatchNotification {
  const isPartial = ev.sellerChangeAmt > 0n;
  return {
    matchId: ev.matchId,
    side: "seller",
    isPartialFill: isPartial,
    tradeLeaf: ev.noteDleaf,
    changeLeaf: ev.noteFleaf === U64_MAX ? null : ev.noteFleaf,
    // Seller pays the base-side fee → the base fee note (batch-level).
    feeLeaf: ev.noteFeeBaseLeaf === U64_MAX ? null : ev.noteFeeBaseLeaf,
    feePaid: ev.sellerFeeAmt,
    relockActive: ev.sellerRelockActive,
    baseAmount: ev.baseAmount,
    quoteAmount: ev.quoteAmount,
    clearingPrice: ev.clearingPrice,
    newRoot: ev.newRoot,
  };
}

/** Deserialise the Anchor event data bytes (everything *after* the 8-byte
 *  discriminator) into a `TradeSettledEvent`. The producer is
 *  `programs/vault/src/instructions/tee_forced_settle.rs::TradeSettled`.
 *
 *  Layout (Borsh):
 *    16  match_id
 *    8   clearing_price
 *    8   base_amount
 *    8   quote_amount
 *    8   buyer_change_amt
 *    8   seller_change_amt
 *    8   buyer_fee_amt
 *    8   seller_fee_amt
 *    8   note_c_leaf
 *    8   note_d_leaf
 *    8   note_e_leaf
 *    8   note_f_leaf
 *    8   note_fee_base_leaf
 *    8   note_fee_quote_leaf
 *    1   buyer_relock_active
 *    1   seller_relock_active
 *    32  new_root
 */
export function decodeTradeSettled(eventData: Uint8Array): TradeSettledEvent {
  // 16 (match_id) + 13 u64 fields (incl. base+quote fee leaves) + 2 bools + 32 root.
  const expected = 16 + 8 * 13 + 1 + 1 + 32;
  if (eventData.length !== expected) {
    throw new Error(
      `TradeSettled event length mismatch: got ${eventData.length}, expected ${expected}`,
    );
  }
  const dv = new DataView(eventData.buffer, eventData.byteOffset, eventData.byteLength);
  let off = 0;
  const matchId = eventData.slice(off, off + 16); off += 16;
  const clearingPrice = dv.getBigUint64(off, true); off += 8;
  const baseAmount = dv.getBigUint64(off, true); off += 8;
  const quoteAmount = dv.getBigUint64(off, true); off += 8;
  const buyerChangeAmt = dv.getBigUint64(off, true); off += 8;
  const sellerChangeAmt = dv.getBigUint64(off, true); off += 8;
  const buyerFeeAmt = dv.getBigUint64(off, true); off += 8;
  const sellerFeeAmt = dv.getBigUint64(off, true); off += 8;
  const noteCleaf = dv.getBigUint64(off, true); off += 8;
  const noteDleaf = dv.getBigUint64(off, true); off += 8;
  const noteEleaf = dv.getBigUint64(off, true); off += 8;
  const noteFleaf = dv.getBigUint64(off, true); off += 8;
  const noteFeeBaseLeaf = dv.getBigUint64(off, true); off += 8;
  const noteFeeQuoteLeaf = dv.getBigUint64(off, true); off += 8;
  const buyerRelockActive = eventData[off] === 1; off += 1;
  const sellerRelockActive = eventData[off] === 1; off += 1;
  const newRoot = eventData.slice(off, off + 32);
  return {
    matchId,
    clearingPrice,
    baseAmount,
    quoteAmount,
    buyerChangeAmt,
    sellerChangeAmt,
    buyerFeeAmt,
    sellerFeeAmt,
    noteCleaf,
    noteDleaf,
    noteEleaf,
    noteFleaf,
    noteFeeBaseLeaf,
    noteFeeQuoteLeaf,
    buyerRelockActive,
    sellerRelockActive,
    newRoot,
  };
}
