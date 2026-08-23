/**
 * Settlement watcher + `MatchNotification` shape.
 *
 * A relayer subscribes to the vault program's `TradeSettled` event (emitted
 * by `tee_forced_settle`) and converts each occurrence into a
 * user-friendly `MatchNotification` the client / UI consumes.
 *
 * Key details:
 *   - `isPartialFill` is derived from `buyerChangeAmt` / `sellerChangeAmt`.
 *   - `relockActive` tells the relayer whether the client still has an
 *     active order — if true, DO NOT resubmit; the continuing order's
 *     residual is already re-locked against the change note.
 *   - `feeNoteLeaf` is set when the batch's fee note was flushed on this
 *     settlement (= `noteFeeLeaf !== U64_MAX`).
 */

/** Matches the on-chain `TradeSettled` event (Borsh order).
 *
 *  Amount-privacy: the trade amounts / change / fees / clearing price
 *  were removed from the event (they were a public leak). The event now carries
 *  only leaf indices + relock flags + root; a client reconstructs its own
 *  amounts from the per-account FillMemo (`fills` on `/v1/stream`). */
export interface TradeSettledEvent {
  /** The Merkle-tree shard the output notes were appended to. */
  treeId: number;
  matchId: Uint8Array;
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
  tradeLeaf: bigint; // buyer=noteCleaf, seller=noteDleaf
  changeLeaf: bigint | null; // buyer=noteEleaf, seller=noteFleaf (null if exact fill)
  feeLeaf: bigint | null; // protocol fee-note leaf for this side's mint (buyer=quote, seller=base), batch-level, or null
  /** `true` when the continuing order was re-locked against the change
   *  note — relayer must NOT resubmit; the next batch continues trading. */
  relockActive: boolean;
  newRoot: Uint8Array;
}

/** Project the on-chain event into the buyer-side client view. */
export function buyerNotification(ev: TradeSettledEvent): MatchNotification {
  // Partial fill ⇔ a change note was inserted (its leaf index is present).
  // The amount itself is no longer on-chain — the client reads it from the memo.
  const changeLeaf = ev.noteEleaf === U64_MAX ? null : ev.noteEleaf;
  return {
    matchId: ev.matchId,
    side: "buyer",
    isPartialFill: changeLeaf !== null,
    tradeLeaf: ev.noteCleaf,
    changeLeaf,
    // Buyer pays the quote-side fee → the quote fee note (batch-level).
    feeLeaf: ev.noteFeeQuoteLeaf === U64_MAX ? null : ev.noteFeeQuoteLeaf,
    relockActive: ev.buyerRelockActive,
    newRoot: ev.newRoot,
  };
}

/** Project the on-chain event into the seller-side client view. */
export function sellerNotification(ev: TradeSettledEvent): MatchNotification {
  const changeLeaf = ev.noteFleaf === U64_MAX ? null : ev.noteFleaf;
  return {
    matchId: ev.matchId,
    side: "seller",
    isPartialFill: changeLeaf !== null,
    tradeLeaf: ev.noteDleaf,
    changeLeaf,
    // Seller pays the base-side fee → the base fee note (batch-level).
    feeLeaf: ev.noteFeeBaseLeaf === U64_MAX ? null : ev.noteFeeBaseLeaf,
    relockActive: ev.sellerRelockActive,
    newRoot: ev.newRoot,
  };
}

/** Deserialise the Anchor event data bytes (everything *after* the 8-byte
 *  discriminator) into a `TradeSettledEvent`. The producer is
 *  `programs/vault/src/instructions/tee_forced_settle.rs::TradeSettled`.
 *
 *  Layout (Borsh) — amount-privacy dropped the amount/price fields:
 *    1   tree_id      <- the shard the outputs landed in; LEADS the event
 *    16  match_id
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
  // 1 (tree_id) + 16 (match_id) + 6 u64 leaf indices + 2 bools + 32 root.
  //
  // The leading `tree_id` byte was missed when tree sharding added it: this
  // expected 98 bytes against a 99-byte event, so every decode threw. It went
  // unnoticed because nothing in production calls this — `chain-history.ts`
  // has its own decoder and gets the offset right. Fixed here rather than left
  // as a trap for the first caller.
  const expected = 1 + 16 + 8 * 6 + 1 + 1 + 32;
  if (eventData.length !== expected) {
    throw new Error(
      `TradeSettled event length mismatch: got ${eventData.length}, expected ${expected}`,
    );
  }
  const dv = new DataView(
    eventData.buffer,
    eventData.byteOffset,
    eventData.byteLength,
  );
  let off = 0;
  const treeId = eventData[off];
  off += 1;
  const matchId = eventData.slice(off, off + 16);
  off += 16;
  const noteCleaf = dv.getBigUint64(off, true);
  off += 8;
  const noteDleaf = dv.getBigUint64(off, true);
  off += 8;
  const noteEleaf = dv.getBigUint64(off, true);
  off += 8;
  const noteFleaf = dv.getBigUint64(off, true);
  off += 8;
  const noteFeeBaseLeaf = dv.getBigUint64(off, true);
  off += 8;
  const noteFeeQuoteLeaf = dv.getBigUint64(off, true);
  off += 8;
  const buyerRelockActive = eventData[off] === 1;
  off += 1;
  const sellerRelockActive = eventData[off] === 1;
  off += 1;
  const newRoot = eventData.slice(off, off + 32);
  return {
    treeId,
    matchId,
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
