/**
 * Decode parity: the indexer's offset-based decoder must recover exactly what
 * the SDK's `serializePayload` (mirror of the on-chain `MatchResultPayload`)
 * encodes. If the on-chain layout ever shifts, `serializePayload`'s output
 * shifts with it and these fixed offsets recover wrong values → this fails.
 */

import { describe, it, expect } from "vitest";
import { serializePayload, type MatchResultPayload } from "../../sdk/src/settlement/settle-builder.js";
import {
  decodeMatchPayload,
  decodeSettleIxData,
  payloadToFills,
  PAYLOAD_LEN,
  SETTLE_DISCRIMINATOR,
} from "../src/decode.js";

const fill = (len: number, b: number) => new Uint8Array(len).fill(b);
const hexN = (b: number, len: number) => b.toString(16).padStart(2, "0").repeat(len);

function makePayload(over: Partial<MatchResultPayload> = {}): MatchResultPayload {
  return {
    matchId: fill(16, 0x11),
    noteAcommitment: fill(32, 0xa),
    noteBcommitment: fill(32, 0xb),
    noteCcommitment: fill(32, 0xc),
    noteDcommitment: fill(32, 0xd),
    noteEcommitment: fill(32, 0xee),
    noteFcommitment: fill(32, 0xff),
    nullifierA: fill(32, 0x1a),
    nullifierB: fill(32, 0x1b),
    orderIdA: fill(16, 0xaa),
    orderIdB: fill(16, 0xbb),
    noteFeeBaseCommitment: fill(32, 0),
    noteFeeQuoteCommitment: fill(32, 0),
    buyerRelockOrderId: fill(16, 0),
    buyerRelockExpiry: 0n,
    sellerRelockOrderId: fill(16, 0),
    sellerRelockExpiry: 0n,
    batchSlot: 99n,
    fillRecovery: fill(128, 0),
    ...over,
  };
}

function ixData(p: MatchResultPayload): Uint8Array {
  const body = serializePayload(p);
  // Real `tee_forced_settle_batched` ix data: disc(8) + tree_id(u8) + payload +
  // match_index(u8) + merkle_proof(4×32). The leading `tree_id` byte (the
  // cross-shard output-shard id) MUST be present so the decoder's payload offset
  // is exercised against the true framing — omitting it is the gap that let the
  // off-by-one decode bug (every settle's order_ids shifted 1 byte) ship.
  const out = new Uint8Array(8 + 1 + body.length + 1 + 128);
  out.set(SETTLE_DISCRIMINATOR, 0);
  out[8] = 0x03; // tree_id (any shard id) — the byte decodeSettleIxData must skip
  out.set(body, 9);
  return out;
}

describe("MatchResultPayload decode", () => {
  it("serializePayload is exactly PAYLOAD_LEN bytes (layout pin)", () => {
    expect(serializePayload(makePayload()).length).toBe(PAYLOAD_LEN);
  });

  it("recovers every decoded field at the right offset", () => {
    const p = decodeMatchPayload(serializePayload(makePayload()));
    expect(p.matchId).toBe(hexN(0x11, 16));
    expect(p.orderIdA).toBe(hexN(0xaa, 16));
    expect(p.orderIdB).toBe(hexN(0xbb, 16));
    expect(p.noteEcommitment).toBe(hexN(0xee, 32));
    expect(p.noteFcommitment).toBe(hexN(0xff, 32));
    // Amount-privacy (P3b): no amounts on the wire anymore — only batch_slot
    // remains of the trailing u64s.
    expect(p.batchSlot).toBe(99n);
  });

  it("projects a partial fill into buyer + seller rows with change notes", () => {
    const fills = decodeSettleIxData(ixData(makePayload()))!;
    expect(fills).toHaveLength(2);
    const [buyer, seller] = fills;
    expect(buyer.side).toBe("buyer");
    expect(buyer.orderId).toBe(hexN(0xaa, 16));
    expect(buyer.isPartialFill).toBe(true);
    expect(buyer.changeNoteCommitment).toBe(hexN(0xee, 32));
    expect(seller.side).toBe("seller");
    expect(seller.orderId).toBe(hexN(0xbb, 16));
    expect(seller.isPartialFill).toBe(true);
    expect(seller.changeNoteCommitment).toBe(hexN(0xff, 32));
  });

  it("treats a zero note_e/f commitment as an exact fill (null change note)", () => {
    const exact = makePayload({
      noteEcommitment: fill(32, 0),
      noteFcommitment: fill(32, 0),
    });
    const [buyer, seller] = payloadToFills(decodeMatchPayload(serializePayload(exact)));
    expect(buyer.changeNoteCommitment).toBeNull();
    expect(buyer.isPartialFill).toBe(false);
    expect(seller.changeNoteCommitment).toBeNull();
  });

  it("returns null for a non-settle ix (wrong discriminator)", () => {
    const data = ixData(makePayload());
    data[0] ^= 0xff; // corrupt the discriminator
    expect(decodeSettleIxData(data)).toBeNull();
  });

  it("returns null for too-short data", () => {
    expect(decodeSettleIxData(new Uint8Array(10))).toBeNull();
  });
});
