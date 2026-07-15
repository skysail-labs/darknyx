/**
 * Direct-chain rediscovery (`fills/chain-history.ts`) — the indexer-free backfill.
 *
 * Guards the byte-layout contract by building the settle ix data with the REAL
 * `serializePayload` encoder (so the decoder's offsets can't drift from the
 * encoder / the indexer's `decode.ts`), and exercises the HD gap-scan with a
 * mocked scanner (no live RPC).
 */

import { describe, it, expect } from "vitest";
import type { Connection, PublicKey } from "@solana/web3.js";
import {
  serializePayload,
  type MatchResultPayload,
} from "../src/settlement/settle-builder.js";
import { anchorDiscriminator } from "../src/idl/vault-client.js";
import { deriveOrderId } from "../src/keys/key-generators.js";
import {
  decodeSettleFills,
  backfillHistoryFromChain,
  type RawSettleTx,
} from "../src/fills/chain-history.js";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const fill = (len: number, byte: number) => new Uint8Array(len).fill(byte);

function cat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((s, p) => s + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

const SEED = fill(64, 0x5a);
// A buyer-side partial fill for THIS account's order #0; seller side exact.
const orderIdA = deriveOrderId(SEED, 0); // my order
const orderIdB = fill(16, 0xbb); // counterparty
const noteE = fill(32, 0xe5); // buyer change note (partial fill)
const eph = fill(32, 0x11);
const buyerEnc = fill(36, 0x22); // buyer change ciphertext
const sellerEnc = fill(36, 0x00); // seller exact ⇒ zero ciphertext

const payload: MatchResultPayload = {
  matchId: fill(16, 0x01),
  noteAcommitment: fill(32, 0xa1),
  noteBcommitment: fill(32, 0xa2),
  noteCcommitment: fill(32, 0xa3),
  noteDcommitment: fill(32, 0xa4),
  noteEcommitment: noteE,
  noteFcommitment: fill(32, 0x00), // seller change zero ⇒ exact fill
  orderIdA,
  orderIdB,
  noteFeeBaseCommitment: fill(32, 0xf1),
  noteFeeQuoteCommitment: fill(32, 0xf2),
  buyerRelockOrderId: fill(16, 0x00),
  buyerRelockExpiry: 0n,
  sellerRelockOrderId: fill(16, 0x00),
  sellerRelockExpiry: 0n,
  batchSlot: 123n,
  fillRecovery: cat(eph, buyerEnc, sellerEnc, fill(24, 0x00)),
};

// Realistic ix data: disc(8) ‖ tree_id(1) ‖ payload(488) ‖ match_index(1) ‖ siblings(128).
const ixData = cat(
  anchorDiscriminator("tee_forced_settle_batched"),
  new Uint8Array([0]), // tree_id
  serializePayload(payload),
  new Uint8Array([0]), // match_index
  fill(128, 0x00), // siblings
);

describe("decodeSettleFills", () => {
  it("decodes both sides with the encoder's exact offsets", () => {
    const fills = decodeSettleFills(ixData, "sig1");
    expect(fills).not.toBeNull();
    const [buyer, seller] = fills!;

    expect(buyer.orderId).toBe(hex(orderIdA));
    expect(buyer.side).toBe("buyer");
    expect(buyer.isPartialFill).toBe(true);
    expect(buyer.changeNoteCommitment).toBe(hex(noteE));
    expect(buyer.ephemeralPubkey).toBe(hex(eph));
    expect(buyer.changeEnc).toBe(hex(buyerEnc));
    expect(buyer.batchSlot).toBe("123");
    expect(buyer.signature).toBe("sig1");

    expect(seller.orderId).toBe(hex(orderIdB));
    expect(seller.side).toBe("seller");
    expect(seller.isPartialFill).toBe(false); // exact ⇒ no change note
    expect(seller.changeNoteCommitment).toBeNull();
    expect(seller.changeEnc).toBeNull(); // zero ciphertext ⇒ null
  });

  it("returns null for a non-settle ix (wrong discriminator)", () => {
    const notSettle = cat(anchorDiscriminator("deposit"), fill(560, 0x00));
    expect(decodeSettleFills(notSettle, "sig")).toBeNull();
  });

  it("returns null when the data is too short", () => {
    expect(decodeSettleFills(fill(100, 0x00), "sig")).toBeNull();
  });
});

describe("backfillHistoryFromChain", () => {
  it("HD-gap-scans the seed and locates the account's own change-note fill", async () => {
    const scan = async (): Promise<RawSettleTx[]> => [
      { signature: "sig1", slot: 123, ixDatas: [ixData] },
    ];

    const res = await backfillHistoryFromChain({
      // connection/programId are unused when `scan` is injected.
      connection: undefined as unknown as Connection,
      programId: undefined as unknown as PublicKey,
      masterSeed: SEED,
      scan,
    });

    expect(res.located).toHaveLength(1); // buyer partial; seller exact excluded
    expect(res.located[0].orderId).toBe(hex(orderIdA));
    expect(res.located[0].changeNoteCommitment).toBe(hex(noteE));
    expect(res.located[0].changeEnc).toBe(hex(buyerEnc));
    expect(res.located[0].ephemeralPubkey).toBe(hex(eph));
    expect(res.highestUsedIndex).toBe(0);
    expect(res.cursorSlot).toBe(123);
  });

  it("returns an empty result when none of the HD order ids appear on-chain", async () => {
    const scan = async (): Promise<RawSettleTx[]> => [];
    const res = await backfillHistoryFromChain({
      connection: undefined as unknown as Connection,
      programId: undefined as unknown as PublicKey,
      masterSeed: SEED,
      scan,
    });
    expect(res.located).toHaveLength(0);
    expect(res.highestUsedIndex).toBe(-1);
  });
});
