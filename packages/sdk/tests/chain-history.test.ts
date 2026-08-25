/**
 * Direct-chain rediscovery (`fills/chain-history.ts`) — the indexer-free backfill.
 *
 * Guards the byte-layout contract by building the settle ix data with the REAL
 * `serializePayload` encoder (so the decoder's offsets can't drift from the
 * encoder / the indexer's `decode.ts`), and exercises the HD gap-scan with a
 * mocked scanner (no live RPC).
 */

import { describe, it, expect } from "vitest";
import { PublicKey, type Connection } from "@solana/web3.js";

/** Stand-in vault program id; only its base58 form matters here. */
const PROGRAM_ID = new PublicKey(new Uint8Array(32).fill(0x51));
import {
  serializePayload,
  type MatchResultPayload,
} from "../src/settlement/settle-builder.js";
import { anchorDiscriminator } from "../src/idl/vault-client.js";
import { deriveOrderId } from "../src/keys/key-generators.js";
import {
  decodeSettleFeeCommitments,
  decodeSettleFills,
  backfillHistoryFromChain,
  makeConnectionScan,
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
const buyerEnc = fill(44, 0x22); // buyer output tuple ciphertext
const sellerEnc = fill(44, 0x00); // no seller viewing key

const payload: MatchResultPayload = {
  matchId: fill(16, 0x01),
  noteAuseTag: fill(32, 0xa1),
  noteBuseTag: fill(32, 0xa2),
  noteCcommitment: fill(32, 0xa3),
  noteDcommitment: fill(32, 0xa4),
  noteEcommitment: noteE,
  noteFcommitment: fill(32, 0x00), // seller change zero ⇒ exact fill
  noteEuseTag: fill(32, 0xe6), // buyer relock handle
  noteFuseTag: fill(32, 0x00), // seller exact ⇒ no relock
  orderIdA,
  orderIdB,
  noteFeeBaseCommitment: fill(32, 0xf1),
  noteFeeQuoteCommitment: fill(32, 0xf2),
  buyerRelockOrderId: fill(16, 0x00),
  buyerRelockExpiry: 0n,
  sellerRelockOrderId: fill(16, 0x00),
  sellerRelockExpiry: 0n,
  batchSlot: 123n,
  fillRecovery: cat(
    eph,
    buyerEnc,
    sellerEnc,
    new TextEncoder().encode("DNYXREC3"),
  ),
};

// Realistic ix data: disc(8) ‖ tree_id(1) ‖ payload(552) ‖ match_index(1) ‖ siblings(128).
const ixData = cat(
  anchorDiscriminator("tee_forced_settle_batched"),
  new Uint8Array([0]), // tree_id
  serializePayload(payload),
  new Uint8Array([0]), // match_index
  fill(128, 0x00), // siblings
);

describe("decodeSettleFills", () => {
  it("decodes both sides with the encoder's exact offsets", () => {
    const fills = decodeSettleFills(ixData, "sig1", 456);
    expect(fills).not.toBeNull();
    const [buyer, seller] = fills!;

    expect(buyer.orderId).toBe(hex(orderIdA));
    expect(buyer.side).toBe("buyer");
    expect(buyer.inputNoteUseTag).toBe(hex(payload.noteAuseTag));
    expect(buyer.tradeNoteCommitment).toBe(hex(payload.noteCcommitment));
    expect(buyer.isPartialFill).toBe(true);
    expect(buyer.changeNoteCommitment).toBe(hex(noteE));
    expect(buyer.ephemeralPubkey).toBe(hex(eph));
    expect(buyer.outputEnc).toBe(hex(buyerEnc));
    expect(buyer.batchSlot).toBe("123");
    expect(buyer.signature).toBe("sig1");
    expect(buyer.slot).toBe(456);

    expect(seller.orderId).toBe(hex(orderIdB));
    expect(seller.side).toBe("seller");
    expect(seller.isPartialFill).toBe(false); // exact ⇒ no change note
    expect(seller.changeNoteCommitment).toBeNull();
    expect(seller.outputEnc).toBeNull(); // zero ciphertext ⇒ null
  });

  it("returns null for a non-settle ix (wrong discriminator)", () => {
    const notSettle = cat(anchorDiscriminator("deposit"), fill(560, 0x00));
    expect(decodeSettleFills(notSettle, "sig")).toBeNull();
  });

  it("returns null when the data is too short", () => {
    expect(decodeSettleFills(fill(100, 0x00), "sig")).toBeNull();
  });
});

describe("decodeSettleFeeCommitments", () => {
  it("decodes both fee commitments with the encoder's exact offsets", () => {
    const fees = decodeSettleFeeCommitments(ixData);
    expect(fees).not.toBeNull();
    expect(fees!.base).toEqual(payload.noteFeeBaseCommitment);
    expect(fees!.quote).toEqual(payload.noteFeeQuoteCommitment);
  });

  it("rejects non-settle and truncated instruction data", () => {
    const notSettle = cat(anchorDiscriminator("deposit"), fill(560, 0x00));
    expect(decodeSettleFeeCommitments(notSettle)).toBeNull();
    expect(decodeSettleFeeCommitments(fill(100, 0x00))).toBeNull();
  });
});

describe("backfillHistoryFromChain", () => {
  it("HD-gap-scans the seed and locates the account's own fill", async () => {
    const scan = async (): Promise<RawSettleTx[]> => [
      { signature: "sig1", slot: 456, ixDatas: [ixData] },
    ];

    const res = await backfillHistoryFromChain({
      // `connection` is unused when `scan` is injected. `programId` still is:
      // it scopes the `TradeSettled` log decode to the vault, so an event
      // emitted by any other program in the same tx is not read.
      connection: undefined as unknown as Connection,
      programId: PROGRAM_ID,
      masterSeed: SEED,
      scan,
    });

    expect(res.located).toHaveLength(1); // only the buyer order id belongs to this seed
    expect(res.located[0].orderId).toBe(hex(orderIdA));
    expect(res.located[0].changeNoteCommitment).toBe(hex(noteE));
    expect(res.located[0].outputEnc).toBe(hex(buyerEnc));
    expect(res.located[0].ephemeralPubkey).toBe(hex(eph));
    expect(res.highestUsedIndex).toBe(0);
    expect(res.cursorSlot).toBe(456);
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

describe("makeConnectionScan", () => {
  it("pins both signature and transaction reads to finalized commitment", async () => {
    const programId = new PublicKey(fill(32, 0x77));
    const connection = {
      getSignaturesForAddress: async (
        address: PublicKey,
        _opts: unknown,
        commitment: string,
      ) => {
        expect(address.equals(programId)).toBe(true);
        expect(commitment).toBe("finalized");
        return [
          {
            signature: "sig-finalized",
            slot: 456,
            err: null,
            memo: null,
            blockTime: null,
            confirmationStatus: "finalized",
          },
        ];
      },
      getTransactions: async (
        signatures: string[],
        config: { commitment: string },
      ) => {
        expect(signatures).toEqual(["sig-finalized"]);
        expect(config.commitment).toBe("finalized");
        return [
          {
            slot: 456,
            meta: { logMessages: ["Program log: finalized"] },
            transaction: {
              message: {
                accountKeys: [programId],
                compiledInstructions: [
                  { programIdIndex: 0, accountKeyIndexes: [], data: ixData },
                ],
              },
            },
          },
        ];
      },
    } as unknown as Connection;

    const rows = await makeConnectionScan(connection, programId)({});
    expect(rows).toHaveLength(1);
    expect(rows[0].slot).toBe(456);
    expect(rows[0].ixDatas[0]).toEqual(ixData);
    expect(rows[0].logMessages).toEqual(["Program log: finalized"]);
  });

  it("bounds history at the recovery floor and batches transaction reads by 50", async () => {
    const programId = new PublicKey(fill(32, 0x77));
    const requested: string[][] = [];
    const signatures = Array.from({ length: 51 }, (_, index) => ({
      signature: `sig-${index}`,
      slot: 200 - index,
      err: null,
      memo: null,
      blockTime: null,
      confirmationStatus: "finalized" as const,
    }));
    signatures.push({
      signature: "below-floor",
      slot: 149,
      err: null,
      memo: null,
      blockTime: null,
      confirmationStatus: "finalized",
    });
    const connection = {
      getSignaturesForAddress: async () => signatures,
      getTransactions: async (batch: string[]) => {
        requested.push(batch);
        return batch.map((_signature, index) => ({
          slot: index,
          meta: { logMessages: [] },
          transaction: {
            message: {
              accountKeys: [programId],
              compiledInstructions: [
                { programIdIndex: 0, accountKeyIndexes: [], data: ixData },
              ],
            },
          },
        }));
      },
    } as unknown as Connection;

    const rows = await makeConnectionScan(
      connection,
      programId,
    )({
      sinceSlot: 150,
    });
    expect(requested.map((batch) => batch.length)).toEqual([50, 1]);
    expect(requested.flat()).not.toContain("below-floor");
    expect(rows).toHaveLength(51);
  });
});
