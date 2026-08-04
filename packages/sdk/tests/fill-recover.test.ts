/** Durable trade + change recovery under consumed-input-derived v3 outputs. */

import { describe, it, expect } from "vitest";
import crypto from "node:crypto";
import nacl from "tweetnacl";
import {
  deriveViewingEncKeypair,
  bn254ToBE32,
} from "../src/keys/key-generators.js";
import { encryptFillAmounts } from "../src/keys/fill-encryption.js";
import {
  deriveMatchOutputInner,
  MATCH_ROLE_CHANGE_BUYER,
  MATCH_ROLE_CHANGE_SELLER,
  MATCH_ROLE_TRADE_BUYER,
  MATCH_ROLE_TRADE_SELLER,
} from "../src/utxo/match-output.js";
import { noteCommitmentV2 } from "../src/utxo/note.js";
import { deriveNoteUseTag } from "../src/utxo/note-use.js";
import {
  recoverChangeFromChain,
  recoverFillFromChain,
} from "../src/fills/recover.js";
import type { IndexerFill } from "../src/fills/history.js";
import type { StoredNote } from "../src/utxo/note-store.js";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const be32ToBig = (b: Uint8Array): bigint => {
  let n = 0n;
  for (const x of b) n = (n << 8n) | BigInt(x);
  return n;
};

const SEED = new Uint8Array(64).fill(0x07);
const OWNER = 0x1234_5678n;
const QUOTE_MINT = new Uint8Array(32).fill(0x9e);
const BASE_MINT = new Uint8Array(32).fill(0xb1);
const ORDER_ID = new Uint8Array(16).fill(0xab);

async function inputNote(
  side: "buyer" | "seller",
  innerHash = 0x1234n,
): Promise<StoredNote> {
  const tokenMint = side === "buyer" ? QUOTE_MINT : BASE_MINT;
  const amount = 2_000n;
  const commitment = await noteCommitmentV2({
    tokenMint,
    amount,
    ownerCommitment: OWNER,
    innerHash,
  });
  return {
    commitment: hex(commitment),
    tokenMint,
    amount,
    ownerCommitment: OWNER,
    innerHash,
    leafIndex: 1n,
    treeId: 0,
  };
}

async function outputCommitment(
  input: StoredNote,
  tokenMint: Uint8Array,
  amount: bigint,
  role: number,
): Promise<Uint8Array> {
  const innerHash = be32ToBig(
    await deriveMatchOutputInner(bn254ToBE32(input.innerHash), role),
  );
  return noteCommitmentV2({
    tokenMint,
    amount,
    ownerCommitment: input.ownerCommitment,
    innerHash,
  });
}

async function makeFill(opts: {
  side: "buyer" | "seller";
  input: StoredNote;
  trade: bigint;
  change: bigint;
  recipientPub?: Uint8Array;
}): Promise<IndexerFill> {
  const buyer = opts.side === "buyer";
  const trade = await outputCommitment(
    opts.input,
    buyer ? BASE_MINT : QUOTE_MINT,
    opts.trade,
    buyer ? MATCH_ROLE_TRADE_BUYER : MATCH_ROLE_TRADE_SELLER,
  );
  const change =
    opts.change > 0n
      ? await outputCommitment(
          opts.input,
          buyer ? QUOTE_MINT : BASE_MINT,
          opts.change,
          buyer ? MATCH_ROLE_CHANGE_BUYER : MATCH_ROLE_CHANGE_SELLER,
        )
      : null;
  const recipient =
    opts.recipientPub ?? deriveViewingEncKeypair(SEED).publicKey;
  const ephSecret = crypto.randomBytes(32);
  const ephPub = nacl.scalarMult.base(ephSecret);
  const outputEnc = encryptFillAmounts(
    ephSecret,
    recipient,
    { trade: opts.trade, change: opts.change },
    crypto.randomBytes(12),
  );
  return {
    orderId: hex(ORDER_ID),
    side: opts.side,
    matchId: "55".repeat(16),
    signature: "00",
    slot: 500,
    inputNoteUseTag: hex(
      await deriveNoteUseTag(
        Uint8Array.from(Buffer.from(opts.input.commitment, "hex")),
        bn254ToBE32(opts.input.innerHash),
      ),
    ),
    tradeNoteCommitment: hex(trade),
    isPartialFill: change !== null,
    changeNoteCommitment: change ? hex(change) : null,
    batchSlot: "1",
    ephemeralPubkey: hex(ephPub),
    outputEnc: hex(outputEnc),
    tradeLeafIndex: "10",
    changeLeafIndex: change ? "11" : null,
  };
}

const params = (candidateInputs: StoredNote[]) => ({
  masterSeed: SEED,
  candidateInputs,
  baseMint: BASE_MINT,
  quoteMint: QUOTE_MINT,
});

describe("recoverFillFromChain recovery v3", () => {
  it("recovers buyer and seller trade + change outputs", async () => {
    for (const side of ["buyer", "seller"] as const) {
      const input = await inputNote(side);
      const fill = await makeFill({
        side,
        input,
        trade: 400n,
        change: 250n,
      });
      const outputs = await recoverFillFromChain(fill, params([input]));
      expect(outputs).not.toBeNull();
      expect(outputs!.trade.amount).toBe(400n);
      expect(outputs!.trade.commitment).toBe(fill.tradeNoteCommitment);
      expect(outputs!.trade.leafIndex).toBe(10n);
      expect(outputs!.change?.amount).toBe(250n);
      expect(outputs!.change?.commitment).toBe(fill.changeNoteCommitment);
      expect(outputs!.change?.leafIndex).toBe(11n);
      expect(outputs!.trade.consumedCommitment).toBe(input.commitment);
    }
  });

  it("recovers exact fills instead of dropping them", async () => {
    const input = await inputNote("buyer");
    const fill = await makeFill({
      side: "buyer",
      input,
      trade: 400n,
      change: 0n,
    });
    const outputs = await recoverFillFromChain(fill, params([input]));
    expect(outputs?.trade.amount).toBe(400n);
    expect(outputs?.change).toBeNull();
    expect(await recoverChangeFromChain(fill, params([input]))).toBeNull();
  });

  it("compares commitments as bytes and canonicalizes hex", async () => {
    const input = await inputNote("buyer");
    const fill = await makeFill({
      side: "buyer",
      input,
      trade: 400n,
      change: 250n,
    });
    fill.inputNoteUseTag = fill.inputNoteUseTag.toUpperCase();
    fill.tradeNoteCommitment = fill.tradeNoteCommitment.toUpperCase();
    fill.changeNoteCommitment = fill.changeNoteCommitment!.toUpperCase();
    const outputs = await recoverFillFromChain(fill, params([input]));
    expect(outputs?.trade.commitment).toBe(fill.tradeNoteCommitment.toLowerCase());
    expect(outputs?.change?.commitment).toBe(
      fill.changeNoteCommitment.toLowerCase(),
    );
  });

  it("recovers an input-derived continuation chain", async () => {
    const initial = await inputNote("seller");
    const firstFill = await makeFill({
      side: "seller",
      input: initial,
      trade: 100n,
      change: 777n,
    });
    const first = await recoverFillFromChain(firstFill, params([initial]));
    const secondFill = await makeFill({
      side: "seller",
      input: first!.change!,
      trade: 50n,
      change: 555n,
    });
    const second = await recoverFillFromChain(
      secondFill,
      params([initial, first!.change!]),
    );
    expect(second?.change?.amount).toBe(555n);
    expect(second?.change?.consumedCommitment).toBe(first!.change!.commitment);
  });

  it("rejects missing inputs, wrong keys, tampering, and tuple mismatches", async () => {
    const input = await inputNote("buyer");
    const fill = await makeFill({
      side: "buyer",
      input,
      trade: 400n,
      change: 250n,
    });
    expect(await recoverFillFromChain(fill, params([]))).toBeNull();

    const stranger = deriveViewingEncKeypair(
      new Uint8Array(64).fill(0x99),
    ).publicKey;
    const wrongKey = await makeFill({
      side: "buyer",
      input,
      trade: 400n,
      change: 250n,
      recipientPub: stranger,
    });
    expect(await recoverFillFromChain(wrongKey, params([input]))).toBeNull();

    const ciphertext = Uint8Array.from(Buffer.from(fill.outputEnc!, "hex"));
    ciphertext[ciphertext.length - 1] ^= 1;
    fill.outputEnc = hex(ciphertext);
    expect(await recoverFillFromChain(fill, params([input]))).toBeNull();

    const inconsistent = await makeFill({
      side: "buyer",
      input,
      trade: 400n,
      change: 0n,
    });
    inconsistent.changeNoteCommitment = "11".repeat(32);
    expect(await recoverFillFromChain(inconsistent, params([input]))).toBeNull();
  });
});
