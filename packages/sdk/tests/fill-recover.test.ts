/** Durable change-amount recovery under consumed-input-derived v3 outputs. */

import { describe, it, expect } from "vitest";
import crypto from "node:crypto";
import nacl from "tweetnacl";
import {
  deriveViewingEncKeypair,
  bn254ToBE32,
} from "../src/keys/key-generators.js";
import { encryptChangeAmount } from "../src/keys/fill-encryption.js";
import {
  deriveMatchOutputInner,
  MATCH_ROLE_CHANGE_BUYER,
  MATCH_ROLE_CHANGE_SELLER,
} from "../src/utxo/match-output.js";
import { noteCommitmentV2 } from "../src/utxo/note.js";
import { recoverChangeFromChain } from "../src/fills/recover.js";
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
  };
}

async function makeFill(opts: {
  side: "buyer" | "seller";
  input: StoredNote;
  amount: bigint;
  recipientPub?: Uint8Array;
}): Promise<IndexerFill> {
  const tokenMint = opts.side === "buyer" ? QUOTE_MINT : BASE_MINT;
  const role =
    opts.side === "buyer"
      ? MATCH_ROLE_CHANGE_BUYER
      : MATCH_ROLE_CHANGE_SELLER;
  const innerHash = be32ToBig(
    await deriveMatchOutputInner(bn254ToBE32(opts.input.innerHash), role),
  );
  const commitment = await noteCommitmentV2({
    tokenMint,
    amount: opts.amount,
    ownerCommitment: opts.input.ownerCommitment,
    innerHash,
  });
  const recipient =
    opts.recipientPub ?? deriveViewingEncKeypair(SEED).publicKey;
  const ephSecret = crypto.randomBytes(32);
  const ephPub = nacl.scalarMult.base(ephSecret);
  const nonce = crypto.randomBytes(12);
  const changeEnc = encryptChangeAmount(
    ephSecret,
    recipient,
    opts.amount,
    nonce,
  );
  return {
    orderId: hex(ORDER_ID),
    side: opts.side,
    matchId: "55".repeat(16),
    signature: "00",
    isPartialFill: true,
    changeNoteCommitment: hex(commitment),
    batchSlot: "1",
    ephemeralPubkey: hex(ephPub),
    changeEnc: hex(changeEnc),
  };
}

const params = (candidateInputs: StoredNote[]) => ({
  masterSeed: SEED,
  candidateInputs,
  baseMint: BASE_MINT,
  quoteMint: QUOTE_MINT,
});

describe("recoverChangeFromChain v3", () => {
  it("recovers buyer and seller change from their consumed openings", async () => {
    for (const side of ["buyer", "seller"] as const) {
      const input = await inputNote(side);
      const fill = await makeFill({ side, input, amount: 250n });
      const note = await recoverChangeFromChain(fill, params([input]));
      expect(note).not.toBeNull();
      expect(note!.amount).toBe(250n);
      expect(note!.commitment).toBe(fill.changeNoteCommitment);
      expect(note!.consumedCommitment).toBe(input.commitment);
      expect(hex(note!.tokenMint)).toBe(
        hex(side === "buyer" ? QUOTE_MINT : BASE_MINT),
      );
    }
  });

  it("compares output commitments as bytes and canonicalizes hex", async () => {
    const input = await inputNote("buyer");
    const fill = await makeFill({ side: "buyer", input, amount: 250n });
    const canonical = fill.changeNoteCommitment!;
    fill.changeNoteCommitment = canonical.toUpperCase();

    const note = await recoverChangeFromChain(fill, params([input]));
    expect(note?.commitment).toBe(canonical);
  });

  it("recovers an input-derived continuation chain without settlement ids", async () => {
    const firstInput = await inputNote("seller");
    const firstFill = await makeFill({
      side: "seller",
      input: firstInput,
      amount: 777n,
    });
    const first = await recoverChangeFromChain(
      firstFill,
      params([firstInput]),
    );
    expect(first).not.toBeNull();

    const secondFill = await makeFill({
      side: "seller",
      input: first!,
      amount: 555n,
    });
    const second = await recoverChangeFromChain(
      secondFill,
      params([firstInput, first!]),
    );
    expect(second?.amount).toBe(555n);
    expect(second?.consumedCommitment).toBe(first!.commitment);
  });

  it("returns null without the consumed input opening", async () => {
    const input = await inputNote("buyer");
    const unrelated = await inputNote("buyer", 0x9999n);
    const fill = await makeFill({ side: "buyer", input, amount: 250n });
    expect(await recoverChangeFromChain(fill, params([unrelated]))).toBeNull();
  });

  it("returns null for a wrong viewing key", async () => {
    const input = await inputNote("buyer");
    const stranger = deriveViewingEncKeypair(
      new Uint8Array(64).fill(0x99),
    ).publicKey;
    const fill = await makeFill({
      side: "buyer",
      input,
      amount: 250n,
      recipientPub: stranger,
    });
    expect(await recoverChangeFromChain(fill, params([input]))).toBeNull();
  });

  it("returns null for ciphertext or commitment tampering", async () => {
    const input = await inputNote("buyer");
    const ciphertextFill = await makeFill({
      side: "buyer",
      input,
      amount: 250n,
    });
    const bytes = Uint8Array.from(
      Buffer.from(ciphertextFill.changeEnc!, "hex"),
    );
    bytes[bytes.length - 1] ^= 0x01;
    ciphertextFill.changeEnc = hex(bytes);
    expect(
      await recoverChangeFromChain(ciphertextFill, params([input])),
    ).toBeNull();

    const commitmentFill = await makeFill({
      side: "buyer",
      input,
      amount: 250n,
    });
    commitmentFill.changeNoteCommitment = "11".repeat(32);
    expect(
      await recoverChangeFromChain(commitmentFill, params([input])),
    ).toBeNull();
  });

  it("returns null for an exact fill", async () => {
    const exact: IndexerFill = {
      orderId: hex(ORDER_ID),
      side: "buyer",
      matchId: "00".repeat(16),
      signature: "00",
      isPartialFill: false,
      changeNoteCommitment: null,
      batchSlot: "1",
      ephemeralPubkey: null,
      changeEnc: null,
    };
    expect(await recoverChangeFromChain(exact, params([]))).toBeNull();
  });
});
