/** Cross-package recovery v3: settle encode → indexer decode → SDK recover. */

import { describe, it, expect } from "vitest";
import crypto from "node:crypto";
import nacl from "tweetnacl";
import {
  deriveViewingEncKeypair,
  bn254ToBE32,
} from "../../sdk/src/keys/key-generators.js";
import { encryptFillAmounts } from "../../sdk/src/keys/fill-encryption.js";
import {
  deriveMatchOutputInner,
  MATCH_ROLE_CHANGE_BUYER,
  MATCH_ROLE_TRADE_BUYER,
} from "../../sdk/src/utxo/match-output.js";
import { noteCommitmentV2 } from "../../sdk/src/utxo/note.js";
import type { StoredNote } from "../../sdk/src/utxo/note-store.js";
import {
  exactFillPayload,
  serializePayload,
} from "../../sdk/src/settlement/settle-builder.js";
import { recoverFillFromChain } from "../../sdk/src/fills/recover.js";
import { decodeSettleIxData, SETTLE_DISCRIMINATOR } from "../src/decode.js";

const fill = (n: number, value: number) => new Uint8Array(n).fill(value);
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const SEED = fill(64, 0x42);
const VIEWING = deriveViewingEncKeypair(SEED);
const OWNER = 0x1234_5678n;
const QUOTE_MINT = fill(32, 0x9e);
const BASE_MINT = fill(32, 0xb1);

function be32ToBig(bytes: Uint8Array): bigint {
  let out = 0n;
  for (const byte of bytes) out = (out << 8n) | BigInt(byte);
  return out;
}

function cat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

async function output(
  input: StoredNote,
  mint: Uint8Array,
  amount: bigint,
  role: number,
): Promise<Uint8Array> {
  const innerHash = be32ToBig(
    await deriveMatchOutputInner(bn254ToBE32(input.innerHash), role),
  );
  return noteCommitmentV2({
    tokenMint: mint,
    amount,
    ownerCommitment: OWNER,
    innerHash,
  });
}

describe("recovery v3 cross-package e2e", () => {
  it("recovers trade and change from the indexer's opaque row", async () => {
    const inputCommitment = await noteCommitmentV2({
      tokenMint: QUOTE_MINT,
      amount: 2_000n,
      ownerCommitment: OWNER,
      innerHash: 0x1234n,
    });
    const input: StoredNote = {
      commitment: hex(inputCommitment),
      tokenMint: QUOTE_MINT,
      amount: 2_000n,
      ownerCommitment: OWNER,
      innerHash: 0x1234n,
      leafIndex: 0n,
      treeId: 0,
    };
    const trade = await output(input, BASE_MINT, 400n, MATCH_ROLE_TRADE_BUYER);
    const change = await output(
      input,
      QUOTE_MINT,
      250n,
      MATCH_ROLE_CHANGE_BUYER,
    );
    const ephSecret = crypto.randomBytes(32);
    const ephPub = nacl.scalarMult.base(ephSecret);
    const buyerEnc = encryptFillAmounts(
      ephSecret,
      VIEWING.publicKey,
      { trade: 400n, change: 250n },
      crypto.randomBytes(12),
    );
    const recovery = cat(
      ephPub,
      buyerEnc,
      fill(44, 0),
      new TextEncoder().encode("DNYXREC3"),
    );
    const payload = exactFillPayload({
      matchId: fill(16, 0x11),
      noteAcommitment: inputCommitment,
      noteBcommitment: fill(32, 0x12),
      noteCcommitment: trade,
      noteDcommitment: fill(32, 0x13),
      orderIdA: fill(16, 0xaa),
      orderIdB: fill(16, 0xbb),
    });
    payload.noteEcommitment = change;
    payload.fillRecovery = recovery;
    const body = serializePayload(payload);
    const ix = cat(
      SETTLE_DISCRIMINATOR,
      new Uint8Array([0]),
      body,
      new Uint8Array(129),
    );

    const buyer = decodeSettleIxData(ix)!.find((row) => row.side === "buyer")!;
    expect(buyer.inputNoteCommitment).toBe(hex(inputCommitment));
    expect(buyer.tradeNoteCommitment).toBe(hex(trade));
    expect(buyer.outputEnc).toBe(hex(buyerEnc));

    const recovered = await recoverFillFromChain(buyer, {
      masterSeed: SEED,
      candidateInputs: [input],
      baseMint: BASE_MINT,
      quoteMint: QUOTE_MINT,
    });
    expect(recovered?.trade.amount).toBe(400n);
    expect(recovered?.trade.commitment).toBe(hex(trade));
    expect(recovered?.change?.amount).toBe(250n);
    expect(recovered?.change?.commitment).toBe(hex(change));
  });

  it("rejects a legacy recovery layout without the v2 trailer", () => {
    const payload = exactFillPayload({
      matchId: fill(16, 1),
      noteAcommitment: fill(32, 2),
      noteBcommitment: fill(32, 3),
      noteCcommitment: fill(32, 4),
      noteDcommitment: fill(32, 5),
      orderIdA: fill(16, 6),
      orderIdB: fill(16, 7),
    });
    payload.fillRecovery = cat(fill(32, 1), fill(36, 2), fill(36, 3), fill(24, 0));
    const ix = cat(
      SETTLE_DISCRIMINATOR,
      new Uint8Array([0]),
      serializePayload(payload),
      new Uint8Array(129),
    );
    const rows = decodeSettleIxData(ix)!;
    expect(rows[0].ephemeralPubkey).toBeNull();
    expect(rows[0].outputEnc).toBeNull();
  });
});
