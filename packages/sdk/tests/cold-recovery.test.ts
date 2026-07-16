/** Seed + chain recovery of deposits, settlement outputs, and merges. */

import { createHash } from "node:crypto";
import crypto from "node:crypto";
import nacl from "tweetnacl";
import { PublicKey, type Connection } from "@solana/web3.js";
import { describe, expect, it } from "vitest";
import {
  anchorDiscriminator,
  buildDepositInstruction,
  buildMergeInstruction,
} from "../src/idl/vault-client.js";
import {
  bn254ToBE32,
  deriveBlindingFactor,
  deriveOwnerCommitmentBlinding,
  deriveSpendingKey,
  deriveViewingEncKeypair,
} from "../src/keys/key-generators.js";
import { encryptFillAmounts } from "../src/keys/fill-encryption.js";
import { recoverNotesFromChain } from "../src/fills/cold-recovery.js";
import type { RawSettleTx } from "../src/fills/chain-history.js";
import {
  deriveMatchOutputInner,
  MATCH_ROLE_CHANGE_BUYER,
  MATCH_ROLE_TRADE_BUYER,
} from "../src/utxo/match-output.js";
import { deriveDepositInnerHash } from "../src/utxo/deposit-inner.js";
import { deriveMergeOutputInnerHash } from "../src/utxo/merge.js";
import { noteCommitmentV2, ownerCommitment } from "../src/utxo/note.js";
import {
  exactFillPayload,
  serializePayload,
} from "../src/settlement/settle-builder.js";

const bytes = (length: number, value: number) =>
  new Uint8Array(length).fill(value);
const hex = (value: Uint8Array) => Buffer.from(value).toString("hex");
const SEED = bytes(64, 0x42);
const PROGRAM_ID = new PublicKey(bytes(32, 0x51));
const PAYER = new PublicKey(bytes(32, 0x52));
const BASE_MINT = bytes(32, 0xb1);
const QUOTE_MINT = bytes(32, 0x9e);

function cat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function u64(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value, true);
  return out;
}

function event(name: string, ...body: Uint8Array[]): string {
  const disc = createHash("sha256")
    .update(`event:${name}`)
    .digest()
    .subarray(0, 8);
  return `Program data: ${Buffer.from(cat(disc, ...body)).toString("base64")}`;
}

function noteCreatedLog(opts: {
  treeId: number;
  leaf: bigint;
  commitment: Uint8Array;
  mint: Uint8Array;
  amount: bigint;
}): string {
  return event(
    "NoteCreated",
    new Uint8Array([opts.treeId]),
    u64(opts.leaf),
    opts.commitment,
    opts.mint,
    u64(opts.amount),
    bytes(32, 0),
  );
}

function tradeSettledLog(matchId: Uint8Array): string {
  const none = 0xffff_ffff_ffff_ffffn;
  return event(
    "TradeSettled",
    new Uint8Array([0]),
    matchId,
    u64(10n),
    u64(11n),
    u64(12n),
    u64(none),
    u64(none),
    u64(none),
    new Uint8Array([0, 0]),
    bytes(32, 0),
  );
}

function noteMergedLog(
  commitment: Uint8Array,
  mint: Uint8Array,
): string {
  return event(
    "NoteMerged",
    new Uint8Array([0]),
    commitment,
    mint,
    new Uint8Array([2]),
    u64(20n),
    bytes(32, 0),
  );
}

function be32ToBig(value: Uint8Array): bigint {
  let out = 0n;
  for (const byte of value) out = (out << 8n) | BigInt(byte);
  return out;
}

describe("recoverNotesFromChain", () => {
  it("rebuilds deposit → trade/change → merge without stream state", async () => {
    const owner = await ownerCommitment(
      deriveSpendingKey(SEED),
      deriveOwnerCommitmentBlinding(SEED),
    );
    const ownerBytes = bn254ToBE32(owner);
    const quoteNonce = deriveBlindingFactor(SEED, 0n);
    const baseNonce = deriveBlindingFactor(SEED, 1n);
    const quoteInner = be32ToBig(
      await deriveDepositInnerHash(ownerBytes, bn254ToBE32(quoteNonce)),
    );
    const baseInner = be32ToBig(
      await deriveDepositInnerHash(ownerBytes, bn254ToBE32(baseNonce)),
    );
    const quoteDeposit = await noteCommitmentV2({
      tokenMint: QUOTE_MINT,
      amount: 2_000n,
      ownerCommitment: owner,
      innerHash: quoteInner,
    });
    const baseDeposit = await noteCommitmentV2({
      tokenMint: BASE_MINT,
      amount: 300n,
      ownerCommitment: owner,
      innerHash: baseInner,
    });
    const depositTx = (
      mint: Uint8Array,
      amount: bigint,
      recoveryNonce: bigint,
      commitment: Uint8Array,
      leaf: bigint,
    ): RawSettleTx => ({
      signature: `deposit-${leaf}`,
      slot: Number(leaf + 1n),
      ixDatas: [
        buildDepositInstruction({
          programId: PROGRAM_ID,
          treeId: 0,
          depositor: PAYER,
          tokenMint: new PublicKey(mint),
          depositorTokenAccount: PAYER,
          tokenProgramId: PROGRAM_ID,
          amount,
          noteCommitment: commitment,
          recoveryNonce: bn254ToBE32(recoveryNonce),
          proof: {
            piA: bytes(64, 1),
            piB: bytes(128, 2),
            piC: bytes(64, 3),
          },
        }).data,
      ],
      logMessages: [
        noteCreatedLog({ treeId: 0, leaf, commitment, mint, amount }),
      ],
    });

    const tradeInner = be32ToBig(
      await deriveMatchOutputInner(
        bn254ToBE32(quoteInner),
        MATCH_ROLE_TRADE_BUYER,
      ),
    );
    const changeInner = be32ToBig(
      await deriveMatchOutputInner(
        bn254ToBE32(quoteInner),
        MATCH_ROLE_CHANGE_BUYER,
      ),
    );
    const trade = await noteCommitmentV2({
      tokenMint: BASE_MINT,
      amount: 400n,
      ownerCommitment: owner,
      innerHash: tradeInner,
    });
    const change = await noteCommitmentV2({
      tokenMint: QUOTE_MINT,
      amount: 250n,
      ownerCommitment: owner,
      innerHash: changeInner,
    });
    const viewing = deriveViewingEncKeypair(SEED);
    const ephSecret = crypto.randomBytes(32);
    const recovery = cat(
      nacl.scalarMult.base(ephSecret),
      encryptFillAmounts(
        ephSecret,
        viewing.publicKey,
        { trade: 400n, change: 250n },
        crypto.randomBytes(12),
      ),
      bytes(44, 0),
      new TextEncoder().encode("NYXREC02"),
    );
    const matchId = bytes(16, 0x61);
    const payload = exactFillPayload({
      matchId,
      noteAcommitment: quoteDeposit,
      noteBcommitment: bytes(32, 0x62),
      noteCcommitment: trade,
      noteDcommitment: bytes(32, 0x63),
      orderIdA: bytes(16, 0x64),
      orderIdB: bytes(16, 0x65),
    });
    payload.noteEcommitment = change;
    payload.fillRecovery = recovery;
    const settleTx: RawSettleTx = {
      signature: "settle",
      slot: 3,
      ixDatas: [
        cat(
          anchorDiscriminator("tee_forced_settle_batched"),
          new Uint8Array([0]),
          serializePayload(payload),
          new Uint8Array(129),
        ),
      ],
      logMessages: [tradeSettledLog(matchId)],
    };

    const mergeInputs = [baseDeposit, trade];
    const mergeInner = await deriveMergeOutputInnerHash(mergeInputs);
    const merged = await noteCommitmentV2({
      tokenMint: BASE_MINT,
      amount: 700n,
      ownerCommitment: owner,
      innerHash: mergeInner,
    });
    const mergeTx: RawSettleTx = {
      signature: "merge",
      slot: 4,
      ixDatas: [
        buildMergeInstruction({
          programId: PROGRAM_ID,
          treeId: 0,
          payer: PAYER,
          inputCommitments: mergeInputs,
          outputCommitment: merged,
          tokenMint: new PublicKey(BASE_MINT),
          merkleRoot: bytes(32, 0),
          k: 2,
          proof: {
            piA: bytes(64, 1),
            piB: bytes(128, 2),
            piC: bytes(64, 3),
          },
        }).data,
      ],
      logMessages: [noteMergedLog(merged, BASE_MINT)],
    };

    // Intentionally reverse the scan: the recovery fixed-point must not rely
    // on RPC ordering for dependency chains.
    const scan = async (): Promise<RawSettleTx[]> => [
      mergeTx,
      settleTx,
      depositTx(BASE_MINT, 300n, baseNonce, baseDeposit, 1n),
      depositTx(QUOTE_MINT, 2_000n, quoteNonce, quoteDeposit, 0n),
    ];
    const result = await recoverNotesFromChain({
      connection: undefined as unknown as Connection,
      programId: PROGRAM_ID,
      masterSeed: SEED,
      baseMint: BASE_MINT,
      quoteMint: QUOTE_MINT,
      scan,
    });

    expect(result.recovered).toEqual({
      deposits: 2,
      trade: 1,
      change: 1,
      merges: 1,
    });
    expect(result.unresolvedSettlements).toBe(0);
    expect(result.unresolvedMerges).toBe(0);
    const byCommitment = new Map(result.notes.map((note) => [note.commitment, note]));
    expect(byCommitment.get(hex(trade))?.amount).toBe(400n);
    expect(byCommitment.get(hex(trade))?.leafIndex).toBe(10n);
    expect(byCommitment.get(hex(change))?.leafIndex).toBe(12n);
    expect(byCommitment.get(hex(merged))?.amount).toBe(700n);
    expect(byCommitment.get(hex(merged))?.leafIndex).toBe(20n);
  });

  it("does not claim deposits owned by another seed", async () => {
    const scan = async (): Promise<RawSettleTx[]> => [];
    const result = await recoverNotesFromChain({
      connection: undefined as unknown as Connection,
      programId: PROGRAM_ID,
      masterSeed: bytes(64, 0x99),
      baseMint: BASE_MINT,
      quoteMint: QUOTE_MINT,
      scan,
    });
    expect(result.notes).toEqual([]);
  });
});
