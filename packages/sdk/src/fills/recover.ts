/**
 * Recover both user-owned outputs of a VALID_MATCH_BATCH v3 fill from the
 * permanent on-chain recovery-v3 ciphertext.
 *
 * The payload names the exact consumed commitment and the trade/change output
 * commitments. After decrypting `(trade, change)`, the client resolves that
 * consumed opening, derives each output inner as
 * `Poseidon3(24, input_inner, role)`, and accepts an output only when its
 * recomputed commitment equals the chain bytes. This supports exact fills and
 * cold continuation chains without live stream history.
 */

import {
  deriveViewingEncKeypair,
  bn254ToBE32,
} from "../keys/key-generators.js";
import { decryptFillAmounts } from "../keys/fill-encryption.js";
import {
  deriveMatchOutputInner,
  MATCH_ROLE_CHANGE_BUYER,
  MATCH_ROLE_CHANGE_SELLER,
  MATCH_ROLE_TRADE_BUYER,
  MATCH_ROLE_TRADE_SELLER,
} from "../utxo/match-output.js";
import { noteCommitmentV2 } from "../utxo/note.js";
import type { StoredNote } from "../utxo/note-store.js";
import type { IndexerFill } from "./history.js";

export interface RecoverParams {
  masterSeed: Uint8Array;
  /** Recovered/local openings. The payload selects one by exact commitment. */
  candidateInputs: Iterable<StoredNote>;
  baseMint: Uint8Array;
  quoteMint: Uint8Array;
}

export interface RecoveredFillOutputs {
  trade: StoredNote;
  change: StoredNote | null;
}

const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");

function fromHexExact(value: string, bytes: number): Uint8Array | null {
  if (value.length !== bytes * 2 || !/^[0-9a-fA-F]+$/.test(value)) {
    return null;
  }
  return Uint8Array.from(Buffer.from(value, "hex"));
}

function be32ToBig(b: Uint8Array): bigint {
  let n = 0n;
  for (const x of b) n = (n << 8n) | BigInt(x);
  return n;
}

const sameBytes = (a: Uint8Array, b: Uint8Array): boolean =>
  Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;

function optionalLeafIndex(value: string | null | undefined): bigint | undefined {
  if (value === null || value === undefined || !/^\d+$/.test(value)) return undefined;
  return BigInt(value);
}

async function verifyInput(
  fill: IndexerFill,
  candidates: Iterable<StoredNote>,
): Promise<{ note: StoredNote; commitment: Uint8Array } | null> {
  const expected = fromHexExact(fill.inputNoteCommitment, 32);
  if (!expected) return null;
  const expectedHex = toHex(expected);
  for (const note of candidates) {
    if (note.commitment.toLowerCase() !== expectedHex) continue;
    const recomputed = await noteCommitmentV2({
      tokenMint: note.tokenMint,
      amount: note.amount,
      ownerCommitment: note.ownerCommitment,
      innerHash: note.innerHash,
    });
    if (sameBytes(recomputed, expected)) return { note, commitment: expected };
  }
  return null;
}

async function recoverOutput(opts: {
  input: StoredNote;
  inputCommitment: Uint8Array;
  orderId: string;
  targetHex: string;
  tokenMint: Uint8Array;
  amount: bigint;
  role: number;
  leafIndex?: bigint;
}): Promise<StoredNote | null> {
  const target = fromHexExact(opts.targetHex, 32);
  if (!target) return null;
  const innerBytes = await deriveMatchOutputInner(
    bn254ToBE32(opts.input.innerHash),
    opts.role,
  );
  const innerHash = be32ToBig(innerBytes);
  const commitment = await noteCommitmentV2({
    tokenMint: opts.tokenMint,
    amount: opts.amount,
    ownerCommitment: opts.input.ownerCommitment,
    innerHash,
  });
  if (!sameBytes(commitment, target)) return null;
  return {
    commitment: toHex(commitment),
    tokenMint: opts.tokenMint,
    amount: opts.amount,
    ownerCommitment: opts.input.ownerCommitment,
    innerHash,
    leafIndex: opts.leafIndex,
    orderId: opts.orderId.toLowerCase(),
    consumedCommitment: toHex(opts.inputCommitment),
  };
}

/** Recover and self-verify the trade note plus optional continuation note. */
export async function recoverFillFromChain(
  fill: IndexerFill,
  params: RecoverParams,
): Promise<RecoveredFillOutputs | null> {
  if (!fill.ephemeralPubkey || !fill.outputEnc) return null;
  const ephemeralPubkey = fromHexExact(fill.ephemeralPubkey, 32);
  const outputEnc = fromHexExact(fill.outputEnc, 44);
  if (!ephemeralPubkey || !outputEnc) return null;

  const resolved = await verifyInput(fill, params.candidateInputs);
  if (!resolved) return null;
  const expectedInputMint =
    fill.side === "buyer" ? params.quoteMint : params.baseMint;
  if (!sameBytes(resolved.note.tokenMint, expectedInputMint)) return null;

  const { secretKey } = deriveViewingEncKeypair(params.masterSeed);
  const amounts = decryptFillAmounts(secretKey, ephemeralPubkey, outputEnc);
  if (!amounts || amounts.trade === 0n) return null;

  const trade = await recoverOutput({
    input: resolved.note,
    inputCommitment: resolved.commitment,
    orderId: fill.orderId,
    targetHex: fill.tradeNoteCommitment,
    tokenMint: fill.side === "buyer" ? params.baseMint : params.quoteMint,
    amount: amounts.trade,
    role:
      fill.side === "buyer"
        ? MATCH_ROLE_TRADE_BUYER
        : MATCH_ROLE_TRADE_SELLER,
    leafIndex: optionalLeafIndex(fill.tradeLeafIndex),
  });
  if (!trade) return null;

  if (amounts.change === 0n) {
    if (fill.changeNoteCommitment !== null) return null;
    return { trade, change: null };
  }
  if (!fill.changeNoteCommitment) return null;
  const change = await recoverOutput({
    input: resolved.note,
    inputCommitment: resolved.commitment,
    orderId: fill.orderId,
    targetHex: fill.changeNoteCommitment,
    tokenMint: expectedInputMint,
    amount: amounts.change,
    role:
      fill.side === "buyer"
        ? MATCH_ROLE_CHANGE_BUYER
        : MATCH_ROLE_CHANGE_SELLER,
    leafIndex: optionalLeafIndex(fill.changeLeafIndex),
  });
  return change ? { trade, change } : null;
}

/** Compatibility convenience for callers interested only in continuations.
 * Exact fills intentionally return `null`; use `recoverFillFromChain` to obtain
 * their trade note. */
export async function recoverChangeFromChain(
  fill: IndexerFill,
  params: RecoverParams,
): Promise<StoredNote | null> {
  return (await recoverFillFromChain(fill, params))?.change ?? null;
}
