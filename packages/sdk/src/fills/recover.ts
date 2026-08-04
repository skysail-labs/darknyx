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
import { deriveNoteUseTag } from "../utxo/note-use.js";
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

/**
 * What chain recovery actually needs from a fill.
 *
 * Deliberately NOT `IndexerFill`: that type additionally requires `signature`
 * and `slot`, which are transaction-identity fields this path never reads. The
 * over-broad parameter meant a fill decoded straight from an instruction (the
 * indexer's `SettleFill`, which has no signature/slot of its own) could not be
 * passed without a cast — even though recovery works on it perfectly. Narrowing
 * to what is used keeps direct-from-chain recovery a first-class caller rather
 * than something that has to lie to the type system.
 */
export type RecoverableFill = Omit<IndexerFill, "signature" | "slot">;

/**
 * Resolve which of the caller's notes a fill consumed.
 *
 * The chain no longer publishes the consumed commitment, so this inverts: for
 * each candidate note the caller already holds, recompute its commitment from
 * the full opening, derive `Poseidon3(29, commitment, inner)`, and compare
 * that to the tag on the fill. Only the note's owner can run this search —
 * which is exactly the unlinkability property, seen from the inside.
 *
 * It is also strictly stronger than the string match it replaces: a candidate
 * matches only if its ENTIRE opening (mint, amount, owner, inner) reproduces
 * the tag, so a note store row with a stale amount can no longer satisfy it.
 *
 * Cost is O(candidates) Poseidon pairs per fill rather than O(1) string
 * compares. The caller passes only its own unspent notes, so the set is small;
 * if it ever is not, the fix is a client-side tag index, not re-publishing the
 * commitment.
 */
async function verifyInput(
  fill: RecoverableFill,
  candidates: Iterable<StoredNote>,
): Promise<{ note: StoredNote; commitment: Uint8Array } | null> {
  const expectedTag = fromHexExact(fill.inputNoteUseTag, 32);
  if (!expectedTag) return null;
  for (const note of candidates) {
    const recomputed = await noteCommitmentV2({
      tokenMint: note.tokenMint,
      amount: note.amount,
      ownerCommitment: note.ownerCommitment,
      innerHash: note.innerHash,
    });
    const tag = await deriveNoteUseTag(recomputed, bn254ToBE32(note.innerHash));
    if (sameBytes(tag, expectedTag)) return { note, commitment: recomputed };
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
  fill: RecoverableFill,
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
