/**
 * Recover a v3 change note from the permanent on-chain ciphertext.
 *
 * The ciphertext reveals the private amount only. The output inner is not
 * settlement-id- or anchor-derived: VALID_MATCH_BATCH v3 derives it from the
 * consumed input opening. Recovery therefore tests the caller's known input
 * notes, derives `Poseidon3(24, input_inner, role)`, and accepts only the one
 * whose recomputed commitment equals the on-chain output bytes.
 *
 * The later durable-recovery slice expands the 128-byte envelope to recover
 * trade outputs and seed-plus-chain cold starts. This function already avoids
 * the retired anchor/session assumptions and safely reconstructs change chains
 * when their initial input opening is present locally.
 */

import {
  deriveViewingEncKeypair,
  bn254ToBE32,
} from "../keys/key-generators.js";
import { decryptChangeAmount } from "../keys/fill-encryption.js";
import {
  deriveMatchOutputInner,
  MATCH_ROLE_CHANGE_BUYER,
  MATCH_ROLE_CHANGE_SELLER,
} from "../utxo/match-output.js";
import { noteCommitmentV2 } from "../utxo/note.js";
import type { StoredNote } from "../utxo/note-store.js";
import type { IndexerFill } from "./history.js";

export interface RecoverParams {
  masterSeed: Uint8Array;
  /** Known spendable inputs. Recovery derives candidate v3 outputs from these. */
  candidateInputs: Iterable<StoredNote>;
  /** Buyer change is quote-denominated; seller change is base-denominated. */
  baseMint: Uint8Array;
  quoteMint: Uint8Array;
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

/**
 * Attempt to recover one change note. Returns `null` when the fill is exact,
 * the ciphertext is malformed/not ours, or none of the supplied input notes
 * derives the on-chain commitment.
 */
export async function recoverChangeFromChain(
  fill: IndexerFill,
  params: RecoverParams,
): Promise<StoredNote | null> {
  if (!fill.changeNoteCommitment || !fill.ephemeralPubkey || !fill.changeEnc) {
    return null;
  }

  const ephemeralPubkey = fromHexExact(fill.ephemeralPubkey, 32);
  const changeEnc = fromHexExact(fill.changeEnc, 36);
  const targetBytes = fromHexExact(fill.changeNoteCommitment, 32);
  if (!ephemeralPubkey || !changeEnc || !targetBytes) return null;

  const { secretKey } = deriveViewingEncKeypair(params.masterSeed);
  const amount = decryptChangeAmount(secretKey, ephemeralPubkey, changeEnc);
  if (amount === null) return null;

  const tokenMint = fill.side === "buyer" ? params.quoteMint : params.baseMint;
  const role =
    fill.side === "buyer"
      ? MATCH_ROLE_CHANGE_BUYER
      : MATCH_ROLE_CHANGE_SELLER;

  for (const input of params.candidateInputs) {
    if (!sameBytes(input.tokenMint, tokenMint)) continue;

    const inputBytes = fromHexExact(input.commitment, 32);
    if (!inputBytes) continue;
    const recomputedInput = await noteCommitmentV2({
      tokenMint: input.tokenMint,
      amount: input.amount,
      ownerCommitment: input.ownerCommitment,
      innerHash: input.innerHash,
    });
    if (!sameBytes(recomputedInput, inputBytes)) continue;

    const outputInnerBytes = await deriveMatchOutputInner(
      bn254ToBE32(input.innerHash),
      role,
    );
    const outputInner = be32ToBig(outputInnerBytes);
    const output = await noteCommitmentV2({
      tokenMint,
      amount,
      ownerCommitment: input.ownerCommitment,
      innerHash: outputInner,
    });
    if (!sameBytes(output, targetBytes)) continue;

    return {
      commitment: toHex(output),
      tokenMint,
      amount,
      ownerCommitment: input.ownerCommitment,
      innerHash: outputInner,
      orderId: fill.orderId.toLowerCase(),
      consumedCommitment: toHex(inputBytes),
    };
  }

  return null;
}
