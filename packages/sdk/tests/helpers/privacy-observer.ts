import { noteCommitmentV2, poseidonHashBytesBE } from "../../src/utxo/note.js";

const DOMAIN_LEGACY_FEE_INNER = 25n;
const DOMAIN_LEGACY_MERGE_INNER = 26n;
const MAX_DICTIONARY_CANDIDATES = 1_000_000n;

function bigintFromBE(value: Uint8Array): bigint {
  if (value.length !== 32) throw new Error("field value must be 32 bytes");
  let result = 0n;
  for (const byte of value) result = (result << 8n) | BigInt(byte);
  return result;
}

function same(left: Uint8Array, right: Uint8Array): boolean {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

/** Reproduce the retired public-data fee dictionary used by PA-01. */
export async function searchLegacyFeeDictionary(params: {
  inputCommitment: Uint8Array;
  targetFeeCommitment: Uint8Array;
  tokenMint: Uint8Array;
  protocolOwnerCommitment: bigint;
  role: number;
  maxFee: bigint;
}): Promise<bigint | null> {
  if (params.maxFee < 0n || params.maxFee > MAX_DICTIONARY_CANDIDATES) {
    throw new Error(
      `observer dictionary bound must be in [0, ${MAX_DICTIONARY_CANDIDATES}]`,
    );
  }
  const inner = bigintFromBE(
    await poseidonHashBytesBE([
      DOMAIN_LEGACY_FEE_INNER,
      bigintFromBE(params.inputCommitment),
      BigInt(params.role),
    ]),
  );
  for (let amount = 0n; amount <= params.maxFee; amount += 1n) {
    const candidate = await noteCommitmentV2({
      tokenMint: params.tokenMint,
      amount,
      ownerCommitment: params.protocolOwnerCommitment,
      innerHash: inner,
    });
    if (same(candidate, params.targetFeeCommitment)) return amount;
  }
  return null;
}

/** Reproduce the retired commitment-derived merge inner used by PA-02. */
export async function deriveLegacyMergeInner(
  inputCommitments: readonly Uint8Array[],
): Promise<Uint8Array> {
  if (inputCommitments.length !== 2 && inputCommitments.length !== 4) {
    throw new Error("legacy merge requires exactly 2 or 4 input commitments");
  }
  const slots = Array.from({ length: 4 }, () => 0n);
  let activeBitmap = 0;
  for (const [index, commitment] of inputCommitments.entries()) {
    const field = bigintFromBE(commitment);
    slots[index] = field;
    if (field !== 0n) activeBitmap |= 1 << index;
  }
  return poseidonHashBytesBE([
    DOMAIN_LEGACY_MERGE_INNER,
    slots[0],
    slots[1],
    slots[2],
    slots[3],
    BigInt(activeBitmap),
  ]);
}

export function feeDictionaryCeiling(
  publicGrossAmount: bigint,
  feeRateBps: bigint,
): bigint {
  if (publicGrossAmount < 0n || feeRateBps < 0n) {
    throw new Error("fee dictionary inputs must be non-negative");
  }
  return (publicGrossAmount * feeRateBps) / 10_000n;
}
