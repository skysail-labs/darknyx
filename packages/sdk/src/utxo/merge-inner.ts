import { poseidonHashBytesBE } from "./note.js";

const MAX_K = 4;
const DOMAIN_MERGE_INNER = 26n;

const u8ToBigBE = (value: Uint8Array): bigint => {
  let result = 0n;
  for (const byte of value) result = (result << 8n) | BigInt(byte);
  return result;
};

/** Derive the VALID_MERGE output inner from its private commitment slots. */
export async function deriveMergeOutputInnerHash(
  inputCommitments: readonly Uint8Array[],
): Promise<bigint> {
  if (inputCommitments.length !== 2 && inputCommitments.length !== 4) {
    throw new Error("merge commitments must contain exactly 2 or 4 slots");
  }
  const slots = Array.from({ length: MAX_K }, () => 0n);
  let activeBitmap = 0;
  for (let index = 0; index < inputCommitments.length; index += 1) {
    const commitment = inputCommitments[index];
    if (commitment.length !== 32) {
      throw new Error(`merge commitment ${index} must be 32 bytes`);
    }
    const value = u8ToBigBE(commitment);
    slots[index] = value;
    if (value !== 0n) activeBitmap |= 1 << index;
  }
  if (activeBitmap === 0) {
    throw new Error("merge must contain at least one active commitment");
  }
  return u8ToBigBE(
    await poseidonHashBytesBE([
      DOMAIN_MERGE_INNER,
      slots[0],
      slots[1],
      slots[2],
      slots[3],
      BigInt(activeBitmap),
    ]),
  );
}
