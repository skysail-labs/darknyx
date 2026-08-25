import { poseidonHashBytesBE } from "./note.js";

const MAX_K = 4;
export const DOMAIN_MERGE_INNER_V2 = 34n;

const u8ToBigBE = (value: Uint8Array): bigint => {
  let result = 0n;
  for (const byte of value) result = (result << 8n) | BigInt(byte);
  return result;
};

/** Derive the VALID_MERGE output inner from its private input-inner slots. */
export async function deriveMergeOutputInnerHash(
  inputInners: readonly Uint8Array[],
): Promise<bigint> {
  if (inputInners.length !== 2 && inputInners.length !== 4) {
    throw new Error("merge inners must contain exactly 2 or 4 slots");
  }
  const slots = Array.from({ length: MAX_K }, () => 0n);
  let activeBitmap = 0;
  for (let index = 0; index < inputInners.length; index += 1) {
    const inner = inputInners[index];
    if (inner.length !== 32) {
      throw new Error(`merge inner ${index} must be 32 bytes`);
    }
    const value = u8ToBigBE(inner);
    slots[index] = value;
    if (value !== 0n) activeBitmap |= 1 << index;
  }
  if (activeBitmap === 0) {
    throw new Error("merge must contain at least one active commitment");
  }
  return u8ToBigBE(
    await poseidonHashBytesBE([
      DOMAIN_MERGE_INNER_V2,
      slots[0],
      slots[1],
      slots[2],
      slots[3],
      BigInt(activeBitmap),
    ]),
  );
}
