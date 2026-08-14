export const U64_MAX = (1n << 64n) - 1n;

/** Parse the decimal-string representation used at browser trust boundaries. */
export function canonicalU64(value: unknown, label: string): bigint {
  if (typeof value !== "string" || !/^(0|[1-9]\d*)$/.test(value)) {
    throw new Error(`${label} must be a canonical u64 string`);
  }
  const parsed = BigInt(value);
  if (parsed > U64_MAX) throw new Error(`${label} exceeds u64`);
  return parsed;
}
