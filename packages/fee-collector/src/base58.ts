const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const MAP = new Map(Array.from(ALPHABET, (char, index) => [char, index]));

/** Minimal strict base58 decoder for Helius' raw instruction `data` field. */
export function base58Decode(value: string): Uint8Array {
  if (value.length === 0) return new Uint8Array();
  const bytes: number[] = [0];
  for (const char of value) {
    const digit = MAP.get(char);
    if (digit === undefined) throw new Error("invalid base58 instruction data");
    let carry = digit;
    for (let index = 0; index < bytes.length; index += 1) {
      const next = bytes[index] * 58 + carry;
      bytes[index] = next & 0xff;
      carry = next >> 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  let leading = 0;
  while (leading < value.length - 1 && value[leading] === "1") leading += 1;
  const out = new Uint8Array(leading + bytes.length);
  for (let index = 0; index < bytes.length; index += 1) {
    out[out.length - 1 - index] = bytes[index];
  }
  return out;
}
