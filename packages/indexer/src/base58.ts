/**
 * Minimal base58 (Bitcoin alphabet) encode/decode — the indexer only needs to
 * turn a gTFA instruction's `data` string into bytes (decode) and, in tests,
 * the reverse (encode). Avoids pulling a `bs58` dependency for ~30 lines.
 */

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE = ALPHABET.length;
const MAP: Int8Array = (() => {
  const m = new Int8Array(128).fill(-1);
  for (let i = 0; i < ALPHABET.length; i++) m[ALPHABET.charCodeAt(i)] = i;
  return m;
})();

/** Decode a base58 string to bytes. Throws on an invalid character. */
export function base58Decode(s: string): Uint8Array {
  if (s.length === 0) return new Uint8Array(0);
  const bytes: number[] = [];
  for (const ch of s) {
    const code = ch.charCodeAt(0);
    const val = code < 128 ? MAP[code] : -1;
    if (val < 0) throw new Error(`invalid base58 character '${ch}'`);
    let carry = val;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * BASE;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  // Each leading '1' is a leading zero byte.
  for (let k = 0; k < s.length && s[k] === "1"; k++) bytes.push(0);
  return new Uint8Array(bytes.reverse());
}

/** Encode bytes to a base58 string. (Used by tests to build fixtures.) */
export function base58Encode(bytes: Uint8Array): string {
  if (bytes.length === 0) return "";
  const digits: number[] = [];
  for (const byte of bytes) {
    let carry = byte;
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % BASE;
      carry = (carry / BASE) | 0;
    }
    while (carry > 0) {
      digits.push(carry % BASE);
      carry = (carry / BASE) | 0;
    }
  }
  let out = "";
  for (let k = 0; k < bytes.length && bytes[k] === 0; k++) out += "1";
  for (let q = digits.length - 1; q >= 0; q--) out += ALPHABET[digits[q]];
  return out;
}
