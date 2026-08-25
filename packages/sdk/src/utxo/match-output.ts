/** Canonical VALID_MATCH_BATCH v3 output-inner derivation. */

import { poseidonHashBytesBE } from "./note.js";

export const DOMAIN_MATCH_OUTPUT_INNER = 24n;
export const DOMAIN_FEE_KEY_BINDING = 35n;
export const DOMAIN_FEE_INNER_V2 = 36n;
export const MATCH_ROLE_TRADE_BUYER = 0xc1;
export const MATCH_ROLE_TRADE_SELLER = 0xd1;
export const MATCH_ROLE_CHANGE_BUYER = 0xb1;
export const MATCH_ROLE_CHANGE_SELLER = 0x5e;
export const MATCH_ROLE_FEE_BASE = 0xfb;
export const MATCH_ROLE_FEE_QUOTE = 0xfc;

function bytesToBigIntBE(value: Uint8Array): bigint {
  if (value.length !== 32) throw new Error("input must be 32 bytes");
  let out = 0n;
  for (const byte of value) out = (out << 8n) | BigInt(byte);
  return out;
}

function requireRole(role: number): bigint {
  if (!Number.isInteger(role) || role < 0 || role > 0xff) {
    throw new Error(`role must be a u8; got ${role}`);
  }
  return BigInt(role);
}

/** `Poseidon3(24, consumed_input_inner, role)`. */
export async function deriveMatchOutputInner(
  inputInner: Uint8Array,
  role: number,
): Promise<Uint8Array> {
  return poseidonHashBytesBE([
    DOMAIN_MATCH_OUTPUT_INNER,
    bytesToBigIntBE(inputInner),
    requireRole(role),
  ]);
}

/** `Poseidon2(35, fee_epoch_key)`. */
export async function deriveFeeKeyBinding(
  feeEpochKey: Uint8Array,
): Promise<Uint8Array> {
  return poseidonHashBytesBE([
    DOMAIN_FEE_KEY_BINDING,
    bytesToBigIntBE(feeEpochKey),
  ]);
}

/** `Poseidon4(36, fee_epoch_key, consumed_use_tag, role)`. */
export async function deriveMatchFeeInner(
  feeEpochKey: Uint8Array,
  consumedUseTag: Uint8Array,
  role: number,
): Promise<Uint8Array> {
  return poseidonHashBytesBE([
    DOMAIN_FEE_INNER_V2,
    bytesToBigIntBE(feeEpochKey),
    bytesToBigIntBE(consumedUseTag),
    requireRole(role),
  ]);
}
