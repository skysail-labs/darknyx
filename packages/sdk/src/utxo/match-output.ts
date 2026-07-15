/** Canonical VALID_MATCH_BATCH v3 output-inner derivation. */

import { poseidonHashBytesBE } from "./note.js";

export const DOMAIN_MATCH_OUTPUT_INNER = 24n;
export const DOMAIN_MATCH_FEE_INNER = 25n;
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

/** `Poseidon3(25, consumed_input_commitment, role)`. */
export async function deriveMatchFeeInner(
  inputCommitment: Uint8Array,
  role: number,
): Promise<Uint8Array> {
  return poseidonHashBytesBE([
    DOMAIN_MATCH_FEE_INNER,
    bytesToBigIntBE(inputCommitment),
    requireRole(role),
  ]);
}
