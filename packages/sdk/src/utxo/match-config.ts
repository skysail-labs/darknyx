/** Canonical governed-config digest for VALID_MATCH_BATCH. */

import { poseidonHashBytesBE, pubkeyToFrPair } from "./note.js";

export const DOMAIN_MATCH_CONFIG = 28n;
const MAX_U64 = (1n << 64n) - 1n;
const BN254_SCALAR_MODULUS = BigInt(
  "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
);

function bytesToCanonicalFr(value: Uint8Array, label: string): bigint {
  if (value.length !== 32) throw new Error(`${label} must be 32 bytes`);
  let out = 0n;
  for (const byte of value) out = (out << 8n) | BigInt(byte);
  if (out >= BN254_SCALAR_MODULUS) {
    throw new Error(`${label} is not a canonical BN254 scalar`);
  }
  return out;
}

function requireU64(value: bigint, label: string): bigint {
  if (value < 0n || value > MAX_U64) throw new Error(`${label} must be a u64`);
  return value;
}

export interface MatchConfigDigestFields {
  feeRateBps: bigint;
  protocolOwnerCommitment: Uint8Array;
  baseMint: Uint8Array;
  quoteMint: Uint8Array;
  priceScale: bigint;
}

/**
 * `Poseidon8(28, fee_rate_bps, protocol_owner, base_lo, base_hi,
 * quote_lo, quote_hi, price_scale)`.
 */
export async function matchConfigDigest(
  fields: MatchConfigDigestFields,
): Promise<Uint8Array> {
  const [baseLo, baseHi] = pubkeyToFrPair(fields.baseMint);
  const [quoteLo, quoteHi] = pubkeyToFrPair(fields.quoteMint);
  return poseidonHashBytesBE([
    DOMAIN_MATCH_CONFIG,
    requireU64(fields.feeRateBps, "feeRateBps"),
    bytesToCanonicalFr(
      fields.protocolOwnerCommitment,
      "protocolOwnerCommitment",
    ),
    baseLo,
    baseHi,
    quoteLo,
    quoteHi,
    requireU64(fields.priceScale, "priceScale"),
  ]);
}
