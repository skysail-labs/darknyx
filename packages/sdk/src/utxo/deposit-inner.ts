/** Recoverable VALID_DEPOSIT inner-hash derivation. */

import { poseidonHashBytesBE } from "./note.js";

export const DOMAIN_DEPOSIT_INNER = 27n;

function be32ToBigInt(value: Uint8Array, label: string): bigint {
  if (value.length !== 32) throw new Error(`${label} must be 32 bytes`);
  let out = 0n;
  for (const byte of value) out = (out << 8n) | BigInt(byte);
  return out;
}

/** `Poseidon3(27, hidden_owner_commitment, public_recovery_nonce)`. */
export function deriveDepositInnerHash(
  ownerCommitment: Uint8Array,
  recoveryNonce: Uint8Array,
): Promise<Uint8Array> {
  return poseidonHashBytesBE([
    DOMAIN_DEPOSIT_INNER,
    be32ToBigInt(ownerCommitment, "ownerCommitment"),
    be32ToBigInt(recoveryNonce, "recoveryNonce"),
  ]);
}
