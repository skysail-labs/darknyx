/** Recoverable VALID_DEPOSIT inner-hash derivation. */

import { poseidonHashBytesBE } from "./note.js";

export const DOMAIN_DEPOSIT_INNER_V2 = 33n;

function be32ToBigInt(value: Uint8Array, label: string): bigint {
  if (value.length !== 32) throw new Error(`${label} must be 32 bytes`);
  let out = 0n;
  for (const byte of value) out = (out << 8n) | BigInt(byte);
  return out;
}

/**
 * `Poseidon3(33, public_recovery_nonce, note_secret)`.
 *
 * The fourth input is what keeps the inner — and therefore the public note-use
 * tag derived from it — from being a function of on-chain data plus one
 * wallet-wide value. `recovery_nonce` is a public deposit instruction argument
 * and `owner_commitment` is reused across every note a user holds, so under the
 * old 3-input form anyone who learned that one value could recompute every tag
 * the user ever produced, retroactively.
 *
 * `noteSecret` comes from {@link deriveNoteSecret} and never leaves the client.
 * Recovery is unaffected: it is a pure function of the master seed and the
 * public nonce.
 *
 * The domain tag stays 27 while the arity moves 3 -> 4, which is safe because
 * Poseidon is a different permutation per arity.
 */
export function deriveDepositInnerHash(
  recoveryNonce: Uint8Array,
  noteSecret: Uint8Array,
): Promise<Uint8Array> {
  return poseidonHashBytesBE([
    DOMAIN_DEPOSIT_INNER_V2,
    be32ToBigInt(recoveryNonce, "recoveryNonce"),
    be32ToBigInt(noteSecret, "noteSecret"),
  ]);
}
