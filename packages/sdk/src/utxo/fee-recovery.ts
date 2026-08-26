/** Fixed-size protocol fee-recovery record carried by MATCH_BATCH Tx B.
 *
 * Byte-identical to `darkpool_crypto::fee_recovery`: XChaCha20-Poly1305 over
 * sixteen `(base_fee, quote_fee)` u64 pairs, with the batch/market/epoch bound
 * as associated data. Clients do not need this primitive; it is exported for
 * the protocol fee collector and cross-language recovery drills.
 */

import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { sha256 } from "@noble/hashes/sha2";
import { hkdfExpand } from "../keys/key-generators.js";

export const FEE_RECOVERY_SLOTS = 16;
export const FEE_RECOVERY_PLAINTEXT_LEN = FEE_RECOVERY_SLOTS * 16;
export const FEE_RECOVERY_CIPHERTEXT_LEN = FEE_RECOVERY_PLAINTEXT_LEN + 16;
export const FEE_RECOVERY_VERSION = 1;

const KEY_INFO = new TextEncoder().encode("darknyx/fee-recovery-aead/v1");
const NONCE_DOMAIN = new TextEncoder().encode("darknyx/fee-recovery-nonce/v1");
const U64_MAX = 0xffff_ffff_ffff_ffffn;

export interface ProtocolFeeAmounts {
  base: bigint;
  quote: bigint;
}

function fixed32(value: Uint8Array, name: string): Uint8Array {
  if (value.length !== 32) throw new Error(`${name} must be 32 bytes`);
  return value;
}

function requireEpoch(epoch: bigint): void {
  if (epoch <= 0n || epoch > U64_MAX) {
    throw new Error("fee recovery epoch must be a nonzero u64");
  }
}

function u64be(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value, false);
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function recoveryKey(epochKey: Uint8Array, epoch: bigint): Uint8Array {
  fixed32(epochKey, "fee epoch key");
  requireEpoch(epoch);
  return hkdfExpand(epochKey, concat(KEY_INFO, u64be(epoch)), 32);
}

function recoveryNonce(batchRoot: Uint8Array, epoch: bigint): Uint8Array {
  // AEAD invariant: a (batchRoot, epoch) tuple is single-use. Settlement
  // retries must reuse the existing ciphertext. Any changed fee amounts require
  // a newly derived batch root before encryption, otherwise the deterministic
  // XChaCha20 nonce would be reused under the same epoch key.
  return sha256
    .create()
    .update(NONCE_DOMAIN)
    .update(fixed32(batchRoot, "batch root"))
    .update(u64be(epoch))
    .digest()
    .slice(0, 24);
}

function recoveryAad(params: {
  batchRoot: Uint8Array;
  market: Uint8Array;
  baseMint: Uint8Array;
  quoteMint: Uint8Array;
  epoch: bigint;
}): Uint8Array {
  return concat(
    new Uint8Array([FEE_RECOVERY_VERSION]),
    fixed32(params.batchRoot, "batch root"),
    fixed32(params.market, "market"),
    fixed32(params.baseMint, "base mint"),
    fixed32(params.quoteMint, "quote mint"),
    u64be(params.epoch),
  );
}

export function encodeProtocolFeeAmounts(
  amounts: readonly ProtocolFeeAmounts[],
): Uint8Array {
  if (amounts.length !== FEE_RECOVERY_SLOTS) {
    throw new Error(`fee recovery requires ${FEE_RECOVERY_SLOTS} slots`);
  }
  const out = new Uint8Array(FEE_RECOVERY_PLAINTEXT_LEN);
  const view = new DataView(out.buffer);
  for (const [index, amount] of amounts.entries()) {
    if (
      amount.base < 0n ||
      amount.base > U64_MAX ||
      amount.quote < 0n ||
      amount.quote > U64_MAX
    ) {
      throw new Error(`fee recovery slot ${index} contains a non-u64 amount`);
    }
    view.setBigUint64(index * 16, amount.base, true);
    view.setBigUint64(index * 16 + 8, amount.quote, true);
  }
  return out;
}

export function decodeProtocolFeeAmounts(
  plaintext: Uint8Array,
): ProtocolFeeAmounts[] {
  if (plaintext.length !== FEE_RECOVERY_PLAINTEXT_LEN) {
    throw new Error(
      `fee recovery plaintext must be ${FEE_RECOVERY_PLAINTEXT_LEN} bytes`,
    );
  }
  const view = new DataView(
    plaintext.buffer,
    plaintext.byteOffset,
    plaintext.byteLength,
  );
  return Array.from({ length: FEE_RECOVERY_SLOTS }, (_, index) => ({
    base: view.getBigUint64(index * 16, true),
    quote: view.getBigUint64(index * 16 + 8, true),
  }));
}

export function encryptProtocolFeeRecovery(params: {
  epochKey: Uint8Array;
  epoch: bigint;
  batchRoot: Uint8Array;
  market: Uint8Array;
  baseMint: Uint8Array;
  quoteMint: Uint8Array;
  amounts: readonly ProtocolFeeAmounts[];
}): Uint8Array {
  const plaintext = encodeProtocolFeeAmounts(params.amounts);
  const sealed = xchacha20poly1305(
    recoveryKey(params.epochKey, params.epoch),
    recoveryNonce(params.batchRoot, params.epoch),
    recoveryAad(params),
  ).encrypt(plaintext);
  if (sealed.length !== FEE_RECOVERY_CIPHERTEXT_LEN) {
    throw new Error("fee recovery cipher returned an unexpected length");
  }
  return sealed;
}

export function decryptProtocolFeeRecovery(params: {
  epochKey: Uint8Array;
  epoch: bigint;
  batchRoot: Uint8Array;
  market: Uint8Array;
  baseMint: Uint8Array;
  quoteMint: Uint8Array;
  ciphertext: Uint8Array;
}): ProtocolFeeAmounts[] {
  if (params.ciphertext.length !== FEE_RECOVERY_CIPHERTEXT_LEN) {
    throw new Error(
      `fee recovery ciphertext must be ${FEE_RECOVERY_CIPHERTEXT_LEN} bytes`,
    );
  }
  const plaintext = xchacha20poly1305(
    recoveryKey(params.epochKey, params.epoch),
    recoveryNonce(params.batchRoot, params.epoch),
    recoveryAad(params),
  ).decrypt(params.ciphertext);
  return decodeProtocolFeeAmounts(plaintext);
}
