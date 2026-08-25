/**
 * Read the on-chain `VaultConfig.tee_pubkeys` set — the keys the vault accepts
 * settle payloads from — so a client can reconcile the enclave's attested set
 * (quote-bound via `verifyTeeAttestation`) against on-chain governance. A
 * mismatch means the vault trusts a key the enclave doesn't hold (or vice
 * versa) — a settlement-integrity red flag.
 *
 * Fixed-offset parser mirroring `programs/vault/src/state.rs::VaultConfig`
 * (and the TEE-side `crates/darknyx-tee/src/solana_rpc/vault_config.rs`). Layout
 * after the 8-byte discriminator: `admin` (32) then `tee_pubkeys: [Pubkey; 16]`
 * at offset 40; `num_tee_keys: u8` sits at offset 1298. Offsets are pinned by a
 * unit test. Per-market parameters live in the separate `MarketConfig` PDA.
 */

import { sha256 } from "@noble/hashes/sha2";
import { PublicKey } from "@solana/web3.js";

import { AttestationError } from "./verify-core.js";

const DISCRIMINATOR = 8;
const ADMIN_LEN = 32;
/** Offset of `tee_pubkeys: [Pubkey; 16]` (right after the discriminator + admin). */
export const TEE_PUBKEYS_OFFSET = DISCRIMINATOR + ADMIN_LEN; // 40
const PUBKEY_LEN = 32;
const MAX_TEE_KEYS = 16;
/** Offset of `num_tee_keys: u8`. */
export const NUM_TEE_KEYS_OFFSET = 1298;
/** Offset of `num_trees: u8`. */
export const NUM_TREES_OFFSET = 1299;
/** Offset of global `fee_rate_bps: u16` (little-endian). */
export const FEE_KEY_BINDING_OFFSET = 1256;
export const FEE_KEY_EPOCH_OFFSET = 1288;
export const FEE_RATE_BPS_OFFSET = 1296;
export const VAULT_CONFIG_ACCOUNT_LEN = 1304;

const VAULT_CONFIG_DISCRIMINATOR = sha256(
  new TextEncoder().encode("account:VaultConfig"),
).subarray(0, 8);

/** Parse the active `tee_pubkeys` (base58, shard order) from raw account data.
 *  (Derive the account address with `vaultConfigPda` from `idl/vault-client`.) */
export function vaultConfigTeePubkeys(data: Uint8Array): string[] {
  if (data.length !== VAULT_CONFIG_ACCOUNT_LEN) {
    throw new Error(
      `vault_config account length must be ${VAULT_CONFIG_ACCOUNT_LEN}, got ${data.length}`,
    );
  }
  if (
    !data
      .subarray(0, 8)
      .every((value, index) => value === VAULT_CONFIG_DISCRIMINATOR[index])
  ) {
    throw new Error("invalid VaultConfig discriminator");
  }
  const n = data[NUM_TEE_KEYS_OFFSET];
  if (n < 1 || n > MAX_TEE_KEYS) {
    throw new Error(`vault_config num_tee_keys out of range: ${n}`);
  }
  const numTrees = data[NUM_TREES_OFFSET];
  if (numTrees < 1 || numTrees > MAX_TEE_KEYS || n !== numTrees) {
    throw new Error(
      `vault_config signer/tree count mismatch: num_tee_keys=${n}, num_trees=${numTrees}`,
    );
  }
  const out: string[] = [];
  for (let i = 0; i < n; i++) {
    const start = TEE_PUBKEYS_OFFSET + i * PUBKEY_LEN;
    out.push(
      new PublicKey(data.subarray(start, start + PUBKEY_LEN)).toBase58(),
    );
  }
  if (
    out.includes(PublicKey.default.toBase58()) ||
    new Set(out).size !== out.length
  ) {
    throw new Error("vault_config tee_pubkeys are zero or duplicated");
  }
  return out;
}

/** Parse the proof-bound global fee and shard count from finalized governance. */
export function vaultConfigTradingParameters(data: Uint8Array): {
  feeRateBps: number;
  numTrees: number;
  feeKeyBinding: Uint8Array;
  feeKeyEpoch: bigint;
} {
  // Reuse the strict length/discriminator/signer-count validation above.
  vaultConfigTeePubkeys(data);
  const feeRateBps = new DataView(
    data.buffer,
    data.byteOffset,
    data.byteLength,
  ).getUint16(FEE_RATE_BPS_OFFSET, true);
  if (feeRateBps > 10_000)
    throw new Error("vault_config fee rate exceeds 100%");
  const feeKeyBinding = data.slice(FEE_KEY_BINDING_OFFSET, FEE_KEY_BINDING_OFFSET + 32);
  const feeKeyEpoch = new DataView(
    data.buffer,
    data.byteOffset,
    data.byteLength,
  ).getBigUint64(FEE_KEY_EPOCH_OFFSET, true);
  return { feeRateBps, numTrees: data[NUM_TREES_OFFSET], feeKeyBinding, feeKeyEpoch };
}

/**
 * Assert the attested (quote-bound) signer set equals the on-chain governance
 * set (order-independent). Throws {@link AttestationError} (`pubkey_mismatch`)
 * on any difference.
 */
export function assertTeePubkeysMatch(
  attested: string[],
  onchain: string[],
): void {
  const a = [...attested].sort();
  const b = [...onchain].sort();
  const equal = a.length === b.length && a.every((x, i) => x === b[i]);
  if (!equal) {
    throw new AttestationError(
      `attested tee_pubkeys (${attested.length}) != on-chain vault_config.tee_pubkeys (${onchain.length})`,
      "pubkey_mismatch",
    );
  }
}
