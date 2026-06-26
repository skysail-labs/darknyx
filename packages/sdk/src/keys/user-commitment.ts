/**
 * User Commitment (a.k.a. Wallet Commitment).
 *
 * Mirror of `crates/darkpool-crypto/src/user_commitment.rs`. Must produce
 * byte-identical output to both the Rust helper and the circom
 * `valid_wallet_create` circuit.
 *
 * Formula (must match circuits/valid_wallet_create/circuit.circom):
 *   Domain tags prevent cross-role second-preimage collisions:
 *   DOMAIN_ROOT=10, DOMAIN_SPEND=11, DOMAIN_VIEW=12, DOMAIN_LEAF=13, DOMAIN_TOP=14
 *
 *   rootHash    = Poseidon4(DOMAIN_ROOT,  root_lo, root_hi, r0)
 *   spendHash   = Poseidon3(DOMAIN_SPEND, spending_key, r1)
 *   viewHash    = Poseidon3(DOMAIN_VIEW,  viewing_key,  r2)
 *   leafPair    = Poseidon3(DOMAIN_LEAF,  rootHash, spendHash)
 *   commitment  = Poseidon3(DOMAIN_TOP,   leafPair, viewHash)
 */

import { buildPoseidon } from "circomlibjs";
import { pubkeyToFrPair } from "../utxo/note.js";
import { bn254ToBE32 } from "./key-generators.js";

type PoseidonFn = ((inputs: bigint[]) => Uint8Array) & {
  F: { toObject: (x: Uint8Array) => bigint };
};

let cached: PoseidonFn | null = null;
async function getPoseidon(): Promise<PoseidonFn> {
  if (cached) return cached;
  const p = await buildPoseidon();
  const fn = ((inputs: bigint[]) =>
    p(inputs.map((i) => p.F.e(i)))) as PoseidonFn;
  fn.F = p.F;
  cached = fn;
  return fn;
}

export interface UserCommitmentInputs {
  /** Ed25519 pubkey bytes of the Root / Vault Key (32 bytes). */
  rootKeyPubkey: Uint8Array;
  /** Shielded Spending Key as a BN254 scalar. */
  spendingKey: bigint;
  /** Master Viewing Key as a BN254 scalar. */
  viewingKey: bigint;
  /** Per-leaf blinding factors r0, r1, r2 (independent BN254 scalars). */
  r0: bigint;
  r1: bigint;
  r2: bigint;
}

/**
 * Compute the 32-byte User Commitment (big-endian).
 *
 * Note the type signature: there is *no* `tradingKey` field. This matches the
 * Rust struct and structurally guarantees
 * `test_commitment_excludes_trading_key` — you cannot accidentally include the
 * trading key in the commitment.
 */
// Domain tags — must match circuits/valid_wallet_create/circuit.circom
// and crates/darkpool-crypto/src/user_commitment.rs exactly.
const DOMAIN_ROOT = 10n;
const DOMAIN_SPEND = 11n;
const DOMAIN_VIEW = 12n;
const DOMAIN_LEAF = 13n;
const DOMAIN_TOP = 14n;

export async function userCommitmentFromKeys(
  inputs: UserCommitmentInputs,
): Promise<Uint8Array> {
  if (inputs.rootKeyPubkey.length !== 32) {
    throw new Error("rootKeyPubkey must be 32 bytes");
  }
  const [rootLo, rootHi] = pubkeyToFrPair(inputs.rootKeyPubkey);
  const p = await getPoseidon();

  const rootHash = p.F.toObject(p([DOMAIN_ROOT, rootLo, rootHi, inputs.r0]));
  const spendHash = p.F.toObject(
    p([DOMAIN_SPEND, inputs.spendingKey, inputs.r1]),
  );
  const viewHash = p.F.toObject(p([DOMAIN_VIEW, inputs.viewingKey, inputs.r2]));
  const leafPair = p.F.toObject(p([DOMAIN_LEAF, rootHash, spendHash]));
  const commitment = p.F.toObject(p([DOMAIN_TOP, leafPair, viewHash]));
  return bn254ToBE32(commitment);
}
