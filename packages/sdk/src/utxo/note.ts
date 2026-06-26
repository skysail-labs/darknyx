/**
 * UTXO note construction + commitment.
 *
 * Must produce byte-identical Poseidon output to:
 *   - crates/darkpool-crypto (Rust, via light-poseidon)
 *   - circuits/valid_spend/circuit.circom (circom, via circomlib's poseidon)
 *
 * We use circomlibjs — the JavaScript counterpart of circomlib — which the
 * snarkjs/circom stack uses internally. It is byte-compatible with light-poseidon
 * when both are run with BN254 + CIRCOM parameters.
 *
 * Domain tags (must match circuit.circom and crates/darkpool-crypto exactly):
 *   DOMAIN_OWNER = 1n  — owner_commitment = Poseidon3(1, spendingKey, r_owner)
 *   DOMAIN_NOTE  = 2n  — noteCommitment   = Poseidon7(2, mint_lo, mint_hi, amount, owner, nonce, r)
 *   DOMAIN_NULL  = 3n  — nullifier        = Poseidon3(3, spendingKey, noteCommitment)
 *
 * v2 (inner_hash) construction — collapses (nonce, r) into a single inner_hash
 * and re-anchors the nullifier on inner_hash (amount-independent, so a client
 * can pre-supply change-note nullifiers). Mint binding kept:
 *   noteCommitmentV2 = Poseidon6(2, mint_lo, mint_hi, amount, owner, inner_hash)
 *   nullifierV2      = Poseidon3(3, spendingKey, inner_hash)
 */

import { buildPoseidon } from "circomlibjs";
import { bn254ToBE32 } from "../keys/key-generators.js";

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

/** Hash an array of field elements (each in [0, BN254_r)) -> 32-byte BE result. */
export async function poseidonHashBytesBE(
  inputs: bigint[],
): Promise<Uint8Array> {
  const p = await getPoseidon();
  const packed = p(inputs);
  // circomlibjs returns a Montgomery-form Uint8Array. Convert to canonical bigint.
  const out = p.F.toObject(packed);
  return bn254ToBE32(out);
}

/** Split a 32-byte Solana pubkey into [lo_u128, hi_u128] bigints. */
export function pubkeyToFrPair(pk: Uint8Array): [bigint, bigint] {
  if (pk.length !== 32) throw new Error("pubkey must be 32 bytes");
  let hi = 0n;
  for (let i = 0; i < 16; i++) hi = (hi << 8n) | BigInt(pk[i]);
  let lo = 0n;
  for (let i = 16; i < 32; i++) lo = (lo << 8n) | BigInt(pk[i]);
  return [lo, hi];
}

export interface Note {
  tokenMint: Uint8Array; // 32 bytes
  amount: bigint;
  ownerCommitment: bigint;
  nonce: bigint;
  blindingR: bigint;
}

// Domain tags — must match circuits/valid_spend/circuit.circom and
// crates/darkpool-crypto/src/{note,nullifier}.rs exactly.
const DOMAIN_OWNER = 1n;
const DOMAIN_NOTE = 2n;
const DOMAIN_NULL = 3n;

/** Compute owner_commitment = Poseidon3(DOMAIN_OWNER, spendingKey, r_owner). */
export async function ownerCommitment(
  spendingKey: bigint,
  blinding: bigint,
): Promise<bigint> {
  const p = await getPoseidon();
  const packed = p([DOMAIN_OWNER, spendingKey, blinding]);
  return p.F.toObject(packed);
}

/** Compute the 32-byte BE note commitment = Poseidon7(DOMAIN_NOTE, mint_lo, mint_hi, amount, ownerCommit, nonce, blindingR). */
export async function noteCommitment(note: Note): Promise<Uint8Array> {
  const [lo, hi] = pubkeyToFrPair(note.tokenMint);
  return poseidonHashBytesBE([
    DOMAIN_NOTE,
    lo,
    hi,
    note.amount,
    note.ownerCommitment,
    note.nonce,
    note.blindingR,
  ]);
}

/** Compute nullifier = Poseidon3(DOMAIN_NULL, spendingKey, noteCommitmentBigint). */
export async function nullifier(
  spendingKey: bigint,
  commitmentBE: Uint8Array,
): Promise<Uint8Array> {
  if (commitmentBE.length !== 32)
    throw new Error("commitment must be 32 bytes");
  let cBig = 0n;
  for (const b of commitmentBE) cBig = (cBig << 8n) | BigInt(b);
  const p = await getPoseidon();
  const packed = p([DOMAIN_NULL, spendingKey, cBig]);
  return bn254ToBE32(p.F.toObject(packed));
}

export interface NoteV2 {
  tokenMint: Uint8Array; // 32 bytes
  amount: bigint;
  ownerCommitment: bigint;
  innerHash: bigint;
}

/**
 * v2 note commitment = Poseidon6(DOMAIN_NOTE, mint_lo, mint_hi, amount,
 * ownerCommitment, innerHash). Mirrors
 * `darkpool_crypto::note::commitment_from_fields_v2`.
 */
export async function noteCommitmentV2(note: NoteV2): Promise<Uint8Array> {
  const [lo, hi] = pubkeyToFrPair(note.tokenMint);
  return poseidonHashBytesBE([
    DOMAIN_NOTE,
    lo,
    hi,
    note.amount,
    note.ownerCommitment,
    note.innerHash,
  ]);
}

/**
 * v2 nullifier = Poseidon3(DOMAIN_NULL, spendingKey, innerHash). Mirrors
 * `darkpool_crypto::nullifier::nullifier_v2`. Amount-independent — computable
 * before the change-note amount is known.
 */
export async function nullifierV2(
  spendingKey: bigint,
  innerHash: bigint,
): Promise<Uint8Array> {
  const p = await getPoseidon();
  const packed = p([DOMAIN_NULL, spendingKey, innerHash]);
  return bn254ToBE32(p.F.toObject(packed));
}
