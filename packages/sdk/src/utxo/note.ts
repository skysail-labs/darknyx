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
 * Domain tags (must match circuit.circom and crates/darkpool-crypto exactly).
 * The LIVE construction is v2 (inner_hash) — a single per-note blinding that
 * anchors BOTH the commitment and the nullifier (amount-independent, so a client
 * can pre-supply change-note nullifiers):
 *   DOMAIN_OWNER = 1n  — owner_commitment = Poseidon3(1, spendingKey, r_owner)
 *   DOMAIN_NOTE  = 2n  — noteCommitmentV2 = Poseidon6(2, mint_lo, mint_hi, amount, owner, inner_hash)
 *   DOMAIN_NULL  = 3n  — nullifierV2      = Poseidon3(3, spendingKey, inner_hash)
 *
 * (The pre-v2 v1 construction — a Poseidon7 note with separate nonce/blindingR
 * fields + a nullifier over the note commitment — has been fully retired.)
 */

import { buildPoseidon } from "circomlibjs";
import { BN254_R, bn254ToBE32 } from "../keys/key-generators.js";

type PoseidonFn = ((inputs: bigint[]) => Uint8Array) & {
  F: { toObject: (x: Uint8Array) => bigint };
};

/**
 * Reject a value the Rust side would reject (SW-23).
 *
 * circomlibjs' `p.F.e(i)` **reduces** anything >= the BN254 modulus. Rust does
 * one of two things depending on the input, and TypeScript has to match each:
 *
 * * `fr_from_be_bytes` **rejects** out-of-range (`PoseidonFailed 6030`). That
 *   is the rule for values that are already field elements — `inner_hash`,
 *   `owner_commitment`, mint halves, amounts. TypeScript silently reduced them,
 *   so the same input produced a hash on one side and an error on the other, in
 *   exactly the primitive CLAUDE.md §7 pins byte-for-byte. That is what this
 *   guards.
 * * `Fr::from_be_bytes_mod_order` **reduces** — used deliberately for the
 *   256-bit spending key. Reduction there is the matching behaviour, not a
 *   divergence, and `nullifier-parity.test.ts` pins it. So this must NOT be
 *   applied blanket inside the Poseidon wrapper; doing that broke that test,
 *   which is how the distinction surfaced.
 *
 * `bn254ToBE32` already range-checks on the way OUT; the asymmetry was only on
 * the way in. Matching Rust means failing rather than reducing, because a silent
 * reduction changes which note is being committed to.
 */
function assertInField(label: string, value: bigint): bigint {
  if (value < 0n || value >= BN254_R) {
    throw new Error(
      `${label} is outside [0, BN254_r) — circomlibjs would silently reduce it ` +
        "while the Rust side rejects it, so the two would disagree on the hash",
    );
  }
  return value;
}

/**
 * Reduce mod r, matching Rust's `Fr::from_be_bytes_mod_order`.
 *
 * NEGATIVES ARE REJECTED, not wrapped. Rust reduces *bytes*, so a negative has
 * no counterpart there — `((v % r) + r) % r` was inventing a mapping the pinned
 * side cannot express, silently turning `-1n` into a perfectly valid-looking
 * `r - 1` commitment. That is the same silent-reduction failure SW-23 is about,
 * on a different axis: reduction is correct for a 256-bit key that Rust also
 * reduces, and wrong for an input Rust could never have received.
 *
 * Every in-repo caller passes the output of `beToBigInt` over 32 bytes, which
 * is non-negative by construction, so this rejects only a caller that hand-built
 * a signed value — a bug, and one worth surfacing at the call rather than as a
 * commitment nobody can open.
 */
function toField(value: bigint): bigint {
  if (value < 0n) {
    throw new Error(
      "field input is negative — Rust reduces bytes and has no negative to " +
        "match, so wrapping it here would produce a commitment the Rust side " +
        "could never derive",
    );
  }
  return value % BN254_R;
}

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

/** Hash an array of field elements (each in [0, BN254_r)) -> 32-byte BE result.
 *  Out-of-range inputs are REJECTED, matching `fr_from_be_bytes` (SW-23). */
export async function poseidonHashBytesBE(
  inputs: bigint[],
): Promise<Uint8Array> {
  inputs.forEach((v, i) => assertInField(`poseidon input ${i}`, v));
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
  // Both inputs are derived key material that Rust parses with
  // `Fr::from_be_bytes_mod_order` (`owner_commitment` takes `&Fr`), so reduction
  // is the matching behaviour here — the same distinction as `nullifierV2`.
  const packed = p([DOMAIN_OWNER, toField(spendingKey), toField(blinding)]);
  return p.F.toObject(packed);
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
  // The spending key is REDUCED on both sides — Rust's helper uses
  // `Fr::from_be_bytes_mod_order`. `inner_hash` is already a field element and
  // Rust rejects it out of range, so it is checked rather than reduced.
  const packed = p([
    DOMAIN_NULL,
    toField(spendingKey),
    assertInField("nullifier inner_hash", innerHash),
  ]);
  return bn254ToBE32(p.F.toObject(packed));
}
