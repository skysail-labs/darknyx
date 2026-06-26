/**
 * Price Commitment.
 *
 * Mirror of `crates/darkpool-crypto/src/price_commitment.rs` and the
 * `circuits/valid_price/circuit.circom` `price_commitment` constraint:
 *
 *   price_commitment = Poseidon3(DOMAIN_PRICE=5, clearing_price, batch_slot)
 *
 * The on-chain `tee_forced_settle` handler recomputes this exact value from
 * `payload.clearingPrice + payload.batchSlot` to look up the
 * `ValidPriceMarker` PDA written by a preceding `verify_valid_price` ix.
 * Output MUST be byte-identical to the Rust helper.
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

// Must match `DOMAIN_PRICE` in:
//   circuits/valid_price/circuit.circom
//   crates/darkpool-crypto/src/price_commitment.rs
const DOMAIN_PRICE = 5n;

/**
 * Compute the 32-byte `price_commitment` for a (clearingPrice, batchSlot)
 * pair. Big-endian byte order, same as the on-chain Rust output.
 */
export async function priceCommitment(
  clearingPrice: bigint,
  batchSlot: bigint,
): Promise<Uint8Array> {
  const p = await getPoseidon();
  const hash = p.F.toObject(p([DOMAIN_PRICE, clearingPrice, batchSlot]));
  return bn254ToBE32(hash);
}
