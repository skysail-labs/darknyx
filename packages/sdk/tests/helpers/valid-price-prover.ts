/**
 * v3.1 — VALID_PRICE prover helper.
 *
 * Generates a Groth16 proof attesting that:
 *
 *   quote_amount === base_amount * clearing_price      (exact, no rounding)
 *   clearing_price, base_amount, quote_amount ∈ [0, 2^64)
 *   price_commitment === Poseidon3(DOMAIN_PRICE=5, clearing_price, batch_slot)
 *
 * The TEE generates this proof when it builds a settlement and lands a
 * `verify_valid_price` ix BEFORE the settle. That ix writes a
 * `ValidPriceMarker` PDA at `[b"valid_price", price_commitment]`; the
 * settle's account list carries the same PDA, and the on-chain handler
 * recomputes `price_commitment` from `payload.clearingPrice +
 * payload.batchSlot` and asserts the account is at the derived address.
 *
 * Public inputs (declaration order):
 *   wire 1: price_commitment (32 BE bytes — Poseidon output)
 *   wire 2: batch_slot       (u64, encoded as 32 BE bytes)
 *
 * `clearing_price`, `base_amount`, `quote_amount` stay private.
 */

import { resolve } from "node:path";

import type { Groth16OnChainProof } from "../../src/idl/vault-client.js";
import { priceCommitment } from "../../src/zk/price-commitment.js";
import { snarkjsFullProve } from "./snarkjs-prover.js";

const WASM_REL = "circuits/build/valid_price/circuit_js/circuit.wasm";
const ZKEY_REL = "circuits/build/valid_price/circuit_final.zkey";

export interface ValidPriceProveParams {
  repoRoot: string;
  /** Private — the TEE's clearing price (matched orderbook output). */
  clearingPrice: bigint;
  /** Private — base side amount the trade settles. */
  baseAmount: bigint;
  /** Private — quote side amount (= baseAmount * clearingPrice). */
  quoteAmount: bigint;
  /** Public — the batch slot the match landed in. */
  batchSlot: bigint;
}

export interface ValidPriceProveResult {
  proof: Groth16OnChainProof;
  /** 32-byte priceCommitment (Poseidon3(5, clearingPrice, batchSlot)). */
  priceCommitment: Uint8Array;
  /** 2 public inputs in declaration order, each 32 BE bytes. */
  publicInputsBE: Uint8Array[];
}

export async function proveValidPrice(
  args: ValidPriceProveParams,
): Promise<ValidPriceProveResult> {
  // Sanity check the circuit's central constraint before we pay snarkjs.
  // A failing assertion here surfaces as a much clearer error than the
  // generic "Error in template ValidPrice line X" snarkjs spits out.
  if (args.quoteAmount !== args.baseAmount * args.clearingPrice) {
    throw new Error(
      `valid-price-prover: quoteAmount (${args.quoteAmount}) !== ` +
        `baseAmount (${args.baseAmount}) * clearingPrice (${args.clearingPrice})`,
    );
  }

  const pc = await priceCommitment(args.clearingPrice, args.batchSlot);

  // snarkjs takes signal names + decimal string values.
  // Public signals come first in the wire-index order declared by the circuit.
  const inputs: Record<string, string | string[]> = {
    // Public
    price_commitment: bigintFromBE32(pc).toString(),
    batch_slot: args.batchSlot.toString(),
    // Private
    clearing_price: args.clearingPrice.toString(),
    base_amount: args.baseAmount.toString(),
    quote_amount: args.quoteAmount.toString(),
  };

  const result = await snarkjsFullProve(inputs, {
    repoRoot: args.repoRoot,
    circuitWasmPath: resolve(args.repoRoot, WASM_REL),
    circuitZkeyPath: resolve(args.repoRoot, ZKEY_REL),
  });

  return {
    proof: result.proof,
    priceCommitment: pc,
    publicInputsBE: result.publicInputsBE,
  };
}

function bigintFromBE32(bytes: Uint8Array): bigint {
  let acc = 0n;
  for (const b of bytes) acc = (acc << 8n) | BigInt(b);
  return acc;
}
