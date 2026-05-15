/**
 * v3 — VALID_CREATE prover helper.
 *
 * Generates a Groth16 proof attesting that the TEE constructed the output
 * notes correctly for a given match:
 *
 *   - note_c is in BASE mint, amount = base_amount, addressed to the BUYER
 *   - note_d is in QUOTE mint, amount = quote_amount, addressed to the SELLER
 *   - note_e (buyer change) in QUOTE mint, addressed to BUYER (or empty)
 *   - note_f (seller change) in BASE mint, addressed to SELLER (or empty)
 *
 * The owner_commitments stay private — the on-chain verify_valid_create ix
 * only ever sees the commitments + amounts + mints as public inputs.
 *
 * The TEE generates this proof when it builds a settlement, and lands a
 * `verify_valid_create` ix BEFORE the settle. The settle's account list
 * carries a `ValidCreateMarker` PDA created by that ix; if it isn't there,
 * the settle aborts.
 */

import { resolve } from "node:path";

import type { Groth16OnChainProof } from "../../src/idl/vault-client.js";
import { pubkeyToFrPair } from "../../src/utxo/note.js";
import { be32ToDec } from "./e2e-helpers.js";
import { snarkjsFullProve } from "./snarkjs-prover.js";

const WASM_REL = "circuits/build/valid_create/circuit_js/circuit.wasm";
const ZKEY_REL = "circuits/build/valid_create/circuit_final.zkey";

export interface ValidCreateNote {
  /** Note's owner_commitment (Fr scalar bigint). Stays PRIVATE in the proof. */
  ownerCommit: bigint;
  /** Note amount in base units. */
  amount: bigint;
  /** Random nonce used in the commitment Poseidon. */
  nonce: bigint;
  /** Random blinding factor used in the commitment Poseidon. */
  blindingR: bigint;
}

export interface ValidCreateProveParams {
  repoRoot: string;

  // The two mints used in the match. Raw 32-byte pubkeys.
  quoteMint: Uint8Array;
  baseMint: Uint8Array;

  // Input-note openings (private witnesses + their public commitments).
  inputA: ValidCreateNote;     // QUOTE-side input (buyer's note_a)
  inputAcommitmentBE: Uint8Array;
  inputB: ValidCreateNote;     // BASE-side input (seller's note_b)
  inputBcommitmentBE: Uint8Array;

  // Trade-leg outputs (always present).
  outputC: ValidCreateNote;    // BASE-mint, amount = baseAmount, owner = inputA.ownerCommit
  outputCcommitmentBE: Uint8Array;
  outputD: ValidCreateNote;    // QUOTE-mint, amount = quoteAmount, owner = inputB.ownerCommit
  outputDcommitmentBE: Uint8Array;

  // Change-leg outputs. When the change amount is 0, the corresponding
  // commitment MUST be all-zero AND ownerCommit/nonce/blindingR can be 0
  // (the circuit's selector zeroes the computed hash).
  outputE?: ValidCreateNote;            // QUOTE-mint, owner = inputA.ownerCommit
  outputEcommitmentBE: Uint8Array;      // [0;32] if no buyer change
  outputF?: ValidCreateNote;            // BASE-mint,  owner = inputB.ownerCommit
  outputFcommitmentBE: Uint8Array;      // [0;32] if no seller change

  // Trade economics.
  baseAmount: bigint;
  quoteAmount: bigint;
  buyerChangeAmt: bigint;
  sellerChangeAmt: bigint;
  buyerFeeAmt: bigint;
  sellerFeeAmt: bigint;
}

export interface ValidCreateProveResult {
  proof: Groth16OnChainProof;
  /**
   * 16 public inputs in declaration order:
   *   note_a, note_b, note_c, note_d, note_e, note_f,
   *   quote_mint_lo, quote_mint_hi, base_mint_lo, base_mint_hi,
   *   base_amount, quote_amount, buyer_change, seller_change,
   *   buyer_fee, seller_fee
   * Each 32-byte BE.
   */
  publicInputsBE: Uint8Array[];
}

function noteOrZero(n: ValidCreateNote | undefined): ValidCreateNote {
  if (n) return n;
  return { ownerCommit: 0n, amount: 0n, nonce: 0n, blindingR: 0n };
}

export async function proveValidCreate(
  args: ValidCreateProveParams,
): Promise<ValidCreateProveResult> {
  if (args.quoteMint.length !== 32) throw new Error("quoteMint must be 32 bytes");
  if (args.baseMint.length !== 32) throw new Error("baseMint must be 32 bytes");

  const [qLo, qHi] = pubkeyToFrPair(args.quoteMint);
  const [bLo, bHi] = pubkeyToFrPair(args.baseMint);

  // Selectors for change/fee notes. We always provide nonce/blinding bigints;
  // when the change amount is 0, the circuit's IsZero gates the constraint
  // such that the corresponding commitment must be 0 regardless of nonce/blinding.
  const eFilled = noteOrZero(args.outputE);
  const fFilled = noteOrZero(args.outputF);

  const inputs: Record<string, string | string[]> = {
    // Public
    note_a_commitment: be32ToDec(args.inputAcommitmentBE),
    note_b_commitment: be32ToDec(args.inputBcommitmentBE),
    note_c_commitment: be32ToDec(args.outputCcommitmentBE),
    note_d_commitment: be32ToDec(args.outputDcommitmentBE),
    note_e_commitment: be32ToDec(args.outputEcommitmentBE),
    note_f_commitment: be32ToDec(args.outputFcommitmentBE),
    quote_mint: [qLo.toString(), qHi.toString()],
    base_mint: [bLo.toString(), bHi.toString()],
    base_amount: args.baseAmount.toString(),
    quote_amount: args.quoteAmount.toString(),
    buyer_change_amt: args.buyerChangeAmt.toString(),
    seller_change_amt: args.sellerChangeAmt.toString(),
    buyer_fee_amt: args.buyerFeeAmt.toString(),
    seller_fee_amt: args.sellerFeeAmt.toString(),

    // Private
    a_owner_commit: args.inputA.ownerCommit.toString(),
    b_owner_commit: args.inputB.ownerCommit.toString(),
    a_amount: args.inputA.amount.toString(),
    b_amount: args.inputB.amount.toString(),
    a_nonce: args.inputA.nonce.toString(),
    a_blinding: args.inputA.blindingR.toString(),
    b_nonce: args.inputB.nonce.toString(),
    b_blinding: args.inputB.blindingR.toString(),
    c_nonce: args.outputC.nonce.toString(),
    c_blinding: args.outputC.blindingR.toString(),
    d_nonce: args.outputD.nonce.toString(),
    d_blinding: args.outputD.blindingR.toString(),
    e_nonce: eFilled.nonce.toString(),
    e_blinding: eFilled.blindingR.toString(),
    f_nonce: fFilled.nonce.toString(),
    f_blinding: fFilled.blindingR.toString(),
  };

  return snarkjsFullProve(inputs, {
    repoRoot: args.repoRoot,
    circuitWasmPath: resolve(args.repoRoot, WASM_REL),
    circuitZkeyPath: resolve(args.repoRoot, ZKEY_REL),
  });
}
