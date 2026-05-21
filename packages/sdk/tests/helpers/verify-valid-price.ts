/**
 * One-shot helper that lands a `verify_valid_price` tx on L1 for the
 * given payload and returns the priceCommitment so the caller can pass
 * it to `buildSettleIx`. Consolidates ~25 lines of repetitive setup
 * that would otherwise appear at every settle site in the E2E tests.
 *
 * Mirrors the existing `proveValidCreate` + `buildVerifyValidCreateInstruction`
 * pattern, just for VALID_PRICE.
 */

import {
  ComputeBudgetProgram,
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";

import { buildVerifyValidPriceInstruction } from "../../src/idl/vault-client.js";
import type { MatchResultPayload } from "../../src/settlement/settle-builder.js";
import { proveValidPrice } from "./valid-price-prover.js";

export interface LandVerifyValidPriceParams {
  connection: Connection;
  vaultProgramId: PublicKey;
  teeKeypair: Keypair;
  payload: Pick<
    MatchResultPayload,
    "clearingPrice" | "baseAmount" | "quoteAmount" | "batchSlot"
  >;
  repoRoot: string;
}

export interface LandVerifyValidPriceResult {
  /** 32-byte priceCommitment, pass to `buildSettleIx`. */
  priceCommitment: Uint8Array;
  /** Tx signature of the landed verify_valid_price tx. */
  txSig: string;
}

export async function landVerifyValidPrice(
  p: LandVerifyValidPriceParams,
): Promise<LandVerifyValidPriceResult> {
  const proveResult = await proveValidPrice({
    repoRoot: p.repoRoot,
    clearingPrice: p.payload.clearingPrice,
    baseAmount: p.payload.baseAmount,
    quoteAmount: p.payload.quoteAmount,
    batchSlot: p.payload.batchSlot,
  });

  const currentSlot = await p.connection.getSlot("confirmed");
  const expirySlot = BigInt(currentSlot + 200);

  const tx = new Transaction().add(
    ComputeBudgetProgram.setComputeUnitLimit({ units: 600_000 }),
    buildVerifyValidPriceInstruction({
      programId: p.vaultProgramId,
      payer: p.teeKeypair.publicKey,
      priceCommitment: proveResult.priceCommitment,
      batchSlot: p.payload.batchSlot,
      expirySlot,
      proof: proveResult.proof,
    }),
  );

  const txSig = await sendAndConfirmTransaction(p.connection, tx, [p.teeKeypair], {
    commitment: "confirmed",
  });

  return {
    priceCommitment: proveResult.priceCommitment,
    txSig,
  };
}
