import {
  buildDelegateBatchResultsInstruction,
  buildDelegateDarkClobInstruction,
  buildDelegateMatchingConfigInstruction,
} from "@nyx/sdk/dist/idl/er-client.js";
import {
  Keypair,
  PublicKey,
  sendAndConfirmTransaction,
  Transaction,
} from "@solana/web3.js";

import { darkClobPda } from "@nyx/sdk";

const DELEGATION_PROGRAM_ID = new PublicKey(
  "DELeGGvXpWV2fqJUhqcF5ZSYMS4JTLjteaAMARRSaeSh",
);

export async function ensureMarketDelegatedOnL1(
  l1: import("@solana/web3.js").Connection,
  meProgramId: PublicKey,
  market: PublicKey,
  funder: Keypair,
): Promise<void> {
  const [clobPda] = darkClobPda(meProgramId, market);
  const clob = await l1.getAccountInfo(clobPda, "confirmed");
  if (!clob) throw new Error("DarkCLOB account missing on L1.");
  if (clob.owner.equals(DELEGATION_PROGRAM_ID)) return;

  await sendAndConfirmTransaction(
    l1,
    new Transaction().add(
      buildDelegateDarkClobInstruction({
        programId: meProgramId,
        payer: funder.publicKey,
        market,
      }),
      buildDelegateMatchingConfigInstruction({
        programId: meProgramId,
        payer: funder.publicKey,
        market,
      }),
      buildDelegateBatchResultsInstruction({
        programId: meProgramId,
        payer: funder.publicKey,
        market,
      }),
    ),
    [funder],
    { commitment: "confirmed" },
  );
}
