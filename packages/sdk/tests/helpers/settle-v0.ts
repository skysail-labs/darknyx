/**
 * v3 — VersionedTransaction wrapper for the settle tx.
 *
 * The legacy settle tx is near the 1232-byte cap once a `ValidCreateMarker`
 * account is added; the re-lock variant in particular goes 1243/1232. This
 * helper packages the same set of instructions into a v0 tx that resolves
 * three static accounts (vault_config, instructions_sysvar, system_program)
 * through an Address Lookup Table, saving ~60 bytes net.
 *
 * Usage:
 *   const sig = await sendSettleV0({
 *     connection, signer: teeKeypair,
 *     altPubkey: cfg.settleLookupTable,
 *     instructions: [
 *       ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
 *       buildEd25519VerifyIx({...}),
 *       buildSettleIx({...}),
 *     ],
 *   });
 */

import {
  Connection,
  Keypair,
  PublicKey,
  TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";

export interface SendSettleV0Params {
  connection: Connection;
  /** Fee-payer + sole signer for the settle tx (typically tee_authority). */
  signer: Keypair;
  /** Pubkey of the Address Lookup Table created in devnet-setup. */
  altPubkey: PublicKey;
  /** Compute-budget + ed25519 precompile + buildSettleIx, in that order. */
  instructions: TransactionInstruction[];
  /** v3.5 — optional extra ALTs to stack on top of the primary one.
   *  Useful for the batched settle path: the per-batch ALT holds the
   *  derived note_lock_a/b/e/f + batch_validity_marker so the settle
   *  tx fits under the 1232-byte cap. */
  extraAltPubkeys?: PublicKey[];
}

export async function sendSettleV0(p: SendSettleV0Params): Promise<string> {
  const lookup = await p.connection.getAddressLookupTable(p.altPubkey, {
    commitment: "confirmed",
  });
  if (!lookup.value) {
    throw new Error(
      `Address Lookup Table ${p.altPubkey.toBase58()} not found; ` +
        "did devnet-setup.test.ts run with v3? Check .devnet/e2e-config.json.settleLookupTable",
    );
  }

  const altAccounts = [lookup.value];
  for (const extraPubkey of p.extraAltPubkeys ?? []) {
    const extra = await p.connection.getAddressLookupTable(extraPubkey, {
      commitment: "confirmed",
    });
    if (!extra.value) {
      throw new Error(`extra ALT ${extraPubkey.toBase58()} not found`);
    }
    altAccounts.push(extra.value);
  }

  const { blockhash } = await p.connection.getLatestBlockhash("confirmed");
  const messageV0 = new TransactionMessage({
    payerKey: p.signer.publicKey,
    recentBlockhash: blockhash,
    instructions: p.instructions,
  }).compileToV0Message(altAccounts);

  const tx = new VersionedTransaction(messageV0);
  tx.sign([p.signer]);

  const sig = await p.connection.sendTransaction(tx, {
    skipPreflight: false,
    preflightCommitment: "confirmed",
  });
  await p.connection.confirmTransaction(
    { signature: sig, blockhash, lastValidBlockHeight: (await p.connection.getLatestBlockhash()).lastValidBlockHeight },
    "confirmed",
  );
  return sig;
}
