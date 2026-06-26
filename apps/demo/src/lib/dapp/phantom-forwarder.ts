/**
 * PhantomTransactionForwarder — `TransactionForwarder` impl backed by the
 * Solana wallet-adapter. Concrete responsibilities:
 *
 *   1. Accept either a fully built `Transaction` or a list of
 *      `TransactionInstruction`s (matching the SDK's polymorphic API).
 *   2. Attach `feePayer` + a fresh `recentBlockhash` if missing.
 *   3. Apply any extra `Keypair` co-signers handed in by the SDK (used by ER
 *      flows where an ephemeral session keypair signs alongside the wallet).
 *   4. Route the final tx through `wallet.sendTransaction` so Phantom prompts
 *      the user, then wait for confirmation.
 *
 * The forwarder is intentionally cluster-agnostic — pass either an L1 or ER
 * `Connection`. The matching-engine flows on the ER use the same forwarder
 * with a different connection.
 */

import type { TransactionForwarder } from "@nyx/sdk";
import { WalletSendTransactionError } from "@solana/wallet-adapter-base";
import type { WalletContextState } from "@solana/wallet-adapter-react";
import type {
  Connection,
  Keypair,
  TransactionSignature,
} from "@solana/web3.js";
import {
  SendTransactionError,
  Transaction,
  TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";

function compileUnsignedV0(tx: Transaction): VersionedTransaction {
  if (!tx.feePayer) throw new Error("compileUnsignedV0: tx.feePayer missing");
  if (!tx.recentBlockhash)
    throw new Error("compileUnsignedV0: recentBlockhash missing");
  const msg = new TransactionMessage({
    payerKey: tx.feePayer,
    recentBlockhash: tx.recentBlockhash,
    instructions: tx.instructions,
  }).compileToV0Message();
  return new VersionedTransaction(msg);
}

/**
 * Phantom's wallet-standard adapter very often surfaces failures as
 * `WalletSendTransactionError("Unexpected error")` with `error.error`
 * undefined — so the only reliable way to learn what actually failed is to
 * re-simulate the same transaction ourselves. We do that on every send error
 * and append program logs to the thrown message.
 */
async function formatWalletSendFailure(
  err: unknown,
  ctx: { connection: Connection; tx: Transaction },
): Promise<string> {
  console.error("[PhantomTransactionForwarder] raw error", err);

  let inner: unknown;
  let outerMsg = "";
  if (err instanceof WalletSendTransactionError) {
    inner = err.error;
    outerMsg = err.message;
  } else if (err instanceof Error) {
    outerMsg = err.message;
  } else {
    outerMsg = String(err);
  }

  let detail: string | undefined;
  let logs: string[] | undefined;
  if (inner instanceof SendTransactionError) {
    const te = inner.transactionError;
    detail = te?.message ?? inner.message;
    logs = inner.logs ?? te?.logs ?? undefined;
  } else if (inner instanceof Error) {
    detail = inner.message;
  } else if (inner != null) {
    detail = String(inner);
  }

  if (!logs || logs.length === 0) {
    try {
      const vtx = compileUnsignedV0(ctx.tx);
      const sim = await ctx.connection.simulateTransaction(vtx, {
        sigVerify: false,
        replaceRecentBlockhash: true,
      });
      logs = sim.value.logs ?? undefined;
      if (!detail && sim.value.err) {
        detail = `simulateTransaction err: ${JSON.stringify(sim.value.err)}`;
      }
      console.warn(
        "[PhantomTransactionForwarder] manual simulation",
        sim.value,
      );
    } catch (simErr) {
      console.warn(
        "[PhantomTransactionForwarder] manual simulation failed",
        simErr,
      );
    }
  }

  const parts: string[] = [];
  parts.push(outerMsg || "Wallet rejected or failed to send the transaction.");
  if (detail && detail !== outerMsg) parts.push(detail);
  if (logs && logs.length > 0) {
    const filtered = logs.filter(Boolean);
    if (filtered.length > 0) {
      parts.push(`--- program logs ---\n${filtered.join("\n")}`);
    }
  } else {
    parts.push(
      [
        "No program logs available — Phantom rejected before submitting.",
        "Common causes:",
        "• Phantom is on a different cluster than the app (must be devnet).",
        "• Wallet has no SOL to pay fees / ATA rent.",
        "• You haven't run the airdrop step, so your token ATA has 0 balance.",
      ].join("\n"),
    );
  }
  return parts.join("\n\n");
}

export interface PhantomForwarderOpts {
  /** Solana connection used for blockhash + send + confirm. */
  connection: Connection;
  /** Wallet context from `useWallet()`. Must be connected when `sendAndConfirm` is called. */
  wallet: WalletContextState;
  /**
   * Confirmation level — `confirmed` is the right default for UI feedback
   * (sub-second on devnet) without sacrificing safety. Caller can switch to
   * `finalized` for the last-mile receipt / withdraw path.
   */
  commitment?: "processed" | "confirmed" | "finalized";
}

export class PhantomTransactionForwarder implements TransactionForwarder {
  constructor(private readonly opts: PhantomForwarderOpts) {}

  async sendAndConfirm(
    txOrIxs: Transaction | TransactionInstruction[],
    signers?: unknown[],
  ): Promise<TransactionSignature> {
    const { connection, wallet, commitment = "confirmed" } = this.opts;
    if (!wallet.publicKey) {
      throw new Error("PhantomTransactionForwarder: wallet is not connected");
    }
    if (!wallet.sendTransaction) {
      throw new Error(
        "PhantomTransactionForwarder: connected wallet does not implement sendTransaction",
      );
    }

    const tx = toTransaction(txOrIxs);
    if (!tx.feePayer) tx.feePayer = wallet.publicKey;
    if (!tx.recentBlockhash) {
      const { blockhash } = await connection.getLatestBlockhash(commitment);
      tx.recentBlockhash = blockhash;
    }

    const extraSigners = (signers ?? []).filter(isKeypair) as Keypair[];

    try {
      const vtx = compileUnsignedV0(tx);
      const sim = await connection.simulateTransaction(vtx, {
        sigVerify: false,
        replaceRecentBlockhash: true,
        commitment,
      });
      if (sim.value.err) {
        const lines = (sim.value.logs ?? []).filter(Boolean);
        throw new Error(
          [
            `Pre-flight simulation failed before asking the wallet to sign.`,
            `err: ${JSON.stringify(sim.value.err)}`,
            lines.length > 0 ? `--- program logs ---\n${lines.join("\n")}` : "",
          ]
            .filter(Boolean)
            .join("\n\n"),
        );
      }
    } catch (e) {
      if (
        e instanceof Error &&
        e.message.startsWith("Pre-flight simulation failed")
      ) {
        throw e;
      }
      console.warn(
        "[PhantomTransactionForwarder] pre-flight simulate threw, continuing",
        e,
      );
    }

    let signature: TransactionSignature;
    try {
      signature = await wallet.sendTransaction(tx, connection, {
        skipPreflight: false,
        preflightCommitment: commitment,
        signers: extraSigners,
      });
    } catch (e) {
      const msg = await formatWalletSendFailure(e, { connection, tx });
      throw new Error(msg);
    }

    const latest = await connection.getLatestBlockhash(commitment);
    await connection.confirmTransaction(
      {
        signature,
        blockhash: latest.blockhash,
        lastValidBlockHeight: latest.lastValidBlockHeight,
      },
      commitment,
    );
    return signature;
  }
}

function toTransaction(
  input: Transaction | TransactionInstruction[],
): Transaction {
  if (input instanceof Transaction) return input;
  const tx = new Transaction();
  for (const ix of input) tx.add(ix);
  return tx;
}

function isKeypair(value: unknown): value is Keypair {
  return (
    typeof value === "object" &&
    value !== null &&
    "publicKey" in value &&
    "secretKey" in value &&
    (value as { secretKey: unknown }).secretKey instanceof Uint8Array
  );
}
