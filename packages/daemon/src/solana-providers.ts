/**
 * Concrete Solana providers for the SDK `DarkPoolClient`.
 *
 * `@nyx/sdk` ships only the provider INTERFACES (`providers.ts`); these are the
 * daemon's implementations over a real `@solana/web3.js` Connection + the
 * operator's payer keypair. They back the daemon's DIRECT on-chain actions
 * (deposit; later merge/withdraw) — NOT order flow, which the TEE settles.
 *
 * Each provider takes its Connection injected, so the shapes are unit-testable
 * with a fake connection (no devnet).
 */

import {
  Connection,
  Keypair,
  Transaction,
  type PublicKey,
  type TransactionInstruction,
} from "@solana/web3.js";
import type {
  AccountInfoProvider,
  MasterSeedMode,
  SolanaConnectionProvider,
  TransactionForwarder,
} from "@nyx/sdk";

/** Minimal Connection surface the forwarder + account reader use (for tests). */
export interface ConnectionLike {
  getAccountInfo(
    pubkey: PublicKey,
  ): Promise<{ data: Buffer; owner: PublicKey } | null>;
  getLatestBlockhash(): Promise<{ blockhash: string }>;
  sendRawTransaction(raw: Uint8Array): Promise<string>;
  confirmTransaction(sig: string, commitment?: string): Promise<unknown>;
}

export function createConnection(rpcUrl: string): Connection {
  return new Connection(rpcUrl, "confirmed");
}

export function connectionProvider(
  connection: Connection,
): SolanaConnectionProvider {
  return { connection, perRpcUrl: connection.rpcEndpoint };
}

export function accountInfoProvider(
  connection: ConnectionLike,
): AccountInfoProvider {
  return {
    async getAccountInfo(pubkey) {
      const info = await connection.getAccountInfo(pubkey);
      return info ? { data: info.data, owner: info.owner } : null;
    },
  };
}

/**
 * A {@link TransactionForwarder} that attaches `payer` as fee-payer, signs, and
 * sends + confirms. Send/confirm are split into explicit Connection calls (vs.
 * `sendAndConfirmTransaction`) so the path is testable with a fake connection.
 */
export function keypairForwarder(
  connection: ConnectionLike,
  payer: Keypair,
): TransactionForwarder {
  return {
    async sendAndConfirm(txOrIxs, signers = []) {
      const tx = Array.isArray(txOrIxs)
        ? new Transaction().add(...(txOrIxs as TransactionInstruction[]))
        : (txOrIxs as Transaction);
      tx.feePayer = payer.publicKey;
      tx.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
      tx.sign(payer, ...(signers as Keypair[]));
      const sig = await connection.sendRawTransaction(tx.serialize());
      await connection.confirmTransaction(sig, "confirmed");
      return sig;
    },
  };
}

/** A `MasterSeedMode` that just hands back the daemon's already-loaded seed
 *  (the keystore is the source of truth; the SDK never generates/stores). */
export function fixedSeedMode(seed: Uint8Array): MasterSeedMode {
  return {
    type: "csprng",
    storage: {
      load: async () => seed,
      store: async () => {},
      generate: async () => seed,
    },
  };
}
