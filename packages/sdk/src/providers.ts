import type {
  Connection,
  PublicKey,
  Transaction,
  TransactionInstruction,
  TransactionSignature,
} from "@solana/web3.js";

/**
 * Injectable infrastructure dependencies. Each can be swapped for a mock in tests.
 */

export interface AccountInfoProvider {
  getAccountInfo(
    pubkey: PublicKey,
  ): Promise<{ data: Uint8Array; owner: PublicKey } | null>;
}

export interface TransactionForwarder {
  /**
   * Sign (if needed), send, and confirm a transaction. Receives either a
   * fully constructed `Transaction` or a bare instruction list so the
   * forwarder can attach its own fee-payer / blockhash / signatures.
   */
  sendAndConfirm(
    txOrIxs: Transaction | TransactionInstruction[],
    signers?: unknown[],
  ): Promise<TransactionSignature>;
}

export interface MerkleProofProvider {
  getInclusionProof(leafIndex: bigint): Promise<{
    root: Uint8Array;
    siblings: Uint8Array[];
    pathIndices: number[];
  }>;
}

export interface MasterSeedStorage {
  load(): Promise<Uint8Array | null>;
  store(seed: Uint8Array): Promise<void>;
}

/**
 * Master-seed mode supports only a locally generated 64-byte CSPRNG seed held
 * by secure storage. A portable wallet signature must never be a spending
 * authority. Use the versioned encrypted seed-backup helpers for recovery.
 */
export type MasterSeedMode = { type: "csprng"; storage: MasterSeedStorage };

export interface SolanaConnectionProvider {
  connection: Connection;
  perRpcUrl: string;
}

export interface TransactionCallbacks {
  pre?(step: string): void | Promise<void>;
  post?(step: string, signature?: TransactionSignature): void | Promise<void>;
}
