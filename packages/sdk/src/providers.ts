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
  ): Promise<{ data: Buffer; owner: PublicKey } | null>;
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
  generate(): Promise<Uint8Array>;
}

/**
 * Master-seed mode controls where the 64-byte seed comes from. Two modes per
 * spec Section 4.5:
 *  - "csprng" — generate locally via crypto.getRandomValues, store via
 *               `MasterSeedStorage`. Backup responsibility is on the user.
 *  - "wallet-signature" — derive seed from an Ed25519 signature over a fixed
 *                         message. No separate backup needed; rebind on each
 *                         session via the user's Solana wallet.
 */
export type MasterSeedMode =
  | { type: "csprng"; storage: MasterSeedStorage }
  | {
      type: "wallet-signature";
      signMessage: (msg: Uint8Array) => Promise<Uint8Array>;
      message?: Uint8Array;
    };

export interface SolanaConnectionProvider {
  connection: Connection;
  perRpcUrl: string;
}

export interface TransactionCallbacks {
  pre?(step: string): void | Promise<void>;
  post?(step: string, signature?: TransactionSignature): void | Promise<void>;
}
