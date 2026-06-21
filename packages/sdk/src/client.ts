import { PublicKey } from "@solana/web3.js";
import type {
  AccountInfoProvider,
  MasterSeedMode,
  MerkleProofProvider,
  SolanaConnectionProvider,
  TransactionForwarder,
} from "./providers.js";
import {
  deriveMasterViewingKey,
  deriveSpendingKey,
  deriveRootKey,
  deriveTradingKeyAtOffset,
  resolveMasterSeed,
} from "./keys/key-generators.js";
import type { IDarkPoolZkProverSuite } from "./zk/prover-suite.js";
import { consumedNotePda, noteLockPda } from "./idl/vault-client.js";

export interface DarkPoolClientConfig {
  programId: PublicKey;
  seedMode: MasterSeedMode;
  tradingOffset?: bigint;
  connectionProvider: SolanaConnectionProvider;
  providers: {
    accountInfoProvider: AccountInfoProvider;
    transactionForwarder: TransactionForwarder;
    merkleProofProvider: MerkleProofProvider;
  };
  zkProver: IDarkPoolZkProverSuite;
  /** Blinding factor used for the user's owner_commitment. Provide a
   *  deterministic value (e.g., a per-wallet constant) or generate per-note. */
  ownerCommitmentBlinding: bigint;
}

export type NoteStatus = "active" | "locked" | "consumed" | "unknown";

export interface NoteStatusInfo {
  status: NoteStatus;
}

export class DarkPoolClient {
  readonly programId: PublicKey;
  readonly connectionProvider: SolanaConnectionProvider;
  readonly providers: DarkPoolClientConfig["providers"];
  readonly zkProver: IDarkPoolZkProverSuite;
  private readonly seedMode: MasterSeedMode;
  private readonly tradingOffset: bigint;
  private resolvedSeed: Uint8Array | null = null;
  private readonly ownerBlinding: bigint;

  constructor(cfg: DarkPoolClientConfig) {
    this.programId = cfg.programId;
    this.connectionProvider = cfg.connectionProvider;
    this.providers = cfg.providers;
    this.zkProver = cfg.zkProver;
    this.seedMode = cfg.seedMode;
    this.tradingOffset = cfg.tradingOffset ?? 0n;
    this.ownerBlinding = cfg.ownerCommitmentBlinding;
  }

  get perRpcUrl(): string {
    return this.connectionProvider.perRpcUrl;
  }

  vaultConfigPda(): PublicKey {
    const [pda] = PublicKey.findProgramAddressSync(
      [new TextEncoder().encode("vault_config")],
      this.programId,
    );
    return pda;
  }

  async getResolvedKeys() {
    if (!this.resolvedSeed) {
      this.resolvedSeed = await resolveMasterSeed(this.seedMode);
    }
    return {
      masterSeed: this.resolvedSeed,
      spendingKey: deriveSpendingKey(this.resolvedSeed),
      viewingKey: deriveMasterViewingKey(this.resolvedSeed),
      rootKey: deriveRootKey(this.resolvedSeed),
      tradingKey: deriveTradingKeyAtOffset(this.resolvedSeed, this.tradingOffset),
      ownerBlinding: this.ownerBlinding,
    };
  }

  /**
   * Return the current lifecycle state of a UTXO note.
   *   - "consumed" — a ConsumedNote PDA exists (already settled).
   *   - "locked"   — a NoteLock PDA exists but ConsumedNote does not.
   *   - "active"   — neither PDA exists. Safe to use for a new order.
   *   - "unknown"  — RPC read failed. Caller should retry or abort.
   */
  async getNoteStatus(noteCommitment: Uint8Array): Promise<NoteStatusInfo> {
    try {
      const [consumed] = consumedNotePda(this.programId, noteCommitment);
      const [locked] = noteLockPda(this.programId, noteCommitment);
      const consumedInfo =
        await this.providers.accountInfoProvider.getAccountInfo(consumed);
      if (consumedInfo !== null) return { status: "consumed" };
      const lockInfo =
        await this.providers.accountInfoProvider.getAccountInfo(locked);
      if (lockInfo !== null) return { status: "locked" };
      return { status: "active" };
    } catch {
      return { status: "unknown" };
    }
  }
}

export function getDarkPoolClient(cfg: DarkPoolClientConfig): DarkPoolClient {
  return new DarkPoolClient(cfg);
}
