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
  deriveOwnerCommitmentBlinding,
  resolveMasterSeed,
} from "./keys/key-generators.js";
import type { IDarkPoolZkProverSuite } from "./zk/prover-suite.js";
import {
  consumedNotePda,
  noteLockPda,
  parseNoteLock,
} from "./idl/vault-client.js";
import { deriveNoteUseTag } from "./utxo/note-use.js";

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
  /** Blinding factor used for the user's owner_commitment. Omit to derive the
   * canonical wallet-level value from the master seed (required for seed-only
   * disaster recovery). An override creates a separately backed-up identity. */
  ownerCommitmentBlinding?: bigint;
}

export type NoteStatus = "active" | "locked" | "consumed" | "unknown";

export interface NoteStatusInfo {
  status: NoteStatus;
  /**
   * Only set when `status === "locked"`: the slot at and after which the lock
   * can be released with `buildReleaseLockInstruction`.
   */
  lockExpirySlot?: bigint;
  /**
   * Only set when `status === "locked"` and a current slot was resolvable:
   * whether the lock is already past its expiry, i.e. whether calling
   * `release_lock` would succeed right now.
   *
   * Audit 2026-07-25 S-03: this distinction was invisible before. A note left
   * locked by a failed settle looked identical to one locked by a live order,
   * and nothing in any shipped component could release either.
   */
  lockReleasable?: boolean;
}

export class DarkPoolClient {
  readonly programId: PublicKey;
  readonly connectionProvider: SolanaConnectionProvider;
  readonly providers: DarkPoolClientConfig["providers"];
  readonly zkProver: IDarkPoolZkProverSuite;
  private readonly seedMode: MasterSeedMode;
  private readonly tradingOffset: bigint;
  private resolvedSeed: Uint8Array | null = null;
  private readonly ownerBlinding?: bigint;

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

  async vaultConfigPda(): Promise<PublicKey> {
    const [pda] = await PublicKey.findProgramAddress(
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
      tradingKey: deriveTradingKeyAtOffset(
        this.resolvedSeed,
        this.tradingOffset,
      ),
      ownerBlinding:
        this.ownerBlinding ?? deriveOwnerCommitmentBlinding(this.resolvedSeed),
    };
  }

  /**
   * Return the current lifecycle state of a UTXO note.
   *   - "consumed" — a ConsumedNote PDA exists (already settled).
   *   - "locked"   — a NoteLock PDA exists but ConsumedNote does not.
   *   - "active"   — neither PDA exists. Safe to use for a new order.
   *   - "unknown"  — RPC read failed. Caller should retry or abort.
   *
   * Takes the note's COMMITMENT and its INNER HASH, not a pre-derived handle.
   * `ConsumedNoteEntry` and `NoteLock` are both seeded by the note-use TAG
   * (`Poseidon3(29, commitment, inner_hash)`), never by the commitment —
   * see CRYPTOGRAPHY.md §2.1. Both values are `[u8; 32]`, so a signature
   * taking one opaque handle lets a commitment be passed where a tag belongs:
   * that compiles, derives a plausible address no instruction ever writes,
   * and reports "active" for a note that is in fact consumed or locked —
   * which is exactly how a wallet ends up selecting a spent note. Requiring
   * both halves makes the wrong call impossible to express.
   */
  async getNoteStatus(
    noteCommitment: Uint8Array,
    innerHash: Uint8Array,
  ): Promise<NoteStatusInfo> {
    try {
      const noteUseTag = await deriveNoteUseTag(noteCommitment, innerHash);
      const [consumed] = await consumedNotePda(this.programId, noteUseTag);
      const [locked] = await noteLockPda(this.programId, noteUseTag);
      const consumedInfo =
        await this.providers.accountInfoProvider.getAccountInfo(consumed);
      if (consumedInfo !== null) return { status: "consumed" };
      const lockInfo =
        await this.providers.accountInfoProvider.getAccountInfo(locked);
      if (lockInfo !== null) {
        // Report WHETHER the lock is still effective, not merely that one
        // exists (S-03). An expired lock is recoverable with `release_lock`;
        // reporting both identically is what made the freeze look permanent.
        const parsed = lockInfo.data ? parseNoteLock(lockInfo.data) : null;
        if (parsed === null) return { status: "locked" };
        let releasable: boolean | undefined;
        try {
          const slot = await this.connectionProvider.connection.getSlot();
          releasable = BigInt(slot) >= parsed.expirySlot;
        } catch {
          // Slot unavailable — still report the expiry so the caller can
          // decide, but don't guess at releasability.
          releasable = undefined;
        }
        return {
          status: "locked",
          lockExpirySlot: parsed.expirySlot,
          lockReleasable: releasable,
        };
      }
      return { status: "active" };
    } catch {
      return { status: "unknown" };
    }
  }
}

export function getDarkPoolClient(cfg: DarkPoolClientConfig): DarkPoolClient {
  return new DarkPoolClient(cfg);
}
