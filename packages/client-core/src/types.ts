export type JsonPrimitive = string | number | boolean | null;
export type JsonValue =
  | JsonPrimitive
  | readonly JsonValue[]
  | Readonly<{ [key: string]: JsonValue }>;

export interface TraderIntentDraft {
  /** Canonical order-schema version understood by the selected CVM. */
  readonly protocolVersion: number;
  /** Uppercase base-quote symbol, for example `SOL-USDC`. */
  readonly marketSymbol: string;
  readonly side: "bid" | "ask";
  /** Positive canonical u64 string in base-token atomic units. */
  readonly baseAmountAtoms: string;
  /**
   * Canonical u64 string in the market's configured price ticks. Ask-side
   * market orders use `"0"` as the sentinel for selling at any clearing price.
   */
  readonly limitPriceTicks: string;
  /** Versioned extension surface. Unknown keys are preserved, never dropped. */
  readonly attributes: Readonly<Record<string, JsonValue>>;
}

export interface BalanceView {
  mint: string;
  spendableAtoms: string;
  reservedAtoms: string;
  pendingSettlementAtoms: string;
}

export interface ProofReadinessView {
  ready: number;
  proving: number;
  stale: number;
  /** Earliest accepted-root eviction slot among ready proofs, when known. */
  earliestExpirySlot?: string;
}

export type IntentRejectionCode =
  | "INVALID_INTENT"
  | "AUTHORIZATION_FAILED"
  | "VENUE_REJECTED";

export type IntentPendingReason =
  | "PROOF_NOT_READY"
  | "INVENTORY_UNAVAILABLE"
  | "TRANSPORT_AMBIGUOUS"
  | "LOCAL_RECONCILIATION_REQUIRED";

export type SubmitIntentResult =
  | {
      status: "accepted";
      orderId: string;
    }
  | {
      status: "pending";
      reason: IntentPendingReason;
      retryAfterMs?: number;
      orderId?: string;
    }
  | {
      status: "rejected";
      code: IntentRejectionCode;
      retryable: boolean;
    };

export interface TraderClientPort {
  /** Aggregate balances only; decrypted note records never enter page UI. */
  balances(): Promise<readonly BalanceView[]>;
  proofReadiness(): Promise<ProofReadinessView>;
  submitIntent(draft: TraderIntentDraft): Promise<SubmitIntentResult>;
}

export type VaultState = "unprovisioned" | "locked" | "unlocked" | "busy";

export interface VaultStatus {
  state: VaultState;
  operation?: "provision" | "unlock" | "backup" | "restore";
}

export interface EncryptedSeedBackupV2 {
  format: "darknyx-master-seed-backup";
  version: 2;
  kdf: {
    name: "scrypt";
    n: number;
    r: number;
    p: number;
    salt: string;
  };
  cipher: {
    name: "aes-256-gcm";
    iv: string;
    ciphertext: string;
    tag: string;
  };
}

/**
 * The only custody lifecycle exposed outside the trusted client core.
 * Deliberately absent: raw seed export, witness access, generic sign(bytes),
 * and arbitrary prove calls.
 */
export interface VaultLifecyclePort {
  status(): Promise<VaultStatus>;
  provision(label: string): Promise<void>;
  unlock(): Promise<void>;
  lock(): Promise<void>;
  exportBackup(passphrase: string): Promise<EncryptedSeedBackupV2>;
  restoreBackup(
    backup: EncryptedSeedBackupV2,
    passphrase: string,
    label: string,
  ): Promise<void>;
}
