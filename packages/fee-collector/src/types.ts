export interface ScannedVaultInstruction {
  programId: string;
  /** Resolved account addresses in instruction order. */
  accounts: string[];
  data: Uint8Array;
}

/** One successful transaction returned at finalized commitment. */
export interface FinalizedVaultTransaction {
  signature: string;
  slot: number;
  instructions: ScannedVaultInstruction[];
  logMessages: string[];
}

export interface MarketIdentity {
  address: Uint8Array;
  baseMint: Uint8Array;
  quoteMint: Uint8Array;
}

export type MarketResolver = (address: string) => Promise<MarketIdentity>;

export interface FeeKeyMaterial {
  epoch: bigint;
  key: Uint8Array;
  binding: Uint8Array;
}

export type FeeKeyProvider = (epoch: bigint) => FeeKeyMaterial | null;

export type FeeSide = "base" | "quote";

export interface RecoveredFeeNote {
  epoch: bigint;
  batchRoot: Uint8Array;
  verifySignature: string;
  settleSignature: string;
  matchIndex: number;
  side: FeeSide;
  tokenMint: Uint8Array;
  amount: bigint;
  ownerCommitment: Uint8Array;
  innerHash: Uint8Array;
  commitment: Uint8Array;
  treeId: number;
  leafIndex: bigint;
}

export type UnresolvedFeeReason =
  | "missing_protocol_config"
  | "epoch_mismatch"
  | "missing_epoch_key"
  | "fee_key_binding_mismatch"
  | "market_config_unavailable"
  | "invalid_recovery_ciphertext"
  | "invalid_settlement_binding"
  | "missing_verify_record"
  | "commitment_mismatch"
  | "missing_settlement_event";

export interface UnresolvedFeeRecord {
  reason: UnresolvedFeeReason;
  signature: string;
  slot: number;
  epoch?: bigint;
  batchRoot?: Uint8Array;
  matchIndex?: number;
}

export interface FeeRecoveryResult {
  notes: RecoveredFeeNote[];
  unresolved: UnresolvedFeeRecord[];
  /** Nonzero encrypted slots for which no Tx D finalized. They minted nothing. */
  skippedUnsettledSlots: number;
}
