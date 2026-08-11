import type { StoredNote } from "@darknyx/sdk";

export type InventoryNoteState =
  | "spendable"
  | "reserved"
  | "pending_settlement"
  | "locked"
  | "consumed";

export interface InventoryNote extends Omit<StoredNote, "treeId"> {
  /** Browser inventory never guesses a shard; recovery must provide it. */
  treeId: number;
  /** Public consumption handle, derived and verified when the note enters inventory. */
  noteUseTag: string;
  state: InventoryNoteState;
  reservationId?: string;
}

export interface FinalizedRootRing {
  treeId: number;
  finalizedSlot: number;
  /** Current root followed by retained historical roots, newest first. */
  acceptedRoots: readonly string[];
}

export interface CachedInputProof {
  handle: string;
  cacheKey: string;
  noteCommitment: string;
  noteUseTag: string;
  treeId: number;
  merkleRoot: string;
  circuitVersion: string;
  provingKeyVersion: string;
  proofBytes: Uint8Array;
  createdAtMs: number;
  rootHistoryPosition: number;
  state: "ready" | "stale";
  invalidationReason?: "root_evicted" | "artifact_changed" | "note_consumed";
}

export interface InventoryReservation {
  reservationId: string;
  noteCommitment: string;
  proofHandle: string;
  createdAtMs: number;
}

export type BrowserOrderKind =
  | "submitting"
  | "open"
  | "pending_settlement"
  | "partially_filled"
  | "fully_filled"
  | "settlement_failed"
  | "cancelled"
  | "expired"
  | "ambiguous"
  | "rejected";

/** Encrypted lifecycle state. Raw note openings remain in the note collection. */
export interface BrowserOrderRecord {
  orderId: string;
  reservationId: string;
  noteCommitment: string;
  tradingIndex: number;
  /** Next strictly increasing u64 to burn before signing a cancellation. */
  nextCancelNonce: string;
  marketSymbol: string;
  side: "bid" | "ask";
  baseAmountAtoms: string;
  limitPriceTicks: string;
  kind: BrowserOrderKind;
  filledAtoms?: string;
  reason?: string;
  lockExpirySlot?: string;
  createdAtMs: number;
  updatedAtMs: number;
}

export interface InventorySnapshot {
  format: "darknyx-browser-inventory";
  version: 2;
  notes: InventoryNote[];
  proofs: CachedInputProof[];
  reservations: InventoryReservation[];
  roots: FinalizedRootRing[];
  orders: BrowserOrderRecord[];
  nextOrderIndex: number;
}

export interface BrowserMarketInventoryConfig {
  symbol: string;
  baseMintHex: string;
  quoteMintHex: string;
  priceScale: bigint;
  feeRateBps: bigint;
}

export interface InputProofRequest {
  note: InventoryNote;
  root: string;
  treeId: number;
  circuitVersion: string;
  provingKeyVersion: string;
}

export interface InputProofResult {
  /** `pi_a || pi_b || pi_c`, already in the vault verifier's 256-byte form. */
  proofBytes: Uint8Array;
}

export type InputProofProducer = (
  request: InputProofRequest,
) => Promise<InputProofResult>;

export interface RecoveryReport {
  /** Full scans replace absent notes; cursor-based scans merge their delta. */
  fullScan: boolean;
  notes: StoredNote[];
  recovered: {
    deposits: number;
    trade: number;
    change: number;
    merges: number;
  };
  unresolvedSettlements: number;
  unresolvedMerges: number;
}
