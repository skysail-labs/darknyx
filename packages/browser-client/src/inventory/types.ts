import type { StoredNote } from "@darknyx/sdk";

export type InventoryNoteState =
  | "spendable"
  | "reserved"
  | "pending_settlement"
  | "locked"
  | "consumed";

export interface InventoryNote extends StoredNote {
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

export interface InventorySnapshot {
  format: "darknyx-browser-inventory";
  version: 1;
  notes: InventoryNote[];
  proofs: CachedInputProof[];
  reservations: InventoryReservation[];
  roots: FinalizedRootRing[];
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
