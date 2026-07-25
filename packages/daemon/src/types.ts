/**
 * Daemon domain model.
 *
 * A {@link ManagedOrder} is the daemon's durable view of one order it placed on
 * behalf of the strategy: enough to drive the lifecycle state machine
 * (`order-lifecycle.ts`) and to recover after a crash (`store.ts`). The CVM is
 * the source of truth for matching; this record is the source of truth for the
 * daemon's automation decisions (when to consolidate residual change notes).
 *
 * Crypto material (seeds, keys, note openings) lives in the keystore + the
 * NoteStore, never here — a ManagedOrder only references notes by id.
 */

/** Lifecycle phase of a managed order inside the daemon. */
export type OrderPhase =
  /** Built + signed locally; `POST /orders` not yet acknowledged. */
  | "pending"
  /** Accepted by the CVM; resting or partially filled (still matchable). */
  | "open"
  /** Matched and reserved; quantities/fills wait for Tx D finality. */
  | "pending_settlement"
  /** Fully filled — no further matching; only settlement + residuals remain. */
  | "filled"
  /** Cancelled by the strategy or by cancel-on-disconnect. */
  | "cancelled"
  /** Left the book on its time-in-force (TEE `orders` channel `expired`). */
  | "expired"
  /** CVM rejected the order at intake. */
  | "rejected"
  /** Tx D definitively failed; a fresh signed order is required after unlock. */
  | "settlement_failed"
  /** Terminal: settled, reconciled, residual change notes consolidated. */
  | "closed";

/** Phases from which the order can no longer be matched or revived. */
export const TERMINAL_PHASES: ReadonlySet<OrderPhase> = new Set<OrderPhase>([
  "cancelled",
  "expired",
  "rejected",
  "settlement_failed",
  "closed",
]);

/** Order side, mirrored from the SDK's `OrderSide` at the wire boundary. */
export type Side = "bid" | "ask";

export interface ManagedOrder {
  /** 16-byte order id, hex (the deterministic HD order id). */
  orderId: string;
  /** Master-seed order index used to derive `orderId` + its trading key. */
  seedIndex: number;
  /** Canonical `/instruments` symbol of the isolated market book. */
  symbol: string;
  side: Side;
  /** Strategy-supplied price/size (raw integer units) — for reporting only. */
  priceRaw: bigint;
  sizeRaw: bigint;
  phase: OrderPhase;
  /** True while a consolidation merge is in flight. */
  mergeInFlight: boolean;
  /** Residual change notes awaiting consolidation. */
  pendingChangeNotes: number;
  /** Commitment (hex) of the note this order locked as collateral. The note is
   *  excluded from selection while the order rests, and pruned once a fill
   *  consumes it (rotated into a change note). */
  collateralCommitment?: string;
  /** Terminal settlement failure detail surfaced by the TEE. */
  settlementFailureReason?: string;
  /** Earliest Solana slot at which the failed collateral lock expires. */
  settlementUnlockSlot?: number;
  createdAt: number;
  updatedAt: number;
}

/** A fresh managed order in the `pending` phase (pre-`POST /orders`). */
export function newManagedOrder(args: {
  orderId: string;
  seedIndex: number;
  /** Defaults only for migration of pre-multi-market local records/tests. */
  symbol?: string;
  side: Side;
  priceRaw: bigint;
  sizeRaw: bigint;
  /** Commitment (hex) of the locked collateral note, if known at build time. */
  collateralCommitment?: string;
  now?: number;
}): ManagedOrder {
  const now = args.now ?? Date.now();
  return {
    orderId: args.orderId,
    seedIndex: args.seedIndex,
    symbol: args.symbol ?? "UNKNOWN",
    side: args.side,
    priceRaw: args.priceRaw,
    sizeRaw: args.sizeRaw,
    phase: "pending",
    mergeInFlight: false,
    pendingChangeNotes: 0,
    collateralCommitment: args.collateralCommitment,
    createdAt: now,
    updatedAt: now,
  };
}
