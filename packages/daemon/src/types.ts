/**
 * Daemon domain model.
 *
 * A {@link ManagedOrder} is the daemon's durable view of one order it placed on
 * behalf of the strategy: enough to drive the lifecycle state machine
 * (`order-lifecycle.ts`) and to recover after a crash (`store.ts`). The CVM is
 * the source of truth for matching; this record is the source of truth for the
 * daemon's *automation* decisions (when to top up anchors, when to consolidate
 * residual change notes).
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
  /** Fully filled — no further matching; only settlement + residuals remain. */
  | "filled"
  /** Cancelled by the strategy or by cancel-on-disconnect. */
  | "cancelled"
  /** Left the book on its time-in-force (TEE `/ws/orders` `expired`). */
  | "expired"
  /** CVM rejected the order at intake. */
  | "rejected"
  /** Terminal: settled, reconciled, residual change notes consolidated. */
  | "closed";

/** Phases from which the order can no longer be matched or revived. */
export const TERMINAL_PHASES: ReadonlySet<OrderPhase> = new Set<OrderPhase>([
  "cancelled",
  "expired",
  "rejected",
  "closed",
]);

/** Order side, mirrored from the SDK's `OrderSide` at the wire boundary. */
export type Side = "bid" | "ask";

export interface ManagedOrder {
  /** 16-byte order id, hex (the deterministic HD order id). */
  orderId: string;
  /** Master-seed order index used to derive `orderId` + the anchor pool. */
  seedIndex: number;
  side: Side;
  /** Strategy-supplied price/size (raw integer units) — for reporting only. */
  priceRaw: bigint;
  sizeRaw: bigint;
  phase: OrderPhase;
  /** Total anchors provisioned so far (initial pool + confirmed top-ups). */
  anchorPoolSize: number;
  /** Anchors consumed by fills (= highest observed `anchorIndex` + 1). */
  anchorsConsumed: number;
  /** Next anchor-topup nonce (monotone per order; never reused). */
  topupNonce: number;
  /** True while a top-up `POST` is in flight (suppresses duplicate intents). */
  topupInFlight: boolean;
  /** True while a consolidation merge is in flight. */
  mergeInFlight: boolean;
  /** Residual change notes awaiting consolidation. */
  pendingChangeNotes: number;
  /** Commitment (hex) of the note this order locked as collateral. The note is
   *  excluded from selection while the order rests, and pruned once a fill
   *  consumes it (rotated into a change note). */
  collateralCommitment?: string;
  createdAt: number;
  updatedAt: number;
}

/** A fresh managed order in the `pending` phase (pre-`POST /orders`). */
export function newManagedOrder(args: {
  orderId: string;
  seedIndex: number;
  side: Side;
  priceRaw: bigint;
  sizeRaw: bigint;
  /** Initial anchor-pool size (defaults to the SDK `ANCHOR_POOL_SIZE`). */
  anchorPoolSize: number;
  /** Commitment (hex) of the locked collateral note, if known at build time. */
  collateralCommitment?: string;
  now?: number;
}): ManagedOrder {
  const now = args.now ?? Date.now();
  return {
    orderId: args.orderId,
    seedIndex: args.seedIndex,
    side: args.side,
    priceRaw: args.priceRaw,
    sizeRaw: args.sizeRaw,
    phase: "pending",
    anchorPoolSize: args.anchorPoolSize,
    anchorsConsumed: 0,
    topupNonce: 0,
    topupInFlight: false,
    mergeInFlight: false,
    pendingChangeNotes: 0,
    collateralCommitment: args.collateralCommitment,
    createdAt: now,
    updatedAt: now,
  };
}
