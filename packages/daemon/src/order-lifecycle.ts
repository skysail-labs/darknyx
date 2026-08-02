/**
 * Order-lifecycle state machine — the daemon's automation core.
 *
 * A **pure reducer**: `reduceOrder(order, event) -> { order, actions }`. It owns
 * the auto-merge decision that makes a persistent client worth running:
 * Partial fills shed residual change notes; left alone they
 *      fragment the UTXO set and force a fresh proof per future order. When
 *      enough accumulate (or the order goes quiescent with residuals left) the
 *      reducer emits a `merge` intent to consolidate them via VALID_MERGE,
 *      amortizing proving across many fills.
 *
 * Purity is the point: every transition is deterministic and side-effect-free,
 * so it's unit-testable with no CVM, and the daemon can replay events to
 * reconstruct state after a crash. The reducer never performs I/O — it returns
 * *intents*; the daemon executes them and feeds the result back as a follow-up
 * event (`merge-confirmed` / `merge-failed`).
 */

import {
  type ManagedOrder,
  type OrderPhase,
  TERMINAL_PHASES,
} from "./types.js";

/** Tunable automation thresholds (from {@link DaemonConfig}). */
export interface LifecycleThresholds {
  /** Consolidate once this many residual change notes accumulate. */
  mergeThreshold: number;
}

export const DEFAULT_THRESHOLDS: LifecycleThresholds = {
  // VALID_MERGE consolidates K=2/4; 4 residuals = one K=4 merge.
  mergeThreshold: 4,
};

/**
 * Events the daemon feeds the reducer. Two streams drive distinct concerns:
 * `fills` channel → recovered residuals (`fill`); `orders` channel → phase
 * (`accepted` / `filled` / `cancelled` / `expired`). They're deliberately
 * decoupled so neither stream double-drives the other.
 */
export type LifecycleEvent =
  // ── phase (placement ack + orders channel) ──
  | { type: "accepted"; arrivalSlot: number }
  | { type: "rejected"; reason: string }
  | { type: "settlement-pending"; lockExpirySlot: number }
  | { type: "partial-fill-confirmed" }
  | { type: "settlement-failed"; reason: string; lockExpirySlot: number }
  | { type: "filled" }
  | { type: "cancelled" }
  | { type: "expired" }
  // ── fill recovery (fills channel) ──
  /** A continuation fill produced a recoverable change note.
   * `producedChangeNote` is false on an exact fill. This carries NO phase
   *  meaning — the terminal `filled` comes from the orders channel. */
  | { type: "fill"; producedChangeNote: boolean }
  // ── action outcomes ──
  /** `remaining` is the trigger order's residual count AFTER the merge, read
   *  from the store. It replaced a cross-order `consumed` that was subtracted
   *  from one order and therefore drifted in both directions (SW-13). */
  | { type: "merge-confirmed"; remaining: number }
  | { type: "merge-failed" }
  /** Settlement reconciled + residuals consolidated → terminal `closed`. */
  | { type: "closed" };

/** Side-effecting intents the daemon must execute (then report back). */
export type LifecycleAction = {
  type: "merge";
  orderId: string;
  noteCount: number;
};

export interface ReduceResult {
  order: ManagedOrder;
  actions: LifecycleAction[];
}

const isTerminal = (p: OrderPhase): boolean => TERMINAL_PHASES.has(p);

/**
 * Apply one event to a managed order. Returns the new order plus any automation
 * intents derived from the *resulting* state. Pure: no mutation of `order`, no
 * I/O. `now` is injectable for deterministic tests.
 */
export function reduceOrder(
  order: ManagedOrder,
  event: LifecycleEvent,
  thresholds: LifecycleThresholds = DEFAULT_THRESHOLDS,
  now: number = Date.now(),
): ReduceResult {
  const next: ManagedOrder = { ...order, updatedAt: now };
  const actions: LifecycleAction[] = [];

  switch (event.type) {
    case "accepted":
      if (order.phase === "pending") next.phase = "open";
      break;

    case "rejected":
      if (order.phase === "pending") next.phase = "rejected";
      break;

    case "settlement-pending":
      if (order.phase === "pending" || order.phase === "open") {
        next.phase = "pending_settlement";
      }
      break;

    case "partial-fill-confirmed":
      if (
        order.phase === "pending" ||
        order.phase === "open" ||
        order.phase === "pending_settlement"
      ) {
        next.phase = "open";
      }
      break;

    case "settlement-failed":
      if (!isTerminal(order.phase)) {
        next.phase = "settlement_failed";
        next.settlementFailureReason = event.reason;
        next.settlementUnlockSlot = event.lockExpirySlot;
      }
      break;

    case "filled":
      // Terminal matching (from orders-channel `fully_filled`). Accept a still-
      // `pending` order too: a fully_filled implies it was accepted + filled.
      if (
        order.phase === "pending" ||
        order.phase === "open" ||
        order.phase === "pending_settlement"
      ) {
        next.phase = "filled";
      }
      break;

    case "cancelled":
      if (!isTerminal(order.phase)) next.phase = "cancelled";
      break;

    case "expired":
      if (!isTerminal(order.phase)) next.phase = "expired";
      break;

    case "fill": {
      if (event.producedChangeNote) {
        next.pendingChangeNotes = order.pendingChangeNotes + 1;
      }
      break;
    }

    case "merge-confirmed":
      // SET, never subtract: the runner reconciles from the store, which is the
      // authority for this order's unspent residuals.
      next.pendingChangeNotes = Math.max(0, event.remaining);
      next.mergeInFlight = false;
      break;

    case "merge-failed":
      next.mergeInFlight = false;
      break;

    case "closed":
      if (!isTerminal(order.phase)) next.phase = "closed";
      break;
  }

  // ── Derive automation intents from the NEW state ──
  //
  // Intents are EDGE-triggered: derived only from events that represent new
  // matching activity (`fill`) or the order going quiescent (`filled` /
  // `cancelled` / `expired`), NOT from action outcomes. This is what prevents a
  // a permanently-failing merge from hot-looping — clearing its in-flight
  // latch does not immediately re-fire the intent. The retry rides the next
  // fill or quiescent lifecycle transition.
  const triggersIntents =
    event.type === "fill" ||
    event.type === "filled" ||
    event.type === "cancelled" ||
    event.type === "expired" ||
    event.type === "settlement-failed";

  // Auto-merge: consolidate once enough residuals accumulate, or as soon as the
  // order stops matching (filled/cancelled/expired) with any residual left — no
  // point waiting for a quota that will never arrive. One merge in flight at a time.
  const quiescent =
    next.phase === "filled" ||
    next.phase === "cancelled" ||
    next.phase === "expired" ||
    next.phase === "settlement_failed";
  const shouldMerge =
    next.pendingChangeNotes >= thresholds.mergeThreshold ||
    (quiescent && next.pendingChangeNotes > 0);
  if (triggersIntents && shouldMerge && !next.mergeInFlight) {
    actions.push({
      type: "merge",
      orderId: next.orderId,
      noteCount: next.pendingChangeNotes,
    });
    next.mergeInFlight = true;
  }

  return { order: next, actions };
}
