/**
 * Order-lifecycle state machine — the daemon's automation core.
 *
 * A **pure reducer**: `reduceOrder(order, event) -> { order, actions }`. It owns
 * the two decisions that make a persistent client worth running (vs. a one-shot
 * `POST /orders`):
 *
 *   1. **Auto anchor top-up.** The `inner_hash`/anchor-pool design lets one
 *      VALID_INPUT proof back many partial fills (`ANCHOR_POOL_SIZE=10`
 *      continuations rotate the residual with no new proof). When the remaining
 *      anchors fall to the threshold the reducer emits a `topup` intent so
 *      matching never stalls on an exhausted pool (`POST /orders/{id}/anchors`,
 *      `ANCHOR_TOPUP_SIZE=5`).
 *   2. **Auto-merge.** Partial fills shed residual change notes; left alone they
 *      fragment the UTXO set and force a fresh proof per future order. When
 *      enough accumulate (or the order goes quiescent with residuals left) the
 *      reducer emits a `merge` intent to consolidate them via VALID_MERGE,
 *      amortizing proving across many fills.
 *
 * Purity is the point: every transition is deterministic and side-effect-free,
 * so it's unit-testable with no CVM, and the daemon can replay events to
 * reconstruct state after a crash. The reducer never performs I/O — it returns
 * *intents*; the daemon executes them and feeds the result back as a follow-up
 * event (`topup-confirmed` / `topup-failed` / `merge-confirmed` / `merge-failed`).
 */

import { ANCHOR_TOPUP_SIZE } from "@nyx/sdk";

import {
  type ManagedOrder,
  type OrderPhase,
  TERMINAL_PHASES,
} from "./types.js";

/** Tunable automation thresholds (from {@link DaemonConfig}). */
export interface LifecycleThresholds {
  /** Top up when remaining anchors (`poolSize - consumed`) ≤ this. */
  anchorTopUpThreshold: number;
  /** Anchors requested per top-up (mirrors the SDK `ANCHOR_TOPUP_SIZE`). */
  anchorTopUpSize: number;
  /** Consolidate once this many residual change notes accumulate. */
  mergeThreshold: number;
}

export const DEFAULT_THRESHOLDS: LifecycleThresholds = {
  // Top up with 3 anchors of headroom left — covers the ~1-2 fills that can
  // land while the async top-up round-trips.
  anchorTopUpThreshold: 3,
  anchorTopUpSize: ANCHOR_TOPUP_SIZE,
  // VALID_MERGE consolidates K=2/4; 4 residuals = one K=4 merge.
  mergeThreshold: 4,
};

/**
 * Events the daemon feeds the reducer. Two streams drive distinct concerns:
 * `/ws/fills` → anchor consumption (`fill`); `/ws/orders` → phase
 * (`accepted` / `filled` / `cancelled` / `expired`). They're deliberately
 * decoupled so neither stream double-drives the other.
 */
export type LifecycleEvent =
  // ── phase (placement ack + /ws/orders) ──
  | { type: "accepted"; arrivalSlot: number }
  | { type: "rejected"; reason: string }
  | { type: "filled" }
  | { type: "cancelled" }
  | { type: "expired" }
  // ── anchor consumption (/ws/fills) ──
  /** A continuation fill consumed anchor `anchorIndex`. `producedChangeNote`
   *  is false on an exact fill (no residual minted). This carries NO phase
   *  meaning — the terminal `filled` comes from `/ws/orders`. */
  | { type: "fill"; anchorIndex: number; producedChangeNote: boolean }
  // ── action outcomes ──
  | { type: "topup-confirmed"; count: number }
  | { type: "topup-failed" }
  | { type: "merge-confirmed"; consumed: number }
  | { type: "merge-failed" }
  /** Settlement reconciled + residuals consolidated → terminal `closed`. */
  | { type: "closed" };

/** Side-effecting intents the daemon must execute (then report back). */
export type LifecycleAction =
  | {
      type: "topup";
      orderId: string;
      /** Anchor index to start the new batch at (continues the sequence). */
      startIndex: number;
      count: number;
      nonce: number;
    }
  | { type: "merge"; orderId: string; noteCount: number };

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

    case "filled":
      // Terminal matching (from /ws/orders `fully_filled`). Accept a still-
      // `pending` order too: a fully_filled implies it was accepted + filled.
      if (order.phase === "pending" || order.phase === "open") {
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
      // Anchor consumption ONLY — no phase meaning (the terminal `filled`
      // comes from /ws/orders). anchorsConsumed is the high-water mark, since
      // fills can arrive out of order.
      next.anchorsConsumed = Math.max(
        order.anchorsConsumed,
        event.anchorIndex + 1,
      );
      if (event.producedChangeNote) {
        next.pendingChangeNotes = order.pendingChangeNotes + 1;
      }
      break;
    }

    case "topup-confirmed":
      next.anchorPoolSize = order.anchorPoolSize + event.count;
      next.topupInFlight = false;
      next.topupNonce = order.topupNonce + 1;
      break;

    case "topup-failed":
      // Clear the in-flight latch so the next fill can re-emit the intent.
      next.topupInFlight = false;
      break;

    case "merge-confirmed":
      next.pendingChangeNotes = Math.max(
        0,
        order.pendingChangeNotes - event.consumed,
      );
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
  // permanently-failing top-up from hot-looping — clearing the in-flight latch
  // on `topup-failed` does NOT immediately re-fire the intent; the retry rides
  // the next fill (which only pushes `remaining` lower, so it WILL re-trigger).
  // Same for merge.
  const triggersIntents =
    event.type === "fill" ||
    event.type === "filled" ||
    event.type === "cancelled" ||
    event.type === "expired";

  // Auto anchor top-up: only while the order can still match, and only one
  // top-up in flight at a time (the latch prevents a burst of fills from each
  // firing a redundant POST).
  const remaining = next.anchorPoolSize - next.anchorsConsumed;
  if (
    triggersIntents &&
    next.phase === "open" &&
    !next.topupInFlight &&
    remaining <= thresholds.anchorTopUpThreshold
  ) {
    actions.push({
      type: "topup",
      orderId: next.orderId,
      startIndex: next.anchorPoolSize,
      count: thresholds.anchorTopUpSize,
      nonce: next.topupNonce,
    });
    next.topupInFlight = true;
  }

  // Auto-merge: consolidate once enough residuals accumulate, or as soon as the
  // order stops matching (filled/cancelled/expired) with any residual left — no
  // point waiting for a quota that will never arrive. One merge in flight at a time.
  const quiescent =
    next.phase === "filled" ||
    next.phase === "cancelled" ||
    next.phase === "expired";
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
