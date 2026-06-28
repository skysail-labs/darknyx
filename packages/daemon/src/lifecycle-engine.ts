/**
 * LifecycleEngine — the daemon's event loop around the pure reducer.
 *
 * `order-lifecycle.ts` decides *what* should happen (returns intents);
 * this engine makes it happen: it persists every transition to the
 * {@link DaemonStore} and hands each intent to an injectable
 * {@link ActionExecutor}, then folds the executor's outcome back in as a
 * follow-up event. That keeps the side-effecting, CVM-touching code (the
 * executor) cleanly separable + mockable, while the engine itself stays small
 * and deterministic.
 *
 * Concurrency: a single `dispatch` does read → `reduceOrder` → `putOrder` with
 * **no `await` in between**, so on Node's single thread each transition is
 * atomic w.r.t. the store. Actions run detached (`runAction`) and re-enter
 * `dispatch` later with fresh state — so interleaved fills + action outcomes
 * compose correctly without a lock.
 */

import { DaemonStore } from "./store.js";
import type { ManagedOrder } from "./types.js";
import {
  DEFAULT_THRESHOLDS,
  reduceOrder,
  type LifecycleAction,
  type LifecycleEvent,
  type LifecycleThresholds,
} from "./order-lifecycle.js";

type TopupAction = Extract<LifecycleAction, { type: "topup" }>;
type MergeAction = Extract<LifecycleAction, { type: "merge" }>;

/**
 * Executes the reducer's side-effecting intents against the CVM/SDK. Each
 * method resolves with the **follow-up event** to fold back in (e.g. a `topup`
 * resolves to `topup-confirmed` on success or `topup-failed` otherwise) — so a
 * throw is never required for the unhappy path, though the engine also catches
 * throws and converts them to the matching `*-failed` event.
 */
export interface ActionExecutor {
  topup(order: ManagedOrder, action: TopupAction): Promise<LifecycleEvent>;
  merge(order: ManagedOrder, action: MergeAction): Promise<LifecycleEvent>;
}

export interface LifecycleEngineOptions {
  thresholds?: LifecycleThresholds;
  /** Surfaced for unexpected executor throws (after they're converted to a
   *  `*-failed` event). Defaults to `console.error`. */
  onError?: (err: unknown, context: string) => void;
}

export class LifecycleEngine {
  private readonly thresholds: LifecycleThresholds;
  private readonly onError: (err: unknown, context: string) => void;

  constructor(
    private readonly store: DaemonStore,
    private readonly executor: ActionExecutor,
    opts: LifecycleEngineOptions = {},
  ) {
    this.thresholds = opts.thresholds ?? DEFAULT_THRESHOLDS;
    this.onError =
      opts.onError ?? ((err, ctx) => console.error(`[daemon] ${ctx}:`, err));
  }

  /** Persist a freshly built (pending) order so `dispatch` can find it. */
  register(order: ManagedOrder): void {
    this.store.putOrder(order);
  }

  /**
   * Apply one event to `orderId`: reduce → persist → fire any resulting
   * actions. Resolves with the new order state. Action execution is detached;
   * its outcome arrives as a later `dispatch`. Throws only if the order is
   * unknown.
   */
  async dispatch(
    orderId: string,
    event: LifecycleEvent,
    now: number = Date.now(),
  ): Promise<ManagedOrder> {
    const current = this.store.getOrder(orderId);
    if (!current) {
      throw new Error(`dispatch: unknown order ${orderId}`);
    }
    // Atomic: no await between read and write.
    const { order, actions } = reduceOrder(
      current,
      event,
      this.thresholds,
      now,
    );
    this.store.putOrder(order);

    for (const action of actions) {
      // Detached — the engine doesn't block one order's fills on its top-up
      // POST. Errors are caught inside runAction.
      void this.runAction(order, action);
    }
    return order;
  }

  private async runAction(
    order: ManagedOrder,
    action: LifecycleAction,
  ): Promise<void> {
    try {
      const followUp =
        action.type === "topup"
          ? await this.executor.topup(order, action)
          : await this.executor.merge(order, action);
      await this.dispatch(order.orderId, followUp);
    } catch (err) {
      this.onError(err, `executor.${action.type} for ${order.orderId}`);
      // Convert a throw into the matching failure event so the in-flight latch
      // clears and the next fill can retry.
      const failure: LifecycleEvent =
        action.type === "topup"
          ? { type: "topup-failed" }
          : { type: "merge-failed" };
      try {
        await this.dispatch(order.orderId, failure);
      } catch (e2) {
        this.onError(e2, `recovering ${action.type} failure`);
      }
    }
  }
}
