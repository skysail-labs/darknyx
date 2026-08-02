/** Side-effecting executor for lifecycle merge intents. Continuation pools
 * and their HTTP top-up endpoint were removed by canonical-order v2; residual
 * notes are now derived from consumed input inners and only consolidation
 * remains as daemon automation. */

import type { ManagedOrder } from "./types.js";
import type { ActionExecutor } from "./lifecycle-engine.js";
import type { LifecycleAction, LifecycleEvent } from "./order-lifecycle.js";

type MergeAction = Extract<LifecycleAction, { type: "merge" }>;

/** Consolidates up to `noteCount` residual change notes for an order on-chain. */
/** What one consolidation did. */
export interface MergeOutcome {
  /** Notes consolidated across the WHOLE account — selection is account-level. */
  consumed: number;
  /** The TRIGGER order's unspent residuals afterwards, read from the store.
   *  Reported separately because `consumed` spans many orders and subtracting
   *  it from one of them is what drifted (SW-13). */
  remaining: number;
}

export interface MergeRunner {
  run(order: ManagedOrder, noteCount: number): Promise<MergeOutcome>;
}

export interface ActionExecutorDeps {
  merge: MergeRunner;
}

export class DaemonActionExecutor implements ActionExecutor {
  constructor(private readonly deps: ActionExecutorDeps) {}

  async merge(
    order: ManagedOrder,
    action: MergeAction,
  ): Promise<LifecycleEvent> {
    const { remaining } = await this.deps.merge.run(order, action.noteCount);
    return { type: "merge-confirmed", remaining };
  }
}
