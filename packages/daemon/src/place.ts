/**
 * placeManagedOrder — the placement → lifecycle bridge.
 *
 * Given an already-built, signed {@link PlaceOrderRequest} (the caller runs
 * `proveAndBuildOrder`, which needs the keystore + note selection — a later
 * slice) and the {@link ManagedOrder} that tracks it, this:
 *
 *   1. `register`s the order (phase `pending`) so the engine can find it.
 *   2. submits it through the {@link OrderPlacer} (WS by default).
 *   3. on success, dispatches `accepted` (→ `open`) with the acceptance slot;
 *      on failure, dispatches `rejected` (→ `rejected`) and rethrows.
 *
 * Keeping body-building out of here preserves the seam: this is pure
 * orchestration over the engine + placer, unit-testable with fakes.
 */

import type { LifecycleEngine } from "./lifecycle-engine.js";
import type { OrderPlacer } from "./order-placer.js";
import type { ManagedOrder } from "./types.js";
import type { PlaceOrderRequest, PlaceOrderResponse } from "@nyx/sdk";

export interface PlaceManagedOrderArgs {
  engine: LifecycleEngine;
  placer: OrderPlacer;
  /** The pending order record to track (its `orderId` must match `request`). */
  order: ManagedOrder;
  /** The built + signed place body (`proveAndBuildOrder` output). */
  request: PlaceOrderRequest;
}

export async function placeManagedOrder(
  args: PlaceManagedOrderArgs,
): Promise<PlaceOrderResponse> {
  const { engine, placer, order, request } = args;
  engine.register(order);
  try {
    const resp = await placer.place(request);
    await engine.dispatch(order.orderId, {
      type: "accepted",
      arrivalSlot: resp.arrival_slot,
    });
    return resp;
  } catch (err) {
    await engine.dispatch(order.orderId, {
      type: "rejected",
      reason: err instanceof Error ? err.message : String(err),
    });
    throw err;
  }
}
