import type {
  StreamChannel,
  StreamChannelHooks,
  StreamChannelSubscription,
} from "@darknyx/sdk/browser-orders";

import type { BrowserInventory } from "../inventory/browser-inventory.js";
import type { BrowserOrderKind } from "../inventory/types.js";

const ORDER_ID = /^[0-9a-f]{32}$/;
const UPDATE_KINDS = new Set<BrowserOrderKind>([
  "pending_settlement",
  "partially_filled",
  "fully_filled",
  "settlement_failed",
  "cancelled",
  "expired",
]);

export interface LifecycleStreamClient {
  subscribeChannel(
    channel: StreamChannel,
    onMessage: (frame: unknown) => void,
    hooks?: StreamChannelHooks,
  ): StreamChannelSubscription;
}

export interface BrowserLifecycleStreamOptions {
  stream: LifecycleStreamClient;
  inventory: BrowserInventory;
  /** Finalized-chain authority used after fills, gaps, and ambiguous state. */
  reconcile(reason: string): Promise<void>;
  onChange?(): void;
  onError?(error: Error): void;
}

interface ValidOrderUpdate {
  orderId: string;
  kind: BrowserOrderKind;
  filledAtoms?: string;
  reason?: string;
  lockExpirySlot?: string;
}

function optionalSafeU64(value: unknown, label: string): string | undefined {
  if (value === undefined) return undefined;
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new Error(`${label} must be a non-negative safe integer`);
  }
  return String(value);
}

function parseOrderUpdate(frame: unknown): ValidOrderUpdate {
  if (!frame || typeof frame !== "object") {
    throw new Error("order update must be an object");
  }
  const value = frame as Record<string, unknown>;
  if (typeof value.order_id !== "string" || !ORDER_ID.test(value.order_id)) {
    throw new Error("order update has an invalid order id");
  }
  if (
    typeof value.kind !== "string" ||
    !UPDATE_KINDS.has(value.kind as BrowserOrderKind)
  ) {
    throw new Error("order update has an invalid lifecycle kind");
  }
  if (value.reason !== undefined && typeof value.reason !== "string") {
    throw new Error("order update reason must be a string");
  }
  return {
    orderId: value.order_id,
    kind: value.kind as BrowserOrderKind,
    filledAtoms: optionalSafeU64(value.filled_quantity, "filled quantity"),
    reason: value.reason as string | undefined,
    lockExpirySlot: optionalSafeU64(value.lock_expiry_slot, "lock expiry slot"),
  };
}

/**
 * Owns the page's two lifecycle subscriptions on one authenticated stream.
 * Stream messages are notifications only: gaps and fills always defer to a
 * finalized-chain reconciler before collateral is made reusable.
 */
export class BrowserLifecycleStream {
  readonly #options: BrowserLifecycleStreamOptions;
  readonly #subscriptions: StreamChannelSubscription[] = [];
  #reconcilePromise: Promise<void> | null = null;
  #closed = false;

  constructor(options: BrowserLifecycleStreamOptions) {
    this.#options = options;
  }

  start(): void {
    if (this.#closed) throw new Error("lifecycle stream is closed");
    if (this.#subscriptions.length > 0) return;
    const hooks: StreamChannelHooks = {
      onResync: (reason) => void this.reconcile(`stream resync: ${reason}`),
      onClose: (code, reason) => {
        if (code === 1011) {
          void this.reconcile(`stream lagged: ${reason ?? "no reason"}`);
        }
      },
    };
    this.#subscriptions.push(
      this.#options.stream.subscribeChannel(
        "orders",
        (frame) => void this.#handleOrderFrame(frame),
        hooks,
      ),
      this.#options.stream.subscribeChannel(
        "fills",
        () => void this.reconcile("fill notification"),
        hooks,
      ),
    );
  }

  async #handleOrderFrame(frame: unknown): Promise<void> {
    try {
      const update = parseOrderUpdate(frame);
      const order = await this.#options.inventory.order(update.orderId);
      if (!order) {
        await this.reconcile("unknown order update");
        return;
      }
      await this.#options.inventory.updateOrder(update.orderId, {
        kind: update.kind,
        filledAtoms: update.filledAtoms,
        reason: update.reason,
        lockExpirySlot: update.lockExpirySlot,
      });
      switch (update.kind) {
        case "pending_settlement":
          await this.#options.inventory.markPendingSettlement(
            order.reservationId,
          );
          break;
        case "partially_filled":
        case "fully_filled":
          await this.#options.inventory.markConsumed(order.noteCommitment);
          await this.reconcile(`order ${update.kind}`);
          break;
        case "settlement_failed":
          await this.#options.inventory.markOrderLocked(update.orderId);
          break;
        case "cancelled":
        case "expired":
          await this.#options.inventory.releaseReservation(order.reservationId);
          break;
      }
      this.#options.onChange?.();
    } catch (error) {
      this.#options.onError?.(
        error instanceof Error ? error : new Error(String(error)),
      );
      await this.reconcile("malformed or inconsistent order update");
    }
  }

  reconcile(reason: string): Promise<void> {
    if (this.#closed) return Promise.resolve();
    if (this.#reconcilePromise) return this.#reconcilePromise;
    this.#reconcilePromise = this.#options
      .reconcile(reason)
      .then(() => this.#options.onChange?.())
      .catch((error) => {
        this.#options.onError?.(
          error instanceof Error ? error : new Error(String(error)),
        );
      })
      .finally(() => {
        this.#reconcilePromise = null;
      });
    return this.#reconcilePromise;
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    for (const subscription of this.#subscriptions) subscription.close();
    this.#subscriptions.length = 0;
  }
}

export const lifecycleInternals = { parseOrderUpdate };
