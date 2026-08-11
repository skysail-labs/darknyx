import type {
  AuthorizedIntentEnvelope,
  IntentTransportPort,
  TransportSubmissionOutcome,
} from "@darknyx/client-core/internal";
import {
  DarknyxApiError,
  type CancelOrderRequest,
  type PlaceOrderRequest,
  type PlaceOrderResponse,
} from "@darknyx/sdk/browser-orders";

import type { BrowserInventory } from "../inventory/browser-inventory.js";

const ORDER_ID = /^[0-9a-f]{32}$/;

export interface BrowserTradingTransport {
  place(order: PlaceOrderRequest): Promise<PlaceOrderResponse>;
  cancel(
    orderId: string,
    request: CancelOrderRequest,
  ): Promise<{ order_id: string; status: string }>;
}

function decodeOrderBody(
  envelope: AuthorizedIntentEnvelope,
): PlaceOrderRequest {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder().decode(envelope.body));
  } catch {
    throw new Error("authorized order envelope is not JSON");
  }
  if (
    !value ||
    typeof value !== "object" ||
    !("order_id" in value) ||
    value.order_id !== envelope.clientOrderId ||
    !ORDER_ID.test(envelope.clientOrderId)
  ) {
    throw new Error("authorized order envelope has the wrong order id");
  }
  return value as PlaceOrderRequest;
}

/** Settlement-safe transport: network failures become ambiguous, never rejected. */
export class BrowserOrderTransport implements IntentTransportPort {
  constructor(
    readonly client: BrowserTradingTransport,
    readonly inventory: BrowserInventory,
  ) {}

  async submitAuthorized(
    envelope: AuthorizedIntentEnvelope,
  ): Promise<TransportSubmissionOutcome> {
    const body = decodeOrderBody(envelope);
    try {
      const result = await this.client.place(body);
      if (result.order_id !== envelope.clientOrderId) {
        await this.inventory.updateOrder(envelope.clientOrderId, {
          kind: "ambiguous",
          reason: "Venue acknowledged a different order identifier",
        });
        return { status: "ambiguous", orderId: envelope.clientOrderId };
      }
      await this.inventory.updateOrder(envelope.clientOrderId, {
        kind: "open",
      });
      return { status: "accepted", orderId: result.order_id };
    } catch (error) {
      if (
        error instanceof DarknyxApiError &&
        error.status < 500 &&
        error.status !== 408 &&
        error.status !== 429
      ) {
        await this.inventory.updateOrder(envelope.clientOrderId, {
          kind: "rejected",
          reason: error.message,
        });
        const order = await this.inventory.order(envelope.clientOrderId);
        if (order) {
          await this.inventory.releaseReservation(order.reservationId);
        }
        return { status: "rejected" };
      }
      await this.inventory.updateOrder(envelope.clientOrderId, {
        kind: "ambiguous",
        reason: "Placement response was not observed; reconciliation required",
      });
      return { status: "ambiguous", orderId: envelope.clientOrderId };
    }
  }

  async cancel(
    orderId: string,
    request: CancelOrderRequest,
  ): Promise<"cancelled" | "ambiguous"> {
    try {
      const result = await this.client.cancel(orderId, request);
      if (result.order_id !== orderId || result.status !== "cancelled") {
        const reason =
          result.order_id !== orderId
            ? "Venue returned an inconsistent cancellation order identifier"
            : `Venue returned unexpected cancellation status ${result.status}`;
        await this.inventory.updateOrder(orderId, {
          kind: "ambiguous",
          reason,
        });
        return "ambiguous";
      }
      await this.inventory.updateOrder(orderId, { kind: "cancelled" });
      const order = await this.inventory.order(orderId);
      if (order) await this.inventory.releaseReservation(order.reservationId);
      return "cancelled";
    } catch (error) {
      if (
        error instanceof DarknyxApiError &&
        error.status < 500 &&
        error.status !== 408 &&
        error.status !== 429
      ) {
        throw error;
      }
      await this.inventory.updateOrder(orderId, {
        kind: "ambiguous",
        reason: "Cancellation response was not observed; reconciling",
      });
      return "ambiguous";
    }
  }
}
