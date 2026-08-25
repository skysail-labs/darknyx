/**
 * Browser-safe order construction and authenticated transport surface.
 *
 * This entrypoint deliberately excludes Node proving adapters and filesystem
 * helpers. Canonical digests use noble SHA-256, so a browser product does not
 * need a `node:crypto` polyfill to sign an order or cancellation.
 */
export { OrderSide, OrderType } from "./orders/canonical.js";
export {
  buildOrder,
  type BuildOrderArgs,
  type PlaceOrderRequest,
} from "./orders/build-order.js";
export { MAX_ORDER_TTL_SLOTS, gtcExpirySlot } from "./orders/builders.js";
export {
  buildCancel,
  DarknyxApiError,
  type CancelOrderRequest,
  type PlaceOrderResponse,
} from "./orders/order-client.js";
export {
  TradingClient,
  type SendableWebSocketFactory,
  type StreamChannel,
  type StreamChannelHooks,
  type StreamChannelSubscription,
  type TradingClientOptions,
} from "./orders/trading-ws-client.js";
export {
  subscribeOrderUpdates,
  isTerminalUpdate,
  type OrderUpdate,
  type OrderUpdatesSubscription,
} from "./orders/orders-ws-client.js";

export {
  bn254ToBE32,
  deriveOrderId,
  deriveSpendingKey,
  deriveTradingKeyAtOffset,
  deriveViewingEncKeypair,
} from "./keys/key-generators.js";
