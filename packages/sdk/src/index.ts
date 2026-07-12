// Public SDK exports (TEE-v3 surface).
export * from "./errors.js";
export * from "./providers.js";
export * from "./keys/key-generators.js";
export * from "./keys/fill-encryption.js";
export * from "./keys/user-commitment.js";
export * from "./utxo/note.js";
export * from "./utxo/deposit.js";
export * from "./utxo/withdraw.js";
export * from "./utxo/note-store.js";
export * from "./utxo/merge.js";
export * from "./wallet/wallet.js";
export * from "./zk/prover-suite.js";
export * from "./zk/groth16-format.js";
export * from "./idl/vault-client.js";
export * from "./idl/seeds.js";
export * from "./client.js";
// Order canonical encoders + the anchor-pool / fill-memo client surface.
export {
  ORDER_DOMAIN,
  CANCEL_DOMAIN,
  ANCHOR_TOPUP_DOMAIN,
  ANCHOR_POOL_SIZE,
  ANCHOR_TOPUP_SIZE,
  SYMBOL_MAX_LEN,
  CanonicalError,
  OrderSide,
  OrderType,
  orderCanonicalBytes,
  orderCanonicalDigest,
  cancelCanonicalBytes,
  cancelCanonicalDigest,
  anchorPoolHash,
  anchorTopUpCanonicalBytes,
  anchorTopUpCanonicalDigest,
  type OrderCanonical,
  type CancelCanonical,
  type AnchorTopUpCanonical,
  type Anchor,
} from "./orders/canonical.js";
export * from "./orders/anchor-pool.js";
export * from "./orders/fill-memo.js";
// Order-builder sugar (market / AON / FOK / GTT presets) + the per-account
// order-lifecycle WS client + the public system endpoints.
export * from "./orders/builders.js";
export * from "./orders/orders-ws-client.js";
export * from "./system/system-client.js";
// Order submission (Phase 5 / D2): buildOrder assembly, the VALID_INPUT prover
// + witness fetch, and the REST + /ws/trading submit clients.
export * from "./orders/build-order.js";
export * from "./orders/order-client.js";
export * from "./orders/trading-ws-client.js";
export * from "./zk/valid-input-prover.js";
export * from "./fills/history.js";
export * from "./fills/chain-history.js";
export * from "./fills/recover.js";
export * from "./utxo/change-note.js";
export * from "./fills/ws-client.js";
export * from "./settlement/settle-builder.js";
export * from "./settlement/settlement-watcher.js";
// TEE attestation — shared verification core (event-log RTMR3 replay,
// report_data binding, measurement pinning) used by the daemon + browser SDK.
export * from "./tee/verify-core.js";
