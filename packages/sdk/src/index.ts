// Public SDK exports.
export * from "./errors.js";
export * from "./providers.js";
export * from "./keys/key-generators.js";
export * from "./keys/viewing-keys.js";
export * from "./keys/key-rotation.js";
export * from "./keys/user-commitment.js";
export * from "./utxo/note.js";
export * from "./utxo/deposit.js";
export * from "./utxo/withdraw.js";
export * from "./zk/prover-suite.js";
export * from "./zk/groth16-format.js";
export * from "./idl/vault-client.js";
export * from "./idl/matching-engine-client.js";
export * from "./idl/seeds.js";
export * from "./client.js";
export * from "./per/attestation.js";
export * from "./per/session-manager.js";
export * from "./orders/submit-order.js";
export * from "./orders/cancel-order.js";
// `OrderType` is already exported by `./idl/matching-engine-client.js`
// (the on-chain enum); re-export the canonical encoder under
// distinct aliases to avoid a double-export, while keeping the
// canonical-only types visible to consumers.
export {
  ORDER_DOMAIN,
  CANCEL_DOMAIN,
  SYMBOL_MAX_LEN,
  CanonicalError,
  orderCanonicalBytes,
  orderCanonicalDigest,
  cancelCanonicalBytes,
  cancelCanonicalDigest,
  OrderSide as CanonicalOrderSide,
  OrderType as CanonicalOrderType,
  type OrderCanonical,
  type CancelCanonical,
} from "./orders/canonical.js";
export * from "./batch/inclusion-proof.js";
export * from "./settlement/settle-builder.js";
export * from "./settlement/settlement-watcher.js";
