// Public SDK exports (TEE-v3 surface).
export * from "./errors.js";
export * from "./providers.js";
export * from "./keys/key-generators.js";
export * from "./keys/user-commitment.js";
export * from "./utxo/note.js";
export * from "./utxo/deposit.js";
export * from "./utxo/withdraw.js";
export * from "./utxo/note-store.js";
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
export * from "./fills/history.js";
export * from "./fills/ws-client.js";
export * from "./settlement/settle-builder.js";
export * from "./settlement/settlement-watcher.js";
