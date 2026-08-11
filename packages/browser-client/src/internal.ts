/** Product-composition surface. Not exported from the package's public API. */
export { requestVaultInternal } from "./custody/browser-vault.js";
export {
  BrowserProverSuite,
  type BrowserProverOptions,
} from "./prover/browser-prover.js";
export {
  BrowserInventory,
  type BrowserInventoryOptions,
  type RecoveryConsumptionVerifier,
  type RecoveryLockVerifier,
} from "./inventory/browser-inventory.js";
export {
  EncryptedIndexedDbInventoryStore,
  InMemoryInventoryStore,
  type InventoryCipher,
  type InventoryCiphertext,
  type InventorySnapshotStore,
} from "./inventory/inventory-store.js";
export {
  inventoryStoreForVault,
  recoverBrowserInventory,
  type BrowserRecoveryOptions,
} from "./inventory/browser-recovery.js";
export { SolanaFinalizedRootSource } from "./inventory/finalized-root-source.js";
export {
  BrowserInputProofProducer,
  type BrowserInputProofProducerOptions,
} from "./inventory/input-proof-producer.js";
export type {
  BrowserMarketInventoryConfig,
  CachedInputProof,
  FinalizedRootRing,
  InputProofProducer,
  InventoryNote,
  RecoveryReport,
} from "./inventory/types.js";
export {
  bootstrapTrustedVenue,
  type BootstrapTrustedVenueOptions,
} from "./venue/trusted-venue.js";
export { SameOriginSessionBroker } from "./venue/session-broker.js";
export type {
  TrustedInstrument,
  TrustedVenueIdentity,
  TrustedVenueSession,
  VenueReleaseConfig,
  VenueTrustState,
} from "./venue/types.js";
export {
  ExternalWalletController,
  type ConnectedWalletView,
} from "./wallet/wallet-standard.js";
export {
  BrowserIntentAuthorizer,
  type BrowserIntentAuthorizerOptions,
} from "./trader/intent-authorizer.js";
export {
  BrowserOrderTransport,
  type BrowserTradingTransport,
} from "./trader/order-transport.js";
export {
  BrowserLifecycleStream,
  type BrowserLifecycleStreamOptions,
} from "./trader/lifecycle-stream.js";
export {
  createBrowserPrivateRuntime,
  type BrowserPrivateRuntime,
  type BrowserPrivateRuntimeOptions,
} from "./trader/runtime.js";
export {
  BrowserTraderController,
  decimalToAtoms,
  decimalToPriceTicks,
  type BrowserTraderControllerOptions,
} from "./trader/controller.js";
export {
  AccountOperationError,
  BrowserAccountOperations,
  type AccountOperationKind,
  type AccountOperationResult,
  type BrowserAccountOperationsOptions,
} from "./account/account-operations.js";
