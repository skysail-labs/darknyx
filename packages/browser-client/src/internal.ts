/** Product-composition surface. Not exported from the package's public API. */
export {
  BrowserProverSuite,
  type BrowserProverOptions,
} from "./prover/browser-prover.js";
export {
  BrowserInventory,
  type BrowserInventoryOptions,
  type RecoveryConsumptionVerifier,
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
