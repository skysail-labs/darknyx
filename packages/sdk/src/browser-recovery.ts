/** Browser-safe, narrow entrypoint for seed-plus-chain note reconstruction. */
export {
  recoverNotesFromChain,
  type ColdRecoveryResult,
} from "./fills/cold-recovery.js";
export {
  makeConnectionScan,
  type ChainScan,
  type RawSettleTx,
} from "./fills/chain-history.js";
export type { StoredNote } from "./utxo/note-store.js";
