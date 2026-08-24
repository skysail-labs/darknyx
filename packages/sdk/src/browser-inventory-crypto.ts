/** Browser-safe primitives used to verify recovered inventory records. */
export {
  bn254ToBE32,
  deriveBlindingFactor,
  generateRecoveryNonce,
  deriveNoteSecret,
  deriveOwnerCommitmentBlinding,
  deriveSpendingKey,
} from "./keys/key-generators.js";
export { deriveNoteUseTag } from "./utxo/note-use.js";
export {
  noteCommitmentV2,
  nullifierV2,
  ownerCommitment,
  pubkeyToFrPair,
} from "./utxo/note.js";
export { deriveMergeOutputInnerHash } from "./utxo/merge-inner.js";
export { deriveDepositInnerHash } from "./utxo/deposit-inner.js";
export type { StoredNote } from "./utxo/note-store.js";
export {
  consumedNotePda,
  merkleTreePda,
  noteLockPda,
} from "./idl/vault-client.js";
