/** Browser-safe account-operation builders used by the trusted product layer. */
export {
  buildDepositInstruction,
  buildMergeInstruction,
  buildWithdrawInstruction,
  type BuildDepositParams,
  type BuildMergeParams,
  type BuildWithdrawParams,
} from "./idl/vault-client.js";
export { assertPublicInputs } from "./zk/assert-public-inputs.js";
export {
  noteCommitmentFromBytes,
  noteUseTagFromBytes,
} from "./utxo/note-identity.js";
export type {
  DepositInputs,
  Groth16ProofBytes,
  MergeInputs,
  SpendInputs,
} from "./zk/prover-suite.js";
