/** Node/snarkjs adapter for the recovery-safe VALID_DEPOSIT circuit. */

import { bn254ToBE32 } from "../keys/key-generators.js";
import { formatGroth16ForOnChain } from "./groth16-format.js";
import type {
  DepositInputs,
  Groth16ProofBytes,
  IDarkPoolZkProverSuite,
} from "./prover-suite.js";

export interface ValidDepositArtifacts {
  wasmPath: string;
  zkeyPath: string;
}

const same = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((value, index) => value === b[index]);

/** Build the `deposit` member of an `IDarkPoolZkProverSuite`. */
export function nodeValidDepositProver(
  artifacts: ValidDepositArtifacts,
): IDarkPoolZkProverSuite["deposit"] {
  return {
    async prove(inputs: DepositInputs): Promise<Groth16ProofBytes> {
      if (inputs.amount <= 0n || inputs.amount > 0xffff_ffff_ffff_ffffn) {
        throw new Error("VALID_DEPOSIT amount must be a positive u64");
      }
      const witness = {
        noteCommitment: inputs.noteCommitment.toString(),
        tokenMint: inputs.tokenMint.map(String),
        amount: inputs.amount.toString(),
        recoveryNonce: inputs.recoveryNonce.toString(),
        spendingKey: inputs.spendingKey.toString(),
        ownerCommitmentBlinding:
          inputs.ownerCommitmentBlinding.toString(),
      };
      const specifier = "snarkjs";
      const snarkjs = (await import(specifier)) as unknown as {
        groth16: {
          fullProve(
            input: unknown,
            wasm: string,
            zkey: string,
          ): Promise<{ proof: unknown; publicSignals: unknown }>;
        };
      };
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        witness,
        artifacts.wasmPath,
        artifacts.zkeyPath,
      );
      const { proof: onchain, publicInputsBE } = formatGroth16ForOnChain(
        proof as never,
        publicSignals as never,
      );
      const expected = [
        inputs.noteCommitment,
        inputs.tokenMint[0],
        inputs.tokenMint[1],
        inputs.amount,
        inputs.recoveryNonce,
      ].map(bn254ToBE32);
      if (
        publicInputsBE.length !== expected.length ||
        publicInputsBE.some((value, index) => !same(value, expected[index]))
      ) {
        throw new Error("VALID_DEPOSIT public-input ordering mismatch");
      }
      return {
        piA: onchain.piA,
        piB: onchain.piB,
        piC: onchain.piC,
        publicInputs: publicInputsBE,
      };
    },
  };
}
