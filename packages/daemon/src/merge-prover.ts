/**
 * nodeMergeProver — an in-process snarkjs VALID_MERGE prover suite.
 *
 * Implements the SDK `IDarkPoolZkProverSuite` for the daemon's auto-merge: maps
 * `MergeInputs` (which the SDK `getMergeFunction` assembles) onto the merge
 * circuit's witness, proves k=2/4 in-process via snarkjs, and returns the
 * on-chain proof bytes. walletCreate/spend are stubbed — the daemon's merge
 * client only ever proves merges.
 *
 * Proof format matches the validated devnet/CVM merge path: `formatGroth16ForOnChain`
 * (negated pi_a) fed straight into `buildMergeInstruction`.
 */

import {
  formatGroth16ForOnChain,
  type Groth16ProofBytes,
  type IDarkPoolZkProverSuite,
  type MergeInputs,
} from "@nyx/sdk";

export interface MergeCircuitArtifacts {
  k2: { wasmPath: string; zkeyPath: string };
  k4: { wasmPath: string; zkeyPath: string };
}

function stub(name: string) {
  return {
    prove: async (): Promise<Groth16ProofBytes> => {
      throw new Error(`${name}.prove: merge-only prover suite`);
    },
  };
}

export function nodeMergeProver(
  artifacts: MergeCircuitArtifacts,
): IDarkPoolZkProverSuite {
  return {
    walletCreate: stub("walletCreate"),
    spend: stub("spend"),
    merge: {
      async prove(inputs: MergeInputs): Promise<Groth16ProofBytes> {
        const art = inputs.k === 2 ? artifacts.k2 : artifacts.k4;
        const witness = {
          merkleRoot: inputs.merkleRoot.toString(),
          tokenMint: inputs.tokenMint.map((x) => x.toString()),
          spendingKey: inputs.spendingKey.toString(),
          ownerCommitmentBlinding: inputs.ownerCommitmentBlinding.toString(),
          isActive: inputs.isActive.map((x) => x.toString()),
          amount: inputs.amount.map((x) => x.toString()),
          innerHash: inputs.innerHash.map((x) => x.toString()),
          merklePath: inputs.merklePath.map((p) => p.map((x) => x.toString())),
          merkleIndices: inputs.merkleIndices.map((p) =>
            p.map((x) => x.toString()),
          ),
        };
        // `snarkjs` is ESM + untyped — import dynamically (also keeps it optional).
        const specifier = "snarkjs";
        const snarkjs = (await import(specifier)) as unknown as {
          groth16: {
            fullProve(
              i: unknown,
              w: string,
              z: string,
            ): Promise<{ proof: unknown; publicSignals: unknown }>;
          };
        };
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
          witness,
          art.wasmPath,
          art.zkeyPath,
        );
        const { proof: onchain, publicInputsBE } = formatGroth16ForOnChain(
          proof as never,
          publicSignals as never,
        );
        return {
          piA: onchain.piA,
          piB: onchain.piB,
          piC: onchain.piC,
          publicInputs: publicInputsBE,
        };
      },
    },
  };
}
