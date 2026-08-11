declare module "snarkjs" {
  import type { RawGroth16Proof } from "./prover/groth16-format.js";

  interface MemoryWitness {
    type: "mem";
    data?: Uint8Array;
  }

  export const wtns: {
    calculate(
      input: Record<string, unknown>,
      wasm: Uint8Array,
      output: MemoryWitness,
    ): Promise<void>;
  };

  export const groth16: {
    prove(
      zkey: Uint8Array,
      witness: MemoryWitness,
    ): Promise<{ proof: RawGroth16Proof; publicSignals: string[] }>;
    verify(
      verificationKey: unknown,
      publicSignals: string[],
      proof: RawGroth16Proof,
    ): Promise<boolean>;
  };
}
