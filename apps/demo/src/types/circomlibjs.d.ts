declare module "circomlibjs" {
  interface PoseidonFn {
    (inputs: bigint[]): Uint8Array;
    F: {
      e: (n: bigint) => bigint;
      toObject: (x: Uint8Array) => bigint;
    };
  }
  export function buildPoseidon(): Promise<PoseidonFn>;
}
