export interface RawGroth16Proof {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
}

export interface BrowserGroth16Proof {
  piA: Uint8Array;
  piB: Uint8Array;
  piC: Uint8Array;
  publicInputs: Uint8Array[];
}

const BN254_P = Uint8Array.from([
  0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81,
  0x81, 0x58, 0x5d, 0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20,
  0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
]);

function decimalToBe32(value: string): Uint8Array {
  if (!/^\d+$/.test(value))
    throw new Error(`non-decimal proof value: ${value}`);
  const bigint = BigInt(value);
  if (bigint < 0n || bigint >= 1n << 256n) {
    throw new Error("proof value does not fit 32 bytes");
  }
  const output = new Uint8Array(32);
  let remaining = bigint;
  for (let index = 31; index >= 0; index -= 1) {
    output[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return output;
}

function subtractBe(left: Uint8Array, right: Uint8Array): Uint8Array {
  const output = new Uint8Array(32);
  let borrow = 0;
  for (let index = 31; index >= 0; index -= 1) {
    const difference = left[index] - right[index] - borrow;
    output[index] = difference < 0 ? difference + 256 : difference;
    borrow = difference < 0 ? 1 : 0;
  }
  return output;
}

export function formatBrowserGroth16Proof(
  proof: RawGroth16Proof,
  publicSignals: string[],
): BrowserGroth16Proof {
  if (
    proof.pi_a.length < 2 ||
    proof.pi_b.length < 2 ||
    proof.pi_b[0].length < 2 ||
    proof.pi_b[1].length < 2 ||
    proof.pi_c.length < 2
  ) {
    throw new Error("malformed snarkjs Groth16 proof");
  }
  const piA = new Uint8Array(64);
  piA.set(decimalToBe32(proof.pi_a[0]), 0);
  piA.set(subtractBe(BN254_P, decimalToBe32(proof.pi_a[1])), 32);
  const piB = new Uint8Array(128);
  piB.set(decimalToBe32(proof.pi_b[0][1]), 0);
  piB.set(decimalToBe32(proof.pi_b[0][0]), 32);
  piB.set(decimalToBe32(proof.pi_b[1][1]), 64);
  piB.set(decimalToBe32(proof.pi_b[1][0]), 96);
  const piC = new Uint8Array(64);
  piC.set(decimalToBe32(proof.pi_c[0]), 0);
  piC.set(decimalToBe32(proof.pi_c[1]), 32);
  return {
    piA,
    piB,
    piC,
    publicInputs: publicSignals.map(decimalToBe32),
  };
}
