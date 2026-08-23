/**
 * Pure-TS helpers that convert a snarkjs `proof.json` / `public.json` pair into
 * the byte layout expected by the on-chain `groth16-solana` verifier.
 *
 * No `node:*` imports — this module is safe to load in browsers, Workers, and
 * Edge runtimes. The Node-only `tests/helpers/snarkjs-prover.ts` (which shells
 * out to the `snarkjs` CLI) and the browser `BrowserProverSuite` (which calls
 * `snarkjs.groth16.fullProve` in a Web Worker) both delegate the byte-level
 * formatting here.
 *
 * Byte-for-byte mirror of `programs/vault/tests/common/mod.rs` + the original
 * helpers in `packages/sdk/tests/helpers/snarkjs-prover.ts`.
 */

import type { Groth16OnChainProof } from "../idl/vault-client.js";

// BN254 base field modulus, big-endian. Used to compute -y mod P for pi_a.
const BN254_P = new Uint8Array([
  0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81,
  0x81, 0x58, 0x5d, 0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20,
  0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
]);

/** Shape of a snarkjs `proof.json`. */
export interface SnarkjsRawProof {
  pi_a: string[]; // [x, y, "1"]
  pi_b: string[][]; // [[x0, x1], [y0, y1], ["1", "0"]]
  pi_c: string[]; // [x, y, "1"]
}

/** Shape of a snarkjs `public.json`. */
export type SnarkjsRawPublic = string[];

export interface FormatGroth16Result {
  /** On-chain `Groth16OnChainProof` — `pi_a` already negated. */
  proof: Groth16OnChainProof;
  /** Public inputs as 32-byte big-endian buffers, in the order snarkjs emits them. */
  publicInputsBE: Uint8Array[];
}

/**
 * Converts a snarkjs `proof.json` + `public.json` pair into the byte layout
 * expected by `groth16-solana` (the on-chain wrapper does NOT negate pi_a, so
 * we negate here to match the test/program convention).
 */
export function formatGroth16ForOnChain(
  proofJson: SnarkjsRawProof,
  publicJson: SnarkjsRawPublic,
): FormatGroth16Result {
  const piA = groth16G1Bytes(proofJson.pi_a);
  const piB = groth16G2Bytes(proofJson.pi_b);
  const piC = groth16G1Bytes(proofJson.pi_c);
  const piANeg = negateG1(piA);
  const publicInputsBE = publicJson.map((s) => decToBe32(s));
  return {
    proof: { piA: piANeg, piB, piC },
    publicInputsBE,
  };
}

/** Decimal string → 32-byte big-endian buffer (no BigInt — works in all JS runtimes). */
export function decToBe32(s: string): Uint8Array {
  if (!/^\d+$/.test(s)) throw new Error(`non-decimal: ${s}`);
  let digits = Array.from(s, (c) => c.charCodeAt(0) - 48);
  const out = new Uint8Array(32);
  let byteIdx = 32;
  while (digits.length > 0 && byteIdx > 0) {
    let rem = 0;
    const next: number[] = [];
    for (const d of digits) {
      const cur = rem * 10 + d;
      const q = Math.floor(cur / 256);
      rem = cur % 256;
      if (!(next.length === 0 && q === 0)) next.push(q);
    }
    byteIdx -= 1;
    out[byteIdx] = rem;
    digits = next;
  }
  return out;
}

/** G1 point: snarkjs emits `[x, y, "1"]` in decimal — pack as `x||y` BE. */
export function groth16G1Bytes(v: string[]): Uint8Array {
  const out = new Uint8Array(64);
  out.set(decToBe32(v[0]), 0);
  out.set(decToBe32(v[1]), 32);
  return out;
}

/**
 * G2 point: snarkjs emits `[[x0,x1],[y0,y1],["1","0"]]` (Fq2 coefficient pairs
 * in `(c0, c1)` order). The on-chain verifier expects `(c1 || c0)` BE — swap
 * both x and y.
 */
export function groth16G2Bytes(v: string[][]): Uint8Array {
  const x0 = decToBe32(v[0][0]);
  const x1 = decToBe32(v[0][1]);
  const y0 = decToBe32(v[1][0]);
  const y1 = decToBe32(v[1][1]);
  const out = new Uint8Array(128);
  out.set(x1, 0);
  out.set(x0, 32);
  out.set(y1, 64);
  out.set(y0, 96);
  return out;
}

/** Negate a G1 point in place: `(x, y) → (x, -y mod P)`. */
export function negateG1(point: Uint8Array): Uint8Array {
  if (point.length !== 64) throw new Error("G1 point must be 64 bytes");
  const out = new Uint8Array(64);
  out.set(point.subarray(0, 32), 0);
  const yNeg = subBe(BN254_P, point.subarray(32, 64));
  out.set(yNeg, 32);
  return out;
}

function subBe(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length !== 32 || b.length !== 32) throw new Error("32B operands only");
  const out = new Uint8Array(32);
  let borrow = 0;
  for (let i = 31; i >= 0; i--) {
    const diff = a[i] - b[i] - borrow;
    if (diff < 0) {
      out[i] = diff + 256;
      borrow = 1;
    } else {
      out[i] = diff;
      borrow = 0;
    }
  }
  return out;
}
