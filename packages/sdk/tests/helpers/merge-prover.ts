/**
 * VALID_MERGE(K) prover helper (test-side snarkjs shell-out).
 *
 * Builds the witness for a K-slot merge — M real input notes (same owner + mint)
 * + (K−M) dummy padding slots — and proves it. A dummy slot has `isActive=0`,
 * amount 0, zero inner_hash/path, and a public nullifier of 0; the circuit skips
 * its membership + nullifier binding.
 */

import { resolve } from "node:path";

import { type Groth16OnChainProof } from "../../src/idl/vault-client.js";
import { noteCommitmentV2, nullifierV2, ownerCommitment, pubkeyToFrPair } from "../../src/utxo/note.js";
import { be32ToBigInt, be32ToDec } from "./e2e-helpers.js";
import { snarkjsFullProve } from "./snarkjs-prover.js";

export interface MergeSlot {
  /** Real note: its opening + Merkle witness. Omit for a dummy padding slot. */
  amount: bigint;
  innerHash: bigint;
  /** 20 sibling commitments (BN254 Fr) + 20 boolean indices. */
  pathElements: bigint[];
  pathIndices: number[];
}

export interface MergeProveParams {
  repoRoot: string;
  k: 2 | 4;
  /** Shared owner. */
  spendingKey: bigint;
  ownerCommitmentBlinding: bigint;
  /** Recoverable inner_hash of the merged output note. */
  outputInnerHash: bigint;
  /** 32-byte mint (all inputs + output share it). */
  tokenMint: Uint8Array;
  /** 32-byte BE merkle root the active slots prove membership against. */
  merkleRootBE: Uint8Array;
  /** The M real input slots (M ≤ k); the rest are dummy-padded. */
  slots: MergeSlot[];
}

export interface MergeProveResult {
  proof: Groth16OnChainProof;
  /** [outputCommitment, merkleRoot, mint_lo, mint_hi, nullifiers[0..k-1]] (32B BE each). */
  publicInputsBE: Uint8Array[];
  /** The merged-note commitment (32B BE). */
  outputCommitmentBE: Uint8Array;
  outputAmount: bigint;
}

const WASM_REL = (k: number) => `circuits/build/valid_merge_k${k}/circuit_js/circuit.wasm`;
const ZKEY_REL = (k: number) => `circuits/build/valid_merge_k${k}/circuit_final.zkey`;

const ZERO_PATH = Array.from({ length: 20 }, () => 0n);
const ZERO_IDX = Array.from({ length: 20 }, () => 0);

export async function proveValidMerge(args: MergeProveParams): Promise<MergeProveResult> {
  const { k, slots } = args;
  if (slots.length === 0 || slots.length > k) {
    throw new Error(`merge needs 1..${k} real slots; got ${slots.length}`);
  }

  const owner = await ownerCommitment(args.spendingKey, args.ownerCommitmentBlinding);
  const [mintLo, mintHi] = pubkeyToFrPair(args.tokenMint);

  // Per-slot arrays, padded to k with dummies.
  const isActive: string[] = [];
  const amount: string[] = [];
  const innerHash: string[] = [];
  const merklePath: string[][] = [];
  const merkleIndices: string[][] = [];
  const nullifiers: string[] = [];
  let sum = 0n;

  for (let i = 0; i < k; i++) {
    const s = slots[i];
    if (s) {
      isActive.push("1");
      amount.push(s.amount.toString());
      innerHash.push(s.innerHash.toString());
      merklePath.push(s.pathElements.map((e) => e.toString()));
      merkleIndices.push(s.pathIndices.map((x) => x.toString()));
      nullifiers.push(be32ToBigInt(await nullifierV2(args.spendingKey, s.innerHash)).toString());
      sum += s.amount;
    } else {
      isActive.push("0");
      amount.push("0");
      innerHash.push("0");
      merklePath.push(ZERO_PATH.map((e) => e.toString()));
      merkleIndices.push(ZERO_IDX.map((x) => x.toString()));
      nullifiers.push("0");
    }
  }

  const outputCommitmentBE = await noteCommitmentV2({
    tokenMint: args.tokenMint,
    amount: sum,
    ownerCommitment: owner,
    innerHash: args.outputInnerHash,
  });

  const inputs = {
    merkleRoot: be32ToDec(args.merkleRootBE),
    tokenMint: [mintLo.toString(), mintHi.toString()],
    nullifiers,
    spendingKey: args.spendingKey.toString(),
    ownerCommitmentBlinding: args.ownerCommitmentBlinding.toString(),
    outputInnerHash: args.outputInnerHash.toString(),
    isActive,
    amount,
    innerHash,
    merklePath,
    merkleIndices,
  };

  const { proof, publicInputsBE } = snarkjsFullProve(
    inputs as unknown as Record<string, string | string[]>,
    {
      repoRoot: args.repoRoot,
      circuitWasmPath: resolve(args.repoRoot, WASM_REL(k)),
      circuitZkeyPath: resolve(args.repoRoot, ZKEY_REL(k)),
    },
  );

  return { proof, publicInputsBE, outputCommitmentBE, outputAmount: sum };
}
