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
import {
  noteCommitmentV2,
  ownerCommitment,
  pubkeyToFrPair,
} from "../../src/utxo/note.js";
import { deriveMergeOutputInnerHash } from "../../src/utxo/merge.js";
import { deriveNoteUseTag } from "../../src/utxo/note-use.js";
import {
  noteCommitmentFromBytes,
  noteUseTagFromBytes,
  type NoteCommitment,
  type NoteUseTag,
} from "../../src/utxo/note-identity.js";
import { bn254ToBE32 } from "../../src/keys/key-generators.js";
import { be32ToDec } from "./e2e-helpers.js";
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
  /** 32-byte mint (all inputs + output share it). */
  tokenMint: Uint8Array;
  /** 32-byte BE merkle root the active slots prove membership against. */
  merkleRootBE: Uint8Array;
  /** The M real input slots (M ≤ k); the rest are dummy-padded. */
  slots: MergeSlot[];
}

export interface MergeProveResult {
  proof: Groth16OnChainProof;
  /** [outputCommitment, inputUseTags[0..k-1], merkleRoot, mint_lo, mint_hi] (32B BE each). */
  publicInputsBE: Uint8Array[];
  /**
   * The K input note-use TAGS in slot order (zero for dummy slots) — what the
   * merge instruction carries and what the ConsumedNoteEntry PDAs key on.
   * Returned so callers cannot accidentally pass the commitments, which are
   * the same width and would derive plausible-but-wrong PDAs.
   */
  inputUseTagsBE: NoteUseTag[];
  /** The merged-note commitment (32B BE). */
  outputCommitmentBE: NoteCommitment;
  /** Commitment-derived merged-note inner hash. */
  outputInnerHash: bigint;
  outputAmount: bigint;
}

const WASM_REL = (k: number) =>
  `circuits/build/valid_merge_k${k}/circuit_js/circuit.wasm`;
const ZKEY_REL = (k: number) =>
  `circuits/build/valid_merge_k${k}/circuit_final.zkey`;

const ZERO_PATH = Array.from({ length: 20 }, () => 0n);
const ZERO_IDX = Array.from({ length: 20 }, () => 0);

export async function proveValidMerge(
  args: MergeProveParams,
): Promise<MergeProveResult> {
  const { k, slots } = args;
  if (slots.length === 0 || slots.length > k) {
    throw new Error(`merge needs 1..${k} real slots; got ${slots.length}`);
  }

  const owner = await ownerCommitment(
    args.spendingKey,
    args.ownerCommitmentBlinding,
  );
  const [mintLo, mintHi] = pubkeyToFrPair(args.tokenMint);

  // Per-slot arrays, padded to k with dummies.
  const isActive: string[] = [];
  const amount: string[] = [];
  const innerHash: string[] = [];
  const merklePath: string[][] = [];
  const merkleIndices: string[][] = [];
  const inputCommitments: Uint8Array[] = [];
  let sum = 0n;

  for (let i = 0; i < k; i++) {
    const s = slots[i];
    if (s) {
      isActive.push("1");
      amount.push(s.amount.toString());
      innerHash.push(s.innerHash.toString());
      merklePath.push(s.pathElements.map((e) => e.toString()));
      merkleIndices.push(s.pathIndices.map((x) => x.toString()));
      inputCommitments.push(
        await noteCommitmentV2({
          tokenMint: args.tokenMint,
          amount: s.amount,
          ownerCommitment: owner,
          innerHash: s.innerHash,
        }),
      );
      sum += s.amount;
    } else {
      isActive.push("0");
      amount.push("0");
      innerHash.push("0");
      merklePath.push(ZERO_PATH.map((e) => e.toString()));
      merkleIndices.push(ZERO_IDX.map((x) => x.toString()));
      inputCommitments.push(new Uint8Array(32));
    }
  }

  // The circuit masks an inactive slot's tag to zero, so a pad slot's tag is
  // literally 0 rather than Poseidon3(29, 0, 0).
  const inputUseTagsBE = await Promise.all(
    inputCommitments.map((commitment, i) =>
      slots[i]
        ? deriveNoteUseTag(
            noteCommitmentFromBytes(commitment),
            bn254ToBE32(slots[i]!.innerHash),
          )
        : Promise.resolve(noteUseTagFromBytes(new Uint8Array(32))),
    ),
  );

  const outputInnerHash = await deriveMergeOutputInnerHash(inputCommitments);
  const outputCommitmentBE = await noteCommitmentV2({
    tokenMint: args.tokenMint,
    amount: sum,
    ownerCommitment: owner,
    innerHash: outputInnerHash,
  });

  const inputs = {
    merkleRoot: be32ToDec(args.merkleRootBE),
    tokenMint: [mintLo.toString(), mintHi.toString()],
    spendingKey: args.spendingKey.toString(),
    ownerCommitmentBlinding: args.ownerCommitmentBlinding.toString(),
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

  return {
    proof,
    publicInputsBE,
    inputUseTagsBE,
    outputCommitmentBE,
    outputInnerHash,
    outputAmount: sum,
  };
}
