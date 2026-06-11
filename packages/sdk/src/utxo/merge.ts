/**
 * getMergeFunction — in-pool note consolidation (VALID_MERGE K=2/4).
 *
 * Consumes 2–4 input notes (same owner + mint) and mints ONE output note = their
 * sum — no external transfer. The merged note is a normal tree leaf, recoverable
 * from the seed via `deriveMergeInnerHash`, so it's spendable like a deposit.
 *
 * Store-agnostic (like `getWithdrawFunction`): it returns the merged note +
 * `spentCommitments`; the wallet's `consolidate` wires this into a `MergeFn` that
 * prunes the inputs + stores the merged note. The merge is its own vault tx, so
 * `consolidate` chains it for >4 notes.
 */

import { PublicKey } from "@solana/web3.js";

import type { DarkPoolClient } from "../client.js";
import type { TransactionCallbacks } from "../providers.js";
import { DarkPoolError } from "../errors.js";
import { noteCommitmentV2, nullifierV2, pubkeyToFrPair } from "./note.js";
import { deriveMergeInnerHash } from "../keys/key-generators.js";
import { buildMergeInstruction } from "../idl/vault-client.js";
import { readNoteMergedLeafIndex } from "./leaf-index.js";
import type { StoredNote } from "./note-store.js";

const MAX_K = 4;

export interface MergeInputNote {
  commitment: Uint8Array;
  amount: bigint;
  innerHash: bigint;
  leafIndex: bigint;
}

export interface MergeParams {
  payer: PublicKey;
  /** Which Merkle-tree shard the inputs live in + the merged output appends to
   *  (default 0). */
  treeId?: number;
  /** 2–4 input notes — all the same mint + owner. */
  inputs: MergeInputNote[];
  tokenMint: Uint8Array;
  /** Shared owner commitment of all inputs (and the output). */
  ownerCommitment: bigint;
  /** Index for `deriveMergeInnerHash` — the merged note's recoverable inner_hash. */
  mergeIndex: number;
  callbacks?: TransactionCallbacks;
}

export interface MergeReceipt {
  signature: string;
  outputCommitment: Uint8Array;
  outputLeafIndex: bigint;
  /** The merged note, ready to `store.put`. Spendable like a deposit. */
  outputNote: StoredNote;
  /** Hex commitments of the consumed inputs — the wallet prunes these. */
  spentCommitments: string[];
}

const u8ToBigBE = (x: Uint8Array): bigint => {
  let acc = 0n;
  for (const b of x) acc = (acc << 8n) | BigInt(b);
  return acc;
};


export function getMergeFunction(
  { client }: { client: DarkPoolClient },
): (params: MergeParams) => Promise<MergeReceipt> {
  return async (params) => {
    const m = params.inputs.length;
    if (m < 2 || m > MAX_K) {
      throw new DarkPoolError("parameter", `merge needs 2..${MAX_K} input notes; got ${m}`);
    }
    const k: 2 | 4 = m <= 2 ? 2 : 4;
    const { spendingKey } = await client.getResolvedKeys();
    const [mintLo, mintHi] = pubkeyToFrPair(params.tokenMint);

    // --- merkle proofs (all inputs must share one recent root) ---
    await params.callbacks?.pre?.("merkle-proof-fetch");
    const proofs = [];
    for (const inp of params.inputs) {
      const w = await client.providers.merkleProofProvider.getInclusionProof(inp.leafIndex);
      if (w.siblings.length !== 20 || w.pathIndices.length !== 20) {
        throw new DarkPoolError("merkle-proof-fetch", "expected a 20-level Merkle path");
      }
      proofs.push(w);
    }
    const merkleRoot = proofs[0].root;
    for (const w of proofs) {
      if (Buffer.compare(Buffer.from(w.root), Buffer.from(merkleRoot)) !== 0) {
        throw new DarkPoolError("merkle-proof-fetch", "all inputs must prove against the same root");
      }
    }

    // --- build the merged output note ---
    await params.callbacks?.pre?.("note-build");
    const sum = params.inputs.reduce((s, i) => s + i.amount, 0n);
    const outputInnerHash = deriveMergeInnerHash((await client.getResolvedKeys()).masterSeed, params.mergeIndex);
    const outputCommitment = await noteCommitmentV2({
      tokenMint: params.tokenMint,
      amount: sum,
      ownerCommitment: params.ownerCommitment,
      innerHash: outputInnerHash,
    });

    // Per-slot witness, padded to k with dummies (inactive, zero nullifier).
    const isActive: number[] = [];
    const amount: bigint[] = [];
    const innerHash: bigint[] = [];
    const merklePath: bigint[][] = [];
    const merkleIndices: number[][] = [];
    const nullifiers: bigint[] = [];
    const nullifierBytes: Uint8Array[] = [];
    const zero32 = new Uint8Array(32);

    for (let i = 0; i < k; i++) {
      if (i < m) {
        const inp = params.inputs[i];
        const nf = await nullifierV2(spendingKey, inp.innerHash);
        isActive.push(1);
        amount.push(inp.amount);
        innerHash.push(inp.innerHash);
        merklePath.push(proofs[i].siblings.map(u8ToBigBE));
        merkleIndices.push(proofs[i].pathIndices);
        nullifiers.push(u8ToBigBE(nf));
        nullifierBytes.push(nf);
      } else {
        isActive.push(0);
        amount.push(0n);
        innerHash.push(0n);
        merklePath.push(Array.from({ length: 20 }, () => 0n));
        merkleIndices.push(Array.from({ length: 20 }, () => 0));
        nullifiers.push(0n);
        nullifierBytes.push(zero32);
      }
    }

    // --- prove ---
    await params.callbacks?.pre?.("proof-generation");
    const { ownerBlinding } = await client.getResolvedKeys();
    let proof;
    try {
      proof = await client.zkProver.merge.prove({
        k,
        merkleRoot: u8ToBigBE(merkleRoot),
        tokenMint: [mintLo, mintHi],
        outputCommitment: u8ToBigBE(outputCommitment),
        nullifiers,
        spendingKey,
        ownerCommitmentBlinding: ownerBlinding,
        outputInnerHash,
        isActive,
        amount,
        innerHash,
        merklePath,
        merkleIndices,
      });
    } catch (e) {
      throw new DarkPoolError("proof-generation", (e as Error).message, e);
    }

    const treeId = params.treeId ?? 0;

    // --- submit ---
    await params.callbacks?.pre?.("instruction-build");
    const ix = buildMergeInstruction({
      programId: client.programId,
      treeId,
      payer: params.payer,
      nullifiers: nullifierBytes,
      outputCommitment,
      tokenMint: new PublicKey(params.tokenMint),
      merkleRoot,
      k,
      proof: { piA: proof.piA, piB: proof.piB, piC: proof.piC },
    });

    await params.callbacks?.pre?.("transaction-send");
    let signature;
    try {
      signature = await client.providers.transactionForwarder.sendAndConfirm([ix]);
    } catch (e) {
      throw new DarkPoolError("transaction-send", (e as Error).message, e);
    }
    await params.callbacks?.post?.("transaction-send", signature);

    // Read the ACTUAL leaf index from the confirmed tx's NoteMerged event —
    // race-proof against appends that landed between build and execution.
    const outputLeafIndex = await readNoteMergedLeafIndex(
      client.connectionProvider.connection,
      signature,
    );

    const outputNote: StoredNote = {
      commitment: Buffer.from(outputCommitment).toString("hex"),
      tokenMint: params.tokenMint,
      amount: sum,
      ownerCommitment: params.ownerCommitment,
      innerHash: outputInnerHash,
      leafIndex: outputLeafIndex,
    };

    return {
      signature,
      outputCommitment,
      outputLeafIndex,
      outputNote,
      spentCommitments: params.inputs.map((i) => Buffer.from(i.commitment).toString("hex")),
    };
  };
}
