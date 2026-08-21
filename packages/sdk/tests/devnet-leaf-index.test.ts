/**
 * Devnet end-to-end: the HIGH-LEVEL getDepositFunction / getMergeFunction read
 * each note's ACTUAL leaf index from the on-chain NoteCreated / NoteMerged event
 * (race-proof), NOT a pre-send leaf_count guess. This exercises
 * `utxo/leaf-index.ts` (getTransaction → parse event) against real RPC — the
 * path the unit tests can only mock.
 *
 * Gate: RUN_DEVNET_LEAF=1 + .devnet/e2e-config.json + the VALID_MERGE artifacts.
 * Resets shard 0 first so THIS client is the only appender, making the expected
 * indices deterministic (deposits land at 0,1; the merge output at 2).
 */

import { existsSync, readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, it, expect } from "vitest";
import {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  ComputeBudgetProgram,
  sendAndConfirmTransaction,
} from "@solana/web3.js";

import { DarkPoolClient } from "../src/client.js";
import { getDepositFunction } from "../src/utxo/deposit.js";
import { getMergeFunction } from "../src/utxo/merge.js";
import { ownerCommitment } from "../src/utxo/note.js";
import { deriveSpendingKey, bn254ToBE32 } from "../src/keys/key-generators.js";
import {
  buildResetMerkleTreeInstruction,
  merkleTreePda,
} from "../src/idl/vault-client.js";
import type { MergeInputs, Groth16ProofBytes } from "../src/zk/prover-suite.js";
import { MerkleShadow } from "./helpers/merkle-shadow.js";
import { proveValidMerge } from "./helpers/merge-prover.js";
import { nodeValidDepositProver } from "../src/zk/valid-deposit-prover.js";
import {
  TOKEN_PROGRAM_ID,
  associatedTokenAddress,
  createAtaIdempotentIx,
  mintToIx,
} from "./helpers/e2e-helpers.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const CONFIG_PATH = resolve(REPO_ROOT, ".devnet/e2e-config.json");
const MERGE_ZKEY = resolve(
  REPO_ROOT,
  "circuits/build/valid_merge_k2/circuit_final.zkey",
);
const DEPOSIT_WASM = resolve(
  REPO_ROOT,
  "circuits/build/valid_deposit/circuit_js/circuit.wasm",
);
const DEPOSIT_ZKEY = resolve(
  REPO_ROOT,
  "circuits/build/valid_deposit/circuit_final.zkey",
);
const VAULT_ID = new PublicKey(
  process.env.VAULT_PROGRAM_ID ??
    "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
);

const READY =
  process.env.RUN_DEVNET_LEAF === "1" &&
  existsSync(CONFIG_PATH) &&
  existsSync(DEPOSIT_WASM) &&
  existsSync(DEPOSIT_ZKEY) &&
  existsSync(MERGE_ZKEY);
const d = READY ? describe : describe.skip;

async function loadKp(rel: string): Promise<Keypair> {
  return await Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(readFileSync(resolve(REPO_ROOT, rel), "utf8"))),
  );
}

/** leaf_count (u64 @ offset 8) of shard `treeId`'s MerkleTree account. */
async function onChainLeafCount(
  conn: Connection,
  treeId: number,
): Promise<bigint> {
  const [treePda] = await merkleTreePda(VAULT_ID, treeId);
  const info = await conn.getAccountInfo(treePda, "confirmed");
  if (!info) throw new Error(`merkle_tree shard ${treeId} not found`);
  return new DataView(
    info.data.buffer,
    info.data.byteOffset + 8,
    8,
  ).getBigUint64(0, true);
}

d("devnet leaf-index (high-level deposit + merge read the event index)", () => {
  it("getDepositFunction + getMergeFunction store the ACTUAL on-chain leaf index", async () => {
    const cfg = JSON.parse(readFileSync(CONFIG_PATH, "utf8"));
    const rpcUrl = process.env.SOLANA_RPC_URL ?? cfg.l1RpcUrl;
    const conn = new Connection(rpcUrl, "confirmed");
    const admin = await loadKp(".devnet/keypairs/admin.json");
    const mint = new PublicKey(cfg.baseMint.pubkey);
    const ata = await associatedTokenAddress(mint, admin.publicKey);

    // Deterministic per-run keys (admin is the only signer on devnet).
    const masterSeed = new Uint8Array(64).map((_, i) => (i * 31 + 7) & 0xff);
    const ownerBlinding = 99n;
    const spendingKey = deriveSpendingKey(masterSeed);
    const owner = await ownerCommitment(spendingKey, ownerBlinding);
    const tree = await MerkleShadow.create();

    // ── reset shard 0 so indices are deterministic (only this client appends) ──
    await sendAndConfirmTransaction(
      conn,
      new Transaction().add(
        await buildResetMerkleTreeInstruction({
          programId: VAULT_ID,
          admin: admin.publicKey,
          treeId: 0,
        }),
      ),
      [admin],
      { commitment: "confirmed" },
    );
    expect(await onChainLeafCount(conn, 0)).toBe(0n);

    // The client: real devnet providers + a snarkjs-backed merge prover.
    const client = new DarkPoolClient({
      programId: VAULT_ID,
      seedMode: {
        type: "csprng",
        storage: {
          load: async () => masterSeed,
          store: async () => {},
        },
      },
      connectionProvider: { connection: conn, perRpcUrl: rpcUrl },
      ownerCommitmentBlinding: ownerBlinding,
      providers: {
        accountInfoProvider: {
          getAccountInfo: async (pk) => {
            const info = await conn.getAccountInfo(pk, "confirmed");
            return info ? { data: info.data, owner: info.owner } : null;
          },
        },
        transactionForwarder: {
          sendAndConfirm: async (txOrIxs) => {
            const ixs = Array.isArray(txOrIxs) ? txOrIxs : txOrIxs.instructions;
            // Prepend a CU bump — the merge ix verifies a Groth16 proof on-chain
            // (deposit doesn't need it, but the extra limit is harmless).
            const tx = new Transaction()
              .add(ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }))
              .add(...ixs);
            return sendAndConfirmTransaction(conn, tx, [admin], {
              commitment: "confirmed",
            });
          },
        },
        merkleProofProvider: {
          getInclusionProof: async (leafIndex) => {
            const w = await tree.witness(Number(leafIndex));
            return {
              root: w.root,
              siblings: w.siblings,
              pathIndices: w.indices,
            };
          },
        },
      },
      zkProver: {
        walletCreate: {
          prove: async () => {
            throw new Error("walletCreate prover unused in this test");
          },
        },
        deposit: nodeValidDepositProver({
          wasmPath: DEPOSIT_WASM,
          zkeyPath: DEPOSIT_ZKEY,
        }),
        spend: {
          prove: async () => {
            throw new Error("spend prover unused in this test");
          },
        },
        merge: {
          prove: async (inputs: MergeInputs): Promise<Groth16ProofBytes> => {
            const slots = [];
            for (let i = 0; i < inputs.k; i++) {
              if (inputs.isActive[i] === 1) {
                slots.push({
                  amount: inputs.amount[i],
                  innerHash: inputs.innerHash[i],
                  pathElements: inputs.merklePath[i],
                  pathIndices: inputs.merkleIndices[i],
                });
              }
            }
            const res = await proveValidMerge({
              repoRoot: REPO_ROOT,
              k: inputs.k,
              spendingKey: inputs.spendingKey,
              ownerCommitmentBlinding: inputs.ownerCommitmentBlinding,
              tokenMint: mint.toBytes(),
              merkleRootBE: bn254ToBE32(inputs.merkleRoot),
              slots,
            });
            // merge.ts only consumes piA/piB/piC; publicInputs satisfies the type.
            return { ...res.proof, publicInputs: res.publicInputsBE };
          },
        },
      },
    });

    const deposit = getDepositFunction({ client });
    const amounts = [3_000_000n, 2_000_000n];
    const notes: {
      commitment: Uint8Array;
      amount: bigint;
      innerHash: bigint;
      leafIndex: bigint;
    }[] = [];

    for (const [i, amount] of amounts.entries()) {
      // Fund the depositor's ATA (the deposit ix transfers from it).
      await sendAndConfirmTransaction(
        conn,
        new Transaction().add(
          createAtaIdempotentIx(admin, ata, admin.publicKey, mint),
          mintToIx(mint, ata, admin, amount),
        ),
        [admin],
        { commitment: "confirmed" },
      );

      const receipt = await deposit({
        depositor: admin.publicKey,
        treeId: 0,
        tokenMint: mint.toBytes(),
        amount,
        depositIndex: BigInt(i),
        depositorTokenAccount: ata,
        tokenProgramId: TOKEN_PROGRAM_ID,
      });

      // The deposit read its leaf index from the NoteCreated event — assert it
      // equals where the leaf ACTUALLY landed (sequential since we reset + are
      // the sole appender).
      expect(receipt.leafIndex).toBe(BigInt(i));
      expect(await onChainLeafCount(conn, 0)).toBe(BigInt(i + 1));

      await tree.append(receipt.noteCommitment); // keep the shadow in sync for the merge proof
      notes.push({
        commitment: receipt.noteCommitment,
        amount,
        innerHash: receipt.notePlaintext.innerHash,
        leafIndex: receipt.leafIndex,
      });
    }

    // ── merge the two notes via the high-level function ──
    const merge = getMergeFunction({ client });
    const mergeReceipt = await merge({
      payer: admin.publicKey,
      treeId: 0,
      inputs: notes.map((n) => ({
        commitment: n.commitment,
        amount: n.amount,
        innerHash: n.innerHash,
        leafIndex: n.leafIndex,
      })),
      tokenMint: mint.toBytes(),
      ownerCommitment: owner,
    });

    // The merge read its output index from the NoteMerged event — the two inputs
    // sat at 0,1 so the merged output lands at 2.
    expect(mergeReceipt.outputLeafIndex).toBe(2n);
    expect(await onChainLeafCount(conn, 0)).toBe(3n);
    expect(mergeReceipt.outputNote.leafIndex).toBe(2n);
  }, 120_000);
});
