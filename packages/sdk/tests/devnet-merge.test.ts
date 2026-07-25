/**
 * Devnet verification of the on-chain MERGE ix in isolation — NO settle, NO CVM.
 *
 *   reset tree → mint → deposit 2 notes → MERGE (K=2) → VALID_SPEND withdraw the
 *   merged note → assert the consolidated tokens round-trip.
 *
 * This is the full-ix integration the verify roundtrip can't cover: it proves the
 * merge actually creates the input nullifier PDAs, appends ONE output leaf, and
 * that the merged note is a real, spendable leaf.
 *
 * Gate: RUN_DEVNET_MERGE=1 + a vault deployed with the merge ix + the built merge
 * circuits. Uses .devnet/keypairs/admin.json + .devnet/e2e-config.json.
 */

import { readFileSync, existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";
import {
  ComputeBudgetProgram,
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID,
  createAssociatedTokenAccountIdempotentInstruction,
  createMintToInstruction,
  getAccount,
  getAssociatedTokenAddress,
} from "@solana/spl-token";

import {
  deriveSpendingKey,
  bn254ToBE32,
  deriveBlindingFactor,
} from "../src/keys/key-generators.js";
import {
  noteCommitmentV2,
  nullifierV2,
  ownerCommitment,
  pubkeyToFrPair,
} from "../src/utxo/note.js";
import {
  buildDepositInstruction,
  buildWithdrawInstruction,
  buildMergeInstruction,
  buildResetMerkleTreeInstruction,
  merkleTreePda,
} from "../src/idl/vault-client.js";
import { MerkleShadow } from "./helpers/merkle-shadow.js";
import { snarkjsFullProve } from "./helpers/snarkjs-prover.js";
import { be32ToDec, be32ToBigInt, StepTimer } from "./helpers/e2e-helpers.js";
import { proveValidMerge } from "./helpers/merge-prover.js";
import { deriveDepositInnerHash } from "../src/utxo/deposit-inner.js";
import { nodeValidDepositProver } from "../src/zk/valid-deposit-prover.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const CONFIG_PATH = resolve(REPO_ROOT, ".devnet/e2e-config.json");
const SPEND_WASM = resolve(
  REPO_ROOT,
  "circuits/build/valid_spend/circuit_js/circuit.wasm",
);
const SPEND_ZKEY = resolve(
  REPO_ROOT,
  "circuits/build/valid_spend/circuit_final.zkey",
);
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
const VAULT_ID = new PublicKey("C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx");

const READY =
  process.env.RUN_DEVNET_MERGE === "1" &&
  existsSync(CONFIG_PATH) &&
  existsSync(DEPOSIT_WASM) &&
  existsSync(DEPOSIT_ZKEY) &&
  existsSync(MERGE_ZKEY) &&
  existsSync(SPEND_ZKEY);
const d = READY ? describe : describe.skip;

function loadKp(rel: string): Keypair {
  return Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(readFileSync(resolve(REPO_ROOT, rel), "utf8"))),
  );
}
// Post-sharding leaf_count lives in the per-shard MerkleTree account at offset 8
// (after the 8-byte Anchor discriminator), NOT in VaultConfig. Pass a
// merkleTreePda(VAULT_ID, treeId) account.
const leafCount = (info: { data: Uint8Array }): number =>
  Number(
    new DataView(info.data.buffer, info.data.byteOffset + 8, 8).getBigUint64(
      0,
      true,
    ),
  );

d("devnet merge → withdraw (isolated, no CVM)", () => {
  it("merges two notes into one and withdraws the consolidated note", async () => {
    const cfg = JSON.parse(readFileSync(CONFIG_PATH, "utf8"));
    const conn = new Connection(cfg.l1RpcUrl, "confirmed");
    const admin = loadKp(".devnet/keypairs/admin.json");
    const mint = new PublicKey(cfg.baseMint.pubkey);
    const ata = await getAssociatedTokenAddress(mint, admin.publicKey);

    const A0 = 3_000_000n;
    const A1 = 2_000_000n;
    const SUM = A0 + A1;

    const runSalt = BigInt(Date.now());
    const masterSeed = new Uint8Array(64).map(
      (_, i) =>
        (i * 13 + 1 + Number((runSalt >> BigInt(i % 53)) & 0xffn)) & 0xff,
    );
    const spendingKey = deriveSpendingKey(masterSeed);
    const ownerBlinding = 0xabcdef12n;
    const owner = await ownerCommitment(spendingKey, ownerBlinding);

    const t = new StepTimer();

    // ── 1. reset → deposit two notes at leaves 0,1 ──
    await t.step("reset_merkle_tree", () =>
      sendAndConfirmTransaction(
        conn,
        new Transaction().add(
          buildResetMerkleTreeInstruction({
            programId: VAULT_ID,
            admin: admin.publicKey,
            treeId: 0,
          }),
        ),
        [admin],
        { commitment: "confirmed" },
      ),
    );
    const [treePda] = merkleTreePda(VAULT_ID, 0);
    expect(
      leafCount((await conn.getAccountInfo(treePda))!),
      "tree empty after reset",
    ).toBe(0);

    const tree = await MerkleShadow.create();
    const depositProver = nodeValidDepositProver({
      wasmPath: DEPOSIT_WASM,
      zkeyPath: DEPOSIT_ZKEY,
    });
    const notes: {
      amount: bigint;
      innerHash: bigint;
      commitment: Uint8Array;
      leafIndex: number;
    }[] = [];
    for (const [i, amount] of [A0, A1].entries()) {
      const recoveryNonce = deriveBlindingFactor(masterSeed, BigInt(i));
      const innerHash = be32ToBigInt(
        await deriveDepositInnerHash(
          bn254ToBE32(owner),
          bn254ToBE32(recoveryNonce),
        ),
      );
      const commitment = await noteCommitmentV2({
        tokenMint: mint.toBytes(),
        amount,
        ownerCommitment: owner,
        innerHash,
      });
      const [mintLo, mintHi] = pubkeyToFrPair(mint.toBytes());
      const depositProof = await depositProver.prove({
        noteCommitment: be32ToBigInt(commitment),
        tokenMint: [mintLo, mintHi],
        amount,
        recoveryNonce,
        spendingKey,
        ownerCommitmentBlinding: ownerBlinding,
      });
      await t.step(`deposit note ${i}`, () =>
        sendAndConfirmTransaction(
          conn,
          new Transaction().add(
            ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }),
            createAssociatedTokenAccountIdempotentInstruction(
              admin.publicKey,
              ata,
              admin.publicKey,
              mint,
            ),
            createMintToInstruction(mint, ata, admin.publicKey, amount),
            buildDepositInstruction({
              programId: VAULT_ID,
              treeId: 0,
              depositor: admin.publicKey,
              tokenMint: mint,
              depositorTokenAccount: ata,
              tokenProgramId: TOKEN_PROGRAM_ID,
              amount,
              noteCommitment: commitment,
              recoveryNonce: bn254ToBE32(recoveryNonce),
              proof: depositProof,
            }),
          ),
          [admin],
          { commitment: "confirmed" },
        ),
      );
      await tree.append(commitment);
      notes.push({ amount, innerHash, commitment, leafIndex: i });
    }
    console.log(`  · deposited 2 notes (${A0} + ${A1})`);

    // ── 2. MERGE the two notes (K=2) against the 2-leaf root ──
    const slots = await Promise.all(
      notes.map(async (n) => {
        const w = await tree.witness(n.leafIndex);
        return {
          amount: n.amount,
          innerHash: n.innerHash,
          pathElements: w.siblings.map(be32ToBigInt),
          pathIndices: w.indices,
        };
      }),
    );
    const root = await tree.computeRoot();
    const mergeRes = await t.step("VALID_MERGE prove (K=2, snarkjs)", () =>
      proveValidMerge({
        repoRoot: REPO_ROOT,
        k: 2,
        spendingKey,
        ownerCommitmentBlinding: ownerBlinding,
        tokenMint: mint.toBytes(),
        merkleRootBE: root,
        slots,
      }),
    );
    const mergeSig = await t.step("merge ix submit + confirm", () =>
      sendAndConfirmTransaction(
        conn,
        new Transaction().add(
          ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }),
          buildMergeInstruction({
            programId: VAULT_ID,
            treeId: 0,
            payer: admin.publicKey,
            inputCommitments: [notes[0].commitment, notes[1].commitment],
            outputCommitment: mergeRes.outputCommitmentBE,
            tokenMint: mint,
            merkleRoot: root,
            k: 2,
            proof: mergeRes.proof,
          }),
        ),
        [admin],
        { commitment: "confirmed" },
      ),
    );
    console.log(`  · merge ${mergeSig.slice(0, 8)}… → one note of ${SUM}`);

    // The merged note appended at leaf 2 (leaf_count 2 → 3).
    expect(
      leafCount((await conn.getAccountInfo(treePda))!),
      "merge appended one leaf",
    ).toBe(3);
    await tree.append(mergeRes.outputCommitmentBE);

    // ── 3. withdraw the merged note (VALID_SPEND) ──
    const mergedLeaf = 2;
    const w = await tree.witness(mergedLeaf);
    const [mintLo, mintHi] = pubkeyToFrPair(mint.toBytes());
    const mergedNull = await nullifierV2(spendingKey, mergeRes.outputInnerHash);
    // S-01: the destination is a public input, so the proof only authorises a
    // withdraw into this exact token account. Must be the same `ata` the
    // withdraw ix passes as `destinationTokenAccount` below, or the on-chain
    // verify fails — and if it is omitted entirely, witness generation fails
    // before that with a missing-input-signal error.
    const [destLo, destHi] = pubkeyToFrPair(ata.toBytes());
    const { proof } = await t.step("VALID_SPEND prove (snarkjs)", async () =>
      snarkjsFullProve(
        {
          merkleRoot: be32ToDec(w.root),
          nullifier: be32ToDec(mergedNull),
          tokenMint: [mintLo.toString(), mintHi.toString()],
          amount: SUM.toString(),
          spendingKey: spendingKey.toString(),
          ownerCommitmentBlinding: ownerBlinding.toString(),
          innerHash: mergeRes.outputInnerHash.toString(),
          merklePath: w.siblings.map((s) => be32ToDec(s)),
          merkleIndices: w.indices.map((i) => i.toString()),
          recipient: [destLo.toString(), destHi.toString()],
        },
        {
          circuitWasmPath: SPEND_WASM,
          circuitZkeyPath: SPEND_ZKEY,
          repoRoot: REPO_ROOT,
        },
      ),
    );

    const balBefore = (await getAccount(conn, ata)).amount;
    await t.step("withdraw ix submit + confirm", () =>
      sendAndConfirmTransaction(
        conn,
        new Transaction().add(
          ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }),
          buildWithdrawInstruction({
            programId: VAULT_ID,
            treeId: 0,
            payer: admin.publicKey,
            tokenMint: mint,
            destinationTokenAccount: ata,
            tokenProgramId: TOKEN_PROGRAM_ID,
            noteCommitment: mergeRes.outputCommitmentBE,
            nullifier: mergedNull,
            merkleRoot: w.root,
            amount: SUM,
            proof,
          }),
        ),
        [admin],
        { commitment: "confirmed" },
      ),
    );

    // The merged note was spendable for the FULL consolidated amount.
    const balAfter = (await getAccount(conn, ata)).amount;
    expect(balAfter - balBefore).toBe(SUM);
    console.log(`  · withdrew the merged note — ${SUM} tokens round-tripped`);
    t.report("devnet-merge: deposit×2 → MERGE(K=2) → withdraw");
  }, 180_000);
});
