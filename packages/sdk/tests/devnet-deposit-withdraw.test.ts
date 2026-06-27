/**
 * Minimal devnet verification of the v2 on-chain DEPOSIT + WITHDRAW
 * components in isolation — NO settle, NO TEE authority, NO matching engine.
 *
 *   reset tree → mint → deposit (v2 inner_hash) → VALID_SPEND withdraw → assert round-trip
 *
 * Gate: RUN_DEVNET_DW=1. Uses .devnet/keypairs/admin.json (mint authority +
 * payer) and the mints from .devnet/e2e-config.json. Run a tree reset is done
 * in-test so leaf_count starts at 0 and the shadow tree mirrors on-chain.
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
  buildResetMerkleTreeInstruction,
  vaultConfigPda,
  merkleTreePda,
} from "../src/idl/vault-client.js";
import { MerkleShadow } from "./helpers/merkle-shadow.js";
import { snarkjsFullProve } from "./helpers/snarkjs-prover.js";
import { be32ToDec } from "./helpers/e2e-helpers.js";

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
const VAULT_ID = new PublicKey("C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx");

const READY =
  process.env.RUN_DEVNET_DW === "1" &&
  existsSync(CONFIG_PATH) &&
  existsSync(SPEND_ZKEY);
const d = READY ? describe : describe.skip;

function loadKp(rel: string): Keypair {
  return Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(readFileSync(resolve(REPO_ROOT, rel), "utf8"))),
  );
}

d("devnet v2 deposit → withdraw (isolated, no settle)", () => {
  it("deposits a v2 note and withdraws it via VALID_SPEND, round-tripping the tokens", async () => {
    const cfg = JSON.parse(readFileSync(CONFIG_PATH, "utf8"));
    const conn = new Connection(cfg.l1RpcUrl, "confirmed");
    const admin = loadKp(".devnet/keypairs/admin.json");

    const mint = new PublicKey(cfg.baseMint.pubkey);
    const AMOUNT = 7_000_000n; // 7 tokens @ 6 decimals
    const ata = await getAssociatedTokenAddress(mint, admin.publicKey);

    // Darkpool note keys (independent of the Solana payer). Seed is unique
    // per run so the note's nullifier/consumed-note PDAs don't collide with a
    // prior run (reset_merkle_tree clears the tree, NOT those replay PDAs).
    const runSalt = BigInt(Date.now());
    const masterSeed = new Uint8Array(64).map(
      (_, i) =>
        (i * 13 + 1 + Number((runSalt >> BigInt(i % 53)) & 0xffn)) & 0xff,
    );
    const spendingKey = deriveSpendingKey(masterSeed);
    const ownerBlinding = 0xabcdef12n;
    const ownerCommit = await ownerCommitment(spendingKey, ownerBlinding);

    // ── 1. reset the tree so we deposit at a known leaf 0 ──
    const resetSig = await sendAndConfirmTransaction(
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
    );
    console.log(`  · reset_merkle_tree ${resetSig.slice(0, 8)}…`);

    // Read shard-0's per-shard leaf counter. Under tree sharding the global
    // leaf count lives in each `MerkleTree` shard account (`leaf_count` is its
    // first field, at byte offset 8 after the 8-byte discriminator), NOT in
    // `VaultConfig` — which has no leaf field at all (offset 104 there is
    // `tee_pubkeys[2]`). After resetting shard 0 this must be 0.
    const [tree0Pda] = merkleTreePda(VAULT_ID, 0);
    const tinfo = await conn.getAccountInfo(tree0Pda);
    if (!tinfo) throw new Error("merkle_tree(0) missing");
    const leafIndex = Number(
      new DataView(
        tinfo.data.buffer,
        tinfo.data.byteOffset + 8,
        8,
      ).getBigUint64(0, true),
    );
    expect(leafIndex, "tree must be empty after reset").toBe(0);

    // ── 2. mint + deposit the v2 note ──
    const innerHash = deriveBlindingFactor(masterSeed, BigInt(leafIndex));
    const commitment = await noteCommitmentV2({
      tokenMint: mint.toBytes(),
      amount: AMOUNT,
      ownerCommitment: ownerCommit,
      innerHash,
    });

    const balBefore = await getAccount(conn, ata)
      .then((a) => a.amount)
      .catch(() => 0n);
    const depositSig = await sendAndConfirmTransaction(
      conn,
      new Transaction().add(
        createAssociatedTokenAccountIdempotentInstruction(
          admin.publicKey,
          ata,
          admin.publicKey,
          mint,
        ),
        createMintToInstruction(mint, ata, admin.publicKey, AMOUNT),
        buildDepositInstruction({
          programId: VAULT_ID,
          treeId: 0,
          depositor: admin.publicKey,
          tokenMint: mint,
          depositorTokenAccount: ata,
          tokenProgramId: TOKEN_PROGRAM_ID,
          amount: AMOUNT,
          ownerCommitment: bn254ToBE32(ownerCommit),
          innerHash: bn254ToBE32(innerHash),
        }),
      ),
      [admin],
      { commitment: "confirmed" },
    );
    console.log(`  · deposit ${depositSig.slice(0, 8)}… (note committed)`);

    const tree = await MerkleShadow.create();
    await tree.append(commitment);

    // ── 3. VALID_SPEND withdraw the SAME note ──
    const w = await tree.witness(leafIndex);
    const [mintLo, mintHi] = pubkeyToFrPair(mint.toBytes());
    const nulli = await nullifierV2(spendingKey, innerHash);
    const { proof } = snarkjsFullProve(
      {
        merkleRoot: be32ToDec(w.root),
        nullifier: be32ToDec(nulli),
        tokenMint: [mintLo.toString(), mintHi.toString()],
        amount: AMOUNT.toString(),
        spendingKey: spendingKey.toString(),
        ownerCommitmentBlinding: ownerBlinding.toString(),
        innerHash: innerHash.toString(),
        merklePath: w.siblings.map((s) => be32ToDec(s)),
        merkleIndices: w.indices.map((i) => i.toString()),
      },
      {
        circuitWasmPath: SPEND_WASM,
        circuitZkeyPath: SPEND_ZKEY,
        repoRoot: REPO_ROOT,
      },
    );

    const balAfterDeposit = (await getAccount(conn, ata)).amount;
    const withdrawSig = await sendAndConfirmTransaction(
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
          noteCommitment: commitment,
          nullifier: nulli,
          merkleRoot: w.root,
          amount: AMOUNT,
          proof,
        }),
      ),
      [admin],
      { commitment: "confirmed" },
    );
    console.log(
      `  · withdraw ${withdrawSig.slice(0, 8)}… (VALID_SPEND verified on-chain)`,
    );

    // ── 4. assert the tokens round-tripped back ──
    const balFinal = (await getAccount(conn, ata)).amount;
    expect(balFinal - balAfterDeposit).toBe(AMOUNT);
    void balBefore;
  }, 120_000);
});
