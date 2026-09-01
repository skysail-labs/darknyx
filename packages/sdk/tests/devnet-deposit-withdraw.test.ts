/**
 * Devnet verification of the v2 deposit, lock, release, and withdraw lifecycle
 * in isolation — no matcher and no settlement batch.
 *
 *   reset → deposit → reject replay → lock → release → re-lock → expire →
 *   withdraw → reject re-lock after consumption
 *
 * Gate: RUN_DEVNET_DW=1. Uses .devnet/keypairs/admin.json (mint authority +
 * payer) and the mints from .devnet/e2e-config.json. A tree reset is done
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
  SystemProgram,
  Transaction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";

import {
  deriveSpendingKey,
  bn254ToBE32,
  deriveBlindingFactor,
  deriveNoteSecret,
} from "../src/keys/key-generators.js";
import {
  noteCommitmentV2,
  ownerCommitment,
  pubkeyToFrPair,
} from "../src/utxo/note.js";
import {
  buildDepositInstruction,
  buildLockNoteInstruction,
  buildReleaseLockInstruction,
  buildResetMerkleTreeInstruction,
  buildSetTeePubkeyInstruction,
  buildWithdrawInstruction,
  consumedNotePda,
  depositedNotePda,
  merkleTreePda,
  noteLockPda,
  parseNoteLock,
  vaultConfigPda,
} from "../src/idl/vault-client.js";
import { MerkleShadow } from "./helpers/merkle-shadow.js";
import { snarkjsFullProve } from "./helpers/snarkjs-prover.js";
import {
  TOKEN_PROGRAM_ID,
  associatedTokenAddress,
  be32ToBigInt,
  be32ToDec,
  createAtaIdempotentIx,
  getTokenAccount,
  mintToIx,
} from "./helpers/e2e-helpers.js";
import { deriveDepositInnerHash } from "../src/utxo/deposit-inner.js";
import { deriveNoteUseTag } from "../src/utxo/note-use.js";
import { nodeValidDepositProver } from "../src/zk/valid-deposit-prover.js";
import { nodeValidInputProver } from "../src/zk/valid-input-prover.js";
import {
  vaultConfigTeePubkeys,
  vaultConfigTradingParameters,
} from "../src/tee/vault-config.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const CONFIG_PATH = resolve(
  REPO_ROOT,
  process.env.DARKNYX_E2E_CONFIG_PATH ?? ".devnet/e2e-config.json",
);
const SPEND_WASM = resolve(
  REPO_ROOT,
  "circuits/build/valid_spend/circuit_js/circuit.wasm",
);
const SPEND_ZKEY = resolve(
  REPO_ROOT,
  "circuits/build/valid_spend/circuit_final.zkey",
);
const DEPOSIT_WASM = resolve(
  REPO_ROOT,
  "circuits/build/valid_deposit/circuit_js/circuit.wasm",
);
const DEPOSIT_ZKEY = resolve(
  REPO_ROOT,
  "circuits/build/valid_deposit/circuit_final.zkey",
);
const INPUT_WASM = resolve(
  REPO_ROOT,
  "circuits/build/valid_input/circuit_js/circuit.wasm",
);
const INPUT_ZKEY = resolve(
  REPO_ROOT,
  "circuits/build/valid_input/circuit_final.zkey",
);
// Env-overridable, like devnet-setup.test.ts already is. Without this the test
// silently runs against the PRODUCTION devnet vault regardless of which program
// the caller meant to exercise. That is not hypothetical: during the Anchor v2
// experiment this run looked like a no-op against the new program while
// actually depositing and withdrawing on the old one.
const VAULT_ID = new PublicKey(
  process.env.VAULT_PROGRAM_ID ??
    "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
);

const READY =
  process.env.RUN_DEVNET_DW === "1" &&
  existsSync(CONFIG_PATH) &&
  existsSync(DEPOSIT_WASM) &&
  existsSync(DEPOSIT_ZKEY) &&
  existsSync(INPUT_WASM) &&
  existsSync(INPUT_ZKEY) &&
  existsSync(SPEND_WASM) &&
  existsSync(SPEND_ZKEY);
const d = READY ? describe : describe.skip;

async function loadKp(rel: string): Promise<Keypair> {
  return await Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(readFileSync(resolve(REPO_ROOT, rel), "utf8"))),
  );
}

d("devnet v2 deposit → lock lifecycle → withdraw", () => {
  it("pins compact replay markers and lock semantics on devnet", async () => {
    const cfg = JSON.parse(readFileSync(CONFIG_PATH, "utf8"));
    // A locally exported private RPC must override the snapshot embedded in
    // e2e-config. Provider credentials rotate more often than the devnet
    // mints/config, and the runbook explicitly supplies this override.
    const rpcUrl = process.env.SOLANA_RPC_URL ?? cfg.l1RpcUrl;
    const conn = new Connection(rpcUrl, "confirmed");
    const admin = await loadKp(
      process.env.ADMIN_KEYPAIR ?? ".devnet/keypairs/admin.json",
    );

    const mint = new PublicKey(cfg.baseMint.pubkey);
    const AMOUNT = 7_000_000n; // 7 tokens @ 6 decimals
    const ata = await associatedTokenAddress(mint, admin.publicKey);

    // Darkpool note keys (independent of the Solana payer). Seed is unique
    // per run so the note's nullifier/consumed-note PDAs don't collide with a
    // prior run (reset_merkle_tree clears the tree, NOT those replay PDAs).
    const runSalt = BigInt(Date.now());
    const masterSeed = new Uint8Array(64).map(
      (_, i) =>
        (i * 13 + 1 + Number((runSalt >> BigInt(i % 53)) & 0xffn)) & 0xff,
    );
    const spendingKey = deriveSpendingKey(masterSeed);
    const ownerCommit = await ownerCommitment(spendingKey);

    // ── 1. reset the tree so we deposit at a known leaf 0 ──
    const resetSig = await sendAndConfirmTransaction(
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
    console.log(`  · reset_merkle_tree ${resetSig}`);

    // Read shard-0's per-shard leaf counter. Under tree sharding the global
    // leaf count lives in each `MerkleTree` shard account (`leaf_count` is its
    // first field, at byte offset 8 after the 8-byte discriminator), NOT in
    // `VaultConfig` — which has no leaf field at all (offset 104 there is
    // `tee_pubkeys[2]`). After resetting shard 0 this must be 0.
    const [tree0Pda] = await merkleTreePda(VAULT_ID, 0);
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
    const recoveryNonce = deriveBlindingFactor(masterSeed, BigInt(leafIndex));
    const recoveryNonceBytes = bn254ToBE32(recoveryNonce);
    const innerHash = be32ToBigInt(
      await deriveDepositInnerHash(
        recoveryNonceBytes,
        bn254ToBE32(deriveNoteSecret(masterSeed, recoveryNonceBytes)),
      ),
    );
    const commitment = await noteCommitmentV2({
      tokenMint: mint.toBytes(),
      amount: AMOUNT,
      ownerCommitment: ownerCommit,
      innerHash,
    });
    const [depositMintLo, depositMintHi] = pubkeyToFrPair(mint.toBytes());
    const depositProof = await nodeValidDepositProver({
      wasmPath: DEPOSIT_WASM,
      zkeyPath: DEPOSIT_ZKEY,
    }).prove({
      noteCommitment: be32ToBigInt(commitment),
      tokenMint: [depositMintLo, depositMintHi],
      amount: AMOUNT,
      recoveryNonce,
      spendingKey,
      noteSecret: deriveNoteSecret(masterSeed, recoveryNonceBytes),
    });

    const depositSig = await sendAndConfirmTransaction(
      conn,
      new Transaction().add(
        ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }),
        createAtaIdempotentIx(admin, ata, admin.publicKey, mint),
        mintToIx(mint, ata, admin, AMOUNT),
        await buildDepositInstruction({
          programId: VAULT_ID,
          treeId: 0,
          depositor: admin.publicKey,
          tokenMint: mint,
          depositorTokenAccount: ata,
          tokenProgramId: TOKEN_PROGRAM_ID,
          amount: AMOUNT,
          noteCommitment: commitment,
          recoveryNonce: bn254ToBE32(recoveryNonce),
          proof: depositProof,
        }),
      ),
      [admin],
      { commitment: "confirmed" },
    );
    console.log(`  · deposit ${depositSig} (note committed)`);

    const tree = await MerkleShadow.create();
    await tree.append(commitment);

    const noteUseTag = await deriveNoteUseTag(
      commitment,
      bn254ToBE32(innerHash),
    );
    const [depositedMarker] = await depositedNotePda(VAULT_ID, commitment);
    const depositedInfo = await conn.getAccountInfo(depositedMarker);
    expect(depositedInfo?.data.length, "compact deposit marker").toBe(8);

    // The same commitment cannot append twice. Include another mint in the
    // replay transaction and assert both token balance and leaf count remain
    // unchanged, proving the account-validation failure is atomic.
    const replayBalanceBefore = (await getTokenAccount(conn, ata)).amount;
    const replayTreeBefore = await conn.getAccountInfo(tree0Pda);
    await expect(
      sendAndConfirmTransaction(
        conn,
        new Transaction().add(
          mintToIx(mint, ata, admin, AMOUNT),
          await buildDepositInstruction({
            programId: VAULT_ID,
            treeId: 0,
            depositor: admin.publicKey,
            tokenMint: mint,
            depositorTokenAccount: ata,
            tokenProgramId: TOKEN_PROGRAM_ID,
            amount: AMOUNT,
            noteCommitment: commitment,
            recoveryNonce: bn254ToBE32(recoveryNonce),
            proof: depositProof,
          }),
        ),
        [admin],
        { commitment: "confirmed" },
      ),
    ).rejects.toThrow();
    expect((await getTokenAccount(conn, ata)).amount).toBe(replayBalanceBefore);
    const replayTreeAfter = await conn.getAccountInfo(tree0Pda);
    expect(replayTreeAfter?.data.subarray(8, 16)).toEqual(
      replayTreeBefore?.data.subarray(8, 16),
    );
    console.log("  · duplicate deposit rejected atomically (marker=8 bytes)");

    // ── 3. Prove VALID_INPUT for the same deposited note ──
    const w = await tree.witness(leafIndex);
    const validInput = await nodeValidInputProver({
      wasmPath: INPUT_WASM,
      zkeyPath: INPUT_ZKEY,
    })({
      spendingKey,
      innerHash,
      tokenMint: mint.toBytes(),
      amount: AMOUNT,
      witness: {
        leafIndex,
        merkleRoot: w.root,
        siblings: w.siblings.map(be32ToBigInt),
        pathIndices: w.indices,
      },
    });
    const lockProof = {
      piA: validInput.proofBytes.slice(0, 64),
      piB: validInput.proofBytes.slice(64, 192),
      piC: validInput.proofBytes.slice(192, 256),
    };

    // ── 4. Exercise live/released/expired lock behavior ──
    const [vaultConfig] = await vaultConfigPda(VAULT_ID);
    const vaultInfo = await conn.getAccountInfo(vaultConfig);
    if (!vaultInfo) throw new Error("vault_config missing");
    const { numTrees } = vaultConfigTradingParameters(vaultInfo.data);
    expect(numTrees).toBe(cfg.numTrees);
    const originalTeePubkeys = vaultConfigTeePubkeys(vaultInfo.data).map(
      (pubkey) => new PublicKey(pubkey),
    );
    const testTeeSigners = await Promise.all(
      Array.from({ length: numTrees }, () => Keypair.generate()),
    );
    let signerSetRotated = false;
    try {
      // Treat the state as possibly rotated before submission. If RPC returns
      // an ambiguous error after landing the transaction, `finally` must still
      // restore the production signer set.
      signerSetRotated = true;
      const rotateSig = await sendAndConfirmTransaction(
        conn,
        new Transaction().add(
          await buildSetTeePubkeyInstruction({
            programId: VAULT_ID,
            admin: admin.publicKey,
            teePubkeys: testTeeSigners.map((signer) => signer.publicKey),
            numTrees,
          }),
        ),
        [admin],
        { commitment: "confirmed" },
      );
      console.log(`  · temporary TEE signer rotation ${rotateSig}`);

      await sendAndConfirmTransaction(
        conn,
        new Transaction().add(
          SystemProgram.transfer({
            fromPubkey: admin.publicKey,
            toPubkey: testTeeSigners[0].publicKey,
            lamports: 20_000_000,
          }),
        ),
        [admin],
        { commitment: "confirmed" },
      );

      const orderIdA = new Uint8Array(16).fill(0x41);
      // Leave enough room for lock confirmation plus the account-layout reads
      // below; an 8-slot window can expire while devnet confirms the lock.
      const expiryA = (await conn.getSlot("confirmed")) + 50n;
      const lockSig = await sendAndConfirmTransaction(
        conn,
        new Transaction().add(
          ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 }),
          await buildLockNoteInstruction({
            programId: VAULT_ID,
            treeId: 0,
            teeAuthority: testTeeSigners[0].publicKey,
            noteUseTag,
            orderId: orderIdA,
            expirySlot: expiryA,
            tokenMint: mint,
            merkleRoot: validInput.merkleRoot,
            proof: lockProof,
          }),
        ),
        [testTeeSigners[0]],
        { commitment: "confirmed" },
      );
      console.log(`  · lock_note ${lockSig}`);

      const [noteLock] = await noteLockPda(VAULT_ID, noteUseTag);
      const lockInfo = await conn.getAccountInfo(noteLock);
      expect(lockInfo?.data.length, "compact NoteLock account").toBe(72);
      const parsedLock = parseNoteLock(lockInfo!.data);
      expect(parsedLock?.tokenMint.equals(mint)).toBe(true);
      expect(parsedLock?.orderId).toEqual(orderIdA);
      expect(parsedLock?.expirySlot).toBe(expiryA);

      await expect(
        sendAndConfirmTransaction(
          conn,
          new Transaction().add(
            await buildReleaseLockInstruction({
              programId: VAULT_ID,
              rentReceiver: admin.publicKey,
              noteUseTag,
            }),
          ),
          [admin],
          { commitment: "confirmed" },
        ),
      ).rejects.toThrow();
      expect((await conn.getAccountInfo(noteLock))?.data.length).toBe(72);
      console.log("  · pre-expiry release rejected (lock=72 bytes)");

      const waitForSlot = async (target: bigint) => {
        const deadline = Date.now() + 30_000;
        while (BigInt(await conn.getSlot("confirmed")) < target) {
          if (Date.now() >= deadline) {
            throw new Error(`timed out waiting for devnet slot ${target}`);
          }
          await new Promise((resolveWait) => setTimeout(resolveWait, 250));
        }
      };
      await waitForSlot(expiryA);
      const releaseSig = await sendAndConfirmTransaction(
        conn,
        new Transaction().add(
          await buildReleaseLockInstruction({
            programId: VAULT_ID,
            rentReceiver: admin.publicKey,
            noteUseTag,
          }),
        ),
        [admin],
        { commitment: "confirmed" },
      );
      console.log(`  · release_lock ${releaseSig}`);
      expect(await conn.getAccountInfo(noteLock)).toBeNull();

      const orderIdB = new Uint8Array(16).fill(0x42);
      const expiryB = (await conn.getSlot("confirmed")) + 8n;
      const relockSig = await sendAndConfirmTransaction(
        conn,
        new Transaction().add(
          ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 }),
          await buildLockNoteInstruction({
            programId: VAULT_ID,
            treeId: 0,
            teeAuthority: testTeeSigners[0].publicKey,
            noteUseTag,
            orderId: orderIdB,
            expirySlot: expiryB,
            tokenMint: mint,
            merkleRoot: validInput.merkleRoot,
            proof: lockProof,
          }),
        ),
        [testTeeSigners[0]],
        { commitment: "confirmed" },
      );
      console.log(`  · second lock_note ${relockSig}`);
      await waitForSlot(expiryB);

      // ── 5. VALID_SPEND withdraw through the expired lock ──
      const [mintLo, mintHi] = pubkeyToFrPair(mint.toBytes());
      // S-01: the destination is a public input, so the proof only authorises
      // this exact token account.
      const [destLo, destHi] = pubkeyToFrPair(ata.toBytes());
      const { proof } = snarkjsFullProve(
        {
          merkleRoot: be32ToDec(w.root),
          tokenMint: [mintLo.toString(), mintHi.toString()],
          amount: AMOUNT.toString(),
          spendingKey: spendingKey.toString(),
          innerHash: innerHash.toString(),
          merklePath: w.siblings.map((s) => be32ToDec(s)),
          merkleIndices: w.indices.map((i) => i.toString()),
          recipient: [destLo.toString(), destHi.toString()],
        },
        {
          circuitWasmPath: SPEND_WASM,
          circuitZkeyPath: SPEND_ZKEY,
          repoRoot: REPO_ROOT,
        },
      );

      const balAfterDeposit = (await getTokenAccount(conn, ata)).amount;
      const withdrawSig = await sendAndConfirmTransaction(
        conn,
        new Transaction().add(
          ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }),
          await buildWithdrawInstruction({
            programId: VAULT_ID,
            treeId: 0,
            payer: admin.publicKey,
            tokenMint: mint,
            destinationTokenAccount: ata,
            tokenProgramId: TOKEN_PROGRAM_ID,
            // VALID_SPEND's public output 0 is now the tag; the commitment
            // stays a private intermediate inside the proof.
            noteUseTag,
            merkleRoot: w.root,
            amount: AMOUNT,
            proof,
          }),
        ),
        [admin],
        { commitment: "confirmed" },
      );
      console.log(
        `  · withdraw ${withdrawSig} (VALID_SPEND verified on-chain)`,
      );

      const [consumedMarker] = await consumedNotePda(VAULT_ID, noteUseTag);
      expect(
        (await conn.getAccountInfo(consumedMarker))?.data.length,
        "compact consume marker",
      ).toBe(8);
      expect((await conn.getAccountInfo(noteLock))?.data.length).toBe(72);
      console.log("  · expired lock allowed withdraw (consume marker=8 bytes)");

      const expiredReleaseSig = await sendAndConfirmTransaction(
        conn,
        new Transaction().add(
          await buildReleaseLockInstruction({
            programId: VAULT_ID,
            rentReceiver: admin.publicKey,
            noteUseTag,
          }),
        ),
        [admin],
        { commitment: "confirmed" },
      );
      console.log(`  · release expired lock ${expiredReleaseSig}`);
      expect(await conn.getAccountInfo(noteLock)).toBeNull();

      await expect(
        sendAndConfirmTransaction(
          conn,
          new Transaction().add(
            await buildLockNoteInstruction({
              programId: VAULT_ID,
              treeId: 0,
              teeAuthority: testTeeSigners[0].publicKey,
              noteUseTag,
              orderId: new Uint8Array(16).fill(0x43),
              expirySlot: (await conn.getSlot("confirmed")) + 8n,
              tokenMint: mint,
              merkleRoot: validInput.merkleRoot,
              proof: lockProof,
            }),
          ),
          [testTeeSigners[0]],
          { commitment: "confirmed" },
        ),
      ).rejects.toThrow();
      console.log("  · consumed note rejected by lock_note");

      // ── 6. assert the tokens round-tripped back ──
      const balFinal = (await getTokenAccount(conn, ata)).amount;
      expect(balFinal - balAfterDeposit).toBe(AMOUNT);
    } finally {
      if (signerSetRotated) {
        const restoreSig = await sendAndConfirmTransaction(
          conn,
          new Transaction().add(
            await buildSetTeePubkeyInstruction({
              programId: VAULT_ID,
              admin: admin.publicKey,
              teePubkeys: originalTeePubkeys,
              numTrees,
            }),
          ),
          [admin],
          { commitment: "confirmed" },
        );
        console.log(`  · restored TEE signer set ${restoreSig}`);
      }
      const signerBalance = await conn.getBalance(
        testTeeSigners[0].publicKey,
        "confirmed",
      );
      if (signerBalance > 0n) {
        const reclaimTx = new Transaction().add(
          SystemProgram.transfer({
            fromPubkey: testTeeSigners[0].publicKey,
            toPubkey: admin.publicKey,
            lamports: signerBalance,
          }),
        );
        // The admin pays the fee so the ephemeral signer can be drained to
        // zero instead of leaving an unreachable fee reserve behind.
        reclaimTx.feePayer = admin.publicKey;
        const reclaimSig = await sendAndConfirmTransaction(
          conn,
          reclaimTx,
          [admin, testTeeSigners[0]],
          { commitment: "confirmed" },
        );
        console.log(`  · reclaimed temporary signer balance ${reclaimSig}`);
      }
    }
  }, 180_000);
});
