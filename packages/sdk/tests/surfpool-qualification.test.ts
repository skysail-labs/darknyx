/**
 * Narrow Surfpool qualification for the canonical Darknyx vault.
 *
 * This suite is intentionally separate from the later local foundation: it
 * proves that Surfpool can execute the production program ID, account layouts,
 * BN254 Groth16 syscall path, and the production N=16 verifier fixture. It is
 * opt-in and refuses a non-loopback RPC.
 */

import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
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
  batchValidityMarkerPda,
  buildInitializeMarketInstruction,
  buildSetProtocolConfigInstruction,
  buildSetTeePubkeyInstruction,
  buildVerifyMatchBatchInstruction,
} from "../src/idl/vault-client.js";
import { deriveFeeKeyBinding } from "../src/utxo/match-output.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const CONFIG_PATH = resolve(
  REPO_ROOT,
  process.env.DARKNYX_E2E_CONFIG_PATH ?? ".surfpool/e2e-config.json",
);
const FIXTURE_PATH = resolve(
  REPO_ROOT,
  "programs/vault/tests/fixtures/match_batch_n16_proof.bin",
);
const RUN = process.env.RUN_SURFPOOL_QUALIFICATION === "1";
const ready = RUN && existsSync(CONFIG_PATH) && existsSync(FIXTURE_PATH);
const d = ready ? describe : describe.skip;

async function loadKeypair(path: string): Promise<Keypair> {
  return await Keypair.fromSecretKey(
    Uint8Array.from(
      JSON.parse(readFileSync(resolve(REPO_ROOT, path), "utf8")) as number[],
    ),
  );
}

function fixtureMint(lastByte: number): PublicKey {
  const bytes = new Uint8Array(32);
  bytes[0] = 1;
  bytes[31] = lastByte;
  return new PublicKey(bytes);
}

function fieldSafe(byte: number): Uint8Array {
  const value = new Uint8Array(32).fill(byte);
  value[0] = 0;
  return value;
}

async function surfpoolRpc(
  rpcUrl: string,
  method: string,
  params: unknown[],
): Promise<unknown> {
  const response = await fetch(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  expect(response.ok).toBe(true);
  const body = (await response.json()) as {
    result?: unknown;
    error?: unknown;
  };
  if (body.error !== undefined) {
    throw new Error(`${method}: ${JSON.stringify(body.error)}`);
  }
  return body.result;
}

d("Surfpool canonical vault qualification", () => {
  it(
    "accepts the committed N=16 proof through the real on-chain verifier",
    { timeout: 120_000 },
    async () => {
      const cfg = JSON.parse(readFileSync(CONFIG_PATH, "utf8")) as {
        l1RpcUrl: string;
        vaultProgramId: string;
        baseMint: { pubkey: string };
        numTrees: number;
      };
      const rpcUrl = process.env.SOLANA_RPC_URL ?? cfg.l1RpcUrl;
      const hostname = new URL(rpcUrl).hostname;
      expect(["127.0.0.1", "localhost", "::1", "[::1]"]).toContain(
        hostname,
      );

      const adminPath = process.env.ADMIN_KEYPAIR;
      const tee0Path = process.env.TEE_AUTHORITY_KEYPAIR;
      const tee1Path = process.env.TEE_AUTHORITY_1_KEYPAIR;
      if (!adminPath || !tee0Path || !tee1Path) {
        throw new Error(
          "ADMIN_KEYPAIR, TEE_AUTHORITY_KEYPAIR, and TEE_AUTHORITY_1_KEYPAIR are required",
        );
      }
      const admin = await loadKeypair(adminPath);
      const tee0 = await loadKeypair(tee0Path);
      const tee1 = await loadKeypair(tee1Path);
      const connection = new Connection(rpcUrl, "confirmed");
      const programId = new PublicKey(cfg.vaultProgramId);
      expect(programId.toBase58()).toBe(
        "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
      );

      const programAccount = await connection.getAccountInfo(programId);
      expect(programAccount?.executable).toBe(true);

      const baseMint = fixtureMint(0xb1);
      const quoteMint = fixtureMint(0x9e);
      const sourceMint = await connection.getAccountInfo(
        new PublicKey(cfg.baseMint.pubkey),
      );
      if (!sourceMint) throw new Error("foundation mint is missing");
      for (const mint of [baseMint, quoteMint]) {
        await surfpoolRpc(rpcUrl, "surfnet_setAccount", [
          mint.toBase58(),
          {
            lamports: Number(sourceMint.lamports),
            data: Buffer.from(sourceMint.data).toString("hex"),
            owner: sourceMint.owner.toBase58(),
            executable: false,
            rentEpoch: 0,
          },
        ]);
      }

      const feeEpochKey = fieldSafe(0x08);
      const feeKeyBinding = await deriveFeeKeyBinding(feeEpochKey);
      const configure = new Transaction().add(
        await buildSetTeePubkeyInstruction({
          programId,
          admin: admin.publicKey,
          teePubkeys: [tee0.publicKey, tee1.publicKey],
          numTrees: cfg.numTrees,
        }),
        await buildSetProtocolConfigInstruction({
          programId,
          admin: admin.publicKey,
          protocolOwnerCommitment: fieldSafe(0x07),
          feeRateBps: 0,
          feeKeyBinding,
          feeKeyEpoch: 1n,
        }),
        await buildInitializeMarketInstruction({
          programId,
          admin: admin.publicKey,
          baseMint,
          quoteMint,
          priceScale: 1n,
          tickSize: 1n,
          minOrderSize: 1n,
          circuitBreakerBps: 10_000n,
        }),
      );
      await sendAndConfirmTransaction(connection, configure, [admin], {
        commitment: "confirmed",
      });

      const fixture = new Uint8Array(readFileSync(FIXTURE_PATH));
      expect(fixture).toHaveLength(288);
      const proof = {
        piA: fixture.slice(0, 64),
        piB: fixture.slice(64, 192),
        piC: fixture.slice(192, 256),
      };
      const merkleRoot = fixture.slice(256, 288);
      const verifyInstruction = await buildVerifyMatchBatchInstruction({
        programId,
        payer: tee0.publicKey,
        baseMint,
        quoteMint,
        merkleRoot,
        proof,
        feeKeyEpoch: 1n,
        feeRecoveryCiphertext: new Uint8Array(272),
      });
      const latest = await connection.getLatestBlockhash("confirmed");
      const verifyTransaction = new Transaction({
        feePayer: tee0.publicKey,
        recentBlockhash: latest.blockhash,
      }).add(
        ComputeBudgetProgram.setComputeUnitLimit({ units: 140_000 }),
        verifyInstruction,
      );
      await verifyTransaction.sign(tee0);
      const serializedBytes = (await verifyTransaction.serialize()).length;
      expect(serializedBytes).toBeLessThanOrEqual(1232);

      const teeFunding = await connection.requestAirdrop(
        tee0.publicKey,
        1_000_000_000,
      );
      await connection.confirmTransaction(teeFunding, "confirmed");
      const signature = await connection.sendRawTransaction(
        await verifyTransaction.serialize(),
        { skipPreflight: false },
      );
      const confirmation = await connection.confirmTransaction(
        { signature, ...latest },
        "confirmed",
      );
      expect(confirmation.value.err).toBeNull();

      const [marker] = await batchValidityMarkerPda(programId, merkleRoot);
      expect(await connection.getAccountInfo(marker, "confirmed")).not.toBeNull();
      const landed = await connection.getTransaction(signature, {
        commitment: "confirmed",
        maxSupportedTransactionVersion: 0,
      });
      if (!landed) throw new Error("verified transaction is not queryable");
      const computeUnits = Number(landed.meta?.computeUnitsConsumed ?? 0n);
      expect(computeUnits).toBeGreaterThan(0);
      expect(computeUnits).toBeLessThan(140_000);

      console.log(
        JSON.stringify({
          result: "pass",
          signature,
          marker: marker.toBase58(),
          serializedBytes,
          computeUnits,
        }),
      );
    },
  );
});
