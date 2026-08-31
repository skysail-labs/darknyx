import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

import { Connection, PublicKey } from "@solana/web3.js";
import { describe, expect, it } from "vitest";

import { merkleTreePda } from "../src/idl/vault-client.js";
import { verifyTeeAttestation } from "../src/tee/attestation.js";
import { AttestationError } from "../src/tee/verify-core.js";

const RUN = process.env.RUN_SURFPOOL_TEE_E2E === "1";
const maybeDescribe = RUN ? describe : describe.skip;
const REPO_ROOT = resolve(__dirname, "../../..");
const CONFIG_PATH = resolve(
  REPO_ROOT,
  process.env.DARKNYX_E2E_CONFIG_PATH ??
    ".surfpool/foundation/current/e2e-config.json",
);
const GATEWAY = (process.env.DARKNYX_TEE_GATEWAY ?? "").replace(/\/$/, "");
const EVIDENCE_DIR = resolve(REPO_ROOT, ".surfpool/local-tee/current");

interface LocalConfig {
  l1RpcUrl: string;
  vaultProgramId: string;
  numTrees: number;
}

interface TreeRoot {
  tree_id: number;
  merkle_root: string;
  leaf_count: number;
  on_chain_slot: number;
}

async function eventually<T>(
  timeoutMs: number,
  read: () => Promise<T | undefined>,
): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  let lastError: unknown;
  for (;;) {
    try {
      const value = await read();
      if (value !== undefined) return value;
    } catch (error) {
      lastError = error;
    }
    if (Date.now() >= deadline) {
      throw new Error(
        `eventual assertion timed out; last observation: ${String(lastError)}`,
      );
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 250));
  }
}

maybeDescribe("Surfpool production-TEE evidence boundary", () => {
  it("cold mirror state exactly reconciles every nonempty K shard", async () => {
    expect(GATEWAY).toMatch(/^http:\/\/(127\.0\.0\.1|localhost):\d+$/);
    expect(existsSync(CONFIG_PATH)).toBe(true);
    const config = JSON.parse(readFileSync(CONFIG_PATH, "utf8")) as LocalConfig;
    expect(new URL(config.l1RpcUrl).hostname).toMatch(
      /^(127\.0\.0\.1|localhost)$/,
    );
    expect(config.numTrees).toBeGreaterThan(0);

    const connection = new Connection(config.l1RpcUrl, "confirmed");
    const programId = new PublicKey(config.vaultProgramId);
    let totalLeaves = 0;
    const reconciled: TreeRoot[] = [];

    for (let treeId = 0; treeId < config.numTrees; treeId += 1) {
      const [treePda] = await merkleTreePda(programId, treeId);
      const root = await eventually(30_000, async () => {
        const [account, response] = await Promise.all([
          connection.getAccountInfo(treePda, "confirmed"),
          fetch(`${GATEWAY}/tree/root?tree_id=${treeId}`),
        ]);
        if (!account || account.data.length < 48 || !response.ok) {
          throw new Error(
            `tree=${treeId} account=${account?.data.length ?? "missing"} http=${response.status}`,
          );
        }
        const body = (await response.json()) as TreeRoot;
        const chainCount = Number(
          new DataView(
            account.data.buffer,
            account.data.byteOffset + 8,
            8,
          ).getBigUint64(0, true),
        );
        const chainRoot = Buffer.from(account.data.subarray(16, 48)).toString(
          "hex",
        );
        if (
          body.tree_id !== treeId ||
          body.leaf_count !== chainCount ||
          body.merkle_root !== chainRoot ||
          (body.leaf_count > 0 && body.on_chain_slot === 0)
        ) {
          throw new Error(
            `tree=${treeId} api=${JSON.stringify(body)} chain_count=${chainCount} chain_root=${chainRoot}`,
          );
        }
        return body;
      });
      totalLeaves += root.leaf_count;
      reconciled.push(root);
    }

    expect(totalLeaves).toBeGreaterThan(0);
    console.log(
      `SURFPOOL_TEE_RESTART_RECONCILED shards=${reconciled.length} total_leaves=${totalLeaves} ` +
        reconciled
          .map((root) => `tree${root.tree_id}=${root.leaf_count}`)
          .join(" "),
    );
    writeFileSync(
      resolve(EVIDENCE_DIR, "restart-reconciliation.json"),
      `${JSON.stringify({ shards: reconciled, totalLeaves }, null, 2)}\n`,
      { mode: 0o600 },
    );
  }, 45_000);

  it("the production DCAP verifier rejects dstack simulator evidence", async () => {
    const infoResponse = await fetch(`${GATEWAY}/info`);
    expect(infoResponse.ok).toBe(true);
    const info = (await infoResponse.json()) as { compose_hash: string };

    let rejection: unknown;
    try {
      await verifyTeeAttestation(GATEWAY, info.compose_hash, {
        fetchImpl: fetch,
      });
    } catch (error) {
      rejection = error;
    }
    expect(rejection).toBeInstanceOf(AttestationError);
    expect((rejection as AttestationError).kind).toBe("quote_invalid");
    console.log("SURFPOOL_TEE_SIMULATOR_QUOTE_REJECTED kind=quote_invalid");
    writeFileSync(
      resolve(EVIDENCE_DIR, "simulator-quote-rejection.json"),
      `${JSON.stringify({ rejected: true, kind: "quote_invalid" }, null, 2)}\n`,
      { mode: 0o600 },
    );
  });
});
