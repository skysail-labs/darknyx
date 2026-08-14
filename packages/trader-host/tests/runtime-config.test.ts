import { chmod, mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import {
  createReleaseHost,
  loadTraderHostRuntimeConfig,
} from "../src/index.js";

async function fixture(): Promise<{
  env: NodeJS.ProcessEnv;
  cookieKey: string;
  storeKey: string;
}> {
  const root = await mkdtemp(join(tmpdir(), "darknyx-runtime-config-"));
  const staticRoot = join(root, "static");
  await mkdir(staticRoot);
  await writeFile(join(staticRoot, "index.html"), "ok");
  const releaseFile = join(root, "release.json");
  await writeFile(
    releaseFile,
    JSON.stringify({
      schema_version: 1,
      release_id: "runtime-test",
      venue_id: "devnet",
      gateway_url: "https://app.example/api/darknyx/venue/",
      rpc_url: "https://app.example/api/darknyx/rpc",
      vault_program_id: "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
      expected_compose_hash: "ab".repeat(32),
      expected_oracle_mode: "pyth-solana-push-v1",
      artifact_manifest_url: "https://app.example/artifacts/manifest.json",
      artifact_set_id: "client-artifacts-v1",
      artifact_protocol_version: 1,
      artifact_key_id: "release-key-v1",
      artifact_public_key: "A".repeat(43),
      circuit_version: "note-use-v1",
      proving_key_version: "phase2-v1",
    }),
  );
  const secret = async (name: string, contents: string) => {
    const path = join(root, name);
    await writeFile(path, `${contents}\n`, { mode: 0o600 });
    return path;
  };
  const cookieKey = Buffer.alloc(32, 1).toString("base64url");
  const storeKey = Buffer.alloc(32, 2).toString("base64url");
  return {
    cookieKey,
    storeKey,
    env: {
      DARKNYX_TRADER_ORIGIN: "https://app.example",
      DARKNYX_TRADER_STATIC_ROOT: staticRoot,
      DARKNYX_TRADER_RELEASE_FILE: releaseFile,
      DARKNYX_TRADER_CVM_GATEWAY_UPSTREAM: "https://cvm.example/",
      DARKNYX_TRADER_RPC_UPSTREAM_FILE: await secret(
        "rpc.url",
        "https://devnet.helius-rpc.com/?api-key=private",
      ),
      DARKNYX_TRADER_COOKIE_KEY_FILE: await secret("cookie.key", cookieKey),
      DARKNYX_TRADER_ACCOUNT_STORE_KEY_FILE: await secret(
        "account-store.key",
        storeKey,
      ),
      DARKNYX_TRADER_ADMIN_CREDENTIALS_FILE: await secret(
        "admin.json",
        JSON.stringify({
          api_key: "admin-api-key",
          api_secret: "admin-api-secret",
          passphrase: "admin-passphrase",
        }),
      ),
      DARKNYX_TRADER_ACCOUNT_STORE: join(root, "state", "accounts.enc.json"),
    },
  };
}

describe("trader-host runtime configuration", () => {
  it("composes a separately deployable host from strict file-backed secrets", async () => {
    const { env } = await fixture();
    const config = await loadTraderHostRuntimeConfig(env);
    expect(config).toMatchObject({ listenHost: "127.0.0.1", port: 8080 });
    const server = createReleaseHost(config.host);
    expect(server.listening).toBe(false);
  });

  it("rejects unknown configuration, reused keys, and exposed secret files", async () => {
    const unknown = await fixture();
    unknown.env.DARKNYX_TRADER_CVM_API_SECRET = "inline-secret";
    await expect(loadTraderHostRuntimeConfig(unknown.env)).rejects.toThrow(
      "unknown trader-host environment",
    );

    const reused = await fixture();
    await writeFile(
      reused.env.DARKNYX_TRADER_ACCOUNT_STORE_KEY_FILE!,
      `${reused.cookieKey}\n`,
      { mode: 0o600 },
    );
    await expect(loadTraderHostRuntimeConfig(reused.env)).rejects.toThrow(
      "must be independent",
    );

    const exposed = await fixture();
    await chmod(exposed.env.DARKNYX_TRADER_COOKIE_KEY_FILE!, 0o644);
    await expect(loadTraderHostRuntimeConfig(exposed.env)).rejects.toThrow(
      "must not be accessible",
    );
  });
});
