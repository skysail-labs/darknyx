import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import {
  createCvmTokenIssuer,
  createProvisioningCredentialResolver,
  createReleaseHost,
  parsePublicRelease,
  type IsolatedTokenIssuer,
  type PublicRelease,
} from "../src/index.js";

const release: PublicRelease = {
  schema_version: 1,
  release_id: "test-release",
  venue_id: "devnet",
  gateway_url: "https://gateway.example/",
  rpc_url: "https://rpc.example/",
  vault_program_id: "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
  expected_compose_hash: "ab".repeat(32),
  artifact_manifest_url: "https://app.example/artifacts/manifest.json",
  artifact_set_id: "client-artifacts-v1",
  artifact_protocol_version: 1,
  artifact_key_id: "release-key-v1",
  artifact_public_key: "A".repeat(43),
  circuit_version: "note-use-v1",
  proving_key_version: "phase2-v1",
};

const servers: ReturnType<typeof createReleaseHost>[] = [];
afterEach(async () => {
  await Promise.all(
    servers
      .splice(0)
      .map(
        (server) =>
          new Promise<void>((resolve) => server.close(() => resolve())),
      ),
  );
});

async function fixture(issueToken: IsolatedTokenIssuer) {
  const root = await mkdtemp(join(tmpdir(), "darknyx-host-"));
  await writeFile(
    join(root, "index.html"),
    "<!doctype html><main>Darknyx</main>",
  );
  await writeFile(join(root, `app.${"a".repeat(16)}.js`), "export {};\n");
  const server = createReleaseHost({
    origin: "http://localhost",
    staticRoot: root,
    release,
    cookieKey: new Uint8Array(32).fill(9),
    issueToken,
    randomBytes: (length) => new Uint8Array(length).fill(7),
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string")
    throw new Error("missing address");
  return `http://127.0.0.1:${address.port}`;
}

function sessionRequest(base: string, cookie?: string) {
  return fetch(`${base}/api/darknyx/session`, {
    method: "POST",
    headers: {
      origin: "http://localhost",
      "sec-fetch-site": "same-origin",
      "content-type": "application/json",
      ...(cookie ? { cookie } : {}),
    },
    body: JSON.stringify({ venue_id: "devnet" }),
  });
}

describe("release host", () => {
  it("persists isolated CVM accounts in an authenticated store", async () => {
    const root = await mkdtemp(join(tmpdir(), "darknyx-account-store-"));
    const storePath = join(root, "accounts.enc.json");
    const calls: string[] = [];
    const fetchImpl = async (input: string | URL | Request) => {
      const url = String(input);
      calls.push(url);
      if (url.endsWith("/auth/token")) {
        return new Response(
          JSON.stringify({
            access_token: "a".repeat(64),
            token_type: "Bearer",
            expires_in: 300,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      return new Response(
        JSON.stringify({ api_key: "created", is_admin: false }),
        { status: 201, headers: { "content-type": "application/json" } },
      );
    };
    const options = {
      gatewayUrl: "https://gateway.example",
      storePath,
      encryptionKey: new Uint8Array(32).fill(4),
      adminCredentials: {
        apiKey: "admin",
        apiSecret: "admin-secret",
        passphrase: "admin-passphrase",
      },
      fetchImpl,
      randomBytes: (length: number) => new Uint8Array(length).fill(8),
      now: () => new Date("2026-08-11T00:00:00.000Z"),
    };
    const firstResolver = createProvisioningCredentialResolver(options);
    const first = await firstResolver("01".repeat(32), "devnet");
    expect(first.apiKey).toMatch(/^web-[0-9a-f]{32}$/);
    expect(calls).toHaveLength(2);
    const disk = await readFile(storePath, "utf8");
    expect(disk).not.toContain(first.apiKey);
    expect(disk).not.toContain(first.apiSecret);
    expect(disk).not.toContain("admin-secret");

    const restored = createProvisioningCredentialResolver({
      ...options,
      fetchImpl: async () => {
        throw new Error("active account should not hit the network");
      },
    });
    await expect(restored("01".repeat(32), "devnet")).resolves.toEqual(first);

    const tampered = JSON.parse(disk) as { ciphertext: string };
    const last = tampered.ciphertext.at(-1);
    tampered.ciphertext = `${tampered.ciphertext.slice(0, -1)}${last === "A" ? "B" : "A"}`;
    await writeFile(storePath, JSON.stringify(tampered));
    const rejectsTamper = createProvisioningCredentialResolver(options);
    await expect(rejectsTamper("01".repeat(32), "devnet")).rejects.toThrow(
      /authentication failed/,
    );
  });

  it("exchanges only resolver-supplied isolated credentials", async () => {
    const seen: unknown[] = [];
    const issuer = createCvmTokenIssuer({
      gatewayUrl: "https://gateway.example",
      resolveCredentials: async (sessionId, venueId) => ({
        apiKey: `${venueId}-${sessionId}`,
        apiSecret: "server-only-secret",
        passphrase: "server-only-passphrase",
      }),
      fetchImpl: async (_input, init) => {
        seen.push(JSON.parse(String(init?.body)));
        return new Response(
          JSON.stringify({
            access_token: "j".repeat(64),
            token_type: "Bearer",
            expires_in: 300,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      },
    });
    const token = await issuer({
      venueId: "devnet",
      sessionId: "session-a",
      request: {} as never,
    });
    expect(token.accountId).toBe("devnet-session-a");
    expect(seen).toEqual([
      {
        api_key: "devnet-session-a",
        api_secret: "server-only-secret",
        passphrase: "server-only-passphrase",
      },
    ]);
  });

  it("serves public pins with production isolation headers and cache policy", async () => {
    const base = await fixture(async ({ sessionId }) => ({
      accountId: sessionId,
      accessToken: "t".repeat(64),
      expiresIn: 300,
    }));
    const page = await fetch(base);
    expect(await page.text()).toContain("Darknyx");
    expect(page.headers.get("cross-origin-opener-policy")).toBe("same-origin");
    expect(page.headers.get("cross-origin-embedder-policy")).toBe(
      "require-corp",
    );
    expect(page.headers.get("content-security-policy")).toContain(
      "require-trusted-types-for 'script'",
    );
    expect(page.headers.get("content-security-policy")).not.toContain(
      "unsafe-inline",
    );
    const pins = await fetch(`${base}/release.json`);
    expect(pins.headers.get("cache-control")).toBe("no-store");
    expect(await pins.json()).toEqual(release);
    const asset = await fetch(`${base}/app.${"a".repeat(16)}.js`);
    expect(asset.headers.get("cache-control")).toContain("immutable");
  });

  it("issues an HttpOnly session and refuses a shared CVM account", async () => {
    let counter = 0;
    const root = await mkdtemp(join(tmpdir(), "darknyx-host-isolation-"));
    await writeFile(join(root, "index.html"), "ok");
    const server = createReleaseHost({
      origin: "http://localhost",
      staticRoot: root,
      release,
      cookieKey: new Uint8Array(32).fill(9),
      issueToken: async () => ({
        accountId: "incorrectly-shared-account",
        accessToken: "t".repeat(64),
        expiresIn: 300,
      }),
      randomBytes: (length) => new Uint8Array(length).fill(++counter),
    });
    servers.push(server);
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    const address = server.address();
    if (!address || typeof address === "string")
      throw new Error("missing address");
    const isolatedBase = `http://127.0.0.1:${address.port}`;
    const first = await sessionRequest(isolatedBase);
    expect(first.status).toBe(200);
    expect(first.headers.get("set-cookie")).toContain(
      "__Host-darknyx_session=",
    );
    expect(first.headers.get("set-cookie")).toContain("HttpOnly");
    expect(first.headers.get("set-cookie")).toContain("SameSite=Strict");
    expect((await sessionRequest(isolatedBase)).status).toBe(503);
  });

  it("rejects cross-origin brokerage and secret-shaped public manifests", async () => {
    const base = await fixture(async ({ sessionId }) => ({
      accountId: sessionId,
      accessToken: "t".repeat(64),
      expiresIn: 300,
    }));
    const rejected = await fetch(`${base}/api/darknyx/session`, {
      method: "POST",
      headers: {
        origin: "https://evil.example",
        "content-type": "application/json",
      },
      body: JSON.stringify({ venue_id: "devnet" }),
    });
    expect(rejected.status).toBe(403);
    expect(() =>
      parsePublicRelease({ ...release, api_secret: "must-never-be-public" }),
    ).toThrow(/unknown or missing fields/);
  });
});
