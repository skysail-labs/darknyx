import { mkdtemp, readFile, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  createCvmTokenIssuer,
  createProvisioningCredentialResolver,
  createReleaseHost,
  parsePublicRelease,
  type IsolatedTokenIssuer,
  type PublicRelease,
  type ReleaseHostOptions,
} from "../src/index.js";

const canonicalOrigin = "https://app.example";
const release: PublicRelease = {
  schema_version: 1,
  release_id: "test-release",
  venue_id: "devnet",
  gateway_url: "https://gateway.example/venue/",
  rpc_url: "https://rpc.example/",
  vault_program_id: "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
  expected_compose_hash: "ab".repeat(32),
  expected_oracle_mode: "pyth-solana-push-v1",
  recovery_start_slot: 123_456,
  artifact_manifest_url: "https://artifacts.example/client/manifest.json",
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
    servers.splice(0).map(
      (server) =>
        new Promise<void>((resolve) => {
          server.closeAllConnections();
          server.close(() => resolve());
        }),
    ),
  );
  vi.restoreAllMocks();
});

async function fixture(
  issueToken: IsolatedTokenIssuer,
  override: Partial<ReleaseHostOptions> = {},
) {
  const root = await mkdtemp(join(tmpdir(), "darknyx-host-"));
  await writeFile(
    join(root, "index.html"),
    "<!doctype html><main>Darknyx</main>",
  );
  await writeFile(join(root, `app.${"a".repeat(16)}.js`), "export {};\n");
  let randomCounter = 0;
  const server = createReleaseHost({
    origin: canonicalOrigin,
    staticRoot: root,
    release,
    cookieKey: new Uint8Array(32).fill(9),
    issueToken,
    randomBytes: (length) => new Uint8Array(length).fill((randomCounter += 1)),
    ...override,
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("missing address");
  }
  return { base: `http://127.0.0.1:${address.port}`, root };
}

function sessionRequest(
  base: string,
  options: {
    cookie?: string;
    origin?: string;
    site?: string;
    method?: string;
    contentType?: string;
    body?: string;
  } = {},
) {
  return fetch(`${base}/api/darknyx/session`, {
    method: options.method ?? "POST",
    headers: {
      ...(options.origin === "absent"
        ? {}
        : { origin: options.origin ?? canonicalOrigin }),
      "sec-fetch-site": options.site ?? "same-origin",
      ...(options.contentType === "absent"
        ? {}
        : { "content-type": options.contentType ?? "application/json" }),
      ...(options.cookie ? { cookie: options.cookie } : {}),
    },
    ...((options.method ?? "POST") === "GET"
      ? {}
      : {
          body: options.body ?? JSON.stringify({ venue_id: "devnet" }),
        }),
  });
}

function cookie(response: Response): string {
  const value = response.headers.get("set-cookie")?.split(";")[0];
  if (!value) throw new Error("session cookie is missing");
  return value;
}

function mutateEncoded(value: string): string {
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length === 0) throw new Error("encoded test value is empty");
  bytes[0] = (bytes[0] ?? 0) ^ 0xff;
  return bytes.toString("base64url");
}

describe("release host", () => {
  it("persists isolated CVM accounts durably with unique authenticated IVs", async () => {
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
      return new Response(JSON.stringify({ api_key: "created" }), {
        status: 201,
        headers: { "content-type": "application/json" },
      });
    };
    let randomCounter = 0;
    const ivs: string[] = [];
    const options = {
      gatewayUrl: "https://gateway.example/venue/",
      storePath,
      encryptionKey: new Uint8Array(32).fill(4),
      adminCredentials: {
        apiKey: "admin",
        apiSecret: "admin-secret",
        passphrase: "admin-passphrase",
      },
      fetchImpl,
      randomBytes: (length: number) => {
        const bytes = new Uint8Array(length).fill((randomCounter += 1));
        if (length === 12) ivs.push(Buffer.from(bytes).toString("hex"));
        return bytes;
      },
      now: () => new Date("2026-08-11T00:00:00.000Z"),
    };
    const firstResolver = createProvisioningCredentialResolver(options);
    const first = await firstResolver("01".repeat(32), "devnet");
    expect(first.apiKey).toMatch(/^web-[0-9a-f]{32}$/);
    expect(calls).toEqual([
      "https://gateway.example/venue/auth/token",
      "https://gateway.example/venue/admin/accounts",
    ]);
    expect(ivs).toHaveLength(2);
    expect(new Set(ivs).size).toBe(2);
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

    for (const field of ["ciphertext", "tag"] as const) {
      const tampered = JSON.parse(disk) as Record<typeof field, string>;
      tampered[field] = mutateEncoded(tampered[field]);
      await writeFile(storePath, JSON.stringify(tampered));
      const rejectsTamper = createProvisioningCredentialResolver(options);
      await expect(rejectsTamper("01".repeat(32), "devnet")).rejects.toThrow(
        /authentication failed/,
      );
    }
  });

  it("bounds token exchange latency, body size, lifetime, and gateway paths", async () => {
    const seen: string[] = [];
    const issuer = createCvmTokenIssuer({
      gatewayUrl: "https://gateway.example/venue/",
      resolveCredentials: async (sessionId, venueId) => ({
        apiKey: `${venueId}-${sessionId}`,
        apiSecret: "server-only-secret",
        passphrase: "server-only-passphrase",
      }),
      fetchImpl: async (input) => {
        seen.push(String(input));
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
    await expect(
      issuer({
        venueId: "devnet",
        sessionId: "session-a",
        request: {} as never,
      }),
    ).resolves.toMatchObject({ accountId: "devnet-session-a" });
    expect(seen).toEqual(["https://gateway.example/venue/auth/token"]);

    const timeoutIssuer = createCvmTokenIssuer({
      gatewayUrl: "https://gateway.example",
      resolveCredentials: async () => ({
        apiKey: "account",
        apiSecret: "secret",
        passphrase: "passphrase",
      }),
      requestTimeoutMs: 5,
      fetchImpl: async (_input, init) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () =>
            reject(new Error("aborted")),
          );
        }),
    });
    await expect(
      timeoutIssuer({
        venueId: "devnet",
        sessionId: "b",
        request: {} as never,
      }),
    ).rejects.toThrow("aborted");

    for (const expiresIn of [29, 3_601]) {
      const invalid = createCvmTokenIssuer({
        gatewayUrl: "https://gateway.example",
        resolveCredentials: async () => ({
          apiKey: "account",
          apiSecret: "secret",
          passphrase: "passphrase",
        }),
        fetchImpl: async () =>
          new Response(
            JSON.stringify({
              access_token: "j".repeat(64),
              token_type: "Bearer",
              expires_in: expiresIn,
            }),
          ),
      });
      await expect(
        invalid({ venueId: "devnet", sessionId: "c", request: {} as never }),
      ).rejects.toThrow(/malformed response/);
    }
    const oversized = createCvmTokenIssuer({
      gatewayUrl: "https://gateway.example",
      resolveCredentials: async () => ({
        apiKey: "account",
        apiSecret: "secret",
        passphrase: "passphrase",
      }),
      fetchImpl: async () =>
        new Response("x".repeat(32 * 1024 + 1), {
          headers: { "content-length": String(32 * 1024 + 1) },
        }),
    });
    await expect(
      oversized({ venueId: "devnet", sessionId: "d", request: {} as never }),
    ).rejects.toThrow(/too large/);
  });

  it("serves bounded real files with the complete isolation/header contract", async () => {
    const { base, root } = await fixture(async ({ sessionId }) => ({
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
    expect(page.headers.get("cross-origin-resource-policy")).toBe(
      "same-origin",
    );
    expect(page.headers.get("strict-transport-security")).toBe(
      "max-age=63072000; includeSubDomains",
    );
    expect(page.headers.get("permissions-policy")).toBe(
      "camera=(), microphone=(), geolocation=(), payment=(), usb=(), publickey-credentials-get=(self), publickey-credentials-create=(self)",
    );
    expect(page.headers.get("x-frame-options")).toBe("DENY");
    expect(page.headers.get("x-content-type-options")).toBe("nosniff");
    expect(page.headers.get("referrer-policy")).toBe("no-referrer");
    const csp = String(page.headers.get("content-security-policy"));
    expect(csp).toContain("require-trusted-types-for 'script'");
    expect(csp).toContain("https://artifacts.example");
    expect(csp).toContain("https://pccs.phala.network");
    expect(csp).not.toContain("unsafe-inline");
    expect(csp).not.toContain("preload");
    const etag = page.headers.get("etag");
    expect(etag).toBeTruthy();
    expect(
      (
        await fetch(base, {
          headers: { "if-none-match": String(etag) },
        })
      ).status,
    ).toBe(304);
    const pins = await fetch(`${base}/release.json`);
    expect(pins.headers.get("cache-control")).toBe("no-store");
    expect(await pins.json()).toEqual(release);
    const asset = await fetch(`${base}/app.${"a".repeat(16)}.js`);
    expect(asset.headers.get("cache-control")).toContain("immutable");
    const health = await fetch(`${base}/healthz`);
    expect(health.status).toBe(200);
    expect(await health.text()).toBe("ok\n");
    expect(health.headers.get("cache-control")).toBe("no-store");
    expect((await fetch(`${base}/healthz`, { method: "POST" })).status).toBe(
      405,
    );

    const outside = join(
      await mkdtemp(join(tmpdir(), "darknyx-outside-")),
      "secret",
    );
    await writeFile(outside, "must not be served");
    await symlink(outside, join(root, "linked.txt"));
    expect((await fetch(`${base}/linked.txt`)).status).toBe(404);
  });

  it("expires signed sessions, rate-limits issuance, and distinguishes isolation failures", async () => {
    let now = Date.UTC(2026, 7, 11);
    const violations: unknown[] = [];
    const { base } = await fixture(
      async () => ({
        accountId: "incorrectly-shared-account",
        accessToken: "t".repeat(64),
        expiresIn: 300,
      }),
      {
        now: () => now,
        sessionTtlSeconds: 60,
        maxTokenRequestsPerMinute: 2,
        onIsolationViolation: (details) => void violations.push(details),
      },
    );
    const first = await sessionRequest(base);
    expect(first.status).toBe(200);
    const firstCookie = cookie(first);
    expect(first.headers.get("set-cookie")).toContain("HttpOnly");
    expect(first.headers.get("set-cookie")).toContain("SameSite=Strict");
    expect(first.headers.get("set-cookie")).toContain("Max-Age=60");
    expect(firstCookie.split(".")).toHaveLength(3);
    expect((await sessionRequest(base, { cookie: firstCookie })).status).toBe(
      200,
    );
    const rateLimited = await sessionRequest(base, { cookie: firstCookie });
    expect(rateLimited.status).toBe(429);
    expect(await rateLimited.json()).toEqual({ error: "token_rate_limited" });

    const collision = await sessionRequest(base);
    expect(collision.status).toBe(503);
    expect(await collision.json()).toEqual({
      error: "account_isolation_failed",
    });
    expect(violations).toHaveLength(1);

    now += 61_000;
    const expired = await sessionRequest(base, { cookie: firstCookie });
    expect(expired.status).toBe(200);
    expect(cookie(expired)).not.toBe(firstCookie);
  });

  it("allows distinct durable accounts for distinct sessions", async () => {
    const accounts = new Map<string, string>();
    const { base } = await fixture(async ({ sessionId }) => {
      const accountId = `account-${sessionId}`;
      accounts.set(sessionId, accountId);
      return { accountId, accessToken: "t".repeat(64), expiresIn: 300 };
    });
    const first = await sessionRequest(base);
    const second = await sessionRequest(base);
    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect(accounts.size).toBe(2);
    expect(new Set(accounts.values()).size).toBe(2);
    expect((await sessionRequest(base, { cookie: cookie(first) })).status).toBe(
      200,
    );
  });

  it("pins every same-origin session rejection and public-manifest boundary", async () => {
    const { base } = await fixture(async ({ sessionId }) => ({
      accountId: sessionId,
      accessToken: "t".repeat(64),
      expiresIn: 300,
    }));
    const cases: Array<{
      options: Parameters<typeof sessionRequest>[1];
      status: number;
      error: string;
    }> = [
      {
        options: { origin: "https://evil.example" },
        status: 403,
        error: "origin_rejected",
      },
      {
        options: { origin: "absent" },
        status: 403,
        error: "origin_rejected",
      },
      {
        options: { site: "cross-site" },
        status: 403,
        error: "site_rejected",
      },
      {
        options: { method: "GET" },
        status: 405,
        error: "method_not_allowed",
      },
      {
        options: { contentType: "absent" },
        status: 415,
        error: "content_type_required",
      },
      {
        options: { body: JSON.stringify({ venue_id: "wrong" }) },
        status: 400,
        error: "unknown_venue",
      },
      {
        options: {
          body: JSON.stringify({ venue_id: "devnet", extra: true }),
        },
        status: 400,
        error: "unknown_venue",
      },
      {
        options: { body: JSON.stringify({ padding: "x".repeat(1_025) }) },
        status: 400,
        error: "malformed_request",
      },
    ];
    for (const testCase of cases) {
      const response = await sessionRequest(base, testCase.options);
      expect(response.status).toBe(testCase.status);
      expect(await response.json()).toEqual({ error: testCase.error });
    }
    expect(() =>
      parsePublicRelease({ ...release, api_secret: "must-never-be-public" }),
    ).toThrow(/unknown or missing fields/);
    expect(() =>
      parsePublicRelease({
        ...release,
        rpc_url: "https://rpc.example/?api-key=must-not-be-public",
      }),
    ).toThrow(/credential-free HTTPS URL/);
    expect(() =>
      parsePublicRelease({ ...release, expected_oracle_mode: "untrusted" }),
    ).toThrow(/invalid pin/);
  });

  it("contains unexpected handler failures behind a 500 boundary", async () => {
    const errors: unknown[] = [];
    const { base } = await fixture(
      async ({ sessionId }) => ({
        accountId: sessionId,
        accessToken: "t".repeat(64),
        expiresIn: 300,
      }),
      {
        clientKey: () => {
          throw new Error("unexpected client identity failure");
        },
        onError: (error) => void errors.push(error),
      },
    );
    const response = await sessionRequest(base);
    expect(response.status).toBe(500);
    expect(errors).toHaveLength(1);
  });
});
