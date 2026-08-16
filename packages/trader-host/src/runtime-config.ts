import { constants } from "node:fs";
import { open, readFile } from "node:fs/promises";

import { createProvisioningCredentialResolver } from "./account-store.js";
import { createCvmTokenIssuer } from "./cvm-issuer.js";
import { parsePublicRelease } from "./release.js";
import type { CvmAccountCredentials, ReleaseHostOptions } from "./types.js";

const ENV = [
  "DARKNYX_TRADER_ORIGIN",
  "DARKNYX_TRADER_STATIC_ROOT",
  "DARKNYX_TRADER_RELEASE_FILE",
  "DARKNYX_TRADER_CVM_GATEWAY_UPSTREAM",
  "DARKNYX_TRADER_RPC_UPSTREAM_FILE",
  "DARKNYX_TRADER_COOKIE_KEY_FILE",
  "DARKNYX_TRADER_ACCOUNT_STORE_KEY_FILE",
  "DARKNYX_TRADER_ADMIN_CREDENTIALS_FILE",
  "DARKNYX_TRADER_ACCOUNT_STORE",
  "DARKNYX_TRADER_LISTEN_HOST",
  "DARKNYX_TRADER_PORT",
  "DARKNYX_TRADER_MAX_ACCOUNTS",
  "DARKNYX_TRADER_MAX_TRACKED_SESSIONS",
  "DARKNYX_TRADER_PROXY_TIMEOUT_MS",
  "DARKNYX_TRADER_MAX_PROXY_REQUESTS_PER_MINUTE",
] as const;

const ALLOWED = new Set<string>(ENV);

export interface TraderHostRuntimeConfig {
  listenHost: string;
  port: number;
  host: ReleaseHostOptions;
}

function required(env: NodeJS.ProcessEnv, name: (typeof ENV)[number]): string {
  const value = env[name];
  if (!value || value.trim() !== value) {
    throw new Error(`${name} must be set without surrounding whitespace`);
  }
  return value;
}

function integer(
  env: NodeJS.ProcessEnv,
  name: (typeof ENV)[number],
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  const raw = env[name];
  if (raw === undefined || raw === "") return fallback;
  if (!/^(0|[1-9]\d*)$/.test(raw))
    throw new Error(`${name} must be an integer`);
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be between ${minimum} and ${maximum}`);
  }
  return value;
}

async function secretFile(path: string, label: string): Promise<Buffer> {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) throw new Error(`${label} must be a regular file`);
    if ((stat.mode & 0o077) !== 0) {
      throw new Error(
        `${label} must not be accessible by group or other users`,
      );
    }
    if (stat.size < 1 || stat.size > 16 * 1024) {
      throw new Error(`${label} has an invalid size`);
    }
    return await handle.readFile();
  } finally {
    await handle.close();
  }
}

async function keyFile(path: string, label: string): Promise<Uint8Array> {
  const encoded = (await secretFile(path, label)).toString("utf8").trimEnd();
  if (!/^[A-Za-z0-9_-]{43}$/.test(encoded)) {
    throw new Error(`${label} must contain one canonical base64url key`);
  }
  const bytes = Buffer.from(encoded, "base64url");
  if (bytes.length !== 32 || bytes.toString("base64url") !== encoded) {
    throw new Error(`${label} must contain exactly 32 bytes`);
  }
  return Uint8Array.from(bytes);
}

async function rpcFile(path: string): Promise<string> {
  const value = (await secretFile(path, "RPC upstream file"))
    .toString("utf8")
    .trimEnd();
  if (!value || value.includes("\n") || value.includes("\r")) {
    throw new Error("RPC upstream file must contain one URL");
  }
  return value;
}

async function adminCredentials(path: string): Promise<CvmAccountCredentials> {
  let value: unknown;
  try {
    value = JSON.parse(
      (await secretFile(path, "CVM admin credentials file")).toString("utf8"),
    );
  } catch (error) {
    if (error instanceof SyntaxError) {
      throw new Error("CVM admin credentials file is not valid JSON");
    }
    throw error;
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("CVM admin credentials must be an object");
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  if (keys.join(",") !== "api_key,api_secret,passphrase") {
    throw new Error("CVM admin credentials have unknown or missing fields");
  }
  for (const key of keys) {
    const field = record[key];
    if (typeof field !== "string" || field.length < 8 || field.length > 1024) {
      throw new Error(`CVM admin credential ${key} has an invalid length`);
    }
  }
  return {
    apiKey: record.api_key as string,
    apiSecret: record.api_secret as string,
    passphrase: record.passphrase as string,
  };
}

function assertKnownEnvironment(env: NodeJS.ProcessEnv): void {
  const unknown = Object.keys(env)
    .filter((key) => key.startsWith("DARKNYX_TRADER_") && !ALLOWED.has(key))
    .sort();
  if (unknown.length) {
    throw new Error(
      `unknown trader-host environment variables: ${unknown.join(", ")}`,
    );
  }
}

/** Non-environment inputs a deployment supplies in code. */
export interface TraderHostRuntimeOptions {
  /**
   * `fetch` for every CVM-bound request (T-03P). Supply the verified transport
   * from `@darknyx/sdk/transport-node` to bind each upstream enclave request to
   * an attested certificate on the socket carrying it.
   *
   * Not an environment variable, because building it requires a DCAP verifier
   * and governance pins that belong to the deployment rather than to a string.
   * Unset is the legacy gateway-terminated path.
   */
  cvmFetch?: typeof fetch;
}

export async function loadTraderHostRuntimeConfig(
  env: NodeJS.ProcessEnv = process.env,
  options?: TraderHostRuntimeOptions,
): Promise<TraderHostRuntimeConfig> {
  assertKnownEnvironment(env);
  const origin = required(env, "DARKNYX_TRADER_ORIGIN");
  const staticRoot = required(env, "DARKNYX_TRADER_STATIC_ROOT");
  const releaseFile = required(env, "DARKNYX_TRADER_RELEASE_FILE");
  const gateway = required(env, "DARKNYX_TRADER_CVM_GATEWAY_UPSTREAM");
  const accountStore = required(env, "DARKNYX_TRADER_ACCOUNT_STORE");
  const [release, cookieKey, encryptionKey, admin, rpc] = await Promise.all([
    readFile(releaseFile, "utf8").then((text) => {
      if (Buffer.byteLength(text) > 64 * 1024) {
        throw new Error("public release file is too large");
      }
      return parsePublicRelease(JSON.parse(text) as unknown);
    }),
    keyFile(required(env, "DARKNYX_TRADER_COOKIE_KEY_FILE"), "cookie key file"),
    keyFile(
      required(env, "DARKNYX_TRADER_ACCOUNT_STORE_KEY_FILE"),
      "account-store key file",
    ),
    adminCredentials(required(env, "DARKNYX_TRADER_ADMIN_CREDENTIALS_FILE")),
    rpcFile(required(env, "DARKNYX_TRADER_RPC_UPSTREAM_FILE")),
  ]);
  if (Buffer.from(cookieKey).equals(Buffer.from(encryptionKey))) {
    throw new Error("cookie and account-store keys must be independent");
  }
  const maxAccounts = integer(
    env,
    "DARKNYX_TRADER_MAX_ACCOUNTS",
    10_000,
    1,
    1_000_000,
  );
  const proxyTimeoutMs = integer(
    env,
    "DARKNYX_TRADER_PROXY_TIMEOUT_MS",
    20_000,
    1_000,
    60_000,
  );
  // T-03P: one fetch for every CVM-bound path — the proxy, the token issuer,
  // and account provisioning. A deployment supplies the verified transport
  // from `@darknyx/sdk/transport-node`; unset is the legacy
  // gateway-terminated path. Threading it in ONE place is deliberate: three
  // separate opt-ins is how one of them ends up unverified.
  const cvmFetch = options?.cvmFetch;

  const resolveCredentials = createProvisioningCredentialResolver({
    gatewayUrl: gateway,
    ...(cvmFetch ? { fetchImpl: cvmFetch } : {}),
    storePath: accountStore,
    encryptionKey,
    adminCredentials: admin,
    maxAccounts,
    requestTimeoutMs: proxyTimeoutMs,
  });
  const listenHost = env.DARKNYX_TRADER_LISTEN_HOST || "127.0.0.1";
  if (!new Set(["127.0.0.1", "::1", "0.0.0.0", "::"]).has(listenHost)) {
    throw new Error(
      "DARKNYX_TRADER_LISTEN_HOST must be an explicit loopback or wildcard address",
    );
  }
  return {
    listenHost,
    port: integer(env, "DARKNYX_TRADER_PORT", 8080, 1, 65_535),
    host: {
      origin,
      staticRoot,
      release,
      cookieKey,
      issueToken: createCvmTokenIssuer({
        gatewayUrl: gateway,
        resolveCredentials,
        requestTimeoutMs: proxyTimeoutMs,
        ...(cvmFetch ? { fetchImpl: cvmFetch } : {}),
      }),
      gatewayUpstreamUrl: gateway,
      rpcUpstreamUrl: rpc,
      ...(cvmFetch ? { cvmFetch } : {}),
      proxyTimeoutMs,
      maxProxyRequestsPerMinute: integer(
        env,
        "DARKNYX_TRADER_MAX_PROXY_REQUESTS_PER_MINUTE",
        600,
        1,
        10_000,
      ),
      maxTrackedSessions: integer(
        env,
        "DARKNYX_TRADER_MAX_TRACKED_SESSIONS",
        10_000,
        1,
        1_000_000,
      ),
    },
  };
}
