import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes as nodeRandomBytes,
} from "node:crypto";
import {
  mkdir,
  open as openFile,
  readFile,
  rename,
  rm,
} from "node:fs/promises";
import { dirname } from "node:path";

import { fetchBounded, gatewayBase, readJsonBounded } from "./http.js";
import type { CvmAccountCredentials } from "./types.js";

interface StoredAccount extends CvmAccountCredentials {
  createdAt: string;
  status: "pending" | "active";
}

interface PlainStore {
  schema_version: 1;
  accounts: Record<string, StoredAccount>;
}

interface SealedStore {
  schema_version: 1;
  cipher: "aes-256-gcm";
  iv: string;
  ciphertext: string;
  tag: string;
}

export interface ProvisioningCredentialResolverOptions {
  gatewayUrl: string;
  storePath: string;
  encryptionKey: Uint8Array;
  adminCredentials: CvmAccountCredentials;
  maxAccounts?: number;
  fetchImpl?: typeof fetch;
  randomBytes?: (length: number) => Uint8Array;
  now?: () => Date;
  requestTimeoutMs?: number;
}

const AAD = Buffer.from("darknyx/trader-host-account-store/v1\0");

function token(value: Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}

function accountKey(venueId: string, sessionId: string): string {
  return `${venueId}:${sessionId}`;
}

function apiKey(venueId: string, sessionId: string): string {
  const digest = createHash("sha256")
    .update("darknyx/browser-account/v1\0")
    .update(venueId)
    .update("\0")
    .update(sessionId)
    .digest("hex")
    .slice(0, 32);
  return `web-${digest}`;
}

function emptyStore(): PlainStore {
  return { schema_version: 1, accounts: {} };
}

function parsePlain(value: unknown): PlainStore {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    (value as Record<string, unknown>).schema_version !== 1 ||
    !(value as Record<string, unknown>).accounts ||
    typeof (value as Record<string, unknown>).accounts !== "object"
  ) {
    throw new Error("account store plaintext is malformed");
  }
  const store = value as PlainStore;
  for (const [key, account] of Object.entries(store.accounts)) {
    if (
      !/^[a-z0-9._-]+:[0-9a-f]{64}$/.test(key) ||
      !account ||
      typeof account.apiKey !== "string" ||
      !account.apiKey ||
      typeof account.apiSecret !== "string" ||
      !account.apiSecret ||
      typeof account.passphrase !== "string" ||
      !account.passphrase ||
      typeof account.createdAt !== "string" ||
      Number.isNaN(Date.parse(account.createdAt)) ||
      (account.status !== "pending" && account.status !== "active")
    ) {
      throw new Error("account store contains a malformed record");
    }
  }
  return store;
}

function seal(store: PlainStore, key: Uint8Array, iv: Uint8Array): SealedStore {
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(AAD);
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(store), "utf8"),
    cipher.final(),
  ]);
  return {
    schema_version: 1,
    cipher: "aes-256-gcm",
    iv: token(iv),
    ciphertext: ciphertext.toString("base64url"),
    tag: cipher.getAuthTag().toString("base64url"),
  };
}

function open(value: unknown, key: Uint8Array): PlainStore {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    (value as SealedStore).schema_version !== 1 ||
    (value as SealedStore).cipher !== "aes-256-gcm"
  ) {
    throw new Error("account store envelope is malformed");
  }
  const sealed = value as SealedStore;
  let plaintext: Buffer;
  try {
    const decipher = createDecipheriv(
      "aes-256-gcm",
      key,
      Buffer.from(sealed.iv, "base64url"),
    );
    decipher.setAAD(AAD);
    decipher.setAuthTag(Buffer.from(sealed.tag, "base64url"));
    plaintext = Buffer.concat([
      decipher.update(Buffer.from(sealed.ciphertext, "base64url")),
      decipher.final(),
    ]);
  } catch {
    throw new Error("account store authentication failed");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(plaintext.toString("utf8"));
  } catch {
    throw new Error("account store plaintext is not valid JSON");
  }
  return parsePlain(parsed);
}

async function exchange(
  gateway: URL,
  credentials: CvmAccountCredentials,
  fetchImpl: typeof fetch,
  timeoutMs?: number,
): Promise<string> {
  const response = await fetchBounded(
    fetchImpl,
    new URL("auth/token", gateway),
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify({
        api_key: credentials.apiKey,
        api_secret: credentials.apiSecret,
        passphrase: credentials.passphrase,
      }),
    },
    timeoutMs,
  );
  if (!response.ok)
    throw new Error(`admin token exchange failed (${response.status})`);
  const body = await readJsonBounded(response, 32 * 1024, timeoutMs);
  if (
    typeof body.access_token !== "string" ||
    body.access_token.length < 32 ||
    body.access_token.length > 16_384
  ) {
    throw new Error("admin token exchange returned a malformed response");
  }
  return body.access_token;
}

/**
 * Reference encrypted resolver. It provisions one persistent non-admin CVM
 * account per signed browser session; managed deployments may replace it.
 */
export function createProvisioningCredentialResolver(
  options: ProvisioningCredentialResolverOptions,
): (sessionId: string, venueId: string) => Promise<CvmAccountCredentials> {
  if (options.encryptionKey.length !== 32) {
    throw new Error("account-store encryption key must be 32 bytes");
  }
  const gateway = gatewayBase(options.gatewayUrl);
  const maxAccounts = options.maxAccounts ?? 10_000;
  if (!Number.isSafeInteger(maxAccounts) || maxAccounts < 1) {
    throw new Error("maxAccounts must be a positive safe integer");
  }
  const fetchImpl = options.fetchImpl ?? fetch;
  const random =
    options.randomBytes ?? ((length: number) => nodeRandomBytes(length));
  const now = options.now ?? (() => new Date());
  let cached: PlainStore | null = null;
  let serialized = Promise.resolve();

  async function load(): Promise<PlainStore> {
    if (cached) return cached;
    try {
      cached = open(
        JSON.parse(await readFile(options.storePath, "utf8")),
        options.encryptionKey,
      );
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      cached = emptyStore();
    }
    return cached;
  }

  async function save(store: PlainStore): Promise<void> {
    const iv = random(12);
    if (iv.length !== 12)
      throw new Error("randomBytes returned the wrong IV length");
    const suffix = random(8);
    if (suffix.length !== 8)
      throw new Error("randomBytes returned the wrong temporary-file suffix");
    const bytes = `${JSON.stringify(seal(store, options.encryptionKey, iv))}\n`;
    const temporary = `${options.storePath}.${process.pid}.${token(suffix)}.tmp`;
    const directory = dirname(options.storePath);
    await mkdir(directory, { recursive: true, mode: 0o700 });
    let file: Awaited<ReturnType<typeof openFile>> | undefined;
    try {
      file = await openFile(temporary, "wx", 0o600);
      await file.writeFile(bytes, "utf8");
      await file.sync();
      await file.close();
      file = undefined;
      await rename(temporary, options.storePath);
      const parent = await openFile(directory, "r");
      try {
        await parent.sync();
      } finally {
        await parent.close();
      }
    } catch (error) {
      await file?.close().catch(() => undefined);
      await rm(temporary, { force: true }).catch(() => undefined);
      throw error;
    }
  }

  return async (sessionId, venueId) => {
    if (
      !/^[0-9a-f]{64}$/.test(sessionId) ||
      !/^[a-z0-9][a-z0-9._-]{0,127}$/.test(venueId)
    ) {
      throw new Error("credential resolver received an invalid identity");
    }
    let resolve!: (value: CvmAccountCredentials) => void;
    let reject!: (error: unknown) => void;
    const result = new Promise<CvmAccountCredentials>((yes, no) => {
      resolve = yes;
      reject = no;
    });
    serialized = serialized.then(async () => {
      try {
        const store = await load();
        const key = accountKey(venueId, sessionId);
        let existing = store.accounts[key];
        if (existing?.status === "active") {
          return resolve({
            apiKey: existing.apiKey,
            apiSecret: existing.apiSecret,
            passphrase: existing.passphrase,
          });
        }
        if (!existing && Object.keys(store.accounts).length >= maxAccounts) {
          throw new Error("browser CVM account capacity reached");
        }
        if (!existing) {
          const secret = random(32);
          const passphrase = random(32);
          if (secret.length !== 32 || passphrase.length !== 32) {
            throw new Error("randomBytes returned the wrong credential length");
          }
          existing = {
            apiKey: apiKey(venueId, sessionId),
            apiSecret: token(secret),
            passphrase: token(passphrase),
            createdAt: now().toISOString(),
            status: "pending",
          };
          const pending: PlainStore = {
            schema_version: 1,
            accounts: { ...store.accounts, [key]: existing },
          };
          await save(pending);
          cached = pending;
        }
        const credentials: CvmAccountCredentials = {
          apiKey: existing.apiKey,
          apiSecret: existing.apiSecret,
          passphrase: existing.passphrase,
        };
        const adminToken = await exchange(
          gateway,
          options.adminCredentials,
          fetchImpl,
          options.requestTimeoutMs,
        );
        const registration = await fetchBounded(
          fetchImpl,
          new URL("admin/accounts", gateway),
          {
            method: "POST",
            headers: {
              authorization: `Bearer ${adminToken}`,
              "content-type": "application/json",
            },
            body: JSON.stringify({
              api_key: credentials.apiKey,
              api_secret: credentials.apiSecret,
              passphrase: credentials.passphrase,
              is_admin: false,
            }),
          },
          options.requestTimeoutMs,
        );
        if (registration.status === 409) {
          // A crash may occur after the CVM persisted registration but before
          // the local pending record became active. Prove that the stored
          // credentials own the existing account before completing recovery.
          await exchange(
            gateway,
            credentials,
            fetchImpl,
            options.requestTimeoutMs,
          );
        } else if (registration.status !== 201) {
          throw new Error(
            `CVM account registration failed (${registration.status})`,
          );
        }
        const active: PlainStore = {
          schema_version: 1,
          accounts: {
            ...(cached ?? store).accounts,
            [key]: { ...existing, status: "active" },
          },
        };
        await save(active);
        cached = active;
        resolve(credentials);
      } catch (error) {
        reject(error);
      }
    });
    return result;
  };
}
