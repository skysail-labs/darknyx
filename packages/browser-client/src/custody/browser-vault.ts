import type {
  EncryptedSeedBackupV2,
  VaultLifecyclePort,
  VaultStatus,
} from "@darknyx/client-core";

import {
  randomBytes,
  validateRecord,
  vaultHeader,
  type BrowserVaultRecord,
} from "./codec.js";
import {
  IndexedDbVaultStore,
  type VaultRecordStore,
} from "./indexeddb-store.js";
import {
  createPrfCredential,
  deriveWrappingKey,
  evaluatePrf,
} from "./webauthn-prf.js";

type BusyOperation = NonNullable<VaultStatus["operation"]>;
type Pending = {
  resolve(value: unknown): void;
  reject(error: unknown): void;
};

interface TrustedTypesFactoryLike {
  createPolicy(
    name: string,
    rules: { createScriptURL(value: string): string },
  ): { createScriptURL(value: string): unknown };
}

export interface BrowserVaultOptions {
  store?: VaultRecordStore;
  workerUrl?: string | URL;
  inactivityMs?: number;
  workerFactory?: (url: string | URL) => Worker;
}

let workerUrlPolicy:
  | { canonical: string; policy: { createScriptURL(value: string): unknown } }
  | undefined;

function trustedVaultWorkerUrl(canonical: string): string | URL {
  const trustedTypes = (
    globalThis as typeof globalThis & {
      trustedTypes?: TrustedTypesFactoryLike;
    }
  ).trustedTypes;
  if (!trustedTypes) return canonical;
  if (!workerUrlPolicy) {
    workerUrlPolicy = {
      canonical,
      policy: trustedTypes.createPolicy("darknyx-vault-worker", {
        createScriptURL(value) {
          if (value !== canonical) {
            throw new Error("refusing a non-canonical vault Worker URL");
          }
          return value;
        },
      }),
    };
  }
  if (workerUrlPolicy.canonical !== canonical) {
    throw new Error("only one canonical browser-vault Worker URL is allowed");
  }
  return workerUrlPolicy.policy.createScriptURL(canonical) as string;
}

async function createWrappingContext(label: string): Promise<{
  header: Omit<BrowserVaultRecord, "cipher">;
  wrappingKey: CryptoKey;
}> {
  const credential = await createPrfCredential(label);
  const hkdfSalt = randomBytes(32);
  try {
    return {
      header: vaultHeader(
        credential.credentialId,
        credential.prfInput,
        hkdfSalt,
      ),
      wrappingKey: await deriveWrappingKey(credential.output, hkdfSalt),
    };
  } finally {
    credential.output.fill(0);
  }
}

/**
 * Browser implementation of the narrow custody lifecycle.
 *
 * The master seed exists only in the dedicated Worker. This prevents ordinary
 * UI code from receiving it, but deliberately does not claim protection from
 * malicious code delivered by the same trusted origin.
 */
export class BrowserVault implements VaultLifecyclePort {
  readonly #store: VaultRecordStore;
  readonly #worker: Worker;
  readonly #inactivityMs: number;
  readonly #pending = new Map<number, Pending>();
  #nextId = 1;
  #destroyed = false;
  #failure: Error | null = null;
  #operation: BusyOperation | undefined;
  #cachedState: "locked" | "unlocked" = "locked";

  constructor(options: BrowserVaultOptions = {}) {
    this.#store = options.store ?? new IndexedDbVaultStore();
    this.#inactivityMs = options.inactivityMs ?? 5 * 60_000;
    if (!Number.isFinite(this.#inactivityMs) || this.#inactivityMs <= 0) {
      throw new Error("inactivity timeout must be a positive number");
    }
    const canonical = new URL(
      options.workerUrl ?? "./vault.worker.js",
      import.meta.url,
    ).href;
    const createWorker =
      options.workerFactory ?? ((url: string | URL) => new Worker(url));
    this.#worker = createWorker(trustedVaultWorkerUrl(canonical));
    this.#worker.onmessage = ({ data }: MessageEvent) => {
      if (data?.kind === "event" && data.event === "locked") {
        this.#cachedState = "locked";
        return;
      }
      const pending = this.#pending.get(data?.id);
      if (!pending) return;
      this.#pending.delete(data.id);
      if (data.ok) pending.resolve(data.value);
      else pending.reject(new Error(String(data.error)));
    };
    this.#worker.onerror = ({ message }) => {
      const error = new Error(`vault Worker failed: ${message}`);
      this.#failure = error;
      for (const { reject } of this.#pending.values()) reject(error);
      this.#pending.clear();
      this.#worker.terminate();
    };
  }

  async #request<T>(
    type: string,
    payload: Record<string, unknown> = {},
  ): Promise<T> {
    if (this.#destroyed) throw new Error("browser vault is destroyed");
    if (this.#failure) throw this.#failure;
    const id = this.#nextId++;
    return new Promise<T>((resolve, reject) => {
      this.#pending.set(id, {
        resolve: (value) => resolve(value as T),
        reject,
      });
      try {
        this.#worker.postMessage({ id, type, payload });
      } catch (error) {
        this.#pending.delete(id);
        reject(error);
      }
    });
  }

  async #exclusive<T>(
    operation: BusyOperation,
    run: () => Promise<T>,
  ): Promise<T> {
    if (this.#operation) {
      throw new Error(`browser vault is busy with ${this.#operation}`);
    }
    this.#operation = operation;
    try {
      return await run();
    } finally {
      this.#operation = undefined;
    }
  }

  async status(): Promise<VaultStatus> {
    if (this.#operation) return { state: "busy", operation: this.#operation };
    const persisted = await this.#store.load();
    if (!persisted) return { state: "unprovisioned" };
    validateRecord(persisted);
    const status = await this.#request<VaultStatus>("status");
    this.#cachedState = status.state === "unlocked" ? "unlocked" : "locked";
    return { state: this.#cachedState };
  }

  async provision(label: string): Promise<void> {
    await this.#exclusive("provision", async () => {
      if (await this.#store.load()) {
        throw new Error("browser vault is already provisioned");
      }
      const { header, wrappingKey } = await createWrappingContext(label);
      const result = await this.#request<{
        cipher: BrowserVaultRecord["cipher"];
      }>("provision", {
        wrappingKey,
        header,
        inactivityMs: this.#inactivityMs,
      });
      try {
        await this.#store.save({ ...header, cipher: result.cipher });
        this.#cachedState = "unlocked";
      } catch (error) {
        await this.#request("lock").catch(() => undefined);
        this.#cachedState = "locked";
        throw error;
      }
    });
  }

  async unlock(): Promise<void> {
    await this.#exclusive("unlock", async () => {
      const persisted = await this.#store.load();
      if (!persisted) throw new Error("browser vault is not provisioned");
      const parsed = validateRecord(persisted);
      const output = await evaluatePrf(
        parsed.record.credential_id,
        parsed.prfInput,
      );
      try {
        const wrappingKey = await deriveWrappingKey(output, parsed.hkdfSalt);
        await this.#request("unlock", {
          wrappingKey,
          record: parsed.record,
          inactivityMs: this.#inactivityMs,
        });
        this.#cachedState = "unlocked";
      } finally {
        output.fill(0);
      }
    });
  }

  async lock(): Promise<void> {
    if (this.#operation) {
      throw new Error(`browser vault is busy with ${this.#operation}`);
    }
    await this.#request("lock");
    this.#cachedState = "locked";
  }

  async exportBackup(passphrase: string): Promise<EncryptedSeedBackupV2> {
    return this.#exclusive("backup", () =>
      this.#request<EncryptedSeedBackupV2>("exportBackup", { passphrase }),
    );
  }

  async restoreBackup(
    backup: EncryptedSeedBackupV2,
    passphrase: string,
    label: string,
  ): Promise<void> {
    await this.#exclusive("restore", async () => {
      if (await this.#store.load()) {
        throw new Error("clear the existing vault before restore");
      }
      const { header, wrappingKey } = await createWrappingContext(label);
      const result = await this.#request<{
        cipher: BrowserVaultRecord["cipher"];
      }>("restore", {
        backup,
        passphrase,
        wrappingKey,
        header,
        inactivityMs: this.#inactivityMs,
      });
      try {
        await this.#store.save({ ...header, cipher: result.cipher });
        this.#cachedState = "unlocked";
      } catch (error) {
        await this.#request("lock").catch(() => undefined);
        this.#cachedState = "locked";
        throw error;
      }
    });
  }

  destroy(): void {
    if (this.#destroyed) return;
    this.#destroyed = true;
    this.#worker.terminate();
    for (const { reject } of this.#pending.values()) {
      reject(new Error("browser vault destroyed"));
    }
    this.#pending.clear();
    this.#cachedState = "locked";
  }
}
