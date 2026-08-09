import { randomBytes, validateRecord, vaultHeader } from "./codec.js";
import { IndexedDbVaultStore } from "./indexeddb-store.js";
import {
  createPrfCredential,
  deriveWrappingKey,
  evaluatePrf,
} from "./webauthn-prf.js";

let workerUrlPolicy;

function trustedVaultWorkerUrl(workerUrl) {
  if (!globalThis.trustedTypes) return workerUrl;
  workerUrlPolicy ??= globalThis.trustedTypes.createPolicy(
    "darknyx-vault-worker",
    {
      createScriptURL(value) {
        if (value !== "/vault-worker.js") {
          throw new Error("refusing a non-canonical vault Worker URL");
        }
        return value;
      },
    },
  );
  return workerUrlPolicy.createScriptURL(workerUrl);
}

async function createWrappingContext(label) {
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

export class BrowserVault {
  constructor({
    store = new IndexedDbVaultStore(),
    workerUrl = "/vault-worker.js",
    inactivityMs = 5 * 60_000,
  } = {}) {
    this.store = store;
    this.inactivityMs = inactivityMs;
    this.worker = new Worker(trustedVaultWorkerUrl(workerUrl));
    this.pending = new Map();
    this.nextId = 1;
    this.destroyed = false;
    this.failure = null;
    this.worker.onmessage = ({ data }) => {
      if (data.kind === "event") return;
      const pending = this.pending.get(data.id);
      if (!pending) return;
      this.pending.delete(data.id);
      if (data.ok) pending.resolve(data.value);
      else pending.reject(new Error(data.error));
    };
    this.worker.onerror = ({ message }) => {
      const error = new Error(`vault Worker failed: ${message}`);
      this.failure = error;
      for (const { reject } of this.pending.values()) reject(error);
      this.pending.clear();
      this.worker.terminate();
    };
  }

  request(type, payload = {}) {
    if (this.destroyed)
      return Promise.reject(new Error("browser vault is destroyed"));
    if (this.failure) return Promise.reject(this.failure);
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      try {
        this.worker.postMessage({ id, type, payload });
      } catch (error) {
        this.pending.delete(id);
        reject(error);
      }
    });
  }

  async provision(label) {
    if (await this.store.load())
      throw new Error("browser vault is already provisioned");
    const { header, wrappingKey } = await createWrappingContext(label);
    const result = await this.request("provision", {
      wrappingKey,
      header,
      inactivityMs: this.inactivityMs,
    });
    const record = { ...header, cipher: result.cipher };
    await this.store.save(record);
    return { state: "unlocked", testFingerprint: result.testFingerprint };
  }

  async unlock() {
    const parsed = validateRecord(await this.store.load());
    const output = await evaluatePrf(
      parsed.record.credential_id,
      parsed.prfInput,
    );
    let wrappingKey;
    try {
      wrappingKey = await deriveWrappingKey(output, parsed.hkdfSalt);
    } finally {
      output.fill(0);
    }
    await this.request("unlock", {
      wrappingKey,
      record: parsed.record,
      inactivityMs: this.inactivityMs,
    });
  }

  async lock() {
    await this.request("lock");
  }

  async status() {
    return this.request("status");
  }

  async exportBackup(passphrase) {
    return this.request("exportBackup", { passphrase });
  }

  async restore(backup, passphrase, label) {
    if (await this.store.load())
      throw new Error("clear the existing vault before restore");
    const { header, wrappingKey } = await createWrappingContext(label);
    const result = await this.request("restore", {
      backup,
      passphrase,
      wrappingKey,
      header,
      inactivityMs: this.inactivityMs,
    });
    await this.store.save({ ...header, cipher: result.cipher });
    return { state: "unlocked", testFingerprint: result.testFingerprint };
  }

  async testOnlyFingerprint() {
    return this.request("testOnlyFingerprint");
  }

  async testOnlyMatchesSeed(candidate) {
    return this.request("testOnlyMatchesSeed", { candidate });
  }

  destroy() {
    if (this.destroyed) return;
    this.destroyed = true;
    this.worker.terminate();
    for (const { reject } of this.pending.values())
      reject(new Error("browser vault destroyed"));
    this.pending.clear();
  }
}
