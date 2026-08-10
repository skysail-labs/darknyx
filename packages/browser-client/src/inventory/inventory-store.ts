import { fromBase64Url, toBase64Url } from "../custody/codec.js";
import type { InventorySnapshot } from "./types.js";

const DATABASE = "darknyx-browser-inventory";
const STORE = "inventory";
const RECORD_KEY = "primary";
interface EncryptedInventoryRecord {
  format: "darknyx-browser-inventory-ciphertext";
  version: 1;
  cipher: "AES-256-GCM";
  iv: string;
  ciphertext: string;
}

export interface InventorySnapshotStore {
  load(): Promise<InventorySnapshot | null>;
  save(snapshot: InventorySnapshot): Promise<void>;
  clear(): Promise<void>;
}

export interface InventoryCiphertext {
  iv: Uint8Array;
  ciphertext: Uint8Array;
}

export interface InventoryCipher {
  seal(plaintext: Uint8Array): Promise<InventoryCiphertext>;
  open(ciphertext: InventoryCiphertext): Promise<Uint8Array>;
}

function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () =>
      reject(request.error ?? new Error("IndexedDB request failed"));
  });
}

function transactionDone(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onabort = () =>
      reject(transaction.error ?? new Error("IndexedDB transaction aborted"));
    transaction.onerror = () =>
      reject(transaction.error ?? new Error("IndexedDB transaction failed"));
  });
}

function encodeSnapshot(snapshot: InventorySnapshot): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(
    new TextEncoder().encode(
      JSON.stringify(snapshot, (_key, value: unknown) => {
        if (typeof value === "bigint") return { $bigint: value.toString() };
        if (value instanceof Uint8Array) {
          return { $bytes: toBase64Url(value) };
        }
        return value;
      }),
    ),
  );
}

function decodeSnapshot(bytes: Uint8Array): InventorySnapshot {
  let value: unknown;
  try {
    value = JSON.parse(
      new TextDecoder().decode(bytes),
      (_key, item: unknown) => {
        if (item && typeof item === "object" && "$bigint" in item) {
          const encoded = (item as { $bigint: unknown }).$bigint;
          if (typeof encoded !== "string" || !/^(0|[1-9]\d*)$/.test(encoded)) {
            throw new Error("invalid bigint in inventory snapshot");
          }
          return BigInt(encoded);
        }
        if (item && typeof item === "object" && "$bytes" in item) {
          const encoded = (item as { $bytes: unknown }).$bytes;
          if (typeof encoded !== "string") {
            throw new Error("invalid bytes in inventory snapshot");
          }
          return fromBase64Url(encoded);
        }
        return item;
      },
    );
  } catch {
    throw new Error("browser inventory plaintext is malformed");
  }
  if (
    !value ||
    typeof value !== "object" ||
    !("format" in value) ||
    value.format !== "darknyx-browser-inventory" ||
    !("version" in value) ||
    value.version !== 1 ||
    !("notes" in value) ||
    !Array.isArray(value.notes) ||
    !("proofs" in value) ||
    !Array.isArray(value.proofs) ||
    !("reservations" in value) ||
    !Array.isArray(value.reservations) ||
    !("roots" in value) ||
    !Array.isArray(value.roots)
  ) {
    throw new Error("unsupported browser inventory snapshot");
  }
  return value as InventorySnapshot;
}

function validateEncryptedRecord(value: unknown): EncryptedInventoryRecord {
  if (
    !value ||
    typeof value !== "object" ||
    !("format" in value) ||
    value.format !== "darknyx-browser-inventory-ciphertext" ||
    !("version" in value) ||
    value.version !== 1 ||
    !("cipher" in value) ||
    value.cipher !== "AES-256-GCM" ||
    !("iv" in value) ||
    typeof value.iv !== "string" ||
    !("ciphertext" in value) ||
    typeof value.ciphertext !== "string"
  ) {
    throw new Error("unsupported or malformed browser inventory record");
  }
  const record = value as EncryptedInventoryRecord;
  if (fromBase64Url(record.iv).length !== 12) {
    throw new Error("browser inventory IV must be 12 bytes");
  }
  return record;
}

/** Ciphertext-only durable storage for note openings, proofs and reservations. */
export class EncryptedIndexedDbInventoryStore implements InventorySnapshotStore {
  readonly #cipher: InventoryCipher;
  readonly #databaseName: string;
  #databasePromise: Promise<IDBDatabase> | null = null;

  constructor(cipher: InventoryCipher, databaseName = DATABASE) {
    this.#cipher = cipher;
    this.#databaseName = databaseName;
  }

  async #database(): Promise<IDBDatabase> {
    this.#databasePromise ??= new Promise((resolve, reject) => {
      const request = indexedDB.open(this.#databaseName, 1);
      request.onupgradeneeded = () => {
        if (!request.result.objectStoreNames.contains(STORE)) {
          request.result.createObjectStore(STORE);
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () =>
        reject(request.error ?? new Error("IndexedDB open failed"));
      request.onblocked = () => reject(new Error("IndexedDB upgrade blocked"));
    });
    return this.#databasePromise;
  }

  async load(): Promise<InventorySnapshot | null> {
    const database = await this.#database();
    const transaction = database.transaction(STORE, "readonly");
    const done = transactionDone(transaction);
    const raw = await requestResult(
      transaction.objectStore(STORE).get(RECORD_KEY),
    );
    await done;
    if (raw === undefined) return null;
    const record = validateEncryptedRecord(raw);
    try {
      const plaintext = await this.#cipher.open({
        iv: fromBase64Url(record.iv),
        ciphertext: fromBase64Url(record.ciphertext),
      });
      try {
        return decodeSnapshot(plaintext);
      } finally {
        plaintext.fill(0);
      }
    } catch (error) {
      if (
        error instanceof Error &&
        (error.message.includes("snapshot") ||
          error.message === "browser vault is locked")
      ) {
        throw error;
      }
      throw new Error("browser inventory decrypt failed");
    }
  }

  async save(snapshot: InventorySnapshot): Promise<void> {
    const plaintext = encodeSnapshot(snapshot);
    try {
      const sealed = await this.#cipher.seal(plaintext);
      if (sealed.iv.length !== 12 || sealed.ciphertext.length < 16) {
        throw new Error("inventory cipher returned malformed ciphertext");
      }
      const record: EncryptedInventoryRecord = {
        format: "darknyx-browser-inventory-ciphertext",
        version: 1,
        cipher: "AES-256-GCM",
        iv: toBase64Url(sealed.iv),
        ciphertext: toBase64Url(sealed.ciphertext),
      };
      const database = await this.#database();
      const transaction = database.transaction(STORE, "readwrite");
      await Promise.all([
        requestResult(transaction.objectStore(STORE).put(record, RECORD_KEY)),
        transactionDone(transaction),
      ]);
    } finally {
      plaintext.fill(0);
    }
  }

  async clear(): Promise<void> {
    const database = await this.#database();
    const transaction = database.transaction(STORE, "readwrite");
    await Promise.all([
      requestResult(transaction.objectStore(STORE).delete(RECORD_KEY)),
      transactionDone(transaction),
    ]);
  }
}

export class InMemoryInventoryStore implements InventorySnapshotStore {
  #snapshot: InventorySnapshot | null = null;

  async load(): Promise<InventorySnapshot | null> {
    return this.#snapshot ? structuredClone(this.#snapshot) : null;
  }

  async save(snapshot: InventorySnapshot): Promise<void> {
    this.#snapshot = structuredClone(snapshot);
  }

  async clear(): Promise<void> {
    this.#snapshot = null;
  }
}
