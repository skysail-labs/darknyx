import type { BrowserVaultRecord } from "./codec.js";

const DATABASE = "darknyx-browser-vault";
const STORE = "vault";
const RECORD_KEY = "primary";

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

export interface VaultRecordStore {
  load(): Promise<unknown | null>;
  save(record: BrowserVaultRecord): Promise<void>;
  clear(): Promise<void>;
}

/** Ciphertext-only persistence for the browser note credential. */
export class IndexedDbVaultStore implements VaultRecordStore {
  readonly #databaseName: string;
  #databasePromise: Promise<IDBDatabase> | null = null;

  constructor(databaseName = DATABASE) {
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
      request.onerror = () => {
        this.#databasePromise = null;
        reject(request.error ?? new Error("IndexedDB open failed"));
      };
      request.onblocked = () => {
        this.#databasePromise = null;
        reject(new Error("IndexedDB upgrade blocked"));
      };
    });
    return this.#databasePromise;
  }

  async load(): Promise<unknown | null> {
    const database = await this.#database();
    const transaction = database.transaction(STORE, "readonly");
    const done = transactionDone(transaction);
    const value = await requestResult(
      transaction.objectStore(STORE).get(RECORD_KEY),
    );
    await done;
    return value ?? null;
  }

  async save(record: BrowserVaultRecord): Promise<void> {
    const database = await this.#database();
    const transaction = database.transaction(STORE, "readwrite");
    await Promise.all([
      requestResult(transaction.objectStore(STORE).put(record, RECORD_KEY)),
      transactionDone(transaction),
    ]);
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
