const DATABASE = "darknyx-browser-vault-spike";
const STORE = "vault";
const RECORD_KEY = "primary";

function requestResult(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () =>
      reject(request.error ?? new Error("IndexedDB request failed"));
  });
}

function transactionDone(transaction) {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = resolve;
    transaction.onabort = () =>
      reject(transaction.error ?? new Error("IndexedDB transaction aborted"));
    transaction.onerror = () =>
      reject(transaction.error ?? new Error("IndexedDB transaction failed"));
  });
}

export class IndexedDbVaultStore {
  constructor(databaseName = DATABASE) {
    this.databaseName = databaseName;
    this.databasePromise = null;
  }

  async database() {
    if (!this.databasePromise) {
      this.databasePromise = new Promise((resolve, reject) => {
        const request = indexedDB.open(this.databaseName, 1);
        request.onupgradeneeded = () => request.result.createObjectStore(STORE);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () =>
          reject(request.error ?? new Error("IndexedDB open failed"));
      });
    }
    return this.databasePromise;
  }

  async load() {
    const database = await this.database();
    const transaction = database.transaction(STORE, "readonly");
    const value = await requestResult(
      transaction.objectStore(STORE).get(RECORD_KEY),
    );
    return value ?? null;
  }

  async save(record) {
    const database = await this.database();
    const transaction = database.transaction(STORE, "readwrite");
    const committed = transactionDone(transaction);
    await requestResult(transaction.objectStore(STORE).put(record, RECORD_KEY));
    await committed;
  }

  async clear() {
    const database = await this.database();
    const transaction = database.transaction(STORE, "readwrite");
    const committed = transactionDone(transaction);
    await requestResult(transaction.objectStore(STORE).delete(RECORD_KEY));
    await committed;
  }
}
