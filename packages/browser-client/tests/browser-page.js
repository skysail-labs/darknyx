import { BrowserVault, IndexedDbVaultStore } from "/dist/index.js";
import {
  BrowserInventory,
  BrowserIntentAuthorizer,
  inventoryStoreForVault,
  recoverBrowserInventory,
} from "/dist/internal.js";

const status = document.querySelector("#status");
const config = await fetch("/config.json").then((response) => response.json());
const store = new IndexedDbVaultStore(`darknyx-product-${config.scenario}`);

async function report(body) {
  await fetch("/result", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

function mutate(value) {
  return `${value[0] === "A" ? "B" : "A"}${value.slice(1)}`;
}

function trustedTypesAreEnforced() {
  if (!("trustedTypes" in globalThis)) return false;
  try {
    const worker = new Worker("/dist/vault.worker.js");
    worker.terminate();
    return false;
  } catch (error) {
    return error instanceof TypeError;
  }
}

function readInventoryRecord(databaseName) {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(databaseName, 1);
    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      const transaction = request.result.transaction("inventory", "readonly");
      const get = transaction.objectStore("inventory").get("primary");
      get.onerror = () => reject(get.error);
      get.onsuccess = () => resolve(get.result);
    };
  });
}

function writeInventoryRecord(databaseName, record) {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(databaseName, 1);
    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      const transaction = request.result.transaction("inventory", "readwrite");
      transaction.onerror = () => reject(transaction.error);
      transaction.oncomplete = resolve;
      transaction.objectStore("inventory").put(record, "primary");
    };
  });
}

function fromHex(value) {
  return Uint8Array.from(value.match(/../g) ?? [], (byte) =>
    Number.parseInt(byte, 16),
  );
}

function fromBase64(value) {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}

async function unsupported() {
  await store.clear();
  const vault = new BrowserVault({ store });
  try {
    await vault.provision("Darknyx unsupported PRF test");
    throw new Error("non-PRF authenticator was accepted");
  } catch (error) {
    if (!/PRF is unavailable/.test(String(error))) throw error;
  } finally {
    vault.destroy();
  }
  return { unsupported_prf_failed_closed: true };
}

async function supported() {
  await store.clear();
  const inactivityMs = 150;
  let vault = new BrowserVault({ store, inactivityMs });
  await vault.provision("Darknyx browser vault");
  const original = structuredClone(await store.load());
  if (!original) throw new Error("provision did not persist a record");
  if ((await vault.status()).state !== "unlocked") {
    throw new Error("new vault was not unlocked");
  }

  await vault.lock();
  if ((await vault.status()).state !== "locked") {
    throw new Error("explicit lock failed");
  }
  await vault.unlock();

  const tampered = structuredClone(original);
  tampered.cipher.ciphertext = mutate(tampered.cipher.ciphertext);
  await store.save(tampered);
  await vault.lock();
  let tamperRejected = false;
  try {
    await vault.unlock();
  } catch (error) {
    tamperRejected = /decrypt failed/.test(String(error));
  }
  if (!tamperRejected) throw new Error("tampered ciphertext was accepted");
  await store.save(original);
  await vault.unlock();

  const pollingDeadline = performance.now() + inactivityMs + 120;
  let polled = "unlocked";
  while (performance.now() < pollingDeadline) {
    polled = (await vault.status()).state;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  await new Promise((resolve) => setTimeout(resolve, 80));
  polled = (await vault.status()).state;
  if (polled !== "locked")
    throw new Error("status polling extended inactivity");
  vault.destroy();

  await store.clear();
  vault = new BrowserVault({ store, inactivityMs: 60_000 });
  status.textContent = "restoring";
  const restoreStarted = performance.now();
  await vault.restoreBackup(
    config.node_backup,
    config.passphrase,
    "Restored Darknyx browser vault",
  );
  const restoreMs = performance.now() - restoreStarted;
  const restoredRecord = structuredClone(await store.load());
  const inventoryDatabase = `darknyx-inventory-${config.scenario}`;
  status.textContent = "creating-inventory-store";
  const inventoryStore = await inventoryStoreForVault(vault, inventoryDatabase);
  await inventoryStore.clear();
  status.textContent = "recovering-inventory";
  const recovered = await recoverBrowserInventory({
    vault,
    programId: config.recovery.program_id,
    baseMint: fromHex(config.recovery.base_mint),
    quoteMint: fromHex(config.recovery.quote_mint),
    scan: async () => [
      {
        signature: config.recovery.transaction.signature,
        slot: config.recovery.transaction.slot,
        ixDatas: [fromBase64(config.recovery.transaction.ix_data)],
        logMessages: config.recovery.transaction.logs,
      },
    ],
  });
  const inventory = await BrowserInventory.create({
    store: inventoryStore,
    markets: [
      {
        symbol: "SOL-USDC",
        baseMintHex: config.recovery.base_mint,
        quoteMintHex: config.recovery.quote_mint,
        priceScale: 1_000_000n,
        feeRateBps: 30n,
      },
    ],
    circuitVersion: "valid-input-v3",
    provingKeyVersion: "test-pk",
  });
  status.textContent = "applying-recovery";
  await inventory.recover(recovered, async () => false);
  const inventoryBalance = (await inventory.listBalances())[0];
  if (inventoryBalance.spendableAtoms !== config.recovery.amount) {
    throw new Error("browser seed-plus-chain recovery produced wrong balance");
  }
  const inventoryRecord = structuredClone(
    await readInventoryRecord(inventoryDatabase),
  );
  if (JSON.stringify(inventoryRecord).includes(config.recovery.amount)) {
    throw new Error("inventory plaintext was persisted in IndexedDB");
  }
  const reloaded = await BrowserInventory.create({
    store: inventoryStore,
    markets: [
      {
        symbol: "SOL-USDC",
        baseMintHex: config.recovery.base_mint,
        quoteMintHex: config.recovery.quote_mint,
        priceScale: 1_000_000n,
        feeRateBps: 30n,
      },
    ],
    circuitVersion: "valid-input-v3",
    provingKeyVersion: "test-pk",
  });
  if (
    (await reloaded.listBalances())[0].spendableAtoms !== config.recovery.amount
  ) {
    throw new Error("encrypted inventory did not round-trip");
  }
  status.textContent = "authorizing-order";
  const acceptedRoot = "44".repeat(32);
  await reloaded.synchronizeFinalizedRoots([
    { treeId: 0, finalizedSlot: 101, acceptedRoots: [acceptedRoot] },
  ]);
  await reloaded.cacheReadyProof(
    recovered.notes[0].commitment,
    acceptedRoot,
    new Uint8Array(256).fill(7),
  );
  const draft = {
    protocolVersion: 1,
    marketSymbol: "SOL-USDC",
    side: "bid",
    baseAmountAtoms: "100",
    limitPriceTicks: "1000000",
    attributes: { orderType: "limit", expirySlot: "0", minFillSize: "0" },
  };
  const reservation = await reloaded.reserveReadyIntent(draft);
  if (reservation.status !== "ready") throw new Error("proof was not reservable");
  const authorizer = new BrowserIntentAuthorizer({
    vault,
    inventory: reloaded,
    bootSessionId: "11".repeat(32),
  });
  const envelope = await authorizer.authorizeIntent(draft, reservation.reservation);
  const orderBody = JSON.parse(new TextDecoder().decode(envelope.body));
  if (
    orderBody.order_id !== envelope.clientOrderId ||
    orderBody.trading_key_signature.length !== 128 ||
    orderBody.session_id !== "11".repeat(32)
  ) {
    throw new Error("custody Worker returned a malformed signed order");
  }
  const cancelBody = await authorizer.authorizeCancel(envelope.clientOrderId);
  if (
    cancelBody.trading_key_signature.length !== 128 ||
    cancelBody.session_id !== "11".repeat(32)
  ) {
    throw new Error("custody Worker returned a malformed signed cancel");
  }
  status.textContent = "testing-inventory-lock";
  await vault.lock();
  let inventoryLocked = false;
  try {
    await inventoryStore.load();
  } catch (error) {
    inventoryLocked = /vault is locked/.test(String(error));
  }
  if (!inventoryLocked)
    throw new Error("locked vault still decrypted inventory");
  await vault.unlock();
  const tamperedInventory = structuredClone(inventoryRecord);
  tamperedInventory.ciphertext = mutate(tamperedInventory.ciphertext);
  await writeInventoryRecord(inventoryDatabase, tamperedInventory);
  let inventoryTamperRejected = false;
  try {
    await inventoryStore.load();
  } catch (error) {
    inventoryTamperRejected = /decrypt failed/.test(String(error));
  }
  if (!inventoryTamperRejected) {
    throw new Error("tampered inventory ciphertext was accepted");
  }
  await writeInventoryRecord(inventoryDatabase, inventoryRecord);
  status.textContent = "exporting-backup";
  let responsivenessTicks = 0;
  const heartbeat = setInterval(() => {
    responsivenessTicks += 1;
  }, 10);
  const exportStarted = performance.now();
  const exportPromise = vault.exportBackup(config.passphrase);
  const busyDuringBackup = (await vault.status()).operation === "backup";
  const browserBackup = await exportPromise;
  const exportMs = performance.now() - exportStarted;
  clearInterval(heartbeat);
  const minimumResponsivenessTicks = Math.floor(exportMs / 25);
  const interop = await fetch("/interop", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ browserBackup, restoredRecord }),
  }).then((response) => response.json());
  vault.destroy();

  if (!interop.same_seed || interop.indexeddb_contains_plaintext_seed) {
    throw new Error(
      `backup/storage interop failed: ${JSON.stringify(interop)}`,
    );
  }
  return {
    provision_unlock_lock: true,
    ciphertext_tamper_rejected: tamperRejected,
    status_polling_did_not_extend_inactivity: polled === "locked",
    backup_v2_node_to_browser_to_node: interop.same_seed,
    indexeddb_contains_plaintext_seed:
      interop.indexeddb_contains_plaintext_seed,
    encrypted_inventory_roundtrip: true,
    browser_seed_chain_recovery: recovered.recovered.deposits === 1,
    inventory_revoked_on_lock: inventoryLocked,
    inventory_tamper_rejected: inventoryTamperRejected,
    worker_held_order_authorization: true,
    busy_during_backup: busyDuringBackup,
    ui_responsive_during_backup:
      responsivenessTicks >= minimumResponsivenessTicks,
    restore_ms: Number(restoreMs.toFixed(2)),
    export_ms: Number(exportMs.toFixed(2)),
    cross_origin_isolated: self.crossOriginIsolated,
    trusted_types_available: "trustedTypes" in globalThis,
    trusted_types_enforced: trustedTypesAreEnforced(),
    service_worker_registrations:
      "serviceWorker" in navigator
        ? (await navigator.serviceWorker.getRegistrations()).length
        : 0,
  };
}

try {
  const result = config.hasPrf ? await supported() : await unsupported();
  status.textContent = "complete";
  await report({ ok: true, scenario: config.scenario, result });
} catch (error) {
  const message = error?.stack ?? error?.message ?? String(error);
  status.textContent = message;
  await report({ ok: false, scenario: config.scenario, error: message });
}
