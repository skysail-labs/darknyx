import { BrowserVault, IndexedDbVaultStore } from "/dist/index.js";

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
  const restoreStarted = performance.now();
  await vault.restoreBackup(
    config.node_backup,
    config.passphrase,
    "Restored Darknyx browser vault",
  );
  const restoreMs = performance.now() - restoreStarted;
  const restoredRecord = structuredClone(await store.load());
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
