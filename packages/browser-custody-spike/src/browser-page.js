import { BrowserVault } from "./browser-vault.js";
import { toBase64Url } from "./codec.js";
import { IndexedDbVaultStore } from "./indexeddb-store.js";
import { simulateSameOriginCompromise } from "./same-origin-attack.js";

const status = document.querySelector("#status");
const config = await fetch("/config.json").then((response) => response.json());
const store = new IndexedDbVaultStore(`darknyx-custody-${config.scenario}`);

function mutateBase64Url(value) {
  return `${value[0] === "A" ? "B" : "A"}${value.slice(1)}`;
}

function bytesToHex(value) {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

function bytesToBase64(value) {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary);
}

async function postResult(result) {
  await fetch("/result", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(result),
  });
}

async function progress(stage) {
  status.textContent = stage;
  await fetch("/progress", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ stage }),
  });
}

function trustedTypesAreEnforced() {
  if (!("trustedTypes" in globalThis)) return false;
  try {
    const worker = new Worker("/vault-worker.js");
    worker.terminate();
    return false;
  } catch (error) {
    return error instanceof TypeError;
  }
}

async function runUnsupportedScenario() {
  await store.clear();
  const vault = new BrowserVault({ store, inactivityMs: 60_000 });
  let error = null;
  try {
    await vault.provision("PRF unavailable test");
  } catch (caught) {
    error = caught instanceof Error ? caught.message : String(caught);
  } finally {
    vault.destroy();
  }
  if (!/PRF is unavailable/.test(error ?? "")) {
    throw new Error(`unsupported authenticator did not fail closed: ${error}`);
  }
  return { prf_unsupported_failed_closed: true, error };
}

async function runSupportedScenario() {
  await store.clear();
  await progress("provision");
  const inactivityMs = 150;
  let vault = new BrowserVault({ store, inactivityMs });
  const provisioned = await vault.provision("Darknyx custody spike");
  const firstRecord = structuredClone(await store.load());
  if (!firstRecord) throw new Error("provisioning wrote no IndexedDB record");

  await vault.lock();
  let lockedCommandRejected = false;
  try {
    await vault.testOnlyFingerprint();
  } catch (error) {
    lockedCommandRejected = /locked/.test(String(error));
  }
  await vault.unlock();
  await progress("unlock-roundtrip");
  const unlockedFingerprint = await vault.testOnlyFingerprint();
  if (unlockedFingerprint !== provisioned.testFingerprint) {
    throw new Error("unlock recovered a different seed");
  }

  const backupStarted = performance.now();
  await progress("backup-export");
  const backup = await vault.exportBackup("correct horse battery staple");
  const backupExportMs = performance.now() - backupStarted;
  if (backup.kdf.n !== 131_072 || backup.version !== 2) {
    throw new Error("browser backup drifted from master-seed backup v2");
  }
  const interop = await fetch("/interop", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(backup),
  }).then((response) => response.json());
  if (!interop.browser_backup_opened_by_node) {
    throw new Error("Node could not open the browser-produced backup");
  }

  await vault.lock();
  const tampered = structuredClone(firstRecord);
  tampered.cipher.ciphertext = mutateBase64Url(tampered.cipher.ciphertext);
  await store.save(tampered);
  let tamperRejected = false;
  try {
    await vault.unlock();
  } catch (error) {
    tamperRejected = /decrypt failed/.test(String(error));
  }
  await store.save(firstRecord);
  await vault.unlock();
  await progress("tamper-rejected");
  const pollingDeadline = performance.now() + inactivityMs + 100;
  let lastPolledState = "unlocked";
  while (performance.now() < pollingDeadline) {
    lastPolledState = (await vault.status()).state;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  lastPolledState = (await vault.status()).state;
  const inactivityLocked = lastPolledState === "locked";
  vault.destroy();

  // Recovery is intentionally a new credential: this proves the portable
  // passphrase backup, not passkey synchronisation, is the disaster path.
  await store.clear();
  vault = new BrowserVault({ store, inactivityMs: 60_000 });
  const restoreStarted = performance.now();
  await progress("backup-import");
  const restored = await vault.restore(
    interop.node_backup,
    "correct horse battery staple",
    "Restored Darknyx custody",
  );
  const backupImportMs = performance.now() - restoreStarted;
  if (restored.testFingerprint !== provisioned.testFingerprint) {
    throw new Error("backup restore recovered a different seed");
  }

  const restoredRecord = structuredClone(await store.load());
  await progress("same-origin-attack");
  const attack = await simulateSameOriginCompromise(restoredRecord);
  const serializedRecord = JSON.stringify(restoredRecord);
  const plaintextAbsentFromIndexedDb =
    !serializedRecord.includes(bytesToHex(attack.plaintext)) &&
    !serializedRecord.includes(bytesToBase64(attack.plaintext)) &&
    !serializedRecord.includes(toBase64Url(attack.plaintext));
  const sameOriginAttackSucceeded = await vault.testOnlyMatchesSeed(
    attack.plaintext,
  );
  attack.plaintext.fill(0);

  const serviceWorkers =
    "serviceWorker" in navigator
      ? await navigator.serviceWorker.getRegistrations()
      : [];
  vault.destroy();
  let terminatedWorkerRejected = false;
  try {
    await vault.status();
  } catch (error) {
    terminatedWorkerRejected = /destroyed/.test(String(error));
  }

  return {
    provision_unlock_same_seed:
      unlockedFingerprint === provisioned.testFingerprint,
    locked_command_rejected: lockedCommandRejected,
    ciphertext_tamper_rejected: tamperRejected,
    inactivity_locked: inactivityLocked,
    status_polling_did_not_extend_inactivity: inactivityLocked,
    backup_v2_roundtrip_same_seed:
      interop.browser_backup_opened_by_node &&
      restored.testFingerprint === provisioned.testFingerprint,
    browser_backup_opened_by_node: interop.browser_backup_opened_by_node,
    node_backup_opened_by_browser:
      restored.testFingerprint === provisioned.testFingerprint,
    backup_export_ms: Number(backupExportMs.toFixed(2)),
    backup_import_ms: Number(backupImportMs.toFixed(2)),
    indexeddb_contains_plaintext_seed: !plaintextAbsentFromIndexedDb,
    wrapping_key_extractable: attack.wrappingKeyExtractable,
    same_origin_attack_succeeded: sameOriginAttackSucceeded,
    terminated_worker_rejected: terminatedWorkerRejected,
    cross_origin_isolated: self.crossOriginIsolated,
    trusted_types_available: "trustedTypes" in globalThis,
    trusted_types_enforced: trustedTypesAreEnforced(),
    service_worker_registrations: serviceWorkers.length,
    user_agent: navigator.userAgent,
  };
}

try {
  const result = config.hasPrf
    ? await runSupportedScenario()
    : await runUnsupportedScenario();
  status.textContent = "complete";
  await postResult({ ok: true, scenario: config.scenario, result });
} catch (error) {
  const message = error?.stack ?? error?.message ?? String(error);
  status.textContent = message;
  await postResult({
    ok: false,
    scenario: config.scenario,
    error: message,
  });
}
