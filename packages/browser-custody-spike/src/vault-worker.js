/* global scrypt */
// The harness prepends the pinned scrypt-js source to this classic Worker.
// Production packaging would bundle it the same way: no runtime importScripts,
// no second script URL, and no Trusted Types escape hatch for dynamic imports.

const encoder = new TextEncoder();
const VAULT_AAD_DOMAIN = "darknyx/browser-vault/v1";
const BACKUP_AAD = encoder.encode("darknyx/master-seed-backup/v2");
const BACKUP_FORMAT = "darknyx-master-seed-backup";
const BACKUP_VERSION = 2;
const CURRENT_SCRYPT_N = 131_072;
const ACCEPTED_SCRYPT_N = new Set([16_384, CURRENT_SCRYPT_N]);
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const MIN_PASSPHRASE_LENGTH = 12;

let seed = null;
let inactivityTimer = null;
let configuredInactivityMs = 0;
let inactivityDeadline = 0;

function randomBytes(length) {
  const value = new Uint8Array(length);
  crypto.getRandomValues(value);
  return value;
}

function toBase64Url(value) {
  let binary = "";
  for (const byte of new Uint8Array(value)) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

function fromBase64Url(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("invalid base64url value");
  }
  const padded = value
    .replaceAll("-", "+")
    .replaceAll("_", "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  const decoded = Uint8Array.from(binary, (character) =>
    character.charCodeAt(0),
  );
  if (toBase64Url(decoded) !== value)
    throw new Error("non-canonical base64url value");
  return decoded;
}

function toHex(value) {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

function fromHex(value, length, label) {
  if (
    typeof value !== "string" ||
    value.length !== length * 2 ||
    !/^[0-9a-fA-F]+$/.test(value)
  ) {
    throw new Error(`${label} must be exactly ${length} bytes of hex`);
  }
  return Uint8Array.from(value.match(/../g), (byte) =>
    Number.parseInt(byte, 16),
  );
}

function aadForHeader(header) {
  return encoder.encode(
    `${VAULT_AAD_DOMAIN}\n${header.format}\n${header.version}\n${header.key_source}\n${header.credential_id}\n${header.prf_input}\n${header.hkdf_salt}`,
  );
}

function clearSeed(reason = "explicit") {
  if (inactivityTimer) clearTimeout(inactivityTimer);
  inactivityTimer = null;
  inactivityDeadline = 0;
  seed?.fill(0);
  seed = null;
  if (reason === "inactivity") {
    postMessage({ kind: "event", event: "locked", reason });
  }
}

function configureInactivity(inactivityMs) {
  if (!Number.isFinite(inactivityMs) || inactivityMs <= 0) {
    throw new Error("inactivity timeout must be a positive number");
  }
  configuredInactivityMs = inactivityMs;
}

function armInactivity(inactivityMs = configuredInactivityMs) {
  if (inactivityTimer) clearTimeout(inactivityTimer);
  inactivityDeadline = performance.now() + inactivityMs;
  inactivityTimer = setTimeout(() => clearSeed("inactivity"), inactivityMs);
}

function rearmUntil(deadline) {
  if (!seed || deadline <= 0) return;
  const remaining = deadline - performance.now();
  if (remaining <= 0) {
    clearSeed("inactivity");
    return;
  }
  inactivityDeadline = deadline;
  inactivityTimer = setTimeout(() => clearSeed("inactivity"), remaining);
}

function requireSeed() {
  if (!seed) throw new Error("browser vault is locked");
  return seed;
}

async function fingerprint(value) {
  const domain = encoder.encode("darknyx/browser-vault-spike/fingerprint/v1");
  const input = new Uint8Array(domain.length + value.length);
  input.set(domain);
  input.set(value, domain.length);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", input));
  input.fill(0);
  return toBase64Url(digest);
}

async function encryptVault(wrappingKey, header, value) {
  const iv = randomBytes(12);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: aadForHeader(header) },
      wrappingKey,
      value,
    ),
  );
  return {
    name: "AES-256-GCM",
    iv: toBase64Url(iv),
    ciphertext: toBase64Url(ciphertext),
  };
}

async function decryptVault(wrappingKey, record) {
  let plaintext;
  try {
    plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: fromBase64Url(record.cipher.iv),
          additionalData: aadForHeader(record),
        },
        wrappingKey,
        fromBase64Url(record.cipher.ciphertext),
      ),
    );
  } catch {
    throw new Error("browser-vault decrypt failed");
  }
  if (plaintext.length !== 64) {
    plaintext.fill(0);
    throw new Error("browser-vault plaintext has the wrong length");
  }
  return plaintext;
}

function requirePassphrase(passphrase) {
  if (
    typeof passphrase !== "string" ||
    passphrase.length < MIN_PASSPHRASE_LENGTH
  ) {
    throw new Error(
      `seed-backup passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters`,
    );
  }
}

async function deriveBackupKey(passphrase, salt, n) {
  return scrypt.scrypt(
    encoder.encode(passphrase),
    salt,
    n,
    SCRYPT_R,
    SCRYPT_P,
    32,
  );
}

async function exportBackup(passphrase) {
  requirePassphrase(passphrase);
  const currentSeed = requireSeed();
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const keyBytes = await deriveBackupKey(passphrase, salt, CURRENT_SCRYPT_N);
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      "AES-GCM",
      false,
      ["encrypt"],
    );
    const sealed = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: BACKUP_AAD },
        key,
        currentSeed,
      ),
    );
    return {
      format: BACKUP_FORMAT,
      version: BACKUP_VERSION,
      kdf: {
        name: "scrypt",
        n: CURRENT_SCRYPT_N,
        r: SCRYPT_R,
        p: SCRYPT_P,
        salt: toHex(salt),
      },
      cipher: {
        name: "aes-256-gcm",
        iv: toHex(iv),
        ciphertext: toHex(sealed.subarray(0, 64)),
        tag: toHex(sealed.subarray(64)),
      },
    };
  } finally {
    keyBytes.fill(0);
  }
}

async function importBackup(backup, passphrase) {
  requirePassphrase(passphrase);
  if (
    !backup ||
    backup.format !== BACKUP_FORMAT ||
    backup.version !== BACKUP_VERSION ||
    backup.kdf?.name !== "scrypt" ||
    !ACCEPTED_SCRYPT_N.has(backup.kdf.n) ||
    backup.kdf.r !== SCRYPT_R ||
    backup.kdf.p !== SCRYPT_P ||
    backup.cipher?.name !== "aes-256-gcm"
  ) {
    throw new Error("unsupported encrypted seed-backup format or parameters");
  }
  const salt = fromHex(backup.kdf.salt, 16, "backup salt");
  const iv = fromHex(backup.cipher.iv, 12, "backup IV");
  const ciphertext = fromHex(backup.cipher.ciphertext, 64, "backup ciphertext");
  const tag = fromHex(backup.cipher.tag, 16, "backup authentication tag");
  const sealed = new Uint8Array(80);
  sealed.set(ciphertext);
  sealed.set(tag, 64);
  const keyBytes = await deriveBackupKey(passphrase, salt, backup.kdf.n);
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      "AES-GCM",
      false,
      ["decrypt"],
    );
    const plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv, additionalData: BACKUP_AAD },
        key,
        sealed,
      ),
    );
    if (plaintext.length !== 64) {
      plaintext.fill(0);
      throw new Error("decrypted seed has the wrong length");
    }
    return plaintext;
  } catch (error) {
    if (
      error instanceof Error &&
      error.message === "decrypted seed has the wrong length"
    ) {
      throw error;
    }
    throw new Error(
      "seed-backup decrypt failed (wrong passphrase or corrupt backup)",
    );
  } finally {
    keyBytes.fill(0);
    sealed.fill(0);
  }
}

const handlers = {
  async provision({ wrappingKey, header, inactivityMs }) {
    clearSeed();
    configureInactivity(inactivityMs);
    seed = randomBytes(64);
    const cipher = await encryptVault(wrappingKey, header, seed);
    return { cipher, testFingerprint: await fingerprint(seed) };
  },
  async unlock({ wrappingKey, record, inactivityMs }) {
    clearSeed();
    configureInactivity(inactivityMs);
    seed = await decryptVault(wrappingKey, record);
    return { state: "unlocked" };
  },
  async lock() {
    clearSeed();
    return { state: "locked" };
  },
  async status() {
    return { state: seed ? "unlocked" : "locked" };
  },
  async exportBackup({ passphrase }) {
    return exportBackup(passphrase);
  },
  async restore({ backup, passphrase, wrappingKey, header, inactivityMs }) {
    clearSeed();
    configureInactivity(inactivityMs);
    seed = await importBackup(backup, passphrase);
    const cipher = await encryptVault(wrappingKey, header, seed);
    return { cipher, testFingerprint: await fingerprint(seed) };
  },
};

if (self.DARKNYX_CUSTODY_SPIKE_TEST === true) {
  handlers.testOnlyFingerprint = async () => fingerprint(requireSeed());
  handlers.testOnlyMatchesSeed = async ({ candidate }) => {
    const currentSeed = requireSeed();
    const supplied = new Uint8Array(candidate);
    if (supplied.length !== currentSeed.length) return false;
    let different = 0;
    for (let index = 0; index < supplied.length; index += 1) {
      different |= supplied[index] ^ currentSeed[index];
    }
    return different === 0;
  };
}

const PASSIVE_COMMANDS = new Set(["status"]);

async function handleMessage(data) {
  const hasHandler = Object.prototype.hasOwnProperty.call(handlers, data.type);
  if (!hasHandler) {
    postMessage({
      id: data.id,
      ok: false,
      error: `unsupported vault command: ${data.type}`,
    });
    return;
  }
  const passive = PASSIVE_COMMANDS.has(data.type);
  const previousDeadline = inactivityDeadline;
  try {
    // An authorised command is activity. In particular, backup scrypt can run
    // longer than a deliberately short test timeout; never zero the seed in
    // the middle of an in-flight operation and accidentally encrypt zeros.
    if (
      passive &&
      seed &&
      previousDeadline > 0 &&
      performance.now() >= previousDeadline
    ) {
      clearSeed("inactivity");
    }
    if (inactivityTimer) clearTimeout(inactivityTimer);
    inactivityTimer = null;
    const handler = handlers[data.type];
    const value = await handler(data.payload);
    if (seed) {
      if (passive) rearmUntil(previousDeadline);
      else if (data.type !== "lock") armInactivity();
    }
    postMessage({ id: data.id, ok: true, value });
  } catch (error) {
    if (seed) {
      if (passive) rearmUntil(previousDeadline);
      else armInactivity();
    }
    postMessage({
      id: data.id,
      ok: false,
      error:
        error instanceof Error
          ? error.message
          : "browser-vault operation failed",
    });
  }
}

// Worker message handlers are re-entrant across `await`. Serialize them so a
// lock or second export cannot zero/replace the seed while scrypt or AES-GCM is
// still operating on it.
let commandQueue = Promise.resolve();
self.onmessage = ({ data }) => {
  commandQueue = commandQueue.then(() => handleMessage(data));
};
