import type { EncryptedSeedBackupV2 } from "@darknyx/client-core";

const encoder = new TextEncoder();

export const MASTER_SEED_BYTES = 64;
export const VAULT_FORMAT = "darknyx-browser-vault";
export const VAULT_VERSION = 1;
export const VAULT_AAD_DOMAIN = "darknyx/browser-vault/v1";
export const WRAP_INFO = encoder.encode("darknyx/browser-vault-wrap/v1");
export const BACKUP_AAD = encoder.encode("darknyx/master-seed-backup/v2");

export interface BrowserVaultRecord {
  format: typeof VAULT_FORMAT;
  version: typeof VAULT_VERSION;
  key_source: "webauthn-prf-v1";
  credential_id: string;
  prf_input: string;
  hkdf_salt: string;
  cipher: {
    name: "AES-256-GCM";
    iv: string;
    ciphertext: string;
  };
}

export function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  if (!Number.isSafeInteger(length) || length <= 0) {
    throw new Error("random byte length must be a positive integer");
  }
  const value = new Uint8Array(length);
  crypto.getRandomValues(value);
  return value;
}

export function toBase64Url(value: ArrayBuffer | Uint8Array): string {
  let binary = "";
  for (const byte of new Uint8Array(value)) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

export function fromBase64Url(value: string): Uint8Array<ArrayBuffer> {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("invalid base64url value");
  }
  const padded = value
    .replaceAll("-", "+")
    .replaceAll("_", "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");
  const decoded = Uint8Array.from(atob(padded), (character) =>
    character.charCodeAt(0),
  );
  if (toBase64Url(decoded) !== value) {
    throw new Error("non-canonical base64url value");
  }
  return decoded;
}

export function equalBytes(
  left: ArrayBuffer | Uint8Array,
  right: ArrayBuffer | Uint8Array,
): boolean {
  const a = new Uint8Array(left);
  const b = new Uint8Array(right);
  if (a.length !== b.length) return false;
  let different = 0;
  for (let index = 0; index < a.length; index += 1) {
    different |= a[index] ^ b[index];
  }
  return different === 0;
}

export function vaultHeader(
  credentialIdBase64Url: string,
  prfInput: Uint8Array<ArrayBuffer>,
  hkdfSalt: Uint8Array<ArrayBuffer>,
): Omit<BrowserVaultRecord, "cipher"> {
  const credentialId = fromBase64Url(credentialIdBase64Url);
  if (
    credentialId.length === 0 ||
    prfInput.length !== 32 ||
    hkdfSalt.length !== 32
  ) {
    throw new Error("malformed browser-vault key metadata");
  }
  return {
    format: VAULT_FORMAT,
    version: VAULT_VERSION,
    key_source: "webauthn-prf-v1",
    credential_id: credentialIdBase64Url,
    prf_input: toBase64Url(prfInput),
    hkdf_salt: toBase64Url(hkdfSalt),
  };
}

export function aadForHeader(
  header: Omit<BrowserVaultRecord, "cipher">,
): Uint8Array<ArrayBuffer> {
  return encoder.encode(
    `${VAULT_AAD_DOMAIN}\n${header.format}\n${header.version}\n${header.key_source}\n${header.credential_id}\n${header.prf_input}\n${header.hkdf_salt}`,
  );
}

export function validateRecord(value: unknown): {
  record: BrowserVaultRecord;
  prfInput: Uint8Array<ArrayBuffer>;
  hkdfSalt: Uint8Array<ArrayBuffer>;
} {
  if (
    !value ||
    typeof value !== "object" ||
    !("format" in value) ||
    !("version" in value) ||
    !("key_source" in value) ||
    !("credential_id" in value) ||
    !("prf_input" in value) ||
    !("hkdf_salt" in value) ||
    !("cipher" in value)
  ) {
    throw new Error("unsupported or malformed browser-vault record");
  }
  const candidate = value as Partial<BrowserVaultRecord>;
  if (
    candidate.format !== VAULT_FORMAT ||
    candidate.version !== VAULT_VERSION ||
    candidate.key_source !== "webauthn-prf-v1" ||
    typeof candidate.credential_id !== "string" ||
    typeof candidate.prf_input !== "string" ||
    typeof candidate.hkdf_salt !== "string" ||
    candidate.cipher?.name !== "AES-256-GCM" ||
    typeof candidate.cipher.iv !== "string" ||
    typeof candidate.cipher.ciphertext !== "string"
  ) {
    throw new Error("unsupported or malformed browser-vault record");
  }
  const record = candidate as BrowserVaultRecord;
  const credentialId = fromBase64Url(record.credential_id);
  const prfInput = fromBase64Url(record.prf_input);
  const hkdfSalt = fromBase64Url(record.hkdf_salt);
  const iv = fromBase64Url(record.cipher.iv);
  const ciphertext = fromBase64Url(record.cipher.ciphertext);
  if (
    credentialId.length === 0 ||
    prfInput.length !== 32 ||
    hkdfSalt.length !== 32 ||
    iv.length !== 12 ||
    ciphertext.length !== MASTER_SEED_BYTES + 16
  ) {
    throw new Error("malformed browser-vault record lengths");
  }
  return { record, prfInput, hkdfSalt };
}

export function validateBackup(value: unknown): EncryptedSeedBackupV2 {
  if (
    !value ||
    typeof value !== "object" ||
    !("format" in value) ||
    !("version" in value) ||
    !("kdf" in value) ||
    !("cipher" in value)
  ) {
    throw new Error("unsupported encrypted seed-backup format");
  }
  return value as EncryptedSeedBackupV2;
}
