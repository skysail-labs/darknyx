const encoder = new TextEncoder();

export const VAULT_FORMAT = "darknyx-browser-vault";
export const VAULT_VERSION = 1;
export const VAULT_AAD_DOMAIN = "darknyx/browser-vault/v1";
export const WRAP_INFO = encoder.encode("darknyx/browser-vault-wrap/v1");

export function randomBytes(length) {
  const value = new Uint8Array(length);
  crypto.getRandomValues(value);
  return value;
}

export function toBase64Url(value) {
  let binary = "";
  for (const byte of new Uint8Array(value)) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

export function fromBase64Url(value) {
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

export function equalBytes(left, right) {
  const a = new Uint8Array(left);
  const b = new Uint8Array(right);
  if (a.length !== b.length) return false;
  let different = 0;
  for (let index = 0; index < a.length; index += 1)
    different |= a[index] ^ b[index];
  return different === 0;
}

export function vaultHeader(credentialId, prfInput, hkdfSalt) {
  return {
    format: VAULT_FORMAT,
    version: VAULT_VERSION,
    key_source: "webauthn-prf-v1",
    credential_id: credentialId,
    prf_input: toBase64Url(prfInput),
    hkdf_salt: toBase64Url(hkdfSalt),
  };
}

export function aadForHeader(header) {
  return encoder.encode(
    `${VAULT_AAD_DOMAIN}\n${header.format}\n${header.version}\n${header.key_source}\n${header.credential_id}\n${header.prf_input}\n${header.hkdf_salt}`,
  );
}

export function validateRecord(value) {
  if (
    !value ||
    typeof value !== "object" ||
    value.format !== VAULT_FORMAT ||
    value.version !== VAULT_VERSION ||
    value.key_source !== "webauthn-prf-v1" ||
    typeof value.credential_id !== "string" ||
    typeof value.prf_input !== "string" ||
    typeof value.hkdf_salt !== "string" ||
    !value.cipher ||
    value.cipher.name !== "AES-256-GCM" ||
    typeof value.cipher.iv !== "string" ||
    typeof value.cipher.ciphertext !== "string"
  ) {
    throw new Error("unsupported or malformed browser-vault record");
  }
  const credentialId = fromBase64Url(value.credential_id);
  const prfInput = fromBase64Url(value.prf_input);
  const hkdfSalt = fromBase64Url(value.hkdf_salt);
  const iv = fromBase64Url(value.cipher.iv);
  const ciphertext = fromBase64Url(value.cipher.ciphertext);
  if (
    credentialId.length === 0 ||
    prfInput.length !== 32 ||
    hkdfSalt.length !== 32
  ) {
    throw new Error("malformed browser-vault key metadata");
  }
  if (iv.length !== 12 || ciphertext.length !== 80) {
    throw new Error("malformed browser-vault ciphertext");
  }
  return { record: value, credentialId, prfInput, hkdfSalt };
}
