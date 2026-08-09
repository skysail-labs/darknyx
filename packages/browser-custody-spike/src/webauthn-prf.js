import {
  equalBytes,
  fromBase64Url,
  randomBytes,
  toBase64Url,
  WRAP_INFO,
} from "./codec.js";

function requireWebAuthn() {
  if (!globalThis.isSecureContext || !navigator.credentials) {
    throw new Error("WebAuthn requires a secure browser context");
  }
}

function prfOutput(credential) {
  const output = credential.getClientExtensionResults().prf;
  const first = output?.results?.first;
  return first ? new Uint8Array(first) : null;
}

export async function createPrfCredential(label = "Darknyx account") {
  requireWebAuthn();
  const prfInput = randomBytes(32);
  const created = await navigator.credentials.create({
    publicKey: {
      challenge: randomBytes(32),
      rp: { name: "Darknyx" },
      user: {
        id: randomBytes(32),
        name: "darknyx-local-vault",
        displayName: label,
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      timeout: 60_000,
      attestation: "none",
      authenticatorSelection: {
        residentKey: "required",
        userVerification: "required",
      },
      extensions: { prf: { eval: { first: prfInput } } },
    },
  });
  if (!(created instanceof PublicKeyCredential)) {
    throw new Error("WebAuthn credential creation returned no credential");
  }
  const extension = created.getClientExtensionResults().prf;
  if (extension?.enabled !== true) {
    throw new Error("WebAuthn PRF is unavailable on this authenticator");
  }
  const credentialId = toBase64Url(created.rawId);
  let output = prfOutput(created);
  if (!output) output = await evaluatePrf(credentialId, prfInput);
  return { credentialId, prfInput, output };
}

export async function evaluatePrf(credentialId, prfInput) {
  requireWebAuthn();
  const expectedId = fromBase64Url(credentialId);
  const asserted = await navigator.credentials.get({
    publicKey: {
      challenge: randomBytes(32),
      allowCredentials: [{ type: "public-key", id: expectedId }],
      timeout: 60_000,
      userVerification: "required",
      extensions: { prf: { eval: { first: prfInput } } },
    },
  });
  if (
    !(asserted instanceof PublicKeyCredential) ||
    !equalBytes(asserted.rawId, expectedId)
  ) {
    throw new Error("WebAuthn assertion used an unexpected credential");
  }
  const output = prfOutput(asserted);
  if (!output || output.length !== 32) {
    throw new Error("WebAuthn PRF produced no 32-byte result");
  }
  return output;
}

export async function deriveWrappingKey(prfResult, hkdfSalt) {
  if (prfResult.length !== 32 || hkdfSalt.length !== 32) {
    throw new Error("wrapping-key inputs must be 32 bytes");
  }
  const material = await crypto.subtle.importKey(
    "raw",
    prfResult,
    "HKDF",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: hkdfSalt, info: WRAP_INFO },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}
