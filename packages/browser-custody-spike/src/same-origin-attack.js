import { aadForHeader, fromBase64Url, validateRecord } from "./codec.js";
import { deriveWrappingKey, evaluatePrf } from "./webauthn-prf.js";

/**
 * Adversarial test deliberately isolated from the BrowserVault entry point.
 *
 * It models arbitrary same-origin JavaScript: read public wrapping metadata and
 * ciphertext from IndexedDB, prompt the credential, then use the PRF output to
 * decrypt directly. A successful result is the limitation the spike is meant
 * to make visible; production code must never bundle this module.
 */
export async function simulateSameOriginCompromise(record) {
  const parsed = validateRecord(record);
  const output = await evaluatePrf(record.credential_id, parsed.prfInput);
  let wrappingKey;
  try {
    wrappingKey = await deriveWrappingKey(output, parsed.hkdfSalt);
  } finally {
    output.fill(0);
  }
  const plaintext = new Uint8Array(
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
  if (plaintext.length !== 64) {
    plaintext.fill(0);
    throw new Error("same-origin attack recovered the wrong plaintext length");
  }
  return { plaintext, wrappingKeyExtractable: wrappingKey.extractable };
}
