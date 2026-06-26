/**
 * Decrypt (and, for tests, encrypt) a fill's `change_amount` — the client side
 * of the on-chain recovery backstop (change-amount recovery, Proposal B).
 *
 * Mirrors `crates/darkpool-crypto/src/fill_encryption.rs`. The TEE encrypts each
 * side's 8-byte `change_amount` to that side's X25519 viewing-encryption public
 * key (`deriveViewingEncKeypair().publicKey`, sent with the order). One ephemeral
 * key per fill (multi-recipient ECIES): a single ephemeral public lands on-chain
 * plus one 36-byte blob per side. Only the matching viewing secret decrypts.
 *
 * Scheme (per side):
 *   shared   = X25519(ephemeral_secret, recipient_pub)
 *   aead_key = HKDF-SHA256(ikm = shared,
 *                          info = "nyx-fill-enc-v1" ‖ eph_pub ‖ recipient_pub)[:32]
 *   blob     = nonce(12) ‖ ChaCha20Poly1305(aead_key, nonce).encrypt(amount_le8)
 *            = 12 + 8 + 16 = 36 bytes
 *
 * X25519 via tweetnacl (`scalarMult`); HKDF + ChaCha20-Poly1305 via `node:crypto`
 * — no new dependency. The construction is pinned to the Rust encryptor by the
 * fixed vector in `tests/fill-encryption.test.ts`.
 */

import crypto from "node:crypto";
import nacl from "tweetnacl";
import { hkdfExpand } from "./key-generators.js";

const FILL_ENC_INFO = new TextEncoder().encode("nyx-fill-enc-v1");

export const NONCE_LEN = 12;
export const AMOUNT_LEN = 8;
export const TAG_LEN = 16;
/** One side's on-chain ciphertext blob: `nonce ‖ ct ‖ tag`. */
export const SIDE_BLOB_LEN = NONCE_LEN + AMOUNT_LEN + TAG_LEN; // 36
export const X25519_LEN = 32;

/** HKDF-SHA256 → 32-byte ChaCha20-Poly1305 key, binding both pubkeys into `info`. */
function deriveAeadKey(
  shared: Uint8Array,
  ephPub: Uint8Array,
  recipientPub: Uint8Array,
): Uint8Array {
  const info = new Uint8Array(FILL_ENC_INFO.length + 2 * X25519_LEN);
  info.set(FILL_ENC_INFO, 0);
  info.set(ephPub, FILL_ENC_INFO.length);
  info.set(recipientPub, FILL_ENC_INFO.length + X25519_LEN);
  // hkdfExpand uses salt = 32 zero bytes, matching the Rust `Hkdf::new(None, …)`.
  return hkdfExpand(shared, info, 32);
}

/**
 * Encrypt one side's `change_amount` to `recipientPub`. Caller supplies the
 * fill's ephemeral secret (reused across both sides) and a unique 12-byte nonce.
 * Primarily a test/parity helper — in production the TEE encrypts; the client
 * only decrypts. Returns the 36-byte `nonce ‖ ct ‖ tag` blob.
 */
export function encryptChangeAmount(
  ephemeralSecret: Uint8Array,
  recipientPub: Uint8Array,
  amount: bigint,
  nonce12: Uint8Array,
): Uint8Array {
  if (nonce12.length !== NONCE_LEN)
    throw new Error(`nonce must be ${NONCE_LEN} bytes`);
  const ephPub = nacl.scalarMult.base(ephemeralSecret);
  const shared = nacl.scalarMult(ephemeralSecret, recipientPub);
  const key = deriveAeadKey(shared, ephPub, recipientPub);

  const cipher = crypto.createCipheriv(
    "chacha20-poly1305",
    Buffer.from(key),
    Buffer.from(nonce12),
    {
      authTagLength: TAG_LEN,
    },
  );
  const amt = Buffer.alloc(AMOUNT_LEN);
  amt.writeBigUInt64LE(amount);
  const ct = Buffer.concat([cipher.update(amt), cipher.final()]);
  const tag = cipher.getAuthTag();

  const blob = new Uint8Array(SIDE_BLOB_LEN);
  blob.set(nonce12, 0);
  blob.set(ct, NONCE_LEN);
  blob.set(tag, NONCE_LEN + AMOUNT_LEN);
  return blob;
}

/**
 * Decrypt one side's blob with this client's viewing-encryption secret. Returns
 * `null` on any failure (wrong key, tampered ciphertext, malformed plaintext) —
 * the "this key cannot read this blob" signal. The recipient's own public key
 * (bound into the HKDF `info`) is recomputed from the secret, so it need not be
 * passed.
 */
export function decryptChangeAmount(
  viewingSecret: Uint8Array,
  ephemeralPub: Uint8Array,
  blob: Uint8Array,
): bigint | null {
  if (blob.length !== SIDE_BLOB_LEN) return null;
  const myPub = nacl.scalarMult.base(viewingSecret);
  const shared = nacl.scalarMult(viewingSecret, ephemeralPub);
  const key = deriveAeadKey(shared, ephemeralPub, myPub);

  const nonce = blob.subarray(0, NONCE_LEN);
  const ct = blob.subarray(NONCE_LEN, NONCE_LEN + AMOUNT_LEN);
  const tag = blob.subarray(NONCE_LEN + AMOUNT_LEN);
  try {
    const decipher = crypto.createDecipheriv(
      "chacha20-poly1305",
      Buffer.from(key),
      Buffer.from(nonce),
      { authTagLength: TAG_LEN },
    );
    decipher.setAuthTag(Buffer.from(tag));
    const pt = Buffer.concat([
      decipher.update(Buffer.from(ct)),
      decipher.final(),
    ]);
    if (pt.length !== AMOUNT_LEN) return null;
    return pt.readBigUInt64LE(0);
  } catch {
    return null;
  }
}
