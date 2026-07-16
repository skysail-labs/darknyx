/**
 * Decrypt (and, for tests, encrypt) one fill side's trade + change amounts —
 * the client side of the on-chain recovery backstop.
 *
 * Mirrors `crates/darkpool-crypto/src/fill_encryption.rs`. The TEE encrypts each
 * side's two u64 output amounts to that side's X25519 viewing-encryption public
 * key (`deriveViewingEncKeypair().publicKey`, sent with the order). One ephemeral
 * key per fill (multi-recipient ECIES): a single ephemeral public lands on-chain
 * plus one 44-byte blob per side. Only the matching viewing secret decrypts.
 *
 * Scheme (per side):
 *   shared   = X25519(ephemeral_secret, recipient_pub)
 *   aead_key = HKDF-SHA256(ikm = shared,
 *                          info = "nyx-fill-enc-v2" ‖ eph_pub ‖ recipient_pub)[:32]
 *   plaintext = trade_amount_le8 ‖ change_amount_le8
 *   blob      = nonce(12) ‖ ChaCha20Poly1305(aead_key, nonce).encrypt(plaintext)
 *             = 12 + 16 + 16 = 44 bytes
 *
 * X25519 via tweetnacl (`scalarMult`); HKDF + ChaCha20-Poly1305 via `node:crypto`
 * — no new dependency. The construction is pinned to the Rust encryptor by the
 * fixed vector in `tests/fill-encryption.test.ts`.
 */

import crypto from "node:crypto";
import nacl from "tweetnacl";
import { hkdfExpand } from "./key-generators.js";

const FILL_ENC_INFO = new TextEncoder().encode("nyx-fill-enc-v2");

export const NONCE_LEN = 12;
export const AMOUNTS_LEN = 16;
export const TAG_LEN = 16;
/** One side's on-chain ciphertext blob: `nonce ‖ ct ‖ tag`. */
export const SIDE_BLOB_LEN = NONCE_LEN + AMOUNTS_LEN + TAG_LEN; // 44
export const X25519_LEN = 32;

/** Buyer semantics: trade=base, change=quote. Seller semantics: trade=quote,
 * change=base. */
export interface FillAmounts {
  trade: bigint;
  change: bigint;
}

/** Reject low-order X25519 encodings by applying a fixed probe scalar and
 * requiring a non-zero shared secret (RFC 7748 contributory check). */
export function isContributoryX25519PublicKey(
  publicKey: Uint8Array,
): boolean {
  if (publicKey.length !== X25519_LEN) return false;
  try {
    const shared = nacl.scalarMult(new Uint8Array(32).fill(0x42), publicKey);
    return shared.some((byte) => byte !== 0);
  } catch {
    return false;
  }
}

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
 * Encrypt one side's trade + change amounts to `recipientPub`. Caller supplies the
 * fill's ephemeral secret (reused across both sides) and a unique 12-byte nonce.
 * Primarily a test/parity helper — in production the TEE encrypts; the client
 * only decrypts. Returns the 44-byte `nonce ‖ ct ‖ tag` blob.
 */
export function encryptFillAmounts(
  ephemeralSecret: Uint8Array,
  recipientPub: Uint8Array,
  amounts: FillAmounts,
  nonce12: Uint8Array,
): Uint8Array {
  if (nonce12.length !== NONCE_LEN)
    throw new Error(`nonce must be ${NONCE_LEN} bytes`);
  if (!isContributoryX25519PublicKey(recipientPub))
    throw new Error("recipientPub is a non-contributory X25519 point");
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
  const plaintext = Buffer.alloc(AMOUNTS_LEN);
  plaintext.writeBigUInt64LE(amounts.trade, 0);
  plaintext.writeBigUInt64LE(amounts.change, 8);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  const blob = new Uint8Array(SIDE_BLOB_LEN);
  blob.set(nonce12, 0);
  blob.set(ct, NONCE_LEN);
  blob.set(tag, NONCE_LEN + AMOUNTS_LEN);
  return blob;
}

/**
 * Decrypt one side's blob with this client's viewing-encryption secret. Returns
 * `null` on any failure (wrong key, tampered ciphertext, malformed plaintext) —
 * the "this key cannot read this blob" signal. The recipient's own public key
 * (bound into the HKDF `info`) is recomputed from the secret, so it need not be
 * passed.
 */
export function decryptFillAmounts(
  viewingSecret: Uint8Array,
  ephemeralPub: Uint8Array,
  blob: Uint8Array,
): FillAmounts | null {
  if (blob.length !== SIDE_BLOB_LEN) return null;
  if (!isContributoryX25519PublicKey(ephemeralPub)) return null;
  try {
    const myPub = nacl.scalarMult.base(viewingSecret);
    const shared = nacl.scalarMult(viewingSecret, ephemeralPub);
    const key = deriveAeadKey(shared, ephemeralPub, myPub);
    const nonce = blob.subarray(0, NONCE_LEN);
    const ct = blob.subarray(NONCE_LEN, NONCE_LEN + AMOUNTS_LEN);
    const tag = blob.subarray(NONCE_LEN + AMOUNTS_LEN);
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
    if (pt.length !== AMOUNTS_LEN) return null;
    return {
      trade: pt.readBigUInt64LE(0),
      change: pt.readBigUInt64LE(8),
    };
  } catch {
    return null;
  }
}
