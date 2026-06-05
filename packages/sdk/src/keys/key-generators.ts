/**
 * Four-key derivation — TypeScript mirror of `crates/darkpool-crypto/src/keys.rs`.
 *
 * Must produce byte-identical outputs to the Rust implementation for a given
 * master seed + info string. See the cross-env parity test in
 * `packages/sdk/tests/keys-parity.test.ts` (uses the same fixed test seed the
 * Rust tests use).
 */

import crypto from "node:crypto";
import type { MasterSeedMode } from "../providers.js";

export const MASTER_SEED_BYTES = 64;

const INFO_SPENDING = new TextEncoder().encode("darkpool_spend_key_v1");
const INFO_VIEWING = new TextEncoder().encode("darkpool_viewing_key_v1");
const INFO_TRADING = new TextEncoder().encode("darkpool_trading_key_v1");
const INFO_ROOT = new TextEncoder().encode("darkpool_root_key_v1");
const INFO_BLINDING = new TextEncoder().encode("note_blinding_v1");
const INFO_INNER_HASH = new TextEncoder().encode("nyx-inner-hash-v1");
const INFO_ORDER_ID = new TextEncoder().encode("nyx-order-id-v1");

/** BN254 scalar field modulus r. */
export const BN254_R =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/** HKDF-SHA256 expand returning an arbitrary-length byte string. */
function hkdfExpand(ikm: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  // HKDF-SHA256: extract (salt=empty) then expand.
  const salt = new Uint8Array(32); // all zeros
  const prk = crypto.createHmac("sha256", Buffer.from(salt)).update(Buffer.from(ikm)).digest();
  const out = Buffer.alloc(length);
  let prev = Buffer.alloc(0);
  let filled = 0;
  let counter = 1;
  while (filled < length) {
    const h = crypto.createHmac("sha256", prk);
    h.update(prev);
    h.update(Buffer.from(info));
    h.update(Buffer.from([counter]));
    prev = h.digest();
    const take = Math.min(prev.length, length - filled);
    prev.copy(out, filled, 0, take);
    filled += take;
    counter += 1;
  }
  return new Uint8Array(out);
}

/** Reduce a big-endian byte buffer modulo BN254_r. */
function reduceMod(bytes: Uint8Array): bigint {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return n % BN254_R;
}

function bigintToBE32(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let x = n;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  if (x !== 0n) throw new Error("value does not fit in 32 bytes");
  return out;
}

/** 64-byte random master seed (CSPRNG). */
export function generateMasterSeed(): Uint8Array {
  return new Uint8Array(crypto.randomBytes(MASTER_SEED_BYTES));
}

/** Resolve a `MasterSeedMode` to actual seed bytes. */
export async function resolveMasterSeed(mode: MasterSeedMode): Promise<Uint8Array> {
  if (mode.type === "csprng") {
    const existing = await mode.storage.load();
    if (existing) return existing;
    const fresh = generateMasterSeed();
    await mode.storage.store(fresh);
    return fresh;
  }
  // wallet-signature: sign a fixed message, use first 64 bytes of SHA-512 of signature.
  const msg = mode.message ?? new TextEncoder().encode("NYX_DARKPOOL_SEED_V1");
  const sig = await mode.signMessage(msg);
  const hash = crypto.createHash("sha512").update(Buffer.from(sig)).digest();
  return new Uint8Array(hash.subarray(0, MASTER_SEED_BYTES));
}

export function deriveSpendingKey(seed: Uint8Array): bigint {
  const okm = hkdfExpand(seed, INFO_SPENDING, 64);
  return reduceMod(okm);
}

export function deriveMasterViewingKey(seed: Uint8Array): bigint {
  const okm = kmac256(seed, INFO_VIEWING, new Uint8Array(), 64);
  return reduceMod(okm);
}

export interface Ed25519RawKeypair {
  secretKey: Uint8Array; // 32-byte seed
}

export function deriveTradingKeyAtOffset(
  seed: Uint8Array,
  offset: bigint,
): Ed25519RawKeypair {
  const offsetBuf = new ArrayBuffer(8);
  new DataView(offsetBuf).setBigUint64(0, offset, true); // little-endian
  const info = new Uint8Array(INFO_TRADING.length + 8);
  info.set(INFO_TRADING, 0);
  info.set(new Uint8Array(offsetBuf), INFO_TRADING.length);
  const okm = hkdfExpand(seed, info, 32);
  return { secretKey: okm };
}

export function deriveRootKey(seed: Uint8Array): Ed25519RawKeypair {
  return { secretKey: hkdfExpand(seed, INFO_ROOT, 32) };
}

/**
 * Derive the blinding factor for the note at a given Merkle insertion counter.
 * Matches `darkpool_crypto::keys::derive_blinding_factor`.
 */
export function deriveBlindingFactor(seed: Uint8Array, counter: bigint): bigint {
  const offsetBuf = new ArrayBuffer(8);
  new DataView(offsetBuf).setBigUint64(0, counter, true);
  const info = new Uint8Array(INFO_BLINDING.length + 8);
  info.set(INFO_BLINDING, 0);
  info.set(new Uint8Array(offsetBuf), INFO_BLINDING.length);
  const okm = kmac256(seed, info, new Uint8Array(), 64);
  return reduceMod(okm);
}

/**
 * Derive the `inner_hash` for anchor `index` of a given order. Mirrors
 * `darkpool_crypto::keys::derive_inner_hash`. Deterministic from
 * `(seed, orderId, index)` so the whole anchor pool — and the matching
 * nullifiers via `nullifierV2` — is regenerable without persisted state.
 *
 * KMAC custom-info = `INFO_INNER_HASH || orderId[16] || index_u32_le`.
 */
export function deriveInnerHash(seed: Uint8Array, orderId: Uint8Array, index: number): bigint {
  if (orderId.length !== 16) throw new Error(`orderId must be 16 bytes; got ${orderId.length}`);
  if (!Number.isInteger(index) || index < 0 || index > 0xffff_ffff) {
    throw new Error(`index must be a u32; got ${index}`);
  }
  const idxBuf = new ArrayBuffer(4);
  new DataView(idxBuf).setUint32(0, index, true); // little-endian
  const info = new Uint8Array(INFO_INNER_HASH.length + 16 + 4);
  info.set(INFO_INNER_HASH, 0);
  info.set(orderId, INFO_INNER_HASH.length);
  info.set(new Uint8Array(idxBuf), INFO_INNER_HASH.length + 16);
  const okm = kmac256(seed, info, new Uint8Array(), 64);
  return reduceMod(okm);
}

/**
 * Derive the deterministic 16-byte order id for the `n`-th order of this seed.
 *
 * Same philosophy as the anchor pool + note blinding: derive everything from
 * the seed, persist nothing. The client regenerates order ids on demand, and a
 * fresh device rebuilds full trade history by gap-scanning `deriveOrderId(seed,
 * 0), [1], …` against the indexer until a run of empties. A distinct info
 * string (`nyx-order-id-v1`) keeps order ids in a separate domain from note
 * blinding / inner_hash so they can never collide.
 *
 * `HKDF-SHA256-expand(seed, INFO_ORDER_ID || n_u32_le)[:16]`. Client-only — the
 * TEE merely echoes `order_id` back in the settle payload, so there is no
 * cross-language consumer to keep parity with; pinned by a fixed vector.
 */
export function deriveOrderId(seed: Uint8Array, n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xffff_ffff) {
    throw new Error(`n must be a u32; got ${n}`);
  }
  const nBuf = new ArrayBuffer(4);
  new DataView(nBuf).setUint32(0, n, true); // little-endian
  const info = new Uint8Array(INFO_ORDER_ID.length + 4);
  info.set(INFO_ORDER_ID, 0);
  info.set(new Uint8Array(nBuf), INFO_ORDER_ID.length);
  return hkdfExpand(seed, info, 16);
}

/** Serialize a BN254 field element as 32-byte BE. */
export function bn254ToBE32(x: bigint): Uint8Array {
  if (x < 0n || x >= BN254_R) throw new Error("field element out of range");
  return bigintToBE32(x);
}

// ------ KMAC256 implementation (matches Rust side exactly) ------
// NIST SP 800-185 encoding on top of SHAKE256.

function leftEncode(x: bigint): Uint8Array {
  if (x === 0n) return new Uint8Array([1, 0]);
  const bytes: number[] = [];
  let y = x;
  while (y > 0n) {
    bytes.unshift(Number(y & 0xffn));
    y >>= 8n;
  }
  return new Uint8Array([bytes.length, ...bytes]);
}

function rightEncode(x: bigint): Uint8Array {
  if (x === 0n) return new Uint8Array([0, 1]);
  const bytes: number[] = [];
  let y = x;
  while (y > 0n) {
    bytes.unshift(Number(y & 0xffn));
    y >>= 8n;
  }
  return new Uint8Array([...bytes, bytes.length]);
}

function encodeString(s: Uint8Array): Uint8Array {
  const bits = BigInt(s.length) * 8n;
  const enc = leftEncode(bits);
  const out = new Uint8Array(enc.length + s.length);
  out.set(enc, 0);
  out.set(s, enc.length);
  return out;
}

function bytepad(x: Uint8Array, w: number): Uint8Array {
  const le = leftEncode(BigInt(w));
  let out = new Uint8Array(le.length + x.length);
  out.set(le, 0);
  out.set(x, le.length);
  while (out.length % w !== 0) {
    const padded = new Uint8Array(out.length + 1);
    padded.set(out, 0);
    padded[out.length] = 0;
    out = padded;
  }
  return out;
}

function kmac256(
  key: Uint8Array,
  customInfo: Uint8Array,
  data: Uint8Array,
  outLen: number,
): Uint8Array {
  const shake = crypto.createHash("shake256", { outputLength: outLen });
  const name = new TextEncoder().encode("KMAC");
  const header = new Uint8Array([...encodeString(name), ...encodeString(customInfo)]);
  const paddedHeader = bytepad(header, 136);
  const paddedKey = bytepad(encodeString(key), 136);

  shake.update(Buffer.from(paddedHeader));
  shake.update(Buffer.from(paddedKey));
  shake.update(Buffer.from(data));
  const bits = BigInt(outLen) * 8n;
  shake.update(Buffer.from(rightEncode(bits)));
  return new Uint8Array(shake.digest());
}

export const __testing = { kmac256, hkdfExpand, reduceMod };
