/**
 * Keystore — the daemon's on-device crypto identity.
 *
 * **The trust boundary is the PROCESS, not this module** (SW-16). The headline
 * used to read "Keys NEVER leave here", which is the sentence a reader believes
 * when deciding where to look for key handling — and it is not true: the public
 * `masterSeed` getter hands the 64-byte root secret to five call sites
 * (`daemon.ts`, `build-place-request.ts` x2, `merge-client.ts`,
 * `daemon-client.ts`, `fills-listener.ts`). All in-process, so the security
 * posture is exactly what the AT REST note below describes — but a reader
 * auditing "where can the seed go" would have stopped at this file and missed
 * them. The accurate statement is the one further down: keys never leave the
 * process, and the passphrase-sealed file is what protects them at rest.
 *
 * Holds the account's {@link AccountIdentity} (the 64-byte master seed + the
 * blinding/`r`-values + root-key pubkey that pin the owner + user commitments)
 * and derives everything an order needs, all locally:
 *
 *   - `spendingKey` / `viewingKey`            (BN254 scalars, from the seed)
 *   - `ownerCommitment` / `userCommitment`    (the account's on-chain identity)
 *   - a per-order Ed25519 **trading key** at the order's `seedIndex`
 *     (`deriveTradingKeyAtOffset`) + a detached signer over a canonical digest
 *
 * AT REST: the identity is sealed with AES-256-GCM under a scrypt-stretched
 * passphrase ({@link saveKeystore} / {@link loadKeystore}) — a stolen file is
 * useless without the passphrase. In memory the seed is plaintext (it has to be,
 * to sign); the process is the trust boundary.
 */

import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
} from "node:crypto";
import fs from "node:fs";
import { basename, dirname, join } from "node:path";

import nacl from "tweetnacl";
import {
  deriveSpendingKey,
  deriveMasterViewingKey,
  deriveTradingKeyAtOffset,
  deriveBlindingFactor,
  deriveOwnerCommitmentBlinding,
  ACCOUNT_OWNER_BLINDING_COUNTER,
  generateMasterSeed,
  ownerCommitment,
  userCommitmentFromKeys,
} from "@darknyx/sdk";

const toHex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

/**
 * Account-blinding domain. The owner/user-commitment blindings derive from the
 * seed at these high counters, away from the small leaf-counter range that note
 * (`deriveBlindingFactor`) blindings use — so the WHOLE identity is recoverable
 * from the seed alone (the keystore file is just an encrypted convenience).
 */
const ACCOUNT_BLINDING_BASE = ACCOUNT_OWNER_BLINDING_COUNTER;

/**
 * Deterministically derive an {@link AccountIdentity} from a master seed + the
 * operator's root (payer) key. Same `(seed, rootKey)` always yields the same
 * on-chain identity, so a lost keystore is recoverable from the backed-up seed.
 */
export function deriveAccountIdentity(
  masterSeed: Uint8Array,
  rootKeyPubkey: Uint8Array,
): AccountIdentity {
  return {
    masterSeed,
    ownerBlinding: deriveOwnerCommitmentBlinding(masterSeed),
    r0: deriveBlindingFactor(masterSeed, ACCOUNT_BLINDING_BASE + 1n),
    r1: deriveBlindingFactor(masterSeed, ACCOUNT_BLINDING_BASE + 2n),
    r2: deriveBlindingFactor(masterSeed, ACCOUNT_BLINDING_BASE + 3n),
    rootKeyPubkey,
  };
}

/** Generate a fresh identity (random 64-byte seed) for a root key. */
export function generateAccountIdentity(
  rootKeyPubkey: Uint8Array,
): AccountIdentity {
  return deriveAccountIdentity(generateMasterSeed(), rootKeyPubkey);
}

/** The account's persisted crypto identity. All else derives from this. */
export interface AccountIdentity {
  /** 64-byte master seed (the root secret). */
  masterSeed: Uint8Array;
  /** Owner-commitment blinding: `ownerCommitment(spendingKey, ownerBlinding)`. */
  ownerBlinding: bigint;
  /** User-commitment per-leaf blindings. */
  r0: bigint;
  r1: bigint;
  r2: bigint;
  /** 32-byte Ed25519 pubkey of the root/vault (payer) key. */
  rootKeyPubkey: Uint8Array;
}

export class Keystore {
  private readonly spend: bigint;
  private readonly view: bigint;

  constructor(private readonly identity: AccountIdentity) {
    if (identity.masterSeed.length !== 64) {
      throw new Error("master seed must be 64 bytes");
    }
    if (identity.rootKeyPubkey.length !== 32) {
      throw new Error("rootKeyPubkey must be 32 bytes");
    }
    this.spend = deriveSpendingKey(identity.masterSeed);
    this.view = deriveMasterViewingKey(identity.masterSeed);
  }

  get masterSeed(): Uint8Array {
    return this.identity.masterSeed;
  }
  get spendingKey(): bigint {
    return this.spend;
  }
  get viewingKey(): bigint {
    return this.view;
  }
  get ownerBlinding(): bigint {
    return this.identity.ownerBlinding;
  }

  /** The account's owner commitment (Poseidon — async). */
  ownerCommitment(): Promise<bigint> {
    return ownerCommitment(this.spend, this.identity.ownerBlinding);
  }

  /** The account's 32-byte big-endian user commitment (Poseidon — async).
   *
   *  This is the genuine `create_wallet` Poseidon output: the identity a
   *  `WalletEntry` is registered under on-chain. The order path does NOT send
   *  it — see `build-place-request.ts`.
   *
   *  Canonicality is guaranteed by the field reduction inside
   *  `userCommitmentFromKeys` — the Poseidon output IS a BN254 element — not by
   *  any property of the leading byte. A first-byte bound is not a sufficient
   *  test at the modulus boundary, where the remaining 31 bytes still decide.
   *
   *  This is worth stating because the value used to be returned with its top
   *  byte forced to 0, to satisfy a TEE intake rule that rejected any
   *  `user_commitment` whose top byte was non-zero. Audit 2026-07-25 (T-07)
   *  removed that rule: it was not Fr-safety, and it guarded a hash that no
   *  longer happened. The zeroing had made this value un-matchable against any
   *  registered `WalletEntry`, which is the one thing it exists for. */
  async userCommitment(): Promise<Uint8Array> {
    return userCommitmentFromKeys({
      rootKeyPubkey: this.identity.rootKeyPubkey,
      spendingKey: this.spend,
      viewingKey: this.view,
      r0: this.identity.r0,
      r1: this.identity.r1,
      r2: this.identity.r2,
    });
  }

  /** The Ed25519 keypair for the order at `index` (deterministic from the seed).
   *  `Ed25519RawKeypair` is a 32-byte seed → expand to a nacl keypair. */
  private tradingKeypair(index: number): nacl.SignKeyPair {
    const { secretKey } = deriveTradingKeyAtOffset(
      this.identity.masterSeed,
      BigInt(index),
    );
    return nacl.sign.keyPair.fromSeed(secretKey);
  }

  /** 32-byte trading public key for order `index`. */
  tradingPublicKey(index: number): Uint8Array {
    return this.tradingKeypair(index).publicKey;
  }

  /** Detached Ed25519 signature over `digest` with order `index`'s trading key. */
  signWithTradingKey(index: number, digest: Uint8Array): Uint8Array {
    return nacl.sign.detached(digest, this.tradingKeypair(index).secretKey);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Encrypted-at-rest persistence (AES-256-GCM under a scrypt-stretched passphrase)
// ─────────────────────────────────────────────────────────────────────────────

interface KeystoreFileV1 {
  version: 1;
  kdf: "scrypt";
  n: number;
  r: number;
  p: number;
  salt: string; // hex
  iv: string; // hex (12 bytes, GCM)
  ciphertext: string; // hex
  tag: string; // hex (16-byte GCM auth tag)
}

interface KeystoreFileV2 {
  version: 2;
  kdf: "scrypt";
  profile: "scrypt-n17-r8-p1-v1";
  cipher: "aes-256-gcm";
  salt: string; // lowercase hex, 16 bytes
  iv: string; // lowercase hex, 12 bytes
  ciphertext: string; // lowercase hex
  tag: string; // lowercase hex, 16 bytes
}

const LEGACY_SCRYPT = {
  N: 1 << 14,
  r: 8,
  p: 1,
  maxmem: 32 * 1024 * 1024,
} as const;
const V2_SCRYPT = {
  N: 1 << 17,
  r: 8,
  p: 1,
  // Node rejects a valid N=2^17/r=8 invocation unless maxmem exceeds the
  // algorithm's ~128 MiB working set. Keep the ceiling explicit so neither a
  // runtime default nor an untrusted file field controls the allocation.
  maxmem: 256 * 1024 * 1024,
} as const;
const V2_KDF_PROFILE = "scrypt-n17-r8-p1-v1" as const;
const V2_CIPHER = "aes-256-gcm" as const;
const V2_AAD_DOMAIN = Buffer.from("darknyx-daemon-keystore/v2\0", "utf8");
const MAX_KEYSTORE_FILE_BYTES = 32 * 1024;
const MAX_CIPHERTEXT_BYTES = 8 * 1024;
const BN254_SCALAR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

type JsonObject = Record<string, unknown>;

function asObject(value: unknown, label: string): JsonObject {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be a JSON object`);
  }
  return value as JsonObject;
}

function requireExactKeys(
  value: JsonObject,
  expected: readonly string[],
  label: string,
): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((key, index) => key !== wanted[index])
  ) {
    throw new Error(`${label} has unknown or missing fields`);
  }
}

function decodeFixedHex(
  value: unknown,
  field: string,
  byteLength: number,
): Buffer {
  if (
    typeof value !== "string" ||
    value.length !== byteLength * 2 ||
    !/^[0-9a-f]+$/.test(value)
  ) {
    throw new Error(`${field} must be ${byteLength} bytes of lowercase hex`);
  }
  return Buffer.from(value, "hex");
}

function decodeCiphertext(value: unknown): Buffer {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length % 2 !== 0 ||
    value.length > MAX_CIPHERTEXT_BYTES * 2 ||
    !/^[0-9a-f]+$/.test(value)
  ) {
    throw new Error(
      `ciphertext must be 1..${MAX_CIPHERTEXT_BYTES} bytes of lowercase hex`,
    );
  }
  return Buffer.from(value, "hex");
}

function parseFieldDecimal(value: unknown, field: string): bigint {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`${field} must be a canonical unsigned decimal integer`);
  }
  const parsed = BigInt(value);
  if (parsed >= BN254_SCALAR_MODULUS) {
    throw new Error(`${field} must be a canonical BN254 scalar`);
  }
  return parsed;
}

function serializeIdentity(id: AccountIdentity): string {
  return JSON.stringify({
    seed: toHex(id.masterSeed),
    ownerBlinding: id.ownerBlinding.toString(),
    r0: id.r0.toString(),
    r1: id.r1.toString(),
    r2: id.r2.toString(),
    rootKeyPubkey: toHex(id.rootKeyPubkey),
  });
}

function deserializeIdentity(json: string): AccountIdentity {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new Error("keystore plaintext is not valid JSON");
  }
  const o = asObject(parsed, "keystore identity");
  requireExactKeys(
    o,
    ["seed", "ownerBlinding", "r0", "r1", "r2", "rootKeyPubkey"],
    "keystore identity",
  );
  return {
    masterSeed: Uint8Array.from(decodeFixedHex(o.seed, "seed", 64)),
    ownerBlinding: parseFieldDecimal(o.ownerBlinding, "ownerBlinding"),
    r0: parseFieldDecimal(o.r0, "r0"),
    r1: parseFieldDecimal(o.r1, "r1"),
    r2: parseFieldDecimal(o.r2, "r2"),
    rootKeyPubkey: Uint8Array.from(
      decodeFixedHex(o.rootKeyPubkey, "rootKeyPubkey", 32),
    ),
  };
}

function deriveV2Key(passphrase: string, salt: Buffer): Buffer {
  return scryptSync(passphrase, salt, 32, {
    ...V2_SCRYPT,
  });
}

function deriveLegacyKey(passphrase: string, salt: Buffer): Buffer {
  return scryptSync(passphrase, salt, 32, {
    ...LEGACY_SCRYPT,
  });
}

function v2Aad(salt: Buffer, iv: Buffer): Buffer {
  return Buffer.concat([
    V2_AAD_DOMAIN,
    Buffer.from("scrypt\0", "utf8"),
    Buffer.from(`${V2_KDF_PROFILE}\0`, "utf8"),
    Buffer.from(`${V2_CIPHER}\0`, "utf8"),
    salt,
    iv,
  ]);
}

function sealV2(
  identity: AccountIdentity,
  passphrase: string,
  salt = randomBytes(16),
  iv = randomBytes(12),
): KeystoreFileV2 {
  const validated = deserializeIdentity(serializeIdentity(identity));
  new Keystore(validated);
  const key = deriveV2Key(passphrase, salt);
  try {
    const cipher = createCipheriv(V2_CIPHER, key, iv);
    cipher.setAAD(v2Aad(salt, iv));
    const plaintext = Buffer.from(serializeIdentity(validated), "utf8");
    const ciphertext = Buffer.concat([
      cipher.update(plaintext),
      cipher.final(),
    ]);
    const tag = cipher.getAuthTag();
    return {
      version: 2,
      kdf: "scrypt",
      profile: V2_KDF_PROFILE,
      cipher: V2_CIPHER,
      salt: salt.toString("hex"),
      iv: iv.toString("hex"),
      ciphertext: ciphertext.toString("hex"),
      tag: tag.toString("hex"),
    };
  } finally {
    key.fill(0);
  }
}

function atomicReplace(path: string, contents: string): void {
  const directory = dirname(path);
  const tempPath = join(
    directory,
    `.${basename(path)}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`,
  );
  let fd: number | undefined;
  let directoryFd: number | undefined;
  try {
    fd = fs.openSync(tempPath, "wx", 0o600);
    fs.writeFileSync(fd, contents, "utf8");
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(tempPath, path);
    // Persist the rename itself, not only the new file's bytes. Darknyx
    // supports POSIX daemon hosts (macOS/Linux), where syncing the containing
    // directory makes the atomic replacement survive a power loss.
    directoryFd = fs.openSync(directory, "r");
    fs.fsyncSync(directoryFd);
    fs.closeSync(directoryFd);
    directoryFd = undefined;
  } catch (error) {
    if (fd !== undefined) {
      try {
        fs.closeSync(fd);
      } catch {
        // Preserve the original failure.
      }
    }
    if (directoryFd !== undefined) {
      try {
        fs.closeSync(directoryFd);
      } catch {
        // Preserve the original failure.
      }
    }
    try {
      fs.unlinkSync(tempPath);
    } catch {
      // The temp may not have been created, or rename may already have
      // atomically installed it. No partial file is ever exposed at `path`.
    }
    throw error;
  }
}

function parseFile(path: string): JsonObject {
  const stat = fs.statSync(path);
  if (!stat.isFile() || stat.size <= 0 || stat.size > MAX_KEYSTORE_FILE_BYTES) {
    throw new Error(
      `keystore file must be 1..${MAX_KEYSTORE_FILE_BYTES} bytes`,
    );
  }
  // Every write path creates this `0600` and says so, but nothing checked it on
  // READ — so a keystore restored `0644` from a backup, or copied through a
  // permissive umask, loaded silently (SW-16). This is OpenSSH's refusal case,
  // and for the same reason: the file is only as private as its mode, and the
  // moment to notice is before it is decrypted.
  //
  // Group/other bits only. Owner-executable is odd but harmless, and Windows
  // reports modes that would false-positive a stricter check.
  const mode = stat.mode & 0o077;
  if (mode !== 0) {
    throw new Error(
      `keystore ${path} is group/world-accessible (mode ${(stat.mode & 0o777)
        .toString(8)
        .padStart(3, "0")}); run: chmod 600 ${path}`,
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(fs.readFileSync(path, "utf8"));
  } catch {
    throw new Error("keystore file is not valid JSON");
  }
  return asObject(parsed, "keystore file");
}

function decryptIdentity(
  key: Buffer,
  iv: Buffer,
  ciphertext: Buffer,
  tag: Buffer,
  aad?: Buffer,
): AccountIdentity {
  try {
    const decipher = createDecipheriv(V2_CIPHER, key, iv);
    if (aad) {
      decipher.setAAD(aad);
    }
    decipher.setAuthTag(tag);
    let plaintext: Buffer;
    try {
      plaintext = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final(),
      ]);
    } catch {
      throw new Error(
        "keystore decrypt failed (wrong passphrase or corrupt file)",
      );
    }
    const identity = deserializeIdentity(plaintext.toString("utf8"));
    // Constructor validation is part of the migration boundary: never replace
    // a legacy file until the decrypted identity is demonstrably usable.
    new Keystore(identity);
    return identity;
  } finally {
    key.fill(0);
  }
}

function openV2(file: JsonObject, passphrase: string): AccountIdentity {
  requireExactKeys(
    file,
    ["version", "kdf", "profile", "cipher", "salt", "iv", "ciphertext", "tag"],
    "keystore v2",
  );
  if (
    file.version !== 2 ||
    file.kdf !== "scrypt" ||
    file.profile !== V2_KDF_PROFILE ||
    file.cipher !== V2_CIPHER
  ) {
    throw new Error("unsupported keystore v2 profile");
  }
  const salt = decodeFixedHex(file.salt, "salt", 16);
  const iv = decodeFixedHex(file.iv, "iv", 12);
  const ciphertext = decodeCiphertext(file.ciphertext);
  const tag = decodeFixedHex(file.tag, "tag", 16);
  return decryptIdentity(
    deriveV2Key(passphrase, salt),
    iv,
    ciphertext,
    tag,
    v2Aad(salt, iv),
  );
}

function openV1(file: JsonObject, passphrase: string): AccountIdentity {
  requireExactKeys(
    file,
    ["version", "kdf", "n", "r", "p", "salt", "iv", "ciphertext", "tag"],
    "keystore v1",
  );
  if (
    file.version !== 1 ||
    file.kdf !== "scrypt" ||
    file.n !== LEGACY_SCRYPT.N ||
    file.r !== LEGACY_SCRYPT.r ||
    file.p !== LEGACY_SCRYPT.p
  ) {
    throw new Error("unsupported keystore v1 profile");
  }
  const salt = decodeFixedHex(file.salt, "salt", 16);
  const iv = decodeFixedHex(file.iv, "iv", 12);
  const ciphertext = decodeCiphertext(file.ciphertext);
  const tag = decodeFixedHex(file.tag, "tag", 16);
  return decryptIdentity(
    deriveLegacyKey(passphrase, salt),
    iv,
    ciphertext,
    tag,
  );
}

/** Seal an identity to disk under `passphrase` using the fixed v2 profile. */
/**
 * Minimum passphrase length (SW-16).
 *
 * A strong KDF profile buys TIME against a weak secret, not immunity: at
 * N=2^17 a short or dictionary passphrase is still enumerable, and this file is
 * exactly the artifact an attacker walks off with. A length floor is the
 * cheapest control that changes the arithmetic; it is not a substitute for a
 * good passphrase, which is why the message says so.
 *
 * Deliberately a floor and not an entropy estimator: entropy scoring on
 * human-chosen strings is unreliable enough that it mostly teaches users to
 * defeat it.
 */
export const MIN_KEYSTORE_PASSPHRASE_LENGTH = 12;

function assertUsablePassphrase(passphrase: string): void {
  if (passphrase.length < MIN_KEYSTORE_PASSPHRASE_LENGTH) {
    throw new Error(
      `keystore passphrase must be at least ${MIN_KEYSTORE_PASSPHRASE_LENGTH} characters ` +
        "— the scrypt profile slows an attacker down, it does not make a short passphrase safe",
    );
  }
}

export function saveKeystore(
  identity: AccountIdentity,
  path: string,
  passphrase: string,
): void {
  assertUsablePassphrase(passphrase);
  atomicReplace(path, JSON.stringify(sealV2(identity, passphrase)));
}

/**
 * Open a sealed keystore.
 *
 * V2 files use the fixed N=2^17/r=8/p=1 profile and authenticated header.
 * A valid v1 file is decrypted with the only profile the old writer emitted,
 * fully validated, then atomically replaced with v2 before this returns.
 */
export function loadKeystore(path: string, passphrase: string): Keystore {
  const file = parseFile(path);
  if (file.version === 2) {
    return new Keystore(openV2(file, passphrase));
  }
  if (file.version === 1) {
    const identity = openV1(file, passphrase);
    try {
      atomicReplace(path, JSON.stringify(sealV2(identity, passphrase)));
    } catch {
      throw new Error(
        "keystore v1 decrypted but atomic migration to v2 failed; no partial file was exposed",
      );
    }
    return new Keystore(identity);
  }
  throw new Error("unsupported keystore file version");
}
