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
 * Holds the account's {@link AccountIdentity} (only the 64-byte master seed)
 * and derives everything the live protocol needs locally:
 *
 *   - `spendingKey` / `ownerCommitment`       (the shielded-note identity)
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
  deriveTradingKeyAtOffset,
  generateMasterSeed,
  ownerCommitment,
} from "@darknyx/sdk";

const toHex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

/**
 * Build the persisted identity from a master seed. Every operational key and
 * blinding is derived after unlock, so the encrypted file has one root secret
 * and no redundant state that can drift.
 */
export function deriveAccountIdentity(masterSeed: Uint8Array): AccountIdentity {
  return {
    masterSeed: Uint8Array.from(masterSeed),
  };
}

/** Generate a fresh identity from a random 64-byte seed. */
export function generateAccountIdentity(): AccountIdentity {
  return deriveAccountIdentity(generateMasterSeed());
}

/** The account's persisted crypto identity. All else derives from this. */
export interface AccountIdentity {
  /** 64-byte master seed (the root secret). */
  masterSeed: Uint8Array;
}

export class Keystore {
  private readonly spend: bigint;

  constructor(private readonly identity: AccountIdentity) {
    if (identity.masterSeed.length !== 64) {
      throw new Error("master seed must be 64 bytes");
    }
    this.spend = deriveSpendingKey(identity.masterSeed);
  }

  get masterSeed(): Uint8Array {
    return this.identity.masterSeed;
  }
  get spendingKey(): bigint {
    return this.spend;
  }
  /** The account's owner commitment (Poseidon — async). */
  ownerCommitment(): Promise<bigint> {
    return ownerCommitment(this.spend);
  }

  /** The Ed25519 keypair for the order at `index` (deterministic from the seed).
   *  `Ed25519RawKeypair` is a 32-byte seed → expand to a nacl keypair. */
  protected tradingKeypair(index: number): nacl.SignKeyPair {
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

  /**
   * Derive once for one order operation, without retaining expanded secret
   * keys beyond the returned closure's lifetime. This removes duplicate
   * tweetnacl scalar multiplications without introducing an unbounded cache.
   */
  tradingSigner(index: number): {
    publicKey: Uint8Array;
    sign: (digest: Uint8Array) => Uint8Array;
  } {
    const keypair = this.tradingKeypair(index);
    return {
      publicKey: keypair.publicKey,
      sign: (digest) => nacl.sign.detached(digest, keypair.secretKey),
    };
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

interface KeystoreFileV3 {
  version: 3;
  kdf: "scrypt";
  profile: "scrypt-n17-r8-p1-v1";
  cipher: "aes-256-gcm";
  salt: string;
  iv: string;
  ciphertext: string;
  tag: string;
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
const V3_AAD_DOMAIN = Buffer.from("darknyx-daemon-keystore/v3\0", "utf8");
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

function serializeIdentityV3(id: AccountIdentity): string {
  return JSON.stringify({
    seed: toHex(id.masterSeed),
  });
}

function parsePlaintextObject(json: string): JsonObject {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new Error("keystore plaintext is not valid JSON");
  }
  return asObject(parsed, "keystore identity");
}

function deserializeIdentityV3(json: string): AccountIdentity {
  const o = parsePlaintextObject(json);
  requireExactKeys(o, ["seed"], "keystore v3 identity");
  return deriveAccountIdentity(
    Uint8Array.from(decodeFixedHex(o.seed, "seed", 64)),
  );
}

/** Parse the redundant v1/v2 plaintext once, validate every historical field,
 * then deliberately retain only the master seed for the v3 identity. */
function deserializeLegacyIdentity(json: string): AccountIdentity {
  const o = parsePlaintextObject(json);
  requireExactKeys(
    o,
    ["seed", "ownerBlinding", "r0", "r1", "r2", "rootKeyPubkey"],
    "keystore identity",
  );
  parseFieldDecimal(o.ownerBlinding, "ownerBlinding");
  parseFieldDecimal(o.r0, "r0");
  parseFieldDecimal(o.r1, "r1");
  parseFieldDecimal(o.r2, "r2");
  decodeFixedHex(o.rootKeyPubkey, "rootKeyPubkey", 32);
  return deriveAccountIdentity(
    Uint8Array.from(decodeFixedHex(o.seed, "seed", 64)),
  );
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

function v3Aad(salt: Buffer, iv: Buffer): Buffer {
  return Buffer.concat([
    V3_AAD_DOMAIN,
    Buffer.from("scrypt\0", "utf8"),
    Buffer.from(`${V2_KDF_PROFILE}\0`, "utf8"),
    Buffer.from(`${V2_CIPHER}\0`, "utf8"),
    salt,
    iv,
  ]);
}

function sealV3(
  identity: AccountIdentity,
  passphrase: string,
  salt = randomBytes(16),
  iv = randomBytes(12),
): KeystoreFileV3 {
  const validated = deserializeIdentityV3(serializeIdentityV3(identity));
  new Keystore(validated);
  const key = deriveV2Key(passphrase, salt);
  try {
    const cipher = createCipheriv(V2_CIPHER, key, iv);
    cipher.setAAD(v3Aad(salt, iv));
    const plaintext = Buffer.from(serializeIdentityV3(validated), "utf8");
    const ciphertext = Buffer.concat([
      cipher.update(plaintext),
      cipher.final(),
    ]);
    const tag = cipher.getAuthTag();
    return {
      version: 3,
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
  deserialize: (json: string) => AccountIdentity,
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
    const identity = deserialize(plaintext.toString("utf8"));
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
    deserializeLegacyIdentity,
    v2Aad(salt, iv),
  );
}

function openV3(file: JsonObject, passphrase: string): AccountIdentity {
  requireExactKeys(
    file,
    ["version", "kdf", "profile", "cipher", "salt", "iv", "ciphertext", "tag"],
    "keystore v3",
  );
  if (
    file.version !== 3 ||
    file.kdf !== "scrypt" ||
    file.profile !== V2_KDF_PROFILE ||
    file.cipher !== V2_CIPHER
  ) {
    throw new Error("unsupported keystore v3 profile");
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
    deserializeIdentityV3,
    v3Aad(salt, iv),
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
    deserializeLegacyIdentity,
  );
}

/** Seal an identity to disk under `passphrase` using the fixed v3 profile. */
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
  atomicReplace(path, JSON.stringify(sealV3(identity, passphrase)));
}

/**
 * Open a sealed keystore.
 *
 * V3 files use the fixed N=2^17/r=8/p=1 profile and contain only the master
 * seed. Valid v1/v2 files are fully validated, reduced to that same seed, and
 * atomically replaced with v3 before this returns.
 */
export function loadKeystore(path: string, passphrase: string): Keystore {
  const file = parseFile(path);
  if (file.version === 3) {
    return new Keystore(openV3(file, passphrase));
  }
  if (file.version === 2) {
    const identity = openV2(file, passphrase);
    try {
      atomicReplace(path, JSON.stringify(sealV3(identity, passphrase)));
    } catch {
      throw new Error(
        "keystore v2 decrypted but atomic migration to v3 failed; no partial file was exposed",
      );
    }
    return new Keystore(identity);
  }
  if (file.version === 1) {
    const identity = openV1(file, passphrase);
    try {
      atomicReplace(path, JSON.stringify(sealV3(identity, passphrase)));
    } catch {
      throw new Error(
        "keystore v1 decrypted but atomic migration to v3 failed; no partial file was exposed",
      );
    }
    return new Keystore(identity);
  }
  throw new Error("unsupported keystore file version");
}
