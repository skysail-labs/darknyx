import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
} from "node:crypto";
import { lstat, mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import { dirname, basename, join } from "node:path";

const PROFILE = "scrypt-n17-r8-p1-v1" as const;
const CIPHER = "aes-256-gcm" as const;
const MAX_FILE_BYTES = 64 * 1024 * 1024;
const SCRYPT = {
  N: 1 << 17,
  r: 8,
  p: 1,
  maxmem: 256 * 1024 * 1024,
} as const;

interface SealedFileV1 {
  version: 1;
  kind: string;
  kdf: "scrypt";
  profile: typeof PROFILE;
  cipher: typeof CIPHER;
  salt: string;
  iv: string;
  ciphertext: string;
  tag: string;
}

function aad(kind: string): Buffer {
  return Buffer.from(`darknyx/operator-sealed-json/v1\0${kind}`, "utf8");
}

function requirePassphrase(passphrase: string): void {
  if (passphrase.length < 16) {
    throw new Error(
      "operator secret-store passphrase must be at least 16 characters",
    );
  }
}

function hex(value: string, bytes: number | null, name: string): Buffer {
  if (
    value.length % 2 !== 0 ||
    !/^[0-9a-f]+$/.test(value) ||
    (bytes !== null && value.length !== bytes * 2)
  ) {
    throw new Error(`invalid sealed-file ${name}`);
  }
  return Buffer.from(value, "hex");
}

function parseEnvelope(value: unknown, expectedKind: string): SealedFileV1 {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("sealed file must contain an object");
  }
  const item = value as Record<string, unknown>;
  const expected = [
    "cipher",
    "ciphertext",
    "iv",
    "kdf",
    "kind",
    "profile",
    "salt",
    "tag",
    "version",
  ];
  if (Object.keys(item).sort().join("\0") !== expected.sort().join("\0")) {
    throw new Error("sealed file contains unknown or missing fields");
  }
  if (
    item.version !== 1 ||
    item.kind !== expectedKind ||
    item.kdf !== "scrypt" ||
    item.profile !== PROFILE ||
    item.cipher !== CIPHER ||
    typeof item.salt !== "string" ||
    typeof item.iv !== "string" ||
    typeof item.ciphertext !== "string" ||
    typeof item.tag !== "string"
  ) {
    throw new Error("unsupported or malformed sealed file");
  }
  hex(item.salt, 16, "salt");
  hex(item.iv, 12, "iv");
  hex(item.tag, 16, "tag");
  const ciphertext = hex(item.ciphertext, null, "ciphertext");
  if (ciphertext.length > MAX_FILE_BYTES) {
    throw new Error("sealed-file ciphertext exceeds the size limit");
  }
  return item as unknown as SealedFileV1;
}

async function assertRegularFile(path: string): Promise<void> {
  const stat = await lstat(path);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error("operator secret-store path must be a regular file");
  }
  if (stat.size > MAX_FILE_BYTES * 2 + 4096) {
    throw new Error("operator secret-store file exceeds the size limit");
  }
}

/** Atomically seal JSON under a fixed KDF profile and file mode 0600. */
export async function writeSealedJson(
  path: string,
  kind: string,
  value: unknown,
  passphrase: string,
): Promise<void> {
  requirePassphrase(passphrase);
  if (!/^[a-z0-9-]{1,64}$/.test(kind))
    throw new Error("invalid sealed-file kind");
  const plaintext = Buffer.from(JSON.stringify(value), "utf8");
  if (plaintext.length > MAX_FILE_BYTES) {
    throw new Error("operator secret-store plaintext exceeds the size limit");
  }
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = scryptSync(passphrase, salt, 32, SCRYPT);
  let temporary: string | null = null;
  try {
    const cipher = createCipheriv(CIPHER, key, iv);
    cipher.setAAD(aad(kind));
    const ciphertext = Buffer.concat([
      cipher.update(plaintext),
      cipher.final(),
    ]);
    const envelope: SealedFileV1 = {
      version: 1,
      kind,
      kdf: "scrypt",
      profile: PROFILE,
      cipher: CIPHER,
      salt: salt.toString("hex"),
      iv: iv.toString("hex"),
      ciphertext: ciphertext.toString("hex"),
      tag: cipher.getAuthTag().toString("hex"),
    };
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    temporary = join(
      dirname(path),
      `.${basename(path)}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`,
    );
    const temporaryFile = await open(temporary, "wx", 0o600);
    try {
      await temporaryFile.writeFile(`${JSON.stringify(envelope)}\n`, "utf8");
      await temporaryFile.sync();
    } finally {
      await temporaryFile.close();
    }
    await rename(temporary, path);
    const directory = await open(dirname(path), "r");
    try {
      await directory.sync();
    } finally {
      await directory.close();
    }
    temporary = null;
  } finally {
    if (temporary) await unlink(temporary).catch(() => undefined);
    key.fill(0);
    plaintext.fill(0);
  }
}

/** Open and authenticate a sealed JSON file. */
export async function readSealedJson(
  path: string,
  kind: string,
  passphrase: string,
): Promise<unknown> {
  requirePassphrase(passphrase);
  await assertRegularFile(path);
  const encoded = await readFile(path, "utf8");
  const envelope = parseEnvelope(JSON.parse(encoded) as unknown, kind);
  const salt = hex(envelope.salt, 16, "salt");
  const iv = hex(envelope.iv, 12, "iv");
  const ciphertext = hex(envelope.ciphertext, null, "ciphertext");
  const key = scryptSync(passphrase, salt, 32, SCRYPT);
  let plaintext: Buffer | null = null;
  try {
    const decipher = createDecipheriv(CIPHER, key, iv);
    decipher.setAAD(aad(kind));
    decipher.setAuthTag(hex(envelope.tag, 16, "tag"));
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return JSON.parse(plaintext.toString("utf8")) as unknown;
  } catch {
    throw new Error("operator secret store authentication failed");
  } finally {
    key.fill(0);
    plaintext?.fill(0);
  }
}
