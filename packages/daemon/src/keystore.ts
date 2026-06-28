/**
 * Keystore — the daemon's on-device crypto identity. Keys NEVER leave here.
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
 * It implements {@link KeyProvider}, so the {@link DaemonActionExecutor} pulls
 * the exact same trading key for an anchor top-up that the order was placed
 * under (the TEE verifies the signature against it).
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
import { readFileSync, writeFileSync } from "node:fs";

import nacl from "tweetnacl";
import {
  deriveSpendingKey,
  deriveMasterViewingKey,
  deriveTradingKeyAtOffset,
  ownerCommitment,
  userCommitmentFromKeys,
} from "@nyx/sdk";

import type { KeyProvider, OrderKeys } from "./action-executor.js";
import type { ManagedOrder } from "./types.js";

const toHex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
const fromHex = (h: string): Uint8Array =>
  Uint8Array.from(Buffer.from(h, "hex"));

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

export class Keystore implements KeyProvider {
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

  /** The account's 32-byte big-endian user commitment (Poseidon — async). */
  userCommitment(): Promise<Uint8Array> {
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

  // ── KeyProvider ──
  keysForOrder(order: ManagedOrder): OrderKeys {
    const idx = order.seedIndex;
    const kp = this.tradingKeypair(idx);
    return {
      masterSeed: this.identity.masterSeed,
      spendingKey: this.spend,
      tradingKeyPubkey: kp.publicKey,
      sign: (digest) => nacl.sign.detached(digest, kp.secretKey),
    };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Encrypted-at-rest persistence (AES-256-GCM under a scrypt-stretched passphrase)
// ─────────────────────────────────────────────────────────────────────────────

interface KeystoreFile {
  version: 1;
  kdf: "scrypt";
  /** scrypt params. */
  n: number;
  r: number;
  p: number;
  salt: string; // hex
  iv: string; // hex (12 bytes, GCM)
  ciphertext: string; // hex
  tag: string; // hex (16-byte GCM auth tag)
}

const SCRYPT = { n: 16384, r: 8, p: 1 } as const;

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
  const o = JSON.parse(json) as Record<string, string>;
  return {
    masterSeed: fromHex(o.seed),
    ownerBlinding: BigInt(o.ownerBlinding),
    r0: BigInt(o.r0),
    r1: BigInt(o.r1),
    r2: BigInt(o.r2),
    rootKeyPubkey: fromHex(o.rootKeyPubkey),
  };
}

function deriveKey(passphrase: string, salt: Buffer): Buffer {
  return scryptSync(passphrase, salt, 32, {
    N: SCRYPT.n,
    r: SCRYPT.r,
    p: SCRYPT.p,
  });
}

/** Seal an identity to disk under `passphrase`. Writes `0600`. */
export function saveKeystore(
  identity: AccountIdentity,
  path: string,
  passphrase: string,
): void {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = deriveKey(passphrase, salt);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const plaintext = Buffer.from(serializeIdentity(identity), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  const file: KeystoreFile = {
    version: 1,
    kdf: "scrypt",
    n: SCRYPT.n,
    r: SCRYPT.r,
    p: SCRYPT.p,
    salt: salt.toString("hex"),
    iv: iv.toString("hex"),
    ciphertext: ciphertext.toString("hex"),
    tag: tag.toString("hex"),
  };
  writeFileSync(path, JSON.stringify(file), { mode: 0o600 });
}

/** Open a sealed keystore. Throws if the passphrase is wrong (GCM tag fails). */
export function loadKeystore(path: string, passphrase: string): Keystore {
  const file = JSON.parse(readFileSync(path, "utf8")) as KeystoreFile;
  if (file.version !== 1 || file.kdf !== "scrypt") {
    throw new Error("unsupported keystore file");
  }
  const key = scryptSync(passphrase, Buffer.from(file.salt, "hex"), 32, {
    N: file.n,
    r: file.r,
    p: file.p,
  });
  const decipher = createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(file.iv, "hex"),
  );
  decipher.setAuthTag(Buffer.from(file.tag, "hex"));
  let plaintext: Buffer;
  try {
    plaintext = Buffer.concat([
      decipher.update(Buffer.from(file.ciphertext, "hex")),
      decipher.final(),
    ]);
  } catch {
    throw new Error(
      "keystore decrypt failed (wrong passphrase or corrupt file)",
    );
  }
  return new Keystore(deserializeIdentity(plaintext.toString("utf8")));
}
