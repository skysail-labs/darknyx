/**
 * Durable two-output recovery v3 crypto foundation.
 *
 * Two contracts:
 *  1. TS round-trips its own encrypt→decrypt (the client path).
 *  2. The FIXED VECTOR pins the encryption construction to the Rust encryptor
 *     (`crates/darkpool-crypto/src/fill_encryption.rs::fixed_vector_is_stable`).
 *     Same inputs (RECIPIENT_SECRET, EPH_SECRET, NONCE, AMOUNT) must yield the
 *     SAME ephemeral pubkey (proving tweetnacl X25519 base-mult == x25519-dalek)
 *     and the SAME 44-byte blob, and that blob must decrypt both amounts.
 *     If this drifts, the TEE-encrypted on-chain ciphertext won't decrypt
 *     client-side. There is NO key-derivation parity test (the TEE only consumes
 *     the client's pubkey; it never re-derives it).
 */

import { describe, it, expect } from "vitest";
import {
  encryptFillAmounts,
  decryptFillAmounts,
  isContributoryX25519PublicKey,
  SIDE_BLOB_LEN,
} from "../src/keys/fill-encryption.js";
import { deriveViewingEncKeypair } from "../src/keys/key-generators.js";
import nacl from "tweetnacl";

// ---- The cross-language fixed vector (mirror of the Rust test) -------------
const RECIPIENT_SECRET = new Uint8Array(32).fill(0x02);
const EPH_SECRET = new Uint8Array(32).fill(0x07);
const NONCE = new Uint8Array([
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
]);
const AMOUNTS = { trade: 1_234_567_890_123n, change: 98_765_432_101n };
const EXPECTED_EPH_PUB_HEX =
  "13be4feaeaf204c7fd3358fc9c00721881d174278128227ec674f37f7fe97b6d";
const EXPECTED_BLOB_HEX =
  "101112131415161718191a1b90b91ce896d093df943c6875cd06f2dd114d124486ffcedc672edf6cfb1b6bc3";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

describe("fill-encryption recovery v3", () => {
  it("round-trips encrypt → decrypt", () => {
    const recipientPub = nacl.scalarMult.base(RECIPIENT_SECRET);
    const ephPub = nacl.scalarMult.base(EPH_SECRET);
    const blob = encryptFillAmounts(EPH_SECRET, recipientPub, AMOUNTS, NONCE);
    expect(blob.length).toBe(SIDE_BLOB_LEN);
    expect(decryptFillAmounts(RECIPIENT_SECRET, ephPub, blob)).toEqual(AMOUNTS);
  });

  it("matches the Rust fixed vector (ephemeral pub + blob)", () => {
    // tweetnacl X25519 base-mult must agree with x25519-dalek.
    expect(hex(nacl.scalarMult.base(EPH_SECRET))).toBe(EXPECTED_EPH_PUB_HEX);

    const recipientPub = nacl.scalarMult.base(RECIPIENT_SECRET);
    const blob = encryptFillAmounts(EPH_SECRET, recipientPub, AMOUNTS, NONCE);
    expect(hex(blob)).toBe(EXPECTED_BLOB_HEX);
  });

  it("decrypts the Rust-produced blob back to the amount", () => {
    const ephPub = Buffer.from(EXPECTED_EPH_PUB_HEX, "hex");
    const blob = Buffer.from(EXPECTED_BLOB_HEX, "hex");
    expect(decryptFillAmounts(RECIPIENT_SECRET, ephPub, blob)).toEqual(AMOUNTS);
  });

  it("rejects a wrong key", () => {
    const recipientPub = nacl.scalarMult.base(RECIPIENT_SECRET);
    const ephPub = nacl.scalarMult.base(EPH_SECRET);
    const blob = encryptFillAmounts(EPH_SECRET, recipientPub, AMOUNTS, NONCE);
    expect(
      decryptFillAmounts(new Uint8Array(32).fill(0x09), ephPub, blob),
    ).toBeNull();
  });

  it("rejects low-order X25519 encodings", () => {
    const lowOrder = [
      "00".repeat(32),
      `01${"00".repeat(31)}`,
      "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
      "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
      `ec${"ff".repeat(30)}7f`,
      `ed${"ff".repeat(30)}7f`,
      `ee${"ff".repeat(30)}7f`,
    ].map((encoded) => Uint8Array.from(Buffer.from(encoded, "hex")));
    for (const point of lowOrder) {
      expect(isContributoryX25519PublicKey(point)).toBe(false);
    }
    const zero = lowOrder[0]!;
    const one = lowOrder[1]!;
    expect(() => encryptFillAmounts(EPH_SECRET, zero, AMOUNTS, NONCE)).toThrow(
      /non-contributory/,
    );
    expect(() => encryptFillAmounts(EPH_SECRET, one, AMOUNTS, NONCE)).toThrow(
      /non-contributory/,
    );
    expect(
      decryptFillAmounts(RECIPIENT_SECRET, zero, new Uint8Array(SIDE_BLOB_LEN)),
    ).toBeNull();
  });

  it("rejects a tampered blob", () => {
    const recipientPub = nacl.scalarMult.base(RECIPIENT_SECRET);
    const ephPub = nacl.scalarMult.base(EPH_SECRET);
    const blob = encryptFillAmounts(EPH_SECRET, recipientPub, AMOUNTS, NONCE);
    blob[SIDE_BLOB_LEN - 1] ^= 0x01; // flip a tag byte
    expect(decryptFillAmounts(RECIPIENT_SECRET, ephPub, blob)).toBeNull();
  });

  it("one ephemeral key serves both sides (multi-recipient)", () => {
    const aliceKp = deriveViewingEncKeypair(new Uint8Array(64).fill(0x31));
    const bobKp = deriveViewingEncKeypair(new Uint8Array(64).fill(0x32));
    const ephSecret = new Uint8Array(32).fill(0x55);
    const ephPub = nacl.scalarMult.base(ephSecret);

    const amountsA = { trade: 111n, change: 11n };
    const amountsB = { trade: 222n, change: 22n };
    const blobA = encryptFillAmounts(
      ephSecret,
      aliceKp.publicKey,
      amountsA,
      new Uint8Array(12).fill(1),
    );
    const blobB = encryptFillAmounts(
      ephSecret,
      bobKp.publicKey,
      amountsB,
      new Uint8Array(12).fill(2),
    );

    expect(decryptFillAmounts(aliceKp.secretKey, ephPub, blobA)).toEqual(amountsA);
    expect(decryptFillAmounts(bobKp.secretKey, ephPub, blobB)).toEqual(amountsB);
    // Cross-decrypt fails (recipient binding in HKDF info).
    expect(decryptFillAmounts(aliceKp.secretKey, ephPub, blobB)).toBeNull();
    expect(decryptFillAmounts(bobKp.secretKey, ephPub, blobA)).toBeNull();
  });

  it("deriveViewingEncKeypair is deterministic from the seed", () => {
    const seed = new Uint8Array(64).fill(0x42);
    const a = deriveViewingEncKeypair(seed);
    const b = deriveViewingEncKeypair(seed);
    expect(hex(a.secretKey)).toBe(hex(b.secretKey));
    expect(hex(a.publicKey)).toBe(hex(b.publicKey));
    expect(a.publicKey.length).toBe(32);
    // public is the X25519 base-mult of the secret.
    expect(hex(nacl.scalarMult.base(a.secretKey))).toBe(hex(a.publicKey));
  });
});
