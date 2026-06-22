/**
 * Change-amount recovery (Proposal B), B.1 crypto foundation.
 *
 * Two contracts:
 *  1. TS round-trips its own encrypt→decrypt (the client path).
 *  2. The FIXED VECTOR pins the encryption construction to the Rust encryptor
 *     (`crates/darkpool-crypto/src/fill_encryption.rs::fixed_vector_is_stable`).
 *     Same inputs (RECIPIENT_SECRET, EPH_SECRET, NONCE, AMOUNT) must yield the
 *     SAME ephemeral pubkey (proving tweetnacl X25519 base-mult == x25519-dalek)
 *     and the SAME 36-byte blob, and that blob must decrypt back to AMOUNT.
 *     If this drifts, the TEE-encrypted on-chain ciphertext won't decrypt
 *     client-side. There is NO key-derivation parity test (the TEE only consumes
 *     the client's pubkey; it never re-derives it).
 */

import { describe, it, expect } from "vitest";
import {
  encryptChangeAmount,
  decryptChangeAmount,
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
const AMOUNT = 1_234_567_890_123n;
const EXPECTED_EPH_PUB_HEX =
  "13be4feaeaf204c7fd3358fc9c00721881d174278128227ec674f37f7fe97b6d";
const EXPECTED_BLOB_HEX =
  "101112131415161718191a1bf38cd2533492baadb9e66ce516a13d47fca255f1f877cb1e";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

describe("fill-encryption (change-amount recovery B.1)", () => {
  it("round-trips encrypt → decrypt", () => {
    const recipientPub = nacl.scalarMult.base(RECIPIENT_SECRET);
    const ephPub = nacl.scalarMult.base(EPH_SECRET);
    const blob = encryptChangeAmount(EPH_SECRET, recipientPub, AMOUNT, NONCE);
    expect(blob.length).toBe(SIDE_BLOB_LEN);
    expect(decryptChangeAmount(RECIPIENT_SECRET, ephPub, blob)).toBe(AMOUNT);
  });

  it("matches the Rust fixed vector (ephemeral pub + blob)", () => {
    // tweetnacl X25519 base-mult must agree with x25519-dalek.
    expect(hex(nacl.scalarMult.base(EPH_SECRET))).toBe(EXPECTED_EPH_PUB_HEX);

    const recipientPub = nacl.scalarMult.base(RECIPIENT_SECRET);
    const blob = encryptChangeAmount(EPH_SECRET, recipientPub, AMOUNT, NONCE);
    expect(hex(blob)).toBe(EXPECTED_BLOB_HEX);
  });

  it("decrypts the Rust-produced blob back to the amount", () => {
    const ephPub = Buffer.from(EXPECTED_EPH_PUB_HEX, "hex");
    const blob = Buffer.from(EXPECTED_BLOB_HEX, "hex");
    expect(decryptChangeAmount(RECIPIENT_SECRET, ephPub, blob)).toBe(AMOUNT);
  });

  it("rejects a wrong key", () => {
    const recipientPub = nacl.scalarMult.base(RECIPIENT_SECRET);
    const ephPub = nacl.scalarMult.base(EPH_SECRET);
    const blob = encryptChangeAmount(EPH_SECRET, recipientPub, AMOUNT, NONCE);
    expect(decryptChangeAmount(new Uint8Array(32).fill(0x09), ephPub, blob)).toBeNull();
  });

  it("rejects a tampered blob", () => {
    const recipientPub = nacl.scalarMult.base(RECIPIENT_SECRET);
    const ephPub = nacl.scalarMult.base(EPH_SECRET);
    const blob = encryptChangeAmount(EPH_SECRET, recipientPub, AMOUNT, NONCE);
    blob[SIDE_BLOB_LEN - 1] ^= 0x01; // flip a tag byte
    expect(decryptChangeAmount(RECIPIENT_SECRET, ephPub, blob)).toBeNull();
  });

  it("one ephemeral key serves both sides (multi-recipient)", () => {
    const aliceKp = deriveViewingEncKeypair(new Uint8Array(64).fill(0x31));
    const bobKp = deriveViewingEncKeypair(new Uint8Array(64).fill(0x32));
    const ephSecret = new Uint8Array(32).fill(0x55);
    const ephPub = nacl.scalarMult.base(ephSecret);

    const blobA = encryptChangeAmount(ephSecret, aliceKp.publicKey, 111n, new Uint8Array(12).fill(1));
    const blobB = encryptChangeAmount(ephSecret, bobKp.publicKey, 222n, new Uint8Array(12).fill(2));

    expect(decryptChangeAmount(aliceKp.secretKey, ephPub, blobA)).toBe(111n);
    expect(decryptChangeAmount(bobKp.secretKey, ephPub, blobB)).toBe(222n);
    // Cross-decrypt fails (recipient binding in HKDF info).
    expect(decryptChangeAmount(aliceKp.secretKey, ephPub, blobB)).toBeNull();
    expect(decryptChangeAmount(bobKp.secretKey, ephPub, blobA)).toBeNull();
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
