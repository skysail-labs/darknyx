/**
 * Wallet-signature master-seed derivation (Proposal A — deterministic seed).
 *
 * Pins the canonical derivation so the SDK's `resolveMasterSeed({ type:
 * "wallet-signature" })` and any production client deriving the seed server-side
 * from the same signature (via `seedFromWalletSignature`) can never drift — a
 * drift would make a user's keys (and thus their recoverable notes)
 * irreproducible across devices.
 */

import { describe, it, expect } from "vitest";
import crypto from "node:crypto";
import {
  seedFromWalletSignature,
  resolveMasterSeed,
  MASTER_SEED_MESSAGE,
  MASTER_SEED_BYTES,
} from "../src/keys/key-generators.js";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

describe("wallet-signature master seed", () => {
  it("the seed message is the fixed NYX_DARKPOOL_SEED_V1 string", () => {
    expect(new TextDecoder().decode(MASTER_SEED_MESSAGE)).toBe("NYX_DARKPOOL_SEED_V1");
  });

  it("seedFromWalletSignature = SHA-512(signature)[:64]", () => {
    const sig = new Uint8Array(64).fill(0xab);
    const expected = new Uint8Array(
      crypto.createHash("sha512").update(Buffer.from(sig)).digest().subarray(0, MASTER_SEED_BYTES),
    );
    const seed = seedFromWalletSignature(sig);
    expect(seed.length).toBe(64);
    expect(hex(seed)).toBe(hex(expected));
  });

  it("resolveMasterSeed(wallet-signature) routes through seedFromWalletSignature", async () => {
    const sig = new Uint8Array(64).fill(0x07);
    let signedMsg: Uint8Array | null = null;
    const seed = await resolveMasterSeed({
      type: "wallet-signature",
      signMessage: async (msg) => {
        signedMsg = msg;
        return sig;
      },
    });
    // It signs the fixed message …
    expect(signedMsg).not.toBeNull();
    expect(new TextDecoder().decode(signedMsg!)).toBe("NYX_DARKPOOL_SEED_V1");
    // … and derives exactly what the shared helper does.
    expect(hex(seed)).toBe(hex(seedFromWalletSignature(sig)));
  });

  it("is deterministic + recoverable (same signature → same seed)", () => {
    const sig = crypto.randomBytes(64);
    expect(hex(seedFromWalletSignature(sig))).toBe(hex(seedFromWalletSignature(sig)));
  });
});
