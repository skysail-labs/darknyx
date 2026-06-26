/**
 * Cross-environment parity for the Note Commitment formula.
 *
 * Formula (must match `circuits/valid_spend/circuit.circom`):
 *
 *   noteCommitment = Poseidon7(
 *     DOMAIN_NOTE=2,        // domain separation tag
 *     token_mint_lo_u128,
 *     token_mint_hi_u128,
 *     amount_u64,
 *     owner_commitment_fr,  // = Poseidon3(DOMAIN_OWNER=1, spending_key, r_owner)
 *     nonce_fr,
 *     blinding_r_fr,
 *   )
 *
 * The TS `noteCommitment()` must produce the same 32-byte hex as the Rust
 * `commitment_from_fields()`. If they diverge, every shielded deposit ⇄
 * withdraw becomes unspendable from the other environment.
 *
 * This is the highest-leverage parity test we could add — note_commitment is
 * the foundation of every UTXO operation. (Sibling: `nullifier-parity.test.ts`.)
 */

import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { existsSync } from "node:fs";

import { noteCommitment } from "../src/utxo/note.js";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", "..", "..");
const helper = resolve(repoRoot, "target/debug/examples/note-commitment");

function rustHelper(
  mintHex: string,
  amount: bigint,
  ownerHex: string,
  nonceHex: string,
  blindingHex: string,
): string {
  if (!existsSync(helper)) throw new Error("note-commitment helper missing");
  const res = spawnSync(
    helper,
    [mintHex, amount.toString(), ownerHex, nonceHex, blindingHex],
    { encoding: "utf8" },
  );
  if (res.status !== 0) throw new Error(res.stderr || "helper failed");
  return res.stdout.trim();
}

function hex32(bytes: Uint8Array): string {
  if (bytes.length !== 32) throw new Error("expected 32 bytes");
  return Buffer.from(bytes).toString("hex");
}

function bytesFromHex32(hex: string): Uint8Array {
  if (hex.length !== 64) throw new Error("expected 64 hex chars");
  return Uint8Array.from(Buffer.from(hex, "hex"));
}

function bigintFromHex32(hex: string): bigint {
  if (hex.length !== 64) throw new Error("expected 64 hex chars");
  let n = 0n;
  for (let i = 0; i < hex.length; i += 2) {
    n = (n << 8n) | BigInt(parseInt(hex.slice(i, i + 2), 16));
  }
  return n;
}

describe("Note commitment parity (TS vs Rust)", () => {
  const available = existsSync(helper);
  const ait = (name: string, fn: () => Promise<void>) =>
    available ? it(name, fn) : it.skip(name, fn);

  ait("matches on fixed canonical inputs", async () => {
    // Hand-picked safe values: every 32-byte field is < BN254_r so both the
    // strict Rust path and circomlibjs accept them identically.
    const mintHex = "01".repeat(32);
    const amount = 1_000_000_000n;
    const ownerHex = "0a".repeat(32);
    const nonceHex = "0b".repeat(32);
    const blindingHex = "0c".repeat(32);

    const tsHex = hex32(
      await noteCommitment({
        tokenMint: bytesFromHex32(mintHex),
        amount,
        ownerCommitment: bigintFromHex32(ownerHex),
        nonce: bigintFromHex32(nonceHex),
        blindingR: bigintFromHex32(blindingHex),
      }),
    );
    const rsHex = rustHelper(mintHex, amount, ownerHex, nonceHex, blindingHex);
    expect(tsHex).toBe(rsHex);
  });

  ait("changes when each input changes (witness sensitivity)", async () => {
    // All field elements MUST be < BN254 r = 0x30644e72e131a029b85045b68181585d…
    // Using high-bytes ≤ 0x10 keeps everything safely in-field for the strict
    // Rust path (see field.rs::fr_from_be_bytes). circomlibjs silently mod-
    // reduces, so picking out-of-field values here would mask divergence
    // rather than expose it.
    const base = {
      mintHex: "11".repeat(32),
      amount: 42n,
      ownerHex: "10".repeat(32),
      nonceHex: "0f".repeat(32),
      blindingHex: "0e".repeat(32),
    };
    const baseTs = hex32(
      await noteCommitment({
        tokenMint: bytesFromHex32(base.mintHex),
        amount: base.amount,
        ownerCommitment: bigintFromHex32(base.ownerHex),
        nonce: bigintFromHex32(base.nonceHex),
        blindingR: bigintFromHex32(base.blindingHex),
      }),
    );
    const baseRs = rustHelper(
      base.mintHex,
      base.amount,
      base.ownerHex,
      base.nonceHex,
      base.blindingHex,
    );
    expect(baseTs).toBe(baseRs);

    // Mutate each field one at a time — both sides must agree it changed and agree on the new value.
    const variants = [
      { ...base, mintHex: "12".repeat(32) },
      { ...base, amount: 43n },
      { ...base, ownerHex: "0d".repeat(32) },
      { ...base, nonceHex: "0c".repeat(32) },
      { ...base, blindingHex: "0b".repeat(32) },
    ];
    for (const v of variants) {
      const ts = hex32(
        await noteCommitment({
          tokenMint: bytesFromHex32(v.mintHex),
          amount: v.amount,
          ownerCommitment: bigintFromHex32(v.ownerHex),
          nonce: bigintFromHex32(v.nonceHex),
          blindingR: bigintFromHex32(v.blindingHex),
        }),
      );
      const rs = rustHelper(
        v.mintHex,
        v.amount,
        v.ownerHex,
        v.nonceHex,
        v.blindingHex,
      );
      expect(ts).toBe(rs);
      expect(ts).not.toBe(baseTs);
    }
  });

  // Documents the deliberate strict-vs-lenient asymmetry between Rust
  // (`fr_from_be_bytes` rejects out-of-field) and TS (circomlibjs silently
  // mod-reduces). The TS surface SHOULD eventually mirror the strict Rust
  // behaviour — see the open punch-list item in the cryptography review.
  // Until then, this test pins the current behaviour so any future change is
  // intentional.
  ait(
    "Rust strictly rejects out-of-field inputs; TS silently reduces",
    async () => {
      // 0x33 * (256^32 - 1) / 255 ≈ 0.2 * 2^256, just above BN254 r.
      const outOfFieldHex = "33".repeat(32);
      const mintHex = "01".repeat(32);

      // TS path silently reduces and produces a hash without throwing.
      const tsOK = await noteCommitment({
        tokenMint: bytesFromHex32(mintHex),
        amount: 1n,
        ownerCommitment: bigintFromHex32(outOfFieldHex),
        nonce: 1n,
        blindingR: 1n,
      });
      expect(tsOK).toBeInstanceOf(Uint8Array);
      expect(tsOK.length).toBe(32);

      // Rust path rejects with NotInField.
      const res = spawnSync(
        helper,
        [mintHex, "1", outOfFieldHex, "01".repeat(32), "01".repeat(32)],
        { encoding: "utf8" },
      );
      expect(res.status).not.toBe(0);
      expect(res.stderr).toContain("NotInField");
    },
  );

  ait("matches on amount = 0 and large u64", async () => {
    const mintHex = "ff".repeat(16) + "00".repeat(16); // mixed high/low halves
    const ownerHex = "0d".repeat(32);
    const nonceHex = "0e".repeat(32);
    const blindingHex = "0f".repeat(32);

    for (const amount of [0n, 1n, 18446744073709551615n /* u64::MAX */]) {
      const ts = hex32(
        await noteCommitment({
          tokenMint: bytesFromHex32(mintHex),
          amount,
          ownerCommitment: bigintFromHex32(ownerHex),
          nonce: bigintFromHex32(nonceHex),
          blindingR: bigintFromHex32(blindingHex),
        }),
      );
      const rs = rustHelper(mintHex, amount, ownerHex, nonceHex, blindingHex);
      expect(ts).toBe(rs);
    }
  });
});
