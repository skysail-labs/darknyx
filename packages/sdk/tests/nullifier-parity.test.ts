/**
 * Cross-environment parity for the Nullifier formula.
 *
 * Formula (must match `circuits/valid_spend/circuit.circom`):
 *
 *   nullifier = Poseidon3( DOMAIN_NULL=3, spending_key_fr, note_commitment_fr )
 *
 * Domain tag prevents second-preimage collisions with owner_commitment (DOMAIN_OWNER=1)
 * and note_commitment (DOMAIN_NOTE=2). This test pins the correct formula in place;
 * any drift from the circuit will fail here before it has a chance to fail a real settlement.
 *
 * Sibling: `note-commitment-parity.test.ts`.
 */

import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { existsSync } from "node:fs";

import { nullifier as tsNullifier, noteCommitment } from "../src/utxo/note.js";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", "..", "..");
const helper = resolve(repoRoot, "target/debug/examples/nullifier");

function rustHelper(skDec: bigint, noteCommitmentHex: string): string {
  if (!existsSync(helper)) throw new Error("nullifier helper missing");
  const res = spawnSync(helper, [skDec.toString(), noteCommitmentHex], {
    encoding: "utf8",
  });
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

describe("Nullifier parity (TS vs Rust)", () => {
  const available = existsSync(helper);
  const ait = (name: string, fn: () => Promise<void>) =>
    available ? it(name, fn) : it.skip(name, fn);

  ait("matches on a small fixed (sk, commitment)", async () => {
    // Build a real note commitment so the second input is guaranteed in-field.
    const mintHex = "01".repeat(32);
    const ownerHex = "02".repeat(32);
    const nonceHex = "03".repeat(32);
    const blindingHex = "04".repeat(32);
    const commitment = await noteCommitment({
      tokenMint: bytesFromHex32(mintHex),
      amount: 100n,
      ownerCommitment: bigintFromHex32(ownerHex),
      nonce: bigintFromHex32(nonceHex),
      blindingR: bigintFromHex32(blindingHex),
    });

    const sk = 42n;
    const tsHex = hex32(await tsNullifier(sk, commitment));
    const rsHex = rustHelper(sk, hex32(commitment));
    expect(tsHex).toBe(rsHex);
  });

  ait("changes when sk or commitment changes", async () => {
    const cA = await noteCommitment({
      tokenMint: bytesFromHex32("aa".repeat(32)),
      amount: 1n,
      ownerCommitment: bigintFromHex32("bb".repeat(32)),
      nonce: bigintFromHex32("cc".repeat(32)),
      blindingR: bigintFromHex32("dd".repeat(32)),
    });
    const cB = await noteCommitment({
      tokenMint: bytesFromHex32("aa".repeat(32)),
      amount: 2n /* differs */,
      ownerCommitment: bigintFromHex32("bb".repeat(32)),
      nonce: bigintFromHex32("cc".repeat(32)),
      blindingR: bigintFromHex32("dd".repeat(32)),
    });

    const sk1 = 7n;
    const sk2 = 8n;

    const n_sk1_cA = hex32(await tsNullifier(sk1, cA));
    const n_sk2_cA = hex32(await tsNullifier(sk2, cA));
    const n_sk1_cB = hex32(await tsNullifier(sk1, cB));

    expect(n_sk1_cA).not.toBe(n_sk2_cA);
    expect(n_sk1_cA).not.toBe(n_sk1_cB);

    expect(n_sk1_cA).toBe(rustHelper(sk1, hex32(cA)));
    expect(n_sk2_cA).toBe(rustHelper(sk2, hex32(cA)));
    expect(n_sk1_cB).toBe(rustHelper(sk1, hex32(cB)));
  });

  ait("matches across a spread of spending-key sizes", async () => {
    const commitment = await noteCommitment({
      tokenMint: bytesFromHex32("11".repeat(32)),
      amount: 9_999_999n,
      ownerCommitment: bigintFromHex32("22".repeat(32)),
      nonce: bigintFromHex32("33".repeat(32)),
      blindingR: bigintFromHex32("44".repeat(32)),
    });
    const commitmentHex = hex32(commitment);

    // Includes very small, mid-range, and 251-bit values (all well within Fr).
    const keys: bigint[] = [
      1n,
      0xffffffffffffffffn,
      0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789n,
    ];
    for (const sk of keys) {
      const ts = hex32(await tsNullifier(sk, commitment));
      const rs = rustHelper(sk, commitmentHex);
      expect(ts).toBe(rs);
    }
  });
});
