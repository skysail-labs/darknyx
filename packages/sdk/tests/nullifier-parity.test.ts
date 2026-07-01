/**
 * Cross-environment parity for the v2 (inner_hash) Nullifier formula.
 *
 * Formula (must match `circuits/valid_spend/circuit.circom` v2):
 *
 *   nullifierV2 = Poseidon3( DOMAIN_NULL=3, spending_key_fr, inner_hash_fr )
 *
 * Anchored on the amount-independent inner_hash (not the commitment), so it can be
 * precomputed before the note amount is known. The domain tag prevents
 * second-preimage collisions with owner_commitment (DOMAIN_OWNER=1) and
 * note_commitment (DOMAIN_NOTE=2). Any drift from the circuit fails here before it
 * can fail a real settlement. Sibling: `note-commitment-parity.test.ts`.
 */

import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { existsSync } from "node:fs";

import { nullifierV2 } from "../src/utxo/note.js";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", "..", "..");
const helper = resolve(repoRoot, "target/debug/examples/nullifier-v2");

function rustHelper(skDec: bigint, innerHashHex: string): string {
  if (!existsSync(helper)) throw new Error("nullifier-v2 helper missing");
  const res = spawnSync(helper, [skDec.toString(), innerHashHex], {
    encoding: "utf8",
  });
  if (res.status !== 0) throw new Error(res.stderr || "helper failed");
  return res.stdout.trim();
}

function hex32(bytes: Uint8Array): string {
  if (bytes.length !== 32) throw new Error("expected 32 bytes");
  return Buffer.from(bytes).toString("hex");
}

function bigintFromHex32(hex: string): bigint {
  if (hex.length !== 64) throw new Error("expected 64 hex chars");
  let n = 0n;
  for (let i = 0; i < hex.length; i += 2) {
    n = (n << 8n) | BigInt(parseInt(hex.slice(i, i + 2), 16));
  }
  return n;
}

// Fr-safe inner_hash values (high bytes small → strictly < BN254 r, so the strict
// Rust `fr_from_be_bytes` path accepts them identically to circomlibjs).
const IH_A = "0a".repeat(32);
const IH_B = "0b".repeat(32);

describe("Nullifier parity — v2 (TS vs Rust)", () => {
  const available = existsSync(helper);
  const ait = (name: string, fn: () => Promise<void>) =>
    available ? it(name, fn) : it.skip(name, fn);

  ait("matches on a small fixed (sk, inner_hash)", async () => {
    const sk = 42n;
    const tsHex = hex32(await nullifierV2(sk, bigintFromHex32(IH_A)));
    const rsHex = rustHelper(sk, IH_A);
    expect(tsHex).toBe(rsHex);
  });

  ait("changes when sk or inner_hash changes", async () => {
    const ihA = bigintFromHex32(IH_A);
    const ihB = bigintFromHex32(IH_B);
    const sk1 = 7n;
    const sk2 = 8n;

    const n_sk1_A = hex32(await nullifierV2(sk1, ihA));
    const n_sk2_A = hex32(await nullifierV2(sk2, ihA));
    const n_sk1_B = hex32(await nullifierV2(sk1, ihB));

    expect(n_sk1_A).not.toBe(n_sk2_A);
    expect(n_sk1_A).not.toBe(n_sk1_B);

    expect(n_sk1_A).toBe(rustHelper(sk1, IH_A));
    expect(n_sk2_A).toBe(rustHelper(sk2, IH_A));
    expect(n_sk1_B).toBe(rustHelper(sk1, IH_B));
  });

  ait("matches across a spread of spending-key sizes", async () => {
    const ihHex = "11".repeat(32);
    const ih = bigintFromHex32(ihHex);
    // Very small, mid-range, and a 256-bit value — both sides reduce the
    // spending key mod r consistently.
    const keys: bigint[] = [
      1n,
      0xffffffffffffffffn,
      0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789n,
    ];
    for (const sk of keys) {
      const ts = hex32(await nullifierV2(sk, ih));
      const rs = rustHelper(sk, ihHex);
      expect(ts).toBe(rs);
    }
  });
});
