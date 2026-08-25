/**
 * Cross-environment parity for the v2 (inner_hash) Note Commitment formula.
 *
 * Formula (must match `circuits/valid_spend/circuit.circom` v2 + the on-chain
 * hasher):
 *
 *   noteCommitmentV2 = Poseidon6(
 *     DOMAIN_NOTE=2,        // domain separation tag
 *     token_mint_lo_u128,
 *     token_mint_hi_u128,
 *     amount_u64,
 *     owner_commitment_fr,  // = Poseidon2(DOMAIN_OWNER_V2=32, spending_key)
 *     inner_hash_fr,        // single per-note blinding (v2 — replaced nonce+blinding_r)
 *   )
 *
 * The TS `noteCommitmentV2()` must produce the same 32-byte hex as the Rust
 * `commitment_from_fields_v2()`. If they diverge, every shielded deposit ⇄
 * withdraw becomes unspendable from the other environment.
 *
 * This is the highest-leverage parity test we could add — note_commitment is
 * the foundation of every UTXO operation.
 */

import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { existsSync } from "node:fs";

import {
  noteCommitmentV2,
  ownerCommitment,
} from "../src/utxo/note.js";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", "..", "..");
const helper = resolve(repoRoot, "target/debug/examples/note-commitment-v2");

function rustHelper(
  mintHex: string,
  amount: bigint,
  ownerHex: string,
  innerHex: string,
): string {
  if (!existsSync(helper)) throw new Error("note-commitment-v2 helper missing");
  const res = spawnSync(
    helper,
    [mintHex, amount.toString(), ownerHex, innerHex],
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

describe("Note commitment parity — v2 (TS vs Rust)", () => {
  const available = existsSync(helper);
  const ait = (name: string, fn: () => Promise<void>) =>
    available ? it(name, fn) : it.skip(name, fn);

  ait("matches on fixed canonical inputs", async () => {
    // Hand-picked safe values: every 32-byte field is < BN254_r so both the
    // strict Rust path and circomlibjs accept them identically.
    const mintHex = "01".repeat(32);
    const amount = 1_000_000_000n;
    const ownerHex = "0a".repeat(32);
    const innerHex = "0b".repeat(32);

    const tsHex = hex32(
      await noteCommitmentV2({
        tokenMint: bytesFromHex32(mintHex),
        amount,
        ownerCommitment: bigintFromHex32(ownerHex),
        innerHash: bigintFromHex32(innerHex),
      }),
    );
    const rsHex = rustHelper(mintHex, amount, ownerHex, innerHex);
    expect(tsHex).toBe(rsHex);
  });

  ait("changes when each input changes (witness sensitivity)", async () => {
    // All field elements MUST be < BN254 r. Using high-bytes ≤ 0x10 keeps
    // everything safely in-field for the strict Rust path (see
    // field.rs::fr_from_be_bytes). circomlibjs silently mod-reduces, so picking
    // out-of-field values here would mask divergence rather than expose it.
    const base = {
      mintHex: "11".repeat(32),
      amount: 42n,
      ownerHex: "10".repeat(32),
      innerHex: "0f".repeat(32),
    };
    const baseTs = hex32(
      await noteCommitmentV2({
        tokenMint: bytesFromHex32(base.mintHex),
        amount: base.amount,
        ownerCommitment: bigintFromHex32(base.ownerHex),
        innerHash: bigintFromHex32(base.innerHex),
      }),
    );
    const baseRs = rustHelper(
      base.mintHex,
      base.amount,
      base.ownerHex,
      base.innerHex,
    );
    expect(baseTs).toBe(baseRs);

    // Mutate each field one at a time — both sides must agree it changed and agree on the new value.
    const variants = [
      { ...base, mintHex: "12".repeat(32) },
      { ...base, amount: 43n },
      { ...base, ownerHex: "0d".repeat(32) },
      { ...base, innerHex: "0e".repeat(32) },
    ];
    for (const v of variants) {
      const ts = hex32(
        await noteCommitmentV2({
          tokenMint: bytesFromHex32(v.mintHex),
          amount: v.amount,
          ownerCommitment: bigintFromHex32(v.ownerHex),
          innerHash: bigintFromHex32(v.innerHex),
        }),
      );
      const rs = rustHelper(v.mintHex, v.amount, v.ownerHex, v.innerHex);
      expect(ts).toBe(rs);
      expect(ts).not.toBe(baseTs);
    }
  });

  // Documents the deliberate strict-vs-lenient asymmetry between Rust
  // (`fr_from_be_bytes` rejects out-of-field) and TS (circomlibjs silently
  // mod-reduces). This test pins the current behaviour so any future change is
  // intentional.
  ait("BOTH languages reject an out-of-field input (SW-23)", async () => {
    // 0x33 * (256^32 - 1) / 255 ≈ 0.2 * 2^256, just above BN254 r.
    const outOfFieldHex = "33".repeat(32);
    const mintHex = "01".repeat(32);

    // This test used to be named "Rust strictly rejects out-of-field inputs;
    // TS silently reduces" and ASSERTED that divergence: circomlibjs'
    // `p.F.e()` reduced mod r and returned a hash, while Rust errored. So the
    // same input produced a value on one side and a failure on the other, in
    // exactly the primitive CLAUDE.md §7 pins byte-for-byte — and the test
    // documented it as expected rather than flagging it. TS now rejects too.
    await expect(
      noteCommitmentV2({
        tokenMint: bytesFromHex32(mintHex),
        amount: 1n,
        ownerCommitment: bigintFromHex32(outOfFieldHex),
        innerHash: 1n,
      }),
    ).rejects.toThrow(/outside \[0, BN254_r\)/);

    // Rust path rejects with NotInField.
    const res = spawnSync(
      helper,
      [mintHex, "1", outOfFieldHex, "01".repeat(32)],
      { encoding: "utf8" },
    );
    expect(res.status).not.toBe(0);
    expect(res.stderr).toContain("NotInField");
  });

  // The REDUCING helpers have their own boundary, and it is not the same one.
  //
  // `ownerCommitment` deliberately reduces its spending-key input mod r,
  // because Rust reduces there too (`Fr::from_be_bytes_mod_order`). Rust
  // reduces BYTES, which cannot be
  // negative, so a negative bigint has no Rust counterpart at all. Wrapping it
  // (`((v % r) + r) % r`) invented one: `-1n` became a perfectly valid-looking
  // `r - 1` commitment that the Rust side could never derive.
  it("rejects a negative spending key rather than wrapping it into the field", async () => {
    await expect(ownerCommitment(-1n)).rejects.toThrow(/negative/);
  });

  it("still reduces a legitimately oversized (256-bit) spending key", async () => {
    // The guard must not become "reject everything out of range" — that would
    // break the real derivation path, where a 256-bit key is reduced on BOTH
    // sides. Rejecting here would be a divergence, not a fix.
    const oversized = (1n << 255n) + 7n;
    await expect(ownerCommitment(oversized)).resolves.toEqual(
      expect.any(BigInt),
    );
  });

  ait("matches on amount = 0 and large u64", async () => {
    const mintHex = "ff".repeat(16) + "00".repeat(16); // mixed high/low halves
    const ownerHex = "0d".repeat(32);
    const innerHex = "0e".repeat(32);

    for (const amount of [0n, 1n, 18446744073709551615n /* u64::MAX */]) {
      const ts = hex32(
        await noteCommitmentV2({
          tokenMint: bytesFromHex32(mintHex),
          amount,
          ownerCommitment: bigintFromHex32(ownerHex),
          innerHash: bigintFromHex32(innerHex),
        }),
      );
      const rs = rustHelper(mintHex, amount, ownerHex, innerHex);
      expect(ts).toBe(rs);
    }
  });
});
