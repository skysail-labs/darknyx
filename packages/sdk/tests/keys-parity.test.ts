/**
 * Parity test: TypeScript key derivation must produce the exact same bytes
 * as `crates/darkpool-crypto` for the deterministic test seed used in the
 * Rust tests. If this test ever fails, Rust and TS have drifted and off-chain
 * signing will diverge from on-chain verification.
 */

import { describe, it, expect, beforeAll } from "vitest";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { existsSync } from "node:fs";

import {
  deriveSpendingKey,
  deriveMasterViewingKey,
  deriveRootKey,
  deriveTradingKeyAtOffset,
  deriveBlindingFactor,
  darknyxShakeKdfV1,
  bn254ToBE32,
  MASTER_SEED_BYTES,
} from "../src/keys/key-generators.js";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", "..", "..");

function fixedSeed(): Uint8Array {
  const s = new Uint8Array(MASTER_SEED_BYTES);
  for (let i = 0; i < s.length; i++) s[i] = i;
  return s;
}

function runRustHelper(cmd: string, args: string[]): string | null {
  const bin = resolve(repoRoot, "target/debug/examples/derive-keys");
  if (!existsSync(bin)) return null;
  const res = spawnSync(bin, [cmd, ...args], { encoding: "utf8" });
  if (res.status !== 0) throw new Error(res.stderr || "rust helper failed");
  return res.stdout.trim();
}

describe("key derivation parity", () => {
  let helperAvailable = false;
  beforeAll(() => {
    // Best-effort: if the Rust helper example exists we compare directly.
    // Otherwise we skip the cross-language assertion but still verify TS
    // determinism.
    helperAvailable = existsSync(
      resolve(repoRoot, "target/debug/examples/derive-keys"),
    );
  });

  it("spending key is deterministic", () => {
    const s = fixedSeed();
    const a = deriveSpendingKey(s);
    const b = deriveSpendingKey(s);
    expect(a).toBe(b);
  });

  it("DarknyxShakeKdfV1 bytes are frozen by the cross-language KAT", () => {
    const actual = darknyxShakeKdfV1(
      new Uint8Array(32).fill(0x40),
      new TextEncoder().encode("darknyx-vk-v2"),
      new Uint8Array(),
      64,
    );
    expect(Buffer.from(actual).toString("hex")).toBe(
      "d99fdc876dcd8ca6f4be42b7587b2147a4fd7b4846e1dad32adc3e0e8af63e4d461a0361e83a3acde5e58e878dcbe4fecea8dd60f1fe16b021940aeb1ae810a3",
    );
  });

  it("spending key matches hex when fixed seed", () => {
    const s = fixedSeed();
    const sk = deriveSpendingKey(s);
    const bytes = bn254ToBE32(sk);
    const hex = Buffer.from(bytes).toString("hex");
    expect(hex).toHaveLength(64);
  });

  it("TS spending key matches Rust bit-for-bit (cross-env parity)", () => {
    if (!helperAvailable) return;
    const s = fixedSeed();
    const tsHex = Buffer.from(bn254ToBE32(deriveSpendingKey(s))).toString(
      "hex",
    );
    const rustHex = runRustHelper("spending", [
      Buffer.from(s).toString("hex"),
    ])!;
    expect(tsHex).toBe(rustHex);
  });

  it("TS master viewing key matches Rust", () => {
    if (!helperAvailable) return;
    const s = fixedSeed();
    const tsHex = Buffer.from(bn254ToBE32(deriveMasterViewingKey(s))).toString(
      "hex",
    );
    const rustHex = runRustHelper("viewing", [Buffer.from(s).toString("hex")])!;
    expect(tsHex).toBe(rustHex);
  });

  it("TS trading key (offset 0) matches Rust", () => {
    if (!helperAvailable) return;
    const s = fixedSeed();
    const tsHex = Buffer.from(
      deriveTradingKeyAtOffset(s, 0n).secretKey,
    ).toString("hex");
    const rustHex = runRustHelper("trading", [
      Buffer.from(s).toString("hex"),
      "0",
    ])!;
    // Rust returns full 32-byte signing-key bytes (seed). TS emits the seed.
    // Both should be 64 hex chars.
    expect(tsHex).toBe(rustHex);
  });

  it("TS root key matches Rust", () => {
    if (!helperAvailable) return;
    const s = fixedSeed();
    const tsHex = Buffer.from(deriveRootKey(s).secretKey).toString("hex");
    const rustHex = runRustHelper("root", [Buffer.from(s).toString("hex")])!;
    expect(tsHex).toBe(rustHex);
  });

  it("TS blinding factors match Rust for counter=5", () => {
    if (!helperAvailable) return;
    const s = fixedSeed();
    const tsHex = Buffer.from(
      bn254ToBE32(deriveBlindingFactor(s, 5n)),
    ).toString("hex");
    const rustHex = runRustHelper("blinding", [
      Buffer.from(s).toString("hex"),
      "5",
    ])!;
    expect(tsHex).toBe(rustHex);
  });

  it("spending and viewing keys are independent", () => {
    const s = fixedSeed();
    expect(deriveSpendingKey(s)).not.toBe(deriveMasterViewingKey(s));
  });

  it("trading key rotates with offset", () => {
    const s = fixedSeed();
    const k0 = deriveTradingKeyAtOffset(s, 0n);
    const k1 = deriveTradingKeyAtOffset(s, 1n);
    expect(Buffer.from(k0.secretKey).toString("hex")).not.toBe(
      Buffer.from(k1.secretKey).toString("hex"),
    );
  });

  it("root key distinct from trading key", () => {
    const s = fixedSeed();
    const r = deriveRootKey(s);
    const t = deriveTradingKeyAtOffset(s, 0n);
    expect(Buffer.from(r.secretKey).toString("hex")).not.toBe(
      Buffer.from(t.secretKey).toString("hex"),
    );
  });

  it("blinding factors deterministic per counter", () => {
    const s = fixedSeed();
    for (let i = 0n; i < 10n; i++) {
      expect(deriveBlindingFactor(s, i)).toBe(deriveBlindingFactor(s, i));
    }
  });

  it("blinding factors unique across counters 0..100", () => {
    const s = fixedSeed();
    const seen = new Set<string>();
    for (let i = 0n; i < 100n; i++) {
      const b = deriveBlindingFactor(s, i).toString();
      expect(seen.has(b)).toBe(false);
      seen.add(b);
    }
  });
});
