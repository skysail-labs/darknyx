/**
 * Cross-environment parity for the v2 (inner_hash) note construction.
 *
 * Pins TS ⇄ Rust byte equality for the three v2 primitives that the anchor-pool
 * / partial-fill-continuation feature rests on:
 *
 *   1. inner_hash derivation
 *        inner_hash(order_id, j) = reduce_mod_r(
 *          KMAC256(seed, "nyx-inner-hash-v1" || order_id[16] || j_u32_le, 512))
 *      TS  `deriveInnerHash`  ⇄  Rust `derive_inner_hash`
 *
 *   2. v2 note commitment
 *        Poseidon6(DOMAIN_NOTE=2, mint_lo, mint_hi, amount, owner, inner_hash)
 *      TS  `noteCommitmentV2`  ⇄  Rust `commitment_from_fields_v2`
 *
 *   3. v2 nullifier
 *        Poseidon3(DOMAIN_NULL=3, spending_key, inner_hash)
 *      TS  `nullifierV2`  ⇄  Rust `nullifier_v2`
 *
 * If any of these diverge, change notes minted by the in-TEE matcher become
 * unspendable / unmatchable from the client side. (Sibling files:
 * `note-commitment-parity.test.ts`, `nullifier-parity.test.ts`.)
 */

import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { existsSync } from "node:fs";

import { noteCommitmentV2, nullifierV2 } from "../src/utxo/note.js";
import { deriveInnerHash } from "../src/keys/key-generators.js";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", "..", "..");
const noteV2Helper = resolve(
  repoRoot,
  "target/debug/examples/note-commitment-v2",
);
const nullV2Helper = resolve(repoRoot, "target/debug/examples/nullifier-v2");
const keysHelper = resolve(repoRoot, "target/debug/examples/derive-keys");

function run(bin: string, args: string[]): string {
  const res = spawnSync(bin, args, { encoding: "utf8" });
  if (res.status !== 0) throw new Error(res.stderr || `${bin} failed`);
  return res.stdout.trim();
}

function hex32(bytes: Uint8Array): string {
  if (bytes.length !== 32) throw new Error("expected 32 bytes");
  return Buffer.from(bytes).toString("hex");
}

function bytesFromHex(hex: string): Uint8Array {
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

// Same fixed 64-byte seed the Rust keys tests use (bytes 0x00..0x3f).
const SEED_HEX = Array.from({ length: 64 }, (_, i) =>
  i.toString(16).padStart(2, "0"),
).join("");
const SEED = bytesFromHex(SEED_HEX);

describe("inner_hash v2 parity (TS vs Rust)", () => {
  const available =
    existsSync(noteV2Helper) &&
    existsSync(nullV2Helper) &&
    existsSync(keysHelper);
  const ait = (name: string, fn: () => Promise<void>) =>
    available ? it(name, fn) : it.skip(name, fn);

  ait("derive_inner_hash matches across indices + order ids", async () => {
    const orderIds = ["11".repeat(16), "22".repeat(16), "00".repeat(15) + "ff"];
    for (const oidHex of orderIds) {
      const oid = bytesFromHex(oidHex);
      for (const index of [0, 1, 9, 10, 255, 0x0001_0000]) {
        const ts = deriveInnerHash(SEED, oid, index);
        const rs = run(keysHelper, [
          "inner-hash",
          SEED_HEX,
          oidHex,
          index.toString(),
        ]);
        expect(ts.toString(16).padStart(64, "0")).toBe(rs);
      }
    }
  });

  ait("v2 note commitment matches on fixed + perturbed inputs", async () => {
    const base = {
      mintHex: "01".repeat(32),
      amount: 1_000_000_000n,
      ownerHex: "0a".repeat(32),
      innerHex: "0c".repeat(32),
    };
    const compute = async (v: typeof base) => {
      const ts = hex32(
        await noteCommitmentV2({
          tokenMint: bytesFromHex(v.mintHex),
          amount: v.amount,
          ownerCommitment: bigintFromHex32(v.ownerHex),
          innerHash: bigintFromHex32(v.innerHex),
        }),
      );
      const rs = run(noteV2Helper, [
        v.mintHex,
        v.amount.toString(),
        v.ownerHex,
        v.innerHex,
      ]);
      return { ts, rs };
    };

    const { ts: baseTs, rs: baseRs } = await compute(base);
    expect(baseTs).toBe(baseRs);

    const variants: (typeof base)[] = [
      { ...base, mintHex: "12".repeat(32) },
      { ...base, amount: 1_000_000_001n },
      { ...base, ownerHex: "0d".repeat(32) },
      { ...base, innerHex: "0e".repeat(32) },
    ];
    for (const v of variants) {
      const { ts, rs } = await compute(v);
      expect(ts).toBe(rs);
      expect(ts).not.toBe(baseTs);
    }
  });

  ait(
    "v2 note commitment matches on amount edges (0, 1, u64::MAX)",
    async () => {
      const mintHex = "ff".repeat(16) + "00".repeat(16);
      const ownerHex = "0d".repeat(32);
      const innerHex = "0f".repeat(32);
      for (const amount of [0n, 1n, 18446744073709551615n]) {
        const ts = hex32(
          await noteCommitmentV2({
            tokenMint: bytesFromHex(mintHex),
            amount,
            ownerCommitment: bigintFromHex32(ownerHex),
            innerHash: bigintFromHex32(innerHex),
          }),
        );
        const rs = run(noteV2Helper, [
          mintHex,
          amount.toString(),
          ownerHex,
          innerHex,
        ]);
        expect(ts).toBe(rs);
      }
    },
  );

  ait("v2 nullifier matches + is sensitive to sk and inner_hash", async () => {
    const sk = 42n;
    const innerHex = "0c".repeat(32);
    const ts = hex32(await nullifierV2(sk, bigintFromHex32(innerHex)));
    const rs = run(nullV2Helper, [sk.toString(), innerHex]);
    expect(ts).toBe(rs);

    // Different sk → different nullifier (both sides agree).
    const ts2 = hex32(await nullifierV2(43n, bigintFromHex32(innerHex)));
    const rs2 = run(nullV2Helper, ["43", innerHex]);
    expect(ts2).toBe(rs2);
    expect(ts2).not.toBe(ts);

    // Different inner_hash → different nullifier.
    const innerHex2 = "0d".repeat(32);
    const ts3 = hex32(await nullifierV2(sk, bigintFromHex32(innerHex2)));
    const rs3 = run(nullV2Helper, [sk.toString(), innerHex2]);
    expect(ts3).toBe(rs3);
    expect(ts3).not.toBe(ts);
  });

  ait(
    "end-to-end: derived inner_hash flows through commitment + nullifier",
    async () => {
      // Exercise the realistic path: derive an inner_hash, then use it in both
      // the commitment and the nullifier — exactly how the anchor pool is built.
      const oid = bytesFromHex("ab".repeat(16));
      const innerBig = deriveInnerHash(SEED, oid, 3);
      const innerHex = innerBig.toString(16).padStart(64, "0");
      const mintHex = "01".repeat(32);
      const ownerHex = "0a".repeat(32);
      const sk = 7n;

      const commitTs = hex32(
        await noteCommitmentV2({
          tokenMint: bytesFromHex(mintHex),
          amount: 500n,
          ownerCommitment: bigintFromHex32(ownerHex),
          innerHash: innerBig,
        }),
      );
      const commitRs = run(noteV2Helper, [mintHex, "500", ownerHex, innerHex]);
      expect(commitTs).toBe(commitRs);

      const nullTs = hex32(await nullifierV2(sk, innerBig));
      const nullRs = run(nullV2Helper, [sk.toString(), innerHex]);
      expect(nullTs).toBe(nullRs);
    },
  );
});
