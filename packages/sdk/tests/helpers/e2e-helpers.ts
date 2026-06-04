/**
 * Phase-5 devnet E2E helpers — shared between setup + trade-flow tests.
 *
 * Deliberately NOT exported from the SDK proper — these live under
 * `tests/helpers/` so they stay dependency-light and explicit about their
 * shortcuts (deterministic TRADE_ROLE derivation, test-process TEE signer,
 * etc.).
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, resolve } from "node:path";
import { createHash } from "node:crypto";

import { Keypair } from "@solana/web3.js";

// ── Role tags for deterministic note derivation in the test relayer ─────────
// `CHANGE_ROLE_*` must match the on-chain constants in
// `programs/matching_engine/src/state/change_note.rs`.
export const CHANGE_ROLE_BUYER = 0xb1;
export const CHANGE_ROLE_SELLER = 0x5e;

// TRADE_ROLE_* is test-only: it derives the inner_hash for note_c / note_d
// (the full-fill output notes) so the user can rebuild the plaintext and later
// withdraw. The TEE does NOT emit these — they're deterministic from
// (match_id, role), so the user re-derives them itself. The `/ws/fills` channel
// (crates/nyx-tee/src/matcher/fills.rs) streams ONLY continuation change-note
// (note_e/f) memos. Defining the trade roles here mirrors change_note.rs's
// domain-tag pattern for the test harness.
export const TRADE_ROLE_BUYER = 0xc1; // note_c
export const TRADE_ROLE_SELLER = 0xd1; // note_d

// Fee roles mirror the FEE_ROLE_* constants inlined in run_batch.rs.
export const FEE_ROLE_BASE = 0xfb;
export const FEE_ROLE_QUOTE = 0xfc;

/**
 * Mirrors `change_note::derive_inner` (v2) in the matcher/on-chain program:
 * SHA-256("nyx-change-inner" ‖ match_id_le ‖ role), Fr-safe masked. This is
 * the single per-note inner_hash that replaced the old (nonce, blinding) pair.
 */
export function deriveInner(matchId: bigint, role: number): Uint8Array {
  const h = createHash("sha256");
  h.update(Buffer.from("nyx-change-inner"));
  const mid = new Uint8Array(8);
  new DataView(mid.buffer).setBigUint64(0, matchId, true);
  h.update(mid);
  h.update(new Uint8Array([role]));
  const d = new Uint8Array(h.digest());
  d[0] = 0;
  d[1] &= 0x0f;
  return d;
}

/** Big-endian 32-byte decimal string for snarkjs input.json. */
export function be32ToDec(x: Uint8Array): string {
  if (x.length !== 32) throw new Error("need 32 bytes");
  let hex = "0x";
  for (const b of x) hex += b.toString(16).padStart(2, "0");
  return BigInt(hex).toString();
}

export function be32ToBigInt(x: Uint8Array): bigint {
  let hex = "0x";
  for (const b of x) hex += b.toString(16).padStart(2, "0");
  return BigInt(hex);
}

export function bigIntToBe32(x: bigint): Uint8Array {
  let hex = x.toString(16);
  if (hex.length > 64) throw new Error("overflows 32B");
  hex = hex.padStart(64, "0");
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** u64 decimal string → 32-byte BE (for Merkle path encoding). */
export function u64ToBe32(x: bigint): Uint8Array {
  return bigIntToBe32(x);
}

/** Load a Solana keypair from a JSON array file. */
export function loadKeypairFile(absPath: string): Keypair {
  if (!existsSync(absPath)) throw new Error(`keypair missing: ${absPath}`);
  const raw = JSON.parse(readFileSync(absPath, "utf8")) as number[];
  return Keypair.fromSecretKey(new Uint8Array(raw));
}

export function loadKeypairRel(repoRoot: string, relPath: string): Keypair {
  return loadKeypairFile(resolve(repoRoot, relPath));
}

/** Load a keypair from an absolute path, expanding a leading `~` to `$HOME`. */
export function loadKeypairFileExpand(p: string): Keypair {
  if (p.startsWith("~/") || p === "~") p = p.replace(/^~/, homedir());
  return loadKeypairFile(p);
}

/** Save a Solana keypair as a JSON array (Solana-CLI-compatible). */
export function saveKeypairFile(absPath: string, kp: Keypair): void {
  mkdirSync(dirname(absPath), { recursive: true });
  writeFileSync(absPath, JSON.stringify(Array.from(kp.secretKey)));
}

/** Load a keypair from disk if it exists, else generate a fresh one + persist. */
export function loadOrCreateKeypair(absPath: string): Keypair {
  if (existsSync(absPath)) return loadKeypairFile(absPath);
  const kp = Keypair.generate();
  saveKeypairFile(absPath, kp);
  return kp;
}
