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

import { Connection, Keypair, PublicKey } from "@solana/web3.js";

import { anchorDiscriminator } from "../../src/idl/vault-client.js";

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
  for (let i = 0; i < 32; i++)
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
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

// ── Step-level time profiling for the e2e flows ─────────────────────────────
// A tiny labelled stopwatch: wrap each phase with `await t.step("label", fn)`
// (or drop a `t.mark("label")` boundary), then `t.report(title)` prints a
// per-step + cumulative table to stdout. Lets you pinpoint where wall-time
// goes — almost always the snarkjs proofs and the devnet confirm round-trips,
// not the local crypto. Pure measurement: no behavioural effect on the test.
export interface StepTiming {
  label: string;
  ms: number;
  cumulativeMs: number;
}

export class StepTimer {
  private readonly t0 = performance.now();
  private last = this.t0;
  private readonly rows: StepTiming[] = [];

  /** Time `fn` as one labelled step. Returns whatever `fn` returns. */
  async step<T>(label: string, fn: () => Promise<T>): Promise<T> {
    const start = performance.now();
    try {
      return await fn();
    } finally {
      this.push(label, performance.now() - start);
    }
  }

  /** Record a boundary: elapsed since the previous mark/step. */
  mark(label: string): void {
    const now = performance.now();
    this.push(label, now - this.last);
  }

  private push(label: string, ms: number): void {
    this.last = performance.now();
    this.rows.push({ label, ms, cumulativeMs: this.last - this.t0 });
  }

  timings(): StepTiming[] {
    return this.rows.slice();
  }

  totalMs(): number {
    return performance.now() - this.t0;
  }

  /** Print a right-aligned per-step + cumulative table; returns the rows. */
  report(title: string): StepTiming[] {
    const w = Math.max(20, ...this.rows.map((r) => r.label.length));
    const fmt = (n: number) => `${n.toFixed(0)}`.padStart(8);
    const lines = [
      ``,
      `  ⏱  ${title}`,
      `  ${"─".repeat(w + 22)}`,
      `  ${"step".padEnd(w)} ${"step ms".padStart(8)} ${"cum ms".padStart(8)}`,
      `  ${"─".repeat(w + 22)}`,
      ...this.rows.map(
        (r) => `  ${r.label.padEnd(w)} ${fmt(r.ms)} ${fmt(r.cumulativeMs)}`,
      ),
      `  ${"─".repeat(w + 22)}`,
      `  ${"TOTAL".padEnd(w)} ${fmt(this.totalMs())}`,
      ``,
    ];
    console.log(lines.join("\n"));
    return this.timings();
  }
}

// ── On-chain settle-pipeline breakdown (no CVM rebuild needed) ──────────────
// The CVM signs all 5 settle txs (lock_note ×2 → verify_match_batch →
// tee_forced_settle_batched → close_batch_validity_marker) with its dstack key,
// which is ALSO the fee-payer. So we can read the per-stage landing times
// straight off the chain by walking the signer's recent signatures and
// classifying each tx by the vault instruction's Anchor discriminator. This
// is finer + more reliable than `phala cvms logs` (which has no per-stage
// timestamped line), and needs zero changes to the in-enclave binary.

const VAULT_PROGRAM_ID = "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx";
const ADDRESS_LOOKUP_TABLE_PROGRAM =
  "AddressLookupTab1e1111111111111111111111111";

// disc(name)[..8] hex → human stage label, for the vault settle ixs.
const SETTLE_DISC: Record<string, string> = (() => {
  const m: Record<string, string> = {};
  for (const name of [
    "lock_note",
    "verify_match_batch",
    "tee_forced_settle_batched",
    "close_batch_validity_marker",
  ]) {
    m[Buffer.from(anchorDiscriminator(name)).toString("hex")] = name;
  }
  return m;
})();

export interface SettleTxRow {
  stage: string;
  signature: string;
  slot: number;
  blockTimeMs: number | null;
}

/**
 * Walk the CVM signer's signatures newer than `sinceSig` (the last tx the
 * client sent before submitting orders, so we only see the CVM's settle txs),
 * classify each, and return them oldest→newest. Best-effort: an unclassifiable
 * tx is labelled by its program; never throws (profiling must not fail a test).
 */
export async function fetchSettleTimeline(
  conn: Connection,
  teeSigner: PublicKey,
  opts: { limit?: number; vaultProgramId?: string } = {},
): Promise<SettleTxRow[]> {
  const vault = opts.vaultProgramId ?? VAULT_PROGRAM_ID;
  let sigs;
  try {
    sigs = await conn.getSignaturesForAddress(teeSigner, {
      limit: opts.limit ?? 30,
    });
  } catch {
    return [];
  }
  const rows: SettleTxRow[] = [];
  for (const s of sigs) {
    let tx;
    try {
      tx = await conn.getTransaction(s.signature, {
        maxSupportedTransactionVersion: 0,
        commitment: "confirmed",
      });
    } catch {
      continue;
    }
    if (!tx) continue;
    const msg = tx.transaction.message;
    const keys = msg.getAccountKeys({
      accountKeysFromLookups: tx.meta?.loadedAddresses ?? undefined,
    });
    let stage = "unknown";
    for (const ix of msg.compiledInstructions) {
      const programId = keys.get(ix.programIdIndex);
      if (!programId) continue;
      if (programId.toBase58() === ADDRESS_LOOKUP_TABLE_PROGRAM) {
        stage = "alt create/extend";
        break;
      }
      if (programId.toBase58() === vault) {
        const disc = Buffer.from(ix.data.slice(0, 8)).toString("hex");
        stage = SETTLE_DISC[disc] ?? `vault:${disc.slice(0, 8)}`;
        break;
      }
    }
    rows.push({
      stage,
      signature: s.signature,
      slot: s.slot,
      blockTimeMs: s.blockTime != null ? s.blockTime * 1000 : null,
    });
  }
  return rows.reverse(); // oldest → newest
}

/** Pretty-print the settle timeline with slot + blockTime deltas. */
export function reportSettleTimeline(title: string, rows: SettleTxRow[]): void {
  if (rows.length === 0) {
    console.log(`\n  ⏱  ${title}: (no settle txs found on the signer)\n`);
    return;
  }
  const w = Math.max(24, ...rows.map((r) => r.stage.length));
  const t0Slot = rows[0].slot;
  const t0Ms = rows[0].blockTimeMs ?? 0;
  const lines = [
    ``,
    `  ⏱  ${title}`,
    `  ${"─".repeat(w + 34)}`,
    `  ${"settle stage".padEnd(w)} ${"slot".padStart(10)} ${"Δslot".padStart(7)} ${"Δ blockTime".padStart(12)}`,
    `  ${"─".repeat(w + 34)}`,
    ...rows.map((r) => {
      const dSlot = r.slot - t0Slot;
      const dMs =
        r.blockTimeMs != null
          ? `${((r.blockTimeMs - t0Ms) / 1000).toFixed(0)}s`
          : "—";
      return `  ${r.stage.padEnd(w)} ${`${r.slot}`.padStart(10)} ${`+${dSlot}`.padStart(7)} ${dMs.padStart(12)}`;
    }),
    `  ${"─".repeat(w + 34)}`,
    `  note: ~400ms/slot; blockTime is 1s-granular. ${rows.length} settle txs.`,
    ``,
  ];
  console.log(lines.join("\n"));
}
