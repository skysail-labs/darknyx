/**
 * Phase-5 Nyx Darkpool — change-note + partial-fill E2E tests on devnet.
 *
 * Two scenarios that exercise the change-note + re-lock paths that the
 * happy-path `er-trade-flow.test.ts` doesn't:
 *
 *  Test A — over-collateralised exact fill
 *    Alice deposits a 5000 QUOTE note but BUYs only 30 BASE @ 100
 *    (= 3000 QUOTE notional + 9 fee = 3009 used). Bob deposits 30 BASE
 *    and SELLs all of it. After settlement Alice receives:
 *      - note_c (BASE 30, the trade leg)
 *      - note_e (QUOTE 1991, the change leg)
 *    Both notes are appended to the Merkle tree and Alice withdraws
 *    BOTH via VALID_SPEND — proving change notes are spendable.
 *
 *  Test B — partial fill with re-lock
 *    Alice BUYs 100 BASE @ 100 with deposit 10030 QUOTE. Bob SELLs only
 *    30 BASE with deposit 30 BASE. Only 30 BASE matches. After
 *    settlement:
 *      - note_c (BASE 30 → Alice trade leg)
 *      - note_d (QUOTE 3000 → Bob trade leg)
 *      - note_e (QUOTE 7021 → Alice's change), atomically re-locked
 *        against Alice's order so it continues trading next batch.
 *      - note_fee (QUOTE 9 → protocol)
 *    Alice's PendingOrder slot is rotated: status stays Pending,
 *    amount=70, collateral_note=note_e. Bob's note_d is freely
 *    withdrawable.
 *
 * Each step is wall-clock timed and a summary table prints at the end
 * so we can gauge the live ER + L1 latency profile.
 *
 * Gated on RUN_CN_E2E=1 (CN = Change-Note). Requires the same env vars
 * as `er-trade-flow.test.ts` plus a completed `devnet-setup.test.ts`
 * run (fresh market + reset tree).
 */

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { createHash } from "node:crypto";

import { config as dotenvConfig } from "dotenv";
import { beforeAll, describe, expect, it } from "vitest";
import nacl from "tweetnacl";
import {
  createAssociatedTokenAccountIdempotentInstruction,
  createMintToInstruction,
  getAssociatedTokenAddress,
  TOKEN_PROGRAM_ID,
} from "@solana/spl-token";
import {
  ComputeBudgetProgram,
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";

import {
  bn254ToBE32,
  deriveBlindingFactor,
  deriveMasterViewingKey,
  deriveSpendingKey,
} from "../src/keys/key-generators.js";
import { userCommitmentFromKeys } from "../src/keys/user-commitment.js";
import {
  noteCommitment,
  nullifier,
  ownerCommitment,
  pubkeyToFrPair,
} from "../src/utxo/note.js";
import {
  buildCreateWalletInstruction,
  buildDepositInstruction,
  buildLockNoteInstruction,
  buildSetProtocolConfigInstruction,
  buildResetMerkleTreeInstruction,
  buildWithdrawInstruction,
  noteLockPda,
  vaultConfigPda,
  walletEntryPda,
} from "../src/idl/vault-client.js";
import {
  buildRunBatchInstruction,
  buildSubmitOrderInstruction,
  buildInitPendingOrderSlotInstruction,
  buildDelegatePendingOrderInstruction,
  batchResultsPda,
  darkClobPda,
  pendingOrderPda,
  OrderType,
} from "../src/idl/matching-engine-client.js";
import {
  buildDelegateBatchResultsInstruction,
  buildDelegateDarkClobInstruction,
  buildDelegateMatchingConfigInstruction,
  buildUndelegateMarketInstruction,
  openDualConnections,
  waitForL1AccountChange,
} from "../src/idl/er-client.js";
import {
  buildEd25519VerifyIx,
  buildSettleIx,
  canonicalPayloadHash,
  exactFillPayload,
  type MatchResultPayload,
} from "../src/settlement/settle-builder.js";
import {
  decodeBatchResults,
  RELOCK_ORDER_ID_NONE,
} from "../src/batch/inclusion-proof.js";

import { snarkjsFullProve } from "./helpers/snarkjs-prover.js";
import { MerkleShadow } from "./helpers/merkle-shadow.js";
import { proveValidInput } from "./helpers/valid-input-prover.js";
import { proveValidCreate } from "./helpers/valid-create-prover.js";
import { sendSettleV0 } from "./helpers/settle-v0.js";
import { landVerifyValidPrice } from "./helpers/verify-valid-price.js";
import { settleViaBatched } from "./helpers/batched-settle.js";
import { type MatchSlotWitness } from "./helpers/match-batch-prover.js";

/** v3.5 — set `USE_BATCHED_PROOF=1` in the env to route settles
 *  through `verify_match_batch` + `tee_forced_settle_batched`. Both
 *  paths produce identical state transitions; downstream assertions
 *  (tree appends, withdraws, balances) don't care which one ran. */
const USE_BATCHED_PROOF = process.env.USE_BATCHED_PROOF === "1";
import { validCreateBindingHash } from "../src/settlement/settle-builder.js";
import { buildVerifyValidCreateInstruction } from "../src/idl/vault-client.js";
import {
  be32ToBigInt,
  be32ToDec,
  CHANGE_ROLE_BUYER,
  CHANGE_ROLE_SELLER,
  deriveBlinding,
  deriveNonce,
  FEE_ROLE_QUOTE,
  TRADE_ROLE_BUYER,
  TRADE_ROLE_SELLER,
  loadKeypairFileExpand,
  loadKeypairRel,
  loadOrCreateKeypair,
} from "./helpers/e2e-helpers.js";

import type { E2EConfig } from "./devnet-setup.test.js";

// ───────────────────────────────────────────────────────────────────────────
// Environment + gating
// ───────────────────────────────────────────────────────────────────────────

dotenvConfig({ path: resolve(__dirname, "../.env.devnet") });

const RUN = process.env.RUN_CN_E2E === "1";

const REPO_ROOT = resolve(__dirname, "../../..");
const CONFIG_PATH = resolve(REPO_ROOT, ".devnet/e2e-config.json");
const ER_RPC_URL = process.env.ER_RPC_URL ?? "https://devnet.magicblock.app";

const CREATE_WASM = resolve(
  REPO_ROOT,
  "circuits/build/valid_wallet_create/circuit_js/circuit.wasm",
);
const CREATE_ZKEY = resolve(
  REPO_ROOT,
  "circuits/build/valid_wallet_create/circuit_final.zkey",
);
const SPEND_WASM = resolve(
  REPO_ROOT,
  "circuits/build/valid_spend/circuit_js/circuit.wasm",
);
const SPEND_ZKEY = resolve(
  REPO_ROOT,
  "circuits/build/valid_spend/circuit_final.zkey",
);
const SNARKJS_BIN = resolve(REPO_ROOT, "node_modules/.bin/snarkjs");

const READY =
  RUN &&
  existsSync(CONFIG_PATH) &&
  existsSync(CREATE_WASM) &&
  existsSync(CREATE_ZKEY) &&
  existsSync(SPEND_WASM) &&
  existsSync(SPEND_ZKEY) &&
  existsSync(SNARKJS_BIN);

const maybeDescribe = READY ? describe : describe.skip;

// ───────────────────────────────────────────────────────────────────────────
// Narrative logging + step timing instrumentation
// ───────────────────────────────────────────────────────────────────────────

const BAR = "═".repeat(78);
const HBAR = "─".repeat(78);
const DHBAR = "·".repeat(78);

function banner(title: string) {
  console.log("\n" + BAR);
  console.log("  " + title);
  console.log(BAR);
}
function step(num: string | number, title: string) {
  console.log("\n" + HBAR);
  console.log(`  [STEP ${num}] ${title}`);
  console.log(HBAR);
}
function substep(text: string) {
  console.log("\n" + DHBAR);
  console.log(`  · ${text}`);
  console.log(DHBAR);
}
function txline(note: string, signature: string, cluster: "l1" | "er" = "l1") {
  console.log(`  >> [${cluster.toUpperCase()}] ${note}`);
  console.log(`     TX: ${signature}`);
  if (cluster === "l1") {
    console.log(`     EXPLORER: https://explorer.solana.com/tx/${signature}?cluster=devnet`);
  } else {
    console.log(`     (ER tx — no public explorer; inspect via ER RPC or validator logs)`);
  }
}
function bullet(t: string) { console.log(`     • ${t}`); }
function noteLine(t: string) { console.log(`     NOTE: ${t}`); }
function leaf(label: string, bytes: Uint8Array) {
  console.log(`     LEAF [${label}] = 0x${toHex(bytes).slice(0, 16)}…${toHex(bytes).slice(-8)}`);
}
function toHex(x: Uint8Array): string {
  return Array.from(x).map((b) => b.toString(16).padStart(2, "0")).join("");
}

interface TimingRecord {
  label: string;
  cluster: "L1" | "ER" | "ER+L1" | "local";
  ms: number;
}

class StepTimer {
  private rows: TimingRecord[] = [];
  private orderAcceptedAtMs: number | null = null;
  private firstWithdrawAtMs: number | null = null;

  async time<T>(
    label: string,
    cluster: TimingRecord["cluster"],
    fn: () => Promise<T>,
  ): Promise<T> {
    const t0 = Date.now();
    const out = await fn();
    const ms = Date.now() - t0;
    this.rows.push({ label, cluster, ms });
    console.log(`     ⌛ ${label}: ${(ms / 1000).toFixed(2)} s [${cluster}]`);
    return out;
  }

  /** Mark the moment ER `submit_order` finished — used for the
   *  "order placed → user can withdraw" derived metric. */
  markOrderAccepted() {
    this.orderAcceptedAtMs = Date.now();
  }

  /** Mark the moment the FIRST withdraw confirmed. */
  markFirstWithdraw() {
    if (this.firstWithdrawAtMs === null) {
      this.firstWithdrawAtMs = Date.now();
    }
  }

  printSummary(title: string) {
    const total = this.rows.reduce((s, r) => s + r.ms, 0);
    banner(`TIMING SUMMARY — ${title}`);
    const lpad = (s: string, w: number) => s + " ".repeat(Math.max(0, w - s.length));
    const rpad = (s: string, w: number) => " ".repeat(Math.max(0, w - s.length)) + s;
    console.log(
      `   ${lpad("step", 56)}${rpad("duration", 12)}    cluster`,
    );
    console.log(`   ${"─".repeat(74)}`);
    let i = 1;
    for (const r of this.rows) {
      const idx = `${i}.`.padEnd(4);
      const sec = `${(r.ms / 1000).toFixed(2)} s`;
      console.log(
        `   ${lpad(`${idx}${r.label}`, 56)}${rpad(sec, 12)}     ${r.cluster}`,
      );
      i++;
    }
    console.log(`   ${"─".repeat(74)}`);
    console.log(
      `   ${lpad("TOTAL (cold start → user can withdraw)", 56)}${rpad(`${(total / 1000).toFixed(2)} s`, 12)}`,
    );
    if (this.orderAcceptedAtMs !== null && this.firstWithdrawAtMs !== null) {
      const window = this.firstWithdrawAtMs - this.orderAcceptedAtMs;
      console.log(
        `   ${lpad("submit_order accepted → withdraw confirmed", 56)}${rpad(`${(window / 1000).toFixed(2)} s`, 12)}`,
      );
    }
    console.log(BAR);
  }
}

// ───────────────────────────────────────────────────────────────────────────
// PendingOrder zero-copy decoder (read live ER state to verify re-lock)
// ───────────────────────────────────────────────────────────────────────────

interface PendingOrderView {
  tradingKey: Uint8Array;
  market: Uint8Array;
  status: number;
  side: number;
  orderType: number;
  slotIdx: number;
  bump: number;
  arrivalSlot: bigint;
  expirySlot: bigint;
  priceLimit: bigint;
  amount: bigint;
  totalQuantity: bigint;
  filledQuantity: bigint;
  minFillQty: bigint;
  noteAmount: bigint;
  collateralNote: Uint8Array;
  userCommitment: Uint8Array;
  orderId: Uint8Array;
  orderInclusionCommitment: Uint8Array;
}

const PENDING_STATUS_EMPTY = 0;
const PENDING_STATUS_PENDING = 1;
const PENDING_STATUS_MATCHED = 2;

function decodePendingOrder(data: Uint8Array): PendingOrderView {
  // 8-byte anchor zero-copy discriminator + struct.
  if (data.length < 264) {
    throw new Error(`PendingOrder data too short: ${data.length}`);
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let off = 8;
  const tradingKey = data.slice(off, off + 32); off += 32;
  const market = data.slice(off, off + 32); off += 32;
  const status = data[off++];
  const side = data[off++];
  const orderType = data[off++];
  const slotIdx = data[off++];
  const bump = data[off++];
  off += 3; // _padding_a
  const arrivalSlot = dv.getBigUint64(off, true); off += 8;
  const expirySlot = dv.getBigUint64(off, true); off += 8;
  const priceLimit = dv.getBigUint64(off, true); off += 8;
  const amount = dv.getBigUint64(off, true); off += 8;
  const totalQuantity = dv.getBigUint64(off, true); off += 8;
  const filledQuantity = dv.getBigUint64(off, true); off += 8;
  const minFillQty = dv.getBigUint64(off, true); off += 8;
  const noteAmount = dv.getBigUint64(off, true); off += 8;
  const collateralNote = data.slice(off, off + 32); off += 32;
  const userCommitment = data.slice(off, off + 32); off += 32;
  const orderId = data.slice(off, off + 16); off += 16;
  off += 8; // _padding_b
  const orderInclusionCommitment = data.slice(off, off + 32);
  return {
    tradingKey, market, status, side, orderType, slotIdx, bump,
    arrivalSlot, expirySlot, priceLimit, amount,
    totalQuantity, filledQuantity, minFillQty, noteAmount,
    collateralNote, userCommitment, orderId, orderInclusionCommitment,
  };
}

// ───────────────────────────────────────────────────────────────────────────
// NoteLock decoder (verify re-lock pinned the change note)
// ───────────────────────────────────────────────────────────────────────────

interface NoteLockView {
  noteCommitment: Uint8Array;
  tokenMint: Uint8Array;
  orderId: Uint8Array;
  expirySlot: bigint;
  lockedBy: Uint8Array;
  amount: bigint;
  bump: number;
}

// v2 layout: noteCommitment(32) + tokenMint(32) + orderId(16) + expirySlot(8)
// + lockedBy(32) + amount(8) + bump(1) + padding(7) = 136 bytes (+8 disc).
function decodeNoteLock(data: Uint8Array): NoteLockView {
  if (data.length < 8 + 32 + 32 + 16 + 8 + 32 + 8 + 1) {
    throw new Error(`NoteLock data too short: ${data.length}`);
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let off = 8;
  const noteCommitment = data.slice(off, off + 32); off += 32;
  const tokenMint = data.slice(off, off + 32); off += 32;
  const orderId = data.slice(off, off + 16); off += 16;
  const expirySlot = dv.getBigUint64(off, true); off += 8;
  const lockedBy = data.slice(off, off + 32); off += 32;
  const amount = dv.getBigUint64(off, true); off += 8;
  const bump = data[off];
  return { noteCommitment, tokenMint, orderId, expirySlot, lockedBy, amount, bump };
}

// ───────────────────────────────────────────────────────────────────────────
// Persona
// ───────────────────────────────────────────────────────────────────────────

interface Persona {
  name: string;
  payer: Keypair;
  tradingKey: Keypair;
  masterSeed: Uint8Array;
  spendingKey: bigint;
  viewingKey: bigint;
  ownerBlinding: bigint;
  ownerCommit: bigint;
  r0: bigint; r1: bigint; r2: bigint;
  userCommitment: Uint8Array;
  depositNote?: {
    mint: PublicKey;
    amount: bigint;
    nonce: bigint;
    blindingR: bigint;
    commitment: Uint8Array;
    leafIndex: number;
  };
  tradeNote?: {
    mint: PublicKey;
    amount: bigint;
    nonce: Uint8Array;
    blindingR: Uint8Array;
    commitment: Uint8Array;
    leafIndex: number;
  };
  changeNote?: {
    mint: PublicKey;
    amount: bigint;
    nonce: Uint8Array;
    blindingR: Uint8Array;
    commitment: Uint8Array;
    leafIndex: number;
  };
}

async function makePersona(
  name: string,
  seed0: number,
  runSeed: Uint8Array,
): Promise<Persona> {
  // The CN test FRESHLY GENERATES a trading keypair on every run so the
  // PendingOrder PDA is always virgin (avoids a stuck slot polluting
  // the next run with stale `note_amount` / `status` carry-over). The
  // `payer` is persisted across runs to conserve devnet SOL.
  //
  // `runSeed` (32 bytes, generated once per `it()`) is mixed into the
  // master seed and the WalletEntry's `userCommitment` so:
  //   • spending/viewing keys differ per run → fresh nullifiers
  //   • note nonce/blinding differ per run → fresh note commitments
  //   • WalletEntry PDA differs per run → idempotent create_wallet
  //   • NoteLock PDAs (seeded by note commitment) never collide
  const payerPath = resolve(REPO_ROOT, `.devnet/keypairs/${name}-cn-payer.json`);
  const payer = loadOrCreateKeypair(payerPath);
  const tradingKey = Keypair.generate();
  const masterSeed = new Uint8Array(64);
  for (let i = 0; i < 64; i++) {
    masterSeed[i] = ((seed0 + i * 11) & 0xff) ^ runSeed[i % runSeed.length];
  }
  const spendingKey = deriveSpendingKey(masterSeed);
  const viewingKey = deriveMasterViewingKey(masterSeed);
  const ownerBlinding = BigInt(seed0) + 0xCAFECAFEn;
  const ownerCommit = await ownerCommitment(spendingKey, ownerBlinding);
  const r0 = BigInt(seed0) + 1n;
  const r1 = BigInt(seed0) + 2n;
  const r2 = BigInt(seed0) + 3n;
  const uc = await userCommitmentFromKeys({
    rootKeyPubkey: payer.publicKey.toBytes(),
    spendingKey, viewingKey,
    r0, r1, r2,
  });
  return {
    name, payer, tradingKey, masterSeed,
    spendingKey, viewingKey, ownerBlinding, ownerCommit,
    r0, r1, r2, userCommitment: uc,
  };
}

function freshRunSeed(): Uint8Array {
  const out = new Uint8Array(32);
  const ms = BigInt(Date.now());
  new DataView(out.buffer).setBigUint64(0, ms, true);
  for (let i = 8; i < 32; i++) out[i] = Math.floor(Math.random() * 256);
  return out;
}

// ───────────────────────────────────────────────────────────────────────────
// TEE simulator
// ───────────────────────────────────────────────────────────────────────────

function teeSign(kp: Keypair, msg: Uint8Array): Uint8Array {
  if (msg.length !== 32) throw new Error("canonical hash must be 32 bytes");
  return nacl.sign.detached(msg, kp.secretKey);
}

// ───────────────────────────────────────────────────────────────────────────
// Shared fixture state — bootstrap each describe-block once
// ───────────────────────────────────────────────────────────────────────────

interface Fixture {
  l1: Connection;
  er: Connection;
  cfg: E2EConfig;
  admin: Keypair;
  funder: Keypair;
  teeKeypair: Keypair;
  vaultProgramId: PublicKey;
  meProgramId: PublicKey;
  market: PublicKey;
  baseMint: PublicKey;
  quoteMint: PublicKey;
  pythAccount: PublicKey;
  protocolOwnerCommitment: Uint8Array;
  protocolFeeBps: number;
  tree: MerkleShadow;
  /** v3 settle Address Lookup Table from devnet-setup. Undefined for legacy configs. */
  settleLookupTable?: PublicKey;
}

function requireEnv(k: string): string {
  const v = process.env[k];
  if (!v) throw new Error(`missing env: ${k}`);
  return v;
}

function asU8a16(x: bigint): Uint8Array {
  const out = new Uint8Array(16);
  new DataView(out.buffer).setBigUint64(8, x, true);
  return out;
}

async function bootstrap(): Promise<Fixture> {
  const cfg = JSON.parse(readFileSync(CONFIG_PATH, "utf8")) as E2EConfig;
  const conns = openDualConnections(cfg.l1RpcUrl, ER_RPC_URL, "confirmed");
  const admin = loadKeypairRel(REPO_ROOT, requireEnv("ADMIN_KEYPAIR"));
  const teeKeypair = loadKeypairRel(REPO_ROOT, requireEnv("TEE_AUTHORITY_KEYPAIR"));

  const funderPath = process.env.FUNDER_KEYPAIR;
  const funder = funderPath
    ? (funderPath.startsWith("/") || funderPath.startsWith("~")
        ? loadKeypairFileExpand(funderPath)
        : loadKeypairRel(REPO_ROOT, funderPath))
    : admin;

  const tree = await MerkleShadow.create();

  return {
    l1: conns.l1,
    er: conns.er,
    cfg,
    admin,
    funder,
    teeKeypair,
    vaultProgramId: new PublicKey(cfg.vaultProgramId),
    meProgramId: new PublicKey(cfg.matchingEngineProgramId),
    market: new PublicKey(cfg.market.pubkey),
    baseMint: new PublicKey(cfg.baseMint.pubkey),
    quoteMint: new PublicKey(cfg.quoteMint.pubkey),
    pythAccount: new PublicKey(cfg.pythAccount),
    protocolOwnerCommitment: new Uint8Array(
      Buffer.from(cfg.protocol.ownerCommitmentHex, "hex"),
    ),
    protocolFeeBps: cfg.protocol.feeRateBps,
    tree,
    settleLookupTable: cfg.settleLookupTable
      ? new PublicKey(cfg.settleLookupTable)
      : undefined,
  };
}

// ───────────────────────────────────────────────────────────────────────────
// Common steps shared between Test A and Test B
// ───────────────────────────────────────────────────────────────────────────

async function fundAndMint(
  fx: Fixture,
  alice: Persona,
  bob: Persona,
  aliceQuoteAmt: bigint,
  bobBaseAmt: bigint,
  timer: StepTimer,
) {
  const PAYER_LAMPORTS = 2_000_000_000, PAYER_MIN = 500_000_000;
  const TK_LAMPORTS = 100_000_000, TK_MIN = 20_000_000;
  type FT = { label: string; to: PublicKey; target: number; min: number };
  const targets: FT[] = [
    { label: `${alice.name} payer`,   to: alice.payer.publicKey,      target: PAYER_LAMPORTS, min: PAYER_MIN },
    { label: `${bob.name} payer`,     to: bob.payer.publicKey,        target: PAYER_LAMPORTS, min: PAYER_MIN },
    { label: `${alice.name} trading`, to: alice.tradingKey.publicKey, target: TK_LAMPORTS,    min: TK_MIN    },
    { label: `${bob.name} trading`,   to: bob.tradingKey.publicKey,   target: TK_LAMPORTS,    min: TK_MIN    },
  ];
  const ixs = [];
  let total = 0;
  for (const t of targets) {
    const b = await fx.l1.getBalance(t.to);
    if (b < t.min) {
      const delta = t.target - b;
      bullet(`${t.label.padEnd(16)} ${(b / 1e9).toFixed(4)} SOL — top up ${(delta / 1e9).toFixed(4)}`);
      ixs.push(SystemProgram.transfer({
        fromPubkey: fx.funder.publicKey, toPubkey: t.to, lamports: delta,
      }));
      total += delta;
    } else {
      bullet(`${t.label.padEnd(16)} ${(b / 1e9).toFixed(4)} SOL — skip`);
    }
  }
  if (ixs.length > 0) {
    await timer.time("fund SOL top-ups", "L1", async () => {
      const fs = await sendAndConfirmTransaction(
        fx.l1, new Transaction().add(...ixs), [fx.funder], { commitment: "confirmed" },
      );
      txline(`funder transferred ${(total / 1e9).toFixed(4)} SOL`, fs);
    });
  } else {
    bullet("no SOL top-up needed (skipping tx)");
  }

  const aliceQuoteAta = await getAssociatedTokenAddress(fx.quoteMint, alice.payer.publicKey);
  const bobBaseAta    = await getAssociatedTokenAddress(fx.baseMint,  bob.payer.publicKey);
  const aliceBaseAta  = await getAssociatedTokenAddress(fx.baseMint,  alice.payer.publicKey);
  const bobQuoteAta   = await getAssociatedTokenAddress(fx.quoteMint, bob.payer.publicKey);

  await timer.time("create ATAs + mint deposit balances", "L1", async () => {
    const ataTx = new Transaction().add(
      createAssociatedTokenAccountIdempotentInstruction(fx.admin.publicKey, aliceQuoteAta, alice.payer.publicKey, fx.quoteMint),
      createAssociatedTokenAccountIdempotentInstruction(fx.admin.publicKey, aliceBaseAta,  alice.payer.publicKey, fx.baseMint),
      createAssociatedTokenAccountIdempotentInstruction(fx.admin.publicKey, bobBaseAta,    bob.payer.publicKey,   fx.baseMint),
      createAssociatedTokenAccountIdempotentInstruction(fx.admin.publicKey, bobQuoteAta,   bob.payer.publicKey,   fx.quoteMint),
      createMintToInstruction(fx.quoteMint, aliceQuoteAta, fx.admin.publicKey, Number(aliceQuoteAmt)),
      createMintToInstruction(fx.baseMint,  bobBaseAta,    fx.admin.publicKey, Number(bobBaseAmt)),
    );
    const ataSig = await sendAndConfirmTransaction(fx.l1, ataTx, [fx.admin], { commitment: "confirmed" });
    txline("created ATAs + minted balances", ataSig);
  });

  return { aliceQuoteAta, bobBaseAta, aliceBaseAta, bobQuoteAta };
}

async function ensureWallets(fx: Fixture, alice: Persona, bob: Persona, timer: StepTimer) {
  await timer.time("create_wallet (idempotent for both)", "L1", async () => {
    for (const p of [alice, bob]) {
      const [wpda] = walletEntryPda(fx.vaultProgramId, p.userCommitment);
      const ex = await fx.l1.getAccountInfo(wpda);
      if (ex) {
        bullet(`${p.name}: WalletEntry exists — skip`);
        continue;
      }
      substep(`${p.name}: VALID_WALLET_CREATE via snarkjs`);
      const [ucLo, ucHi] = pubkeyToFrPair(p.payer.publicKey.toBytes());
      const { proof } = snarkjsFullProve(
        {
          userCommitment: be32ToDec(p.userCommitment),
          rootKey: [ucLo.toString(), ucHi.toString()],
          spendingKey: p.spendingKey.toString(),
          viewingKey: p.viewingKey.toString(),
          r0: p.r0.toString(), r1: p.r1.toString(), r2: p.r2.toString(),
        },
        { circuitWasmPath: CREATE_WASM, circuitZkeyPath: CREATE_ZKEY, repoRoot: REPO_ROOT },
      );
      const cwTx = new Transaction().add(
        buildCreateWalletInstruction({
          programId: fx.vaultProgramId, owner: p.payer.publicKey,
          commitment: p.userCommitment, proof,
        }),
      );
      const cwSig = await sendAndConfirmTransaction(fx.l1, cwTx, [p.payer], { commitment: "confirmed" });
      txline(`${p.name}: create_wallet`, cwSig);
    }
  });
}

async function depositNote(
  fx: Fixture,
  p: Persona,
  mint: PublicKey,
  amount: bigint,
  ata: PublicKey,
) {
  substep(`${p.name}: depositing ${amount}`);
  const [vPda] = vaultConfigPda(fx.vaultProgramId);
  const info = await fx.l1.getAccountInfo(vPda);
  if (!info) throw new Error("vault_config missing");
  const leafIndex = Number(
    new DataView(info.data.buffer, info.data.byteOffset + 104, 8).getBigUint64(0, true),
  );
  const nonce = deriveBlindingFactor(p.masterSeed, BigInt(leafIndex));
  const blindingR = deriveBlindingFactor(p.masterSeed, BigInt(leafIndex) + 1n);
  const c = await noteCommitment({
    tokenMint: mint.toBytes(), amount,
    ownerCommitment: p.ownerCommit, nonce, blindingR,
  });
  leaf(`note (${p.name} deposit)`, c);
  const ix = buildDepositInstruction({
    programId: fx.vaultProgramId, depositor: p.payer.publicKey,
    tokenMint: mint, depositorTokenAccount: ata, tokenProgramId: TOKEN_PROGRAM_ID,
    amount,
    ownerCommitment: bn254ToBE32(p.ownerCommit),
    nonce: bn254ToBE32(nonce),
    blindingR: bn254ToBE32(blindingR),
  });
  const sig = await sendAndConfirmTransaction(
    fx.l1, new Transaction().add(ix), [p.payer], { commitment: "confirmed" },
  );
  txline(`${p.name}: deposit`, sig);
  await fx.tree.append(c);
  p.depositNote = { mint, amount, nonce, blindingR, commitment: c, leafIndex };
}

async function ensureSlot(
  fx: Fixture,
  persona: Persona,
  slotIdx: number,
) {
  const [slotPda] = pendingOrderPda(
    fx.meProgramId, fx.market, persona.tradingKey.publicKey, slotIdx,
  );
  const existingSlot = await fx.l1.getAccountInfo(slotPda, "confirmed");
  if (existingSlot && existingSlot.owner.toBase58() !== fx.meProgramId.toBase58()) {
    bullet(`${persona.name} slot[${slotIdx}] already delegated — skip init+delegate`);
    return slotPda;
  }
  if (!existingSlot) {
    const initTx = new Transaction().add(
      buildInitPendingOrderSlotInstruction({
        programId: fx.meProgramId,
        tradingKey: persona.tradingKey.publicKey,
        market: fx.market,
        slotIdx,
      }),
    );
    const initSig = await sendAndConfirmTransaction(
      fx.l1, initTx, [persona.tradingKey], { commitment: "confirmed" },
    );
    txline(`${persona.name}: init_pending_order_slot[${slotIdx}]`, initSig);
  } else {
    bullet(`${persona.name} slot[${slotIdx}] init exists — skip init, doing delegate`);
  }
  const delSlotTx = new Transaction().add(
    buildDelegatePendingOrderInstruction({
      programId: fx.meProgramId,
      payer: fx.funder.publicKey,
      tradingKey: persona.tradingKey.publicKey,
      market: fx.market,
      slotIdx,
    }),
  );
  const delSlotSig = await sendAndConfirmTransaction(
    fx.l1, delSlotTx, [fx.funder, persona.tradingKey], { commitment: "confirmed" },
  );
  txline(`${persona.name}: delegate_pending_order[${slotIdx}]`, delSlotSig);
  return slotPda;
}

async function resetTreeFresh(fx: Fixture) {
  // Wipe leaf_count + right_path + roots ring buffer so the in-memory
  // shadow tree starts in lock-step with on-chain. Admin-signed.
  // This DOES NOT affect existing nullifier / WalletEntry / NoteLock PDAs.
  const tx = new Transaction().add(
    buildResetMerkleTreeInstruction({
      programId: fx.vaultProgramId,
      admin: fx.admin.publicKey,
    }),
  );
  const sig = await sendAndConfirmTransaction(
    fx.l1, tx, [fx.admin], { commitment: "confirmed" },
  );
  txline("reset_merkle_tree (per-test fresh)", sig);
  // Replace the shadow with a fresh empty tree.
  fx.tree = await MerkleShadow.create();
}

async function ensureMarketDelegated(fx: Fixture) {
  // Idempotent: if already delegated this is a no-op tx, but the delegate
  // ix itself errors on re-delegate; check ownership first.
  const [clob] = darkClobPda(fx.meProgramId, fx.market);
  const acct = await fx.l1.getAccountInfo(clob, "confirmed");
  if (acct && acct.owner.toBase58() !== fx.meProgramId.toBase58()) {
    bullet("market PDAs already delegated — skip");
    return;
  }
  const delTx = new Transaction().add(
    ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
    buildDelegateDarkClobInstruction({
      programId: fx.meProgramId, payer: fx.funder.publicKey, market: fx.market,
    }),
    buildDelegateMatchingConfigInstruction({
      programId: fx.meProgramId, payer: fx.funder.publicKey, market: fx.market,
    }),
    buildDelegateBatchResultsInstruction({
      programId: fx.meProgramId, payer: fx.funder.publicKey, market: fx.market,
    }),
  );
  const delSig = await sendAndConfirmTransaction(
    fx.l1, delTx, [fx.funder], { commitment: "confirmed" },
  );
  txline("delegated DarkCLOB + MatchingConfig + BatchResults", delSig);
}

// ───────────────────────────────────────────────────────────────────────────

maybeDescribe(
  "Phase 5 — change-note + partial-fill E2E (devnet, ER)",
  () => {
    let fx: Fixture;

    beforeAll(async () => {
      fx = await bootstrap();
      banner("NYX DARKPOOL — change-note / partial-fill E2E");
      bullet(`L1 RPC: ${fx.cfg.l1RpcUrl}`);
      bullet(`ER RPC: ${ER_RPC_URL}`);
      bullet(`market: ${fx.market.toBase58()}`);
      bullet(`TEE:    ${fx.teeKeypair.publicKey.toBase58()}`);
      bullet(`funder: ${fx.funder.publicKey.toBase58()}`);
      const funderBal = await fx.l1.getBalance(fx.funder.publicKey);
      bullet(`funder balance: ${(funderBal / 1e9).toFixed(4)} SOL`);
      if (funderBal < 0.5 * 1e9) {
        throw new Error(
          `funder has < 0.5 SOL (CN flow runs two scenarios + lots of delegate PDAs); ` +
          `top up first or set FUNDER_KEYPAIR=<path-to-keypair-with-sol>`,
        );
      }
    }, 60_000);

    // ─────────────────────────────────────────────────────────────────────
    // TEST A — over-collateralised exact fill
    // ─────────────────────────────────────────────────────────────────────
    it(
      "A: over-collateralised exact fill — Alice gets note_c (BASE) + note_e (QUOTE change)",
      { timeout: 900_000 },
      async () => {
        const timer = new StepTimer();
        banner("TEST A — over-collateralised exact fill (5000 QUOTE → buy 30 BASE @ 100)");

        // Alice deposits 5000 QUOTE; spends 30*100 + fee = 3009; gets 1991 back.
        // Bob deposits 30 BASE; spends 30; gets 0 back (exact).
        const PRICE = 100n;
        const MATCH_BASE = 30n;
        const MATCH_QUOTE = MATCH_BASE * PRICE; // 3000
        const FEE_BPS = BigInt(fx.protocolFeeBps);
        const BUYER_FEE = (MATCH_QUOTE * FEE_BPS) / 10_000n; // 9
        const SELLER_FEE = (MATCH_BASE * FEE_BPS) / 10_000n; // 0
        const ALICE_DEPOSIT = 5000n;
        const BOB_DEPOSIT = 30n;
        const ALICE_CHANGE = ALICE_DEPOSIT - MATCH_QUOTE - BUYER_FEE; // 1991
        const BOB_CHANGE = BOB_DEPOSIT - MATCH_BASE - SELLER_FEE;     // 0

        bullet(`Alice deposits ${ALICE_DEPOSIT} QUOTE; matches ${MATCH_QUOTE} + fee ${BUYER_FEE}; CHANGE ${ALICE_CHANGE} QUOTE`);
        bullet(`Bob   deposits ${BOB_DEPOSIT} BASE;  matches ${MATCH_BASE} + fee ${SELLER_FEE};  CHANGE ${BOB_CHANGE} BASE (exact)`);
        expect(ALICE_CHANGE).toBeGreaterThan(0n);
        expect(BOB_CHANGE).toBe(0n);

        // ── Step 0: per-test tree wipe — keeps shadow + on-chain in lock-step.
        step(0, "reset_merkle_tree (per-test fresh tree)");
        await timer.time("reset_merkle_tree", "L1", () => resetTreeFresh(fx));

        // ── Step 1: personas (fresh per-run seed so nullifiers + NoteLock PDAs are unique)
        const runSeed = freshRunSeed();
        const alice = await timer.time("derive Alice persona", "local", () => makePersona("alice", 0xC1, runSeed));
        const bob = await timer.time("derive Bob persona", "local", () => makePersona("bob", 0xC2, runSeed));
        for (const p of [alice, bob]) {
          bullet(`${p.name.padEnd(6)} payer:        ${p.payer.publicKey.toBase58()}`);
        }

        // ── Step 2: fund + mint
        step(2, "fund SOL + mint deposit balances (L1)");
        const atas = await fundAndMint(fx, alice, bob, ALICE_DEPOSIT, BOB_DEPOSIT, timer);

        // ── Step 3: create_wallet
        step(3, "create_wallet (idempotent)");
        await ensureWallets(fx, alice, bob, timer);

        // ── Step 4: deposit
        step(4, "deposit notes (L1)");
        await timer.time("deposit ×2", "L1", async () => {
          await depositNote(fx, alice, fx.quoteMint, ALICE_DEPOSIT, atas.aliceQuoteAta);
          await depositNote(fx, bob,   fx.baseMint,  BOB_DEPOSIT,   atas.bobBaseAta);
        });

        // ── Step 5: init + delegate PendingOrder slots (slot 0 each)
        step(5, "init + delegate PendingOrder slots (privacy-fix L1 setup)");
        const ALICE_SLOT = 0, BOB_SLOT = 0;
        await timer.time("init + delegate slot ×2", "L1", async () => {
          await ensureSlot(fx, alice, ALICE_SLOT);
          await ensureSlot(fx, bob, BOB_SLOT);
        });

        // ── Step 6: delegate market PDAs
        step(6, "delegate DarkCLOB + MatchingConfig + BatchResults");
        await timer.time("delegate market PDAs", "L1", async () => {
          await ensureMarketDelegated(fx);
        });

        // ── Step 7: submit_order x2 (ER)
        step(7, "submit_order ×2 — order intent stays inside the rollup");
        // Order ids must be unique-per-run since they're used as PDA seeds
        // for `NoteLock` on L1. Derive them from the trading-key pubkey
        // (which is fresh every run thanks to `Keypair.generate()`).
        const aliceOrderId = alice.tradingKey.publicKey.toBytes().slice(0, 16);
        aliceOrderId[0] |= 0x80; // ensure non-zero high bit
        const bobOrderId = bob.tradingKey.publicKey.toBytes().slice(0, 16);
        bobOrderId[0] |= 0x80;
        const now = await fx.l1.getSlot("confirmed");
        const expiry = BigInt(now) + 500n;
        await timer.time("submit_order Alice (BUY)", "ER", async () => {
          const { ix } = buildSubmitOrderInstruction({
            programId: fx.meProgramId,
            tradingKey: alice.tradingKey.publicKey,
            market: fx.market,
            slotIdx: ALICE_SLOT,
            // PendingOrder.user_commitment is documented as
            // Poseidon(spending_key, r_owner) — i.e. the OWNER commitment
            // (the one VALID_SPEND can prove), NOT the wallet/user
            // commitment from `userCommitmentFromKeys`. Passing the wrong
            // value here makes the change note (note_e) unspendable
            // because its leaf in the Merkle tree would be hashed against
            // a value the spend circuit can't reconstruct.
            userCommitment: bn254ToBE32(alice.ownerCommit),
            noteCommitment: alice.depositNote!.commitment,
            amount: MATCH_BASE,                // wants 30 BASE
            priceLimit: PRICE,
            side: 0,                            // BID
            noteAmount: alice.depositNote!.amount, // 5000 QUOTE
            expirySlot: expiry,
            orderId: aliceOrderId,
            orderType: OrderType.Limit,
          });
          const tx = new Transaction().add(
            ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 }),
            ix,
          );
          const sig = await sendAndConfirmTransaction(
            fx.er, tx, [alice.tradingKey], { commitment: "confirmed" },
          );
          txline(`alice: submit_order BUY ${MATCH_BASE} @ ${PRICE}`, sig, "er");
        });
        await timer.time("submit_order Bob (SELL)", "ER", async () => {
          const { ix } = buildSubmitOrderInstruction({
            programId: fx.meProgramId,
            tradingKey: bob.tradingKey.publicKey,
            market: fx.market,
            slotIdx: BOB_SLOT,
            userCommitment: bn254ToBE32(bob.ownerCommit),
            noteCommitment: bob.depositNote!.commitment,
            amount: MATCH_BASE,
            priceLimit: PRICE,
            side: 1,
            noteAmount: bob.depositNote!.amount,
            expirySlot: expiry,
            orderId: bobOrderId,
            orderType: OrderType.Limit,
          });
          const tx = new Transaction().add(
            ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 }),
            ix,
          );
          const sig = await sendAndConfirmTransaction(
            fx.er, tx, [bob.tradingKey], { commitment: "confirmed" },
          );
          txline(`bob:   submit_order SELL ${MATCH_BASE} @ ${PRICE}`, sig, "er");
        });
        timer.markOrderAccepted();

        // ── Step 8: run_batch
        step(8, "run_batch (ER) — produces note_e (Alice change) commitment");
        const [aliceSlotPda] = pendingOrderPda(
          fx.meProgramId, fx.market, alice.tradingKey.publicKey, ALICE_SLOT,
        );
        const [bobSlotPda] = pendingOrderPda(
          fx.meProgramId, fx.market, bob.tradingKey.publicKey, BOB_SLOT,
        );
        const [batchPda] = batchResultsPda(fx.meProgramId, fx.market);

        const preAcct = await fx.l1.getAccountInfo(batchPda, "confirmed");
        const preHash = preAcct ? Buffer.from(preAcct.data).toString("hex") : null;

        await timer.time("run_batch", "ER", async () => {
          const rbTx = new Transaction().add(
            ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
            buildRunBatchInstruction({
              programId: fx.meProgramId,
              vaultProgramId: fx.vaultProgramId,
              teeAuthority: fx.teeKeypair.publicKey,
              market: fx.market,
              pythAccount: fx.pythAccount,
              pendingOrderPdas: [aliceSlotPda, bobSlotPda],
            }),
          );
          const rbSig = await sendAndConfirmTransaction(
            fx.er, rbTx, [fx.teeKeypair], { commitment: "confirmed" },
          );
          txline("run_batch", rbSig, "er");
        });

        // ── Step 9: undelegate_market + L1 commit poll
        step(9, "undelegate_market (commits BatchResults to L1)");
        await timer.time("undelegate + L1 poll for commit", "ER+L1", async () => {
          const undTx = new Transaction().add(
            ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
            buildUndelegateMarketInstruction({
              programId: fx.meProgramId, payer: fx.funder.publicKey, market: fx.market,
            }),
          );
          const undSig = await sendAndConfirmTransaction(
            fx.er, undTx, [fx.funder], { commitment: "confirmed" },
          );
          txline("undelegate_market", undSig, "er");
          const postData = await waitForL1AccountChange(fx.l1, batchPda, preHash, {
            timeoutMs: 90_000, intervalMs: 1_000,
          });
          bullet(`L1 BatchResults post-commit size: ${postData.length} bytes`);
        });

        // ── Step 10: decode BatchResults + cross-check on-chain match
        step(10, "decode BatchResults — verify change-note fields");
        const batchPostAcct = await fx.l1.getAccountInfo(batchPda, "confirmed");
        if (!batchPostAcct) throw new Error("BatchResults missing");
        const view = decodeBatchResults(new Uint8Array(batchPostAcct.data));
        // BatchResults is a ring buffer keyed by `next_match_id` — older
        // matches from prior runs may still occupy lower indices. Pick the
        // record that names THIS run's trading keys (post-run-seed they're
        // unique per `it()` run, so collisions are impossible).
        const filled = view.results.find(
          (r) =>
            r.status === 1 &&
            Buffer.from(r.ownerBuyer).equals(alice.tradingKey.publicKey.toBuffer()) &&
            Buffer.from(r.ownerSeller).equals(bob.tradingKey.publicKey.toBuffer()),
        );
        if (!filled) throw new Error("no filled MatchResult for THIS run's Alice/Bob in BatchResults");
        bullet(`match_id           = ${filled.matchId}`);
        bullet(`base_amt           = ${filled.baseAmt} (expected ${MATCH_BASE})`);
        bullet(`quote_amt          = ${filled.quoteAmt} (expected ${MATCH_QUOTE})`);
        bullet(`buyer_change_amt   = ${filled.buyerChangeAmt} (expected ${ALICE_CHANGE})`);
        bullet(`seller_change_amt  = ${filled.sellerChangeAmt} (expected ${BOB_CHANGE})`);
        bullet(`buyer_fee_amt      = ${filled.buyerFeeAmt} (expected ${BUYER_FEE})`);
        bullet(`buyer_relock_oid   = ${Buffer.from(filled.buyerRelockOrderId).toString("hex")} (expected zeros — exact fill)`);
        expect(filled.baseAmt).toBe(MATCH_BASE);
        expect(filled.quoteAmt).toBe(MATCH_QUOTE);
        expect(filled.buyerChangeAmt).toBe(ALICE_CHANGE);
        expect(filled.sellerChangeAmt).toBe(BOB_CHANGE);
        expect(filled.buyerFeeAmt).toBe(BUYER_FEE);
        expect(filled.sellerFeeAmt).toBe(SELLER_FEE);
        expect(Buffer.from(filled.buyerRelockOrderId).equals(Buffer.from(RELOCK_ORDER_ID_NONE))).toBe(true);
        expect(Buffer.from(filled.sellerRelockOrderId).equals(Buffer.from(RELOCK_ORDER_ID_NONE))).toBe(true);

        // ── Step 11: TEE recomputes note_c, note_d, note_e, fee + signs payload
        step(11, "TEE recomputes notes + signs canonical payload");
        const matchId = filled.matchId;
        const matchIdBytes = asU8a16(matchId);

        const noteCnonce = deriveNonce(matchId, TRADE_ROLE_BUYER);
        const noteCblind = deriveBlinding(matchId, TRADE_ROLE_BUYER);
        const noteCcommitment = await noteCommitment({
          tokenMint: fx.baseMint.toBytes(), amount: MATCH_BASE,
          ownerCommitment: alice.ownerCommit,
          nonce: be32ToBigInt(noteCnonce), blindingR: be32ToBigInt(noteCblind),
        });
        leaf("note_c (Alice receives BASE)", noteCcommitment);

        const noteDnonce = deriveNonce(matchId, TRADE_ROLE_SELLER);
        const noteDblind = deriveBlinding(matchId, TRADE_ROLE_SELLER);
        const noteDcommitment = await noteCommitment({
          tokenMint: fx.quoteMint.toBytes(), amount: MATCH_QUOTE,
          ownerCommitment: bob.ownerCommit,
          nonce: be32ToBigInt(noteDnonce), blindingR: be32ToBigInt(noteDblind),
        });
        leaf("note_d (Bob receives QUOTE)", noteDcommitment);

        // Change note (note_e) — same Poseidon derivation as run_batch.rs.
        // `run_batch` hashes against `bids[bi].user_commitment`, which the
        // submit_order docstring defines as Poseidon(spendingKey, r_owner)
        // = `ownerCommit`. Match that exactly here so:
        //   1. The locally-recomputed leaf == on-chain `note_e_commitment`.
        //   2. The leaf VALID_SPEND reconstructs from `(spendingKey,
        //      ownerBlinding)` later also matches → withdraw succeeds.
        const noteEnonce = deriveNonce(matchId, CHANGE_ROLE_BUYER);
        const noteEblind = deriveBlinding(matchId, CHANGE_ROLE_BUYER);
        const noteEcommitment = await noteCommitment({
          tokenMint: fx.quoteMint.toBytes(), amount: ALICE_CHANGE,
          ownerCommitment: alice.ownerCommit,
          nonce: be32ToBigInt(noteEnonce), blindingR: be32ToBigInt(noteEblind),
        });
        leaf("note_e (Alice's QUOTE change)", noteEcommitment);

        // Cross-check against the on-chain note_e from BatchResults.
        bullet(`on-chain note_e:   0x${toHex(filled.noteEcommitment).slice(0, 32)}…`);
        bullet(`recomputed note_e: 0x${toHex(noteEcommitment).slice(0, 32)}…`);
        expect(Buffer.from(filled.noteEcommitment).equals(Buffer.from(noteEcommitment))).toBe(true);

        const slot = await fx.l1.getSlot("confirmed");
        const feeNonce = deriveNonce(BigInt(slot), FEE_ROLE_QUOTE);
        const feeBlind = deriveBlinding(BigInt(slot), FEE_ROLE_QUOTE);
        const feeCommitment = BUYER_FEE > 0n ? await noteCommitment({
          tokenMint: fx.quoteMint.toBytes(), amount: BUYER_FEE,
          ownerCommitment: be32ToBigInt(fx.protocolOwnerCommitment),
          nonce: be32ToBigInt(feeNonce), blindingR: be32ToBigInt(feeBlind),
        }) : new Uint8Array(32);
        if (BUYER_FEE > 0n) leaf("note_fee (protocol QUOTE)", feeCommitment);

        const nullA = await nullifier(alice.spendingKey, alice.depositNote!.commitment);
        const nullB = await nullifier(bob.spendingKey, bob.depositNote!.commitment);

        const payload: MatchResultPayload = exactFillPayload({
          matchId: matchIdBytes,
          noteAcommitment: alice.depositNote!.commitment,
          noteBcommitment: bob.depositNote!.commitment,
          noteCcommitment, noteDcommitment,
          nullifierA: nullA, nullifierB: nullB,
          orderIdA: aliceOrderId, orderIdB: bobOrderId,
          baseAmount: MATCH_BASE, quoteAmount: MATCH_QUOTE,
        });
        payload.buyerChangeAmt = ALICE_CHANGE;
        payload.noteEcommitment = noteEcommitment;
        payload.buyerFeeAmt = BUYER_FEE;
        payload.sellerFeeAmt = SELLER_FEE;
        payload.noteFeeCommitment = feeCommitment;

        const msg = canonicalPayloadHash(payload);
        const teeSig = teeSign(fx.teeKeypair, msg);
        bullet(`canonical hash: 0x${toHex(msg).slice(0, 16)}…`);

        // ── Step 12: lock_note ×2 on L1 + Ed25519 + tee_forced_settle
        step(12, "lock_note ×2 (L1) then Ed25519 + tee_forced_settle (L1)");

        // v2: per-side VALID_INPUT proofs gating lock_note.
        const aliceWitness1 = await fx.tree.witness(alice.depositNote!.leafIndex);
        const aliceVI1 = await proveValidInput({
          repoRoot: REPO_ROOT,
          spendingKey: alice.spendingKey,
          ownerCommitmentBlinding: alice.ownerBlinding,
          nonce: alice.depositNote!.nonce,
          blindingR: alice.depositNote!.blindingR,
          tokenMint: alice.depositNote!.mint.toBytes(),
          amount: alice.depositNote!.amount,
          merkleRootBE: aliceWitness1.root,
          merkleWitness: {
            pathElements: aliceWitness1.siblings.map(be32ToBigInt),
            pathIndices: aliceWitness1.indices,
          },
        });
        const bobWitness1 = await fx.tree.witness(bob.depositNote!.leafIndex);
        const bobVI1 = await proveValidInput({
          repoRoot: REPO_ROOT,
          spendingKey: bob.spendingKey,
          ownerCommitmentBlinding: bob.ownerBlinding,
          nonce: bob.depositNote!.nonce,
          blindingR: bob.depositNote!.blindingR,
          tokenMint: bob.depositNote!.mint.toBytes(),
          amount: bob.depositNote!.amount,
          merkleRootBE: bobWitness1.root,
          merkleWitness: {
            pathElements: bobWitness1.siblings.map(be32ToBigInt),
            pathIndices: bobWitness1.indices,
          },
        });

        await timer.time("lock_note ×2", "L1", async () => {
          const lockTx = new Transaction().add(
            ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }),
            buildLockNoteInstruction({
              programId: fx.vaultProgramId,
              teeAuthority: fx.teeKeypair.publicKey,
              noteCommitment: alice.depositNote!.commitment,
              orderId: aliceOrderId,
              expirySlot: expiry,
              amount: ALICE_DEPOSIT,
              tokenMint: alice.depositNote!.mint,
              merkleRoot: aliceWitness1.root,
              proof: aliceVI1.proof,
            }),
            buildLockNoteInstruction({
              programId: fx.vaultProgramId,
              teeAuthority: fx.teeKeypair.publicKey,
              noteCommitment: bob.depositNote!.commitment,
              orderId: bobOrderId,
              expirySlot: expiry,
              amount: BOB_DEPOSIT,
              tokenMint: bob.depositNote!.mint,
              merkleRoot: bobWitness1.root,
              proof: bobVI1.proof,
            }),
          );
          const lockSig = await sendAndConfirmTransaction(
            fx.l1, lockTx, [fx.teeKeypair], { commitment: "confirmed" },
          );
          txline("lock_note(note_a) + lock_note(note_b)", lockSig);
        });

        if (USE_BATCHED_PROOF) {
          // ── v3.5 batched path — single Groth16 attests VALID_CREATE +
          // VALID_PRICE for the whole batch (here padded to N=16 with
          // dummy slots), then a single tee_forced_settle_batched per
          // real match. Exercises the with-change-note edge case.
          if (!fx.settleLookupTable) {
            throw new Error("e2e-config.json missing settleLookupTable — rerun devnet-setup");
          }
          await timer.time("v3.5 batched settle (with change note)", "L1", async () => {
            const ZERO_32 = new Uint8Array(32);
            const realSlot: MatchSlotWitness = {
              noteAcommitment: alice.depositNote!.commitment,
              noteBcommitment: bob.depositNote!.commitment,
              noteCcommitment,
              noteDcommitment,
              noteEcommitment,
              noteFcommitment: ZERO_32,
              quoteMint: fx.quoteMint.toBytes(),
              baseMint: fx.baseMint.toBytes(),
              baseAmount: MATCH_BASE,
              quoteAmount: MATCH_QUOTE,
              buyerChangeAmt: ALICE_CHANGE,
              sellerChangeAmt: 0n,
              buyerFeeAmt: BUYER_FEE,
              sellerFeeAmt: SELLER_FEE,
              batchSlot: payload.batchSlot,
              aOwnerCommit: alice.ownerCommit,
              bOwnerCommit: bob.ownerCommit,
              aAmount: alice.depositNote!.amount,
              bAmount: bob.depositNote!.amount,
              aNonce: alice.depositNote!.nonce,
              aBlinding: alice.depositNote!.blindingR,
              bNonce: bob.depositNote!.nonce,
              bBlinding: bob.depositNote!.blindingR,
              cNonce: be32ToBigInt(noteCnonce),
              cBlinding: be32ToBigInt(noteCblind),
              dNonce: be32ToBigInt(noteDnonce),
              dBlinding: be32ToBigInt(noteDblind),
              eNonce: be32ToBigInt(noteEnonce),
              eBlinding: be32ToBigInt(noteEblind),
              fNonce: 0n,
              fBlinding: 0n,
              clearingPrice: MATCH_QUOTE / MATCH_BASE,
            };
            await settleViaBatched({
              connection: fx.l1,
              vaultProgramId: fx.vaultProgramId,
              teeKeypair: fx.teeKeypair,
              realSlot,
              payload,
              teeSig,
              canonicalHash: msg,
              settleLookupTable: fx.settleLookupTable!,
              repoRoot: REPO_ROOT,
              onTx: txline,
            });
          });
        } else {
        // v3: VALID_CREATE proof — buyer-change present, no seller-change.
        {
          const ZERO_32 = new Uint8Array(32);
          const vcArgs = {
            noteA: alice.depositNote!.commitment,
            noteB: bob.depositNote!.commitment,
            noteC: noteCcommitment,
            noteD: noteDcommitment,
            noteE: noteEcommitment,
            noteF: ZERO_32,
            quoteMint: fx.quoteMint.toBytes(),
            baseMint: fx.baseMint.toBytes(),
            baseAmount: MATCH_BASE,
            quoteAmount: MATCH_QUOTE,
            buyerChangeAmt: ALICE_CHANGE,
            sellerChangeAmt: 0n,
            buyerFeeAmt: BUYER_FEE,
            sellerFeeAmt: SELLER_FEE,
          };
          const validCreate = await proveValidCreate({
            repoRoot: REPO_ROOT,
            quoteMint: fx.quoteMint.toBytes(),
            baseMint: fx.baseMint.toBytes(),
            inputA: { ownerCommit: alice.ownerCommit, amount: alice.depositNote!.amount,
                      nonce: alice.depositNote!.nonce, blindingR: alice.depositNote!.blindingR },
            inputAcommitmentBE: alice.depositNote!.commitment,
            inputB: { ownerCommit: bob.ownerCommit, amount: bob.depositNote!.amount,
                      nonce: bob.depositNote!.nonce, blindingR: bob.depositNote!.blindingR },
            inputBcommitmentBE: bob.depositNote!.commitment,
            outputC: { ownerCommit: alice.ownerCommit, amount: MATCH_BASE,
                       nonce: be32ToBigInt(noteCnonce), blindingR: be32ToBigInt(noteCblind) },
            outputCcommitmentBE: noteCcommitment,
            outputD: { ownerCommit: bob.ownerCommit, amount: MATCH_QUOTE,
                       nonce: be32ToBigInt(noteDnonce), blindingR: be32ToBigInt(noteDblind) },
            outputDcommitmentBE: noteDcommitment,
            outputE: { ownerCommit: alice.ownerCommit, amount: ALICE_CHANGE,
                       nonce: be32ToBigInt(noteEnonce), blindingR: be32ToBigInt(noteEblind) },
            outputEcommitmentBE: noteEcommitment,
            outputF: undefined, outputFcommitmentBE: ZERO_32,
            baseAmount: MATCH_BASE, quoteAmount: MATCH_QUOTE,
            buyerChangeAmt: ALICE_CHANGE, sellerChangeAmt: 0n,
            buyerFeeAmt: BUYER_FEE, sellerFeeAmt: SELLER_FEE,
          });
          const binding = validCreateBindingHash(vcArgs);
          const markerExpiry = BigInt((await fx.l1.getSlot("confirmed")) + 200);
          const verifyTx = new Transaction().add(
            ComputeBudgetProgram.setComputeUnitLimit({ units: 600_000 }),
            buildVerifyValidCreateInstruction({
              programId: fx.vaultProgramId, payer: fx.teeKeypair.publicKey,
              bindingHash: binding,
              noteAcommitment: alice.depositNote!.commitment,
              noteBcommitment: bob.depositNote!.commitment,
              noteCcommitment, noteDcommitment,
              noteEcommitment, noteFcommitment: ZERO_32,
              quoteMint: fx.quoteMint, baseMint: fx.baseMint,
              baseAmount: MATCH_BASE, quoteAmount: MATCH_QUOTE,
              buyerChangeAmt: ALICE_CHANGE, sellerChangeAmt: 0n,
              buyerFeeAmt: BUYER_FEE, sellerFeeAmt: SELLER_FEE,
              expirySlot: markerExpiry, proof: validCreate.proof,
            }),
          );
          await sendAndConfirmTransaction(fx.l1, verifyTx, [fx.teeKeypair], { commitment: "confirmed" });
        }

        // v3.1: land VALID_PRICE proof in its own tx (creates the
        // ValidPriceMarker PDA the settle handler reads).
        const priceMarker = await landVerifyValidPrice({
          connection: fx.l1,
          vaultProgramId: fx.vaultProgramId,
          teeKeypair: fx.teeKeypair,
          payload,
          repoRoot: REPO_ROOT,
        });
        txline("verify_valid_price", priceMarker.txSig);

        await timer.time("Ed25519 + tee_forced_settle", "L1", async () => {
          // v3: with-change-note variant — same tx-size pressure as Test B
          // (lock_e and lock_f no longer dedupe because note_e is non-zero).
          // Route through the v0/ALT helper.
          if (!fx.settleLookupTable) {
            throw new Error("e2e-config.json missing settleLookupTable — rerun devnet-setup");
          }
          const settleSig = await sendSettleV0({
            connection: fx.l1,
            signer: fx.teeKeypair,
            altPubkey: fx.settleLookupTable,
            instructions: [
              ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
              buildEd25519VerifyIx({
                teePubkey: fx.teeKeypair.publicKey.toBytes(),
                signature: teeSig, message: msg,
              }),
              buildSettleIx({
                programId: fx.vaultProgramId,
                teeAuthority: fx.teeKeypair.publicKey,
                payload,
                quoteMint: fx.quoteMint, baseMint: fx.baseMint,
                priceCommitment: priceMarker.priceCommitment,
              }),
            ],
          });
          txline("Ed25519 + tee_forced_settle (v0)", settleSig);
        });
        }

        // Append tree leaves in the SAME order tee_forced_settle appended:
        // note_c, note_d, note_e (since change>0), note_fee (since fee>0).
        await fx.tree.append(noteCcommitment);
        alice.tradeNote = {
          mint: fx.baseMint, amount: MATCH_BASE,
          nonce: noteCnonce, blindingR: noteCblind,
          commitment: noteCcommitment, leafIndex: fx.tree.leafCount - 1,
        };
        await fx.tree.append(noteDcommitment);
        bob.tradeNote = {
          mint: fx.quoteMint, amount: MATCH_QUOTE,
          nonce: noteDnonce, blindingR: noteDblind,
          commitment: noteDcommitment, leafIndex: fx.tree.leafCount - 1,
        };
        await fx.tree.append(noteEcommitment);
        alice.changeNote = {
          mint: fx.quoteMint, amount: ALICE_CHANGE,
          nonce: noteEnonce, blindingR: noteEblind,
          commitment: noteEcommitment, leafIndex: fx.tree.leafCount - 1,
        };
        if (BUYER_FEE > 0n) await fx.tree.append(feeCommitment);

        // Sanity-check the on-chain root against the shadow root.
        {
          const [vPda] = vaultConfigPda(fx.vaultProgramId);
          const vc = await fx.l1.getAccountInfo(vPda, "confirmed");
          if (!vc) throw new Error("vault_config missing post-settle");
          // 8 disc + 32 admin + 32 tee + 32 root_key + 8 leaf_count = 112
          const OFF = 8 + 32 + 32 + 32;
          const onChainRoot = vc.data.subarray(OFF + 8, OFF + 8 + 32);
          const shadowRoot = await fx.tree.computeRoot();
          const onHex = Buffer.from(onChainRoot).toString("hex");
          const shHex = Buffer.from(shadowRoot).toString("hex");
          bullet(`on-chain root: ${onHex.slice(0, 32)}…`);
          bullet(`shadow root:   ${shHex.slice(0, 32)}…`);
          expect(onHex).toBe(shHex);
        }

        // ── Step 13: withdraw note_c (BASE) + note_e (QUOTE change)
        step(13, "withdraw note_c (Alice BASE) + note_e (Alice QUOTE change)");
        await timer.time("VALID_SPEND + withdraw note_c", "L1", async () => {
          await proveAndWithdraw(
            fx, alice, alice.tradeNote!, atas.aliceBaseAta, alice.payer,
            alice.ownerBlinding, "Alice → BASE (trade)",
          );
        });
        timer.markFirstWithdraw();
        await timer.time("VALID_SPEND + withdraw note_e (CHANGE)", "L1", async () => {
          await proveAndWithdraw(
            fx, alice, alice.changeNote!, atas.aliceQuoteAta, alice.payer,
            alice.ownerBlinding, "Alice → QUOTE (change note)",
          );
        });

        const aBaseBal = await fx.l1.getTokenAccountBalance(atas.aliceBaseAta);
        const aQuoteBal = await fx.l1.getTokenAccountBalance(atas.aliceQuoteAta);
        bullet(`Alice BASE  withdrawn: ${aBaseBal.value.amount}`);
        bullet(`Alice QUOTE withdrawn: ${aQuoteBal.value.amount}`);
        expect(BigInt(aBaseBal.value.amount)).toBeGreaterThanOrEqual(MATCH_BASE);
        expect(BigInt(aQuoteBal.value.amount)).toBeGreaterThanOrEqual(ALICE_CHANGE);

        timer.printSummary("over-collateralised exact fill");
      },
    );

    // ─────────────────────────────────────────────────────────────────────
    // TEST B — partial fill with re-lock
    // ─────────────────────────────────────────────────────────────────────
    it(
      "B: partial fill — Alice's order keeps trading, change re-locked against her order",
      { timeout: 900_000 },
      async () => {
        const timer = new StepTimer();
        banner("TEST B — partial fill with re-lock (BUY 100 BASE @ 100 vs SELL 30 BASE @ 100)");

        const PRICE = 100n;
        const ALICE_BUY = 100n;
        const BOB_SELL = 30n;
        const MATCHED_BASE = BOB_SELL; // Bob's full size
        const MATCHED_QUOTE = MATCHED_BASE * PRICE; // 3000
        const FEE_BPS = BigInt(fx.protocolFeeBps);
        const BUYER_FEE = (MATCHED_QUOTE * FEE_BPS) / 10_000n; // 9
        const SELLER_FEE = (MATCHED_BASE * FEE_BPS) / 10_000n; // 0
        // Alice deposits enough QUOTE to cover the full 100 BASE @ 100 + fees.
        const ALICE_FULL_NOTIONAL = ALICE_BUY * PRICE; // 10000
        const ALICE_FULL_FEE = (ALICE_FULL_NOTIONAL * FEE_BPS) / 10_000n; // 30
        const ALICE_DEPOSIT = ALICE_FULL_NOTIONAL + ALICE_FULL_FEE; // 10030
        const BOB_DEPOSIT = BOB_SELL;
        const ALICE_CHANGE = ALICE_DEPOSIT - MATCHED_QUOTE - BUYER_FEE; // 10030-3000-9 = 7021
        const BOB_CHANGE = BOB_DEPOSIT - MATCHED_BASE - SELLER_FEE; // 0 (exact)

        bullet(`Alice BUY ${ALICE_BUY} @ ${PRICE}, deposit ${ALICE_DEPOSIT} QUOTE`);
        bullet(`Bob   SELL ${BOB_SELL}  @ ${PRICE}, deposit ${BOB_DEPOSIT} BASE`);
        bullet(`expected match: ${MATCHED_BASE} BASE @ ${PRICE}`);
        bullet(`expected Alice change = ${ALICE_CHANGE} QUOTE (re-locked vs alice order)`);
        bullet(`expected Bob   change = ${BOB_CHANGE} BASE  (exact)`);

        // ── Step 0: tree wipe
        step(0, "reset_merkle_tree (per-test fresh tree)");
        await timer.time("reset_merkle_tree", "L1", () => resetTreeFresh(fx));

        // ── personas (fresh per-run seed)
        const runSeed = freshRunSeed();
        const alice = await timer.time("derive Alice persona", "local", () => makePersona("alice", 0xC1, runSeed));
        const bob = await timer.time("derive Bob persona", "local", () => makePersona("bob", 0xC2, runSeed));

        // ── fund + mint
        step(2, "fund SOL + mint deposit balances (L1)");
        const atas = await fundAndMint(fx, alice, bob, ALICE_DEPOSIT, BOB_DEPOSIT, timer);

        // ── wallets
        step(3, "create_wallet (idempotent)");
        await ensureWallets(fx, alice, bob, timer);

        // ── deposit
        step(4, "deposit notes (L1)");
        await timer.time("deposit ×2", "L1", async () => {
          await depositNote(fx, alice, fx.quoteMint, ALICE_DEPOSIT, atas.aliceQuoteAta);
          await depositNote(fx, bob,   fx.baseMint,  BOB_DEPOSIT,   atas.bobBaseAta);
        });

        // ── slots — use slot 1 to keep state isolated from Test A
        step(5, "init + delegate PendingOrder slots — slot 1 each");
        const ALICE_SLOT = 1, BOB_SLOT = 1;
        await timer.time("init + delegate slot ×2", "L1", async () => {
          await ensureSlot(fx, alice, ALICE_SLOT);
          await ensureSlot(fx, bob, BOB_SLOT);
        });

        // ── delegate market PDAs (idempotent — already done in Test A)
        step(6, "delegate market PDAs (idempotent if Test A already delegated)");
        await timer.time("market delegation check", "L1", async () => {
          await ensureMarketDelegated(fx);
        });

        // ── submit_order
        step(7, "submit_order — Alice 100, Bob 30 (partial-fill setup)");
        const aliceOrderId = alice.tradingKey.publicKey.toBytes().slice(0, 16);
        aliceOrderId[0] |= 0x80;
        const bobOrderId = bob.tradingKey.publicKey.toBytes().slice(0, 16);
        bobOrderId[0] |= 0x80;
        const now = await fx.l1.getSlot("confirmed");
        const expiry = BigInt(now) + 500n;
        await timer.time("submit_order Alice (BUY 100)", "ER", async () => {
          const { ix } = buildSubmitOrderInstruction({
            programId: fx.meProgramId,
            tradingKey: alice.tradingKey.publicKey,
            market: fx.market,
            slotIdx: ALICE_SLOT,
            userCommitment: bn254ToBE32(alice.ownerCommit),
            noteCommitment: alice.depositNote!.commitment,
            amount: ALICE_BUY,
            priceLimit: PRICE,
            side: 0,
            noteAmount: alice.depositNote!.amount,
            expirySlot: expiry,
            orderId: aliceOrderId,
            orderType: OrderType.Limit,
          });
          const tx = new Transaction().add(
            ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 }),
            ix,
          );
          const sig = await sendAndConfirmTransaction(
            fx.er, tx, [alice.tradingKey], { commitment: "confirmed" },
          );
          txline(`alice: submit_order BUY ${ALICE_BUY} @ ${PRICE}`, sig, "er");
        });
        await timer.time("submit_order Bob (SELL 30)", "ER", async () => {
          const { ix } = buildSubmitOrderInstruction({
            programId: fx.meProgramId,
            tradingKey: bob.tradingKey.publicKey,
            market: fx.market,
            slotIdx: BOB_SLOT,
            userCommitment: bn254ToBE32(bob.ownerCommit),
            noteCommitment: bob.depositNote!.commitment,
            amount: BOB_SELL,
            priceLimit: PRICE,
            side: 1,
            noteAmount: bob.depositNote!.amount,
            expirySlot: expiry,
            orderId: bobOrderId,
            orderType: OrderType.Limit,
          });
          const tx = new Transaction().add(
            ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 }),
            ix,
          );
          const sig = await sendAndConfirmTransaction(
            fx.er, tx, [bob.tradingKey], { commitment: "confirmed" },
          );
          txline(`bob:   submit_order SELL ${BOB_SELL} @ ${PRICE}`, sig, "er");
        });
        timer.markOrderAccepted();

        // ── run_batch
        step(8, "run_batch (ER) — partial fill: 30 of 100 BASE matched");
        const [aliceSlotPda] = pendingOrderPda(
          fx.meProgramId, fx.market, alice.tradingKey.publicKey, ALICE_SLOT,
        );
        const [bobSlotPda] = pendingOrderPda(
          fx.meProgramId, fx.market, bob.tradingKey.publicKey, BOB_SLOT,
        );
        const [batchPda] = batchResultsPda(fx.meProgramId, fx.market);
        const preAcct = await fx.l1.getAccountInfo(batchPda, "confirmed");
        const preHash = preAcct ? Buffer.from(preAcct.data).toString("hex") : null;
        await timer.time("run_batch", "ER", async () => {
          const rbTx = new Transaction().add(
            ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
            buildRunBatchInstruction({
              programId: fx.meProgramId,
              vaultProgramId: fx.vaultProgramId,
              teeAuthority: fx.teeKeypair.publicKey,
              market: fx.market,
              pythAccount: fx.pythAccount,
              pendingOrderPdas: [aliceSlotPda, bobSlotPda],
            }),
          );
          const rbSig = await sendAndConfirmTransaction(
            fx.er, rbTx, [fx.teeKeypair], { commitment: "confirmed" },
          );
          txline("run_batch", rbSig, "er");
        });

        // ── undelegate market + L1 commit poll
        step(9, "undelegate_market (commits BatchResults to L1)");
        await timer.time("undelegate + L1 poll for commit", "ER+L1", async () => {
          const undTx = new Transaction().add(
            ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
            buildUndelegateMarketInstruction({
              programId: fx.meProgramId, payer: fx.funder.publicKey, market: fx.market,
            }),
          );
          const undSig = await sendAndConfirmTransaction(
            fx.er, undTx, [fx.funder], { commitment: "confirmed" },
          );
          txline("undelegate_market", undSig, "er");
          await waitForL1AccountChange(fx.l1, batchPda, preHash, {
            timeoutMs: 90_000, intervalMs: 1_000,
          });
        });

        // ── decode + verify partial-fill results
        step(10, "decode BatchResults — verify partial-fill + re-lock fields");
        const batchPostAcct = await fx.l1.getAccountInfo(batchPda, "confirmed");
        if (!batchPostAcct) throw new Error("BatchResults missing");
        const view = decodeBatchResults(new Uint8Array(batchPostAcct.data));
        const filled = view.results.find((r) =>
          r.status === 1 &&
          Buffer.from(r.ownerBuyer).equals(alice.tradingKey.publicKey.toBuffer()) &&
          Buffer.from(r.ownerSeller).equals(bob.tradingKey.publicKey.toBuffer()),
        );
        if (!filled) throw new Error("MatchResult for Alice/Bob missing in BatchResults");
        bullet(`base_amt           = ${filled.baseAmt} (expected ${MATCHED_BASE})`);
        bullet(`quote_amt          = ${filled.quoteAmt} (expected ${MATCHED_QUOTE})`);
        bullet(`buyer_change_amt   = ${filled.buyerChangeAmt} (expected ${ALICE_CHANGE})`);
        bullet(`seller_change_amt  = ${filled.sellerChangeAmt} (expected ${BOB_CHANGE})`);
        bullet(`buyer_relock_oid   = ${Buffer.from(filled.buyerRelockOrderId).toString("hex")}`);
        bullet(`expected   oid     = ${Buffer.from(aliceOrderId).toString("hex")}`);
        expect(filled.baseAmt).toBe(MATCHED_BASE);
        expect(filled.quoteAmt).toBe(MATCHED_QUOTE);
        expect(filled.buyerChangeAmt).toBe(ALICE_CHANGE);
        expect(filled.sellerChangeAmt).toBe(BOB_CHANGE);
        // Re-lock MUST be active for Alice; not for Bob (exact fill).
        expect(Buffer.from(filled.buyerRelockOrderId).equals(Buffer.from(aliceOrderId))).toBe(true);
        expect(Buffer.from(filled.sellerRelockOrderId).equals(Buffer.from(RELOCK_ORDER_ID_NONE))).toBe(true);

        // ── recompute notes (note_c, note_d, note_e, fee) + sign payload
        step(11, "TEE recomputes notes + signs canonical payload (with re-lock)");
        const matchId = filled.matchId;
        const matchIdBytes = asU8a16(matchId);

        const noteCnonce = deriveNonce(matchId, TRADE_ROLE_BUYER);
        const noteCblind = deriveBlinding(matchId, TRADE_ROLE_BUYER);
        const noteCcommitment = await noteCommitment({
          tokenMint: fx.baseMint.toBytes(), amount: MATCHED_BASE,
          ownerCommitment: alice.ownerCommit,
          nonce: be32ToBigInt(noteCnonce), blindingR: be32ToBigInt(noteCblind),
        });
        leaf("note_c (Alice BASE 30)", noteCcommitment);

        const noteDnonce = deriveNonce(matchId, TRADE_ROLE_SELLER);
        const noteDblind = deriveBlinding(matchId, TRADE_ROLE_SELLER);
        const noteDcommitment = await noteCommitment({
          tokenMint: fx.quoteMint.toBytes(), amount: MATCHED_QUOTE,
          ownerCommitment: bob.ownerCommit,
          nonce: be32ToBigInt(noteDnonce), blindingR: be32ToBigInt(noteDblind),
        });
        leaf("note_d (Bob QUOTE 3000)", noteDcommitment);

        // See Test A note_e construction comment — must hash against
        // `alice.ownerCommit` (= Poseidon(spendingKey, ownerBlinding)) so the
        // locally-built leaf matches on-chain and remains spendable via
        // VALID_SPEND if/when the user later cancels and withdraws.
        const noteEnonce = deriveNonce(matchId, CHANGE_ROLE_BUYER);
        const noteEblind = deriveBlinding(matchId, CHANGE_ROLE_BUYER);
        const noteEcommitment = await noteCommitment({
          tokenMint: fx.quoteMint.toBytes(), amount: ALICE_CHANGE,
          ownerCommitment: alice.ownerCommit,
          nonce: be32ToBigInt(noteEnonce), blindingR: be32ToBigInt(noteEblind),
        });
        leaf("note_e (Alice change 7021 — re-locked)", noteEcommitment);
        expect(Buffer.from(filled.noteEcommitment).equals(Buffer.from(noteEcommitment))).toBe(true);

        const slot = await fx.l1.getSlot("confirmed");
        const feeNonce = deriveNonce(BigInt(slot), FEE_ROLE_QUOTE);
        const feeBlind = deriveBlinding(BigInt(slot), FEE_ROLE_QUOTE);
        const feeCommitment = BUYER_FEE > 0n ? await noteCommitment({
          tokenMint: fx.quoteMint.toBytes(), amount: BUYER_FEE,
          ownerCommitment: be32ToBigInt(fx.protocolOwnerCommitment),
          nonce: be32ToBigInt(feeNonce), blindingR: be32ToBigInt(feeBlind),
        }) : new Uint8Array(32);

        const nullA = await nullifier(alice.spendingKey, alice.depositNote!.commitment);
        const nullB = await nullifier(bob.spendingKey, bob.depositNote!.commitment);

        const payload: MatchResultPayload = exactFillPayload({
          matchId: matchIdBytes,
          noteAcommitment: alice.depositNote!.commitment,
          noteBcommitment: bob.depositNote!.commitment,
          noteCcommitment, noteDcommitment,
          nullifierA: nullA, nullifierB: nullB,
          orderIdA: aliceOrderId, orderIdB: bobOrderId,
          baseAmount: MATCHED_BASE, quoteAmount: MATCHED_QUOTE,
        });
        payload.buyerChangeAmt = ALICE_CHANGE;
        payload.noteEcommitment = noteEcommitment;
        payload.buyerFeeAmt = BUYER_FEE;
        payload.sellerFeeAmt = SELLER_FEE;
        payload.noteFeeCommitment = feeCommitment;
        // Activate re-lock — instructs tee_forced_settle to atomically allocate
        // a NoteLock(note_e) → aliceOrderId on L1.
        payload.buyerRelockOrderId = aliceOrderId;
        payload.buyerRelockExpiry = expiry;

        const msg = canonicalPayloadHash(payload);
        const teeSig = teeSign(fx.teeKeypair, msg);
        bullet(`canonical hash: 0x${toHex(msg).slice(0, 16)}…`);

        // ── lock_note + settle
        step(12, "lock_note ×2 (L1) then Ed25519 + tee_forced_settle (L1, with re-lock)");

        // v2: per-side VALID_INPUT proofs gating lock_note.
        const aliceWitness2 = await fx.tree.witness(alice.depositNote!.leafIndex);
        const aliceVI2 = await proveValidInput({
          repoRoot: REPO_ROOT,
          spendingKey: alice.spendingKey,
          ownerCommitmentBlinding: alice.ownerBlinding,
          nonce: alice.depositNote!.nonce,
          blindingR: alice.depositNote!.blindingR,
          tokenMint: alice.depositNote!.mint.toBytes(),
          amount: alice.depositNote!.amount,
          merkleRootBE: aliceWitness2.root,
          merkleWitness: {
            pathElements: aliceWitness2.siblings.map(be32ToBigInt),
            pathIndices: aliceWitness2.indices,
          },
        });
        const bobWitness2 = await fx.tree.witness(bob.depositNote!.leafIndex);
        const bobVI2 = await proveValidInput({
          repoRoot: REPO_ROOT,
          spendingKey: bob.spendingKey,
          ownerCommitmentBlinding: bob.ownerBlinding,
          nonce: bob.depositNote!.nonce,
          blindingR: bob.depositNote!.blindingR,
          tokenMint: bob.depositNote!.mint.toBytes(),
          amount: bob.depositNote!.amount,
          merkleRootBE: bobWitness2.root,
          merkleWitness: {
            pathElements: bobWitness2.siblings.map(be32ToBigInt),
            pathIndices: bobWitness2.indices,
          },
        });

        await timer.time("lock_note ×2", "L1", async () => {
          const lockTx = new Transaction().add(
            ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }),
            buildLockNoteInstruction({
              programId: fx.vaultProgramId,
              teeAuthority: fx.teeKeypair.publicKey,
              noteCommitment: alice.depositNote!.commitment,
              orderId: aliceOrderId,
              expirySlot: expiry,
              amount: ALICE_DEPOSIT,
              tokenMint: alice.depositNote!.mint,
              merkleRoot: aliceWitness2.root,
              proof: aliceVI2.proof,
            }),
            buildLockNoteInstruction({
              programId: fx.vaultProgramId,
              teeAuthority: fx.teeKeypair.publicKey,
              noteCommitment: bob.depositNote!.commitment,
              orderId: bobOrderId,
              expirySlot: expiry,
              amount: BOB_DEPOSIT,
              tokenMint: bob.depositNote!.mint,
              merkleRoot: bobWitness2.root,
              proof: bobVI2.proof,
            }),
          );
          const lockSig = await sendAndConfirmTransaction(
            fx.l1, lockTx, [fx.teeKeypair], { commitment: "confirmed" },
          );
          txline("lock_note(note_a) + lock_note(note_b)", lockSig);
        });

        if (USE_BATCHED_PROOF) {
          // ── v3.5 batched path — re-lock variant: payload still carries
          // buyer change + fee, and the settle handler still atomically
          // re-locks note_e against the remaining open buyer order.
          if (!fx.settleLookupTable) {
            throw new Error("e2e-config.json missing settleLookupTable — rerun devnet-setup");
          }
          await timer.time("v3.5 batched settle (with re-lock)", "L1", async () => {
            const ZERO_32 = new Uint8Array(32);
            const realSlot: MatchSlotWitness = {
              noteAcommitment: alice.depositNote!.commitment,
              noteBcommitment: bob.depositNote!.commitment,
              noteCcommitment,
              noteDcommitment,
              noteEcommitment,
              noteFcommitment: ZERO_32,
              quoteMint: fx.quoteMint.toBytes(),
              baseMint: fx.baseMint.toBytes(),
              baseAmount: MATCHED_BASE,
              quoteAmount: MATCHED_QUOTE,
              buyerChangeAmt: ALICE_CHANGE,
              sellerChangeAmt: 0n,
              buyerFeeAmt: BUYER_FEE,
              sellerFeeAmt: SELLER_FEE,
              batchSlot: payload.batchSlot,
              aOwnerCommit: alice.ownerCommit,
              bOwnerCommit: bob.ownerCommit,
              aAmount: alice.depositNote!.amount,
              bAmount: bob.depositNote!.amount,
              aNonce: alice.depositNote!.nonce,
              aBlinding: alice.depositNote!.blindingR,
              bNonce: bob.depositNote!.nonce,
              bBlinding: bob.depositNote!.blindingR,
              cNonce: be32ToBigInt(noteCnonce),
              cBlinding: be32ToBigInt(noteCblind),
              dNonce: be32ToBigInt(noteDnonce),
              dBlinding: be32ToBigInt(noteDblind),
              eNonce: be32ToBigInt(noteEnonce),
              eBlinding: be32ToBigInt(noteEblind),
              fNonce: 0n,
              fBlinding: 0n,
              clearingPrice: MATCHED_QUOTE / MATCHED_BASE,
            };
            await settleViaBatched({
              connection: fx.l1,
              vaultProgramId: fx.vaultProgramId,
              teeKeypair: fx.teeKeypair,
              realSlot,
              payload,
              teeSig,
              canonicalHash: msg,
              settleLookupTable: fx.settleLookupTable!,
              repoRoot: REPO_ROOT,
              onTx: txline,
            });
          });
        } else {
        // v3: VALID_CREATE proof — Test B has buyer-change + re-lock active.
        {
          const ZERO_32 = new Uint8Array(32);
          const vcArgs = {
            noteA: alice.depositNote!.commitment,
            noteB: bob.depositNote!.commitment,
            noteC: noteCcommitment,
            noteD: noteDcommitment,
            noteE: noteEcommitment,
            noteF: ZERO_32,
            quoteMint: fx.quoteMint.toBytes(),
            baseMint: fx.baseMint.toBytes(),
            baseAmount: MATCHED_BASE,
            quoteAmount: MATCHED_QUOTE,
            buyerChangeAmt: ALICE_CHANGE,
            sellerChangeAmt: 0n,
            buyerFeeAmt: BUYER_FEE,
            sellerFeeAmt: SELLER_FEE,
          };
          const validCreate = await proveValidCreate({
            repoRoot: REPO_ROOT,
            quoteMint: fx.quoteMint.toBytes(),
            baseMint: fx.baseMint.toBytes(),
            inputA: { ownerCommit: alice.ownerCommit, amount: alice.depositNote!.amount,
                      nonce: alice.depositNote!.nonce, blindingR: alice.depositNote!.blindingR },
            inputAcommitmentBE: alice.depositNote!.commitment,
            inputB: { ownerCommit: bob.ownerCommit, amount: bob.depositNote!.amount,
                      nonce: bob.depositNote!.nonce, blindingR: bob.depositNote!.blindingR },
            inputBcommitmentBE: bob.depositNote!.commitment,
            outputC: { ownerCommit: alice.ownerCommit, amount: MATCHED_BASE,
                       nonce: be32ToBigInt(noteCnonce), blindingR: be32ToBigInt(noteCblind) },
            outputCcommitmentBE: noteCcommitment,
            outputD: { ownerCommit: bob.ownerCommit, amount: MATCHED_QUOTE,
                       nonce: be32ToBigInt(noteDnonce), blindingR: be32ToBigInt(noteDblind) },
            outputDcommitmentBE: noteDcommitment,
            outputE: { ownerCommit: alice.ownerCommit, amount: ALICE_CHANGE,
                       nonce: be32ToBigInt(noteEnonce), blindingR: be32ToBigInt(noteEblind) },
            outputEcommitmentBE: noteEcommitment,
            outputF: undefined, outputFcommitmentBE: ZERO_32,
            baseAmount: MATCHED_BASE, quoteAmount: MATCHED_QUOTE,
            buyerChangeAmt: ALICE_CHANGE, sellerChangeAmt: 0n,
            buyerFeeAmt: BUYER_FEE, sellerFeeAmt: SELLER_FEE,
          });
          const binding = validCreateBindingHash(vcArgs);
          const markerExpiry = BigInt((await fx.l1.getSlot("confirmed")) + 200);
          const verifyTx = new Transaction().add(
            ComputeBudgetProgram.setComputeUnitLimit({ units: 600_000 }),
            buildVerifyValidCreateInstruction({
              programId: fx.vaultProgramId, payer: fx.teeKeypair.publicKey,
              bindingHash: binding,
              noteAcommitment: alice.depositNote!.commitment,
              noteBcommitment: bob.depositNote!.commitment,
              noteCcommitment, noteDcommitment,
              noteEcommitment, noteFcommitment: ZERO_32,
              quoteMint: fx.quoteMint, baseMint: fx.baseMint,
              baseAmount: MATCHED_BASE, quoteAmount: MATCHED_QUOTE,
              buyerChangeAmt: ALICE_CHANGE, sellerChangeAmt: 0n,
              buyerFeeAmt: BUYER_FEE, sellerFeeAmt: SELLER_FEE,
              expirySlot: markerExpiry, proof: validCreate.proof,
            }),
          );
          await sendAndConfirmTransaction(fx.l1, verifyTx, [fx.teeKeypair], { commitment: "confirmed" });
        }

        const priceMarker = await landVerifyValidPrice({
          connection: fx.l1,
          vaultProgramId: fx.vaultProgramId,
          teeKeypair: fx.teeKeypair,
          payload,
          repoRoot: REPO_ROOT,
        });
        txline("verify_valid_price", priceMarker.txSig);

        await timer.time("Ed25519 + tee_forced_settle (with re-lock)", "L1", async () => {
          // v3: with-relock settle was 1243/1232 as a legacy tx. Send as v0
          // with the ALT in e2e-config so the three static accounts
          // (vault_config, sysvar, system_program) collapse to 1-byte
          // indices, freeing ~60 bytes.
          if (!fx.settleLookupTable) {
            throw new Error("e2e-config.json missing settleLookupTable — rerun devnet-setup");
          }
          const settleSig = await sendSettleV0({
            connection: fx.l1,
            signer: fx.teeKeypair,
            altPubkey: fx.settleLookupTable,
            instructions: [
              ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
              buildEd25519VerifyIx({
                teePubkey: fx.teeKeypair.publicKey.toBytes(),
                signature: teeSig, message: msg,
              }),
              buildSettleIx({
                programId: fx.vaultProgramId,
                teeAuthority: fx.teeKeypair.publicKey,
                payload,
                quoteMint: fx.quoteMint, baseMint: fx.baseMint,
                priceCommitment: priceMarker.priceCommitment,
              }),
            ],
          });
          txline("Ed25519 + tee_forced_settle (re-lock active, v0)", settleSig);
        });
        }

        // Append leaves: note_c, note_d, note_e, note_fee.
        await fx.tree.append(noteCcommitment);
        alice.tradeNote = {
          mint: fx.baseMint, amount: MATCHED_BASE,
          nonce: noteCnonce, blindingR: noteCblind,
          commitment: noteCcommitment, leafIndex: fx.tree.leafCount - 1,
        };
        await fx.tree.append(noteDcommitment);
        bob.tradeNote = {
          mint: fx.quoteMint, amount: MATCHED_QUOTE,
          nonce: noteDnonce, blindingR: noteDblind,
          commitment: noteDcommitment, leafIndex: fx.tree.leafCount - 1,
        };
        await fx.tree.append(noteEcommitment);
        // note_e is re-locked — Alice cannot withdraw it directly.
        if (BUYER_FEE > 0n) await fx.tree.append(feeCommitment);

        // ── verify (a) NoteLock PDA on note_e (b) PendingOrder slot in ER
        step(13, "verify (a) L1 NoteLock pinned note_e + (b) ER PendingOrder slot rotated");
        await timer.time("read NoteLock(note_e) on L1", "L1", async () => {
          const [noteEnoteLockPda] = noteLockPda(fx.vaultProgramId, noteEcommitment);
          const noteELockAcct = await fx.l1.getAccountInfo(noteEnoteLockPda, "confirmed");
          if (!noteELockAcct) throw new Error("NoteLock(note_e) was NOT created — re-lock failed");
          const lock = decodeNoteLock(new Uint8Array(noteELockAcct.data));
          bullet(`NoteLock(note_e) amount    = ${lock.amount} (expected ${ALICE_CHANGE})`);
          bullet(`NoteLock(note_e) order_id  = 0x${toHex(lock.orderId)}`);
          bullet(`NoteLock(note_e) expected  = 0x${toHex(aliceOrderId)}`);
          expect(lock.amount).toBe(ALICE_CHANGE);
          expect(Buffer.from(lock.orderId).equals(Buffer.from(aliceOrderId))).toBe(true);
          expect(Buffer.from(lock.noteCommitment).equals(Buffer.from(noteEcommitment))).toBe(true);
        });

        await timer.time("read PendingOrder slot from ER", "ER", async () => {
          // After undelegate_market, the MARKET PDAs returned to L1 — but
          // PendingOrder slots stay delegated. Read from the ER directly.
          const slotAcct = await fx.er.getAccountInfo(aliceSlotPda, "confirmed");
          if (!slotAcct) throw new Error("Alice's PendingOrder slot missing in ER");
          const slot = decodePendingOrder(new Uint8Array(slotAcct.data));
          bullet(`slot.status            = ${slot.status} (expected ${PENDING_STATUS_PENDING})`);
          bullet(`slot.amount            = ${slot.amount} (remaining; expected ${ALICE_BUY - MATCHED_BASE})`);
          bullet(`slot.filled_quantity   = ${slot.filledQuantity} (expected ${MATCHED_BASE})`);
          bullet(`slot.note_amount       = ${slot.noteAmount} (expected ${ALICE_CHANGE})`);
          bullet(`slot.collateral_note   = 0x${toHex(slot.collateralNote).slice(0, 32)}…`);
          bullet(`note_e_commitment      = 0x${toHex(noteEcommitment).slice(0, 32)}…`);
          expect(slot.status).toBe(PENDING_STATUS_PENDING);
          expect(slot.amount).toBe(ALICE_BUY - MATCHED_BASE);
          expect(slot.noteAmount).toBe(ALICE_CHANGE);
          expect(Buffer.from(slot.collateralNote).equals(Buffer.from(noteEcommitment))).toBe(true);
          expect(Buffer.from(slot.orderId).equals(Buffer.from(aliceOrderId))).toBe(true);
        });

        // ── Bob withdraws his note_d (3000 QUOTE) — proves the matched
        //    portion is freely spendable.
        step(14, "Bob withdraws note_d (QUOTE 3000) — matched portion is spendable");
        await timer.time("VALID_SPEND + withdraw note_d", "L1", async () => {
          await proveAndWithdraw(
            fx, bob, bob.tradeNote!, atas.bobQuoteAta, bob.payer,
            bob.ownerBlinding, "Bob → QUOTE (matched)",
          );
        });
        timer.markFirstWithdraw();
        const bQuoteBal = await fx.l1.getTokenAccountBalance(atas.bobQuoteAta);
        bullet(`Bob QUOTE: ${bQuoteBal.value.amount}`);
        expect(BigInt(bQuoteBal.value.amount)).toBeGreaterThanOrEqual(MATCHED_QUOTE);

        timer.printSummary("partial fill with re-lock");
      },
    );

    it(
      "C: privacy regression — ER submit_order leaves no order-intent bytes on L1",
      { timeout: 900_000 },
      async () => {
        const timer = new StepTimer();
        banner("TEST C — privacy regression (ER submit_order leaves no L1 order bytes)");

        const ALICE_DEPOSIT = 2_000n;
        const PRICE = 100n;
        const AMOUNT = 10n;

        step(0, "reset_merkle_tree (per-test fresh tree)");
        await timer.time("reset_merkle_tree", "L1", () => resetTreeFresh(fx));

        const runSeed = freshRunSeed();
        const alice = await timer.time("derive Alice persona", "local", () => makePersona("alice", 0xD1, runSeed));
        const bob = await timer.time("derive Bob persona", "local", () => makePersona("bob", 0xD2, runSeed));

        step(1, "fund + mint + wallet + deposit");
        const atas = await fundAndMint(fx, alice, bob, ALICE_DEPOSIT, 1n, timer);
        await ensureWallets(fx, alice, bob, timer);
        await timer.time("deposit Alice note", "L1", async () => {
          await depositNote(fx, alice, fx.quoteMint, ALICE_DEPOSIT, atas.aliceQuoteAta);
        });

        step(2, "init + delegate Alice PendingOrder slot");
        const ALICE_SLOT = 0;
        const aliceSlotPda = await timer.time("delegate Alice slot", "L1", async () =>
          ensureSlot(fx, alice, ALICE_SLOT),
        );

        const l1Before = await fx.l1.getAccountInfo(aliceSlotPda, "confirmed");
        if (!l1Before) throw new Error("L1 PendingOrder slot missing before submit");
        const l1BeforeOwner = l1Before.owner.toBase58();
        const l1BeforeHash = createHash("sha256")
          .update(l1Before.data)
          .digest("hex");
        const sigsBefore = await fx.l1.getSignaturesForAddress(
          alice.tradingKey.publicKey,
          { limit: 20 },
          "confirmed",
        );

        step(3, "submit_order via ER");
        const orderId = alice.tradingKey.publicKey.toBytes().slice(0, 16);
        orderId[0] |= 0x80;
        const now = await fx.l1.getSlot("confirmed");
        const expiry = BigInt(now) + 500n;
        await timer.time("submit_order Alice (ER)", "ER", async () => {
          const { ix } = buildSubmitOrderInstruction({
            programId: fx.meProgramId,
            tradingKey: alice.tradingKey.publicKey,
            market: fx.market,
            slotIdx: ALICE_SLOT,
            userCommitment: bn254ToBE32(alice.ownerCommit),
            noteCommitment: alice.depositNote!.commitment,
            amount: AMOUNT,
            priceLimit: PRICE,
            side: 0,
            noteAmount: alice.depositNote!.amount,
            expirySlot: expiry,
            orderId,
            orderType: OrderType.Limit,
          });
          const tx = new Transaction().add(
            ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 }),
            ix,
          );
          const sig = await sendAndConfirmTransaction(
            fx.er, tx, [alice.tradingKey], { commitment: "confirmed" },
          );
          txline("alice: submit_order BUY 10 @ 100", sig, "er");
        });
        timer.markOrderAccepted();

        step(4, "assert privacy: slot bytes unchanged on L1, while ER state changed");
        const erSlotAcct = await fx.er.getAccountInfo(aliceSlotPda, "confirmed");
        if (!erSlotAcct) throw new Error("ER PendingOrder slot missing after submit");
        const erSlot = decodePendingOrder(new Uint8Array(erSlotAcct.data));
        expect(erSlot.status).toBe(PENDING_STATUS_PENDING);
        expect(erSlot.amount).toBe(AMOUNT);
        expect(erSlot.priceLimit).toBe(PRICE);

        const l1After = await fx.l1.getAccountInfo(aliceSlotPda, "confirmed");
        if (!l1After) throw new Error("L1 PendingOrder slot missing after submit");
        const l1AfterOwner = l1After.owner.toBase58();
        const l1AfterHash = createHash("sha256")
          .update(l1After.data)
          .digest("hex");
        const sigsAfter = await fx.l1.getSignaturesForAddress(
          alice.tradingKey.publicKey,
          { limit: 20 },
          "confirmed",
        );

        expect(l1BeforeOwner).not.toBe(fx.meProgramId.toBase58());
        expect(l1AfterOwner).toBe(l1BeforeOwner);
        expect(l1AfterHash).toBe(l1BeforeHash);
        expect(sigsAfter.map((s) => s.signature)).toEqual(
          sigsBefore.map((s) => s.signature),
        );

        timer.printSummary("privacy regression");
      },
    );

    it(
      "D: multi-batch continuation — residual order matches in a second batch",
      { timeout: 900_000 },
      async () => {
        const timer = new StepTimer();
        banner("TEST D — multi-batch continuation (partial then residual match)");

        const PRICE = 100n;
        const ALICE_BUY = 100n;
        const BOB_SELL = 30n;
        const CAROL_SELL = 70n;
        const FEE_BPS = BigInt(fx.protocolFeeBps);
        const ALICE_FULL_NOTIONAL = ALICE_BUY * PRICE; // 10000
        const ALICE_FULL_FEE = (ALICE_FULL_NOTIONAL * FEE_BPS) / 10_000n; // 30
        const ALICE_DEPOSIT = ALICE_FULL_NOTIONAL + ALICE_FULL_FEE; // 10030
        const BOB_DEPOSIT = BOB_SELL;
        const CAROL_DEPOSIT = CAROL_SELL;
        const MATCH1_QUOTE = BOB_SELL * PRICE; // 3000
        const MATCH1_FEE = (MATCH1_QUOTE * FEE_BPS) / 10_000n; // 9
        const EXPECTED_ALICE_REMAINDER = ALICE_DEPOSIT - MATCH1_QUOTE - MATCH1_FEE; // 7021

        step(0, "reset_merkle_tree (per-test fresh tree)");
        await timer.time("reset_merkle_tree", "L1", () => resetTreeFresh(fx));

        const runSeed = freshRunSeed();
        const alice = await timer.time("derive Alice persona", "local", () => makePersona("alice", 0xE1, runSeed));
        const bob = await timer.time("derive Bob persona", "local", () => makePersona("bob", 0xE2, runSeed));
        const carol = await timer.time("derive Carol persona", "local", () => makePersona("carol", 0xE3, runSeed));

        step(1, "fund + mint for Alice/Bob/Carol");
        const PAYER_LAMPORTS = 2_000_000_000, PAYER_MIN = 500_000_000;
        const TK_LAMPORTS = 100_000_000, TK_MIN = 20_000_000;
        type FT = { label: string; to: PublicKey; target: number; min: number };
        const targets: FT[] = [
          { label: "alice payer",   to: alice.payer.publicKey,      target: PAYER_LAMPORTS, min: PAYER_MIN },
          { label: "bob payer",     to: bob.payer.publicKey,        target: PAYER_LAMPORTS, min: PAYER_MIN },
          { label: "carol payer",   to: carol.payer.publicKey,      target: PAYER_LAMPORTS, min: PAYER_MIN },
          { label: "alice trading", to: alice.tradingKey.publicKey, target: TK_LAMPORTS,    min: TK_MIN },
          { label: "bob trading",   to: bob.tradingKey.publicKey,   target: TK_LAMPORTS,    min: TK_MIN },
          { label: "carol trading", to: carol.tradingKey.publicKey, target: TK_LAMPORTS,    min: TK_MIN },
        ];
        const fundIxs = [];
        for (const t of targets) {
          const b = await fx.l1.getBalance(t.to);
          if (b < t.min) {
            fundIxs.push(
              SystemProgram.transfer({
                fromPubkey: fx.funder.publicKey,
                toPubkey: t.to,
                lamports: t.target - b,
              }),
            );
          }
        }
        if (fundIxs.length > 0) {
          await timer.time("fund SOL top-ups", "L1", async () => {
            const sig = await sendAndConfirmTransaction(
              fx.l1,
              new Transaction().add(...fundIxs),
              [fx.funder],
              { commitment: "confirmed" },
            );
            txline("funded Alice/Bob/Carol", sig);
          });
        }

        const aliceQuoteAta = await getAssociatedTokenAddress(fx.quoteMint, alice.payer.publicKey);
        const bobBaseAta = await getAssociatedTokenAddress(fx.baseMint, bob.payer.publicKey);
        const carolBaseAta = await getAssociatedTokenAddress(fx.baseMint, carol.payer.publicKey);
        await timer.time("create ATAs + mint balances", "L1", async () => {
          const tx = new Transaction().add(
            createAssociatedTokenAccountIdempotentInstruction(fx.admin.publicKey, aliceQuoteAta, alice.payer.publicKey, fx.quoteMint),
            createAssociatedTokenAccountIdempotentInstruction(fx.admin.publicKey, bobBaseAta, bob.payer.publicKey, fx.baseMint),
            createAssociatedTokenAccountIdempotentInstruction(fx.admin.publicKey, carolBaseAta, carol.payer.publicKey, fx.baseMint),
            createMintToInstruction(fx.quoteMint, aliceQuoteAta, fx.admin.publicKey, Number(ALICE_DEPOSIT)),
            createMintToInstruction(fx.baseMint, bobBaseAta, fx.admin.publicKey, Number(BOB_DEPOSIT)),
            createMintToInstruction(fx.baseMint, carolBaseAta, fx.admin.publicKey, Number(CAROL_DEPOSIT)),
          );
          const sig = await sendAndConfirmTransaction(fx.l1, tx, [fx.admin], { commitment: "confirmed" });
          txline("minted deposits for all personas", sig);
        });

        step(2, "create_wallet for Alice/Bob/Carol");
        await timer.time("create_wallet ×3", "L1", async () => {
          for (const p of [alice, bob, carol]) {
            const [wpda] = walletEntryPda(fx.vaultProgramId, p.userCommitment);
            const ex = await fx.l1.getAccountInfo(wpda);
            if (ex) continue;
            const [ucLo, ucHi] = pubkeyToFrPair(p.payer.publicKey.toBytes());
            const { proof } = snarkjsFullProve(
              {
                userCommitment: be32ToDec(p.userCommitment),
                rootKey: [ucLo.toString(), ucHi.toString()],
                spendingKey: p.spendingKey.toString(),
                viewingKey: p.viewingKey.toString(),
                r0: p.r0.toString(), r1: p.r1.toString(), r2: p.r2.toString(),
              },
              { circuitWasmPath: CREATE_WASM, circuitZkeyPath: CREATE_ZKEY, repoRoot: REPO_ROOT },
            );
            const tx = new Transaction().add(
              buildCreateWalletInstruction({
                programId: fx.vaultProgramId,
                owner: p.payer.publicKey,
                commitment: p.userCommitment,
                proof,
              }),
            );
            const sig = await sendAndConfirmTransaction(fx.l1, tx, [p.payer], { commitment: "confirmed" });
            txline(`${p.name}: create_wallet`, sig);
          }
        });

        step(3, "deposit notes for all personas");
        await timer.time("deposit ×3", "L1", async () => {
          await depositNote(fx, alice, fx.quoteMint, ALICE_DEPOSIT, aliceQuoteAta);
          await depositNote(fx, bob, fx.baseMint, BOB_DEPOSIT, bobBaseAta);
          await depositNote(fx, carol, fx.baseMint, CAROL_DEPOSIT, carolBaseAta);
        });

        step(4, "init + delegate pending slots and market PDAs");
        const SLOT = 1;
        const aliceSlotPda = await ensureSlot(fx, alice, SLOT);
        const bobSlotPda = await ensureSlot(fx, bob, SLOT);
        const carolSlotPda = await ensureSlot(fx, carol, SLOT);
        await ensureMarketDelegated(fx);

        const aliceOrderId = alice.tradingKey.publicKey.toBytes().slice(0, 16);
        aliceOrderId[0] |= 0x80;
        const bobOrderId = bob.tradingKey.publicKey.toBytes().slice(0, 16);
        bobOrderId[0] |= 0x80;
        const carolOrderId = carol.tradingKey.publicKey.toBytes().slice(0, 16);
        carolOrderId[0] |= 0x80;
        const now = await fx.l1.getSlot("confirmed");
        const expiry = BigInt(now) + 600n;

        step(5, "batch 1 — submit Alice BUY 100 and Bob SELL 30, then run_batch");
        await timer.time("submit_order Alice/Bob", "ER", async () => {
          const a = buildSubmitOrderInstruction({
            programId: fx.meProgramId,
            tradingKey: alice.tradingKey.publicKey,
            market: fx.market,
            slotIdx: SLOT,
            userCommitment: bn254ToBE32(alice.ownerCommit),
            noteCommitment: alice.depositNote!.commitment,
            amount: ALICE_BUY,
            priceLimit: PRICE,
            side: 0,
            noteAmount: alice.depositNote!.amount,
            expirySlot: expiry,
            orderId: aliceOrderId,
            orderType: OrderType.Limit,
          });
          const b = buildSubmitOrderInstruction({
            programId: fx.meProgramId,
            tradingKey: bob.tradingKey.publicKey,
            market: fx.market,
            slotIdx: SLOT,
            userCommitment: bn254ToBE32(bob.ownerCommit),
            noteCommitment: bob.depositNote!.commitment,
            amount: BOB_SELL,
            priceLimit: PRICE,
            side: 1,
            noteAmount: bob.depositNote!.amount,
            expirySlot: expiry,
            orderId: bobOrderId,
            orderType: OrderType.Limit,
          });
          const txA = new Transaction().add(
            ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 }),
            a.ix,
          );
          const sigA = await sendAndConfirmTransaction(
            fx.er, txA, [alice.tradingKey], { commitment: "confirmed" },
          );
          txline("alice: submit_order BUY 100 @ 100", sigA, "er");
          const txB = new Transaction().add(
            ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 }),
            b.ix,
          );
          const sigB = await sendAndConfirmTransaction(
            fx.er, txB, [bob.tradingKey], { commitment: "confirmed" },
          );
          txline("bob: submit_order SELL 30 @ 100", sigB, "er");
        });
        timer.markOrderAccepted();

        await timer.time("run_batch #1", "ER", async () => {
          const tx = new Transaction().add(
            ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
            buildRunBatchInstruction({
              programId: fx.meProgramId,
              vaultProgramId: fx.vaultProgramId,
              teeAuthority: fx.teeKeypair.publicKey,
              market: fx.market,
              pythAccount: fx.pythAccount,
              pendingOrderPdas: [aliceSlotPda, bobSlotPda, carolSlotPda],
            }),
          );
          const sig = await sendAndConfirmTransaction(
            fx.er, tx, [fx.teeKeypair], { commitment: "confirmed" },
          );
          txline("run_batch #1", sig, "er");
        });

        const aliceAfterBatch1Acct = await fx.er.getAccountInfo(aliceSlotPda, "confirmed");
        if (!aliceAfterBatch1Acct) throw new Error("Alice slot missing after batch 1");
        const aliceAfterBatch1 = decodePendingOrder(new Uint8Array(aliceAfterBatch1Acct.data));
        expect(aliceAfterBatch1.status).toBe(PENDING_STATUS_PENDING);
        expect(aliceAfterBatch1.amount).toBe(ALICE_BUY - BOB_SELL);
        expect(aliceAfterBatch1.noteAmount).toBe(EXPECTED_ALICE_REMAINDER);
        expect(
          Buffer.from(aliceAfterBatch1.collateralNote).equals(
            Buffer.from(alice.depositNote!.commitment),
          ),
        ).toBe(false);

        step(6, "batch 2 — submit Carol SELL 70 and run_batch again");
        await timer.time("submit_order Carol", "ER", async () => {
          const c = buildSubmitOrderInstruction({
            programId: fx.meProgramId,
            tradingKey: carol.tradingKey.publicKey,
            market: fx.market,
            slotIdx: SLOT,
            userCommitment: bn254ToBE32(carol.ownerCommit),
            noteCommitment: carol.depositNote!.commitment,
            amount: CAROL_SELL,
            priceLimit: PRICE,
            side: 1,
            noteAmount: carol.depositNote!.amount,
            expirySlot: expiry,
            orderId: carolOrderId,
            orderType: OrderType.Limit,
          });
          const tx = new Transaction().add(
            ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 }),
            c.ix,
          );
          const sig = await sendAndConfirmTransaction(
            fx.er, tx, [carol.tradingKey], { commitment: "confirmed" },
          );
          txline("carol: submit_order SELL 70 @ 100", sig, "er");
        });

        await timer.time("run_batch #2", "ER", async () => {
          const tx = new Transaction().add(
            ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
            buildRunBatchInstruction({
              programId: fx.meProgramId,
              vaultProgramId: fx.vaultProgramId,
              teeAuthority: fx.teeKeypair.publicKey,
              market: fx.market,
              pythAccount: fx.pythAccount,
              pendingOrderPdas: [aliceSlotPda, bobSlotPda, carolSlotPda],
            }),
          );
          const sig = await sendAndConfirmTransaction(
            fx.er, tx, [fx.teeKeypair], { commitment: "confirmed" },
          );
          txline("run_batch #2", sig, "er");
        });

        const aliceAfterBatch2Acct = await fx.er.getAccountInfo(aliceSlotPda, "confirmed");
        const carolAfterBatch2Acct = await fx.er.getAccountInfo(carolSlotPda, "confirmed");
        if (!aliceAfterBatch2Acct || !carolAfterBatch2Acct) {
          throw new Error("slot account missing after batch 2");
        }
        const aliceAfterBatch2 = decodePendingOrder(new Uint8Array(aliceAfterBatch2Acct.data));
        const carolAfterBatch2 = decodePendingOrder(new Uint8Array(carolAfterBatch2Acct.data));
        expect(aliceAfterBatch2.status).toBe(PENDING_STATUS_MATCHED);
        expect(aliceAfterBatch2.amount).toBe(0n);
        expect(carolAfterBatch2.status).toBe(PENDING_STATUS_MATCHED);
        expect(carolAfterBatch2.amount).toBe(0n);

        await timer.time("undelegate_market cleanup", "ER", async () => {
          const tx = new Transaction().add(
            ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
            buildUndelegateMarketInstruction({
              programId: fx.meProgramId,
              payer: fx.funder.publicKey,
              market: fx.market,
            }),
          );
          const sig = await sendAndConfirmTransaction(
            fx.er, tx, [fx.funder], { commitment: "confirmed" },
          );
          txline("undelegate_market", sig, "er");
        });

        timer.printSummary("multi-batch continuation");
      },
    );

    it(
      "E: real protocol-owner fee withdrawal E2E",
      { timeout: 900_000 },
      async () => {
        const timer = new StepTimer();
        banner("TEST E — real protocol-owner fee withdrawal");

        const PRICE = 100n;
        const BASE_AMT = 50n;
        const QUOTE_AMT = BASE_AMT * PRICE; // 5000
        const BUYER_FEE = (QUOTE_AMT * BigInt(fx.protocolFeeBps)) / 10_000n; // 15
        const SELLER_FEE = (BASE_AMT * BigInt(fx.protocolFeeBps)) / 10_000n; // 0
        const ALICE_DEPOSIT = QUOTE_AMT + BUYER_FEE; // 5015
        const BOB_DEPOSIT = BASE_AMT + SELLER_FEE;   // 50

        const previousProtocolCommitment = new Uint8Array(fx.protocolOwnerCommitment);
        const runSeed = freshRunSeed();
        const alice = await timer.time("derive Alice persona", "local", () => makePersona("alice", 0xF1, runSeed));
        const bob = await timer.time("derive Bob persona", "local", () => makePersona("bob", 0xF2, runSeed));
        const protocol = await timer.time("derive protocol-owner persona", "local", () => makePersona("protocol", 0xF3, runSeed));
        const protocolCommitment = bn254ToBE32(protocol.ownerCommit);
        const protocolQuoteAta = await getAssociatedTokenAddress(
          fx.quoteMint,
          protocol.payer.publicKey,
        );

        try {
          step(0, "reset_merkle_tree + set real protocol_owner_commitment");
          await timer.time("reset_merkle_tree", "L1", () => resetTreeFresh(fx));
          await timer.time("set_protocol_config(real owner commitment)", "L1", async () => {
            const tx = new Transaction().add(
              buildSetProtocolConfigInstruction({
                programId: fx.vaultProgramId,
                admin: fx.admin.publicKey,
                protocolOwnerCommitment: protocolCommitment,
                feeRateBps: fx.protocolFeeBps,
              }),
            );
            const sig = await sendAndConfirmTransaction(
              fx.l1, tx, [fx.admin], { commitment: "confirmed" },
            );
            txline("set_protocol_config(real protocol owner)", sig);
            fx.protocolOwnerCommitment = protocolCommitment;
          });

          step(1, "fund + mint + create protocol fee ATA");
          const atas = await fundAndMint(fx, alice, bob, ALICE_DEPOSIT, BOB_DEPOSIT, timer);
          const protocolBal = await fx.l1.getBalance(protocol.payer.publicKey);
          if (protocolBal < 500_000_000) {
            await timer.time("fund protocol payer", "L1", async () => {
              const sig = await sendAndConfirmTransaction(
                fx.l1,
                new Transaction().add(
                  SystemProgram.transfer({
                    fromPubkey: fx.funder.publicKey,
                    toPubkey: protocol.payer.publicKey,
                    lamports: 1_000_000_000 - protocolBal,
                  }),
                ),
                [fx.funder],
                { commitment: "confirmed" },
              );
              txline("funded protocol payer", sig);
            });
          }
          await timer.time("create protocol quote ATA", "L1", async () => {
            const tx = new Transaction().add(
              createAssociatedTokenAccountIdempotentInstruction(
                fx.admin.publicKey,
                protocolQuoteAta,
                protocol.payer.publicKey,
                fx.quoteMint,
              ),
            );
            const sig = await sendAndConfirmTransaction(
              fx.l1, tx, [fx.admin], { commitment: "confirmed" },
            );
            txline("created protocol quote ATA", sig);
          });

          step(2, "create_wallet + deposit + delegate slots/market");
          await ensureWallets(fx, alice, bob, timer);
          await timer.time("deposit ×2", "L1", async () => {
            await depositNote(fx, alice, fx.quoteMint, ALICE_DEPOSIT, atas.aliceQuoteAta);
            await depositNote(fx, bob, fx.baseMint, BOB_DEPOSIT, atas.bobBaseAta);
          });
          const SLOT = 2;
          const aliceSlotPda = await ensureSlot(fx, alice, SLOT);
          const bobSlotPda = await ensureSlot(fx, bob, SLOT);
          await ensureMarketDelegated(fx);

          step(3, "submit_order ×2 + run_batch");
          const aliceOrderId = alice.tradingKey.publicKey.toBytes().slice(0, 16);
          aliceOrderId[0] |= 0x80;
          const bobOrderId = bob.tradingKey.publicKey.toBytes().slice(0, 16);
          bobOrderId[0] |= 0x80;
          const now = await fx.l1.getSlot("confirmed");
          const expiry = BigInt(now) + 500n;

          await timer.time("submit_order Alice/Bob", "ER", async () => {
            const a = buildSubmitOrderInstruction({
              programId: fx.meProgramId,
              tradingKey: alice.tradingKey.publicKey,
              market: fx.market,
              slotIdx: SLOT,
              userCommitment: bn254ToBE32(alice.ownerCommit),
              noteCommitment: alice.depositNote!.commitment,
              amount: BASE_AMT,
              priceLimit: PRICE,
              side: 0,
              noteAmount: alice.depositNote!.amount,
              expirySlot: expiry,
              orderId: aliceOrderId,
              orderType: OrderType.Limit,
            });
            const b = buildSubmitOrderInstruction({
              programId: fx.meProgramId,
              tradingKey: bob.tradingKey.publicKey,
              market: fx.market,
              slotIdx: SLOT,
              userCommitment: bn254ToBE32(bob.ownerCommit),
              noteCommitment: bob.depositNote!.commitment,
              amount: BASE_AMT,
              priceLimit: PRICE,
              side: 1,
              noteAmount: bob.depositNote!.amount,
              expirySlot: expiry,
              orderId: bobOrderId,
              orderType: OrderType.Limit,
            });
            const txA = new Transaction().add(
              ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 }),
              a.ix,
            );
            const sigA = await sendAndConfirmTransaction(
              fx.er, txA, [alice.tradingKey], { commitment: "confirmed" },
            );
            txline("alice: submit_order BUY 50 @ 100", sigA, "er");
            const txB = new Transaction().add(
              ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 }),
              b.ix,
            );
            const sigB = await sendAndConfirmTransaction(
              fx.er, txB, [bob.tradingKey], { commitment: "confirmed" },
            );
            txline("bob: submit_order SELL 50 @ 100", sigB, "er");
          });
          timer.markOrderAccepted();

          const [batchPda] = batchResultsPda(fx.meProgramId, fx.market);
          const preAcct = await fx.l1.getAccountInfo(batchPda, "confirmed");
          const preHash = preAcct ? Buffer.from(preAcct.data).toString("hex") : null;

          await timer.time("run_batch", "ER", async () => {
            const tx = new Transaction().add(
              ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
              buildRunBatchInstruction({
                programId: fx.meProgramId,
                vaultProgramId: fx.vaultProgramId,
                teeAuthority: fx.teeKeypair.publicKey,
                market: fx.market,
                pythAccount: fx.pythAccount,
                pendingOrderPdas: [aliceSlotPda, bobSlotPda],
              }),
            );
            const sig = await sendAndConfirmTransaction(
              fx.er, tx, [fx.teeKeypair], { commitment: "confirmed" },
            );
            txline("run_batch", sig, "er");
          });

          await timer.time("undelegate_market + L1 commit poll", "ER+L1", async () => {
            const tx = new Transaction().add(
              ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
              buildUndelegateMarketInstruction({
                programId: fx.meProgramId,
                payer: fx.funder.publicKey,
                market: fx.market,
              }),
            );
            const sig = await sendAndConfirmTransaction(
              fx.er, tx, [fx.funder], { commitment: "confirmed" },
            );
            txline("undelegate_market", sig, "er");
            await waitForL1AccountChange(fx.l1, batchPda, preHash, {
              timeoutMs: 90_000, intervalMs: 1_000,
            });
          });

          const brAcct = await fx.l1.getAccountInfo(batchPda, "confirmed");
          if (!brAcct) throw new Error("BatchResults missing after undelegate");
          const view = decodeBatchResults(new Uint8Array(brAcct.data));
          const filled = view.results.find(
            (r) =>
              r.status === 1 &&
              Buffer.from(r.ownerBuyer).equals(alice.tradingKey.publicKey.toBuffer()) &&
              Buffer.from(r.ownerSeller).equals(bob.tradingKey.publicKey.toBuffer()),
          );
          if (!filled) throw new Error("no filled MatchResult for this run");
          const matchId = filled.matchId;

          step(4, "build payload + lock_note×2 + tee_forced_settle");
          const noteCnonce = deriveNonce(matchId, TRADE_ROLE_BUYER);
          const noteCblind = deriveBlinding(matchId, TRADE_ROLE_BUYER);
          const noteCcommitment = await noteCommitment({
            tokenMint: fx.baseMint.toBytes(), amount: BASE_AMT,
            ownerCommitment: alice.ownerCommit,
            nonce: be32ToBigInt(noteCnonce), blindingR: be32ToBigInt(noteCblind),
          });

          const noteDnonce = deriveNonce(matchId, TRADE_ROLE_SELLER);
          const noteDblind = deriveBlinding(matchId, TRADE_ROLE_SELLER);
          const noteDcommitment = await noteCommitment({
            tokenMint: fx.quoteMint.toBytes(), amount: QUOTE_AMT,
            ownerCommitment: bob.ownerCommit,
            nonce: be32ToBigInt(noteDnonce), blindingR: be32ToBigInt(noteDblind),
          });

          const slot = await fx.l1.getSlot("confirmed");
          const feeNonce = deriveNonce(BigInt(slot), FEE_ROLE_QUOTE);
          const feeBlind = deriveBlinding(BigInt(slot), FEE_ROLE_QUOTE);
          const feeCommitment = await noteCommitment({
            tokenMint: fx.quoteMint.toBytes(), amount: BUYER_FEE,
            ownerCommitment: protocol.ownerCommit,
            nonce: be32ToBigInt(feeNonce), blindingR: be32ToBigInt(feeBlind),
          });

          const nullA = await nullifier(alice.spendingKey, alice.depositNote!.commitment);
          const nullB = await nullifier(bob.spendingKey, bob.depositNote!.commitment);

          const payload: MatchResultPayload = exactFillPayload({
            matchId: asU8a16(matchId),
            noteAcommitment: alice.depositNote!.commitment,
            noteBcommitment: bob.depositNote!.commitment,
            noteCcommitment,
            noteDcommitment,
            nullifierA: nullA,
            nullifierB: nullB,
            orderIdA: aliceOrderId,
            orderIdB: bobOrderId,
            baseAmount: BASE_AMT,
            quoteAmount: QUOTE_AMT,
          });
          payload.buyerFeeAmt = BUYER_FEE;
          payload.sellerFeeAmt = SELLER_FEE;
          payload.noteFeeCommitment = feeCommitment;

          const msg = canonicalPayloadHash(payload);
          const teeSig = teeSign(fx.teeKeypair, msg);

          // v2: per-side VALID_INPUT proofs gating lock_note.
          const aliceWitness3 = await fx.tree.witness(alice.depositNote!.leafIndex);
          const aliceVI3 = await proveValidInput({
            repoRoot: REPO_ROOT,
            spendingKey: alice.spendingKey,
            ownerCommitmentBlinding: alice.ownerBlinding,
            nonce: alice.depositNote!.nonce,
            blindingR: alice.depositNote!.blindingR,
            tokenMint: alice.depositNote!.mint.toBytes(),
            amount: alice.depositNote!.amount,
            merkleRootBE: aliceWitness3.root,
            merkleWitness: {
              pathElements: aliceWitness3.siblings.map(be32ToBigInt),
              pathIndices: aliceWitness3.indices,
            },
          });
          const bobWitness3 = await fx.tree.witness(bob.depositNote!.leafIndex);
          const bobVI3 = await proveValidInput({
            repoRoot: REPO_ROOT,
            spendingKey: bob.spendingKey,
            ownerCommitmentBlinding: bob.ownerBlinding,
            nonce: bob.depositNote!.nonce,
            blindingR: bob.depositNote!.blindingR,
            tokenMint: bob.depositNote!.mint.toBytes(),
            amount: bob.depositNote!.amount,
            merkleRootBE: bobWitness3.root,
            merkleWitness: {
              pathElements: bobWitness3.siblings.map(be32ToBigInt),
              pathIndices: bobWitness3.indices,
            },
          });

          await timer.time("lock_note ×2", "L1", async () => {
            const tx = new Transaction().add(
              ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }),
              buildLockNoteInstruction({
                programId: fx.vaultProgramId,
                teeAuthority: fx.teeKeypair.publicKey,
                noteCommitment: alice.depositNote!.commitment,
                orderId: aliceOrderId,
                expirySlot: expiry,
                amount: ALICE_DEPOSIT,
                tokenMint: alice.depositNote!.mint,
                merkleRoot: aliceWitness3.root,
                proof: aliceVI3.proof,
              }),
              buildLockNoteInstruction({
                programId: fx.vaultProgramId,
                teeAuthority: fx.teeKeypair.publicKey,
                noteCommitment: bob.depositNote!.commitment,
                orderId: bobOrderId,
                expirySlot: expiry,
                amount: BOB_DEPOSIT,
                tokenMint: bob.depositNote!.mint,
                merkleRoot: bobWitness3.root,
                proof: bobVI3.proof,
              }),
            );
            const sig = await sendAndConfirmTransaction(
              fx.l1, tx, [fx.teeKeypair], { commitment: "confirmed" },
            );
            txline("lock_note(note_a) + lock_note(note_b)", sig);
          });

          if (USE_BATCHED_PROOF) {
            // ── v3.5 batched path — exact-fill variant (no change notes).
            // Real protocol owner is set; the fee leaf is appended at the
            // end. Drives the same batched flow as the trade-flow test.
            if (!fx.settleLookupTable) {
              throw new Error("e2e-config.json missing settleLookupTable — rerun devnet-setup");
            }
            await timer.time("v3.5 batched settle (exact fill)", "L1", async () => {
              const ZERO_32 = new Uint8Array(32);
              const realSlot: MatchSlotWitness = {
                noteAcommitment: alice.depositNote!.commitment,
                noteBcommitment: bob.depositNote!.commitment,
                noteCcommitment,
                noteDcommitment,
                noteEcommitment: ZERO_32,
                noteFcommitment: ZERO_32,
                quoteMint: fx.quoteMint.toBytes(),
                baseMint: fx.baseMint.toBytes(),
                baseAmount: BASE_AMT,
                quoteAmount: QUOTE_AMT,
                buyerChangeAmt: 0n,
                sellerChangeAmt: 0n,
                buyerFeeAmt: BUYER_FEE,
                sellerFeeAmt: SELLER_FEE,
                batchSlot: payload.batchSlot,
                aOwnerCommit: alice.ownerCommit,
                bOwnerCommit: bob.ownerCommit,
                aAmount: alice.depositNote!.amount,
                bAmount: bob.depositNote!.amount,
                aNonce: alice.depositNote!.nonce,
                aBlinding: alice.depositNote!.blindingR,
                bNonce: bob.depositNote!.nonce,
                bBlinding: bob.depositNote!.blindingR,
                cNonce: be32ToBigInt(noteCnonce),
                cBlinding: be32ToBigInt(noteCblind),
                dNonce: be32ToBigInt(noteDnonce),
                dBlinding: be32ToBigInt(noteDblind),
                eNonce: 0n,
                eBlinding: 0n,
                fNonce: 0n,
                fBlinding: 0n,
                clearingPrice: QUOTE_AMT / BASE_AMT,
              };
              await settleViaBatched({
                connection: fx.l1,
                vaultProgramId: fx.vaultProgramId,
                teeKeypair: fx.teeKeypair,
                realSlot,
                payload,
                teeSig,
                canonicalHash: msg,
                settleLookupTable: fx.settleLookupTable!,
                repoRoot: REPO_ROOT,
                onTx: txline,
              });
            });
          } else {
          // v3: VALID_CREATE — Test E is exact fill, no change.
          {
            const ZERO_32 = new Uint8Array(32);
            const vcArgs = {
              noteA: alice.depositNote!.commitment,
              noteB: bob.depositNote!.commitment,
              noteC: noteCcommitment,
              noteD: noteDcommitment,
              noteE: ZERO_32,
              noteF: ZERO_32,
              quoteMint: fx.quoteMint.toBytes(),
              baseMint: fx.baseMint.toBytes(),
              baseAmount: BASE_AMT,
              quoteAmount: QUOTE_AMT,
              buyerChangeAmt: 0n,
              sellerChangeAmt: 0n,
              buyerFeeAmt: BUYER_FEE,
              sellerFeeAmt: SELLER_FEE,
            };
            const validCreate = await proveValidCreate({
              repoRoot: REPO_ROOT,
              quoteMint: fx.quoteMint.toBytes(),
              baseMint: fx.baseMint.toBytes(),
              inputA: { ownerCommit: alice.ownerCommit, amount: alice.depositNote!.amount,
                        nonce: alice.depositNote!.nonce, blindingR: alice.depositNote!.blindingR },
              inputAcommitmentBE: alice.depositNote!.commitment,
              inputB: { ownerCommit: bob.ownerCommit, amount: bob.depositNote!.amount,
                        nonce: bob.depositNote!.nonce, blindingR: bob.depositNote!.blindingR },
              inputBcommitmentBE: bob.depositNote!.commitment,
              outputC: { ownerCommit: alice.ownerCommit, amount: BASE_AMT,
                         nonce: be32ToBigInt(noteCnonce), blindingR: be32ToBigInt(noteCblind) },
              outputCcommitmentBE: noteCcommitment,
              outputD: { ownerCommit: bob.ownerCommit, amount: QUOTE_AMT,
                         nonce: be32ToBigInt(noteDnonce), blindingR: be32ToBigInt(noteDblind) },
              outputDcommitmentBE: noteDcommitment,
              outputE: undefined, outputEcommitmentBE: ZERO_32,
              outputF: undefined, outputFcommitmentBE: ZERO_32,
              baseAmount: BASE_AMT, quoteAmount: QUOTE_AMT,
              buyerChangeAmt: 0n, sellerChangeAmt: 0n,
              buyerFeeAmt: BUYER_FEE, sellerFeeAmt: SELLER_FEE,
            });
            const binding = validCreateBindingHash(vcArgs);
            const markerExpiry = BigInt((await fx.l1.getSlot("confirmed")) + 200);
            const verifyTx = new Transaction().add(
              ComputeBudgetProgram.setComputeUnitLimit({ units: 600_000 }),
              buildVerifyValidCreateInstruction({
                programId: fx.vaultProgramId, payer: fx.teeKeypair.publicKey,
                bindingHash: binding,
                noteAcommitment: alice.depositNote!.commitment,
                noteBcommitment: bob.depositNote!.commitment,
                noteCcommitment, noteDcommitment,
                noteEcommitment: ZERO_32, noteFcommitment: ZERO_32,
                quoteMint: fx.quoteMint, baseMint: fx.baseMint,
                baseAmount: BASE_AMT, quoteAmount: QUOTE_AMT,
                buyerChangeAmt: 0n, sellerChangeAmt: 0n,
                buyerFeeAmt: BUYER_FEE, sellerFeeAmt: SELLER_FEE,
                expirySlot: markerExpiry, proof: validCreate.proof,
              }),
            );
            await sendAndConfirmTransaction(fx.l1, verifyTx, [fx.teeKeypair], { commitment: "confirmed" });
          }

          const priceMarker = await landVerifyValidPrice({
            connection: fx.l1,
            vaultProgramId: fx.vaultProgramId,
            teeKeypair: fx.teeKeypair,
            payload,
            repoRoot: REPO_ROOT,
          });
          txline("verify_valid_price", priceMarker.txSig);

          await timer.time("Ed25519 + tee_forced_settle", "L1", async () => {
            // v3 v0/ALT path — keeps every settle uniform across tests.
            if (!fx.settleLookupTable) {
              throw new Error("e2e-config.json missing settleLookupTable — rerun devnet-setup");
            }
            const sig = await sendSettleV0({
              connection: fx.l1,
              signer: fx.teeKeypair,
              altPubkey: fx.settleLookupTable,
              instructions: [
                ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
                buildEd25519VerifyIx({
                  teePubkey: fx.teeKeypair.publicKey.toBytes(),
                  signature: teeSig,
                  message: msg,
                }),
                buildSettleIx({
                  programId: fx.vaultProgramId,
                  teeAuthority: fx.teeKeypair.publicKey,
                  payload,
                  quoteMint: fx.quoteMint, baseMint: fx.baseMint,
                  priceCommitment: priceMarker.priceCommitment,
                }),
              ],
            });
            txline("Ed25519 + tee_forced_settle (v0)", sig);
          });
          }

          await fx.tree.append(noteCcommitment);
          await fx.tree.append(noteDcommitment);
          await fx.tree.append(feeCommitment);
          const protocolFeeNote = {
            mint: fx.quoteMint,
            amount: BUYER_FEE,
            nonce: feeNonce,
            blindingR: feeBlind,
            commitment: feeCommitment,
            leafIndex: fx.tree.leafCount - 1,
          };

          step(5, "protocol-owner withdraws fee note");
          await timer.time("VALID_SPEND + fee withdraw", "L1", async () => {
            await proveAndWithdraw(
              fx,
              protocol,
              protocolFeeNote,
              protocolQuoteAta,
              protocol.payer,
              protocol.ownerBlinding,
              "Protocol owner → QUOTE fee",
            );
          });
          timer.markFirstWithdraw();
          const protocolBalAfter = await fx.l1.getTokenAccountBalance(protocolQuoteAta);
          expect(BigInt(protocolBalAfter.value.amount)).toBeGreaterThanOrEqual(BUYER_FEE);

          timer.printSummary("real protocol-owner fee withdrawal");
        } finally {
          const restoreTx = new Transaction().add(
            buildSetProtocolConfigInstruction({
              programId: fx.vaultProgramId,
              admin: fx.admin.publicKey,
              protocolOwnerCommitment: previousProtocolCommitment,
              feeRateBps: fx.protocolFeeBps,
            }),
          );
          const restoreSig = await sendAndConfirmTransaction(
            fx.l1, restoreTx, [fx.admin], { commitment: "confirmed" },
          );
          txline("restore set_protocol_config (original commitment)", restoreSig);
          fx.protocolOwnerCommitment = previousProtocolCommitment;
        }
      },
    );
  },
);

// ───────────────────────────────────────────────────────────────────────────
// Withdraw helper (VALID_SPEND + buildWithdrawInstruction)
// ───────────────────────────────────────────────────────────────────────────

async function proveAndWithdraw(
  fx: Fixture,
  p: Persona,
  trade: { mint: PublicKey; amount: bigint; nonce: Uint8Array; blindingR: Uint8Array; commitment: Uint8Array; leafIndex: number },
  destAta: PublicKey,
  payerKp: Keypair,
  ownerCommitBlinding: bigint,
  label: string,
) {
  substep(`${label}: proving VALID_SPEND`);
  const w = await fx.tree.witness(trade.leafIndex);
  const [mLo, mHi] = pubkeyToFrPair(trade.mint.toBytes());
  const nulli = await nullifier(p.spendingKey, trade.commitment);
  const { proof } = snarkjsFullProve(
    {
      merkleRoot: be32ToDec(w.root),
      nullifier: be32ToDec(nulli),
      tokenMint: [mLo.toString(), mHi.toString()],
      amount: trade.amount.toString(),
      spendingKey: p.spendingKey.toString(),
      ownerCommitmentBlinding: ownerCommitBlinding.toString(),
      nonce: be32ToBigInt(trade.nonce).toString(),
      blindingR: be32ToBigInt(trade.blindingR).toString(),
      merklePath: w.siblings.map((s) => be32ToDec(s)),
      merkleIndices: w.indices.map((i) => i.toString()),
    },
    { circuitWasmPath: SPEND_WASM, circuitZkeyPath: SPEND_ZKEY, repoRoot: REPO_ROOT },
  );
  const ix = buildWithdrawInstruction({
    programId: fx.vaultProgramId, payer: payerKp.publicKey,
    tokenMint: trade.mint, destinationTokenAccount: destAta,
    tokenProgramId: TOKEN_PROGRAM_ID,
    noteCommitment: trade.commitment,
    nullifier: nulli, merkleRoot: w.root,
    amount: trade.amount, proof,
  });
  const tx = new Transaction().add(
    ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
    ix,
  );
  const sig = await sendAndConfirmTransaction(fx.l1, tx, [payerKp], { commitment: "confirmed" });
  txline(`${label}: withdraw`, sig);
}
