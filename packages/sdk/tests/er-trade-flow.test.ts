/**
 * Phase-5 Nyx Darkpool — ER (Ephemeral Rollup) E2E trade flow.
 *
 * Mirror of `devnet-trade-flow.test.ts` but routes `run_batch` through the
 * MagicBlock Ephemeral Rollup instead of L1. The overall sequence is:
 *
 *   Steps 1-6  (L1): fund / mint / wallets / deposits / submit_order  x2
 *                    DarkCLOB + MatchingConfig + BatchResults are NOT yet
 *                    delegated — `submit_order` needs L1 because it CPIs
 *                    `vault::lock_note` which creates new `note_lock` PDAs.
 *
 *   Step 7    (L1): delegate_dark_clob + delegate_matching_config +
 *                    delegate_batch_results — atomic 3-ix tx that hands
 *                    the three PDAs to the ER validator.
 *
 *   Step 8    (ER): run_batch — finds the crossing, writes MatchResult +
 *                    FeeAccumulator state inside the ER session.
 *
 *   Step 9    (ER): undelegate_market — CPIs
 *                    `ScheduleCommitAndUndelegate` on the MagicBlock magic
 *                    program. The validator will push the new state back
 *                    to L1 and return the three PDAs to ordinary L1
 *                    ownership.
 *
 *   Step 10   (L1 poll): wait for L1 BatchResults to reflect the commit.
 *
 *   Steps 11-13 (L1): build MatchResultPayload, tee_forced_settle, withdraw.
 *
 * Gated on RUN_ER_E2E=1 and ER_RPC_URL (defaults to
 * https://devnet.magicblock.app). Requires a fully-funded funder and a
 * completed `devnet-setup.test.ts` run (fresh market + reset tree).
 */

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

import { config as dotenvConfig } from "dotenv";
import { beforeAll, describe, expect, it } from "vitest";
import nacl from "tweetnacl";
import {
  createAssociatedTokenAccountIdempotentInstruction,
  createAssociatedTokenAccountInstruction,
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
  buildVerifyValidCreateInstruction,
  buildWithdrawInstruction,
  vaultConfigPda,
  walletEntryPda,
} from "../src/idl/vault-client.js";
import {
  buildRunBatchInstruction,
  buildSubmitOrderInstruction,
  buildInitPendingOrderSlotInstruction,
  buildDelegatePendingOrderInstruction,
  batchResultsPda,
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
  buildLockNoteInstruction,
} from "../src/idl/vault-client.js";
import {
  buildEd25519VerifyIx,
  buildSettleIx,
  canonicalPayloadHash,
  exactFillPayload,
  validCreateBindingHash,
  type MatchResultPayload,
} from "../src/settlement/settle-builder.js";

import { snarkjsFullProve } from "./helpers/snarkjs-prover.js";
import { MerkleShadow } from "./helpers/merkle-shadow.js";
import { proveValidInput } from "./helpers/valid-input-prover.js";
import { proveValidCreate } from "./helpers/valid-create-prover.js";
import {
  be32ToBigInt,
  be32ToDec,
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

const RUN = process.env.RUN_ER_E2E === "1";

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
// Narrative logging
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
}

async function makePersona(name: string, seed0: number): Promise<Persona> {
  // ER test uses a DIFFERENT pair of user-persona keypairs so it doesn't
  // conflict with the L1 devnet-trade-flow.test's already-registered
  // WalletEntry PDAs (create_wallet is idempotent-skip but then the deposit
  // note collides with note_lock on L1 if both tests run against the same
  // devnet state). Keeping the suffix `-er` keeps the two test surfaces
  // cleanly isolated on the same shared devnet.
  const payerPath = resolve(REPO_ROOT, `.devnet/keypairs/${name}-er-payer.json`);
  const tradingPath = resolve(REPO_ROOT, `.devnet/keypairs/${name}-er-trading.json`);
  const payer = loadOrCreateKeypair(payerPath);
  const tradingKey = loadOrCreateKeypair(tradingPath);
  const masterSeed = new Uint8Array(64);
  for (let i = 0; i < 64; i++) masterSeed[i] = (seed0 + i * 7) & 0xff;
  const spendingKey = deriveSpendingKey(masterSeed);
  const viewingKey = deriveMasterViewingKey(masterSeed);
  const ownerBlinding = BigInt(seed0) + 0xBEEFBEEFn;
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

// ───────────────────────────────────────────────────────────────────────────
// TEE simulator
// ───────────────────────────────────────────────────────────────────────────

interface TeeSim {
  keypair: Keypair;
  signCanonical(msg: Uint8Array): Uint8Array;
}
function makeTeeSim(keypair: Keypair): TeeSim {
  return {
    keypair,
    signCanonical(msg: Uint8Array): Uint8Array {
      if (msg.length !== 32) throw new Error("canonical hash must be 32 bytes");
      return nacl.sign.detached(msg, keypair.secretKey);
    },
  };
}

// ───────────────────────────────────────────────────────────────────────────

maybeDescribe(
  "Phase 5 ER E2E — delegate → run_batch in ER → commit+undelegate → settle on L1",
  () => {
    let l1: Connection;
    let er: Connection;
    let cfg: E2EConfig;
    let admin: Keypair;
    let funder: Keypair;
    let teeKeypair: Keypair;
    let tee: TeeSim;
    let vaultProgramId: PublicKey;
    let meProgramId: PublicKey;
    let market: PublicKey;
    let baseMint: PublicKey;
    let quoteMint: PublicKey;
    let pythAccount: PublicKey;
    let protocolOwnerCommitment: Uint8Array;
    let protocolFeeBps: number;
    let tree: MerkleShadow;
    let alice: Persona;
    let bob: Persona;

    beforeAll(async () => {
      cfg = JSON.parse(readFileSync(CONFIG_PATH, "utf8")) as E2EConfig;
      const conns = openDualConnections(cfg.l1RpcUrl, ER_RPC_URL, "confirmed");
      l1 = conns.l1;
      er = conns.er;

      admin = loadKeypairRel(REPO_ROOT, requireEnv("ADMIN_KEYPAIR"));
      teeKeypair = loadKeypairRel(REPO_ROOT, requireEnv("TEE_AUTHORITY_KEYPAIR"));
      tee = makeTeeSim(teeKeypair);

      const funderPath = process.env.FUNDER_KEYPAIR;
      if (funderPath) {
        funder = funderPath.startsWith("/") || funderPath.startsWith("~")
          ? loadKeypairFileExpand(funderPath)
          : loadKeypairRel(REPO_ROOT, funderPath);
      } else {
        funder = admin;
      }

      vaultProgramId = new PublicKey(cfg.vaultProgramId);
      meProgramId = new PublicKey(cfg.matchingEngineProgramId);
      pythAccount = new PublicKey(cfg.pythAccount);
      market = new PublicKey(cfg.market.pubkey);
      baseMint = new PublicKey(cfg.baseMint.pubkey);
      quoteMint = new PublicKey(cfg.quoteMint.pubkey);
      protocolOwnerCommitment = new Uint8Array(
        Buffer.from(cfg.protocol.ownerCommitmentHex, "hex"),
      );
      protocolFeeBps = cfg.protocol.feeRateBps;

      tree = await MerkleShadow.create();

      banner("NYX DARKPOOL — ER E2E (L1 → delegate → ER run_batch → commit+undelegate → L1)");
      bullet(`L1 RPC: ${cfg.l1RpcUrl}`);
      bullet(`ER RPC: ${ER_RPC_URL}`);
      bullet(`market: ${market.toBase58()}`);
      bullet(`TEE:    ${teeKeypair.publicKey.toBase58()}`);
      bullet(`funder: ${funder.publicKey.toBase58()}`);
      const funderBal = await l1.getBalance(funder.publicKey);
      bullet(`funder balance: ${(funderBal / 1e9).toFixed(4)} SOL`);
      if (funderBal < 0.4 * 1e9) {
        throw new Error(
          `funder has < 0.4 SOL (ER flow needs more for delegate PDAs); ` +
          `fund first or set FUNDER_KEYPAIR=<path-to-keypair-with-sol>`,
        );
      }
    }, 60_000);

    it(
      "happy-path exact fill via ER: 50 base @ 100 quote/base, 30 bps fee",
      { timeout: 900_000 },
      async () => {
        // ─────────────────────────────────────────────────────────────────
        step(1, "Generate ER personas (independent from L1-only personas)");
        // ─────────────────────────────────────────────────────────────────
        alice = await makePersona("alice", 0xA1);
        bob = await makePersona("bob", 0xB0);
        for (const p of [alice, bob]) {
          bullet(`${p.name.padEnd(6)} payer:        ${p.payer.publicKey.toBase58()}`);
          bullet(`${p.name.padEnd(6)} userCommitment: 0x${toHex(p.userCommitment)}`);
        }

        // ─────────────────────────────────────────────────────────────────
        step(2, "Fund Alice + Bob (L1) — idempotent top-up");
        // ─────────────────────────────────────────────────────────────────
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
          const b = await l1.getBalance(t.to);
          if (b < t.min) {
            const delta = t.target - b;
            bullet(`${t.label.padEnd(16)} ${(b / 1e9).toFixed(4)} SOL — top up ${(delta / 1e9).toFixed(4)}`);
            ixs.push(SystemProgram.transfer({
              fromPubkey: funder.publicKey, toPubkey: t.to, lamports: delta,
            }));
            total += delta;
          } else {
            bullet(`${t.label.padEnd(16)} ${(b / 1e9).toFixed(4)} SOL — skip`);
          }
        }
        if (ixs.length > 0) {
          const fs = await sendAndConfirmTransaction(
            l1, new Transaction().add(...ixs), [funder], { commitment: "confirmed" },
          );
          txline(`funder transferred ${(total / 1e9).toFixed(4)} SOL`, fs);
        }

        // ─────────────────────────────────────────────────────────────────
        step(3, "Mint deposits (L1)");
        // ─────────────────────────────────────────────────────────────────
        const BASE_AMT = 50n;
        const PRICE = 100n;
        const QUOTE_AMT = BASE_AMT * PRICE; // 5000
        const BUYER_FEE = (QUOTE_AMT * BigInt(protocolFeeBps)) / 10_000n; // 15
        const SELLER_FEE = (BASE_AMT * BigInt(protocolFeeBps)) / 10_000n; // 0
        const ALICE_DEPOSIT = QUOTE_AMT + BUYER_FEE; // 5015
        const BOB_DEPOSIT = BASE_AMT + SELLER_FEE;   // 50

        bullet(`base_amt=${BASE_AMT}, price=${PRICE}, quote_amt=${QUOTE_AMT}`);
        bullet(`Alice deposits ${ALICE_DEPOSIT} QUOTE (BUY), Bob deposits ${BOB_DEPOSIT} BASE (SELL)`);

        const aliceQuoteAta = await getAssociatedTokenAddress(quoteMint, alice.payer.publicKey);
        const bobBaseAta    = await getAssociatedTokenAddress(baseMint,  bob.payer.publicKey);
        const aliceBaseAta  = await getAssociatedTokenAddress(baseMint,  alice.payer.publicKey);
        const bobQuoteAta   = await getAssociatedTokenAddress(quoteMint, bob.payer.publicKey);

        const ataTx = new Transaction().add(
          createAssociatedTokenAccountIdempotentInstruction(admin.publicKey, aliceQuoteAta, alice.payer.publicKey, quoteMint),
          createAssociatedTokenAccountIdempotentInstruction(admin.publicKey, aliceBaseAta,  alice.payer.publicKey, baseMint),
          createAssociatedTokenAccountIdempotentInstruction(admin.publicKey, bobBaseAta,    bob.payer.publicKey,   baseMint),
          createAssociatedTokenAccountIdempotentInstruction(admin.publicKey, bobQuoteAta,   bob.payer.publicKey,   quoteMint),
          createMintToInstruction(quoteMint, aliceQuoteAta, admin.publicKey, Number(ALICE_DEPOSIT)),
          createMintToInstruction(baseMint,  bobBaseAta,    admin.publicKey, Number(BOB_DEPOSIT)),
        );
        const ataSig = await sendAndConfirmTransaction(l1, ataTx, [admin], { commitment: "confirmed" });
        txline("created ATAs + minted balances", ataSig);

        // ─────────────────────────────────────────────────────────────────
        step(4, "Create WalletEntry PDAs on L1 (skips if already present)");
        // ─────────────────────────────────────────────────────────────────
        for (const p of [alice, bob]) {
          const [wpda] = walletEntryPda(vaultProgramId, p.userCommitment);
          const ex = await l1.getAccountInfo(wpda);
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
              programId: vaultProgramId, owner: p.payer.publicKey,
              commitment: p.userCommitment, proof,
            }),
          );
          const cwSig = await sendAndConfirmTransaction(l1, cwTx, [p.payer], { commitment: "confirmed" });
          txline(`${p.name}: create_wallet`, cwSig);
        }

        // ─────────────────────────────────────────────────────────────────
        step(5, "Deposit notes (L1) — appends note_a + note_b to vault tree");
        // ─────────────────────────────────────────────────────────────────
        async function depositNote(p: Persona, mint: PublicKey, amount: bigint, ata: PublicKey) {
          substep(`${p.name}: depositing ${amount}`);
          const [vPda] = vaultConfigPda(vaultProgramId);
          const info = await l1.getAccountInfo(vPda);
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
            programId: vaultProgramId, depositor: p.payer.publicKey,
            tokenMint: mint, depositorTokenAccount: ata, tokenProgramId: TOKEN_PROGRAM_ID,
            amount,
            ownerCommitment: bn254ToBE32(p.ownerCommit),
            nonce: bn254ToBE32(nonce),
            blindingR: bn254ToBE32(blindingR),
          });
          const sig = await sendAndConfirmTransaction(
            l1, new Transaction().add(ix), [p.payer], { commitment: "confirmed" },
          );
          txline(`${p.name}: deposit`, sig);
          await tree.append(c);
          p.depositNote = { mint, amount, nonce, blindingR, commitment: c, leafIndex };
        }
        await depositNote(alice, quoteMint, ALICE_DEPOSIT, aliceQuoteAta);
        await depositNote(bob, baseMint, BOB_DEPOSIT, bobBaseAta);

        // ─────────────────────────────────────────────────────────────────
        step(6, "init + delegate PendingOrder slots (L1) — privacy-fix setup");
        // ─────────────────────────────────────────────────────────────────
        noteLine(
          "One PendingOrder PDA per (user, market, slot_idx). Created EMPTY " +
          "on L1 — the L1 init tx contains zero order intent. Then handed " +
          "to the ER validator. From this point on the slot is only " +
          "writable inside the ER session.",
        );
        const ALICE_SLOT = 0;
        const BOB_SLOT = 0;
        for (const [persona, slotIdx] of [
          [alice, ALICE_SLOT] as const,
          [bob, BOB_SLOT] as const,
        ]) {
          const [slotPda] = pendingOrderPda(
            meProgramId,
            market,
            persona.tradingKey.publicKey,
            slotIdx,
          );
          const existingSlot = await l1.getAccountInfo(slotPda, "confirmed");
          if (existingSlot && existingSlot.owner.toBase58() !== meProgramId.toBase58()) {
            // Slot already delegated from a prior run — skip both ixs.
            bullet(`${persona.name} slot[${slotIdx}] already delegated — skip`);
            continue;
          }
          const initTx = new Transaction().add(
            buildInitPendingOrderSlotInstruction({
              programId: meProgramId,
              tradingKey: persona.tradingKey.publicKey,
              market,
              slotIdx,
            }),
          );
          const initSig = await sendAndConfirmTransaction(
            l1, initTx, [persona.tradingKey], { commitment: "confirmed" },
          );
          txline(`${persona.name}: init_pending_order_slot[${slotIdx}]`, initSig);

          const delSlotTx = new Transaction().add(
            buildDelegatePendingOrderInstruction({
              programId: meProgramId,
              payer: funder.publicKey,
              tradingKey: persona.tradingKey.publicKey,
              market,
              slotIdx,
            }),
          );
          const delSlotSig = await sendAndConfirmTransaction(
            l1, delSlotTx, [funder, persona.tradingKey], { commitment: "confirmed" },
          );
          txline(`${persona.name}: delegate_pending_order[${slotIdx}]`, delSlotSig);
        }

        // ─────────────────────────────────────────────────────────────────
        step(7, "DELEGATE market PDAs (L1) — DarkCLOB + MatchingConfig + BatchResults");
        // ─────────────────────────────────────────────────────────────────
        noteLine(
          "Three independent delegate ixs bundled into one tx. Each CPIs the " +
          "delegation program, which copies the PDA's data to a per-program " +
          "buffer, zeroes the original, and assigns ownership to the ER " +
          "validator. Until we commit_and_undelegate, these accounts are " +
          "writable only inside the ER session.",
        );
        const delTx = new Transaction().add(
          ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
          buildDelegateDarkClobInstruction({
            programId: meProgramId, payer: funder.publicKey, market,
          }),
          buildDelegateMatchingConfigInstruction({
            programId: meProgramId, payer: funder.publicKey, market,
          }),
          buildDelegateBatchResultsInstruction({
            programId: meProgramId, payer: funder.publicKey, market,
          }),
        );
        const delSig = await sendAndConfirmTransaction(
          l1, delTx, [funder], { commitment: "confirmed" },
        );
        txline("delegated DarkCLOB + MatchingConfig + BatchResults to ER validator", delSig);

        // ─────────────────────────────────────────────────────────────────
        step(8, "submit_order x2 (ER) — order intents stay inside the rollup");
        // ─────────────────────────────────────────────────────────────────
        noteLine(
          "This is the privacy-fix payoff. submit_order writes (side, amount, " +
          "price_limit, note_commitment) directly into the delegated " +
          "PendingOrder slot. Tx is sent to the ER RPC — order details NEVER " +
          "appear in any L1 transaction log. In production this goes through " +
          "the authenticated PER session (JWT-gated); the test signs with " +
          "the trading_key and routes via the same ER connection.",
        );
        const aliceOrderId = new Uint8Array(16); aliceOrderId[0] = 0xA1;
        const bobOrderId   = new Uint8Array(16); bobOrderId[0]   = 0xB0;
        const now = await l1.getSlot("confirmed");
        const expiry = BigInt(now) + 500n;

        async function submitOrderEr(
          p: Persona, slotIdx: number, side: 0 | 1, amount: bigint, priceLimit: bigint, oid: Uint8Array,
        ) {
          const { ix } = buildSubmitOrderInstruction({
            programId: meProgramId,
            tradingKey: p.tradingKey.publicKey,
            market,
            slotIdx,
            // PendingOrder.user_commitment is documented (see
            // programs/matching_engine/src/instructions/submit_order.rs) as
            // Poseidon(spending_key, r_owner) — the OWNER commitment used
            // by VALID_SPEND, NOT the wallet/user commitment from
            // userCommitmentFromKeys. Wrong here only matters when a
            // change note is later spent (see change-note-flow.test.ts),
            // but use the correct value to avoid bit-rot.
            userCommitment: bn254ToBE32(p.ownerCommit),
            noteCommitment: p.depositNote!.commitment,
            amount, priceLimit, side,
            noteAmount: p.depositNote!.amount,
            expirySlot: expiry,
            orderId: oid,
            orderType: OrderType.Limit,
          });
          const tx = new Transaction().add(
            ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 }),
            ix,
          );
          const sig = await sendAndConfirmTransaction(
            er, tx, [p.tradingKey], { commitment: "confirmed" },
          );
          txline(`${p.name}: submit_order ${side === 0 ? "BUY" : "SELL"} ${amount} @ ${priceLimit}`, sig, "er");
        }
        await submitOrderEr(alice, ALICE_SLOT, 0, BASE_AMT, PRICE, aliceOrderId);
        await submitOrderEr(bob,   BOB_SLOT,   1, BASE_AMT, PRICE, bobOrderId);

        // ─────────────────────────────────────────────────────────────────
        step(8.5 as unknown as number, "run_batch on ER — matches Alice vs Bob from delegated slots");
        // ─────────────────────────────────────────────────────────────────
        const [aliceSlotPda] = pendingOrderPda(
          meProgramId, market, alice.tradingKey.publicKey, ALICE_SLOT,
        );
        const [bobSlotPda] = pendingOrderPda(
          meProgramId, market, bob.tradingKey.publicKey, BOB_SLOT,
        );
        const rbTx = new Transaction().add(
          ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
          buildRunBatchInstruction({
            programId: meProgramId,
            vaultProgramId,
            teeAuthority: teeKeypair.publicKey,
            market,
            pythAccount,
            pendingOrderPdas: [aliceSlotPda, bobSlotPda],
          }),
        );
        const rbSig = await sendAndConfirmTransaction(
          er, rbTx, [teeKeypair], { commitment: "confirmed" },
        );
        txline("run_batch (ER)", rbSig, "er");

        // Capture the L1 pre-commit BatchResults hash so we can detect when
        // the ER commit lands.
        const [batchPda] = batchResultsPda(meProgramId, market);
        const preAcct = await l1.getAccountInfo(batchPda, "confirmed");
        const preHash = preAcct ? Buffer.from(preAcct.data).toString("hex") : null;
        bullet(`L1 BatchResults pre-commit hash: ${preHash ? preHash.slice(0, 32) + "…" : "(absent)"}`);

        // ─────────────────────────────────────────────────────────────────
        step(9, "commit_and_undelegate (ER) — push state to L1 + release delegation");
        // ─────────────────────────────────────────────────────────────────
        const undTx = new Transaction().add(
          ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
          buildUndelegateMarketInstruction({
            programId: meProgramId, payer: funder.publicKey, market,
          }),
        );
        const undSig = await sendAndConfirmTransaction(
          er, undTx, [funder], { commitment: "confirmed" },
        );
        txline("undelegate_market (ScheduleCommitAndUndelegate)", undSig, "er");

        // ─────────────────────────────────────────────────────────────────
        step(10, "Wait for L1 BatchResults to reflect the ER commit");
        // ─────────────────────────────────────────────────────────────────
        const postData = await waitForL1AccountChange(l1, batchPda, preHash, {
          timeoutMs: 90_000, intervalMs: 1_000,
        });
        bullet(`L1 BatchResults post-commit size: ${postData.length} bytes`);

        // Verify post-commit ownership is back to matching_engine.
        const postAcct = await l1.getAccountInfo(batchPda, "confirmed");
        if (!postAcct) throw new Error("BatchResults account missing post-commit");
        bullet(`BatchResults owner: ${postAcct.owner.toBase58()}`);
        expect(postAcct.owner.toBase58()).toBe(meProgramId.toBase58());

        // ─────────────────────────────────────────────────────────────────
        step(11, "TEE builds MatchResultPayload + signs canonical hash (L1)");
        // ─────────────────────────────────────────────────────────────────
        const matchId = 0n;
        bullet(`match_id = ${matchId}`);

        const noteCnonce = deriveNonce(matchId, TRADE_ROLE_BUYER);
        const noteCblind = deriveBlinding(matchId, TRADE_ROLE_BUYER);
        const noteCcommitment = await noteCommitment({
          tokenMint: baseMint.toBytes(), amount: BASE_AMT,
          ownerCommitment: alice.ownerCommit,
          nonce: be32ToBigInt(noteCnonce), blindingR: be32ToBigInt(noteCblind),
        });
        leaf("note_c (Alice receives BASE)", noteCcommitment);

        const noteDnonce = deriveNonce(matchId, TRADE_ROLE_SELLER);
        const noteDblind = deriveBlinding(matchId, TRADE_ROLE_SELLER);
        const noteDcommitment = await noteCommitment({
          tokenMint: quoteMint.toBytes(), amount: QUOTE_AMT,
          ownerCommitment: bob.ownerCommit,
          nonce: be32ToBigInt(noteDnonce), blindingR: be32ToBigInt(noteDblind),
        });
        leaf("note_d (Bob receives QUOTE)", noteDcommitment);

        const slot = await l1.getSlot("confirmed");
        const feeNonce = deriveNonce(BigInt(slot), FEE_ROLE_QUOTE);
        const feeBlind = deriveBlinding(BigInt(slot), FEE_ROLE_QUOTE);
        const feeCommitment = await noteCommitment({
          tokenMint: quoteMint.toBytes(), amount: BUYER_FEE,
          ownerCommitment: be32ToBigInt(protocolOwnerCommitment),
          nonce: be32ToBigInt(feeNonce), blindingR: be32ToBigInt(feeBlind),
        });
        leaf("note_fee (protocol QUOTE)", feeCommitment);

        const nullA = await nullifier(alice.spendingKey, alice.depositNote!.commitment);
        const nullB = await nullifier(bob.spendingKey, bob.depositNote!.commitment);

        const payload: MatchResultPayload = exactFillPayload({
          matchId: asU8a(matchId, 16),
          noteAcommitment: alice.depositNote!.commitment,
          noteBcommitment: bob.depositNote!.commitment,
          noteCcommitment, noteDcommitment,
          nullifierA: nullA, nullifierB: nullB,
          orderIdA: aliceOrderId, orderIdB: bobOrderId,
          baseAmount: BASE_AMT, quoteAmount: QUOTE_AMT,
        });
        payload.buyerFeeAmt = BUYER_FEE;
        payload.sellerFeeAmt = SELLER_FEE;
        payload.noteFeeCommitment = feeCommitment;

        const msg = canonicalPayloadHash(payload);
        const teeSig = tee.signCanonical(msg);
        bullet(`canonical hash: 0x${toHex(msg).slice(0, 16)}…`);

        // ─────────────────────────────────────────────────────────────────
        step(12, "lock_note×2 (L1) then Ed25519 + tee_forced_settle (L1)");
        // ─────────────────────────────────────────────────────────────────
        noteLine(
          "Privacy-fix settlement: since submit_order no longer creates " +
          "NoteLock PDAs (it never touched the vault program), the TEE " +
          "must allocate them at settle time. The combined tx exceeds " +
          "the 1232-byte tx cap, so we send TWO L1 txs:\n" +
          "  (12a) lock_note(note_a) + lock_note(note_b)\n" +
          "  (12b) Ed25519 verify + tee_forced_settle\n" +
          "Privacy is unaffected — lock_note only references note " +
          "commitments already public on L1 (from deposit) and amounts " +
          "already public on L1 (from deposit). No order intent is " +
          "exposed by either tx.",
        );
        // v2: lock_note now requires a VALID_INPUT proof per side. Generate
        // both proofs against the current shadow-tree root before building
        // the tx.
        const aliceWitness = await tree.witness(alice.depositNote!.leafIndex);
        const aliceVI = await proveValidInput({
          repoRoot: REPO_ROOT,
          spendingKey: alice.spendingKey,
          ownerCommitmentBlinding: alice.ownerBlinding,
          nonce: alice.depositNote!.nonce,
          blindingR: alice.depositNote!.blindingR,
          tokenMint: alice.depositNote!.mint.toBytes(),
          amount: alice.depositNote!.amount,
          merkleRootBE: aliceWitness.root,
          merkleWitness: {
            pathElements: aliceWitness.siblings.map(be32ToBigInt),
            pathIndices: aliceWitness.indices,
          },
        });
        const bobWitness = await tree.witness(bob.depositNote!.leafIndex);
        const bobVI = await proveValidInput({
          repoRoot: REPO_ROOT,
          spendingKey: bob.spendingKey,
          ownerCommitmentBlinding: bob.ownerBlinding,
          nonce: bob.depositNote!.nonce,
          blindingR: bob.depositNote!.blindingR,
          tokenMint: bob.depositNote!.mint.toBytes(),
          amount: bob.depositNote!.amount,
          merkleRootBE: bobWitness.root,
          merkleWitness: {
            pathElements: bobWitness.siblings.map(be32ToBigInt),
            pathIndices: bobWitness.indices,
          },
        });

        const lockTx = new Transaction().add(
          ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }),
          buildLockNoteInstruction({
            programId: vaultProgramId,
            teeAuthority: teeKeypair.publicKey,
            noteCommitment: alice.depositNote!.commitment,
            orderId: aliceOrderId,
            expirySlot: expiry,
            amount: ALICE_DEPOSIT,
            tokenMint: alice.depositNote!.mint,
            merkleRoot: aliceWitness.root,
            proof: aliceVI.proof,
          }),
          buildLockNoteInstruction({
            programId: vaultProgramId,
            teeAuthority: teeKeypair.publicKey,
            noteCommitment: bob.depositNote!.commitment,
            orderId: bobOrderId,
            expirySlot: expiry,
            amount: BOB_DEPOSIT,
            tokenMint: bob.depositNote!.mint,
            merkleRoot: bobWitness.root,
            proof: bobVI.proof,
          }),
        );
        const lockSig = await sendAndConfirmTransaction(
          l1, lockTx, [teeKeypair], { commitment: "confirmed" },
        );
        txline("lock_note(note_a) + lock_note(note_b)", lockSig);

        // v3: VALID_CREATE proof must land before settle.
        const ZERO_32 = new Uint8Array(32);
        const vcArgs = {
          noteA: alice.depositNote!.commitment,
          noteB: bob.depositNote!.commitment,
          noteC: noteCcommitment,
          noteD: noteDcommitment,
          noteE: ZERO_32,
          noteF: ZERO_32,
          quoteMint: quoteMint.toBytes(),
          baseMint: baseMint.toBytes(),
          baseAmount: BASE_AMT,
          quoteAmount: QUOTE_AMT,
          buyerChangeAmt: 0n,
          sellerChangeAmt: 0n,
          buyerFeeAmt: BUYER_FEE,
          sellerFeeAmt: SELLER_FEE,
        };
        const validCreate = await proveValidCreate({
          repoRoot: REPO_ROOT,
          quoteMint: quoteMint.toBytes(),
          baseMint: baseMint.toBytes(),
          inputA: {
            ownerCommit: alice.ownerCommit,
            amount: alice.depositNote!.amount,
            nonce: alice.depositNote!.nonce,
            blindingR: alice.depositNote!.blindingR,
          },
          inputAcommitmentBE: alice.depositNote!.commitment,
          inputB: {
            ownerCommit: bob.ownerCommit,
            amount: bob.depositNote!.amount,
            nonce: bob.depositNote!.nonce,
            blindingR: bob.depositNote!.blindingR,
          },
          inputBcommitmentBE: bob.depositNote!.commitment,
          outputC: {
            ownerCommit: alice.ownerCommit, amount: BASE_AMT,
            nonce: be32ToBigInt(noteCnonce), blindingR: be32ToBigInt(noteCblind),
          },
          outputCcommitmentBE: noteCcommitment,
          outputD: {
            ownerCommit: bob.ownerCommit, amount: QUOTE_AMT,
            nonce: be32ToBigInt(noteDnonce), blindingR: be32ToBigInt(noteDblind),
          },
          outputDcommitmentBE: noteDcommitment,
          outputE: undefined, outputEcommitmentBE: ZERO_32,
          outputF: undefined, outputFcommitmentBE: ZERO_32,
          baseAmount: BASE_AMT, quoteAmount: QUOTE_AMT,
          buyerChangeAmt: 0n, sellerChangeAmt: 0n,
          buyerFeeAmt: BUYER_FEE, sellerFeeAmt: SELLER_FEE,
        });
        const binding = validCreateBindingHash(vcArgs);
        const markerExpiry = BigInt((await l1.getSlot("confirmed")) + 200);
        const verifyTx = new Transaction().add(
          ComputeBudgetProgram.setComputeUnitLimit({ units: 600_000 }),
          buildVerifyValidCreateInstruction({
            programId: vaultProgramId,
            payer: teeKeypair.publicKey,
            bindingHash: binding,
            noteAcommitment: alice.depositNote!.commitment,
            noteBcommitment: bob.depositNote!.commitment,
            noteCcommitment, noteDcommitment,
            noteEcommitment: ZERO_32, noteFcommitment: ZERO_32,
            quoteMint, baseMint,
            baseAmount: BASE_AMT, quoteAmount: QUOTE_AMT,
            buyerChangeAmt: 0n, sellerChangeAmt: 0n,
            buyerFeeAmt: BUYER_FEE, sellerFeeAmt: SELLER_FEE,
            expirySlot: markerExpiry,
            proof: validCreate.proof,
          }),
        );
        const verifySig = await sendAndConfirmTransaction(
          l1, verifyTx, [teeKeypair], { commitment: "confirmed" },
        );
        txline("verify_valid_create", verifySig);

        const settleTx = new Transaction().add(
          ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
          buildEd25519VerifyIx({
            teePubkey: teeKeypair.publicKey.toBytes(),
            signature: teeSig, message: msg,
          }),
          buildSettleIx({
            programId: vaultProgramId,
            teeAuthority: teeKeypair.publicKey,
            payload,
            quoteMint, baseMint,
          }),
        );
        const settleSig = await sendAndConfirmTransaction(
          l1, settleTx, [teeKeypair], { commitment: "confirmed" },
        );
        txline("Ed25519 + tee_forced_settle", settleSig);

        await tree.append(noteCcommitment);
        alice.tradeNote = {
          mint: baseMint, amount: BASE_AMT,
          nonce: noteCnonce, blindingR: noteCblind,
          commitment: noteCcommitment, leafIndex: tree.leafCount - 1,
        };
        await tree.append(noteDcommitment);
        bob.tradeNote = {
          mint: quoteMint, amount: QUOTE_AMT,
          nonce: noteDnonce, blindingR: noteDblind,
          commitment: noteDcommitment, leafIndex: tree.leafCount - 1,
        };
        await tree.append(feeCommitment);

        // Shadow-tree / on-chain root invariant.
        {
          const [vPda] = vaultConfigPda(vaultProgramId);
          const vc = await l1.getAccountInfo(vPda, "confirmed");
          if (!vc) throw new Error("vault_config missing");
          const OFF = 8 + 32 + 32 + 32;
          const onChainRoot = vc.data.subarray(OFF + 8, OFF + 8 + 32);
          const shadowRoot = await tree.computeRoot();
          const onHex = Buffer.from(onChainRoot).toString("hex");
          const shHex = Buffer.from(shadowRoot).toString("hex");
          bullet(`on-chain root: ${onHex.slice(0, 32)}…`);
          bullet(`shadow root:   ${shHex.slice(0, 32)}…`);
          if (onHex !== shHex) {
            throw new Error("shadow tree diverged from on-chain root — re-run devnet-setup");
          }
        }

        // ─────────────────────────────────────────────────────────────────
        step(13, "Withdraw (L1): Alice → BASE, Bob → QUOTE");
        // ─────────────────────────────────────────────────────────────────
        async function proveAndWithdraw(
          p: Persona,
          trade: NonNullable<Persona["tradeNote"]>,
          destAta: PublicKey, payerKp: Keypair,
          ownerCommitBlinding: bigint, label: string,
        ) {
          substep(`${label}: proving VALID_SPEND`);
          const w = await tree.witness(trade.leafIndex);
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
            programId: vaultProgramId, payer: payerKp.publicKey,
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
          const sig = await sendAndConfirmTransaction(l1, tx, [payerKp], { commitment: "confirmed" });
          txline(`${label}: withdraw`, sig);
        }
        await proveAndWithdraw(
          alice, alice.tradeNote!, aliceBaseAta, alice.payer, alice.ownerBlinding,
          "Alice → BASE",
        );
        await proveAndWithdraw(
          bob, bob.tradeNote!, bobQuoteAta, bob.payer, bob.ownerBlinding,
          "Bob → QUOTE",
        );

        banner("ER TRADE FLOW COMPLETE — state committed L1↔ER↔L1 + balances verified");
        const aBal = await l1.getTokenAccountBalance(aliceBaseAta);
        const bBal = await l1.getTokenAccountBalance(bobQuoteAta);
        bullet(`Alice BASE: ${aBal.value.amount}`);
        bullet(`Bob   QUOTE: ${bBal.value.amount}`);
        expect(BigInt(aBal.value.amount)).toBeGreaterThanOrEqual(BASE_AMT);
        expect(BigInt(bBal.value.amount)).toBeGreaterThanOrEqual(QUOTE_AMT);
      },
    );
  },
);

// ───────────────────────────────────────────────────────────────────────────

function requireEnv(k: string): string {
  const v = process.env[k];
  if (!v) throw new Error(`missing env: ${k}`);
  return v;
}

function asU8a(x: bigint, len: number): Uint8Array {
  const out = new Uint8Array(len);
  new DataView(out.buffer).setBigUint64(len - 8, x, true);
  return out;
}
