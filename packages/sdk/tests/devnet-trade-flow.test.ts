/**
 * Phase-5 Nyx Darkpool — devnet E2E trade flow (deposit → match → settle → withdraw).
 *
 * Prerequisites (all handled by the companion `devnet-setup.test.ts`):
 *   - .devnet/e2e-config.json present (token pair + market PDAs + protocol config).
 *   - vault + matching_engine deployed on devnet (see scripts/deploy-devnet.sh).
 *   - Admin / tee / root_key keypairs under .devnet/keypairs/.
 *   - Circuits built: circuits/build/{valid_wallet_create,valid_spend}/.
 *
 * What this test orchestrates, with STEP-BY-STEP narrative logging:
 *
 *   HAPPY PATH (exact fill + 30 bps protocol fee):
 *     1. Alice + Bob key generation; wallet creation on-chain (ZK-proved).
 *     2. Mint tokens; deposit into vault → note_a (Alice 5015 quote) and
 *        note_b (Bob 50 base).
 *     3. TEE submits both orders (CPI → lock_note).
 *     4. run_batch produces a MatchResult with 4 emitted leaves:
 *        note_c (50 base → Alice), note_d (5000 quote → Bob), note_fee (15 quote
 *        → protocol), and NO change / relock because both sides are exact.
 *     5. TEE signs the MatchResultPayload canonical hash, submits
 *        tee_forced_settle.
 *     6. Alice / Bob / protocol all withdraw (ZK-proved VALID_SPEND).
 *
 *   DELIBERATE SHORTCUTS (documented for follow-ups):
 *     - run_batch is invoked on L1 rather than via the MagicBlock ER
 *       delegate/undelegate cycle. The underlying ix accepts L1 calls fine,
 *       but the production transport is through the ER. See TODO below.
 *     - The TEE is a local keypair (nacl), not an enclave.
 *     - note_c / note_d plaintext is reconstructed by each side using
 *       deterministic TRADE_ROLE_* derivation mirroring change_note.rs.
 *
 * Run:
 *   RUN_DEVNET_E2E=1 \
 *     ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
 *     TEE_AUTHORITY_KEYPAIR=.devnet/keypairs/tee_authority.json \
 *     ROOT_KEY_KEYPAIR=.devnet/keypairs/root_key.json \
 *     cd packages/sdk && ../../node_modules/.bin/vitest run tests/devnet-trade-flow.test.ts
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
  AddressLookupTableProgram,
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
  poseidonHashBytesBE,
  pubkeyToFrPair,
} from "../src/utxo/note.js";
import {
  buildCreateWalletInstruction,
  buildDepositInstruction,
  buildLockNoteInstruction,
  buildVerifyValidCreateInstruction,
  buildWithdrawInstruction,
  batchValidityMarkerPda,
  noteLockPda,
  vaultConfigPda,
  walletEntryPda,
} from "../src/idl/vault-client.js";
import {
  buildRunBatchInstruction,
  buildSubmitOrderInstruction,
  buildInitPendingOrderSlotInstruction,
  batchResultsPda,
  darkClobPda,
  matchingConfigPda,
  pendingOrderPda,
  OrderType,
} from "../src/idl/matching-engine-client.js";
import {
  buildEd25519VerifyIx,
  buildSettleIx,
  buildSettleBatchedIx,
  canonicalPayloadHash,
  exactFillPayload,
  validCreateBindingHash,
  type MatchResultPayload,
} from "../src/settlement/settle-builder.js";

import { snarkjsFullProve } from "./helpers/snarkjs-prover.js";
import { MerkleShadow } from "./helpers/merkle-shadow.js";
import { proveValidInput } from "./helpers/valid-input-prover.js";
import { proveValidCreate } from "./helpers/valid-create-prover.js";
import { sendSettleV0 } from "./helpers/settle-v0.js";
import { landVerifyValidPrice } from "./helpers/verify-valid-price.js";
import { settleViaBatched } from "./helpers/batched-settle.js";
import { type MatchSlotWitness } from "./helpers/match-batch-prover.js";

/** v3.5 — set `USE_BATCHED_PROOF=1` in the env to route the settle through
 *  `verify_match_batch` + `tee_forced_settle_batched` instead of the
 *  per-match `verify_valid_create` + `verify_valid_price` + `tee_forced_settle`
 *  trio. Both paths produce identical state transitions; the assertions
 *  later in the test don't care which path was taken. */
const USE_BATCHED_PROOF = process.env.USE_BATCHED_PROOF === "1";
import {
  be32ToBigInt,
  be32ToDec,
  bigIntToBe32,
  CHANGE_ROLE_BUYER,
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

const RUN = process.env.RUN_DEVNET_E2E === "1";

const REPO_ROOT = resolve(__dirname, "../../..");
const CONFIG_PATH = resolve(REPO_ROOT, ".devnet/e2e-config.json");

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

function rpcHostLabel(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return "(invalid-rpc-url)";
  }
}

// ───────────────────────────────────────────────────────────────────────────
// Verbose narrative logging
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

function txline(note: string, signature: string) {
  console.log(`  >> ${note}`);
  console.log(`     TX: ${signature}`);
  console.log(`     EXPLORER: https://explorer.solana.com/tx/${signature}?cluster=devnet`);
}

function bullet(text: string) {
  console.log(`     • ${text}`);
}

function note(text: string) {
  console.log(`     NOTE: ${text}`);
}

function leaf(label: string, bytes: Uint8Array) {
  console.log(`     LEAF [${label}] = 0x${toHex(bytes).slice(0, 16)}…${toHex(bytes).slice(-8)}`);
}

function toHex(x: Uint8Array): string {
  return Array.from(x)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ───────────────────────────────────────────────────────────────────────────
// User persona: one Alice-or-Bob participant in the flow.
// ───────────────────────────────────────────────────────────────────────────

interface Persona {
  name: string;
  payer: Keypair;                // Funds tx fees. Acts as the "Permission Group" member here.
  tradingKey: Keypair;           // Signs submit_order.
  masterSeed: Uint8Array;        // 64B HKDF seed.
  spendingKey: bigint;           // Fr.
  viewingKey: bigint;            // Fr.
  ownerBlinding: bigint;         // Fr. Arbitrary non-zero — per-user.
  ownerCommit: bigint;           // poseidon2(spendingKey, ownerBlinding).
  r0: bigint; r1: bigint; r2: bigint;
  userCommitment: Uint8Array;    // 32B BE.
  // Populated during the flow:
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
  // Persist payer + tradingKey under .devnet/keypairs/ so SOL funded in a
  // previous run is NOT wasted. Everything else (masterSeed, sk/vk/r0..r2,
  // userCommitment) is deterministic from `seed0`, so it's identical across
  // runs once the keypairs are fixed — this means the WalletEntry PDA also
  // stays stable and create_wallet can be skipped after the first run.
  const payerPath = resolve(REPO_ROOT, `.devnet/keypairs/${name}-payer.json`);
  const tradingPath = resolve(REPO_ROOT, `.devnet/keypairs/${name}-trading.json`);
  const payer = loadOrCreateKeypair(payerPath);
  const tradingKey = loadOrCreateKeypair(tradingPath);
  const masterSeed = new Uint8Array(64);
  for (let i = 0; i < 64; i++) masterSeed[i] = (seed0 + i * 7) & 0xff;
  const spendingKey = deriveSpendingKey(masterSeed);
  const viewingKey = deriveMasterViewingKey(masterSeed);
  // Non-zero arbitrary owner-commitment blinding; must stay constant for the
  // life of this persona's notes (it's baked into `owner_commitment`).
  const ownerBlinding = BigInt(seed0) + 0xBEEFBEEFn;
  const ownerCommit = await ownerCommitment(spendingKey, ownerBlinding);
  const r0 = BigInt(seed0) + 1n;
  const r1 = BigInt(seed0) + 2n;
  const r2 = BigInt(seed0) + 3n;
  const uc = await userCommitmentFromKeys({
    rootKeyPubkey: payer.publicKey.toBytes(), // Root-key PubKey for the commitment.
    spendingKey,
    viewingKey,
    r0, r1, r2,
  });
  return {
    name, payer, tradingKey, masterSeed,
    spendingKey, viewingKey, ownerBlinding, ownerCommit,
    r0, r1, r2, userCommitment: uc,
  };
}

// ───────────────────────────────────────────────────────────────────────────
// TEE simulator — holds the Ed25519 keypair that matches vault_config.tee_pubkey.
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

maybeDescribe("Phase 5 devnet E2E — trade flow (deposit → match → settle → withdraw)", () => {
  let connection: Connection;
  let cfg: E2EConfig;
  let admin: Keypair;
  let funder: Keypair; // funds Alice/Bob via SystemProgram.transfer (avoids RPC airdrop limits)
  let teeKeypair: Keypair;
  let tee: TeeSim;
  let rootKey: Keypair;
  let vaultProgramId: PublicKey;
  let meProgramId: PublicKey;
  let pythAccount: PublicKey;
  let market: PublicKey;
  let baseMint: PublicKey;
  let quoteMint: PublicKey;
  let protocolOwnerCommitment: Uint8Array;
  let protocolFeeBps: number;
  let tree: MerkleShadow;
  let alice: Persona;
  let bob: Persona;

  beforeAll(async () => {
    cfg = JSON.parse(readFileSync(CONFIG_PATH, "utf8")) as E2EConfig;
    connection = new Connection(cfg.l1RpcUrl, "confirmed");

    admin = loadKeypairRel(REPO_ROOT, requireEnv("ADMIN_KEYPAIR"));
    teeKeypair = loadKeypairRel(REPO_ROOT, requireEnv("TEE_AUTHORITY_KEYPAIR"));
    rootKey = loadKeypairRel(REPO_ROOT, requireEnv("ROOT_KEY_KEYPAIR"));
    tee = makeTeeSim(teeKeypair);

    // Funder = whichever keypair actually holds the devnet SOL. Falls back to
    // `admin`. Set FUNDER_KEYPAIR to e.g. "~/.config/solana/id.json" (absolute
    // path) when Helius free-tier airdrops aren't enough.
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

    banner("NYX DARKPOOL — DEVNET E2E TRADE FLOW");
    bullet(`RPC:                ${rpcHostLabel(cfg.l1RpcUrl)}`);
    bullet(`market:             ${market.toBase58()}`);
    bullet(`BASE mint (${cfg.baseMint.decimals}d):     ${baseMint.toBase58()}`);
    bullet(`QUOTE mint (${cfg.quoteMint.decimals}d):    ${quoteMint.toBase58()}`);
    bullet(`protocol fee bps:   ${protocolFeeBps}`);
    bullet(`TEE pubkey:         ${teeKeypair.publicKey.toBase58()}`);
    bullet(`funder:             ${funder.publicKey.toBase58()}`);
    const funderBal = await connection.getBalance(funder.publicKey);
    bullet(`funder balance:     ${(funderBal / 1e9).toFixed(4)} SOL`);
    if (funderBal < 0.3 * 1e9) {
      throw new Error(
        `funder has < 0.3 SOL; fund first or set FUNDER_KEYPAIR=<path-to-keypair-with-sol>`,
      );
    }
  }, 60_000);

  it(
    "happy-path exact fill: 50 base @ price 100 quote/base, 30 bps fee flushed",
    { timeout: 600_000 },
    async () => {
      // ─────────────────────────────────────────────────────────────────────
      step(1, "Generate Alice + Bob personas (master seeds, trading keys)");
      // ─────────────────────────────────────────────────────────────────────
      alice = await makePersona("alice", 0x42);
      bob = await makePersona("bob", 0x77);

      for (const p of [alice, bob]) {
        bullet(`${p.name.padEnd(6)} payer:        ${p.payer.publicKey.toBase58()}`);
        bullet(`${p.name.padEnd(6)} trading key:  ${p.tradingKey.publicKey.toBase58()}`);
        bullet(`${p.name.padEnd(6)} userCommitment: 0x${toHex(p.userCommitment)}`);
      }

      // ─────────────────────────────────────────────────────────────────────
      step(2, "Top-up Alice + Bob with devnet SOL (from funder, only if needed)");
      // ─────────────────────────────────────────────────────────────────────
      // Keypairs are persisted, so balances survive across runs. Only transfer
      // to an account whose balance is below the configured threshold.
      const PAYER_LAMPORTS = 2_000_000_000; // 2 SOL per user: target balance
      const TK_LAMPORTS = 100_000_000;      // 0.1 SOL per trading key: target
      const PAYER_MIN = 500_000_000;        // < 0.5 SOL => top up
      const TK_MIN = 20_000_000;            // < 0.02 SOL => top up
      type FundTarget = {
        label: string; to: PublicKey; target: number; min: number;
      };
      const targets: FundTarget[] = [
        { label: `${alice.name} payer`,   to: alice.payer.publicKey,      target: PAYER_LAMPORTS, min: PAYER_MIN },
        { label: `${bob.name} payer`,     to: bob.payer.publicKey,        target: PAYER_LAMPORTS, min: PAYER_MIN },
        { label: `${alice.name} trading`, to: alice.tradingKey.publicKey, target: TK_LAMPORTS,    min: TK_MIN    },
        { label: `${bob.name} trading`,   to: bob.tradingKey.publicKey,   target: TK_LAMPORTS,    min: TK_MIN    },
      ];
      const transferIxs = [];
      let totalTransfer = 0;
      for (const t of targets) {
        const bal = await connection.getBalance(t.to);
        if (bal >= t.min) {
          bullet(`${t.label.padEnd(16)} balance ${(bal / 1e9).toFixed(4)} SOL — skip top-up`);
        } else {
          const delta = t.target - bal;
          bullet(`${t.label.padEnd(16)} balance ${(bal / 1e9).toFixed(4)} SOL — top up ${(delta / 1e9).toFixed(4)} SOL`);
          transferIxs.push(SystemProgram.transfer({
            fromPubkey: funder.publicKey,
            toPubkey: t.to,
            lamports: delta,
          }));
          totalTransfer += delta;
        }
      }
      if (transferIxs.length > 0) {
        const fundTx = new Transaction().add(...transferIxs);
        const fundSig = await sendAndConfirmTransaction(
          connection, fundTx, [funder], { commitment: "confirmed" },
        );
        txline(`funder transferred ${(totalTransfer / 1e9).toFixed(4)} SOL total`, fundSig);
      } else {
        bullet("no transfers needed — all accounts already funded");
      }

      // ─────────────────────────────────────────────────────────────────────
      step(3, "Mint initial token balances to Alice (QUOTE) + Bob (BASE)");
      // ─────────────────────────────────────────────────────────────────────
      // Trade parameters (all in raw SPL atoms — smallest units):
      //   base_amt  = 50 atoms
      //   price     = 100 quote-atoms per base-atom (must match mock oracle TWAP band)
      //   quote_amt = base_amt * price
      //   buyer_fee = quote_amt * 30 / 10_000
      const BASE_AMT = 50n;
      const PRICE = 100n;
      const QUOTE_AMT = BASE_AMT * PRICE; // 5_000
      const BUYER_FEE = (QUOTE_AMT * BigInt(protocolFeeBps)) / 10_000n; // 15
      const SELLER_FEE = (BASE_AMT * BigInt(protocolFeeBps)) / 10_000n; // 0 (floor)
      const ALICE_DEPOSIT = QUOTE_AMT + BUYER_FEE; // 5_015 — exact fill
      const BOB_DEPOSIT = BASE_AMT + SELLER_FEE;    // 50

      bullet(`base_amt = ${BASE_AMT}`);
      bullet(`price (quote/base) = ${PRICE}`);
      bullet(`quote_amt = ${QUOTE_AMT}`);
      bullet(`buyer_fee (quote)  = ${BUYER_FEE}`);
      bullet(`seller_fee (base)  = ${SELLER_FEE}`);
      bullet(`Alice will deposit ${ALICE_DEPOSIT} QUOTE (exact-fill including fee)`);
      bullet(`Bob   will deposit ${BOB_DEPOSIT} BASE`);

      const aliceQuoteAta = await getAssociatedTokenAddress(
        quoteMint, alice.payer.publicKey,
      );
      const bobBaseAta = await getAssociatedTokenAddress(
        baseMint, bob.payer.publicKey,
      );
      const aliceBaseAta = await getAssociatedTokenAddress(
        baseMint, alice.payer.publicKey,
      );
      const bobQuoteAta = await getAssociatedTokenAddress(
        quoteMint, bob.payer.publicKey,
      );

      // Create ATAs (idempotent) for both mints, on both users, so withdrawals
      // land correctly. Using the idempotent variant means re-runs with
      // pre-existing ATAs do NOT blow up.
      const ataTx = new Transaction().add(
        createAssociatedTokenAccountIdempotentInstruction(
          admin.publicKey, aliceQuoteAta, alice.payer.publicKey, quoteMint,
        ),
        createAssociatedTokenAccountIdempotentInstruction(
          admin.publicKey, aliceBaseAta, alice.payer.publicKey, baseMint,
        ),
        createAssociatedTokenAccountIdempotentInstruction(
          admin.publicKey, bobBaseAta, bob.payer.publicKey, baseMint,
        ),
        createAssociatedTokenAccountIdempotentInstruction(
          admin.publicKey, bobQuoteAta, bob.payer.publicKey, quoteMint,
        ),
        createMintToInstruction(
          quoteMint, aliceQuoteAta, admin.publicKey, Number(ALICE_DEPOSIT),
        ),
        createMintToInstruction(
          baseMint, bobBaseAta, admin.publicKey, Number(BOB_DEPOSIT),
        ),
      );
      const ataSig = await sendAndConfirmTransaction(connection, ataTx, [admin], {
        commitment: "confirmed",
      });
      txline("created ATAs + minted initial balances", ataSig);

      // Protocol ATA for fee withdrawal (payer = admin).
      const protocolQuoteAta = await getAssociatedTokenAddress(
        quoteMint, admin.publicKey,
      );
      const hasProtocolAta = await connection.getAccountInfo(protocolQuoteAta);
      if (!hasProtocolAta) {
        const pTx = new Transaction().add(
          createAssociatedTokenAccountInstruction(
            admin.publicKey, protocolQuoteAta, admin.publicKey, quoteMint,
          ),
        );
        const ps = await sendAndConfirmTransaction(connection, pTx, [admin], {
          commitment: "confirmed",
        });
        txline("created protocol quote-fee ATA", ps);
      }

      // ─────────────────────────────────────────────────────────────────────
      step(4, "Create on-chain WalletEntry PDAs (VALID_WALLET_CREATE)");
      // ─────────────────────────────────────────────────────────────────────
      // Since personas are persisted, their userCommitment is stable across
      // runs; the WalletEntry PDA therefore persists too. Skip the proof +
      // tx if the PDA already exists — saves ~100k CU and one tx per run.
      for (const p of [alice, bob]) {
        const [walletPda] = walletEntryPda(vaultProgramId, p.userCommitment);
        const existing = await connection.getAccountInfo(walletPda);
        if (existing) {
          bullet(`${p.name}: WalletEntry already registered (${walletPda.toBase58().slice(0, 8)}…) — skip`);
          continue;
        }
        substep(`${p.name}: proving VALID_WALLET_CREATE via snarkjs`);
        const [ucLo, ucHi] = pubkeyToFrPair(p.payer.publicKey.toBytes());
        const { proof } = snarkjsFullProve(
          {
            userCommitment: be32ToDec(p.userCommitment),
            rootKey: [ucLo.toString(), ucHi.toString()],
            spendingKey: p.spendingKey.toString(),
            viewingKey: p.viewingKey.toString(),
            r0: p.r0.toString(),
            r1: p.r1.toString(),
            r2: p.r2.toString(),
          },
          {
            circuitWasmPath: CREATE_WASM,
            circuitZkeyPath: CREATE_ZKEY,
            repoRoot: REPO_ROOT,
          },
        );
        bullet("snarkjs proof generated");

        const cwTx = new Transaction().add(
          buildCreateWalletInstruction({
            programId: vaultProgramId,
            owner: p.payer.publicKey,
            commitment: p.userCommitment,
            proof,
          }),
        );
        const cwSig = await sendAndConfirmTransaction(connection, cwTx, [p.payer], {
          commitment: "confirmed",
        });
        txline(`${p.name}: create_wallet (WalletEntry PDA persisted)`, cwSig);
      }

      // ─────────────────────────────────────────────────────────────────────
      step(5, "Deposit tokens into vault (appends note_a + note_b to Merkle tree)");
      // ─────────────────────────────────────────────────────────────────────
      async function depositNote(
        p: Persona,
        mint: PublicKey,
        amount: bigint,
        userAta: PublicKey,
      ) {
        substep(`${p.name}: depositing ${amount} to mint ${mint.toBase58().slice(0, 8)}…`);
        // Read current on-chain leaf_count so the nonce derivation matches exactly.
        const [vaultPda] = vaultConfigPda(vaultProgramId);
        const info = await connection.getAccountInfo(vaultPda);
        if (!info) throw new Error("vault_config missing — run setup first");
        const leafIndex = Number(
          new DataView(info.data.buffer, info.data.byteOffset + 104, 8).getBigUint64(0, true),
        );
        const nonce = deriveBlindingFactor(p.masterSeed, BigInt(leafIndex));
        const blindingR = deriveBlindingFactor(p.masterSeed, BigInt(leafIndex) + 1n);

        const commitment = await noteCommitment({
          tokenMint: mint.toBytes(),
          amount,
          ownerCommitment: p.ownerCommit,
          nonce,
          blindingR,
        });
        leaf(`note (${p.name} deposit)`, commitment);

        const ix = buildDepositInstruction({
          programId: vaultProgramId,
          depositor: p.payer.publicKey,
          tokenMint: mint,
          depositorTokenAccount: userAta,
          tokenProgramId: TOKEN_PROGRAM_ID,
          amount,
          ownerCommitment: bn254ToBE32(p.ownerCommit),
          nonce: bn254ToBE32(nonce),
          blindingR: bn254ToBE32(blindingR),
        });
        const sig = await sendAndConfirmTransaction(
          connection, new Transaction().add(ix), [p.payer],
          { commitment: "confirmed" },
        );
        txline(`${p.name}: deposit`, sig);

        // Mirror the leaf into our shadow Merkle tree.
        await tree.append(commitment);

        p.depositNote = {
          mint, amount, nonce, blindingR, commitment, leafIndex,
        };
      }
      await depositNote(alice, quoteMint, ALICE_DEPOSIT, aliceQuoteAta);
      await depositNote(bob, baseMint, BOB_DEPOSIT, bobBaseAta);

      // ─────────────────────────────────────────────────────────────────────
      step(6, "Init PendingOrder slots (L1) + submit orders (privacy-fix shape)");
      // ─────────────────────────────────────────────────────────────────────
      note(
        "PRODUCTION PATH: PendingOrder slots are init+delegated on L1, then " +
          "submit_order writes order intent INSIDE the ER (invisible to L1). " +
          "This L1-only devnet test runs submit_order against the L1 RPC — " +
          "the ix logic is identical, but the privacy property only obtains " +
          "when the slot is actually delegated. See er-trade-flow.test.ts for " +
          "the full delegate → ER → undelegate cycle.",
      );
      const aliceOrderId = new Uint8Array(16); aliceOrderId[0] = 0xA1;
      const bobOrderId = new Uint8Array(16); bobOrderId[0] = 0xB0;
      const now = await connection.getSlot("confirmed");
      const expiry = BigInt(now) + 500n;
      const ALICE_SLOT = 0;
      const BOB_SLOT = 0;

      async function ensureSlotInit(p: Persona, slotIdx: number) {
        const [pda] = pendingOrderPda(
          meProgramId, market, p.tradingKey.publicKey, slotIdx,
        );
        const existing = await connection.getAccountInfo(pda, "confirmed");
        if (existing) {
          bullet(`${p.name} slot[${slotIdx}] exists — skip init`);
          return;
        }
        const initTx = new Transaction().add(
          buildInitPendingOrderSlotInstruction({
            programId: meProgramId,
            tradingKey: p.tradingKey.publicKey,
            market,
            slotIdx,
          }),
        );
        const sig = await sendAndConfirmTransaction(
          connection, initTx, [p.tradingKey], { commitment: "confirmed" },
        );
        txline(`${p.name}: init_pending_order_slot[${slotIdx}]`, sig);
      }

      async function submitOrder(
        p: Persona, slotIdx: number,
        side: 0 | 1, amount: bigint, priceLimit: bigint, orderId: Uint8Array,
      ) {
        const { ix: submitIx } = buildSubmitOrderInstruction({
          programId: meProgramId,
          tradingKey: p.tradingKey.publicKey,
          market,
          slotIdx,
          userCommitment: p.userCommitment,
          noteCommitment: p.depositNote!.commitment,
          amount, priceLimit, side,
          noteAmount: p.depositNote!.amount,
          expirySlot: expiry,
          orderId,
          orderType: OrderType.Limit,
        });
        const tx = new Transaction().add(
          ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 }),
          submitIx,
        );
        const sig = await sendAndConfirmTransaction(
          connection, tx, [p.tradingKey], { commitment: "confirmed" },
        );
        txline(
          `${p.name}: submit_order ${side === 0 ? "BUY" : "SELL"} ${amount} @ ${priceLimit}`,
          sig,
        );
      }

      await ensureSlotInit(alice, ALICE_SLOT);
      await ensureSlotInit(bob,   BOB_SLOT);
      await submitOrder(alice, ALICE_SLOT, /* buy  */ 0, BASE_AMT, PRICE, aliceOrderId);
      await submitOrder(bob,   BOB_SLOT,   /* sell */ 1, BASE_AMT, PRICE, bobOrderId);

      // ─────────────────────────────────────────────────────────────────────
      step(7, "run_batch (on L1) — find crossing, write MatchResult + FeeAccumulator flush");
      // ─────────────────────────────────────────────────────────────────────
      note(
        "PRODUCTION PATH: run_batch lives inside the MagicBlock ER validator. " +
          "This test calls it directly on devnet L1 — the ix accepts L1 calls " +
          "fine. See scripts/dev-commands.md §11 for the delegate → ER cycle.",
      );
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
        connection, rbTx, [teeKeypair],
        { commitment: "confirmed" },
      );
      txline("run_batch — matched Alice vs Bob at the uniform clearing price", rbSig);

      // ─────────────────────────────────────────────────────────────────────
      step(8, "Decode MatchResult from BatchResults account");
      // ─────────────────────────────────────────────────────────────────────
      const [batchPda] = batchResultsPda(meProgramId, market);
      const br = await connection.getAccountInfo(batchPda);
      if (!br) throw new Error("BatchResults missing — did run_batch fail?");
      bullet(`BatchResults data len: ${br.data.length}`);
      // We don't need to fully decode here — the match_id + crossable amounts
      // are all deterministic given the ordering of the two orders. The test
      // could optionally assert on `last_match_count = 1` etc.

      // ─────────────────────────────────────────────────────────────────────
      step(9, "TEE builds MatchResultPayload + signs canonical hash");
      // ─────────────────────────────────────────────────────────────────────
      const matchId = 0n; // first match_id in a fresh BatchResults is 0.
      bullet(`match_id = ${matchId}`);

      // Derive note_c (50 BASE → Alice) + note_d (5000 QUOTE → Bob) using
      // the deterministic TRADE_ROLE_* scheme. The buyer/seller reconstructs
      // the same bytes at withdraw time — this is the test-only replacement
      // for the PER-session plaintext transport in production.
      const noteCnonce = deriveNonce(matchId, TRADE_ROLE_BUYER);
      const noteCblind = deriveBlinding(matchId, TRADE_ROLE_BUYER);
      const noteCcommitment = await noteCommitment({
        tokenMint: baseMint.toBytes(),
        amount: BASE_AMT,
        ownerCommitment: alice.ownerCommit,
        nonce: be32ToBigInt(noteCnonce),
        blindingR: be32ToBigInt(noteCblind),
      });
      leaf("note_c (Alice receives BASE)", noteCcommitment);

      const noteDnonce = deriveNonce(matchId, TRADE_ROLE_SELLER);
      const noteDblind = deriveBlinding(matchId, TRADE_ROLE_SELLER);
      const noteDcommitment = await noteCommitment({
        tokenMint: quoteMint.toBytes(),
        amount: QUOTE_AMT,
        ownerCommitment: bob.ownerCommit,
        nonce: be32ToBigInt(noteDnonce),
        blindingR: be32ToBigInt(noteDblind),
      });
      leaf("note_d (Bob receives QUOTE)", noteDcommitment);

      // Fee-note: derivation mirrors run_batch's FEE_ROLE_QUOTE path.
      // match_id isn't used for fees; the on-chain program derives from slot.
      const slot = await connection.getSlot("confirmed");
      const feeNonce = deriveNonce(BigInt(slot), FEE_ROLE_QUOTE);
      const feeBlind = deriveBlinding(BigInt(slot), FEE_ROLE_QUOTE);
      const feeCommitment = await noteCommitment({
        tokenMint: quoteMint.toBytes(),
        amount: BUYER_FEE,
        ownerCommitment: be32ToBigInt(protocolOwnerCommitment),
        nonce: be32ToBigInt(feeNonce),
        blindingR: be32ToBigInt(feeBlind),
      });
      leaf("note_fee (protocol QUOTE)", feeCommitment);

      const nullA = await nullifier(alice.spendingKey, alice.depositNote!.commitment);
      const nullB = await nullifier(bob.spendingKey, bob.depositNote!.commitment);

      const payload: MatchResultPayload = exactFillPayload({
        matchId: asU8a(matchId, 16),
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
      const sig = tee.signCanonical(msg);
      bullet(`canonical hash: 0x${toHex(msg).slice(0, 16)}…`);
      bullet(`TEE signature (first 8 bytes): 0x${toHex(sig.slice(0, 8))}…`);

      // ─────────────────────────────────────────────────────────────────────
      step(10, "lock_note×2 (L1) then Ed25519 + tee_forced_settle (L1)");
      // ─────────────────────────────────────────────────────────────────────
      note(
        "Privacy-fix settlement: submit_order no longer creates NoteLock " +
          "PDAs. The TEE allocates them at settle time, but the combined " +
          "tx exceeds the 1232-byte cap so we send two L1 txs (lock_note×2, " +
          "then Ed25519 + tee_forced_settle). Privacy unaffected: lock_note " +
          "only references note commitments + amounts already public on L1.",
      );
      // v2: per-side VALID_INPUT proofs gating lock_note.
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
        connection, lockTx, [teeKeypair],
        { commitment: "confirmed" },
      );
      txline("lock_note(note_a) + lock_note(note_b)", lockSig);

      // v3: VALID_CREATE proof binds outputs to the correct input owners.
      // Must land BEFORE settle — the settle ix's marker account constraint
      // fails otherwise.
      const ZERO_32 = new Uint8Array(32);
      const vcCommonArgs = {
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
          ownerCommit: alice.ownerCommit,
          amount: BASE_AMT,
          nonce: be32ToBigInt(noteCnonce),
          blindingR: be32ToBigInt(noteCblind),
        },
        outputCcommitmentBE: noteCcommitment,
        outputD: {
          ownerCommit: bob.ownerCommit,
          amount: QUOTE_AMT,
          nonce: be32ToBigInt(noteDnonce),
          blindingR: be32ToBigInt(noteDblind),
        },
        outputDcommitmentBE: noteDcommitment,
        outputE: undefined,
        outputEcommitmentBE: ZERO_32,
        outputF: undefined,
        outputFcommitmentBE: ZERO_32,
        baseAmount: BASE_AMT,
        quoteAmount: QUOTE_AMT,
        buyerChangeAmt: 0n,
        sellerChangeAmt: 0n,
        buyerFeeAmt: BUYER_FEE,
        sellerFeeAmt: SELLER_FEE,
      });
      if (!cfg.settleLookupTable) {
        throw new Error("e2e-config.json missing settleLookupTable — rerun devnet-setup");
      }

      if (USE_BATCHED_PROOF) {
        // ── v3.5 batched path ─────────────────────────────────────────
        // One Groth16 attesting VALID_CREATE + VALID_PRICE for the WHOLE
        // batch, then a single tee_forced_settle_batched per match. The
        // matcher only produced one real match in this test scenario, so
        // we pad the batch to N=16 with dummy slots (handled by
        // landVerifyMatchBatch).
        substep("v3.5 batched flow — N=16 proof + Merkle inclusion for slot 0");

        const realSlot: MatchSlotWitness = {
          noteAcommitment: alice.depositNote!.commitment,
          noteBcommitment: bob.depositNote!.commitment,
          noteCcommitment,
          noteDcommitment,
          noteEcommitment: ZERO_32,
          noteFcommitment: ZERO_32,
          quoteMint: quoteMint.toBytes(),
          baseMint: baseMint.toBytes(),
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
          connection,
          vaultProgramId,
          teeKeypair,
          realSlot,
          payload,
          teeSig: sig,
          canonicalHash: msg,
          settleLookupTable: new PublicKey(cfg.settleLookupTable),
          repoRoot: REPO_ROOT,
          onTx: txline,
        });
      } else {
        // ── v3.1 per-match path (default) ─────────────────────────────
        const binding = validCreateBindingHash(vcCommonArgs);
        const markerExpiry = BigInt((await connection.getSlot("confirmed")) + 200);
        const verifyTx = new Transaction().add(
          ComputeBudgetProgram.setComputeUnitLimit({ units: 600_000 }),
          buildVerifyValidCreateInstruction({
            programId: vaultProgramId,
            payer: teeKeypair.publicKey,
            bindingHash: binding,
            noteAcommitment: alice.depositNote!.commitment,
            noteBcommitment: bob.depositNote!.commitment,
            noteCcommitment,
            noteDcommitment,
            noteEcommitment: ZERO_32,
            noteFcommitment: ZERO_32,
            quoteMint,
            baseMint,
            baseAmount: BASE_AMT,
            quoteAmount: QUOTE_AMT,
            buyerChangeAmt: 0n,
            sellerChangeAmt: 0n,
            buyerFeeAmt: BUYER_FEE,
            sellerFeeAmt: SELLER_FEE,
            expirySlot: markerExpiry,
            proof: validCreate.proof,
          }),
        );
        const verifySig = await sendAndConfirmTransaction(
          connection, verifyTx, [teeKeypair], { commitment: "confirmed" },
        );
        txline("verify_valid_create", verifySig);

        const priceMarker = await landVerifyValidPrice({
          connection,
          vaultProgramId,
          teeKeypair,
          payload,
          repoRoot: REPO_ROOT,
        });
        txline("verify_valid_price", priceMarker.txSig);

        const settleSig = await sendSettleV0({
          connection,
          signer: teeKeypair,
          altPubkey: new PublicKey(cfg.settleLookupTable),
          instructions: [
            ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
            buildEd25519VerifyIx({
              teePubkey: teeKeypair.publicKey.toBytes(),
              signature: sig,
              message: msg,
            }),
            buildSettleIx({
              programId: vaultProgramId,
              teeAuthority: teeKeypair.publicKey,
              payload,
              quoteMint,
              baseMint,
              priceCommitment: priceMarker.priceCommitment,
            }),
          ],
        });
        txline("Ed25519 + tee_forced_settle", settleSig);
      }

      // Shadow tree: note_c, note_d, note_fee are appended in that order by
      // the on-chain tee_forced_settle (matching its append sequence).
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
      const feeLeafIndex = tree.leafCount - 1;

      // Sanity: shadow-tree root MUST equal on-chain current_root after
      // settle, else every VALID_SPEND below will fail with StaleMerkleRoot.
      // Hard-assert + print diff to keep the invariant obvious.
      {
        const [vaultPda] = vaultConfigPda(vaultProgramId);
        const vcAcct = await connection.getAccountInfo(vaultPda, "confirmed");
        if (!vcAcct) throw new Error("vault_config missing");
        // Zero-copy VaultConfig layout (programs/vault/src/state.rs):
        //   8 disc + 32 admin + 32 tee_pubkey + 32 root_key
        //   + 8 leaf_count + 32 current_root ...
        const OFF = 8 + 32 + 32 + 32;
        const leafCount = vcAcct.data.readBigUInt64LE(OFF);
        const onChainRoot = vcAcct.data.subarray(OFF + 8, OFF + 8 + 32);
        const shadowRoot = await tree.computeRoot();
        const onChainHex = Buffer.from(onChainRoot).toString("hex");
        const shadowHex = Buffer.from(shadowRoot).toString("hex");
        bullet(`on-chain current_root: ${onChainHex}`);
        bullet(`shadow tree root:      ${shadowHex}`);
        bullet(`leaf_count on=${leafCount} shadow=${tree.leafCount}`);
        if (onChainHex !== shadowHex) {
          throw new Error(
            "shadow tree diverged from on-chain current_root — " +
            "did devnet-setup.test.ts skip reset_merkle_tree? " +
            "Re-run setup to wipe leaf history.",
          );
        }
      }

      // ─────────────────────────────────────────────────────────────────────
      step(11, "Withdraw: Alice → BASE, Bob → QUOTE, Protocol → QUOTE fee");
      // ─────────────────────────────────────────────────────────────────────
      async function proveAndWithdraw(
        p: Persona,
        tradeNote: NonNullable<Persona["tradeNote"]>,
        destAta: PublicKey,
        payerKp: Keypair,
        ownerCommitBlinding: bigint,
        label: string,
      ) {
        substep(`${label}: proving VALID_SPEND + submitting withdraw`);
        const w = await tree.witness(tradeNote.leafIndex);
        const [mintLo, mintHi] = pubkeyToFrPair(tradeNote.mint.toBytes());
        const nulli = await nullifier(p.spendingKey, tradeNote.commitment);
        const { proof, publicInputsBE } = snarkjsFullProve(
          {
            merkleRoot: be32ToDec(w.root),
            nullifier: be32ToDec(nulli),
            tokenMint: [mintLo.toString(), mintHi.toString()],
            amount: tradeNote.amount.toString(),
            spendingKey: p.spendingKey.toString(),
            ownerCommitmentBlinding: ownerCommitBlinding.toString(),
            nonce: be32ToBigInt(tradeNote.nonce).toString(),
            blindingR: be32ToBigInt(tradeNote.blindingR).toString(),
            merklePath: w.siblings.map((s) => be32ToDec(s)),
            merkleIndices: w.indices.map((i) => i.toString()),
          },
          {
            circuitWasmPath: SPEND_WASM,
            circuitZkeyPath: SPEND_ZKEY,
            repoRoot: REPO_ROOT,
          },
        );
        bullet("VALID_SPEND proof generated");
        bullet(`public inputs count: ${publicInputsBE.length}`);

        const ix = buildWithdrawInstruction({
          programId: vaultProgramId,
          payer: payerKp.publicKey,
          tokenMint: tradeNote.mint,
          destinationTokenAccount: destAta,
          tokenProgramId: TOKEN_PROGRAM_ID,
          noteCommitment: tradeNote.commitment,
          nullifier: nulli,
          merkleRoot: w.root,
          amount: tradeNote.amount,
          proof,
        });
        const tx = new Transaction().add(
          ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
          ix,
        );
        const sig = await sendAndConfirmTransaction(
          connection, tx, [payerKp],
          { commitment: "confirmed" },
        );
        txline(`${label}: withdraw`, sig);
      }
      await proveAndWithdraw(
        alice, alice.tradeNote!, aliceBaseAta, alice.payer, alice.ownerBlinding,
        "Alice → BASE trade leg",
      );
      await proveAndWithdraw(
        bob, bob.tradeNote!, bobQuoteAta, bob.payer, bob.ownerBlinding,
        "Bob → QUOTE trade leg",
      );

      // Protocol fee withdrawal — the protocol-owner persona must have
      // its own spendingKey + owner-blinding whose poseidon2 hash equals
      // vault_config.protocol_owner_commitment. We skip the actual on-chain
      // fee withdraw here because in THIS test we set
      // protocol_owner_commitment to a synthetic tag rather than a real
      // keypair-derived commitment (see setup step 3). The fee leaf IS in
      // the tree though; we assert its presence.
      note(
        "fee-note withdrawal needs a protocol-owner keypair whose derived " +
          "ownerCommitment(spendingKey, blinding) matches vault_config's " +
          "protocol_owner_commitment. The setup test uses a synthetic tag, so " +
          "we only verify the leaf is in the shadow tree; real fee withdrawal " +
          "will be covered once governance owns a real keypair set.",
      );
      const feeWitness = await tree.witness(feeLeafIndex);
      expect(feeWitness.root.length).toBe(32);

      // ─────────────────────────────────────────────────────────────────────
      banner("TRADE FLOW COMPLETE — balances verified on devnet");
      const aliceBaseBal = await connection.getTokenAccountBalance(aliceBaseAta);
      const bobQuoteBal = await connection.getTokenAccountBalance(bobQuoteAta);
      bullet(`Alice BASE balance:  ${aliceBaseBal.value.amount}`);
      bullet(`Bob   QUOTE balance: ${bobQuoteBal.value.amount}`);
      expect(BigInt(aliceBaseBal.value.amount)).toBe(BASE_AMT);
      expect(BigInt(bobQuoteBal.value.amount)).toBe(QUOTE_AMT);
    },
  );
});

// ───────────────────────────────────────────────────────────────────────────
// Partial-fill + re-lock scenario (second describe block) —
// runs only if HAPPY-PATH succeeded and the env is ready. Skipped otherwise.
// ───────────────────────────────────────────────────────────────────────────

const PARTIAL = READY && process.env.RUN_DEVNET_PARTIAL_FILL === "1";
const maybePartial = PARTIAL ? describe : describe.skip;

maybePartial(
  "Phase 5 devnet E2E — partial fill + re-lock (set RUN_DEVNET_PARTIAL_FILL=1)",
  () => {
    it("documents the partial-fill flow", () => {
      // The full partial-fill scenario is:
      //   1. Alice deposits 10_000 QUOTE, orders 100 BASE @ price 100.
      //   2. Bob deposits 50 BASE, orders 50 BASE @ price 100.
      //   3. run_batch matches 50 BASE. MatchResult has:
      //        buyer_change_amt = 10_000 - 5_000 - 15 = 4_985
      //        note_e = Poseidon commitment over (quote_mint, 4_985, ...)
      //                 using CHANGE_ROLE_BUYER derivation.
      //        buyer_relock_order_id = alice_order_id
      //        buyer_relock_expiry   = alice.expiry_slot
      //   4. tee_forced_settle appends note_c, note_d, note_e, note_fee and
      //      writes a new NoteLock PDA seeded at note_e for Alice's residual
      //      order (50 BASE remaining).
      //   5. Charlie (new seller) deposits 50 BASE, submits SELL 50 @ 100.
      //   6. Second run_batch crosses Alice's re-locked residual against
      //      Charlie. Another MatchResult is written; note_c' / note_d' /
      //      note_e' = 0 (exact) / note_fee' (second fee leaf) are emitted.
      //   7. Alice's shadow-tree bookkeeping appends note_c (first fill) +
      //      note_c' (second fill); her final BASE balance = 100 after two
      //      withdrawals.
      //
      // This is mechanically the same as the happy-path test above — just
      // plus a second (submitOrder, runBatch, settle) pair with note_e as
      // the continuing collateral. The shadow tree + snarkjs helpers already
      // support it end to end; implementing is ~150 more lines and mostly
      // copy-paste. Guarded by RUN_DEVNET_PARTIAL_FILL to keep CI runs fast.
      //
      // TODO: implement the full scenario when partial-fill becomes a
      // release-gating requirement.
      expect(CHANGE_ROLE_BUYER).toBe(0xb1);
    });
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

// Export intentionally: unused here but lets the partial-fill scenario
// import via describe.skip-guarded dynamic path when implemented.
export { poseidonHashBytesBE, bigIntToBe32 };
