/**
 * Phase-5 Nyx Darkpool — one-time devnet bootstrap for the E2E trade flow.
 *
 * This file is meant to run ONCE per environment (or whenever the token pair
 * changes / the market is reset). It is idempotent where possible — init_market
 * against an existing market will fail, so we key the market PDA off the
 * (base_mint, quote_mint) pair and only re-create if the config is absent.
 *
 * What it does, with heavy narrative logging:
 *
 *   1. Reads admin / tee / root_key keypairs from `.devnet/keypairs/`.
 *   2. Connects to devnet RPC.
 *   3. Creates two fresh SPL mints (BASE + QUOTE share the same decimal count,
 *      default 6 each — override with DEMO_MINT_DECIMALS=0..9) and records them.
 *   4. Initialises the vault (if not already done) with the deployed program.
 *   5. Calls `set_protocol_config` to enable a 30 bps protocol fee, addressed
 *      to a synthetic protocol-owner commitment.
 *   6. Chooses a "market" pubkey (a fresh Keypair.publicKey) and calls
 *      `init_market` on matching_engine with that pair.
 *   7. Writes everything to `.devnet/e2e-config.json` so the flow test can
 *      consume it without duplicating PDA derivation.
 *
 * NOT done here (intentionally, to keep this test focused on setup):
 *   - Creating end-user Alice / Bob keypairs or depositing.
 *   - Calling `delegate_dark_clob` — the flow test runs `run_batch` directly
 *     on L1 (a deliberate shortcut; see §9 of dev-commands.md).
 *
 * Run:
 *   RUN_DEVNET_E2E=1 \
 *     ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
 *     TEE_AUTHORITY_KEYPAIR=.devnet/keypairs/tee_authority.json \
 *     ROOT_KEY_KEYPAIR=.devnet/keypairs/root_key.json \
 *     cd packages/sdk && ../../node_modules/.bin/vitest run tests/devnet-setup.test.ts
 */

import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { resolve } from "node:path";

import { config as dotenvConfig } from "dotenv";
import { beforeAll, describe, expect, it } from "vitest";
import {
  createInitializeMintInstruction,
  MINT_SIZE,
  TOKEN_PROGRAM_ID,
  getMinimumBalanceForRentExemptMint,
} from "@solana/spl-token";
import {
  AddressLookupTableProgram,
  Connection,
  Keypair,
  PublicKey,
  SYSVAR_INSTRUCTIONS_PUBKEY,
  SystemProgram,
  Transaction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";

import {
  buildInitializeInstruction,
  buildResetMerkleTreeInstruction,
  buildSetProtocolConfigInstruction,
  vaultConfigPda,
} from "../src/idl/vault-client.js";
import {
  buildInitMarketInstruction,
  buildInitMockOracleInstruction,
  batchResultsPda,
  darkClobPda,
  matchingConfigPda,
} from "../src/idl/matching-engine-client.js";

// ────────────────────────────────────────────────────────────────────────────
// env + keypair loading
// ────────────────────────────────────────────────────────────────────────────

dotenvConfig({ path: resolve(__dirname, "../.env.devnet") });

const RUN = process.env.RUN_DEVNET_E2E === "1";
const maybeDescribe = RUN ? describe : describe.skip;

const REPO_ROOT = resolve(__dirname, "../../..");
const CONFIG_PATH = resolve(REPO_ROOT, ".devnet/e2e-config.json");

const L1_RPC_URL =
  process.env.L1_RPC_URL ?? "https://api.devnet.solana.com";
const VAULT_PROGRAM_ID = new PublicKey(
  process.env.VAULT_PROGRAM_ID ??
    "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
);
const ME_PROGRAM_ID = new PublicKey(
  process.env.MATCHING_ENGINE_PROGRAM_ID ??
    "6EasFxo6RCWrK4KAwcdUJqL4KjReLC3rtah8EtHgHSqe",
);
// Pyth SOL/USD devnet feed. init_market only persists this; it's read by run_batch.
const PYTH_ACCOUNT = new PublicKey(
  process.env.PYTH_ACCOUNT ??
    "J83w4HKfqxwcq3BEMMkPFSppX3gqekLyLJBexebFVkix",
);

const PROTOCOL_FEE_BPS = Number(process.env.PROTOCOL_FEE_BPS ?? "30");

/** SPL mint decimals for both BASE and QUOTE (0–9). Default 6 keeps human peg aligned with atomic `price_limit` when mock TWAP = 100. */
const DEMO_MINT_DECIMALS = (() => {
  const n = Number(process.env.DEMO_MINT_DECIMALS ?? "6");
  if (!Number.isInteger(n) || n < 0 || n > 9) {
    throw new Error("DEMO_MINT_DECIMALS must be an integer 0..9");
  }
  return n;
})();

function rpcHostLabel(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return "(invalid-rpc-url)";
  }
}

function loadKeypair(relPath: string): Keypair {
  const abs = resolve(REPO_ROOT, relPath);
  if (!existsSync(abs)) {
    throw new Error(
      `keypair not found at ${abs} — run scripts/setup-devnet.sh first`,
    );
  }
  const raw = JSON.parse(readFileSync(abs, "utf8")) as number[];
  return Keypair.fromSecretKey(new Uint8Array(raw));
}

function requireEnv(k: string): string {
  const v = process.env[k];
  if (!v) throw new Error(`missing env: ${k}`);
  return v;
}

// ────────────────────────────────────────────────────────────────────────────
// Verbose, highlighted logging
// ────────────────────────────────────────────────────────────────────────────

const BAR = "═".repeat(78);
const HBAR = "─".repeat(78);

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

function tx(note: string, signature: string) {
  console.log(`  >> ${note}`);
  console.log(`     TX: ${signature}`);
  console.log(`     EXPLORER: https://explorer.solana.com/tx/${signature}?cluster=devnet`);
}

function bullet(text: string) {
  console.log(`     • ${text}`);
}

// ────────────────────────────────────────────────────────────────────────────

export interface E2EConfig {
  l1RpcUrl: string;
  vaultProgramId: string;
  matchingEngineProgramId: string;
  pythAccount: string;
  baseMint: {
    pubkey: string;
    decimals: number;
    secretKey: number[];
  };
  quoteMint: {
    pubkey: string;
    decimals: number;
    secretKey: number[];
  };
  market: {
    pubkey: string;
    secretKey: number[];
    batchIntervalSlots: string;
    circuitBreakerBps: string;
    tickSize: string;
    minOrderSize: string;
  };
  protocol: {
    ownerCommitmentHex: string;
    feeRateBps: number;
  };
  vaultConfigPda: string;
  darkClobPda: string;
  matchingConfigPda: string;
  batchResultsPda: string;
  /**
   * v3 — Address Lookup Table that hoists the three static accounts
   * (vault_config, instructions_sysvar, system_program) out of the settle
   * tx's account-keys list. Saves ~60 bytes on every settle vs. legacy txs,
   * which buys headroom for the VALID_CREATE marker + future expansion.
   *
   * Optional: callers can still send a legacy settle tx when the marker
   * fits; the v0 wrapper is preferred for change-note / re-lock paths
   * where the tx is at the edge of the 1232-byte cap.
   */
  settleLookupTable?: string;
  createdAt: string;
}

function saveConfig(cfg: E2EConfig) {
  mkdirSync(resolve(REPO_ROOT, ".devnet"), { recursive: true });
  writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2) + "\n");
}

async function tryReadVaultConfig(
  connection: Connection,
  vaultPda: PublicKey,
): Promise<boolean> {
  const info = await connection.getAccountInfo(vaultPda, "confirmed");
  return !!info;
}

// ────────────────────────────────────────────────────────────────────────────

maybeDescribe("Phase 5 devnet E2E — one-shot setup", () => {
  let connection: Connection;
  let admin: Keypair;
  let tee: Keypair;
  let rootKey: Keypair;

  beforeAll(async () => {
    connection = new Connection(L1_RPC_URL, "confirmed");
    admin = loadKeypair(requireEnv("ADMIN_KEYPAIR"));
    tee = loadKeypair(requireEnv("TEE_AUTHORITY_KEYPAIR"));
    rootKey = loadKeypair(requireEnv("ROOT_KEY_KEYPAIR"));

    banner("NYX DARKPOOL — DEVNET E2E SETUP");
    bullet(`RPC:                   ${rpcHostLabel(L1_RPC_URL)}`);
    bullet(`vault program:         ${VAULT_PROGRAM_ID.toBase58()}`);
    bullet(`matching_engine:       ${ME_PROGRAM_ID.toBase58()}`);
    bullet(`pyth:                  ${PYTH_ACCOUNT.toBase58()}`);
    bullet(`admin:                 ${admin.publicKey.toBase58()}`);
    bullet(`tee_authority:         ${tee.publicKey.toBase58()}`);
    bullet(`root_key:              ${rootKey.publicKey.toBase58()}`);
    bullet(`protocol fee (bps):    ${PROTOCOL_FEE_BPS}`);
    bullet(`mint decimals (both):  ${DEMO_MINT_DECIMALS} (override with DEMO_MINT_DECIMALS)`);

    const bal = await connection.getBalance(admin.publicKey);
    bullet(`admin balance:         ${(bal / 1e9).toFixed(4)} SOL`);
    if (bal < 0.5 * 1e9) {
      throw new Error(
        `admin has < 0.5 SOL; fund first via 'solana airdrop 2 ${admin.publicKey.toBase58()}'`,
      );
    }
  }, 30_000);

  it(
    "creates token pair, initialises vault + protocol config + market, writes config.json",
    { timeout: 180_000 },
    async () => {
      // ────────────────────────────────────────────────────────────────────
      step(1, `Create BASE + QUOTE SPL mints (${DEMO_MINT_DECIMALS} decimals each)`);
      // ────────────────────────────────────────────────────────────────────
      const baseMint = Keypair.generate();
      const quoteMint = Keypair.generate();
      bullet(`BASE mint pubkey:   ${baseMint.publicKey.toBase58()}`);
      bullet(`QUOTE mint pubkey:  ${quoteMint.publicKey.toBase58()}`);

      const rentLamports = await getMinimumBalanceForRentExemptMint(connection);

      const mintTx = new Transaction().add(
        SystemProgram.createAccount({
          fromPubkey: admin.publicKey,
          newAccountPubkey: baseMint.publicKey,
          space: MINT_SIZE,
          lamports: rentLamports,
          programId: TOKEN_PROGRAM_ID,
        }),
        createInitializeMintInstruction(
          baseMint.publicKey,
          DEMO_MINT_DECIMALS,
          admin.publicKey,
          null,
          TOKEN_PROGRAM_ID,
        ),
        SystemProgram.createAccount({
          fromPubkey: admin.publicKey,
          newAccountPubkey: quoteMint.publicKey,
          space: MINT_SIZE,
          lamports: rentLamports,
          programId: TOKEN_PROGRAM_ID,
        }),
        createInitializeMintInstruction(
          quoteMint.publicKey,
          DEMO_MINT_DECIMALS,
          admin.publicKey,
          null,
          TOKEN_PROGRAM_ID,
        ),
      );
      const mintSig = await sendAndConfirmTransaction(
        connection,
        mintTx,
        [admin, baseMint, quoteMint],
        { commitment: "confirmed" },
      );
      tx(`created both SPL mints (BASE=${DEMO_MINT_DECIMALS}d, QUOTE=${DEMO_MINT_DECIMALS}d)`, mintSig);

      // ────────────────────────────────────────────────────────────────────
      step(2, "Initialise vault_config (idempotent)");
      // ────────────────────────────────────────────────────────────────────
      const [vaultPda] = vaultConfigPda(VAULT_PROGRAM_ID);
      bullet(`vault_config PDA:   ${vaultPda.toBase58()}`);
      const alreadyInit = await tryReadVaultConfig(connection, vaultPda);
      if (alreadyInit) {
        bullet("vault_config exists; skipping initialize");
      } else {
        const initTx = new Transaction().add(
          buildInitializeInstruction({
            programId: VAULT_PROGRAM_ID,
            admin: admin.publicKey,
            teePubkey: tee.publicKey,
            rootKey: rootKey.publicKey,
          }),
        );
        const sig = await sendAndConfirmTransaction(connection, initTx, [admin], {
          commitment: "confirmed",
        });
        tx("initialize(vault_config)", sig);
      }

      // ────────────────────────────────────────────────────────────────────
      step(3, "Set protocol-fee config (30 bps, synthetic owner commitment)");
      // ────────────────────────────────────────────────────────────────────
      // Protocol-owner commitment is an opaque 32-byte field; treat it as the
      // Poseidon commitment of the protocol multisig's viewing-key family.
      // In a real deployment this is derived from a dedicated governance seed;
      // here we use a deterministic constant so the test is reproducible.
      // NOTE: Poseidon requires inputs < BN254 Fr modulus (first byte <= 0x30).
      // "nyx-protocol-owner-v1" starts with 0x6e which exceeds the field — we
      // zero the top byte to keep the commitment in-range. Mirrors the
      // `user_commitment[0] = 0` pattern in the matching_engine Rust harness.
      const protocolOwnerCommitment = new Uint8Array(32);
      const tag = new TextEncoder().encode("nyx-protocol-owner-v1");
      protocolOwnerCommitment.set(tag.slice(0, 32));
      protocolOwnerCommitment[0] = 0; // keep value < BN254 Fr

      // DEV-NET: wipe the vault's Merkle tree so the trade-flow test's
      // in-memory shadow tree starts from the same empty root as on-chain.
      // Idempotent + admin-gated. See programs/vault/src/instructions/reset_merkle_tree.rs.
      const resetTx = new Transaction().add(
        buildResetMerkleTreeInstruction({
          programId: VAULT_PROGRAM_ID,
          admin: admin.publicKey,
        }),
      );
      const resetSig = await sendAndConfirmTransaction(connection, resetTx, [admin], {
        commitment: "confirmed",
      });
      tx("reset_merkle_tree (devnet-only)", resetSig);

      const spcTx = new Transaction().add(
        buildSetProtocolConfigInstruction({
          programId: VAULT_PROGRAM_ID,
          admin: admin.publicKey,
          protocolOwnerCommitment,
          feeRateBps: PROTOCOL_FEE_BPS,
        }),
      );
      const spcSig = await sendAndConfirmTransaction(connection, spcTx, [admin], {
        commitment: "confirmed",
      });
      tx(`set_protocol_config(fee_rate=${PROTOCOL_FEE_BPS}bps)`, spcSig);

      // ────────────────────────────────────────────────────────────────────
      step(4, "init_market on matching_engine (with mock oracle for devnet)");
      // ────────────────────────────────────────────────────────────────────
      // Pyth Pull-Oracle v2 (`PriceUpdateV2`) accounts on devnet are rarely
      // actively-maintained for arbitrary feeds, and the old Pythnet-legacy
      // accounts (magic 0xa1b2c3d4) are not recognised by our `read_oracle`.
      // So we create a tiny mock-oracle account (magic NYXMKPTH + u64 TWAP)
      // via the new `init_mock_oracle` ix and bake its pubkey into the
      // market config. The circuit breaker still fires meaningfully —
      // just against a TWAP we control.
      const useMockOracle =
        !process.env.PYTH_ACCOUNT ||
        (process.env.USE_MOCK_ORACLE ?? "1") === "1";

      let oracleAccount: PublicKey;
      if (useMockOracle) {
        const mockOracleKp = Keypair.generate();
        const MOCK_TWAP = 100n;
        const mockTx = new Transaction().add(
          buildInitMockOracleInstruction({
            programId: ME_PROGRAM_ID,
            payer: admin.publicKey,
            mockOracle: mockOracleKp.publicKey,
            twap: MOCK_TWAP,
          }),
        );
        const mockSig = await sendAndConfirmTransaction(
          connection, mockTx, [admin, mockOracleKp],
          { commitment: "confirmed" },
        );
        tx(`init_mock_oracle (twap=${MOCK_TWAP}) at ${mockOracleKp.publicKey.toBase58()}`, mockSig);
        oracleAccount = mockOracleKp.publicKey;
      } else {
        oracleAccount = PYTH_ACCOUNT;
        bullet(`using real Pyth feed: ${oracleAccount.toBase58()}`);
      }

      const market = Keypair.generate();
      const batchIntervalSlots = 8n;
      const circuitBreakerBps = 500n; // 5% deviation before breaker trips
      const tickSize = 1n;
      const minOrderSize = 1n;

      bullet(`market pubkey:          ${market.publicKey.toBase58()}`);
      bullet(`oracle account:         ${oracleAccount.toBase58()}`);
      bullet(`batch interval slots:   ${batchIntervalSlots}`);
      bullet(`circuit breaker bps:    ${circuitBreakerBps}`);
      bullet(`tick size:              ${tickSize}`);
      bullet(`min order size:         ${minOrderSize}`);

      const [clob] = darkClobPda(ME_PROGRAM_ID, market.publicKey);
      const [mcfg] = matchingConfigPda(ME_PROGRAM_ID, market.publicKey);
      const [breq] = batchResultsPda(ME_PROGRAM_ID, market.publicKey);
      bullet(`dark_clob PDA:          ${clob.toBase58()}`);
      bullet(`matching_config PDA:    ${mcfg.toBase58()}`);
      bullet(`batch_results PDA:      ${breq.toBase58()}`);

      const imTx = new Transaction().add(
        buildInitMarketInstruction({
          programId: ME_PROGRAM_ID,
          vaultProgramId: VAULT_PROGRAM_ID,
          payer: admin.publicKey,
          market: market.publicKey,
          baseMint: baseMint.publicKey,
          quoteMint: quoteMint.publicKey,
          pythAccount: oracleAccount,
          batchIntervalSlots,
          circuitBreakerBps,
          tickSize,
          minOrderSize,
        }),
      );
      const imSig = await sendAndConfirmTransaction(connection, imTx, [admin], {
        commitment: "confirmed",
      });
      tx("init_market", imSig);

      // ────────────────────────────────────────────────────────────────────
      step(5, "Create Address Lookup Table for settle txs (v3 size relief)");
      // ────────────────────────────────────────────────────────────────────
      // Hoist the three accounts that appear in EVERY settle tx and never
      // change: vault_config, instructions sysvar, system program. The
      // address-lookup-table compresses each from 32 bytes (in the keys
      // list) to 1 byte (an index into the ALT), saving ~60 bytes net
      // after the ALT pubkey overhead.
      const slot = await connection.getSlot("confirmed");
      const [createAltIx, settleLookupTable] =
        AddressLookupTableProgram.createLookupTable({
          authority: admin.publicKey,
          payer: admin.publicKey,
          recentSlot: slot,
        });
      const extendAltIx = AddressLookupTableProgram.extendLookupTable({
        payer: admin.publicKey,
        authority: admin.publicKey,
        lookupTable: settleLookupTable,
        addresses: [vaultPda, SYSVAR_INSTRUCTIONS_PUBKEY, SystemProgram.programId],
      });
      const altTx = new Transaction().add(createAltIx, extendAltIx);
      const altSig = await sendAndConfirmTransaction(connection, altTx, [admin], {
        commitment: "confirmed",
      });
      tx("createLookupTable + extendLookupTable", altSig);
      bullet(`settle ALT: ${settleLookupTable.toBase58()}`);
      // Solana requires a fresh ALT to be at least one slot old before it
      // can be referenced by a tx. Block briefly so the test that runs
      // immediately after setup doesn't hit "ALT not found".
      const altReadySlot = await connection.getSlot("confirmed");
      while ((await connection.getSlot("confirmed")) <= altReadySlot) {
        await new Promise((r) => setTimeout(r, 200));
      }

      // ────────────────────────────────────────────────────────────────────
      step(6, "Persist config to .devnet/e2e-config.json");
      // ────────────────────────────────────────────────────────────────────
      const cfg: E2EConfig = {
        l1RpcUrl: L1_RPC_URL,
        vaultProgramId: VAULT_PROGRAM_ID.toBase58(),
        matchingEngineProgramId: ME_PROGRAM_ID.toBase58(),
        pythAccount: oracleAccount.toBase58(),
        baseMint: {
          pubkey: baseMint.publicKey.toBase58(),
          decimals: DEMO_MINT_DECIMALS,
          secretKey: Array.from(baseMint.secretKey),
        },
        quoteMint: {
          pubkey: quoteMint.publicKey.toBase58(),
          decimals: DEMO_MINT_DECIMALS,
          secretKey: Array.from(quoteMint.secretKey),
        },
        market: {
          pubkey: market.publicKey.toBase58(),
          secretKey: Array.from(market.secretKey),
          batchIntervalSlots: batchIntervalSlots.toString(),
          circuitBreakerBps: circuitBreakerBps.toString(),
          tickSize: tickSize.toString(),
          minOrderSize: minOrderSize.toString(),
        },
        protocol: {
          ownerCommitmentHex: Buffer.from(protocolOwnerCommitment).toString("hex"),
          feeRateBps: PROTOCOL_FEE_BPS,
        },
        vaultConfigPda: vaultPda.toBase58(),
        darkClobPda: clob.toBase58(),
        matchingConfigPda: mcfg.toBase58(),
        batchResultsPda: breq.toBase58(),
        settleLookupTable: settleLookupTable.toBase58(),
        createdAt: new Date().toISOString(),
      };
      saveConfig(cfg);
      bullet(`wrote: ${CONFIG_PATH}`);

      banner("SETUP COMPLETE — run devnet-trade-flow.test.ts next");

      // Sanity assertions
      expect(existsSync(CONFIG_PATH)).toBe(true);
      const reread = JSON.parse(readFileSync(CONFIG_PATH, "utf8")) as E2EConfig;
      expect(reread.market.pubkey).toBe(market.publicKey.toBase58());
      expect(reread.protocol.feeRateBps).toBe(PROTOCOL_FEE_BPS);
    },
  );
});
