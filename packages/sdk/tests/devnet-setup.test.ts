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

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
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
  buildInitializeTreeInstruction,
  buildResetMerkleTreeInstruction,
  buildSetProtocolConfigInstruction,
  merkleTreePda,
  staticSettleAltAddresses,
  vaultConfigPda,
} from "../src/idl/vault-client.js";

// ────────────────────────────────────────────────────────────────────────────
// env + keypair loading
// ────────────────────────────────────────────────────────────────────────────

dotenvConfig({ path: resolve(__dirname, "../.env.devnet") });

const RUN = process.env.RUN_DEVNET_E2E === "1";
const maybeDescribe = RUN ? describe : describe.skip;

const REPO_ROOT = resolve(__dirname, "../../..");
const CONFIG_PATH = resolve(REPO_ROOT, ".devnet/e2e-config.json");

const L1_RPC_URL = process.env.L1_RPC_URL ?? "https://api.devnet.solana.com";
const VAULT_PROGRAM_ID = new PublicKey(
  process.env.VAULT_PROGRAM_ID ??
    "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
);

const PROTOCOL_FEE_BPS = Number(process.env.PROTOCOL_FEE_BPS ?? "30");

/** Number of Merkle-tree shards to provision. The CVM settle worker
 *  round-robins settles across K shards + K fee-payer keys; this must equal
 *  the CVM's `NYX_TEE_NUM_TREES`. Default 1 (single shard). */
const NUM_TREES = (() => {
  const n = Number(process.env.NYX_NUM_TREES ?? "1");
  if (!Number.isInteger(n) || n < 1 || n > 16) {
    throw new Error("NYX_NUM_TREES must be an integer 1..16");
  }
  return n;
})();

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
  console.log(
    `     EXPLORER: https://explorer.solana.com/tx/${signature}?cluster=devnet`,
  );
}

function bullet(text: string) {
  console.log(`     • ${text}`);
}

// ────────────────────────────────────────────────────────────────────────────

export interface E2EConfig {
  l1RpcUrl: string;
  vaultProgramId: string;
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
  protocol: {
    ownerCommitmentHex: string;
    feeRateBps: number;
  };
  vaultConfigPda: string;
  /** Number of Merkle-tree shards provisioned. The CVM's NYX_TEE_NUM_TREES
   *  must equal this. */
  numTrees: number;
  /** The K `MerkleTree` shard PDAs, indexed by tree_id. */
  merkleTreePdas: string[];
  /**
   * v3 — Address Lookup Table that hoists the static settle accounts
   * (vault_config, instructions_sysvar, system_program) AND the K merkle_tree
   * shard PDAs out of the settle tx's account-keys list. Saves bytes on every
   * settle vs. legacy txs, which buys headroom under the 1232-byte cap.
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
  // A closed VaultConfig (post `close_vault_config`) can briefly linger as a
  // 0-lamport, program- or System-owned shell on some RPCs even though it's been
  // reclaimed. Only a FUNDED, vault-program-owned account is genuinely
  // initialized — an existence-only check would wrongly skip `initialize` during
  // a re-foundation (VaultConfig layout change) and then fail at reset_merkle_tree.
  return !!info && info.lamports > 0 && info.owner.equals(VAULT_PROGRAM_ID);
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
    bullet(`admin:                 ${admin.publicKey.toBase58()}`);
    bullet(`tee_authority:         ${tee.publicKey.toBase58()}`);
    bullet(`root_key:              ${rootKey.publicKey.toBase58()}`);
    bullet(`protocol fee (bps):    ${PROTOCOL_FEE_BPS}`);
    bullet(
      `mint decimals (both):  ${DEMO_MINT_DECIMALS} (override with DEMO_MINT_DECIMALS)`,
    );

    const bal = await connection.getBalance(admin.publicKey);
    bullet(`admin balance:         ${(bal / 1e9).toFixed(4)} SOL`);
    if (bal < 0.5 * 1e9) {
      throw new Error(
        `admin has < 0.5 SOL; fund first via 'solana airdrop 2 ${admin.publicKey.toBase58()}'`,
      );
    }
  }, 30_000);

  it(
    "creates token pair, initialises vault + protocol config + settle ALT, writes config.json",
    { timeout: 180_000 },
    async () => {
      // ────────────────────────────────────────────────────────────────────
      step(
        1,
        `Create BASE + QUOTE SPL mints (${DEMO_MINT_DECIMALS} decimals each)`,
      );
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
      tx(
        `created both SPL mints (BASE=${DEMO_MINT_DECIMALS}d, QUOTE=${DEMO_MINT_DECIMALS}d)`,
        mintSig,
      );

      // ────────────────────────────────────────────────────────────────────
      step(
        2,
        `Initialise vault_config + ${NUM_TREES} Merkle-tree shard(s) (idempotent)`,
      );
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
            numTrees: NUM_TREES,
          }),
        );
        const sig = await sendAndConfirmTransaction(
          connection,
          initTx,
          [admin],
          {
            commitment: "confirmed",
          },
        );
        tx("initialize(vault_config)", sig);
      }

      // Create each Merkle-tree shard account (idempotent — skip if it exists).
      // The settle worker appends to merkle_tree[tree_id]; ALL K must exist
      // before the CVM can settle to any non-zero shard.
      const merkleTreePdas: PublicKey[] = [];
      for (let treeId = 0; treeId < NUM_TREES; treeId++) {
        const [treePda] = merkleTreePda(VAULT_PROGRAM_ID, treeId);
        merkleTreePdas.push(treePda);
        const exists = await connection.getAccountInfo(treePda);
        if (exists) {
          bullet(`merkle_tree[${treeId}] exists: ${treePda.toBase58()}`);
          continue;
        }
        const treeTx = new Transaction().add(
          buildInitializeTreeInstruction({
            programId: VAULT_PROGRAM_ID,
            admin: admin.publicKey,
            treeId,
          }),
        );
        const sig = await sendAndConfirmTransaction(
          connection,
          treeTx,
          [admin],
          {
            commitment: "confirmed",
          },
        );
        tx(`initialize_tree(${treeId})`, sig);
        bullet(`merkle_tree[${treeId}]: ${treePda.toBase58()}`);
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

      // DEV-NET: wipe every Merkle-tree shard so the trade-flow test's
      // in-memory shadow trees start from the same empty root as on-chain.
      // Idempotent + admin-gated. See programs/vault/src/instructions/reset_merkle_tree.rs.
      for (let treeId = 0; treeId < NUM_TREES; treeId++) {
        const resetTx = new Transaction().add(
          buildResetMerkleTreeInstruction({
            programId: VAULT_PROGRAM_ID,
            admin: admin.publicKey,
            treeId,
          }),
        );
        const resetSig = await sendAndConfirmTransaction(
          connection,
          resetTx,
          [admin],
          {
            commitment: "confirmed",
          },
        );
        tx(`reset_merkle_tree(${treeId}) (devnet-only)`, resetSig);
      }

      // Publish the matcher-governance params on-chain (single-place config in
      // VaultConfig). The TEE adopts each non-zero value over its env/dev default
      // at boot (0 = unset). Non-zero + != the env defaults so a CVM run proves
      // the on-chain read fired (look for "adopting on-chain matcher param" in
      // the boot log).
      //
      // circuit_breaker_bps is 5000 (50% band), NOT a tight production value:
      // cvm-settle-e2e submits synthetic bid=1.2x / ask=0.8x oracle spreads, so
      // the clearing price deviates ~20% from the Pyth TWAP. A band below that
      // (e.g. 250) correctly TRIPS the breaker (deviates_by_more_than_bps →
      // cb_tripped, no matches) and nothing settles — validated live 2026-07-10.
      // 5000 comfortably clears the ~20% synthetic deviation while still being a
      // meaningful non-default that exercises the adopt path.
      const ON_CHAIN_TICK_SIZE = 5n;
      const ON_CHAIN_MIN_ORDER_SIZE = 1_000n;
      const ON_CHAIN_CIRCUIT_BREAKER_BPS = 5_000n;
      const spcTx = new Transaction().add(
        buildSetProtocolConfigInstruction({
          programId: VAULT_PROGRAM_ID,
          admin: admin.publicKey,
          protocolOwnerCommitment,
          feeRateBps: PROTOCOL_FEE_BPS,
          tickSize: ON_CHAIN_TICK_SIZE,
          minOrderSize: ON_CHAIN_MIN_ORDER_SIZE,
          circuitBreakerBps: ON_CHAIN_CIRCUIT_BREAKER_BPS,
        }),
      );
      const spcSig = await sendAndConfirmTransaction(
        connection,
        spcTx,
        [admin],
        {
          commitment: "confirmed",
        },
      );
      tx(
        `set_protocol_config(fee_rate=${PROTOCOL_FEE_BPS}bps, tick=${ON_CHAIN_TICK_SIZE}, ` +
          `min_order=${ON_CHAIN_MIN_ORDER_SIZE}, cb=${ON_CHAIN_CIRCUIT_BREAKER_BPS}bps)`,
        spcSig,
      );

      // ────────────────────────────────────────────────────────────────────
      step(4, "Create Address Lookup Table for settle txs (size relief)");
      // ────────────────────────────────────────────────────────────────────
      // Hoist the static settle accounts (vault_config, instructions sysvar,
      // system program) AND the K merkle_tree shard PDAs out of the settle tx's
      // account-keys list — the address-lookup-table compresses each from 32
      // bytes to a 1-byte index. With sharding the worker references its
      // merkle_tree[j] from this ALT, so all K shards must be listed (mirrors
      // the Rust static_alt_addresses).
      const altAddresses = staticSettleAltAddresses(
        VAULT_PROGRAM_ID,
        NUM_TREES,
      );
      // Use the blockhash's context slot, not getSlot("confirmed") — the latter
      // can return a leader-skipped slot absent from SlotHashes → ALT create
      // fails with "is not a recent slot" (CRYPTOGRAPHY.md §9).
      const slot = (await connection.getLatestBlockhashAndContext()).context
        .slot;
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
        addresses: altAddresses,
      });
      const altTx = new Transaction().add(createAltIx, extendAltIx);
      const altSig = await sendAndConfirmTransaction(
        connection,
        altTx,
        [admin],
        {
          commitment: "confirmed",
        },
      );
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
      step(5, "Persist config to .devnet/e2e-config.json");
      // ────────────────────────────────────────────────────────────────────
      const cfg: E2EConfig = {
        l1RpcUrl: L1_RPC_URL,
        vaultProgramId: VAULT_PROGRAM_ID.toBase58(),
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
        protocol: {
          ownerCommitmentHex: Buffer.from(protocolOwnerCommitment).toString(
            "hex",
          ),
          feeRateBps: PROTOCOL_FEE_BPS,
        },
        vaultConfigPda: vaultPda.toBase58(),
        numTrees: NUM_TREES,
        merkleTreePdas: merkleTreePdas.map((p) => p.toBase58()),
        settleLookupTable: settleLookupTable.toBase58(),
        createdAt: new Date().toISOString(),
      };
      saveConfig(cfg);
      bullet(`wrote: ${CONFIG_PATH}`);

      banner("SETUP COMPLETE — run cvm-settle-e2e.test.ts next");

      // Sanity assertions
      expect(existsSync(CONFIG_PATH)).toBe(true);
      const reread = JSON.parse(readFileSync(CONFIG_PATH, "utf8")) as E2EConfig;
      expect(reread.baseMint.pubkey).toBe(baseMint.publicKey.toBase58());
      expect(reread.protocol.feeRateBps).toBe(PROTOCOL_FEE_BPS);
    },
  );
});
