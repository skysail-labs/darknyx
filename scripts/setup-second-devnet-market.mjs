#!/usr/bin/env node
/**
 * Create (or reuse) a second governed devnet market for the focused
 * multi-market CVM rehearsal.
 *
 * The fixture creates a fresh BTC-like base mint, reuses the existing
 * e2e-config quote mint, initializes its MarketConfig, and writes only public
 * metadata to `.devnet/multi-market-e2e-config.json`. The admin remains mint
 * authority, so the generated base-mint secret never needs to be persisted.
 *
 * Idempotent after the first successful run. To exercise the live governance
 * pause/resume path:
 *
 *   MARKET_ENABLED=false node scripts/setup-second-devnet-market.mjs
 *   MARKET_ENABLED=true  node scripts/setup-second-devnet-market.mjs
 *
 * Required env: SOLANA_RPC_URL, ADMIN_KEYPAIR.
 */

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  getInitializeMintInstruction,
  getMintSize,
  TOKEN_PROGRAM_ADDRESS,
} from "@solana-program/token";
import {
  Connection,
  Keypair,
  PublicKey,
  sendAndConfirmTransaction,
  SystemProgram,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";

// `@solana-program/token` speaks kit-branded Address strings; SystemProgram
// and Connection want the v3 Address class. Convert once, here.
const TOKEN_PROGRAM_ID = new PublicKey(TOKEN_PROGRAM_ADDRESS);

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const PRIMARY_CONFIG_PATH = resolve(REPO_ROOT, ".devnet/e2e-config.json");
const MULTI_CONFIG_PATH = resolve(
  REPO_ROOT,
  ".devnet/multi-market-e2e-config.json",
);
const RPC = process.env.SOLANA_RPC_URL ?? "https://api.devnet.solana.com";
const ADMIN_KEYPAIR =
  process.env.ADMIN_KEYPAIR ?? ".devnet/keypairs/admin.json";
const BTC_USD_FEED =
  "e62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43";
const SOL_USD_FEED =
  "ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d";

async function loadKeypair(path) {
  const absolute = resolve(REPO_ROOT, path);
  return await Keypair.fromSecretKey(
    new Uint8Array(JSON.parse(readFileSync(absolute, "utf8"))),
  );
}

function discriminator(name) {
  return createHash("sha256").update(`global:${name}`).digest().subarray(0, 8);
}

function u64(value) {
  const out = Buffer.alloc(8);
  out.writeBigUInt64LE(BigInt(value));
  return out;
}

async function marketPda(programId, baseMint, quoteMint) {
  return (
    await PublicKey.findProgramAddress(
      [Buffer.from("market_config"), baseMint.toBytes(), quoteMint.toBytes()],
      programId,
    )
  )[0];
}

async function initializeMarketIx({
  programId,
  admin,
  baseMint,
  quoteMint,
  priceScale,
  tickSize,
  minOrderSize,
  circuitBreakerBps,
}) {
  const [vaultConfig] = await PublicKey.findProgramAddress(
    [Buffer.from("vault_config")],
    programId,
  );
  const market = await marketPda(programId, baseMint, quoteMint);
  const data = Buffer.concat([
    discriminator("initialize_market"),
    u64(priceScale),
    u64(tickSize),
    u64(minOrderSize),
    u64(circuitBreakerBps),
  ]);
  return new TransactionInstruction({
    programId,
    keys: [
      { pubkey: admin, isSigner: true, isWritable: true },
      { pubkey: vaultConfig, isSigner: false, isWritable: false },
      { pubkey: baseMint, isSigner: false, isWritable: false },
      { pubkey: quoteMint, isSigner: false, isWritable: false },
      { pubkey: market, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });
}

async function updateMarketIx({
  programId,
  admin,
  baseMint,
  quoteMint,
  enabled,
  priceScale,
  tickSize,
  minOrderSize,
  circuitBreakerBps,
}) {
  const [vaultConfig] = await PublicKey.findProgramAddress(
    [Buffer.from("vault_config")],
    programId,
  );
  const market = await marketPda(programId, baseMint, quoteMint);
  const data = Buffer.concat([
    discriminator("update_market_config"),
    Buffer.from([enabled ? 1 : 0]),
    u64(priceScale),
    u64(tickSize),
    u64(minOrderSize),
    u64(circuitBreakerBps),
  ]);
  return new TransactionInstruction({
    programId,
    keys: [
      { pubkey: admin, isSigner: true, isWritable: false },
      { pubkey: vaultConfig, isSigner: false, isWritable: false },
      { pubkey: market, isSigner: false, isWritable: true },
    ],
    data,
  });
}

if (!existsSync(PRIMARY_CONFIG_PATH)) {
  throw new Error(
    ".devnet/e2e-config.json is missing; run devnet-setup before adding a second market",
  );
}

const primary = JSON.parse(readFileSync(PRIMARY_CONFIG_PATH, "utf8"));
const programId = new PublicKey(primary.vaultProgramId);
const quoteMint = new PublicKey(primary.quoteMint.pubkey);
const admin = await loadKeypair(ADMIN_KEYPAIR);
const connection = new Connection(RPC, "confirmed");

let existing;
if (existsSync(MULTI_CONFIG_PATH)) {
  existing = JSON.parse(readFileSync(MULTI_CONFIG_PATH, "utf8"));
  if (
    existing.vaultProgramId !== primary.vaultProgramId ||
    existing.markets?.[0]?.baseMint?.pubkey !== primary.baseMint.pubkey ||
    existing.markets?.[0]?.quoteMint?.pubkey !== primary.quoteMint.pubkey
  ) {
    throw new Error(
      "multi-market config does not match the current primary e2e config; remove the generated multi-market config and rerun",
    );
  }
}

const params = {
  priceScale: BigInt(primary.market.priceScale),
  tickSize: BigInt(primary.market.tickSize),
  minOrderSize: BigInt(primary.market.minOrderSize),
  circuitBreakerBps: BigInt(primary.market.circuitBreakerBps),
};

let secondBaseMint;
if (existing) {
  secondBaseMint = new PublicKey(existing.markets[1].baseMint.pubkey);
  const mintAccount = await connection.getAccountInfo(
    secondBaseMint,
    "confirmed",
  );
  const marketAccount = await connection.getAccountInfo(
    await marketPda(programId, secondBaseMint, quoteMint),
    "confirmed",
  );
  if (!mintAccount || !mintAccount.owner.equals(TOKEN_PROGRAM_ID)) {
    throw new Error(
      "the generated second base mint is missing or has the wrong owner; remove the generated multi-market config and rerun",
    );
  }
  if (!marketAccount || !marketAccount.owner.equals(programId)) {
    throw new Error(
      "the generated second MarketConfig is missing or has the wrong owner; remove the generated multi-market config and rerun",
    );
  }
  console.log(
    `reusing BTC-USDC base=${secondBaseMint.toBase58()} market=${(
      await marketPda(programId, secondBaseMint, quoteMint)
    ).toBase58()}`,
  );
} else {
  secondBaseMint = await Keypair.generate();
  const mintSize = getMintSize();
  const rent = await connection.getMinimumBalanceForRentExemption(mintSize);
  const decimals = Number(primary.baseMint.decimals);
  const mintSignature = await sendAndConfirmTransaction(
    connection,
    new Transaction().add(
      SystemProgram.createAccount({
        fromPubkey: admin.publicKey,
        newAccountPubkey: secondBaseMint.publicKey,
        space: mintSize,
        lamports: rent,
        programId: TOKEN_PROGRAM_ID,
      }),
      getInitializeMintInstruction({
        mint: secondBaseMint.publicKey.toBase58(),
        decimals,
        mintAuthority: admin.publicKey.toBase58(),
        freezeAuthority: null,
      }),
    ),
    [admin, secondBaseMint],
    { commitment: "confirmed" },
  );
  console.log(
    `created BTC-like base mint ${secondBaseMint.publicKey.toBase58()} (${mintSignature})`,
  );

  const marketSignature = await sendAndConfirmTransaction(
    connection,
    new Transaction().add(
      await initializeMarketIx({
        programId,
        admin: admin.publicKey,
        baseMint: secondBaseMint.publicKey,
        quoteMint,
        ...params,
      }),
    ),
    [admin],
    { commitment: "confirmed" },
  );
  console.log(
    `initialized BTC-USDC MarketConfig ${(
      await marketPda(programId, secondBaseMint.publicKey, quoteMint)
    ).toBase58()} (${marketSignature})`,
  );
  secondBaseMint = secondBaseMint.publicKey;
}

let enabled = existing?.markets?.[1]?.market?.enabled ?? true;
if (process.env.MARKET_ENABLED !== undefined) {
  const normalized = process.env.MARKET_ENABLED.trim().toLowerCase();
  if (!["true", "false", "1", "0"].includes(normalized)) {
    throw new Error("MARKET_ENABLED must be true/false/1/0");
  }
  enabled = normalized === "true" || normalized === "1";
  const signature = await sendAndConfirmTransaction(
    connection,
    new Transaction().add(
      await updateMarketIx({
        programId,
        admin: admin.publicKey,
        baseMint: secondBaseMint,
        quoteMint,
        enabled,
        ...params,
      }),
    ),
    [admin],
    { commitment: "confirmed" },
  );
  console.log(`updated BTC-USDC enabled=${enabled} (${signature})`);
}

const config = {
  vaultProgramId: primary.vaultProgramId,
  vaultConfigPda: primary.vaultConfigPda,
  numTrees: primary.numTrees,
  merkleTreePdas: primary.merkleTreePdas,
  protocol: primary.protocol,
  markets: [
    {
      symbol: "SOL-USDC",
      oracleFeedId: SOL_USD_FEED,
      baseMint: {
        pubkey: primary.baseMint.pubkey,
        decimals: primary.baseMint.decimals,
      },
      quoteMint: {
        pubkey: primary.quoteMint.pubkey,
        decimals: primary.quoteMint.decimals,
      },
      marketConfigPda: primary.marketConfigPda,
      market: primary.market,
    },
    {
      symbol: "BTC-USDC",
      oracleFeedId: BTC_USD_FEED,
      baseMint: {
        pubkey: secondBaseMint.toBase58(),
        decimals: primary.baseMint.decimals,
      },
      quoteMint: {
        pubkey: primary.quoteMint.pubkey,
        decimals: primary.quoteMint.decimals,
      },
      marketConfigPda: await marketPda(
        programId,
        secondBaseMint,
        quoteMint,
      ).toBase58(),
      market: {
        enabled,
        priceScale: params.priceScale.toString(),
        tickSize: params.tickSize.toString(),
        minOrderSize: params.minOrderSize.toString(),
        circuitBreakerBps: params.circuitBreakerBps.toString(),
      },
    },
  ],
  createdAt: existing?.createdAt ?? new Date().toISOString(),
  updatedAt: new Date().toISOString(),
};

mkdirSync(resolve(REPO_ROOT, ".devnet"), { recursive: true });
writeFileSync(MULTI_CONFIG_PATH, `${JSON.stringify(config, null, 2)}\n`, {
  mode: 0o600,
});
console.log(`wrote ${MULTI_CONFIG_PATH}`);
