import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { resolve } from "node:path";

import { Connection, Keypair, PublicKey } from "@solana/web3.js";
import bs58 from "bs58";
import nacl from "tweetnacl";

export interface DemoE2eConfigJson {
  l1RpcUrl: string;
  vaultProgramId: string;
  matchingEngineProgramId: string;
  pythAccount: string;
  market: { pubkey: string };
  baseMint: { pubkey: string; decimals: number };
  quoteMint: { pubkey: string; decimals: number };
}

export function resolveRepoRoot(): string {
  const cwd = process.cwd();
  if (existsSync(resolve(cwd, "packages", "sdk"))) return cwd;
  const upTwo = resolve(cwd, "..", "..");
  if (existsSync(resolve(upTwo, "packages", "sdk"))) return upTwo;
  throw new Error("Unable to resolve monorepo root from cwd.");
}

export function expandUserPath(inputPath: string): string {
  if (inputPath.startsWith("~/")) return resolve(homedir(), inputPath.slice(2));
  return inputPath;
}

export function loadKeypairFromPath(
  repoRoot: string,
  maybeRelative: string,
): Keypair {
  const expanded = expandUserPath(maybeRelative);
  const absolute = expanded.startsWith("/")
    ? expanded
    : resolve(repoRoot, expanded);
  const raw = JSON.parse(readFileSync(absolute, "utf8")) as number[];
  return Keypair.fromSecretKey(new Uint8Array(raw));
}

export function keypairFromBase58(secret: string): Keypair {
  const bytes = bs58.decode(secret.trim());
  if (bytes.length === 64) return Keypair.fromSecretKey(bytes);
  if (bytes.length === 32) {
    return Keypair.fromSecretKey(nacl.sign.keyPair.fromSeed(bytes).secretKey);
  }
  throw new Error(
    "Base58 key must decode to 32-byte seed or 64-byte secret key.",
  );
}

/**
 * Resolution order:
 *   1. `DEMO_E2E_CONFIG_JSON` env var (full JSON literal)
 *   2. `DEMO_E2E_CONFIG_PATH` env var (path on disk, relative to repoRoot)
 *   3. Fallback: `<repoRoot>/.devnet/e2e-config.json`
 *
 * Lets serverless deploys (Vercel etc.) inject the (non-secret) devnet
 * config inline — program IDs, market PDA, mints, RPC URL — without having
 * to ship `.devnet/` onto the deploy filesystem.
 */
function parseE2eConfig(raw: string, source: string): DemoE2eConfigJson {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(
      `Failed to parse e2e config from ${source}: ` +
        (err instanceof Error ? err.message : String(err)),
    );
  }
  if (!parsed || typeof parsed !== "object") {
    throw new Error(`E2e config from ${source} must be a JSON object`);
  }
  return parsed as DemoE2eConfigJson;
}

export function loadDemoE2eConfig(repoRoot: string): DemoE2eConfigJson {
  const inline = process.env.DEMO_E2E_CONFIG_JSON;
  if (inline && inline.trim().length > 0) {
    return parseE2eConfig(inline, "DEMO_E2E_CONFIG_JSON env");
  }

  const customPath = process.env.DEMO_E2E_CONFIG_PATH;
  const p = customPath
    ? customPath.startsWith("/")
      ? customPath
      : resolve(repoRoot, customPath)
    : resolve(repoRoot, ".devnet", "e2e-config.json");

  if (!existsSync(p)) {
    throw new Error(
      `Missing e2e config: tried env DEMO_E2E_CONFIG_JSON / DEMO_E2E_CONFIG_PATH, ` +
        `and disk fallback "${p}" does not exist. ` +
        `Generate devnet fixtures (see packages/sdk tests / demo docs) ` +
        `or set DEMO_E2E_CONFIG_JSON on serverless deploys.`,
    );
  }
  return parseE2eConfig(readFileSync(p, "utf8"), p);
}

export function getDemoConnections(cfg: DemoE2eConfigJson) {
  const l1RpcUrl = process.env.DEMO_L1_RPC_URL ?? cfg.l1RpcUrl;
  const erRpcUrl =
    process.env.DEMO_ER_RPC_URL ?? "https://devnet.magicblock.app";
  return {
    l1: new Connection(l1RpcUrl, "confirmed"),
    er: new Connection(erRpcUrl, "confirmed"),
    erRpcUrl,
  };
}

export interface DemoKeyring {
  admin: Keypair;
  funder: Keypair;
  tee: Keypair;
  maker: Keypair;
}

/**
 * Try to load a keypair from env vars before falling back to disk.
 *
 * Resolution order for `envBase = "DEMO_FOO_KEYPAIR"`:
 *   1. `DEMO_FOO_KEYPAIR_JSON`    — Solana-CLI-style JSON byte-array, e.g. `[1,2,3,...]`
 *   2. `DEMO_FOO_KEYPAIR_BASE58`  — base58 of the 32-byte seed or 64-byte secret
 *   3. (returns null — caller decides whether to fall back to disk)
 *
 * This lets serverless deploys (Vercel, etc.) inject signing keys via
 * environment variables instead of mounting `.devnet/keypairs/*.json`.
 */
function loadKeypairFromEnv(envBase: string): Keypair | null {
  const jsonRaw = process.env[`${envBase}_JSON`];
  if (jsonRaw && jsonRaw.trim().length > 0) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(jsonRaw);
    } catch (err) {
      throw new Error(
        `${envBase}_JSON is not valid JSON: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    if (!Array.isArray(parsed) || parsed.some((b) => typeof b !== "number")) {
      throw new Error(
        `${envBase}_JSON must be a JSON byte-array (e.g. [1,2,3,...])`,
      );
    }
    if (parsed.length !== 64 && parsed.length !== 32) {
      throw new Error(
        `${envBase}_JSON must be 32 or 64 bytes long, got ${parsed.length}`,
      );
    }
    const bytes = new Uint8Array(parsed as number[]);
    if (bytes.length === 32) {
      return Keypair.fromSecretKey(nacl.sign.keyPair.fromSeed(bytes).secretKey);
    }
    return Keypair.fromSecretKey(bytes);
  }

  const base58Raw = process.env[`${envBase}_BASE58`];
  if (base58Raw && base58Raw.trim().length > 0) {
    return keypairFromBase58(base58Raw);
  }

  return null;
}

/**
 * Load a keypair, preferring env vars over disk paths.
 *
 * @param envBase     Base name for env-var lookup (`${envBase}_JSON` / `_BASE58`).
 * @param pathEnvName Legacy env that holds a filesystem path (e.g. `DEMO_ADMIN_KEYPAIR_PATH`).
 * @param defaultPath Fallback path when the path env is also unset.
 */
function loadKeypairFromEnvOrPath(
  envBase: string,
  repoRoot: string,
  pathEnvName: string,
  defaultPath: string,
): Keypair {
  const fromEnv = loadKeypairFromEnv(envBase);
  if (fromEnv) return fromEnv;

  const diskPath = process.env[pathEnvName] ?? defaultPath;
  try {
    return loadKeypairFromPath(repoRoot, diskPath);
  } catch (err) {
    throw new Error(
      `Failed to load ${envBase}: ` +
        `env vars ${envBase}_JSON / ${envBase}_BASE58 are unset, ` +
        `and disk fallback "${diskPath}" could not be read ` +
        `(${err instanceof Error ? err.message : String(err)}). ` +
        `On serverless deploys, set ${envBase}_JSON to the keypair byte-array.`,
    );
  }
}

/**
 * Maker is the counter-persona — required for the live trade flow.
 * Accepts the new `DEMO_MAKER_KEYPAIR_*` envs as well as the legacy
 * `DEMO_MAKER_SECRET_BASE58` that earlier `.env.local` files used.
 */
function loadDemoMakerKeypair(): Keypair {
  const fromNew = loadKeypairFromEnv("DEMO_MAKER_KEYPAIR");
  if (fromNew) return fromNew;
  const legacy = process.env.DEMO_MAKER_SECRET_BASE58;
  if (legacy && legacy.trim().length > 0) return keypairFromBase58(legacy);
  throw new Error(
    "Missing maker keypair. Set one of: DEMO_MAKER_KEYPAIR_JSON, " +
      "DEMO_MAKER_KEYPAIR_BASE58, or (legacy) DEMO_MAKER_SECRET_BASE58.",
  );
}

/** Load only the admin keypair — used by airdrop, which doesn't need maker/tee. */
export function loadDemoAdminKeypair(repoRoot: string): Keypair {
  return loadKeypairFromEnvOrPath(
    "DEMO_ADMIN_KEYPAIR",
    repoRoot,
    "DEMO_ADMIN_KEYPAIR_PATH",
    ".devnet/keypairs/admin.json",
  );
}

export function loadDemoKeyring(repoRoot: string): DemoKeyring {
  return {
    admin: loadDemoAdminKeypair(repoRoot),
    funder: loadKeypairFromEnvOrPath(
      "DEMO_FUNDER_KEYPAIR",
      repoRoot,
      "DEMO_FUNDER_KEYPAIR_PATH",
      "~/.config/solana/id.json",
    ),
    tee: loadKeypairFromEnvOrPath(
      "DEMO_TEE_KEYPAIR",
      repoRoot,
      "DEMO_TEE_KEYPAIR_PATH",
      ".devnet/keypairs/tee_authority.json",
    ),
    maker: loadDemoMakerKeypair(),
  };
}

export function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing required env: ${name}`);
  return v;
}

export interface DemoPrograms {
  vaultProgramId: PublicKey;
  meProgramId: PublicKey;
  market: PublicKey;
  pythAccount: PublicKey;
  baseMint: PublicKey;
  quoteMint: PublicKey;
}

export function parseDemoPrograms(cfg: DemoE2eConfigJson): DemoPrograms {
  return {
    vaultProgramId: new PublicKey(cfg.vaultProgramId),
    meProgramId: new PublicKey(cfg.matchingEngineProgramId),
    market: new PublicKey(cfg.market.pubkey),
    pythAccount: new PublicKey(cfg.pythAccount),
    baseMint: new PublicKey(cfg.baseMint.pubkey),
    quoteMint: new PublicKey(cfg.quoteMint.pubkey),
  };
}
