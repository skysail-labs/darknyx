/**
 * Vitest setup file — loads test secrets/config from `.env` files so the
 * RPC credential (and the CVM gateway, run flags, etc.) lives in ONE gitignored
 * place instead of `/tmp/*.env` files or CLI args.
 *
 * Load order (later does NOT override an already-set var — `override: false`):
 *   1. process.env            (an explicitly-exported var always wins)
 *   2. packages/sdk/.env       (local, gitignored — put the release RPC here)
 *   3. packages/sdk/.env.devnet (existing devnet foundation config, gitignored)
 *
 * See `.env.example` for the documented keys. Nothing here is required: the
 * local bucket needs no env at all, and the devnet/cvm buckets self-skip when
 * their `RUN_*` flag is absent.
 */

import { config as loadDotenv } from "dotenv";
import { resolve } from "node:path";
import { existsSync } from "node:fs";

const SDK_ROOT = resolve(__dirname, "..");

for (const file of [".env", ".env.devnet"]) {
  const path = resolve(SDK_ROOT, file);
  if (existsSync(path)) {
    loadDotenv({ path, override: false });
  }
}
