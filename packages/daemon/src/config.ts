/**
 * Daemon configuration from the environment.
 *
 * The daemon talks to two services: the **CVM gateway** (order intake + fills
 * WS, authenticated by a bearer token) and a **Solana RPC** (settlement
 * reconciliation + leaf-index reads). Everything else is local: the sqlite
 * store and the keystore live on the operator's machine.
 */

import {
  DEFAULT_THRESHOLDS,
  type LifecycleThresholds,
} from "./order-lifecycle.js";
import type { ExpectedMeasurements } from "./attestation.js";

export interface DaemonConfig {
  /** CVM gateway origin, e.g. `https://<app>-8080.dstack-pha-prod5.phala.network`. */
  gatewayUrl: string;
  /** CVM gateway WS origin. Defaults to `gatewayUrl` with `http(s)`→`ws(s)`. */
  gatewayWsUrl: string;
  /** Bearer token from `POST /auth/token`. */
  token: string;
  /** Solana RPC (Helius) for settlement reconciliation / leaf-index reads. */
  rpcUrl: string;
  /** Local sqlite path for note + managed-order persistence. */
  dbPath: string;
  /** Local control-API port (REST + one WS the strategy drives). */
  controlPort: number;
  /** Path to the encrypted master-seed keystore. */
  keystorePath: string;
  /** Automation thresholds for the lifecycle reducer. */
  thresholds: LifecycleThresholds;
  /** Operator-pinned TEE measurements to enforce on connect (any subset). When
   *  set, the daemon refuses to trade unless the gateway's attestation matches. */
  attestation?: ExpectedMeasurements;
  /** Require real DCAP verification + governance pins (secure-by-default). Set
   *  `NYX_DAEMON_ATTEST_STRICT=0` to downgrade to the legacy partial check
   *  (dev only — NOT a security guarantee). Ignored when attestation is skipped. */
  attestationStrict: boolean;
  /** Cross-check the attested (quote-bound) tee_pubkeys set against on-chain
   *  `vault_config.tee_pubkeys` at finalized commitment on startup and every
   *  minute. Default true. `NYX_DAEMON_ATTEST_ONCHAIN_CHECK=0` is accepted only
   *  together with non-strict development mode. Startup fails on RPC, missing
   *  config, or mismatch; runtime mismatch pauses immediately and RPC staleness
   *  pauses new trading after five minutes. */
  attestOnchainCheck: boolean;
  /** PCCS endpoint for DCAP collateral. Defaults to Phala's PCCS in the verifier;
   *  override for a self-hosted/offline PCCS. Never taken from gateway input. */
  pccsUrl?: string;
  /** Vault program id (base58). Default = the devnet vault. */
  programId: string;
  /** Path to the operator's Solana payer keypair (enables on-chain deposit). */
  payerKeypairPath?: string;
}

/** Default devnet vault program id (matches `declare_id!` in programs/vault). */
export const DEFAULT_PROGRAM_ID =
  "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx";

/** Default control-API port (loopback). */
export const DEFAULT_CONTROL_PORT = 8770;

function httpToWs(url: string): string {
  return url.replace(/^http/, "ws");
}

function intFromEnv(
  env: NodeJS.ProcessEnv,
  key: string,
  fallback: number,
): number {
  const raw = env[key];
  if (raw === undefined || raw === "") return fallback;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 0) {
    throw new Error(`${key} must be a non-negative integer, got ${raw}`);
  }
  return n;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): DaemonConfig {
  const gatewayUrl = env.NYX_DAEMON_GATEWAY_URL;
  if (!gatewayUrl) throw new Error("NYX_DAEMON_GATEWAY_URL is required");
  const token = env.NYX_DAEMON_TOKEN;
  if (!token) throw new Error("NYX_DAEMON_TOKEN is required");
  const rpcUrl = env.NYX_DAEMON_RPC_URL;
  if (!rpcUrl) throw new Error("NYX_DAEMON_RPC_URL is required");

  return {
    gatewayUrl,
    gatewayWsUrl: env.NYX_DAEMON_GATEWAY_WS_URL ?? httpToWs(gatewayUrl),
    token,
    rpcUrl,
    dbPath: env.NYX_DAEMON_DB ?? "./nyx-daemon.sqlite",
    controlPort: intFromEnv(
      env,
      "NYX_DAEMON_CONTROL_PORT",
      DEFAULT_CONTROL_PORT,
    ),
    keystorePath: env.NYX_DAEMON_KEYSTORE ?? "./nyx-keystore.json",
    thresholds: {
      anchorTopUpThreshold: intFromEnv(
        env,
        "NYX_DAEMON_ANCHOR_TOPUP_THRESHOLD",
        DEFAULT_THRESHOLDS.anchorTopUpThreshold,
      ),
      anchorTopUpSize: intFromEnv(
        env,
        "NYX_DAEMON_ANCHOR_TOPUP_SIZE",
        DEFAULT_THRESHOLDS.anchorTopUpSize,
      ),
      mergeThreshold: intFromEnv(
        env,
        "NYX_DAEMON_MERGE_THRESHOLD",
        DEFAULT_THRESHOLDS.mergeThreshold,
      ),
    },
    attestation: parseExpected(env),
    attestationStrict: env.NYX_DAEMON_ATTEST_STRICT !== "0",
    attestOnchainCheck: env.NYX_DAEMON_ATTEST_ONCHAIN_CHECK !== "0",
    pccsUrl: env.NYX_DAEMON_PCCS_URL,
    programId: env.NYX_DAEMON_PROGRAM_ID ?? DEFAULT_PROGRAM_ID,
    payerKeypairPath: env.NYX_DAEMON_PAYER_KEYPAIR,
  };
}

/** Pinned TEE measurements from the environment (undefined if none set). */
function parseExpected(
  env: NodeJS.ProcessEnv,
): ExpectedMeasurements | undefined {
  const composeHash = env.NYX_DAEMON_EXPECT_COMPOSE_HASH;
  const mrtd = env.NYX_DAEMON_EXPECT_MRTD;
  const teePubkey = env.NYX_DAEMON_EXPECT_TEE_PUBKEY;
  if (!composeHash && !mrtd && !teePubkey) return undefined;
  return { composeHash, mrtd, teePubkey };
}
