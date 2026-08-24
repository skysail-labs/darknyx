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

/**
 * Which transport the daemon requires (T-03P).
 *
 * `ra-tls` means the daemon verifies, on the socket carrying each request,
 * that it is talking to the attested enclave. `gateway-terminated` is the
 * legacy path where the dstack gateway terminates TLS and no such binding
 * exists.
 */
export type DaemonTransportMode = "ra-tls" | "gateway-terminated";
export type DaemonDeploymentTier = "production" | "development" | "simulator";

export interface DaemonConfig {
  /** CVM RA-TLS origin, e.g. `https://<app>-8443s.dstack-pha-prod9.phala.network`. */
  gatewayUrl: string;
  /** CVM gateway WS origin. Defaults to `gatewayUrl` with `http(s)`→`ws(s)`. */
  gatewayWsUrl: string;
  /** Bearer token from `POST /auth/token`. */
  token: string;
  /**
   * Transport the daemon requires (T-03P). Defaults to `ra-tls`; the legacy
   * path is an explicit non-production exception.
   */
  transportMode: DaemonTransportMode;
  /** Security policy tier. Production permits only quote-bound RA-TLS. */
  deploymentTier: DaemonDeploymentTier;
  /** Explicit acknowledgement required for the legacy transport in non-production. */
  allowLegacyTransport: boolean;
  /**
   * SHA-256 over the on-chain `VaultConfig.tee_pubkeys` in shard order, hex.
   * Required when `transportMode` is `ra-tls`: without it a verified transport
   * proves the channel but not that the enclave holds the governed settle keys.
   */
  expectSignerSetSha256?: string;
  /** Solana RPC (Helius) for settlement reconciliation / leaf-index reads. */
  rpcUrl: string;
  /** Local sqlite path for note + managed-order persistence. */
  dbPath: string;
  /** Local control-API port (REST + one WS the strategy drives). */
  controlPort: number;
  /** Path to the encrypted master-seed keystore. */
  keystorePath: string;
  /** Separate authenticated high-water file for order ids/trading keys. */
  orderSequencePath: string;
  /** Automation thresholds for the lifecycle reducer. */
  thresholds: LifecycleThresholds;
  /** Operator-pinned TEE measurements to enforce on connect (any subset). When
   *  set, the daemon refuses to trade unless the gateway's attestation matches. */
  attestation?: ExpectedMeasurements;
  /** Require real DCAP verification + governance pins (secure-by-default). Set
   *  `DARKNYX_DAEMON_ATTEST_STRICT=0` to downgrade to the legacy partial check
   *  (dev only — NOT a security guarantee). Ignored when attestation is skipped. */
  attestationStrict: boolean;
  /** Cross-check the attested (quote-bound) tee_pubkeys set against on-chain
   *  `vault_config.tee_pubkeys` at finalized commitment on startup and every
   *  minute. Default true. `DARKNYX_DAEMON_ATTEST_ONCHAIN_CHECK=0` is accepted only
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
  const gatewayUrl = env.DARKNYX_DAEMON_GATEWAY_URL;
  if (!gatewayUrl) throw new Error("DARKNYX_DAEMON_GATEWAY_URL is required");
  const token = env.DARKNYX_DAEMON_TOKEN;
  if (!token) throw new Error("DARKNYX_DAEMON_TOKEN is required");
  const rpcUrl = env.DARKNYX_DAEMON_RPC_URL;
  if (!rpcUrl) throw new Error("DARKNYX_DAEMON_RPC_URL is required");

  const keystorePath = env.DARKNYX_DAEMON_KEYSTORE ?? "./darknyx-keystore.json";
  const cfg: DaemonConfig = {
    gatewayUrl,
    gatewayWsUrl: env.DARKNYX_DAEMON_GATEWAY_WS_URL ?? httpToWs(gatewayUrl),
    token,
    rpcUrl,
    dbPath: env.DARKNYX_DAEMON_DB ?? "./darknyx-daemon.sqlite",
    controlPort: intFromEnv(
      env,
      "DARKNYX_DAEMON_CONTROL_PORT",
      DEFAULT_CONTROL_PORT,
    ),
    keystorePath,
    orderSequencePath:
      env.DARKNYX_DAEMON_ORDER_SEQUENCE ?? `${keystorePath}.order-sequence`,
    thresholds: {
      mergeThreshold: intFromEnv(
        env,
        "DARKNYX_DAEMON_MERGE_THRESHOLD",
        DEFAULT_THRESHOLDS.mergeThreshold,
      ),
    },
    transportMode: parseTransportMode(env),
    deploymentTier: parseDeploymentTier(env),
    allowLegacyTransport: env.DARKNYX_DAEMON_ALLOW_LEGACY_TRANSPORT === "1",
    expectSignerSetSha256: env.DARKNYX_DAEMON_EXPECT_SIGNER_SET_SHA256,
    attestation: parseExpected(env),
    attestationStrict: env.DARKNYX_DAEMON_ATTEST_STRICT !== "0",
    attestOnchainCheck: env.DARKNYX_DAEMON_ATTEST_ONCHAIN_CHECK !== "0",
    pccsUrl: env.DARKNYX_DAEMON_PCCS_URL,
    programId: env.DARKNYX_DAEMON_PROGRAM_ID ?? DEFAULT_PROGRAM_ID,
    payerKeypairPath: env.DARKNYX_DAEMON_PAYER_KEYPAIR,
  };
  assertTransportConfigCoherent(cfg);
  return cfg;
}

/**
 * RA-TLS without its governance pins would verify a channel to *an* enclave
 * and prove nothing about which one, so the daemon refuses to start rather
 * than run in a state that reads as secure and is not.
 */
export function assertTransportConfigCoherent(cfg: DaemonConfig): void {
  if (cfg.transportMode === "gateway-terminated") {
    if (cfg.deploymentTier === "production") {
      throw new Error(
        "DARKNYX_DAEMON_TRANSPORT_MODE=gateway-terminated is forbidden in production",
      );
    }
    if (!cfg.allowLegacyTransport) {
      throw new Error(
        "gateway-terminated transport requires " +
          "DARKNYX_DAEMON_ALLOW_LEGACY_TRANSPORT=1 in development or simulator mode",
      );
    }
    return;
  }
  const missing: string[] = [];
  if (!cfg.attestation?.composeHash) {
    missing.push("DARKNYX_DAEMON_EXPECT_COMPOSE_HASH");
  }
  if (!cfg.expectSignerSetSha256) {
    missing.push("DARKNYX_DAEMON_EXPECT_SIGNER_SET_SHA256");
  }
  if (missing.length > 0) {
    throw new Error(
      `DARKNYX_DAEMON_TRANSPORT_MODE=ra-tls requires ${missing.join(" and ")}. ` +
        "Without these a verified transport proves a channel to some enclave, " +
        "not that it is the governed one. Refusing to start.",
    );
  }
}

/**
 * Parse `DARKNYX_DAEMON_TRANSPORT_MODE`.
 *
 * Unset or empty selects RA-TLS. A set but unrecognised value is a hard
 * error rather than a fallback — a typo like `ratls` must not leave an operator
 * on the weaker transport believing they enabled the stronger one. Mirrors the
 * same rule on the TEE side (`DARKNYX_TEE_TRANSPORT_MODE`).
 */
function parseTransportMode(env: NodeJS.ProcessEnv): DaemonTransportMode {
  const raw = env.DARKNYX_DAEMON_TRANSPORT_MODE?.trim();
  if (!raw) return "ra-tls";
  if (raw === "ra-tls" || raw === "gateway-terminated") return raw;
  throw new Error(
    `DARKNYX_DAEMON_TRANSPORT_MODE=${JSON.stringify(raw)} is not recognised; ` +
      'expected "ra-tls" or "gateway-terminated". Refusing to start rather ' +
      "than silently falling back to the legacy transport.",
  );
}

function parseDeploymentTier(env: NodeJS.ProcessEnv): DaemonDeploymentTier {
  const raw = env.DARKNYX_DAEMON_DEPLOYMENT_TIER?.trim();
  if (!raw) return "production";
  if (raw === "production" || raw === "development" || raw === "simulator") {
    return raw;
  }
  throw new Error(
    `DARKNYX_DAEMON_DEPLOYMENT_TIER=${JSON.stringify(raw)} is not recognised; ` +
      'expected "production", "development", or "simulator".',
  );
}

/** Pinned TEE measurements from the environment (undefined if none set). */
function parseExpected(
  env: NodeJS.ProcessEnv,
): ExpectedMeasurements | undefined {
  const composeHash = env.DARKNYX_DAEMON_EXPECT_COMPOSE_HASH;
  const mrtd = env.DARKNYX_DAEMON_EXPECT_MRTD;
  const teePubkey = env.DARKNYX_DAEMON_EXPECT_TEE_PUBKEY;
  if (!composeHash && !mrtd && !teePubkey) return undefined;
  return { composeHash, mrtd, teePubkey };
}
