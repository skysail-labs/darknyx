import type { IncomingMessage } from "node:http";

export interface PublicRelease {
  schema_version: 1;
  release_id: string;
  venue_id: string;
  gateway_url: string;
  rpc_url: string;
  vault_program_id: string;
  expected_compose_hash: string;
  expected_oracle_mode: "pyth-router-quorum-v1" | "pyth-solana-push-v1";
  recovery_start_slot: number;
  expected_mrtd?: string;
  artifact_manifest_url: string;
  artifact_set_id: string;
  artifact_protocol_version: number;
  artifact_key_id: string;
  artifact_public_key: string;
  circuit_version: string;
  proving_key_version: string;
}

export interface IsolatedTokenRequest {
  venueId: string;
  /** Stable random browser session; never exposed to the CVM or page JS. */
  sessionId: string;
  request: IncomingMessage;
}

export interface IsolatedToken {
  accessToken: string;
  expiresIn: number;
  /** Server-side CVM account identity. Must be isolated per browser session. */
  accountId: string;
}

export type IsolatedTokenIssuer = (
  request: IsolatedTokenRequest,
) => Promise<IsolatedToken>;

export interface CvmAccountCredentials {
  apiKey: string;
  apiSecret: string;
  passphrase: string;
}

export interface ReleaseHostOptions {
  origin: string;
  staticRoot: string;
  release: PublicRelease;
  cookieKey: Uint8Array;
  issueToken: IsolatedTokenIssuer;
  maxStaticBytes?: number;
  now?: () => number;
  randomBytes?: (length: number) => Uint8Array;
  /** Trusted client identity for creation throttling (for example a proxy-normalized IP). */
  clientKey?: (request: IncomingMessage) => string;
  maxNewSessionsPerMinute?: number;
  maxTokenRequestsPerMinute?: number;
  /** Signed-cookie lifetime and runtime-isolation retention. Defaults to 7 days. */
  sessionTtlSeconds?: number;
  /** Hard cap for all in-memory session/rate-limit maps. */
  maxTrackedSessions?: number;
  onIsolationViolation?: (details: {
    sessionId: string;
    accountId: string;
    conflictingSessionId?: string;
    conflictingAccountId?: string;
  }) => void | Promise<void>;
  onError?: (error: unknown) => void;
  /** Server-only upstreams. Set both to enable the same-origin live proxy. */
  gatewayUpstreamUrl?: string;
  /**
   * `fetch` used for **CVM-bound** requests only (T-03P).
   *
   * Supply the verified transport from `@darknyx/sdk/transport-node` to make
   * every upstream enclave request check, on the socket carrying it, that it
   * terminates at the attested enclave. Defaults to the global `fetch`, which
   * is the legacy gateway-terminated path.
   *
   * Deliberately NOT used for the Solana RPC upstream: that goes to Helius,
   * not the enclave, and routing it through an enclave-pinned transport would
   * be nonsense — it would fail verification against a certificate Helius has
   * no reason to present.
   */
  cvmFetch?: typeof fetch;
  rpcUpstreamUrl?: string;
  proxyTimeoutMs?: number;
  maxProxyRequestsPerMinute?: number;
}
