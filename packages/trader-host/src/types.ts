import type { IncomingMessage } from "node:http";

export interface PublicRelease {
  schema_version: 1;
  release_id: string;
  venue_id: string;
  gateway_url: string;
  rpc_url: string;
  vault_program_id: string;
  expected_compose_hash: string;
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
}
