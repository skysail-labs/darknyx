import type {
  SystemStatus,
  TeeAttestation,
} from "@darknyx/sdk/browser-attestation";

export interface VenueReleaseConfig {
  /** Stable identifier understood by the same-origin session broker. */
  venueId: string;
  gatewayUrl: string;
  rpcUrl: string;
  vaultProgramId: string;
  /** Audited compose hash pinned by the client release, never the gateway. */
  expectedComposeHash: string;
  expectedMrtd?: string;
  /** Relative, same-origin endpoint. Defaults to `/api/darknyx/session`. */
  sessionEndpoint?: string;
}

export interface TrustedInstrument {
  symbol: string;
  baseMint: string;
  quoteMint: string;
  baseDecimals: number;
  quoteDecimals: number;
  priceScale: bigint;
  tickSize: bigint;
  minOrderSize: bigint;
  tradingEnabled: boolean;
  oracleFeed: string;
}

export interface TrustedVenueIdentity {
  attestation: TeeAttestation;
  finalizedGovernanceSlot: number;
  instruments: readonly TrustedInstrument[];
  status: SystemStatus;
}

export interface TrustedVenueSession extends TrustedVenueIdentity {
  /** Short-lived token only. The browser never receives API credentials. */
  token(): Promise<string>;
}

export type VenueTrustState =
  | { state: "checking" }
  | { state: "trusted"; identity: TrustedVenueIdentity }
  | { state: "failed"; message: string };
