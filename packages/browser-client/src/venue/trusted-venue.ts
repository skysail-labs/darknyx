import { PublicKey } from "@solana/web3.js";
import {
  assertTeePubkeysMatch,
  decodeMarketConfig,
  fetchSystemStatus,
  marketConfigPda,
  vaultConfigPda,
  vaultConfigTeePubkeys,
  verifyTeeAttestation,
  type TeeAttestation,
  type VerifyTeeAttestationOptions,
} from "@darknyx/sdk/browser-attestation";

import { SameOriginSessionBroker } from "./session-broker.js";
import type {
  TrustedInstrument,
  TrustedVenueSession,
  VenueReleaseConfig,
} from "./types.js";

interface RpcAccount {
  context: { slot: number };
  value: { data: [string, "base64"] } | null;
}

interface WireInstrument {
  symbol?: unknown;
  base_mint?: unknown;
  quote_mint?: unknown;
  tick_size?: unknown;
  min_order_size?: unknown;
  trading_enabled?: unknown;
  oracle?: { type?: unknown; pubkey?: unknown };
}

export interface BootstrapTrustedVenueOptions {
  fetchImpl?: typeof fetch;
  origin?: string;
  attestationVerifier?: (
    gatewayUrl: string,
    expectedComposeHash: string,
    options: VerifyTeeAttestationOptions,
  ) => Promise<TeeAttestation>;
}

function base64Bytes(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function strictU64(value: unknown, field: string): bigint {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`${field} must be a canonical u64 string`);
  }
  const parsed = BigInt(value);
  if (parsed > 18_446_744_073_709_551_615n) {
    throw new Error(`${field} exceeds u64`);
  }
  return parsed;
}

async function finalizedAccount(
  rpcUrl: string,
  address: PublicKey,
  fetchImpl: typeof fetch,
): Promise<{ data: Uint8Array; slot: number }> {
  const response = await fetchImpl(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "getAccountInfo",
      params: [
        address.toBase58(),
        {
          commitment: "finalized",
          encoding: "base64",
        },
      ],
    }),
  });
  if (!response.ok)
    throw new Error(`finalized RPC read failed (${response.status})`);
  const json = (await response.json()) as {
    result?: RpcAccount;
    error?: { message?: string };
  };
  if (json.error)
    throw new Error(
      `finalized RPC read failed: ${json.error.message ?? "unknown"}`,
    );
  const value = json.result;
  if (!value?.value || value.value.data[1] !== "base64") {
    throw new Error(`finalized account ${address.toBase58()} is missing`);
  }
  return { data: base64Bytes(value.value.data[0]), slot: value.context.slot };
}

async function instruments(
  gatewayUrl: string,
  fetchImpl: typeof fetch,
): Promise<WireInstrument[]> {
  const response = await fetchImpl(new URL("/instruments", gatewayUrl));
  if (!response.ok) throw new Error(`/instruments failed (${response.status})`);
  const body = (await response.json()) as unknown;
  if (!Array.isArray(body) || body.length === 0 || body.length > 64) {
    throw new Error("venue returned an invalid instrument list");
  }
  return body as WireInstrument[];
}

/**
 * Establish the browser's trust root before requesting credentials or opening
 * a trading stream: finalized governance → DCAP quote → exact signer-set
 * equality → governed market-config equality.
 */
export async function bootstrapTrustedVenue(
  release: VenueReleaseConfig,
  options: BootstrapTrustedVenueOptions = {},
): Promise<TrustedVenueSession> {
  if (!release.expectedComposeHash) {
    throw new Error("release is missing the audited compose-hash pin");
  }
  const fetchImpl = options.fetchImpl ?? fetch;
  const programId = new PublicKey(release.vaultProgramId);
  const [vaultConfig] = vaultConfigPda(programId);
  const governance = await finalizedAccount(
    release.rpcUrl,
    vaultConfig,
    fetchImpl,
  );
  const onchainSigners = vaultConfigTeePubkeys(governance.data);

  const attest = options.attestationVerifier ?? verifyTeeAttestation;
  const attestation = await attest(
    release.gatewayUrl,
    release.expectedComposeHash,
    {
      expectedTeePubkey: onchainSigners[0],
      expectedMrtd: release.expectedMrtd,
      fetchImpl,
    },
  );
  assertTeePubkeysMatch(attestation.teePubkeys, onchainSigners);

  const wireInstruments = await instruments(release.gatewayUrl, fetchImpl);
  const seen = new Set<string>();
  const trusted: TrustedInstrument[] = [];
  let finalizedGovernanceSlot = governance.slot;
  for (const wire of wireInstruments) {
    if (
      typeof wire.symbol !== "string" ||
      !/^[A-Z0-9]{2,16}-[A-Z0-9]{2,16}$/.test(wire.symbol) ||
      typeof wire.base_mint !== "string" ||
      typeof wire.quote_mint !== "string" ||
      typeof wire.trading_enabled !== "boolean" ||
      wire.oracle?.type !== "pyth_pull_v2" ||
      typeof wire.oracle.pubkey !== "string"
    ) {
      throw new Error("venue returned a malformed instrument");
    }
    if (seen.has(wire.symbol))
      throw new Error(`duplicate instrument ${wire.symbol}`);
    seen.add(wire.symbol);
    const base = new PublicKey(wire.base_mint);
    const quote = new PublicKey(wire.quote_mint);
    const [marketAddress] = marketConfigPda(programId, base, quote);
    const account = await finalizedAccount(
      release.rpcUrl,
      marketAddress,
      fetchImpl,
    );
    finalizedGovernanceSlot = Math.min(finalizedGovernanceSlot, account.slot);
    const market = decodeMarketConfig(account.data);
    const tickSize = strictU64(wire.tick_size, `${wire.symbol}.tick_size`);
    const minOrderSize = strictU64(
      wire.min_order_size,
      `${wire.symbol}.min_order_size`,
    );
    if (
      !market.baseMint.equals(base) ||
      !market.quoteMint.equals(quote) ||
      market.tickSize !== tickSize ||
      market.minOrderSize !== minOrderSize ||
      (wire.trading_enabled && !market.enabled)
    ) {
      throw new Error(
        `instrument ${wire.symbol} disagrees with finalized governance`,
      );
    }
    trusted.push({
      symbol: wire.symbol,
      baseMint: base.toBase58(),
      quoteMint: quote.toBase58(),
      baseDecimals: market.baseDecimals,
      quoteDecimals: market.quoteDecimals,
      priceScale: market.priceScale,
      tickSize,
      minOrderSize,
      tradingEnabled: wire.trading_enabled && market.enabled,
      oracleFeed: wire.oracle.pubkey,
    });
  }

  const status = await fetchSystemStatus(release.gatewayUrl, { fetchImpl });
  const broker = new SameOriginSessionBroker({
    venueId: release.venueId,
    endpoint: release.sessionEndpoint,
    fetchImpl,
    origin: options.origin,
  });
  return Object.freeze({
    attestation,
    finalizedGovernanceSlot,
    instruments: Object.freeze(trusted),
    status,
    token: () => broker.token(),
  });
}
