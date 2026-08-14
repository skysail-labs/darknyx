import { PublicKey } from "@solana/web3.js";
import { apiUrl } from "@darknyx/sdk/api-url";
import {
  assertTeePubkeysMatch,
  decodeMarketConfig,
  fetchSystemStatus,
  marketConfigPda,
  vaultConfigPda,
  vaultConfigTeePubkeys,
  vaultConfigTradingParameters,
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
  oracle?: { type?: unknown; pubkey?: unknown; source?: unknown };
}

interface ValidatedWireInstrument {
  symbol: string;
  tickSize: string;
  minOrderSize: string;
  tradingEnabled: boolean;
  oracleFeed: string;
  oracleSource: "pyth-router-quorum-v1" | "pyth-solana-push-v1";
}

export interface BootstrapTrustedVenueOptions {
  fetchImpl?: typeof fetch;
  origin?: string;
  attestationVerifier?: (
    gatewayUrl: string,
    expectedComposeHash: string,
    options: VerifyTeeAttestationOptions,
  ) => Promise<TeeAttestation>;
  signal?: AbortSignal;
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
  signal?: AbortSignal,
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
    signal,
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
  signal?: AbortSignal,
): Promise<WireInstrument[]> {
  const response = await fetchImpl(apiUrl(gatewayUrl, "instruments"), {
    signal,
  });
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
  const fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
  const broker = new SameOriginSessionBroker({
    venueId: release.venueId,
    endpoint: release.sessionEndpoint,
    fetchImpl,
    origin: options.origin,
  });
  // Establish only the signed HttpOnly host session before same-origin proxy
  // reads. The CVM account and bearer token remain unprovisioned until every
  // finalized-governance and attestation check below succeeds.
  await broker.establish(options.signal);
  const programId = new PublicKey(release.vaultProgramId);
  const [vaultConfig] = vaultConfigPda(programId);
  const governance = await finalizedAccount(
    release.rpcUrl,
    vaultConfig,
    fetchImpl,
    options.signal,
  );
  const onchainSigners = vaultConfigTeePubkeys(governance.data);
  const tradingParameters = vaultConfigTradingParameters(governance.data);

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

  const wireInstruments = await instruments(
    release.gatewayUrl,
    fetchImpl,
    options.signal,
  );
  const seen = new Set<string>();
  const parsed = wireInstruments.map((wire) => {
    if (
      typeof wire.symbol !== "string" ||
      !/^[A-Z0-9]{2,16}-[A-Z0-9]{2,16}$/.test(wire.symbol) ||
      typeof wire.base_mint !== "string" ||
      typeof wire.quote_mint !== "string" ||
      typeof wire.tick_size !== "string" ||
      typeof wire.min_order_size !== "string" ||
      typeof wire.trading_enabled !== "boolean" ||
      (wire.oracle?.type !== "pyth_pull_v2" &&
        wire.oracle?.type !== "pyth_push_v2") ||
      typeof wire.oracle.pubkey !== "string" ||
      !/^[0-9a-f]{64}$/.test(wire.oracle.pubkey) ||
      (wire.oracle.source !== "pyth-router-quorum-v1" &&
        wire.oracle.source !== "pyth-solana-push-v1")
    ) {
      throw new Error("venue returned a malformed instrument");
    }
    if (wire.oracle.source !== release.expectedOracleMode) {
      throw new Error(
        "venue oracle source does not match the client release pin",
      );
    }
    const expectedOracleType =
      wire.oracle.source === "pyth-solana-push-v1"
        ? "pyth_push_v2"
        : "pyth_pull_v2";
    if (wire.oracle.type !== expectedOracleType) {
      throw new Error("venue oracle adapter type contradicts its source");
    }
    if (seen.has(wire.symbol))
      throw new Error(`duplicate instrument ${wire.symbol}`);
    seen.add(wire.symbol);
    const base = new PublicKey(wire.base_mint);
    const quote = new PublicKey(wire.quote_mint);
    const [marketAddress] = marketConfigPda(programId, base, quote);
    return {
      wire: {
        symbol: wire.symbol,
        tickSize: wire.tick_size,
        minOrderSize: wire.min_order_size,
        tradingEnabled: wire.trading_enabled,
        oracleFeed: wire.oracle.pubkey,
        oracleSource: wire.oracle.source,
      } satisfies ValidatedWireInstrument,
      base,
      quote,
      marketAddress,
    };
  });
  const accounts = await Promise.all(
    parsed.map(({ marketAddress }) =>
      finalizedAccount(
        release.rpcUrl,
        marketAddress,
        fetchImpl,
        options.signal,
      ),
    ),
  );
  const trusted: TrustedInstrument[] = [];
  let finalizedGovernanceSlot = governance.slot;
  for (const [index, { wire, base, quote }] of parsed.entries()) {
    const account = accounts[index];
    finalizedGovernanceSlot = Math.min(finalizedGovernanceSlot, account.slot);
    const market = decodeMarketConfig(account.data);
    const tickSize = strictU64(wire.tickSize, `${wire.symbol}.tick_size`);
    const minOrderSize = strictU64(
      wire.minOrderSize,
      `${wire.symbol}.min_order_size`,
    );
    if (
      !market.baseMint.equals(base) ||
      !market.quoteMint.equals(quote) ||
      market.tickSize !== tickSize ||
      market.minOrderSize !== minOrderSize ||
      (wire.tradingEnabled && !market.enabled)
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
      tradingEnabled: wire.tradingEnabled && market.enabled,
      oracleFeed: wire.oracleFeed,
      oracleSource: wire.oracleSource,
    });
  }

  const status = await fetchSystemStatus(release.gatewayUrl, { fetchImpl });
  if (status.oracle_mode !== release.expectedOracleMode) {
    throw new Error(
      "venue status oracle source does not match the client release pin",
    );
  }
  return Object.freeze({
    attestation,
    finalizedGovernanceSlot,
    feeRateBps: tradingParameters.feeRateBps,
    numTrees: tradingParameters.numTrees,
    instruments: Object.freeze(trusted),
    status,
    token: () => broker.token(),
  });
}
