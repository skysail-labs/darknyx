import { sha256 } from "@noble/hashes/sha2";
import { PublicKey } from "@solana/web3.js";
import {
  marketConfigPda,
  vaultConfigPda,
  type TeeAttestation,
} from "@darknyx/sdk/browser-attestation";
import { describe, expect, it, vi } from "vitest";

import {
  bootstrapTrustedVenue,
  SameOriginSessionBroker,
} from "../src/internal.js";

const PROGRAM = new PublicKey("C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx");
const SIGNER = new PublicKey(new Uint8Array(32).fill(7));
const BASE = new PublicKey(new Uint8Array(32).fill(8));
const QUOTE = new PublicKey(new Uint8Array(32).fill(9));

function discriminator(name: string): Uint8Array {
  return sha256(new TextEncoder().encode(`account:${name}`)).subarray(0, 8);
}

function u64(data: Uint8Array, offset: number, value: bigint): void {
  new DataView(data.buffer).setBigUint64(offset, value, true);
}

function vaultConfig(): Uint8Array {
  const data = new Uint8Array(1_264);
  data.set(discriminator("VaultConfig"));
  data.set(SIGNER.toBytes(), 40);
  data[1_258] = 1;
  data[1_259] = 1;
  return data;
}

function marketConfig(tick = 100n, enabled = true): Uint8Array {
  const data = new Uint8Array(108);
  data.set(discriminator("MarketConfig"));
  data.set(BASE.toBytes(), 8);
  data.set(QUOTE.toBytes(), 40);
  u64(data, 72, 1_000_000n);
  u64(data, 80, tick);
  u64(data, 88, 10_000n);
  u64(data, 96, 1_000n);
  data[104] = 9;
  data[105] = 6;
  data[106] = enabled ? 1 : 0;
  data[107] = 255;
  return data;
}

function b64(data: Uint8Array): string {
  return btoa(String.fromCharCode(...data));
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function attestation(): TeeAttestation {
  return {
    teePubkey: SIGNER.toBase58(),
    teePubkeys: [SIGNER.toBase58()],
    composeHash: "ab".repeat(32),
    mrtd: "cd".repeat(48),
    quote: "ef",
    bootSessionId: "12".repeat(32),
  };
}

function venueFetch(
  options: { mismatchedTick?: boolean; marketEnabled?: boolean } = {},
): typeof fetch {
  const [vault] = vaultConfigPda(PROGRAM);
  const [market] = marketConfigPda(PROGRAM, BASE, QUOTE);
  return vi.fn(async (input, init) => {
    const url = String(input);
    if (url === "https://rpc.example/") {
      const request = JSON.parse(String(init?.body)) as {
        params: [string];
      };
      const data =
        request.params[0] === vault.toBase58()
          ? vaultConfig()
          : request.params[0] === market.toBase58()
            ? marketConfig(100n, options.marketEnabled ?? true)
            : undefined;
      return json({
        result: {
          context: { slot: 4242 },
          value: data ? { data: [b64(data), "base64"] } : null,
        },
      });
    }
    if (url === "https://cvm.example/instruments") {
      return json([
        {
          symbol: "SOL-USDC",
          base_mint: BASE.toBase58(),
          quote_mint: QUOTE.toBase58(),
          tick_size: options.mismatchedTick ? "101" : "100",
          min_order_size: "10000",
          trading_enabled: true,
          oracle: { type: "pyth_pull_v2", pubkey: "ab".repeat(32) },
        },
      ]);
    }
    if (url === "https://cvm.example/system/status") {
      return json({
        degraded: false,
        matcher_running: true,
        settle_enabled: true,
        oracle_configured: true,
        current_slot: 4243,
        version: "test",
      });
    }
    if (url === "https://app.example/api/darknyx/session/start") {
      return new Response(null, { status: 204 });
    }
    if (url === "https://app.example/api/darknyx/session") {
      return json({ access_token: "x".repeat(64), expires_in: 3600 });
    }
    return json({}, 404);
  }) as typeof fetch;
}

const RELEASE = {
  venueId: "devnet-primary",
  gatewayUrl: "https://cvm.example",
  rpcUrl: "https://rpc.example/",
  vaultProgramId: PROGRAM.toBase58(),
  expectedComposeHash: "ab".repeat(32),
};

describe("strict browser venue bootstrap", () => {
  it("binds attestation and instrument metadata to finalized governance", async () => {
    const fetchImpl = venueFetch();
    const verify = vi.fn(async () => attestation());
    const venue = await bootstrapTrustedVenue(RELEASE, {
      fetchImpl,
      origin: "https://app.example",
      attestationVerifier: verify,
    });

    expect(verify).toHaveBeenCalledWith(
      RELEASE.gatewayUrl,
      RELEASE.expectedComposeHash,
      expect.objectContaining({ expectedTeePubkey: SIGNER.toBase58() }),
    );
    expect(venue.finalizedGovernanceSlot).toBe(4242);
    expect(venue.instruments[0]).toMatchObject({
      symbol: "SOL-USDC",
      priceScale: 1_000_000n,
      tickSize: 100n,
      tradingEnabled: true,
    });
    expect(await venue.token()).toBe("x".repeat(64));
    const calls = vi.mocked(fetchImpl).mock.calls;
    const broker = calls.find(([input]) =>
      String(input).endsWith("/api/darknyx/session"),
    );
    expect(JSON.parse(String(broker?.[1]?.body))).toEqual({
      venue_id: "devnet-primary",
    });
  });

  it("fails closed when venue market metadata differs from governance", async () => {
    const fetchImpl = venueFetch({ mismatchedTick: true });
    await expect(
      bootstrapTrustedVenue(RELEASE, {
        fetchImpl,
        origin: "https://app.example",
        attestationVerifier: async () => attestation(),
      }),
    ).rejects.toThrow("disagrees with finalized governance");
    expect(
      vi
        .mocked(fetchImpl)
        .mock.calls.some(([input]) =>
          String(input).endsWith("/api/darknyx/session"),
        ),
    ).toBe(false);
  });

  it("fails closed on signer-set drift and a disabled governed market", async () => {
    await expect(
      bootstrapTrustedVenue(RELEASE, {
        fetchImpl: venueFetch(),
        origin: "https://app.example",
        attestationVerifier: async () => ({
          ...attestation(),
          teePubkeys: [new PublicKey(new Uint8Array(32).fill(6)).toBase58()],
        }),
      }),
    ).rejects.toThrow(/attested tee_pubkeys.*on-chain/i);
    await expect(
      bootstrapTrustedVenue(RELEASE, {
        fetchImpl: venueFetch({ marketEnabled: false }),
        origin: "https://app.example",
        attestationVerifier: async () => attestation(),
      }),
    ).rejects.toThrow("disagrees with finalized governance");
  });
});

describe("same-origin token broker", () => {
  it("rejects a credential broker on another origin", () => {
    expect(
      () =>
        new SameOriginSessionBroker({
          venueId: "primary",
          origin: "https://app.example",
          endpoint: "https://evil.example/token",
        }),
    ).toThrow("same-origin");
  });

  it("caches a short-lived token and never accepts long-lived credentials", async () => {
    let now = 1_000;
    const fetchImpl = vi.fn(async () =>
      json({ access_token: "t".repeat(64), expires_in: 300 }),
    );
    const broker = new SameOriginSessionBroker({
      venueId: "primary",
      origin: "https://app.example",
      fetchImpl,
      now: () => now,
    });
    expect(await broker.token()).toBe("t".repeat(64));
    expect(await broker.token()).toBe("t".repeat(64));
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    now += 240_001;
    expect(await broker.token()).toBe("t".repeat(64));
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });
});
