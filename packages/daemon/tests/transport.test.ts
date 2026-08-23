/**
 * Daemon transport selection (T-03P).
 *
 * The property worth guarding is that there is **no partial mode**. A daemon
 * that verified HTTP but streamed over an unverified WebSocket would be worse
 * than one that verified neither, because its operator and its logs would both
 * say "verified". So the tests here are mostly about refusing to construct.
 */

import { describe, expect, it } from "vitest";

import { buildDaemonTransport } from "../src/transport.js";
import {
  assertTransportConfigCoherent,
  loadConfig,
  type DaemonConfig,
} from "../src/config.js";

const SIGNER_SET = "33".repeat(32);
const COMPOSE = "aa".repeat(32);

function cfg(over: Partial<DaemonConfig> = {}): DaemonConfig {
  return {
    gatewayUrl: "https://example",
    gatewayWsUrl: "wss://example",
    token: "t",
    transportMode: "gateway-terminated",
    deploymentTier: "simulator",
    allowLegacyTransport: true,
    rpcUrl: "https://rpc",
    dbPath: ":memory:",
    controlPort: 0,
    keystorePath: "/dev/null",
    orderSequencePath: "/dev/null",
    thresholds: {} as never,
    attestationStrict: false,
    attestOnchainCheck: false,
    programId: "prog",
    ...over,
  } as DaemonConfig;
}

describe("assertTransportConfigCoherent", () => {
  it("accepts the legacy mode without pins", () => {
    expect(() => assertTransportConfigCoherent(cfg())).not.toThrow();
  });

  it("refuses ra-tls without a compose-hash pin", () => {
    // A verified channel to *an* enclave proves nothing about which one.
    expect(() =>
      assertTransportConfigCoherent(
        cfg({
          transportMode: "ra-tls",
          expectSignerSetSha256: SIGNER_SET,
        }),
      ),
    ).toThrow(/EXPECT_COMPOSE_HASH/);
  });

  it("refuses ra-tls without a signer-set pin", () => {
    expect(() =>
      assertTransportConfigCoherent(
        cfg({
          transportMode: "ra-tls",
          attestation: { composeHash: COMPOSE },
        }),
      ),
    ).toThrow(/EXPECT_SIGNER_SET_SHA256/);
  });

  it("names every missing pin at once rather than one per restart", () => {
    // An operator fixing config should not have to discover the requirements
    // one failed boot at a time.
    let msg = "";
    try {
      assertTransportConfigCoherent(cfg({ transportMode: "ra-tls" }));
    } catch (e) {
      msg = (e as Error).message;
    }
    expect(msg).toContain("EXPECT_COMPOSE_HASH");
    expect(msg).toContain("EXPECT_SIGNER_SET_SHA256");
  });

  it("accepts ra-tls with both pins", () => {
    expect(() =>
      assertTransportConfigCoherent(
        cfg({
          transportMode: "ra-tls",
          attestation: { composeHash: COMPOSE },
          expectSignerSetSha256: SIGNER_SET,
        }),
      ),
    ).not.toThrow();
  });
});

describe("loadConfig — production transport policy", () => {
  const base = (): NodeJS.ProcessEnv => ({
    DARKNYX_DAEMON_GATEWAY_URL: "https://example",
    DARKNYX_DAEMON_TOKEN: "t",
    DARKNYX_DAEMON_RPC_URL: "https://rpc",
    DARKNYX_DAEMON_EXPECT_COMPOSE_HASH: COMPOSE,
    DARKNYX_DAEMON_EXPECT_SIGNER_SET_SHA256: SIGNER_SET,
  });

  it("defaults to production RA-TLS", () => {
    const loaded = loadConfig(base());
    expect(loaded.transportMode).toBe("ra-tls");
    expect(loaded.deploymentTier).toBe("production");
  });

  it("refuses the default RA-TLS mode when its governance pins are absent", () => {
    expect(() =>
      loadConfig({
        DARKNYX_DAEMON_GATEWAY_URL: "https://example",
        DARKNYX_DAEMON_TOKEN: "t",
        DARKNYX_DAEMON_RPC_URL: "https://rpc",
      }),
    ).toThrow(/EXPECT_COMPOSE_HASH.*EXPECT_SIGNER_SET_SHA256/);
  });

  it("rejects gateway termination in production", () => {
    expect(() =>
      loadConfig({
        ...base(),
        DARKNYX_DAEMON_TRANSPORT_MODE: "gateway-terminated",
        DARKNYX_DAEMON_ALLOW_LEGACY_TRANSPORT: "1",
      }),
    ).toThrow(/forbidden in production/);
  });

  it("requires an explicit legacy acknowledgement in development", () => {
    const env = {
      ...base(),
      DARKNYX_DAEMON_DEPLOYMENT_TIER: "development",
      DARKNYX_DAEMON_TRANSPORT_MODE: "gateway-terminated",
    };
    expect(() => loadConfig(env)).toThrow(/ALLOW_LEGACY_TRANSPORT/);
    expect(
      loadConfig({ ...env, DARKNYX_DAEMON_ALLOW_LEGACY_TRANSPORT: "1" })
        .transportMode,
    ).toBe("gateway-terminated");
  });

  it("rejects a deployment-tier typo", () => {
    expect(() =>
      loadConfig({ ...base(), DARKNYX_DAEMON_DEPLOYMENT_TIER: "prod" }),
    ).toThrow(/DEPLOYMENT_TIER/);
  });

  it("rejects a transport-mode typo instead of falling back", () => {
    expect(() =>
      loadConfig({ ...base(), DARKNYX_DAEMON_TRANSPORT_MODE: "ratls" }),
    ).toThrow(/TRANSPORT_MODE/);
  });
});

describe("buildDaemonTransport — legacy mode", () => {
  it("returns a plain fetch and never reports staleness", async () => {
    const t = await buildDaemonTransport(cfg(), { verifierDeps: {} as never });
    expect(t.mode).toBe("gateway-terminated");
    expect(t.webSocketFactory).toBeUndefined();
    expect(t.isStale()).toBe(false);
  });
});

describe("buildDaemonTransport — ra-tls refuses to half-protect", () => {
  const ratls = (over: Partial<DaemonConfig> = {}) =>
    cfg({
      transportMode: "ra-tls",
      attestation: { composeHash: COMPOSE },
      expectSignerSetSha256: SIGNER_SET,
      ...over,
    });

  it("refuses without a WebSocket constructor", async () => {
    // THE test in this file. Verifying HTTP while leaving /v1/stream
    // unverified is the failure that would read as success.
    await expect(
      buildDaemonTransport(ratls(), { verifierDeps: {} as never }),
    ).rejects.toThrow(/gated|unverified/i);
  });

  it("refuses without a compose-hash pin even if config validation was bypassed", async () => {
    // This module is reachable from a hand-built config, so it re-checks
    // rather than trusting loadConfig to have run.
    await expect(
      buildDaemonTransport(ratls({ attestation: undefined }), {
        verifierDeps: {} as never,
        createWebSocket: () => ({}) as never,
      }),
    ).rejects.toThrow(/compose hash/i);
  });

  it("refuses a signer-set pin that is not 32 bytes", async () => {
    await expect(
      buildDaemonTransport(ratls({ expectSignerSetSha256: "aabb" }), {
        verifierDeps: {} as never,
        createWebSocket: () => ({}) as never,
      }),
    ).rejects.toThrow(/32 bytes/);
  });

  it("refuses a signer-set pin that is not hex", async () => {
    await expect(
      buildDaemonTransport(ratls({ expectSignerSetSha256: "zz".repeat(32) }), {
        verifierDeps: {} as never,
        createWebSocket: () => ({}) as never,
      }),
    ).rejects.toThrow(/valid hex/);
  });
});

describe("buildDaemonTransport — what the daemon actually receives", () => {
  it("hands back a fetch the daemon can use as fetchImpl", async () => {
    // The Daemon threads `deps.fetchImpl` into every CVM call site, so the
    // wiring in bin/daemon.ts is only as good as this being a real fetch.
    const t = await buildDaemonTransport(cfg(), { verifierDeps: {} as never });
    expect(typeof t.fetch).toBe("function");
  });

  it("legacy mode supplies no WebSocket factory, so the daemon keeps its default", async () => {
    // Under gateway-terminated there is nothing to gate. The daemon must fall
    // back to its ordinary factory rather than receive a broken one.
    const t = await buildDaemonTransport(cfg(), { verifierDeps: {} as never });
    expect(t.webSocketFactory).toBeUndefined();
    expect(t.mode).toBe("gateway-terminated");
  });

  it("reports the mode so the entrypoint can warn on the legacy path", async () => {
    // bin/daemon.ts branches on this to print either the ra-tls confirmation
    // or an explicit warning that nothing binds the quote to the connection.
    // A mode that could not be read would make that warning impossible.
    const t = await buildDaemonTransport(cfg(), { verifierDeps: {} as never });
    expect(["ra-tls", "gateway-terminated"]).toContain(t.mode);
  });
});
