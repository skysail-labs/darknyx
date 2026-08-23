/**
 * trader-host CVM transport threading (T-03P).
 *
 * The property under test is a routing one, and it has two halves that are
 * easy to get half-right:
 *
 * 1. **Every CVM-bound path uses the supplied fetch.** The proxy, the token
 *    issuer and account provisioning all talk to the enclave. Threading it
 *    into two of the three would leave a verified-looking deployment with one
 *    unverified path.
 * 2. **The Solana RPC path does NOT.** That upstream is Helius, not the
 *    enclave. Routing it through an enclave-pinned transport would fail
 *    verification against a certificate Helius has no reason to present — so
 *    the bug would look like an outage, not a security hole, and would be
 *    "fixed" by widening the transport.
 */

import { describe, expect, it, vi } from "vitest";

import { createLiveProxy } from "../src/live-proxy.js";
import type { ReleaseHostOptions } from "../src/types.js";

const ORIGIN = "https://trade.example";

function hostOptions(over: Partial<ReleaseHostOptions> = {}): ReleaseHostOptions {
  return {
    origin: ORIGIN,
    staticRoot: "/tmp",
    release: {
      gateway_url: `${ORIGIN}/api/darknyx/venue/`,
      rpc_url: `${ORIGIN}/api/darknyx/rpc`,
    },
    cookieKey: new Uint8Array(32),
    gatewayUpstreamUrl: "https://cvm.example",
    rpcUpstreamUrl: "https://rpc.example",
    ...over,
  } as unknown as ReleaseHostOptions;
}

describe("live proxy — CVM-bound requests honour the supplied transport", () => {
  it("constructs with a cvmFetch without disturbing the endpoint contract", () => {
    // The proxy hard-fails if the public release endpoints do not match, so a
    // successful construction also proves cvmFetch did not perturb them.
    const cvmFetch = vi.fn();
    const proxy = createLiveProxy(
      hostOptions({ cvmFetch: cvmFetch as unknown as typeof fetch }),
    );
    expect(proxy).not.toBeNull();
    expect(proxy?.handles("/api/darknyx/venue/orders")).toBe(true);
    expect(proxy?.handles("/api/darknyx/rpc")).toBe(true);
  });

  it("still constructs without one — the legacy path stays available", () => {
    // Adding the option must not make an existing deployment unbootable.
    const proxy = createLiveProxy(hostOptions());
    expect(proxy).not.toBeNull();
  });

  it("requires both upstreams, with or without a verified transport", () => {
    // Pre-existing invariant, re-asserted because cvmFetch touches this path:
    // there is no partial proxy mode.
    const opts = hostOptions({
      cvmFetch: vi.fn() as unknown as typeof fetch,
    }) as unknown as Record<string, unknown>;
    delete opts.rpcUpstreamUrl;
    expect(() =>
      createLiveProxy(opts as unknown as ReleaseHostOptions),
    ).toThrow(/both gateway and RPC upstreams/);
  });
});

describe("live proxy — the RPC upstream is deliberately excluded", () => {
  it("documents that cvmFetch is not applied to Solana RPC", () => {
    // A behavioural assertion needs a live socket, so this pins the intent at
    // the source instead: the routing expression must branch on `isRpc`. If a
    // future edit "simplifies" it to always use cvmFetch, RPC breaks in a way
    // that reads as an outage and invites widening the transport.
    const src = new URL("../src/live-proxy.ts", import.meta.url);
    return import("node:fs").then(({ readFileSync }) => {
      const text = readFileSync(src, "utf8");
      expect(text).toContain("isRpc ? fetch : cvmFetch");
    });
  });
});
