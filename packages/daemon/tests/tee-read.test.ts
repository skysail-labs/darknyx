/**
 * TeeReadClient tests — authenticated GETs to the TEE read surface, fake fetch.
 */

import { describe, expect, it, vi } from "vitest";

import { TeeReadClient } from "../src/tee-read.js";

function client(): { c: TeeReadClient; calls: string[] } {
  const calls: string[] = [];
  const fetchImpl = vi.fn(async (url: string, init?: RequestInit) => {
    calls.push(url);
    const auth = (init?.headers as Record<string, string>)?.authorization;
    expect(auth).toBe("Bearer tok");
    return new Response(JSON.stringify({ ok: url }), { status: 200 });
  }) as unknown as typeof fetch;
  return {
    c: new TeeReadClient({ gatewayUrl: "https://gw", token: "tok", fetchImpl }),
    calls,
  };
}

describe("TeeReadClient", () => {
  it("GETs each endpoint with the bearer token", async () => {
    const { c, calls } = client();
    await c.account();
    await c.instruments();
    await c.instrument("SOL-USDC");
    await c.settlementStatus(42);
    await c.systemStatus();
    await c.serverTime();
    await c.transparency();
    expect(calls).toEqual([
      "https://gw/account",
      "https://gw/instruments",
      "https://gw/instruments/SOL-USDC",
      "https://gw/settlement/status/42",
      "https://gw/system/status",
      "https://gw/time",
      "https://gw/transparency",
    ]);
  });

  it("returns the parsed JSON", async () => {
    const { c } = client();
    expect(await c.account()).toEqual({ ok: "https://gw/account" });
  });

  it("throws on a non-2xx", async () => {
    const fetchImpl = vi.fn(
      async () => new Response("nope", { status: 503 }),
    ) as unknown as typeof fetch;
    const c = new TeeReadClient({
      gatewayUrl: "https://gw",
      token: "t",
      fetchImpl,
    });
    await expect(c.transparency()).rejects.toThrow(/503/);
  });
});
