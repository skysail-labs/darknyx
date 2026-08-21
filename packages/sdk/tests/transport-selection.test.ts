/**
 * How the `cvm-*` suites choose their transport (T-03P cutover).
 *
 * All six suites reach the CVM through `gwFetch`, so this is the single place
 * the cutover happens. These tests guard the two ways that could go quietly
 * wrong:
 *
 * 1. **A silent fallback.** If `DARKNYX_CVM_TRANSPORT=ra-tls` were to fall back
 *    to plain fetch when its pins are missing, the suite would report a green
 *    cutover that never happened — the worst possible outcome, because it looks
 *    like evidence.
 * 2. **The `NODE_TLS_REJECT_UNAUTHORIZED=0` shortcut.** Pointing the legacy
 *    transport at the `s` route fails on the self-signed certificate. The
 *    tempting fix is to disable certificate verification, which accepts any
 *    certificate from anyone while looking like RA-TLS. That is strictly worse
 *    than the legacy path and must never be how this suite is made to pass.
 *
 * These run without a CVM: they test the selection logic, not the connection.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { gwFetch } from "./helpers/cvm-harness.js";

const KEYS = [
  "DARKNYX_CVM_TRANSPORT",
  "DARKNYX_TEE_GATEWAY",
  "DARKNYX_EXPECT_COMPOSE_HASH",
  "DARKNYX_EXPECT_SIGNER_SET",
] as const;

let saved: Record<string, string | undefined>;

beforeEach(() => {
  saved = Object.fromEntries(KEYS.map((k) => [k, process.env[k]]));
  for (const k of KEYS) delete process.env[k];
});

afterEach(() => {
  for (const k of KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k]!;
  }
});

describe("cvm transport selection", () => {
  it("defaults to the legacy path when nothing is set", async () => {
    // The suites must keep working unchanged until the cutover window.
    process.env.DARKNYX_TEE_GATEWAY = "https://example.invalid";
    // A bare `.rejects.toThrow()` would pass on ANY error — including the
    // missing-pin error this test exists to prove did NOT happen. Assert the
    // discriminating negative instead: whatever failed, it was not the
    // verified-transport construction path.
    const err = await gwFetch(
      "https://example.invalid/health",
      undefined,
      1,
    ).then(
      () => null,
      (e: unknown) => e as Error,
    );
    expect(err, "the call unexpectedly succeeded").not.toBeNull();
    expect(
      (err as Error).message,
      "the legacy path constructed a verified transport instead of plain fetch",
    ).not.toMatch(/EXPECT_COMPOSE_HASH|EXPECT_SIGNER_SET|ra-tls/i);
    expect(process.env.DARKNYX_CVM_TRANSPORT).toBeUndefined();
  });

  it("refuses ra-tls without a compose-hash pin rather than falling back", async () => {
    process.env.DARKNYX_CVM_TRANSPORT = "ra-tls";
    process.env.DARKNYX_TEE_GATEWAY = "https://example.invalid";
    process.env.DARKNYX_EXPECT_SIGNER_SET = "33".repeat(32);
    await expect(
      gwFetch("https://example.invalid/health", undefined, 1),
    ).rejects.toThrow(/EXPECT_COMPOSE_HASH|governed one/);
  });

  it("refuses ra-tls without a signer-set pin rather than falling back", async () => {
    process.env.DARKNYX_CVM_TRANSPORT = "ra-tls";
    process.env.DARKNYX_TEE_GATEWAY = "https://example.invalid";
    process.env.DARKNYX_EXPECT_COMPOSE_HASH = "aa".repeat(32);
    await expect(
      gwFetch("https://example.invalid/health", undefined, 1),
    ).rejects.toThrow(/EXPECT_SIGNER_SET|governed one/);
  });

  it("refuses ra-tls without a gateway rather than falling back", async () => {
    process.env.DARKNYX_CVM_TRANSPORT = "ra-tls";
    process.env.DARKNYX_EXPECT_COMPOSE_HASH = "aa".repeat(32);
    process.env.DARKNYX_EXPECT_SIGNER_SET = "33".repeat(32);
    await expect(
      gwFetch("https://example.invalid/health", undefined, 1),
    ).rejects.toThrow(/DARKNYX_TEE_GATEWAY/);
  });
});

describe("the NODE_TLS_REJECT_UNAUTHORIZED shortcut is not how this suite passes", () => {
  it("is not set by the suite itself", () => {
    // If this ever becomes set, a "passing" cvm run proves nothing about the
    // certificate the enclave served.
    expect(process.env.NODE_TLS_REJECT_UNAUTHORIZED).not.toBe("0");
  });
});
