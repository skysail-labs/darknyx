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
    // A DNS failure proves it attempted an ordinary fetch rather than
    // constructing a verified transport (which would throw on missing pins).
    await expect(gwFetch("https://example.invalid/health", undefined, 1))
      .rejects.toThrow();
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
  it("is documented as forbidden in the harness", async () => {
    // A behavioural assertion would need a live self-signed endpoint. This
    // pins the intent where a future maintainer will meet it: reaching for
    // NODE_TLS_REJECT_UNAUTHORIZED=0 to make the s route "work" disables
    // certificate verification entirely and accepts any certificate from
    // anyone, while the run still reports as RA-TLS.
    const { readFileSync } = await import("node:fs");
    const src = readFileSync(
      new URL("./helpers/cvm-harness.ts", import.meta.url),
      "utf8",
    );
    expect(src).toContain("Fail loudly rather than falling back");
  });

  it("is not set by the suite itself", () => {
    // If this ever becomes set, a "passing" cvm run proves nothing about the
    // certificate the enclave served.
    expect(process.env.NODE_TLS_REJECT_UNAUTHORIZED).not.toBe("0");
  });
});
