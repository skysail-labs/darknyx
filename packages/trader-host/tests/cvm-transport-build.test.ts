/**
 * trader-host verified-transport construction (T-03P).
 *
 * `trader-host` is the process that sees every browser order in plaintext, so
 * it is the single most consequential consumer of the verified transport. The
 * failure that matters is not "ra-tls did not work" — that is loud. It is
 * "ra-tls was requested, a pin was missing, and the process started anyway on
 * the legacy path" — which is silent, and leaves an operator who believes the
 * channel is bound to a quote.
 *
 * So every test here is about refusing to start.
 */

import { describe, expect, it } from "vitest";

import { buildCvmFetch } from "../src/cvm-transport.js";

const FULL = {
  DARKNYX_TRADER_CVM_TRANSPORT: "ra-tls",
  DARKNYX_TRADER_CVM_GATEWAY_UPSTREAM: "https://cvm.example",
  DARKNYX_TRADER_EXPECT_COMPOSE_HASH: "aa".repeat(32),
  DARKNYX_TRADER_EXPECT_SIGNER_SET: "bb".repeat(32),
} as NodeJS.ProcessEnv;

const without = (k: string): NodeJS.ProcessEnv => {
  const e = { ...FULL };
  delete e[k];
  return e;
};

describe("legacy path stays the default", () => {
  it("returns undefined when the mode is unset", async () => {
    // Existing deployments must keep booting. If this ever threw, the cutover
    // would be forced rather than chosen.
    await expect(buildCvmFetch({})).resolves.toBeUndefined();
  });

  it("returns undefined for an explicit gateway-terminated mode", async () => {
    await expect(
      buildCvmFetch({ DARKNYX_TRADER_CVM_TRANSPORT: "gateway-terminated" }),
    ).resolves.toBeUndefined();
  });

  it("REFUSES a near-miss value rather than falling back to legacy", async () => {
    // Reversed from an earlier version of this test, which asserted these
    // resolved to `undefined` (legacy). That was wrong: a set-but-unrecognised
    // value is a typo, not a choice, and silently selecting the weaker
    // transport for it is the fail-open this whole feature exists to remove.
    // Unset still means legacy — that is tested above.
    for (const v of ["ratls", "ra_tls", "RA-TLS", "ra-tls-ish"]) {
      await expect(
        buildCvmFetch({ DARKNYX_TRADER_CVM_TRANSPORT: v }),
      ).rejects.toThrow(/not recognised/);
    }
  });

  it("tolerates surrounding whitespace on the real value", async () => {
    // Env files routinely carry trailing spaces; that must not silently
    // downgrade a deployment that asked for ra-tls.
    await expect(
      buildCvmFetch({ ...FULL, DARKNYX_TRADER_CVM_TRANSPORT: " ra-tls " }),
    ).resolves.toBeTypeOf("function");
  });
});

describe("ra-tls refuses to start without its governance pins", () => {
  it("refuses without an upstream", async () => {
    await expect(
      buildCvmFetch(without("DARKNYX_TRADER_CVM_GATEWAY_UPSTREAM")),
    ).rejects.toThrow(/DARKNYX_TRADER_CVM_GATEWAY_UPSTREAM/);
  });

  it("refuses without a compose-hash pin", async () => {
    // Without this, verification proves a channel to an enclave, not to the
    // enclave whose code we govern.
    await expect(
      buildCvmFetch(without("DARKNYX_TRADER_EXPECT_COMPOSE_HASH")),
    ).rejects.toThrow(/DARKNYX_TRADER_EXPECT_COMPOSE_HASH/);
  });

  it("refuses without a signer-set pin", async () => {
    await expect(
      buildCvmFetch(without("DARKNYX_TRADER_EXPECT_SIGNER_SET")),
    ).rejects.toThrow(/DARKNYX_TRADER_EXPECT_SIGNER_SET/);
  });

  it("names every missing pin in one message", async () => {
    // An operator should not discover the requirements one failed boot at a
    // time.
    const err = await buildCvmFetch({
      DARKNYX_TRADER_CVM_TRANSPORT: "ra-tls",
    }).catch((e: unknown) => e as Error);
    expect((err as Error).message).toContain("DARKNYX_TRADER_CVM_GATEWAY_UPSTREAM");
    expect((err as Error).message).toContain("DARKNYX_TRADER_EXPECT_COMPOSE_HASH");
    expect((err as Error).message).toContain("DARKNYX_TRADER_EXPECT_SIGNER_SET");
  });

  it("rejects rather than returns undefined, so a caller cannot fall through", async () => {
    // The distinction this file exists for. `undefined` means "legacy, by
    // choice"; a misconfigured ra-tls must never produce it, because the
    // entrypoint would then boot and print the legacy warning as though the
    // operator had asked for it.
    const r = await buildCvmFetch(
      without("DARKNYX_TRADER_EXPECT_COMPOSE_HASH"),
    ).then(
      (v) => ({ resolved: v }),
      () => ({ threw: true }),
    );
    expect(r).toEqual({ threw: true });
  });
});

describe("the signer-set pin is validated, not merely present", () => {
  it("rejects a short pin", async () => {
    await expect(
      buildCvmFetch({ ...FULL, DARKNYX_TRADER_EXPECT_SIGNER_SET: "aabb" }),
    ).rejects.toThrow(/32 bytes/);
  });

  it("rejects a non-hex pin of the right length", async () => {
    // 64 characters that are not hex would otherwise parse to NaN bytes and
    // compare unequal against everything — a pin that can never match reads
    // as an outage and invites removing it.
    await expect(
      buildCvmFetch({ ...FULL, DARKNYX_TRADER_EXPECT_SIGNER_SET: "zz".repeat(32) }),
    ).rejects.toThrow(/hex/);
  });

  it("accepts a well-formed pin and returns a fetch", async () => {
    // The control. Without this, every rejection above could be passing for
    // some unrelated reason — the mistake already made once in this
    // remediation, where four negative tests passed on a wiring error.
    await expect(buildCvmFetch(FULL)).resolves.toBeTypeOf("function");
  });

  it("accepts uppercase hex", async () => {
    await expect(
      buildCvmFetch({
        ...FULL,
        DARKNYX_TRADER_EXPECT_SIGNER_SET: "AB".repeat(32),
      }),
    ).resolves.toBeTypeOf("function");
  });
});
