/**
 * Verified upstream transport for CVM-bound trader-host requests (T-03P).
 *
 * Lives in its own module rather than in `bin.ts` so the fail-closed behaviour
 * is reachable from tests. A startup guard that only runs during `main()` is a
 * guard nothing can exercise, which is how the rest of this remediation has
 * repeatedly produced green-but-vacuous checks.
 */
import { randomBytes } from "node:crypto";

/**
 * Build the verified upstream transport, or `undefined` for the legacy path.
 *
 * Fails closed: `ra-tls` without its governance pins throws rather than
 * quietly returning `undefined`, because a trader-host that reported ra-tls
 * while proxying over an unverified upstream is the exact outcome T-03P
 * exists to prevent.
 */
export async function buildCvmFetch(
  env: NodeJS.ProcessEnv,
): Promise<typeof fetch | undefined> {
  const mode = env.DARKNYX_TRADER_CVM_TRANSPORT?.trim();
  // Unset or empty means the legacy path, deliberately — existing deployments
  // must keep booting. But a value that is SET and unrecognised is a typo, not
  // a choice: `ratls`, `RA-TLS`, `ra_tls` would otherwise start trader-host on
  // the gateway-terminated path, `bin.ts` would print the legacy notice, and
  // every browser order would be proxied over an unverified upstream while the
  // operator believed RA-TLS was on.
  //
  // This corrects an earlier decision here that treated near-misses as "legacy
  // by choice". The daemon's own `TransportMode::from_env` fails closed on an
  // unrecognised value; the process that relays browser order intent should
  // not be laxer than the one that relays a market maker's.
  if (mode === undefined || mode === "") return undefined;
  // The legacy path, named explicitly. Accepted so an operator can state the
  // intent rather than relying on absence to mean it.
  if (mode === "gateway-terminated") return undefined;
  if (mode !== "ra-tls") {
    throw new Error(
      `DARKNYX_TRADER_CVM_TRANSPORT=${JSON.stringify(mode)} is not recognised; ` +
        'expected "ra-tls" or "gateway-terminated" (or unset for legacy). ' +
        "Refusing to start rather than silently proxying browser orders over " +
        "an unverified upstream.",
    );
  }

  const gateway = env.DARKNYX_TRADER_CVM_GATEWAY_UPSTREAM?.trim();
  const compose = env.DARKNYX_TRADER_EXPECT_COMPOSE_HASH?.trim();
  const signers = env.DARKNYX_TRADER_EXPECT_SIGNER_SET?.trim();
  const missing = [
    !gateway && "DARKNYX_TRADER_CVM_GATEWAY_UPSTREAM",
    !compose && "DARKNYX_TRADER_EXPECT_COMPOSE_HASH",
    !signers && "DARKNYX_TRADER_EXPECT_SIGNER_SET",
  ].filter(Boolean);
  if (missing.length > 0) {
    throw new Error(
      `DARKNYX_TRADER_CVM_TRANSPORT=ra-tls requires ${missing.join(", ")}. ` +
        "Without these a verified transport proves a channel to some enclave, " +
        "not the governed one. Refusing to start.",
    );
  }
  if (!/^[0-9a-fA-F]{64}$/.test(signers!)) {
    throw new Error("DARKNYX_TRADER_EXPECT_SIGNER_SET must be 32 bytes of hex");
  }

  const { TransportAgent, createVerifiedFetch } =
    await import("@darknyx/sdk/transport-node");
  const { createDcapQuoteVerifier, parseEventLog } =
    await import("@darknyx/sdk");
  const dcap = createDcapQuoteVerifier({});
  return createVerifiedFetch({
    baseUrl: gateway!,
    agent: new TransportAgent(),
    deps: {
      verifyQuote: (quoteHex: string) =>
        dcap(
          Uint8Array.from(
            quoteHex.match(/../g)?.map((b) => parseInt(b, 16)) ?? [],
          ),
        ),
      parseEventLog,
      randomNonce: () => new Uint8Array(randomBytes(32)),
    },
    expectedComposeHash: compose!,
    expectedSignerSetSha256: Uint8Array.from(
      signers!.match(/../g)!.map((b) => parseInt(b, 16)),
    ),
  });
}
