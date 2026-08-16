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
  if (env.DARKNYX_TRADER_CVM_TRANSPORT?.trim() !== "ra-tls") return undefined;

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

  const { TransportAgent, createVerifiedFetch } = await import(
    "@darknyx/sdk/transport-node"
  );
  const { createDcapQuoteVerifier, parseEventLog } = await import(
    "@darknyx/sdk"
  );
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
