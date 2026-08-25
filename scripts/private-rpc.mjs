const PUBLIC_SOLANA_RPC_HOSTS = new Set([
  "api.devnet.solana.com",
  "api.mainnet-beta.solana.com",
  "api.testnet.solana.com",
]);

/**
 * Require an explicitly configured, non-public RPC endpoint before an
 * operator script sends privileged or high-volume requests. Deployments may
 * additionally pin an exact provider origin with DARKNYX_TRUSTED_RPC_ORIGIN.
 */
export function requirePrivateRpcUrl(raw) {
  if (!raw) {
    throw new Error(
      "SOLANA_RPC_URL is required (use the configured private RPC)",
    );
  }
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error("SOLANA_RPC_URL must be a valid absolute URL");
  }
  const local =
    parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1";
  if (parsed.protocol !== "https:" && !(local && parsed.protocol === "http:")) {
    throw new Error("SOLANA_RPC_URL must use HTTPS (except localhost)");
  }
  if (PUBLIC_SOLANA_RPC_HOSTS.has(parsed.hostname.toLowerCase())) {
    throw new Error("SOLANA_RPC_URL must not use a public Solana RPC endpoint");
  }

  const trustedOrigin = process.env.DARKNYX_TRUSTED_RPC_ORIGIN?.trim();
  if (trustedOrigin) {
    let expected;
    try {
      expected = new URL(trustedOrigin).origin;
    } catch {
      throw new Error("DARKNYX_TRUSTED_RPC_ORIGIN must be a valid origin");
    }
    if (parsed.origin !== expected) {
      throw new Error(
        `SOLANA_RPC_URL origin ${parsed.origin} does not match DARKNYX_TRUSTED_RPC_ORIGIN`,
      );
    }
  }
  return raw;
}
