import type { PublicRelease } from "./types.js";

// Must match @phala/dcap-qvl's pinned PHALA_PCCS_URL. Browser-side quote
// verification fetches Intel collateral here; it is not gateway-controlled.
const PHALA_PCCS_ORIGIN = "https://pccs.phala.network";

function wsOrigin(value: string): string {
  const url = new URL(value);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  return url.origin;
}

export function securityHeaders(
  origin: URL,
  release: PublicRelease,
): Readonly<Record<string, string>> {
  const connect = [
    "'self'",
    new URL(release.gateway_url).origin,
    wsOrigin(release.gateway_url),
    new URL(release.rpc_url).origin,
    new URL(release.artifact_manifest_url).origin,
    PHALA_PCCS_ORIGIN,
  ].join(" ");
  const csp = [
    "default-src 'none'",
    "script-src 'self' 'wasm-unsafe-eval'",
    "worker-src 'self' blob:",
    `connect-src ${connect}`,
    "style-src 'self'",
    "font-src 'self'",
    "img-src 'self' data:",
    "frame-src 'self'",
    "manifest-src 'self'",
    "form-action 'none'",
    "base-uri 'none'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "require-trusted-types-for 'script'",
    "trusted-types darknyx-vault-worker darknyx-prover-worker darknyx-snarkjs-worker",
  ].join("; ");
  const headers: Record<string, string> = {
    "Content-Security-Policy": csp,
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy":
      "camera=(), microphone=(), geolocation=(), payment=(), usb=(), publickey-credentials-get=(self), publickey-credentials-create=(self)",
    "X-Frame-Options": "DENY",
  };
  if (origin.protocol === "https:") {
    headers["Strict-Transport-Security"] =
      "max-age=63072000; includeSubDomains";
  }
  return Object.freeze(headers);
}

/**
 * Narrow exception for the opaque-origin TradingView child document.
 *
 * The custody application retains `securityHeaders()`. Only
 * `/tradingview.html`, which the parent loads with `sandbox=allow-scripts`,
 * receives this policy and may execute the external widget bootstrap.
 */
export function tradingViewFrameSecurityHeaders(
  origin: URL,
): Readonly<Record<string, string>> {
  const csp = [
    "default-src 'none'",
    "script-src 'self' https://s3.tradingview.com",
    "frame-src https://www.tradingview-widget.com",
    "style-src 'unsafe-inline'",
    "img-src data: https:",
    "font-src data: https:",
    "connect-src https:",
    "form-action 'none'",
    "base-uri 'none'",
    "object-src 'none'",
    `frame-ancestors ${origin.origin}`,
  ].join("; ");
  return Object.freeze({
    "Content-Security-Policy": csp,
    "Cross-Origin-Opener-Policy": "unsafe-none",
    "Cross-Origin-Embedder-Policy": "unsafe-none",
    "Cross-Origin-Resource-Policy": "same-origin",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy":
      "camera=(), microphone=(), geolocation=(), payment=(), usb=(), publickey-credentials-get=(), publickey-credentials-create=()",
  });
}
