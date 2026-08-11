import type { PublicRelease } from "./types.js";

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
  ].join(" ");
  const csp = [
    "default-src 'none'",
    "script-src 'self' 'wasm-unsafe-eval'",
    "worker-src 'self' blob:",
    `connect-src ${connect}`,
    "style-src 'self'",
    "font-src 'self'",
    "img-src 'self' data:",
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
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cross-Origin-Resource-Policy": "same-origin",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy":
      "camera=(), microphone=(), geolocation=(), payment=(), usb=(), publickey-credentials-get=(self), publickey-credentials-create=(self)",
    "X-Frame-Options": "DENY",
  };
  if (origin.protocol === "https:") {
    headers["Strict-Transport-Security"] =
      "max-age=63072000; includeSubDomains; preload";
  }
  return Object.freeze(headers);
}
