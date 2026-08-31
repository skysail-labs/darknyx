import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "::1", "[::1]"]);

/**
 * Parse a local Surfpool endpoint and reject every non-loopback control plane.
 *
 * Surfpool's `surfnet_*` methods can mutate arbitrary local accounts. Keeping
 * this check in one module prevents a helper from quietly reintroducing the
 * old `SURFPOOL_ALLOW_REMOTE` escape hatch.
 */
export function requireLoopbackRpc(rawUrl, label = "Surfpool RPC") {
  let url;
  try {
    url = new URL(rawUrl);
  } catch (error) {
    throw new Error(`${label} is not a valid URL: ${error.message}`);
  }
  if (url.protocol !== "http:") {
    throw new Error(`${label} must use plain HTTP on the local loopback`);
  }
  if (!LOOPBACK_HOSTS.has(url.hostname)) {
    throw new Error(`${label} must be loopback, received ${url.hostname}`);
  }
  if (url.username || url.password) {
    throw new Error(`${label} must not contain credentials`);
  }
  return url;
}

if (
  process.argv[1] &&
  fileURLToPath(import.meta.url) === resolve(process.argv[1])
) {
  const rawUrl = process.argv[2];
  if (!rawUrl) throw new Error("usage: loopback.mjs <rpc-url>");
  const url = requireLoopbackRpc(rawUrl);
  process.stdout.write(`${url.href}\n`);
}
