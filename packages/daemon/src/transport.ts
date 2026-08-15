/**
 * The daemon's transport selection (T-03P, Phase 2e).
 *
 * The daemon either verifies the socket carrying each request against a
 * quote-bound certificate (`ra-tls`) or it does not (`gateway-terminated`,
 * the legacy path). This module is the single place that decision is made, so
 * the rest of the daemon receives a `fetch` and — when RA-TLS is on — a gated
 * WebSocket factory, without knowing which mode produced them.
 *
 * # Why there is no partial mode
 *
 * A daemon that verified HTTP but streamed over an unverified WebSocket would
 * be worse than one that did neither, because its logs and its operator would
 * both say "verified". So when RA-TLS is selected and the WebSocket cannot be
 * gated, construction fails rather than returning a half-protected transport.
 *
 * # What this does not do
 *
 * It does not re-verify on a timer. A CVM restart rotates the boot-random key,
 * which `isStale()` surfaces; reacting to that — pausing placement, rebuilding
 * the transport — is the daemon's lifecycle concern, not this module's.
 */

import {
  createVerifiedTransport,
  type VerifiedTransport,
} from "@darknyx/sdk/transport-node";
import type { NodeWebSocketLike } from "@darknyx/sdk/transport-node";

import type { DaemonConfig } from "./config.js";

export interface DaemonTransport {
  /** Use for every CVM request. */
  fetch: typeof fetch;
  /** Present only under `ra-tls`; the legacy path has nothing to gate. */
  webSocketFactory?: (url: string) => unknown;
  /** `true` when the enclave has restarted under us. */
  isStale(): boolean;
  mode: DaemonConfig["transportMode"];
}

export interface BuildTransportDeps {
  /** DCAP verification, event-log parsing and nonce generation. */
  verifierDeps: Parameters<typeof createVerifiedTransport>[0]["deps"];
  /** Opens the underlying `ws` socket. Required for `ra-tls`. */
  createWebSocket?: (url: string) => NodeWebSocketLike;
  /** Injected for tests. */
  fetchImpl?: typeof fetch;
}

function hexToBytes(hex: string, field: string): Uint8Array {
  const clean = hex.replace(/^0x/i, "");
  if (!/^[0-9a-fA-F]+$/.test(clean) || clean.length % 2 !== 0) {
    throw new Error(`${field} is not valid hex`);
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Build the daemon's transport from config.
 *
 * Throws rather than degrading. Every failure here is a misconfiguration the
 * operator can fix, and starting anyway would mean trading over a channel the
 * operator believes is verified.
 */
export async function buildDaemonTransport(
  cfg: DaemonConfig,
  deps: BuildTransportDeps,
): Promise<DaemonTransport> {
  if (cfg.transportMode === "gateway-terminated") {
    return {
      fetch: deps.fetchImpl ?? fetch,
      isStale: () => false,
      mode: "gateway-terminated",
    };
  }

  // `loadConfig` already refuses ra-tls without these, but this module is also
  // reachable from a hand-built config, so it re-checks rather than assuming.
  const composeHash = cfg.attestation?.composeHash;
  if (!composeHash) {
    throw new Error(
      "ra-tls transport requires a pinned compose hash (DARKNYX_DAEMON_EXPECT_COMPOSE_HASH)",
    );
  }
  if (!cfg.expectSignerSetSha256) {
    throw new Error(
      "ra-tls transport requires DARKNYX_DAEMON_EXPECT_SIGNER_SET_SHA256",
    );
  }
  if (!deps.createWebSocket) {
    // See the module note: half-protected is worse than unprotected, because
    // it reads as protected.
    throw new Error(
      "ra-tls transport requires a WebSocket constructor so the stream can be " +
        "gated; refusing to verify HTTP while leaving /v1/stream unverified",
    );
  }

  const signerSet = hexToBytes(
    cfg.expectSignerSetSha256,
    "DARKNYX_DAEMON_EXPECT_SIGNER_SET_SHA256",
  );
  if (signerSet.length !== 32) {
    throw new Error(
      "DARKNYX_DAEMON_EXPECT_SIGNER_SET_SHA256 must be 32 bytes of hex",
    );
  }

  const transport: VerifiedTransport = await createVerifiedTransport({
    baseUrl: cfg.gatewayUrl,
    deps: deps.verifierDeps,
    expectedComposeHash: composeHash,
    expectedSignerSetSha256: signerSet,
    ...(cfg.attestation?.mrtd ? { expectedMrtd: cfg.attestation.mrtd } : {}),
    createWebSocket: deps.createWebSocket,
    ...(deps.fetchImpl ? { fetchImpl: deps.fetchImpl } : {}),
  });

  if (!transport.webSocketFactory) {
    // Defensive: the factory only omits it when no constructor was supplied,
    // which we checked above. Reaching here means that contract changed.
    throw new Error(
      "verified transport returned no WebSocket factory; refusing to run with " +
        "an ungated stream",
    );
  }

  return {
    fetch: transport.fetch,
    webSocketFactory: transport.webSocketFactory,
    isStale: () => transport.isStale(),
    mode: "ra-tls",
  };
}
