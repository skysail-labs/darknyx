/**
 * The one entry point a Node consumer should use (T-03P, Phase 2d).
 *
 * `TransportAgent`, `verifyTransportOnSocket`, `createVerifiedFetch` and
 * `createVerifiedWebSocketFactory` are each individually correct and each
 * individually easy to wire up wrongly. The failure mode is not exotic: build
 * the agent, forget to gate the WebSocket, and the stream carries a bearer
 * token over an unverified connection while the HTTP path looks fine.
 *
 * So consumers get one call that returns both transports already bound to the
 * same verified socket identity, and the pieces stay exported for tests rather
 * than for assembly.
 *
 * ```ts
 * const transport = await createVerifiedTransport({
 *   baseUrl, deps, expectedComposeHash, expectedSignerSetSha256,
 * });
 * // every request and every stream frame is now gated
 * await transport.fetch("/orders", { method: "POST", body });
 * subscribeFills({ webSocketFactory: transport.webSocketFactory, ... });
 * ```
 *
 * # What it does not do
 *
 * It does not re-attest on a schedule. The boot session is pinned at
 * construction, so a CVM restart invalidates this transport and the consumer
 * must build a new one — `isStale()` reports that condition rather than
 * silently reconnecting to a different boot.
 */

import {
  TransportAgent,
  createVerifiedFetch,
  verifyTransportOnSocket,
  type TransportVerifierDeps,
} from "./transport-agent.node.js";
import {
  createVerifiedWebSocketFactory,
  type NodeWebSocketLike,
} from "./transport-ws.node.js";
import { TransportVerificationError } from "./verify-transport.js";
import type { SendableWebSocketFactory } from "../orders/trading-ws-client.js";

export interface CreateVerifiedTransportOptions {
  /** HTTPS base URL of the enclave, via the dstack passthrough route. */
  baseUrl: string;
  deps: TransportVerifierDeps;
  /** Governed compose hash. Required — strict mode is not optional here. */
  expectedComposeHash: string;
  /** SHA-256 over the on-chain `VaultConfig.tee_pubkeys`, in shard order. */
  expectedSignerSetSha256: Uint8Array;
  expectedMrtd?: string;
  /** Opens the underlying `ws` socket. Supplied by the consumer so the SDK
   *  carries no dependency on a particular WebSocket implementation. */
  createWebSocket?: (url: string) => NodeWebSocketLike;
  /** Injected for tests. */
  fetchImpl?: typeof fetch;
}

export interface VerifiedTransport {
  /** A `fetch` that will not send until its socket is verified. */
  fetch: typeof fetch;
  /**
   * A WebSocket factory whose sends are queued until the upgrade socket
   * presents the attested certificate. Absent when no `createWebSocket` was
   * supplied — deliberately absent rather than an unverified fallback.
   */
  webSocketFactory?: SendableWebSocketFactory;
  /** The agent, for consumers that must pass it to another HTTP client. */
  agent: TransportAgent;
  /** SPKI hash verified for this boot. */
  verifiedSpkiSha256: Uint8Array;
  /** Boot session this transport was verified against. */
  bootSessionId: Uint8Array;
  /**
   * True once the enclave's live socket no longer presents the verified
   * certificate — which means a restart. The consumer must build a new
   * transport; reconnecting through this one would be reconnecting to a
   * different boot than the one it verified.
   */
  isStale(): boolean;
}

/**
 * Verify the transport once, then hand back HTTP and WebSocket transports that
 * are both bound to the socket identity that verification established.
 */
export async function createVerifiedTransport(
  opts: CreateVerifiedTransportOptions,
): Promise<VerifiedTransport> {
  const agent = new TransportAgent();

  const verifyOpts = {
    baseUrl: opts.baseUrl,
    agent,
    deps: opts.deps,
    expectedComposeHash: opts.expectedComposeHash,
    expectedSignerSetSha256: opts.expectedSignerSetSha256,
    ...(opts.expectedMrtd ? { expectedMrtd: opts.expectedMrtd } : {}),
    ...(opts.fetchImpl ? { fetchImpl: opts.fetchImpl } : {}),
  };

  // The verifier returns what it verified, so there is exactly one source of
  // truth for the SPKI and the boot session.
  const { manifest, spkiSha256: verifiedSpkiSha256 } =
    await verifyTransportOnSocket(verifyOpts);
  const bootSessionId = manifest.bootSessionId;

  // Reconnects are pinned to the boot session established HERE.
  //
  // `createVerifiedFetch` re-verifies whenever it gets a replacement socket.
  // Without this pin that re-verification only checks compose hash and signer
  // set — both of which survive a restart — so a RESTARTED enclave would pass
  // and start receiving this session's private request bytes. The transport is
  // supposed to bind one boot, and `verify-transport` already implements the
  // check; it was simply never given the expected value.
  //
  // Deliberately a separate object from `verifyOpts`: the FIRST verification
  // cannot pin a boot session it has not learned yet, so only the reconnect
  // path carries it.
  const reconnectOpts = { ...verifyOpts, expectedBootSessionId: bootSessionId };
  const fetchImpl = createVerifiedFetch(reconnectOpts);

  const webSocketFactory = opts.createWebSocket
    ? createVerifiedWebSocketFactory({
        verifiedSpkiSha256,
        createSocket: opts.createWebSocket,
      })
    : undefined;

  return {
    fetch: fetchImpl,
    ...(webSocketFactory ? { webSocketFactory } : {}),
    agent,
    verifiedSpkiSha256,
    bootSessionId,
    isStale(): boolean {
      const live = agent.currentSocket();
      if (!live) return false; // no connection right now says nothing
      try {
        const observed = agent.spkiFor(live);
        return !equalBytes(observed, verifiedSpkiSha256);
      } catch {
        // A socket we cannot read is not a socket we should trust.
        return true;
      }
    },
  };
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

export { TransportVerificationError };
