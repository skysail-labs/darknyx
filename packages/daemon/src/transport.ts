/**
 * The daemon's transport selection (T-03P).
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
import { TransportVerificationError } from "@darknyx/sdk/transport-node";

import { assertTransportConfigCoherent, type DaemonConfig } from "./config.js";

export interface DaemonTransport {
  /** Use for every CVM request. */
  fetch: typeof fetch;
  /** Present only under `ra-tls`; the legacy path has nothing to gate. */
  webSocketFactory?: (url: string) => unknown;
  /** `true` when the enclave has restarted under us. */
  isStale(): boolean;
  mode: DaemonConfig["transportMode"];
  /** Quote-bound boot id for RA-TLS; absent on the legacy transport. */
  bootSessionId?: Uint8Array;
  /** Close every resource owned by this immutable generation. */
  close(): Promise<void>;
}

export interface BuildTransportDeps {
  /** DCAP verification, event-log parsing and nonce generation. */
  verifierDeps: Parameters<typeof createVerifiedTransport>[0]["deps"];
  /** Opens the underlying `ws` socket. Required for `ra-tls`. */
  createWebSocket?: (url: string) => NodeWebSocketLike;
  /** Injected for tests. */
  fetchImpl?: typeof fetch;
  /** Report a typed refusal to the lifecycle supervisor. */
  onTransportViolation?: (error: TransportVerificationError) => void;
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
  // This boundary is public to programmatic embedders, which may construct a
  // DaemonConfig without loadConfig(). Enforce the production policy here too
  // so the legacy early return cannot bypass it.
  assertTransportConfigCoherent(cfg);
  if (cfg.transportMode === "gateway-terminated") {
    return {
      fetch: deps.fetchImpl ?? fetch,
      isStale: () => false,
      mode: "gateway-terminated",
      close: async () => undefined,
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
    // Make a stream-transport refusal LOUD. Without this the daemon
    // reconnects into the same refusal indefinitely while reporting only a
    // generic "WebSocket transport error" — which is how a live failure
    // became undiagnosable after the fact. A rejected peer on the order
    // stream is the event this whole feature exists to detect, so it is
    // logged at error level with its kind.
    onTransportViolation: (err) => {
      console.error(
        `[daemon] STREAM TRANSPORT REJECTED (${err.kind}): ${err.message}. ` +
          "The /v1/stream peer failed its quote-bound certificate check; " +
          "orders are NOT being sent over this connection.",
      );
      deps.onTransportViolation?.(err);
    },
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
    bootSessionId: transport.bootSessionId,
    close: async () => transport.agent.close(),
  };
}

export type DaemonTransportFactory = () => Promise<DaemonTransport>;

/**
 * Stable HTTP/WS delegates over one atomically replaceable transport generation.
 * A candidate is completely built and verified before {@link commit}; callers
 * therefore observe either generation N or N+1, never a half-swapped pair.
 */
export class DaemonTransportSupervisor {
  private violationHandler: ((error: Error) => void) | null = null;
  private closed = false;

  constructor(
    private active: DaemonTransport,
    private readonly factory: DaemonTransportFactory,
  ) {}

  readonly fetch: typeof fetch = async (input, init) => {
    try {
      return await this.active.fetch(input, init);
    } catch (error) {
      const violation = findTransportViolation(error);
      if (violation) this.reportViolation(violation);
      throw error;
    }
  };

  readonly webSocketFactory = (url: string): unknown => {
    const factory = this.active.webSocketFactory;
    if (!factory) {
      throw new Error("active transport has no verified WebSocket factory");
    }
    return factory(url);
  };

  setViolationHandler(handler: (error: Error) => void): void {
    this.violationHandler = handler;
  }

  reportViolation(error: Error): void {
    if (!this.closed) this.violationHandler?.(error);
  }

  isStale(): boolean {
    return this.active.isStale();
  }

  verifiedBootSessionId(): Uint8Array | undefined {
    return this.active.bootSessionId;
  }

  buildCandidate(): Promise<DaemonTransport> {
    if (this.closed)
      return Promise.reject(new Error("transport supervisor is closed"));
    return this.factory();
  }

  async commit(candidate: DaemonTransport): Promise<void> {
    if (this.closed) {
      await candidate.close();
      throw new Error("transport supervisor is closed");
    }
    if (candidate.mode !== this.active.mode) {
      await candidate.close();
      throw new Error("transport recovery cannot change the configured mode");
    }
    const previous = this.active;
    this.active = candidate;
    try {
      await previous.close();
    } catch (error) {
      console.warn(
        `[daemon] previous transport generation did not close cleanly: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    this.violationHandler = null;
    await this.active.close();
  }
}

function findTransportViolation(
  error: unknown,
): TransportVerificationError | null {
  let current: unknown = error;
  for (let depth = 0; depth < 4; depth += 1) {
    if (current instanceof TransportVerificationError) return current;
    if (
      typeof current !== "object" ||
      current === null ||
      !("cause" in current)
    ) {
      return null;
    }
    current = (current as { cause?: unknown }).cause;
  }
  return null;
}
