/**
 * Node actual-socket transport adapter (T-03P, Phase 2b).
 *
 * # The problem this solves, and the wrong way to solve it
 *
 * The verification core (`verify-transport.ts`) needs the SPKI of the
 * certificate on **the connection carrying the request**. The obvious
 * implementation — open a `tls.connect()`, read the certificate, verify, then
 * make ordinary `fetch()` calls — is worthless. DNS changes, load balancing, a
 * relay, or simple connection churn can make the probe and the request reach
 * different peers. You would have verified something you then stopped using.
 *
 * This adapter closes that by making the socket itself the unit of trust:
 *
 * 1. A custom `https.Agent` records each TLS socket's SPKI at connect time.
 * 2. A socket starts **unverified**. Nothing sensitive may cross it.
 * 3. The first exchange on a new socket is the transport attestation, fetched
 *    *over that socket*, and verified against *that socket's* recorded SPKI.
 * 4. Only then is the socket marked verified.
 * 5. A new socket — reconnect, pool growth, keep-alive expiry — starts at
 *    step 2 again. Verification is never inherited.
 *
 * # Why `maxSockets: 1`
 *
 * With a pool, the attestation exchange and a subsequent request can land on
 * different sockets, which reintroduces exactly the probe-vs-request gap. One
 * socket per host makes "the socket that answered" and "the socket I am about
 * to use" the same object by construction. The cost is request concurrency on
 * a single connection, which HTTP/1.1 keep-alive already serialises.
 *
 * # Browser safety
 *
 * This module imports `node:https`, `node:tls`, and `node:crypto`. It is
 * deliberately a separate file with a `.node.ts` suffix and is **not** exported
 * from the package index — importing it from browser code is a build error, not
 * a runtime surprise. The verification core it calls is environment-neutral.
 */

import type { TLSSocket } from "node:tls";
import { createHash } from "node:crypto";
import { Agent, buildConnector, fetch as undiciFetch } from "undici";

import {
  verifyTransportAttestation,
  TransportVerificationError,
  type ObservedManifest,
  type TransportFailure,
} from "./verify-transport.js";
import type { EventLogEntry, VerifiedQuoteReport } from "./verify-core.js";
import { TransportMode } from "./transport-manifest.js";

/** Hard caps applied before any expensive parsing. */
export const LIMITS = {
  /** Whole-verification budget, including the attestation round trip. */
  totalMs: 15_000,
  /** Maximum `/transport-attestation` response body. */
  bodyBytes: 512 * 1024,
  /** Maximum event-log entries to replay. */
  eventLogEntries: 512,
} as const;

function sha256Der(der: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(der).digest());
}

function hexToBytes(hex: string, field: string): Uint8Array {
  if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) {
    throw new TransportVerificationError(
      `${field} is not valid hex`,
      "malformed",
    );
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Extract the DER SubjectPublicKeyInfo from a live TLS socket's peer
 * certificate. This is the value the whole contract turns on — it comes from
 * the socket, never from a response body.
 */
export function socketSpkiSha256(socket: TLSSocket): Uint8Array {
  const cert = socket.getPeerX509Certificate?.();
  if (!cert) {
    throw new TransportVerificationError(
      "peer presented no certificate",
      "malformed",
    );
  }
  const der = cert.publicKey.export({ type: "spki", format: "der" });
  return sha256Der(new Uint8Array(der));
}

/**
 * An `https.Agent` that records the SPKI of every TLS socket it opens and
 * tracks which sockets have completed transport verification.
 */
export class TransportAgent extends Agent {
  /** SPKI hash per live socket. */
  private readonly spki = new WeakMap<object, Uint8Array>();
  /** Sockets that have passed verification. Never inherited across sockets. */
  private readonly verified = new WeakSet<object>();
  /** The socket most recently established, for the single-connection pool. */
  private current?: TLSSocket;

  constructor() {
    // `connect` is the hook that makes this whole adapter work.
    //
    // An earlier revision passed an `https.Agent` to global `fetch` and read
    // the socket off it. That silently did nothing: Node's global fetch is
    // undici, which ignores the `agent` option entirely (it takes a
    // `dispatcher`). The agent never saw a socket, so the SPKI comparison ran
    // against a value that was never captured — the check was inert. Hence
    // undici directly, with our own connector.
    const base = buildConnector({
      // The certificate is self-signed by design; WebPKI validation is
      // meaningless here and its absence is NOT the security model. The SPKI
      // comparison against a quote-bound manifest is.
      rejectUnauthorized: false,
    });
    super({
      // One connection: with a pool, the attestation exchange and the request
      // that follows can land on different sockets, which is the gap this
      // exists to close.
      connections: 1,
      pipelining: 1,
      connect: (opts, callback) => {
        base(opts, (err, socket) => {
          if (!err && socket) {
            const tls = socket as unknown as TLSSocket;
            try {
              this.spki.set(tls, socketSpkiSha256(tls));
              this.current = tls;
              tls.once("close", () => {
                if (this.current === tls) this.current = undefined;
              });
            } catch {
              // Leave it unrecorded: `spkiFor` throws, so the socket can never
              // be marked verified. Failing closed beats guessing.
            }
          }
          callback(err as Error | null, socket as never);
        });
      },
    });
  }

  /** The SPKI recorded for a socket, or throw if none was captured. */
  spkiFor(socket: object): Uint8Array {
    const s = this.spki.get(socket);
    if (!s) {
      throw new TransportVerificationError(
        "no SPKI was recorded for this socket",
        "malformed",
      );
    }
    return s;
  }

  isVerified(socket: object | undefined): boolean {
    return socket !== undefined && this.verified.has(socket);
  }

  markVerified(socket: object): void {
    this.verified.add(socket);
  }

  /** The socket the next request will use, if one is live. */
  currentSocket(): TLSSocket | undefined {
    return this.current;
  }

  /**
   * Drop a socket immediately. Called on any verification failure so a
   * connection that failed a check cannot carry a later request.
   */
  destroySocket(socket: TLSSocket): void {
    try {
      socket.destroy();
    } catch {
      /* already gone */
    }
    if (this.current === socket) this.current = undefined;
  }
}

/** The wire shape of `GET /transport-attestation`. */
interface TransportAttestationBody {
  manifest: {
    protocol_version: number;
    transport_mode: string;
    app_id_sha256: string;
    instance_id_sha256: string;
    boot_session_id: string;
    tls_spki_sha256: string;
    signer_set_sha256: string;
  };
  quote: string;
  event_log: string;
  report_data: string;
  domain: string;
}

/** Parse the served manifest into the verifier's input shape. */
export function parseObservedManifest(
  body: TransportAttestationBody,
): ObservedManifest {
  const m = body.manifest;
  const mode =
    m.transport_mode === "ra-tls"
      ? TransportMode.RaTls
      : m.transport_mode === "gateway-terminated"
        ? TransportMode.GatewayTerminated
        : undefined;
  if (mode === undefined) {
    throw new TransportVerificationError(
      `unknown transport_mode ${JSON.stringify(m.transport_mode)}`,
      "malformed",
    );
  }
  return {
    protocolVersion: m.protocol_version,
    transportMode: mode,
    appIdSha256: hexToBytes(m.app_id_sha256, "app_id_sha256"),
    instanceIdSha256: hexToBytes(m.instance_id_sha256, "instance_id_sha256"),
    bootSessionId: hexToBytes(m.boot_session_id, "boot_session_id"),
    tlsSpkiSha256: hexToBytes(m.tls_spki_sha256, "tls_spki_sha256"),
    signerSetSha256: hexToBytes(m.signer_set_sha256, "signer_set_sha256"),
  };
}

export interface TransportVerifierDeps {
  /**
   * DCAP-verify a hex quote and return the report. Injected so this module
   * carries no dependency on a particular `dcap-qvl` binding, and so tests can
   * exercise the socket logic without real TDX hardware.
   */
  verifyQuote(quoteHex: string): Promise<VerifiedQuoteReport>;
  /** Parse the dstack event-log JSON string. */
  parseEventLog(json: string): EventLogEntry[];
  /** 32 random bytes. */
  randomNonce(): Uint8Array;
}

export interface VerifiedTransportOptions {
  /** Base URL, e.g. `https://<app-id>-8443s.dstack-pha-prod9.phala.network`. */
  baseUrl: string;
  agent: TransportAgent;
  deps: TransportVerifierDeps;
  expectedComposeHash: string;
  expectedSignerSetSha256: Uint8Array;
  expectedBootSessionId?: Uint8Array;
  expectedMrtd?: string;
  /** Injected for tests. Defaults to global fetch. */
  fetchImpl?: typeof fetch;
}

function fail(kind: TransportFailure, detail: string): never {
  // Typed reason, no credential and no untrusted response body echoed back.
  throw new TransportVerificationError(
    `transport verification failed (${kind}): ${detail}`,
    kind,
  );
}

/** What a successful verification established. */
export interface VerifiedSocket {
  socket: TLSSocket;
  /**
   * The manifest the quote committed to. Returned rather than published
   * through module state so a caller can read the verified boot session
   * without a second source of truth.
   */
  manifest: ObservedManifest;
  /** SPKI of the certificate on `socket`, as attested. */
  spkiSha256: Uint8Array;
}

/**
 * Verify the socket that will carry subsequent requests.
 *
 * Returns the verified socket and what the quote committed to. Throws
 * {@link TransportVerificationError} and destroys the connection on any
 * failure, so a caller that catches and retries cannot end up reusing a socket
 * that failed a check.
 */
export async function verifyTransportOnSocket(
  opts: VerifiedTransportOptions,
): Promise<VerifiedSocket> {
  const { agent, deps } = opts;
  // undici's fetch, not the global one — the dispatcher below is only honoured
  // by undici, and the global may be a different implementation entirely.
  const fetchImpl = opts.fetchImpl ?? (undiciFetch as unknown as typeof fetch);
  const nonce = deps.randomNonce();
  if (nonce.length !== 32) fail("malformed", "nonce generator returned non-32 bytes");
  const nonceHex = Array.from(nonce, (b) => b.toString(16).padStart(2, "0")).join(
    "",
  );

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), LIMITS.totalMs);
  let body: TransportAttestationBody;
  let socket: TLSSocket;
  try {
    const res = await fetchImpl(
      `${opts.baseUrl.replace(/\/$/, "")}/transport-attestation?nonce=${nonceHex}`,
      {
        // A redirect could move this exchange to another origin or another
        // socket, which is precisely what must not happen.
        redirect: "error",
        signal: controller.signal,
        dispatcher: agent,
      } as never,
    );
    if (!res.ok) fail("malformed", `attestation endpoint returned ${res.status}`);

    const declared = res.headers.get("content-length");
    if (declared !== null && Number(declared) > LIMITS.bodyBytes) {
      fail("malformed", "attestation response exceeds the size limit");
    }
    const text = await res.text();
    if (text.length > LIMITS.bodyBytes) {
      fail("malformed", "attestation response exceeds the size limit");
    }
    body = JSON.parse(text) as TransportAttestationBody;

    // The most recently CONNECTED socket — which is the serving socket here
    // only because this agent is pinned to `connections: 1, pipelining: 1`,
    // so at most one socket exists and requests do not overlap on it.
    //
    // Stated precisely because the previous comment claimed more than the
    // code provides ("the socket that served THIS response"): undici exposes
    // no per-response socket attribution, so the single-connection pin IS the
    // mechanism, not an optimisation. Raising `connections` above 1 would
    // silently invalidate this and must not be done.
    const live = agent.currentSocket();
    if (!live) fail("malformed", "no live socket carried the attestation");
    socket = live;
  } catch (e) {
    if (e instanceof TransportVerificationError) throw e;
    fail("malformed", "attestation exchange failed");
  } finally {
    clearTimeout(timer);
  }

  const observedSpkiSha256 = agent.spkiFor(socket);

  let report: VerifiedQuoteReport;
  let eventLog: EventLogEntry[];
  try {
    report = await deps.verifyQuote(body.quote);
    eventLog = deps.parseEventLog(body.event_log);
  } catch {
    agent.destroySocket(socket);
    fail("malformed", "quote or event log could not be parsed/verified");
  }
  if (eventLog.length > LIMITS.eventLogEntries) {
    agent.destroySocket(socket);
    fail("malformed", "event log exceeds the entry limit");
  }

  const observed = parseObservedManifest(body);
  const failure = verifyTransportAttestation({
    report,
    eventLog,
    nonce,
    manifest: observed,
    observedSpkiSha256,
    expectedComposeHash: opts.expectedComposeHash,
    expectedSignerSetSha256: opts.expectedSignerSetSha256,
    ...(opts.expectedBootSessionId
      ? { expectedBootSessionId: opts.expectedBootSessionId }
      : {}),
    ...(opts.expectedMrtd ? { expectedMrtd: opts.expectedMrtd } : {}),
    strict: true,
  });

  if (failure) {
    // Close immediately. A socket that failed a check must not be reachable by
    // a later request, and leaving it pooled is how that happens.
    agent.destroySocket(socket);
    fail(failure, "see the failure kind");
  }

  agent.markVerified(socket);
  return { socket, manifest: observed, spkiSha256: observedSpkiSha256 };
}

/**
 * A `fetch` that refuses to send anything until the socket carrying it has
 * passed transport verification, and re-verifies whenever a new socket appears.
 *
 * Use this for every request that carries a credential, order intent, or any
 * other private payload.
 */
export function createVerifiedFetch(
  opts: VerifiedTransportOptions,
): typeof fetch {
  const { agent } = opts;
  let inflight: Promise<VerifiedSocket> | undefined;

  const ensureVerified = async (): Promise<void> => {
    if (agent.isVerified(agent.currentSocket())) return;
    // Single-flight: concurrent callers must not each open a verification
    // exchange, and none may proceed until one succeeds.
    inflight ??= verifyTransportOnSocket(opts).finally(() => {
      inflight = undefined;
    });
    await inflight;
  };

  const verifiedOrigin = new URL(opts.baseUrl).origin;

  return async (input, init) => {
    // Refuse any origin other than the one that was verified.
    //
    // The returned function used to forward `input` unchanged, so a consumer
    // could hand it an absolute URL for a different host — through a bug, a
    // config value, or a server-supplied endpoint — and the request would
    // leave over a transport whose attestation says nothing about that peer,
    // while every log line still read "verified".
    const target = new URL(
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.href
          : (input as Request).url,
      opts.baseUrl,
    );
    if (target.origin !== verifiedOrigin) {
      throw new TransportVerificationError(
        `refusing to send to ${target.origin} on a transport verified for ${verifiedOrigin}`,
        "malformed",
      );
    }

    await ensureVerified();
    const fetchImpl = opts.fetchImpl ?? (undiciFetch as unknown as typeof fetch);
    return fetchImpl(input, {
      ...init,
      redirect: "error",
      dispatcher: agent,
    } as never);
  };
}
