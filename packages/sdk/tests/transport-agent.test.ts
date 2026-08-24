/**
 * Node actual-socket transport adapter (T-03P).
 *
 * Two kinds of test here:
 *
 * 1. **Real TLS.** `socketSpkiSha256` must return the SPKI of the certificate
 *    a peer actually presented. That is the value the entire contract turns
 *    on, so it is tested against a live handshake rather than a stub. Skipped
 *    if `openssl` is unavailable — and the skip is loud, because a silently
 *    skipped test of the load-bearing function is worse than no test.
 *
 * 2. **The state machine**, with stub sockets. Bootstrap verification attaches
 *    to one socket; only the connector may adopt a replacement after matching
 *    the quote-bound SPKI. Arbitrary socket identity is never trusted.
 */

import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { createServer, type Server } from "node:https";
import { connect, type TLSSocket } from "node:tls";
import { readFileSync } from "node:fs";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  LIMITS,
  TransportAgent,
  createVerifiedFetch,
  verifyTransportOnSocket,
  parseObservedManifest,
  socketSpkiSha256,
} from "../src/tee/transport-agent.node.js";
import { TransportMode } from "../src/tee/transport-manifest.js";
import { TransportVerificationError } from "../src/tee/verify-transport.js";

const hex = (b: Uint8Array) =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

function opensslAvailable(): boolean {
  try {
    execFileSync("openssl", ["version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

const HAS_OPENSSL = opensslAvailable();
let connectionCount = 0;

describe("socketSpkiSha256 — against a real TLS handshake", () => {
  let dir: string;
  let server: Server;
  let port: number;
  let expectedSpki: string;

  beforeAll(async () => {
    if (!HAS_OPENSSL) return;
    dir = mkdtempSync(join(tmpdir(), "darknyx-tls-"));
    const key = join(dir, "key.pem");
    const cert = join(dir, "cert.pem");
    execFileSync("openssl", [
      "req", "-x509", "-newkey", "ec",
      "-pkeyopt", "ec_paramgen_curve:prime256v1",
      "-keyout", key, "-out", cert,
      "-days", "1", "-nodes", "-subj", "/CN=localhost",
    ], { stdio: "ignore" });

    // The SPKI we EXPECT, derived independently from the certificate file —
    // not from the socket. If the socket path agreed with itself but not with
    // the file, this would still catch it.
    const spkiDer = execFileSync("openssl", ["x509", "-in", cert, "-pubkey", "-noout"]);
    const der = execFileSync("openssl", ["pkey", "-pubin", "-outform", "DER"], {
      input: spkiDer,
    });
    expectedSpki = createHash("sha256").update(der).digest("hex");

    server = createServer(
      { key: readFileSync(key), cert: readFileSync(cert) },
      (_req, res) => res.end("ok"),
    );
    // Counted so the single-connection property can be asserted behaviourally;
    // undici's Agent does not expose its options.
    server.on("secureConnection", () => {
      connectionCount += 1;
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    port = (server.address() as { port: number }).port;
  });

  afterAll(() => {
    server?.close();
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it.skipIf(!HAS_OPENSSL)(
    "returns the SPKI of the certificate the peer actually presented",
    async () => {
      const socket: TLSSocket = await new Promise((resolve, reject) => {
        const s = connect(
          { port, host: "127.0.0.1", rejectUnauthorized: false },
          () => resolve(s),
        );
        s.once("error", reject);
      });
      try {
        expect(hex(socketSpkiSha256(socket))).toBe(expectedSpki);
      } finally {
        socket.destroy();
      }
    },
  );

  it("openssl is available in this environment", () => {
    // A loud marker rather than a silent skip. If this fails, the test above
    // did not run and the load-bearing function is unverified here.
    expect(HAS_OPENSSL).toBe(true);
  });
  it.skipIf(!HAS_OPENSSL)(
    "uses a single connection so the attestation and the request share a socket",
    async () => {
      // With a pool, the exchange that was verified and the request that
      // follows can land on different connections — the probe-vs-request gap
      // this adapter exists to close. undici expresses that as
      // `connections: 1`, and does not expose its options for inspection.
      //
      // So assert it where it is observable: at the SERVER. Four concurrent
      // requests through one agent must produce exactly one TLS connection.
      // The previous version of this test asserted only that the agent was an
      // instance of its own class and that `currentSocket` was a function —
      // neither of which constrains `connections` at all, so raising it to 8
      // would have left this green.
      const agent = new TransportAgent();
      connectionCount = 0;
      const { fetch: uf } = await import("undici");
      await Promise.all(
        Array.from({ length: 4 }, () =>
          uf(`https://127.0.0.1:${port}/`, { dispatcher: agent } as never).then(
            (r) => r.text(),
          ),
        ),
      );
      expect(
        connectionCount,
        "the agent opened more than one connection; attestation and request " +
          "can no longer be assumed to share a socket",
      ).toBe(1);
      await agent.close();
    },
  );
});

describe("TransportAgent — verification attaches to one socket", () => {
  // Object identity is the whole property; stubs express it exactly.
  const stubSocket = () => ({}) as unknown as TLSSocket;

  it("treats an unknown socket as unverified", () => {
    const agent = new TransportAgent();
    expect(agent.isVerified(stubSocket())).toBe(false);
  });

  it("treats undefined as unverified rather than throwing", () => {
    const agent = new TransportAgent();
    expect(agent.isVerified(undefined)).toBe(false);
  });

  it("does not let one socket's verification cover another", () => {
    // THE property. If verification were tracked per-agent or per-host instead
    // of per-socket, a reconnect would silently inherit trust from a
    // connection that no longer exists.
    const agent = new TransportAgent();
    const a = stubSocket();
    const b = stubSocket();
    agent.markVerified(a);
    expect(agent.isVerified(a)).toBe(true);
    expect(agent.isVerified(b)).toBe(false);
  });

  it("throws rather than guessing when no SPKI was recorded", () => {
    // Failing closed matters here: a socket whose certificate could not be
    // read must never reach the comparison with a fabricated value.
    const agent = new TransportAgent();
    expect(() => agent.spkiFor(stubSocket())).toThrow(
      TransportVerificationError,
    );
  });



  it("takes no caller options that could widen the pool", () => {
    // The constructor deliberately accepts nothing: a caller must not be able
    // to reintroduce a connection pool.
    expect(TransportAgent.length).toBe(0);
  });
});

describe("parseObservedManifest", () => {
  const wire = (over: Record<string, unknown> = {}) => ({
    manifest: {
      protocol_version: 1,
      transport_mode: "ra-tls",
      app_id_sha256: "aa".repeat(32),
      instance_id_sha256: "bb".repeat(32),
      boot_session_id: "cc".repeat(32),
      tls_spki_sha256: "dd".repeat(32),
      signer_set_sha256: "ee".repeat(32),
      ...over,
    },
    quote: "",
    event_log: "[]",
    report_data: "",
    domain: "darknyx/transport-attestation/v1",
  });

  it("maps the wire shape onto the verifier's input", () => {
    const m = parseObservedManifest(wire());
    expect(m.protocolVersion).toBe(1);
    expect(m.transportMode).toBe(TransportMode.RaTls);
    expect(hex(m.tlsSpkiSha256)).toBe("dd".repeat(32));
    expect(hex(m.signerSetSha256)).toBe("ee".repeat(32));
  });

  it("maps the legacy mode without accepting it", () => {
    // Parsing must preserve the value so the VERIFIER can reject it with the
    // right reason. Silently coercing it to ra-tls here would defeat that.
    const m = parseObservedManifest(wire({ transport_mode: "gateway-terminated" }));
    expect(m.transportMode).toBe(TransportMode.GatewayTerminated);
  });

  it("rejects an unknown transport mode rather than defaulting", () => {
    expect(() => parseObservedManifest(wire({ transport_mode: "plaintext" }))).toThrow(
      TransportVerificationError,
    );
  });

  it.each([
    "app_id_sha256",
    "instance_id_sha256",
    "boot_session_id",
    "tls_spki_sha256",
    "signer_set_sha256",
  ])("rejects non-hex in %s", (field) => {
    expect(() => parseObservedManifest(wire({ [field]: "zz".repeat(32) }))).toThrow(
      TransportVerificationError,
    );
  });

  it("rejects odd-length hex rather than truncating", () => {
    expect(() => parseObservedManifest(wire({ tls_spki_sha256: "abc" }))).toThrow(
      TransportVerificationError,
    );
  });
});

describe("LIMITS", () => {
  it("bounds time, body size, and event-log entries before parsing", () => {
    // These exist so an unauthenticated peer cannot make a client do unbounded
    // work. Pinned so a future edit cannot quietly relax them.
    expect(LIMITS.totalMs).toBeLessThanOrEqual(30_000);
    expect(LIMITS.bodyBytes).toBeLessThanOrEqual(1024 * 1024);
    expect(LIMITS.eventLogEntries).toBeLessThanOrEqual(1024);
  });
});

describe("browser safety", () => {
  it("the Node adapter is not reachable from the package index", async () => {
    // The adapter imports node:https / node:tls / node:crypto. If it were
    // re-exported from the index, every browser consumer of @darknyx/sdk would
    // pull it into their bundle graph. The `.node.ts` suffix is a convention;
    // this test is the enforcement.
    const index = await import("../src/index.js");
    expect(Object.keys(index)).not.toContain("TransportAgent");
    expect(Object.keys(index)).not.toContain("socketSpkiSha256");
    expect(Object.keys(index)).not.toContain("createVerifiedFetch");
  });

  it("the environment-neutral verifier IS exported", () => {
    // The counterpart: browser code must still be able to verify a transport
    // attestation, it just supplies the observed SPKI by other means.
    return import("../src/index.js").then((index) => {
      expect(Object.keys(index)).toContain("verifyTransportAttestation");
    });
  });
});

describe("verifyTransportOnSocket — returns what it verified", () => {
  it("exposes the verified manifest rather than publishing it elsewhere", async () => {
    // A regression guard for a design smell caught in 2d: the boot session was
    // briefly smuggled from the verifier to its caller through mutable module
    // state. Two sources of truth for "what did we verify" is how they drift.
    const mod = await import("../src/tee/transport-agent.node.js");
    expect(Object.keys(mod)).not.toContain("_recordVerifiedBootSession");
    expect(Object.keys(mod)).not.toContain("lastVerifiedBootSession");
  });
});

describe("browser safety — the WebSocket gate", () => {
  it("the verified WS factory is not reachable from the package index", async () => {
    // Same rule as the HTTP adapter: it imports node:crypto and node:tls types
    // and must not enter a browser bundle graph.
    const index = await import("../src/index.js");
    expect(Object.keys(index)).not.toContain("createVerifiedWebSocketFactory");
    expect(Object.keys(index)).not.toContain("upgradeSocketSpki");
  });
});

describe("createVerifiedFetch is pinned to the origin it verified", () => {
  // The transport's attestation says something about ONE peer. Forwarding an
  // arbitrary absolute URL would send the request to a host the quote says
  // nothing about, while the consumer's logs still read "verified".
  const opts = () => ({
    baseUrl: "https://cvm.example",
    agent: new TransportAgent(),
    deps: {} as never,
    expectedComposeHash: "aa".repeat(32),
    expectedSignerSetSha256: new Uint8Array(32).fill(1),
    // Must never be reached for a cross-origin target.
    fetchImpl: (() => {
      throw new Error("fetch must not be called for a rejected origin");
    }) as unknown as typeof fetch,
  });

  it("refuses an absolute URL for a different host", async () => {
    const f = createVerifiedFetch(opts());
    await expect(f("https://evil.example/orders")).rejects.toThrow(
      /refusing to send to https:\/\/evil\.example/,
    );
  });

  it("refuses a different port on the same host", async () => {
    // Origin includes the port: :8080 is not the peer that :443 attested.
    const f = createVerifiedFetch(opts());
    await expect(f("https://cvm.example:8080/orders")).rejects.toThrow(
      /refusing to send/,
    );
  });

  it("refuses a downgrade to http", async () => {
    const f = createVerifiedFetch(opts());
    await expect(f("http://cvm.example/orders")).rejects.toThrow(
      /refusing to send/,
    );
  });

  it("rejects before attempting any verification or network call", async () => {
    // The check must be cheap and first: a cross-origin call should never
    // trigger a verification exchange against the legitimate peer.
    const agent = new TransportAgent();
    const f = createVerifiedFetch({ ...opts(), agent });
    await expect(f("https://evil.example/")).rejects.toThrow();
    expect(agent.currentSocket()).toBeUndefined();
  });
});

describe("verifyTransportOnSocket retries a lost socket, never a verdict", () => {
  // `connections: 1` means a consumer that polls for a while can have its one
  // pooled connection closed by an idle timeout or a peer close. That is
  // ordinary churn, and it failed `cvm-self-trade` in CI after ~57 s of
  // polling. The retry exists for exactly that, and must not extend to a
  // refusal about the peer.
  const baseOpts = {
    baseUrl: "https://enclave.example",
    expectedComposeHash: "aa".repeat(32),
    expectedSignerSetSha256: new Uint8Array(32).fill(1),
    // `randomNonce` is consumed before the fetch, so it must be real even
    // though this suite never reaches quote verification.
    deps: {
      randomNonce: () => new Uint8Array(32).fill(9),
      verifyQuote: async () => {
        throw new Error("unreachable: the fetch fails first");
      },
      parseEventLog: () => [],
    } as never,
  };

  /** A fetch that fails with a chosen TransportVerificationError kind. */
  const failingFetch = (kind: string, count: { n: number }) =>
    (async () => {
      count.n += 1;
      const e = new TransportVerificationError(`synthetic ${kind}`, kind as never);
      throw e;
    }) as unknown as typeof fetch;

  it("does NOT retry a spki_mismatch — that is a relay, not churn", async () => {
    const count = { n: 0 };
    await expect(
      verifyTransportOnSocket({
        ...baseOpts,
        agent: new TransportAgent(),
        fetchImpl: failingFetch("spki_mismatch", count),
      } as never),
    ).rejects.toMatchObject({ kind: "spki_mismatch" });
    expect(count.n, "a verdict was retried").toBe(1);
  });

  it("does NOT retry a compose_mismatch — that is the wrong enclave", async () => {
    const count = { n: 0 };
    await expect(
      verifyTransportOnSocket({
        ...baseOpts,
        agent: new TransportAgent(),
        fetchImpl: failingFetch("compose_mismatch", count),
      } as never),
    ).rejects.toMatchObject({ kind: "compose_mismatch" });
    expect(count.n).toBe(1);
  });

  it("retries socket_lost, then gives up with that kind", async () => {
    // Bounded: it must not spin forever on a peer that keeps dropping.
    const count = { n: 0 };
    await expect(
      verifyTransportOnSocket({
        ...baseOpts,
        agent: new TransportAgent(),
        fetchImpl: failingFetch("socket_lost", count),
      } as never),
    ).rejects.toMatchObject({ kind: "socket_lost" });
    expect(count.n, "socket_lost should be retried a bounded number of times").toBe(3);
  });

  it("classifies a raw fetch outage as retryable socket loss", async () => {
    const count = { n: 0 };
    const fetchImpl = (async () => {
      count.n += 1;
      throw new TypeError("fetch failed");
    }) as unknown as typeof fetch;
    await expect(
      verifyTransportOnSocket({
        ...baseOpts,
        agent: new TransportAgent(),
        fetchImpl,
      } as never),
    ).rejects.toMatchObject({ kind: "socket_lost" });
    expect(count.n).toBe(3);
  });

  it("classifies a rolling-restart 503 as retryable socket loss", async () => {
    const count = { n: 0 };
    const fetchImpl = (async () => {
      count.n += 1;
      return new Response("unavailable", { status: 503 });
    }) as unknown as typeof fetch;
    await expect(
      verifyTransportOnSocket({
        ...baseOpts,
        agent: new TransportAgent(),
        fetchImpl,
      } as never),
    ).rejects.toMatchObject({ kind: "socket_lost" });
    expect(count.n).toBe(3);
  });

  it("does not retry a definitive non-OK attestation status", async () => {
    const count = { n: 0 };
    const fetchImpl = (async () => {
      count.n += 1;
      return new Response("forbidden", { status: 403 });
    }) as unknown as typeof fetch;
    await expect(
      verifyTransportOnSocket({
        ...baseOpts,
        agent: new TransportAgent(),
        fetchImpl,
      } as never),
    ).rejects.toMatchObject({ kind: "malformed" });
    expect(count.n).toBe(1);
  });

  it("does not retry a syntactically malformed attestation response", async () => {
    const count = { n: 0 };
    const fetchImpl = (async () => {
      count.n += 1;
      return new Response("not-json", { status: 200 });
    }) as unknown as typeof fetch;
    await expect(
      verifyTransportOnSocket({
        ...baseOpts,
        agent: new TransportAgent(),
        fetchImpl,
      } as never),
    ).rejects.toMatchObject({ kind: "malformed" });
    expect(count.n).toBe(1);
  });
});
