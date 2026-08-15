/**
 * Node actual-socket transport adapter (T-03P, Phase 2b).
 *
 * Two kinds of test here:
 *
 * 1. **Real TLS.** `socketSpkiSha256` must return the SPKI of the certificate
 *    a peer actually presented. That is the value the entire contract turns
 *    on, so it is tested against a live handshake rather than a stub. Skipped
 *    if `openssl` is unavailable — and the skip is loud, because a silently
 *    skipped test of the load-bearing function is worse than no test.
 *
 * 2. **The state machine**, with stub sockets. Verification must attach to a
 *    specific socket and never be inherited by a different one. That property
 *    is about object identity, not TLS, so stubs test it precisely.
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

  it("pins maxSockets to 1 so the attestation and the request share a socket", () => {
    // With a pool, the exchange that was verified and the request that follows
    // can land on different connections — the probe-vs-request gap this
    // adapter exists to close.
    const agent = new TransportAgent();
    expect(agent.maxSockets).toBe(1);
    expect(agent.options.keepAlive).toBe(true);
  });

  it("cannot be constructed with a larger pool", () => {
    // Caller-supplied options must not be able to widen it.
    const agent = new TransportAgent({ maxSockets: 64 } as never);
    expect(agent.maxSockets).toBe(1);
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
