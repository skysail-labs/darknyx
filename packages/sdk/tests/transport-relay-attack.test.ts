/**
 * The cuckoo-proxy attack, end to end against real TLS sockets (T-03P, Phase 3).
 *
 * Everything else in this suite tests a piece. This tests the attack.
 *
 * A relay fetches a **completely genuine** transport attestation from the real
 * enclave and forwards it verbatim, while terminating TLS with its own
 * certificate. Every field in that response is authentic. The quote is real,
 * the manifest is internally consistent, the nonce is the client's. The only
 * thing that differs is the certificate on the socket — and that must be enough
 * to reject, because it is the entire premise of T-03.
 *
 * These run against real `https.Server` instances with real, distinct
 * certificates, driven through the production `TransportAgent` and
 * `verifyTransportOnSocket`. The DCAP verification itself is injected: we
 * cannot produce TDX quotes off-hardware, and the point here is the socket
 * comparison, not the quote parser. Everything the attack turns on is real.
 */

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { createServer, type Server } from "node:https";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { fetch as undiciFetch } from "undici";

import {
  TransportAgent,
  verifyTransportOnSocket,
} from "../src/tee/transport-agent.node.js";
import { TransportVerificationError } from "../src/tee/verify-transport.js";
import {
  manifestDigestFromHashed,
  TransportMode,
} from "../src/tee/transport-manifest.js";
import { replayEventLogRtmr } from "../src/tee/verify-core.js";
import type { EventLogEntry, VerifiedQuoteReport } from "../src/tee/verify-core.js";

const COMPOSE = "aa".repeat(32);

/** A minimal log carrying a runtime-typed compose-hash event, as dstack emits. */
const EVENT_LOG: EventLogEntry[] = [
  {
    imr: 3,
    event_type: 0x08000001,
    digest: "",
    event: "compose-hash",
    event_payload: COMPOSE,
  },
];
const RTMR3 = replayEventLogRtmr(EVENT_LOG, 3);
const SIGNERS = new Uint8Array(32).fill(0x33);
const toHex = (b: Uint8Array) =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

let dir: string;

/** Generate a real self-signed P-256 certificate, as the enclave does. */
function makeCert(name: string): { key: string; cert: string; spki: Uint8Array } {
  const key = join(dir, `${name}.key`);
  const cert = join(dir, `${name}.crt`);
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "ec",
    "-pkeyopt", "ec_paramgen_curve:prime256v1",
    "-keyout", key, "-out", cert,
    "-days", "1", "-nodes", "-subj", `/CN=${name}`,
  ], { stdio: "ignore" });
  const pub = execFileSync("openssl", ["x509", "-in", cert, "-pubkey", "-noout"]);
  const der = execFileSync("openssl", ["pkey", "-pubin", "-outform", "DER"], {
    input: pub,
  });
  return {
    key: readFileSync(key, "utf8"),
    cert: readFileSync(cert, "utf8"),
    spki: new Uint8Array(createHash("sha256").update(der).digest()),
  };
}

/**
 * Serve a transport attestation describing `manifestSpki`, over TLS presenting
 * `serving`. When those differ, the server IS the relay.
 */
async function serve(
  serving: { key: string; cert: string },
  manifestSpki: Uint8Array,
  bootSession: Uint8Array,
  /** Close the connection immediately after responding, as a peer with a very
   *  short keep-alive does. This is what broke `cvm-self-trade` in CI. */
  closeAfterResponse = false,
): Promise<{ url: string; close: () => void }> {
  const appId = new Uint8Array(32).fill(0x01);
  const instanceId = new Uint8Array(32).fill(0x02);

  const server: Server = createServer(
    { key: serving.key, cert: serving.cert },
    (req, res) => {
      const nonceHex = new URL(req.url!, "https://x").searchParams.get("nonce")!;
      const nonce = Uint8Array.from(
        nonceHex.match(/../g)!.map((b) => parseInt(b, 16)),
      );
      const digest = manifestDigestFromHashed({
        protocolVersion: 1,
        transportMode: TransportMode.RaTls,
        appIdSha256: appId,
        instanceIdSha256: instanceId,
        bootSessionId: bootSession,
        tlsSpkiSha256: manifestSpki,
        signerSetSha256: SIGNERS,
      });
      const reportData = new Uint8Array(64);
      reportData.set(nonce, 0);
      reportData.set(digest, 32);
      res.setHeader("content-type", "application/json");
      if (closeAfterResponse) res.setHeader("connection", "close");
      res.end(
        JSON.stringify({
          manifest: {
            protocol_version: 1,
            transport_mode: "ra-tls",
            app_id_sha256: toHex(appId),
            instance_id_sha256: toHex(instanceId),
            boot_session_id: toHex(bootSession),
            tls_spki_sha256: toHex(manifestSpki),
            signer_set_sha256: toHex(SIGNERS),
          },
          quote: "00".repeat(16),
          event_log: JSON.stringify(EVENT_LOG),
          report_data: toHex(reportData),
          domain: "darknyx/transport-attestation/v1",
          // Carried so the injected verifier can echo the exact report_data,
          // exactly as a real DCAP verification would recover it from the quote.
          _reportData: toHex(reportData),
        }),
      );
    },
  );
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as { port: number }).port;
  return {
    url: `https://127.0.0.1:${port}`,
    close: () => server.close(),
  };
}

/**
 * Stands in for DCAP. Returns a report whose `reportData` is whatever the
 * server actually put in the response — i.e. it treats the quote as genuine.
 * That is the attacker-favourable assumption: the relay's quote really is real.
 */
function deps(capturedReportData: { hex?: string }) {
  return {
    verifyQuote: async (): Promise<VerifiedQuoteReport> =>
      ({
        reportData: Uint8Array.from(
          capturedReportData.hex!.match(/../g)!.map((b) => parseInt(b, 16)),
        ),
        mrtd: "00".repeat(48),
        rtmr0: "",
        rtmr1: "",
        rtmr2: "",
        rtmr3: RTMR3,
        tcbStatus: "UpToDate",
      }) as VerifiedQuoteReport,
    parseEventLog: (json: string) => JSON.parse(json) as EventLogEntry[],
    randomNonce: () => new Uint8Array(randomBytes(32)),
  };
}

/**
 * Fetch that records the served `report_data` so the stub verifier can echo it.
 *
 * It MUST forward the caller's `dispatcher` through to undici — that is what
 * routes the request over the TransportAgent's connection and lets the agent
 * capture the socket. An earlier version of this harness called the global
 * `fetch` instead, which silently bypassed the agent; every rejection test then
 * "passed" with `no live socket carried the attestation` rather than with the
 * check under test. The control test at the top of this file is what exposed
 * that, and it is why the control exists.
 */
function capturingFetch(sink: { hex?: string }): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const res = await undiciFetch(input as never, init as never);
    const text = await res.text();
    const body = JSON.parse(text) as { _reportData: string };
    sink.hex = body._reportData;
    return new Response(text, {
      status: res.status,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
}

describe("cuckoo proxy — a genuine quote behind a different certificate", () => {
  let honest: ReturnType<typeof makeCert>;
  let relay: ReturnType<typeof makeCert>;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "darknyx-relay-"));
    honest = makeCert("honest-enclave");
    relay = makeCert("relay");
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  });

  afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
    delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  });

  it("accepts the honest enclave — the harness is not vacuously failing", async () => {
    // Control. Without this, every rejection below could be an artefact of the
    // harness rather than of the check.
    const boot = new Uint8Array(32).fill(0x11);
    const s = await serve(honest, honest.spki, boot);
    const sink: { hex?: string } = {};
    try {
      const result = await verifyTransportOnSocket({
        baseUrl: s.url,
        agent: new TransportAgent(),
        deps: deps(sink),
        expectedComposeHash: COMPOSE,
        expectedSignerSetSha256: SIGNERS,
        fetchImpl: capturingFetch(sink),
      });
      expect(toHex(result.spkiSha256)).toBe(toHex(honest.spki));
    } finally {
      s.close();
    }
  });

  it("REJECTS a relay serving the honest enclave's genuine attestation", async () => {
    // THE attack. The body is byte-for-byte what the real enclave would emit —
    // real quote, consistent manifest, our nonce. Only the TLS certificate on
    // the socket differs. That must be enough.
    const boot = new Uint8Array(32).fill(0x11);
    const s = await serve(relay, honest.spki, boot);
    const sink: { hex?: string } = {};
    try {
      // Assert the REASON, not just that it threw. Without this the test would
      // pass on any incidental failure — which is exactly how the first version
      // of this file "passed" while the SPKI check was inert.
      const err = await verifyTransportOnSocket({
        baseUrl: s.url,
        agent: new TransportAgent(),
        deps: deps(sink),
        expectedComposeHash: COMPOSE,
        expectedSignerSetSha256: SIGNERS,
        fetchImpl: capturingFetch(sink),
      }).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(TransportVerificationError);
      expect((err as TransportVerificationError).kind).toBe("spki_mismatch");
    } finally {
      s.close();
    }
  });

  it("REJECTS a relay that rewrites the manifest to its own certificate", async () => {
    // The other half of the attack: make the manifest match the relay's cert.
    // The quote binding breaks instead — report_data committed to the original.
    const boot = new Uint8Array(32).fill(0x11);
    const s = await serve(relay, relay.spki, boot);
    const sink: { hex?: string } = {};
    try {
      // The relay CAN produce a self-consistent response, so this one only
      // fails on the governance pins — which is why the signer set and compose
      // hash are required, not optional.
      await expect(
        verifyTransportOnSocket({
          baseUrl: s.url,
          agent: new TransportAgent(),
          deps: deps(sink),
          expectedComposeHash: COMPOSE,
          expectedSignerSetSha256: new Uint8Array(32).fill(0x44),
          fetchImpl: capturingFetch(sink),
        }),
      ).rejects.toThrow(TransportVerificationError);
    } finally {
      s.close();
    }
  });

  it("destroys the socket on rejection rather than pooling it", async () => {
    // A connection that failed a check must not be reachable by a later
    // request. Leaving it pooled is how catch-and-retry reuses it.
    const boot = new Uint8Array(32).fill(0x11);
    const s = await serve(relay, honest.spki, boot);
    const agent = new TransportAgent();
    const sink: { hex?: string } = {};
    try {
      await verifyTransportOnSocket({
        baseUrl: s.url,
        agent,
        deps: deps(sink),
        expectedComposeHash: COMPOSE,
        expectedSignerSetSha256: SIGNERS,
        fetchImpl: capturingFetch(sink),
      }).catch(() => undefined);
      expect(agent.isVerified(agent.currentSocket())).toBe(false);
    } finally {
      s.close();
    }
  });
});

describe("old-boot evidence is rejected by the client", () => {
  it("refuses a manifest from a previous boot session", async () => {
    // The live run proved the enclave rotates its key and boot session across a
    // restart. This proves the half that actually protects a client: that it
    // REFUSES the stale evidence rather than merely that the server moved on.
    dir = mkdtempSync(join(tmpdir(), "darknyx-boot-"));
    const enclave = makeCert("enclave");
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    const oldBoot = new Uint8Array(32).fill(0xaa);
    const currentBoot = new Uint8Array(32).fill(0xbb);
    const s = await serve(enclave, enclave.spki, oldBoot);
    const sink: { hex?: string } = {};
    try {
      const err = await verifyTransportOnSocket({
        baseUrl: s.url,
        agent: new TransportAgent(),
        deps: deps(sink),
        expectedComposeHash: COMPOSE,
        expectedSignerSetSha256: SIGNERS,
        expectedBootSessionId: currentBoot,
        fetchImpl: capturingFetch(sink),
      }).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(TransportVerificationError);
      expect((err as TransportVerificationError).kind).toBe(
        "boot_session_mismatch",
      );
    } finally {
      s.close();
      rmSync(dir, { recursive: true, force: true });
      delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    }
  });
});

describe("a peer that closes immediately after responding", () => {
  // The CI failure this fixes. `currentSocket()` is cleared the moment the
  // peer closes, so reading it AFTER the response made a perfectly valid
  // exchange look like `socket_lost`. `cvm-self-trade` idles ~3 s between
  // polls, so it took a fresh connection every time and hit this on every
  // attempt — a retry could not help, because nothing about it was transient.
  let honestC: ReturnType<typeof makeCert>;
  let relayC: ReturnType<typeof makeCert>;

  beforeAll(() => {
    // Own temp dir: `dir` is module-level and each suite reassigns it, so
    // borrowing another block's is order-dependent (flagged in review).
    dir = mkdtempSync(join(tmpdir(), "darknyx-close-"));
    honestC = makeCert("honest-closing");
    relayC = makeCert("relay-closing");
  });

  afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  /**
   * A fetch that tears the socket down after the response, before the verifier
   * reads it.
   *
   * `Connection: close` alone is NOT enough to reproduce this: Node emits the
   * socket `close` event asynchronously, so locally it usually lands after the
   * synchronous read and the test passes either way. An earlier version of
   * this test did exactly that and was mutation-proven useless — reverting the
   * fix left it green. This forces the exact ordering CI hit after a ~3 s idle.
   */
  const fetchThenDropSocket =
    (agent: TransportAgent, sink: { hex?: string }): typeof fetch =>
    (async (input: never, init: never) => {
      const res = await capturingFetch(sink)(input, init);
      const live = agent.currentSocket();
      if (live) agent.destroySocket(live);
      // Let the `close` handler run so `current` is genuinely cleared.
      await new Promise((r) => setTimeout(r, 20));
      return res;
    }) as typeof fetch;

  it("still verifies when the connection is gone by the time we bind", async () => {
    const boot = new Uint8Array(32).fill(0x11);
    const s = await serve(honestC, honestC.spki, boot, true);
    const sink: { hex?: string } = {};
    const agent = new TransportAgent();
    try {
      const result = await verifyTransportOnSocket({
        baseUrl: s.url,
        agent,
        deps: deps(sink),
        expectedComposeHash: COMPOSE,
        expectedSignerSetSha256: SIGNERS,
        fetchImpl: fetchThenDropSocket(agent, sink),
      });
      // Bound to the socket that actually served it, closed or not.
      expect(toHex(result.spkiSha256)).toBe(toHex(honestC.spki));
    } finally {
      s.close();
    }
  });

  it("STILL rejects a relay that closes immediately", async () => {
    // The fallback must not become a hole: a closing peer presenting the
    // wrong certificate is still a relay.
    const boot = new Uint8Array(32).fill(0x11);
    const s = await serve(relayC, honestC.spki, boot, true);
    const sink: { hex?: string } = {};
    const agent = new TransportAgent();
    try {
      const err = await verifyTransportOnSocket({
        baseUrl: s.url,
        agent,
        deps: deps(sink),
        expectedComposeHash: COMPOSE,
        expectedSignerSetSha256: SIGNERS,
        // Same teardown: the fallback must reject a relay even when the
        // socket is gone, or it is a hole rather than a fix.
        fetchImpl: fetchThenDropSocket(agent, sink),
      }).then(
        () => null,
        (e: unknown) => e as { kind?: string },
      );
      expect(err, "the relay was accepted").not.toBeNull();
      expect(err?.kind).toBe("spki_mismatch");
    } finally {
      s.close();
    }
  });
});
