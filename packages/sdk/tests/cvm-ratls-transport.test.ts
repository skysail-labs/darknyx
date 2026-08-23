/**
 * The verified transport against a REAL enclave (T-03P).
 *
 * Gated on `RUN_CVM_RATLS=1` + `DARKNYX_TEE_RATLS_URL` (the `s`-suffix
 * passthrough route). Self-skips otherwise.
 *
 * # Why this test matters more than its size suggests
 *
 * Everything else exercising the client adapter uses a locally-generated
 * certificate and an injected DCAP verifier. That is enough to prove the logic,
 * and it is exactly what let a real defect survive: the adapter passed an
 * `https.Agent` to global `fetch`, which is undici and ignores it, so the socket
 * was never captured and the SPKI comparison ran against nothing. Local tests
 * with a stubbed transport could not see that. Neither could the first live
 * window, which used `curl` and `openssl` and never put the adapter in the loop.
 *
 * This is the first thing that drives the production adapter against a real
 * enclave, a real TDX quote, and a real passthrough route.
 */

import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
// undici's fetch, NOT the global one. Node's built-in undici and the npm
// package are distinct instances, so handing a dispatcher from one to the
// other fails with `invalid onError method`. Consumers passing a custom
// fetchImpl must use this same import.
import { fetch as uf } from "undici";

import {
  TransportAgent,
  verifyTransportOnSocket,
  createVerifiedFetch,
} from "../src/tee/transport-agent.node.js";
import { verifyTransportAttestation } from "../src/tee/verify-transport.js";
import {
  parseEventLog,
  replayEventLogRtmr,
  type VerifiedQuoteReport,
} from "../src/tee/verify-core.js";

const RUN = process.env.RUN_CVM_RATLS === "1";

// Fail CLOSED on a half-configured run. With `RUN_CVM_RATLS=1` an empty
// signer set made `hex()` throw a bare TypeError from inside a helper, and an
// empty URL produced an invalid request — both of which read as "the enclave
// is broken" rather than "you forgot an env var". An empty compose hash is
// worse than noisy: it is silently accepted by strict verification as
// `pin_required`, so the run looks like it tested something.
if (RUN) {
  const missing = (
    [
      ["DARKNYX_TEE_RATLS_URL", process.env.DARKNYX_TEE_RATLS_URL],
      ["DARKNYX_EXPECT_COMPOSE_HASH", process.env.DARKNYX_EXPECT_COMPOSE_HASH],
      ["DARKNYX_EXPECT_SIGNER_SET", process.env.DARKNYX_EXPECT_SIGNER_SET],
    ] as const
  )
    .filter(([, v]) => !v?.trim())
    .map(([k]) => k);
  if (missing.length > 0) {
    throw new Error(
      `RUN_CVM_RATLS=1 requires ${missing.join(", ")}. Refusing to run a ` +
        "transport suite that would pass without checking what it claims to.",
    );
  }
  for (const [name, v] of [
    ["DARKNYX_EXPECT_COMPOSE_HASH", process.env.DARKNYX_EXPECT_COMPOSE_HASH],
    ["DARKNYX_EXPECT_SIGNER_SET", process.env.DARKNYX_EXPECT_SIGNER_SET],
  ] as const) {
    if (!/^[0-9a-fA-F]{64}$/.test((v ?? "").trim())) {
      throw new Error(`${name} must be 32 bytes of hex`);
    }
  }
}
const URL_ = process.env.DARKNYX_TEE_RATLS_URL ?? "";
const COMPOSE = process.env.DARKNYX_EXPECT_COMPOSE_HASH ?? "";
const SIGNERS_HEX = process.env.DARKNYX_EXPECT_SIGNER_SET ?? "";

const hex = (h: string) =>
  Uint8Array.from(h.match(/../g)!.map((b) => parseInt(b, 16)));
const toHex = (b: Uint8Array) =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

/**
 * DCAP is injected even here. `@phala/dcap-qvl` verification is covered by the
 * existing attestation suite; what is under test is the SOCKET binding, which
 * no amount of quote verification would exercise. The report echoes the
 * server's own `report_data`, which is the attacker-favourable assumption —
 * the quote is treated as genuine, so only the SPKI comparison can reject.
 */
function deps(sink: { rd?: string; log?: string }) {
  return {
    verifyQuote: async (): Promise<VerifiedQuoteReport> =>
      ({
        reportData: hex(sink.rd!),
        mrtd: "00".repeat(48),
        rtmr0: "",
        rtmr1: "",
        rtmr2: "",
        // Replay the enclave's OWN event log. A stub returning a fixed value
        // would make the event-log check vacuous; this makes the RTMR3
        // comparison a genuine self-consistency check on real data, while
        // leaving only the Intel signature (which needs hardware) injected.
        rtmr3: replayEventLogRtmr(parseEventLog(sink.log ?? "[]"), 3),
        tcbStatus: "UpToDate",
      }) as VerifiedQuoteReport,
    parseEventLog,
    randomNonce: () => new Uint8Array(randomBytes(32)),
  };
}

describe.skipIf(!RUN)("RA-TLS transport against a live CVM", () => {
  it("the production adapter captures the real socket's SPKI", async () => {
    // The regression this file exists for. If the adapter is not routing
    // through its own dispatcher, `spkiFor` throws and this fails — which is
    // precisely what happened before the undici fix, undetected.
    const agent = new TransportAgent();
    const res = await uf(`${URL_}/health`, { dispatcher: agent } as never);
    expect(res.status).toBe(200);
    const socket = agent.currentSocket();
    expect(
      socket,
      "no socket was captured — the dispatcher is not wired",
    ).toBeDefined();
    const spki = agent.spkiFor(socket!);
    expect(spki.length).toBe(32);
    console.log("live socket SPKI:", toHex(spki));
  }, 60_000);

  it("verifies the live transport end to end and marks the socket verified", async () => {
    const agent = new TransportAgent();
    const sink: { rd?: string; log?: string } = {};
    // Capture the served report_data so the injected verifier echoes it.
    const capturing: typeof fetch = (async (i: never, init: never) => {
      const r = await uf(i, {
        ...(init as object),
        dispatcher: agent,
      } as never);
      const t = await r.text();
      try {
        const parsed = JSON.parse(t) as {
          report_data: string;
          event_log: string;
        };
        sink.rd = parsed.report_data;
        sink.log = parsed.event_log;
      } catch {
        /* not the attestation response */
      }
      return new Response(t, {
        status: r.status,
        headers: { "content-type": "application/json" },
      });
    }) as never;

    const verified = await verifyTransportOnSocket({
      baseUrl: URL_,
      agent,
      deps: deps(sink),
      expectedComposeHash: COMPOSE,
      expectedSignerSetSha256: hex(SIGNERS_HEX),
      fetchImpl: capturing,
    });

    console.log("verified SPKI  :", toHex(verified.spkiSha256));
    console.log("boot session   :", toHex(verified.manifest.bootSessionId));
    console.log("signer set     :", toHex(verified.manifest.signerSetSha256));

    // The attested SPKI is the one on the socket the adapter is holding.
    expect(toHex(verified.spkiSha256)).toBe(
      toHex(agent.spkiFor(verified.socket)),
    );
    expect(agent.isVerified(verified.socket)).toBe(true);
    expect(toHex(verified.manifest.signerSetSha256)).toBe(SIGNERS_HEX);
  }, 90_000);

  it("a verified fetch reaches an authenticated route over the same socket", async () => {
    // Proves the gate does not merely verify and then hand back an unusable
    // transport: real traffic flows over the connection that was checked.
    const agent = new TransportAgent();
    const sink: { rd?: string; log?: string } = {};
    const capturing: typeof fetch = (async (i: never, init: never) => {
      const r = await uf(i, {
        ...(init as object),
        dispatcher: agent,
      } as never);
      const t = await r.text();
      try {
        const parsed = JSON.parse(t) as {
          report_data: string;
          event_log: string;
        };
        sink.rd = parsed.report_data;
        sink.log = parsed.event_log;
      } catch {
        /* not the attestation response */
      }
      return new Response(t, {
        status: r.status,
        headers: { "content-type": "application/json" },
      });
    }) as never;

    const vfetch = createVerifiedFetch({
      baseUrl: URL_,
      agent,
      deps: deps(sink),
      expectedComposeHash: COMPOSE,
      expectedSignerSetSha256: hex(SIGNERS_HEX),
      fetchImpl: capturing,
    });

    const info = await vfetch(`${URL_}/info`);
    expect(info.status).toBe(200);
    const body = (await info.json()) as { tee_pubkeys?: string[] };
    expect(Array.isArray(body.tee_pubkeys)).toBe(true);
    console.log("live /info tee_pubkeys:", body.tee_pubkeys?.length);
  }, 90_000);

  it("rejects when pinned to a signer set the enclave does not hold", async () => {
    // A live negative. Everything else about the response is genuine; only the
    // governance pin differs, and that must be enough.
    const agent = new TransportAgent();
    const sink: { rd?: string; log?: string } = {};
    const capturing: typeof fetch = (async (i: never, init: never) => {
      const r = await uf(i, {
        ...(init as object),
        dispatcher: agent,
      } as never);
      const t = await r.text();
      try {
        const parsed = JSON.parse(t) as {
          report_data: string;
          event_log: string;
        };
        sink.rd = parsed.report_data;
        sink.log = parsed.event_log;
      } catch {
        /* ignore */
      }
      return new Response(t, {
        status: r.status,
        headers: { "content-type": "application/json" },
      });
    }) as never;

    const err = await verifyTransportOnSocket({
      baseUrl: URL_,
      agent,
      deps: deps(sink),
      expectedComposeHash: COMPOSE,
      expectedSignerSetSha256: new Uint8Array(32).fill(0x44),
      fetchImpl: capturing,
    }).catch((e: unknown) => e as Error & { kind?: string });
    expect((err as { kind?: string }).kind).toBe("signer_set_mismatch");
  }, 90_000);

  it("records transport establishment latency", async () => {
    const samples: number[] = [];
    for (let i = 0; i < 5; i += 1) {
      const agent = new TransportAgent();
      const sink: { rd?: string; log?: string } = {};
      const capturing: typeof fetch = (async (a: never, b: never) => {
        const r = await uf(a, { ...(b as object), dispatcher: agent } as never);
        const t = await r.text();
        try {
          const parsed = JSON.parse(t) as {
            report_data: string;
            event_log: string;
          };
          sink.rd = parsed.report_data;
          sink.log = parsed.event_log;
        } catch {
          /* ignore */
        }
        return new Response(t, {
          status: r.status,
          headers: { "content-type": "application/json" },
        });
      }) as never;
      const t0 = performance.now();
      await verifyTransportOnSocket({
        baseUrl: URL_,
        agent,
        deps: deps(sink),
        expectedComposeHash: COMPOSE,
        expectedSignerSetSha256: hex(SIGNERS_HEX),
        fetchImpl: capturing,
      });
      samples.push(Math.round(performance.now() - t0));
    }
    samples.sort((a, b) => a - b);
    console.log("transport verify ms (5 cold):", samples.join(", "));
    console.log("median:", samples[2], "max:", samples[4]);
    expect(samples.length).toBe(5);
  }, 180_000);

  it("records client RSS across repeated verified transports", async () => {
    // The counterpart to the latency sample. Each verified transport pins a
    // dedicated dispatcher, a TLS socket, and a WeakMap entry keyed on that
    // socket. A consumer that reconnects — the daemon does, on every stream
    // drop — builds one per reconnect, so a retained socket here is an
    // unbounded leak in the longest-lived process we ship.
    //
    // WeakMap keys do not hold the socket alive, so the property under test is
    // that nothing ELSE does: the agent must be collectable once destroyed.
    // Reported, not asserted on a threshold — GC timing makes any fixed bound
    // flaky, and a number in CI output that a human reads beats a green test
    // that tolerates anything.
    // `global.gc?.()` silently no-ops without `--expose-gc`, which would make
    // this measure uncollected garbage rather than retention — failing on
    // ordinary heap noise or passing while a socket leaks, depending on
    // timing. Require the flag rather than pretend to measure.
    if (typeof global.gc !== "function") {
      throw new Error(
        "RSS retention test requires --expose-gc " +
          '(run with NODE_OPTIONS="--expose-gc"); without it the measurement ' +
          "is meaningless rather than merely approximate",
      );
    }
    const rss = () => Math.round(process.memoryUsage().rss / 1024 / 1024);

    // Warm up so one-time module/TLS-context allocation is not counted as growth.
    for (let i = 0; i < 3; i += 1) {
      const a = new TransportAgent();
      await uf(`${URL_}/health`, { dispatcher: a } as never).then((r) =>
        r.text(),
      );
      await a.close();
    }
    global.gc?.();
    const before = rss();

    const ROUNDS = 25;
    for (let i = 0; i < ROUNDS; i += 1) {
      const agent = new TransportAgent();
      const sink: { rd?: string; log?: string } = {};
      const capturing: typeof fetch = (async (a: never, b: never) => {
        const r = await uf(a, { ...(b as object), dispatcher: agent } as never);
        const t = await r.text();
        try {
          const parsed = JSON.parse(t) as {
            report_data: string;
            event_log: string;
          };
          sink.rd = parsed.report_data;
          sink.log = parsed.event_log;
        } catch {
          /* not the attestation response */
        }
        return new Response(t, {
          status: r.status,
          headers: { "content-type": "application/json" },
        });
      }) as never;
      await verifyTransportOnSocket({
        baseUrl: URL_,
        agent,
        deps: deps(sink),
        expectedComposeHash: COMPOSE,
        expectedSignerSetSha256: hex(SIGNERS_HEX),
        fetchImpl: capturing,
      });
      // The consumer contract: a transport that is finished with must be
      // closed. If this is the line that makes the numbers acceptable, that
      // is itself the finding to record.
      await agent.close();
    }
    global.gc?.();
    const after = rss();

    console.log(
      `client RSS MB: before=${before} after=${after} ` +
        `delta=${after - before} over ${ROUNDS} verified transports ` +
        `(${((after - before) / ROUNDS).toFixed(2)} MB/transport)`,
    );
    // Only a sanity bound: an order-of-magnitude regression (a retained socket
    // is ~1 MB of buffers, so 25 rounds would show ~25 MB+) fails, ordinary
    // heap noise does not.
    expect(after - before).toBeLessThan(60);
  }, 180_000);
});

describe.skipIf(RUN)("RA-TLS live suite", () => {
  it("is env-gated and skipped without RUN_CVM_RATLS=1", () => {
    expect(RUN).toBe(false);
  });
});
