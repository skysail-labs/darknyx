/**
 * `createVerifiedTransport` (T-03P).
 *
 * The factory exists because the individual pieces are each easy to wire up
 * wrongly, and the interesting failure is not exotic: build the agent, forget
 * to gate the WebSocket, and the stream carries a bearer token over an
 * unverified connection while the HTTP path looks perfectly fine.
 *
 * These tests are about that composition — that both transports come back
 * bound to the *same* verified identity, and that the WebSocket is absent
 * rather than unverified when it cannot be gated.
 */

import { describe, expect, it, vi } from "vitest";
import { createHash } from "node:crypto";

import type { NodeWebSocketLike } from "../src/tee/transport-ws.node.js";

const stubSpki = new Uint8Array(
  createHash("sha256").update(new Uint8Array(32).fill(0x22)).digest(),
);

// Stub the verification itself. Its correctness is covered exhaustively in
// verify-transport.test.ts and transport-agent.test.ts; what is under test
// here is the wiring on top of a successful verification.
vi.mock("../src/tee/transport-agent.node.js", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("../src/tee/transport-agent.node.js")>();
  return {
    ...actual,
    verifyTransportOnSocket: vi.fn(async () => ({
      socket: {} as never,
      manifest: {
        protocolVersion: 1,
        transportMode: 1,
        appIdSha256: new Uint8Array(32),
        instanceIdSha256: new Uint8Array(32),
        bootSessionId: new Uint8Array(32).fill(0x11),
        tlsSpkiSha256: stubSpki,
        signerSetSha256: new Uint8Array(32).fill(0x33),
      },
      spkiSha256: stubSpki,
    })),
    createVerifiedFetch: vi.fn(() => vi.fn()),
  };
});

const { createVerifiedTransport } =
  await import("../src/tee/transport.node.js");

const SPKI_PREIMAGE = new Uint8Array(32).fill(0x22);
const spkiHash = new Uint8Array(
  createHash("sha256").update(SPKI_PREIMAGE).digest(),
);
const BOOT = new Uint8Array(32).fill(0x11);
const SIGNERS = new Uint8Array(32).fill(0x33);
const COMPOSE = "aa".repeat(32);

function fakeWs(): NodeWebSocketLike {
  return {
    on() {},
    send() {},
    close() {},
  } as NodeWebSocketLike;
}

describe("createVerifiedTransport — composition", () => {
  const base = {
    baseUrl: "https://example",
    deps: {} as never,
    expectedComposeHash: COMPOSE,
    expectedSignerSetSha256: SIGNERS,
  };

  it("returns no WebSocket factory when none can be gated", async () => {
    // Absent, not unverified. Handing back an ungated socket because the
    // consumer forgot to supply a constructor is exactly the shape this
    // factory exists to prevent.
    const t = await createVerifiedTransport(base);
    expect(t.webSocketFactory).toBeUndefined();
  });

  it("binds the WebSocket gate to the SAME SPKI the HTTP path verified", async () => {
    // The composition property. Two transports verified against two different
    // identities would each look fine in isolation.
    const t = await createVerifiedTransport({
      ...base,
      createWebSocket: () => fakeWs(),
    });
    expect(t.webSocketFactory).toBeDefined();
    expect(Array.from(t.verifiedSpkiSha256)).toEqual(Array.from(spkiHash));
  });

  it("exposes the boot session the verifier returned", async () => {
    // Not read from module state, not re-fetched — the single source of truth
    // is what verifyTransportOnSocket handed back.
    const t = await createVerifiedTransport(base);
    expect(Array.from(t.bootSessionId)).toEqual(Array.from(BOOT));
  });
});

describe("createVerifiedTransport — staleness", () => {
  const base = {
    baseUrl: "https://example",
    deps: {} as never,
    expectedComposeHash: COMPOSE,
    expectedSignerSetSha256: SIGNERS,
  };

  it("reports not-stale when there is no live socket", async () => {
    // Exercises the REAL isStale() on a constructed transport, not a
    // reimplementation of its logic. "No connection right now" is not evidence
    // of a restart, and treating it as one would make a consumer tear down a
    // healthy transport on every idle period.
    const t = await createVerifiedTransport(base);
    expect(t.agent.currentSocket()).toBeUndefined();
    expect(t.isStale()).toBe(false);
  });

  it("reports stale once the live socket no longer matches the attested SPKI", async () => {
    // A restart changes the boot-random key, so the certificate on the next
    // connection differs. Driven through the real agent rather than a stub of
    // it: markVerified/spkiFor are the actual implementations.
    const t = await createVerifiedTransport(base);
    const other = {} as never;
    // Teach the real agent about a socket carrying a DIFFERENT certificate.
    (t.agent as unknown as { spki: WeakMap<object, Uint8Array> }).spki.set(
      other,
      new Uint8Array(32).fill(0xee),
    );
    (t.agent as unknown as { current?: object }).current = other;
    expect(t.isStale()).toBe(true);
  });

  it("treats a socket whose certificate cannot be read as stale", async () => {
    // Failing closed. A socket with no recorded SPKI makes spkiFor throw, and
    // that must read as stale rather than as fine.
    const t = await createVerifiedTransport(base);
    (t.agent as unknown as { current?: object }).current = {} as never;
    expect(t.isStale()).toBe(true);
  });
});

describe("createVerifiedTransport — browser safety", () => {
  it("is not reachable from the package index", async () => {
    const index = await import("../src/index.js");
    expect(Object.keys(index)).not.toContain("createVerifiedTransport");
  });
});
