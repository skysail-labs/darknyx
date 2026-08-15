/**
 * Verified WebSocket transport (T-03P, Phase 2c).
 *
 * The property under test is narrow and important: **no frame the caller hands
 * this socket may reach the wire before the connection has been checked, and
 * none may reach it at all if the check fails.**
 *
 * That is the whole reason the gate exists. `/v1/stream` carries a login frame
 * with a bearer token as its first message, so "verify in the background and
 * let the caller start talking" is the failure mode, not the design.
 */

import { describe, expect, it, vi } from "vitest";

import {
  createVerifiedWebSocketFactory,
  type NodeWebSocketLike,
} from "../src/tee/transport-ws.node.js";
import { TransportVerificationError } from "../src/tee/verify-transport.js";

const SPKI = new Uint8Array(32).fill(0x22);
const OTHER_SPKI = new Uint8Array(32).fill(0x99);

/** A fake `ws` socket whose events we drive by hand. */
function fakeSocket() {
  const handlers = new Map<string, Array<(...a: unknown[]) => void>>();
  const sent: string[] = [];
  let closedWith: { code?: number; reason?: string } | undefined;

  const sock: NodeWebSocketLike = {
    on(event: string, cb: (...a: unknown[]) => void) {
      const list = handlers.get(event) ?? [];
      list.push(cb);
      handlers.set(event, list);
    },
    send(data: string) {
      sent.push(data);
    },
    close(code?: number, reason?: string) {
      closedWith = { code, reason };
    },
  } as NodeWebSocketLike;

  const emit = (event: string, ...args: unknown[]) => {
    for (const cb of handlers.get(event) ?? []) cb(...args);
  };

  /** A stand-in for the TLS socket carried on the upgrade response. */
  const peer = (spki: Uint8Array | null) => ({
    socket:
      spki === null
        ? {}
        : {
            getPeerX509Certificate: () => ({
              publicKey: {
                // The gate hashes this DER; feeding the digest's preimage keeps
                // the fake honest about going through the same code path.
                export: () => Buffer.from(spkiPreimage(spki)),
              },
            }),
          },
  });

  return { sock, sent, emit, peer, closed: () => closedWith };
}

/**
 * The gate hashes the exported DER, so tests need a preimage that hashes to the
 * SPKI they want. Rather than invert SHA-256, the tests compare against the
 * hash of a known preimage.
 */
function spkiPreimage(marker: Uint8Array): Uint8Array {
  return marker;
}

/** SHA-256 of a preimage, matching what the gate computes. */
async function hashOf(preimage: Uint8Array): Promise<Uint8Array> {
  const { createHash } = await import("node:crypto");
  return new Uint8Array(createHash("sha256").update(preimage).digest());
}

describe("createVerifiedWebSocketFactory — send gating", () => {
  it("does not send a frame before the connection is verified", async () => {
    const f = fakeSocket();
    const expected = await hashOf(SPKI);
    const factory = createVerifiedWebSocketFactory({
      verifiedSpkiSha256: expected,
      createSocket: () => f.sock,
    });
    const ws = factory("wss://example/v1/stream");

    // The caller sends its login frame immediately, as the real client does.
    ws.send('{"login":"bearer-token"}');
    expect(f.sent).toEqual([]); // still queued — nothing on the wire yet

    f.emit("upgrade", f.peer(SPKI));
    expect(f.sent).toEqual(['{"login":"bearer-token"}']); // flushed, in order
  });

  it("never sends a queued frame when the check fails", async () => {
    // THE test. A queued credential must be discarded, not delivered late.
    const f = fakeSocket();
    const expected = await hashOf(SPKI);
    const violations: TransportVerificationError[] = [];
    const factory = createVerifiedWebSocketFactory({
      verifiedSpkiSha256: expected,
      createSocket: () => f.sock,
      onViolation: (e) => violations.push(e),
    });
    const ws = factory("wss://example/v1/stream");

    ws.send('{"login":"bearer-token"}');
    f.emit("upgrade", f.peer(OTHER_SPKI)); // a relay's certificate

    expect(f.sent).toEqual([]);
    expect(violations).toHaveLength(1);
    expect(violations[0]).toBeInstanceOf(TransportVerificationError);
    expect(f.closed()?.code).toBe(1008);

    // And a later send must not resurrect it.
    ws.send('{"order":"secret"}');
    expect(f.sent).toEqual([]);
  });

  it("flushes multiple queued frames in order", async () => {
    const f = fakeSocket();
    const factory = createVerifiedWebSocketFactory({
      verifiedSpkiSha256: await hashOf(SPKI),
      createSocket: () => f.sock,
    });
    const ws = factory("wss://example/v1/stream");
    ws.send("a");
    ws.send("b");
    ws.send("c");
    f.emit("upgrade", f.peer(SPKI));
    expect(f.sent).toEqual(["a", "b", "c"]);
  });

  it("sends straight through once verified", async () => {
    const f = fakeSocket();
    const factory = createVerifiedWebSocketFactory({
      verifiedSpkiSha256: await hashOf(SPKI),
      createSocket: () => f.sock,
    });
    const ws = factory("wss://example/v1/stream");
    f.emit("upgrade", f.peer(SPKI));
    ws.send("later");
    expect(f.sent).toEqual(["later"]);
  });
});

describe("createVerifiedWebSocketFactory — open and message gating", () => {
  it("does not surface open until the connection is verified", async () => {
    // A caller keys its login off `open`. Surfacing it early would defeat the
    // send gate by making the caller believe it is safe to talk.
    const f = fakeSocket();
    const factory = createVerifiedWebSocketFactory({
      verifiedSpkiSha256: await hashOf(SPKI),
      createSocket: () => f.sock,
    });
    const ws = factory("wss://example/v1/stream");
    const onOpen = vi.fn();
    ws.addEventListener("open", onOpen);

    f.emit("open");
    expect(onOpen).not.toHaveBeenCalled();

    f.emit("upgrade", f.peer(SPKI));
    expect(onOpen).toHaveBeenCalledTimes(1);
  });

  it("does not deliver inbound frames from an unverified peer", async () => {
    const f = fakeSocket();
    const factory = createVerifiedWebSocketFactory({
      verifiedSpkiSha256: await hashOf(SPKI),
      createSocket: () => f.sock,
    });
    const ws = factory("wss://example/v1/stream");
    const onMessage = vi.fn();
    ws.addEventListener("message", onMessage);

    f.emit("message", "before-verification");
    expect(onMessage).not.toHaveBeenCalled();

    f.emit("upgrade", f.peer(SPKI));
    f.emit("message", "after");
    expect(onMessage).toHaveBeenCalledTimes(1);
  });

  it("surfaces open only once", async () => {
    const f = fakeSocket();
    const factory = createVerifiedWebSocketFactory({
      verifiedSpkiSha256: await hashOf(SPKI),
      createSocket: () => f.sock,
    });
    const ws = factory("wss://example/v1/stream");
    const onOpen = vi.fn();
    ws.addEventListener("open", onOpen);
    f.emit("upgrade", f.peer(SPKI));
    f.emit("open");
    expect(onOpen).toHaveBeenCalledTimes(1);
  });
});

describe("createVerifiedWebSocketFactory — refusals", () => {
  it("rejects a connection that never presented a certificate", async () => {
    // Plain ws:// reaches here. There is nothing to compare, so it must fail
    // rather than pass by absence.
    const f = fakeSocket();
    const factory = createVerifiedWebSocketFactory({
      verifiedSpkiSha256: await hashOf(SPKI),
      createSocket: () => f.sock,
    });
    const ws = factory("ws://example/v1/stream");
    ws.send("secret");
    f.emit("open"); // no `upgrade` event at all
    expect(f.sent).toEqual([]);
    expect(f.closed()?.code).toBe(1008);
  });

  it("rejects an upgrade socket with no peer certificate", async () => {
    const f = fakeSocket();
    const factory = createVerifiedWebSocketFactory({
      verifiedSpkiSha256: await hashOf(SPKI),
      createSocket: () => f.sock,
    });
    const ws = factory("wss://example/v1/stream");
    ws.send("secret");
    f.emit("upgrade", f.peer(null));
    expect(f.sent).toEqual([]);
    expect(f.closed()?.code).toBe(1008);
  });

  it("refuses to build a factory without a 32-byte pin", () => {
    // Without a real pin the gate would compare against nothing and pass
    // everything — decorative security is worse than none.
    expect(() =>
      createVerifiedWebSocketFactory({
        verifiedSpkiSha256: new Uint8Array(31),
        createSocket: () => fakeSocket().sock,
      }),
    ).toThrow(TransportVerificationError);
  });

  it("reports the violation without echoing frame contents", async () => {
    const f = fakeSocket();
    const violations: TransportVerificationError[] = [];
    const factory = createVerifiedWebSocketFactory({
      verifiedSpkiSha256: await hashOf(SPKI),
      createSocket: () => f.sock,
      onViolation: (e) => violations.push(e),
    });
    const ws = factory("wss://example/v1/stream");
    ws.send('{"login":"SUPER-SECRET-TOKEN"}');
    f.emit("upgrade", f.peer(OTHER_SPKI));
    expect(violations[0]?.message).not.toContain("SUPER-SECRET-TOKEN");
  });
});
