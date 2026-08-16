/**
 * The gated WebSocket must not lose events that fire before listeners attach
 * (T-03P).
 *
 * `gwWebSocket` and every production consumer are async: they await transport
 * verification, then construct the socket, then hand it back. The caller can
 * only attach `open` handlers after that promise resolves. If the underlying
 * connection completes in the meantime, an implementation that fires `open`
 * once and forgets loses it forever — the caller waits for an event that
 * already happened.
 *
 * That is not a hypothetical. It is the live failure this file was written to
 * explain: against a real CVM the login frame was never sent and the test died
 * with "no pong within 15s", while a probe that attached its listeners
 * synchronously connected fine.
 */

import { describe, expect, it, vi } from "vitest";

import { createVerifiedWebSocketFactory } from "../src/tee/transport-ws.node.js";
import type { NodeWebSocketLike } from "../src/tee/transport-ws.node.js";

const SPKI = new Uint8Array(32).fill(7);

/**
 * A socket that completes its upgrade IMMEDIATELY on construction, before the
 * caller has had any chance to register handlers. A real TLS connection on a
 * warm path can do the same.
 */
class EagerSocket implements NodeWebSocketLike {
  readonly sent: string[] = [];
  private handlers = new Map<string, ((...a: never[]) => void)[]>();
  private readonly spki: Uint8Array;

  constructor(spki: Uint8Array = SPKI) {
    this.spki = spki;
    // Fire on the next microtask: after the factory has wired its own internal
    // handlers, but before an async caller can attach theirs.
    queueMicrotask(() => {
      this.emit("upgrade", {
        socket: {
          getPeerX509Certificate: () => ({
            publicKey: { export: () => Buffer.from(this.spki) },
          }),
        },
      });
      this.emit("open");
    });
  }

  on(event: string, cb: (...a: never[]) => void): void {
    const list = this.handlers.get(event) ?? [];
    list.push(cb);
    this.handlers.set(event, list);
  }
  private emit(event: string, ...args: unknown[]): void {
    for (const cb of this.handlers.get(event) ?? []) {
      (cb as (...a: unknown[]) => void)(...args);
    }
  }
  send(data: string): void {
    this.sent.push(data);
  }
  close(): void {}
}

/** Hash of the SPKI bytes the EagerSocket presents, as the gate computes it. */
async function expectedSpki(raw: Uint8Array): Promise<Uint8Array> {
  const { createHash } = await import("node:crypto");
  return new Uint8Array(createHash("sha256").update(raw).digest());
}

/**
 * A socket that mimics `ws` faithfully on the one point that matters: `upgrade`
 * fires while the socket is still CONNECTING, and `send()` THROWS until `open`.
 */
class RealisticOrderSocket implements NodeWebSocketLike {
  readonly sent: string[] = [];
  private handlers = new Map<string, ((...a: never[]) => void)[]>();
  private open = false;

  constructor() {
    queueMicrotask(() => {
      this.emit("upgrade", {
        socket: {
          getPeerX509Certificate: () => ({
            publicKey: { export: () => Buffer.from(SPKI) },
          }),
        },
      });
      // `open` lands strictly later, as it does in `ws`.
      setTimeout(() => {
        this.open = true;
        this.emit("open");
      }, 10);
    });
  }
  on(event: string, cb: (...a: never[]) => void): void {
    const l = this.handlers.get(event) ?? [];
    l.push(cb);
    this.handlers.set(event, l);
  }
  private emit(event: string, ...args: unknown[]): void {
    for (const cb of this.handlers.get(event) ?? []) {
      (cb as (...a: unknown[]) => void)(...args);
    }
  }
  send(data: string): void {
    if (!this.open) {
      throw new Error("WebSocket is not open: readyState 0 (CONNECTING)");
    }
    this.sent.push(data);
  }
  close(): void {}
}

describe("gated WebSocket — upgrade fires before the socket is writable", () => {
  it("does not surface open until the socket can actually be written to", async () => {
    // THE live bug. `ws` emits `upgrade` (where verification happens) while the
    // socket is still CONNECTING. Surfacing `open` there makes the caller send
    // its login frame into a socket that throws, and the exception escapes
    // through the caller's own handler. Against a real CVM this looked like a
    // silent hang — "no pong within 15s" — on a transport that was healthy.
    let inner!: RealisticOrderSocket;
    const factory = createVerifiedWebSocketFactory({
      verifiedSpkiSha256: await expectedSpki(SPKI),
      createSocket: () => (inner = new RealisticOrderSocket()),
    });
    const ws = factory("wss://enclave.example/v1/stream");

    const sendError = await new Promise<unknown>((resolve) => {
      const t = setTimeout(() => resolve(null), 500);
      ws.addEventListener("open", () => {
        clearTimeout(t);
        try {
          ws.send(JSON.stringify({ op: "login" }));
          resolve(null);
        } catch (e) {
          resolve(e);
        }
      });
    });
    expect(sendError, "send threw inside the open handler").toBeNull();
    expect(inner.sent).toHaveLength(1);
  });

  it("queues a frame sent between verification and open, then flushes it", async () => {
    // A caller that sends immediately must not lose the frame either. It has
    // to be held until the socket is writable and delivered exactly once.
    let inner!: RealisticOrderSocket;
    const factory = createVerifiedWebSocketFactory({
      verifiedSpkiSha256: await expectedSpki(SPKI),
      createSocket: () => (inner = new RealisticOrderSocket()),
    });
    const ws = factory("wss://enclave.example/v1/stream");
    ws.send(JSON.stringify({ op: "login" })); // before anything has happened

    await new Promise((r) => setTimeout(r, 100));
    expect(inner.sent).toEqual([JSON.stringify({ op: "login" })]);
  });
});

describe("gated WebSocket — listeners attached after the connection completes", () => {
  it("still delivers open to a listener registered a tick later", async () => {
    // THE regression. An async consumer cannot attach handlers any earlier
    // than this, so losing the event here means losing it in production.
    let inner!: EagerSocket;
    const factory = createVerifiedWebSocketFactory({
      verifiedSpkiSha256: await expectedSpki(SPKI),
      createSocket: () => (inner = new EagerSocket()),
    });
    const ws = factory("wss://enclave.example/v1/stream");

    // Simulate the async boundary in `gwWebSocket`.
    await Promise.resolve();
    await Promise.resolve();

    const opened = await new Promise<boolean>((resolve) => {
      const t = setTimeout(() => resolve(false), 500);
      ws.addEventListener("open", () => {
        clearTimeout(t);
        resolve(true);
      });
    });
    expect(opened, "open was fired before the listener attached and lost").toBe(
      true,
    );
    expect(inner).toBeDefined();
  });

  it("a frame sent after the late open actually reaches the socket", async () => {
    // Delivering `open` but dropping the send would be the same bug wearing a
    // different hat: the caller believes it logged in.
    let inner!: EagerSocket;
    const factory = createVerifiedWebSocketFactory({
      verifiedSpkiSha256: await expectedSpki(SPKI),
      createSocket: () => (inner = new EagerSocket()),
    });
    const ws = factory("wss://enclave.example/v1/stream");
    await Promise.resolve();
    await Promise.resolve();

    await new Promise<void>((resolve) => {
      ws.addEventListener("open", () => {
        ws.send(JSON.stringify({ op: "login" }));
        resolve();
      });
      setTimeout(resolve, 500);
    });
    expect(inner.sent).toHaveLength(1);
    expect(inner.sent[0]).toContain("login");
  });

  it("does NOT surface open late when the certificate did not match", async () => {
    // The replay must not become a bypass: a connection that failed its check
    // has to stay failed no matter when the listener arrives.
    const factory = createVerifiedWebSocketFactory({
      verifiedSpkiSha256: await expectedSpki(new Uint8Array(32).fill(9)),
      createSocket: () => new EagerSocket(SPKI),
    });
    const ws = factory("wss://relay.example/v1/stream");
    await Promise.resolve();
    await Promise.resolve();

    const opened = await new Promise<boolean>((resolve) => {
      const t = setTimeout(() => resolve(false), 300);
      ws.addEventListener("open", () => {
        clearTimeout(t);
        resolve(true);
      });
    });
    expect(opened, "a rejected connection surfaced open").toBe(false);
  });

  it("reports the violation to a late error listener too", async () => {
    // An operator attaching an error handler after construction must still
    // learn that the peer was rejected, or the failure is silent.
    const factory = createVerifiedWebSocketFactory({
      verifiedSpkiSha256: await expectedSpki(new Uint8Array(32).fill(9)),
      createSocket: () => new EagerSocket(SPKI),
    });
    const ws = factory("wss://relay.example/v1/stream");
    await Promise.resolve();
    await Promise.resolve();

    const err = await new Promise<unknown>((resolve) => {
      const t = setTimeout(() => resolve(null), 300);
      ws.addEventListener("error", (e) => {
        clearTimeout(t);
        resolve(e);
      });
    });
    expect(err, "late error listener never learned of the rejection").toBeTruthy();
  });
});

describe("gated WebSocket — close and stall are terminal", () => {
  /** A socket that connects at TCP level and then never upgrades or opens. */
  class StalledSocket implements NodeWebSocketLike {
    readonly sent: string[] = [];
    private handlers = new Map<string, ((...a: never[]) => void)[]>();
    on(event: string, cb: (...a: never[]) => void): void {
      const l = this.handlers.get(event) ?? [];
      l.push(cb);
      this.handlers.set(event, l);
    }
    emit(event: string, ...args: unknown[]): void {
      for (const cb of this.handlers.get(event) ?? []) {
        (cb as (...a: unknown[]) => void)(...args);
      }
    }
    send(data: string): void {
      this.sent.push(data);
    }
    close(): void {}
  }

  it("drops queued frames when the socket closes", async () => {
    // A credential queued before verification must not survive the socket.
    // Previously `close` only forwarded the event, so `state` stayed "pending"
    // and the bearer token sat in the queue on a dead connection.
    const inner = new StalledSocket();
    const factory = createVerifiedWebSocketFactory({
      verifiedSpkiSha256: await expectedSpki(SPKI),
      createSocket: () => inner,
    });
    const ws = factory("wss://enclave.example/v1/stream");
    ws.send(JSON.stringify({ op: "login", token: "bearer" }));

    inner.emit("close", 1006);

    // DIFFERENTIAL: asserting `sent === []` here would pass either way, since
    // a frame that is still queued has also not reached the wire. So drive the
    // connection to a state that WOULD flush — a successful upgrade + open —
    // and assert nothing comes out. With the queue retained, the credential
    // flushes here; with close terminal, it is gone.
    inner.emit("upgrade", {
      socket: {
        getPeerX509Certificate: () => ({
          publicKey: { export: () => Buffer.from(SPKI) },
        }),
      },
    });
    inner.emit("open");
    expect(
      inner.sent,
      "a frame queued before close survived and flushed afterwards",
    ).toEqual([]);

    // A send after close must not re-queue either — same differential.
    ws.send(JSON.stringify({ op: "login", token: "bearer" }));
    inner.emit("open");
    expect(inner.sent).toEqual([]);
  });

  it("rejects a handshake that never completes, rather than queueing forever", async () => {
    // The peer accepts TCP and then goes silent. Without a bound this stays
    // "pending" for the life of the process with the token still queued.
    vi.useFakeTimers();
    try {
      const inner = new StalledSocket();
      const violations: string[] = [];
      const factory = createVerifiedWebSocketFactory({
        verifiedSpkiSha256: await expectedSpki(SPKI),
        createSocket: () => inner,
        onViolation: (e) => violations.push(e.kind),
      });
      const ws = factory("wss://enclave.example/v1/stream");
      ws.send(JSON.stringify({ op: "login", token: "bearer" }));

      vi.advanceTimersByTime(20_001);

      expect(violations).toContain("malformed");
      expect(inner.sent, "a stalled handshake still flushed the queue").toEqual(
        [],
      );
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("gated WebSocket — reconnect is verified independently", () => {
  // The plan (§8.4) requires "reverify every WebSocket reconnect". The daemon
  // reconnects on `auth_expired` and on any server close, so this is the
  // common path, not an edge case — and a factory that only worked once would
  // strand a long-lived stream exactly as observed against a live CVM.
  it("gates a second connection from the same factory", async () => {
    const sockets: EagerSocket[] = [];
    const factory = createVerifiedWebSocketFactory({
      verifiedSpkiSha256: await expectedSpki(SPKI),
      createSocket: () => {
        const s = new EagerSocket();
        sockets.push(s);
        return s;
      },
    });

    const first = factory("wss://enclave.example/v1/stream");
    await Promise.resolve();
    await Promise.resolve();
    const firstOpen = await new Promise<boolean>((r) => {
      const t = setTimeout(() => r(false), 300);
      first.addEventListener("open", () => {
        clearTimeout(t);
        r(true);
      });
    });
    expect(firstOpen).toBe(true);

    // Reconnect: a NEW wrapper over a NEW socket.
    const second = factory("wss://enclave.example/v1/stream");
    await Promise.resolve();
    await Promise.resolve();
    const secondOpen = await new Promise<boolean>((r) => {
      const t = setTimeout(() => r(false), 300);
      second.addEventListener("open", () => {
        clearTimeout(t);
        r(true);
      });
    });
    expect(
      secondOpen,
      "the reconnect never surfaced open — a long-lived stream cannot recover",
    ).toBe(true);

    expect(sockets).toHaveLength(2);
    second.send(JSON.stringify({ op: "login" }));
    expect(sockets[1].sent).toHaveLength(1);
    // Verification is per-socket, never inherited from the first.
    expect(sockets[0].sent).toHaveLength(0);
  });

  it("rejects a reconnect that presents a different certificate", async () => {
    // The property that makes per-connection gating worth having: a relay
    // that appears only on the reconnect must still be caught.
    let n = 0;
    const violations: string[] = [];
    const factory = createVerifiedWebSocketFactory({
      verifiedSpkiSha256: await expectedSpki(SPKI),
      createSocket: () => {
        n += 1;
        return n === 1 ? new EagerSocket() : new EagerSocket(new Uint8Array(32).fill(0xaa));
      },
      onViolation: (e) => violations.push(e.kind),
    });

    factory("wss://enclave.example/v1/stream");
    await Promise.resolve();
    await Promise.resolve();

    const second = factory("wss://enclave.example/v1/stream");
    await Promise.resolve();
    await Promise.resolve();
    const opened = await new Promise<boolean>((r) => {
      const t = setTimeout(() => r(false), 300);
      second.addEventListener("open", () => {
        clearTimeout(t);
        r(true);
      });
    });
    expect(opened, "a substituted certificate passed on reconnect").toBe(false);
    expect(violations).toContain("spki_mismatch");
  });
});
