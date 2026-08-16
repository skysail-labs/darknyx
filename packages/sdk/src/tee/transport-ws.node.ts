/**
 * Verified WebSocket transport (T-03P, Phase 2c).
 *
 * # The problem
 *
 * `/v1/stream` carries order intent, cancellations and fills — everything the
 * HTTP path protects. But the SDK's WebSocket seam is **synchronous**
 * (`(url) => SendableWebSocketLike`) while transport verification is
 * asynchronous, so a factory cannot simply `await` before returning a socket.
 *
 * The tempting shortcuts are both wrong:
 *
 * - *Verify the HTTP transport and assume the WebSocket inherits it.* It does
 *   not. The upgrade is a separate connection and can land on a different peer.
 * - *Return the socket immediately and verify in the background.* The caller
 *   sends its login frame the moment `open` fires, so a credential crosses an
 *   unverified connection.
 *
 * # What this does instead
 *
 * The returned socket is a **gate**. It is live from the caller's point of view,
 * but every `send()` is queued until the connection has been checked, and
 * `open` is not surfaced to the caller until then. On success the queue flushes
 * in order; on failure the socket is closed and the queue is discarded
 * unsent — a queued credential must never be delivered late.
 *
 * # What the check is
 *
 * The upgrade's TLS socket must present **exactly** the SPKI a full transport
 * attestation already verified for this boot. That is sufficient rather than
 * lazy: the key is boot-random and quote-bound, and a relay cannot complete a
 * TLS handshake with a certificate whose private key it does not hold. So an
 * SPKI match proves the stream terminates at the same enclave and the same
 * boot as the attested HTTP path.
 *
 * It is **not** a substitute for the full verification — it is an equality
 * against the result of one. `verifiedSpkiSha256` must come from a
 * `verifyTransportOnSocket` call, and a new boot session requires a new one.
 */

import { createHash } from "node:crypto";
import type { TLSSocket } from "node:tls";

import { TransportVerificationError } from "./verify-transport.js";
import type { TransportFailure } from "./verify-transport.js";

/**
 * Bound on a WebSocket handshake that never completes.
 *
 * Generous — a slow gateway is not an attack — but finite, because the queued
 * login frame carries a bearer token and must not sit in memory indefinitely
 * on a socket that will never be verified.
 */
const HANDSHAKE_TIMEOUT_MS = 20_000;
import type {
  SendableWebSocketFactory,
  SendableWebSocketLike,
} from "../orders/trading-ws-client.js";

/** The subset of a Node `ws` socket this module needs. */
export interface NodeWebSocketLike {
  on(event: "open", cb: () => void): void;
  on(event: "message", cb: (data: unknown) => void): void;
  on(event: "close", cb: (code: number, reason?: unknown) => void): void;
  on(event: "error", cb: (err: unknown) => void): void;
  /** Emitted with the underlying HTTP response before `open`. */
  on(event: "upgrade", cb: (res: { socket: unknown }) => void): void;
  send(data: string): void;
  close(code?: number, reason?: string): void;
}

export interface VerifiedWebSocketOptions {
  /**
   * SPKI hash established by a completed transport verification for the
   * current boot session. Not optional: without it there is nothing to compare
   * against and the gate would be decorative.
   */
  verifiedSpkiSha256: Uint8Array;
  /** Opens the underlying socket. Injected so tests need no real server. */
  createSocket: (url: string) => NodeWebSocketLike;
  /** Called when a connection is rejected. Never receives credential data. */
  onViolation?: (err: TransportVerificationError) => void;
}

function sha256(der: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(der).digest());
}

function eq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** SPKI of the TLS socket underlying a WebSocket upgrade, or `null`. */
export function upgradeSocketSpki(socket: unknown): Uint8Array | null {
  const tls = socket as Partial<TLSSocket> | null;
  const getCert = tls?.getPeerX509Certificate;
  if (typeof getCert !== "function") return null;
  const cert = getCert.call(tls);
  if (!cert) return null;
  return sha256(new Uint8Array(cert.publicKey.export({ type: "spki", format: "der" })));
}

/**
 * Wrap a WebSocket factory so every connection is checked against the attested
 * SPKI before anything is sent over it.
 */
export function createVerifiedWebSocketFactory(
  opts: VerifiedWebSocketOptions,
): SendableWebSocketFactory {
  if (opts.verifiedSpkiSha256.length !== 32) {
    throw new TransportVerificationError(
      "verifiedSpkiSha256 must be 32 bytes",
      "malformed",
    );
  }

  return (url: string): SendableWebSocketLike => {
    const inner = opts.createSocket(url);

    let state: "pending" | "verified" | "rejected" | "closed" = "pending";
    /** Frames the caller tried to send before the check completed. */
    let pending: string[] = [];
    let sawUpgrade = false;
    // A server can accept the TCP connection and then emit neither `upgrade`
    // nor `open`. Without a bound, `state` stays "pending" for the life of the
    // process and the queued login frame — which carries a bearer token —
    // stays in memory on a socket that will never be verified.
    const handshakeTimer = setTimeout(() => {
      if (state === "pending") reject("handshake did not complete in time", "malformed");
    }, HANDSHAKE_TIMEOUT_MS);
    // Never let this timer hold a Node process open on its own.
    (handshakeTimer as unknown as { unref?: () => void }).unref?.();

    const openCbs: Array<() => void> = [];
    const messageCbs: Array<(ev: { data: unknown }) => void> = [];
    const closeCbs: Array<(ev: { code: number; reason?: string }) => void> = [];
    const errorCbs: Array<(ev: unknown) => void> = [];

    let openFired = false;
    /**
     * Whether the UNDERLYING socket has actually opened.
     *
     * `ws` emits `upgrade` before `open`, and at upgrade time the socket is
     * still CONNECTING. Verification completing is therefore NOT sufficient to
     * start writing: `inner.send()` throws "WebSocket is not open: readyState
     * 0". Both conditions must hold before anything is delivered or flushed.
     */
    let innerOpened = false;
    /** Retained so a listener attached after the fact still learns of it. */
    let rejection: TransportVerificationError | undefined;
    /** Deliver `open` and flush queued frames once BOTH conditions hold. */
    const surfaceOpen = () => {
      if (openFired || state !== "verified" || !innerOpened) return;
      openFired = true;
      clearTimeout(handshakeTimer);
      // Flush here rather than at verification time — the socket may not have
      // been writable then.
      for (const frame of pending) inner.send(frame);
      pending = [];
      for (const cb of openCbs) cb();
    };

    const reject = (detail: string, kind: TransportFailure = "spki_mismatch") => {
      if (state === "rejected") return;
      state = "rejected";
      clearTimeout(handshakeTimer);
      // Discard unsent frames. A queued login frame must not be delivered
      // late on a connection that failed its check.
      pending = [];
      const err = new TransportVerificationError(
        `websocket transport rejected: ${detail}`,
        kind,
      );
      rejection = err;
      opts.onViolation?.(err);
      for (const cb of errorCbs) cb(err);
      try {
        inner.close(1008, "transport verification failed");
      } catch {
        /* already closing */
      }
    };

    inner.on("upgrade", (res) => {
      // Terminal states stay terminal. A late `upgrade` after close (or after
      // a rejection) must not resurrect the connection to "verified" — doing
      // so re-armed `send()` on a dead socket.
      if (state === "closed" || state === "rejected") return;
      sawUpgrade = true;
      const observed = upgradeSocketSpki(res?.socket);
      if (!observed) {
        reject("no peer certificate on the upgrade socket", "malformed");
        return;
      }
      if (!eq(observed, opts.verifiedSpkiSha256)) {
        reject("upgrade socket presented a different certificate");
        return;
      }
      state = "verified";
      surfaceOpen();
    });

    inner.on("open", () => {
      if (state === "closed" || state === "rejected") return;
      // If `open` arrives without an `upgrade` event we have no certificate to
      // compare and must not assume the connection is fine. Plain `ws://`
      // reaches here, which is exactly the case worth refusing.
      if (!sawUpgrade) {
        reject("connection completed without a TLS upgrade to inspect", "malformed");
        return;
      }
      innerOpened = true;
      surfaceOpen();
    });

    inner.on("message", (data) => {
      // Inbound frames before verification are not delivered either: a caller
      // acting on them would be acting on data from an unverified peer.
      if (state !== "verified") return;
      for (const cb of messageCbs) cb({ data });
    });

    inner.on("close", (code, reason) => {
      // `close` is TERMINAL. Previously it only forwarded the event, leaving
      // `state` at "pending", with two consequences: `send()` kept appending
      // to a queue on a dead socket — accumulating a bearer token in memory
      // with no error to the caller — and nothing ever released it.
      if (state !== "rejected") state = "closed";
      pending = [];
      clearTimeout(handshakeTimer);
      for (const cb of closeCbs) {
        cb({ code, reason: typeof reason === "string" ? reason : undefined });
      }
    });

    inner.on("error", (e) => {
      for (const cb of errorCbs) cb(e);
    });

    return {
      addEventListener(type: string, cb: unknown): void {
        // Terminal states are REPLAYED to listeners that arrive late.
        //
        // Every consumer of this factory is async — it awaits transport
        // verification, then builds the socket, then returns it — so the
        // caller cannot attach handlers until at least a microtask after the
        // connection was created. On a warm path the upgrade completes first,
        // and a fire-and-forget implementation loses the event permanently:
        // the caller then waits forever for an `open` that already happened,
        // which is what produced a live "no pong within 15s" against a CVM
        // whose transport was in fact perfectly healthy.
        //
        // Replaying `open` is safe precisely because `openFired` is only ever
        // set by `surfaceOpen`, which refuses to run unless the certificate
        // check has already passed. A rejected connection therefore replays
        // its error and never its open.
        if (type === "open") {
          openCbs.push(cb as () => void);
          if (openFired) (cb as () => void)();
        } else if (type === "message")
          messageCbs.push(cb as (ev: { data: unknown }) => void);
        else if (type === "close")
          closeCbs.push(cb as (ev: { code: number; reason?: string }) => void);
        else if (type === "error") {
          errorCbs.push(cb as (ev: unknown) => void);
          if (rejection) (cb as (ev: unknown) => void)(rejection);
        }
      },
      send(data: string): void {
        // Never send on a failed OR closed connection. Queueing after close
        // silently retains credentials on a dead socket.
        if (state === "rejected" || state === "closed") return;
        // Queue until the check has passed AND the socket is writable. Writing
        // at "verified but still CONNECTING" throws inside the caller's own
        // open handler, which is how a healthy transport produced a hung
        // login against a live CVM.
        if (state === "pending" || !innerOpened) {
          pending.push(data);
          return;
        }
        inner.send(data);
      },
      close(): void {
        try {
          inner.close();
        } catch {
          /* already closing */
        }
      },
    } as SendableWebSocketLike;
  };
}
