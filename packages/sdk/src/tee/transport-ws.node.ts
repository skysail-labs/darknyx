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

    let state: "pending" | "verified" | "rejected" = "pending";
    /** Frames the caller tried to send before the check completed. */
    let pending: string[] = [];
    let sawUpgrade = false;

    const openCbs: Array<() => void> = [];
    const messageCbs: Array<(ev: { data: unknown }) => void> = [];
    const closeCbs: Array<(ev: { code: number; reason?: string }) => void> = [];
    const errorCbs: Array<(ev: unknown) => void> = [];

    let openFired = false;
    const surfaceOpen = () => {
      if (openFired || state !== "verified") return;
      openFired = true;
      for (const cb of openCbs) cb();
    };

    const reject = (detail: string) => {
      if (state === "rejected") return;
      state = "rejected";
      // Discard unsent frames. A queued login frame must not be delivered
      // late on a connection that failed its check.
      pending = [];
      const err = new TransportVerificationError(
        `websocket transport rejected: ${detail}`,
        "spki_mismatch",
      );
      opts.onViolation?.(err);
      for (const cb of errorCbs) cb(err);
      try {
        inner.close(1008, "transport verification failed");
      } catch {
        /* already closing */
      }
    };

    inner.on("upgrade", (res) => {
      sawUpgrade = true;
      const observed = upgradeSocketSpki(res?.socket);
      if (!observed) {
        reject("no peer certificate on the upgrade socket");
        return;
      }
      if (!eq(observed, opts.verifiedSpkiSha256)) {
        reject("upgrade socket presented a different certificate");
        return;
      }
      state = "verified";
      for (const frame of pending) inner.send(frame);
      pending = [];
      surfaceOpen();
    });

    inner.on("open", () => {
      // If `open` arrives without an `upgrade` event we have no certificate to
      // compare and must not assume the connection is fine. Plain `ws://`
      // reaches here, which is exactly the case worth refusing.
      if (!sawUpgrade) {
        reject("connection completed without a TLS upgrade to inspect");
        return;
      }
      surfaceOpen();
    });

    inner.on("message", (data) => {
      // Inbound frames before verification are not delivered either: a caller
      // acting on them would be acting on data from an unverified peer.
      if (state !== "verified") return;
      for (const cb of messageCbs) cb({ data });
    });

    inner.on("close", (code, reason) => {
      for (const cb of closeCbs) {
        cb({ code, reason: typeof reason === "string" ? reason : undefined });
      }
    });

    inner.on("error", (e) => {
      for (const cb of errorCbs) cb(e);
    });

    return {
      addEventListener(type: string, cb: unknown): void {
        if (type === "open") openCbs.push(cb as () => void);
        else if (type === "message")
          messageCbs.push(cb as (ev: { data: unknown }) => void);
        else if (type === "close")
          closeCbs.push(cb as (ev: { code: number; reason?: string }) => void);
        else if (type === "error") errorCbs.push(cb as (ev: unknown) => void);
      },
      send(data: string): void {
        if (state === "rejected") return; // never send on a failed connection
        if (state === "pending") {
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
