/**
 * Transport-attestation verification core (T-03P).
 *
 * # What this adds over `verifyReportAgainstExpected`
 *
 * That function answers "is this a genuine, governed Darknyx enclave?". It does
 * **not** answer "is it the peer on the other end of *this* socket?" — a party
 * able to terminate TLS can relay a genuine `/attestation` response while
 * routing traffic elsewhere. This core closes that by adding one comparison the
 * other cannot make: the SPKI observed on the caller's own connection against
 * the SPKI bound into the quote.
 *
 * # Environment-neutral on purpose
 *
 * Nothing here imports `node:tls`. The observed SPKI hash is an **input**, so
 * this module works unchanged in the browser and stays unit-testable without a
 * socket. The Node adapter that actually reads a live peer certificate is a
 * separate layer, and it must pass the certificate from the connection carrying
 * the request — never from a probe connection opened alongside it.
 *
 * > **A probe is not the connection.** DNS changes, load balancing, or a relay
 * > can make `tls.connect()` and a subsequent `fetch()` reach different peers.
 * > Verifying one and using the other verifies nothing. That is the single
 * > easiest way to implement this whole feature and get zero security from it.
 *
 * # What is checked, and what each check buys
 *
 * | Check | Without it |
 * |---|---|
 * | DCAP + TCB (caller, via `verify-core`) | any hardware could answer |
 * | `report_data[0..32] == nonce` | a recorded response replays |
 * | `report_data[32..64] == SHA-256(DOMAIN‖manifest)` | manifest fields are unbound claims |
 * | event log replays to RTMR3, compose pinned | an unapproved build passes |
 * | **observed SPKI == manifest SPKI** | **a relay passes** |
 * | boot session matches | evidence from a previous boot passes |
 * | signer set matches on-chain governance | a genuine enclave with foreign settle keys passes |
 */

import {
  composeHashFromEventLog,
  hasImpossibleEventLogEntry,
  replayEventLogRtmr,
  DEFAULT_TCB_ALLOWLIST,
  type EventLogEntry,
  type VerifiedQuoteReport,
} from "./verify-core.js";
import {
  manifestDigest,
  manifestDigestFromHashed,
  PROTOCOL_VERSION,
  TransportMode,
} from "./transport-manifest.js";

/** Failure kinds specific to transport verification. */
export type TransportFailure =
  | "malformed"
  | "tcb_outdated"
  | "freshness"
  | "manifest_binding"
  | "event_log_invalid"
  | "compose_mismatch"
  | "mrtd_mismatch"
  | "spki_mismatch"
  | "boot_session_mismatch"
  | "signer_set_mismatch"
  | "transport_mode_rejected"
  | "protocol_version_unsupported"
  | "pin_required"
  /**
   * The connection vanished between the attestation exchange and binding it to
   * a socket — an idle timeout or a peer close, not a rejection.
   *
   * Kept distinct from `malformed` on purpose: every other kind here is a
   * VERDICT about the peer and must never be retried, whereas this one says
   * only "there is no socket left to bind to" and is safe to retry on a fresh
   * connection. Collapsing the two would force callers to choose between
   * retrying real rejections and failing on ordinary socket churn.
   */
  | "socket_lost";

export class TransportVerificationError extends Error {
  constructor(
    message: string,
    readonly kind: TransportFailure,
  ) {
    super(message);
    this.name = "TransportVerificationError";
  }
}

/** The manifest as served on the wire, hex-decoded by the caller. */
export interface ObservedManifest {
  protocolVersion: number;
  transportMode: TransportMode;
  appIdSha256: Uint8Array;
  instanceIdSha256: Uint8Array;
  bootSessionId: Uint8Array;
  tlsSpkiSha256: Uint8Array;
  signerSetSha256: Uint8Array;
}

export interface VerifyTransportOptions {
  /** DCAP-verified quote report, from the node/web `dcap-qvl` adapter. */
  report: VerifiedQuoteReport;
  /** Event log fetched alongside the quote. */
  eventLog: EventLogEntry[];
  /** The nonce this client generated. Must be 32 bytes. */
  nonce: Uint8Array;
  /** The manifest the server returned. Claims until verified below. */
  manifest: ObservedManifest;
  /**
   * SHA-256 of the DER SubjectPublicKeyInfo of the certificate observed on
   * **the connection carrying this request**. Not a probe connection.
   */
  observedSpkiSha256: Uint8Array;
  /** Governed compose hash. Required unless `strict` is false. */
  expectedComposeHash?: string;
  /** Optional MRTD pin. */
  expectedMrtd?: string;
  /**
   * SHA-256 over the concatenated on-chain `VaultConfig.tee_pubkeys` in shard
   * order. Required unless `strict` is false — without it a verified transport
   * proves the channel but not that the enclave holds the governed settle keys.
   */
  expectedSignerSetSha256?: Uint8Array;
  /** Boot session from `/info`, if the caller cross-checks it. */
  expectedBootSessionId?: Uint8Array;
  /** Accepted TCB statuses. Defaults to the secure-by-default allowlist. */
  tcbAllowlist?: readonly string[];
  /** Strict mode requires the governance pins. Default true. */
  strict?: boolean;
}

function eq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

function normHex(s: string): string {
  return s.replace(/^0x/i, "").toLowerCase();
}

/**
 * Evaluate a transport attestation. Returns the first failure kind, or `null`
 * when the channel is trusted.
 *
 * Precondition: `report` is the output of a *successful* DCAP verification. If
 * DCAP itself failed the caller must already have rejected the connection and
 * never reach here.
 */
export function verifyTransportAttestation(
  opts: VerifyTransportOptions,
): TransportFailure | null {
  const strict = opts.strict ?? true;
  const tcbAllowlist = opts.tcbAllowlist ?? DEFAULT_TCB_ALLOWLIST;
  const { report, eventLog, nonce, manifest } = opts;

  // 0. Shape. A short nonce would make the freshness check below weaker than
  //    it looks, so it is rejected rather than accommodated.
  if (nonce.length !== 32) return "malformed";
  if (report.reportData.length !== 64) return "malformed";
  for (const field of [
    manifest.appIdSha256,
    manifest.instanceIdSha256,
    manifest.bootSessionId,
    manifest.tlsSpkiSha256,
    manifest.signerSetSha256,
  ]) {
    if (field.length !== 32) return "malformed";
  }
  if (opts.observedSpkiSha256.length !== 32) return "malformed";

  // 1. Refuse a protocol version we do not implement rather than attempting a
  //    partial verification of it.
  if (manifest.protocolVersion !== PROTOCOL_VERSION) {
    return "protocol_version_unsupported";
  }

  // 2. The legacy gateway-terminated mode cannot satisfy this contract — there
  //    is no enclave-held certificate to bind. Accepting it would let a
  //    downgrade pass as a verified transport.
  if (manifest.transportMode !== TransportMode.RaTls) {
    return "transport_mode_rejected";
  }

  // 3. TCB must be explicitly accepted, not treated as informational.
  if (!tcbAllowlist.includes(report.tcbStatus)) return "tcb_outdated";

  // 4. Freshness: the quote answers OUR challenge.
  if (!eq(report.reportData.subarray(0, 32), nonce)) return "freshness";

  // 5. The binding that makes every manifest field meaningful. Recompute the
  //    digest from the returned fields; if the server altered any of them the
  //    digest will not match what the quote committed to.
  //
  //    Routed through the shared pre-hashed encoder so the verifier and the
  //    server cannot disagree about the field layout.
  const expectedDigest = manifestDigestFromHashed({
    transportMode: manifest.transportMode,
    appIdSha256: manifest.appIdSha256,
    instanceIdSha256: manifest.instanceIdSha256,
    bootSessionId: manifest.bootSessionId,
    tlsSpkiSha256: manifest.tlsSpkiSha256,
    signerSetSha256: manifest.signerSetSha256,
    protocolVersion: manifest.protocolVersion,
  });
  if (!eq(report.reportData.subarray(32, 64), expectedDigest)) {
    return "manifest_binding";
  }

  // 6. Structurally impossible entries first — an entry carrying both a
  //    verbatim digest and a payload can reproduce a genuine digest while
  //    carrying a payload the measurement never covered, so replaying it would
  //    succeed. That is exactly why the check precedes the replay.
  if (hasImpossibleEventLogEntry(eventLog)) return "event_log_invalid";

  // 7. The log must replay to the attested RTMR3 before anything is read from
  //    it. Only then is the compose hash trustworthy.
  if (replayEventLogRtmr(eventLog, 3) !== normHex(report.rtmr3)) {
    return "event_log_invalid";
  }

  if (strict && (!opts.expectedComposeHash || !opts.expectedSignerSetSha256)) {
    return "pin_required";
  }

  if (opts.expectedComposeHash) {
    const measured = composeHashFromEventLog(eventLog);
    if (!measured || measured !== normHex(opts.expectedComposeHash)) {
      return "compose_mismatch";
    }
  }

  if (opts.expectedMrtd && normHex(opts.expectedMrtd) !== normHex(report.mrtd)) {
    return "mrtd_mismatch";
  }

  // 8. THE check. Everything above proves a governed enclave produced this
  //    quote. Only this proves it is the peer on the other end of the socket
  //    the caller is holding.
  if (!eq(opts.observedSpkiSha256, manifest.tlsSpkiSha256)) {
    return "spki_mismatch";
  }

  // 9. Reject evidence from a previous boot. The server's key is boot-random,
  //    so a stale manifest cannot describe the live connection.
  if (
    opts.expectedBootSessionId &&
    !eq(opts.expectedBootSessionId, manifest.bootSessionId)
  ) {
    return "boot_session_mismatch";
  }

  // 10. The enclave must hold the governed settle keys. Without this a genuine,
  //     correctly-measured enclave with a foreign signer set would pass.
  if (
    opts.expectedSignerSetSha256 &&
    !eq(opts.expectedSignerSetSha256, manifest.signerSetSha256)
  ) {
    return "signer_set_mismatch";
  }

  return null;
}

/** Re-exported so callers can assert the two digests agree in their own tests. */
export { manifestDigest };
