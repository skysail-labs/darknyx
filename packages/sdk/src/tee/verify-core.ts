/**
 * Shared, environment-agnostic core of TEE attestation verification.
 *
 * This module holds the *pure* checks that must be byte-identical wherever they
 * run — the node daemon and the browser SDK both feed a DCAP-verified quote
 * report into the same functions here, so the two clients cannot drift (the
 * §7-style parity contract).
 *
 * The actual Intel-TCB verification (signature + PCK chain + QE identity +
 * enforced TCB status) is done by the pure-JS `@phala/dcap-qvl` (>= 0.3.9, the
 * QE-identity-patched release — the WASM `-node`/`-web` builds are NOT patched,
 * see CVE-2026-22696) in the caller; this module takes the *already-verified*
 * report and does the parts DCAP does NOT do for us:
 *
 *   1. **report_data binding** — the verified quote's `report_data` must equal
 *      `nonce ‖ SHA-256(tee_pubkey)` (freshness + key binding).
 *   2. **event-log → RTMR3 replay** — recompute RTMR3 from the event log and
 *      confirm it equals the *attested* RTMR3 in the verified quote, so the
 *      event log is provably the one behind this quote (not attacker JSON).
 *   3. **measurement pinning** — the `compose-hash` read from the *now-trusted*
 *      event log (and optionally MRTD) must match source-pinned expected values.
 *
 * Why this matters (audit_2 A-1): without (2)+(3) a client can only compare a
 * self-reported `/info.compose_hash` — which an operator running a genuine-but-
 * malicious build forges freely. MRTD is the shared dstack-OS measurement and
 * does NOT distinguish apps; only the RTMR3 `compose-hash` event does. So the
 * compose hash MUST be bound to the quote via the event log, done here.
 *
 * The RTMR replay reproduces dstack's `replay_rtmr`
 * (`dstack/sdk/rust/types/src/dstack.rs`) exactly:
 *   mr₀ = 48 zero bytes; for each event with the target IMR, in log order,
 *   mrᵢ₊₁ = SHA-384( mrᵢ ‖ digestᵢ )  (digest right-padded to ≥48 bytes).
 *
 * Hashing uses `node:crypto` to match every other SDK crypto module; bundlers
 * polyfill it for the browser build, as they already do for the rest of the SDK.
 */

import { createHash } from "node:crypto";

/** A single measured-event entry from the dstack quote `event_log` JSON string.
 *  Mirrors `EventLog` in `dstack/sdk/rust/types/src/dstack.rs`. */
export interface EventLogEntry {
  /** Integrity Measurement Register index (RTMR0-3 ⇒ imr 0-3). */
  imr: number;
  event_type: number;
  /** Hex-encoded event digest (normally 48 bytes / SHA-384). */
  digest: string;
  /** Event name, e.g. `"compose-hash"`, `"app-id"`, `"instance-id"`. */
  event: string;
  /** Hex-encoded event payload (for `compose-hash`, the compose hash itself). */
  event_payload: string;
}

/**
 * A DCAP-verified TDX quote, reduced to the fields this core needs. The caller's
 * `dcap-qvl` adapter (node or web) maps the library's report into this shape —
 * so this module never depends on the WASM package directly.
 */
export interface VerifiedQuoteReport {
  /** The 64-byte `report_data` extracted from the *verified* quote. */
  reportData: Uint8Array;
  /** Hex MRTD (dstack-OS / firmware measurement). */
  mrtd: string;
  /** Hex RTMR0-3 as attested in the verified quote. */
  rtmr0: string;
  rtmr1: string;
  rtmr2: string;
  rtmr3: string;
  /** Intel TCB status string, e.g. `"UpToDate"`. Enforced against an allowlist. */
  tcbStatus: string;
  /** TCB advisory IDs (informational; surfaced for logging/policy). */
  advisoryIds: string[];
}

/** Operator-pinned expected measurements (source-committed, ceremony-curated). */
export interface ExpectedMeasurements {
  /** Hex compose hash of the audited image. REQUIRED in strict mode. */
  composeHash?: string;
  /** Hex MRTD (dstack-OS). Optional pin. */
  mrtd?: string;
  /** Base58 TEE signer pubkey. REQUIRED in strict mode. */
  teePubkey?: string;
}

export type AttestationFailure =
  | "fetch"
  | "malformed"
  | "freshness"
  | "binding"
  | "pubkey_mismatch"
  | "compose_mismatch"
  | "mrtd_mismatch"
  | "quote_invalid"
  // Added for real DCAP enforcement (audit_2 A-1):
  | "tcb_outdated" // TCB status not in the allowlist
  | "event_log_invalid" // replay(event_log) != attested RTMR3, or no compose-hash event
  | "pin_required" // strict mode without the required compose_hash / tee_pubkey pin
  | "report_data_mismatch"; // verified quote's report_data != the one the gateway echoed

export class AttestationError extends Error {
  constructor(
    message: string,
    readonly kind: AttestationFailure,
  ) {
    super(message);
    this.name = "AttestationError";
  }
}

/** TCB statuses accepted by default (secure-by-default: only fully up-to-date). */
export const DEFAULT_TCB_ALLOWLIST: readonly string[] = ["UpToDate"];

/** dstack event name carrying the compose hash in RTMR3. */
export const COMPOSE_HASH_EVENT = "compose-hash";

/**
 * dstack runtime-event type (the app measurements in RTMR3: compose-hash,
 * app-id, instance-id, key-provider, …). For these events the event log's
 * `digest` field is EMPTY and the digest that was extended into the RTMR must be
 * COMPUTED from the event; all other (firmware/boot) events carry a pre-filled
 * `digest`. See `dstack/cc-eventlog/src/{tdx,runtime_events}.rs`.
 */
export const DSTACK_RUNTIME_EVENT_TYPE = 0x08000001;

const RTMR_INIT = Buffer.alloc(48, 0);

const eq = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && Buffer.from(a).equals(Buffer.from(b));

const normHex = (h: string): string => h.replace(/^0x/, "").toLowerCase();

/** Parse the dstack `event_log` (a JSON string, NOT hex — see B-7). */
export function parseEventLog(eventLogJson: string): EventLogEntry[] {
  const parsed = JSON.parse(eventLogJson) as unknown;
  if (!Array.isArray(parsed)) {
    throw new AttestationError(
      "event_log is not a JSON array",
      "event_log_invalid",
    );
  }
  return parsed as EventLogEntry[];
}

/**
 * The 48-byte digest an event extends into its RTMR. dstack runtime events
 * (app measurements) COMPUTE it as
 * `SHA-384( LE32(event_type) ‖ ":" ‖ event ‖ ":" ‖ payload )`
 * (`event_payload` hex-decoded to raw bytes); every other event carries a
 * pre-filled `digest`, padded up to 48 bytes. Mirrors dstack
 * `cc-eventlog::TdxEventLog::digest`.
 */
function eventDigest(e: EventLogEntry): Buffer {
  if (e.event_type === DSTACK_RUNTIME_EVENT_TYPE) {
    const t = Buffer.alloc(4);
    t.writeUInt32LE(e.event_type >>> 0, 0);
    return createHash("sha384")
      .update(
        Buffer.concat([
          t,
          Buffer.from(":"),
          Buffer.from(e.event, "utf8"),
          Buffer.from(":"),
          Buffer.from(normHex(e.event_payload), "hex"),
        ]),
      )
      .digest();
  }
  const d = Buffer.from(normHex(e.digest), "hex");
  if (d.length >= 48) return d;
  const padded = Buffer.alloc(48, 0); // dstack pads up, never truncates
  d.copy(padded);
  return padded;
}

/**
 * Replay a single RTMR from the event log, reproducing dstack's
 * `TdxEventLog::digest` + `replay_rtmr` byte-for-byte. Returns lowercase hex.
 */
export function replayEventLogRtmr(
  eventLog: EventLogEntry[],
  imr: number,
): string {
  const events = eventLog.filter((e) => e.imr === imr);
  if (events.length === 0) return RTMR_INIT.toString("hex");

  let mr: Buffer = RTMR_INIT;
  for (const e of events) {
    mr = createHash("sha384")
      .update(Buffer.concat([mr, eventDigest(e)]))
      .digest();
  }
  return mr.toString("hex");
}

/** The compose hash recorded in the RTMR3 event log, or `undefined` if absent. */
export function composeHashFromEventLog(
  eventLog: EventLogEntry[],
): string | undefined {
  const ev = eventLog.find(
    (e) => e.imr === 3 && e.event === COMPOSE_HASH_EVENT,
  );
  return ev ? normHex(ev.event_payload) : undefined;
}

/**
 * Concatenate the raw K-shard signer pubkeys (shard order) into the byte string
 * the quote's `report_data` right-half commits to. For a single-shard TEE this
 * is just the one pubkey.
 */
export function teeKeySetBytes(pubkeys: Uint8Array[]): Uint8Array {
  return Buffer.concat(pubkeys.map((p) => Buffer.from(p)));
}

/**
 * report_data binding: the verified quote must carry
 * `nonce ‖ SHA-256(pk_0 ‖ … ‖ pk_{K-1})`. `boundKeySetBytes` is the raw K-shard
 * pubkeys concatenated in shard order (see {@link teeKeySetBytes}); the TEE puts
 * SHA-256 of exactly those bytes in `report_data[32..64]`, so this binds the
 * ENTIRE settle-key set — not just shard 0 — to the verified quote. Returns the
 * failure kind, or `null` on success.
 */
export function checkReportDataBinding(
  reportData: Uint8Array,
  nonce: Uint8Array,
  boundKeySetBytes: Uint8Array,
): AttestationFailure | null {
  if (reportData.length !== 64) return "malformed";
  if (!eq(reportData.subarray(0, 32), nonce)) return "freshness";
  const expected = createHash("sha256")
    .update(Buffer.from(boundKeySetBytes))
    .digest();
  if (!eq(reportData.subarray(32, 64), expected)) return "binding";
  return null;
}

export interface VerifyReportOptions {
  /** The DCAP-verified quote report (from the node/web `dcap-qvl` adapter). */
  report: VerifiedQuoteReport;
  /** The parsed event log fetched alongside the quote. */
  eventLog: EventLogEntry[];
  /** The nonce this client sent in `reportData`. */
  nonce: Uint8Array;
  /** The raw K-shard signer pubkeys concatenated in shard order (the set the
   *  quote's report_data binds — see {@link teeKeySetBytes}). */
  boundKeySetBytes: Uint8Array;
  /** Base58 shard-0 (primary) signer pubkey (for the pin comparison). */
  teePubkeyBase58: string;
  /** Source-pinned expected measurements. */
  expected?: ExpectedMeasurements;
  /** Accepted TCB statuses. Defaults to {@link DEFAULT_TCB_ALLOWLIST}. */
  tcbAllowlist?: readonly string[];
  /** Strict mode requires compose_hash + tee_pubkey pins (secure-by-default). */
  strict: boolean;
}

/**
 * The full post-DCAP evaluation: TCB enforcement, report_data binding, event-log
 * → RTMR3 replay, compose-hash + MRTD + tee_pubkey pinning. Returns the first
 * failure kind, or `null` if the report is fully trusted.
 *
 * Precondition: `report` is the output of a *successful* `dcap-qvl` verification
 * (Intel signature + PCK chain + QE identity already checked). If DCAP itself
 * failed, the caller must have already thrown `quote_invalid` and never reach here.
 */
export function verifyReportAgainstExpected(
  opts: VerifyReportOptions,
): AttestationFailure | null {
  const { report, eventLog, nonce, boundKeySetBytes, teePubkeyBase58, strict } =
    opts;
  const expected = opts.expected ?? {};
  const tcbAllowlist = opts.tcbAllowlist ?? DEFAULT_TCB_ALLOWLIST;

  // 1. TCB status must be explicitly accepted (Jan-2026 dstack lesson: enforce,
  //    do not treat as informational).
  if (!tcbAllowlist.includes(report.tcbStatus)) return "tcb_outdated";

  // 2. report_data binds our nonce + the advertised signer key, and the value
  //    is the one embedded in the *verified* quote.
  const binding = checkReportDataBinding(
    report.reportData,
    nonce,
    boundKeySetBytes,
  );
  if (binding) return binding;

  // 3. Strict mode requires the governance pins — without them a "verified"
  //    quote proves only "some genuine TDX enclave", not OURS.
  if (strict && (!expected.composeHash || !expected.teePubkey)) {
    return "pin_required";
  }

  // 4. Event log must replay to the attested RTMR3 (proves it is THIS quote's
  //    log), then the compose hash is read from that now-trusted log.
  const replayed = replayEventLogRtmr(eventLog, 3);
  if (replayed !== normHex(report.rtmr3)) return "event_log_invalid";

  const composeHash = composeHashFromEventLog(eventLog);
  if (expected.composeHash) {
    if (!composeHash || composeHash !== normHex(expected.composeHash)) {
      return "compose_mismatch";
    }
  }

  // 5. Optional MRTD pin (dstack-OS image) against the verified quote's MRTD.
  if (expected.mrtd && normHex(expected.mrtd) !== normHex(report.mrtd)) {
    return "mrtd_mismatch";
  }

  // 6. tee_pubkey pin — the key that signs settle payloads.
  if (expected.teePubkey && expected.teePubkey !== teePubkeyBase58) {
    return "pubkey_mismatch";
  }

  return null;
}
