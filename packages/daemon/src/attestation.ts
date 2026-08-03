/**
 * Attestation-on-connect — the non-custody trust anchor.
 *
 * Before trading, the daemon proves the gateway it is about to send order flow
 * to is a genuine Intel TDX enclave running our audited build — not a normal
 * server that fabricates JSON. It does this client-side:
 *
 *   1. Fetch `GET /attestation?reportData=<nonce>` → a fresh TDX quote whose
 *      `report_data = nonce ‖ SHA-256(tee_pubkey)`, plus the `event_log`.
 *   2. **Real DCAP** (`quoteVerifier`, backed by `@phala/dcap-qvl`): verify
 *      Intel's signature + PCK chain + QE identity + TCB status over the quote.
 *   3. Hand the *verified* report to the SDK's `verify-core`, which enforces the
 *      TCB allowlist, the `report_data` binding, replays the event log to bind
 *      RTMR3, reads the `compose-hash` from that now-trusted log, and matches it
 *      (+ optional MRTD + tee_pubkey) against source-pinned expected values.
 *
 * **Strict mode (default):** trading requires a working DCAP verifier AND the
 * governance pins (`compose_hash` + `tee_pubkey`). Without DCAP, every field the
 * client inspects is self-reported by the gateway (audit_2 finding A-1). Set
 * `strict: false` ONLY for local dstack-simulator dev (its stub quotes cannot be
 * DCAP-verified by design); it downgrades to the legacy nonce+binding+`/info`
 * pin check, which is NOT a security guarantee against a malicious operator.
 */

import { randomBytes } from "node:crypto";
import { PublicKey } from "@solana/web3.js";
import {
  AttestationError,
  type AttestationFailure,
  type ExpectedMeasurements,
  type QuoteVerifier,
  DEFAULT_TCB_ALLOWLIST,
  checkReportDataBinding,
  composeHashFromEventLog,
  parseEventLog,
  teeKeySetBytes,
  verifyReportAgainstExpected,
} from "@darknyx/sdk";

// Re-export the shared types so existing daemon imports (config.ts, daemon.ts,
// bin/daemon.ts) keep resolving through this module. QuoteVerifier +
// createDcapQuoteVerifier now live in the SDK (shared with the browser client).
export {
  AttestationError,
  type AttestationFailure,
  type ExpectedMeasurements,
  type QuoteVerifier,
} from "@darknyx/sdk";

const fromHex = (h: string): Uint8Array =>
  Uint8Array.from(Buffer.from(h.replace(/^0x/, ""), "hex"));

export interface TeeInfo {
  appId: string;
  composeHash: string;
  mrtd?: string;
  teePubkey: string; // base58 (shard-0 primary)
  teePubkeys: string[]; // full K-shard set, shard order
  bootSessionId: string; // 32-byte hex, fresh per CVM boot
}

export interface AttestationQuote {
  quote: string; // hex TDX quote
  eventLog: string; // JSON string of measured events (NOT hex)
  reportData: string; // hex, 64 bytes
  teePubkey: string; // base58
}

export interface AttestationResult {
  teePubkey: string;
  /** The full K-shard signer set, bound to the quote (strict) / from /info. */
  teePubkeys: string[];
  composeHash: string;
  mrtd?: string;
  /** Raw hex quote (for an out-of-band audit). */
  quote: string;
  /** True when the result came from full DCAP verification (strict path). */
  dcapVerified: boolean;
  /**
   * 32-byte boot-session id, hex — the S-07 session scope signed into every
   * order and cancel.
   *
   * **NOT ATTESTED (SW-18).** Every other field on this object is either
   * DCAP-derived or quote-bound; this one is read from the unauthenticated
   * `/info` and simply carried alongside `dcapVerified: true`. The quote's
   * `report_data` is `nonce ‖ SHA-256(signer_set)` and is FULL at 64 bytes, so
   * there is no room to bind the session without changing what `report_data`
   * commits to (the reason T-03 stayed deferred).
   *
   * The ceiling is low and worth stating so nobody over-reacts to this comment:
   * the TEE validates the session at intake, so a gateway serving a WRONG value
   * causes rejections — a denial of service it could achieve by simply not
   * answering — and cannot cause a STALE session to be accepted. The structural
   * point is only that S-07's scoping rests on a field attestation does not
   * cover, and a reader should not infer otherwise from its neighbours.
   */
  bootSessionId: string;
}

/**
 * Bound every read of the gateway (SW-17).
 *
 * This is the one module whose stated premise is that the peer may be "a normal
 * server that fabricates JSON" — it is the code deciding whether to trust the
 * gateway at all, so it must not assume the gateway is well-behaved while
 * asking that question. Two limits, both absent before:
 *
 * * **A deadline.** Without one, a gateway that accepts the connection and then
 *   stalls hangs `Daemon.start()` forever, with no diagnostic and no timeout to
 *   distinguish "slow" from "hung".
 * * **A size cap.** `res.json()` buffers whatever arrives, and the `event_log`
 *   it returns is then walked by `parseEventLog` -> `replayEventLogRtmr`. An
 *   unbounded body is memory exhaustion before a single measurement is checked.
 */
const ATTESTATION_TIMEOUT_MS = 15_000;
/** Generous for a real quote + event log (the observed CVM log is ~30 entries). */
const ATTESTATION_MAX_BYTES = 4 * 1024 * 1024;

async function getJson<T>(
  url: string,
  token: string,
  fetchImpl: typeof fetch,
): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ATTESTATION_TIMEOUT_MS);
  let res: Response;
  try {
    res = await fetchImpl(url, {
      headers: { authorization: `Bearer ${token}` },
      signal: controller.signal,
    });
  } catch (e) {
    const aborted = controller.signal.aborted;
    throw new AttestationError(
      aborted
        ? `attestation fetch timed out after ${ATTESTATION_TIMEOUT_MS}ms`
        : `attestation fetch failed: ${e instanceof Error ? e.message : e}`,
      "fetch",
    );
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) {
    throw new AttestationError(`${url} → ${res.status}`, "fetch");
  }

  // Trust `content-length` only to reject early; a lying or absent header is
  // still caught by measuring the body we actually read.
  const declared = Number(res.headers.get("content-length") ?? "0");
  if (Number.isFinite(declared) && declared > ATTESTATION_MAX_BYTES) {
    throw new AttestationError(
      `attestation response too large (${declared} bytes)`,
      "malformed",
    );
  }
  const text = await res.text();
  if (text.length > ATTESTATION_MAX_BYTES) {
    throw new AttestationError(
      `attestation response too large (${text.length} bytes)`,
      "malformed",
    );
  }
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new AttestationError("attestation response is not JSON", "malformed");
  }
}

export async function fetchInfo(
  gatewayUrl: string,
  token: string,
  fetchImpl: typeof fetch = fetch,
): Promise<TeeInfo> {
  const b = await getJson<{
    app_id: string;
    compose_hash: string;
    // B-1: the server nests mrtd under `tcb_info`. We read that; the legacy
    // top-level `mrtd` is accepted as a forward-compat fallback.
    tcb_info?: { mrtd?: string };
    mrtd?: string;
    tee_pubkey: string;
    tee_pubkeys?: string[];
    boot_session_id: string;
  }>(new URL("/info", gatewayUrl).toString(), token, fetchImpl);
  if (!/^[0-9a-fA-F]{64}$/.test(b.boot_session_id)) {
    throw new AttestationError("invalid /info boot_session_id", "malformed");
  }
  return {
    appId: b.app_id,
    composeHash: b.compose_hash,
    mrtd: b.tcb_info?.mrtd ?? b.mrtd,
    teePubkey: b.tee_pubkey,
    teePubkeys: b.tee_pubkeys ?? [b.tee_pubkey],
    bootSessionId: b.boot_session_id,
  };
}

export async function fetchAttestation(
  gatewayUrl: string,
  token: string,
  nonce: Uint8Array,
  fetchImpl: typeof fetch = fetch,
): Promise<AttestationQuote> {
  const url = new URL("/attestation", gatewayUrl);
  // The TEE query param is camelCase `reportData` (serde rename); the response
  // field is snake `report_data`. Sending the wrong name → the nonce is ignored
  // (zero-filled) → the freshness check fails.
  url.searchParams.set("reportData", Buffer.from(nonce).toString("hex"));
  const b = await getJson<{
    quote: string;
    event_log: string;
    report_data: string;
    tee_pubkey: string;
  }>(url.toString(), token, fetchImpl);
  return {
    quote: b.quote,
    eventLog: b.event_log,
    reportData: b.report_data,
    teePubkey: b.tee_pubkey,
  };
}

export interface VerifyAttestationOptions {
  gatewayUrl: string;
  token: string;
  expected?: ExpectedMeasurements;
  quoteVerifier?: QuoteVerifier;
  fetchImpl?: typeof fetch;
  /** Require real DCAP + governance pins. Defaults to true (secure-by-default). */
  strict?: boolean;
  /** Accepted TCB statuses. Defaults to {@link DEFAULT_TCB_ALLOWLIST}. */
  tcbAllowlist?: readonly string[];
}

/**
 * Fetch + verify the gateway's attestation. Throws {@link AttestationError} on
 * any failure (the daemon then refuses to trade). Returns the verified identity.
 */
export async function verifyAttestation(
  opts: VerifyAttestationOptions,
): Promise<AttestationResult> {
  const strict = opts.strict ?? true;
  const fetchImpl = opts.fetchImpl ?? fetch;
  const nonce = Uint8Array.from(randomBytes(32));

  const att = await fetchAttestation(
    opts.gatewayUrl,
    opts.token,
    nonce,
    fetchImpl,
  );
  // /info gives the full K-shard set the quote's report_data binds. Fetch it up
  // front (both paths need it), and tie shard 0 to the attestation.
  const info = await fetchInfo(opts.gatewayUrl, opts.token, fetchImpl);
  if (info.teePubkey !== att.teePubkey) {
    throw new AttestationError(
      "/info tee_pubkey != /attestation tee_pubkey",
      "pubkey_mismatch",
    );
  }
  const teePubkeys = info.teePubkeys.length ? info.teePubkeys : [att.teePubkey];
  if (teePubkeys[0] !== att.teePubkey) {
    throw new AttestationError(
      "/info tee_pubkeys[0] != /attestation tee_pubkey (shard-0 mismatch)",
      "pubkey_mismatch",
    );
  }
  let boundKeySetBytes: Uint8Array;
  try {
    boundKeySetBytes = teeKeySetBytes(
      teePubkeys.map((k) => new PublicKey(k).toBytes()),
    );
  } catch {
    throw new AttestationError("tee_pubkeys not all valid base58", "malformed");
  }

  if (strict) {
    if (!opts.quoteVerifier) {
      throw new AttestationError(
        "strict attestation requires a DCAP quote verifier (set DARKNYX_DAEMON_SKIP_ATTEST=1 only for local simulator)",
        "quote_invalid",
      );
    }
    // 1. Real Intel-TCB verification of the raw quote. Throws quote_invalid on
    //    a bad signature / QE identity / expired TCB / a fabricated quote.
    const report = await opts.quoteVerifier(fromHex(att.quote));

    // 2. Post-DCAP checks over the *verified* report + event log. The binding
    //    covers the WHOLE K-shard set, so /info.tee_pubkeys is now quote-bound.
    const eventLog = parseEventLog(att.eventLog);
    const fail = verifyReportAgainstExpected({
      report,
      eventLog,
      nonce,
      boundKeySetBytes,
      teePubkeyBase58: att.teePubkey,
      expected: opts.expected,
      tcbAllowlist: opts.tcbAllowlist ?? DEFAULT_TCB_ALLOWLIST,
      strict: true,
    });
    if (fail) {
      throw new AttestationError(`attestation rejected: ${fail}`, fail);
    }

    // No `?? info.composeHash` fallback. It was unreachable on this path — the
    // strict check above already required a non-undefined, pin-matching
    // log-derived hash — but it modelled the SELF-REPORTED value as an
    // acceptable substitute for the attested one, which is the exact
    // substitution attestation exists to reject.
    const composeHash = composeHashFromEventLog(eventLog);
    if (!composeHash) {
      throw new AttestationError(
        "compose hash absent from the verified event log after a passing strict check",
        "event_log_invalid",
      );
    }
    return {
      teePubkey: att.teePubkey,
      teePubkeys,
      composeHash,
      mrtd: report.mrtd,
      quote: att.quote,
      dcapVerified: true,
      bootSessionId: info.bootSessionId,
    };
  }

  // ── dev-partial (strict:false): NOT a security guarantee. ──
  // Legacy nonce + key-set-binding + self-reported /info pins. Defeats replay
  // and key-substitution against an honest enclave, but NOT a malicious operator.
  const binding = checkReportDataBinding(
    fromHex(att.reportData),
    nonce,
    boundKeySetBytes,
  );
  if (binding) {
    throw new AttestationError(`report_data ${binding}`, binding);
  }
  const exp = opts.expected;
  if (exp?.teePubkey && exp.teePubkey !== att.teePubkey) {
    throw new AttestationError("tee_pubkey != expected", "pubkey_mismatch");
  }
  if (exp?.composeHash && exp.composeHash !== info.composeHash) {
    throw new AttestationError("compose_hash != expected", "compose_mismatch");
  }
  if (exp?.mrtd && exp.mrtd !== info.mrtd) {
    throw new AttestationError("mrtd != expected", "mrtd_mismatch");
  }
  return {
    teePubkey: att.teePubkey,
    teePubkeys,
    composeHash: info.composeHash,
    mrtd: info.mrtd,
    quote: att.quote,
    dcapVerified: false,
    bootSessionId: info.bootSessionId,
  };
}
