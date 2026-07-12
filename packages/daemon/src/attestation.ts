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
  type VerifiedQuoteReport,
  DEFAULT_TCB_ALLOWLIST,
  checkReportDataBinding,
  composeHashFromEventLog,
  parseEventLog,
  verifyReportAgainstExpected,
} from "@nyx/sdk";

// Re-export the shared types so existing daemon imports (config.ts, daemon.ts)
// keep resolving through this module.
export {
  AttestationError,
  type AttestationFailure,
  type ExpectedMeasurements,
} from "@nyx/sdk";

const fromHex = (h: string): Uint8Array =>
  Uint8Array.from(Buffer.from(h.replace(/^0x/, ""), "hex"));

export interface TeeInfo {
  appId: string;
  composeHash: string;
  mrtd?: string;
  teePubkey: string; // base58
}

export interface AttestationQuote {
  quote: string; // hex TDX quote
  eventLog: string; // JSON string of measured events (NOT hex)
  reportData: string; // hex, 64 bytes
  teePubkey: string; // base58
}

export interface AttestationResult {
  teePubkey: string;
  composeHash: string;
  mrtd?: string;
  /** Raw hex quote (for an out-of-band audit). */
  quote: string;
  /** True when the result came from full DCAP verification (strict path). */
  dcapVerified: boolean;
}

/**
 * A real DCAP quote verifier: verifies the raw quote (Intel signature + PCK
 * chain + QE identity + TCB) and resolves the *verified* report, or throws
 * {@link AttestationError} (kind `quote_invalid`) on failure. See `./dcap.ts`.
 */
export type QuoteVerifier = (quote: Uint8Array) => Promise<VerifiedQuoteReport>;

async function getJson<T>(
  url: string,
  token: string,
  fetchImpl: typeof fetch,
): Promise<T> {
  let res: Response;
  try {
    res = await fetchImpl(url, {
      headers: { authorization: `Bearer ${token}` },
    });
  } catch (e) {
    throw new AttestationError(
      `attestation fetch failed: ${e instanceof Error ? e.message : e}`,
      "fetch",
    );
  }
  if (!res.ok) {
    throw new AttestationError(`${url} → ${res.status}`, "fetch");
  }
  return (await res.json()) as T;
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
  }>(new URL("/info", gatewayUrl).toString(), token, fetchImpl);
  return {
    appId: b.app_id,
    composeHash: b.compose_hash,
    mrtd: b.tcb_info?.mrtd ?? b.mrtd,
    teePubkey: b.tee_pubkey,
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

  let pubkeyBytes: Uint8Array;
  try {
    pubkeyBytes = new PublicKey(att.teePubkey).toBytes();
  } catch {
    throw new AttestationError("tee_pubkey not valid base58", "malformed");
  }

  if (strict) {
    if (!opts.quoteVerifier) {
      throw new AttestationError(
        "strict attestation requires a DCAP quote verifier (set NYX_DAEMON_SKIP_ATTEST=1 only for local simulator)",
        "quote_invalid",
      );
    }
    // 1. Real Intel-TCB verification of the raw quote. Throws quote_invalid on
    //    a bad signature / QE identity / expired TCB / a fabricated quote.
    const report = await opts.quoteVerifier(fromHex(att.quote));

    // 2. Post-DCAP checks over the *verified* report + event log.
    const eventLog = parseEventLog(att.eventLog);
    const fail = verifyReportAgainstExpected({
      report,
      eventLog,
      nonce,
      teePubkeyBytes: pubkeyBytes,
      teePubkeyBase58: att.teePubkey,
      expected: opts.expected,
      tcbAllowlist: opts.tcbAllowlist ?? DEFAULT_TCB_ALLOWLIST,
      strict: true,
    });
    if (fail) {
      throw new AttestationError(`attestation rejected: ${fail}`, fail);
    }

    // 3. /info is a convenience cross-check only — the authoritative compose
    //    hash comes from the attested event log, not this self-reported field.
    const info = await fetchInfo(opts.gatewayUrl, opts.token, fetchImpl);
    if (info.teePubkey !== att.teePubkey) {
      throw new AttestationError(
        "/info tee_pubkey != /attestation tee_pubkey",
        "pubkey_mismatch",
      );
    }
    const composeHash = composeHashFromEventLog(eventLog);
    return {
      teePubkey: att.teePubkey,
      composeHash: composeHash ?? info.composeHash,
      mrtd: report.mrtd,
      quote: att.quote,
      dcapVerified: true,
    };
  }

  // ── dev-partial (strict:false): NOT a security guarantee. ──
  // Legacy nonce + key-binding + self-reported /info pins. Defeats replay and
  // key-substitution against an honest enclave, but NOT a malicious operator.
  const binding = checkReportDataBinding(
    fromHex(att.reportData),
    nonce,
    pubkeyBytes,
  );
  if (binding) {
    throw new AttestationError(`report_data ${binding}`, binding);
  }
  const info = await fetchInfo(opts.gatewayUrl, opts.token, fetchImpl);
  if (info.teePubkey !== att.teePubkey) {
    throw new AttestationError(
      "/info tee_pubkey != /attestation tee_pubkey",
      "pubkey_mismatch",
    );
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
    composeHash: info.composeHash,
    mrtd: info.mrtd,
    quote: att.quote,
    dcapVerified: false,
  };
}
