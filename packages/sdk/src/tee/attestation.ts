/**
 * `verifyTeeAttestation` — the browser/SDK client's non-custody trust anchor.
 *
 * Implements the design in `docs/tee-attestation-flow.md` §4.3 with REAL DCAP:
 * fetch a fresh TDX quote from `GET /attestation`, verify Intel's signature +
 * PCK chain + QE identity + TCB with the pure-JS `@phala/dcap-qvl`, then run the
 * shared {@link verifyReportAgainstExpected} — report_data binding, event-log
 * RTMR3 replay, and compose-hash pinning against `expectedComposeHash`. Throws
 * {@link AttestationError} on any failure; a client must refuse to trade.
 *
 * This shares the exact verification core with the node daemon
 * (`@darknyx/daemon`), so the two clients cannot drift. It runs in the browser
 * because `@phala/dcap-qvl` is pure JS.
 */

import { PublicKey } from "@solana/web3.js";

import { apiUrl } from "../api-url.js";
import {
  AttestationError,
  DEFAULT_TCB_ALLOWLIST,
  type ExpectedMeasurements,
  composeHashFromEventLog,
  parseEventLog,
  teeKeySetBytes,
  verifyReportAgainstExpected,
} from "./verify-core.js";
import { createDcapQuoteVerifier, type QuoteVerifier } from "./dcap.js";

/**
 * The compose hash of the audited, deployed `darknyx-tee` image. **Committed in
 * source and bumped in lockstep with the Docker image tag** — that is how a
 * client knows exactly which build it is trusting. Empty until the first
 * mainnet/devnet image is pinned; pass an explicit value to
 * {@link verifyTeeAttestation} until then. NEVER read the expected hash from the
 * gateway.
 */
export const EXPECTED_COMPOSE_HASH = "";

export interface TeeAttestation {
  /** The shard-0 (primary) TEE Ed25519 signer, base58. */
  teePubkey: string;
  /** The full K-shard signer set the vault trusts (base58, shard order). */
  teePubkeys: string[];
  /** Compose hash read from the DCAP-verified RTMR3 event log. */
  composeHash: string;
  /** MRTD (dstack-OS) from the verified quote, hex. */
  mrtd: string;
  /** Raw hex quote, for an out-of-band audit. */
  quote: string;
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

export interface VerifyTeeAttestationOptions {
  /** Out-of-band expected shard-0 signer, sourced from on-chain
   *  `vault_config.tee_pubkeys` — **required**, because this is a strict-mode
   *  verification and a pin the caller does not supply is not a pin.
   *
   *  This used to fall back to the attested key when omitted, which made step 7
   *  compare that key against itself: a comparison that could never fail, in a
   *  mode whose `pin_required` guard the same fallback also made unreachable.
   *  Nothing was exploitable — `report_data` binds the whole K-shard set to the
   *  quote, so no key can be substituted — but strict mode read as though it
   *  enforced two governance pins while enforcing one. Omitting it now returns
   *  `pin_required` rather than silently passing. */
  expectedTeePubkey?: string;
  /** Optional MRTD (dstack-OS) pin. */
  expectedMrtd?: string;
  /** Bearer token, if the gateway requires auth on `/attestation` + `/info`. */
  token?: string;
  /** Inject a verifier (tests); defaults to real DCAP via `@phala/dcap-qvl`. */
  quoteVerifier?: QuoteVerifier;
  /** PCCS endpoint override (pinned to Phala by default). */
  pccsUrl?: string;
  /**
   * REQUIRED. The transport this call must use.
   *
   * Not optional and not defaulted: an omitted `fetchImpl` used to fall back
   * to `globalThis.fetch`, which silently bypasses the verified transport.
   * Seven call sites did exactly that, each looking correct, and each only
   * surfaced during a billable live CVM run. Making it required converts every
   * one of those into a compile error.
   *
   * Browser and legacy callers pass `globalThis.fetch` explicitly — a
   * statement of intent rather than an accident.
   */
  fetchImpl: typeof fetch;
  /** Accepted TCB statuses. Defaults to {@link DEFAULT_TCB_ALLOWLIST}. */
  tcbAllowlist?: readonly string[];
}

const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

const fromHex = (value: string): Uint8Array => {
  const hex = value.replace(/^0x/, "");
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new AttestationError("malformed attestation hex", "malformed");
  }
  return Uint8Array.from(hex.match(/../g) ?? [], (byte) =>
    Number.parseInt(byte, 16),
  );
};

async function getJson<T>(
  url: string,
  token: string | undefined,
  fetchImpl: typeof fetch,
): Promise<T> {
  let res: Response;
  const headers: Record<string, string> = token
    ? { authorization: `Bearer ${token}` }
    : {};
  try {
    res = await fetchImpl(url, { headers });
  } catch (e) {
    throw new AttestationError(
      `attestation fetch failed: ${e instanceof Error ? e.message : e}`,
      "fetch",
    );
  }
  if (!res.ok) throw new AttestationError(`${url} → ${res.status}`, "fetch");
  return (await res.json()) as T;
}

/**
 * Fetch + fully verify the gateway's TEE attestation. Returns the verified
 * identity, or throws {@link AttestationError}.
 */
export async function verifyTeeAttestation(
  apiBaseUrl: string,
  expectedComposeHash: string,
  // No `= {}` default: `fetchImpl` is required, so an empty object is not a
  // valid options value and the caller must state its transport.
  opts: VerifyTeeAttestationOptions,
): Promise<TeeAttestation> {
  if (!expectedComposeHash) {
    throw new AttestationError(
      "expectedComposeHash is required — refusing to trust an unpinned build",
      "pin_required",
    );
  }
  const fetchImpl = opts.fetchImpl;
  const verifier =
    opts.quoteVerifier ?? createDcapQuoteVerifier({ pccsUrl: opts.pccsUrl });
  const nonce = crypto.getRandomValues(new Uint8Array(32));

  const attUrl = apiUrl(apiBaseUrl, "attestation");
  attUrl.searchParams.set("reportData", toHex(nonce));
  const att = await getJson<{
    quote: string;
    event_log: string;
    report_data: string;
    tee_pubkey: string;
  }>(attUrl.toString(), opts.token, fetchImpl);

  // /info gives the full K-shard set the quote's report_data binds. Fetch it up
  // front, tie shard 0 to the attestation, and build the bound key-set bytes.
  const info = await getJson<{
    compose_hash: string;
    tee_pubkey: string;
    tee_pubkeys?: string[];
    boot_session_id: string;
  }>(apiUrl(apiBaseUrl, "info").toString(), opts.token, fetchImpl);
  if (info.tee_pubkey !== att.tee_pubkey) {
    throw new AttestationError(
      "/info tee_pubkey != /attestation tee_pubkey",
      "pubkey_mismatch",
    );
  }
  const teePubkeys = info.tee_pubkeys?.length
    ? info.tee_pubkeys
    : [att.tee_pubkey];
  if (teePubkeys[0] !== att.tee_pubkey) {
    throw new AttestationError(
      "/info tee_pubkeys[0] != /attestation tee_pubkey (shard-0 mismatch)",
      "pubkey_mismatch",
    );
  }
  if (!/^[0-9a-fA-F]{64}$/.test(info.boot_session_id)) {
    throw new AttestationError("invalid /info boot_session_id", "malformed");
  }
  let boundKeySetBytes: Uint8Array;
  try {
    boundKeySetBytes = teeKeySetBytes(
      teePubkeys.map((k) => new PublicKey(k).toBytes()),
    );
  } catch {
    throw new AttestationError("tee_pubkeys not all valid base58", "malformed");
  }

  // Real Intel-TCB verification, then the shared post-DCAP checks (the binding
  // covers the WHOLE K-shard set, so /info.tee_pubkeys is now quote-bound).
  const report = await verifier(fromHex(att.quote));
  const eventLog = parseEventLog(att.event_log);
  const expected: ExpectedMeasurements = {
    composeHash: expectedComposeHash,
    // No `?? att.tee_pubkey` — that compared the attested key against itself.
    teePubkey: opts.expectedTeePubkey,
    mrtd: opts.expectedMrtd,
  };
  const fail = verifyReportAgainstExpected({
    report,
    eventLog,
    nonce,
    boundKeySetBytes,
    teePubkeyBase58: att.tee_pubkey,
    expected,
    tcbAllowlist: opts.tcbAllowlist ?? DEFAULT_TCB_ALLOWLIST,
    strict: true,
  });
  if (fail) throw new AttestationError(`attestation rejected: ${fail}`, fail);

  // No `?? info.compose_hash` fallback. It was unreachable — the strict check
  // above already required a non-undefined, pin-matching log-derived hash — but
  // it modelled the SELF-REPORTED value as an acceptable substitute for the
  // attested one, which is the exact substitution this module exists to reject.
  const composeHash = composeHashFromEventLog(eventLog);
  if (!composeHash) {
    throw new AttestationError(
      "compose hash absent from the verified event log after a passing strict check",
      "event_log_invalid",
    );
  }
  return {
    teePubkey: att.tee_pubkey,
    teePubkeys,
    composeHash,
    mrtd: report.mrtd,
    quote: att.quote,
    bootSessionId: info.boot_session_id,
  };
}
