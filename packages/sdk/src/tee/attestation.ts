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
 * (`@nyx/daemon`), so the two clients cannot drift. It runs in the browser
 * because `@phala/dcap-qvl` is pure JS.
 */

import { randomBytes } from "node:crypto";
import { PublicKey } from "@solana/web3.js";

import {
  AttestationError,
  DEFAULT_TCB_ALLOWLIST,
  type ExpectedMeasurements,
  composeHashFromEventLog,
  parseEventLog,
  verifyReportAgainstExpected,
} from "./verify-core.js";
import { createDcapQuoteVerifier, type QuoteVerifier } from "./dcap.js";

/**
 * The compose hash of the audited, deployed `nyx-tee` image. **Committed in
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
}

export interface VerifyTeeAttestationOptions {
  /** Out-of-band expected shard-0 signer (e.g. from on-chain `vault_config`).
   *  If omitted, the attested key is used (compose-hash is the real anchor). */
  expectedTeePubkey?: string;
  /** Optional MRTD (dstack-OS) pin. */
  expectedMrtd?: string;
  /** Bearer token, if the gateway requires auth on `/attestation` + `/info`. */
  token?: string;
  /** Inject a verifier (tests); defaults to real DCAP via `@phala/dcap-qvl`. */
  quoteVerifier?: QuoteVerifier;
  /** PCCS endpoint override (pinned to Phala by default). */
  pccsUrl?: string;
  fetchImpl?: typeof fetch;
  /** Accepted TCB statuses. Defaults to {@link DEFAULT_TCB_ALLOWLIST}. */
  tcbAllowlist?: readonly string[];
}

const fromHex = (h: string): Uint8Array =>
  Uint8Array.from(Buffer.from(h.replace(/^0x/, ""), "hex"));

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
  opts: VerifyTeeAttestationOptions = {},
): Promise<TeeAttestation> {
  if (!expectedComposeHash) {
    throw new AttestationError(
      "expectedComposeHash is required — refusing to trust an unpinned build",
      "pin_required",
    );
  }
  const fetchImpl = opts.fetchImpl ?? fetch;
  const verifier =
    opts.quoteVerifier ?? createDcapQuoteVerifier({ pccsUrl: opts.pccsUrl });
  const nonce = Uint8Array.from(randomBytes(32));

  const attUrl = new URL("/attestation", apiBaseUrl);
  attUrl.searchParams.set("reportData", Buffer.from(nonce).toString("hex"));
  const att = await getJson<{
    quote: string;
    event_log: string;
    report_data: string;
    tee_pubkey: string;
  }>(attUrl.toString(), opts.token, fetchImpl);

  let pubkeyBytes: Uint8Array;
  try {
    pubkeyBytes = new PublicKey(att.tee_pubkey).toBytes();
  } catch {
    throw new AttestationError("tee_pubkey not valid base58", "malformed");
  }

  // Real Intel-TCB verification, then the shared post-DCAP checks.
  const report = await verifier(fromHex(att.quote));
  const eventLog = parseEventLog(att.event_log);
  const expected: ExpectedMeasurements = {
    composeHash: expectedComposeHash,
    teePubkey: opts.expectedTeePubkey ?? att.tee_pubkey,
    mrtd: opts.expectedMrtd,
  };
  const fail = verifyReportAgainstExpected({
    report,
    eventLog,
    nonce,
    teePubkeyBytes: pubkeyBytes,
    teePubkeyBase58: att.tee_pubkey,
    expected,
    tcbAllowlist: opts.tcbAllowlist ?? DEFAULT_TCB_ALLOWLIST,
    strict: true,
  });
  if (fail) throw new AttestationError(`attestation rejected: ${fail}`, fail);

  // /info is a convenience cross-check (tie shard-0 to the attestation) + the
  // full K-shard set the caller should reconcile with on-chain governance.
  const info = await getJson<{
    compose_hash: string;
    tee_pubkey: string;
    tee_pubkeys?: string[];
  }>(new URL("/info", apiBaseUrl).toString(), opts.token, fetchImpl);
  if (info.tee_pubkey !== att.tee_pubkey) {
    throw new AttestationError(
      "/info tee_pubkey != /attestation tee_pubkey",
      "pubkey_mismatch",
    );
  }

  const composeHash = composeHashFromEventLog(eventLog) ?? info.compose_hash;
  return {
    teePubkey: att.tee_pubkey,
    teePubkeys: info.tee_pubkeys ?? [att.tee_pubkey],
    composeHash,
    mrtd: report.mrtd,
    quote: att.quote,
  };
}
