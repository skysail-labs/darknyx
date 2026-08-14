/**
 * Real Intel-TCB DCAP quote verifier — shared by the node daemon and the
 * browser SDK (the pure-JS `@phala/dcap-qvl` runs in both).
 *
 * We deliberately use the pure-JS package, NOT the WASM `@phala/dcap-qvl-node`/
 * `-web` builds: per GHSA-796p-j2gh-9m2q / CVE-2026-22696 the WASM builds are
 * unpatched (<= 0.3.3, no QE-identity verification); Phala's guidance is to use
 * `@phala/dcap-qvl` (patched in 0.3.9 — QE-identity signature + MRSIGNER /
 * ISVPRODID / ISVSVN enforcement).
 *
 * `getCollateralAndVerify` fetches the quote's collateral from Phala's PCCS and
 * runs the full Intel verification (signature + PCK chain + QE identity + TCB).
 * It THROWS on any failure — surfaced as `quote_invalid`. On success the
 * `VerifiedReport` is mapped into the environment-agnostic
 * {@link VerifiedQuoteReport}, which `verify-core` then checks.
 */

import {
  getCollateralAndVerify,
  PHALA_PCCS_URL,
  type VerifiedReport,
} from "@phala/dcap-qvl";

import { AttestationError, type VerifiedQuoteReport } from "./verify-core.js";

/**
 * Verify a raw TDX quote and resolve the mapped report, or throw
 * {@link AttestationError} (kind `quote_invalid`) if Intel verification fails.
 */
export type QuoteVerifier = (quote: Uint8Array) => Promise<VerifiedQuoteReport>;

const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
const errMsg = (e: unknown): string =>
  e instanceof Error ? e.message : String(e);

export interface DcapVerifierOptions {
  /** PCCS endpoint. Pinned to Phala's PCCS by default — never taken from any
   *  gateway-controlled input (SSRF guard, per the Jan-2026 dstack hardening). */
  pccsUrl?: string;
}

export function createDcapQuoteVerifier(
  opts: DcapVerifierOptions = {},
): QuoteVerifier {
  const pccsUrl = opts.pccsUrl ?? PHALA_PCCS_URL;

  return async (quote: Uint8Array): Promise<VerifiedQuoteReport> => {
    let verified: VerifiedReport;
    try {
      verified = await getCollateralAndVerify(quote, pccsUrl);
    } catch (e) {
      throw new AttestationError(
        `dcap verification failed: ${errMsg(e)}`,
        "quote_invalid",
      );
    }

    // dstack TDX quotes are TD10; TD15 carries the same measurements under `base`.
    const td = verified.report.asTd10() ?? verified.report.asTd15()?.base;
    if (!td) {
      throw new AttestationError(
        "attested quote is not a TDX report (no TD10/TD15 body)",
        "quote_invalid",
      );
    }

    return {
      reportData: td.reportData,
      mrtd: toHex(td.mrTd),
      rtmr0: toHex(td.rtMr0),
      rtmr1: toHex(td.rtMr1),
      rtmr2: toHex(td.rtMr2),
      rtmr3: toHex(td.rtMr3),
      tcbStatus: verified.status,
      advisoryIds: verified.advisory_ids ?? [],
    };
  };
}
