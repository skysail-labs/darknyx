/**
 * Attestation-on-connect — the non-custody trust anchor.
 *
 * Before trading, the daemon verifies the gateway it's about to send order flow
 * to is the TEE it expects. The TEE exposes `GET /attestation` (a TDX quote
 * whose `report_data` binds a caller nonce + the signer key) and `GET /info`
 * (the `compose_hash` + `mrtd` measurements + `tee_pubkey`). This module checks,
 * client-side:
 *
 *   1. **Freshness** — `report_data[0..32]` echoes our random nonce (the quote
 *      was produced for THIS request, not replayed).
 *   2. **Key binding** — `report_data[32..64] == SHA-256(tee_pubkey bytes)`, so
 *      the quote commits to the same Ed25519 key that signs settle payloads
 *      (the TEE decodes the base58 `tee_pubkey` → 32 bytes → SHA-256).
 *   3. **Pinned measurements** — `compose_hash` / `mrtd` / `tee_pubkey` match the
 *      operator-vetted expected values (the "I audited this exact CVM build"
 *      check).
 *
 * HONEST LIMIT: without a DCAP verifier (`dcap-qvl` is Rust) this does NOT verify
 * Intel's signature over the quote. The binding + nonce defeat key-substitution
 * and replay; pinning defeats a wrong build. For full TCB verification, inject a
 * {@link QuoteVerifier} (a real DCAP backend) — the raw quote is handed to it.
 */

import { createHash, randomBytes } from "node:crypto";
import { PublicKey } from "@solana/web3.js";

const fromHex = (h: string): Uint8Array =>
  Uint8Array.from(Buffer.from(h.replace(/^0x/, ""), "hex"));
const sha256 = (b: Uint8Array): Uint8Array =>
  Uint8Array.from(createHash("sha256").update(b).digest());
const eq = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && Buffer.from(a).equals(Buffer.from(b));

export interface TeeInfo {
  appId: string;
  composeHash: string;
  mrtd?: string;
  teePubkey: string; // base58
}

export interface AttestationQuote {
  quote: string; // hex TDX quote
  reportData: string; // hex, 64 bytes
  teePubkey: string; // base58
}

/** Operator-pinned values the gateway MUST match (any subset). */
export interface ExpectedMeasurements {
  composeHash?: string;
  mrtd?: string;
  teePubkey?: string; // base58
}

export interface AttestationResult {
  teePubkey: string;
  composeHash: string;
  mrtd?: string;
  /** Raw hex quote (for an out-of-band DCAP audit). */
  quote: string;
}

export type AttestationFailure =
  | "fetch"
  | "malformed"
  | "freshness"
  | "binding"
  | "pubkey_mismatch"
  | "compose_mismatch"
  | "mrtd_mismatch"
  | "quote_invalid";

export class AttestationError extends Error {
  constructor(
    message: string,
    readonly kind: AttestationFailure,
  ) {
    super(message);
    this.name = "AttestationError";
  }
}

/** A real DCAP quote verifier (Intel TCB). Resolves true iff the quote is valid. */
export type QuoteVerifier = (
  quote: Uint8Array,
  reportData: Uint8Array,
) => Promise<boolean>;

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
    mrtd?: string;
    tee_pubkey: string;
  }>(new URL("/info", gatewayUrl).toString(), token, fetchImpl);
  return {
    appId: b.app_id,
    composeHash: b.compose_hash,
    mrtd: b.mrtd,
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
  url.searchParams.set("report_data", Buffer.from(nonce).toString("hex"));
  const b = await getJson<{
    quote: string;
    report_data: string;
    tee_pubkey: string;
  }>(url.toString(), token, fetchImpl);
  return { quote: b.quote, reportData: b.report_data, teePubkey: b.tee_pubkey };
}

/**
 * Fetch + verify the gateway's attestation. Throws {@link AttestationError} on
 * any failure (the daemon refuses to trade). Returns the verified identity.
 */
export async function verifyAttestation(opts: {
  gatewayUrl: string;
  token: string;
  expected?: ExpectedMeasurements;
  quoteVerifier?: QuoteVerifier;
  fetchImpl?: typeof fetch;
}): Promise<AttestationResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const nonce = Uint8Array.from(randomBytes(32));

  const att = await fetchAttestation(
    opts.gatewayUrl,
    opts.token,
    nonce,
    fetchImpl,
  );
  const reportData = fromHex(att.reportData);
  if (reportData.length !== 64) {
    throw new AttestationError(
      `report_data is ${reportData.length} bytes; expected 64`,
      "malformed",
    );
  }

  // 1. Freshness — our nonce sits in the left half.
  if (!eq(reportData.subarray(0, 32), nonce)) {
    throw new AttestationError("report_data nonce mismatch", "freshness");
  }

  // 2. Key binding — right half == SHA-256(tee_pubkey bytes).
  let pubkeyBytes: Uint8Array;
  try {
    pubkeyBytes = new PublicKey(att.teePubkey).toBytes();
  } catch {
    throw new AttestationError("tee_pubkey not valid base58", "malformed");
  }
  if (!eq(reportData.subarray(32, 64), sha256(pubkeyBytes))) {
    throw new AttestationError("report_data key binding mismatch", "binding");
  }

  // 3. Pinned measurements (+ /info consistency).
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

  // 4. Optional full DCAP verification (Intel TCB).
  if (opts.quoteVerifier) {
    const ok = await opts.quoteVerifier(fromHex(att.quote), reportData);
    if (!ok) {
      throw new AttestationError(
        "DCAP quote verification failed",
        "quote_invalid",
      );
    }
  }

  return {
    teePubkey: att.teePubkey,
    composeHash: info.composeHash,
    mrtd: info.mrtd,
    quote: att.quote,
  };
}
