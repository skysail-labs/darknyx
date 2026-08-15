/**
 * `TransportAttestationManifestV1` — TypeScript mirror of
 * `crates/darknyx-tee/src/transport/manifest.rs`.
 *
 * # What it is for
 *
 * `/attestation` proves an enclave with a given signer set is alive. It does
 * not prove that the TLS connection carrying your orders terminates at that
 * enclave — a party able to terminate TLS can relay a genuine quote while
 * routing traffic elsewhere. This manifest closes that by committing the
 * served certificate's public key into an attested value.
 *
 * # Two implementations, one pinned vector
 *
 * This is a deliberate re-implementation, not a port: the SDK does not depend
 * on the TEE crate. Both sides are pinned by the same fixed vector
 * (`FIXED_VECTOR_DIGEST`), the pattern `canonicalPayloadHash` already uses. A
 * drift in either language fails both suites. Change the encoding here and you
 * must change `manifest.rs` in the same commit.
 *
 * # Layout
 *
 * ```text
 * report_data[0..32]  = caller nonce (exactly 32 bytes)
 * report_data[32..64] = SHA-256(DOMAIN ‖ canonicalBytes())
 *
 * canonicalBytes() — 164 bytes, every field fixed-width:
 *   [  0..  2] protocolVersion   u16 big-endian
 *   [  2..  3] transportMode     u8
 *   [  3..  4] reserved          u8 (MUST be 0)
 *   [  4.. 36] sha256(appId)
 *   [ 36.. 68] sha256(instanceId)
 *   [ 68..100] bootSessionId
 *   [100..132] tlsSpkiSha256
 *   [132..164] signerSetSha256
 * ```
 *
 * `signerSetSha256` is inside the manifest on purpose: a client must not verify
 * a transport quote and an `/attestation` quote separately and infer they came
 * from the same enclave. That inference is what a relay exploits.
 *
 * The compose hash is deliberately absent — it stays in the quote's event log,
 * replayed against RTMR3 (`verify-core.ts`). A manifest field would be a
 * self-report; the event log is not.
 */

import { sha256 } from "@noble/hashes/sha2";

/** Domain separation tag. Bump with `PROTOCOL_VERSION`, never alone. */
export const DOMAIN = new TextEncoder().encode(
  "darknyx/transport-attestation/v1",
);

/** Wire version. Bump with `DOMAIN`, never alone. */
export const PROTOCOL_VERSION = 1;

/** Length of `canonicalBytes()`. Asserted in tests. */
export const CANONICAL_LEN = 164;

/** How the client reaches the enclave. Mirrors the Rust `TransportMode`. */
export enum TransportMode {
  /** TLS terminated inside the enclave with a boot-random key. */
  RaTls = 1,
  /** TLS terminated by the dstack gateway — the legacy path. */
  GatewayTerminated = 2,
}

export interface TransportManifestInput {
  transportMode: TransportMode;
  /** Raw dstack `app_id` bytes (hashed into the manifest). */
  appId: Uint8Array;
  /** Raw dstack `instance_id` bytes (hashed into the manifest). */
  instanceId: Uint8Array;
  bootSessionId: Uint8Array;
  tlsSpkiSha256: Uint8Array;
  signerSetSha256: Uint8Array;
  /** Defaults to `PROTOCOL_VERSION`; settable so tests can pin drift. */
  protocolVersion?: number;
}

function fixed32(value: Uint8Array, field: string): Uint8Array {
  if (value.length !== 32) {
    throw new Error(`${field} must be exactly 32 bytes, got ${value.length}`);
  }
  return value;
}

/**
 * A manifest whose variable-length identifiers are **already hashed**.
 *
 * A verifier only ever receives the hashed forms — the raw `app_id` and
 * `instance_id` never cross the wire — so it cannot use
 * {@link TransportManifestInput}, which would hash them a second time and
 * silently never match.
 */
export interface TransportManifestHashed {
  transportMode: TransportMode;
  appIdSha256: Uint8Array;
  instanceIdSha256: Uint8Array;
  bootSessionId: Uint8Array;
  tlsSpkiSha256: Uint8Array;
  signerSetSha256: Uint8Array;
  protocolVersion?: number;
}

/**
 * The fixed-width canonical encoding, from pre-hashed identifiers.
 *
 * **This is the only place the field offsets are written.** Both
 * {@link canonicalBytes} (server side, raw identifiers) and the verifier
 * (client side, hashed identifiers) route through here, so the layout cannot
 * drift between the two — the failure mode this codebase keeps rediscovering.
 */
export function canonicalBytesFromHashed(
  input: TransportManifestHashed,
): Uint8Array {
  const out = new Uint8Array(CANONICAL_LEN);
  const version = input.protocolVersion ?? PROTOCOL_VERSION;
  out[0] = (version >>> 8) & 0xff;
  out[1] = version & 0xff;
  out[2] = input.transportMode;
  out[3] = 0; // reserved
  out.set(fixed32(input.appIdSha256, "appIdSha256"), 4);
  out.set(fixed32(input.instanceIdSha256, "instanceIdSha256"), 36);
  out.set(fixed32(input.bootSessionId, "bootSessionId"), 68);
  out.set(fixed32(input.tlsSpkiSha256, "tlsSpkiSha256"), 100);
  out.set(fixed32(input.signerSetSha256, "signerSetSha256"), 132);
  return out;
}

/** The fixed-width canonical encoding. See the layout above. */
export function canonicalBytes(input: TransportManifestInput): Uint8Array {
  return canonicalBytesFromHashed({
    transportMode: input.transportMode,
    appIdSha256: sha256(input.appId),
    instanceIdSha256: sha256(input.instanceId),
    bootSessionId: input.bootSessionId,
    tlsSpkiSha256: input.tlsSpkiSha256,
    signerSetSha256: input.signerSetSha256,
    ...(input.protocolVersion !== undefined
      ? { protocolVersion: input.protocolVersion }
      : {}),
  });
}

/** {@link manifestDigest}, from pre-hashed identifiers. */
export function manifestDigestFromHashed(
  input: TransportManifestHashed,
): Uint8Array {
  const canonical = canonicalBytesFromHashed(input);
  const buf = new Uint8Array(DOMAIN.length + canonical.length);
  buf.set(DOMAIN, 0);
  buf.set(canonical, DOMAIN.length);
  return sha256(buf);
}

/** `SHA-256(DOMAIN ‖ canonicalBytes())` — the right half of `report_data`. */
export function manifestDigest(input: TransportManifestInput): Uint8Array {
  const canonical = canonicalBytes(input);
  const buf = new Uint8Array(DOMAIN.length + canonical.length);
  buf.set(DOMAIN, 0);
  buf.set(canonical, DOMAIN.length);
  return sha256(buf);
}

/**
 * Assemble the 64-byte `report_data` a client expects to find in the quote.
 *
 * The nonce must be exactly 32 bytes. `/attestation` zero-pads a short nonce;
 * this contract refuses, because a caller who sends 4 bytes and believes it has
 * 32 bytes of replay protection is wrong in a way padding would hide.
 */
export function transportReportData(
  input: TransportManifestInput,
  nonce: Uint8Array,
): Uint8Array {
  if (nonce.length !== 32) {
    throw new Error(`nonce must be exactly 32 bytes, got ${nonce.length}`);
  }
  const out = new Uint8Array(64);
  out.set(nonce, 0);
  out.set(manifestDigest(input), 32);
  return out;
}
