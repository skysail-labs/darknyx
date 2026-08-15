/**
 * TS↔Rust parity for `TransportAttestationManifestV1` (T-03P).
 *
 * The SDK does not depend on the TEE crate, so the two implementations are
 * independent by design — the same situation as `canonicalPayloadHash`. What
 * keeps them honest is `FIXED_VECTOR_DIGEST`: the identical constant is
 * asserted in `crates/darknyx-tee/src/transport/manifest.rs`. Change the
 * encoding on one side and both suites fail.
 *
 * If you are here because this test broke: do not "fix" the constant. Work out
 * which side changed, and change both or neither.
 */

import { describe, expect, it } from "vitest";
import { sha256 } from "@noble/hashes/sha2";

import {
  CANONICAL_LEN,
  DOMAIN,
  PROTOCOL_VERSION,
  TransportMode,
  canonicalBytes,
  manifestDigest,
  transportReportData,
  type TransportManifestInput,
} from "../src/tee/transport-manifest.js";

const utf8 = (s: string) => new TextEncoder().encode(s);
const filled = (byte: number) => new Uint8Array(32).fill(byte);
const hex = (b: Uint8Array) =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

/** Identical to `fixture()` in manifest.rs. */
function fixture(): TransportManifestInput {
  return {
    transportMode: TransportMode.RaTls,
    appId: utf8("darknyx-test-app"),
    instanceId: utf8("darknyx-test-instance"),
    bootSessionId: filled(0x11),
    tlsSpkiSha256: filled(0x22),
    signerSetSha256: filled(0x33),
  };
}

/**
 * THE PIN. Byte-identical to `FIXED_VECTOR_DIGEST` in
 * `crates/darknyx-tee/src/transport/manifest.rs`.
 */
const FIXED_VECTOR_DIGEST =
  "d04907e53cd58635b7cf589c8eb4c331be1d1ff83ca57339d679e67a474427c1";

describe("transport manifest — cross-language pin", () => {
  it("matches the Rust fixed vector", () => {
    expect(hex(manifestDigest(fixture()))).toBe(FIXED_VECTOR_DIGEST);
  });

  it("encodes to exactly 164 bytes", () => {
    expect(canonicalBytes(fixture()).length).toBe(CANONICAL_LEN);
    expect(CANONICAL_LEN).toBe(164);
  });

  it("places each field where the layout documents", () => {
    const input = fixture();
    const b = canonicalBytes(input);
    expect([b[0], b[1]]).toEqual([0, PROTOCOL_VERSION]);
    expect(b[2]).toBe(TransportMode.RaTls);
    expect(b[3]).toBe(0);
    expect(hex(b.slice(4, 36))).toBe(hex(sha256(input.appId)));
    expect(hex(b.slice(36, 68))).toBe(hex(sha256(input.instanceId)));
    expect(hex(b.slice(68, 100))).toBe(hex(input.bootSessionId));
    expect(hex(b.slice(100, 132))).toBe(hex(input.tlsSpkiSha256));
    expect(hex(b.slice(132, 164))).toBe(hex(input.signerSetSha256));
  });
});

describe("transport manifest — every field is bound", () => {
  const base = manifestDigest(fixture());

  const perturbations: Array<[string, TransportManifestInput]> = [
    ["appId", { ...fixture(), appId: utf8("OTHER-app") }],
    ["instanceId", { ...fixture(), instanceId: utf8("OTHER-instance") }],
    ["bootSessionId", { ...fixture(), bootSessionId: filled(0x99) }],
    ["tlsSpkiSha256", { ...fixture(), tlsSpkiSha256: filled(0x99) }],
    ["signerSetSha256", { ...fixture(), signerSetSha256: filled(0x99) }],
    [
      "transportMode",
      { ...fixture(), transportMode: TransportMode.GatewayTerminated },
    ],
    ["protocolVersion", { ...fixture(), protocolVersion: 2 }],
  ];

  it.each(perturbations)("%s changes the digest", (_field, perturbed) => {
    expect(hex(manifestDigest(perturbed))).not.toBe(hex(base));
  });

  it("a different domain tag yields a different digest", () => {
    // Proves DOMAIN is load-bearing: a quote minted under this contract cannot
    // be replayed as one minted under a sibling contract.
    const canonical = canonicalBytes(fixture());
    const otherDomain = utf8("darknyx/transport-attestation/v2");
    const buf = new Uint8Array(otherDomain.length + canonical.length);
    buf.set(otherDomain, 0);
    buf.set(canonical, otherDomain.length);
    expect(hex(sha256(buf))).not.toBe(hex(base));
  });

  it("the domain constant is the v1 string", () => {
    expect(new TextDecoder().decode(DOMAIN)).toBe(
      "darknyx/transport-attestation/v1",
    );
  });
});

describe("transport manifest — report_data", () => {
  it("places the nonce left and the digest right", () => {
    const input = fixture();
    const nonce = filled(0xab);
    const rd = transportReportData(input, nonce);
    expect(rd.length).toBe(64);
    expect(hex(rd.slice(0, 32))).toBe(hex(nonce));
    expect(hex(rd.slice(32))).toBe(hex(manifestDigest(input)));
  });

  it.each([0, 4, 31, 33, 64])("rejects a %i-byte nonce", (len) => {
    expect(() => transportReportData(fixture(), new Uint8Array(len))).toThrow(
      /exactly 32 bytes/,
    );
  });

  it.each(["bootSessionId", "tlsSpkiSha256", "signerSetSha256"] as const)(
    "rejects a short %s rather than silently padding it",
    (field) => {
      expect(() =>
        canonicalBytes({ ...fixture(), [field]: new Uint8Array(31) }),
      ).toThrow(/exactly 32 bytes/);
    },
  );
});
