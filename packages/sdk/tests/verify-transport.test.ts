/**
 * Transport-attestation verification (T-03P).
 *
 * Every check gets a test that makes it *fail*. A verifier whose checks are
 * only ever exercised on the happy path is indistinguishable from one that
 * returns `null` unconditionally — and this codebase has shipped that shape
 * before (see `audits/` on green-but-vacuous guards).
 *
 * The headline case is `spki_mismatch`: a relay that forwards a completely
 * genuine quote from a real enclave, but terminates TLS with its own
 * certificate. Everything else about that response verifies. Only the SPKI
 * comparison catches it, and it is the reason this module exists.
 */

import { describe, expect, it } from "vitest";
import { sha256 } from "@noble/hashes/sha2";

import {
  manifestDigestFromHashed,
  TransportMode,
} from "../src/tee/transport-manifest.js";
import {
  verifyTransportAttestation,
  type ObservedManifest,
  type VerifyTransportOptions,
} from "../src/tee/verify-transport.js";
import { replayEventLogRtmr } from "../src/tee/verify-core.js";
import type {
  EventLogEntry,
  VerifiedQuoteReport,
} from "../src/tee/verify-core.js";

const filled = (b: number) => new Uint8Array(32).fill(b);
const NONCE = filled(0xa1);
const SPKI = filled(0x22);
const SIGNERS = filled(0x33);
const BOOT = filled(0x11);

const COMPOSE_HASH = "aa".repeat(32);

/**
 * A minimal event log whose RTMR3 replay we can compute, carrying a
 * runtime-typed compose-hash event. Mirrors the shape `verify-core` expects.
 */
function eventLog(): EventLogEntry[] {
  return [
    {
      imr: 3,
      event_type: 0x08000001,
      digest: "",
      event: "compose-hash",
      event_payload: COMPOSE_HASH,
    },
  ];
}

function manifest(over: Partial<ObservedManifest> = {}): ObservedManifest {
  return {
    protocolVersion: 1,
    transportMode: TransportMode.RaTls,
    appIdSha256: sha256(new TextEncoder().encode("app")),
    instanceIdSha256: sha256(new TextEncoder().encode("instance")),
    bootSessionId: BOOT,
    tlsSpkiSha256: SPKI,
    signerSetSha256: SIGNERS,
    ...over,
  };
}

/** Build a report whose report_data correctly commits to `m`. */
function report(
  m: ObservedManifest,
  over: Partial<VerifiedQuoteReport> = {},
): VerifiedQuoteReport {
  const rd = new Uint8Array(64);
  rd.set(NONCE, 0);
  rd.set(manifestDigestFromHashed(m), 32);
  return {
    reportData: rd,
    mrtd: "00".repeat(48),
    rtmr0: "",
    rtmr1: "",
    rtmr2: "",
    rtmr3: rtmr3For(eventLog()),
    tcbStatus: "UpToDate",
    ...over,
  } as VerifiedQuoteReport;
}

/** Replay helper so the fixture's rtmr3 is self-consistent.
 *  Reuses the production replay so the fixture cannot drift from the checker. */
function rtmr3For(log: EventLogEntry[]): string {
  return replayEventLogRtmr(log, 3);
}

function opts(over: Partial<VerifyTransportOptions> = {}): VerifyTransportOptions {
  const m = over.manifest ?? manifest();
  return {
    report: over.report ?? report(m),
    eventLog: eventLog(),
    nonce: NONCE,
    manifest: m,
    observedSpkiSha256: SPKI,
    expectedComposeHash: COMPOSE_HASH,
    expectedSignerSetSha256: SIGNERS,
    expectedBootSessionId: BOOT,
    ...over,
  };
}

describe("verifyTransportAttestation — happy path", () => {
  it("accepts a fully consistent transport attestation", () => {
    expect(verifyTransportAttestation(opts())).toBeNull();
  });
});

describe("verifyTransportAttestation — the relay case", () => {
  it("rejects a genuine quote served behind a different certificate", () => {
    // THE test. A relay fetches a real transport attestation from the real
    // enclave and forwards it verbatim, but terminates TLS itself. Nonce,
    // manifest binding, event log, compose hash, signer set and boot session
    // all verify. Only the SPKI differs — and that must be enough.
    const attackerSpki = filled(0x99);
    expect(
      verifyTransportAttestation(opts({ observedSpkiSha256: attackerSpki })),
    ).toBe("spki_mismatch");
  });

  it("rejects a manifest whose SPKI was swapped to match the relay", () => {
    // The other half of the same attack: rewrite the manifest so its SPKI
    // matches the relay's certificate. That breaks the quote binding, because
    // report_data committed to the original manifest.
    const attackerSpki = filled(0x99);
    const m = manifest({ tlsSpkiSha256: attackerSpki });
    expect(
      verifyTransportAttestation(
        opts({
          manifest: m,
          // report_data still commits to the ORIGINAL manifest
          report: report(manifest()),
          observedSpkiSha256: attackerSpki,
        }),
      ),
    ).toBe("manifest_binding");
  });
});

describe("verifyTransportAttestation — every check rejects", () => {
  it("rejects a replayed nonce", () => {
    expect(verifyTransportAttestation(opts({ nonce: filled(0xbb) }))).toBe(
      "freshness",
    );
  });

  it("rejects an unacceptable TCB status", () => {
    const m = manifest();
    expect(
      verifyTransportAttestation(
        opts({ manifest: m, report: report(m, { tcbStatus: "OutOfDate" }) }),
      ),
    ).toBe("tcb_outdated");
  });

  it("rejects a tampered manifest field", () => {
    // signer_set changed after the quote was minted.
    const m = manifest({ signerSetSha256: filled(0x77) });
    expect(
      verifyTransportAttestation(
        opts({ manifest: m, report: report(manifest()) }),
      ),
    ).toBe("manifest_binding");
  });

  it("rejects an event log that does not replay to the attested RTMR3", () => {
    const m = manifest();
    expect(
      verifyTransportAttestation(
        opts({ manifest: m, report: report(m, { rtmr3: "ff".repeat(48) }) }),
      ),
    ).toBe("event_log_invalid");
  });

  it("rejects a structurally impossible event-log entry before replaying it", () => {
    const bad: EventLogEntry[] = [
      {
        imr: 3,
        event_type: 0x08000001,
        digest: "ab".repeat(48),
        event: "compose-hash",
        event_payload: COMPOSE_HASH,
      },
    ];
    expect(verifyTransportAttestation(opts({ eventLog: bad }))).toBe(
      "event_log_invalid",
    );
  });

  it("rejects an unapproved compose hash", () => {
    expect(
      verifyTransportAttestation(
        opts({ expectedComposeHash: "bb".repeat(32) }),
      ),
    ).toBe("compose_mismatch");
  });

  it("rejects a foreign signer set", () => {
    // A genuine, correctly-measured enclave that does not hold the governed
    // settle keys. Without this check it would pass everything else.
    expect(
      verifyTransportAttestation(
        opts({ expectedSignerSetSha256: filled(0x44) }),
      ),
    ).toBe("signer_set_mismatch");
  });

  it("rejects evidence from a previous boot", () => {
    expect(
      verifyTransportAttestation(opts({ expectedBootSessionId: filled(0x55) })),
    ).toBe("boot_session_mismatch");
  });

  it("rejects the legacy gateway-terminated mode", () => {
    // A downgrade must not pass as a verified transport.
    const m = manifest({ transportMode: TransportMode.GatewayTerminated });
    expect(
      verifyTransportAttestation(opts({ manifest: m, report: report(m) })),
    ).toBe("transport_mode_rejected");
  });

  it("rejects an unimplemented protocol version", () => {
    const m = manifest({ protocolVersion: 99 });
    expect(
      verifyTransportAttestation(opts({ manifest: m, report: report(m) })),
    ).toBe("protocol_version_unsupported");
  });

  it("rejects a missing governance pin in strict mode", () => {
    const { expectedComposeHash: _c, ...rest } = opts();
    expect(
      verifyTransportAttestation(rest as VerifyTransportOptions),
    ).toBe("pin_required");
  });

  it("rejects an MRTD mismatch when pinned", () => {
    expect(
      verifyTransportAttestation(opts({ expectedMrtd: "cc".repeat(48) })),
    ).toBe("mrtd_mismatch");
  });
});

describe("verifyTransportAttestation — shape guards", () => {
  it.each([0, 4, 31, 33])("rejects a %i-byte nonce", (len) => {
    expect(
      verifyTransportAttestation(opts({ nonce: new Uint8Array(len) })),
    ).toBe("malformed");
  });

  it("rejects a short observed SPKI rather than comparing a prefix", () => {
    expect(
      verifyTransportAttestation(
        opts({ observedSpkiSha256: new Uint8Array(31) }),
      ),
    ).toBe("malformed");
  });

  it("rejects a report_data that is not 64 bytes", () => {
    const m = manifest();
    expect(
      verifyTransportAttestation(
        opts({
          manifest: m,
          report: report(m, { reportData: new Uint8Array(32) }),
        }),
      ),
    ).toBe("malformed");
  });

  it.each([
    "appIdSha256",
    "instanceIdSha256",
    "bootSessionId",
    "tlsSpkiSha256",
    "signerSetSha256",
  ] as const)("rejects a short %s in the manifest", (field) => {
    // The report is built from a VALID manifest on purpose: the malformed one
    // must be classified by the verifier's shape guard, not blow up the
    // encoder while constructing the fixture.
    const bad = manifest({
      [field]: new Uint8Array(31),
    } as Partial<ObservedManifest>);
    expect(
      verifyTransportAttestation(
        opts({ manifest: bad, report: report(manifest()) }),
      ),
    ).toBe("malformed");
  });
});
