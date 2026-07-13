import { createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import {
  type EventLogEntry,
  type VerifiedQuoteReport,
  checkReportDataBinding,
  composeHashFromEventLog,
  parseEventLog,
  replayEventLogRtmr,
  teeKeySetBytes,
  verifyReportAgainstExpected,
} from "../src/tee/verify-core.js";

// ─────────────────────────────────────────────────────────────────────────────
// Independent reference implementation of dstack's `replay_rtmr`
// (dstack/sdk/rust/types/src/dstack.rs). Written differently from the module
// under test so agreement is a real differential-parity signal, not a tautology.
// ─────────────────────────────────────────────────────────────────────────────
function referenceReplay(digestsHex: string[]): string {
  const INIT = "00".repeat(48);
  if (digestsHex.length === 0) return INIT;
  let acc = Buffer.from(INIT, "hex");
  for (const h of digestsHex) {
    const raw = Buffer.from(h.replace(/^0x/, ""), "hex");
    const padded =
      raw.length >= 48
        ? raw
        : Buffer.concat([raw, Buffer.alloc(48 - raw.length)]);
    const h1 = createHash("sha384");
    h1.update(acc);
    h1.update(padded);
    acc = h1.digest();
  }
  return acc.toString("hex");
}

const digest = (seed: string): string =>
  createHash("sha384").update(seed).digest("hex");

const evt = (
  imr: number,
  event: string,
  dig: string,
  payload = "",
): EventLogEntry => ({
  imr,
  event_type: 1,
  digest: dig,
  event,
  event_payload: payload,
});

describe("replayEventLogRtmr (dstack parity)", () => {
  it("empty history is the 48-byte zero init register", () => {
    expect(replayEventLogRtmr([], 3)).toBe("00".repeat(48));
  });

  it("matches the independent reference across random logs", () => {
    for (let trial = 0; trial < 50; trial++) {
      const log: EventLogEntry[] = [];
      const rtmr3Digests: string[] = [];
      const n = 1 + (trial % 6);
      for (let i = 0; i < n; i++) {
        // Mix in events on other IMRs — they must be ignored for RTMR3.
        log.push(evt(i % 4, `e${i}`, digest(`noise-${trial}-${i}`)));
        if (i % 4 === 3) rtmr3Digests.push(digest(`noise-${trial}-${i}`));
        const d = digest(`rtmr3-${trial}-${i}`);
        log.push(evt(3, `x${i}`, d));
        rtmr3Digests.push(d);
      }
      expect(replayEventLogRtmr(log, 3)).toBe(referenceReplay(rtmr3Digests));
    }
  });

  it("only folds events for the requested IMR", () => {
    const log = [evt(0, "a", digest("a")), evt(3, "b", digest("b"))];
    expect(replayEventLogRtmr(log, 3)).toBe(referenceReplay([digest("b")]));
    expect(replayEventLogRtmr(log, 0)).toBe(referenceReplay([digest("a")]));
    expect(replayEventLogRtmr(log, 1)).toBe("00".repeat(48));
  });

  it("pads short digests up to 48 bytes (never truncates long ones)", () => {
    const short = "abcd"; // 2 bytes
    const log = [evt(3, "s", short)];
    expect(replayEventLogRtmr(log, 3)).toBe(referenceReplay([short]));
  });
});

describe("replayEventLogRtmr — real dstack CVM fixture", () => {
  // Captured from a live Phala CVM (tee-v3-hardening-46). dstack leaves the
  // app-event (RTMR3) digests EMPTY and computes them from (event_type, event,
  // payload) — the exact case a synthetic log can't cover. Regression guard.
  const fx = JSON.parse(
    readFileSync(
      new URL("./fixtures/dstack-eventlog.json", import.meta.url),
      "utf8",
    ),
  ) as {
    compose_hash: string;
    rtmr0: string;
    rtmr3: string;
    event_log: EventLogEntry[];
  };

  it("reproduces the real quote's RTMR3 (computed app-event digests)", () => {
    expect(replayEventLogRtmr(fx.event_log, 3)).toBe(fx.rtmr3);
  });

  it("still reproduces RTMR0 (pre-filled boot-event digests)", () => {
    expect(replayEventLogRtmr(fx.event_log, 0)).toBe(fx.rtmr0);
  });

  it("extracts the compose hash from the real RTMR3 log", () => {
    expect(composeHashFromEventLog(fx.event_log)).toBe(fx.compose_hash);
  });
});

describe("parseEventLog / composeHashFromEventLog", () => {
  it("parses the JSON-string event log (not hex — B-7)", () => {
    const log = [evt(3, "compose-hash", digest("ch"), "deadbeef")];
    const json = JSON.stringify(log);
    const parsed = parseEventLog(json);
    expect(parsed).toHaveLength(1);
    expect(composeHashFromEventLog(parsed)).toBe("deadbeef");
  });

  it("throws event_log_invalid on non-array JSON", () => {
    expect(() => parseEventLog('{"not":"array"}')).toThrowError(
      /not a JSON array/,
    );
  });

  it("returns undefined when there is no RTMR3 compose-hash event", () => {
    expect(
      composeHashFromEventLog([evt(0, "compose-hash", digest("x"), "aa")]),
    ).toBeUndefined();
  });
});

describe("checkReportDataBinding", () => {
  const nonce = randomBytes(32);
  const pubkey = randomBytes(32);
  const goodReportData = (): Uint8Array =>
    Buffer.concat([nonce, createHash("sha256").update(pubkey).digest()]);

  it("passes on a correct nonce + pubkey binding", () => {
    expect(checkReportDataBinding(goodReportData(), nonce, pubkey)).toBeNull();
  });

  it("rejects the wrong length", () => {
    expect(checkReportDataBinding(new Uint8Array(63), nonce, pubkey)).toBe(
      "malformed",
    );
  });

  it("rejects a stale nonce", () => {
    expect(
      checkReportDataBinding(goodReportData(), randomBytes(32), pubkey),
    ).toBe("freshness");
  });

  it("rejects an unbound (attacker) pubkey", () => {
    expect(
      checkReportDataBinding(goodReportData(), nonce, randomBytes(32)),
    ).toBe("binding");
  });

  it("binds the FULL K-shard set (not just shard 0)", () => {
    const k0 = randomBytes(32);
    const k1 = randomBytes(32);
    const set = teeKeySetBytes([k0, k1]);
    const rd = Buffer.concat([
      nonce,
      createHash("sha256").update(set).digest(),
    ]);
    // Correct: bound to the concatenated set.
    expect(checkReportDataBinding(rd, nonce, set)).toBeNull();
    // A report that binds only shard-0 must NOT satisfy the set binding.
    const shard0Only = Buffer.concat([
      nonce,
      createHash("sha256").update(k0).digest(),
    ]);
    expect(checkReportDataBinding(shard0Only, nonce, set)).toBe("binding");
  });
});

describe("verifyReportAgainstExpected", () => {
  const nonce = randomBytes(32);
  const teePubkeyBytes = randomBytes(32);
  const teePubkeyBase58 = "SoLsIgNeRkEy11111111111111111111111111111111";
  const eventLog = [
    evt(0, "os", digest("os")),
    evt(3, "app-id", digest("app")),
    evt(3, "compose-hash", digest("ch"), "c0ffee"),
  ];
  const rtmr3 = replayEventLogRtmr(eventLog, 3);

  const baseReport = (): VerifiedQuoteReport => ({
    reportData: Buffer.concat([
      nonce,
      createHash("sha256").update(teePubkeyBytes).digest(),
    ]),
    mrtd: "aa".repeat(48),
    rtmr0: "00".repeat(48),
    rtmr1: "00".repeat(48),
    rtmr2: "00".repeat(48),
    rtmr3,
    tcbStatus: "UpToDate",
    advisoryIds: [],
  });

  const opts = (
    over: Partial<Parameters<typeof verifyReportAgainstExpected>[0]> = {},
  ) => ({
    report: baseReport(),
    eventLog,
    nonce,
    // single-shard: the bound set concat is just the one pubkey
    boundKeySetBytes: teePubkeyBytes,
    teePubkeyBase58,
    expected: { composeHash: "c0ffee", teePubkey: teePubkeyBase58 },
    strict: true,
    ...over,
  });

  it("returns null when everything checks out (strict, pinned)", () => {
    expect(verifyReportAgainstExpected(opts())).toBeNull();
  });

  it("rejects a TCB status outside the allowlist", () => {
    const report = baseReport();
    report.tcbStatus = "OutOfDate";
    expect(verifyReportAgainstExpected(opts({ report }))).toBe("tcb_outdated");
  });

  it("requires pins in strict mode", () => {
    expect(verifyReportAgainstExpected(opts({ expected: {} }))).toBe(
      "pin_required",
    );
    expect(
      verifyReportAgainstExpected(
        opts({ expected: { composeHash: "c0ffee" } }),
      ),
    ).toBe("pin_required");
  });

  it("rejects an event log that does not replay to the attested RTMR3", () => {
    const report = baseReport();
    report.rtmr3 = "bb".repeat(48);
    expect(verifyReportAgainstExpected(opts({ report }))).toBe(
      "event_log_invalid",
    );
  });

  it("rejects a compose hash that does not match the pin", () => {
    expect(
      verifyReportAgainstExpected(
        opts({ expected: { composeHash: "beef", teePubkey: teePubkeyBase58 } }),
      ),
    ).toBe("compose_mismatch");
  });

  it("rejects a mismatched MRTD pin", () => {
    expect(
      verifyReportAgainstExpected(
        opts({
          expected: {
            composeHash: "c0ffee",
            teePubkey: teePubkeyBase58,
            mrtd: "bb".repeat(48),
          },
        }),
      ),
    ).toBe("mrtd_mismatch");
  });

  it("rejects a mismatched tee_pubkey pin", () => {
    expect(
      verifyReportAgainstExpected(
        opts({ expected: { composeHash: "c0ffee", teePubkey: "OtherKey" } }),
      ),
    ).toBe("pubkey_mismatch");
  });

  it("rejects an attacker-bound report_data even with valid pins", () => {
    const report = baseReport();
    report.reportData = Buffer.concat([
      nonce,
      createHash("sha256").update(randomBytes(32)).digest(), // attacker key
    ]);
    expect(verifyReportAgainstExpected(opts({ report }))).toBe("binding");
  });
});
