import { createHash, randomBytes } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { Keypair } from "@solana/web3.js";

import {
  type EventLogEntry,
  type QuoteVerifier,
  type VerifiedQuoteReport,
  DSTACK_RUNTIME_EVENT_TYPE,
  replayEventLogRtmr,
  verifyTeeAttestation,
} from "../src/index.js";
import { dummyAddress } from "./helpers/e2e-helpers.js";

const BASE = "https://gw.example";
const teeKp = await Keypair.generate();
const kp1 = await Keypair.generate();
const TEE_B58 = teeKp.publicKey.toBase58();
const COMPOSE = "c0ffeec0ffee";
const MRTD = "aa".repeat(48);
const KEYS = [TEE_B58, kp1.publicKey.toBase58()];
// The quote binds SHA-256 of the FULL set (shard order), not just shard 0.
const KEYSET_HASH = createHash("sha256")
  .update(Buffer.concat([teeKp.publicKey.toBytes(), kp1.publicKey.toBytes()]))
  .digest();

// dstack RUNTIME events — empty `digest` (the verifier computes it from the
// event + payload), payload populated. This is the only event type whose
// payload the RTMR actually covers, and it matches the real-CVM fixture in
// `fixtures/dstack-eventlog.json`.
//
// These entries used to be `event_type: 1` with BOTH `digest` and
// `event_payload` set — the shape dstack's `TdxEvent::stripped()` cannot emit,
// and precisely the one CA-01 exploits to serve a pinned compose hash the
// measurement never covered. The suite's happy path was a forged log.
const EVENT_LOG: EventLogEntry[] = [
  {
    imr: 3,
    event_type: DSTACK_RUNTIME_EVENT_TYPE,
    digest: "",
    event: "app-id",
    event_payload: "a99d",
  },
  {
    imr: 3,
    event_type: DSTACK_RUNTIME_EVENT_TYPE,
    digest: "",
    event: "compose-hash",
    event_payload: COMPOSE,
  },
];
const RTMR3 = replayEventLogRtmr(EVENT_LOG, 3);

function fakeFetch(opts: { composeHash?: string } = {}): typeof fetch {
  return vi.fn(async (input: string | URL) => {
    const url = new URL(String(input));
    if (
      url.pathname === "/attestation" ||
      url.pathname === "/api/darknyx/venue/attestation"
    ) {
      const nonce = Buffer.from(
        url.searchParams.get("reportData") ?? "",
        "hex",
      );
      const rd = Buffer.alloc(64);
      nonce.copy(rd, 0);
      KEYSET_HASH.copy(rd, 32);
      return new Response(
        JSON.stringify({
          quote: rd.toString("hex"),
          event_log: JSON.stringify(EVENT_LOG),
          report_data: rd.toString("hex"),
          tee_pubkey: TEE_B58,
        }),
        { status: 200 },
      );
    }
    if (
      url.pathname === "/info" ||
      url.pathname === "/api/darknyx/venue/info"
    ) {
      return new Response(
        JSON.stringify({
          compose_hash: opts.composeHash ?? COMPOSE,
          tee_pubkey: TEE_B58,
          tee_pubkeys: KEYS,
          boot_session_id: "5a".repeat(32),
        }),
        { status: 200 },
      );
    }
    return new Response("nope", { status: 404 });
  }) as unknown as typeof fetch;
}

function goodVerifier(over: Partial<VerifiedQuoteReport> = {}): QuoteVerifier {
  return async (quote) => ({
    reportData: quote,
    mrtd: MRTD,
    rtmr0: "00".repeat(48),
    rtmr1: "00".repeat(48),
    rtmr2: "00".repeat(48),
    rtmr3: RTMR3,
    tcbStatus: "UpToDate",
    advisoryIds: [],
    ...over,
  });
}

describe("verifyTeeAttestation (SDK / browser)", () => {
  it("verifies a good attestation and returns the full K-shard set", async () => {
    const r = await verifyTeeAttestation(BASE, COMPOSE, {
      quoteVerifier: goodVerifier(),
      fetchImpl: fakeFetch(),
      expectedTeePubkey: TEE_B58,
    });
    expect(r.teePubkey).toBe(TEE_B58);
    expect(r.teePubkeys).toEqual(KEYS);
    expect(r.composeHash).toBe(COMPOSE);
    expect(r.mrtd).toBe(MRTD);
    expect(r.bootSessionId).toBe("5a".repeat(32));
  });

  it("preserves a same-origin gateway path prefix", async () => {
    const fetchImpl = fakeFetch();
    await verifyTeeAttestation(
      "https://app.example/api/darknyx/venue/",
      COMPOSE,
      {
        quoteVerifier: goodVerifier(),
        fetchImpl,
        expectedTeePubkey: TEE_B58,
      },
    );
    expect(fetchImpl).toHaveBeenNthCalledWith(
      1,
      expect.stringContaining("/api/darknyx/venue/attestation?"),
      expect.any(Object),
    );
    expect(fetchImpl).toHaveBeenNthCalledWith(
      2,
      "https://app.example/api/darknyx/venue/info",
      expect.any(Object),
    );
  });

  it("refuses an unpinned build (empty expectedComposeHash)", async () => {
    await expect(
      verifyTeeAttestation(BASE, "", {
        quoteVerifier: goodVerifier(),
        fetchImpl: fakeFetch(),
        expectedTeePubkey: TEE_B58,
      }),
    ).rejects.toMatchObject({ kind: "pin_required" });
  });

  it("rejects a fake gateway whose quote DCAP can't verify", async () => {
    await expect(
      verifyTeeAttestation(BASE, COMPOSE, {
        quoteVerifier: async () => {
          throw new Error("bad quote");
        },
        fetchImpl: fakeFetch(),
        expectedTeePubkey: TEE_B58,
      }),
    ).rejects.toBeInstanceOf(Error);
  });

  it("rejects a compose hash that doesn't match the pin", async () => {
    await expect(
      verifyTeeAttestation(BASE, "deadbeef", {
        quoteVerifier: goodVerifier(),
        fetchImpl: fakeFetch(),
        expectedTeePubkey: TEE_B58,
      }),
    ).rejects.toMatchObject({ kind: "compose_mismatch" });
  });

  // CA-02. `expectedTeePubkey` used to default to `att.tee_pubkey`, so step 7
  // compared the attested key against itself — a comparison that cannot fail —
  // and the `??` also guaranteed `expected.teePubkey` was present, making
  // strict mode's `pin_required` unreachable for the pubkey half. Strict mode
  // advertised two governance pins and enforced one.
  it("refuses strict verification with no tee_pubkey pin supplied", async () => {
    await expect(
      verifyTeeAttestation(BASE, COMPOSE, {
        quoteVerifier: goodVerifier(),
        fetchImpl: fakeFetch(),
        // expectedTeePubkey deliberately omitted
      }),
    ).rejects.toMatchObject({ kind: "pin_required" });
  });

  it("rejects a tee_pubkey that is not the one the caller pinned", async () => {
    await expect(
      verifyTeeAttestation(BASE, COMPOSE, {
        quoteVerifier: goodVerifier(),
        fetchImpl: fakeFetch(),
        expectedTeePubkey: dummyAddress().toBase58(),
      }),
    ).rejects.toMatchObject({ kind: "pubkey_mismatch" });
  });

  // CA-03. `composeHashFromEventLog(eventLog) ?? info.compose_hash` presented
  // the SELF-REPORTED value as an acceptable substitute for the attested one.
  // Unreachable on the strict path, but it is the substitution this module
  // exists to reject, so a divergent /info must not be able to influence the
  // returned value.
  it("returns the ATTESTED compose hash, never the self-reported one", async () => {
    const r = await verifyTeeAttestation(BASE, COMPOSE, {
      quoteVerifier: goodVerifier(),
      fetchImpl: fakeFetch({ composeHash: "ffffffffffff" }),
      expectedTeePubkey: TEE_B58,
    });
    expect(r.composeHash).toBe(COMPOSE);
  });
});
