/**
 * Attestation tests — the connect-time verifier, no live TEE.
 *
 * Strict mode runs a (mocked) DCAP verifier over the quote and routes the
 * verified report through the SDK `verify-core` (event-log RTMR3 replay,
 * report_data binding, measurement pinning). The decisive test is the
 * **fake gateway**: valid-looking JSON (echoed nonce, bound key, pinned compose
 * hash) but a quote DCAP rejects → the daemon still refuses. Dev-partial mode
 * (strict:false) keeps the legacy self-reported check for the local simulator.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createHash } from "node:crypto";
import { Keypair } from "@solana/web3.js";

import {
  type EventLogEntry,
  type VerifiedQuoteReport,
  replayEventLogRtmr,
} from "@nyx/sdk";
import {
  verifyAttestation,
  AttestationError,
  type QuoteVerifier,
} from "../src/attestation.js";
import { Daemon } from "../src/daemon.js";
import { DaemonStore } from "../src/store.js";
import { Keystore, type AccountIdentity } from "../src/keystore.js";
import { DEFAULT_THRESHOLDS } from "../src/order-lifecycle.js";
import type { DaemonConfig } from "../src/config.js";

const GW = "https://gw.example";
const TOKEN = "tok";

const teeKp = Keypair.generate();
const TEE_PUBKEY_B58 = teeKp.publicKey.toBase58();
const TEE_PUBKEY_HASH = createHash("sha256")
  .update(teeKp.publicKey.toBytes())
  .digest();

const COMPOSE = "c0ffeec0ffee";
const MRTD = "aa".repeat(48);

// An event log whose RTMR3 we can reproduce, carrying the compose-hash event.
const EVENT_LOG: EventLogEntry[] = [
  {
    imr: 0,
    event_type: 1,
    digest: createHash("sha384").update("os").digest("hex"),
    event: "os",
    event_payload: "",
  },
  {
    imr: 3,
    event_type: 1,
    digest: createHash("sha384").update("app").digest("hex"),
    event: "app-id",
    event_payload: "app",
  },
  {
    imr: 3,
    event_type: 1,
    digest: createHash("sha384").update("ch").digest("hex"),
    event: "compose-hash",
    event_payload: COMPOSE,
  },
];
const RTMR3 = replayEventLogRtmr(EVENT_LOG, 3);

/** A fake gateway. `quote` is set to the 64-byte report_data hex so the mocked
 *  DCAP verifier can echo it back as the verified report's report_data. */
function attestFetch(
  opts: {
    composeHash?: string;
    teePubkeyB58?: string;
    bindWrongKey?: boolean;
    staleNonce?: boolean;
  } = {},
): typeof fetch {
  const composeHash = opts.composeHash ?? COMPOSE;
  const teePubkey = opts.teePubkeyB58 ?? TEE_PUBKEY_B58;
  return vi.fn(async (input: string | URL) => {
    const url = new URL(String(input));
    if (url.pathname === "/attestation") {
      const nonce = Buffer.from(
        url.searchParams.get("reportData") ?? "",
        "hex",
      );
      const rd = Buffer.alloc(64);
      if (!opts.staleNonce) nonce.copy(rd, 0);
      (opts.bindWrongKey
        ? createHash("sha256").update(Buffer.from("nope")).digest()
        : TEE_PUBKEY_HASH
      ).copy(rd, 32);
      return new Response(
        JSON.stringify({
          quote: rd.toString("hex"),
          event_log: JSON.stringify(EVENT_LOG),
          report_data: rd.toString("hex"),
          tee_pubkey: teePubkey,
        }),
        { status: 200 },
      );
    }
    if (url.pathname === "/info") {
      return new Response(
        JSON.stringify({
          app_id: "app_x",
          compose_hash: composeHash,
          tcb_info: { mrtd: MRTD }, // B-1: nested, not top-level
          tee_pubkey: teePubkey,
        }),
        { status: 200 },
      );
    }
    return new Response("not found", { status: 404 });
  }) as unknown as typeof fetch;
}

/** A mocked DCAP verifier that "verifies" the quote by treating its bytes as the
 *  report_data and stamping the shared RTMR3 / MRTD. Override to inject failures. */
function goodVerifier(over: Partial<VerifiedQuoteReport> = {}): QuoteVerifier {
  return async (quote: Uint8Array): Promise<VerifiedQuoteReport> => ({
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

const PINS = { composeHash: COMPOSE, teePubkey: TEE_PUBKEY_B58 };

describe("verifyAttestation — strict DCAP", () => {
  it("accepts a fully-verified, pinned attestation", async () => {
    const r = await verifyAttestation({
      gatewayUrl: GW,
      token: TOKEN,
      fetchImpl: attestFetch(),
      quoteVerifier: goodVerifier(),
      expected: { ...PINS, mrtd: MRTD },
    });
    expect(r.teePubkey).toBe(TEE_PUBKEY_B58);
    expect(r.composeHash).toBe(COMPOSE);
    expect(r.dcapVerified).toBe(true);
  });

  it("THE decisive test: rejects a fake gateway whose quote DCAP can't verify", async () => {
    // Nonce echoed, key bound, compose pinned — all the JSON looks right — but
    // there is no genuine quote, so DCAP throws. Pre-DCAP this passed (A-1).
    await expect(
      verifyAttestation({
        gatewayUrl: GW,
        token: TOKEN,
        fetchImpl: attestFetch(),
        quoteVerifier: async () => {
          throw new AttestationError("bad signature", "quote_invalid");
        },
        expected: PINS,
      }),
    ).rejects.toMatchObject({ kind: "quote_invalid" });
  });

  it("rejects when no DCAP verifier is supplied in strict mode", async () => {
    await expect(
      verifyAttestation({
        gatewayUrl: GW,
        token: TOKEN,
        fetchImpl: attestFetch(),
        expected: PINS,
      }),
    ).rejects.toMatchObject({ kind: "quote_invalid" });
  });

  it("requires the governance pins in strict mode", async () => {
    await expect(
      verifyAttestation({
        gatewayUrl: GW,
        token: TOKEN,
        fetchImpl: attestFetch(),
        quoteVerifier: goodVerifier(),
        expected: { composeHash: COMPOSE }, // missing teePubkey
      }),
    ).rejects.toMatchObject({ kind: "pin_required" });
  });

  it("rejects an out-of-date TCB status", async () => {
    await expect(
      verifyAttestation({
        gatewayUrl: GW,
        token: TOKEN,
        fetchImpl: attestFetch(),
        quoteVerifier: goodVerifier({ tcbStatus: "OutOfDate" }),
        expected: PINS,
      }),
    ).rejects.toMatchObject({ kind: "tcb_outdated" });
  });

  it("rejects an event log that does not replay to the attested RTMR3", async () => {
    await expect(
      verifyAttestation({
        gatewayUrl: GW,
        token: TOKEN,
        fetchImpl: attestFetch(),
        quoteVerifier: goodVerifier({ rtmr3: "bb".repeat(48) }),
        expected: PINS,
      }),
    ).rejects.toMatchObject({ kind: "event_log_invalid" });
  });

  it("rejects a compose hash that doesn't match the pin", async () => {
    await expect(
      verifyAttestation({
        gatewayUrl: GW,
        token: TOKEN,
        fetchImpl: attestFetch(),
        quoteVerifier: goodVerifier(),
        expected: { composeHash: "deadbeef", teePubkey: TEE_PUBKEY_B58 },
      }),
    ).rejects.toMatchObject({ kind: "compose_mismatch" });
  });

  it("rejects an attacker-bound report_data even with matching pins", async () => {
    await expect(
      verifyAttestation({
        gatewayUrl: GW,
        token: TOKEN,
        fetchImpl: attestFetch({ bindWrongKey: true }),
        quoteVerifier: goodVerifier(),
        expected: PINS,
      }),
    ).rejects.toMatchObject({ kind: "binding" });
  });
});

describe("verifyAttestation — dev-partial (strict:false)", () => {
  it("accepts a bound, pinned attestation without DCAP", async () => {
    const r = await verifyAttestation({
      gatewayUrl: GW,
      token: TOKEN,
      strict: false,
      fetchImpl: attestFetch(),
      expected: { composeHash: COMPOSE, mrtd: MRTD, teePubkey: TEE_PUBKEY_B58 },
    });
    expect(r.dcapVerified).toBe(false);
    expect(r.mrtd).toBe(MRTD); // B-1: read from tcb_info.mrtd
  });

  it("still rejects a replayed (stale) nonce", async () => {
    await expect(
      verifyAttestation({
        gatewayUrl: GW,
        token: TOKEN,
        strict: false,
        fetchImpl: attestFetch({ staleNonce: true }),
      }),
    ).rejects.toMatchObject({ kind: "freshness" });
  });
});

describe("Daemon — attestation gate", () => {
  let store: DaemonStore;
  beforeEach(() => {
    store = new DaemonStore(":memory:");
  });
  afterEach(() => store.close());

  function keystore(): Keystore {
    const masterSeed = new Uint8Array(64);
    for (let i = 0; i < 64; i++) masterSeed[i] = (i * 13 + 5) & 0xff;
    const id: AccountIdentity = {
      masterSeed,
      ownerBlinding: 0xabcn,
      r0: 1n,
      r1: 2n,
      r2: 3n,
      rootKeyPubkey: new Uint8Array(32).fill(4),
    };
    return new Keystore(id);
  }
  const config = (): DaemonConfig => ({
    gatewayUrl: GW,
    gatewayWsUrl: "wss://gw",
    token: TOKEN,
    rpcUrl: "https://rpc",
    dbPath: ":memory:",
    controlPort: 0,
    keystorePath: "x",
    thresholds: DEFAULT_THRESHOLDS,
    attestationStrict: true,
    attestOnchainCheck: true,
    programId: "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
  });

  it("refuses to start when attestation fails", async () => {
    const daemon = new Daemon({
      config: config(),
      keystore: keystore(),
      store,
      prover: (async () => {
        throw new Error("unused");
      }) as never,
      placer: {
        place: vi.fn(),
        cancel: vi.fn(),
        modify: vi.fn(),
        close: vi.fn(),
      } as never,
      subscribeFills: (() => ({ close() {} })) as never,
      subscribeOrders: (() => ({ close() {} })) as never,
      verifyAttestation: async () => {
        throw new AttestationError("bad", "binding");
      },
    });
    await expect(daemon.start()).rejects.toThrow(/bad/);
    expect(daemon.getAttestation()).toBeNull();
  });

  it("starts + records the identity when attestation passes", async () => {
    const daemon = new Daemon({
      config: config(),
      keystore: keystore(),
      store,
      prover: (async () => ({
        proofBytes: new Uint8Array(256),
        merkleRoot: new Uint8Array(32),
      })) as never,
      placer: {
        place: vi.fn(),
        cancel: vi.fn(),
        modify: vi.fn(),
        close: vi.fn(),
      } as never,
      subscribeFills: (() => ({ close() {} })) as never,
      subscribeOrders: (() => ({ close() {} })) as never,
      verifyAttestation: async () => ({
        teePubkey: TEE_PUBKEY_B58,
        teePubkeys: [TEE_PUBKEY_B58],
        composeHash: COMPOSE,
        mrtd: MRTD,
        quote: "q",
        dcapVerified: true,
      }),
      // on-chain governance set matches the attested set → passes.
      onchainTeePubkeys: async () => [TEE_PUBKEY_B58],
    });
    await daemon.start();
    expect(daemon.getAttestation()?.teePubkey).toBe(TEE_PUBKEY_B58);
  });

  it("refuses to start when on-chain tee_pubkeys don't match the attested set", async () => {
    const daemon = new Daemon({
      config: config(),
      keystore: keystore(),
      store,
      prover: (async () => ({
        proofBytes: new Uint8Array(256),
        merkleRoot: new Uint8Array(32),
      })) as never,
      placer: {
        place: vi.fn(),
        cancel: vi.fn(),
        modify: vi.fn(),
        close: vi.fn(),
      } as never,
      subscribeFills: (() => ({ close() {} })) as never,
      subscribeOrders: (() => ({ close() {} })) as never,
      verifyAttestation: async () => ({
        teePubkey: TEE_PUBKEY_B58,
        teePubkeys: [TEE_PUBKEY_B58],
        composeHash: COMPOSE,
        mrtd: MRTD,
        quote: "q",
        dcapVerified: true,
      }),
      // Vault trusts an extra key the enclave doesn't hold → refuse.
      onchainTeePubkeys: async () => [
        TEE_PUBKEY_B58,
        Keypair.generate().publicKey.toBase58(),
      ],
    });
    await expect(daemon.start()).rejects.toMatchObject({
      kind: "pubkey_mismatch",
    });
  });
});
