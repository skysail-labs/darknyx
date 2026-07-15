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
  limitPolicy,
  OrderSide,
  type EventLogEntry,
  type StoredNote,
  type VerifiedQuoteReport,
  replayEventLogRtmr,
} from "@nyx/sdk";
import {
  verifyAttestation,
  AttestationError,
  type QuoteVerifier,
} from "../src/attestation.js";
import { Daemon, DEFAULT_TEE_KEY_REFRESH_MS } from "../src/daemon.js";
import { DaemonStore } from "../src/store.js";
import { Keystore, type AccountIdentity } from "../src/keystore.js";
import { DEFAULT_THRESHOLDS } from "../src/order-lifecycle.js";
import type { DaemonConfig } from "../src/config.js";
import { newManagedOrder } from "../src/types.js";

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
    bootSessionId?: string;
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
          boot_session_id: opts.bootSessionId ?? "5a".repeat(32),
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

  it("rejects a malformed boot session before trading", async () => {
    await expect(
      verifyAttestation({
        gatewayUrl: GW,
        token: TOKEN,
        fetchImpl: attestFetch({ bootSessionId: `${"5a".repeat(32)}z` }),
        quoteVerifier: goodVerifier(),
        expected: { ...PINS, mrtd: MRTD },
        strict: true,
      }),
    ).rejects.toMatchObject({ kind: "malformed" });
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
  const config = (overrides: Partial<DaemonConfig> = {}): DaemonConfig => ({
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
    ...overrides,
  });

  const verifiedIdentity = () => ({
    teePubkey: TEE_PUBKEY_B58,
    teePubkeys: [TEE_PUBKEY_B58],
    composeHash: COMPOSE,
    bootSessionId: "5a".repeat(32),
    mrtd: MRTD,
    quote: "q",
    dcapVerified: true,
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
      verifyRoot: false,
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
      verifyAttestation: async () => verifiedIdentity(),
      // on-chain governance set matches the attested set → passes.
      onchainTeePubkeys: async () => [TEE_PUBKEY_B58],
      verifyRoot: false,
    });
    await daemon.start();
    expect(daemon.getAttestation()?.teePubkey).toBe(TEE_PUBKEY_B58);
    expect(daemon.getTrustStatus()).toMatchObject({
      tradingEnabled: true,
      onchainKeyMonitoring: true,
    });
    daemon.stop();
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
      verifyAttestation: async () => verifiedIdentity(),
      // Vault trusts an extra key the enclave doesn't hold → refuse.
      onchainTeePubkeys: async () => [
        TEE_PUBKEY_B58,
        Keypair.generate().publicKey.toBase58(),
      ],
      verifyRoot: false,
    });
    await expect(daemon.start()).rejects.toMatchObject({
      kind: "pubkey_mismatch",
    });
  });

  it("fails strict startup on an RPC error or missing VaultConfig", async () => {
    const common = {
      config: config(),
      keystore: keystore(),
      store,
      prover: vi.fn() as never,
      placer: {
        place: vi.fn(),
        cancel: vi.fn(),
        modify: vi.fn(),
        close: vi.fn(),
      } as never,
      subscribeFills: (() => ({ close() {} })) as never,
      subscribeOrders: (() => ({ close() {} })) as never,
      verifyAttestation: async () => verifiedIdentity(),
      verifyRoot: false as const,
    };
    const rpcFailure = new Daemon({
      ...common,
      onchainTeePubkeys: async () => {
        throw new Error("RPC unavailable");
      },
    });
    await expect(rpcFailure.start()).rejects.toThrow(/RPC unavailable/);

    const missing = new Daemon({
      ...common,
      onchainTeePubkeys: async () => null,
    });
    await expect(missing.start()).rejects.toThrow(/vault_config not found/);
  });

  it("does not permit the on-chain key check to be disabled in strict mode", async () => {
    const attest = vi.fn(async () => verifiedIdentity());
    const daemon = new Daemon({
      config: config({ attestOnchainCheck: false }),
      keystore: keystore(),
      store,
      prover: vi.fn() as never,
      placer: {
        place: vi.fn(),
        cancel: vi.fn(),
        modify: vi.fn(),
        close: vi.fn(),
      } as never,
      subscribeFills: (() => ({ close() {} })) as never,
      subscribeOrders: (() => ({ close() {} })) as never,
      verifyAttestation: attest,
      verifyRoot: false,
    });
    await expect(daemon.start()).rejects.toThrow(
      /strict attestation requires the finalized on-chain TEE-key check/,
    );
    expect(attest).not.toHaveBeenCalled();
  });

  it("pauses placement immediately on key mismatch but keeps cancellation and streams live", async () => {
    let onchain = [TEE_PUBKEY_B58];
    let fillsClosed = false;
    let ordersClosed = false;
    const prover = vi.fn();
    const anchorPoster = { post: vi.fn(async () => {}) };
    const mergeRunner = { run: vi.fn(async () => 1) };
    const placer = {
      place: vi.fn(),
      cancel: vi.fn(async (orderId: string) => ({
        order_id: orderId,
        status: "cancelled",
      })),
      modify: vi.fn(),
      close: vi.fn(),
    };
    const daemon = new Daemon({
      config: config(),
      keystore: keystore(),
      store,
      prover: prover as never,
      placer: placer as never,
      subscribeFills: (() => ({
        close() {
          fillsClosed = true;
        },
      })) as never,
      subscribeOrders: (() => ({
        close() {
          ordersClosed = true;
        },
      })) as never,
      verifyAttestation: async () => verifiedIdentity(),
      onchainTeePubkeys: async () => onchain,
      anchorPoster,
      mergeRunner,
      verifyRoot: false,
    });
    await daemon.start();

    onchain = [Keypair.generate().publicKey.toBase58()];
    await daemon.refreshTrustNow();
    expect(daemon.getTrustStatus().tradingEnabled).toBe(false);
    expect(daemon.getTrustStatus().pauseReason).toMatch(/on-chain/);
    expect(fillsClosed).toBe(false);
    expect(ordersClosed).toBe(false);

    const collateral: StoredNote = {
      commitment: "11".repeat(32),
      tokenMint: new Uint8Array(32).fill(9),
      amount: 1_000n,
      ownerCommitment: 1n,
      innerHash: 2n,
      leafIndex: 0n,
    };
    await expect(
      daemon.placeOrder(
        {
          symbol: "SOL-USDC",
          side: OrderSide.Bid,
          policy: limitPolicy({ priceLimit: 100n }),
          amount: 10n,
        },
        collateral,
      ),
    ).rejects.toThrow(/trading paused/);
    expect(prover).not.toHaveBeenCalled();

    const orderId = "ab".repeat(16);
    store.putOrder({
      ...newManagedOrder({
        orderId,
        seedIndex: 0,
        side: "bid",
        priceRaw: 100n,
        sizeRaw: 10n,
      }),
      phase: "open",
    });
    await (
      daemon as unknown as {
        engine: { dispatch: (id: string, event: unknown) => Promise<unknown> };
      }
    ).engine.dispatch(orderId, {
      type: "fill",
      producedChangeNote: true,
    });
    expect(anchorPoster.post).not.toHaveBeenCalled();

    await daemon.cancelOrder(orderId);
    expect(placer.cancel).toHaveBeenCalledOnce();
    expect(store.getOrder(orderId)?.phase).toBe("cancelled");
    await vi.waitFor(() => expect(mergeRunner.run).toHaveBeenCalledOnce());
    daemon.stop();
  });

  it("uses the last finalized key set for at most five minutes, then recovers on a matching refresh", async () => {
    let now = 1_000;
    let rpcFails = false;
    const daemon = new Daemon({
      config: config(),
      keystore: keystore(),
      store,
      prover: vi.fn() as never,
      placer: {
        place: vi.fn(),
        cancel: vi.fn(),
        modify: vi.fn(),
        close: vi.fn(),
      } as never,
      subscribeFills: (() => ({ close() {} })) as never,
      subscribeOrders: (() => ({ close() {} })) as never,
      verifyAttestation: async () => verifiedIdentity(),
      onchainTeePubkeys: async () => {
        if (rpcFails) throw new Error("temporary RPC failure");
        return [TEE_PUBKEY_B58];
      },
      verifyRoot: false,
      now: () => now,
      teeKeyStaleMs: 300_000,
    });
    await daemon.start();
    expect(daemon.getTrustStatus().lastFinalizedKeyRefreshMs).toBe(1_000);

    rpcFails = true;
    now = 300_999;
    await daemon.refreshTrustNow();
    expect(daemon.getTrustStatus().tradingEnabled).toBe(true);

    now = 301_000;
    await daemon.refreshTrustNow();
    expect(daemon.getTrustStatus()).toMatchObject({
      tradingEnabled: false,
      pauseReason: expect.stringMatching(/stale/),
    });

    rpcFails = false;
    now = 302_000;
    await daemon.refreshTrustNow();
    expect(daemon.getTrustStatus()).toMatchObject({
      tradingEnabled: true,
      pauseReason: null,
      lastFinalizedKeyRefreshMs: 302_000,
    });
    daemon.stop();
  });

  it("refreshes the finalized key set every minute", async () => {
    vi.useFakeTimers();
    const reader = vi.fn(async () => [TEE_PUBKEY_B58]);
    const daemon = new Daemon({
      config: config(),
      keystore: keystore(),
      store,
      prover: vi.fn() as never,
      placer: {
        place: vi.fn(),
        cancel: vi.fn(),
        modify: vi.fn(),
        close: vi.fn(),
      } as never,
      subscribeFills: (() => ({ close() {} })) as never,
      subscribeOrders: (() => ({ close() {} })) as never,
      verifyAttestation: async () => verifiedIdentity(),
      onchainTeePubkeys: reader,
      verifyRoot: false,
    });
    try {
      await daemon.start();
      expect(reader).toHaveBeenCalledOnce();
      await vi.advanceTimersByTimeAsync(DEFAULT_TEE_KEY_REFRESH_MS - 1);
      expect(reader).toHaveBeenCalledOnce();
      await vi.advanceTimersByTimeAsync(1);
      expect(reader).toHaveBeenCalledTimes(2);
    } finally {
      daemon.stop();
      vi.useRealTimers();
    }
  });
});
