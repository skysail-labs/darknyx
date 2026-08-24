/** D2: one supervised transport generation across restart recovery. */

import { afterEach, describe, expect, it, vi } from "vitest";

import { Daemon } from "../src/daemon.js";
import { DaemonStore } from "../src/store.js";
import { Keystore } from "../src/keystore.js";
import { DEFAULT_THRESHOLDS } from "../src/order-lifecycle.js";
import {
  DaemonTransportSupervisor,
  type DaemonTransport,
} from "../src/transport.js";
import {
  AttestationError,
  type AttestationResult,
} from "../src/attestation.js";
import type { DaemonConfig } from "../src/config.js";
import { TransportVerificationError } from "@darknyx/sdk/transport-node";

const stores: DaemonStore[] = [];
afterEach(() => {
  for (const store of stores.splice(0)) store.close();
  vi.restoreAllMocks();
});

const config = (): DaemonConfig => ({
  gatewayUrl: "https://cvm",
  gatewayWsUrl: "wss://cvm",
  token: "token",
  transportMode: "ra-tls",
  deploymentTier: "production",
  allowLegacyTransport: false,
  expectSignerSetSha256: "33".repeat(32),
  rpcUrl: "https://rpc",
  dbPath: ":memory:",
  controlPort: 0,
  keystorePath: "unused",
  orderSequencePath: "unused",
  thresholds: DEFAULT_THRESHOLDS,
  attestation: { composeHash: "aa".repeat(32) },
  attestationStrict: false,
  attestOnchainCheck: false,
  programId: "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
});

function identity(bootByte: string): AttestationResult {
  return {
    teePubkey: "tee",
    teePubkeys: ["tee"],
    composeHash: "aa".repeat(32),
    quote: "quote",
    dcapVerified: true,
    bootSessionId: bootByte.repeat(32),
    transportMode: "ra-tls",
  };
}

function generation(name: string) {
  const close = vi.fn(async () => undefined);
  const transport: DaemonTransport = {
    fetch: vi.fn(async () => new Response(name)) as unknown as typeof fetch,
    webSocketFactory: vi.fn(() => ({ name })),
    isStale: () => false,
    mode: "ra-tls",
    close,
  };
  return { transport, close };
}

function buildDaemon(
  supervisor: DaemonTransportSupervisor,
  verifyAttestation: NonNullable<
    ConstructorParameters<typeof Daemon>[0]["verifyAttestation"]
  >,
  overrides: Partial<ConstructorParameters<typeof Daemon>[0]> = {},
) {
  const store = new DaemonStore(":memory:");
  stores.push(store);
  const streamClient = {
    suspend: vi.fn(),
    resume: vi.fn(),
    close: vi.fn(),
  };
  const placer = {
    place: vi.fn(),
    cancel: vi.fn(),
    modify: vi.fn(),
    close: vi.fn(),
  };
  const daemon = new Daemon({
    config: overrides.config ?? config(),
    keystore: new Keystore({
      masterSeed: new Uint8Array(64).fill(7),
    }),
    store,
    prover: vi.fn() as never,
    placer: placer as never,
    streamClient: streamClient as never,
    fetchImpl: supervisor.fetch,
    transportSupervisor: supervisor,
    verifyAttestation,
    verifyRoot: false,
    reconcileOnStart: false,
    finalizedSlot: async () => 100,
    ...overrides,
  });
  const reconcileSpy = vi.spyOn(daemon, "reconcileNow").mockResolvedValue({
    ordersRephased: 1,
    ordersUnknown: 0,
    mergeLatchesCleared: 0,
    notesRecovered: 1,
    errors: [],
  });
  return { daemon, streamClient, placer, reconcileSpy };
}

describe("daemon transport lifecycle", () => {
  it("routes a typed HTTP refusal into the same supervisor callback", async () => {
    const active = generation("active");
    active.transport.fetch = vi.fn(async () => {
      throw new TypeError("fetch failed", {
        cause: new TransportVerificationError("wrong peer", "spki_mismatch"),
      });
    }) as unknown as typeof fetch;
    const supervisor = new DaemonTransportSupervisor(
      active.transport,
      async () => generation("unused").transport,
    );
    const onViolation = vi.fn();
    supervisor.setViolationHandler(onViolation);

    await expect(supervisor.fetch("https://cvm/orders")).rejects.toMatchObject({
      cause: { kind: "spki_mismatch" },
    });
    expect(onViolation).toHaveBeenCalledTimes(1);
    expect(onViolation.mock.calls[0]?.[0]).toMatchObject({
      kind: "spki_mismatch",
    });
  });

  it("collapses concurrent violations and swaps HTTP/WS only after verification", async () => {
    const old = generation("old");
    const next = generation("next");
    let resolveCandidate!: (value: DaemonTransport) => void;
    const factory = vi.fn(
      () =>
        new Promise<DaemonTransport>((resolve) => {
          resolveCandidate = resolve;
        }),
    );
    const supervisor = new DaemonTransportSupervisor(old.transport, factory);
    const verify = vi.fn(async () => identity("5b"));
    const { daemon, streamClient, placer, reconcileSpy } = buildDaemon(
      supervisor,
      verify,
    );
    let resolveReconcile!: (
      value: Awaited<ReturnType<Daemon["reconcileNow"]>>,
    ) => void;
    reconcileSpy.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveReconcile = resolve;
        }),
    );

    const recoveries = Array.from({ length: 10 }, () =>
      daemon.recoverTransportNow("boot_changed"),
    );
    await Promise.resolve();
    expect(factory).toHaveBeenCalledTimes(1);
    expect(streamClient.suspend).toHaveBeenCalledTimes(1);
    expect(await (await supervisor.fetch("https://cvm/info")).text()).toBe(
      "old",
    );
    expect(supervisor.webSocketFactory("wss://cvm")).toEqual({ name: "old" });

    resolveCandidate(next.transport);
    await vi.waitFor(() => {
      expect(daemon.getTrustStatus().transportState).toBe("reconciling");
    });
    expect(daemon.getTrustStatus()).toMatchObject({
      tradingEnabled: false,
      transportState: "reconciling",
    });
    resolveReconcile({
      ordersRephased: 1,
      ordersUnknown: 0,
      mergeLatchesCleared: 0,
      notesRecovered: 1,
      errors: [],
    });
    await Promise.all(recoveries);

    expect(verify).toHaveBeenCalledTimes(1);
    expect(old.close).toHaveBeenCalledTimes(1);
    expect(next.close).not.toHaveBeenCalled();
    expect(streamClient.resume).toHaveBeenCalledTimes(1);
    expect(await (await supervisor.fetch("https://cvm/info")).text()).toBe(
      "next",
    );
    expect(supervisor.webSocketFactory("wss://cvm")).toEqual({ name: "next" });
    expect(daemon.getTrustStatus()).toMatchObject({
      tradingEnabled: true,
      transportState: "ready",
      transportPauseReason: null,
      transportRecoveryAttempts: 0,
    });
    expect(daemon.getAttestation()?.bootSessionId).toBe("5b".repeat(32));
    expect(placer.place).not.toHaveBeenCalled();
  });

  it("latches recovery before a synchronous error subscriber can re-enter", async () => {
    const old = generation("old");
    const next = generation("next");
    const factory = vi.fn(async () => next.transport);
    const supervisor = new DaemonTransportSupervisor(old.transport, factory);
    const { daemon } = buildDaemon(supervisor, async () => identity("5b"));
    let reentrant: Promise<void> | null = null;
    daemon.subscribe((event) => {
      if (
        event.type === "error" &&
        event.context === "transport" &&
        reentrant === null
      ) {
        reentrant = daemon.recoverTransportNow("boot_changed");
      }
    });

    await daemon.recoverTransportNow("boot_changed", new Error("boot rotated"));
    await reentrant;

    expect(
      reentrant,
      "the transport event must have re-entered",
    ).not.toBeNull();
    expect(factory).toHaveBeenCalledTimes(1);
    expect(old.close).toHaveBeenCalledTimes(1);
  });

  it("keeps a security verdict paused and closes the rejected candidate", async () => {
    const old = generation("old");
    const rejected = generation("rejected");
    const supervisor = new DaemonTransportSupervisor(
      old.transport,
      async () => rejected.transport,
    );
    const { daemon, streamClient } = buildDaemon(supervisor, async () => {
      throw new AttestationError("compose mismatch", "compose_mismatch");
    });

    await daemon.recoverTransportNow("transport_rejected");

    expect(rejected.close).toHaveBeenCalledTimes(1);
    expect(old.close).not.toHaveBeenCalled();
    expect(streamClient.resume).not.toHaveBeenCalled();
    expect(daemon.getTrustStatus()).toMatchObject({
      tradingEnabled: false,
      transportState: "paused",
      transportPauseReason: "application_attestation_rejected",
      transportNextAttemptMs: null,
    });
  });

  it("keeps placement paused when reconciliation fails after the swap", async () => {
    const old = generation("old");
    const next = generation("next");
    const supervisor = new DaemonTransportSupervisor(
      old.transport,
      async () => next.transport,
    );
    const { daemon, reconcileSpy } = buildDaemon(supervisor, async () =>
      identity("5b"),
    );
    reconcileSpy.mockResolvedValue({
      ordersRephased: 0,
      ordersUnknown: 0,
      mergeLatchesCleared: 0,
      notesRecovered: 0,
      errors: ["chain reconciliation failed"],
    });

    await daemon.recoverTransportNow("boot_changed");

    expect(old.close).toHaveBeenCalledTimes(1);
    expect(next.close).not.toHaveBeenCalled();
    expect(daemon.getTrustStatus()).toMatchObject({
      tradingEnabled: false,
      transportState: "paused",
      transportPauseReason: "reconciliation_failed",
      transportNextAttemptMs: null,
    });
  });

  it("rejects /info from a boot other than the quote-bound transport boot", async () => {
    const old = generation("old");
    const rejected = generation("rejected");
    rejected.transport.bootSessionId = new Uint8Array(32).fill(0x4a);
    const supervisor = new DaemonTransportSupervisor(
      old.transport,
      async () => rejected.transport,
    );
    const { daemon } = buildDaemon(supervisor, async () => identity("5b"));

    await daemon.recoverTransportNow("boot_changed");

    expect(rejected.close).toHaveBeenCalledTimes(1);
    expect(daemon.getTrustStatus()).toMatchObject({
      transportState: "paused",
      transportPauseReason: "application_attestation_rejected",
    });
  });

  it("reports finalized signer disagreement as a governance rejection", async () => {
    const old = generation("old");
    const rejected = generation("rejected");
    const supervisor = new DaemonTransportSupervisor(
      old.transport,
      async () => rejected.transport,
    );
    const strictConfig = {
      ...config(),
      attestOnchainCheck: true,
    };
    const { daemon } = buildDaemon(supervisor, async () => identity("5b"), {
      config: strictConfig,
      onchainTeePubkeys: async () => ["different"],
    });

    await daemon.recoverTransportNow("boot_changed");

    expect(rejected.close).toHaveBeenCalledTimes(1);
    expect(daemon.getTrustStatus()).toMatchObject({
      transportState: "paused",
      transportPauseReason: "governance_rejected",
    });
  });

  it("backs off only a network failure and stop cancels the retry", async () => {
    const old = generation("old");
    const candidate = generation("candidate");
    const supervisor = new DaemonTransportSupervisor(
      old.transport,
      async () => candidate.transport,
    );
    const { daemon } = buildDaemon(supervisor, async () => {
      throw new AttestationError("offline", "fetch");
    });

    await daemon.recoverTransportNow("boot_changed");
    expect(daemon.getTrustStatus()).toMatchObject({
      transportState: "paused",
      transportPauseReason: "network_unavailable",
    });
    expect(daemon.getTrustStatus().transportNextAttemptMs).not.toBeNull();

    daemon.stop();
    expect(daemon.getTrustStatus()).toMatchObject({
      transportState: "paused",
      transportPauseReason: "stopped",
      transportNextAttemptMs: null,
      transportRecoveryAttempts: 0,
    });
  });

  it("stop during verification closes the candidate and never resumes", async () => {
    const old = generation("old");
    const candidate = generation("candidate");
    let resolveCandidate!: (value: DaemonTransport) => void;
    const supervisor = new DaemonTransportSupervisor(
      old.transport,
      () =>
        new Promise<DaemonTransport>((resolve) => {
          resolveCandidate = resolve;
        }),
    );
    const { daemon, streamClient } = buildDaemon(supervisor, async () =>
      identity("5b"),
    );

    const recovery = daemon.recoverTransportNow("boot_changed");
    await Promise.resolve();
    daemon.stop();
    resolveCandidate(candidate.transport);
    await recovery;

    expect(candidate.close).toHaveBeenCalledTimes(1);
    expect(streamClient.resume).not.toHaveBeenCalled();
    expect(daemon.getTrustStatus()).toMatchObject({
      transportState: "paused",
      transportPauseReason: "stopped",
    });
  });
});
