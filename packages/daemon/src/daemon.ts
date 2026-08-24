/**
 * Daemon — the assembled, runnable client.
 *
 * Wires every slice into one long-running object: the {@link DaemonStore} (UTXO
 * + managed orders), the {@link LifecycleEngine} driving a
 * {@link DaemonActionExecutor} (auto-merge via the {@link MergeRunner}), the multiplexed TEE stream
 * channels ({@link FillsListener} fills, {@link OrdersListener} orders), and
 * the {@link OrderPlacer}. It exposes the high-level operations
 * a control surface needs — `placeOrder` / `cancelOrder` / `listOrders` /
 * `balances` — plus a `subscribe` stream of order + fill events.
 *
 * Everything heavy is injectable (placer, merge runner, the WS
 * `subscribe*` fns, the prover, fetch) so the whole thing is testable without a
 * CVM; `bin/daemon.ts` supplies the real implementations.
 */

import { Connection, PublicKey } from "@solana/web3.js";
import {
  OrderSide,
  assertTeePubkeysMatch,
  buildCancel,
  depositNoteFromReceipt,
  onchainRootVerifier,
  vaultConfigPda,
  vaultConfigTeePubkeys,
  TradingClient,
  type DepositParams,
  type DepositReceipt,
  type RootVerifier,
  type StoredNote,
  type ValidInputProver,
  type WebSocketFactory,
  type SendableWebSocketFactory,
  type StreamTokenProvider,
} from "@darknyx/sdk";

import type { DaemonConfig } from "./config.js";
import { DaemonStore } from "./store.js";
import { Keystore } from "./keystore.js";
import { LifecycleEngine } from "./lifecycle-engine.js";
import { DaemonActionExecutor, type MergeRunner } from "./action-executor.js";
import { FillsListener, type SubscribeFillsFn } from "./fills-listener.js";
import {
  OrdersListener,
  type SubscribeOrderUpdatesFn,
} from "./orders-listener.js";
import { WsOrderPlacer, type OrderPlacer } from "./order-placer.js";
import { placeManagedOrder } from "./place.js";
import { buildPlaceRequest, type OrderIntent } from "./build-place-request.js";
import { newManagedOrder, type ManagedOrder } from "./types.js";
import {
  fetchInfo,
  verifyAttestation,
  type AttestationResult,
  type QuoteVerifier,
} from "./attestation.js";
import {
  SettlementTracker,
  type FetchInclusionFn,
} from "./settlement-tracker.js";
import type { CollateralRequest } from "./note-select.js";
import { TeeReadClient } from "./tee-read.js";
import { reconcile, type ReconcileResult } from "./reconcile.js";
import { MemoryOrderSequence, type OrderSequence } from "./order-sequence.js";
import type {
  DaemonTransport,
  DaemonTransportSupervisor,
} from "./transport.js";

const toHex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
const fromHex = (h: string): Uint8Array =>
  Uint8Array.from(Buffer.from(h, "hex"));

export const DEFAULT_TEE_KEY_REFRESH_MS = 60_000;
export const DEFAULT_TEE_KEY_STALE_MS = 5 * 60_000;
const TRANSPORT_RECOVERY_MAX_ATTEMPTS = 5;
const TRANSPORT_RECOVERY_BASE_MS = 250;
const TRANSPORT_RECOVERY_MAX_MS = 10_000;

export type TransportLifecycleState =
  | "ready"
  | "reverifying"
  | "reconciling"
  | "paused";
export type TransportPauseReason =
  | "boot_changed"
  | "transport_rejected"
  | "application_attestation_rejected"
  | "governance_rejected"
  | "network_unavailable"
  | "reconciliation_failed"
  | "stopped";

/** Reads finalized on-chain `vault_config.tee_pubkeys` (base58, active set), or
 *  `null` if the config account is absent. Injectable so the attestation
 *  cross-check is testable without a live RPC. */
export type OnchainTeePubkeysReader = (
  rpcUrl: string,
  programId: string,
) => Promise<string[] | null>;

const defaultOnchainTeePubkeys: OnchainTeePubkeysReader = async (
  rpcUrl,
  programId,
) => {
  const owner = new PublicKey(programId);
  const conn = new Connection(rpcUrl, "finalized");
  const [pda] = await vaultConfigPda(owner);
  const acct = await conn.getAccountInfo(pda, "finalized");
  if (acct && !acct.owner.equals(owner)) {
    throw new Error(
      `vault_config is owned by ${acct.owner.toBase58()}, not ${owner.toBase58()}`,
    );
  }
  return acct ? vaultConfigTeePubkeys(acct.data) : null;
};

/** An event the daemon pushes to subscribers (the control-API stream). */
export type DaemonEvent =
  | { type: "order"; order: ManagedOrder }
  | { type: "fill"; note: StoredNote }
  | { type: "error"; context: string; message: string };

/** Per-mint balance (sum of unspent note amounts). */
export interface Balance {
  mint: string; // hex
  amount: string; // decimal (bigint)
  notes: number;
}

/** Security state exposed through the local control API. A paused daemon keeps
 *  streams, cancellation, and settlement reconciliation alive. */
export interface DaemonTrustStatus {
  tradingEnabled: boolean;
  /** The effective reason placement is refused — trust OR reconciliation. */
  pauseReason: string | null;
  /** A reconciliation is running right now. */
  reconciling: boolean;
  /** Set while the last reconciliation is known not to have completed cleanly;
   *  cleared only by a later error-free one. */
  reconcileFailureReason: string | null;
  lastFinalizedKeyRefreshMs: number | null;
  onchainKeyMonitoring: boolean;
  transportState: TransportLifecycleState;
  transportPauseReason: TransportPauseReason | null;
  transportRecoveryAttempts: number;
  transportNextAttemptMs: number | null;
}

/** A MergeRunner that refuses — the default until the on-chain merge path is
 *  wired (needs devnet). Surfaces as `merge-failed`, so residuals just wait. */
const UNCONFIGURED_MERGE: MergeRunner = {
  async run() {
    throw new Error("merge runner not configured");
  },
};

export interface DaemonDeps {
  config: DaemonConfig;
  keystore: Keystore;
  store: DaemonStore;
  /** Durable HD-index high-water mark; must outlive the rebuildable DB. */
  orderSequence?: OrderSequence;
  /** VALID_INPUT prover for order placement (e.g. SDK `nodeValidInputProver`). */
  prover: ValidInputProver;
  // ── injectables (defaults built from config) ──
  placer?: OrderPlacer;
  mergeRunner?: MergeRunner;
  subscribeFills?: SubscribeFillsFn;
  subscribeOrders?: SubscribeOrderUpdatesFn;
  webSocketFactory?: WebSocketFactory;
  sendableWebSocketFactory?: SendableWebSocketFactory;
  /** Refreshable bearer source for the long-lived `/v1/stream` session. */
  streamTokenProvider?: StreamTokenProvider;
  /** Existing multiplexed stream session (tests or advanced embedding). */
  streamClient?: TradingClient;
  /**
   * REQUIRED. The transport every CVM call in this daemon uses.
   *
   * Optional here is what let `/auth/token`, `/tree/leaves` and the order POST
   * each quietly reach the enclave on `globalThis.fetch` while the daemon
   * logged "transport: ra-tls". Offline callers pass `globalThis.fetch`
   * explicitly.
   */
  fetchImpl: typeof fetch;
  /** Atomic owner of the RA-TLS HTTP/WS generation. */
  transportSupervisor?: DaemonTransportSupervisor;
  /** Verify the gateway's TEE attestation on start. Defaults to the real
   *  {@link verifyAttestation}; pass `false` to skip (tests/local-sim). */
  verifyAttestation?: typeof verifyAttestation | false;
  /** Optional DCAP quote verifier (full Intel TCB) handed to the attestation. */
  quoteVerifier?: QuoteVerifier;
  /** Reads on-chain `vault_config.tee_pubkeys` for the attestation cross-check.
   *  Defaults to a `Connection`-based read from `config.rpcUrl`. */
  onchainTeePubkeys?: OnchainTeePubkeysReader;
  /** Root-ring verifier for order proofs. Defaults to a finalized on-chain
   *  check; `false` is reserved for isolated tests. */
  verifyRoot?: RootVerifier | false;
  /** Finalized TEE-key refresh interval; defaults to one minute. */
  teeKeyRefreshMs?: number;
  /** Maximum age of the last successful finalized read; defaults to 5 min. */
  teeKeyStaleMs?: number;
  /** Clock seam for deterministic trust-state tests. */
  now?: () => number;
  /** Settlement-tracker poll interval (ms) for resolving change-note leaves. */
  settlementPollMs?: number;
  /** Reconcile local state against the CVM + chain during `start()` (SW-11).
   *  Defaults to `true`; isolated unit suites that stand up no CVM pass
   *  `false`. */
  reconcileOnStart?: boolean;
  /** Finalized slot high-water reader for incremental reconciliation.
   * Defaults to the configured Solana RPC; injectable for tests. */
  finalizedSlot?: () => Promise<number>;
  /** Seam for the tracker's `/tree/inclusion` fetch (tests). */
  fetchInclusion?: FetchInclusionFn;
  /** SDK deposit fn (`getDepositFunction({ client })`). Enables `deposit`. */
  depositFn?: (params: DepositParams) => Promise<DepositReceipt>;
  /** The deposit fee-payer / depositor pubkey (matches `depositFn`'s payer). */
  depositor?: PublicKey;
}

export class Daemon {
  private readonly config: DaemonConfig;
  private readonly keystore: Keystore;
  private readonly store: DaemonStore;
  private readonly orderSequence: OrderSequence;
  private readonly prover: ValidInputProver;
  private readonly engine: LifecycleEngine;
  private readonly placer: OrderPlacer;
  /** Authenticated read-only TEE surface (account/instruments/settlement/…). */
  readonly tee: TeeReadClient;
  private readonly fetchImpl: typeof fetch;
  private readonly transportSupervisor?: DaemonTransportSupervisor;
  private readonly treeId = 0;

  private readonly subscribeFillsFn?: SubscribeFillsFn;
  private readonly subscribeOrdersFn?: SubscribeOrderUpdatesFn;
  private readonly streamClient: TradingClient;

  private readonly verifyAttestationFn: typeof verifyAttestation | false;
  private readonly quoteVerifier?: QuoteVerifier;
  private readonly onchainTeePubkeysFn: OnchainTeePubkeysReader;
  private readonly verifyRootFn?: RootVerifier;
  private readonly teeKeyRefreshMs: number;
  private readonly teeKeyStaleMs: number;
  private readonly now: () => number;
  private attestationResult: AttestationResult | null = null;
  private bootSessionId: Uint8Array | null = null;
  private expectedTeePubkeys: string[] | null = null;
  private lastFinalizedKeyRefreshMs: number | null = null;
  private tradingPauseReason: string | null = null;
  /**
   * Set while a reconciliation is running (SW-11). Deliberately separate from
   * `tradingPauseReason`: `resumeTrading()` clears that field unconditionally,
   * so reusing it here would silently clear an outstanding TRUST pause when the
   * reconcile finished. Independent reasons, same lesson as the enclave's
   * `TradingPauseReason` bitset.
   */
  private reconciling = false;
  /** Guards against a second reconcile starting while one is in flight. */
  private reconcileInFlight: Promise<ReconcileResult> | null = null;
  /**
   * Set when a reconciliation could not complete cleanly; cleared only by a
   * later error-free one.
   *
   * A failed reconcile means local state is UNVERIFIED, not merely stale.
   * Resuming placement then risks spending collateral the chain has already
   * consumed, so the pause has to outlive the attempt that failed — which is
   * why this is its own field and not `tradingPauseReason`: the trust-refresh
   * path calls `resumeTrading()`, which clears that one unconditionally and
   * would silently re-open trading onto unverified state.
   */
  private reconcileFailureReason: string | null = null;
  /**
   * Whether `start()` reconciles. On by default; the unit suites construct a
   * daemon with no CVM or RPC behind it and assert on `start()` itself, so they
   * opt out rather than every one of them growing a mock chain.
   */
  private readonly reconcileOnStart: boolean;
  private readonly finalizedSlotFn: () => Promise<number>;
  /** Inclusive lower bound for the next live-session chain recovery. A true
   * process restart deliberately starts without one and performs cold
   * recovery before establishing a new high-water mark. */
  private reconciliationCursorSlot: number | undefined;
  private teeKeyRefreshTimer: ReturnType<typeof setInterval> | null = null;
  private teeKeyRefreshInFlight = false;
  private transportState: TransportLifecycleState = "ready";
  private transportPauseReason: TransportPauseReason | null = null;
  private transportRecoveryAttempts = 0;
  private transportNextAttemptMs: number | null = null;
  private transportRecoveryInFlight: Promise<void> | null = null;
  private transportRecoveryTimer: ReturnType<typeof setTimeout> | null = null;
  private stopped = false;

  private readonly settlementPollMs?: number;
  private readonly fetchInclusion?: FetchInclusionFn;
  private readonly depositFn?: (
    params: DepositParams,
  ) => Promise<DepositReceipt>;
  private readonly depositor?: PublicKey;

  private fills: FillsListener | null = null;
  private orders: OrdersListener | null = null;
  private tracker: SettlementTracker | null = null;
  private readonly listeners = new Set<(e: DaemonEvent) => void>();
  private started = false;

  constructor(deps: DaemonDeps) {
    this.config = deps.config;
    this.keystore = deps.keystore;
    this.store = deps.store;
    if (!deps.orderSequence && !this.store.isEphemeral) {
      throw new Error(
        "a durable orderSequence is required when the daemon store is persistent",
      );
    }
    this.orderSequence =
      deps.orderSequence ??
      new MemoryOrderSequence(this.store.maxSeedIndex() + 1);
    this.prover = deps.prover;
    this.fetchImpl = deps.fetchImpl;
    this.transportSupervisor = deps.transportSupervisor;
    this.subscribeFillsFn = deps.subscribeFills;
    this.subscribeOrdersFn = deps.subscribeOrders;
    const streamSocketFactory =
      deps.sendableWebSocketFactory ?? deps.webSocketFactory;
    this.streamClient =
      deps.streamClient ??
      new TradingClient({
        gatewayWsUrl: this.config.gatewayWsUrl,
        token: this.config.token,
        tokenProvider: deps.streamTokenProvider,
        cancelOnDisconnect: true,
        webSocketFactory: streamSocketFactory,
        onError: (error) => this.emitError("stream", error),
      });
    // Attest by default (non-custody is the point); inject `false` to skip.
    this.verifyAttestationFn = deps.verifyAttestation ?? verifyAttestation;
    this.quoteVerifier = deps.quoteVerifier;
    this.onchainTeePubkeysFn =
      deps.onchainTeePubkeys ?? defaultOnchainTeePubkeys;
    this.verifyRootFn =
      deps.verifyRoot === false
        ? undefined
        : (deps.verifyRoot ??
          onchainRootVerifier({
            connection: new Connection(this.config.rpcUrl, "finalized"),
            programId: new PublicKey(this.config.programId),
          }));
    this.teeKeyRefreshMs = deps.teeKeyRefreshMs ?? DEFAULT_TEE_KEY_REFRESH_MS;
    this.teeKeyStaleMs = deps.teeKeyStaleMs ?? DEFAULT_TEE_KEY_STALE_MS;
    this.now = deps.now ?? Date.now;
    if (
      this.teeKeyRefreshMs <= 0 ||
      this.teeKeyStaleMs <= 0 ||
      this.teeKeyStaleMs < this.teeKeyRefreshMs
    ) {
      throw new Error(
        "TEE key intervals must be positive and stale must not be shorter than refresh",
      );
    }
    if (this.verifyAttestationFn) {
      this.tradingPauseReason = "attestation has not completed";
    }
    this.settlementPollMs = deps.settlementPollMs;
    this.reconcileOnStart = deps.reconcileOnStart ?? true;
    this.finalizedSlotFn =
      deps.finalizedSlot ??
      (async () => {
        const raw = await new Connection(
          this.config.rpcUrl,
          "finalized",
        ).getSlot("finalized");
        const slot = Number(raw);
        if (!Number.isSafeInteger(slot) || slot < 0) {
          throw new Error(`finalized slot is outside the safe range: ${raw}`);
        }
        return slot;
      });
    this.fetchInclusion = deps.fetchInclusion;
    this.depositFn = deps.depositFn;
    this.depositor = deps.depositor;

    const executor = new DaemonActionExecutor({
      merge: deps.mergeRunner ?? UNCONFIGURED_MERGE,
    });

    this.engine = new LifecycleEngine(this.store, executor, {
      thresholds: this.config.thresholds,
      onError: (err, ctx) => this.emitError(ctx, err),
      onTransition: (order, event) => {
        if (event.type === "fill") this.pruneConsumedCollateral(order);
        this.emit({ type: "order", order });
      },
    });

    this.placer =
      deps.placer ??
      new WsOrderPlacer({
        gatewayWsUrl: this.config.gatewayWsUrl,
        token: this.config.token,
        cancelOnDisconnect: true,
        client: this.streamClient,
      });

    this.tee = new TeeReadClient({
      gatewayUrl: this.config.gatewayUrl,
      token: this.config.token,
      fetchImpl: this.fetchImpl,
    });
    this.transportSupervisor?.setViolationHandler((error) => {
      void this.recoverTransportNow("transport_rejected", error);
    });
  }

  // ── lifecycle ──

  private async verifyApplicationIdentity(
    fetchImpl: typeof fetch,
    expectedTransportBoot?: Uint8Array,
  ): Promise<{
    attestation: AttestationResult | null;
    bootSessionId: Uint8Array;
    teePubkeys: string[] | null;
  }> {
    if (this.verifyAttestationFn) {
      const attestation = await this.verifyAttestationFn({
        gatewayUrl: this.config.gatewayUrl,
        token: this.config.token,
        expected: this.config.attestation,
        quoteVerifier: this.quoteVerifier,
        fetchImpl,
        strict: this.config.attestationStrict,
        expectedTransportMode: this.config.transportMode,
      });
      const teePubkeys = this.config.attestOnchainCheck
        ? [...attestation.teePubkeys]
        : null;
      const bootSessionId = fromHex(attestation.bootSessionId);
      this.assertTransportBootMatches(expectedTransportBoot, bootSessionId);
      return {
        attestation,
        bootSessionId,
        teePubkeys,
      };
    }

    const info = await fetchInfo(
      this.config.gatewayUrl,
      this.config.token,
      fetchImpl,
    );
    if (info.transportMode !== this.config.transportMode) {
      throw new Error(
        `/info transport_mode ${info.transportMode} != expected ${this.config.transportMode}`,
      );
    }
    const bootSessionId = fromHex(info.bootSessionId);
    this.assertTransportBootMatches(expectedTransportBoot, bootSessionId);
    return {
      attestation: null,
      bootSessionId,
      teePubkeys: null,
    };
  }

  private assertTransportBootMatches(
    expected: Uint8Array | undefined,
    observed: Uint8Array,
  ): void {
    if (!expected) return;
    if (
      expected.length !== observed.length ||
      expected.some((byte, index) => byte !== observed[index])
    ) {
      throw new Error(
        "/info boot_session_id does not match the quote-bound transport boot",
      );
    }
  }

  private applyVerifiedIdentity(identity: {
    attestation: AttestationResult | null;
    bootSessionId: Uint8Array;
    teePubkeys: string[] | null;
  }): void {
    if (identity.bootSessionId.length !== 32) {
      throw new Error("/info boot_session_id must be 32 bytes");
    }
    this.attestationResult = identity.attestation;
    this.bootSessionId = identity.bootSessionId;
    this.expectedTeePubkeys = identity.teePubkeys;
  }

  private isRetryableTransportFailure(error: unknown): boolean {
    let current: unknown = error;
    for (let depth = 0; depth < 4; depth += 1) {
      const kind =
        typeof current === "object" && current !== null && "kind" in current
          ? String((current as { kind?: unknown }).kind)
          : null;
      if (kind === "fetch" || kind === "socket_lost") return true;
      if (
        typeof current !== "object" ||
        current === null ||
        !("cause" in current)
      ) {
        return false;
      }
      current = (current as { cause?: unknown }).cause;
    }
    return false;
  }

  private scheduleTransportRecoveryRetry(): void {
    if (
      this.stopped ||
      this.transportRecoveryTimer ||
      this.transportRecoveryAttempts >= TRANSPORT_RECOVERY_MAX_ATTEMPTS
    ) {
      return;
    }
    const exponent = Math.max(0, this.transportRecoveryAttempts - 1);
    const ceiling = Math.min(
      TRANSPORT_RECOVERY_MAX_MS,
      TRANSPORT_RECOVERY_BASE_MS * 2 ** exponent,
    );
    const delay = Math.max(
      1,
      Math.floor(ceiling * (0.75 + Math.random() * 0.5)),
    );
    this.transportNextAttemptMs = this.now() + delay;
    this.transportRecoveryTimer = setTimeout(() => {
      this.transportRecoveryTimer = null;
      this.transportNextAttemptMs = null;
      void this.recoverTransportNow("network_unavailable");
    }, delay);
    this.transportRecoveryTimer.unref?.();
  }

  /**
   * Rebuild the entire HTTP/WS generation, re-run application + finalized
   * governance verification, then reconcile before placement resumes.
   * Concurrent callers share one attempt; security failures never auto-retry.
   */
  async recoverTransportNow(
    reason: TransportPauseReason = "boot_changed",
    trigger?: unknown,
  ): Promise<void> {
    if (!this.transportSupervisor || this.stopped) return;
    if (this.transportRecoveryInFlight) return this.transportRecoveryInFlight;

    this.transportState = "reverifying";
    this.transportPauseReason = reason;
    this.transportRecoveryAttempts += 1;
    const run = (async () => {
      // Yield so the single-flight latch below is assigned before the
      // synchronous error event can let a subscriber re-enter this method.
      await Promise.resolve();
      this.streamClient.suspend();
      if (trigger) this.emitError("transport", trigger);
      let candidate: DaemonTransport | null = null;
      let committed = false;
      let failureReason: TransportPauseReason = "transport_rejected";
      try {
        candidate = await this.transportSupervisor!.buildCandidate();
        failureReason = "application_attestation_rejected";
        const identity = await this.verifyApplicationIdentity(
          candidate.fetch,
          candidate.bootSessionId,
        );
        failureReason = "governance_rejected";
        if (identity.teePubkeys) {
          await this.requireFinalizedTeePubkeys(identity.teePubkeys, false);
        }
        if (this.stopped) {
          await candidate.close();
          candidate = null;
          return;
        }
        await this.transportSupervisor!.commit(candidate);
        committed = true;
        candidate = null;
        if (this.stopped) return;
        this.applyVerifiedIdentity(identity);
        if (identity.teePubkeys) this.lastFinalizedKeyRefreshMs = this.now();
        this.resumeTrading();
        this.transportState = "reconciling";
        this.transportPauseReason = "boot_changed";
        this.streamClient.resume();
        const reconciliation = await this.reconcileNow(
          "verified transport generation changed",
        );
        if (this.stopped) return;
        if (reconciliation.errors.length > 0) {
          this.transportState = "paused";
          this.transportPauseReason = "reconciliation_failed";
          return;
        }
        this.transportState = "ready";
        this.transportPauseReason = null;
        this.transportRecoveryAttempts = 0;
        this.transportNextAttemptMs = null;
      } catch (error) {
        if (!committed) await candidate?.close().catch(() => undefined);
        if (this.stopped) return;
        this.transportState = "paused";
        const retryable = this.isRetryableTransportFailure(error);
        this.transportPauseReason = retryable
          ? "network_unavailable"
          : failureReason;
        this.emitError("transport-recovery", error);
        if (retryable) this.scheduleTransportRecoveryRetry();
      } finally {
        this.transportRecoveryInFlight = null;
      }
    })();
    this.transportRecoveryInFlight = run;
    return run;
  }

  /** Strict startup requires one successful finalized governance read. */
  private async requireFinalizedTeePubkeys(
    attested: string[],
    recordSuccess = true,
  ): Promise<void> {
    const onchain = await this.onchainTeePubkeysFn(
      this.config.rpcUrl,
      this.config.programId,
    );
    if (!onchain) {
      throw new Error(
        "vault_config not found at finalized commitment — refusing to start",
      );
    }
    assertTeePubkeysMatch(attested, onchain);
    if (recordSuccess) this.lastFinalizedKeyRefreshMs = this.now();
    console.log(
      `[daemon] finalized tee_pubkeys cross-check OK (${onchain.length} keys match)`,
    );
  }

  /**
   * Re-derive local state from the CVM and the chain (SW-11).
   *
   * Entry points: a `1011` stream close on either channel, and boot. Both leave
   * the daemon in the same condition — an unknown amount of missed state — so
   * they run the same routine.
   *
   * Placement is paused for the duration. Cancellation is deliberately NOT
   * paused: cancelling a stale order is always safe and is exactly what an
   * operator wants available while state is uncertain.
   *
   * Concurrent calls share one run. Both channels can fault together, and two
   * overlapping chain scans would double the RPC cost to reach the same answer.
   *
   * **Never rejects.** The listener callbacks are synchronous and cannot await,
   * so a rejecting promise here becomes an unhandled rejection — which Node
   * turns into process exit by default. That would crash the daemon in exactly
   * the situation this method exists to survive. Failures are reported through
   * `errors` on the result and the event stream instead, so both call sites are
   * safe by construction rather than by remembering to attach a `.catch()`.
   */
  async reconcileNow(reason: string): Promise<ReconcileResult> {
    if (this.reconcileInFlight) return this.reconcileInFlight;

    // Set BEFORE the body runs. An async IIFE executes synchronously up to its
    // first `await`, and the body's first act is a synchronous `emitError` — so
    // a subscriber whose handler re-enters `reconcileNow` (a retry, a control
    // route) would have seen `reconcileInFlight` still null and started a
    // SECOND scan, which is exactly the duplication the sharing exists to
    // prevent. `reconciling` is set here for the same reason: placement must be
    // refused from the instant this is called, not one microtask later.
    this.reconciling = true;

    const run = (async (): Promise<ReconcileResult> => {
      // Yield once so the assignment below lands before the body proceeds.
      await Promise.resolve();
      // Surface it: silent drift is the failure mode this exists to end, so an
      // operator learns from the event stream, not from a balance that quietly
      // stopped growing.
      this.emitError("reconcile", new Error(`reconciling — ${reason}`));
      try {
        // Snapshot before scanning. Advancing to the pre-scan high-water mark
        // is conservative: transactions finalized during the scan are read
        // again next time instead of falling into a cursor race.
        const scanThroughSlot = await this.finalizedSlotFn();
        const markets = await this.tee.instruments();
        const market = markets[0];
        if (!market) throw new Error("/instruments returned no market");
        const result = await reconcile({
          store: this.store,
          reads: this.tee,
          rpcUrl: this.config.rpcUrl,
          programId: this.config.programId,
          masterSeed: this.keystore.masterSeed,
          baseMint: new PublicKey(market.base_mint).toBytes(),
          quoteMint: new PublicKey(market.quote_mint).toBytes(),
          sinceSlot: this.reconciliationCursorSlot,
          log: (m) => console.log(m),
        });
        console.log(
          `[daemon] reconcile done (${reason}): rephased=${result.ordersRephased} ` +
            `unknown=${result.ordersUnknown} merge_latches_cleared=${result.mergeLatchesCleared} ` +
            `notes_recovered=${result.notesRecovered} errors=${result.errors.length}`,
        );
        for (const e of result.errors) {
          this.emitError("reconcile", new Error(e));
        }
        // Only an ERROR-FREE reconcile clears the latch. A partial one leaves
        // some slice of local state unverified, and placing against state we
        // know we could not confirm is how a daemon spends collateral the chain
        // has already consumed.
        this.reconcileFailureReason =
          result.errors.length > 0 ? result.errors[0] : null;
        if (result.errors.length === 0) {
          this.reconciliationCursorSlot = scanThroughSlot;
          this.tracker?.retryQuarantined();
          if (
            this.transportState === "paused" &&
            this.transportPauseReason === "reconciliation_failed"
          ) {
            this.transportState = "ready";
            this.transportPauseReason = null;
          }
        }
        return result;
      } catch (e) {
        const message = e instanceof Error ? e.message : String(e);
        this.reconcileFailureReason = message;
        this.emitError("reconcile", new Error(`reconcile failed: ${message}`));
        return {
          ordersRephased: 0,
          ordersUnknown: 0,
          mergeLatchesCleared: 0,
          notesRecovered: 0,
          errors: [message],
        };
      } finally {
        this.reconciling = false;
        this.reconcileInFlight = null;
      }
    })();

    this.reconcileInFlight = run;
    return run;
  }

  private pauseTrading(reason: string): void {
    if (this.tradingPauseReason === reason) return;
    this.tradingPauseReason = reason;
    this.emitError("trust", new Error(reason));
  }

  private resumeTrading(): void {
    this.tradingPauseReason = null;
  }

  private pauseIfFinalizedKeysStale(): void {
    if (this.expectedTeePubkeys) {
      const age =
        this.lastFinalizedKeyRefreshMs === null
          ? Number.POSITIVE_INFINITY
          : this.now() - this.lastFinalizedKeyRefreshMs;
      if (age >= this.teeKeyStaleMs) {
        this.pauseTrading(
          `finalized tee_pubkeys are stale (${age}ms since last successful refresh)`,
        );
      }
    }
  }

  private assertTradingEnabled(): void {
    this.pauseIfFinalizedKeysStale();
    if (this.transportState !== "ready") {
      throw new Error(
        `trading paused: transport ${this.transportState}` +
          (this.transportPauseReason ? ` (${this.transportPauseReason})` : ""),
      );
    }
    if (this.reconciling) {
      throw new Error(
        "trading paused: reconciling local state after a stream gap or restart",
      );
    }
    if (this.reconcileFailureReason) {
      throw new Error(
        `trading paused: last reconciliation did not complete (${this.reconcileFailureReason}) — ` +
          "local state is unverified; call reconcileNow() once the CVM/RPC is reachable",
      );
    }
    if (this.tradingPauseReason) {
      throw new Error(`trading paused: ${this.tradingPauseReason}`);
    }
  }

  private startTeeKeyRefresh(): void {
    if (!this.expectedTeePubkeys || this.teeKeyRefreshTimer) return;
    this.teeKeyRefreshTimer = setInterval(() => {
      void this.refreshTrustNow();
    }, this.teeKeyRefreshMs);
    this.teeKeyRefreshTimer.unref?.();
  }

  /** Refresh the finalized governance key set. A mismatch or missing config
   *  pauses new trading immediately. RPC failures retain the last good state
   *  only until its five-minute freshness budget expires. */
  async refreshTrustNow(): Promise<void> {
    if (
      this.transportState === "paused" &&
      this.transportPauseReason !== "network_unavailable" &&
      this.transportPauseReason !== "reconciliation_failed"
    ) {
      return;
    }
    if (this.transportSupervisor?.isStale()) {
      await this.recoverTransportNow("boot_changed");
      return;
    }
    if (!this.expectedTeePubkeys || this.teeKeyRefreshInFlight) return;
    this.teeKeyRefreshInFlight = true;
    try {
      let onchain: string[] | null;
      try {
        onchain = await this.onchainTeePubkeysFn(
          this.config.rpcUrl,
          this.config.programId,
        );
      } catch (error) {
        const age =
          this.lastFinalizedKeyRefreshMs === null
            ? Number.POSITIVE_INFINITY
            : this.now() - this.lastFinalizedKeyRefreshMs;
        if (age >= this.teeKeyStaleMs) {
          this.pauseTrading(
            `finalized tee_pubkeys are stale (${age}ms since last successful refresh)`,
          );
        }
        this.emitError("tee-key-refresh", error);
        return;
      }
      if (!onchain) {
        this.pauseTrading(
          "vault_config missing at finalized commitment; new trading is paused",
        );
        return;
      }
      try {
        assertTeePubkeysMatch(this.expectedTeePubkeys, onchain);
      } catch (error) {
        this.pauseTrading(
          error instanceof Error
            ? error.message
            : "attested and on-chain tee_pubkeys differ",
        );
        return;
      }
      this.lastFinalizedKeyRefreshMs = this.now();
      if (this.transportState === "ready") this.resumeTrading();
    } finally {
      this.teeKeyRefreshInFlight = false;
    }
  }

  /**
   * Verify the gateway's TEE attestation (unless disabled), then open the TEE
   * streams + resume the next HD index. Idempotent. If attestation fails the
   * daemon does NOT start — it refuses to send order flow to an unverified
   * gateway (the non-custody guarantee).
   */
  async start(): Promise<void> {
    if (this.started) return;
    this.stopped = false;

    if (
      this.verifyAttestationFn &&
      this.config.attestationStrict &&
      !this.config.attestOnchainCheck
    ) {
      throw new Error(
        "strict attestation requires the finalized on-chain TEE-key check; set DARKNYX_DAEMON_ATTEST_STRICT=0 only for development",
      );
    }
    this.transportState = "reverifying";
    this.applyVerifiedIdentity(
      await this.verifyApplicationIdentity(
        this.fetchImpl,
        this.transportSupervisor?.verifiedBootSessionId(),
      ),
    );
    if (this.expectedTeePubkeys) {
      await this.requireFinalizedTeePubkeys(this.expectedTeePubkeys);
    }
    this.resumeTrading();

    // A supervised live session that intentionally skips the cold-start scan
    // still needs a lower bound before opening its streams. This is used by
    // focused live drills and isolated embeddings; production's default
    // `reconcileOnStart=true` leaves the cursor unset until the mandatory full
    // cold recovery succeeds.
    if (this.transportSupervisor && !this.reconcileOnStart) {
      this.reconciliationCursorSlot = await this.finalizedSlotFn();
    }

    this.started = true;
    // One-time migration safety: an existing DB can advance a newly-created
    // sequence file, but the DB is never allowed to move the durable root
    // backwards. Production refuses a missing file before constructing us.
    this.orderSequence.advanceTo(this.store.maxSeedIndex() + 1);

    const ownerCommitment = await this.keystore.ownerCommitment();
    this.fills = new FillsListener({
      engine: this.engine,
      store: this.store,
      gatewayWsUrl: this.config.gatewayWsUrl,
      token: this.config.token,
      masterSeed: this.keystore.masterSeed,
      ownerCommitment,
      streamClient: this.streamClient,
      subscribeFn: this.subscribeFillsFn,
      onFill: (note) => {
        this.pruneConsumedInput(note);
        this.emit({ type: "fill", note });
      },
      // A 1011 close means the server buffered past us: the fills we missed
      // carried the ONLY in-band copy of their notes' openings (SW-11).
      onResync: (reason) => void this.reconcileNow(`fills gap: ${reason}`),
      onError: (e) => this.emitError("fills", e),
    });
    this.orders = new OrdersListener({
      engine: this.engine,
      gatewayWsUrl: this.config.gatewayWsUrl,
      token: this.config.token,
      streamClient: this.streamClient,
      subscribeFn: this.subscribeOrdersFn,
      onResync: (reason) => void this.reconcileNow(`orders gap: ${reason}`),
      onError: (e) => this.emitError("orders", e),
    });
    this.tracker = new SettlementTracker({
      store: this.store,
      gatewayUrl: this.config.gatewayUrl,
      token: this.config.token,
      treeId: this.treeId,
      fetchImpl: this.fetchImpl,
      pollMs: this.settlementPollMs,
      fetchInclusion: this.fetchInclusion,
      onResolved: (commitment) => {
        const note = this.store.get(commitment);
        if (note) this.emit({ type: "fill", note });
      },
      onQuarantined: (commitment, error) => {
        this.emitError(
          "settlement-tracker",
          new Error(
            `quarantined unresolved note ${commitment}: ${
              error instanceof Error ? error.message : error
            }`,
          ),
        );
        void this.reconcileNow(`unresolved settlement note ${commitment}`);
      },
    });
    this.fills.start();
    this.orders.start();
    this.tracker.start();
    if (this.config.attestOnchainCheck) this.startTeeKeyRefresh();

    // Reconcile at boot as well as on a gap (SW-11). A restart across any
    // transition leaves exactly the same desync a mid-session gap does: the
    // live tails above reopen at "now", so anything that happened while the
    // process was down is invisible, and persisted orders were never checked
    // against the CVM. `start()` previously did neither, which is why a restart
    // made the desync permanent rather than curing it.
    //
    // Awaited: placement is gated on `reconciling`, so returning from `start()`
    // with it still running would just make the first `placeOrder` throw. A
    // failure here is surfaced and does not prevent the daemon running — a
    // daemon that boots degraded and says so beats one that refuses to boot.
    if (this.reconcileOnStart) {
      // Cannot throw — see `reconcileNow`. A daemon that boots degraded and
      // says so beats one that refuses to boot.
      await this.reconcileNow("startup");
    }
    this.transportState = this.reconcileFailureReason ? "paused" : "ready";
    this.transportPauseReason = this.reconcileFailureReason
      ? "reconciliation_failed"
      : null;
  }

  stop(): void {
    this.stopped = true;
    this.transportState = "paused";
    this.transportPauseReason = "stopped";
    this.fills?.stop();
    this.orders?.stop();
    this.tracker?.stop();
    if (this.teeKeyRefreshTimer) clearInterval(this.teeKeyRefreshTimer);
    this.teeKeyRefreshTimer = null;
    if (this.transportRecoveryTimer) clearTimeout(this.transportRecoveryTimer);
    this.transportRecoveryTimer = null;
    this.transportNextAttemptMs = null;
    this.transportRecoveryAttempts = 0;
    this.placer.close();
    this.streamClient.close();
    void this.transportSupervisor?.close();
    this.started = false;
  }

  // ── operations ──

  /** Build (prove + sign) and place an order spending `note`. Returns its id. */
  async placeOrder(
    intent: OrderIntent,
    note: StoredNote,
  ): Promise<{ orderId: string; arrivalSlot: number }> {
    this.assertTradingEnabled();
    if (!this.bootSessionId)
      throw new Error("daemon has not fetched the CVM boot session");
    // Reserve + fsync BEFORE proving/signing. A failed placement burns an
    // index (safe); a crash can never reuse one (unsafe).
    const seedIndex = this.orderSequence.reserve();
    const { request, orderId } = await buildPlaceRequest({
      keystore: this.keystore,
      note,
      seedIndex,
      sessionId: this.bootSessionId,
      intent,
      gatewayUrl: this.config.gatewayUrl,
      token: this.config.token,
      prover: this.prover,
      treeId: this.treeId,
      fetchImpl: this.fetchImpl,
      verifyRoot: this.verifyRootFn,
    });
    const orderIdHex = toHex(orderId);
    const managed = newManagedOrder({
      orderId: orderIdHex,
      seedIndex,
      symbol: intent.symbol,
      side: intent.side === OrderSide.Bid ? "bid" : "ask",
      priceRaw: intent.policy.priceLimit,
      sizeRaw: intent.amount,
      // Lock the spent note to this order (excludes it from selection + lets a
      // fill prune it).
      collateralCommitment: note.commitment,
    });
    const resp = await placeManagedOrder({
      engine: this.engine,
      placer: this.placer,
      order: managed,
      request,
    });
    return { orderId: orderIdHex, arrivalSlot: resp.arrival_slot };
  }

  /**
   * Deposit `amount` of `tokenMint` (from `depositorTokenAccount`) into the
   * vault, recording the minted note in the store so it's selectable as
   * collateral. This is a DIRECT on-chain action signed by the operator's
   * payer — distinct from order flow (which the TEE settles). Needs `depositFn`
   * + `depositor` configured (the daemon-client); throws otherwise.
   */
  async deposit(req: {
    tokenMint: Uint8Array;
    amount: bigint;
    depositorTokenAccount: PublicKey;
    treeId?: number;
  }): Promise<{ commitment: string; leafIndex: bigint }> {
    if (!this.depositFn || !this.depositor) {
      throw new Error("deposit not configured (no payer/RPC/program id)");
    }
    const receipt = await this.depositFn({
      depositor: this.depositor,
      treeId: req.treeId ?? this.treeId,
      tokenMint: req.tokenMint,
      amount: req.amount,
      depositorTokenAccount: req.depositorTokenAccount,
    });
    const note = depositNoteFromReceipt(receipt);
    this.store.put(note);
    this.emit({ type: "fill", note });
    return { commitment: note.commitment, leafIndex: receipt.leafIndex };
  }

  /** Pick the best collateral note for a request, excluding notes already
   *  locked by a resting (pending/open) order. `undefined` if none covers. */
  selectNote(req: CollateralRequest): StoredNote | undefined {
    return this.store.selectCollateral(req.mint, req.minAmount);
  }

  /** A v3 fill memo names the exact input consumed to derive this output. Drop
   *  that note so collateral selection and merging never reuse spent state. */
  private pruneConsumedInput(note: StoredNote): void {
    if (note.consumedCommitment !== undefined) {
      this.store.delete(note.consumedCommitment);
    }
  }

  /** Once a fill consumes the order's collateral note (the matcher rotates it
   *  into a change note), prune it from the UTXO set. Idempotent. */
  private pruneConsumedCollateral(order: ManagedOrder): void {
    if (order.collateralCommitment) {
      this.store.delete(order.collateralCommitment);
    }
  }

  /** Cancel a resting order: sign a cancel, send it, drive the phase. */
  async cancelOrder(orderIdHex: string): Promise<void> {
    const order = this.store.getOrder(orderIdHex);
    if (!order) throw new Error(`unknown order ${orderIdHex}`);
    // S-07: the cancel signature is scoped to a boot session, so refuse to
    // sign one before the handshake has produced it — same guard placement
    // uses. Without this a cancel could be signed against a null session.
    if (!this.bootSessionId)
      throw new Error("daemon has not fetched the CVM boot session");
    const idx = order.seedIndex;
    const tradingSigner = this.keystore.tradingSigner(idx);
    const cancel = await buildCancel({
      orderId: fromHex(orderIdHex),
      tradingKey: tradingSigner.publicKey,
      cancelNonce: BigInt(Date.now()),
      // S-07: scopes the cancel signature to this CVM boot, so a captured
      // body cannot kill a re-placed order after a restart.
      sessionId: this.bootSessionId,
      sign: tradingSigner.sign,
    });
    await this.placer.cancel(orderIdHex, cancel);
    await this.engine.dispatch(orderIdHex, { type: "cancelled" });
  }

  listOrders(): ManagedOrder[] {
    return this.store.listOrders();
  }
  getOrder(orderIdHex: string): ManagedOrder | undefined {
    return this.store.getOrder(orderIdHex);
  }
  listNotes(): StoredNote[] {
    return this.store.list();
  }
  getNote(commitment: string): StoredNote | undefined {
    return this.store.get(commitment);
  }
  /** The verified TEE identity from the connect-time attestation (null if
   *  attestation was skipped or hasn't run yet). */
  getAttestation(): AttestationResult | null {
    return this.attestationResult;
  }

  getTrustStatus(): DaemonTrustStatus {
    this.pauseIfFinalizedKeysStale();
    // Report every reason placement can be refused, not just the trust one.
    // `tradingEnabled` used to be derived from `tradingPauseReason` alone, so
    // `/health` would have advertised trading as enabled while `placeOrder`
    // threw — the reconciliation pauses are independent fields precisely
    // because a trust resume must not clear them.
    const pauseReason =
      (this.transportState !== "ready"
        ? `transport ${this.transportState}${
            this.transportPauseReason ? ` (${this.transportPauseReason})` : ""
          }`
        : null) ??
      this.tradingPauseReason ??
      (this.reconciling
        ? "reconciling local state after a stream gap or restart"
        : null) ??
      (this.reconcileFailureReason
        ? `last reconciliation did not complete (${this.reconcileFailureReason}); local state is unverified`
        : null);
    return {
      tradingEnabled: pauseReason === null,
      pauseReason,
      reconciling: this.reconciling,
      reconcileFailureReason: this.reconcileFailureReason,
      lastFinalizedKeyRefreshMs: this.lastFinalizedKeyRefreshMs,
      onchainKeyMonitoring: this.expectedTeePubkeys !== null,
      transportState: this.transportState,
      transportPauseReason: this.transportPauseReason,
      transportRecoveryAttempts: this.transportRecoveryAttempts,
      transportNextAttemptMs: this.transportNextAttemptMs,
    };
  }

  /** Aggregate unspent notes into per-mint balances. */
  balances(): Balance[] {
    const byMint = new Map<string, { amount: bigint; notes: number }>();
    for (const n of this.store.list()) {
      const mint = toHex(n.tokenMint);
      const cur = byMint.get(mint) ?? { amount: 0n, notes: 0 };
      cur.amount += n.amount;
      cur.notes += 1;
      byMint.set(mint, cur);
    }
    return [...byMint.entries()].map(([mint, v]) => ({
      mint,
      amount: v.amount.toString(),
      notes: v.notes,
    }));
  }

  // ── event stream ──

  /** Subscribe to order/fill/error events. Returns an unsubscribe fn. */
  subscribe(listener: (e: DaemonEvent) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private emit(e: DaemonEvent): void {
    for (const l of this.listeners) {
      try {
        l(e);
      } catch {
        /* a bad subscriber must not break the daemon */
      }
    }
  }
  private emitError(context: string, err: unknown): void {
    this.emit({
      type: "error",
      context,
      message: err instanceof Error ? err.message : String(err),
    });
  }
}
