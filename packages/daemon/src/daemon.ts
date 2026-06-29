/**
 * Daemon — the assembled, runnable client.
 *
 * Wires every slice into one long-running object: the {@link DaemonStore} (UTXO
 * + managed orders), the {@link LifecycleEngine} driving a
 * {@link DaemonActionExecutor} (auto anchor top-up via the keystore + the
 * gateway, auto-merge via the {@link MergeRunner}), the two TEE streams
 * ({@link FillsListener} `/ws/fills`, {@link OrdersListener} `/ws/orders`), and
 * the {@link OrderPlacer} (WS by default). It exposes the high-level operations
 * a control surface needs — `placeOrder` / `cancelOrder` / `listOrders` /
 * `balances` — plus a `subscribe` stream of order + fill events.
 *
 * Everything heavy is injectable (placer, anchor poster, merge runner, the WS
 * `subscribe*` fns, the prover, fetch) so the whole thing is testable without a
 * CVM; `bin/daemon.ts` supplies the real implementations.
 */

import { randomBytes } from "node:crypto";
import type { PublicKey } from "@solana/web3.js";
import {
  ANCHOR_POOL_SIZE,
  OrderSide,
  buildCancel,
  depositNoteFromReceipt,
  type DepositParams,
  type DepositReceipt,
  type StoredNote,
  type ValidInputProver,
  type WebSocketFactory,
  type SendableWebSocketFactory,
} from "@nyx/sdk";

import type { DaemonConfig } from "./config.js";
import { DaemonStore } from "./store.js";
import { Keystore } from "./keystore.js";
import { LifecycleEngine } from "./lifecycle-engine.js";
import {
  DaemonActionExecutor,
  HttpAnchorTopUpPoster,
  type AnchorTopUpPoster,
  type MergeRunner,
} from "./action-executor.js";
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
  verifyAttestation,
  type AttestationResult,
  type QuoteVerifier,
} from "./attestation.js";
import {
  SettlementTracker,
  type FetchInclusionFn,
} from "./settlement-tracker.js";
import { selectCollateralNote, type CollateralRequest } from "./note-select.js";

const toHex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
const fromHex = (h: string): Uint8Array =>
  Uint8Array.from(Buffer.from(h, "hex"));

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
  /** VALID_INPUT prover for order placement (e.g. SDK `nodeValidInputProver`). */
  prover: ValidInputProver;
  // ── injectables (defaults built from config) ──
  placer?: OrderPlacer;
  anchorPoster?: AnchorTopUpPoster;
  mergeRunner?: MergeRunner;
  subscribeFills?: SubscribeFillsFn;
  subscribeOrders?: SubscribeOrderUpdatesFn;
  webSocketFactory?: WebSocketFactory;
  sendableWebSocketFactory?: SendableWebSocketFactory;
  fetchImpl?: typeof fetch;
  /** Verify the gateway's TEE attestation on start. Defaults to the real
   *  {@link verifyAttestation}; pass `false` to skip (tests/local-sim). */
  verifyAttestation?: typeof verifyAttestation | false;
  /** Optional DCAP quote verifier (full Intel TCB) handed to the attestation. */
  quoteVerifier?: QuoteVerifier;
  /** Settlement-tracker poll interval (ms) for resolving change-note leaves. */
  settlementPollMs?: number;
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
  private readonly prover: ValidInputProver;
  private readonly engine: LifecycleEngine;
  private readonly placer: OrderPlacer;
  private readonly fetchImpl?: typeof fetch;
  private readonly treeId = 0;

  private readonly subscribeFillsFn?: SubscribeFillsFn;
  private readonly subscribeOrdersFn?: SubscribeOrderUpdatesFn;
  private readonly webSocketFactory?: WebSocketFactory;

  private readonly verifyAttestationFn: typeof verifyAttestation | false;
  private readonly quoteVerifier?: QuoteVerifier;
  private attestationResult: AttestationResult | null = null;

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
  private nextIndex = 0;
  private started = false;

  constructor(deps: DaemonDeps) {
    this.config = deps.config;
    this.keystore = deps.keystore;
    this.store = deps.store;
    this.prover = deps.prover;
    this.fetchImpl = deps.fetchImpl;
    this.subscribeFillsFn = deps.subscribeFills;
    this.subscribeOrdersFn = deps.subscribeOrders;
    this.webSocketFactory = deps.webSocketFactory;
    // Attest by default (non-custody is the point); inject `false` to skip.
    this.verifyAttestationFn = deps.verifyAttestation ?? verifyAttestation;
    this.quoteVerifier = deps.quoteVerifier;
    this.settlementPollMs = deps.settlementPollMs;
    this.fetchInclusion = deps.fetchInclusion;
    this.depositFn = deps.depositFn;
    this.depositor = deps.depositor;

    const executor = new DaemonActionExecutor({
      keys: this.keystore,
      anchors:
        deps.anchorPoster ??
        new HttpAnchorTopUpPoster({
          baseUrl: this.config.gatewayUrl,
          token: this.config.token,
          fetchImpl: this.fetchImpl,
        }),
      merge: deps.mergeRunner ?? UNCONFIGURED_MERGE,
    });

    this.engine = new LifecycleEngine(this.store, executor, {
      thresholds: this.config.thresholds,
      onError: (err, ctx) => this.emitError(ctx, err),
      onTransition: (order) => {
        this.pruneConsumedCollateral(order);
        this.emit({ type: "order", order });
      },
    });

    this.placer =
      deps.placer ??
      new WsOrderPlacer({
        gatewayWsUrl: this.config.gatewayWsUrl,
        token: this.config.token,
        cancelOnDisconnect: true,
        webSocketFactory: deps.sendableWebSocketFactory,
      });
  }

  // ── lifecycle ──

  /**
   * Verify the gateway's TEE attestation (unless disabled), then open the TEE
   * streams + resume the next HD index. Idempotent. If attestation fails the
   * daemon does NOT start — it refuses to send order flow to an unverified
   * gateway (the non-custody guarantee).
   */
  async start(): Promise<void> {
    if (this.started) return;

    if (this.verifyAttestationFn) {
      this.attestationResult = await this.verifyAttestationFn({
        gatewayUrl: this.config.gatewayUrl,
        token: this.config.token,
        expected: this.config.attestation,
        quoteVerifier: this.quoteVerifier,
        fetchImpl: this.fetchImpl,
      });
    }

    this.started = true;
    this.nextIndex = this.store.maxSeedIndex() + 1;

    const ownerCommitment = await this.keystore.ownerCommitment();
    this.fills = new FillsListener({
      engine: this.engine,
      store: this.store,
      gatewayWsUrl: this.config.gatewayWsUrl,
      token: this.config.token,
      masterSeed: this.keystore.masterSeed,
      ownerCommitment,
      webSocketFactory: this.webSocketFactory,
      subscribeFn: this.subscribeFillsFn,
      onFill: (note) => {
        this.pruneSupersededContinuations(note);
        this.emit({ type: "fill", note });
      },
      onError: (e) => this.emitError("fills", e),
    });
    this.orders = new OrdersListener({
      engine: this.engine,
      gatewayWsUrl: this.config.gatewayWsUrl,
      token: this.config.token,
      webSocketFactory: this.webSocketFactory,
      subscribeFn: this.subscribeOrdersFn,
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
    });
    this.fills.start();
    this.orders.start();
    this.tracker.start();
  }

  stop(): void {
    this.fills?.stop();
    this.orders?.stop();
    this.tracker?.stop();
    this.placer.close();
    this.started = false;
  }

  // ── operations ──

  /** Build (prove + sign) and place an order spending `note`. Returns its id. */
  async placeOrder(
    intent: OrderIntent,
    note: StoredNote,
  ): Promise<{ orderId: string; arrivalSlot: number }> {
    const seedIndex = this.nextIndex++;
    const { request, orderId } = await buildPlaceRequest({
      keystore: this.keystore,
      note,
      seedIndex,
      intent,
      gatewayUrl: this.config.gatewayUrl,
      token: this.config.token,
      prover: this.prover,
      treeId: this.treeId,
      fetchImpl: this.fetchImpl,
    });
    const orderIdHex = toHex(orderId);
    const managed = newManagedOrder({
      orderId: orderIdHex,
      seedIndex,
      side: intent.side === OrderSide.Bid ? "bid" : "ask",
      priceRaw: intent.policy.priceLimit,
      sizeRaw: intent.amount,
      anchorPoolSize: ANCHOR_POOL_SIZE,
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
    // A random per-deposit index seeds the note's inner_hash (recoverable by
    // commitment, not by index — so no persisted counter is needed).
    const depositIndex = randomBytes(8).readBigUInt64BE(0);
    const receipt = await this.depositFn({
      depositor: this.depositor,
      treeId: req.treeId ?? this.treeId,
      depositIndex,
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
    return selectCollateralNote(
      this.store.list(),
      req,
      this.lockedCommitments(),
    );
  }

  /** Commitments locked by orders that still rest (and so can't be re-spent):
   *  the original collateral note of a pending/open order, AND that order's
   *  rolling continuation residual (a change note is RE-LOCKED for continuation
   *  while its order is open — only released when the order goes terminal). */
  private lockedCommitments(): Set<string> {
    const openOrderIds = new Set<string>();
    const locked = new Set<string>();
    for (const o of this.store.listOrders()) {
      if (o.phase === "pending" || o.phase === "open") {
        openOrderIds.add(o.orderId);
        if (o.collateralCommitment) locked.add(o.collateralCommitment);
      }
    }
    for (const n of this.store.list()) {
      if (n.orderId !== undefined && openOrderIds.has(n.orderId)) {
        locked.add(n.commitment);
      }
    }
    return locked;
  }

  /** When a continuation fill rotates the residual onto a new anchor, the prior
   *  change note(s) for that order are consumed on-chain — drop them so neither
   *  collateral selection nor merge ever picks a spent note. Keeps one (latest)
   *  residual per order. */
  private pruneSupersededContinuations(note: StoredNote): void {
    if (note.orderId === undefined || note.anchorIndex === undefined) return;
    for (const n of this.store.notesByOrder(note.orderId)) {
      if (n.anchorIndex !== undefined && n.anchorIndex < note.anchorIndex) {
        this.store.delete(n.commitment);
      }
    }
  }

  /** Once a fill consumes the order's collateral note (the matcher rotates it
   *  into a change note), prune it from the UTXO set. Idempotent. */
  private pruneConsumedCollateral(order: ManagedOrder): void {
    if (order.collateralCommitment && order.anchorsConsumed >= 1) {
      this.store.delete(order.collateralCommitment);
    }
  }

  /** Cancel a resting order: sign a cancel, send it, drive the phase. */
  async cancelOrder(orderIdHex: string): Promise<void> {
    const order = this.store.getOrder(orderIdHex);
    if (!order) throw new Error(`unknown order ${orderIdHex}`);
    const idx = order.seedIndex;
    const cancel = await buildCancel({
      orderId: fromHex(orderIdHex),
      tradingKey: this.keystore.tradingPublicKey(idx),
      cancelNonce: BigInt(Date.now()),
      sign: (d) => this.keystore.signWithTradingKey(idx, d),
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
