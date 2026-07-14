/**
 * FillsListener — the daemon's `/v1/stream` fills channel.
 *
 * Wraps the SDK `subscribeFills`: the TEE pushes one verified `FillMemo` per
 * continuation change note for this account; the SDK recomputes + self-verifies
 * the note opening (the Vuln-4 integrity check) and writes it to the
 * {@link NoteStore} (here, the daemon's sqlite store). For each delivered note
 * this listener then dispatches a lifecycle `fill` event into the engine —
 * advancing the consumed-anchor high-water mark (which drives auto anchor
 * top-up) and counting the residual (which drives auto-merge).
 *
 * Division of labour with the orders channel: `fills` is the source of the
 * change-note OPENINGS + anchor consumption (the `fill` event carries NO phase
 * meaning); the order's PHASE transitions (accepted / filled / cancelled /
 * expired) come from the `orders` channel (the {@link OrdersListener}). The
 * channels share one authenticated session but neither double-drives the other (`anchorsConsumed` is a
 * max() high-water so it's idempotent; `pendingChangeNotes` is counted only
 * here).
 *
 * `subscribeFills` is injected so the listener is unit-testable without forging
 * a cryptographically-valid memo: tests pass a fake that hands back synthetic
 * note records.
 */

import {
  subscribeFills,
  type FillsSubscription,
  type NoteStore,
  type StoredNote,
  type TradingClient,
  type WebSocketFactory,
} from "@nyx/sdk";

import type { LifecycleEngine } from "./lifecycle-engine.js";

/** The SDK entrypoint this listener wraps (injected for tests). */
export type SubscribeFillsFn = typeof subscribeFills;

export interface FillsListenerOptions {
  engine: LifecycleEngine;
  /** The daemon's note store (change notes are written here by the SDK). */
  store: NoteStore;
  /** Gateway WS origin (`/v1/stream` is appended by the SDK). */
  gatewayWsUrl: string;
  token: string;
  masterSeed: Uint8Array;
  ownerCommitment: bigint;
  webSocketFactory?: WebSocketFactory;
  streamClient?: TradingClient;
  /** Fired after a verified change note is stored + dispatched. */
  onFill?: (rec: StoredNote) => void;
  onError?: (err: Error) => void;
  /** Server closed 1011 (lagged past the buffer) — the gap must be re-backfilled
   *  from the chain (the orchestrator's job; this surfaces it). */
  onResync?: (reason: string) => void;
  onClose?: (code: number, reason?: string) => void;
  /** Seam for tests; defaults to the real SDK `subscribeFills`. */
  subscribeFn?: SubscribeFillsFn;
}

export class FillsListener {
  private sub: FillsSubscription | null = null;

  constructor(private readonly opts: FillsListenerOptions) {}

  /** Open the live fills tail. Idempotent-ish: a second `start` replaces the sub. */
  start(): void {
    const subscribe = this.opts.subscribeFn ?? subscribeFills;
    this.sub = subscribe({
      gatewayWsUrl: this.opts.gatewayWsUrl,
      token: this.opts.token,
      masterSeed: this.opts.masterSeed,
      ownerCommitment: this.opts.ownerCommitment,
      store: this.opts.store,
      webSocketFactory: this.opts.webSocketFactory,
      streamClient: this.opts.streamClient,
      onFill: (rec) => {
        void this.handleFill(rec);
      },
      onError: this.opts.onError,
      onResync: this.opts.onResync,
      onClose: this.opts.onClose,
    });
  }

  private async handleFill(rec: StoredNote): Promise<void> {
    this.opts.onFill?.(rec);
    // Only continuation (fill) notes drive the lifecycle; a deposit note (no
    // orderId/anchorIndex) wouldn't arrive here, but guard anyway.
    if (rec.orderId === undefined || rec.anchorIndex === undefined) return;
    try {
      await this.opts.engine.dispatch(rec.orderId, {
        type: "fill",
        anchorIndex: rec.anchorIndex,
        producedChangeNote: rec.amount > 0n,
      });
    } catch (err) {
      // An unknown order (e.g. a fill that races ahead of registration) must
      // not tear down the socket — surface it and keep listening.
      this.opts.onError?.(err as Error);
    }
  }

  stop(): void {
    this.sub?.close();
    this.sub = null;
  }
}
