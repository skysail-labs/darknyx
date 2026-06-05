/**
 * Live fills transport — the "tail" half of "backfill then tail".
 *
 * Opens an authenticated per-account WebSocket to the CVM's `GET /ws/fills`,
 * verifies each `FillMemo` (the Vuln-4 integrity check in `fill-memo.ts`), and
 * stores the change note. The token is passed as `?token=` (the global
 * `WebSocket` — browser + Node 22+ — can't set an Authorization header); the TEE
 * accepts it on the WS route either way.
 *
 * `WebSocket` is injectable so tests can drive frames without a server.
 */

import type { NoteStore, ChangeNoteRecord } from "../utxo/note-store.js";
import { receiveFillMemo, type FillMemo } from "../orders/fill-memo.js";
import { backfillHistory, type BackfillOptions, type BackfillResult } from "./history.js";

export interface WebSocketLike {
  addEventListener(type: "open", cb: () => void): void;
  addEventListener(type: "message", cb: (ev: { data: unknown }) => void): void;
  addEventListener(type: "close", cb: (ev: { code: number; reason?: string }) => void): void;
  addEventListener(type: "error", cb: (ev: unknown) => void): void;
  close(): void;
}
export type WebSocketFactory = (url: string) => WebSocketLike;

const defaultWsFactory: WebSocketFactory = (url) =>
  new (globalThis as { WebSocket: new (u: string) => WebSocketLike }).WebSocket(url);

export interface SubscribeFillsOptions {
  /** Gateway WS origin, e.g. `wss://<app>-8080.dstack-…`. `/ws/fills` is appended. */
  gatewayWsUrl: string;
  token: string;
  masterSeed: Uint8Array;
  ownerCommitment: bigint;
  store: NoteStore;
  onFill?: (rec: ChangeNoteRecord) => void;
  onError?: (err: Error) => void;
  /** Server closed with 1011 (lagged past the buffer) — caller should re-backfill. */
  onResync?: (reason: string) => void;
  onClose?: (code: number, reason?: string) => void;
  webSocketFactory?: WebSocketFactory;
}

export interface FillsSubscription {
  close(): void;
}

/** Open one per-account fills WebSocket. Single connection; surfaces lifecycle. */
export function subscribeFills(opts: SubscribeFillsOptions): FillsSubscription {
  const base = opts.gatewayWsUrl.replace(/\/$/, "");
  const url = `${base}/ws/fills?token=${encodeURIComponent(opts.token)}`;
  const ws = (opts.webSocketFactory ?? defaultWsFactory)(url);
  let closedByCaller = false;

  ws.addEventListener("message", (ev) => {
    void (async () => {
      try {
        const text = typeof ev.data === "string" ? ev.data : String(ev.data);
        const memo = JSON.parse(text) as FillMemo;
        const rec = await receiveFillMemo(memo, opts.masterSeed, opts.ownerCommitment, opts.store);
        opts.onFill?.(rec);
      } catch (e) {
        opts.onError?.(e as Error);
      }
    })();
  });
  ws.addEventListener("error", (e) => opts.onError?.(e as Error));
  ws.addEventListener("close", (ev) => {
    if (closedByCaller) return;
    if (ev.code === 1011) opts.onResync?.(ev.reason ?? "lagged");
    opts.onClose?.(ev.code, ev.reason);
  });

  return {
    close() {
      closedByCaller = true;
      ws.close();
    },
  };
}

export interface FillsSyncOptions
  extends Omit<BackfillOptions, "baseUrl">,
    Omit<SubscribeFillsOptions, "store" | "masterSeed" | "ownerCommitment"> {
  /** Indexer base URL for the history backfill. */
  indexerBaseUrl: string;
}

export interface FillsSync {
  close(): void;
  /** The initial backfill result (history recovered before tailing). */
  backfill: BackfillResult;
}

/**
 * "Backfill then tail": rebuild durable history from the indexer, then open the
 * live WS — invisible to the user. On a 1011 resync the WS closed because we
 * lagged; re-backfill (cheap, incremental from the cursor) and reopen. Dedup is
 * automatic: the NoteStore is keyed by commitment, so a note seen in both paths
 * is just re-put.
 */
export async function startFillsSync(opts: FillsSyncOptions): Promise<FillsSync> {
  const backfill = await backfillHistory({ ...opts, baseUrl: opts.indexerBaseUrl });

  let sub: FillsSubscription | null = null;
  let closed = false;
  let cursorSlot = backfill.cursorSlot;

  const open = () => {
    if (closed) return;
    sub = subscribeFills({
      ...opts,
      onResync: async (reason) => {
        opts.onResync?.(reason);
        // Re-backfill the gap, then reopen.
        try {
          const r = await backfillHistory({ ...opts, baseUrl: opts.indexerBaseUrl, since: cursorSlot });
          cursorSlot = Math.max(cursorSlot, r.cursorSlot);
        } catch (e) {
          opts.onError?.(e as Error);
        }
        if (!closed) open();
      },
    });
  };
  open();

  return {
    backfill,
    close() {
      closed = true;
      sub?.close();
    },
  };
}
