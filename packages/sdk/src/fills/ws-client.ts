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
import { replayFills, type ReplayResult } from "./replay.js";

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
  /** Called with each live memo's `seq` (P7) so the caller can advance its
   *  replay cursor in lockstep with the live tail. */
  onSeq?: (seq: number) => void;
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
        if (typeof memo.seq === "number") opts.onSeq?.(memo.seq);
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
    SubscribeFillsOptions {
  /** Gateway HTTP origin for `GET /fills/replay` — the durable amount-recovery
   *  source (P7). e.g. `https://<app>-8080.dstack-…` (the http:// form). */
  gatewayHttpUrl: string;
  /** Optional indexer base URL. Used ONLY as a commitment LOCATOR for
   *  gap-detection — after amount-privacy (P4) it carries no amounts, so it is
   *  not the recovery source. Omit to skip the locate step. */
  indexerBaseUrl?: string;
  /** Initial replay cursor (the client's last-stored `seq`). `0`/undefined
   *  replays everything the TEE has retained. */
  initialCursor?: number;
}

export interface FillsSync {
  close(): void;
  /** The initial replay result — amounts/openings recovered before tailing. */
  replay: ReplayResult;
  /** Optional indexer locator result (commitments only), when `indexerBaseUrl`
   *  was set. A located commitment with no recovered note flags a gap. */
  located?: BackfillResult;
}

/**
 * "Backfill then tail", self-healing (P7): REPLAY the durable per-account memos
 * from the TEE (`GET /fills/replay`) to recover the amounts/openings the live
 * socket may have missed — then open the live WS tail. Invisible to the user.
 * The replay cursor advances in lockstep with the live tail (`onSeq`); on a 1011
 * resync we re-replay from the cursor and reopen. The `NoteStore` is
 * commitment-keyed, so overlapping replay/live delivery just re-puts.
 *
 * The indexer (if `indexerBaseUrl` is set) is consulted only as a commitment
 * LOCATOR for gap-detection — amount-privacy (P4) means it carries no amounts,
 * so the spendable opening always comes from the replay/live memo.
 */
export async function startFillsSync(opts: FillsSyncOptions): Promise<FillsSync> {
  let cursor = opts.initialCursor ?? 0;

  // 1. Durable recovery FIRST: replay missed memos (the amount source).
  const replay = await replayFills({ ...opts, since: cursor });
  cursor = replay.nextCursor;

  // 2. Optional: locate commitments via the indexer (no amounts) for gap-detect.
  let located: BackfillResult | undefined;
  if (opts.indexerBaseUrl) {
    try {
      located = await backfillHistory({ ...opts, baseUrl: opts.indexerBaseUrl });
    } catch (e) {
      opts.onError?.(e as Error);
    }
  }

  let sub: FillsSubscription | null = null;
  let closed = false;

  const open = () => {
    if (closed) return;
    sub = subscribeFills({
      ...opts,
      // Advance the replay cursor in lockstep with the live tail.
      onSeq: (seq) => {
        if (seq > cursor) cursor = seq;
      },
      onResync: async (reason) => {
        opts.onResync?.(reason);
        // Re-replay the gap from the cursor, then reopen.
        try {
          const r = await replayFills({ ...opts, since: cursor });
          cursor = r.nextCursor;
        } catch (e) {
          opts.onError?.(e as Error);
        }
        if (!closed) open();
      },
    });
  };
  open();

  return {
    replay,
    located,
    close() {
      closed = true;
      sub?.close();
    },
  };
}
