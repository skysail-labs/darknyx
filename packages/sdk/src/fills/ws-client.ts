/**
 * Live fills transport — the "tail" half of "tail then backfill".
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
import {
  backfillHistory,
  type BackfillOptions,
  type BackfillResult,
} from "./history.js";
import { recoverChangeFromChain } from "./recover.js";

export interface WebSocketLike {
  addEventListener(type: "open", cb: () => void): void;
  addEventListener(type: "message", cb: (ev: { data: unknown }) => void): void;
  addEventListener(
    type: "close",
    cb: (ev: { code: number; reason?: string }) => void,
  ): void;
  addEventListener(type: "error", cb: (ev: unknown) => void): void;
  close(): void;
}
export type WebSocketFactory = (url: string) => WebSocketLike;

const defaultWsFactory: WebSocketFactory = (url) =>
  new (globalThis as { WebSocket: new (u: string) => WebSocketLike }).WebSocket(
    url,
  );

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
        const rec = await receiveFillMemo(
          memo,
          opts.masterSeed,
          opts.ownerCommitment,
          opts.store,
        );
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
  extends Omit<BackfillOptions, "baseUrl">, SubscribeFillsOptions {
  /** Indexer base URL. Locates the account's change-note fills (by HD-derived
   *  order id), and — when `baseMint`/`quoteMint` are set — recovers each
   *  amount/opening from the PERMANENT on-chain ciphertext (change-amount
   *  recovery, Proposal B) via `recoverChangeFromChain`. Omit to skip backfill
   *  entirely (live tail only). */
  indexerBaseUrl?: string;
  /** Market mints (32 bytes each). Required to recover located fills from the
   *  chain; without them the backfill only LOCATES commitments (gap-detect). */
  baseMint?: Uint8Array;
  quoteMint?: Uint8Array;
}

export interface FillsSync {
  close(): void;
  /** The indexer locator result (commitments + ciphertext), when `indexerBaseUrl`
   *  was set. Recovered notes are already in the `NoteStore`. */
  located?: BackfillResult;
}

/**
 * "Tail then backfill", self-healing: open the live `/ws/fills` tail AND backfill
 * any gap from the chain. The durable recovery source is the PERMANENT on-chain
 * ciphertext (Proposal B) — for each fill the indexer locates,
 * `recoverChangeFromChain` decrypts + self-verifies the spendable opening into
 * the `NoteStore`. This replaced the retired durable memo-replay log
 * (`GET /fills/replay`), which a CVM redeploy used to wipe.
 *
 * The `NoteStore` is commitment-keyed, so overlapping backfill/live delivery just
 * re-puts. On a 1011 resync we re-backfill from the chain and reopen.
 */
export async function startFillsSync(
  opts: FillsSyncOptions,
): Promise<FillsSync> {
  let located: BackfillResult | undefined;

  const backfill = async () => {
    if (!opts.indexerBaseUrl) return;
    try {
      located = await backfillHistory({
        ...opts,
        baseUrl: opts.indexerBaseUrl,
      });
      if (!opts.baseMint || !opts.quoteMint) return; // locate-only (no mints).
      for (const fill of located.located) {
        const note = await recoverChangeFromChain(fill, {
          masterSeed: opts.masterSeed,
          ownerCommitment: opts.ownerCommitment,
          baseMint: opts.baseMint,
          quoteMint: opts.quoteMint,
        });
        if (note) {
          await opts.store.put(note);
          opts.onFill?.(note);
        }
      }
    } catch (e) {
      opts.onError?.(e as Error);
    }
  };

  await backfill();

  let sub: FillsSubscription | null = null;
  let closed = false;

  const open = () => {
    if (closed) return;
    sub = subscribeFills({
      ...opts,
      onResync: async (reason) => {
        opts.onResync?.(reason);
        await backfill(); // re-recover the gap from the chain, then reopen.
        if (!closed) open();
      },
    });
  };
  open();

  return {
    located,
    close() {
      closed = true;
      sub?.close();
    },
  };
}
