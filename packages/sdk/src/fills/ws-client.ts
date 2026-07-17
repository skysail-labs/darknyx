/**
 * Live fills transport — the "tail" half of "tail then backfill".
 *
 * Subscribes to the `fills` channel on the CVM's authenticated `/v1/stream`
 * session, verifies each `FillMemo` (the Vuln-4 integrity check in
 * `fill-memo.ts`), and stores the low-latency continuation note. Durable chain
 * backfill additionally restores trade notes. Authentication is in-band, so a
 * bearer token never appears in the WebSocket URL.
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
import {
  backfillHistoryFromChain,
  type ChainBackfillOptions,
} from "./chain-history.js";
import { recoverFillFromChain } from "./recover.js";
import {
  TradingClient,
  type SendableWebSocketFactory,
  type SendableWebSocketLike,
  type StreamTokenProvider,
} from "../orders/trading-ws-client.js";

/** Backwards-compatible aliases for the now-bidirectional stream transport. */
export type WebSocketLike = SendableWebSocketLike;
export type WebSocketFactory = SendableWebSocketFactory;

export interface SubscribeFillsOptions {
  /** Gateway WS origin. `/v1/stream` is appended. */
  gatewayWsUrl: string;
  token: string;
  tokenProvider?: StreamTokenProvider;
  masterSeed: Uint8Array;
  ownerCommitment: bigint;
  store: NoteStore;
  onFill?: (rec: ChangeNoteRecord) => void;
  onError?: (err: Error) => void;
  /** Server closed with 1011 (lagged past the buffer) — caller should re-backfill. */
  onResync?: (reason: string) => void;
  onClose?: (code: number, reason?: string) => void;
  webSocketFactory?: WebSocketFactory;
  /** Reuse an existing multiplexed session (recommended for daemons). */
  streamClient?: TradingClient;
}

export interface FillsSubscription {
  close(): void;
}

/** Subscribe to the per-account fills channel; surfaces session lifecycle. */
export function subscribeFills(opts: SubscribeFillsOptions): FillsSubscription {
  const owned = !opts.streamClient;
  const stream =
    opts.streamClient ??
    new TradingClient({
      gatewayWsUrl: opts.gatewayWsUrl,
      token: opts.token,
      tokenProvider: opts.tokenProvider,
      webSocketFactory: opts.webSocketFactory,
      onError: opts.onError,
    });
  const channel = stream.subscribeChannel(
    "fills",
    (frame) => {
      void (async () => {
        try {
          const memo = frame as FillMemo;
          const rec = await receiveFillMemo(memo, opts.store);
          opts.onFill?.(rec);
        } catch (e) {
          opts.onError?.(e as Error);
        }
      })();
    },
    { onResync: opts.onResync, onClose: opts.onClose },
  );

  return {
    close() {
      channel.close();
      if (owned) stream.close();
    },
  };
}

export interface FillsSyncOptions
  extends Omit<BackfillOptions, "baseUrl">, SubscribeFillsOptions {
  /** Indexer base URL. Locates the account's fills (by HD-derived
   *  order id), and — when `baseMint`/`quoteMint` are set — recovers each
   *  trade/change openings from the permanent on-chain recovery-v3 ciphertext.
   *  Omit to skip backfill
   *  entirely (live tail only), or use `chainBackfill` for the indexer-free path. */
  indexerBaseUrl?: string;
  /** Indexer-FREE backfill: rediscover fills by scanning the vault program's
   *  settle history directly (`backfillHistoryFromChain`). Use this when no
   *  indexer is deployed — the daemon/light-client path. Ignored when
   *  `indexerBaseUrl` is also set (the indexer is preferred: O(my order ids)
   *  point queries vs an O(all settles) chain walk). */
  chainBackfill?: Omit<ChainBackfillOptions, "masterSeed" | "gapLimit">;
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
 * "Tail then backfill", self-healing: subscribe to the live `fills` channel AND backfill
 * any gap from the chain. The durable recovery source is the PERMANENT on-chain
 * recovery-v3 ciphertext — for each fill the indexer locates,
 * `recoverFillFromChain` decrypts + self-verifies trade/change openings into
 * the `NoteStore`. This replaced the retired durable memo-replay log
 * (`GET /fills/replay`), which a CVM redeploy used to wipe.
 *
 * The `NoteStore` is commitment-keyed, so overlapping backfill/live delivery just
 * re-puts. On a lag or sequence-gap resync we re-backfill while the shared
 * stream session reconnects and resubscribes.
 */
export async function startFillsSync(
  opts: FillsSyncOptions,
): Promise<FillsSync> {
  let located: BackfillResult | undefined;

  const backfill = async () => {
    try {
      if (opts.indexerBaseUrl) {
        located = await backfillHistory({
          ...opts,
          baseUrl: opts.indexerBaseUrl,
        });
      } else if (opts.chainBackfill) {
        located = await backfillHistoryFromChain({
          ...opts.chainBackfill,
          masterSeed: opts.masterSeed,
          gapLimit: opts.gapLimit,
        });
      } else {
        return; // no backfill source — live tail only.
      }
      if (!opts.baseMint || !opts.quoteMint) return; // locate-only (no mints).
      // A later continuation derives from the prior continuation opening. Run
      // a fixpoint so indexer/chain result ordering cannot strand a recoverable
      // chain: every recovered note becomes a candidate input for the next pass.
      const pending = [...located.located];
      let advanced = true;
      while (pending.length > 0 && advanced) {
        advanced = false;
        for (let i = pending.length - 1; i >= 0; i--) {
          const fill = pending[i];
          const tradeExisting = await opts.store.get(
            fill.tradeNoteCommitment.toLowerCase(),
          );
          const changeExisting = fill.changeNoteCommitment
            ? await opts.store.get(fill.changeNoteCommitment.toLowerCase())
            : undefined;
          if (
            tradeExisting &&
            (!fill.changeNoteCommitment || changeExisting)
          ) {
            pending.splice(i, 1);
            advanced = true;
            continue;
          }
          const outputs = await recoverFillFromChain(fill, {
            masterSeed: opts.masterSeed,
            candidateInputs: await opts.store.list(),
            baseMint: opts.baseMint,
            quoteMint: opts.quoteMint,
          });
          if (outputs) {
            if (!tradeExisting) {
              await opts.store.put(outputs.trade);
              opts.onFill?.(outputs.trade);
            }
            if (outputs.change && !changeExisting) {
              await opts.store.put(outputs.change);
              opts.onFill?.(outputs.change);
            }
            pending.splice(i, 1);
            advanced = true;
          }
        }
      }
    } catch (e) {
      opts.onError?.(e as Error);
    }
  };

  // Open the live tail first so fills finalized during a long history scan are
  // buffered by the sequence-aware stream instead of falling into a gap.
  const sub = subscribeFills({
    ...opts,
    onResync: (reason) => {
      opts.onResync?.(reason);
      void backfill();
    },
  });

  await backfill();

  return {
    located,
    close() {
      sub.close();
    },
  };
}
