/**
 * Durable trade history — the "backfill" half of "backfill then tail".
 *
 * Amount-privacy (P3b): the off-TEE indexer (`packages/indexer`) is now a pure
 * COMMITMENT LOCATOR. Its rows carry no amounts — only `{ orderId, side,
 * matchId, isPartialFill, changeNoteCommitment, batchSlot }`. The amount, the
 * `inner_hash`/`anchor_index`, and therefore the *spendable* change-note
 * opening come ONLY from the per-account `FillMemo` (the authenticated live
 * `/ws/fills` channel, verified in `orders/fill-memo.ts`). A change note's
 * amount is never on-chain, so it cannot be rebuilt from the chain/indexer
 * alone — the same note-plaintext requirement every shielded pool has.
 *
 * So this module's job is narrowed:
 *
 *   1. Gap-scan: derive `deriveOrderId(seed, 0..)`, query the indexer for each,
 *      stop after `gapLimit` consecutive empty order ids. Full set of FILLS
 *      (order_id + change-note commitment + slot) from the seed alone — no
 *      persisted order-id list (HD-wallet style).
 *   2. Return the located fills + a coarse slot cursor for "tail from here".
 *      The client populates its `NoteStore` from FillMemos; the located
 *      commitments let it detect gaps (a located commitment it has no memo/note
 *      for = a fill whose memo it still needs to replay).
 *
 * Gap recovery for a fill the client was offline for (memo missed) is handled by
 * the durable memo-replay endpoint (`replayFills` → `GET /fills/replay`, P7) —
 * the amount + opening come from there, not from this locator. So this module is
 * a secondary gap-detector now; `startFillsSync` recovers via replay first, then
 * tails the live WS.
 */

import { deriveOrderId } from "../keys/key-generators.js";

/** One located fill as served by the indexer's `GET /fills`.
 *
 *  COMMITMENT LOCATOR shape (amount-privacy P3b): it tells you THAT an order
 *  had a fill and the change-note commitment, but NOT the amount — that comes
 *  from the FillMemo. */
export interface IndexerFill {
  orderId: string;
  side: "buyer" | "seller";
  matchId: string;
  signature: string;
  /** `true` when this side received a change note (partial fill). */
  isPartialFill: boolean;
  /** 32-byte hex of the minted change note, or `null` when the side filled exactly. */
  changeNoteCommitment: string | null;
  batchSlot: string;
}

/** Fetch an order's fills from the indexer. */
export async function fetchOrderFills(
  baseUrl: string,
  orderId: string,
  opts: { since?: number; fetchImpl?: typeof fetch } = {},
): Promise<IndexerFill[]> {
  const f = opts.fetchImpl ?? fetch;
  const url = new URL("/fills", baseUrl);
  url.searchParams.set("order_id", orderId);
  if (opts.since) url.searchParams.set("since", String(opts.since));
  const res = await f(url.toString());
  if (!res.ok) throw new Error(`indexer ${res.status}: ${await res.text()}`);
  const body = (await res.json()) as { fills: IndexerFill[] };
  return body.fills ?? [];
}

const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");

export interface BackfillOptions {
  /** Indexer base URL, e.g. http://localhost:8090. */
  baseUrl: string;
  masterSeed: Uint8Array;
  /** Stop gap-scanning after this many consecutive empty order ids. Default 5. */
  gapLimit?: number;
  /** Only consider fills at/after this slot (incremental backfill). */
  since?: number;
  fetchImpl?: typeof fetch;
}

export interface BackfillResult {
  /** Located change-note fills (order_id + commitment + slot), NOT spendable
   *  openings — the amount/opening for each comes from the FillMemo. Only fills
   *  that minted a change note are included (exact fills carry no note). */
  located: IndexerFill[];
  /** Highest order index that returned any fills (for a future incremental scan). */
  highestUsedIndex: number;
  /** Highest batch slot seen (a coarse cursor for "tail from here"). */
  cursorSlot: number;
}

/**
 * Gap-scan order ids from the seed and LOCATE every change-note fill (commitment
 * + order_id + slot). Does not reconstruct spendable openings — amounts live
 * only in the FillMemo (amount-privacy P3b), so the live tail
 * (`subscribeFills`) is what populates the `NoteStore`.
 *
 * Idempotent + stateless: order ids are HD-derived, so re-running (or running
 * with a `since` cursor) just re-locates the same set.
 */
export async function backfillHistory(opts: BackfillOptions): Promise<BackfillResult> {
  const gapLimit = opts.gapLimit ?? 5;
  const located: IndexerFill[] = [];
  let consecutiveEmpty = 0;
  let n = 0;
  let highestUsedIndex = -1;
  let cursorSlot = opts.since ?? 0;

  while (consecutiveEmpty < gapLimit) {
    const orderId = toHex(deriveOrderId(opts.masterSeed, n));
    const fills = await fetchOrderFills(opts.baseUrl, orderId, {
      since: opts.since,
      fetchImpl: opts.fetchImpl,
    });
    if (fills.length === 0) {
      consecutiveEmpty += 1;
    } else {
      consecutiveEmpty = 0;
      highestUsedIndex = n;
      for (const fill of fills) {
        // Guard against a malformed batchSlot poisoning the cursor: Math.max
        // with NaN is NaN, which would break downstream incremental sync.
        const slot = Number(fill.batchSlot);
        if (Number.isFinite(slot)) cursorSlot = Math.max(cursorSlot, slot);
        if (fill.changeNoteCommitment) located.push(fill);
      }
    }
    n += 1;
  }
  return { located, highestUsedIndex, cursorSlot };
}
