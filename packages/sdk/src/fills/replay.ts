/**
 * Durable memo replay — the amount-recovery half of "backfill then tail".
 *
 * `GET /fills/replay?since=<seq>` (the TEE, P7) returns the account's persisted
 * `FillMemo`s with `seq > since`. Amount-privacy (P4) made the off-TEE indexer a
 * commitment-only LOCATOR, so this — not the indexer — is where a client that
 * was offline (or whose CVM restarted) when a fill settled recovers the change
 * note's amount + opening. Each memo runs the SAME `verifyFillMemo` (Vuln-4)
 * integrity check as a live one, so a replayed memo is trusted no more than a
 * live one; a memo that fails the check is skipped, not fatal.
 */

import { receiveFillMemo, type FillMemo } from "../orders/fill-memo.js";
import type { ChangeNoteRecord, NoteStore } from "../utxo/note-store.js";

export interface ReplayOptions {
  /** Gateway HTTP origin, e.g. `https://<app>-8080.dstack-…` (NOT the ws:// form). */
  gatewayHttpUrl: string;
  token: string;
  masterSeed: Uint8Array;
  ownerCommitment: bigint;
  store: NoteStore;
  /** Cursor: the client's last-seen seq. `0` (default) = first/no-cursor sync. */
  since?: number;
  fetchImpl?: typeof fetch;
  /** Called for each recovered + stored note. */
  onFill?: (rec: ChangeNoteRecord) => void;
  /** Called for a memo that failed verification (skipped, not fatal). */
  onError?: (err: Error) => void;
}

export interface ReplayResult {
  /** Notes recovered + stored from this replay. */
  records: ChangeNoteRecord[];
  /** The cursor to pass as `since` next time (the server's `next_cursor`). */
  nextCursor: number;
}

interface ReplayResponseWire {
  memos: FillMemo[];
  next_cursor: number;
}

/**
 * Fetch + verify + store the account's memos newer than `since`. Returns the
 * recovered records + the advanced cursor. Idempotent: the `NoteStore` is keyed
 * by commitment, so re-replaying an overlapping window just re-puts.
 */
export async function replayFills(opts: ReplayOptions): Promise<ReplayResult> {
  const f = opts.fetchImpl ?? fetch;
  const since = opts.since ?? 0;
  const base = opts.gatewayHttpUrl.replace(/\/$/, "");
  const url = `${base}/fills/replay?since=${since}`;
  const res = await f(url, {
    headers: { authorization: `Bearer ${opts.token}` },
  });
  if (!res.ok) {
    throw new Error(`fills/replay ${res.status}: ${await res.text()}`);
  }
  const body = (await res.json()) as ReplayResponseWire;

  const records: ChangeNoteRecord[] = [];
  for (const memo of body.memos ?? []) {
    try {
      const rec = await receiveFillMemo(
        memo,
        opts.masterSeed,
        opts.ownerCommitment,
        opts.store,
      );
      records.push(rec);
      opts.onFill?.(rec);
    } catch (e) {
      // A single memo that fails the Vuln-4 guard must not abort recovery of
      // the rest — skip it (surface via onError) and continue.
      opts.onError?.(e as Error);
    }
  }
  // Clamp the cursor monotonically forward: a stale/malformed server
  // next_cursor must never regress below `since`, or a replay-then-tail driver
  // could re-fetch the same window forever.
  return { records, nextCursor: Math.max(body.next_cursor ?? since, since) };
}
