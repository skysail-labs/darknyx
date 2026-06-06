/**
 * Settle-tx watcher: polls the vault program's signatures (finalized — no
 * reorgs), pulls each tx, extracts `tee_forced_settle_batched` fills, and
 * upserts them by order_id.
 *
 * `extractFills` is a pure function over a `getTransaction` response so it can be
 * tested against a captured/synthetic tx with no live RPC.
 */

import type { Connection, PublicKey, VersionedTransactionResponse } from "@solana/web3.js";
import { decodeSettleIxData, type SettleFill } from "./decode.js";
import type { FillsDb } from "./db.js";

/** Pull every settle fill out of one confirmed tx (any vault settle ixs it contains). */
export function extractFills(programId: PublicKey, tx: VersionedTransactionResponse): SettleFill[] {
  const msg = tx.transaction.message;
  // v0 settle txs reference accounts (incl. the program id) via ALTs, so resolve
  // the full key list including looked-up addresses.
  const keys = msg.getAccountKeys({ accountKeysFromLookups: tx.meta?.loadedAddresses ?? undefined });
  const out: SettleFill[] = [];
  for (const ix of msg.compiledInstructions) {
    const pid = keys.get(ix.programIdIndex);
    if (!pid || !pid.equals(programId)) continue;
    const fills = decodeSettleIxData(ix.data);
    if (fills) out.push(...fills);
  }
  return out;
}

export interface WatcherOpts {
  connection: Connection;
  programId: PublicKey;
  db: FillsDb;
  /** Max signatures to pull per poll. */
  pageLimit?: number;
  /** Logger (defaults to console). */
  log?: (msg: string) => void;
}

export class Watcher {
  private readonly conn: Connection;
  private readonly programId: PublicKey;
  private readonly db: FillsDb;
  private readonly pageLimit: number;
  private readonly log: (msg: string) => void;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private stopped = false;

  constructor(o: WatcherOpts) {
    this.conn = o.connection;
    this.programId = o.programId;
    this.db = o.db;
    this.pageLimit = o.pageLimit ?? 1000;
    this.log = o.log ?? ((m) => console.log(`[watcher] ${m}`));
  }

  /**
   * Cold-start fast path: if the db has no cursor yet, seed it to the chain's
   * newest signature WITHOUT ingesting history, so subsequent polls only see
   * settles that land after this point. A no-op once a cursor exists (resumes
   * normally). Returns the seeded slot, or null if nothing was seeded.
   */
  async seedCursorToTip(): Promise<number | null> {
    const { lastSignature } = this.db.getCursor();
    if (lastSignature) return null; // already tracking — don't rewind
    const newest = await this.conn.getSignaturesForAddress(this.programId, { limit: 1 });
    if (newest.length === 0) return null; // no program history yet; backfill path is fine
    this.db.setCursor(newest[0].signature, newest[0].slot);
    this.log(`cold-start: seeded cursor to tip slot ${newest[0].slot} (no backfill)`);
    return newest[0].slot;
  }

  /** One incremental pass. Returns the number of fill rows ingested. */
  async pollOnce(): Promise<number> {
    const { lastSignature } = this.db.getCursor();
    const sigs = await this.conn.getSignaturesForAddress(this.programId, {
      until: lastSignature ?? undefined,
      limit: this.pageLimit,
    });
    if (sigs.length === 0) return 0;

    // getSignaturesForAddress returns newest-first; process oldest-first so the
    // cursor advances monotonically and a crash mid-pass is resumable.
    let ingested = 0;
    for (const s of [...sigs].reverse()) {
      if (!s.err) {
        const tx = await this.conn.getTransaction(s.signature, {
          maxSupportedTransactionVersion: 0,
        });
        if (tx) {
          const fills = extractFills(this.programId, tx);
          if (fills.length > 0) {
            this.db.upsertFills(s.signature, s.slot, fills);
            ingested += fills.length;
          }
        }
      }
      this.db.setCursor(s.signature, s.slot);
    }
    if (ingested > 0) this.log(`ingested ${ingested} fill row(s)`);
    return ingested;
  }

  /** Poll forever on an interval. Resolves only after `stop()`. */
  async run(intervalMs = 3000): Promise<void> {
    this.stopped = false;
    while (!this.stopped) {
      try {
        await this.pollOnce();
      } catch (e) {
        this.log(`poll error: ${(e as Error).message}`);
      }
      await new Promise<void>((res) => {
        this.timer = setTimeout(res, intervalMs);
      });
    }
  }

  stop(): void {
    this.stopped = true;
    if (this.timer) clearTimeout(this.timer);
  }
}
