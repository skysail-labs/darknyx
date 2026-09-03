/**
 * Settle-tx watcher: scans the vault program's history via Helius
 * `getTransactionsForAddress` (gTFA) — ONE call returns up to 100 FULL
 * transactions (the Helius cap for `transactionDetails: "full"`; signatures +
 * slots + instructions inline), oldest-first,
 * filtered to `status: succeeded`, floored at the cursor slot. This replaces the
 * old `getSignaturesForAddress` + per-signature `getTransaction` fan-out (1 + N
 * calls → ~1 call per 1000 txs). Each settle's fills are upserted by order_id.
 *
 * `extractFills` is a pure function over one gTFA (jsonParsed) tx so it stays
 * testable with a synthetic tx and no live RPC.
 *
 * Devnet caveat: Helius retains ~2 weeks of history on devnet; the indexer seeds
 * its cursor to the tip (`seedCursorToTip`) and only tails forward, so this is
 * not a concern in steady state.
 */

import type { Connection, PublicKey } from "@solana/web3.js";
import { decodeSettleIxData, type SettleFill } from "./decode.js";
import { base58Decode } from "./base58.js";
import type { FillsDb } from "./db.js";

/** One full transaction from gTFA (jsonParsed), trimmed to what the watcher reads. */
export interface GtfaTx {
  slot: number;
  transaction: {
    signatures: string[];
    message: { instructions: GtfaInstruction[] };
  };
  meta?: { err: unknown | null } | null;
}
/** A jsonParsed top-level instruction. For our (unparsed) vault program the RPC
 *  returns the resolved `programId` + base58 `data` (no manual ALT/index work). */
interface GtfaInstruction {
  programId: string;
  data?: string; // base58; present for unparsed instructions
}

/** One page of gTFA results + the `"slot:position"` cursor for the next page. */
export interface GtfaPage {
  txs: GtfaTx[];
  nextToken: string | null;
}

/** Injectable gTFA scanner (a single page). Defaults to a `fetch` against the
 *  connection's RPC URL; tests inject a mock. */
export type GtfaScan = (opts: {
  sortOrder: "asc" | "desc";
  slotGte?: number;
  limit: number;
  paginationToken?: string;
}) => Promise<GtfaPage>;

/** Pull every settle fill out of one gTFA tx (any vault settle ixs it contains). */
export function extractFills(programId: string, tx: GtfaTx): SettleFill[] {
  const out: SettleFill[] = [];
  for (const ix of tx.transaction.message.instructions) {
    if (ix.programId !== programId || typeof ix.data !== "string") continue;
    const fills = decodeSettleIxData(base58Decode(ix.data));
    if (fills) out.push(...fills);
  }
  return out;
}

/** Build the default fetch-based gTFA scanner against `rpcUrl` for `programId`. */
export function makeGtfaScan(rpcUrl: string, programId: string): GtfaScan {
  return async ({ sortOrder, slotGte, limit, paginationToken }) => {
    const filters: Record<string, unknown> = { status: "succeeded" };
    if (slotGte !== undefined) filters.slot = { gte: slotGte };
    const config: Record<string, unknown> = {
      transactionDetails: "full",
      encoding: "jsonParsed",
      sortOrder,
      limit,
      commitment: "confirmed",
      maxSupportedTransactionVersion: 1,
      filters,
    };
    if (paginationToken) config.paginationToken = paginationToken;

    const res = await fetch(rpcUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "getTransactionsForAddress",
        params: [programId, config],
      }),
    });
    if (!res.ok) throw new Error(`gTFA HTTP ${res.status}`);
    const json = (await res.json()) as {
      error?: { message: string };
      result?: { data?: GtfaTx[]; paginationToken?: string | null };
    };
    if (json.error) throw new Error(`gTFA: ${json.error.message}`);
    return {
      txs: json.result?.data ?? [],
      nextToken: json.result?.paginationToken ?? null,
    };
  };
}

export interface WatcherOpts {
  connection: Connection;
  programId: PublicKey;
  db: FillsDb;
  /** Max transactions to pull per gTFA page. Helius caps `getTransactionsForAddress`
   *  at 100 when `transactionDetails: "full"` (a higher limit 400s every poll with
   *  "you can only request up to 100 transactions at a time"); the 1000 cap only
   *  applies to lighter detail levels. Defaults to 100. */
  pageLimit?: number;
  /** Logger (defaults to console). */
  log?: (msg: string) => void;
  /** Override the gTFA scanner (tests inject a mock). Defaults to a `fetch`
   *  against `connection.rpcEndpoint`. */
  scan?: GtfaScan;
}

export class Watcher {
  private readonly programIdStr: string;
  private readonly db: FillsDb;
  private readonly pageLimit: number;
  private readonly log: (msg: string) => void;
  private readonly scan: GtfaScan;
  private timer: ReturnType<typeof setTimeout> | null = null;
  /** Resolver for the inter-poll sleep, so stop() can wake run() immediately. */
  private wake: (() => void) | null = null;
  private stopped = false;

  constructor(o: WatcherOpts) {
    this.programIdStr = o.programId.toBase58();
    this.db = o.db;
    this.pageLimit = o.pageLimit ?? 100;
    this.log = o.log ?? ((m) => console.log(`[watcher] ${m}`));
    this.scan =
      o.scan ?? makeGtfaScan(o.connection.rpcEndpoint, this.programIdStr);
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
    const { txs } = await this.scan({ sortOrder: "desc", limit: 1 });
    if (txs.length === 0) return null; // no program history yet; backfill path is fine
    const tip = txs[0];
    const sig = tip.transaction.signatures[0];
    this.db.setCursor(sig, tip.slot);
    this.log(`cold-start: seeded cursor to tip slot ${tip.slot} (no backfill)`);
    return tip.slot;
  }

  /** One incremental pass. Returns the number of fill rows ingested. */
  async pollOnce(): Promise<number> {
    const { lastSlot } = this.db.getCursor();
    // Re-scan from the cursor slot inclusive (gte): the boundary slot may have
    // gained later txs since we last saw it, and the db upsert is idempotent
    // (INSERT OR IGNORE keyed by signature+match+side), so re-seeing it is safe.
    const slotGte = lastSlot ?? undefined;

    let token: string | undefined;
    let ingested = 0;
    let newest: { sig: string; slot: number } | null = null;

    do {
      const { txs, nextToken } = await this.scan({
        sortOrder: "asc",
        slotGte,
        limit: this.pageLimit,
        paginationToken: token,
      });
      // gTFA asc → oldest-first, so the cursor advances monotonically.
      for (const tx of txs) {
        const sig = tx.transaction.signatures[0];
        if (!sig) continue;
        if (tx.meta?.err) continue; // defensive — status:succeeded already filters reverts
        const fills = extractFills(this.programIdStr, tx);
        if (fills.length > 0) {
          this.db.upsertFills(sig, tx.slot, fills);
          ingested += fills.length;
        }
        newest = { sig, slot: tx.slot };
      }
      token = nextToken ?? undefined;
    } while (token);

    if (newest) this.db.setCursor(newest.sig, newest.slot);
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
      if (this.stopped) break;
      // Sleep between polls, but expose the resolver so stop() can wake us
      // immediately. clearTimeout alone never resolves this promise, so the
      // loop would hang forever after stop() — resolve it explicitly there.
      await new Promise<void>((res) => {
        this.wake = res;
        this.timer = setTimeout(res, intervalMs);
      });
      this.wake = null;
      this.timer = null;
    }
  }

  stop(): void {
    this.stopped = true;
    if (this.timer) clearTimeout(this.timer);
    if (this.wake) this.wake(); // unblock the pending sleep so run() can exit
    this.timer = null;
    this.wake = null;
  }
}
