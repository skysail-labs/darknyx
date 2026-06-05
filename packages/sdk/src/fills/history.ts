/**
 * Durable trade history — the "backfill" half of "backfill then tail".
 *
 * The off-TEE indexer (`packages/indexer`) serves fills BY order_id, decoded from
 * the chain. It is account-agnostic and holds no secrets, so an indexer row
 * carries only `{ orderId, side, changeAmount, changeNoteCommitment }` — NOT the
 * `inner_hash` / `anchor_index` / `mint` the client needs to spend the change
 * note. The client recovers those from its own seed:
 *
 *   1. Gap-scan: derive `deriveOrderId(seed, 0..)`, query the indexer for each,
 *      stop after `gapLimit` consecutive empty order ids. Full history from the
 *      seed alone — no persisted order-id list (HD-wallet style).
 *   2. For each fill with a change note, find the anchor index by deriving
 *      `inner_hash` for k = 0,1,… and recomputing the commitment until it matches
 *      the row's `change_note_commitment`. That search both recovers the opening
 *      AND proves integrity (a wrong commitment never matches).
 *
 * The live WS path (`ws-client.ts`) gets `inner_hash`/`anchor_index` directly in
 * the `FillMemo`, so it skips the search.
 */

import { deriveOrderId, deriveInnerHash, bn254ToBE32 } from "../keys/key-generators.js";
import { noteCommitmentV2 } from "../utxo/note.js";
import type { ChangeNoteRecord, NoteStore } from "../utxo/note-store.js";

/** One fill row as served by the indexer's `GET /fills`. */
export interface IndexerFill {
  orderId: string;
  side: "buyer" | "seller";
  matchId: string;
  signature: string;
  changeAmount: string; // decimal string (u64-safe)
  changeNoteCommitment: string | null; // null = exact fill, no change note
  clearingPrice: string;
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
  ownerCommitment: bigint;
  /** The user's base + quote mints (32 bytes). buyer change = quote, seller change = base. */
  baseMint: Uint8Array;
  quoteMint: Uint8Array;
  store: NoteStore;
  /** Stop gap-scanning after this many consecutive empty order ids. Default 5. */
  gapLimit?: number;
  /** Max anchor indices to search per fill when recovering the opening. Default 64. */
  anchorMax?: number;
  /** Only consider fills at/after this slot (incremental backfill). */
  since?: number;
  fetchImpl?: typeof fetch;
}

export interface BackfillResult {
  /** Change notes recovered + stored. */
  notes: ChangeNoteRecord[];
  /** Highest order index that returned any fills (for a future incremental scan). */
  highestUsedIndex: number;
  /** Highest batch slot seen (a coarse cursor for "tail from here"). */
  cursorSlot: number;
}

/**
 * Recover the `ChangeNoteRecord` for one indexer fill by searching anchor
 * indices. Returns null when the row is an exact fill (no change note) or the
 * commitment can't be reproduced within `anchorMax` (corrupt/foreign row).
 */
export async function reconstructChangeNote(
  fill: IndexerFill,
  opts: Pick<BackfillOptions, "masterSeed" | "ownerCommitment" | "baseMint" | "quoteMint"> & {
    anchorMax?: number;
  },
): Promise<ChangeNoteRecord | null> {
  if (!fill.changeNoteCommitment) return null;
  const orderId = Uint8Array.from(Buffer.from(fill.orderId, "hex"));
  const mint = fill.side === "buyer" ? opts.quoteMint : opts.baseMint;
  const amount = BigInt(fill.changeAmount);
  const anchorMax = opts.anchorMax ?? 64;

  for (let k = 0; k < anchorMax; k++) {
    const innerBig = deriveInnerHash(opts.masterSeed, orderId, k);
    const commitment = await noteCommitmentV2({
      tokenMint: mint,
      amount,
      ownerCommitment: opts.ownerCommitment,
      innerHash: innerBig,
    });
    if (toHex(commitment) === fill.changeNoteCommitment) {
      return {
        commitment: fill.changeNoteCommitment,
        tokenMint: mint,
        amount,
        ownerCommitment: opts.ownerCommitment,
        innerHash: innerBig,
        orderId: fill.orderId,
        anchorIndex: k,
      };
    }
    // bn254ToBE32 guards range; deriveInnerHash already reduces mod r.
    void bn254ToBE32;
  }
  return null;
}

/**
 * Rebuild full trade history from the seed: gap-scan order ids, recover every
 * change note, and store it. Idempotent — the NoteStore is keyed by commitment,
 * so re-running (or overlapping with the live WS tail) just re-puts the same
 * record.
 */
export async function backfillHistory(opts: BackfillOptions): Promise<BackfillResult> {
  const gapLimit = opts.gapLimit ?? 5;
  const notes: ChangeNoteRecord[] = [];
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
        cursorSlot = Math.max(cursorSlot, Number(fill.batchSlot));
        const rec = await reconstructChangeNote(fill, opts);
        if (rec) {
          await opts.store.put(rec);
          notes.push(rec);
        }
      }
    }
    n += 1;
  }
  return { notes, highestUsedIndex, cursorSlot };
}
