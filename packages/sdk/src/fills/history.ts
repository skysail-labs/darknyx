/**
 * Durable trade history — the "backfill" half of "backfill then tail".
 *
 * Amount-privacy (P3b): the off-TEE indexer (`packages/indexer`) is a pure
 * COMMITMENT LOCATOR. Its rows carry no amounts. Recovery v3 encrypts the
 * side's trade + change tuple in the settlement envelope and locates the exact
 * consumed input plus both output commitments.
 *
 * So this module's job is narrowed:
 *
 *   1. Gap-scan: derive `deriveOrderId(seed, 0..)`, query the indexer for each,
 *      stop after `gapLimit` consecutive empty order ids. Full set of FILLS
 *      (order_id + input/output commitments + finalized slot) from the seed
 *      alone — no
 *      persisted order-id list (HD-wallet style).
 *   2. Return the located fills + the finalized Solana slot cursor.
 *      The client populates its `NoteStore` by decrypting located ciphertext
 *      and deriving outputs from the consumed input opening.
 *
 * The permanent on-chain ciphertext survives a CVM redeploy; the live
 * fills-channel push remains only the low-latency fast path.
 */

import { deriveOrderId } from "../keys/key-generators.js";

/** One located fill as served by the indexer's `GET /fills`.
 *
 *  COMMITMENT LOCATOR shape (amount-privacy P3b): it tells you THAT an order
 *  had a fill and surfaces the opaque recovery ciphertext. */
export interface IndexerFill {
  orderId: string;
  side: "buyer" | "seller";
  matchId: string;
  signature: string;
  /** Finalized Solana transaction slot. This, not `batchSlot`, is the
   * incremental history cursor. */
  slot: number;
  /**
   * The consumed input's note-use TAG — `Poseidon3(29, commitment, inner)`,
   * not the commitment. It does not appear as a Merkle leaf and cannot be
   * matched against a note store by string equality; a holder derives the tag
   * for each note it owns and matches on that (see `recover.ts`).
   */
  inputNoteUseTag: string;
  /** The trade output's commitment — this one IS a leaf. */
  tradeNoteCommitment: string;
  /** `true` when this side received a change note (partial fill). */
  isPartialFill: boolean;
  /** 32-byte hex of the minted change note, or `null` when the side filled exactly. */
  changeNoteCommitment: string | null;
  batchSlot: string;
  /** Recovery v3: shared ephemeral X25519 pubkey and THIS side's 44-byte
   * encrypted `(trade, change)` tuple. */
  ephemeralPubkey?: string | null;
  outputEnc?: string | null;
  /** Leaf positions are available from direct-chain recovery, and may be
   * omitted by a lightweight locator indexer. */
  tradeLeafIndex?: string | null;
  changeLeafIndex?: string | null;
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
  /** Located fills (input/output commitments + opaque recovery ciphertext).
   * Exact fills are included because their trade note is recoverable too. */
  located: IndexerFill[];
  /** Highest order index that returned any fills (for a future incremental scan). */
  highestUsedIndex: number;
  /** Highest finalized Solana transaction slot seen. */
  cursorSlot: number;
}

/**
 * Gap-scan order ids from the seed and LOCATE every fill. This locator alone does not
 * reconstruct spendable openings; `startFillsSync` decrypts and verifies them
 * against known consumed inputs, while `subscribeFills` supplies the live path.
 *
 * Idempotent + stateless: order ids are HD-derived, so re-running (or running
 * with a `since` cursor) just re-locates the same set.
 */
export async function backfillHistory(
  opts: BackfillOptions,
): Promise<BackfillResult> {
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
        // The payload's batchSlot is the circuit slot index (0..15), not a
        // chain cursor. Fail closed on malformed locator metadata.
        if (Number.isSafeInteger(fill.slot) && fill.slot >= 0) {
          cursorSlot = Math.max(cursorSlot, fill.slot);
        }
        located.push(fill);
      }
    }
    n += 1;
  }
  return { located, highestUsedIndex, cursorSlot };
}
