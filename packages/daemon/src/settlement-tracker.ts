/**
 * SettlementTracker — resolves change notes' on-chain leaf indices.
 *
 * Continuation change notes arrive from `/ws/fills` with their opening but NO
 * leaf index — the TEE mints them as it settles, and the index is only knowable
 * once the settle tx lands. A note can't be merged (or spent) without its leaf
 * index (the Merkle witness needs it), so the {@link DaemonMergeRunner} skips
 * leaf-less notes. This tracker fills that gap: it polls the TEE's
 * `GET /tree/inclusion` (via the SDK `fetchInclusionProof`) for each unresolved
 * change note and, once the leaf exists, writes the index back to the
 * {@link DaemonStore} — which is what unblocks auto-merge.
 *
 * `/tree/inclusion` (keyed by commitment) is the right source: it returns the
 * exact leaf index the TEE's mirror holds, immune to the concurrent-append race
 * that a `leaf_count` prediction would hit. The fetch is injectable so the
 * tracker is unit-testable without a gateway.
 */

import { fetchInclusionProof, type StoredNote } from "@nyx/sdk";

import type { DaemonStore } from "./store.js";

/** The SDK inclusion fetch this wraps (injected for tests). */
export type FetchInclusionFn = typeof fetchInclusionProof;

export interface SettlementTrackerOptions {
  store: DaemonStore;
  /** Gateway origin (the SDK appends `/tree/inclusion`). */
  gatewayUrl: string;
  token: string;
  treeId?: number;
  fetchImpl?: typeof fetch;
  /** Poll interval for resolving pending leaf indices (ms). Default 5000. */
  pollMs?: number;
  /** Fired when a note's leaf index is resolved. */
  onResolved?: (commitment: string, leafIndex: bigint) => void;
  /** Seam for tests; defaults to the SDK `fetchInclusionProof`. */
  fetchInclusion?: FetchInclusionFn;
}

export class SettlementTracker {
  private timer: ReturnType<typeof setInterval> | null = null;
  private running = false;

  constructor(private readonly opts: SettlementTrackerOptions) {}

  /** Begin polling. The timer is `unref`'d so it never keeps the process up. */
  start(): void {
    if (this.timer) return;
    const ms = this.opts.pollMs ?? 5000;
    this.timer = setInterval(() => void this.resolvePending(), ms);
    this.timer.unref?.();
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  /** Try to resolve every change note that still lacks a leaf index. Returns the
   *  number resolved this pass. Non-overlapping: a slow pass won't stack. */
  async resolvePending(): Promise<number> {
    if (this.running) return 0;
    this.running = true;
    try {
      const pending = this.opts.store
        .list()
        .filter((n) => n.orderId !== undefined && n.leafIndex === undefined);
      let resolved = 0;
      for (const note of pending) {
        if (await this.resolveNote(note)) resolved += 1;
      }
      return resolved;
    } finally {
      this.running = false;
    }
  }

  /** Resolve one note's leaf index from `/tree/inclusion`. Returns true if it
   *  was found + written back. A not-yet-settled note just stays pending. */
  async resolveNote(note: StoredNote): Promise<boolean> {
    const fetchInclusion = this.opts.fetchInclusion ?? fetchInclusionProof;
    try {
      const witness = await fetchInclusion(
        {
          baseUrl: this.opts.gatewayUrl,
          token: this.opts.token,
          treeId: this.opts.treeId,
          fetchImpl: this.opts.fetchImpl,
        },
        note.commitment,
      );
      const leafIndex = BigInt(witness.leafIndex);
      this.opts.store.put({ ...note, leafIndex });
      this.opts.onResolved?.(note.commitment, leafIndex);
      return true;
    } catch {
      // Not on-chain yet (or a transient gateway error) — stays pending for the
      // next pass. Expected for a just-minted change note.
      return false;
    }
  }
}
