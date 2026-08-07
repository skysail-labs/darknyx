/**
 * SettlementTracker — resolves change notes' on-chain leaf indices.
 *
 * Continuation change notes arrive from the `/v1/stream` fills channel with their opening but NO
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

import { fetchInclusionProof, type StoredNote } from "@darknyx/sdk";

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
  /** Fired once when repeated failures quarantine a note for reconciliation. */
  onQuarantined?: (commitment: string, error: unknown) => void;
  /** Seam for tests; defaults to the SDK `fetchInclusionProof`. */
  fetchInclusion?: FetchInclusionFn;
  /** Maximum simultaneous inclusion reads. Default 8. */
  concurrency?: number;
  /** Attempts before handing a note to reconciliation. Default 8. */
  maxAttempts?: number;
  /** Maximum exponential retry delay. Default 5 minutes. */
  maxBackoffMs?: number;
  /** Clock seam for deterministic retry tests. */
  now?: () => number;
}

interface RetryState {
  attempts: number;
  nextAt: number;
  quarantined: boolean;
}

export class SettlementTracker {
  private timer: ReturnType<typeof setInterval> | null = null;
  private running = false;
  private readonly retries = new Map<string, RetryState>();

  constructor(private readonly opts: SettlementTrackerOptions) {
    const concurrency = opts.concurrency ?? 8;
    const maxAttempts = opts.maxAttempts ?? 8;
    if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 64) {
      throw new Error("settlement tracker concurrency must be in 1..64");
    }
    if (!Number.isInteger(maxAttempts) || maxAttempts < 1) {
      throw new Error("settlement tracker maxAttempts must be positive");
    }
  }

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
      const now = (this.opts.now ?? Date.now)();
      const pendingRows = this.opts.store.listPendingLeafNotes();
      const pendingCommitments = new Set(
        pendingRows.map((note) => note.commitment),
      );
      // Reconciliation or lifecycle pruning may remove a note while it is in
      // backoff/quarantine. Drop orphan retry state so the map is bounded by
      // the live pending set rather than historical failures.
      for (const commitment of this.retries.keys()) {
        if (!pendingCommitments.has(commitment))
          this.retries.delete(commitment);
      }
      const pending = pendingRows.filter((note) => {
        const retry = this.retries.get(note.commitment);
        return !retry?.quarantined && (retry?.nextAt ?? 0) <= now;
      });
      let resolved = 0;
      let cursor = 0;
      const concurrency = Math.max(
        1,
        Math.min(this.opts.concurrency ?? 8, pending.length),
      );
      await Promise.all(
        Array.from({ length: concurrency }, async () => {
          while (cursor < pending.length) {
            const note = pending[cursor++];
            if (await this.resolveNote(note)) resolved += 1;
          }
        }),
      );
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
      this.retries.delete(note.commitment);
      this.opts.onResolved?.(note.commitment, leafIndex);
      return true;
    } catch (error) {
      // Not on-chain yet (or a transient gateway error). Retry with bounded
      // exponential backoff; a permanently impossible note is handed to the
      // SW-11 reconciliation path instead of consuming work forever.
      const prior = this.retries.get(note.commitment);
      const attempts = (prior?.attempts ?? 0) + 1;
      const maxAttempts = this.opts.maxAttempts ?? 8;
      const quarantined = attempts >= maxAttempts;
      const base = this.opts.pollMs ?? 5000;
      const delay = Math.min(
        base * 2 ** Math.max(0, attempts - 1),
        this.opts.maxBackoffMs ?? 5 * 60_000,
      );
      this.retries.set(note.commitment, {
        attempts,
        nextAt: (this.opts.now ?? Date.now)() + delay,
        quarantined,
      });
      if (quarantined && !prior?.quarantined) {
        this.opts.onQuarantined?.(note.commitment, error);
      }
      return false;
    }
  }

  /** Re-admit quarantined notes after an explicit, error-free reconciliation. */
  retryQuarantined(): void {
    for (const [commitment, state] of this.retries) {
      if (state.quarantined) this.retries.delete(commitment);
    }
  }
}
