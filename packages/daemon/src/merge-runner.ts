/**
 * DaemonMergeRunner — the on-chain auto-consolidation behind the executor's
 * `merge` intent.
 *
 * When the lifecycle engine decides residual change notes should be merged, this
 * picks a mergeable batch from the {@link DaemonStore} and runs VALID_MERGE
 * (via the injected `mergeFn` = the SDK `getMergeFunction` output), then prunes
 * the spent inputs + stores the merged output note. Consolidating residuals back
 * into a single large note is what amortizes proving across many partial fills.
 *
 * Selection is ACCOUNT-level cross-mint (NOT per-order — see `run`): VALID_MERGE
 * consumes 2–4 same-owner, same-mint SPENDABLE notes. Spendable = leaf-resolved
 * (the settlement-tracker's job) AND not a re-locked rolling residual — i.e. a
 * deposit note or the final residual of a TERMINATED order. Grouped by mint;
 * first group with ≥ 2, capped at 4 (K=4). Fewer than 2 → returns 0 (clean
 * no-op; retried on the next quiescence as residuals accumulate across orders).
 *
 * `mergeFn` (the heavy DarkPoolClient-backed path) is injected, so this stays
 * unit-testable without devnet; `bin/daemon.ts` supplies the real implementation.
 */

import { PublicKey } from "@solana/web3.js";
import type { MergeParams, MergeReceipt, StoredNote } from "@darknyx/sdk";

import type { MergeOutcome, MergeRunner } from "./action-executor.js";
import type { DaemonStore } from "./store.js";
import { TERMINAL_PHASES, type ManagedOrder } from "./types.js";

const fromHex = (h: string): Uint8Array =>
  Uint8Array.from(Buffer.from(h, "hex"));

/** VALID_MERGE consumes at most 4 inputs (K=4). */
const MAX_K = 4;

/** The SDK merge entrypoint this wraps (`getMergeFunction({ client })`). */
export type MergeFn = (params: MergeParams) => Promise<MergeReceipt>;

export interface DaemonMergeRunnerOptions {
  store: DaemonStore;
  /** Solana fee payer for the merge tx. */
  payer: PublicKey;
  /** The account's shared owner commitment (all change notes carry it). */
  ownerCommitment: bigint;
  mergeFn: MergeFn;
  /** Merkle-tree shard the inputs live in + the output appends to (default 0). */
  treeId?: number;
}

/**
 * Compose a {@link DaemonMergeRunner} from an SDK `mergeFn` (the
 * `getMergeFunction({ client })` output) + the account context. The
 * `mergeFn`/`payer`/`ownerCommitment` come from a real `DarkPoolClient` the
 * caller builds. The output inner is commitment-derived inside the SDK, so the
 * daemon has no restart-sensitive counter to persist or reserve.
 */
export function createMergeRunner(args: {
  store: DaemonStore;
  payer: PublicKey;
  ownerCommitment: bigint;
  mergeFn: MergeFn;
  treeId?: number;
}): DaemonMergeRunner {
  return new DaemonMergeRunner({
    store: args.store,
    payer: args.payer,
    ownerCommitment: args.ownerCommitment,
    mergeFn: args.mergeFn,
    treeId: args.treeId,
  });
}

export class DaemonMergeRunner implements MergeRunner {
  constructor(private readonly opts: DaemonMergeRunnerOptions) {}

  async run(_order: ManagedOrder, _noteCount: number): Promise<MergeOutcome> {
    // Selection is ACCOUNT-level cross-mint, not per-order: v3 continuations
    // keep one ROLLING residual per order (each partial fill consumes
    // the prior + rebuilds it), so a single order never has ≥2 spendable
    // residuals. The notes worth consolidating are the FINAL residuals of
    // terminated orders + deposit notes, accumulated across orders + same-mint.
    // The `order` arg is just the trigger; we scan the whole store.
    const batch = this.selectBatch();
    if (!batch) return { consumed: 0, remaining: _order.pendingChangeNotes };

    const params: MergeParams = {
      payer: this.opts.payer,
      treeId: this.opts.treeId ?? 0,
      inputs: batch.map((n) => ({
        commitment: fromHex(n.commitment),
        amount: n.amount,
        innerHash: n.innerHash,
        leafIndex: n.leafIndex as bigint,
      })),
      tokenMint: batch[0].tokenMint,
      ownerCommitment: this.opts.ownerCommitment,
    };

    const receipt = await this.opts.mergeFn(params);

    // Prune the consumed inputs + store the consolidated output.
    for (const c of receipt.spentCommitments) this.opts.store.delete(c);
    this.opts.store.put(receipt.outputNote);

    // Reconcile every order the batch touched, from the store (SW-13).
    //
    // Selection is ACCOUNT-level, so `batch.length` counts notes across many
    // orders. It used to be subtracted from the single TRIGGER order, which
    // under-counted there (clamped at 0, hiding its own residual) and left
    // every other affected order over-counting permanently — parked above
    // `mergeThreshold`, firing a no-op merge intent on every subsequent tick.
    //
    // The store is the authority for "how many unspent change notes does this
    // order still have", so the count is DERIVED rather than tracked
    // incrementally. That removes the drift class, not just this instance.
    const touched = new Set(
      batch
        .map((n) => n.orderId)
        .filter((id): id is string => id !== undefined),
    );
    for (const orderId of touched) {
      const o = this.opts.store.getOrder(orderId);
      if (!o) continue;
      const remaining = this.opts.store
        .notesByOrder(orderId)
        .filter((n) => n.leafIndex !== undefined).length;
      if (remaining !== o.pendingChangeNotes) {
        this.opts.store.putOrder({
          ...o,
          pendingChangeNotes: remaining,
          updatedAt: Date.now(),
        });
      }
    }

    return {
      consumed: batch.length,
      // The trigger order's authoritative count, for the lifecycle event.
      remaining: this.opts.store
        .notesByOrder(_order.orderId)
        .filter((n) => n.leafIndex !== undefined).length,
    };
  }

  /** First mintable batch of 2..4 same-mint SPENDABLE notes (cross-order). */
  private selectBatch(): StoredNote[] | undefined {
    // One order-table read for the whole selection pass. Looking up each note's
    // order here used to turn this filter into N+1 SQLite queries.
    const orders = new Map(
      this.opts.store.listOrders().map((order) => [order.orderId, order]),
    );
    const spendable = this.opts.store
      .list()
      .filter((n) => this.isMergeable(n, orders));
    const byMint = new Map<string, StoredNote[]>();
    for (const n of spendable) {
      const k = Buffer.from(n.tokenMint).toString("hex");
      const g = byMint.get(k);
      if (g) g.push(n);
      else byMint.set(k, [n]);
    }
    for (const group of byMint.values()) {
      if (group.length >= 2) return group.slice(0, MAX_K);
    }
    return undefined;
  }

  /**
   * A note is mergeable iff its leaf is resolved AND nothing on-chain still
   * holds it.
   *
   * A deposit note (no `orderId`) is free. A change note is free only once its
   * order has reached a TERMINAL phase — at which point the final residual is
   * released.
   *
   * This previously excluded only `pending` and `open`, which let a residual in
   * `pending_settlement` or `filled` qualify — precisely the window in which
   * Tx D holds a live `NoteLock` (SW-12). The vault rejects the merge
   * (`merge.rs`'s N-04/S-03 guard), so it was never a double-spend; the cost
   * was a wasted VALID_MERGE proof and a failed transaction per attempt, and
   * because `selectBatch` is deterministic first-mint-group-wins it re-picked
   * the same note every tick — a stuck loop, not a one-off.
   *
   * Keyed on `TERMINAL_PHASES` so a newly added phase is excluded by default
   * rather than silently becoming spendable.
   */
  private isMergeable(
    n: StoredNote,
    orders: ReadonlyMap<string, ManagedOrder>,
  ): boolean {
    if (n.leafIndex === undefined) return false;
    if (n.orderId === undefined) return true; // deposit note
    const o = orders.get(n.orderId);
    return !o || TERMINAL_PHASES.has(o.phase);
  }
}
