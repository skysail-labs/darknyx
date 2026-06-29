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
 * Selection rules (VALID_MERGE consumes 2–4 same-owner, same-mint notes):
 *   - only this order's continuation notes that already have a known on-chain
 *     `leafIndex` (a change note can't be merged until its leaf is resolved —
 *     the settlement-tracker's job, a later slice);
 *   - grouped by mint; the first group with ≥ 2 notes, capped at 4 (K=4).
 * Fewer than 2 mergeable → returns 0 (a clean no-op; the engine just leaves the
 * residual count where it is and retries on the next quiescence).
 *
 * `mergeFn` (the heavy DarkPoolClient-backed path) + `nextMergeIndex` are
 * injected, so this stays unit-testable without devnet; `bin/daemon.ts` supplies
 * the real implementations.
 */

import { PublicKey } from "@solana/web3.js";
import type { MergeParams, MergeReceipt, StoredNote } from "@nyx/sdk";

import type { MergeRunner } from "./action-executor.js";
import type { DaemonStore } from "./store.js";
import type { ManagedOrder } from "./types.js";

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
  /** Monotone unique index for each merged output (recoverable from the seed). */
  nextMergeIndex: () => number;
  /** Merkle-tree shard the inputs live in + the output appends to (default 0). */
  treeId?: number;
}

/**
 * Compose a {@link DaemonMergeRunner} from an SDK `mergeFn` (the
 * `getMergeFunction({ client })` output) + the account context, with a simple
 * monotone merge-index counter starting at `startMergeIndex`. The
 * `mergeFn`/`payer`/`ownerCommitment` come from a real `DarkPoolClient` the
 * caller builds (the provider stack — connection, tx forwarder, merge zk-prover
 * — is constructed + devnet-validated at integration time, which is why bin
 * leaves merge unconfigured until then).
 */
export function createMergeRunner(args: {
  store: DaemonStore;
  payer: PublicKey;
  ownerCommitment: bigint;
  mergeFn: MergeFn;
  startMergeIndex?: number;
  treeId?: number;
}): DaemonMergeRunner {
  let mergeIndex = args.startMergeIndex ?? 0;
  return new DaemonMergeRunner({
    store: args.store,
    payer: args.payer,
    ownerCommitment: args.ownerCommitment,
    mergeFn: args.mergeFn,
    nextMergeIndex: () => mergeIndex++,
    treeId: args.treeId,
  });
}

export class DaemonMergeRunner implements MergeRunner {
  constructor(private readonly opts: DaemonMergeRunnerOptions) {}

  async run(_order: ManagedOrder, _noteCount: number): Promise<number> {
    // Selection is ACCOUNT-level cross-mint, not per-order: the anchor-pool
    // model keeps one ROLLING residual per order (each partial fill consumes
    // the prior + rebuilds it), so a single order never has ≥2 spendable
    // residuals. The notes worth consolidating are the FINAL residuals of
    // terminated orders + deposit notes, accumulated across orders + same-mint.
    // The `order` arg is just the trigger; we scan the whole store.
    const batch = this.selectBatch();
    if (!batch) return 0;

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
      mergeIndex: this.opts.nextMergeIndex(),
    };

    const receipt = await this.opts.mergeFn(params);

    // Prune the consumed inputs + store the consolidated output.
    for (const c of receipt.spentCommitments) this.opts.store.delete(c);
    this.opts.store.put(receipt.outputNote);
    return batch.length;
  }

  /** First mintable batch of 2..4 same-mint SPENDABLE notes (cross-order). */
  private selectBatch(): StoredNote[] | undefined {
    const spendable = this.opts.store.list().filter((n) => this.isMergeable(n));
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

  /** A note is mergeable iff its leaf is resolved AND it isn't a re-locked
   *  rolling residual — i.e. a deposit note (no orderId) or a change note whose
   *  order has gone terminal (its final residual is released). A change note of
   *  a still-open order is re-locked for continuation, so it's NOT spendable. */
  private isMergeable(n: StoredNote): boolean {
    if (n.leafIndex === undefined) return false;
    if (n.orderId === undefined) return true; // deposit note
    const o = this.opts.store.getOrder(n.orderId);
    return !o || (o.phase !== "pending" && o.phase !== "open");
  }
}
