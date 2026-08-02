/**
 * Reconciliation after a stream gap or a restart (SW-11).
 *
 * The `orders` and `fills` channels are notifiers, not durable logs. The TEE
 * buffers them and closes a client that falls behind with code 1011 — the
 * protocol's explicit "you have missed messages, go re-derive them from the
 * chain" signal. The SDK raises it as `onResync`. Nothing consumed it, so the
 * daemon carried on as though the stream were complete, and four things went
 * wrong at once:
 *
 * 1. **Silently stranded value.** A `FillMemo` is the only in-band delivery of a
 *    continuation change note's *opening* — the amount and `inner_hash` needed
 *    to ever spend it again. Notes minted during a gap never entered the store,
 *    so `balances()` under-reported and nothing said so.
 * 2. **Phase desync.** An order that filled inside the gap stayed `open`
 *    forever, so its collateral stayed in `lockedCommitments()` and the daemon
 *    lost access to its own inventory.
 * 3. **Restart is not recovery.** `start()` re-opened live tails at "now" and
 *    never reconciled persisted orders, making the desync permanent.
 * 4. **A stuck automation latch.** `mergeInFlight` is persisted and cleared only
 *    by a merge-confirmed/failed event. Crash mid-merge and it survives forever,
 *    and `reduceOrder` gates every future intent on `!mergeInFlight`.
 *
 * The recovery primitive already existed and self-verifies: SDK recovery v3
 * rebuilds openings from seed + chain. This module is the orchestration that was
 * missing, not new crypto.
 *
 * It is deliberately its own module rather than more of `daemon.ts`: the routine
 * serves two entry points (boot and mid-session resync) and needs to be testable
 * without standing up sockets.
 */

import { Connection, PublicKey } from "@solana/web3.js";
import { recoverNotesFromChain, type StoredNote } from "@darknyx/sdk";

import type { DaemonStore } from "./store.js";
import type { TeeReadClient } from "./tee-read.js";
import { TERMINAL_PHASES, type ManagedOrder, type OrderPhase } from "./types.js";

/**
 * Server `status` → local `OrderPhase`.
 *
 * The two vocabularies differ on purpose: the CVM reports what the BOOK knows
 * (`empty`, `pending`, `pending_settlement`, `expired`, `cancelled`), while the
 * daemon tracks a client lifecycle that also spans local-only states such as
 * `pending` (signed, not yet acknowledged) and terminal ones such as
 * `settlement_failed`.
 *
 * `empty` is the interesting one: the book holds no remaining quantity, which
 * from the client's side is `filled`. Mapping it to `open` — the value a stale
 * daemon keeps — is exactly the desync this fixes.
 */
export function phaseFromServerStatus(status: string): OrderPhase | null {
  switch (status) {
    case "empty":
      return "filled";
    case "pending":
      return "open";
    case "pending_settlement":
      return "pending_settlement";
    case "expired":
      return "expired";
    case "cancelled":
      return "cancelled";
    default:
      // An unrecognised status means a newer CVM than this daemon. Returning
      // null leaves the local phase untouched rather than guessing a
      // transition, which could free collateral that is still committed.
      return null;
  }
}

export interface ReconcileDeps {
  store: DaemonStore;
  reads: TeeReadClient;
  /** Solana RPC endpoint used for the chain-side note recovery. */
  rpcUrl: string;
  /** Vault program id, base58. */
  programId: string;
  masterSeed: Uint8Array;
  /** Market mints the recovery scan should cover. */
  baseMint: Uint8Array;
  quoteMint: Uint8Array;
  /** Bound the chain scan when a cursor is known. */
  sinceSlot?: number;
  /** Injection seam for tests. */
  connectionFactory?: (rpcUrl: string) => Connection;
  log?: (msg: string) => void;
}

export interface ReconcileResult {
  /** Orders whose local phase was corrected from the server's view. */
  ordersRephased: number;
  /** Orders the CVM no longer knows about. */
  ordersUnknown: number;
  /** Stuck `mergeInFlight` latches cleared. */
  mergeLatchesCleared: number;
  /** Notes added to the store that the stream never delivered. */
  notesRecovered: number;
  /** Non-fatal problems; reconciliation is best-effort per item. */
  errors: string[];
}

/**
 * Re-derive local state from the two authorities: the CVM for order phase, the
 * chain for note openings.
 *
 * Best-effort **per item**. One unreachable order must not abandon the rest —
 * a partially reconciled daemon is strictly better than one that gave up, and
 * the caller keeps placement paused until this returns either way.
 */
export async function reconcile(
  deps: ReconcileDeps,
): Promise<ReconcileResult> {
  const log = deps.log ?? (() => {});
  const result: ReconcileResult = {
    ordersRephased: 0,
    ordersUnknown: 0,
    mergeLatchesCleared: 0,
    notesRecovered: 0,
    errors: [],
  };

  // ── 1. Order phases, from the CVM ──────────────────────────────────────
  const active = deps.store.listActiveOrders();
  for (const order of active) {
    try {
      const remote = await deps.reads.order(order.orderId);
      if (remote === null) {
        // Unknown to the CVM. Do NOT invent a terminal phase: "the server has
        // forgotten it" and "it never landed" are indistinguishable here, and
        // guessing `cancelled` would release collateral that may still be
        // committed on-chain. The settlement tracker resolves it from chain
        // state, which is the authority that can actually tell.
        result.ordersUnknown += 1;
        continue;
      }
      const next = remote.status ? phaseFromServerStatus(remote.status) : null;
      if (next && next !== order.phase) {
        deps.store.putOrder({ ...order, phase: next, updatedAt: Date.now() });
        result.ordersRephased += 1;
        log(`[reconcile] ${order.orderId}: ${order.phase} -> ${next}`);
      }
    } catch (e) {
      result.errors.push(
        `order ${order.orderId}: ${e instanceof Error ? e.message : String(e)}`,
      );
    }
  }

  // ── 2. Clear stuck merge latches ───────────────────────────────────────
  // Any intent that was in flight when the process died is gone; the flag is
  // the only thing that survived it. Left set, that order never auto-merges
  // again for the life of the database.
  for (const order of deps.store.listActiveOrders()) {
    if (order.mergeInFlight) {
      deps.store.putOrder({
        ...order,
        mergeInFlight: false,
        updatedAt: Date.now(),
      });
      result.mergeLatchesCleared += 1;
    }
  }

  // ── 3. Note openings, from the chain ───────────────────────────────────
  try {
    const connect = deps.connectionFactory ?? ((u: string) => new Connection(u, "finalized"));
    const recovered = await recoverNotesFromChain({
      connection: connect(deps.rpcUrl),
      programId: new PublicKey(deps.programId),
      masterSeed: deps.masterSeed,
      baseMint: deps.baseMint,
      quoteMint: deps.quoteMint,
      sinceSlot: deps.sinceSlot,
    });
    const known = new Set(deps.store.list().map((n: StoredNote) => n.commitment));
    for (const note of recovered.notes as StoredNote[]) {
      if (known.has(note.commitment)) continue;
      deps.store.put(note);
      result.notesRecovered += 1;
    }
    if (result.notesRecovered > 0) {
      log(
        `[reconcile] recovered ${result.notesRecovered} note opening(s) the stream never delivered`,
      );
    }
  } catch (e) {
    result.errors.push(
      `note recovery: ${e instanceof Error ? e.message : String(e)}`,
    );
  }

  return result;
}

/** Whether a phase is terminal — re-exported so callers need one import. */
export function isTerminal(phase: OrderPhase): boolean {
  return TERMINAL_PHASES.has(phase);
}

export type { ManagedOrder };
