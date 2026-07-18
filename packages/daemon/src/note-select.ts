/**
 * Collateral note selection.
 *
 * Picks which note the daemon spends to back an order. A spendable note must:
 *   - be of the required collateral mint (quote for a bid, base for an ask),
 *   - already have a resolved on-chain `leafIndex` (you can't prove inclusion
 *     for a note whose leaf the daemon doesn't know yet — see the
 *     SettlementTracker),
 *   - cover the required collateral amount,
 *   - not already be locked by another resting order (`excluded`).
 *
 * Strategy: **best fit** — the smallest note that covers the requirement. That
 * preserves the operator's large notes for larger orders and minimizes how much
 * change a fill sheds. Pure (no store, no I/O) so it's trivially testable; the
 * Daemon supplies the candidate list + the locked set.
 */

import type { StoredNote } from "@darknyx/sdk";

export interface CollateralRequest {
  /** 32-byte collateral mint. */
  mint: Uint8Array;
  /** Minimum note value required (nominal + fee — the caller computes this). */
  minAmount: bigint;
}

const mintHex = (m: Uint8Array): string => Buffer.from(m).toString("hex");

/** True for a note that can back an order right now. */
export function isSpendable(n: StoredNote): boolean {
  return n.leafIndex !== undefined;
}

/**
 * The smallest spendable, unlocked note of `req.mint` that covers
 * `req.minAmount`, or `undefined` if none qualifies.
 */
export function selectCollateralNote(
  notes: readonly StoredNote[],
  req: CollateralRequest,
  excluded: ReadonlySet<string> = new Set(),
): StoredNote | undefined {
  const wantMint = mintHex(req.mint);
  const candidates = notes.filter(
    (n) =>
      isSpendable(n) &&
      mintHex(n.tokenMint) === wantMint &&
      n.amount >= req.minAmount &&
      !excluded.has(n.commitment),
  );
  candidates.sort((a, b) =>
    a.amount < b.amount ? -1 : a.amount > b.amount ? 1 : 0,
  );
  return candidates[0];
}
