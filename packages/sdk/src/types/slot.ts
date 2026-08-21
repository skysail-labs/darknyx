/**
 * Slot narrowing for the web3.js v3 port.
 *
 * v3 returns slots, block heights and context slots as `bigint`. This codebase
 * models slots as `number` end to end (order expiry, recovery floors, the
 * fills history), and widening that domain would ripple through the daemon,
 * the browser client and every fixture for no behavioural gain.
 *
 * So slots are narrowed ONCE, at the RPC edge, and the narrowing is checked
 * rather than assumed. A bare `Number(slot)` would silently lose precision
 * past 2^53; Solana is around 3e8 slots and gains roughly 7.9e7 a year, so the
 * bound is ~10^8 years away -- but a corrupt or hostile RPC response is not,
 * and that is what this actually guards.
 */
export function slotToNumber(slot: bigint | number): number {
  if (typeof slot === "number") {
    // NaN, Infinity, fractions and negatives would otherwise pass straight
    // through and land in a recovery floor or a chain-history row.
    if (!Number.isSafeInteger(slot) || slot < 0) {
      throw new RangeError(`slot ${slot} is not a non-negative safe integer`);
    }
    return slot;
  }
  if (slot < 0n || slot > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new RangeError(`slot ${slot} is outside the safe integer range`);
  }
  return Number(slot);
}
