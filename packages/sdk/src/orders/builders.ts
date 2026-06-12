/**
 * Order-builder sugar — market / AON / GTT presets over the existing
 * `OrderCanonical` execution fields.
 *
 * None of these are new wire types: the matcher only ever reads
 * `{ orderType, priceLimit, minFillSize, expirySlot }` (plus the
 * collateral/identity fields the caller already owns). Each helper just
 * fills those four "execution policy" fields for a common intent so a
 * client doesn't hand-encode the convention (and get it subtly wrong).
 *
 *   - **market** — `IOC` with a price cap. A market *bid* names the worst
 *     price it will pay (`priceCap`, which the over-collateralized note must
 *     cover); a market *ask* sets `priceLimit = 0` (sell into any clearing
 *     price). IOC means the residual auto-cancels instead of resting, so a
 *     market order never pins a note in the book.
 *   - **AON (resting)** — a `Limit` order with `minFillSize == amount`. The
 *     matcher already honors `min_fill_size` for limit orders
 *     (`darkpool-matcher::algorithm`), so this is all-or-none across ticks
 *     while it rests.
 *   - **FOK** — immediate all-or-none: `order_type = Fok`. Fills fully in the
 *     tick it arrives or is dropped.
 *   - **GTT** — good-till-time: convert a wall-clock expiry to an
 *     `expiry_slot` via the server's `/time` (current slot + unix ms) so the
 *     client doesn't need its own RPC. See `gttExpirySlot`.
 *
 * The returned `ExecutionPolicy` is merged into a full `OrderCanonical` by
 * the caller (who supplies `symbol`, `orderId`, `noteCommitment`,
 * `userCommitment`, `arrivalNonce`, `anchorPoolHash`).
 */

import { OrderSide, OrderType, CanonicalError } from "./canonical.js";

/** The four execution-policy fields a builder fills on an `OrderCanonical`. */
export interface ExecutionPolicy {
  orderType: OrderType;
  priceLimit: bigint;
  minFillSize: bigint;
  expirySlot: bigint;
}

/** `0` slot = no time expiry (good-till-cancelled). */
const NO_EXPIRY = 0n;

/**
 * A resting limit order. `priceLimit` is the worst price the order accepts
 * (in quote per base, the matcher's unit). `minFillSize` defaults to `0` (any
 * partial fill); set it to `amount` for all-or-none via {@link aonPolicy}.
 */
export function limitPolicy(opts: {
  priceLimit: bigint;
  minFillSize?: bigint;
  expirySlot?: bigint;
}): ExecutionPolicy {
  if (opts.priceLimit <= 0n)
    throw new CanonicalError("limit order needs a positive priceLimit");
  return {
    orderType: OrderType.Limit,
    priceLimit: opts.priceLimit,
    minFillSize: opts.minFillSize ?? 0n,
    expirySlot: opts.expirySlot ?? NO_EXPIRY,
  };
}

/**
 * A market order — `IOC` with a price cap. A bid MUST name `priceCap` (the
 * worst price it will pay, which its collateral note has to cover); an ask
 * leaves `priceLimit = 0` (accept any clearing price). The residual
 * auto-cancels (IOC), so a market order never rests.
 */
export function marketPolicy(opts: {
  side: OrderSide;
  priceCap?: bigint;
}): ExecutionPolicy {
  if (opts.side === OrderSide.Bid) {
    if (opts.priceCap === undefined || opts.priceCap <= 0n) {
      throw new CanonicalError(
        "a market bid needs a positive priceCap (the note must cover it)",
      );
    }
    return {
      orderType: OrderType.Ioc,
      priceLimit: opts.priceCap,
      minFillSize: 0n,
      expirySlot: NO_EXPIRY,
    };
  }
  // Market ask: sell into any clearing price.
  return {
    orderType: OrderType.Ioc,
    priceLimit: 0n,
    minFillSize: 0n,
    expirySlot: NO_EXPIRY,
  };
}

/**
 * All-or-none resting order: a `Limit` with `minFillSize == amount`. It rests
 * (across ticks) until it can fill its full size at `priceLimit` or better.
 */
export function aonPolicy(opts: {
  amount: bigint;
  priceLimit: bigint;
  expirySlot?: bigint;
}): ExecutionPolicy {
  if (opts.amount <= 0n)
    throw new CanonicalError("aon order needs a positive amount");
  return limitPolicy({
    priceLimit: opts.priceLimit,
    minFillSize: opts.amount,
    expirySlot: opts.expirySlot,
  });
}

/**
 * Fill-or-kill: immediate all-or-none. Fills fully in its arrival tick or is
 * dropped — it never rests.
 */
export function fokPolicy(opts: { priceLimit: bigint }): ExecutionPolicy {
  if (opts.priceLimit <= 0n)
    throw new CanonicalError("fok order needs a positive priceLimit");
  return {
    orderType: OrderType.Fok,
    priceLimit: opts.priceLimit,
    minFillSize: 0n,
    expirySlot: NO_EXPIRY,
  };
}

/** Solana's target slot time. Used to project a wall-clock expiry onto a slot. */
export const SLOT_MS = 400;

/**
 * Convert a wall-clock GTT expiry to an `expiry_slot`, anchored on the
 * server's `/time` snapshot (so the client and TEE agree on "now" without the
 * client running its own RPC). `expiry_slot = serverSlot + ceil((expiryUnixMs
 * - serverUnixMs) / slotMs)`. An expiry already in the past throws.
 *
 * @param serverSlot     `slot` from `GET /time`.
 * @param serverUnixMs   `unix_ms` from `GET /time` (the SAME snapshot).
 * @param expiryUnixMs   the wall-clock instant the order should expire.
 * @param slotMs         slot duration; defaults to {@link SLOT_MS}.
 */
export function gttExpirySlot(opts: {
  serverSlot: bigint | number;
  serverUnixMs: bigint | number;
  expiryUnixMs: bigint | number;
  slotMs?: number;
}): bigint {
  const slotMs = opts.slotMs ?? SLOT_MS;
  const serverSlot = BigInt(opts.serverSlot);
  const serverUnixMs = BigInt(opts.serverUnixMs);
  const expiryUnixMs = BigInt(opts.expiryUnixMs);
  const deltaMs = expiryUnixMs - serverUnixMs;
  if (deltaMs <= 0n)
    throw new CanonicalError(
      "GTT expiry is not in the future relative to server time",
    );
  // Round UP so the order lives at least until the requested instant.
  const deltaSlots = (deltaMs + BigInt(slotMs) - 1n) / BigInt(slotMs);
  return serverSlot + deltaSlots;
}

/**
 * GTT over a limit order: a resting limit that auto-expires at `expiryUnixMs`.
 * Convenience over {@link limitPolicy} + {@link gttExpirySlot}.
 */
export function gttLimitPolicy(opts: {
  priceLimit: bigint;
  minFillSize?: bigint;
  serverSlot: bigint | number;
  serverUnixMs: bigint | number;
  expiryUnixMs: bigint | number;
  slotMs?: number;
}): ExecutionPolicy {
  return limitPolicy({
    priceLimit: opts.priceLimit,
    minFillSize: opts.minFillSize,
    expirySlot: gttExpirySlot(opts),
  });
}
