/**
 * Canonical byte encoding of an order intent for signing.
 *
 * The trading-key signature in `POST /orders` is computed over
 * `sha256(orderCanonicalBytes(...))`. The bytes are fully fixed-length
 * per field so that re-encoding from JSON / any wire form produces
 * the same digest — no canonicalisation attacks via field-reordering,
 * whitespace, or leading-zero ambiguity.
 *
 * Cross-language byte equality with the Rust encoder in
 * `crates/darkpool-matcher/src/order_canonical.rs` is pinned by
 * `packages/sdk/tests/order-canonical-parity.test.ts`. The pinned
 * fixture digests in BOTH files MUST stay in lockstep.
 *
 * Wire spec: `docs/tee-architecture.md` §11.2.
 */

import { createHash } from "node:crypto";

export const ORDER_DOMAIN: Uint8Array = new TextEncoder().encode("nyx-order-v2");
export const CANCEL_DOMAIN: Uint8Array = new TextEncoder().encode("nyx-cancel-v1");
export const SYMBOL_MAX_LEN = 32;

/** Fixed number of continuation anchors a client supplies per order.
 *  Mirrors `darkpool_matcher::order_canonical::ANCHOR_POOL_SIZE`. */
export const ANCHOR_POOL_SIZE = 10;
/** Anchors added per WebSocket top-up when a pool drains. */
export const ANCHOR_TOPUP_SIZE = 5;

/** One continuation anchor: the (inner_hash, nullifier) pair for one
 *  future change note. Both 32-byte BE field elements. */
export interface Anchor {
  innerHash: Uint8Array;
  nullifier: Uint8Array;
}

/** SHA-256 over the ordered anchor pool: for each anchor,
 *  innerHash ‖ nullifier. Mirrors `anchor_pool_hash` in the Rust matcher. */
export function anchorPoolHash(anchors: Anchor[]): Uint8Array {
  const h = createHash("sha256");
  for (const a of anchors) {
    if (a.innerHash.length !== 32) throw new CanonicalError("anchor.innerHash must be 32 bytes");
    if (a.nullifier.length !== 32) throw new CanonicalError("anchor.nullifier must be 32 bytes");
    h.update(Buffer.from(a.innerHash));
    h.update(Buffer.from(a.nullifier));
  }
  return new Uint8Array(h.digest());
}

/**
 * `OrderSide` byte discriminants. Wire bytes are `0` (bid) / `1` (ask)
 * — matches `crates/darkpool-matcher::book::OrderSide`'s `#[repr(u8)]`.
 */
export enum OrderSide {
  Bid = 0,
  Ask = 1,
}

/**
 * `OrderType` byte discriminants. Wire bytes are `0` (limit), `1`
 * (ioc), `2` (fok) — matches `crates/darkpool-matcher::book::OrderType`.
 */
export enum OrderType {
  Limit = 0,
  Ioc = 1,
  Fok = 2,
}

export interface OrderCanonical {
  /** ASCII bytes, length ≤ SYMBOL_MAX_LEN. */
  symbol: Uint8Array;
  side: OrderSide;
  orderType: OrderType;
  amount: bigint;
  /** 0 for market orders. */
  priceLimit: bigint;
  /** 0 = any partial fill allowed. */
  minFillSize: bigint;
  expirySlot: bigint;
  /** 16 bytes. */
  orderId: Uint8Array;
  /** 32 bytes. */
  noteCommitment: Uint8Array;
  /** 32 bytes. */
  userCommitment: Uint8Array;
  arrivalNonce: bigint;
  /** 32 bytes — SHA-256 over the order's anchor pool (see `anchorPoolHash`). */
  anchorPoolHash: Uint8Array;
}

export interface CancelCanonical {
  /** 16 bytes — the order being cancelled. */
  orderId: Uint8Array;
  /** 32 bytes — must match the order's trading key. */
  tradingKey: Uint8Array;
  cancelNonce: bigint;
}

export class CanonicalError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CanonicalError";
  }
}

function u64LE(v: bigint): Uint8Array {
  if (v < 0n || v > 0xffff_ffff_ffff_ffffn) {
    throw new CanonicalError(`u64 out of range: ${v}`);
  }
  const buf = new Uint8Array(8);
  const dv = new DataView(buf.buffer);
  dv.setBigUint64(0, v, /* littleEndian */ true);
  return buf;
}

function concat(parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/**
 * Serialise to the canonical byte layout. Layout (offsets running;
 * `S` = symbol bytes length):
 *
 * ```
 *   0..12        ORDER_DOMAIN              ("nyx-order-v1")
 *   12..13       symbol_len : u8
 *   13..13+S     symbol bytes
 *   +0..+1       side       : u8           (0 = bid, 1 = ask)
 *   +1..+2       order_type : u8           (0 = limit, 1 = ioc, 2 = fok)
 *   +2..+10      amount        : u64 LE
 *   +10..+18     price_limit   : u64 LE
 *   +18..+26     min_fill_size : u64 LE
 *   +26..+34     expiry_slot   : u64 LE
 *   +34..+50     order_id        : [u8; 16]
 *   +50..+82     note_commitment : [u8; 32]
 *   +82..+114    user_commitment : [u8; 32]
 *   +114..+122   arrival_nonce : u64 LE
 *   +122..+154   anchor_pool_hash : [u8; 32]
 * ```
 *
 * Total length: `167 + S` bytes.
 */
export function orderCanonicalBytes(o: OrderCanonical): Uint8Array {
  if (o.symbol.length > SYMBOL_MAX_LEN) {
    throw new CanonicalError(
      `symbol length ${o.symbol.length} exceeds SYMBOL_MAX_LEN (${SYMBOL_MAX_LEN})`,
    );
  }
  if (o.orderId.length !== 16) {
    throw new CanonicalError(`orderId must be 16 bytes; got ${o.orderId.length}`);
  }
  if (o.noteCommitment.length !== 32) {
    throw new CanonicalError(
      `noteCommitment must be 32 bytes; got ${o.noteCommitment.length}`,
    );
  }
  if (o.userCommitment.length !== 32) {
    throw new CanonicalError(
      `userCommitment must be 32 bytes; got ${o.userCommitment.length}`,
    );
  }
  if (o.anchorPoolHash.length !== 32) {
    throw new CanonicalError(
      `anchorPoolHash must be 32 bytes; got ${o.anchorPoolHash.length}`,
    );
  }

  return concat([
    ORDER_DOMAIN,
    new Uint8Array([o.symbol.length]),
    o.symbol,
    new Uint8Array([o.side]),
    new Uint8Array([o.orderType]),
    u64LE(o.amount),
    u64LE(o.priceLimit),
    u64LE(o.minFillSize),
    u64LE(o.expirySlot),
    o.orderId,
    o.noteCommitment,
    o.userCommitment,
    u64LE(o.arrivalNonce),
    o.anchorPoolHash,
  ]);
}

/** SHA-256 over `orderCanonicalBytes` — the message the trading-key signature is over. */
export function orderCanonicalDigest(o: OrderCanonical): Uint8Array {
  return new Uint8Array(createHash("sha256").update(orderCanonicalBytes(o)).digest());
}

/**
 * Cancel-order canonical view. Layout:
 *
 * ```
 *   0..13       CANCEL_DOMAIN  ("nyx-cancel-v1")
 *   13..29      order_id      : [u8; 16]
 *   29..61      trading_key   : [u8; 32]
 *   61..69      cancel_nonce  : u64 LE
 * ```
 */
export function cancelCanonicalBytes(c: CancelCanonical): Uint8Array {
  if (c.orderId.length !== 16) {
    throw new CanonicalError(`orderId must be 16 bytes; got ${c.orderId.length}`);
  }
  if (c.tradingKey.length !== 32) {
    throw new CanonicalError(`tradingKey must be 32 bytes; got ${c.tradingKey.length}`);
  }
  return concat([CANCEL_DOMAIN, c.orderId, c.tradingKey, u64LE(c.cancelNonce)]);
}

export function cancelCanonicalDigest(c: CancelCanonical): Uint8Array {
  return new Uint8Array(createHash("sha256").update(cancelCanonicalBytes(c)).digest());
}
