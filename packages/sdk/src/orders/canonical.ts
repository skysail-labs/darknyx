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

export const ORDER_DOMAIN: Uint8Array = new TextEncoder().encode(
  "darknyx-order-v4",
);
export const CANCEL_DOMAIN: Uint8Array = new TextEncoder().encode(
  "darknyx-cancel-v2",
);
export const SYMBOL_MAX_LEN = 32;

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
  /** 32-byte X25519 viewing-encryption public key. */
  viewingPubkey: Uint8Array;
  /** 32-byte boot session id advertised by `/info`. */
  sessionId: Uint8Array;
}

export interface CancelCanonical {
  /** 16 bytes — the order being cancelled. */
  orderId: Uint8Array;
  /** 32 bytes — must match the order's trading key. */
  tradingKey: Uint8Array;
  cancelNonce: bigint;
  /**
   * 32 bytes — the CVM boot session this cancel is scoped to (S-07).
   *
   * Without it a captured cancel signature stayed valid forever, in any boot
   * session. Since `order_id`s are deterministic HD values clients re-derive
   * by design, a stored cancel body could kill a legitimately re-placed order
   * after a restart, and anyone who ever handled that body kept the ability
   * indefinitely.
   */
  sessionId: Uint8Array;
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
 *   0..16        ORDER_DOMAIN              ("darknyx-order-v4")
 *   16..17       symbol_len : u8
 *   17..17+S     symbol bytes
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
 *   +122..+154   viewing_pubkey : [u8; 32]
 *   +154..+186   session_id : [u8; 32]
 * ```
 *
 * Total length: `203 + S` bytes.
 */
export function orderCanonicalBytes(o: OrderCanonical): Uint8Array {
  if (o.symbol.length > SYMBOL_MAX_LEN) {
    throw new CanonicalError(
      `symbol length ${o.symbol.length} exceeds SYMBOL_MAX_LEN (${SYMBOL_MAX_LEN})`,
    );
  }
  if (o.orderId.length !== 16) {
    throw new CanonicalError(
      `orderId must be 16 bytes; got ${o.orderId.length}`,
    );
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
  if (o.viewingPubkey.length !== 32) {
    throw new CanonicalError(
      `viewingPubkey must be 32 bytes; got ${o.viewingPubkey.length}`,
    );
  }
  if (o.sessionId.length !== 32) {
    throw new CanonicalError(
      `sessionId must be 32 bytes; got ${o.sessionId.length}`,
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
    o.viewingPubkey,
    o.sessionId,
  ]);
}

/** SHA-256 over `orderCanonicalBytes` — the message the trading-key signature is over. */
export function orderCanonicalDigest(o: OrderCanonical): Uint8Array {
  return new Uint8Array(
    createHash("sha256").update(orderCanonicalBytes(o)).digest(),
  );
}

/**
 * Cancel-order canonical view. Layout:
 *
 * ```
 *   0..17       CANCEL_DOMAIN  ("darknyx-cancel-v2")
 *   17..33      order_id      : [u8; 16]
 *   33..65      trading_key   : [u8; 32]
 *   65..73      cancel_nonce  : u64 LE
 *   73..105     session_id    : [u8; 32]
 * ```
 */
export function cancelCanonicalBytes(c: CancelCanonical): Uint8Array {
  if (c.orderId.length !== 16) {
    throw new CanonicalError(
      `orderId must be 16 bytes; got ${c.orderId.length}`,
    );
  }
  if (c.tradingKey.length !== 32) {
    throw new CanonicalError(
      `tradingKey must be 32 bytes; got ${c.tradingKey.length}`,
    );
  }
  if (c.sessionId.length !== 32) {
    throw new CanonicalError(
      `sessionId must be 32 bytes; got ${c.sessionId.length}`,
    );
  }
  return concat([
    CANCEL_DOMAIN,
    c.orderId,
    c.tradingKey,
    u64LE(c.cancelNonce),
    c.sessionId,
  ]);
}

export function cancelCanonicalDigest(c: CancelCanonical): Uint8Array {
  return new Uint8Array(
    createHash("sha256").update(cancelCanonicalBytes(c)).digest(),
  );
}
