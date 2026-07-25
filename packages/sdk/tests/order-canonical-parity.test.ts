/**
 * Byte-equality contract between the TS canonical encoder
 * (`packages/sdk/src/orders/canonical.ts`) and the Rust canonical
 * encoder (`crates/darkpool-matcher/src/order_canonical.rs`).
 *
 * The pinned hex digests in this file MUST stay byte-identical with
 * `FIXTURE_DIGEST_HEX` + `CANCEL_FIXTURE_DIGEST_HEX` in the Rust
 * test module. Changing the layout requires updating BOTH this file
 * AND `order_canonical.rs` in the same commit.
 *
 * See CLAUDE.md §6 ("Cross-language byte-equality contracts") for
 * the rule.
 */

import { Buffer } from "node:buffer";
import { describe, expect, test } from "vitest";

import {
  CANCEL_DOMAIN,
  CanonicalError,
  ORDER_DOMAIN,
  OrderSide,
  OrderType,
  SYMBOL_MAX_LEN,
  cancelCanonicalBytes,
  cancelCanonicalDigest,
  orderCanonicalBytes,
  orderCanonicalDigest,
  type CancelCanonical,
  type OrderCanonical,
} from "../src/orders/canonical.js";

// ─── Pinned hex digests — must match the Rust constants ─────────────────────

const FIXTURE_DIGEST_HEX =
  "7a47d4c4dd854c36f394bfa3b6694f5c9b57b0e33da01cbda7c766cb6c757906";

const CANCEL_FIXTURE_DIGEST_HEX =
  "3063a2f1f4a0f71aed1587ca7bd55dd82b78d0b9148e7ac08bbec25b20298f2c";

// ─── Fixtures — same numeric inputs as the Rust `fixture()` fn ──────────────

function fixture(): OrderCanonical {
  return {
    symbol: new TextEncoder().encode("SOL-USDC"),
    side: OrderSide.Bid,
    orderType: OrderType.Limit,
    amount: 10_000_000n,
    priceLimit: 150_000_000n,
    minFillSize: 1_000_000n,
    expirySlot: 320_145_000n,
    orderId: new Uint8Array(16).fill(0x11),
    noteCommitment: new Uint8Array(32).fill(0x22),
    userCommitment: new Uint8Array(32).fill(0x33),
    arrivalNonce: 42n,
    viewingPubkey: new Uint8Array(32).fill(0x44),
    sessionId: new Uint8Array(32).fill(0x66),
  };
}

function cancelFixture(): CancelCanonical {
  return {
    orderId: new Uint8Array(16).fill(0x11),
    tradingKey: new Uint8Array(32).fill(0x55),
    cancelNonce: 7n,
    sessionId: new Uint8Array(32).fill(0x66),
  };
}

const toHex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

// ─── Tests ──────────────────────────────────────────────────────────────────

describe("order canonical encoder — Rust parity", () => {
  test("fixture digest matches the pinned hex from order_canonical.rs", () => {
    const actual = toHex(orderCanonicalDigest(fixture()));
    expect(actual).toBe(FIXTURE_DIGEST_HEX);
  });

  test("fixture byte length is 203 + symbol.length", () => {
    const bytes = orderCanonicalBytes(fixture());
    expect(bytes.length).toBe(203 + "SOL-USDC".length);
  });

  test("each field perturbation changes the digest", () => {
    const base = toHex(orderCanonicalDigest(fixture()));

    const perturb = (f: (o: OrderCanonical) => void, label: string): void => {
      const v = fixture();
      f(v);
      expect(toHex(orderCanonicalDigest(v))).not.toBe(base);
      // Use the label so failures point at the perturbed field.
      void label;
    };

    perturb((o) => (o.symbol = new TextEncoder().encode("SOL-USDT")), "symbol");
    perturb((o) => (o.side = OrderSide.Ask), "side");
    perturb((o) => (o.orderType = OrderType.Ioc), "orderType");
    perturb((o) => (o.amount = 10_000_001n), "amount");
    perturb((o) => (o.priceLimit = 150_000_001n), "priceLimit");
    perturb((o) => (o.minFillSize = 1_000_001n), "minFillSize");
    perturb((o) => (o.expirySlot = 320_145_001n), "expirySlot");
    perturb((o) => (o.orderId = new Uint8Array(16).fill(0x12)), "orderId");
    perturb(
      (o) => (o.noteCommitment = new Uint8Array(32).fill(0x23)),
      "noteCommitment",
    );
    perturb(
      (o) => (o.userCommitment = new Uint8Array(32).fill(0x34)),
      "userCommitment",
    );
    perturb((o) => (o.arrivalNonce = 43n), "arrivalNonce");
    perturb(
      (o) => (o.viewingPubkey = new Uint8Array(32).fill(0x45)),
      "viewingPubkey",
    );
    perturb((o) => (o.sessionId = new Uint8Array(32).fill(0x67)), "sessionId");
  });

  test("symbol over SYMBOL_MAX_LEN is rejected", () => {
    const v = fixture();
    v.symbol = new Uint8Array(SYMBOL_MAX_LEN + 1).fill(0x58);
    expect(() => orderCanonicalBytes(v)).toThrow(CanonicalError);
  });

  test("empty symbol is allowed and distinct from non-empty", () => {
    const withSymbol = toHex(orderCanonicalDigest(fixture()));
    const empty = fixture();
    empty.symbol = new Uint8Array();
    const withoutSymbol = toHex(orderCanonicalDigest(empty));
    expect(withSymbol).not.toBe(withoutSymbol);
  });

  test("wrong-width orderId / noteCommitment / userCommitment rejected", () => {
    const o1 = { ...fixture(), orderId: new Uint8Array(15) };
    expect(() => orderCanonicalBytes(o1)).toThrow(/orderId must be 16 bytes/);

    const o2 = { ...fixture(), noteCommitment: new Uint8Array(31) };
    expect(() => orderCanonicalBytes(o2)).toThrow(
      /noteCommitment must be 32 bytes/,
    );

    const o3 = { ...fixture(), userCommitment: new Uint8Array(33) };
    expect(() => orderCanonicalBytes(o3)).toThrow(
      /userCommitment must be 32 bytes/,
    );

    const o4 = { ...fixture(), viewingPubkey: new Uint8Array(31) };
    expect(() => orderCanonicalBytes(o4)).toThrow(
      /viewingPubkey must be 32 bytes/,
    );
    const o5 = { ...fixture(), sessionId: new Uint8Array(33) };
    expect(() => orderCanonicalBytes(o5)).toThrow(/sessionId must be 32 bytes/);
  });

  test("domain tag is the first 12 bytes", () => {
    const bytes = orderCanonicalBytes(fixture());
    expect(bytes.slice(0, ORDER_DOMAIN.length)).toEqual(ORDER_DOMAIN);
  });
});

describe("cancel canonical encoder — Rust parity", () => {
  test("fixture digest matches the pinned hex from order_canonical.rs", () => {
    const actual = toHex(cancelCanonicalDigest(cancelFixture()));
    expect(actual).toBe(CANCEL_FIXTURE_DIGEST_HEX);
  });

  test("domain tag is the first 13 bytes", () => {
    const bytes = cancelCanonicalBytes(cancelFixture());
    expect(bytes.slice(0, CANCEL_DOMAIN.length)).toEqual(CANCEL_DOMAIN);
  });

  test("order + cancel with same order_id produce different digests", () => {
    const order = fixture();
    const cancel: CancelCanonical = {
      orderId: order.orderId,
      tradingKey: new Uint8Array(32),
      cancelNonce: 0n,
      sessionId: new Uint8Array(32),
    };
    expect(toHex(orderCanonicalDigest(order))).not.toBe(
      toHex(cancelCanonicalDigest(cancel)),
    );
  });

  test("wrong-width orderId / tradingKey rejected", () => {
    const c1 = { ...cancelFixture(), orderId: new Uint8Array(8) };
    expect(() => cancelCanonicalBytes(c1)).toThrow(/orderId must be 16 bytes/);

    const c2 = { ...cancelFixture(), tradingKey: new Uint8Array(31) };
    expect(() => cancelCanonicalBytes(c2)).toThrow(
      /tradingKey must be 32 bytes/,
    );
  });
});
