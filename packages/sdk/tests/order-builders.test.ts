/**
 * Order-builder sugar — market / AON / FOK / GTT presets and the GTT
 * wall-clock → expiry_slot conversion. These are pure field presets over
 * `OrderCanonical`; the matcher reads only the four execution fields they set.
 */

import { describe, expect, it } from "vitest";

import {
  limitPolicy,
  marketPolicy,
  aonPolicy,
  fokPolicy,
  gttExpirySlot,
  gttLimitPolicy,
  SLOT_MS,
} from "../src/orders/builders.js";
import {
  OrderSide,
  OrderType,
  CanonicalError,
} from "../src/orders/canonical.js";

describe("order builders — execution-policy presets", () => {
  it("limitPolicy rests at a price with no expiry and any partial fill", () => {
    const p = limitPolicy({ priceLimit: 1_000n });
    expect(p.orderType).toBe(OrderType.Limit);
    expect(p.priceLimit).toBe(1_000n);
    expect(p.minFillSize).toBe(0n);
    expect(p.expirySlot).toBe(0n);
  });

  it("limitPolicy rejects a non-positive price", () => {
    expect(() => limitPolicy({ priceLimit: 0n })).toThrow(CanonicalError);
  });

  it("market bid is IOC capped at priceCap", () => {
    const p = marketPolicy({ side: OrderSide.Bid, priceCap: 2_500n });
    expect(p.orderType).toBe(OrderType.Ioc);
    expect(p.priceLimit).toBe(2_500n);
    expect(p.minFillSize).toBe(0n);
  });

  it("market ask is IOC into any clearing price (priceLimit 0)", () => {
    const p = marketPolicy({ side: OrderSide.Ask });
    expect(p.orderType).toBe(OrderType.Ioc);
    expect(p.priceLimit).toBe(0n);
  });

  it("market bid without a priceCap is rejected (the note must cover it)", () => {
    expect(() => marketPolicy({ side: OrderSide.Bid })).toThrow(CanonicalError);
    expect(() => marketPolicy({ side: OrderSide.Bid, priceCap: 0n })).toThrow(
      CanonicalError,
    );
  });

  it("aonPolicy is a resting limit with minFillSize == amount", () => {
    const p = aonPolicy({ amount: 50n, priceLimit: 10n });
    expect(p.orderType).toBe(OrderType.Limit);
    expect(p.minFillSize).toBe(50n);
    expect(p.priceLimit).toBe(10n);
  });

  it("fokPolicy is immediate all-or-none", () => {
    const p = fokPolicy({ priceLimit: 7n });
    expect(p.orderType).toBe(OrderType.Fok);
    expect(p.minFillSize).toBe(0n);
  });
});

describe("GTT — wall-clock to expiry_slot", () => {
  it("projects a future instant onto a slot, rounding up", () => {
    // 1 second out at 400ms/slot = 2.5 slots → rounds up to 3.
    const slot = gttExpirySlot({
      serverSlot: 1000,
      serverUnixMs: 1_000_000,
      expiryUnixMs: 1_001_000,
    });
    expect(slot).toBe(1003n);
  });

  it("uses the provided slot duration", () => {
    const slot = gttExpirySlot({
      serverSlot: 0,
      serverUnixMs: 0,
      expiryUnixMs: 5_000,
      slotMs: 500,
    });
    expect(slot).toBe(10n);
  });

  it("default slot duration is Solana's target", () => {
    expect(SLOT_MS).toBe(400);
  });

  it("rejects an expiry that is not in the future", () => {
    expect(() =>
      gttExpirySlot({
        serverSlot: 10,
        serverUnixMs: 1_000,
        expiryUnixMs: 1_000,
      }),
    ).toThrow(CanonicalError);
    expect(() =>
      gttExpirySlot({ serverSlot: 10, serverUnixMs: 1_000, expiryUnixMs: 999 }),
    ).toThrow(CanonicalError);
  });

  it("gttLimitPolicy folds the conversion into a resting limit", () => {
    const p = gttLimitPolicy({
      priceLimit: 42n,
      serverSlot: 1000,
      serverUnixMs: 1_000_000,
      expiryUnixMs: 1_002_000, // 2s → 5 slots
    });
    expect(p.orderType).toBe(OrderType.Limit);
    expect(p.priceLimit).toBe(42n);
    expect(p.expirySlot).toBe(1005n);
  });
});
