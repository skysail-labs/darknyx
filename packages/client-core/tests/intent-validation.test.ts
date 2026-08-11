import { describe, expect, it } from "vitest";

import { readyProofHandle, reservationId } from "../src/internal.js";
import {
  validateIntentDraft,
  type JsonValue,
  type TraderIntentDraft,
} from "../src/index.js";

const valid: TraderIntentDraft = {
  protocolVersion: 1,
  marketSymbol: "SOL-USDC",
  side: "ask",
  baseAmountAtoms: "1",
  limitPriceTicks: "0",
  attributes: {
    nested_future_attribute: { mode: "all_or_none", levels: [1, 2, 3] },
  },
};

describe("validateIntentDraft", () => {
  it("preserves unknown versioned attributes in an immutable null-prototype copy", () => {
    const normalized = validateIntentDraft(valid);
    expect(normalized.attributes).toEqual(valid.attributes);
    expect(Object.getPrototypeOf(normalized.attributes)).toBeNull();
    expect(Object.isFrozen(normalized)).toBe(true);
    expect(Object.isFrozen(normalized.attributes)).toBe(true);
    const nested = normalized.attributes.nested_future_attribute;
    expect(typeof nested === "object" && nested !== null).toBe(true);
    if (typeof nested === "object" && nested !== null && !Array.isArray(nested)) {
      expect(Object.isFrozen(nested)).toBe(true);
      const nestedRecord = nested as Readonly<Record<string, JsonValue>>;
      expect(Object.isFrozen(nestedRecord.levels)).toBe(true);
    }
  });

  it.each([
    ["non-canonical amount", "baseAmountAtoms", { baseAmountAtoms: "01" }],
    ["zero amount", "baseAmountAtoms", { baseAmountAtoms: "0" }],
    ["overflow", "baseAmountAtoms", { baseAmountAtoms: "18446744073709551616" }],
    ["fractional ticks", "limitPriceTicks", { limitPriceTicks: "1.5" }],
    ["lowercase symbol", "marketSymbol", { marketSymbol: "sol-USDC" }],
    ["invalid version", "protocolVersion", { protocolVersion: 0 }],
  ])("rejects %s", (_label, field, override) => {
    expect(() => validateIntentDraft({ ...valid, ...override })).toThrow(
      `invalid intent field: ${field}`,
    );
  });

  it("accepts the inclusive u64 maximum", () => {
    expect(
      validateIntentDraft({
        ...valid,
        baseAmountAtoms: "18446744073709551615",
        limitPriceTicks: "18446744073709551615",
      }),
    ).toMatchObject({
      baseAmountAtoms: "18446744073709551615",
      limitPriceTicks: "18446744073709551615",
    });
  });

  it("rejects prototype-pollution keys", () => {
    for (const key of ["__proto__", "constructor", "prototype"]) {
      const attributes = JSON.parse(`{"${key}":{"polluted":true}}`) as Record<
        string,
        never
      >;
      expect(() => validateIntentDraft({ ...valid, attributes })).toThrow(
        `invalid intent field: attributes.${key}`,
      );
    }
    expect(() =>
      validateIntentDraft({
        ...valid,
        attributes: new (class Attributes {})() as Record<string, never>,
      }),
    ).toThrow("invalid intent field: attributes");
  });

  it("enforces the documented attribute-depth boundary", () => {
    const nested = (levels: number): Record<string, JsonValue> => {
      let value: Record<string, JsonValue> = { value: true };
      for (let index = 0; index < levels; index += 1) value = { next: value };
      return value;
    };
    expect(() =>
      validateIntentDraft({ ...valid, attributes: nested(7) }),
    ).not.toThrow();
    expect(() =>
      validateIntentDraft({ ...valid, attributes: nested(8) }),
    ).toThrow(/attributes\.next/);
  });

  it("rejects non-finite and overlarge attribute payloads", () => {
    expect(() =>
      validateIntentDraft({ ...valid, attributes: { value: Number.NaN } }),
    ).toThrow(/attributes\.value/);
    expect(() =>
      validateIntentDraft({
        ...valid,
        attributes: { value: "x".repeat(4_100) },
      }),
    ).toThrow(/attributes/);
  });

  it("constructs only bounded opaque internal handles", () => {
    expect(reservationId("reservation:1")).toBe("reservation:1");
    expect(readyProofHandle("proof_1")).toBe("proof_1");
    expect(reservationId("r".repeat(128))).toBe("r".repeat(128));
    expect(readyProofHandle("p".repeat(128))).toBe("p".repeat(128));
    expect(() => reservationId("../reservation")).toThrow(/reservation ID/);
    expect(() => readyProofHandle("x".repeat(129))).toThrow(/proof handle/);
  });
});
