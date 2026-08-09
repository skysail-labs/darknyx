import { describe, expect, it } from "vitest";

import { readyProofHandle, reservationId } from "../src/internal.js";
import { validateIntentDraft, type TraderIntentDraft } from "../src/index.js";

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
  });

  it.each([
    ["non-canonical amount", { baseAmountAtoms: "01" }],
    ["zero amount", { baseAmountAtoms: "0" }],
    ["overflow", { baseAmountAtoms: "18446744073709551616" }],
    ["fractional ticks", { limitPriceTicks: "1.5" }],
    ["lowercase symbol", { marketSymbol: "sol-USDC" }],
    ["invalid version", { protocolVersion: 0 }],
  ])("rejects %s", (_label, override) => {
    expect(() => validateIntentDraft({ ...valid, ...override })).toThrow(
      /invalid intent field/,
    );
  });

  it("rejects prototype-pollution keys", () => {
    const attributes = JSON.parse('{"__proto__":{"polluted":true}}') as Record<
      string,
      never
    >;
    expect(() => validateIntentDraft({ ...valid, attributes })).toThrow(
      /attributes\.__proto__/,
    );
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
    expect(() => reservationId("../reservation")).toThrow(/reservation ID/);
    expect(() => readyProofHandle("x".repeat(129))).toThrow(/proof handle/);
  });
});
