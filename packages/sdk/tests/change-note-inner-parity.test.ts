/**
 * Cross-language KAT for the v2 change-note `derive_inner`.
 *
 * The TS helper (`e2e-helpers.ts::deriveInner`) must produce the same bytes
 * as `darkpool_matcher::change_note::derive_inner` (the matcher port) and the
 * on-chain `hashv` reference — both pinned by
 * `crates/darkpool-matcher/tests/change_note_parity.rs` against the same spec:
 *
 *   SHA-256("nyx-change-inner" ‖ match_id_le_u64 ‖ role) then d[0]=0, d[1]&=0x0f
 *
 * The expected hex below was computed independently of the TS code
 * (`printf ... | shasum -a 256`, then the mask applied), so this test pins the
 * TS port to the spec — and transitively to the Rust ports.
 */

import { describe, expect, it } from "vitest";

import { deriveInner, CHANGE_ROLE_BUYER, TRADE_ROLE_BUYER } from "./helpers/e2e-helpers.js";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

describe("derive_inner — cross-language KAT", () => {
  it("matches the independently-computed spec value for (42, CHANGE_ROLE_BUYER)", () => {
    // raw sha256 = 0233e743...286b; mask → byte0=0x00, byte1=0x33&0x0f=0x03.
    const expected = "0003e743eb441d6b6f5363d7ad169cf3b8dd6621303ed9d47cb14ddf05de286b";
    expect(hex(deriveInner(42n, CHANGE_ROLE_BUYER))).toBe(expected);
  });

  it("is Fr-safe (byte0 == 0, byte1 high nibble == 0) + deterministic", () => {
    for (const [mid, role] of [
      [0n, CHANGE_ROLE_BUYER],
      [42n, TRADE_ROLE_BUYER],
      [18446744073709551615n, CHANGE_ROLE_BUYER],
    ] as const) {
      const a = deriveInner(mid, role);
      expect(a[0]).toBe(0);
      expect(a[1] & 0xf0).toBe(0);
      expect(hex(deriveInner(mid, role))).toBe(hex(a)); // deterministic
    }
  });

  it("distinguishes role + match_id", () => {
    expect(hex(deriveInner(42n, CHANGE_ROLE_BUYER))).not.toBe(hex(deriveInner(42n, TRADE_ROLE_BUYER)));
    expect(hex(deriveInner(42n, CHANGE_ROLE_BUYER))).not.toBe(hex(deriveInner(43n, CHANGE_ROLE_BUYER)));
  });
});
