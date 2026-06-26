/**
 * CVM API/WS surface coverage — the first AUTOMATED check of the 5-phase
 * hardening (error envelope + x-request-id, system endpoints, rate limiting,
 * account view + settings, the WS seq stamp, and the /ws/trading send-client)
 * against a LIVE enclave. Everything before this was hit by hand with curl.
 *
 * These assertions are deliberately CHEAP — no on-chain deposit / proof — so the
 * test runs in seconds and exercises the surface, not the settle pipeline. The
 * order-dependent bits (min_notional on a real order, POST /orders idempotency,
 * WS seq on /ws/orders + /ws/fills, account-default cancel-on-disconnect) need a
 * real note + proof and are covered by cvm-settle-e2e / cvm-merge-then-order.
 *
 * Gate: RUN_CVM_E2E=1 + NYX_TEE_GATEWAY. Run:
 *   RUN_CVM_E2E=1 NYX_TEE_GATEWAY=$GW \
 *     ( cd packages/sdk && ../../node_modules/.bin/vitest run --project cvm tests/cvm-api-surface.test.ts )
 */
import { beforeAll, describe, expect, it } from "vitest";

import { gwFetch, authToken } from "./helpers/cvm-harness.js";

const GATEWAY = (process.env.NYX_TEE_GATEWAY ?? "").replace(/\/$/, "");
const READY = process.env.RUN_CVM_E2E === "1" && GATEWAY !== "";
const maybeDescribe = READY ? describe : describe.skip;

/** Parse a JSON body, tolerating a non-JSON error body. */
async function json(res: Response): Promise<Record<string, unknown>> {
  try {
    return (await res.json()) as Record<string, unknown>;
  } catch {
    return {};
  }
}

maybeDescribe("CVM API/WS surface (Phase 1–5 hardening)", () => {
  let token: string;

  beforeAll(async () => {
    token = await authToken(GATEWAY);
  });

  /** A COMPLETE, serde-valid PlaceOrderRequest (so it passes axum's JSON
   *  extraction and reaches the handler), with one deliberately bad field via
   *  `overrides` to trigger an `ApiError` (the {code,message} envelope) rather
   *  than axum's default extraction rejection. */
  function dummyOrderBody(overrides: Record<string, unknown> = {}) {
    const z32 = "00".repeat(32);
    return {
      symbol: "SOL-USDC",
      side: "bid",
      order_type: "limit",
      amount: 1,
      price_limit: 1,
      min_fill_size: 0,
      expiry_slot: 1,
      order_id: "0102030405060708090a0b0c0d0e0f10",
      note_commitment: z32,
      user_commitment: z32,
      arrival_nonce: 1,
      trading_key: z32,
      trading_key_signature: "00".repeat(64),
      owner_commitment: z32,
      note_inner_hash: z32,
      nullifier: z32,
      merkle_root: z32,
      valid_input_proof: "00".repeat(256),
      anchors: Array.from({ length: 10 }, () => ({
        inner_hash: z32,
        nullifier: z32,
      })),
      ...overrides,
    };
  }

  it("error envelope: a handler-rejected POST /orders → {code,message} + x-request-id", async () => {
    const res = await gwFetch(`${GATEWAY}/orders`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
      },
      // Complete body, but valid_input_proof is the wrong length → the handler's
      // decode_hex rejects it with a numeric code (after serde extraction).
      body: JSON.stringify(dummyOrderBody({ valid_input_proof: "00" })),
    });
    expect(res.status, "bad order should be a 4xx").toBeGreaterThanOrEqual(400);
    expect(res.status).toBeLessThan(500);
    expect(
      res.headers.get("x-request-id"),
      "every response must carry x-request-id",
    ).toBeTruthy();
    const body = await json(res);
    expect(typeof body.code, "error body has a numeric code").toBe("number");
    expect(
      body.code,
      "validation codes are in the 1000s",
    ).toBeGreaterThanOrEqual(1000);
    expect(typeof body.message).toBe("string");
  });

  it("x-request-id is stamped on a SUCCESS response too", async () => {
    const res = await gwFetch(`${GATEWAY}/system/status`);
    expect(res.status).toBe(200);
    expect(res.headers.get("x-request-id")).toBeTruthy();
  });

  it("GET /system/status returns the liveness snapshot", async () => {
    const res = await gwFetch(`${GATEWAY}/system/status`);
    expect(res.status).toBe(200);
    const b = await json(res);
    for (const k of [
      "degraded",
      "matcher_running",
      "settle_enabled",
      "oracle_configured",
    ]) {
      expect(typeof b[k], `status.${k} is a bool`).toBe("boolean");
    }
    expect(typeof b.current_slot).toBe("number");
    expect(typeof b.nyx_version).toBe("string");
  });

  it("GET /time returns slot + unix_ms", async () => {
    const res = await gwFetch(`${GATEWAY}/time`);
    expect(res.status).toBe(200);
    const b = await json(res);
    expect(typeof b.slot).toBe("number");
    expect(typeof b.unix_ms).toBe("number");
    expect(b.unix_ms as number).toBeGreaterThan(1_700_000_000_000);
  });

  it("auth required: POST /orders and GET /account without a bearer → 1101", async () => {
    for (const [path, init] of [
      [
        "/orders",
        {
          method: "POST",
          body: "{}",
          headers: { "content-type": "application/json" },
        },
      ],
      ["/account", {}],
    ] as const) {
      const res = await gwFetch(`${GATEWAY}${path}`, init);
      expect(res.status, `${path} unauthenticated → 401`).toBe(401);
      const b = await json(res);
      expect(b.code, `${path} → unauthorized code 1101`).toBe(1101);
    }
  });

  it("GET /account returns the caller's open_orders array", async () => {
    const res = await gwFetch(`${GATEWAY}/account`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(200);
    const b = await json(res);
    expect(Array.isArray(b.open_orders), "open_orders is an array").toBe(true);
    // Balances are intentionally NOT returned (client-derived — the TEE has no
    // spending key).
    expect(b.balances).toBeUndefined();
  });

  it("GET/PUT /account/settings round-trips cancel_on_disconnect_default", async () => {
    const auth = { authorization: `Bearer ${token}` };
    const before = await json(
      await gwFetch(`${GATEWAY}/account/settings`, { headers: auth }),
    );
    const original = Boolean(before.cancel_on_disconnect_default);

    const putRes = await gwFetch(`${GATEWAY}/account/settings`, {
      method: "PUT",
      headers: { ...auth, "content-type": "application/json" },
      body: JSON.stringify({ cancel_on_disconnect_default: !original }),
    });
    expect(putRes.status).toBe(200);
    expect((await json(putRes)).cancel_on_disconnect_default).toBe(!original);

    const after = await json(
      await gwFetch(`${GATEWAY}/account/settings`, { headers: auth }),
    );
    expect(
      after.cancel_on_disconnect_default,
      "the toggled setting persisted",
    ).toBe(!original);

    // Restore the original so re-runs (and other tests) start from the same state.
    await gwFetch(`${GATEWAY}/account/settings`, {
      method: "PUT",
      headers: { ...auth, "content-type": "application/json" },
      body: JSON.stringify({ cancel_on_disconnect_default: original }),
    });
  });

  it("/ws/trading: ping → pong echoes request_id and carries a numeric seq", async () => {
    const wsUrl = `${GATEWAY.replace(/^http/, "ws")}/ws/trading?token=${encodeURIComponent(token)}`;
    const ws = new WebSocket(wsUrl);
    const requestId = `ping-${Date.now()}`;

    const frame = await new Promise<Record<string, unknown>>(
      (resolve, reject) => {
        const timer = setTimeout(
          () => reject(new Error("no pong within 15s")),
          15_000,
        );
        ws.addEventListener("open", () => {
          ws.send(JSON.stringify({ op: "ping", request_id: requestId }));
        });
        ws.addEventListener("message", (ev) => {
          try {
            const msg = JSON.parse(String((ev as MessageEvent).data)) as Record<
              string,
              unknown
            >;
            if (msg.op === "pong") {
              clearTimeout(timer);
              resolve(msg);
            }
          } catch {
            /* ignore non-JSON frames */
          }
        });
        ws.addEventListener("error", () => {
          clearTimeout(timer);
          reject(new Error("ws error"));
        });
      },
    );
    ws.close();

    expect(frame.op).toBe("pong");
    expect(frame.request_id, "pong echoes the request_id").toBe(requestId);
    expect(typeof frame.seq, "every frame carries a monotonic seq").toBe(
      "number",
    );
  });

  // Run LAST: this drains the per-account token bucket, which is shared with the
  // bootstrap admin used by the other assertions above.
  it("rate limiting: a flood trips 429 with code 1401 + Retry-After", async () => {
    const fire = () =>
      gwFetch(
        `${GATEWAY}/orders`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({ symbol: "SOL-USDC", side: "bid" }),
        },
        1, // no retries — we WANT to see the 429
      );
    // place is the heaviest weight; a few hundred concurrent should exhaust the
    // bucket regardless of its exact size.
    const results = await Promise.all(
      Array.from({ length: 300 }, () => fire().catch(() => null)),
    );
    const throttled = results.find((r) => r && r.status === 429);
    expect(
      throttled,
      "expected at least one 429 under a place flood (rate limiter wired?)",
    ).toBeTruthy();
    expect(
      throttled!.headers.get("retry-after"),
      "429 carries Retry-After",
    ).toBeTruthy();
    expect((await json(throttled!)).code, "429 → rate_limited code 1401").toBe(
      1401,
    );
  });
});
