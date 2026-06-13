---
sidebar_position: 1
title: TypeScript Client
description: A worked TypeScript client — authenticate, read markets, build and submit an order with the SDK's order builders, and stream order and fill events.
---

# TypeScript Client

:::info TL;DR
A reference client that ties the pieces together: get a bearer token, read
markets and server time, use the SDK's **order builders** to assemble a signed
order from a deposited note, submit it, and subscribe to the order and fill
streams. The SDK owns the cryptography — note commitments, the input proof, and
the anchor pool — so your code works in economic terms.
:::

## What the SDK does for you

The hard part of a Nyx order is its cryptographic backing: the collateral-note
commitment, the zero-knowledge input proof, the owner-commitment opening, and the
continuation anchor pool (see [Place Order](../orders/place-order)). The SDK
derives all of it from your seed and a spendable note, and signs the canonical
body with your trading key. You supply the *intent* — side, amount, price,
time-in-force — and get back a ready-to-send order.

The SDK also ships:

- **Order builders** — presets for market, all-or-none, and good-til-time orders
  over the native fields.
- **Stream clients** — per-account order-lifecycle and fill subscriptions, with
  the fill-memo verification built in.
- **System helpers** — server time (for slot-based expiry) and the degraded-mode
  status.

## Client implementation

```typescript
import {
  marketPolicy,
  aonPolicy,
  gttLimitPolicy,
  OrderSide,
  fetchServerTime,
  fetchSystemStatus,
  subscribeOrderUpdates,
  subscribeFills,
} from "@nyx/sdk";

class NyxClient {
  private token: string | null = null;

  constructor(private gateway: string) {
    this.gateway = gateway.replace(/\/$/, "");
  }

  // ── Auth ──────────────────────────────────────────────────────────────
  async login(apiKey: string, apiSecret: string, passphrase: string) {
    const r = await fetch(`${this.gateway}/auth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ api_key: apiKey, api_secret: apiSecret, passphrase }),
    });
    if (!r.ok) throw new Error(`auth ${r.status}: ${await r.text()}`);
    const body = await r.json();
    this.token = body.access_token;
    return body; // { access_token, token_type, expires_in, account_id }
  }

  private auth() {
    if (!this.token) throw new Error("call login() first");
    return { Authorization: `Bearer ${this.token}`, "Content-Type": "application/json" };
  }

  // ── Reference data + health ──────────────────────────────────────────
  getInstruments() {
    return fetch(`${this.gateway}/instruments`).then((r) => r.json());
  }
  systemStatus() {
    return fetchSystemStatus(this.gateway);
  }
  serverTime() {
    return fetchServerTime(this.gateway);
  }

  // ── Orders ───────────────────────────────────────────────────────────
  // `order` is a fully-built, signed wire body — produced by the SDK's
  // order-builder from your keys + a spendable note (it fills the note
  // commitment, the VALID_INPUT proof, the anchor pool, and the signature).
  placeOrder(order: object) {
    return fetch(`${this.gateway}/orders`, {
      method: "POST",
      headers: this.auth(),
      body: JSON.stringify(order),
    }).then((r) => r.json());
  }

  cancelOrder(orderId: string, cancel: object) {
    return fetch(`${this.gateway}/orders/${orderId}`, {
      method: "DELETE",
      headers: this.auth(),
      body: JSON.stringify(cancel),
    }).then((r) => r.json());
  }

  modifyOrder(orderId: string, modify: object) {
    return fetch(`${this.gateway}/orders/${orderId}`, {
      method: "PUT",
      headers: this.auth(),
      body: JSON.stringify(modify),
    }).then((r) => r.json());
  }

  getOrder(orderId: string) {
    return fetch(`${this.gateway}/orders/${orderId}`, { headers: this.auth() }).then((r) => r.json());
  }

  settlementStatus(batchId: string) {
    return fetch(`${this.gateway}/settlement/status/${batchId}`, { headers: this.auth() }).then((r) => r.json());
  }
}
```

## Building an order with the SDK builders

The builders set the execution-policy fields (type, price limit, fill size,
expiry) for a common intent. You merge a policy with the collateral the SDK
derives from a deposited note.

```typescript
// A resting bid, good for the next 10 minutes (GTT).
const { slot, unix_ms } = await client.serverTime();
const gttPolicy = gttLimitPolicy({
  priceLimit: 150_000_000n,
  serverSlot: slot,
  serverUnixMs: unix_ms,
  expiryUnixMs: Date.now() + 10 * 60 * 1000,
});

// A market bid: IOC capped at the worst price you'll pay.
const market = marketPolicy({ side: OrderSide.Bid, priceCap: 155_000_000n });

// An all-or-none resting bid.
const aon = aonPolicy({ amount: 10_000_000n, priceLimit: 150_000_000n });

// The SDK's order-builder takes a policy + a spendable note + your keys and
// returns the full signed wire body (note commitment, input proof, anchor pool,
// signature). Submit it as-is.
const order = await sdk.buildOrder({ symbol: "SOL-USDC", side: OrderSide.Bid, amount: 10_000_000n, policy: gttPolicy, note });
const res = await client.placeOrder(order);
console.log("placed", res.order_id, res.status);
```

## Streaming order and fill events

```typescript
// Per-account order lifecycle: partial / full fill, cancel, expiry.
const orders = subscribeOrderUpdates({
  gatewayWsUrl: WSS,
  token: client["token"]!,
  onUpdate: (u) => {
    if (u.kind === "partially_filled") console.log("partial", u.filled_quantity, "resting", u.new_amount);
    if (u.kind === "fully_filled") console.log("filled", u.order_id);
  },
  onResync: () => console.warn("orders stream lagged — reconcile via GET /orders/:id"),
});

// Per-account fills: verified change-note memos (the SDK checks each memo's
// anchor + commitment binding before handing it to you).
const fills = subscribeFills({
  gatewayWsUrl: WSS,
  token: client["token"]!,
  masterSeed,
  ownerCommitment,
  store: noteStore,
  onFill: (rec) => console.log("change note stored", rec.commitment),
  onResync: () => console.warn("fills stream lagged — backfill then reopen"),
});
```

## Submitting over the trading socket

For a high-frequency client, submit orders over the [WebSocket trading
socket](../websocket/ws-trading) instead of REST — one warm connection, plus
cancel-on-disconnect.

```typescript
const ws = new WebSocket(`${WSS}/ws/trading?token=${TOKEN}&cancel_on_disconnect=true`);
ws.onopen = () => ws.send(JSON.stringify({ op: "order.place", request_id: "r1", params: order }));
ws.onmessage = (e) => {
  const msg = JSON.parse(e.data);
  if (msg.op === "error") console.error(msg.code, msg.message);
  else if (msg.op === "order.place") console.log("accepted", msg.result.order_id);
};
```

## Usage

```typescript
const client = new NyxClient("https://<gateway-host>");
await client.login(API_KEY, API_SECRET, PASSPHRASE);

const status = await client.systemStatus();
if (status.degraded) throw new Error("venue degraded — back off");

const markets = await client.getInstruments();
console.log(markets.instruments.map((m) => m.symbol));

// build + place an order (see above), then watch its lifecycle on the streams.
```

:::tip Verify the engine first
For the full trust guarantee, verify the enclave's attestation against an
expected measurement before sending order intent — the SDK ships a helper that
runs the [attestation chain](../api/transport-and-attestation) for you. Skipping it
gives you a private channel to *a* machine, not a verified one.
:::
