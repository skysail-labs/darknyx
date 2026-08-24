---
description: "A worked TypeScript client that authenticates, reads markets, builds and submits an order with the SDK's order builders, and streams order and fill events."
---


# TypeScript Client

{% hint style="info" %}
**TL;DR**

A reference client that ties the pieces together: get a bearer token, read
markets and server time, use the SDK's **order builders** to assemble a signed
order from a deposited note, submit it, and subscribe to the order and fill
streams. The Node client first creates one quote-verified RA-TLS transport and
injects its HTTP and WebSocket adapters everywhere. The SDK owns the
cryptography (note commitments, the input proof, viewing-key derivation, and
canonical signing) so your code works in economic terms.
{% endhint %}

## What the SDK does for you

The hard part of a Darknyx order is its cryptographic backing: the collateral-note
commitment, the zero-knowledge input proof, the owner-commitment opening, the
signed viewing key, and the current boot session (see [Place Order](/api-reference/orders/place-order)). The SDK
derives all of it from your seed and a spendable note, and signs the canonical
body with your trading key. You supply the *intent* (side, amount, price,
time-in-force) and get back a ready-to-send order.

The SDK also ships:

- **Order builders**: presets for market, all-or-none, and good-til-time orders
  over the native fields. They include the `viewing_pubkey` for on-chain
  trade/change recovery **by default**, so exact and partial output notes stay
  recoverable without extra work.
- **Stream clients**: per-account order-lifecycle and fill subscriptions, with
  the fill-memo verification built in.
- **Recovery helpers**: generate and securely store a CSPRNG master seed, export
  or import its authenticated versioned backup with
  `exportEncryptedMasterSeed` / `importEncryptedMasterSeed`, recover fill outputs
  (`recoverFillFromChain`), or rebuild deposits, fills, continuations, and merges
  from seed + chain (`recoverNotesFromChain`).
  Wallet-message signatures are not used as spend authority.
- **System helpers**: server time (for slot-based expiry) and the degraded-mode
  status.
- **Node transport**: `createVerifiedTransport` binds the certificate on the
  live HTTP/WebSocket connection to a fresh enclave quote, approved compose
  hash, boot session, and finalized signer-set pin.

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
  // order submission
  proveAndBuildOrder,
  buildOrder,
  buildCancel,
  nodeValidInputProver,
  placeOrder,
  TradingClient,
  DarknyxApiError,
  deriveOrderId,
} from "@darknyx/sdk";
import { createVerifiedTransport } from "@darknyx/sdk/transport-node";

// Abridged: build `verifierDependencies` with the DCAP verifier used by the
// reference daemon. Obtain the compose and signer-set pins independently from
// the reviewed release and finalized VaultConfig.
const transport = await createVerifiedTransport({
  baseUrl: GATEWAY,
  deps: verifierDependencies,
  expectedComposeHash,
  expectedSignerSetSha256,
  createWebSocket,
});

class DarknyxClient {
  private token: string | null = null;

  constructor(
    private gateway: string,
    private fetchImpl: typeof fetch,
  ) {
    this.gateway = gateway.replace(/\/$/, "");
  }

  // ── Auth ──────────────────────────────────────────────────────────────
  async login(apiKey: string, apiSecret: string, passphrase: string) {
    const r = await this.fetchImpl(`${this.gateway}/auth/token`, {
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
    return this.fetchImpl(`${this.gateway}/instruments`).then((r) => r.json());
  }
  systemStatus() {
    return fetchSystemStatus(this.gateway, { fetchImpl: this.fetchImpl });
  }
  serverTime() {
    return fetchServerTime(this.gateway, { fetchImpl: this.fetchImpl });
  }

  // ── Orders ───────────────────────────────────────────────────────────
  // `order` is a fully-built, signed wire body, produced by the SDK's
  // order-builder from your keys + a spendable note (it fills the note
  // commitment, VALID_INPUT proof, viewing key, session, and signature).
  placeOrder(order: object) {
    return this.fetchImpl(`${this.gateway}/orders`, {
      method: "POST",
      headers: this.auth(),
      body: JSON.stringify(order),
    }).then((r) => r.json());
  }

  cancelOrder(orderId: string, cancel: object) {
    return this.fetchImpl(`${this.gateway}/orders/${orderId}`, {
      method: "DELETE",
      headers: this.auth(),
      body: JSON.stringify(cancel),
    }).then((r) => r.json());
  }

  modifyOrder(orderId: string, modify: object) {
    return this.fetchImpl(`${this.gateway}/orders/${orderId}`, {
      method: "PUT",
      headers: this.auth(),
      body: JSON.stringify(modify),
    }).then((r) => r.json());
  }

  getOrder(orderId: string) {
    return this.fetchImpl(`${this.gateway}/orders/${orderId}`, { headers: this.auth() }).then((r) => r.json());
  }

  settlementStatus(batchId: number) {
    return this.fetchImpl(`${this.gateway}/settlement/status/${batchId}`, { headers: this.auth() }).then((r) => r.json());
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

// `proveAndBuildOrder` does the whole flow: fetch the note's inclusion witness
// from /tree/inclusion, generate the VALID_INPUT proof, then assemble + sign the
// wire body (note commitment, proof, viewing key, session, trading signature). The
// prover is pluggable: `nodeValidInputProver` runs the compiled circuit via
// snarkjs in Node. The separate browser product/prover remains deferred.
const order = await proveAndBuildOrder({
  baseUrl: GATEWAY,
  token: client["token"]!,
  fetchImpl: transport.fetch,
  prover: nodeValidInputProver({ wasmPath, zkeyPath }),
  ownerCommitmentBlinding,
  tokenMint,
  masterSeed,
  spendingKey,
  ownerCommitment,
  tradingKey: trading.publicKey,
  sign: (digest) => nacl.sign.detached(digest, trading.secretKey),
  note,                         // { commitment, innerHash, amount }
  symbol: "SOL-USDC",
  side: OrderSide.Bid,
  policy: gttPolicy,
  amount: 10_000_000n,
  orderId: deriveOrderId(masterSeed, 0),
  sessionId: Uint8Array.from(Buffer.from(info.boot_session_id, "hex")),
});

// Submit over REST...
const res = await placeOrder(
  { baseUrl: GATEWAY, token: client["token"]!, fetchImpl: transport.fetch },
  order,
);
console.log("placed", res.order_id, res.status);
```

{% hint style="success" %}
**Already hold a proof?**

If you already have a VALID_INPUT proof (e.g. relayed from elsewhere), skip the
prover and call `buildOrder({ …, validInput: { proofBytes, merkleRoot } })`
directly. `proveAndBuildOrder` is just the fetch-prove-build convenience on top.
{% endhint %}

## Streaming order and fill events

```typescript
// Per-account order lifecycle: reservation, confirmed fills, failure, cancel, expiry.
const orders = subscribeOrderUpdates({
  gatewayWsUrl: WSS,
  token: client["token"]!,
  webSocketFactory: transport.webSocketFactory,
  onUpdate: (u) => {
    if (u.kind === "partially_filled") console.log("partial", u.filled_quantity, "resting", u.new_amount);
    if (u.kind === "fully_filled") console.log("filled", u.order_id);
  },
  onResync: () => console.warn("orders stream lagged, reconcile via GET /orders/:id"),
});

// Per-account fills: verified change-note memos (the SDK checks each memo's
// consumed-input derivation + commitment binding before handing it to you).
const fills = subscribeFills({
  gatewayWsUrl: WSS,
  token: client["token"]!,
  webSocketFactory: transport.webSocketFactory,
  masterSeed,
  ownerCommitment,
  store: noteStore,
  onFill: (rec) => console.log("change note stored", rec.commitment),
  onResync: () => console.warn("fills stream lagged, backfill then reopen"),
});
```

## Submitting over the trading socket

For a high-frequency client, submit orders over the shared
[`/v1/stream` session](/api-reference/websocket/session-stream) instead of REST, using one warm connection plus
cancel-on-disconnect. The `TradingClient` correlates each reply to its request
and resolves a promise per call:

```typescript
const trader = new TradingClient({
  gatewayWsUrl: WSS,
  token: client["token"]!,
  webSocketFactory: transport.webSocketFactory,
  cancelOnDisconnect: true,
});
await trader.connect();

try {
  const res = await trader.place(order);          // resolves with the acceptance
  console.log("accepted", res.order_id);
} catch (e) {
  if (e instanceof DarknyxApiError) console.error(e.code, e.message); // numeric code
}

// Cancel + modify use the same socket; build the bodies with buildCancel / buildOrder.
const cancel = await buildCancel({
  orderId,
  tradingKey: trading.publicKey,
  cancelNonce: 1n,
  sessionId: Uint8Array.from(Buffer.from(info.boot_session_id, "hex")),
  sign,
});
await trader.cancel(hex(orderId), cancel);
```

## Usage

```typescript
const client = new DarknyxClient(GATEWAY, transport.fetch);
await client.login(API_KEY, API_SECRET, PASSPHRASE);

const status = await client.systemStatus();
const markets = await client.getInstruments();
const market = markets.find((m) => m.symbol === "SOL-USDC");
if (!status.settle_enabled || !market?.trading_enabled) {
  throw new Error("SOL-USDC is not ready, back off");
}
console.log(markets.map((m) => m.symbol));

// build + place an order (see above), then watch its lifecycle on the streams.
```

{% hint style="success" %}
**One verified transport, everywhere**

Every helper that can reach the venue requires an injected `fetchImpl`, and
every stream constructor accepts the verified `webSocketFactory`. Always pass
the pair from the same `createVerifiedTransport` result. Falling back to global
`fetch`, a stock WebSocket, or an accept-any-certificate switch bypasses the
property even if another call successfully verified an attestation quote. The
reference daemon is the complete pin-loading and DCAP-verifier integration.
{% endhint %}
