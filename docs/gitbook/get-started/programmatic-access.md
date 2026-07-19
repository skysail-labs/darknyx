---
description: "The Darknyx API surface at a glance: the two-layer auth model, the REST and WebSocket endpoints, and a quick start."
---


# Programmatic Access

{% hint style="info" %}
**TL;DR**

Darknyx exposes a **REST + WebSocket API** from the confidential-VM deployment.
Authentication is **two layers**: an account **bearer token** (who is
allowed to talk to the venue) plus a per-order **trading-key signature** (who
cryptographically owns the order). Market and health reads are public; private
state and order management are authenticated. Attestation verifies the server
before a client discloses order intent.
{% endhint %}

## The authentication model

Two independent layers gate the API. They answer different questions and you
need both to trade.

| Layer | Credential | Answers | Used on |
|---|---|---|---|
| **Account** | Bearer token from `POST /auth/token` | "Is this caller allowed to use the venue?" (rate-limiting, audit) | Every authenticated request, as `Authorization: Bearer <token>` |
| **Order** | Ed25519 **trading-key** signature over the canonical order body | "Who cryptographically owns this order?" | Every place / cancel / modify |

The separation is deliberate. One account may operate many trading keys (sub-
portfolios, a market-maker fleet), and the **trading key, not the account, is
the cryptographic identity** that authorizes settlement. The bearer token only
enables operational controls; it cannot, by itself, move or cancel another key's
orders.

See [Authentication](../api/authentication.md) for the full credential model and
[Place Order](../orders/place-order.md) for how the order signature is constructed.

## Available APIs

| Surface | Use it for |
|---|---|
| **REST** | One-off calls, cold starts, snapshots: auth, instruments, order management, account state via Merkle proofs, transparency, settlement status. |
| **WebSocket** | Long-running clients: order operations plus `orders`, `fills`, and `tree` subscriptions multiplexed over one `/v1/stream` session. |

REST is simplest to start with. A long-running trading client should use one
warm, in-band-authenticated `/v1/stream` connection for order operations and
subscribe to lifecycle and fill events. Sequence numbers let it detect gaps and
reconcile after reconnecting.

## Endpoint map

### REST

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/auth/token` | public | Exchange API credentials for a bearer token |
| `POST` | `/auth/token/revoke` | bearer | Revoke the calling token |
| `GET` | `/instruments` | public | List tradable markets |
| `GET` | `/instruments/{symbol}` | public | One market's metadata |
| `POST` | `/orders` | bearer + sig | Place an order |
| `DELETE` | `/orders/{order_id}` | bearer + sig | Cancel an order |
| `PUT` | `/orders/{order_id}` | bearer + sig | Modify (atomic cancel + replace) |
| `GET` | `/orders/{order_id}` | bearer | Order status |
| `GET` | `/account` | bearer | Open orders owned by the account |
| `GET/PUT` | `/account/settings` | bearer | Account stream preferences |
| `GET` | `/tree/root` | public | Current Merkle root of a shard |
| `GET` | `/tree/inclusion` | bearer | Inclusion proof for a note commitment |
| `GET` | `/tree/leaves` | bearer | Paginated leaf read |
| `GET` | `/transparency` | public | Proof-of-reserves + engine identity + stats |
| `GET` | `/settlement/status/{batch_id}` | bearer | On-chain settlement status of a batch |
| `GET` | `/system/status` | public | Liveness / degraded-mode snapshot |
| `GET` | `/time` | public | Server slot + unix time |
| `GET` | `/attestation` | public | TDX attestation quote |
| `GET` | `/info` | public | Running image identity (compose hash, app id, signer) |
| `GET` | `/health` | public | Liveness probe |

### WebSocket

| Path | Direction | Purpose |
|---|---|---|
| `/v1/stream` | bidirectional | In-band login; framed order operations; `orders`, `fills`, and `tree` subscriptions; cancel-on-disconnect |

Open `/v1/stream` without query credentials and authenticate with an `op: login`
frame. The SDK multiplexes all channels and order operations on that session.

## Quick start

```bash
# 1. Exchange credentials for a bearer token.
TOKEN=$(curl -s -X POST "$GATEWAY/auth/token" \
  -H "Content-Type: application/json" \
  -d '{"api_key":"...","api_secret":"...","passphrase":"..."}' \
  | jq -r .access_token)

# 2. Read the markets (public).
curl -s "$GATEWAY/instruments" | jq .

# 3. Check the venue is healthy before trading.
curl -s "$GATEWAY/system/status" | jq .

# 4. Place an order. The body carries the collateral-note commitment, the
#    VALID_INPUT proof, signed viewing key + boot session, and a trading-key
#    signature over the canonical body. The SDK builds all of these. See
#    Orders → Place Order for the full field reference.
curl -s -X POST "$GATEWAY/orders" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @order.json | jq .
```

{% hint style="success" %}
**Use the SDK**

A raw place-order body is large: it includes a note commitment, a 256-byte
zero-knowledge input proof, the note opening needed for intake validation, a
contributory viewing key, and the current boot session, all of which the **TypeScript SDK** signs
for you from your keys and a deposited note. Hand-building the body is possible
(the wire contract is documented), but the SDK is the intended path. See
[SDK → TypeScript Client](../sdk/typescript-client.md).
{% endhint %}

## Rate limits

Read endpoints and authenticated order management are subject to operational
rate limiting at the venue. Design clients to back off on `429` responses and to
prefer the shared `/v1/stream` session for high-frequency order management,
since one authenticated connection avoids per-request setup. See
[System Status](../reference/system-status.md) for how the venue signals
degradation.
