---
sidebar_position: 2
title: Programmatic Access
description: The Nyx API surface at a glance — the two-layer auth model, the REST and WebSocket endpoints, and a quick start.
---

# Programmatic Access

:::info TL;DR
Nyx exposes a **REST + WebSocket API** served directly by the enclave over
RA-TLS. Authentication is **two layers**: an account **bearer token** (who is
allowed to talk to the venue) plus a per-order **trading-key signature** (who
cryptographically owns the order). Read endpoints are public; order management is
authenticated.
:::

## The authentication model

Two independent layers gate the API. They answer different questions and you
need both to trade.

| Layer | Credential | Answers | Used on |
|---|---|---|---|
| **Account** | Bearer token from `POST /auth/token` | "Is this caller allowed to use the venue?" (rate-limiting, audit) | Every authenticated request, as `Authorization: Bearer <token>` |
| **Order** | Ed25519 **trading-key** signature over the canonical order body | "Who cryptographically owns this order?" | Every place / cancel / modify |

The separation is deliberate. One account may operate many trading keys (sub-
portfolios, a market-maker fleet), and the **trading key — not the account — is
the cryptographic identity** that authorizes settlement. The bearer token only
enables operational controls; it cannot, by itself, move or cancel another key's
orders.

See [Authentication](../api/authentication) for the full credential model and
[Place Order](../orders/place-order) for how the order signature is constructed.

## Available APIs

| Surface | Use it for |
|---|---|
| **REST** | One-off calls, cold starts, snapshots: auth, instruments, order management, account state via Merkle proofs, transparency, settlement status. |
| **WebSocket** | Long-running clients: a bidirectional **trading** socket, a per-account **orders** lifecycle stream, and a per-account **fills** stream. |

REST is simplest to start with. A long-running trading client should move order
submission to the WebSocket trading socket (one warm, pre-authenticated
connection instead of a TLS + bearer round-trip per request) and subscribe to
the orders and fills channels for push updates.

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
| `POST` | `/orders/{order_id}/anchors` | bearer + sig | Top up an order's continuation anchor pool |
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
| `/ws/trading` | bidirectional | Stream framed `order.place` / `order.cancel` / `order.modify`; optional cancel-on-disconnect |
| `/ws/orders` | server → client | Per-account order-lifecycle events (partial / filled / cancelled / expired) |
| `/ws/fills` | server → client | Per-account continuation-fill memos |

WebSocket sockets self-authenticate with the bearer token as a `?token=` query
parameter (browsers and the global `WebSocket` cannot set an `Authorization`
header on the upgrade); an `Authorization: Bearer` header is also accepted.

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
#    VALID_INPUT proof, the continuation anchor pool, and a trading-key
#    signature over the canonical body — the SDK builds all of these. See
#    Orders → Place Order for the full field reference.
curl -s -X POST "$GATEWAY/orders" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @order.json | jq .
```

:::tip Use the SDK
A raw place-order body is large: it includes a note commitment, a 256-byte
zero-knowledge input proof, an owner-commitment opening, and a ten-entry
continuation anchor pool — all of which the **TypeScript SDK** derives and signs
for you from your keys and a deposited note. Hand-building the body is possible
(the wire contract is documented), but the SDK is the intended path. See
[SDK → TypeScript Client](../sdk/typescript-client).
:::

## Rate limits

Read endpoints and authenticated order management are subject to operational
rate limiting at the venue. Design clients to back off on `429` responses and to
prefer the WebSocket trading socket for high-frequency order management — one
authenticated connection avoids the per-request handshake cost. See
[System Status](../reference/system-status) for how the venue signals
degradation.
