---
sidebar_position: 1
title: Place Order
description: Submit a hidden, fully-collateralized order — the request body, the cryptographic fields the SDK builds for you, and the response lifecycle.
---

# Place Order

:::info TL;DR
`POST /orders` submits a new order. The body carries the usual economic fields
(symbol, side, type, amount, price) **plus** the cryptographic backing that makes
the order private and trustless: the collateral-note commitment, a zero-knowledge
input proof, an owner-commitment opening, a continuation **anchor pool**, and a
trading-key signature over the whole canonical body. The **SDK builds and signs
all of this** from your keys and a deposited note.
:::

```text
POST /orders
```

Auth: `Authorization: Bearer <token>` **and** a trading-key signature in the body.

## How a Nyx order differs

On a transparent venue, placing an order is just sending its economic fields. On
Nyx an order is *fully collateralized by a specific note you already deposited*,
and it is *private* — so the request also carries:

- the **commitment** of the collateral note, and a secret **opening** of that
  note the in-enclave prover needs;
- a **zero-knowledge input proof** that the note exists in the on-chain tree and
  is yours to spend;
- a **continuation anchor pool** that lets the engine settle partial fills and
  keep the remainder working without a round-trip to you per fill;
- an **Ed25519 signature** from your trading key over the canonical body, so the
  engine can attribute — and ultimately settle — the order to you without any
  per-order on-chain transaction.

You do not assemble these by hand. The SDK takes your keys and a spendable note
and produces a ready-to-sign request. The full field reference is here so the
wire contract is unambiguous.

## Request body

### Economic fields

| Field | Type | Required | Description |
|---|---|---|---|
| `symbol` | string | Yes | Market id, e.g. `"SOL-USDC"`. |
| `side` | string | Yes | `"bid"` (buy base) or `"ask"` (sell base). |
| `order_type` | string | Yes | `"limit"`, `"ioc"`, or `"fok"`. See [Order Types](../trading-concepts/order-types). |
| `amount` | integer | Yes | Order size in base units. |
| `price_limit` | integer | Conditional | Worst acceptable price, in quote units per base. Required for a bid; an ask may use `0` to accept any clearing price. |
| `min_fill_size` | integer | No | Reject fills smaller than this. Set equal to `amount` for all-or-none. Default `0` (any partial fill). See [Execution Attributes](../trading-concepts/execution-attributes). |
| `expiry_slot` | integer | Yes | Solana slot past which the order auto-expires. Bounded by the market's max expiry. See [Time in Force](../trading-concepts/time-in-force). |
| `order_id` | string | Yes | A client-chosen 16-byte id, hex. Must be unique and non-zero. |
| `arrival_nonce` | integer | Yes | A per-order nonce bound into the signature. |

### Collateral, opening, and proof

| Field | Type | Required | Description |
|---|---|---|---|
| `note_commitment` | string | Yes | 32-byte hex. The commitment of the collateral note backing this order. The note must exist in the tree and be lockable (not already locked). |
| `collateral_amount` | integer | No | The value the collateral note actually carries, when it exceeds the order's nominal cost. Lets you point a large note at a small order and receive the surplus back as a change note. Omit for exact collateral. |
| `owner_commitment` | string | Yes | 32-byte hex. The collateral note's owner commitment — part of the secret opening the in-enclave prover re-derives the commitment from. Distinct from `user_commitment`. Held in enclave memory only. |
| `note_inner_hash` | string | Yes | 32-byte hex. The note's amount-independent inner hash (an opening field that anchors both the commitment and the nullifier). |
| `user_commitment` | string | Yes | 32-byte hex. Binds the order's output notes to the correct owner on-chain. |
| `nullifier` | string | Yes | 32-byte hex. Precomputed client-side (it needs the spending key, which never enters the enclave). Opaque to the engine; carried into the settlement payload. |
| `merkle_root` | string | Yes | 32-byte hex. The tree root the input proof was generated against. Must still be in the on-chain root window at settlement time. |
| `valid_input_proof` | string | Yes | 256-byte hex. The zero-knowledge proof that the collateral note is in the tree and spendable. The engine relays it unverified; the on-chain program verifies it at lock time. |

### Continuation anchor pool

| Field | Type | Required | Description |
|---|---|---|---|
| `anchors` | array | Yes | Exactly **10** continuation anchors. Each is an `{ inner_hash, nullifier }` pair (both 32-byte hex) for a future change note, so the engine can settle a partial fill and re-lock the remainder without asking you for a new note per fill. The hash of the pool is bound into the signature. See [The Anchor Pool](../trading-concepts/anchor-pool). |

### Signature

| Field | Type | Required | Description |
|---|---|---|---|
| `trading_key` | string | Yes | 32-byte hex. The Ed25519 public key that owns this order. |
| `trading_key_signature` | string | Yes | 64-byte hex. Signature over the canonical encoding of the body — every economic field plus the anchor-pool hash and `arrival_nonce`. |

## Example

```bash
# In practice the SDK produces order.json from your keys + a spendable note.
curl -s -X POST "$GATEWAY/orders" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "symbol": "SOL-USDC",
    "side": "bid",
    "order_type": "limit",
    "amount": 10000000,
    "price_limit": 150000000,
    "min_fill_size": 0,
    "expiry_slot": 309490000,
    "order_id": "aa00000000000000000000000000000001",
    "note_commitment": "…",
    "user_commitment": "…",
    "arrival_nonce": 1,
    "trading_key": "…",
    "trading_key_signature": "…",
    "owner_commitment": "…",
    "note_inner_hash": "…",
    "nullifier": "…",
    "merkle_root": "…",
    "valid_input_proof": "…",
    "anchors": [ { "inner_hash": "…", "nullifier": "…" }, "… 10 total …" ]
  }'
```

## Success response

```json
{
  "order_id": "aa00000000000000000000000000000001",
  "status": "accepted",
  "arrival_slot": 309482113
}
```

Returned with `202 Accepted`.

| Field | Type | Description |
|---|---|---|
| `order_id` | string | The order's id (the one you supplied). |
| `status` | string | `"accepted"` — the order passed verification and entered the book. |
| `arrival_slot` | integer | The slot the engine stamped on arrival; frozen for the order's life. |

:::note Accepted is not filled
A `202` means the order passed signature and collateral verification and entered
the book — **not** that it has filled. Track fills via
[`GET /orders/{order_id}`](./get-order) or the
[Orders Channel](../websocket/orders-channel).
:::

## Order status lifecycle

| Status | Description |
|---|---|
| `pending` | Accepted and resting in the book. |
| `matched` | Matched in a batch; settling or settled on-chain. |
| `expired` | Reached `expiry_slot` without (fully) filling. |
| `cancelled` | Cancelled by you, by a modify, or on session disconnect. |

A market or fill-or-kill order that cannot execute in its arrival batch leaves the
book immediately rather than resting.

## Verification at intake

Every order is verified before it enters the book. A non-`202` response means one
of these failed:

| Check | Status |
|---|---|
| Well-formed fields (hex widths, non-zero `order_id`, field-element safety) | `400` |
| The trading-key signature verifies over the canonical body | `403` |
| The note opening re-derives the signed `note_commitment` | `400` |
| The collateral covers the order's nominal cost plus its own fee | `400` |
| The `order_id` is not already in the book | `409` |

Because the opening is checked against the *signed* commitment, the secret
opening fields are cryptographically pinned to your signature without being part
of the signed canonical body. See [Error Codes](../reference/error-codes).
