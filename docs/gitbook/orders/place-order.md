---
description: "Submit a hidden, fully-collateralized order, covering the request body, the cryptographic fields the SDK builds for you, and the response lifecycle."
---


# Place Order

{% hint style="info" %}
**TL;DR**

`POST /orders` submits a new order. The body carries the usual economic fields
(symbol, side, type, amount, price) **plus** the cryptographic backing that makes
the order private and self-custodial: the collateral-note commitment, a zero-knowledge
input proof, a note opening, a signed contributory viewing key, the current boot
session, and a trading-key signature over the canonical order intent. The
opening is pinned indirectly through the signed note commitment. The **SDK builds and signs
all of this** from your keys and a deposited note.
{% endhint %}

```text
POST /orders
```

Auth: `Authorization: Bearer <token>` **and** a trading-key signature in the body.

## How a Darknyx order differs

On a transparent venue, placing an order is just sending its economic fields. On
Darknyx an order is *fully collateralized by a specific note you already deposited*,
and it is *private*, so the request also carries:

- the **commitment** of the collateral note, and a secret **opening** of that
  note the in-enclave prover needs;
- a **zero-knowledge input proof** that the note exists in the on-chain tree and
  is yours to spend;
- a signed **X25519 viewing key** for private recovery data;
- the current 32-byte **boot session id**, so a signed order cannot be replayed
  into a restarted engine;
- an **Ed25519 signature** from your trading key over the canonical body, so the
  engine can attribute, and ultimately settle, the order to you without any
  per-order on-chain transaction;
- deterministic partial-fill continuation: the settlement circuit derives each
  change inner from the consumed input inner, so no pre-supplied pool is needed.

You do not assemble these by hand. The SDK takes your keys and a spendable note
and produces a ready-to-sign request. The full field reference is here so the
wire contract is unambiguous.

## Request body

### Economic fields

| Field | Type | Required | Description |
|---|---|---|---|
| `symbol` | string | Yes | Market id, e.g. `"SOL-USDC"`. |
| `side` | string | Yes | `"bid"` (buy base) or `"ask"` (sell base). |
| `order_type` | string | Yes | `"limit"`, `"ioc"`, or `"fok"`. See [Order Types](../trading-concepts/order-types.md). |
| `amount` | integer | Yes | Order size in base units. |
| `price_limit` | integer | Conditional | Worst acceptable price, in quote units per base. Required for a bid; an ask may use `0` to accept any clearing price. |
| `min_fill_size` | integer | No | Reject fills smaller than this. Set equal to `amount` for all-or-none. Default `0` (any partial fill). See [Execution Attributes](../trading-concepts/execution-attributes.md). |
| `expiry_slot` | integer | Yes | Solana slot past which the order auto-expires. Bounded by the market's max expiry. See [Time in Force](../trading-concepts/time-in-force.md). |
| `order_id` | string | Yes | A client-chosen 16-byte id, hex. Must be unique and non-zero. The SDK can derive ids deterministically from your seed (`deriveOrderId`), so you can reconcile or recover your order set on a fresh device. |
| `arrival_nonce` | integer | Yes | A strictly increasing u64 per trading key. Exact byte-identical idempotent retries are handled before this replay check. |

### Collateral, opening, and proof

| Field | Type | Required | Description |
|---|---|---|---|
| `note_commitment` | string | Yes | 32-byte hex. The commitment of the collateral note backing this order. The note must exist in the tree and be lockable (not already locked). |
| `collateral_amount` | integer | No | The value the collateral note actually carries, when it exceeds the order's nominal cost. Lets you point a large note at a small order and receive the surplus back as a change note. Omit for exact collateral. |
| `owner_commitment` | string | Yes | 32-byte hex. The collateral note's owner commitment, part of the secret opening the in-enclave prover re-derives the commitment from. Distinct from `user_commitment`. Held in enclave memory only. |
| `note_inner_hash` | string | Yes | 32-byte hex. The note's amount-independent inner hash (an opening field that anchors both the commitment and the nullifier). |
| `user_commitment` | string | Yes | 32-byte hex. Binds the order's output notes to the correct owner on-chain. |
| `nullifier` | string | Yes | 32-byte hex. Precomputed client-side (it needs the spending key, which never enters the enclave). Retained by the current order schema but absent from settlement payload v9; Tx D replay protection is commitment-keyed. |
| `merkle_root` | string | Yes | 32-byte hex. The tree root the input proof was generated against. Must still be in the on-chain root window at settlement time. |
| `valid_input_proof` | string | Yes | 256-byte hex. The zero-knowledge proof that the collateral note is in the tree and spendable. The engine relays it unverified; the on-chain program verifies it at lock time. |
| `tree_id` | integer | No | Merkle-tree shard containing the collateral note. Defaults to `0`; a wrong shard causes the on-chain lock to fail. |

### Recovery and replay binding

| Field | Type | Required | Description |
|---|---|---|---|
| `viewing_pubkey` | string | Yes | 32-byte contributory X25519 public key derived by the SDK. It is signed in the canonical body. Low-order/non-contributory points are rejected before booking. |
| `session_id` | string | Yes | 32-byte current `/info.boot_session_id`, signed in the canonical body. A CVM restart changes it and invalidates stale orders. |

### Signature

| Field | Type | Required | Description |
|---|---|---|---|
| `trading_key` | string | Yes | 32-byte hex. The Ed25519 public key that owns this order. |
| `trading_key_signature` | string | Yes | 64-byte hex. Signature over the canonical v3 encoding, including every economic field, `viewing_pubkey`, `session_id`, and `arrival_nonce`. |

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
    "viewing_pubkey": "…",
    "session_id": "…"
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
| `status` | string | `"accepted"` means the order passed verification and entered the book. |
| `arrival_slot` | integer | The slot the engine stamped on arrival; frozen for the order's life. |

{% hint style="info" %}
**Accepted is not filled**

A `202` means the order passed signature and collateral verification and entered
the book, **not** that it has filled. Track fills via
[`GET /orders/{order_id}`](./get-order.md) or the
[Orders Channel](../websocket/orders-channel.md).
{% endhint %}

## Order status lifecycle

| Status | Description |
|---|---|
| `pending` | Accepted and resting in the book. |
| `pending_settlement` | Reserved for a private match; no book quantity or fill is committed until Solana confirms it. |
| `partially_filled` | Stream event emitted after a confirmed partial settlement; the derived continuation remains live. |
| `fully_filled` | Stream event emitted after the final confirmed quantity. |
| `settlement_failed` | Terminal definitive rejection. Includes a reason and lock-expiry slot; submit a fresh signed order after unlock. |
| `expired` / `cancelled` | Terminal without a confirmed fill. |

A market or fill-or-kill order that cannot execute in its arrival batch leaves the
book immediately rather than resting.

## Idempotency

`order_id` is your idempotency key. A retry that re-sends the **byte-identical**
signed order returns the original acceptance (`202`, same `order_id`) instead of
a conflict, so a network blip is safe to retry. Reusing an `order_id` for a
**different** order (any economic field changed) is a real conflict and returns
`409` (`code` 1201). Because order ids are client-chosen, pick a fresh one per
distinct order.

## Verification at intake

Every order is verified before it enters the book. A non-`202` response carries a
[structured error code](../reference/error-codes.md); the conditions:

| Check | Status | Code |
|---|---|---|
| Well-formed fields (hex widths, non-zero `order_id`) | `400` | 1001 |
| Hashed fields are canonical field elements | `400` | 1002 |
| Order amount meets the market minimum | `400` | 1004 |
| A bid has a positive price limit | `400` | 1005 |
| The note opening re-derives the signed `note_commitment` | `400` | 1006 |
| The collateral covers the order's nominal cost plus its own fee | `400` | 1003 |
| The trading-key signature verifies over the canonical body | `403` | 1102 |
| The viewing key is contributory | `400` | 1008 |
| `expiry_slot` fits within the maximum on-chain lock lifetime | `400` | 1007 |
| The signed session matches this boot | `409` | 1205 |
| The `order_id` is not reused for a different order | `409` | 1201 |
| The nonce is strictly greater than the last accepted nonce for this trading key | `409` | 1202 |
| Per-account rate limit not exceeded | `429` | 1401 |

Because the opening is checked against the *signed* commitment, the secret
opening fields are cryptographically pinned to your signature without being part
of the signed canonical body.

{% hint style="info" %}
**Rate limits are weighted**

Order management is rate-limited per account with a token bucket; cancels are
cheap, place and modify cost more. A `429` includes a `Retry-After` header. For
high-frequency management prefer the shared
[`/v1/stream` session](../websocket/session-stream.md).
{% endhint %}
