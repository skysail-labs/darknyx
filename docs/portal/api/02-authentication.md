---
sidebar_position: 2
title: Authentication
description: The two-layer Nyx auth model — account bearer tokens plus per-order trading-key signatures — and how to obtain and use them.
---

# Authentication

:::info TL;DR
Authentication has **two layers**. An **account bearer token** (`POST
/auth/token`) gates access to the venue. A per-order **Ed25519 trading-key
signature** proves cryptographic ownership of each order. You need the token to
talk to the venue and the signature to place, cancel, or modify an order.
:::

## The credential model

Two layers, two questions.

| Layer | Credential | Question it answers |
|---|---|---|
| **Account** | Bearer token | "Is this caller allowed to use the venue?" |
| **Order** | Trading-key signature | "Who cryptographically owns this order?" |

The account layer is operational: it enables rate-limiting and audit, and is
provisioned out of band (you receive an `api_key`, an `api_secret`, and a
`passphrase`). The order layer is cryptographic: a trading key is an Ed25519
keypair you control, and the venue attributes — and ultimately settles — each
order to the key that signed it.

**One account can drive many trading keys.** A market-maker fleet or a set of
sub-portfolios shares one account login but signs with distinct trading keys.
Because the trading key is the identity that authorizes settlement, holding the
bearer token alone never lets a caller move or cancel another key's orders.

## POST /auth/token

Exchange API credentials for a short-lived bearer token.

```text
POST /auth/token
```

### Request

```json
{
  "api_key": "your-api-key",
  "api_secret": "your-api-secret",
  "passphrase": "your-passphrase"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `api_key` | string | Yes | Public credential identifier provisioned at account setup. |
| `api_secret` | string | Yes | The secret paired with `api_key`. |
| `passphrase` | string | Yes | Account-level passphrase (third factor). |

### Response

```json
{
  "access_token": "eyJhbGciOi...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "account_id": "acct_01H..."
}
```

| Field | Type | Description |
|---|---|---|
| `access_token` | string | The bearer token. Pass as `Authorization: Bearer <token>`. |
| `token_type` | string | Always `Bearer`. |
| `expires_in` | integer | Token lifetime in seconds from issue. |
| `account_id` | string | Stable per-account identifier. |

### cURL

```bash
curl -s -X POST "$GATEWAY/auth/token" \
  -H "Content-Type: application/json" \
  -d '{
    "api_key": "your-api-key",
    "api_secret": "your-api-secret",
    "passphrase": "your-passphrase"
  }'
```

## Using the bearer token

Send it on every authenticated REST request:

```bash
curl -s "$GATEWAY/orders/$ORDER_ID" \
  -H "Authorization: Bearer $TOKEN"
```

On the WebSocket routes, pass it as a query parameter (the upgrade cannot carry
a header from a browser); the `Authorization` header is also accepted:

```text
wss://<gateway-host>/ws/orders?token=<access_token>
```

## Token expiry and revocation

Tokens are short-lived (the `expires_in` window). Cache the token in-process and
refresh it before expiry; a request with an expired token returns `401`.

To invalidate a token before it expires:

```text
POST /auth/token/revoke
```

with the token in the `Authorization` header. The token is denylisted
immediately; subsequent requests with it return `401`.

## The order signature

Placing, cancelling, or modifying an order requires an Ed25519 signature from the
order's trading key, in addition to the bearer token.

- **Place** — sign the canonical order body. The signature binds every economic
  field of the order (symbol, side, type, amount, price limit, expiry, the
  collateral-note commitment, the continuation anchor-pool hash, and a nonce) so
  the venue can attribute the order to your key without any per-order on-chain
  transaction.
- **Cancel** — sign a canonical cancel body over the order id, your trading key,
  and a cancel nonce.
- **Modify** — sign a cancel of the old order *and* a full new order; both
  signatures must come from the same trading key.

The canonical encodings are fixed-length and unambiguous, so re-encoding from
JSON always yields the same bytes to sign. The SDK constructs and signs these for
you. The exact field layout for each is on the corresponding endpoint page —
[Place Order](../orders/place-order), [Cancel Order](../orders/cancel-order),
[Modify Order](../orders/modify-order).

## Public (unauthenticated) endpoints

These require no token:

- `GET /health`, `GET /system/status`, `GET /time`
- `GET /info`, `GET /attestation`, the `/evidences/*` files
- `GET /instruments`, `GET /instruments/{symbol}`
- `GET /tree/root`
- `GET /transparency`

Everything else — order management, account-scoped reads (`/tree/inclusion`,
`/tree/leaves`, `/settlement/status`), and the WebSocket streams — requires the
bearer token.
