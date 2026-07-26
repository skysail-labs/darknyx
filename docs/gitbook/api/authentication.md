---
description: "The two-layer Darknyx auth model, account bearer tokens plus per-order trading-key signatures, and how to obtain and use them."
---


# Authentication

{% hint style="info" %}
**TL;DR**

Authentication has **two layers**. An **account bearer token** (`POST
/auth/token`) gates access to the venue. A per-order **Ed25519 trading-key
signature** proves cryptographic ownership of each order. You need the token to
talk to the venue and the signature to place, cancel, or modify an order.
{% endhint %}

## The credential model

Two layers, two questions.

| Layer | Credential | Question it answers |
|---|---|---|
| **Account** | Bearer token | "Is this caller allowed to use the venue?" |
| **Order** | Trading-key signature | "Who cryptographically owns this order?" |

The account layer is operational: it enables rate-limiting and audit, and is
provisioned out of band (you receive an `api_key`, an `api_secret`, and a
`passphrase`). The order layer is cryptographic: a trading key is an Ed25519
keypair you control, and the venue attributes, and ultimately settles, each
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

Open the sole WebSocket endpoint without credentials in the URL, then send the
token in an in-band `login` frame:

```text
wss://<gateway-host>/v1/stream
```

```json
{ "op": "login", "request_id": "login-1", "token": "<access_token>" }
```

The server emits `auth_expired` shortly before expiry. Obtain a fresh token and
send another `login` frame on the same session; subscriptions remain active.

## Token expiry and revocation

Tokens are short-lived (the `expires_in` window). Cache the token in-process and
refresh it before expiry; a request with an expired token returns `401`.

**Expiry is exact.** There is no grace period: a token is refused from the
second `expires_in` elapses, not shortly after. Refresh on a margin rather than
relying on the boundary being soft, and treat `expires_in` as a hard deadline on
both REST and the WebSocket.

To invalidate a token before it expires:

```text
POST /auth/token/revoke
```

with the token in the `Authorization` header. The token is denylisted
immediately; subsequent requests with it return `401`. A revoked token stays
refused for as long as it would otherwise have been accepted.

## Rate limiting on authentication

Verifying credentials is deliberately expensive — that is what makes a stolen
credential database hard to attack offline — so the authentication endpoint is
metered separately from trading:

- **`429`** — this account has exhausted its own authentication allowance.
  The limit is **per account**, so a noisy client throttles only itself. The
  message includes an approximate retry delay.
- **`503`** — credential verification is momentarily at capacity. Requests are
  **refused rather than queued**, so this clears quickly; use a short,
  jittered retry rather than holding the connection open.

An unrecognised `api_key` is rejected before any verification work happens, so
it consumes no allowance — yours or anyone else's.

The practical guidance is the same either way: **authenticate once per token
lifetime, not once per action.** A client that re-authenticates per request will
meet the limit; one that caches its token for the `expires_in` window will never
come close.

## Suspension

An operator can suspend an account. When that happens:

- every token the account currently holds stops being accepted **immediately**,
  on REST and the WebSocket alike — there is no wait for expiry;
- requests with those tokens return **`403`**, not `401`;
- `POST /auth/token` also returns **`403`** with `account disabled`, so
  re-authenticating does not help.

A `403` carrying `account disabled` is therefore not something to retry or work
around; contact the operator. It is distinct from `401`, which means the token
itself is bad and re-authenticating usually resolves it.

Separately, an operator can invalidate every token an account is holding
*without* suspending it — used when a token may have leaked but the credentials
are believed safe. In that case existing tokens return `401` and a fresh
`POST /auth/token` succeeds normally. Because issuance timestamps have
one-second resolution, a client that re-authenticates in the same second may
need one retry.

## The order signature

Placing, cancelling, or modifying an order requires an Ed25519 signature from the
order's trading key, in addition to the bearer token.

- **Place.** Sign the canonical order body. The signature binds every economic
  field of the order (symbol, side, type, amount, price limit, expiry, the
  collateral-note commitment, viewing key, boot session, and nonce) so
  the venue can attribute the order to your key without any per-order on-chain
  transaction.
- **Cancel.** Sign a canonical cancel body over the order id, your trading key,
  a strictly increasing cancel nonce, and the current boot session.
- **Modify.** Sign a cancel of the old order *and* a full new order; both
  signatures must come from the same trading key.

The canonical encodings are fixed-length and unambiguous, so re-encoding from
JSON always yields the same bytes to sign. The SDK constructs and signs these for
you. The exact field layout for each is on the corresponding endpoint page:
[Place Order](../orders/place-order.md), [Cancel Order](../orders/cancel-order.md),
[Modify Order](../orders/modify-order.md).

## Public (unauthenticated) endpoints

These require no token:

- `GET /health`, `GET /system/status`, `GET /time`
- `GET /info`, `GET /attestation`, the `/evidences/*` files
- `GET /instruments`, `GET /instruments/{symbol}`
- `GET /tree/root`
- `GET /transparency`

Everything else requires the bearer token: order management, account-scoped reads
(`/tree/inclusion`, `/tree/leaves`, `/settlement/status`), and the WebSocket
streams.

## Operator controls

Accounts are provisioned and managed through admin-only bearer routes:

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/admin/accounts` | Register an API account. |
| `POST` | `/admin/accounts/{api_key}/disable` | Suspend an account immediately across REST, WebSocket, and new logins. |
| `POST` | `/admin/accounts/{api_key}/enable` | Reinstate a suspended account. |
| `POST` | `/admin/accounts/{api_key}/revoke-tokens` | Invalidate all currently issued tokens without disabling new authentication. |

The venue refuses to disable its last enabled admin account. These routes manage
API access only; they do not receive spending keys or become a custody authority.
