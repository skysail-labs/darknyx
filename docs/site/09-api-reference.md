---
sidebar_position: 2
title: API reference
description: The Nyx enclave's HTTP + WebSocket API — authentication, order lifecycle, settlement status, live fills, and the public attestation and transparency endpoints.
---

# API reference

:::info TL;DR
Everything order-related talks to the **enclave**, not Solana. The API is plain
HTTPS + a WebSocket for live fills, fronted by RA-TLS (a TLS certificate whose
key is held *inside* the attested enclave). Custody operations — deposit,
withdraw, merge — are Solana transactions and are covered in
[Integration](./integration), not here.
:::

The enclave is reached at a gateway URL of the form
`https://<app-id>-8080.<host>.phala.network`. Order endpoints require a bearer
token; attestation, health, the tree root, and transparency are public.

## Authentication

Auth is two layers, and only the inner one is a security boundary.

**Layer 1 — account token (operational).** Exchange API credentials for a
short-lived JWT used for rate-limiting and routing. This is *not* what protects
your funds.

```http
POST /auth/token
Content-Type: application/json

{ "api_key": "...", "api_secret": "...", "passphrase": "..." }
```

```json
{ "token": "eyJ…", "expires_in": 900 }
```

Send it as `Authorization: Bearer <token>` on every protected call.

**Layer 2 — trading-key signature (the real boundary).** Every order body is
signed with your **trading key** (an Ed25519 keypair distinct from your Solana
wallet). The enclave verifies this signature; the bearer token alone can't place
an order.

:::tip Why two layers
The token is a throwaway identity for fairness and rate-limiting. The trading
key is what actually authorizes a trade — and because it's not your wallet,
even the enclave never learns which wallet is behind an order. See
[Trust model](./trust-model).
:::

## Orders

### Place an order

```http
POST /orders
Authorization: Bearer <token>
```

The body carries the order parameters, the input note's opening, a continuation
**anchor pool** (pre-supplied nullifiers that let the matcher roll a partial
fill forward without a round-trip — see [Matching layer](./matching-layer)), and
your trading-key signature over the canonical body.

```jsonc
{
  "symbol": "SOL-USDC",
  "side": "bid",                 // "bid" | "ask"
  "order_type": "limit",
  "amount": "1000000",
  "price_limit": "150000000",
  "min_fill_size": "0",
  "expiry_slot": 1000000,
  "order_id": "…",               // deterministic, client-derived
  "note_commitment": "…",
  "user_commitment": "…",
  "trading_key": "…",
  "trading_key_signature": "…",
  "merkle_root": "…",
  "valid_input_proof": "…",      // proves the collateral note is real
  "anchors": [ /* continuation (inner_hash, nullifier) pairs */ ]
}
```

A successful response acknowledges intake and returns the order's state. The
order then rests in the hidden book until it matches in a batch auction.

### Cancel / query an order

```http
DELETE /orders/{order_id}     # cancel (trading-key-signed)
GET    /orders/{order_id}     # current state
```

### Settlement status

Order intent never appears in a Solana transaction, so to follow a fill on-chain
you ask the enclave to map a batch to its settle signatures:

```http
GET /settlement/status/{batch_id}
```

```jsonc
{
  "batch_id": "…",
  "state": "settled",          // queued | proving | settling | settled | failed
  "signatures": { "verify": "…", "settles": ["…"], "close": "…" }
}
```

## Live fills (WebSocket)

For a fill to surface in seconds rather than by polling, subscribe to your
per-account fill stream. The connection is **per-account**: you only ever
receive fills for orders you placed.

```text
wss://<gateway>/ws/fills?token=<bearer>
```

Each message is a `FillMemo` carrying everything you need to reconstruct and
store the resulting change note. If the stream lags past its buffer, the server
closes with a resync code; the recommended client flow is **"backfill then
tail"** — recover any gap from the off-enclave fills indexer (keyed by your
deterministic order IDs), then resume the live stream. The SDK does this for
you.

:::note Account-agnostic by design
The fills indexer answers queries *by order ID*, never by wallet. It can serve
your history without ever learning who you are — the order IDs are derived from
your own seed.
:::

## Public endpoints

These need no token — they're how anyone (including you, before you trust the
enclave) verifies Nyx.

### Attestation & info

```http
GET /attestation     # the TDX quote + the enclave's signing pubkey
GET /info            # app id, instance id, compose_hash, signer pubkey
GET /health          # liveness
```

`GET /attestation` returns the Intel-signed TDX quote. A client verifies the
quote, checks the measured image (`compose_hash`) against the one registered
on-chain, and confirms the quote is bound to the signing key — *before* sending
any order. The SDK ships this check as one call. See
[Trust model](./trust-model).

### Merkle tree reads

The enclave mirrors the on-chain tree so clients can build inclusion proofs
without scanning the chain. The tree is sharded; pass `?tree_id` to pick a shard
(default 0).

```http
GET /tree/root?tree_id=0                       # current root + leaf count (public)
GET /tree/inclusion?commitment=<hex>&tree_id=0 # a note's inclusion proof (bearer)
GET /tree/leaves?from=<n>&to=<m>&tree_id=0     # page leaves to re-sync (bearer)
```

:::caution These are a convenience, not a trust layer
Any inclusion proof the enclave serves is *self-verifying*: re-hash the leaf and
siblings to the root, compare against the root you read **directly from Solana**,
and reject if they differ. A dishonest enclave cannot forge an inclusion proof
without you catching it on-chain.
:::

### Transparency (proof of reserves)

```http
GET /transparency
```

Returns, unauthenticated and verifiable by anyone: the mirror root and total
leaf count (summed across shards), each mint's on-chain outstanding-note total
versus the vault's actual SPL balance, the engine's identity, and aggregate
settle stats. Reserves can be checked against the chain at any time.

## A note on encoding

Field encodings (hex vs base58, byte lengths, the canonical order-body layout
the trading-key signs) are exact and enforced byte-for-byte across the SDK and
the enclave. Use the SDK builders rather than hand-rolling request bodies — it
guarantees the canonical form the enclave will accept.
</content>
