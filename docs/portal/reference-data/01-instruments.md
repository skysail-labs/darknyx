---
sidebar_position: 1
title: Get Instruments
description: List the markets Nyx supports and read a single market's parameters — mints, tick size, minimum order size, and the price oracle.
---

# Get Instruments

:::info TL;DR
Instruments describe the markets you can trade: the base and quote token mints,
the price increment, the minimum order size, and the **oracle** that anchors the
clearing price. Both endpoints are public.
:::

Each Nyx market is a pair of SPL token mints — a base and a quote — together with
the parameters the matching engine needs to clear it. Because Nyx clears each
batch at a single oracle-anchored price (see
[Clearing Price](../trading-concepts/clearing-price)), every instrument names the
oracle that provides its reference price.

## List all instruments

```text
GET /instruments
```

Returns every tradable market. Public — no authentication.

### Example

```bash
curl -s "$GATEWAY/instruments" | jq .
```

### Response

```json
{
  "instruments": [
    {
      "symbol": "SOL-USDC",
      "base_mint": "So11111111111111111111111111111111111111112",
      "quote_mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
      "tick_size": "0.001",
      "min_order_size": "0.01",
      "oracle": {
        "type": "pyth_pull_v2",
        "pubkey": "…",
        "circuit_breaker_bps": 100
      }
    }
  ]
}
```

## Single instrument

```text
GET /instruments/{symbol}
```

Returns one market by symbol. Returns `404` if the symbol is not listed.

### Example

```bash
curl -s "$GATEWAY/instruments/SOL-USDC" | jq .
```

## Field reference

| Field | Type | Description |
|---|---|---|
| `symbol` | string | Market identifier, e.g. `"SOL-USDC"`. Use it as the `symbol` on order requests. |
| `base_mint` | string | Base asset SPL mint (base58). The asset you buy or sell. |
| `quote_mint` | string | Quote asset SPL mint (base58). The asset prices are denominated in. |
| `tick_size` | string | Decimal string; the smallest price increment. Prices must be a multiple of this. |
| `min_order_size` | string | Decimal string; the minimum order amount in base units. |
| `oracle.type` | string | The oracle family providing the reference price (for example, a Pyth pull feed). |
| `oracle.pubkey` | string | The oracle account the engine reads. |
| `oracle.circuit_breaker_bps` | integer | Maximum deviation, in basis points, from the oracle reference that the engine will clear at. The same bound is enforced inside the settlement proof, so a clearing price outside this band cannot settle. |

## How the oracle is used

The oracle reference price is the anchor for the uniform clearing price of each
batch. Two consequences matter to you as a trader:

- **Fair reference.** Both sides of a match settle at the same oracle-anchored
  clearing price; there is no maker/taker ordering within a batch to be gamed.
- **A hard circuit breaker.** `circuit_breaker_bps` caps how far the clearing
  price may move from the oracle. This bound is not just a server policy — it is
  enforced inside the zero-knowledge settlement proof, so a settlement that
  violates it is rejected on-chain. A market whose oracle is stale or wildly
  off simply will not clear rather than clear at a bad price.

See [Clearing Price](../trading-concepts/clearing-price) for how the single
per-batch price is determined.

## Cache semantics

Instrument metadata is static for the lifetime of a deployment — the mints, tick
size, and oracle do not change underneath you mid-session. It is safe to fetch
the list once at startup and cache it.
