---
sidebar_position: 1
title: Get Instruments
description: List supported markets and read their mints, raw protocol units, and oracle feed identifier.
---

# Get Instruments

The instrument endpoints are public. They describe the market metadata captured
when the confidential matcher booted.

## List instruments

```text
GET /instruments
```

The response is a JSON **array**, not an object envelope:

```json
[
  {
    "symbol": "SOL-USDC",
    "base_mint": "So11111111111111111111111111111111111111112",
    "quote_mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    "tick_size": "1000",
    "min_order_size": "10000000",
    "oracle": {
      "type": "pyth_pull_v2",
      "pubkey": "ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d"
    }
  }
]
```

## Get one instrument

```text
GET /instruments/{symbol}
```

Returns the same object shape or `404` when the symbol is not configured.

## Fields

| Field | Type | Meaning |
|---|---|---|
| `symbol` | string | Market identifier used in order requests. |
| `base_mint` | string | Base SPL mint, base58. Order `amount` is measured in this asset's smallest units. |
| `quote_mint` | string | Quote SPL mint, base58. |
| `tick_size` | string | Raw integer price increment in protocol price units. |
| `min_order_size` | string | Raw integer minimum base amount in smallest token units. |
| `oracle.type` | string | Oracle adapter used by the matcher. |
| `oracle.pubkey` | string | Pyth feed identifier. Despite the wire name, this value may be a 32-byte hex feed id rather than a base58 Solana account. |

Use the SDK's market helpers and the on-chain `MarketConfig` decimals and
`price_scale` to format raw values for humans. Do not parse these strings as
floating-point numbers.

## Oracle and circuit breaker

The attested matcher reads the configured oracle and refuses clearing prices
outside its configured circuit-breaker band. It also enforces every trader's
limit and the uniform-clearing selection rule.

Those market-policy checks are **not** re-executed inside VALID_MATCH_BATCH. The
settlement proof binds the market mints and `price_scale`, proves scaled floor
arithmetic, conservation, fees, and deterministic outputs. A client that relies
on oracle and limit fairness therefore verifies the expected matcher image as
described in [Privacy & Attestation](../how-it-works/privacy-and-attestation).

The current REST object does not expose `circuit_breaker_bps`; read the finalized
on-chain `MarketConfig` when that value is required for independent monitoring.

## Cache semantics

Instrument metadata is a boot-time snapshot. Cache it for a connected session,
then refresh after a reconnect or engine restart. Governance can update market
configuration on-chain; a new engine boot reads the current configuration.
