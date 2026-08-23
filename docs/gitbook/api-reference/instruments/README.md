---
description: "List supported markets and read their mints, raw protocol units, and oracle feed identifier."
---


# Get Instruments

The instrument endpoints are public. They describe every governed market
available through the currently connected, attested venue. One confidential VM
can expose several independently routed books through this single list.

## List instruments

{% openapi src="https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml" path="/instruments" method="get" %}
https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml
{% endopenapi %}

The response is a JSON **array**, not an object envelope:

```json
[
  {
    "symbol": "SOL-USDC",
    "base_mint": "So11111111111111111111111111111111111111112",
    "quote_mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    "tick_size": "1000",
    "min_order_size": "10000000",
    "trading_enabled": true,
    "oracle": {
      "type": "pyth_push_v2",
      "pubkey": "ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d"
    }
  }
]
```

## Get one instrument

{% openapi src="https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml" path="/instruments/{symbol}" method="get" %}
https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml
{% endopenapi %}

Returns the same object shape or `404` when the symbol is not configured on this
venue. Use the returned `symbol` unchanged in signed order requests.

## Fields

| Field | Type | Meaning |
|---|---|---|
| `symbol` | string | Market identifier used in order requests. |
| `base_mint` | string | Base SPL mint, base58. Order `amount` is measured in this asset's smallest units. |
| `quote_mint` | string | Quote SPL mint, base58. |
| `tick_size` | string | Raw integer price increment in protocol price units. |
| `min_order_size` | string | Raw integer minimum base amount in smallest token units. |
| `trading_enabled` | boolean | Current readiness for new placement, modification, and matching on this market. Cancellation and settlement recovery remain available when false. |
| `oracle.type` | string | Oracle adapter used by the matcher (`pyth_pull_v2` or `pyth_push_v2`). |
| `oracle.pubkey` | string | Pyth feed identifier. Despite the wire name, this value may be a 32-byte hex feed id rather than a base58 Solana account. |

Use the SDK's market helpers and the on-chain `MarketConfig` decimals and
`price_scale` to format raw values for humans. Do not parse these strings as
floating-point numbers.

## Oracle and circuit breaker

The attested matcher reads the configured oracle and refuses clearing prices
outside its configured circuit-breaker band. Signed oracle publish time,
replay ordering, and market-unit conversion are checked before that comparison.
If the authenticated oracle becomes stale or invalid, new order placement,
modification, and matching pause only for markets bound to that feed while
healthy markets continue. The response then reports `trading_enabled: false`
for the affected market. Cancellation and settlement recovery remain
available. Order writes still recheck readiness and may race this public
snapshot with a fail-closed `503`. The matcher also enforces every trader's
limit and the uniform-clearing selection rule.

Those market-policy checks are **not** re-executed inside VALID_MATCH_BATCH. The
settlement proof binds the market mints and `price_scale`, proves scaled floor
arithmetic, conservation, fees, and deterministic outputs. A client that relies
on oracle and limit fairness therefore verifies the expected matcher image as
described in [Privacy & Attestation](/documentation/how-it-works/privacy-and-attestation).

The current REST object does not expose `circuit_breaker_bps`; read the finalized
on-chain `MarketConfig` when that value is required for independent monitoring.

## One endpoint, several books

All instruments in the array share the same verified enclave origin,
bearer-token session, boot identity, and attestation policy. REST and
`/v1/stream` use separate TLS sockets, and each socket is checked against that
same boot identity. The signed `symbol` selects one isolated book. A match proof
never mixes symbols, and an atomic modify cannot move an order between
markets—cancel and place a fresh order when changing pairs.

See [Multi-Market Venue](/documentation/how-it-works/multi-market) for the isolation and
shared-capacity model.

## Cache semantics

Static instrument metadata—symbol, mints, tick/minimum sizes, and oracle
identity—is a boot-time snapshot and may be cached for a connected session.
`trading_enabled` is dynamic readiness, not reference metadata: refresh it after
status changes, reconnects, and a racing place/modify `503`. Governance can
update market configuration on-chain. The venue continuously checks its
finalized governed view and pauses new trading on drift; reconnect and refresh
the static fields after the operator deploys the approved configuration.
