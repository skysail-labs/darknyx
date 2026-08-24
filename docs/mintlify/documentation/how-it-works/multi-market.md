---
description: "How one attested Darknyx venue serves several independently governed spot markets through one endpoint, session, and trust check."
---


# Multi-Market Venue

{% hint style="info" %}
**TL;DR**

One Darknyx confidential VM can serve several spot pairs. Each pair has its own
order book, oracle, limits, and on-chain market configuration, while traders use
one verified enclave origin, one attestation check, and one authenticated stream. Matches from
different markets never share a proof batch.
{% endhint %}

## Why markets share one venue

Running one confidential VM per pair would multiply endpoints, logins, and
attestation checks. It would also make a client decide which machine to trust
before it could even discover a market.

Darknyx instead presents one venue:

```text
one verified origin + one CVM + one /v1/stream session
                           │
             ┌─────────────┼─────────────┐
             ▼             ▼             ▼
          SOL-USDC      BTC-USDC      another pair
          own book      own book       own book
```

`GET /instruments` lists every pair available in that session. An order's signed
`symbol` routes it to exactly one isolated book, and later reads, cancels, and
stream events follow that routing without asking the client to switch endpoints.

## What stays isolated

Every configured pair has:

- a distinct base/quote mint pair and on-chain `MarketConfig`;
- its own order book, clearing-price calculation, oracle feed, and batch sequence;
- its own tick size, minimum size, price scale, and circuit-breaker policy; and
- a separate settlement proof batch, even when several markets clear on the same
  matching tick.

The settlement proof binds one market's governed mints and price scale to every
active match in its batch. A SOL-USDC match and a BTC-USDC match therefore cannot
be mixed into one proof or redirected between books.

An atomic modify also stays within the original market. To move intent to another
pair, cancel the old order and submit a fresh signed order for the new symbol.

## What is shared

The books share the confidential VM's proving, Solana submission, Merkle-shard,
and network capacity. That gives traders a simpler trust experience, but it also
creates shared fate: a venue-wide attestation, signer, or finalized-governance
mismatch pauses **new** trading across every pair.

Cancels and settlement reconciliation continue during that pause. This is a
fail-closed safety choice: the venue does not keep accepting private intent when
its authority or governed market view is uncertain.

Oracle health is isolated more narrowly. A stale, missing, replayed, or
unauthenticated feed pauses only the markets bound to that feed; healthy books
continue using the same attested session. `GET /instruments` exposes a dynamic
`trading_enabled` flag per market, while order writes recheck the gate to close
snapshot races.

## Capacity and future scaling

The number of pairs a machine can serve is a measured capacity decision, not a
branding limit. Operators watch settlement queue age, submit-to-finality
latency, proof contention, RPC errors, CPU and memory headroom, and confirmed
throughput before admitting another market.

If a venue eventually needs more than one confidential-VM cluster, endpoint
discovery must be anchored to finalized governance and each selected endpoint
must be attested independently. A mutable website list alone is not a sufficient
trust root. Today, all instruments returned by one endpoint belong to the one
already-attested venue session.

See [Get Instruments](/api-reference/instruments) for market metadata,
[Privacy & Attestation](./privacy-and-attestation.md) for the trust check, and
[Settlement](./settlement.md) for the one-market-per-proof boundary.
