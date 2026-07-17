---
sidebar_position: 4
title: Clearing Price
description: How the attested matcher selects one price for a batch and how the settlement proof constrains the resulting arithmetic.
---

# Clearing Price

Each matching interval is a uniform-price batch auction. Crossing orders in the
batch settle at one clearing price, subject to every order's limit and the
market's oracle circuit-breaker policy.

## Selection

The matcher considers eligible bid and ask price levels, chooses the price that
maximizes executable volume, and applies deterministic tie-breaking. A zero-limit
market ask can execute at any positive clearing price, but it is not itself a
price candidate. FIFO priority is preserved within a price level.

A bid is eligible only when the clearing price is at or below its `price_limit`.
An ask is eligible only when the price is at or above its limit; an ask limit of
zero accepts any positive clearing price. IOC, FOK, AON, and minimum-fill rules
further constrain executable volume.

## Oracle circuit breaker

The matcher reads the configured oracle reference and refuses candidate prices
outside the market's circuit-breaker bounds. This protects against a stale or
pathological book clearing arbitrarily far from the reference.

This is an **attested matching-policy guarantee**. The settlement circuit does
not receive the oracle observation or re-run the limit book, so clients rely on
verifying the expected matcher image for oracle-band, limit, FIFO, and
tie-breaking correctness.

## What settlement proves

VALID_MATCH_BATCH binds every active match to the on-chain market mints and
`price_scale`, then proves:

```text
quote_amount = floor(base_amount × clearing_price / price_scale)
```

with a constrained remainder. It also proves conservation, the exact configured
fee, and deterministic ownership of user and protocol outputs. The price and
amount stay private even though their arithmetic is checked.

This division matters: attestation answers "did the expected matcher select a
fair eligible price?"; zero knowledge answers "does this private result conserve
the configured assets at exactly that scaled arithmetic?"

## Trader implications

- `price_limit` is a worst acceptable bound, not a requested execution price.
- Every match in the batch receives the same clearing price.
- There is no maker/taker fee role, although supply and demand can still produce
  price improvement relative to one side's limit.
- Use a capped IOC for an immediate marketable order. A market ask may use zero;
  a bid must always carry a positive cap.

See [Order Types](./order-types) and
[Privacy & Attestation](../how-it-works/privacy-and-attestation).
