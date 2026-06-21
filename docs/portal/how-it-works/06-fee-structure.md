---
sidebar_position: 6
title: Fee Structure
description: How trading fees work on Nyx — a basis-point protocol fee both sides pay, collected as notes at settlement and pre-funded by each order's collateral.
---

# Fee Structure

:::info TL;DR
Nyx charges a flat **protocol fee** in basis points (for example, 30 bps). **Both
sides of a trade pay their own fee.** Each order pre-funds its fee as part of its
collateral, and the fee is collected at settlement as a **fee note** minted to the
protocol — so fees, like everything else, settle privately on-chain.
:::

## The fee model

Every trade pays a protocol fee proportional to its value:

```text
fee = trade_value × fee_rate_bps / 10_000
```

Two principles define how it is applied:

- **Both legs pay.** The bid and the ask each pay a fee on their own side of the
  trade — there is no maker rebate or taker surcharge, because a batch auction has
  no maker/taker roles (see [Clearing Price](../trading-concepts/clearing-price)).
- **The fee is pre-funded.** An order must lock enough collateral to cover *both*
  its nominal cost *and* its own fee. The required collateral is:

```text
required collateral = nominal cost + fee
```

where the nominal cost is `amount × price_limit` for a bid (quote units) or
`amount` for an ask (base units). The engine derives this at intake; if an order's
collateral note does not cover it, the order is rejected as conservation-breaking
rather than allowed to under-pay.

:::note The SDK handles fee-inclusive collateral
You do not compute the fee yourself. The SDK sizes an order's collateral note to
cover the nominal cost plus the fee, so the order passes the conservation check.
This is also why a place-order request is fully collateralized up front — the fee
is already accounted for in the note you deposited.
:::

## How fees are collected

Fees are collected **at settlement**, in the same atomic, proven step as the rest
of the trade. When a batch settles, the output notes include the protocol's **fee
notes** — one per asset side — minted alongside the traded asset and any change
note. There is no separate fee transaction and no off-chain fee accounting: the
fee moves as a note, on-chain, under the same zero-knowledge proof that gates the
trade.

```text
settle a match ──► outputs:
                     • counterparty's filled asset
                     • your change note (unfilled remainder)
                     • fee note (base side)   → protocol
                     • fee note (quote side)  → protocol
```

Because the fee is charged on the actual cleared amount, an order that locked
fee-inclusive collateral on its worst-case (limit) price and then fills at a better
clearing price gets the surplus back as part of its change note — you never
overpay the fee on price improvement.

## Worked example

Suppose the fee rate is 30 bps (0.30%) and you place a bid to buy `10` base at a
limit of `150` quote each:

```text
nominal cost   = 10 × 150        = 1500 quote
fee            = 1500 × 30 / 10_000 = 4.5 quote
collateral     = 1500 + 4.5      = 1504.5 quote   ← what your note must cover
```

If the batch clears at `148`, you pay `1480` for the fill, your fee is charged on
the cleared amount, and the difference comes back to you as a change note — all in
one settled, proven step.

## Why fees settle as notes

Collecting fees as on-chain notes keeps the whole system consistent: there is one
value-movement mechanism (notes, gated by proofs), one place fees are visible (the
public [transparency](../account/transparency) reserves, which account for every
mint including the protocol's), and no privileged off-chain ledger. Fees are as
private and as verifiable as trades.
