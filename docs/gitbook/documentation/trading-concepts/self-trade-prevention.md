---
description: "How Darknyx prevents accidental self-matches using note-bound owner identity plus trading-key equality."
---


# Self-Trade Prevention

{% hint style="info" %}
**TL;DR**

Orders backed by notes with the same **owner commitment** never match each other,
even when they use different trading keys. Trading-key equality is checked as a
second guard. If your bid and ask cross, the engine skips that self-pair and
keeps both eligible against other traders.
{% endhint %}

## The rule

The primary identity is the collateral note's **owner commitment**. The enclave
re-derives the signed note commitment from its opening at intake, so a caller
cannot simply claim a different owner for a note they do not control. The normal
SDK derives one wallet-level owner commitment and reuses it across that wallet's
notes.

The matcher also compares trading keys. A self-pair is skipped if **either** the
note-bound owner commitment or the trading key matches.

```text
same wallet, same key       →  skipped
same wallet, different keys →  skipped
different owners            →  eligible to match
```

Skipped orders are not automatically cancelled. They remain eligible to match
with a different owner in the same batch or a later tick.

## Why a single behavior

On a continuous order book, self-trade prevention comes in flavors (cancel the
resting side, cancel the incoming side, cancel both) because there is a maker and
a taker to choose between. A Darknyx batch has no maker/taker ordering: all crossing
orders clear together at one price (see [Clearing Price](./clearing-price.md)). There
is no "resting vs. incoming" side to pick, so the honest behavior is a single
rule, **two orders from one note owner never match each other**, and the orders
remain available to match against everyone else.

## What it protects

- **No accidental wash trades.** A market maker quoting both sides cannot
  accidentally trade two notes from the same wallet, even when strategies use
  separate trading keys.
- **Cleaner execution records.** Every fill is against a distinct note owner.

## What it is not

This is not proof of unique human identity. A user can deliberately create a
second wallet identity—or rotate the owner blinding used for new notes—and the
two owner commitments will look like distinct counterparties. Preventing that
kind of pseudonymous wash trading requires an identity or surveillance policy
outside the matching rule.

The protection is therefore strong against accidental self-matching within the
normal wallet model, not a Sybil-resistance claim.
