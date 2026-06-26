---
sidebar_position: 5
title: Deposit
description: Move SPL tokens into the vault, where they become a private note you can trade or withdraw.
---

# Deposit

:::info TL;DR
A deposit is an on-chain transaction that moves SPL tokens into the vault and
mints a private **note** for you, a commitment added to the Merkle tree. You sign
it with your **wallet**, not your trading key, and the deposit never touches the
matching engine. Record the resulting note locally: deposit notes are the one
thing you must back up yourself.
:::

## What a deposit does

Depositing transfers tokens from your SPL token account into the vault program and
appends a note commitment to the on-chain tree. From that point your balance is
the note, not a ledger entry: the amount, owner, and token are sealed inside the
commitment, and only your keys can recognize and spend it (see
[Account Model](./account-model)).

A deposit is a direct **on-chain** action. It is not an API call to the engine,
and it does not require a bearer token. The engine only ever sees the note later,
as committed collateral when you place an order.

## Using the SDK

```typescript
import { getDepositFunction } from "@nyx/sdk";

const deposit = getDepositFunction({ client });

const receipt = await deposit({
  tokenMint,                    // 32-byte mint of the asset
  amount: 100_000_000n,         // base units
  depositorTokenAccount,        // your SPL token account for that mint
});
// receipt carries the new note's commitment and its Merkle leaf index.
```

The SDK builds the note opening, sends the on-chain deposit transaction, and reads
the new leaf back from the deposit event so the note is immediately spendable.

## Record your deposit notes

:::caution Deposit notes are not seed-recoverable
A deposit note's secret opening comes from a per-deposit counter you own, not from
a chain-readable ciphertext. That means a deposit note **cannot** be reconstructed
from your seed alone on a fresh device. Store each deposit note in your local note
store (the SDK exposes `depositNoteFromReceipt` for this) and keep that store
backed up.

This is the one exception to "recover everything from your seed." Trade **change
notes** are recoverable from on-chain data (see [Fills Channel](../websocket/fills-channel)),
but the original deposits are not.
:::

## After depositing

The new note is **spendable**. You can:

- back an order with it (see [Place Order](../orders/place-order)),
- [merge](../how-it-works/shielded-pool#consolidating-notes) it with other notes
  to form a larger one, or
- [withdraw](./withdraw) it back to an SPL token account.
