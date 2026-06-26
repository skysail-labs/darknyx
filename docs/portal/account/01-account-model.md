---
sidebar_position: 1
title: Account Model
description: How balances work on Nyx, as UTXO-style notes you own on-chain, reconstructed client-side from Merkle proofs and your own keys.
---

# Account Model

:::info TL;DR
Nyx has no server-held balance ledger. Your assets are **UTXO-style notes**
committed on-chain as hashes. Only you, with your spending key, can determine
which notes are yours and what they are worth. You reconstruct your account state
**client-side** from the public Merkle tree plus your keys; the engine never sees
the spending key that would let it do it for you.
:::

## Why there is no balance in `GET /account`

`GET /account` returns the slice of account state the engine legitimately holds:
your **open orders** (the orders you placed that are still in the book). It does
**not** return balances or notes.

On a custodial venue the operator keeps your balance in a database and serves it
on request. That only works because the operator can see what you hold, which is
exactly the position privacy Nyx is built to remove.

On Nyx your balance is the set of **notes** you own. A note is committed on-chain
as a Poseidon hash that seals its owner, value, and token. Determining that a
given note is *yours* and reading its amount requires your **spending key**, and
that key never enters the enclave. So the engine *cannot* compute your balance
for you, by construction. A balance endpoint would either be empty or would
require handing the enclave the one secret the whole design keeps out of it.

Instead, you reconstruct account state yourself:

```text
your spending key  +  the public Merkle tree of note commitments
        │
        ▼
the notes you own  →  their amounts  →  your spendable balance
        │
        ▼
which are unspent (no nullifier published)  →  what you can trade or withdraw
```

This is the trustless design: the data you need is public, and only your keys
turn it into a balance.

## What you read, and from where

| You want | Read | Page |
|---|---|---|
| The current state of the on-chain tree | `GET /tree/root` | [Merkle Proofs](./merkle-proofs) |
| An inclusion proof for one of your notes | `GET /tree/inclusion` | [Merkle Proofs](./merkle-proofs) |
| A page of raw leaves (to rebuild a local mirror) | `GET /tree/leaves` | [Merkle Proofs](./merkle-proofs) |
| Your open orders | `GET /account` (all), or `GET /orders/{order_id}` + the orders stream | [Get Order](../orders/get-order), [Orders Channel](../websocket/orders-channel) |
| Your continuation fills | the fills stream / your durable history | [Fills Channel](../websocket/fills-channel) |
| Venue-wide solvency | `GET /transparency` | [Transparency](./transparency) |
| Your account preferences | `GET`/`PUT /account/settings` | (cancel-on-disconnect default, and so on) |

The **SDK** wraps this: from your seed it derives your keys, scans the tree, and
maintains a local note store of your spendable notes, so in practice you call an
SDK method, not the raw tree endpoints. See
[SDK → TypeScript Client](../sdk/typescript-client).

## The note lifecycle

A note moves through a small set of states, each enforced on-chain by a distinct
record so a note can never be used twice:

```text
 deposit            place order            settle / withdraw
   │                    │                        │
   ▼                    ▼                        ▼
 SPENDABLE  ───────►  LOCKED  ───────►  CONSUMED (and new notes created)
 (in tree,           (pinned by a       (nullified; its value now lives
  no nullifier)       per-order lock)    in the output notes you own)
```

- **Spendable.** The note has an inclusion path in the current Merkle root and
  no nullifier has been published for it. You can back an order with it or
  withdraw it.
- **Locked.** An order references it as collateral; a per-order lock pins it
  between match and settlement so it cannot be double-committed.
- **Consumed.** Settlement (or a withdrawal) has published its nullifier; the
  note is spent. Its value now lives in freshly created output notes (a change
  note for the unfilled remainder, the traded asset, and so on), each a new
  spendable note you own.

Because every touched note produces an on-chain record that blocks a second
touch, double-spends are impossible regardless of what the engine does.

## Recovering your notes

Because your balance is derived, not stored by the venue, you can rebuild it on
any device from one secret: your **master seed**. Everything else follows from it.

- **A deterministic seed.** The SDK can derive your master seed from a **wallet
  signature** over a fixed message, so the same wallet reproduces the same seed on
  any device. There is no separate key file to back up or lose. (You can also use
  a random seed you store yourself.)
- **Keys and notes.** From the seed the SDK derives your trading, spending, and
  viewing keys, scans the public Merkle tree to find the notes you own, and
  regenerates each order's continuation
  [anchors](../trading-concepts/anchor-pool).
- **Change notes.** A change note from a partial fill is recoverable from the
  **encrypted ciphertext stored on-chain at settlement**, written when the order
  was placed with a `viewing_pubkey`. The SDK decrypts the change amount with your
  viewing key and self-verifies it against the on-chain commitment, so change
  notes survive a lost local store, a fresh device, or an engine redeploy. See
  [Fills Channel](../websocket/fills-channel).

The upshot: sign with the same wallet on a new machine and the SDK reconstructs
your full spendable balance from public on-chain data plus your keys. Nothing
about your account lives only on the engine.

## Trading keys vs. spending keys

Two different keys, two different jobs. Keep them distinct.

| Key | Used for | Seen by the enclave? |
|---|---|---|
| **Trading key** | Signing orders (place / cancel / modify). The cryptographic identity an order is attributed to. | The public key, yes, to verify your signature. |
| **Spending key** | Deriving note ownership and nullifiers; authorizing withdrawals. | **Never.** It stays on your client. |

The enclave can verify *who placed an order* (trading key) without ever being
able to determine *what you hold* (spending key). That split is what lets
matching be authenticated while balances stay private.

## Account settings

`GET` / `PUT /account/settings` holds a small set of per-account preferences,
persisted with your account. A `PUT` replaces them wholesale, so send the full
object.

| Setting | Default | Effect |
|---|---|---|
| `cancel_on_disconnect_default` | `false` | When `true`, a [trading socket](../websocket/ws-trading) or [session stream](../websocket/session-stream) for this account cancels your open orders when it disconnects. A socket's own `cancel_on_disconnect` overrides this default. |
