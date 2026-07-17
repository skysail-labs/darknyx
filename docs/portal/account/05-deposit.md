---
sidebar_position: 5
title: Deposit
description: Move SPL tokens into the vault through a proof-gated deposit that hides the shielded note owner and remains recoverable from seed plus chain.
---

# Deposit

:::info TL;DR
A deposit moves SPL tokens into the Solana vault and appends a new note
commitment. Before custody changes, the vault verifies a VALID_DEPOSIT proof that
the commitment contains the public mint and amount and a valid hidden owner. The
transaction reveals the funding signer, mint, and gross amount, but not the
wallet-wide note owner or the note's inner hash.
:::

## What a deposit does

The client constructs a recoverable note, proves it is well formed, and sends a
direct Solana transaction. The vault verifies the proof first; an invalid proof
cannot transfer tokens, increment liabilities, or append a leaf.

The public transaction carries:

- the destination tree shard;
- token mint and deposit amount;
- the opaque note commitment;
- a field-safe recovery nonce; and
- the Groth16 proof.

The spending key, owner blinding, owner commitment, and inner hash remain private
proof witnesses. This closes the old deposit-boundary link where publishing one
wallet-wide owner commitment could cluster every note made by that wallet.

## Using the SDK

```typescript
import { getDepositFunction } from "@nyx/sdk";

const deposit = getDepositFunction({ client });

const receipt = await deposit({
  depositor,                     // fee payer and deposit authority
  tokenMint,
  amount: 100_000_000n,      // smallest token units
  depositorTokenAccount,
  depositIndex: 0n,           // increment for each deposit from this seed
});
// receipt includes signature, treeId, leafIndex, commitment, and note opening
```

The configured prover suite generates VALID_DEPOSIT locally. The SDK submits the
transaction and reads the emitted tree shard and leaf index so the resulting
note can immediately back an order, merge, or withdrawal.

## Recovery

Deposits are recoverable from the encrypted master-seed backup plus finalized
chain history. During recovery, the client:

1. re-derives the wallet's hidden owner commitment from the seed;
2. reads the public recovery nonce from the deposit instruction;
3. derives the hidden deposit inner hash from those two values; and
4. reconstructs and verifies the note commitment.

Keep a local note store for fast startup, but it is a cache rather than the only
copy of the deposit opening. Use the versioned authenticated seed-backup format;
wallet-message signatures are not a master-seed mode.

## Privacy boundary

Proof-gating does not hide the SPL transfer itself. A chain observer still sees
which Solana account funded which mint and gross amount. What it removes is the
reusable shielded-owner label: the public transaction no longer exposes the
owner commitment or inner hash needed to associate that deposit with the
wallet's other notes.

See [Account Model](./account-model) for note recovery and
[Withdraw](./withdraw) for the public exit boundary.
