---
sidebar_position: 6
title: Withdraw
description: Move value out of the pool back to an SPL token account, proven in zero knowledge so the chain releases your tokens.
---

# Withdraw

:::info TL;DR
Withdrawing spends a note out of the vault and releases the tokens to an SPL token
account. It is an on-chain action gated by a zero-knowledge proof: you prove the
note is in the tree and yours, the program publishes the note's **nullifier** so
it cannot be spent again, and it transfers the tokens out. The withdrawal does not
reveal which deposit the value came from.
:::

## What a withdrawal does

A withdrawal is a zero-knowledge spend (see [Shielded Pool](../how-it-works/shielded-pool)).
You produce a proof that the note exists under a recent Merkle root and that you
own it; the vault program verifies the proof, publishes the note's nullifier, and
releases the tokens to your destination token account. Like a deposit, it is a
direct **on-chain** action and does not involve the matching engine.

You need the note's plaintext (which you hold locally) and its Merkle leaf index.
The SDK assembles the proof and the transaction.

## Using the SDK

```typescript
import { getWithdrawFunction } from "@darknyx/sdk";

const withdraw = getWithdrawFunction({ client /* + prover */ });

const receipt = await withdraw({
  payer,                          // fee-payer / signer for the tx
  tokenMint,
  amount: 100_000_000n,
  destinationTokenAccount,        // SPL token account to receive the tokens
  notePlaintext: {                // the note you are spending (from your store)
    tokenMint,
    amount: 100_000_000n,
    ownerCommitment,
    innerHash,
  },
  leafIndex,                      // the note's Merkle leaf index
  treeId: 0,                      // the shard the note lives in (default 0)
});
// receipt: { signature, nullifier, merkleRoot }
```

## What a withdrawal reveals

A withdrawal is a real token transfer out of the pool, so the **amount** and the
**destination account** are visible on-chain, as they must be for the tokens to
land. What stays hidden is the link to the rest of your activity: the published
nullifier is unlinkable to the note commitment, so an observer cannot tie the
withdrawal back to the deposit or trade that produced the note.

:::caution Proofs are generated against a recent root
The inclusion proof is tied to a specific Merkle root. The vault keeps a bounded
window of recent roots, so a withdrawal must land while its root is still in that
window. The SDK reads a current root when it builds the proof; if a withdrawal
fails as stale, rebuild it against the latest root and resubmit. See
[Merkle Proofs](./merkle-proofs).
:::
