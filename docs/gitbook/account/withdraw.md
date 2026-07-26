---
description: "Move value out of the pool back to an SPL token account, proven in zero knowledge so the chain releases your tokens."
---


# Withdraw

{% hint style="info" %}
**TL;DR**

Withdrawing spends a note out of the vault and releases the tokens to an SPL token
account. It is an on-chain action gated by a zero-knowledge proof: you prove the
note is in the tree and yours, the program publishes the note's **nullifier** so
it cannot be spent again, and it transfers the tokens out. The withdrawal does not
reveal which deposit the value came from.
{% endhint %}

## What a withdrawal does

A withdrawal is a zero-knowledge spend (see [Shielded Pool](../how-it-works/shielded-pool.md)).
You produce a proof that the note exists under a recent Merkle root, that you
own it, **and that it is being paid to one specific destination**; the vault
program verifies the proof, publishes the note's nullifier, and releases the
tokens to that account. Like a deposit, it is a direct **on-chain** action and
does not involve the matching engine.

You need the note's plaintext (which you hold locally) and its Merkle leaf index.
The SDK assembles the proof and the transaction.

{% hint style="warning" %}
**The proof is bound to the destination account**

The destination token account is a public input to the withdrawal proof, so a
proof authorises paying *that* account and nothing else. Submitting it with a
substituted destination fails verification.

This matters because a withdrawal transaction is public the moment it reaches
the network — including one that lands and then **reverts**. A reverted
transaction still publishes its proof in the ledger permanently while creating
none of the guard accounts, leaving the note spendable. Without destination
binding, anyone who read those bytes could have resubmitted the same proof and
redirected the payment to themselves.

Practically: build the proof for the exact account you intend to receive the
tokens. Reusing a proof against a different destination will not work, and does
not need to.
{% endhint %}

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

{% hint style="warning" %}
**Proofs are generated against a recent root**

The inclusion proof is tied to a specific Merkle root. The vault keeps a bounded
window of recent roots, so a withdrawal must land while its root is still in that
window. The SDK reads a current root when it builds the proof; if a withdrawal
fails as stale, rebuild it against the latest root and resubmit. See
[Merkle Proofs](./merkle-proofs.md).
{% endhint %}

## A note involved in an order

A resting order reserves its collateral commitment **inside the venue**, but
does not create an on-chain lock merely by being accepted. Cancel the resting
order before withdrawing the note so the venue cannot later match an order whose
collateral you have removed.

Once an order is matched and becomes `pending_settlement`, the engine creates a
commitment-keyed **on-chain lock**. A live lock blocks withdrawal while the
settlement may still land. It carries an expiry, and at that slot it stops
blocking withdrawal or merge automatically—even if the expired lock account has
not yet been closed.

The permissionless release instruction and the engine's sweeper only close an
**expired** lock and reclaim its rent; neither can release a live lock early. If
a withdrawal fails because of a lock, check its expiry and wait for that
bounded settlement window.
