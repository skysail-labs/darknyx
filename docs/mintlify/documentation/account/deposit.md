---
description: "Move SPL tokens into the vault through a proof-gated deposit that hides the shielded note owner and remains recoverable from seed plus chain."
---


# Deposit

<Info>
**TL;DR**

A deposit moves SPL tokens into the Solana vault and appends a new note
commitment. Before custody changes, the vault verifies a VALID_DEPOSIT proof that
the commitment contains the public mint and amount and a valid hidden owner. The
transaction reveals the funding signer, mint, and gross amount, but not the
wallet-wide note owner or the note's inner hash.
</Info>

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

The spending key, owner commitment, note secret, and inner hash remain private
proof witnesses. This closes the old deposit-boundary link where publishing one
wallet-wide owner commitment could cluster every note made by that wallet.

## Using the SDK

```typescript
import { getDepositFunction } from "@darknyx/sdk";

const deposit = getDepositFunction({ client });

const receipt = await deposit({
  depositor,                     // fee payer and deposit authority
  tokenMint,
  amount: 100_000_000n,      // smallest token units
  depositorTokenAccount,
});
// receipt includes signature, treeId, leafIndex, noteCommitment, and notePlaintext
```

The configured prover suite generates VALID_DEPOSIT locally. The SDK submits the
transaction and reads the emitted tree shard and leaf index so the resulting
note can immediately back an order, merge, or withdrawal.

<Warning>
**Fresh deposits and exact retries are separate APIs**

The ordinary SDK deposit call rejection-samples a fresh canonical BN254
recovery nonce from the platform CSPRNG. Callers do not maintain a deposit
counter, so restoring a seed cannot silently restart one and recreate an old
commitment. If a transaction result is ambiguous, persist the nonce delivered
by `onRecoveryNonceGenerated` and redrive through the explicitly named
`getDepositRetryFunction`; that path intentionally recreates the same note.

That rejection is deliberate and it is protecting you. A duplicate commitment
used to be accepted: both deposits moved tokens in, but only one could ever be
consumed. Both copies would derive the same note-use tag, so the first spend
would create the shared consume-once record and the second copy would be
unusable. The duplicate-deposit guard is therefore still keyed on the public
commitment, even though later note use is keyed on the unlinkable tag. Without
that guard, the second deposit's tokens would be silently unrecoverable and,
because the vault was over-collateralised rather than under, no solvency alarm
would fire.

The vault still rejects duplicate commitments. Client-side randomness is a UX
and recovery safeguard, not a replacement for consensus-enforced deposit-once
semantics against retries or malformed clients.
</Warning>

## Recovery

Deposits are recoverable from the encrypted master-seed backup plus finalized
chain history. During recovery, the client:

1. re-derives the wallet's hidden owner commitment from the spending key;
2. reads the public recovery nonce from the deposit instruction;
3. re-derives the note-specific secret from the seed and recovery nonce;
4. derives the hidden deposit inner hash from the nonce and note secret; and
5. reconstructs and verifies the note commitment.

Keep a local note store for fast startup, but it is a cache rather than the only
copy of the deposit opening. Use the versioned authenticated seed-backup format;
wallet-message signatures are not a master-seed mode.

## Privacy boundary

Proof-gating does not hide the SPL transfer itself. A chain observer still sees
which Solana account funded which mint and gross amount. What it removes is the
reusable shielded-owner label: the public transaction no longer exposes the
owner commitment or inner hash needed to associate that deposit with the
wallet's other notes.

See [Account Model](./account-model.md) for note recovery and
[Withdraw](./withdraw.md) for the public exit boundary.
