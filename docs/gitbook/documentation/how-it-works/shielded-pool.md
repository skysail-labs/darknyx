---
description: "How balances are held as shielded notes, accumulated in Merkle-tree shards and protected from replay by path-specific on-chain records."
---


# Shielded Pool

{% hint style="info" %}
**TL;DR**

Your balance on Darknyx is a set of **notes**, UTXO-style values committed on-chain
as Poseidon hashes. Commitments live in Merkle-tree shards. Every use publishes
an unlinkable, circuit-derived note-use tag and all consumption paths share the
same tag-keyed replay guard. Zero-knowledge proofs enforce valid state
transitions without exposing shielded note openings.
{% endhint %}

## Notes, not balances

A custodial venue stores your balance as a number in a database. Darknyx stores it as
a set of **notes**. A note is a commitment, a Poseidon hash, to four things:

```text
note commitment = Hash( token mint, amount, owner, inner_hash )
```

The commitment reveals none of its inputs. From the outside, a note is an opaque
32-byte leaf in a tree. Only the owner, with their spending key, can recognize
which notes are theirs and read the amounts. This is what makes position privacy a
property of the data structure rather than a policy.

## The Merkle tree

Every note commitment is appended to an on-chain incremental **Merkle tree**. The
tree's root is a single hash summarizing every note that exists. To use a note you
prove, in zero knowledge, that it is a leaf under the current root, without
revealing *which* leaf.

```text
                       root  (one hash over all notes)
                      /    \
                   …          …
                 /   \      /   \
              leaf  leaf  leaf  leaf …      ← each leaf is a note commitment
               │
               └─ your note: you hold a secret opening + an inclusion path
```

The tree is **sharded** for settlement throughput (several independent subtrees,
each with its own root), but conceptually it is one accumulator of all
commitments. You read roots and inclusion paths through the
[Merkle Proofs](/api-reference/tree) endpoints.

## Replay guards prevent double-spends

A commitment proves a note *exists*. A withdrawal proof also derives a
**nullifier** from the spending key and private inner hash. The shared on-chain
consume-once handle, however, is the note-use tag:

- `note_use_tag = Hash(note_commitment, inner_hash)` is **unlinkable** to the
  public leaf without the private inner hash, and
- it is **deterministic**: every lock, settle, merge, or withdrawal of the same
  note addresses the same `ConsumedNoteEntry`, so the second use collides.

```text
use note ──► publish note-use tag
                     │
   try to use it again ──► same consumed-note PDA already exists ──► rejected
```

Settlement payload v11 publishes neither input nullifiers nor input commitments.
Instead, the zero-knowledge circuits derive unlinkable note-use tags from each
commitment and its private inner hash; lock, settlement, withdrawal, and merge
derive their PDAs from those tags. A second attempt collides with the existing
lock or shared `ConsumedNoteEntry`, while an observer cannot string-match the
handle to its Merkle leaf. Deposit
also rejects a commitment that has already been appended, so repeating a
deterministic deposit cannot move in a second amount that the same commitment
could never spend. In every path, replay prevention is enforced on-chain rather
than left to the matcher.

## The amount-independent inner hash

Each note's commitment and its nullifier are both anchored on a single
amount-independent value, the note's **inner hash**. For a match output, the
settlement circuit derives the new inner as
`Poseidon3(24, consumed_input_inner, role)`. The matcher can therefore re-lock a
partial-fill remainder without caller-selected output randomness or a per-fill
round-trip, while the client can independently reproduce the same opening.

## Spending in zero knowledge

To withdraw or merge, the client produces a zero-knowledge proof. For matched
trades, the attested engine produces a batch proof. Across these paths, the
proofs establish the relevant combination of:

1. the input note is a leaf under a recent tree root (it exists and is yours),
2. output notes conserve value and use the configured assets and fees, and
3. outputs are derived for the correct owner rather than chosen by the matcher.

The program verifies the proof and applies the result: it records the appropriate
replay guard, appends output commitments, and for a withdrawal releases tokens.
The chain learns that a valid transition happened, not the shielded trade
plaintext; a withdrawal necessarily reveals its transferred amount.

## Consolidating notes

An order is backed by a single note, so to trade more than any one note holds you
first **merge** several notes of the same token into one. A merge is a
zero-knowledge operation against the pool, like a spend: it consumes its input
notes (creating tag-keyed consume records) and appends one output note carrying their
combined value, proven so nothing is created or destroyed. The SDK exposes it as a
single call, leaving you one larger spendable note to back a bigger order.

## The lifecycle, end to end

```text
 deposit ──► note appended to the tree (SPENDABLE)
                │
 place order ──► note reserved inside the venue while resting
                │
 private match ► on-chain note lock created (PENDING SETTLEMENT)
                │
 settle ──────► input note-use tag marked consumed; outputs appended:
                  • your filled asset (a new note)
                  • a change note for any unfilled remainder
                  • fee notes
                │
 withdraw ────► note-use tag consumed; tokens released to your wallet
```

The resting reservation prevents one venue session from booking the same
commitment into two live orders. Once a match begins, the on-chain lock prevents
the note from being withdrawn, merged, or settled elsewhere while that
settlement may still land. At lock expiry it stops blocking use; cleanup of the
expired account is separate from spendability.

Every value-moving transition is gated on-chain by a distinct record (a wallet
entry, duplicate-deposit guard, withdrawal nullifier, consumed-note marker, or
live note lock), so a note can never be spent twice regardless of what the
engine does. See [Deposit](../account/deposit.md) and
[Withdraw](../account/withdraw.md) for the on-ramp and off-ramp,
[Account Model](../account/account-model.md) for how you reconstruct your spendable
set, and [Settlement](./settlement.md) for the on-chain spend pipeline.
