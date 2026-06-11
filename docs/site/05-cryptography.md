---
sidebar_position: 4
title: Cryptography
description: The primitives behind Nyx — Poseidon commitments, the inner-hash note model, the six zero-knowledge circuits, and the replay protection that makes every spend single-use.
---

# Cryptography

:::info TL;DR
Three primitives carry the load: **Poseidon** over BN254 (for everything
Merkle-tree-shaped), **Ed25519** (for the enclave's settle signatures and your
trading key), and **Groth16** (the on-chain ZK verifier). Assets are UTXO-style
**notes** committed as Poseidon hashes; a small family of circuits proves you
may create, spend, merge, or trade them — without revealing what they hold.
:::

## Keys: one seed, many roles

Everything derives deterministically from a single master seed (a standard
mnemonic, or a signature from your wallet — your choice). From it the SDK
derives, on your device only:

- a **spending key** — authorizes spending a note; never leaves your device;
- a **trading key** — an Ed25519 keypair that signs orders, deliberately *not*
  your wallet, so the enclave never learns which wallet is trading;
- an **owner-commitment blinding factor** — binds notes to you without naming
  you.

Because the derivation is deterministic, a fresh device with your seed can
recover your trade history (notes and fills) without any server holding your
secrets.

## The note model

A **note** is the unit of value — like a UTXO. It is stored on-chain only as a
single Poseidon hash, the **commitment**. Owner, value, and token are sealed
inside; nothing about a note is observable until you spend it.

Nyx anchors both the commitment and its spend-tag on one amount-independent
value, the **inner hash**:

```text
commitment = Poseidon( DOMAIN, mint, amount, owner_commitment, inner_hash )
nullifier  = Poseidon( DOMAIN, spending_key, inner_hash )
```

The **nullifier** is the note's one-time spend-tag: publishing it on-chain marks
the note spent, and the chain rejects any second use. Crucially, the nullifier
depends on `inner_hash` but **not** on the amount.

:::tip Why decouple the nullifier from the amount
Because the spend-tag doesn't depend on value, you can **pre-commit** the
nullifiers for your *future* change notes before you know their size. That's
what lets a partial fill roll forward inside the enclave — the matcher rotates
your residual in place and re-matches it, with no client round-trip. The
pre-committed set is the **anchor pool** you submit with each order (see
[Matching layer](./matching-layer)).
:::

## The circuits

A note's whole lifecycle is gated by zero-knowledge proofs verified on-chain.
There are six circuits:

| Circuit | Proves | Generated |
|---|---|---|
| `VALID_WALLET_CREATE` | Your account commitment is well-formed | On your device |
| `VALID_INPUT` | A deposited note matches its declared mint + amount | On your device |
| `VALID_SPEND` | You own a note in the tree, haven't spent it, and your change note is correct | On your device |
| `VALID_MERGE` | Several notes you own (same owner + mint) consolidate into one of equal total | On your device |
| `VALID_MATCH_BATCH` | A whole batch of matches is valid — clearing price, conservation, output routing | **Inside the enclave** |

The user circuits run locally because they touch your spending key. The match
circuit runs inside the enclave because the match data must stay private — the
proof is what makes the settle trustless without revealing the orders.

:::note Batched proving
The match circuit proves an entire batch of up to 16 matches in one proof, so a
batch settles against a single on-chain verification rather than one per trade.
The merge circuit comes in two sizes (consolidating up to 2 or up to 4 notes);
larger consolidations chain.
:::

## Replay protection

Every note touch leaves a one-time on-chain marker, so nothing can be spent
twice — across *any* path:

- spending a note (withdraw) creates its **nullifier** record;
- settling a note (a trade) creates a **spent-note** record *and* its nullifier;
- merging a note creates its nullifier.

A second attempt to touch the same note simply fails to create the marker. Spend
and settle and merge all share the nullifier guard, so a note consumed one way
can't be consumed another. The note locks added during settlement add a second
layer: a note pinned for a trade can't be withdrawn out from under it.

## Domain separation

Every hash is tagged with a domain constant so values from one context can never
be reinterpreted in another — a note commitment can't be mistaken for a
nullifier, a leaf hash, or a batch root. These tags are fixed and identical
across the on-chain program, the enclave, and the SDK.

## One contract, three languages

The same cryptographic values are computed in three places — the SDK
(TypeScript), the enclave and host crates (Rust), and the on-chain program — and
they must agree **byte for byte**. Nyx pins this with parity tests on every
primitive: Poseidon, key derivation, note commitments, nullifiers, and the
canonical order-and-settle payload hashes. A one-byte disagreement anywhere
fails a test before it can fail a trade.

## A note on the trusted setup

The Groth16 circuits use a trusted setup. The production deployment requires a
real multi-party ceremony with independent contributors and publicly verifiable
transcripts; until that ceremony, the circuits run against a development
contribution suitable for testnet only. This is the standard Groth16 caveat and
is tracked openly on the [roadmap](./roadmap).
</content>
