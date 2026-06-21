---
sidebar_position: 3
title: Glossary
description: The terms and acronyms used across the Nyx documentation, in plain language.
---

# Glossary

A quick reference for the concepts and names used throughout these docs.

### Anchor pool

A small set of pre-committed continuation tags (the nullifiers for your *future*
change notes) you submit with each order. It lets a partial fill roll forward
inside the enclave with no client round-trip — the matcher rotates your residual
in place using the next anchor. Possible because a note's spend-tag doesn't
depend on its amount. See [Matching layer](./matching-layer).

### Attestation

A signed statement from Intel's TDX hardware describing exactly what code is
running inside the enclave. Clients verify it — and check it against the image
registered on-chain — before trusting the enclave. See [Trust model](./trust-model).

### Batch auction (frequent batch auction)

The matching model: instead of a continuous first-come book, all crossing orders
clear together at a single uniform price every couple of seconds. Removes the
intra-block timing games. See [Matching layer](./matching-layer).

### Clearing price

The single price at which every crossing order in a batch fills. Constrained to a
band around a verified oracle price and re-proved on-chain, so the operator can't
distort it.

### Commitment (note commitment)

The Poseidon hash that *is* a note on-chain. Seals the note's owner, value, and
token; reveals nothing until you spend it.

### Compose hash

The measurement of the enclave's exact compiled image. Registered on-chain;
a client checks the attested measurement against it. A different image produces a
different hash and is rejected.

### Confidential VM (CVM) / TEE / enclave

The Intel TDX Confidential Virtual Machine that runs the matching layer. Its
memory is hardware-sealed and its code is attested; the operator running the
machine cannot read inside it. Used interchangeably with *enclave* and *TEE*
(Trusted Execution Environment).

### Continuation

The mechanism by which a partially-filled order keeps working across batches
without resubmission, using the anchor pool.

### Inner hash

An amount-independent value that both a note's commitment and its nullifier are
anchored on. Decoupling the spend-tag from the amount is what makes the anchor
pool — and round-free partial fills — possible. See [Cryptography](./cryptography).

### Merge

Consolidating several notes you own (same owner and token) into one of equal
total value, proved by `VALID_MERGE`. Lets a single order be larger than any one
note — including the change notes that accumulate from partial fills.

### Note

The unit of value in Nyx — a UTXO-style object representing some amount of a
token, owned by you, stored on-chain only as a commitment. See
[Custody layer](./custody-layer).

### Nullifier

A note's one-time spend-tag. Publishing it on-chain marks the note spent; the
chain rejects any second use. Shared across the spend, settle, and merge paths,
so a note can't be consumed twice by any route.

### Oracle band

The window around a verified market price (from Pyth, signature-checked inside
the enclave) within which a batch's clearing price must fall — a circuit breaker
against off-market clears.

### Poseidon

A hash function efficient inside zero-knowledge circuits. Used for note
commitments, nullifiers, the Merkle tree, and account commitments.

### Proof of reserves

The on-chain comparison anyone can make between the vault's actual token balance
and its outstanding liabilities. Surfaced by the public `transparency` endpoint.

### RA-TLS

A TLS connection whose certificate key lives *inside* the attested enclave, so
the attestation covers the transport itself — you're cryptographically sure
you're talking to the real enclave, not a proxy.

### Settlement pipeline

The sequence of Solana transactions that turns a matched batch into final
on-chain transfers: lock, verify, settle, close. Tree-sharded and concurrent so
a batch co-includes in one block. See [Settlement pipeline](./settlement-pipeline).

### Tree shard / sharding

Splitting the Merkle tree of notes into several independent accounts (with a
fee-payer key each) so settlements don't serialize on a single account and can
co-include in one block. Invisible to you — a note simply lives in one shard.

### Trading key

An Ed25519 keypair, distinct from your Solana wallet, that signs your orders to
the enclave. Keeps your wallet unlinked from your trades.

### Transparency endpoint

A public, unauthenticated endpoint exposing the mirror root, leaf counts, and the
reserves-vs-liabilities comparison — verifiable by anyone against the chain.

### Validity marker

A short-lived on-chain authorization that a settlement consumes. One marker
covers a whole batch and is closed once, after every match in it settles.

### Vault

The single Solana program that holds all funds and owns the note tree. The only
thing that can move tokens — and only against a proof. See
[Custody layer](./custody-layer).

### The circuits

| Name | Proves |
|---|---|
| `VALID_WALLET_CREATE` | Your account commitment is well-formed |
| `VALID_INPUT` | A deposited note matches its declared mint + amount |
| `VALID_SPEND` | You own a note, haven't spent it, and your change note is correct |
| `VALID_MERGE` | Several notes consolidate into one of equal total |
| `VALID_MATCH_BATCH` | A whole batch of matches is valid (price, conservation, routing) |
</content>
