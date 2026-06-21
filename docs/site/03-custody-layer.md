---
sidebar_position: 2
title: Custody layer
description: The Solana vault program that holds every dollar in Nyx — the note model, the sharded Merkle tree, on-chain state, and the proof-gated instructions that are the only way funds move.
---

# Custody layer

:::info TL;DR
One Solana program — the **vault** — holds all funds and owns the Merkle tree of
note commitments. It is the only thing that can move tokens, and it moves them
only against a zero-knowledge proof. If the enclave and the SDK both vanished
tomorrow, your funds would still be withdrawable directly from the chain with
your own proof.
:::

## Notes: the unit of custody

Nyx holds value as UTXO-style **notes**, not account balances. A note represents
some amount of a token, owned by you, and lives on-chain only as a single
Poseidon hash — its **commitment**. Owner, value, and token are sealed inside;
an observer sees a hash and nothing more. (The exact construction is in
[Cryptography](./cryptography).)

A note's whole life is gated by proofs:

- **Deposit** mints a note from tokens in your wallet.
- **Trade** consumes notes and mints new ones inside a settlement.
- **Merge** consolidates several notes into one.
- **Withdraw** burns a note back to tokens.

Every one of these requires a proof the vault verifies on-chain — there is no
privileged path that moves a note without one.

## The sharded Merkle tree

All note commitments live in an append-only **Merkle tree**, so anyone can prove
a note exists without trusting an indexer. To settle many trades per block, the
tree is **sharded** into several independent tree accounts (see
[Settlement pipeline](./settlement-pipeline) for why). A note lives in one shard;
the SDK tracks which, and inclusion proofs work per shard exactly as they would
for a single tree.

Each shard keeps a small **ring buffer of recent roots**. A proof built against
any root still in the buffer is accepted, which gives clients a comfortable
window between reading a root and landing a transaction — without it, every
concurrent settle would invalidate everyone else's in-flight proof.

## What the vault stores

| State | What it is |
|---|---|
| **Global config** | The registered enclave signing keys, the measured enclave image, the protocol fee rate, the admin governance authority, and the tree's shared parameters. |
| **Tree shards** | The per-shard Merkle state — leaf count, current root, and recent-roots buffer. |
| **Spent-note / nullifier records** | One small account per consumed note. Their *existence* is the double-spend guard. |
| **Note locks** | A pin on a note that's mid-settlement, so it can't be withdrawn out from under a trade. |
| **Per-mint outstanding counter** | Tracks how many note-units of each token are live, so the vault can prove its SPL balance covers its liabilities. |
| **Per-batch validity markers** | A short-lived authorization a settlement consumes; one per batch. |

## The instructions

The vault exposes a small, proof-gated instruction set:

| Instruction | What it does | Gated by |
|---|---|---|
| `create_wallet` | Register your account commitment | `VALID_WALLET_CREATE` proof |
| `deposit` | Mint a note from wallet tokens | `VALID_INPUT` proof |
| `merge` | Consolidate several notes into one | `VALID_MERGE` proof |
| `lock_note` | Pin an input note for a settlement | Enclave signature + `VALID_INPUT` |
| `verify_match_batch` | Accept a batch's match proof | `VALID_MATCH_BATCH` proof |
| `tee_forced_settle_batched` | Atomically settle one match | Enclave signature + the batch marker |
| `close_batch_validity_marker` | Reclaim the batch marker's rent | — |
| `withdraw` | Burn a note back to tokens | `VALID_SPEND` proof |

Settlement-related instructions additionally require an Ed25519 signature from a
**registered enclave key**. The set of accepted keys lives in the global config
and can only be changed through governance (see [Trust model](./trust-model)).

## Why this is auditable

Two properties make the vault independently checkable by anyone, with no
cooperation from Nyx:

- **Trustless withdraw.** Your withdraw proof is built entirely from on-chain
  data (the tree) plus your own secret. You never need an operator to release
  your funds.
- **Proof of reserves.** The per-mint outstanding counter is on-chain, and so is
  the vault's SPL balance. Anyone can confirm reserves cover liabilities — and
  the enclave's public `transparency` endpoint surfaces exactly this comparison
  (see [API reference](./api-reference)).

## What the chain defends against

| Attempt | Why it fails |
|---|---|
| Withdraw a note you don't own | No valid `VALID_SPEND` proof |
| Spend the same note twice | The nullifier record already exists |
| Withdraw a note mid-trade | The note is locked |
| Settle without the enclave | Missing the registered Ed25519 signature |
| Swap in a rogue enclave key | Keys change only through governance |
| Mint value from nothing in a settle | The batch proof enforces conservation |

The vault is the floor of the whole system: even if everything above it is
compromised, the worst outcome is that trades stop — never that funds leave
without your proof.
</content>
