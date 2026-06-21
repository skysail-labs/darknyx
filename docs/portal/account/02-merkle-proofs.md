---
sidebar_position: 2
title: Merkle Proofs
description: Read the on-chain note tree — the current root, an inclusion proof for one of your notes, and paginated leaves to rebuild a local mirror.
---

# Merkle Proofs

:::info TL;DR
The note commitments live in an on-chain incremental Merkle tree. These endpoints
expose the engine's mirror of it: the current **root**, an **inclusion proof** for
a note you own, and a paginated **leaf** read. You use the inclusion proof to
generate the zero-knowledge input proof that backs an order or a withdrawal.
:::

## Why you need these

Two of the things you do on Nyx require proving a note exists in the tree:

- **Backing an order.** An order's collateral note must be provably in the tree;
  the input proof you attach to a place-order request is generated against an
  inclusion path.
- **Withdrawing.** Spending a note out of the pool proves its inclusion and
  publishes its nullifier.

The tree is sharded for settlement throughput; each shard has its own root.
Reads take an optional `tree_id` (default `0`).

## GET /tree/root

The current Merkle root of a shard. Public.

```text
GET /tree/root?tree_id=0
```

### Response

```json
{
  "tree_id": 0,
  "merkle_root": "…",
  "leaf_count": 1284,
  "on_chain_slot": 309482001
}
```

| Field | Type | Description |
|---|---|---|
| `tree_id` | integer | Which shard this root is for (echoes the request; default `0`). |
| `merkle_root` | string | Current root of the shard, hex. Equals the on-chain root (or a recent root still in the shard's ring buffer). |
| `leaf_count` | integer | Number of leaves in this shard. |
| `on_chain_slot` | integer | Solana slot at which the engine last synced this shard from chain. |

:::note Cross-check on-chain
The root is also readable directly from the Solana program. The endpoint is a
convenience mirror; a client that wants zero trust in the engine for this value
can read the on-chain account itself.
:::

## GET /tree/inclusion

An inclusion proof for a note commitment. Authenticated (bearer).

```text
GET /tree/inclusion?note_commitment=<hex>&tree_id=0
```

### Response

```json
{
  "note_commitment": "…",
  "leaf_index": 902,
  "merkle_root": "…",
  "siblings": ["…", "…", "… (20 entries) …"]
}
```

| Field | Type | Description |
|---|---|---|
| `note_commitment` | string | The note commitment proven, hex. |
| `leaf_index` | integer | The note's index in the tree. |
| `merkle_root` | string | The root the proof is against. |
| `siblings` | string[] | The 20 sibling hashes from leaf to root (the authentication path). |

The `siblings` path plus your secret note opening is the witness the SDK feeds to
the input-proof circuit. You do not assemble the proof by hand — the SDK takes
the inclusion proof and produces the Groth16 proof you attach to an order or
withdrawal.

:::caution Roots age out
A proof is generated against a specific root. The on-chain program keeps a
bounded ring buffer of recent roots, so a proof must be *used* (settled or
withdrawn against) while its root is still in that window. In practice this means
an order must settle within a bounded number of tree updates of when it was
proven. The engine and SDK manage this; it is why a placed order carries the
`merkle_root` it was proven against.
:::

## GET /tree/leaves

A paginated read of raw leaves. Authenticated (bearer). Use it to rebuild a local
mirror of the tree from scratch (the "scan once, then follow updates" pattern the
SDK uses to maintain your note store).

```text
GET /tree/leaves?tree_id=0&from=0&limit=512
```

### Response

```json
{
  "tree_id": 0,
  "merkle_root": "…",
  "leaves": [
    { "leaf_index": 0, "value": "…" },
    { "leaf_index": 1, "value": "…" }
  ]
}
```

| Field | Type | Description |
|---|---|---|
| `leaves[].leaf_index` | integer | The leaf's position in the tree. |
| `leaves[].value` | string | The leaf hash (a note commitment), hex. |
| `merkle_root` | string | The root the page is consistent with. |

A leaf value is a note *commitment* — an opaque hash. It tells you a note exists,
not who owns it or what it is worth; only your spending key turns the leaves you
own into balances. See [Account Model](./account-model).
