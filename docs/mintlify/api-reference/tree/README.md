---
description: "Read the on-chain note tree, getting the current root, an inclusion proof for one of your notes, and paginated leaves to rebuild a local mirror."
---


# Merkle Proofs

{% hint style="info" %}
**TL;DR**

The note commitments live in an on-chain incremental Merkle tree. These endpoints
expose the engine's mirror of it: the current **root**, an **inclusion proof** for
a note you own, and a paginated **leaf** read. You use the inclusion proof to
generate the zero-knowledge input proof that backs an order or a withdrawal.
{% endhint %}

## Why you need these

Two of the things you do on Darknyx require proving a note exists in the tree:

- **Backing an order.** An order's collateral note must be provably in the tree;
  the input proof you attach to a place-order request is generated against an
  inclusion path.
- **Withdrawing.** Spending a note out of the pool proves its inclusion and
  publishes its nullifier.

The tree is sharded for settlement throughput; each shard has its own root.
Reads take an optional `tree_id` (default `0`).

## GET /tree/root

The current Merkle root of a shard. Public.

{% openapi src="https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml" path="/tree/root" method="get" %}
https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml
{% endopenapi %}

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
| `merkle_root` | string | The shard's current root, hex. It should equal the finalized on-chain `MerkleTree.current_root`; historical accepted roots are not returned here. |
| `leaf_count` | integer | Number of leaves in this shard. |
| `on_chain_slot` | integer | Solana slot at which the engine last synced this shard from chain. |

{% hint style="info" %}
**Cross-check on-chain**

The root is also readable directly from the Solana program. The endpoint is a
convenience mirror; a client that wants zero trust in the engine for this value
can read the on-chain account itself.
{% endhint %}

If the engine detects that a shard mirror disagrees with Solana, **all three
tree reads for that shard fail closed with HTTP `503`, code `5002`**. Do not
retry proofs against that mirror: read the tree from Solana directly until the
venue has cold-resynced the shard.

## GET /tree/inclusion

An inclusion proof for a note commitment. Authenticated (bearer). Complete
[Transport & Attestation](../getting-started/transport-and-attestation.md)
before sending the bearer token.

{% openapi src="https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml" path="/tree/inclusion" method="get" %}
https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml
{% endopenapi %}

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
the input-proof circuit. You do not assemble the proof by hand. The SDK takes
the inclusion proof and produces the Groth16 proof you attach to an order or
withdrawal.

{% hint style="warning" %}
**Roots age out**

A proof is generated against a specific root. Each shard accepts its current
root plus a 64-entry history. Freshness is measured in **append instructions on
that shard**, not seconds or Solana slots; one instruction can append several
leaves, so elapsed time is not a reliable estimate.

On a settlement-enabled venue, intake checks the engine's recent-root mirror and
rejects an already-stale order with `1010` before booking it. The on-chain check
remains authoritative: the mirror is deliberately permissive, and enough new
appends between acceptance and lock can still age a root out. If that race makes
settlement terminal, rebuild the proof against a current root and submit a fresh
signed order after any live lock expires.
{% endhint %}

## GET /tree/leaves

A paginated read of raw leaves. Authenticated (bearer). Complete
[Transport & Attestation](../getting-started/transport-and-attestation.md)
before sending the token. Use it to rebuild a local mirror of the tree from
scratch (the "scan once, then follow updates" pattern the SDK uses to maintain
your note store).

{% openapi src="https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml" path="/tree/leaves" method="get" %}
https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml
{% endopenapi %}

### Response

```json
{
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

The range is half-open, `[from, to)`. The server caps oversized ranges; advance
`from` to the last returned index plus one when paging.

A leaf value is a note *commitment*, an opaque hash. It tells you a note exists,
not who owns it or what it is worth; only your spending key turns the leaves you
own into balances. See [Account Model](/documentation/account/account-model).
