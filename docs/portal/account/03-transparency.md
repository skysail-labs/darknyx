---
sidebar_position: 3
title: Transparency
description: A public, unauthenticated proof-of-reserves — per-mint outstanding liabilities versus vault balances — plus the engine's attested identity.
---

# Transparency

:::info TL;DR
`GET /transparency` is a **public proof-of-reserves**: for every mint it reports
the outstanding note value (the venue's liability) against the actual SPL balance
held in the vault (the assets). Anyone can verify the vault covers what it owes —
no login, no trust in the operator's word.
:::

A dark pool hides individual orders and balances, but solvency should still be
publicly checkable. Transparency squares that circle: it never reveals who owns
what, but it proves, in aggregate, that the assets in custody cover the
liabilities the notes represent — and ties the response to a specific, measured
engine.

## GET /transparency

```text
GET /transparency
```

Public — no authentication.

### Response

```json
{
  "reserves": {
    "merkle_root": "…",
    "leaf_count": 4096,
    "per_mint": [
      {
        "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        "outstanding": "1250000.00",
        "vault_balance": "1250000.00",
        "stale": false
      }
    ]
  },
  "tee": {
    "app_id": "…",
    "compose_hash": "…",
    "mrtd": "…",
    "signer_pubkey": "…"
  },
  "stats": {
    "batches": 812,
    "jobs": 9341
  }
}
```

## Reserves

| Field | Type | Description |
|---|---|---|
| `reserves.merkle_root` | string | Root of the note tree the snapshot is taken against. |
| `reserves.leaf_count` | integer | Total note commitments across all shards. |
| `per_mint[].mint` | string | The SPL mint, base58. |
| `per_mint[].outstanding` | string | Sum of unspent note value for this mint — the venue's liability. |
| `per_mint[].vault_balance` | string | The actual SPL balance held in the vault for this mint — the assets. |
| `per_mint[].stale` | boolean | `true` if an on-chain read was degraded; treat the numbers as unknown, not zero, when set. |

**The solvency check is `vault_balance >= outstanding` for every mint.** When it
holds, the pool can honor every withdrawal: the tokens are there. If a row is
`stale`, an on-chain read failed and you should ignore that row's numbers rather
than read a transient `0` as insolvency.

## Engine identity

| Field | Description |
|---|---|
| `tee.app_id` | The deployment's application id. |
| `tee.compose_hash` | The measured image hash — the same value you pin in attestation (see [Transport & Attestation](../api/transport-and-attestation)). |
| `tee.mrtd` | The TDX measurement of the running VM. |
| `tee.signer_pubkey` | The enclave's on-chain settlement signer (base58). |

These let you tie a transparency snapshot to a specific measured engine — the
same engine whose attestation you can verify and whose signer settles on Solana.

## Stats

| Field | Description |
|---|---|
| `stats.batches` | Settlement batches tracked. |
| `stats.jobs` | Per-match settlement jobs tracked. |

Aggregate operational counters — useful for a public health dashboard. They
reveal nothing about any individual order.

## How to use it

- **Independent solvency monitoring.** Poll it and alert if any non-stale mint
  shows `vault_balance < outstanding`.
- **Pre-trade trust check.** Before committing significant flow, confirm reserves
  cover liabilities and the `compose_hash` matches the build you trust.
- **Public dashboards.** Because it is unauthenticated and leaks nothing about
  individuals, it is safe to surface on a status page.
