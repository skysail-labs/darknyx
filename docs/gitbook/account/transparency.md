---
description: "A public, unauthenticated proof-of-reserves covering per-mint outstanding liabilities versus vault balances, plus the engine's attested identity."
---


# Transparency

{% hint style="info" %}
**TL;DR**

`GET /transparency` is a **public solvency snapshot**: for every mint it reports
the outstanding note value (the venue's liability) against the actual SPL balance
held in the vault (the assets). Treat the endpoint as a convenience view and
verify the same `OutstandingMint` and vault token accounts directly on Solana
when making a trust decision.
{% endhint %}

A dark pool hides individual orders and balances, but solvency should still be
publicly checkable. Transparency squares that circle: it never reveals who owns
what, but it makes aggregate assets and liabilities easy to compare. The values
remain independently verifiable from Solana, while engine identity is verified
through a separate fresh attestation.

## GET /transparency

```text
GET /transparency
```

Public, with no authentication.

### Response

```json
{
  "reserves": {
    "merkle_root": "…",
    "leaf_count": 4096,
    "per_mint": [
      {
        "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        "outstanding": "1250000000000",
        "vault_balance": "1250000000000",
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
| `reserves.merkle_root` | string | Shard 0's Merkle root. There is no single global root; read every shard through `/tree/root`. |
| `reserves.leaf_count` | integer | Total note commitments across all shards. |
| `per_mint[].mint` | string | The SPL mint, base58. |
| `per_mint[].outstanding` | string | Sum of unspent note value for this mint in smallest token units, the venue's liability. |
| `per_mint[].vault_balance` | string | Actual SPL balance held in the vault in smallest token units, the assets. |
| `per_mint[].stale` | boolean | `true` if an on-chain read was degraded; treat the numbers as unknown, not zero, when set. |

**The solvency check is `vault_balance >= outstanding` for every mint.** When it
holds, the pool can honor every withdrawal: the tokens are there. If a row is
`stale`, an on-chain read failed and you should ignore that row's numbers rather
than read a transient `0` as insolvency.

## Engine identity

| Field | Description |
|---|---|
| `tee.app_id` | The deployment's application id. |
| `tee.compose_hash` | The server's convenience copy of its compose hash; use the quote-bound event log for verification. |
| `tee.mrtd` | The TDX measurement of the running VM. |
| `tee.signer_pubkey` | The enclave's on-chain settlement signer (base58). |

These fields identify what the server claims to be. They are **not** an
attestation proof: derive the compose hash from the DCAP-verified quote event log
and compare the quote-bound full signer set with finalized on-chain
`VaultConfig.tee_pubkeys`. The transparency response exposes only the primary
signer.

## Stats

| Field | Description |
|---|---|
| `stats.batches` | Settlement batches tracked. |
| `stats.jobs` | Per-match settlement jobs tracked. |

Aggregate operational counters, useful for a public health dashboard. They
reveal nothing about any individual order.

## How to use it

- **Independent solvency monitoring.** Poll it and alert if any non-stale mint
  shows `vault_balance < outstanding`.
- **Pre-trade trust check.** Confirm reserves cover liabilities, then perform the
  independent quote, measurement, and full signer-set checks described in
  [Transport & Attestation](../api/transport-and-attestation.md).
- **Public dashboards.** Because it is unauthenticated and leaks nothing about
  individuals, it is safe to surface on a status page.
