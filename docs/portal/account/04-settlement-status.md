---
sidebar_position: 4
title: Settlement Status
description: Track a matched batch from proof through to on-chain finality, and resolve the Solana transaction signatures that settled your trade.
---

# Settlement Status

:::info TL;DR
When your order matches, it settles on Solana as part of a **batch**. `GET
/settlement/status/{batch_id}` translates a batch id into its on-chain
transaction signatures and tells you which stage of the settlement pipeline it is
in. Use it to confirm finality and to get a Solana explorer link for your trade.
:::

A fill on Nyx is not final the instant the engine matches it — it is final when
the settlement transaction lands on Solana. Settlement runs as a short on-chain
pipeline per batch (lock the notes, verify the batch proof, execute the atomic
transfers, then reclaim the batch marker). This endpoint surfaces where a batch is
in that pipeline and the signatures it produced.

You learn the `batch_id` for a matched order from the order's status (`GET
/orders/{order_id}` returns the `batch_id` it matched in) or from the orders
stream.

## GET /settlement/status/&#123;batch_id&#125;

```text
GET /settlement/status/{batch_id}
```

Authenticated (bearer).

### Example

```bash
curl -s "$GATEWAY/settlement/status/$BATCH_ID" \
  -H "Authorization: Bearer $TOKEN" | jq .
```

### Response

```json
{
  "batch_id": "batch_01H…",
  "status": "settled",
  "merkle_root": "…",
  "verify_match_batch_signature": "5xQ…",
  "settle_signatures": ["3aB…", "9kZ…"],
  "close_signature": "7mP…",
  "settled_at": "2026-04-20T10:30:02.880Z",
  "error": null
}
```

### Field reference

| Field | Type | Description |
|---|---|---|
| `batch_id` | string | The batch identifier. |
| `status` | string | The current pipeline stage (see below). |
| `merkle_root` | string | The note-tree root the batch settled against. |
| `verify_match_batch_signature` | string \| null | Solana signature of the transaction that verified the batch's match proof. |
| `settle_signatures` | string[] | Per-match settlement transaction signatures, in match order. |
| `close_signature` | string \| null | Signature of the transaction that reclaimed the batch's on-chain marker. |
| `settled_at` | string \| null | Timestamp the batch reached `settled`. |
| `error` | string \| null | Present only when `status` is `failed`: a human-readable reason. |

## Status values

The pipeline advances through these stages in order:

| Status | Meaning |
|---|---|
| `pending_proof` | The batch's zero-knowledge match proof is being generated. |
| `pending_verify_match_batch` | The proof is generated; the on-chain verify transaction is in flight. |
| `pending_settles` | The batch is verified; the per-match settlement transactions are being submitted. |
| `pending_close` | All matches settled; the marker-close transaction is in flight. |
| `settled` | Fully final on-chain. Funds have moved; output notes exist in the tree. |
| `failed` | The pipeline could not complete; see `error`. |

## Verifying settlement yourself

Each signature is a real Solana transaction you can inspect on any explorer.
Because settlement is enforced on-chain by a zero-knowledge proof, a `settled`
batch is a cryptographic guarantee that the transfers were conservation-correct
and bound to the committed notes — not merely the engine's assertion. To confirm a
trade independently:

1. Read `settle_signatures` for the batch.
2. Look each up on a Solana explorer.
3. Confirm the transaction succeeded and updated the vault's note tree.

The new notes created by settlement — your filled asset, any change note for an
unfilled remainder — appear as fresh leaves in the tree, which the SDK picks up
when it follows tree updates. See [Settlement](../how-it-works/settlement) for the
full pipeline and [Fills Channel](../websocket/fills-channel) for the per-fill
notifications that let you recover the change notes.
