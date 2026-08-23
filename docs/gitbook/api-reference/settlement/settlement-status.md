---
description: "Inspect the per-match jobs and Solana signatures associated with a TEE-local settlement batch handle."
---


# Settlement Status

{% hint style="info" %}
**TL;DR**

`GET /settlement/status/{batch_id}` returns every per-match job in a settlement
batch. A match can be pending, confirmed, rejected, or ambiguous independently
of its siblings. This is an authenticated operational/debug surface; trader
clients should treat the orders and fills streams as their primary lifecycle.
{% endhint %}

## GET /settlement/status/&#123;batch_id&#125;

{% openapi src="https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml" path="/settlement/status/{batch_id}" method="get" %}
https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml
{% endopenapi %}

`batch_id` is an unsigned integer local to the running engine. It is not an
on-chain identifier and the order-read response does not promise a batch-id
field. Use this endpoint when an operator or diagnostic response has supplied a
known batch handle. The engine retains a bounded recent window of terminal
batches, so `404` may mean the handle is unknown **or has aged out**; use the
orders and fills streams as the trader-facing lifecycle source.

Authenticated with a bearer token:

```bash
curl -s "$GATEWAY/settlement/status/$BATCH_ID" \
  -H "Authorization: Bearer $TOKEN" | jq .
```

### Response

```json
{
  "batch_id": 42,
  "jobs": [
    {
      "batch_id": 42,
      "match_idx": 0,
      "stage": "done",
      "outcome": {
        "kind": "confirmed",
        "signature": "5xQ…",
        "slot": 309482113,
        "reconciled_from_consumed_pdas": false
      },
      "created_at_ms": 1784271000000,
      "last_transition_at_ms": 1784271002880,
      "lock_buyer_sig": "2aB…",
      "lock_seller_sig": "3cD…",
      "verify_sig": "4eF…",
      "settle_sig": "5xQ…"
    }
  ]
}
```

Each job has a `match_idx`, current `stage`, independent `outcome`, timestamps,
and whichever Solana signatures have confirmed so far. Optional fields are
omitted until available.

## Stages

`stage` is one of `queued`, `locking_notes`, `proving`, `verifying`, `settling`,
`closing`, `done`, or `failed`. A `done` match has confirmed even when the shared
marker has not yet been reclaimed; marker close is asynchronous rent cleanup,
not part of trade finality.

## Outcomes

| `outcome.kind` | Meaning |
|---|---|
| `pending` | No final per-match result yet. |
| `confirmed` | The settle transaction confirmed, or finalized consumed-note accounts proved it landed. |
| `rejected` | A definitive error made the match terminal. |
| `ambiguous` | RPC evidence is inconclusive; the engine keeps the match reserved while reconciling or safely redriving it. |

Do not infer that every match succeeded from a batch-wide stage. Inspect every
job. The user-facing order lifecycle commits a fill only for `confirmed`; a
definitive failure emits `settlement_failed` and requires a fresh order after
the input lock expires.

See [Settlement](/documentation/how-it-works/settlement) for the finality model.
