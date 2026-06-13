---
sidebar_position: 3
title: Fills Channel
description: A per-account stream of continuation-fill memos — the secret material you need to recover and spend each change note from a partial fill.
---

# Fills Channel

:::info TL;DR
`/ws/fills` streams a **fill memo** per continuation fill: the data you need to
recover the change note a partial fill produced. You verify each memo against
your own keys before storing it — a misbehaving engine cannot slip you a note you
do not control. The stream is per-account.
:::

## Why a separate fills stream

When an order partially fills, the remainder is re-locked into a new **change
note** that you own. To spend that note later you need its secret opening — the
anchor (`inner_hash`) the engine consumed and the resulting commitment. The fills
channel delivers exactly that, per fill, so your local note store stays complete
without you scanning the chain for it.

The [Orders Channel](./orders-channel) tells you *that* an order filled and how
much; the fills channel tells you *which note* the change went into so you can
spend it.

## Connect

```text
wss://<gateway-host>/ws/fills?token=<access_token>
```

Self-authenticating with the bearer token as `?token=`. Per-account: you only
receive memos for orders you placed.

## Memo shape

```json
{
  "order_id": "aa00000000000000000000000000000001",
  "anchor_index": 0,
  "change_amount": 7000000,
  "change_note_commitment": "…",
  "mint": "…",
  "inner_hash": "…"
}
```

| Field | Type | Description |
|---|---|---|
| `order_id` | string | The 16-byte order id, hex. |
| `anchor_index` | integer | Which continuation anchor the engine consumed for this fill. |
| `change_amount` | integer | The value of the change note. |
| `change_note_commitment` | string | 32-byte hex commitment of the change note. |
| `mint` | string | 32-byte hex mint of the change note. |
| `inner_hash` | string | 32-byte hex inner hash of the change note (the anchor that was consumed). |

## Verify before you store

A fill memo is **untrusted input** — verify it before adding the change note to
your store. The SDK performs two checks:

1. **Anchor binding.** The memo's `inner_hash` must equal the anchor your own
   client deterministically derived for `(order_id, anchor_index)`. An engine
   that substituted a different inner hash — so it could later forge a nullifier
   it controls — is caught here.
2. **Commitment binding.** Recomputing the note commitment from the memo's fields
   must equal the reported `change_note_commitment`.

Only a memo that passes both becomes a stored, spendable change note. This is the
guard that keeps a misbehaving engine from substituting a note you do not own.

## Durability and gap recovery

The live stream is the low-latency "tail." For durable history — fills that
happened before your socket opened, or while it was down — recover from your
durable fill history (reconstructed from on-chain settlement data keyed by your
order ids) and then tail the live socket. This "backfill then tail" pattern means
a dropped connection never loses a fill.

If a slow consumer lags past the per-account buffer, the server closes with code
**1011**. On 1011, re-run the backfill from your last cursor and reopen — the note
store is keyed by commitment, so a note seen in both the backfill and the live
stream is simply de-duplicated.

## Example

```javascript
const ws = new WebSocket(`${WSS}/ws/fills?token=${TOKEN}`);

ws.onmessage = async (e) => {
  const memo = JSON.parse(e.data);
  // The SDK verifies (anchor + commitment binding) then stores the change note.
  await sdk.receiveFillMemo(memo);   // throws on a memo that fails verification
};

ws.onclose = (e) => {
  if (e.code === 1011) backfillThenReopen();
};
```
