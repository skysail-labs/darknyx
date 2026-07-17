---
sidebar_position: 3
title: Fills Channel
description: A per-account stream of consumed-input-bound memos for verifying and storing change notes.
---

# Fills Channel

:::info TL;DR
The `fills` channel on `/v1/stream` streams a **fill memo** for every non-zero
change output. The memo names the exact consumed input and circuit role, so your
client derives and verifies the output before storing it. The stream is
per-account.
:::

## Why a separate fills stream

When an order partially fills, the remainder is re-locked into a new **change
note** that you own. To spend it later you need the amount and derived inner
hash. The channel supplies the amount and identifies the consumed note; the SDK
uses that locally held input opening to derive the expected v3 output.

The [Orders Channel](./orders-channel) tells you *that* an order filled and how
much. The fills channel tells you *which note* the change went into so you can
spend it.

## Connect

```text
wss://<gateway-host>/v1/stream
```

Login in-band, then send `{"op":"subscribe","channels":["fills"]}`. The
channel is per-account: you only receive memos for orders you placed.

## Memo shape

```json
{
  "seq": 5,
  "order_id": "aa00000000000000000000000000000001",
  "consumed_note_commitment": "…",
  "output_role": 177,
  "change_amount": 7000000,
  "change_note_commitment": "…",
  "mint": "…",
  "inner_hash": "…"
}
```

| Field | Type | Description |
|---|---|---|
| `seq` | integer | Per-connection monotonic sequence, starting at 1. A gap means missed memos, so re-run the backfill. |
| `order_id` | string | The 16-byte order id, hex. |
| `consumed_note_commitment` | string | Exact 32-byte input commitment consumed by this match. |
| `output_role` | integer | Circuit role byte (`0xb1` buyer change or `0x5e` seller change). |
| `change_amount` | integer | The value of the change note. |
| `change_note_commitment` | string | 32-byte hex commitment of the change note. |
| `mint` | string | 32-byte hex mint of the change note. |
| `inner_hash` | string | 32-byte hex inner hash of the change note. |

## Verify before you store

A fill memo is **untrusted input**. Verify it before adding the change note to
your store. The SDK performs three checks:

1. **Consumed-input binding.** The named input must exist in your note store and
   its opening must reproduce `consumed_note_commitment` and the change mint.
2. **Circuit derivation.** The memo inner must equal
   `Poseidon3(24, consumed_input_inner, output_role)`.
3. **Commitment binding.** Recomputing the output note from the verified owner,
   mint, amount, and derived inner must equal `change_note_commitment` as bytes.

Only a memo that passes all three becomes a stored, spendable change note. This is the
guard that keeps a misbehaving engine from substituting a note you do not own.

## Durability and gap recovery

The live memo is the low-latency path, not the durable one. The permanent source
of a change note is **on-chain**: when you place an order with a `viewing_pubkey`
(see [Place Order](../orders/place-order)), the engine encrypts each change amount
to that key and writes the ciphertext into the settlement on Solana. That
ciphertext is permanent and survives an engine redeploy, so the change note is
recoverable long after the live memo is gone.

Recovery is therefore "backfill then tail":

1. **Backfill from the chain.** For fills that settled before your socket opened,
   or while it was down, the SDK reads the on-chain ciphertext for your settled
   orders, decrypts each change amount with your viewing key, and derives the
   output from a known consumed input opening. The SDK iterates recovery to
   reconstruct multi-fill continuation chains in any result order.
2. **Tail the live stream.** Subscribe to `fills` for low-latency memos of new fills.

Because the note store is keyed by commitment, a note seen in both the backfill
and the live stream is simply de-duplicated, so a dropped connection never loses a
fill. If a slow consumer lags past the per-account buffer, the server closes with
code **1011**; on 1011, re-run the backfill from the chain and reopen.

:::note Cold recovery
Recovery v2 permanently stores each side's encrypted `(trade, change)` tuple.
`recoverNotesFromChain` bootstraps seed-owned deposits, follows settlement
continuations, and reconstructs merge outputs without live stream history.
:::

## Example

```javascript
const ws = new WebSocket(`${WSS}/v1/stream`);

ws.onopen = () => {
  ws.send(JSON.stringify({ op: "login", request_id: "login-1", token: TOKEN }));
};

ws.onmessage = async (e) => {
  const memo = JSON.parse(e.data);
  if (memo.op === "login") {
    ws.send(JSON.stringify({ op: "subscribe", channels: ["fills"] }));
    return;
  }
  if (memo.channel !== "fills") return;
  // The SDK verifies consumed input + derivation + commitment, then stores.
  await sdk.receiveFillMemo(memo, noteStore);
};

ws.onclose = (e) => {
  if (e.code === 1011) backfillThenReopen();
};
```
