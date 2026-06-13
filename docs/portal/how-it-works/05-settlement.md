---
sidebar_position: 5
title: Settlement
description: How matched trades become final on Solana — the batched, proven, atomic settlement pipeline the enclave drives directly.
---

# Settlement

:::info TL;DR
The enclave settles matches on Solana **itself**, in batches. For each batch it
locks the input notes, verifies a zero-knowledge **batch proof** on-chain,
executes the per-match transfers atomically, then reclaims the batch marker. A
trade is final when its settlement transactions land — guaranteed correct by a
proof the chain verifies, not by the engine's word.
:::

## Settlement is on-chain and proven

Matching happens privately inside the enclave, but the *result* is settled on
Solana where anyone can verify it. The enclave does not ask a relayer or a user to
submit anything — it holds an on-chain-registered signing key and drives the
settlement transactions directly. Crucially, those transactions only succeed if
they carry a valid zero-knowledge proof, so the chain — not the operator — is the
final authority on whether a settlement is correct.

## The pipeline

Settlement runs as a short sequence of on-chain transactions per batch:

```text
   ┌─ A ─ lock ─────────┐  pin the input notes of every match in the batch
   │                     │  (a per-note lock blocks any double-commit)
   ▼                     │
   ┌─ B ─ verify ───────┐│  verify the batch's zero-knowledge match proof
   │                     ││  on-chain (one proof covers all matches in the batch)
   ▼                     ▼│
   ┌─ C ─ settle ───────┐ │  execute the atomic transfers: nullify inputs,
   │   (per match)       │ │  append output notes (filled asset, change, fees)
   ▼                     ▼ │
   ┌─ D ─ close ────────┐  │  reclaim the batch marker once every match settled
   └─────────────────────┘ ┘
```

| Stage | What it does |
|---|---|
| **Lock** | Pins each match's input notes with a per-note lock, so nothing can be re-committed between match and settlement. |
| **Verify** | Verifies the batch's match proof on-chain. One proof attests that *every* match in the batch is conservation-correct, bound to the committed notes, and within the oracle circuit-breaker band. |
| **Settle** | For each match, nullifies the inputs and appends the output notes — the traded asset, a change note for any unfilled remainder, and the fee notes. |
| **Close** | After all matches settle, reclaims the batch's on-chain marker. |

You track this per batch through [`GET /settlement/status/{batch_id}`](../account/settlement-status),
which exposes each stage's transaction signatures.

## Batched and sharded for throughput

Two design choices keep settlement fast without weakening the guarantees:

- **Batching.** Many matches settle under one verified proof, so the expensive
  proof verification is amortized across the batch rather than paid per trade.
- **Sharding.** The note tree is split into independent shards, each with its own
  settlement lane and signing key. The engine settles across shards concurrently,
  so throughput scales with the number of shards instead of being bottlenecked on
  a single serialized path.

Neither changes what a settlement *means*: every transfer is still individually
proven correct and bound to committed notes.

## What finality means

A fill is final when its settlement transactions confirm on Solana. Because each
batch is gated by an on-chain-verified zero-knowledge proof:

- **Conservation is guaranteed.** The proof attests that value is neither created
  nor destroyed across the batch — the outputs exactly account for the inputs.
- **Binding is guaranteed.** Each output note is bound to the right owner and the
  match it came from; the engine cannot redirect value to a note it controls.
- **The price is bounded.** The clearing price is inside the oracle circuit-breaker
  band, enforced inside the proof.

So a `settled` batch is not an assertion you trust — it is a fact the chain
checked. Verify any trade yourself by inspecting its settlement signatures on a
Solana explorer (see [Settlement Status](../account/settlement-status)).

## After settlement

Settlement appends new notes to the tree: your filled asset, a change note for any
unfilled remainder, and the protocol fee notes. The
[Fills Channel](../websocket/fills-channel) delivers the secret material to recover
your change note; the SDK picks up the rest by following tree updates. Your new
spendable balance is simply the notes you now own — see
[Account Model](../account/account-model).
