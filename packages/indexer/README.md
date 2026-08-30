# @darknyx/indexer — off-TEE by-order_id fills locator

> **Status: OPTIONAL, kept-not-deleted, no consumer today.**
> This package is a standalone, off-TEE, read-only Solana indexer. It watches the
> vault program's `tee_forced_settle_batched` txs, decodes the `MatchResultPayload`,
> and serves fills **by `order_id`** (`GET /fills?order_id=…`). It is deliberately
> **not** deployed anywhere — it runs locally for tests (`scripts/run-indexer-local.sh`)
> and in CI.

## Why it exists — and why its job shrank

It was designed to serve by-**account** trade history (amounts, prices) via a
TEE-fed intake registry. Three later changes hollowed that mandate out:

1. **The registry was dropped** → it became purely by-`order_id`, account-agnostic
   (no TEE↔indexer coupling — the whole point of the design).
2. **Amount-privacy (P3b)** stripped every plaintext amount/price/fee from the
   settle ix. The indexer is untrusted, so this is by design: it decodes down to
   `{ order_id, side, match_id, signature, slot, input_note_commitment,
   trade_note_commitment, change_note_commitment, batch_slot }` + the
   **opaque** on-chain recovery ciphertext. It is now a pure
   **commitment LOCATOR**, not a system of record. `slot` is the Solana history
   cursor; `batch_slot` is the 0..15 circuit slot index and is never used as a
   chain cursor.
3. **On-chain output recovery v3** puts each side's `(trade, change)` amounts
   ENCRYPTED on chain, recovered directly by the SDK
   (`fills/recover.ts::recoverFillFromChain`). This retired the P7 `/fills/replay`
   memo log and, crucially, made the **chain** — not this service — the durable
   source of truth.

Its one remaining unique value: turning a fresh-device HD rediscovery from an
`O(all settles)` client-side chain scan into `O(my order ids)` point queries
against a pre-built by-order_id index.

## The decision (2026-07-10): keep the code, don't deploy or invest — yet

We are **keeping this package** but treating it as an optional reference /
light-client accelerator, **not** a pending deliverable:

- **The daemon proves it's not load-bearing.** `packages/daemon` (the serious
  client) drives everything off the `fills` + `orders` channels on `/v1/stream` + TEE
  read endpoints + on-chain reads, with **zero references to this package**. Lean
  by construction is the right design for an always-on client.
- **The durable path no longer needs it.** The SDK recovers
  amounts straight from the chain, and can now also rediscover fills **without any
  indexer** via `packages/sdk/src/fills/chain-history.ts::backfillHistoryFromChain`
  (same `BackfillResult` shape as the indexer path — `startFillsSync` picks
  whichever source is configured). So "run an indexer" is a runtime **scaling**
  choice, not an architecture fork.
- **We don't delete it** because it's cheap to keep, well-tested, a useful decode
  spec (its `decode.ts` offsets mirror the SDK encoder + `chain-history.ts`), and
  the seed of a real service we'll want later.

### When to actually deploy it

Pull it off the shelf when either fires:

- A **browser / light-client** experience needs fast stateless rediscovery over
  **deep mainnet history**, where a per-client `O(all settles)` chain scan is too
  slow/expensive and a shared index amortizes the cost across clients; **or**
- client-side chain scans (`backfillHistoryFromChain`) measurably don't keep up.

Until then it stays a dormant reference implementation.

## Byte-layout contract

`src/decode.ts` mirrors `programs/vault/.../settlement_shared.rs::MatchResultPayload`,
the SDK encoder `packages/sdk/src/settlement/settle-builder.ts::serializePayload`,
and the SDK decoder `packages/sdk/src/fills/chain-history.ts`. Change the payload
layout in one place → change all four and re-run their round-trip tests
  (`decode.test.ts` here, `chain-history.test.ts` in the SDK).

Recovery v3 repacks the unchanged 128-byte field as
`ephemeral_pubkey(32) || buyer_enc(44) || seller_enc(44) || "DNYXREC3"`.
The explicit trailer makes the clean cutover fail closed on legacy v1 blobs.

## Run it locally

```sh
INDEXER_RPC_URL="$SOLANA_RPC_URL" scripts/run-indexer-local.sh
```

See the script header for env vars (`INDEXER_PORT`, `INDEXER_DB`,
`INDEXER_PROGRAM_ID`, `INDEXER_START_FROM_TIP`).
