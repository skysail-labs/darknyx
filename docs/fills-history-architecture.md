# Fills delivery + trade history — architecture

> Status: **LIVE + COLD PATHS IMPLEMENTED**. Canonical-order v2 replaces the
> retired anchor memo with a consumed-input-bound v3 memo; recovery v3 rebuilds
> deposit, trade, change/continuation, and merge openings from seed + chain.
>
> **As-built deltas from the original design below:**
> - **The account↔order_id registry (§4) was DROPPED.** Because order ids are
>   deterministic, the client gap-scans its own ids and the indexer serves fills
>   **by order_id only** — staying fully account-agnostic (no TEE→indexer feed, no
>   auth between them, more private). The registry is the documented escape-hatch
>   reverse; we took it from the start.
> - **The indexer decodes the settle INSTRUCTION DATA** (`MatchResultPayload`),
>   not the `TradeSettled` event — the event lacks `order_id` + commitments.
> - **The indexer is a TS package** `packages/indexer/` (SQLite via the built-in
>   `node:sqlite`); the SDK client is `packages/sdk/src/fills/`
>   (`deriveOrderId`, `backfillHistory`, `subscribeFills`, `startFillsSync`);
>   the TEE per-account routing is `api/{state,fills_router,ws}.rs`.
> - **Amount-privacy (P3b) made the indexer a pure COMMITMENT LOCATOR.** The
>   settle ix no longer carries any plaintext amount (trade size / change / fee /
>   price) — they're proven in-circuit and bound by the note commitments, so the
>   untrusted off-TEE indexer can no longer see them (by design). An indexer row
>   is now `{ order_id, side, match_id, signature, slot,
>   input_note_commitment, trade_note_commitment, change_note_commitment,
>   batch_slot }` PLUS the opaque on-chain recovery ciphertext. `slot` is the
>   finalized Solana history cursor; `batch_slot` is only the circuit slot index.
>   Exact fills remain in the locator because they still mint a recoverable
>   trade note.
> - **On-chain output recovery v3 — durable amount source.** Each side's trade
>   and change amounts live ENCRYPTED on-chain in the unchanged 128-byte
>   `fill_recovery` field
>   (X25519-ECIES to the order's `viewing_pubkey`; crypto in
>   `darkpool-crypto/src/fill_encryption.rs`, TEE-side in
>   `darknyx-tee/src/settle/fill_recovery.rs`). The indexer surfaces the opaque
>   recovery-v3 ciphertext (`ephemeral_pubkey` + per-side `output_enc`); the SDK
>   `recoverFillFromChain` decrypts `(trade, change)` with the seed-derived
>   viewing key, derives both outputs from the named consumed opening, and
>   self-verifies their commitments. `recoverNotesFromChain` scans finalized
>   history, reconstructs each hidden deposit inner as
>   `Poseidon3(27, seed_owner, public_recovery_nonce)`, verifies the resulting
>   commitment, restores settlement leaf positions,
>   and reconstructs merge
>   outputs. Its fixed-point pass handles scan-order inversions and chained
>   continuations/merges without live stream history.
>   `startFillsSync` does "tail then backfill". **The old durable per-account memo
>   log + `GET /fills/replay` (P7)
>   were RETIRED** — the chain is the permanent source, so they added no value.
> - **The off-TEE indexer is OPTIONAL — see
>   [`packages/indexer/README.md`](../packages/indexer/README.md).** With the
>   chain as the durable locator, a client can rediscover its own fills WITHOUT any
>   indexer via `packages/sdk/src/fills/chain-history.ts::backfillHistoryFromChain`
>   (returns the same `BackfillResult` as the indexer path; `startFillsSync` picks
>   whichever source is configured). The daemon uses live streams + chain reads
>   and touches no indexer. **Decision (2026-07-10):** keep the indexer code as an
>   optional light-client accelerator; don't deploy/invest until a browser or
>   deep-mainnet-history client actually needs by-order_id point queries.
>
> The sections below are the original decision record (pinned 2026-06-04).
> **NOTE: where they say the chain / `MatchResultPayload` carries the change
> `amount` in plaintext, that is pre-amount-privacy; and where they describe a
> durable `/fills/replay` memo log, that was retired — see the deltas above. The
> output amounts now ride the settle ix ENCRYPTED + are recovered from chain.**

## Problem

A continuation fill mints a change note the client must later spend. To
reconstruct + spend it, the client needs the change `amount` (the one field
it can't derive — Poseidon isn't invertible, and the on-chain leaf is just
the commitment). The CVM tells the client via a `FillMemo`.

Two distinct needs, currently (wrongly) conflated onto one WebSocket:

1. **Live transport** — low-latency "a fill just happened." Ephemeral,
   best-effort. WebSocket is the right tool; it is NOT a system of record.
2. **Durable history** — "I logged in after a week, show my past trades,"
   and "I was disconnected when a fill landed, backfill the gap." Needs
   persistence + query, NOT a socket.

The original single global fills socket was fail-closed behind the
`debug_endpoints` feature because it tried to be both and leaked every user's
memos to every authenticated subscriber. The implemented transport is now the
per-account `fills` channel on `/v1/stream`.

## Key facts that drive the design

- **The chain is the permanent record — of commitments, not amounts.** Every
  fill settles on-chain (`tee_forced_settle_batched`, `MatchResultPayload` =
  order_id + change-note commitment; **amount-privacy P3b removed the amount** —
  see the as-built delta above). The set of notes you own is never truly lost
  (worst case the client re-locates commitments from chain); their *amounts*
  live only in the FillMemo. The WS + any cache are accelerants over immutable
  on-chain truth.
- **The chain has no notion of "account."** On-chain a fill is attributable
  only to `order_id` (and note commitments). The `account` (API credential →
  bearer JWT) is purely off-chain. So an indexer reading only the chain can
  key fills by `order_id` and nothing else. The `account ↔ order_id` link is
  born at exactly ONE moment — **intake** — where the bearer (account) and
  the `order_id` are visible together. By-account history therefore REQUIRES
  an intake-time registry; there is no way to derive it from chain data.

## Decision

### 1. Deterministic, HD-derived order ids (replaces `randomBytes(16)`)

```
order_id[n] = HKDF(masterSeed, "darknyx-order-id" ‖ u32(n))[:16]
```

Same philosophy as deterministic note derivation: derive everything from
the seed, persist nothing. Consequences:

- The user never tracks order ids — the SDK regenerates them from the seed.
- **Stateless rediscovery** (HD-wallet style): on a fresh device the SDK
  derives `order_id[0], [1], …`, queries the indexer for each, and stops
  after a gap-limit run of empties. Full history recovered from the seed
  alone.
- Unpredictable to outsiders (seed secret), unique per (user, n).
- Escape hatch: makes a future switch to by-`order_id` history trivial.

### 2. Live path — WebSocket, per-account routing (option B)

The TEE knows `account → order_id` at intake, so it routes each `FillMemo`
to the owning account's channel (NOT a global broadcast). Replaces the
historical fail-closed global fills socket. Per-account filtering closes the
leak. (A bug here = a leak, so prefer per-account *channels* over
post-delivery filtering when implementing.)

### 3. Durable path — off-TEE indexer, served by-account

A **standard Solana indexer** (NOT part of the TEE — keeps the enclave a
pure, attestable engine):

- Watches the vault program's settle txs, decodes `MatchResultPayload`,
  stores fills keyed by `order_id` + a per-account monotonic cursor.
  (Amount-privacy P3b: the decode yields commitments + order ids only — no
  amounts; the indexer is a commitment locator.)
- Joins to accounts via the **intake registry** (below).
- Serves `GET /account/history?since=<cursor>&limit=N` (bearer-auth'd),
  paginated.

### 4. Intake registry (the join table)

At successful intake the TEE emits a row to the indexer (the same
`account → order_id` fact it already needs for §2 WS routing — build once,
use twice):

```
{ account_id, order_id, market, accepted_slot, ts }
```

Lives in the indexer's DB. This is the only place the `account ↔ order`
linkage is persisted. Accepted trust cost (already conceded by choosing
option B for the WS); the deterministic order ids (§1) give a clean escape
to by-`order_id` (drop the registry) if that ever becomes unacceptable.

## Client flow

```
login →  GET /account/history?since=<lastCursor>   # backfill the gap
      →  WS subscribe                               # live tail from now on
```

"Backfill then tail" is invisible to the user — the SDK sequences it. The
cursor is a per-account monotonic sequence number the indexer assigns;
the client stores only that single integer (or rediscovers via §1 gap-scan).

> **As-built (SUPERSEDED — see the top-of-doc delta):** P7 briefly made the
> gap-recovery call `GET /fills/replay` (a durable TEE memo log). That log +
> endpoint were **RETIRED** (Proposal C, commit `345681c`). The durable
> gap-recovery source is now the **on-chain** encrypted output tuple, decrypted
> by the SDK's `recoverFillFromChain` / `recoverNotesFromChain`.
> `startFillsSync` does live-tail (`fills` on `/v1/stream`) + chain backfill; the by-order_id
> indexer is the OPTIONAL commitment locator for gap-detection.

## What this explicitly does NOT need

- No per-user encryption / Zcash-style view-tags / trial decryption. That
  machinery is only the price of a *blind* server; option B already concedes
  server-side linkage, so it's off the table.
- No user-managed order-id state.
- No history DB inside the TEE (the TEE stays a pure engine; the chain +
  indexer are the record).
  > **As-built (final):** P7 briefly added a bounded exception (a durable
  > per-account fill-memo log for `GET /fills/replay`) — but Proposal B put the
  > encrypted output amounts permanently ON-CHAIN, giving them a durable
  > home, so that log + endpoint were **RETIRED** (Proposal C, `345681c`;
  > `persistence/fills.rs` + `api/fills.rs` removed). The TEE keeps NO history
  > DB; the chain is the durable record of both *which* notes exist and their
  > amounts.

## Build order when resumed

1. SDK: deterministic `order_id` derivation (one KDF where `randomBytes` is
   today) + `getHistory({since})` pager + "backfill then tail" sequencing.
2. TEE: at accepted intake, emit `{account_id, order_id, market, slot}` to
   the indexer feed; switch fills delivery from global broadcast to per-account
   channels (and drop the `debug_endpoints` gate once filtered).
3. Indexer (new service): settle-tx watcher → fills-by-order_id store +
   per-account cursor; `GET /account/history`.

## Cross-refs

- Live session handler: `crates/darknyx-tee/src/api/stream.rs` (in-band auth,
  per-account `fills` subscription).
- `FillMemo`: `crates/darknyx-tee/src/matcher/fills.rs` (live fills-channel push).
- Durable output recovery v3: `darkpool-crypto/src/fill_encryption.rs`
  + `darknyx-tee/src/settle/fill_recovery.rs` (on-chain ciphertext) →
  `packages/sdk/src/fills/recover.ts` (`recoverFillFromChain`) +
  `packages/sdk/src/fills/cold-recovery.ts` (`recoverNotesFromChain`). (The old P7
  memo log + `api/fills.rs` `GET /fills/replay` + `sdk/.../fills/replay.ts` were
  RETIRED — Proposal C, `345681c`.)
- Client memo verify/store: `packages/sdk/src/orders/fill-memo.ts`,
  `packages/sdk/src/utxo/note-store.ts`.
- Client live-tail + chain-backfill: `fills/ws-client.ts` (`startFillsSync`);
  the OPTIONAL by-order_id indexer locator is `fills/history.ts`
  (`backfillHistory`).
- Settle payload: `settlement_shared.rs::MatchResultPayload`.
