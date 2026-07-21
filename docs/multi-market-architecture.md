# Multi-market architecture — one CVM per market, or N markets per CVM?

> **Status: OPEN DECISION, deliberately deferred (2026-07-20).** Nothing here is
> implemented. This doc exists so the decision does not have to be re-derived:
> it records what the code does today, the two hard constraints that bound the
> answer, the tradeoffs, and the tentative lean. Revisit before adding the
> **second** trading pair.
>
> Companion to [`throughput-roadmap.md`](./throughput-roadmap.md) (deferred
> perf work). That doc is gated on platform capability; this one is gated on a
> product/architecture choice.

---

## 1. The question

Today Darknyx runs exactly one market (SOL/USDC). When we add a second pair
(say WBTC/USDC), do we:

* **Option A** — run a **separate CVM per market** (one TEE per pair), or
* **Option B** — run **N order books inside one CVM**, emitting one settle
  batch per market?

---

## 2. What is implemented today: one market per CVM

| Anchor | What it shows |
|---|---|
| `crates/darknyx-tee/src/config.rs` (`base_mint`, `quote_mint`, `governed_market`) | Singular mints from `DARKNYX_TEE_BASE_MINT` / `_QUOTE_MINT`; `governed_market` is true only when BOTH are set |
| `crates/darknyx-tee/src/matcher/interval.rs::MatcherState` | A **single** `book: OrderBook`, plus singular `base_mint`, `quote_mint`, `price_scale`, `fee_rate_bps` |
| `crates/darknyx-tee/src/api/instruments.rs` (module doc) | States it outright: *"one market per `MatcherDriver` for now"* |
| `crates/darknyx-tee/src/main.rs` (instruments construction) | `instruments` is a hardcoded **one-element** `vec![...]` |

The on-chain program, by contrast, is **already market-agnostic**:

* `MarketConfig` is a **per-pair PDA** — `[b"market_config", base_mint, quote_mint]`
  — carrying `price_scale`, `tick_size`, `min_order_size`, `circuit_breaker_bps`,
  `enabled`, and the mint decimals.
* Custody is **per-mint**: a `vault_token` PDA and an `OutstandingMint` counter
  per mint; the solvency invariant is enforced per mint.
* `VaultConfig` holds only the global knobs (fee rate, protocol owner,
  `tee_pubkeys`, `num_trees`).

**So the vault already supports many markets. The single-market assumption lives
entirely in the TEE binary.**

### 2.1 What `GET /instruments` actually returns (and a live bug)

The response *shape* is a list (`Vec<Instrument>`), and `GET /instruments/{symbol}`
does a lookup by symbol — the API was designed for many markets. But the list is
populated at boot with one entry whose **symbol is a string literal**:

```rust
let instruments = vec![InstrumentInfo {
    symbol: "SOL-USDC".to_string(),   // hardcoded
    base_mint: settle_base_mint,      // from config
    quote_mint: settle_quote_mint,
    ...
}];
```

**Bug, independent of this decision:** the symbol does not track the configured
mints. Deploy a WBTC market and `/instruments` still advertises `"SOL-USDC"`
while returning WBTC's mints — breaking any client that keys off `symbol`. Fix
by deriving the symbol from the mints (or making it a config var). Worth doing
now regardless of which option we pick.

---

## 3. The two hard constraints

### 3.1 The circuit forces one market per BATCH — not per TEE

`MatchBatch(N)` in `circuits/templates/match_batch.circom` takes market identity
as **batch-level public inputs** — `base_mint_lo/hi`, `quote_mint_lo/hi`,
`price_scale` — fanned into every slot, and `verify_match_batch` binds them to
the on-chain `MarketConfig` PDA. This was deliberate (the CS-02 remediation:
per-slot mints were previously unbound, allowing cross-mint fee aggregation).

**Consequence:** a single proof can never mix SOL/USDC and WBTC/USDC matches.
But this only mandates **separate batches** — one CVM can emit one batch per
market per tick. *The circuit does not force separate TEEs.*

### 3.2 The vault's signer model assumes ONE TEE cluster per vault ← the real blocker

`vault_config.tee_pubkeys` is a **single global array**, and both
`initialize.rs` and `set_tee_pubkey.rs` enforce:

```rust
require!(keys.len() == cfg.num_trees as usize && keys.len() <= MAX_TEE_KEYS,
         VaultError::InvalidKeyCount);
```

Each CVM derives exactly `num_trees` shard signers
(`darknyx/ed25519-signer/v2/{0..K-1}`, dstack-derived per `app_id`) and expects
**all of them** registered. Two CVMs therefore cannot simply both be authorized:
the global set must be exactly `num_trees` long, and each CVM believes it owns
all `num_trees` shards.

Workarounds exist (bump `num_trees` to 2K and give each CVM a disjoint shard
range) but require config gymnastics — each CVM still derives signers for *all*
`num_trees` indices under the same derivation path. **Per-market CVMs are not
free; they push against a global on-chain coupling that was designed for a
single TEE cluster.**

### 3.3 Shared Merkle shards mean cross-CVM contention

Independent CVMs settling into the **same K Merkle tree shards** contend on those
accounts, eroding the co-inclusion parallelism sharding was introduced to buy
(see `throughput-roadmap.md`). Per-market CVMs would want disjoint shard ranges
to avoid this — which is the same coupling as §3.2 from the other direction.

---

## 4. Tradeoffs

| Dimension | Option A: CVM per market | Option B: N books in one CVM |
|---|---|---|
| **On-chain signer model** | Fights `keys.len() == num_trees`; needs shard-range split or a vault change | ✅ One signer set, unchanged |
| **Client UX / trust** | N gateways, N attestations to verify, N auth sessions | ✅ One venue, one attested identity, one session |
| **`/instruments`** | One entry per endpoint; cross-market discovery is client-side | ✅ A real list — matches the API shape already built |
| **Shard contention** | CVMs contend on shared trees unless ranges are split | ✅ One settle scheduler owns all shards |
| **Blast radius** | ✅ A bug/halt in one market can't touch another | Shared fate — one bug halts all markets |
| **Proving capacity** | ✅ Naturally parallel (separate machines) | Serialized unless per-market settle queues |
| **Cost** | N billable CVMs, N attestation/funding/ALT/mirror stacks | ✅ One stack |
| **Per-market governance** | ✅ Native (`MarketConfig.enabled` per pair) | Also fine — same per-pair PDA |

---

## 5. Tentative lean: Option B (multi-market in one CVM)

Two reasons dominate:

1. **Client trust UX.** Traders expect *one venue, one endpoint, one attestation
   to verify*. Requiring a client to independently attest N enclaves — and
   re-verify MRTD/`compose_hash` per pair — to trade N pairs is a materially
   worse product, and it multiplies the surface where an attestation check can
   be skipped or botched. The API surface (`Vec<Instrument>`, lookup by symbol)
   was already designed for this.
2. **§3.2.** The single global `tee_pubkeys` set sized to `num_trees` means
   Option A is *not* the zero-work option it looks like. It needs either awkward
   shard-range configuration or an on-chain change — whereas Option B needs **no
   on-chain change at all**.

The genuine cost of Option B is **shared blast radius** and **serialized
proving**. Blast radius is mitigable with per-market kill switches
(`MarketConfig.enabled` is already per-pair and read at boot) and by keeping
per-market matcher state isolated. Proving is the one to measure — see §7.

---

## 6. What Option B would take (sketch, not a plan)

**No on-chain program change.** `MarketConfig` is already per-pair; custody is
already per-mint.

TEE side:

* `MatcherState` → `HashMap<MarketId, OrderBook>`; make `price_scale`,
  `fee_rate_bps`, fee buckets, and `next_match_id` per-market.
* **Intake** routes by market and picks the collateral mint from *that* market
  (bid → quote, ask → base) when re-deriving/verifying the note commitment.
* **Matcher tick** runs per market (each has its own clearing price + oracle
  band → the per-market Pyth feed id already exists as `DARKNYX_TEE_FEED_IDS`).
* **Settle assembler** groups matches by market and emits **one batch per
  market** — the circuit already requires this, so it becomes a grouping key,
  not new proof machinery. Per-market settle queues so a slow market doesn't
  head-of-line-block another.
* **Boot** reads a `MarketConfig` per configured pair (today: one fetch) and
  refuses any explicitly disabled market — logic already exists, just needs to
  loop.
* **Config** `DARKNYX_TEE_BASE_MINT`/`_QUOTE_MINT` → a list of pairs.
* **`/instruments`** becomes genuinely multi-entry (and fixes §2.1).

---

## 7. Open questions to resolve before committing

1. **Proving throughput under N markets.** Measured today on prod9:
   `witness ≈ 297 ms`, `prove_step ≈ 2214 ms` per batch. N markets ⇒ N batches
   per tick. Does a per-market queue hold up at target volume, or does proving
   become the wall? This interacts directly with the **🟢 GPU-proving gate** in
   `throughput-roadmap.md` — re-measure once GPU TEE is available.
2. **Shard allocation.** Do all markets share the K shards, or does each market
   get a shard range? Sharing maximizes utilization; splitting isolates failure
   and simplifies a later migration to Option A.
3. **Per-market pause semantics.** If one market's oracle goes stale or its
   breaker trips, does the CVM keep serving the others? (It should — but the
   degraded-mode signaling in `/system/status` currently describes one venue.)
4. **Blast-radius policy.** Is shared fate acceptable for high-value pairs, or
   do we eventually want tiering (majors in one CVM, long-tail in another)?
   Note this is a *hybrid* of A and B and inherits §3.2's constraint.
5. **Symbol scheme.** Canonical symbol derivation from mints (registry? on-chain
   metadata? operator config?) — needed by §2.1 regardless.

---

## 8. Immediate, decision-independent action

Fix the hardcoded `"SOL-USDC"` symbol in `main.rs` so `/instruments` reports a
symbol consistent with the configured mints. This is a correctness bug today and
is required by either option.
