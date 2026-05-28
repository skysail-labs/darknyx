# The matching layer

> Hidden orders cross inside an Intel TDX Confidential VM running
> the open-source dstack framework on Phala Cloud. The matching
> algorithm is a uniform-clearing-price frequent-batch auction with
> FIFO tie-break and a Pyth-band circuit breaker. Orders are
> visible only to the attested enclave; the matcher's signing key
> is deterministically derived inside the enclave and registered
> on Solana through a multisig rotation.

---

## Why a TEE

The matching problem has three constraints that are hard to satisfy
simultaneously:

1. **Privacy.** Order intent (side, size, limit price) must not be
   visible to the operator, validators, sequencers, or other users.
   Public order books and on-chain rollups both fail this trivially.

2. **Trust.** Users must not have to trust the operator's
   intentions. A traditional dark pool operator can front-run,
   wash-trade, or selectively censor; users have to take that on
   faith.

3. **Speed + cost.** Matching has to clear in seconds, not minutes,
   and the marginal cost per order has to be low enough that
   thin markets are economic.

Public rollups and CLOBs solve speed + cost but fail privacy.
Pure-ZK approaches (commit-reveal, MPC matching) solve privacy +
trust but fall over on speed + cost (MPC for an order book is
multi-second per match at small scales, multi-minute at any
realistic scale).

A trusted execution environment is the engineering shortcut that
makes all three work. The TEE:

- Sees orders in plaintext (privacy: the operator can't see them
  because the operator can't see inside the enclave).
- Runs known code (trust: any client can verify the enclave's
  measurement chains to Intel's TCB).
- Runs at conventional CPU speeds (speed + cost: matching is
  microseconds, batching is the rate-limit).

The catch is that the TEE has to be **attested** end-to-end: from
"this is the binary we compiled" → "this is the binary that
booted" → "this binary derived this signing key" → "this
on-chain signature is from that key." [trust-model](./trust-model.md)
walks through the full chain.

---

## Why Intel TDX specifically

| Property | TDX | AMD SEV-SNP | Intel SGX |
|---|---|---|---|
| Memory encryption | Yes (per-VM key) | Yes (per-VM key) | Yes (per-enclave key) |
| Attestation chain to vendor cert root | Yes (DCAP) | Yes (SEV API) | Yes (DCAP) |
| Available on commodity cloud | Phala, GCP, Azure (limited) | GCP, Azure, AWS | Azure (limited) |
| Programming model | Standard OS inside VM | Standard OS inside VM | Special SGX SDK; restricted syscalls |
| Side-channel resistance (post-Spectre/Meltdown class) | Improved over SGX | Improved over SEV-ES | Original target; known limitations |
| Mature open-source tooling | dstack (iden3/Phala), gramine | Limited | Long-standing (Intel SGX SDK, gramine) |
| Suitable for "run a normal Rust process" | Yes | Yes | Awkward |

TDX wins on three counts for our use case:

1. **Programming model.** TDX runs a full Linux guest. We compile
   `nyx-tee` as a normal Rust binary, package it in a Docker image,
   and Phala's tooling launches it inside a TDX VM. No SDK-specific
   gymnastics; no restricted syscall set.

2. **Attestation tooling.** The dstack framework (iden3/Phala
   open-source) gives us a clean attestation API:
   `dstack.info()`, `dstack.get_key(path)`, `dstack.get_quote(report_data)`.
   The verification chain runs the same `dcap-qvl` tool that Intel
   publishes; no proprietary attestation service required.

3. **Cloud availability.** Phala Cloud's TDX offering is publicly
   accessible with per-minute pricing (~$0.003/min on `tdx.small`).
   Alternative options exist on GCP/Azure but with more friction in
   the attestation chain.

The alternative we evaluated was MagicBlock's Permission Group
Ephemeral Rollup (PER). PER was the v1 matching path; the v2
migration is moving away from it. The motivation: PER attestation
depended on MagicBlock's own infrastructure; the cluster ran a
forked Solana rollup with its own delegation/undelegation
choreography. The TDX CVM collapses all of that into a single
Rust process with a single attestation chain.

---

## The matching algorithm

The matcher is a **uniform-clearing-price frequent-batch auction**:

1. Orders accumulate in the in-memory order book.
2. Every `BATCH_MS` milliseconds (default 2000 ms = 2 seconds),
   the matcher tick runs:
   - Snapshot the order book.
   - Read the latest Pyth TWAP from the oracle cache.
   - Compute the clearing price (the price that maximizes matched
     volume subject to all limit constraints).
   - Apply FIFO tie-break: at any given price level, earlier
     orders fill before later orders.
   - Check the Pyth-band circuit breaker: if the clearing price
     differs from Pyth's TWAP by more than `circuit_breaker_bps`,
     skip the batch.
   - Emit `RunBatchOutput { matches, clearing_price, ... }`.

3. Matches feed the settle scheduler (see
   [settlement-pipeline](./settlement-pipeline.md)).

The algorithm lives in a separate crate (`darkpool-matcher`) that
is **the single source of truth**. Both the on-chain `run_batch`
instruction (used in the v1 MagicBlock PER path) and the in-TEE
matcher consume the same crate. Identical bytes in, identical
matches out — regardless of which environment is running it.
Behavioral parity is enforced by a litesvm integration test
(`crates/darkpool-matcher/tests/parity.rs`).

### Why uniform clearing price

Three reasons:

1. **No order-book griefing.** With continuous matching, a
   sophisticated MEV bot can front-run pending orders. With
   batched auctions, every order in the batch clears at the same
   price; front-running buys you nothing.

2. **No price discovery loss.** The clearing price is computed
   over all orders in the batch jointly, so it reflects the
   marginal supply/demand curve rather than the first-mover's
   willingness-to-pay.

3. **Simpler proofs.** VALID_MATCH_BATCH attests a single price
   across N matches. A continuous matcher would need a separate
   proof per match (the v3 design we moved away from); per-match
   proofs cost ~10× the constraint budget of one batched proof.

### Why frequent batches (BATCH_MS = 2000)

The choice of 2 seconds for the default batch interval reflects
three tradeoffs:

- **Settle latency floor.** The on-chain settle pipeline (Tx A
  through E) takes ~2–3 seconds end-to-end on devnet. Running the
  matching tick faster than that pipeline saturates it; new
  matches pile up faster than they can be settled.

- **Order-flow latency.** A trader who submits an order at
  T=0 expects a fill at T=2s, not T=20s. Two seconds is the
  short end of the "feels live" range for human traders; tighter
  is for HFT, looser starts to feel like batch settlement.

- **Per-market tunability.** `MatchingConfig.batch_ms` is on-chain
  and per-market. Liquid markets can dial faster (toward 500ms);
  thin markets can dial slower (toward 10s) without a code change.
  The 2s default is the new-market template.

### Circuit breaker

If the matcher's computed clearing price differs from the Pyth
TWAP by more than `circuit_breaker_bps` (default 500 bps = 5%),
the batch is skipped. No fills, no settle, orders remain in the
book.

The breaker exists because a market with thin order flow can
sometimes "clear" at a price wildly out of line with the external
oracle (e.g., a single order $10 above the next-best bid creates
an artificial $10 price spike). The breaker stops the TEE from
honoring those clears.

In a real-world incident shape (Pyth feed outage, oracle delay,
or adversarial price manipulation), the breaker also bounds the
damage: even if an attacker successfully bribes the matcher to
sign a settle, the settle would have to clear within `band%` of
the Pyth feed. The on-chain verifier doesn't re-check this band
(it would cost too much in Solana compute units), but the
breaker provides an in-TEE safety belt.

---

## The frequent-batch auction in pseudocode

```rust
// crates/darkpool-matcher/src/lib.rs (simplified)
pub fn run_batch(
    book: &OrderBook,
    oracle: &OracleSnapshot,
    cfg: &MatchConfig,
    current_slot: u64,
    start_match_id: u64,
) -> Result<RunBatchOutput, MatchError> {
    // 1. Sweep expired orders (any order with
    //    expiry_slot <= current_slot + SETTLEMENT_BUFFER_SLOTS
    //    is dropped before matching).
    let book = book.without_expired(current_slot);

    // 2. Partition book into bids and asks, each price-sorted.
    let (bids, asks) = partition_book(&book);

    // 3. Compute the clearing price (the price that maximizes
    //    matched volume).
    let clearing_price = compute_clearing_price(&bids, &asks, oracle)?;

    // 4. Circuit-breaker check: |clearing - oracle.twap| <= band.
    if !within_oracle_band(clearing_price, oracle.twap, cfg.circuit_breaker_bps) {
        return Ok(RunBatchOutput::empty(
            current_slot,
            clearing_price,
            CB_TRIPPED,
        ));
    }

    // 5. Match orders in FIFO order at the clearing price.
    let mut matches = Vec::new();
    let mut match_id = start_match_id;
    while let Some((bid, ask)) = next_crossing_pair(&bids, &asks, clearing_price) {
        let pair = build_match_pair(bid, ask, clearing_price, match_id, &cfg)?;
        matches.push(pair);
        match_id += 1;
    }

    // 6. Generate change notes for partial fills, apply
    //    fee accumulator drain rules, etc.
    let output = finalize_output(matches, clearing_price, oracle, current_slot, cfg)?;
    Ok(output)
}
```

The actual implementation is ~2000 lines of pure Rust. No
floating point anywhere — every amount, price, and fee is u64.
The matcher is deterministic given identical inputs (no clock
reads, no random sources). This is what makes the
single-source-of-truth property work: the on-chain `run_batch`
ix and the in-TEE matcher both call into the same Rust crate
and produce identical outputs.

---

## The order book

The in-TEE `OrderBook` is a multi-index data structure:

| Index | Type | Purpose |
|---|---|---|
| `bids` / `asks` | `BTreeMap<Price, FifoQueue<OrderId>>` | Price-time priority for matching |
| `by_id` | `HashMap<OrderId, Order>` | Canonical storage + cancel-by-id lookup |
| `by_trader` | `HashMap<TradingKey, HashSet<OrderId>>` | Cancel-by-owner + self-trade prevention |
| `by_expiry` | `BTreeMap<Slot, HashSet<OrderId>>` | Cheap expiry sweep (range-scan ≤ current_slot) |

Submit and cancel both take a brief write lock (microseconds);
the matcher tick takes a brief write lock to apply the post-batch
updates (also microseconds). Concurrent read traffic (status
queries from clients) takes the read lock and doesn't contend.

The book is purely in-memory. There's no persistence layer in v2;
on TEE restart, the book starts empty. Open orders that were in
flight at restart time are lost — clients have to resubmit. The
deliberate choice here: persistence in a TEE adds attestation
complexity (the disk image becomes part of the trust chain), and
the order-book reset interval (TEE restarts are rare) is short
enough that resubmission is acceptable. v3 may revisit this with
LUKS-encrypted persistence; for now, in-memory.

---

## The oracle integration

The matcher reads oracle prices from a Pyth pull-pattern feed:

1. **Background sync task.** Every 1 second, `oracle_sync` fetches
   the latest signed VAA (Verifiable Action Approval) from Pyth's
   Hermes endpoint for each configured feed.

2. **VAA verification.** The fetched VAA is verified inside the
   TEE using a hand-rolled secp256k1 ecrecover + Keccak256 chain
   that matches Wormhole's signature scheme. The TEE accepts only
   VAAs signed by the current Wormhole guardian set (mainnet
   set 6, 19 guardians, quorum 13).

3. **Cache write.** The verified `(twap, confidence, exponent,
   publish_slot)` is written to the in-process `OracleCache`.

4. **Matcher read.** Every tick, the matcher reads the snapshot
   for the active feed. If the snapshot is stale (older than
   `max_oracle_age_ms = 5_000`), the tick skips — better to
   no-op than match against stale prices.

The VAA verification gives us a meaningful trust property: even
the TEE operator can't substitute Pyth prices, because the
in-process verification chain is rooted at the Wormhole guardian
public keys. The worst the operator can do is censor (refuse to
fetch) or delay; both surface as stale-oracle tick skips, which
is graceful.

---

## How matching composes with settlement

The matcher produces a `RunBatchOutput` per tick. The output flows
into the settle scheduler, which orchestrates the five-transaction
pipeline described in [settlement-pipeline](./settlement-pipeline.md):

```text
matcher tick (every 2s)
    │
    ▼
RunBatchOutput { matches: [MatchPair × N], clearing_price, ... }
    │
    ▼
mpsc::channel  ──►  SettleScheduler
                          │
                          ▼
                    per match:
                    ┌──── Tx A (lock_note × 2)
                    │
                    ├──── in-TEE Groth16 prover
                    │     (VALID_MATCH_BATCH n=16)
                    │
                    ├──── Tx B (verify_match_batch)
                    │
                    ├──── Tx C (per-batch ALT)
                    │
                    ├──── Tx D (tee_forced_settle_batched)
                    │
                    └──── Tx E (close_batch_validity_marker)
```

The settle scheduler is single-threaded per batch but processes
batches concurrently when the matcher emits multiple outputs in
rapid succession. Each match's pipeline is independent — if one
match fails (e.g., the user's note got withdrawn between match
time and settle time), it's surfaced as a `Failed` job; the rest
of the batch proceeds.

---

## Self-trade prevention

Two layers:

1. **In-matcher.** When the matcher checks crossing pairs, it
   skips any pair where `bid.trading_key == ask.trading_key`.
   The check is essentially free (one equality compare).

2. **In-handler.** `POST /orders` rejects an order whose
   `trading_key` doesn't match the order's own self-trade-policy
   field (if set). This is a per-account policy that defaults to
   "no self-trade" and can be toggled on for arbitrage
   strategies that legitimately need to cross themselves.

The matcher-level check is the load-bearing one. The handler-level
is a UX nicety so users get a clean 422 instead of a "silently
unmatchable" experience.

---

## Performance characteristics (informational)

Numbers below are from internal benchmarks on the dstack simulator
(local dev hardware) and a small Phala devnet CVM. The full
benchmark report lives in `crates/nyx-tee-loadgen/BENCHMARK.md`
(planned to be populated as the load-gen workstream completes).

| Metric | Local-simulator (dev machine) | Phala devnet (tdx.small) |
|---|---|---|
| POST /orders end-to-end | ~3 ms p50 | ~25 ms p50 (mostly network) |
| Matcher tick (book size 100) | <1 ms p50 | <1 ms p50 |
| Matcher tick (book size 1000) | ~5 ms p50 | ~6 ms p50 |
| VALID_MATCH_BATCH prove (N=16) | TBD (4g.4b lands the prover) | TBD |
| Settle pipeline end-to-end | ~2.5 s p50 (Solana finality) | ~2.5 s p50 |

The settle pipeline latency is dominated by Solana confirmation
times, not the in-TEE work. Optimizing the TEE's wall-clock
performance won't move the user-visible "submit to fill" number
until on-chain finality also drops.

---

## What's coming

The matching layer is in the middle of the **TEE v2** migration.
Status as of mid-2026:

- ✅ dstack handshake (boot path)
- ✅ Ed25519 signer derivation
- ✅ Oracle VAA verification + sync
- ✅ Matcher driver + tokio interval
- ✅ HTTP surface (`/health`, `/info`, `/attestation`, `/auth/token`,
  `/orders`, `/settlement/status`)
- ✅ POST /orders auth (Layer A + Layer B)
- ✅ Settle scheduler skeleton + Solana RPC client
- ✅ `lock_note` builder + Tx A submission
- ✅ VALID_MATCH_BATCH prover foundation (witness types, leaf/root
  computation, conservation validators)
- ⏳ In-TEE Groth16 prover wiring (next PR)
- ⏳ Tx B / C / D builders
- ⏳ Tx E (close marker)
- ⏳ End-to-end litesvm test

See [roadmap-and-status](./roadmap-and-status.md) for the full
list with commit references.

---

*Last updated 2026-05-29. Source of truth: `crates/darkpool-matcher/`,
`crates/nyx-tee/`, `docs/tee-architecture.md`.*
</content>
