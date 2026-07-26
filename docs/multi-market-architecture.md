# Multi-market architecture — one CVM per market, or N markets per CVM?

> **Status: OPTION B IMPLEMENTED (2026-07-26).** One CVM may serve up to 16
> independently routed market books. The cross-CVM cluster/discovery design is
> deliberately deferred because the vault still authorizes one global TEE
> signer set. This document is both the decision record and the operating
> contract for deciding when a CVM is full.
>
> Companion to [`throughput-roadmap.md`](./throughput-roadmap.md) (deferred
> perf work). That doc is gated on platform capability; this one is gated on a
> product/architecture choice.

---

## 1. The question

Darknyx chose between:

- **Option A** — run a **separate CVM per market** (one TEE per pair), or
- **Option B** — run **N order books inside one CVM**, emitting one settle
  batch per market?

---

## 2. What is implemented: isolated books in one CVM

| Anchor                  | As-built behavior                                                                                        |
| ----------------------- | -------------------------------------------------------------------------------------------------------- |
| `config.rs::MarketSpec` | Strict `DARKNYX_TEE_MARKETS_JSON`, 1–16 entries, unique symbols and ordered mint pairs                   |
| `main.rs`               | One `MatcherState`, `MatcherDriver`, and match channel per market                                        |
| `ApiState::matchers`    | Boot-static symbol→matcher registry; enclave-only order-id→symbol routing for later cancel/get/modify    |
| settle schedulers       | One receiver per market, one shared prover/ALT pool/signer set, one CVM-wide batch-concurrency semaphore |
| `/instruments`          | Lists every configured, finalized governed market                                                        |

The on-chain program, by contrast, is **already market-agnostic**:

- `MarketConfig` is a **per-pair PDA** — `[b"market_config", base_mint, quote_mint]`
  — carrying `price_scale`, `tick_size`, `min_order_size`, `circuit_breaker_bps`,
  `enabled`, and the mint decimals.
- Custody is **per-mint**: a `vault_token` PDA and an `OutstandingMint` counter
  per mint; the solvency invariant is enforced per mint.
- `VaultConfig` holds only the global knobs (fee rate, protocol owner,
  `tee_pubkeys`, `num_trees`).

The vault and TEE now both support multiple markets without an on-chain program
change.

### 2.1 Configuration

Governed multi-market deploys provide a JSON array through encrypted env:

```json
[
  {
    "symbol": "SOL-USDC",
    "base_mint": "<base58>",
    "quote_mint": "<base58>",
    "oracle_feed_id": "<64 hex chars>"
  }
]
```

The singular mint/symbol/feed envs remain a one-market devnet/loadgen
compatibility path. JSON may not be mixed with the singular mint envs. Every
governed market PDA is fetched at finalized commitment before intake starts;
missing, malformed, or disabled entries fail boot.

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
market per tick. _The circuit does not force separate TEEs._

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
range) but require config gymnastics — each CVM still derives signers for _all_
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

| Dimension                 | Option A: CVM per market                                                    | Option B: N books in one CVM                                |
| ------------------------- | --------------------------------------------------------------------------- | ----------------------------------------------------------- |
| **On-chain signer model** | Fights `keys.len() == num_trees`; needs shard-range split or a vault change | ✅ One signer set, unchanged                                |
| **Client UX / trust**     | N gateways, N attestations to verify, N auth sessions                       | ✅ One venue, one attested identity, one session            |
| **`/instruments`**        | One entry per endpoint; cross-market discovery is client-side               | ✅ A real list — matches the API shape already built        |
| **Shard contention**      | CVMs contend on shared trees unless ranges are split                        | ✅ One CVM-wide settle resource pool owns all shards        |
| **Blast radius**          | ✅ A bug/halt in one market can't touch another                             | Shared fate — one bug halts all markets                     |
| **Proving capacity**      | ✅ Naturally parallel (separate machines)                                   | Per-market queues share one explicitly bounded proof budget |
| **Cost**                  | N billable CVMs, N attestation/funding/ALT/mirror stacks                    | ✅ One stack                                                |
| **Per-market governance** | ✅ Native (`MarketConfig.enabled` per pair)                                 | Also fine — same per-pair PDA                               |

---

## 5. Decision: Option B (multi-market in one CVM)

Two reasons dominate:

1. **Client trust UX.** Traders expect _one venue, one endpoint, one attestation
   to verify_. Requiring a client to independently attest N enclaves — and
   re-verify MRTD/`compose_hash` per pair — to trade N pairs is a materially
   worse product, and it multiplies the surface where an attestation check can
   be skipped or botched. The API surface (`Vec<Instrument>`, lookup by symbol)
   was already designed for this.
2. **§3.2.** The single global `tee_pubkeys` set sized to `num_trees` means
   Option A is _not_ the zero-work option it looks like. It needs either awkward
   shard-range configuration or an on-chain change — whereas Option B needs **no
   on-chain change at all**.

The genuine cost of Option B is **shared blast radius** and a shared proving
budget. Each oracle failure skips only its own matcher tick; finalized global
governance/signature drift or any configured `MarketConfig` drift conservatively
pauses new trading venue-wide. Cancels and settlement reconciliation continue.

---

## 6. Routing and isolation invariants

1. Placement resolves the signed canonical `symbol` before commitment/opening
   verification and writes only that market's book.
2. The accepted-intake boundary records an enclave-only
   `order_id → market symbol` join. Cancel, get, modify, account aggregation,
   and cancel-on-disconnect use that join; callers cannot redirect an existing
   order by supplying another symbol.
3. Modify may replace only within the original market. Moving a resting order
   between markets requires cancel + a fresh signed placement.
4. Every matcher has its own book, openings, match counter, feed, and output
   channel. A `RunBatchOutput` therefore has exactly one mint pair by
   construction.
5. Settle drivers share expensive/common infrastructure but retain their
   market-specific assembly config and matcher state. One venue-wide semaphore
   bounds whole batches across all market queues.
6. Account and stream routers aggregate all matcher broadcasts without exposing
   the private account/order/market joins.

---

## 7. Capacity admission: when this CVM is full

The static 16-market parser cap is a safety bound, not an operating target. Add
one market at a time and repeat the C1 CPU baseline (then the same GPU matrix)
with representative traffic on every active book. Admit the next market only
while all of these hold for a sustained 15-minute window:

- settlement throughput is at least 20% above offered matched-pair throughput;
- oldest queued batch is below one matcher interval (2 seconds) at p95 and below
  two intervals at p99;
- submit-to-finalized user latency stays within the product SLO (record p50,
  p95, and p99, not just averages);
- the configured venue-wide proof concurrency does not regress p95 total batch
  latency by more than 10% versus the prior admitted market count;
- CPU effective utilization remains below 70%, memory below 70%, no cgroup
  throttling/OOM, and RPC 429/5xx plus ambiguous-settlement outcomes remain
  below 0.1%;
- each market retains at least 20% measured proof/CU/transaction-size capacity
  margin where the metric applies.

If any hard resource threshold holds for two consecutive windows, stop admitting
markets. If latency/queue thresholds hold after concurrency and RPC tuning,
split the venue only after the on-chain cluster authorization work below lands.

---

## 8. Cross-CVM discovery (deferred, security-gated)

Do not copy endpoint tables among CVMs and do not trust a website-hosted mutable
list. Before a second TEE cluster:

1. change the vault authorization model from one global K-key set to explicit
   cluster/shard-range authorization;
2. publish a finalized on-chain registry generation plus the SHA-256 hash of a
   canonical signed venue manifest;
3. serve that content-addressed manifest from untrusted mirrors (the website,
   GitHub/IPFS, and optionally each CVM);
4. let the daemon verify the finalized hash and governance signature, then
   attest the selected endpoint and cross-check its full signer set plus each
   advertised `MarketConfig`;
5. cache last-known-good manifests with monotonic generations and reject
   rollback, split-view, unknown-compose, or signer mismatch.

Inside one multi-market CVM none of this endpoint switching is needed:
`GET /instruments` is authoritative for the already-attested session, and the
daemon selects a symbol on the same `/v1/stream`.

---

## 9. Focused devnet rehearsal evidence (2026-07-26)

The first two-market correctness rehearsal used image
`tee-v3-hardening-71` (GHCR digest
`sha256:cacdacf6c7b87b0d12749bef359015cb1e69d862980a6b4ea076d2c09eaf3076`)
on one prod9 `tdx.xlarge` CPU CVM (8 vCPU, 16 GiB, no GPU). The boot was
strictly governed and used four Merkle shards, native witness generation,
rapidsnark, settle-send concurrency 16, and venue-wide batch concurrency C2.

The configured pairs were:

| Symbol   | Base mint                                      | `MarketConfig`                                 |
| -------- | ---------------------------------------------- | ---------------------------------------------- |
| SOL-USDC | `43W7XqVv6a6iqLanF1aVYB9YXLh4onLDo9SJ5cQTJwzS` | `DZyMmY4a6QEmh2xvmhUQwYcxbphtfJxwcvYSEdLobBEo` |
| BTC-USDC | `856iYKP8Jg64rWisj91mcMoDjjeqQk8m2VHJhWDM2K9T` | `5kGXPE8GUMN9rBSuVVYuaYTXMyMUdZNxmgJLfuaLGqkB` |

Both reuse the devnet quote mint
`FJoLyHpPZQ2GhiFrh6APjFzsDswSm6k4yY4AS1dxaSZW`. The second base mint is a
test-only BTC-like mint; it is not a production asset address.

Boot evidence:

- both finalized, enabled `MarketConfig` accounts were adopted and two
  independent 2-second matcher drivers spawned;
- the mirror cold-booted at zero leaves across four shards;
- `/instruments` returned both exact governed mint pairs from one endpoint;
- `/system/status` reported `matcher_running=true`, `settle_enabled=true`, and
  `degraded=false`;
- the real-DCAP suite passed 5/5, including RTMR event-log replay, full
  attested signer-set binding, tamper rejection, and equality with finalized
  `vault_config.tee_pubkeys`.

The live harness then deposited all five inputs before matching, rejected a
signed cross-market modify without changing the original SOL order, routed its
cancel to the original book, and submitted one crossing pair per market
concurrently. It observed `pending_settlement` for both markets before both
orders became terminal. The tree moved from 0 to 15 leaves
(`[12, 1, 1, 1]` across shards), and both Tx D signatures finalized:

| Market   | Queue | Native witness | Prove step | Full prove |   Verify |    Settle |  Pipeline | Finalized Tx D                                                                             |
| -------- | ----: | -------------: | ---------: | ---------: | -------: | --------: | --------: | ------------------------------------------------------------------------------------------ |
| SOL-USDC |  0 ms |         313 ms |   2,086 ms |   2,413 ms | 1,371 ms | 11,586 ms | 15,465 ms | `4aNB6jnnCSaJ6jyUZSe6N5MUvfuFfC9nPmXHvoALCHP32773PsnSDG8QasjQQT7ZmtRHyJjvZkbdsVKkhnrBnudE` |
| BTC-USDC | 57 ms |         321 ms |   4,045 ms |   4,412 ms |   743 ms | 10,427 ms | 15,620 ms | `tj2ppeVoYQX7Aw7QUEyWEFrEcjL4W5iL77axHXXnLkU4boj4E7BySPDpdfiDUQCK5Sbgr55FoJRvMg4KnufB1Qi`  |

Each batch had one confirmed match, zero rejected/ambiguous outcomes, and four
rebroadcasts. They finalized in adjacent slots (`478968516` and `478968517`).
The whole Vitest flow passed in 174.76 seconds; this includes five client-side
proof/deposit preparations plus the governance monitor's one-minute
pause/resume cadence, so it is not a settlement-latency metric.

Disabling only BTC-USDC caused the finalized governance monitor to pause the
venue-wide trading gate; restoring the exact boot snapshot resumed it, leaving
the final status healthy. This confirms the deliberately conservative
shared-fate policy in §5.

**Interpretation:** the architecture and isolation invariants passed on a real
CVM and real devnet settlement. C2 also exposed expected CPU contention: the
second concurrent rapidsnark prove took about twice the first while the two full
pipelines still completed together. This one-pair-per-market rehearsal is a
correctness result, not a capacity-admission result. The sustained 15-minute
load and percentile thresholds in §7 remain required before admitting a
production market count.
