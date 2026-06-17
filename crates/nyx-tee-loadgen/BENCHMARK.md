# nyx-tee-loadgen — benchmark report

> **First Phala devnet run — 2026-05-31.** Live report below, followed by
> notes on what it means (and the gap it surfaced). The original
> template / run-protocol reference is preserved, commented out, at the
> bottom of this file.

---

## Harness v2 — scenarios, configurable market, observability

The loadgen is the synthetic-load half of the e2e harness: it stresses **intake
+ the matcher** (batching, paging, anchor rotation, execution policy). Synthetic
orders carry stub VALID_INPUT proofs, so a *match* attempts to settle but the
on-chain lock fails — settle is NOT exercised here (that's `--real-settle`, below).

**Scenarios** (`--scenario`, default `uniform`):

| Scenario | Order shape | Stresses |
|---|---|---|
| `uniform` | side coin-flip; price in `twap × [0.95,1.05]`; lognormal size | broad intake throughput; crosses by chance |
| `exact-match` | alternating bid/ask at the midpoint, equal size | matcher batch path — every pair fully matches |
| `partial-fill` | `exact-match` but bids are 2× the ask size | continuation / anchor-rotation at a high rate |
| `ioc-fok` | `exact-match` with order_type cycling limit/ioc/fok | IOC / FOK execution policies |
| `over-collateral` | `exact-match`; declares `collateral_amount` `--over-collateral-bps` above min | intake's over-collateral path + surplus-as-change |

**Configurable market:** `--base-mint`/`--quote-mint` (32-byte hex) +`--symbol`.
Must match the target CVM's regime — placeholder mints (`…b1`/`…9e`, the default)
for a `from_boot` CVM, or the `.devnet/e2e-config.json` mints for a real-mint CVM.
`--fee-rate-bps` MUST equal the CVM's `NYX_TEE_FEE_RATE_BPS`.

**Observability:**
- `--status-preflight` (default on): `GET /system/status` before firing; aborts if
  the CVM is `degraded`. `--no-status-preflight` to override.
- 429 backoff: the trader respects the rate limiter's `Retry-After` and the report
  breaks out the `↳ 429 rate-limited` subset of 4xx — so a flood measures
  throughput, not an error storm.
- `--poll-orders <0..1>`: sample a fraction of accepted orders for a
  `GET /orders/{id}` lifecycle read (logged at debug).

Example (placeholder-mint CVM, partial-fill stress, 20 traders):

```sh
RAW=$(curl -s "https://hermes.pyth.network/v2/updates/price/latest?ids[]=ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d" | jq -r '.parsed[0].price.price')
cargo run -q -p nyx-tee-loadgen -- --endpoint "$GW" --oracle-twap "$RAW" \
  --scenario partial-fill --fee-rate-bps 30 --traders 20 --duration-secs 25 --poll-orders 0.1
```

## Roadmap — `--real-settle` (opt-in real on-chain settle)

The Hybrid harness's second half: a small N of **real-note traders** that deposit
on-chain, prove a real VALID_INPUT, POST a crossing order, and track the on-chain
settle (leaf-count growth / `TradeSettled`) — the loadgen analogue of
`cvm-settle-e2e`, plus a `merge-before-order` variant. Behind the `real-settle`
cargo feature (keeps the default synthetic build lean — no ark-circom/wasmer).

**Increment A — DONE (`src/real_settle.rs`).** The CVM-free, unit-tested core:
- A **Rust VALID_INPUT prover** (`ValidInputProver`) — ark-circom against
  `circuits/build/valid_input`, mirroring the SDK's `proveValidInput` (none
  existed before: the TEE proves VALID_MATCH_BATCH, clients prove VALID_INPUT
  via snarkjs). Emits the same 256-byte on-chain proof layout.
- A depth-20 Poseidon **`IncrementalTree`** + `MerkleWitness` (mirrors the SDK's
  `MerkleShadow`).
- Validated by `cargo test -p nyx-tee-loadgen --features real-settle`: a proof is
  produced AND verifies against the circuit's own zkey VK — no CVM needed.

**Increment B — building blocks DONE (behind `real-settle-chain`), live wiring
TODO.** The Solana glue on top of Increment A, using the modular solana-* stack
(NOT solana-client — it conflicts with ark 0.5 on zeroize):

- **B1 (`vault.rs`, unit-tested):** the vault `deposit` ix builder + PDAs + anchor
  discriminator + the NoteCreated event parser — hand-mirrored from the SDK and
  asserted byte-for-byte (discriminator, the 81-byte data layout, the 10-account
  order, PDA determinism, event round-trip).
- **B2 (`rpc.rs` + `flow.rs`, unit-tested where pure):** a minimal reqwest
  JSON-RPC client (blockhash / send / confirm / logs / account-data) and a
  `RealSettleHarness` that signs+sends a tx, `deposit()`s a note (recovering its
  real `(tree_id, leaf_index)` from the event into a per-shard `IncrementalTree`),
  reads summed `leaf_count`, and `prove()`s VALID_INPUT against the right shard.

**`--real-settle` — DONE + validated live.** `run.rs` drives a REAL crossing
pair through the live CVM: mints collateral (hand-built SPL MintTo +
CreateIdempotentATA ixs — `spl.rs`, avoiding the `spl-token`/ark zeroize
conflict), deposits a bid + ask note into shard 0 (co-shard inputs — a split
fails lock, see cvm-multimatch), proves VALID_INPUT (Increment A), POSTs both
orders, and watches the settle land.

```sh
cargo run -p nyx-tee-loadgen --features real-settle-chain -- \
  --endpoint "$GW" --real-settle --rpc-url "$HELIUS" \
  --admin-keypair .devnet/keypairs/admin.json \
  --base-mint <hex32> --quote-mint <hex32> \
  --oracle-twap "$ORACLE_RAW" --real-qty 2000 --fee-rate-bps 30 --real-num-trees 4
```

Validated 2026-06-17 on `tee-v3-hardening-29` (num_trees=4): **leaf_count 2 → 7**
(note_c/d + buyer change + base & quote fee notes) — the Rust VALID_INPUT prover's
proofs were accepted by the on-chain `lock_note`. See `docs/cvm-run-runbook.md`.

## `--real-settle` LOAD rig — multi-trader, multi-scenario (the protocol testing rig)

`run_real_settle_load` (auto-selected when `--traders > 1` or a non-trivial
`--real-mix`) drives N scenario INSTANCES end-to-end through the live CVM and
reports the prover-bottleneck evidence. Inputs now **span shards** (the cross-shard
`tree_id` fix — `feat(tee): carry tree_id …`), so deposits parallelize K-ways and a
batch can settle inputs from different shards.

**Scenarios** (`--real-mix "exact-match:50,partial-fill:20,merge:20,over-collateral:5,ioc-fok:5"`):

| Scenario | Pathway | Exercises |
|---|---|---|
| `exact-match` | bid + ask, equal qty | baseline full-fill settle |
| `over-collateral` | bid note +20% over required → surplus change note | over-collateral path |
| `partial-fill` | 1 big bid + M small asks (`--real-multi-anchor-asks`) → M fills over M batches | continuation / consumes M anchors |
| `merge` | deposit 2 sub-threshold notes → VALID_MERGE → ask off the merged note | the merge→spend pathway |
| `ioc-fok` | crossing pair, IOC bid / FOK ask | execution-policy plumbing |

**Phases:** plan → mint+deposit(+merge) all notes (sequential, shards round-robined)
→ **prove all VALID_INPUT concurrently** (`spawn_blocking` across cores) → submit all
concurrently → drain the settle.

**Prover-bottleneck metrics** (loadgen-only + CVM-log cross-ref, per the decision):
- **Client prove rate** — proofs/sec + p50/p95 of every VALID_INPUT/MERGE prove (the
  host-side proving ceiling that caps order submission).
- **End-to-end settle rate** — settled-matches/sec from `leaf_count` growth; plateaus
  below offered load when the TEE prover (VALID_MATCH_BATCH) is the bottleneck.
- **Cross-ref** — the run prints `phala cvms logs <cvm> | grep -E "prove breakdown|
  settle pipeline timing"` to read the TEE's `prove_step_ms` (the dominant settle cost).
  Per `rapidsnark_ab_results`, the lever is vCPU/GPU → the evidence base for GPU proving.

```sh
cargo run -p nyx-tee-loadgen --features real-settle-chain -- \
  --endpoint "$GW" --real-settle --rpc-url "$HELIUS" \
  --admin-keypair .devnet/keypairs/admin.json \
  --base-mint <hex32> --quote-mint <hex32> --oracle-twap "$ORACLE_RAW" \
  --fee-rate-bps 30 --real-num-trees 4 \
  --traders 8 --real-mix "exact-match:40,partial-fill:30,merge:20,over-collateral:5,ioc-fok:5"
```

**Load sweep** (throughput-vs-offered-load curve): an EXTERNAL loop — each step needs a
fresh tree (reset + redeploy cold-boots the mirror; a mid-run reset desyncs it), so:
```sh
for T in 2 4 8 16; do
  # reset all shards + redeploy the image (see docs/cvm-run-runbook.md), then:
  cargo run -p nyx-tee-loadgen --features real-settle-chain -- … --traders "$T"
done
```
The settle-rate plateau across the steps is the prover ceiling.

### Live results — 2026-06-17, image `tee-v3-hardening-30` (num_trees=4)

`--traders 5 --real-mix "exact-match:1,partial-fill:1,merge:1,over-collateral:1,ioc-fok:1"`
(one of each scenario; merge + multi-anchor included):

- **Cross-shard fix validated** — `cvm-multimatch-settle` with round-robin INPUTS
  across all 4 shards SETTLED (previously `StaleMerkleRoot`). The `tree_id` threading
  works end to end.
- **Rig drives all 5 scenarios end to end through matching** — 12 orders (incl. the
  merge's deposit-2→VALID_MERGE→order-off-merged-note) deposited, proved, submitted;
  **12/12 accepted**; the matcher produced **7 matches** across 3 batches at a uniform
  clearing price.
- **★ Prover bottleneck quantified** — client VALID_INPUT proving is **~40 s/proof**
  (12 proofs in 45 s wall ≈ 0.27/s even across cores). This is the host-side ceiling
  that caps order submission, and the TEE's VALID_MATCH_BATCH prove dominates settle
  the same way (`rapidsnark_ab_results`: vCPU is the lever). **→ the evidence base for
  GPU-accelerated proving.**

**Finding — multi-batch settle fails under concurrent load** (a NEW issue the rig
surfaced; single-pair + single-batch tests never hit it). On `-30`:
- partial-fill continuation batches failed `AccountOwnedByWrongProgram (3007)` on
  `note_lock_a` — a dependent batch's settle simulated before the prior batch that
  creates its relock NoteLock landed → a **cross-batch continuation ordering race**.
- the 5-match batch reverted at instruction 1 (`Custom 0`).
- **net result: `leaf_count` 14→14 — 0/7 matches settled.**

**Root cause + fix — `SETTLE_CONCURRENCY` 3→1** (image `-31`, commit `d9a388b`):
the scheduler ran up to 3 settle batches concurrently, but all batches share **one
rolling per-batch ALT** (a Mutex-guarded pool) and continuation batches depend on a
prior batch's relock NoteLock. Three batches racing the same ALT corrupted batch 0's
account list (the `Custom 0` revert) and let continuation batches settle before their
parent's relock landed (the `3007` cascade). Serializing settle (FIFO, one batch at a
time) respects both invariants. The within-batch co-inclusion
(`settle_send_concurrency=16`, the tree-sharding win) is untouched.

### Live re-validation — 2026-06-17, image `tee-v3-hardening-31` (SETTLE_CONCURRENCY=1)

Same run (`--traders 5 --real-mix "exact-match:1,partial-fill:1,merge:1,over-collateral:1,ioc-fok:1"
--real-multi-anchor-asks 3`): 12/12 accepted, 7 matches across 3 batches.
- **`leaf_count` 14→28 (+14 = 7 matches × 2 leaves)** — vs 14→14 on `-30`. Multi-batch
  settle now LANDS; the catastrophic 0/7 failure is resolved.
- Batches settled ~7 s apart (serial), vs ~2 s concurrent on `-30` — the expected
  serialization, and the cost is hidden behind the ~40 s prove anyway.
- The `-31` mixed run also showed residual batch-0 `Custom 0` + continuation `3007` log
  lines timestamped **after** the leaf reached 28 — `send_and_confirm_with_rebroadcast`
  re-simulating an already-landed tx against post-settle state (spurious retry noise), but
  the leaf accounting (+14) alone couldn't distinguish "all settled" from "batch-0-only".

### Isolation run — 2026-06-17, image `-31`, the continuation chain is CLEAN

Focused run (`--real-mix "partial-fill:1" --traders 1 --real-multi-anchor-asks 3`
= 1 big bid + 3 small asks → **3 pure-continuation batches**, fresh-reset tree) to settle
the ambiguity definitively. The CVM settle log (not just the leaf count):

| batch | match | Tx D confirmed slot | total_ms | result |
|---|---|---|---|---|
| 0 | 0 | 470102866 | 16894 | `batch settled; openings evicted` |
| 1 | 0 | 470102908 | 16282 | `batch settled; openings evicted` |
| 2 | 0 | 470102949 | 15437 | `batch settled; openings evicted` |

- **All 3 continuation batches settled cleanly, in strict dependency order** — monotonic
  confirmed slots ~40 apart (serial, as designed); each child batch locked its parent's
  relocked residual. **Zero `3007`, zero `Custom 0`** in the logs. `leaf_count` 4→9→14→19
  (+15 = 3 fills × 5 leaves: 2 trade + 1 buyer change + base+quote fee per fill).
- This is exactly the path that failed `0/7` on `-30`. The `SETTLE_CONCURRENCY=1` fix is
  **fully validated** for the partial-fill continuation chain; the `-31` mixed-run residual
  error lines were confirmed spurious retry-after-confirm noise.
- **Operator note:** the loadgen `--real-settle` needs the real e2e-config mints passed as
  **64-char hex** (`--base-mint`/`--quote-mint`); they default to the placeholder dev mints
  (`…b1`/`…9e`), which aren't on-chain token mints → the first ATA `CreateIdempotent` fails
  `IncorrectProgramId` before any order. Convert base58 → hex (`PublicKey.toBytes()`).
- **Per-stage timing** (n=1 batches): `settle_ms` ≈ 8.7–10.1 s dominates each batch (mostly
  rebroadcast wait on devnet), `prove_ms` ≈ 4 s. At n=1 the on-chain settle IO dominates;
  the VALID_MATCH_BATCH prove only dominates at n=16 — consistent with the prover-bound
  thesis once batches are full. Note: the loadgen's `settled_matches=7` print is a
  leaf/2 heuristic that over-counts (each fill mints 5 leaves, not 2); the **authoritative
  count is 3 fills**, one per continuation batch, per the CVM `batch settled` logs.

---

# nyx-tee-loadgen benchmark

## Run configuration

| Param | Value |
|---|---|
| endpoint | `https://0c2306ef189c4c9837d2b0d3b2c3c3596dd1f3b2-8080.dstack-pha-prod5.phala.network` |
| traders | 10 |
| target rate (aggregate) | 50.0 orders/s |
| duration | 30s |
| workload | Uniform |
| cancel_rate | 0.20 |
| auth_mode | PerTrader |
| oracle_twap | 8259000000 |

## Throughput

| Metric | Value |
|---|---|
| elapsed | 30.26s |
| actual submit rate | 27.5 orders/s |
| target submit rate | 50.0 orders/s |
| achieved/target ratio | 55.0% |

## Submit outcomes

| Outcome | Count | % |
|---|---|---|
| 2xx accepted | 830 | 99.76% |
| 4xx client error | 2 | 0.24% |
| 5xx server error | 0 | 0.00% |
| network error | 0 | 0.00% |
| **success rate** | | **99.76%** |

## Cancel outcomes

| Outcome | Count | % |
|---|---|---|
| 2xx ok | 105 | 45.45% |
| 4xx | 126 | 54.55% |
| 5xx + net err | 0 | 0.00% |

## Latency (ms)

| Stream | count | P50 | P95 | P99 | P99.9 | max |
|---|---|---|---|---|---|---|
| submit | 832 | 274.43 | 316.42 | 564.74 | 840.70 | 840.70 |
| cancel | 231 | 273.66 | 313.86 | 320.25 | 320.77 | 320.77 |
| match (TODO) | 0 | — | — | — | — | — |

*Generated by `nyx-tee-loadgen`. See `docs/tee-architecture.md` §13.4 for design.*

---

## Notes on this run

- **Throughput is RTT-bound, not TEE-bound.** The 27.5/s sustained
  (55% of the 50/s target) reflects the dev-Mac→Phala internet RTT
  (~274ms P50) serializing each trader's submit+cancel — not the TEE,
  which absorbed everything with **0 server errors and 99.76% 2xx**. To
  measure the TEE's true intake ceiling, run the generator from the
  CVM's region or with many more traders to hide the RTT.
- **Matching worked; settle did not keep up.** The matcher cleared
  **23–50 matches per 2 s tick** at a uniform clearing price tracking
  the live ~$82 SOL/USD oracle. But **every batch failed settle
  assembly** — `batch has N matches but circuit N = 16`. The settle
  assembler errors on >16 matches instead of chunking the match set
  into `ceil(N/16)` sub-batches, so **0% of matches settled** under
  load (assembly fails before the lock→prove step is ever reached).
  Follow-up: TEE-side settle chunking (the SDK's `settleBatchViaBatched`
  already does this). This is the D5 (matching-cadence) input.
- The 54% cancel-4xx rate is cancel-after-fill / cancel-after-match
  races — expected at `cancel_rate=0.2` against an actively matching
  book, not an error.
- Run used: real Pyth SOL/USD feed (`NYX_TEE_FEED_IDS`), the env
  bootstrap auth account, and per-side market-mint-aligned note
  commitments (loadgen fix). CVM deleted after the run.

---

## Run 2 — after the paged-matching PR (A + C), 2026-05-31

Same config (10 traders × 5/s × 30s, real Pyth feed). Submit:
**839 / 839 2xx (100%)**, 0 5xx, **27.7 orders/s** (still RTT-bound from
the dev Mac — P50 274ms / P99 570ms). Cancel: 147 2xx / 78 4xx (races).

**What A + C fixed (the point of the run):** the matcher now pages each
tick into ≤16-match batches (34 page-emissions observed; batch sizes
16/14/11/3/1…). The pre-PR failure — `settle: batch assembly failed …
batch has N matches but circuit N = 16` — is **gone (0 occurrences)**.
The settle pipeline now engages per batch instead of dropping oversized
ticks.

**Next gap the run surfaced (was masked by the size error):** assembly
now fails with `no opening in store for buyer/seller note` (×34). When
an order partial-fills it relocks to a change note (note_e), and a later
page matches that note — but the change note's opening was never
recorded in the intake-only opening store, so the assembler can't build
its witness. This blocks before the lock→prove step. It is independent
of A+C (those fixed chunking); it's the next settle-assembly fix
(record/derive change-note openings) on the path to settle-under-load.
Full on-chain settle additionally needs a SOL-funded TEE signer + real
deposited notes (the synthetic loadgen orders aren't on-chain) — the
separate prove→settle harness, deferred.

---

## Run 3 — after the single-fill PR (option A), 2026-05-31

Same config (10 traders × 5/s × 30s, real Pyth feed). Submit: **829 /
829 2xx (100%)**, 0 5xx, 27.4 orders/s (still RTT-bound). Batches paged
≤16 (sizes 16/8/16/4/7/9/12/16/6/13/1…).

**What option A fixed:** the in-TEE matcher now runs single-fill mode
(one fill per order per batch) and drops relocked residuals from the
book, so no match references a change note. The Run-2 gap is **gone**:

| log signal | Run 2 | Run 3 |
|---|---|---|
| `batch has N matches but circuit N = 16` | 0 (fixed by A+C) | 0 |
| `no opening in store …` | **34** | **0** |
| `batch assembly failed …` | 34 | **0** |

**Every batch now assembles and submits an on-chain settle tx.** 23
batches reached the chain and failed at the *expected* next wall:
`Transaction simulation failed: Attempt to debit an account but found
no record of a prior credit` — the synthetic loadgen orders aren't
backed by real deposited notes and the TEE signer holds 0 SOL. That is
the deferred prove→settle harness (funded signer + real notes + market
state), not a code gap.

Pipeline now validated end-to-end on a live CVM: **intake → match →
page (≤16) → assemble ✓ → on-chain settle submit → stops only at the
no-real-funds wall.** Remaining for actual settled throughput: the
funded-signer/real-notes harness, and (for full residual draining) the
client re-submission relayer.

<!-- ─────────────────────────────────────────────────────────────────
ORIGINAL TEMPLATE / RUN-PROTOCOL REFERENCE (commented out 2026-05-31;
superseded by the live run above, kept for the re-run protocol):

# nyx-tee-loadgen — benchmark report (template)

This file is a placeholder. The real version is regenerated each time
`nyx-tee-loadgen` runs against a deployed CVM with `--report
BENCHMARK.md`. Two runs are expected to be checked in alongside any
PR that meaningfully changes the daemon — one against a
local-simulator instance and one against a Phala devnet CVM, side
by side so the gap (TDX overhead + Phala gateway hop) is visible.

See `docs/tee-architecture.md` §13.4 for what each section means and
when to re-run.

## Run protocol

For each meaningful PR touching the in-TEE daemon:

```sh
# Build TEE with the debug oracle-seed endpoint on.
cargo build -p nyx-tee --features debug_endpoints --release

# Local simulator (cheap, fast iteration):
~/dstack/sdk/simulator/dstack-simulator > /tmp/sim.log 2>&1 &
DSTACK_SIMULATOR_ENDPOINT=$(realpath ~/dstack/sdk/simulator/dstack.sock) \
  NYX_TEE_HTTP_BIND=127.0.0.1:8080 \
  ./target/release/nyx-tee &

cargo run -p nyx-tee-loadgen --release -- \
  --endpoint http://127.0.0.1:8080 \
  --traders 100 \
  --orders-per-trader-per-sec 5 \
  --duration-secs 60 \
  --seed-oracle \
  --report BENCHMARK-local.md

# Phala devnet (real numbers):
phala deploy -c deploy/docker-compose.yaml -n nyx-tee-bench
# (wait for boot, then run loadgen without --seed-oracle since
#  production CVMs don't expose /__debug/*)
cargo run -p nyx-tee-loadgen --release -- \
  --endpoint https://nyx-tee-bench.<custom-domain> \
  --traders 100 \
  --orders-per-trader-per-sec 5 \
  --duration-secs 60 \
  --report BENCHMARK-phala.md
phala cvms delete nyx-tee-bench
```

Then commit both files into this directory. The PR description
should call out any percentile that meaningfully regresses.

## Expected sections (rendered by `crate::report`)

- `## Run configuration` — endpoint, traders, rates, workload params
- `## Throughput` — actual submit rate, achieved/target ratio
- `## Submit outcomes` — 2xx / 4xx / 5xx / net-err counts + success rate
- `## Cancel outcomes` — 2xx / 4xx / 5xx counts
- `## Latency (ms)` — submit / cancel / match (TODO) histograms at P50 / P95 / P99 / P99.9 / max

## Last-run snapshots

*(none yet — to be filled in by the first Phala devnet run)*
───────────────────────────────────────────────────────────────────── -->
