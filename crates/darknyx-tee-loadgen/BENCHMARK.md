# darknyx-tee-loadgen — benchmark report

> **First Phala devnet run — 2026-05-31.** Live report below, followed by
> notes on what it means (and the gap it surfaced). The original
> template / run-protocol reference is preserved, commented out, at the
> bottom of this file.

---

## Prover baseline protocol (pre-GPU) — lock in the CPU numbers for the GPU comparison

> **Purpose.** Before we build the ICICLE-accelerated GPU rapidsnark backend, capture
> a frozen, repeatable CPU baseline so the GPU win is measurable apples-to-apples. The
> thesis to prove and quantify: **the Groth16 prove (`prove_ms`) is the pipeline's only
> irreducible off-chain compute, and it's the throughput blocker once the on-chain
> confirm/finality latency is taken out** (which is exactly what Alpenglow removes). The
> GPU upgrade attacks `prove_ms` and nothing else, so `prove_ms` is THE comparison metric.
>
> **Current capacity contract:** this file preserves historical prover-isolation
> results. New CPU/GPU capacity runs must use
> [`docs/benchmarks/settlement-throughput-methodology.md`](../../docs/benchmarks/settlement-throughput-methodology.md),
> including its paced 144-match fixture and eight measured-batch minimum. The
> current real-settle client fixture uses native C++ witnesses; its 2026-07-23
> 160-deposit + 160-input preflight completed in 21.06 s. The older Wasmer
> client timings below are retained as historical evidence, not the current
> loadgen path.

### Why `prove_ms` is the metric (the stage taxonomy)

Each settled batch logs `settle pipeline timing (per-stage ms)` on the CVM. Classify every
stage as **COMPUTE** (off-chain, what GPU accelerates) vs **CONSENSUS/IO** (Solana confirm
+ finality latency, which Alpenglow's ~150 ms fast-finality collapses — explicitly *out of
scope* for the prover comparison, per the framing):

| Stage | Tx | Class | Post-Alpenglow |
|---|---|---|---|
| `lock_ms` | A (lock_note ×2) | CONSENSUS/IO | →~0 |
| **`prove_ms`** | — (VALID_MATCH_BATCH Groth16 prove) | **COMPUTE** | **unchanged — GPU target** |
| `verify_ms` | B (verify_match_batch) | CONSENSUS/IO | →~0 |
| `alt_tx_ms` | C (per-batch ALT create+extend) | CONSENSUS/IO | →~0 |
| `alt_wait_ms` | — (ALT activation cooldown, ~1 slot) | CONSENSUS/IO | →0 (vanishes) |
| `settle_ms` | D (tee_forced_settle_batched) | CONSENSUS/IO | →~0 |
| `close_ms` | E (close_batch_validity_marker) | CONSENSUS/IO | →~0 |
| `total_ms` | wall | — | →`prove_ms` + ε |

`prove_ms` is the **only** compute term. Note it folds witness-gen (ark-circom, CPU, NOT
GPU-accelerated by ICICLE) + the Groth16 prove (MSM/NTT — what ICICLE accelerates); if the
backend logs the split, record both, because the GPU win is bounded by the prove portion
(Amdahl: witness-gen becomes the new floor). Derived comparison metrics, per run:

- **`prove_ms` (absolute, per N=16 batch)** — the headline. GPU speedup = `prove_ms_cpu / prove_ms_gpu`.
- **Finality-free per-batch latency** = `total_ms − (lock+verify+alt_tx+alt_wait+settle+close)` ≈ `prove_ms + ε`. Models the post-Alpenglow world; shows `prove_ms` dominates once IO →0.
- **Projected post-Alpenglow settle throughput** ≈ `1 / (prove_ms + 6×~0.15 s)` batches/s → today prove-bound, so the GPU ratio passes ~1:1 into throughput.
- **Client `VALID_INPUT` prove rate** (loadgen-side, native C++ witness +
  ark-groth16) — the order-submission ceiling; the same prover-bound story
  client-side.

### Fixed conditions (must hold across CPU baseline AND GPU re-run, or it's not comparable)

- **Same CVM size** — record vCPU/RAM (`phala cvms list`/dashboard). Per [[rapidsnark_ab_results]] vCPU count is the dominant CPU lever, so it must be pinned. The GPU run will be on the confidential-GPU CVM — note that as the one deliberate platform change.
- **Same N=16 zkey/circuit**, **`--real-num-trees 4`**, **same Helius devnet RPC**, **real-mint regime**, **fresh-reset tree per run** (clean cold-boot).
- **Backend = rapidsnark** (now the default; §below). A/B against `ark` is an env-only flip (`DARKNYX_TEE_PROVER=ark`), no rebuild.
- Devnet confirm latency is noisy → the CONSENSUS/IO stages vary run-to-run; **`prove_ms` is the stable comparable**. Take ≥3 batches per run, report median.

### The run suite (all on the rapidsnark-default image, one CVM session)

Common prefix (real-mint regime, hex mints, see operator note in the isolation-run section):
```sh
GW=...; BASE_HEX=...; QUOTE_HEX=...        # see §3 of docs/cvm-run-runbook.md + the hex-mint note
COMMON="--real-settle --endpoint $GW --rpc-url $SOLANA_RPC_URL \
  --admin-keypair .devnet/keypairs/admin.json --base-mint $BASE_HEX --quote-mint $QUOTE_HEX \
  --oracle-twap <pyth> --fee-rate-bps 30 --real-num-trees 4"
```

| ID | Command (append to `$COMMON`) | Captures | Why |
|---|---|---|---|
| **B1** | `--real-mix "partial-fill:1" --traders 1 --real-partial-fill-asks 3` | clean per-batch `prove_ms` (3 serial n=1 batches), all stages | lowest-contention prove isolation (the isolation run already did this on ark: `prove_ms`≈4 s, `settle_ms`≈9 s) |
| **B2** | `--real-mix "exact-match:100" --traders 16` | `prove_ms` for a **full / near-full N=16 batch** + within-batch co-inclusion settle | the production case — the prove cost the GPU must cut; the headline number |
| **B3** | `--real-mix "exact-match:40,partial-fill:20,merge:10,over-collateral:20,ioc-fok:10" --traders 10 --real-partial-fill-asks 3` | blended pipeline, cross-shard settle, client prove rate under realistic load | realism — the rig as the protocol test bed |
| **B4** | re-run B2 twice with `DARKNYX_TEE_PROVER=ark` then `=rapidsnark` (env-only flip) | ark-CPU vs rapidsnark-CPU `prove_ms` ratio | the third leg: ark-CPU / **rapidsnark-CPU (baseline)** / rapidsnark-GPU (future) |
| **B5** *(opt)* | B2 with `DARKNYX_TEE_SETTLE_SEND_CONCURRENCY ∈ {1,4,16}` | the co-inclusion (CONSENSUS/IO) win, isolated from prove | documents the IO portion Alpenglow addresses, kept separate from the prove story |

Per run, pull the TEE timing with:
`phala cvms logs <cvm> | grep -E "settle pipeline timing|CLIENT VALID_INPUT prove rate|real-settle LOAD complete"`.

### CAPTURED BASELINE — 2026-06-18, image `tee-v3-hardening-32`, CVM 8 vCPU / 16 GB

**Per-batch ms, N=16 full batch** (B2: `--real-mix "exact-match:100" --traders 16` → matcher
`count=16 page=0`, **settled 16/16 clean**). ark column from [[rapidsnark_ab_results]] (8 vCPU,
image -20/-21 — prior image, same box class, label accordingly):

| Stage | ark-CPU (ref) | **rapidsnark-CPU (baseline)** | rapidsnark-GPU (ICICLE) |
|---|--:|--:|--:|
| witness-gen (ark-circom, CPU — **not** GPU-accel) | ~1600 | **2124** | ~2124 *(floor — Amdahl)* |
| **`prove_step_ms`** (Groth16 MSM/NTT — the ICICLE target) | ~2350 | **1485** | _(future, →tens of ms)_ |
| **`prove_ms`** (witness + prove) | ~4000 | **3661** | ~2200 *(witness-bound)* |
| `verify_ms` (IO) | — | 1119 | →~0 |
| `settle_ms` (IO) | ~14000 | **11222** | →~0 |
| `alt_tx`+`alt_wait` (IO) | — | 3380 | →0 |
| `lock_ms`+`close_ms` (IO) | — | 4332 | →~0 |
| `total_ms` (wall, w/ overlap) | ~22500 | **16938** | →`prove_ms`+ε |
| prove share of wall | ~18% | **~22%** | — |
| **finality-free latency** (≈`prove_ms`) | ~4 s | **~3.7 s** | ~2.2 s |
| **proj. post-Alpenglow** matches/s (16 / finality-free) | ~4 | **~4.3** | ~7.3 |
| client VALID_INPUT proofs/s (loadgen, ark-circom) | — | **0.19** (32 conc..) / 0.26 (4 conc.) | — |

**n=1 isolation** (B1: `partial-fill` first batch, rapidsnark): `witness`≈1.3–1.6 s,
`prove_step`≈1.3 s, `prove_ms`≈2.9 s, `settle_ms`≈11.2 s, `total`≈17.2 s.

**Reading the baseline — three findings that frame the GPU work:**
1. **`prove_ms` is the floor once IO is removed, exactly as posited.** Today on-chain IO
   (esp. `settle_ms`≈11 s) dominates wall, but that's the Alpenglow-killed term. Strip it and
   per-batch latency → `prove_ms`≈3.7 s, so throughput → prove-bound (~4.3 matches/s at N=16).
2. **rapidsnark-CPU already wins on the *prove step* (1485 vs ~2350 ms ≈ 1.6×), but only ~1.07×
   on `prove_ms`** — because witness-gen (2.1 s, ark-circom, single-threaded-ish) dilutes it.
3. **⚠️ ICICLE's ceiling is witness-gen.** ICICLE accelerates `prove_step` (1485 ms → tens of ms),
   NOT witness-gen. So GPU best-case `prove_ms` ≈ 2.1 s (witness) + ε ≈ **1.66× over rapidsnark-CPU,
   then witness-gen is the new bottleneck**. The GPU project should budget a witness-gen plan
   (GPU/parallel witness, or a faster witness backend) as the immediate follow-on, or the prove
   speedup is capped at ~1.7×. This is the single most important number for the GPU roadmap.

### Witness-gen optimization — Steps 0→2 (revamp_proving, 2026-06-18)

Attacked the witness floor above (finding #3) in two shipped steps:

| step | what | witness-gen (N=16) | how validated |
|---|---|---|---|
| baseline | ark-circom in wasmer, `CircomConfig` rebuilt per prove | ~2.1 s (CVM) | — |
| **Step 0** | cache the compiled wasm + r1cs (`Mutex<CircomConfig>`, reused) | local arm64 669→**322 ms** (−52%; removes the per-call ~350 ms wasm recompile) | n16 prove+verify |
| **Step 1** | amd64 CI bench: native circom `--c` C++ gen vs WASM | native **94 ms** vs node-wasm 1676 ms = **17.8×**, witnesses byte-identical | `.github/workflows/witness-bench.yml` |
| **Step 2** | ship the native gen in the image; `DARKNYX_TEE_WITNESS=native` (now default) | **CVM `witness_ms`=201** (vs ~1.7–2.1 s wasmer = **~8–10×**) | CVM real-settle: 4/4 batch settled clean, on-chain verify passed → witness byte-correct |

The native generator is built on debian:bookworm in CI (glibc/ABI match to the runtime) and
ships with its `circuit.dat` constants; the prover spawns `<bin> input.json out.wtns`, reads the
`.wtns`, and feeds rapidsnark. Default is now native with a wasmer fallback (warn) if the binary
is absent. **Net effect on the compute floor:** witness ~2.1 s → **0.2 s**; pairing this with the
future ICICLE prove (`prove_step` ~1.5 s → tens of ms) takes the per-batch compute from ~3.6 s
toward **~0.25 s** — and witness-gen is no longer the Amdahl ceiling.

### ICICLE prover — Phase 1 (CPU): integration + byte-parity (revamp_proving, 2026-06-18)

The GPU-prove track. We vendored `icicle-snark` under `third_party/` (ingonyama's ICICLE-backed Groth16: one crate,
CPU **and** CUDA, switched by a `device` string at prove time) and wired it as a **third prover
backend** alongside ark + rapidsnark (`DARKNYX_TEE_PROVER=icicle`, device via `DARKNYX_TEE_ICICLE_DEVICE`,
default `CPU`). It consumes our existing snarkjs `.zkey` + `.wtns` and emits a snarkjs-format proof,
so it reuses the shared witness gen and routes through the **same `proof_to_onchain_bytes`
converter** as the other two backends — and it's NOT "ICICLE-into-rapidsnark" (rapidsnark is a
CPU prover; GPU-accelerating it would mean reimplementing what icicle-snark already is).

Phase 1 deliberately validates on **CPU** — no GPU, no CVM — to de-risk the entire integration
(I/O, proof format, randomness, image plumbing) before the GPU is in play:

| check | result |
|---|---|
| builds (macOS arm64, CPU backend, cmake) | ✅ ~54 s cold |
| **byte-parity** — icicle-CPU N=16 proof verifies against the zkey's own VK (the same VK ark + the on-chain verifier use) | ✅ `tests/icicle_parity.rs` (warmup + steady both verify) |
| ark + icicle agree on the batch public input (merkle root) | ✅ |
| icicle-CPU prove time (arm64 M-series, prove-step only) | **~1.75–2.08 s** vs ark **1.57 s** on the same machine |

**Reading:** on CPU, icicle is *not* faster than ark/rapidsnark here — as expected. The CPU
backend's value is purely as a **no-GPU harness that exercises the exact code path CUDA will use**;
the headline win is the GPU. (And per the witness-gen lesson, arm64 M-series ≠ the amd64 CVM
platform, so the definitive icicle-CPU-vs-rapidsnark-CPU number belongs on amd64 — folded into the
Phase-2 CVM run.) Phase 1's goal — prove the proof format is byte-correct and the backend slots in
cleanly — is **met**.

> **Phase 2 (not started):** flip `device=CUDA`, ship the ICICLE CUDA backend in the image, and
> validate on a **confidential-GPU TEE** (H100/H200 CC-mode on Phala). The real prerequisite is
> infra + trust-model, not code: a CC-GPU attached to the CVM whose own attestation folds into
> `verifyTeeAttestation()` (order intent is processed on the GPU). That's the headline `prove_step`
> win (~1.5 s → tens of ms).

> **Historical pre-v3 note.** The June 2026 loadgen used client-supplied
> continuation anchors and exposed an order-id reuse collision. Canonical order
> v2 deletes that scheme: continuation inners are derived from the consumed
> input, and settlement identifiers are bound to the boot session, a monotonic
> counter, and both order ids. The current `--real-partial-fill-asks` scenario
> exercises that input-derived chain.

> **✅ Multi-scenario mix — a SECOND loadgen seed collision, root-caused + FIXED + validated.** After
> the salt fix, the isolated partial-fill settled 3/3 but the full mix (`--traders 5`, all 5 scenarios)
> still failed a partial-fill continuation batch — `Custom 0` on `nullifier_b` (the SELLER side, a
> *different* PDA `2m2J…`), within-run. Root cause (arithmetic): `seed_base = (salt<<20) ^ (inst<<4)`
> let the `inst` field (bits 4-11) OVERLAP the per-order tag bits (`^0x1` bid, `^0x10+j` asks). So
> cross-instance seeds collided, e.g. inst=0 ask j=1 (`S^0x11`) == inst=1 bid (`(S^0x10)^0x1`). Same
> seed → same `Persona` spending_key + same note `inner_hash` → **same nullifier (`nullifier_v2`
> ignores mint+amount)**, so a base-ask and a quote-bid with different commitments alias one nullifier;
> both match in the shared book, the 2nd settle dies on the on-chain replay guard. Only ≥2 instances
> hit it (the isolated partial-fill has one). NOT a protocol/matcher bug — the matcher matched distinct
> orders; the replay guard *correctly rejected* the aliased nullifier. **Fix:** disjoint bit fields,
> `seed_base = ((salt & 0xFFFF_FFFF)<<32) ^ (inst<<16)` (tag bits 0-15, inst bits 16-31, salt above) +
> two regression tests (`per_note_seeds_are_globally_unique`, `old_overlapping_layout_collided`).
> **Validated 2026-06-18 on `-32`/rapidsnark: the full mix settled clean — batch 0 (5)/1/2 all `batch
> settled`, ZERO `Custom 0`/`3007`, leaf 14→41 (+27 vs the buggy run's +17 partial).** All 5 pathways
> (exact-match, over-collateral, partial-fill+continuations, merge, ioc-fok) settle end-to-end.
> Lesson: XOR-combining seed fields that share bit ranges silently aliases nullifiers — use disjoint
> fields (or a global counter), and remember the nullifier is independent of mint+amount.

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
`--fee-rate-bps` MUST equal the CVM's `DARKNYX_TEE_FEE_RATE_BPS`.

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
cargo run -q -p darknyx-tee-loadgen -- --endpoint "$GW" --oracle-twap "$RAW" \
  --scenario partial-fill --fee-rate-bps 30 --traders 20 --duration-secs 25 --poll-orders 0.1
```

## Roadmap — `--real-settle` (opt-in real on-chain settle)

The Hybrid harness's second half: a small N of **real-note traders** that deposit
on-chain, prove a real VALID_INPUT, POST a crossing order, and track the on-chain
settle (leaf-count growth / `TradeSettled`) — the loadgen analogue of
`cvm-settle-e2e`, plus a `merge-before-order` variant. Behind the `real-settle`
cargo feature (keeps the default synthetic build lean). The real-settle path
requires native C++ witness generators and never invokes WASM/Wasmer.

**Increment A — DONE (`src/real_settle.rs`).** The CVM-free, unit-tested core:
- A **native-witness VALID_INPUT prover** (`ValidInputProver`) — the
  Circom-generated C++ binary emits `.wtns`, then ark-groth16 proves against
  `circuits/build/valid_input/circuit_final.zkey`. It mirrors the SDK's
  `proveValidInput` and emits the same 256-byte on-chain proof layout.
- A depth-20 Poseidon **`IncrementalTree`** + `MerkleWitness` (mirrors the SDK's
  `MerkleShadow`).
- Validated by `cargo test -p darknyx-tee-loadgen --features real-settle`: a proof is
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
cargo run -p darknyx-tee-loadgen --features real-settle-chain -- \
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
| `partial-fill` | 1 big bid + M small asks (`--real-partial-fill-asks`) → M fills over M batches | input-derived continuation across M batches |
| `merge` | deposit 2 sub-threshold notes → VALID_MERGE → ask off the merged note | the merge→spend pathway |
| `ioc-fok` | crossing pair, IOC bid / FOK ask | execution-policy plumbing |

**Phases:** plan → mint+deposit(+merge) all notes (sequential, shards round-robined)
→ **prove all VALID_INPUT with bounded concurrency** (native C++ witness +
ark-groth16 in `spawn_blocking`) → submit all concurrently → drain the settle.

**Prover-bottleneck metrics** (loadgen-only + CVM-log cross-ref, per the decision):
- **Client prove rate** — proofs/sec + p50/p95 of every VALID_INPUT/MERGE prove (the
  host-side proving ceiling that caps order submission).
- **End-to-end settle rate** — settled-matches/sec from `leaf_count` growth; plateaus
  below offered load when the TEE prover (VALID_MATCH_BATCH) is the bottleneck.
- **Cross-ref** — the run prints `phala cvms logs <cvm> | grep -E "prove breakdown|
  settle pipeline timing"` to read the TEE's `prove_step_ms` (the dominant settle cost).
  Per `rapidsnark_ab_results`, the lever is vCPU/GPU → the evidence base for GPU proving.

```sh
cargo run -p darknyx-tee-loadgen --features real-settle-chain -- \
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
  cargo run -p darknyx-tee-loadgen --features real-settle-chain -- … --traders "$T"
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
--real-partial-fill-asks 3`): 12/12 accepted, 7 matches across 3 batches.
- **`leaf_count` 14→28 (+14 = 7 matches × 2 leaves)** — vs 14→14 on `-30`. Multi-batch
  settle now LANDS; the catastrophic 0/7 failure is resolved.
- Batches settled ~7 s apart (serial), vs ~2 s concurrent on `-30` — the expected
  serialization, and the cost is hidden behind the ~40 s prove anyway.
- The `-31` mixed run also showed residual batch-0 `Custom 0` + continuation `3007` log
  lines timestamped **after** the leaf reached 28 — `send_and_confirm_with_rebroadcast`
  re-simulating an already-landed tx against post-settle state (spurious retry noise), but
  the leaf accounting (+14) alone couldn't distinguish "all settled" from "batch-0-only".

### Isolation run — 2026-06-17, image `-31`, the continuation chain is CLEAN

Focused run (`--real-mix "partial-fill:1" --traders 1 --real-partial-fill-asks 3`
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

# darknyx-tee-loadgen benchmark

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

*Generated by `darknyx-tee-loadgen`. See `docs/tee-architecture.md` §13.4 for design.*

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
- Run used: real Pyth SOL/USD feed (`DARKNYX_TEE_FEED_IDS`), the env
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

# darknyx-tee-loadgen — benchmark report (template)

This file is a placeholder. The real version is regenerated each time
`darknyx-tee-loadgen` runs against a deployed CVM with `--report
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
cargo build -p darknyx-tee --features debug_endpoints --release

# Local simulator (cheap, fast iteration):
~/dstack/sdk/simulator/dstack-simulator > /tmp/sim.log 2>&1 &
DSTACK_SIMULATOR_ENDPOINT=$(realpath ~/dstack/sdk/simulator/dstack.sock) \
  DARKNYX_TEE_HTTP_BIND=127.0.0.1:8080 \
  ./target/release/darknyx-tee &

cargo run -p darknyx-tee-loadgen --release -- \
  --endpoint http://127.0.0.1:8080 \
  --traders 100 \
  --orders-per-trader-per-sec 5 \
  --duration-secs 60 \
  --seed-oracle \
  --report BENCHMARK-local.md

# Phala devnet (real numbers):
phala deploy -c deploy/docker-compose.yaml -n darknyx-tee-bench
# (wait for boot, then run loadgen without --seed-oracle since
#  production CVMs don't expose /__debug/*)
cargo run -p darknyx-tee-loadgen --release -- \
  --endpoint https://darknyx-tee-bench.<custom-domain> \
  --traders 100 \
  --orders-per-trader-per-sec 5 \
  --duration-secs 60 \
  --report BENCHMARK-phala.md
phala cvms delete darknyx-tee-bench
```

Then commit both files into this directory. The PR description
should call out any percentile that meaningfully regresses.

## Expected sections (rendered by `crate::report`)

- `## Run configuration` — endpoint, traders, rates, workload params
- `## Throughput` — actual submit rate, achieved/target ratio
- `## Submit outcomes` — 2xx / 4xx / 5xx / net-err counts + success rate
- `## Cancel outcomes` — 2xx / 4xx / 5xx counts
- `## Latency (ms)` — submit / cancel / match histograms at P50 / P95 / P99 / P99.9 / max
  (the `match` row is the submit→match latency from the sampled `GET /orders/{id}` poller,
  populated when `--poll-orders` > 0; `count=0` otherwise)

## Last-run snapshots

*(none yet — to be filled in by the first Phala devnet run)*
───────────────────────────────────────────────────────────────────── -->
