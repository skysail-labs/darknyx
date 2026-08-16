# Throughput roadmap — settle-path optimizations gated on platform milestones

A single log of TEE settle/throughput optimizations we have **deliberately deferred** behind two
platform milestones, plus the volume-driven ones. The point is to not re-derive the analysis each time
and to know exactly what to build the moment a gate lifts. Each item names its **gate**, the rationale,
the prerequisite work, and where the inline analysis lives.

> Why these are deferred and not just "TODO now": the deferral is grounded in the measured cost model
> below. Building them before the gate lifts either wastes effort (optimizes a term the platform is
> about to collapse for free) or pre-pays complexity for a regime the protocol isn't in yet.

## Gates

- **🟢 GPU** — unblocked once GPU proving (ICICLE CUDA) lands and `prove_ms` drops from ~2.6 s
  (witness 297 + prove_step 2214) toward the ~300 ms witness floor — a **~8×** ceiling, since
  `prove_step` is now ~87% of prove time (item 5). Shelved while Phala has no GPU. The build side is
  already done (`icicle-cuda` feature, Dockerfile `ENABLE_CUDA=1`, `-cuda` CI tag); the open gate is
  the **CUDA parity run on real hardware** (`tests/icicle_cuda_parity.rs` — it asserts the CUDA proof
  verifies against the committed zkey VK and that CUDA/ark agree on the public inputs; Groth16 is
  randomized so byte-identical proofs are NOT the assertion) plus the confidential-GPU requirement —
  the witness carries the private amounts, so a non-CC GPU would leak exactly what amount-privacy
  protects.
  **Target hardware: H200** (Hopper, compute capability 9.0 → `sm_90`), which matches the already
  pinned `CUDA_ARCH=90` build ARG — no arch change needed. Confirmed 2026-07-20.
- **🔵 ALPENGLOW** — unblocked once Solana fast-finality (Alpenglow) collapses on-chain confirmation
  latency (the `settle_ms` / `verify_ms` / `alt_wait` IO terms → ~0).
- **🟡 VOLUME** — not a platform gate; only worth doing once real order flow makes the system
  settle-bound (the settle queue actually backs up). Premature at low volume.
- **🟠 CU-BUDGET** — not latency; the on-chain Groth16 **verify CU** axis. Only worth doing once a
  Tx's compute budget becomes the binding constraint (currently it is not — see item 6).
- **🟣 TX-V1** — larger transactions (SIMD-0296: 1232 → **4096 bytes**) via the new **v1 tx format**
  (SIMD-0385). Targeted ~Q3 2026, lands with/near Alpenglow. v1 **does not support ALTs**, but 4096 B
  fits our full inline address list — so this is the gate that lets the settle path drop the entire ALT
  apparatus. See item 7.

## Cost model this roadmap is reasoned against

From `crates/darknyx-tee-loadgen/BENCHMARK.md` (rapidsnark-CPU, 8 vCPU, full N=16 batch):

| Term | ms | Nature | Killed by |
|---|--:|---|---|
| `prove_ms` (witness **297** + prove_step **2214**) † | ~2,557 | **fixed per batch** (padded N=16) | 🟢 GPU (prove_step — now **~87%** of prove) |
| `verify_ms` | ~1,119 | IO | 🔵 Alpenglow |
| `settle_ms` (Tx D) | ~11,222 | IO — **dominant**; ~fixed per batch (co-inclusion) | 🔵 Alpenglow |
| `alt_tx`+`alt_wait` | ~3,380 | IO — ALT create + slot-warmup | 🟣 TX-V1 (ALT eliminated, not Alpenglow — see item 7) |
| `total_ms` (overlapped wall) | ~16,938 | — | — |

> † **The `prove_ms` split was re-measured 2026-07-18** on a live CVM (prod9,
> image `tee-v3-hardening-64`, rapidsnark backend) **after the native witness
> generator landed**: `witness_ms=297`, `prove_step_ms=2214`. The older
> BENCHMARK.md figure (witness 2124 + prove_step 1485) predates native
> witness-gen and **must not be used to reason about the GPU ceiling** — see
> item 5. The IO rows above are still the BENCHMARK.md numbers.

Two facts drive everything below: (1) the pre-settle phase (lock ‖ prove+verify ‖ ALT) is **already
overlapped** (`worker.rs` `tokio::join!`), and (2) at the production-default
`DARKNYX_TEE_SETTLE_BATCH_CONCURRENCY=1` each batch monopolizes a ~17 s serial
pipeline slot dominated by `settle_ms` IO.

---

## Backlog

### 1. Raise settlement-batch concurrency — instrumented, default still 1
**Gate for production >1: 🟢 GPU + measured benefit.** The scheduler now accepts
`DARKNYX_TEE_SETTLE_BATCH_CONCURRENCY=1..8`, records the actual value in every
settlement benchmark row, and keeps `1` as the production default. This makes
the next H200 window an env-only A/B rather than a code change.

The two historical correctness blockers were re-audited before exposing the
knob:

- Rolling-ALT planning/mutation is held under one mutex across the complete
  create/extend transaction. Each batch captures its table before releasing the
  mutex and re-reads canonical on-chain ordering; later extends append without
  changing earlier indices. Rotation deactivation retains the normal cooldown.
  A two-batch concurrent regression now drives both workers through this shared
  pool.
- A partial-fill continuation is inserted into the opening store only after its
  parent Tx D confirms. The fixed matcher snapshot used by a tick cannot select
  that continuation for a sibling page, so there is no child batch to start
  early.

On CPU, rapidsnark already uses the host cores and `>1` may make proving slower;
do not infer a gain from configuration alone. Run the CPU baseline at 1 and 2,
then the same-box GPU matrix at 1/2/4. Promote a value only if confirmed-match
throughput rises without breaching the queue and latency thresholds in the
settlement benchmark methodology.

**CPU baseline closed 2026-07-23:** on one unchanged prod9/K=4 CVM and the
fixed 144-match real-settle workload, C1 delivered 0.961 confirmed matches/s
while C2 delivered 0.929 (-3.3%); C2 P95 total batch latency increased from
17.101 s to 18.732 s (+9.5%). Keep the CPU default at 1. There is no CPU C4
leg—run 1/2/4 only for icicle CUDA on the same GPU host. Both CPU legs exposed
excessive rebroadcasting, so neither is a production-capacity promotion result.
Evidence:
[`docs/benchmarks/runs/prod9-rapidsnark-cpu-comparison-2026-07-23.md`](benchmarks/runs/prod9-rapidsnark-cpu-comparison-2026-07-23.md).
**Source:** `scheduler.rs`, `worker.rs`, and
`docs/benchmarks/settlement-throughput-methodology.md`.

### 2. Per-shard / per-worker ALT pools
**Gate: measured contention.** The shared rolling pool is now correctness-safe
for concurrent batches but intentionally serializes the Tx C branch. The admin
metrics expose `alt_tx_ms`, `alt_wait_ms`, queue wait, and batch concurrency, so
we can tell whether this mutex is material. Add distinct pools only if GPU A/B
shows Tx C serialization limiting throughput; TX-v1 would delete this subsystem
entirely, so avoid speculative complexity.
**Source:** the ALT-infra assessment (the "Priority 3 / Option A" review); memory `settle_io_and_marker_sweep`.

### 3. Reduce Tx D confirmation dependencies (optimistic / async settle)
**Gate: 🔵 ALPENGLOW (mostly free) — or manual.** The dominant cost is `settle_ms` (Tx D block
confirmation, ~fixed per batch). Alpenglow collapses this at the platform level for ~nothing. The manual
pre-Alpenglow version is to shorten the sequential A→B→C→D confirmation chain (e.g., send Tx D on a
looser commitment, or drive a dependency tracker so the scheduler doesn't block on each confirm). Note:
**Tx E (`close_batch_validity_marker`) is already done** — it was moved off the critical path to an async
sweeper (`settle::marker_sweep`, merged). Tx D is the remaining one.
**Source:** the Tx-chain confirmation-dependency analysis; memory `settle_io_and_marker_sweep`.

### 4. Adaptive batch cadence / coalesce trailing partial batches
**Gate: 🟡 VOLUME (and diminished by 🟢 GPU + item 1).** The matcher tick (`BATCH_MS=2000`,
`matcher/interval.rs`) already freezes one snapshot and pages reusable price-level curves greedily
into `≤16` batches, so the only underfilled
batches are the **remainder page** of a multi-page tick or a **quiet tick** (<16 matches). The prove is
fixed at N=16 (padded), but prove is only ~22 % of wall and overlapped, and `settle_ms` (~fixed per
batch) dominates — so an underfilled batch really wastes the whole serial slot, not the prove. Coalescing
partial batches across ticks (bounded by a `max_wait_ms`, respecting the item-1 continuation ordering)
raises throughput **only when settle-bound**, and is substantially *substituted* by item 1 (parallel
settle drains small batches anyway). The narrow window where it clearly wins is "CPU prove + Alpenglow,"
which isn't the GPU path we're on.
**Lean version worth keeping:** defer only a sub-threshold *trailing* partial page by ≤`max_wait_ms` to
merge with the next tick. Hold until real volume shows the settle queue backing up.
**Source:** the adaptive-batch-cadence assessment ("Priority 5"); `matcher/interval.rs:384-547`.

### 5. Witness-generation acceleration (the GPU ceiling) — ✅ LARGELY RESOLVED
**Status: mostly done. Re-measure on GPU rather than budgeting new work.**

**This item's original premise is obsolete.** It was written when witness-gen ran
through ark-circom (~2124 ms, ~single-threaded) against a 1485 ms `prove_step`, so
GPU best-case `prove_ms` ≈ witness + ε ≈ 2.1 s — a **~1.7× cap**, with witness as
the residual ceiling.

The **native witness generator has since landed** (C++ witness binary built into
the image; boot logs `native witness generator ENABLED`). Re-measured 2026-07-18
on a live CVM (prod9, image `-64`):

| | old (ark-circom) | now (native) |
|---|--:|--:|
| `witness_ms` | ~2124 (59% of prove) | **297 (12%)** |
| `prove_step_ms` | ~1485 | **2214 (87%)** |
| GPU ceiling on `prove_ms` | ~1.7× | **~8×** |

So witness-gen is **no longer the ceiling** — `prove_step`, exactly the term ICICLE
accelerates, is now ~87% of prove time. **Do not budget witness-parallelization
work off the old numbers.**

Residual (small): once GPU lands, witness's 297 ms becomes the new floor — at that
point re-measure the split and only then decide whether shaving witness further is
worth anything. It is a ~300 ms floor against a term that should drop to tens of ms,
so revisit *after* GPU, not before.

**Source:** live CVM measurement 2026-07-18 (image `-64`, prod9, rapidsnark);
supersedes `BENCHMARK.md` finding #3 and the older memory `proving_optimization`.

### 6. On-chain Groth16 verify-CU — MATCH implemented; INPUT deferred for browser data
**Status: MATCH shipped; INPUT measurement-gated.** Full review of the suggested CU-reduction techniques against our actual verifier
stack (`groth16-solana` 0.2.0 + `programs/vault/src/zk/`), across all **7 on-chain verify sites / 6
circuits**:

| Circuit | Instruction | Public inputs |
|---|---|--:|
| VALID_WALLET_CREATE | `create_wallet` | 1 |
| VALID_INPUT | `lock_note` (settle-lock) | 4 |
| VALID_DEPOSIT | `deposit` | 5 |
| VALID_SPEND | `withdraw` | 6 |
| VALID_MERGE K=2 | `merge` | 6 |
| VALID_MERGE K=4 | `merge` | 8 |
| VALID_MATCH_BATCH N=16 | `verify_match_batch` (Tx B) | 2 |

Per verify: a fixed 4-pair pairing (~85k CU) **plus** `N × (~3.8k mul + ~334 add + tiny field-size check)`
MSM over public inputs (`groth16.rs::prepare_inputs`, the `for input in public_inputs` loop).

**Already satisfied — verified from source; do NOT re-investigate:**
- **Single batched pairing syscall** — `verify_common` concatenates all four pairs and calls
  `alt_bn128_pairing` exactly once (`groth16.rs:125-137`). ✓
- **Embedded syscall-ready VK** — `vk_*.rs` are compile-time `[u8;64]`/`[u8;128]` const arrays fed
  straight to the syscalls; `pi_a` is negated off-chain, so there is no runtime negation, JSON parse,
  endianness flip, or generic-VK deserialization on-chain. ✓
- **Uncompressed points** — proof + VK are 64 B G1 / 128 B G2; no on-chain decompression
  (the crate's `decompression.rs` is unused). Settle tx already fits the 1232 B cap uncompressed. ✓
- **Syscalls, not on-chain Arkworks** — the hot path is `alt_bn128_{multiplication,addition,pairing}`.
  The only `BigUint` is the per-input field-size range check (`groth16.rs:147`), which is
  soundness-critical (rejects non-canonical public inputs) — keep it (`verify()`, not `verify_unchecked()`). ✓
- **Fixed-size proof parse** — `Groth16Proof` is three fixed byte arrays; Borsh decode ≈ a length-checked
  memcpy (no nested structs, no `Vec` growth), so a hand-rolled fixed-offset parser buys ~nothing. ✓
- **Verify/settle split where it matters** — the batch path already uses the receipt pattern
  (`verify_match_batch` writes a `BatchValidityMarker` that `tee_forced_settle_batched` consumes),
  forced by the 1232 B cap. The other six verifies are atomic single-tx and comfortably under budget,
  so splitting them would only add replay/lifecycle cost. ✓

So of the suggested techniques, **only public-input collapse (T1) has any headroom left** — and even that
is second-order, because amount-privacy (P1b) + CS-01 already collapsed the 16 matches into one
`batch_root` and removed amounts, putting us near the public-input floor.

**The T1 lever — benchmarked and implemented 2026-07-21:** shrink the `prepare_inputs` MSM by exposing fewer public
inputs. `verify_match_batch` moved **8 → 2** with public `[batch_root, config_digest]`, where
`config_digest = Poseidon8(domain, fee_rate, owner, base_lo, base_hi, quote_lo, quote_hi, price_scale)`.
The circuit constrains the same digest internally. Compute it on-chain from the authoritative
`VaultConfig` + `MarketConfig` values; do **not** store a combined digest in `MarketConfig`, because the
two accounts have independent update instructions and a stored cross-account cache can go stale.

The earlier estimate that `sol_poseidon` would pay the MSM saving back was wrong. The temporary feature-gated
litesvm A/B measured 119,939 CU (8 direct inputs), 90,570 CU (root + Poseidon8 config digest), and
85,979 CU (one Poseidon9 full digest): **8→2 saved 29,369 CU after paying for Poseidon**, while 2→1
saved only another 4,591 CU. The unchanged real `verify_match_batch` measured
132,519 CU; the production two-input handler now measures 103,346 CU, saving
29,173 CU (22.01%). Full N=16 constraint/prover A/B:
232,854 → 234,025 constraints (+0.503%); seven interleaved snarkjs samples measured a +29.31 ms
witness delta but no proving regression outside noise (paired prove delta −0.94%, treated as noise).
Detailed method/raw samples: `docs/benchmarks/public-input-compression-2026-07-21.md`. The production
cutover uses protocol domain 28, recomputes the digest from `VaultConfig` + `MarketConfig`, pins the
Rust/TypeScript bytes with a KAT, and removes the temporary benchmark circuits/instructions/features.

**`VALID_INPUT` remains deferred.** Its focused 21-round benchmark measured 4→2 at +6.10% constraints,
+23.13% witness time, +3.45% prove time, and +5.38% combined client proving time, in exchange for
9,709 CU per `lock_note`. The one-input comparison saved another 5,091 CU but added slightly more
client work. Because `lock_note` already has comfortable headroom and users generate this proof in the
browser, do not cut it over until representative browser measurements quantify the UX cost and CU/block
packing pressure makes the saving operationally useful. Detailed raw samples and the revisit gate:
`docs/benchmarks/valid-input-public-input-compression-2026-07-21.md`.
**Source:** 2026-07-16/17 on-chain verify-CU review; 2026-07-21 focused benchmark;
`groth16-solana` 0.2.0 `groth16.rs`; `programs/vault/src/zk/{verifier.rs,vk_*.rs}`; the 7 verify sites
above.

### 7. Drop ALTs: settle Tx D → v1 inline-address transaction (SIMD-0296 / SIMD-0385)
**Gate: 🟣 TX-V1.** SIMD-0296 raises the tx cap 1232 → **4096 B** via the SIMD-0385 **v1 format**
(leading version byte `129`; compute budget set by a **header config-mask** instead of `ComputeBudget`
instructions; every field after the version byte is re-laid-out). v1 **does not support address lookup
tables** — you inline every address — but 4096 B holds our full settle account list. So this is a straight
win: our entire ALT apparatus exists *only* to fit Tx D under 1232, and adopting v1 makes all of it go
away. **No on-chain program or circuit change** — the vault is indifferent to how accounts arrive.

**Per-tx impact:**
- **Tx C (per-batch ALT create/extend) — DELETED.** No ALT ⇒ nothing to create or warm.
- **Tx D (`tee_forced_settle_batched`) — v0+2-ALT → v1+inline.** The ~13–15 accounts (`tee_authority`,
  `vault_config`, `merkle_tree`, `note_lock_a/b/e/f`, `consumed_a/b`, `batch_validity_marker`,
  `system_program`, `instructions_sysvar`) go inline: ~1173 B (ALT-compressed) → ~1.4–1.6 KB inline,
  comfortably under 4096 (worst-case 6-leaf + 2-relock included, so no "most cases" risk for us). The CU
  limit moves from a prepended `ComputeBudget` ix to the v1 header mask.
- **Tx A (lock ×2), Tx B (verify), Tx E (marker close) — unchanged.** Already ALT-free and <1232;
  optionally migrate to v1 for uniformity, not required.

**Eliminated complexity (the real prize):** the whole `settle/alt_pool.rs` rolling pool (246-entry
rotation, **512-slot deactivation cooldown**, `Create`/`Extend` planning), `settle/alt.rs`, the Tx-C path
threaded through `job.rs`/`pipeline.rs`/`worker.rs`, the `alt_wait` slot-warmup, the
`createLookupTable recentSlot` gotcha, and the entire §6 1232-byte budget discipline (lock_note key-dedup,
payload-size fights). This is a large, audit-surface-reducing deletion.

**Roadmap + cost-model interactions:**
- Kills the **`alt_tx + alt_wait` ~3,380 ms** term outright — the cost-table "Killed by" for that row is
  TX-V1, not Alpenglow (the ALT was structural, not confirmation latency).
- **Substitutes item 2** (per-shard/per-worker ALT pools) entirely — there is no ALT to pool.
- **Removes the ALT-corruption barrier in item 1** — `SETTLE_CONCURRENCY>1` was unsafe partly because
  concurrent batches corrupted the *shared* rolling ALT (the 2026-06-17 loadgen incident); with no ALT
  that failure class disappears. Item 1 then stays 🟢 GPU-gated only for the prove-contention reason, and
  should land *after* this so concurrency is built ALT-free from the start.

**Enabled (secondary, optional):** at 4096 B you can pack 2–3 matches' settle instructions into ONE v1
Tx D (shared `vault_config`/`system_program`/`instructions_sysvar`/payer dedup across ixs; ~70k CU each ≪
1.4M/tx), cutting per-batch settle-tx count 16 → ~6–8. Interacts with tree-sharding (in-tx matches
serialize, so pack same-shard or accept serial) and re-opens the item-6 verify-CU math if proofs are
co-packed. Evaluate under 🟡 VOLUME once settle-bound; don't prescribe now.

**Prerequisites (must land with the switch):**
- `solana-*` client crates (`solana-message` + the tx builder) at a version that constructs v1 txs
  post-activation; both the TEE settle worker and the SDK `settle-builder` build Tx D.
- RPC (Helius) accepting/forwarding v1 txs; a devnet activation to validate against.

**Why gated (not now):** v1 is a post-activation platform format (~Q3 2026); building it early means
carrying both a v0+ALT path and a v1 path for no live benefit. It is a **pure simplification + ~3.4 s
latency trim**, not a throughput multiplier — the dominant `settle_ms` term is Alpenglow's, not this — so
it rides in when the format activates, most valuably *before* item 1's concurrency work.
**Source:** SIMD-0296 + SIMD-0385; `solana.com/upgrades/larger-transaction-sizes`;
`crates/darknyx-tee/src/settle/{alt_pool.rs,alt.rs,job.rs,worker.rs,pipeline.rs}`; the §6 tx-size budget
in CLAUDE.md.

---

### 8. RA-TLS client concurrency — `connections: 1` is a per-client ceiling 🟡

**Gate: 🟡 real volume.** Not on the settle critical path today; deferred until
a workload actually needs it.

`packages/sdk/src/tee/transport-agent.node.ts` pins the verified transport to
`connections: 1, pipelining: 1`:

> One connection: with a pool, the attestation exchange and the request that
> follows can land on different sockets, which is the gap this exists to close.

Two measured consequences:

* **Requests from one client serialise.** Observed live during the T-03P
  cutover: `cvm-api-surface`'s 300 "concurrent" requests became a queue, which
  is why that suite's rate-limit flood is now ra-tls aware.
* **Connection establishment is ~1.4 s**, not ~50 ms, because it includes a real
  TDX `get_quote`. Measured medians across three windows: **1349 / 1413 /
  1517 ms**. Paid on every new connection, including reconnects.

**Why it costs nothing today.** The settle path is dominated by proving:
measured with RA-TLS active, `prove_ms=3395`, `settle_ms=5140`,
`total_ms=10383` — in line with the pre-RA-TLS baseline, i.e. **the transport
adds nothing measurable to settle**. And the daemon's hot path is the
multiplexed `/v1/stream` WebSocket: one long-lived connection carrying fills,
order updates and acks, so the 1.4 s is paid once per session and `connections:
1` never binds. Streaming is the best case for this design, not the worst.

**When it would bind:** many short-lived REST calls from one client, or a client
wanting parallel in-flight requests. Also **many simultaneous browser clients**
— each verified connection costs one TDX quote, which is why
`/transport-attestation` is priced at 10.0 in the public rate limiter. That is
a real argument for the B2 HPKE channel over per-connection RA-TLS in T-03B,
since a quote-bound application channel can amortise one attestation across
many sessions.

**The fix, when the gate lifts.** `connections: 1` is an implementation choice,
not inherent to RA-TLS. It exists because undici exposes no per-response socket
attribution, so pinning to one socket is how "the socket that was verified is
the socket carrying the request" is currently guaranteed. Verifying EACH socket
in a pool at connect time restores parallelism at ~1.4 s per socket while
keeping the property. Bounded work, not a redesign.

**Do NOT reach for reverting to the gateway-terminated transport to solve this.**
That trades the plaintext hop back (reopening T-03P) for throughput that this
item buys without it. See `transport-integrity-plan.md` §5.5.

## Related, separate track (not settle-throughput, but the other proving gate)

- **Client-side `VALID_INPUT` proving (~40 s, snarkjs in-browser).** The order-placement UX killer; an
  architectural fork (in-browser vs delegated-into-TEE vs a faster proof system), independent of the
  TEE settle path. Tracked separately — memory `loadgen_rig_and_prover_bottleneck`.

## Already shipped (for trajectory context)

Pre-settle overlap (`tokio::join!`), tree-sharding + concurrent Tx D co-inclusion, rapidsnark backend +
ICICLE Phase 1 (CPU byte-parity), and the async Tx E marker close. See `BENCHMARK.md` and the settle
module for the measured wins.

---

*This is a living log. When a gate lifts (GPU box available / Alpenglow on mainnet / sustained volume),
pull the matching items here, re-measure against the cost model, and build them in the stated order.*
