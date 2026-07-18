# Throughput roadmap — settle-path optimizations gated on platform milestones

A single log of TEE settle/throughput optimizations we have **deliberately deferred** behind two
platform milestones, plus the volume-driven ones. The point is to not re-derive the analysis each time
and to know exactly what to build the moment a gate lifts. Each item names its **gate**, the rationale,
the prerequisite work, and where the inline analysis lives.

> Why these are deferred and not just "TODO now": the deferral is grounded in the measured cost model
> below. Building them before the gate lifts either wastes effort (optimizes a term the platform is
> about to collapse for free) or pre-pays complexity for a regime the protocol isn't in yet.

## Gates

- **🟢 GPU** — unblocked once GPU proving (rapidsnark + ICICLE) lands and `prove_ms` drops from
  ~3.7 s → tens of ms. ICICLE is shelved while Phala has no GPU.
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
| `prove_ms` (witness 2124 + prove_step 1485) | ~3,661 | **fixed per batch** (padded N=16) | 🟢 GPU (prove_step; witness is the residual ceiling) |
| `verify_ms` | ~1,119 | IO | 🔵 Alpenglow |
| `settle_ms` (Tx D) | ~11,222 | IO — **dominant**; ~fixed per batch (co-inclusion) | 🔵 Alpenglow |
| `alt_tx`+`alt_wait` | ~3,380 | IO — ALT create + slot-warmup | 🟣 TX-V1 (ALT eliminated, not Alpenglow — see item 7) |
| `total_ms` (overlapped wall) | ~16,938 | — | — |

Two facts drive everything below: (1) the pre-settle phase (lock ‖ prove+verify ‖ ALT) is **already
overlapped** (`worker.rs` `tokio::join!`), and (2) under `SETTLE_CONCURRENCY=1` each batch monopolizes
a ~17 s serial pipeline slot dominated by `settle_ms` IO.

---

## Backlog

### 1. Raise `SETTLE_CONCURRENCY` > 1 — pipeline batches concurrently
**Gate: 🟢 GPU.** Today it is hard-pinned to `1` (`crates/darknyx-tee/src/settle/scheduler.rs:30-60`).
On CPU, ark/rapidsnark already saturate all cores on a *single* prove, so concurrent batch proves just
contend — no gain, and `>1` is what corrupted the shared ALT in a live loadgen run (2026-06-17). Once
GPU drops each prove to ~tens of ms, the bottleneck shifts to settle round-trips and overlapping batch
N+1's cheap prove+lock with batch N's settle-IO pays off.
**Prerequisites (must land *with* the bump):**
- a per-batch **distinct ALT** instead of the shared rolling pool (see item 2);
- explicit **continuation-dependency ordering** — a child batch waits for its parent's on-chain re-lock
  (the same dependency that forced `=1`).
**Source:** `scheduler.rs:30-60`; memory `tree_sharding`.

### 2. Per-shard / per-worker ALT pools
**Gate: 🟢 GPU (rides with item 1).** A single rolling ALT pool is correct *and cheaper* while batches
are serial (`SETTLE_CONCURRENCY=1`). Distinct pools (per shard or per settle worker) only matter when
batches run concurrently — they're the mechanism that avoids the shared-ALT corruption class. Premature
standalone; build it as part of item 1.
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

### 5. Witness-generation acceleration (the GPU ceiling)
**Gate: 🟢 GPU (immediate follow-on).** ICICLE accelerates the Groth16 `prove_step` (1485 ms → tens of
ms) but **not** witness-gen (~2124 ms, ark-circom, ~single-threaded). So GPU best-case `prove_ms` ≈
witness + ε ≈ 2.1 s — i.e. the prove speedup is capped at ~1.7× unless witness-gen is also parallelized
or swapped for a faster backend. Budget this as the immediate follow-on to the GPU prove work, or the GPU
win is capped.
**Source:** `BENCHMARK.md` finding #3; memory `proving_optimization`.

### 6. On-chain Groth16 verify-CU — one remaining lever; the rest are already in place
**Gate: 🟠 CU-BUDGET.** Full review of the suggested CU-reduction techniques against our actual verifier
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
| VALID_MATCH_BATCH N=16 | `verify_match_batch` (Tx B) | 8 |

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

**The T1 lever (when the gate lifts):** shrink the `prepare_inputs` MSM by exposing fewer public inputs.
Prime target = **`verify_match_batch` 8 → 2**: precompute `market_digest = Poseidon(fee_rate, owner,
base_lo, base_hi, quote_lo, quote_hi, price_scale)` **once** in the `MarketConfig` account; the circuit
computes the same digest internally and exposes `[batch_root, market_digest]`; on-chain reads the
precomputed digest from the account (do **not** hash 8 fields on-chain per tx — that pays the saving back
in `sol_poseidon`). Saves ~6 × ~4.2k ≈ **~25k CU** on Tx B at near-zero added cost. Minor secondary wins
elsewhere: fold each `mint_lo/mint_hi` pair into one field on `lock_note`/`deposit`/`withdraw` (−1 input
each).
**Why gated (not now):** (1) no verify tx is CU-limited — Tx B is ~132k under a 180k budget (~48k
headroom); (2) verify CU is off the end-to-end critical path (proving + `settle_ms` dominate — see cost
model); (3) any public-input change is a full **§5 circuit ceremony** (regen zkey + VK + the committed
N=16 fixture), a **new cross-language canonical-hash byte-equality contract** (§7 fragility + re-audit of
the CS-01/02 soundness just closed), **more constraints → a slower prover**, and a devnet re-foundation +
CVM revalidation. **Trigger:** a verify tx's CU budget becomes binding (accounts/data added, N raised
above 16, or multi-proof-per-tx batching). Fold into the *next* circuit ceremony and use the
`market_digest` variant.
**Source:** 2026-07-16/17 on-chain verify-CU review; `groth16-solana` 0.2.0 `groth16.rs`;
`programs/vault/src/zk/{verifier.rs,vk_*.rs}`; the 7 verify sites above.

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
  `system_program`, `instructions_sysvar`) go inline: ~1109 B (ALT-compressed) → ~1.4–1.6 KB inline,
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
