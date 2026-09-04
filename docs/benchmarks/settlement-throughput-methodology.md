# Settlement throughput methodology

This is the fixed measurement contract for CPU baselines, the next GPU window,
and multi-market capacity tests. It prevents three misleading comparisons:
counting orders rather than matched pairs, treating the first cached-proving-key
run as steady state, and estimating settlements from Merkle leaf growth (one
match can append a variable number of change and fee notes).

## Metrics we publish

| Metric | Definition | Why it matters |
|---|---|---|
| Confirmed match throughput | Confirmed Tx D match outcomes divided by the interval from the first measured batch start to the last measured batch completion | Venue capacity; one match normally represents two participating orders |
| Workload start-to-batch-terminal latency | First paced HTTP submission to each correlated batch's terminal metrics record; report P50/P95/P99 | Repeatable end-to-end venue latency at a fixed offered rate |
| Post-offer drain latency | Completion of the final HTTP submission to each batch's terminal record (floored at zero for batches that finish while offering continues) | Shows how long the venue takes to drain after load stops |
| Per-order client latency | A client timestamps its accepted submission and the authenticated `orders` event carrying the same `market_id` and `match_id` | User-visible execution friction; the wire correlation is implemented, while client-specific transport/network time is intentionally not mixed into the server benchmark |
| Queue wait | Batch `started_at_ms - enqueued_at_ms`; report P50/P95/P99 and oldest queued age | Detects saturation before outright failures |
| Stage latency | `witness`, `prove_step`, full `prove`, `verify`, ALT, Tx D settle, and total | Attributes gains and identifies the next bottleneck |
| Outcome quality | Confirmed/rejected/ambiguous matches and rebroadcasts | A faster run is invalid if reliability regresses |
| N=16 packing | Sum active matches / sum padded slots | Separates prover speed from workload packing |
| Tx D co-inclusion | `(confirmed slot observations - distinct confirmed slots) / confirmed slot observations` | Shows whether shard sends land together |
| Offered vs achieved rate | Accepted order/match rate compared with terminal confirmed rate | Distinguishes intake capacity from settlement capacity |

`N=16` means **up to sixteen matched pairs**, usually thirty-two order
participations. It does not mean sixteen total orders.

## Collection contract

The TEE keeps a bounded, in-memory schema-v1 stream at
`GET /admin/metrics/settlement`. It is admin-only, cursor-addressable, and
contains no prices, amounts, order ids, commitments, owners, or witness values.
The real-settle loadgen:

1. reads the cursor before submitting;
2. submits a workload whose expected matched-pair count is known;
3. drains until all expected matches have a confirmed, rejected, or ambiguous
   outcome and queue depth is zero;
4. excludes the configured number of earliest batches (default one) as warm-up;
5. writes raw JSON plus a derived Markdown report.

Artifact schema v2 also persists the native client VALID_INPUT proof count,
concurrency, wall time, and P50/P95/P99/max distribution. Schema-v1 evidence
predating that field remains valid and must not be rewritten; retain any
separately captured client-prover log values in the adjacent Markdown report.

Example:

```sh
bash scripts/build-native-client-witnesses.sh
cargo run -p darknyx-tee-loadgen --features real-settle-chain -- \
  --real-settle --endpoint "$GW" --rpc-url "$RPC" \
  --admin-keypair .devnet/keypairs/admin.json \
  --base-mint "$BASE_HEX" --quote-mint "$QUOTE_HEX" \
  --traders 16 --real-mix partial-fill:100 --real-partial-fill-asks 9 \
  --real-submit-rate 15 --min-measured-batches 8 \
  --client-prove-concurrency 1 \
  --benchmark-label prod9-rapidsnark-c1 \
  --warmup-batches 1 \
  --report docs/benchmarks/runs/prod9-rapidsnark-c1.md \
  --metrics-json docs/benchmarks/runs/prod9-rapidsnark-c1.json
```

Benchmark artifacts under `docs/benchmarks/runs/` are evidence, not mutable
golden fixtures. Do not commit credentials, RPC URLs containing API keys, raw
order bodies, or CVM environment files.

The client prover fan-out is bounded (portable default one). VALID_DEPOSIT,
VALID_INPUT, and VALID_MERGE use mandatory Circom-generated native C++ witness
binaries; their `.wtns` assignments feed ark-groth16 directly. There is no
WASM/Wasmer runtime or silent fallback in the real-settle loadgen. On Apple
Silicon the script asks Circom for portable `--no_asm` C++ and builds direct
arm64 binaries; Linux x86_64 retains Circom's optimized generated assembly.

This replaces the 2026-07-23 baseline path in which sequential Wasmer
calculators exhausted the macOS 256-FD soft limit. Before a paid run, exercise
the exact 160-deposit + 160-input fixture:

```sh
bash scripts/build-native-client-witnesses.sh
cargo test -p darknyx-tee-loadgen --release --lib \
  --features real-settle-chain \
  native_client_proofs_sustain_full_fixture -- --ignored
```

Local Apple-Silicon preflight on 2026-07-23: all 320 proofs completed in
**21.06 seconds** after the release build, and the focused deposit/input/merge
proofs all verified against their committed zkey VKs. Treat this as a host
fixture-health check, not a browser proving benchmark.

Raising `--client-prove-concurrency` above the local machine's CPU/memory
capacity still invalidates the run before intake; do not confuse client
fixture-generation concurrency with the TEE's
`DARKNYX_TEE_SETTLE_BATCH_CONCURRENCY`.

The fixed comparison fixture uses sixteen persistent partial-fill bids, each
crossed by nine asks. It therefore offers 160 orders and expects 144 matched
pairs: nine full N=16 pages, of which the first is warm-up. The loadgen preloads
the bid side, paces the asks at fifteen placements per second (below the
single-account twenty-per-second limiter), retries exact-idempotent 429/5xx
responses, and records every retry. Any nonzero retry count is evidence to
explain, not something to hide; any run with fewer than eight measured batches
fails after writing its artifact.

Before deposits, the loadgen fetches the live instrument and aligns both
crossing prices to its nonzero tick. It also rejects workloads that can exceed
the on-chain 64-root history on any shard: for this 144-match fixture,
`ceil(144 / K) <= 64`, so K must be at least three (the controlled baseline
uses K=4). These are validity preflights, not parameters to relax to make a run
pass.

An external wave-synchronisation experiment on 2026-09-05 could not reliably
turn this workload into full pages. Even twenty independently verified
transports took longer than one matcher interval to admit later sixteen-order
waves, producing mostly `1+15` pages. Therefore `--real-submit-rate` controls
offered HTTP pacing, not matcher admission or batch packing. Do not add sleeps,
connection fan-out, or an unaudited production debug route merely to force a
100% packing result. The experiment and the valid transaction-v1 C1 baseline
are recorded in
[`runs/tx-v1-c1-packing-investigation-2026-09-05.md`](./runs/tx-v1-c1-packing-investigation-2026-09-05.md).

## CPU baseline matrix

Run on one healthy prod9 CPU CVM and one unchanged image:

| Leg | Prover | Batch concurrency | Purpose |
|---|---|---:|---|
| C1 | rapidsnark | 1 | Production control |
| C2 | rapidsnark | 2 | Detect CPU contention or IO overlap |

Use at least eight completed batches after warm-up. Record `cpu.max`,
`cpu.stat`, host model/single-thread score, image tag, `app_id`,
`compose_hash`, Solana RPC provider/tier, and exact workload seed/mix.

The completed 2026-07-23 prod9 comparison is recorded in
[`runs/prod9-rapidsnark-cpu-comparison-2026-07-23.md`](./runs/prod9-rapidsnark-cpu-comparison-2026-07-23.md).
C2 was 3.3% slower in confirmed throughput and had a 9.5% worse P95 total
batch latency, so the CPU setting remains concurrency 1. Do not add a CPU C4
leg: concurrency 4 is reserved for the same-box CUDA matrix.

## GPU same-box matrix

Never compare a prod9 CPU CVM directly with an H200 and call the difference
"GPU speedup": the host CPU changes too. On the same H200 CVM/image, run:

| Leg | Backend/device | Batch concurrency |
|---|---|---:|
| G1 | rapidsnark CPU | 1 |
| G2 | icicle CPU | 1 |
| G3 | icicle CUDA | 1 |
| G4 | icicle CUDA | 2 |
| G5 | icicle CUDA | 4 |

For every env-only redeploy, preserve the GPU allocation, reset the devnet
trees, cold-boot the Merkle mirrors, and take a fresh metrics cursor. Confirm
NVIDIA confidential-compute mode before sending private witnesses.

## Promotion and capacity thresholds

A concurrency or markets-per-CVM setting is acceptable only while all hold:

- terminal confirmed throughput is at least 20% above the lower setting;
- P95 queue wait remains below one matcher interval (2 seconds) in steady state;
- P95 workload submit-to-batch-terminal remains within the product SLO selected for that
  environment (initial devnet guardrail: 30 seconds);
- zero unexplained rejected or permanently ambiguous matches;
- rebroadcast rate stays below 1%;
- CPU is below 80% sustained, memory below 75%, and no cgroup throttling;
- the oldest queue age returns to zero after offered load stops.

The first failed threshold is the capacity boundary. Keep 20% headroom below
that boundary; do not use "the process did not crash" as a sizing rule.
