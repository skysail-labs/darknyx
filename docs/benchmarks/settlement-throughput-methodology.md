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
| Workload submit-to-batch-terminal latency | Completion of the workload's concurrent HTTP submissions to each correlated batch's terminal metrics record; report P50/P95/P99 | Repeatable end-to-end venue latency for benchmark comparison |
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

Example:

```sh
cargo run -p darknyx-tee-loadgen --features real-settle-chain -- \
  --real-settle --endpoint "$GW" --rpc-url "$RPC" \
  --admin-keypair .devnet/keypairs/admin.json \
  --base-mint "$BASE_HEX" --quote-mint "$QUOTE_HEX" \
  --traders 12 --real-mix exact-match:70,partial-fill:30 \
  --client-prove-concurrency 1 \
  --benchmark-label prod9-rapidsnark-c1 \
  --warmup-batches 1 \
  --report docs/benchmarks/runs/prod9-rapidsnark-c1.md \
  --metrics-json docs/benchmarks/runs/prod9-rapidsnark-c1.json
```

Benchmark artifacts under `docs/benchmarks/runs/` are evidence, not mutable
golden fixtures. Do not commit credentials, RPC URLs containing API keys, raw
order bodies, or CVM environment files.

The client prover fan-out is bounded (portable default one). Each proof runs in
a short-lived Wasmer runtime so its virtual-mio descriptors are released before
the process continues. This fixes the 2026-07-23 baseline failure in which 42
sequential deposits exhausted a macOS 256-FD soft limit and the first
VALID_INPUT proof failed. Before a paid run, exercise the exact regression:

```sh
cargo test -p darknyx-tee-loadgen --release --lib \
  --features real-settle-chain \
  sequential_client_proofs_do_not_exhaust_descriptors -- --ignored
```

Raising `--client-prove-concurrency` above the local machine's descriptor and
native-thread capacity still invalidates the run before intake; do not confuse
client fixture-generation concurrency with the TEE's
`DARKNYX_TEE_SETTLE_BATCH_CONCURRENCY`.

## CPU baseline matrix

Run on one healthy prod9 CPU CVM and one unchanged image:

| Leg | Prover | Batch concurrency | Purpose |
|---|---|---:|---|
| C1 | rapidsnark | 1 | Production control |
| C2 | rapidsnark | 2 | Detect CPU contention or IO overlap |

Use at least eight completed batches after warm-up. Record `cpu.max`,
`cpu.stat`, host model/single-thread score, image tag, `app_id`,
`compose_hash`, Solana RPC provider/tier, and exact workload seed/mix.

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
