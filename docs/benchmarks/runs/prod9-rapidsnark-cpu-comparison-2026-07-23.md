# Prod9 rapidsnark CPU concurrency comparison — 2026-07-23

## Decision

Keep `DARKNYX_TEE_SETTLE_BATCH_CONCURRENCY=1` as the CPU setting. C2 did
not meet the promotion rule: concurrency 2 reduced confirmed-match throughput
from 0.961 to 0.929 matches/s (-3.3%) and raised P95 total batch latency from
17.101 to 18.732 seconds (+9.5%). There is no CPU C4 leg; concurrency 4 remains
part of the future same-box CUDA matrix, where overlapping GPU work may produce
a different result.

The source artifacts are
[`prod9-rapidsnark-c1.json`](./prod9-rapidsnark-c1.json) and
[`prod9-rapidsnark-c2.json`](./prod9-rapidsnark-c2.json). Their generated
Markdown reports retain the complete stage distributions.

## Controlled setup

| Item | Value |
|---|---|
| CVM | `app_9ca3cded105f16923afb0e3f62537882c14db637` |
| instance | prod9 `tdx.xlarge`, 8 logical CPUs, 16 GB memory, no GPU |
| image | `tee-v3-hardening-69` |
| compose hash | `d4de788e45bb44cc51944caf7a1c2cb28bcd86b584ed35a230afd19abe82b2cb` |
| prover / witness | rapidsnark CPU / native |
| Solana RPC | private Helius devnet endpoint |
| trees / signers | K=4 |
| workload | 16 persistent partial-fill bids × 9 asks = 144 matched pairs |
| offered orders | 160, paced at a target 15 orders/s |
| warm-up policy | exclude the first terminal batch |
| client prover | native VALID_INPUT, concurrency 1 |

The loadgen fetched the live instrument tick and aligned its crossing prices
before proving. It also enforced the Merkle-root-ring budget before deposits:
144 settlement root updates require at least three shards because each shard
retains 64 roots. K=4 was used for both accepted legs.

## Result

| Metric | C1: concurrency 1 | C2: concurrency 2 | Interpretation |
|---|---:|---:|---|
| total confirmed outcomes | 144 | 144 | no loss |
| measured batches after warm-up | 8 | 9 | C2 warm-up contained 2 matches; its next 14-match page remains measured |
| measured confirmed matches | 128 | 142 | both exceed the eight-batch minimum |
| rejected / ambiguous | 0 / 0 | 0 / 0 | healthy terminal outcomes |
| confirmed throughput | 0.961 matches/s | 0.929 matches/s | C2 is 3.3% lower |
| packing efficiency | 100.00% | 98.61% | C1 packed all measured pages |
| Tx D co-inclusion | 83.59% | 85.92% | small C2 gain, not enough to offset throughput |
| queue wait P95 | 1 ms | 1 ms | neither scheduler queue saturated |
| witness P50 / P95 | 246 / 278 ms | 221 / 340 ms | similar central tendency, worse C2 tail |
| prove-step P50 / P95 | 2086 / 2267 ms | 2005 / 2079 ms | no CPU contention regression in this substage |
| full prove P50 / P95 | 2403 / 2543 ms | 2271 / 2434 ms | slightly lower in C2 |
| settle P50 / P95 | 12229 / 13613 ms | 11578 / 14398 ms | confirmation tail worsened |
| total P50 / P95 | 15683 / 17101 ms | 15230 / 18732 ms | C2 tail worsened 9.5% |
| workload-start terminal P95 | 151907 ms | 155097 ms | neither meets the provisional 30-second devnet guardrail |
| rebroadcasts / confirmed match | 4.398 | 4.155 | both violate the <1% promotion guardrail |
| client proof throughput | 11.124 proofs/s | 11.681 proofs/s | host-side fixture noise; client settings were unchanged |
| client proof P50 / P95 | 89.064 / 94.306 ms | 85.297 / 86.851 ms | native host prover, not browser UX |

The high rebroadcast counts are not hidden by the successful terminal result.
They make both legs unsuitable as production-capacity promotion evidence and
need a separate overdue/rebroadcast-threshold investigation against the
observed 10–14 second devnet Tx D confirmation time. They do not support
raising CPU batch concurrency.

`workload_start_to_batch_terminal` is a whole-fixture benchmark clock, not
per-order user latency. Per-order accepted-submission → authenticated order
event latency still requires a client-side `/v1/stream` observer and was not
retroactively inferred from these server batch records.

## Host resource evidence and limitation

The CVM boot profile reported model `06/af` at 2400 MHz, a 219.5 Mops/s
single-thread microbenchmark, `cpu.max = max 100000`, and zero boot-time
`nr_throttled` / `throttled_usec`. Phala SSH was unavailable for this CVM
(`Permission denied (publickey)`), so the post-run `cpu.stat` values could not
be read.

The fallback guest-agent metrics and Phala stats API showed:

- C2 memory before the run: about 0.92 GB used of 15.77 GB.
- C2 peak across fifteen in-run samples: 1.12 GB used (about 7.1%).
- C2 peak one-minute load average: 1.27, about 15.9% of eight logical CPUs.
- C2 after the run: 1.05 GB used and one-minute load average 0.47.

Those samples rule out memory pressure and gross host load, but they are not a
replacement for process CPU or post-run cgroup throttling. The next GPU window
must capture `cpu.max`, before/after `cpu.stat`, and `nvidia-smi` through
working SSH in every leg.
