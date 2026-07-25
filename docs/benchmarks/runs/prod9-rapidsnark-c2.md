# Darknyx settlement benchmark — prod9-rapidsnark-c2

| Identity | Value |
|---|---|
| app_id | `9ca3cded105f16923afb0e3f62537882c14db637` |
| compose_hash | `d4de788e45bb44cc51944caf7a1c2cb28bcd86b584ed35a230afd19abe82b2cb` |
| boot_session_id | `e2988063a17d0155a8b1b73415ff37868fd63820c0a7b8ddd313ac1916d45810` |
| warm-up batches excluded | 1 |

## Outcomes and capacity

| Metric | Value |
|---|---|
| measured batches | 9 |
| confirmed matches | 142 |
| rejected matches | 0 |
| ambiguous matches | 0 |
| submitted orders | 160 |
| accepted orders | 160 |
| target order offer rate | 15.000 orders/s |
| accepted-order offer rate | 13.931 orders/s |
| submission attempts | 160 |
| rate-limit retries | 0 |
| transient retries | 0 |
| steady-state window | 152.823 s |
| confirmed match throughput | 0.929 matches/s |
| N=16 packing efficiency | 98.61% |
| Tx D co-inclusion ratio | 85.92% |
| rebroadcasts | 590 |
| rebroadcasts per confirmed match | 4.155 |

## Client VALID_INPUT proving

These values were captured from the loadgen log. This run used artifact schema
v1, which did not yet persist the client-prover distribution in the JSON.

| Metric | Value |
|---|---:|
| proofs | 160 |
| concurrency | 1 |
| wall time | 13.697 s |
| throughput | 11.681 proofs/s |
| P50 | 85.297 ms |
| P95 | 86.851 ms |
| P99 / max | not retained by schema v1 |

## Batch latency (ms)

| Stage | count | P50 | P95 | P99 | max |
|---|---:|---:|---:|---:|---:|
| queue_wait | 9 | 0 | 1 | 1 | 1 |
| lock | 9 | 1553 | 2654 | 2654 | 2654 |
| witness | 9 | 221 | 340 | 340 | 340 |
| prove_step | 9 | 2005 | 2079 | 2079 | 2079 |
| prove | 9 | 2271 | 2434 | 2434 | 2434 |
| verify | 9 | 1367 | 1803 | 1803 | 1803 |
| alt_tx | 9 | 1782 | 3550 | 3550 | 3550 |
| alt_wait | 9 | 773 | 994 | 994 | 994 |
| parallel | 9 | 4010 | 4320 | 4320 | 4320 |
| settle | 9 | 11578 | 14398 | 14398 | 14398 |
| close | 9 | 0 | 0 | 0 | 0 |
| total | 9 | 15230 | 18732 | 18732 | 18732 |
| workload_start_to_batch_terminal | 9 | 85082 | 155097 | 155097 | 155097 |
| post_offer_drain_to_batch_terminal | 9 | 73597 | 143612 | 143612 | 143612 |
