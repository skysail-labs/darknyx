# Darknyx settlement benchmark — prod9-rapidsnark-c1

| Identity | Value |
|---|---|
| app_id | `9ca3cded105f16923afb0e3f62537882c14db637` |
| compose_hash | `d4de788e45bb44cc51944caf7a1c2cb28bcd86b584ed35a230afd19abe82b2cb` |
| boot_session_id | `44e2f9a260da7ab98b7f20f5c5149bd419e17283a319e596df679016daa1fb8c` |
| warm-up batches excluded | 1 |

## Outcomes and capacity

| Metric | Value |
|---|---|
| measured batches | 8 |
| confirmed matches | 128 |
| rejected matches | 0 |
| ambiguous matches | 0 |
| submitted orders | 160 |
| accepted orders | 160 |
| target order offer rate | 15.000 orders/s |
| accepted-order offer rate | 14.295 orders/s |
| submission attempts | 160 |
| rate-limit retries | 0 |
| transient retries | 0 |
| steady-state window | 133.204 s |
| confirmed match throughput | 0.961 matches/s |
| N=16 packing efficiency | 100.00% |
| Tx D co-inclusion ratio | 83.59% |
| rebroadcasts | 563 |
| rebroadcasts per confirmed match | 4.398 |

## Client VALID_INPUT proving

These values were captured from the loadgen log. This run used artifact schema
v1, which did not yet persist the client-prover distribution in the JSON.

| Metric | Value |
|---|---:|
| proofs | 160 |
| concurrency | 1 |
| wall time | 14.384 s |
| throughput | 11.124 proofs/s |
| P50 | 89.064 ms |
| P95 | 94.306 ms |
| P99 / max | not retained by schema v1 |

## Batch latency (ms)

| Stage | count | P50 | P95 | P99 | max |
|---|---:|---:|---:|---:|---:|
| queue_wait | 8 | 0 | 1 | 1 | 1 |
| lock | 8 | 1923 | 3028 | 3028 | 3028 |
| witness | 8 | 246 | 278 | 278 | 278 |
| prove_step | 8 | 2086 | 2267 | 2267 | 2267 |
| prove | 8 | 2403 | 2543 | 2543 | 2543 |
| verify | 8 | 1326 | 1536 | 1536 | 1536 |
| alt_tx | 8 | 2455 | 3296 | 3296 | 3296 |
| alt_wait | 8 | 762 | 765 | 765 | 765 |
| parallel | 8 | 3709 | 4062 | 4062 | 4062 |
| settle | 8 | 12229 | 13613 | 13613 | 13613 |
| close | 8 | 0 | 0 | 0 | 0 |
| total | 8 | 15683 | 17101 | 17101 | 17101 |
| workload_start_to_batch_terminal | 8 | 99618 | 151907 | 151907 | 151907 |
| post_offer_drain_to_batch_terminal | 8 | 88425 | 140714 | 140714 | 140714 |
