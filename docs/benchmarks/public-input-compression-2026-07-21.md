# Groth16 public-input compression benchmark — 2026-07-21

## Decision

Proceed with a production `VALID_MATCH_BATCH` 8→2 design in the next circuit
change. Keep `batch_root` public and replace the seven governed fee/market
fields with one on-chain-recomputed Poseidon digest. The measured CU saving is
material, while the full N=16 proof path showed no proving regression outside
noise.

Do not store the combined digest in `MarketConfig`: its preimage spans both
`VaultConfig` and `MarketConfig`, which have independent update instructions.
Recompute it from the authoritative accounts during verification.

## Scope and method

- Production `MatchBatch(16)` constraint body reused unchanged.
- Baseline: 8 direct public inputs.
- Conservative candidate: 2 public inputs — root plus `Poseidon8(domain,
  fee, owner, base_lo, base_hi, quote_lo, quote_hi, scale)`.
- Comparison only: 1 public input — `Poseidon9(domain, root, ...config)`.
- Prover benchmark: snarkjs 0.7.5, Node 26.5.0, Apple M3/8 cores/16 GB,
  seven interleaved recorded rounds after one warm-up per variant.
- CU benchmark: the same feature-gated Anchor instruction and three synthetic
  valid Groth16 proofs under litesvm, so the delta isolates public-input MSM and
  Poseidon syscall work.

The benchmark domains `1001`/`1002` are measurement-local and are not reserved
protocol tags.

## Circuit and prover results

| Variant | Public inputs | Constraints | Constraint delta | Witness median | Paired witness delta | Prove median | Paired prove delta | Paired witness+prove delta |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Direct | 8 | 232,854 | — | 370.04 ms | — | 6,659.05 ms | — | — |
| Root + config digest | 2 | 234,025 | +1,171 / +0.503% | 399.28 ms | +29.31 ms / +7.85% | 6,410.25 ms | −59.79 ms / −0.94% | −0.40% |
| Full digest | 1 | 234,085 | +1,231 / +0.529% | 396.86 ms | +27.00 ms / +7.30% | 6,389.09 ms | −96.84 ms / −1.48% | −0.98% |

Negative proving deltas are treated as noise, not a speedup claim. The useful
finding is that the extra Poseidon constraint work did not cause a measurable
end-to-end proving regression. The witness-only percentage looks large because
the baseline witness is short; the absolute 8→2 cost was about 29 ms.

Raw recorded samples (milliseconds):

| Variant | Witness samples | Prove samples |
|---|---|---|
| Direct | 404.35, 391.67, 361.89, 360.52, 370.04, 373.55, 369.89 | 6659.05, 6401.03, 6389.63, 6391.01, 6669.18, 6976.66, 7471.05 |
| Root + config digest | 399.28, 392.13, 406.60, 393.11, 398.46, 402.86, 402.55 | 6476.96, 6312.82, 6410.25, 6331.22, 6378.66, 7535.90, 7762.45 |
| Full digest | 393.36, 396.86, 393.59, 401.97, 390.33, 404.24, 396.89 | 6374.37, 6304.19, 6389.09, 6452.70, 6371.86, 6873.64, 7844.28 |

## On-chain CU results

| Variant | Measured CU | Saving from 8 inputs |
|---|---:|---:|
| 8 direct inputs | 119,939 | — |
| Root + config digest | 90,570 | 29,369 |
| Full digest | 85,979 | 33,960 |

The real unchanged `verify_match_batch` instruction remained exactly 132,519
CU in the same feature-gated SBF build. Applying the isolated deltas projects:

| Production layout | Projected CU | Whole-instruction reduction |
|---|---:|---:|
| Current 8 inputs | 132,519 | — |
| Proposed 2 inputs | ~103,150 | ~22.2% |
| Full digest comparison | ~98,559 | ~25.6% |

The 2→1 step buys only another 4,591 CU. Keeping the batch root explicit is the
better first implementation and auditability tradeoff.

## Reproduction

```sh
bash scripts/build-public-input-benchmarks.sh all
BENCH_RUNS=7 node scripts/benchmark-public-input-compression.mjs
cargo build-sbf --manifest-path programs/vault/Cargo.toml \
  --features devnet-admin,public-input-bench
cargo test -p vault --features devnet-admin,public-input-bench \
  --test public_input_compression_bench -- --nocapture
cargo test -p vault --features devnet-admin,public-input-bench \
  --test match_batch_verify real_n16_proof_accepted_onchain_creates_marker \
  -- --nocapture
```

Heavy benchmark R1CS/wasm/zkeys and generated timing output remain ignored
under `target/public-input-benchmarks/`. Production circuits, zkeys, VKs,
fixtures, instruction layouts, and deployed behavior are unchanged by this
benchmark branch.
