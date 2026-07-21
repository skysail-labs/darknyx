# Public-input compression benchmarks

These circuits are measurement-only. They are not part of
`scripts/build-circuits.sh`, are not deployed, and do not carry production
trusted-setup artifacts.

The N=16 variants wrap the production `MatchBatch(16)` template without
changing it:

- `match_batch_n16_digest2`: public `[batch_root, config_digest]`.
- `match_batch_n16_digest1`: one digest over root and config.

The `verifier_pi{8,2,1}` circuits generate tiny valid fixtures for the
off-by-default `public-input-bench` vault feature. Their only purpose is to
isolate litesvm CU spent on public-input preparation and Poseidon.

Run from the repository root:

```sh
bash scripts/build-public-input-benchmarks.sh all
BENCH_RUNS=7 node scripts/benchmark-public-input-compression.mjs
cargo build-sbf --manifest-path programs/vault/Cargo.toml \
  --features devnet-admin,public-input-bench
cargo test -p vault --features devnet-admin,public-input-bench \
  --test public_input_compression_bench -- --nocapture
```

All heavy artifacts are disposable and remain under
`target/public-input-benchmarks/`. The verifier VK constants and 256-byte proof
fixtures are committed so the CU test remains reproducible without retaining
benchmark proving keys.
