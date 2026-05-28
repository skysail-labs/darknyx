# nyx-tee-loadgen — benchmark report (template)

This file is a placeholder. The real version is regenerated each time
`nyx-tee-loadgen` runs against a deployed CVM with `--report
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
cargo build -p nyx-tee --features debug_endpoints --release

# Local simulator (cheap, fast iteration):
~/dstack/sdk/simulator/dstack-simulator > /tmp/sim.log 2>&1 &
DSTACK_SIMULATOR_ENDPOINT=$(realpath ~/dstack/sdk/simulator/dstack.sock) \
  NYX_TEE_HTTP_BIND=127.0.0.1:8080 \
  ./target/release/nyx-tee &

cargo run -p nyx-tee-loadgen --release -- \
  --endpoint http://127.0.0.1:8080 \
  --traders 100 \
  --orders-per-trader-per-sec 5 \
  --duration-secs 60 \
  --seed-oracle \
  --report BENCHMARK-local.md

# Phala devnet (real numbers):
phala deploy -c deploy/docker-compose.yaml -n nyx-tee-bench
# (wait for boot, then run loadgen without --seed-oracle since
#  production CVMs don't expose /__debug/*)
cargo run -p nyx-tee-loadgen --release -- \
  --endpoint https://nyx-tee-bench.<custom-domain> \
  --traders 100 \
  --orders-per-trader-per-sec 5 \
  --duration-secs 60 \
  --report BENCHMARK-phala.md
phala cvms delete nyx-tee-bench
```

Then commit both files into this directory. The PR description
should call out any percentile that meaningfully regresses.

## Expected sections (rendered by `crate::report`)

- `## Run configuration` — endpoint, traders, rates, workload params
- `## Throughput` — actual submit rate, achieved/target ratio
- `## Submit outcomes` — 2xx / 4xx / 5xx / net-err counts + success rate
- `## Cancel outcomes` — 2xx / 4xx / 5xx counts
- `## Latency (ms)` — submit / cancel / match (TODO) histograms at P50 / P95 / P99 / P99.9 / max

## Last-run snapshots

*(none yet — to be filled in by the first Phala devnet run)*
