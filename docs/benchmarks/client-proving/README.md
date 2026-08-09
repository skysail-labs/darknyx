# Client proving benchmark methodology

This directory records the evidence used to choose Darknyx trader packaging and
the client proving backend. The harness is
`packages/client-prover-bench`; it benchmarks the six circuits that execute on a
client:

- `VALID_WALLET_CREATE`
- `VALID_DEPOSIT`
- `VALID_INPUT`
- `VALID_SPEND`
- `VALID_MERGE`, K=2 and K=4

`VALID_MATCH_BATCH` is TEE-owned and deliberately excluded. No synthetic
benchmark circuits or alternative proving keys are used.

## Comparability contract

Every backend consumes the same deterministic fixture corpus and the committed
WASM/zkey for each circuit. Every generated proof is locally verified and its
public-signal order is compared with a pinned expected vector. Reports include
artifact size and SHA-256 so results from different protocol versions cannot be
mixed accidentally.

The three supported paths are:

1. Node + snarkjs, split into artifact load, witness, prove, and verify.
2. Stable Chrome + a dedicated Worker + snarkjs, including cold/warm artifact
   fetches and cross-origin-isolation metadata.
3. Circom native C++ witness generation + rapidsnark, the native ceiling.

## Sampling

- Cold: 10 fresh/cache-busted samples per circuit.
- Warm-up: one untimed proof per circuit and backend.
- Warm: 300 `VALID_INPUT` samples; 100 samples for each other circuit.
- Soak: ten minutes per backend/device, recording queue stability, crashes,
  memory growth, and first-to-last-quartile degradation.
- Report p50/p95/p99 with deterministic bootstrap 95% intervals. Means are
  permitted only for throughput.

Raw run JSON may be large and machine-specific. Keep exploratory output outside
Git. Commit only reviewed result JSON and the accompanying Markdown conclusion.
The versioned envelope is `packages/client-prover-bench/benchmark-report.schema.json`.

The browser runner's cold samples are true fresh-process starts: each uses a new
Chrome profile and process. This deliberately includes JS/WASM initialization as
well as cache-busted artifact fetch. Warm samples run after one untimed proof in
one Worker session.

Node's `process_high_water_rss_bytes` is the high-water mark for the whole
runner, not a per-call allocation. Run one circuit per command when collecting
its memory gate. The browser runner samples the entire Chrome process tree once
per second and records peak RSS plus first-to-last-quartile growth. The page
also attempts origin memory as supplemental evidence, with a bounded fallback
because Chrome can withhold that API after proof work. The physical x86 report
must use the process-tree RSS gate.

Apple Silicon native generation uses Circom's portable `--no_asm` C++ output
and is correctness evidence, not the native performance ceiling. The
decision-grade native result is the optimized x86 generator plus rapidsnark on
the required physical laptop.

## Commands

Smoke the corpus and report schema:

```sh
npm run test:prover
npm run bench:client-prover:node -- \
  --circuits all --warm-runs 1 --output /tmp/darknyx-node-smoke.json
```

Run the full Node sample (the per-circuit defaults implement the 300/100 split):

```sh
npm run bench:client-prover:node -- \
  --circuits all --output /tmp/darknyx-node-full.json
```

Run stable Chrome with ten cold samples and an optional idealized 10 Mbps server
throttle. Omit `--network-mbps` for latency measurements; use it only for the
artifact-fetch gate. Throttled mode transfers WASM and zkey sequentially so the
configured value is one aggregate bandwidth cap, not a per-response multiplier:

```sh
npm run bench:client-prover:browser -- \
  --circuits all --cold-runs 10 --network-mbps 10 \
  --output /tmp/darknyx-chrome-10mbps.json
```

Build all six native witness generators, then supply a local rapidsnark binary:

```sh
bash scripts/build-native-client-witnesses.sh
# One local build option (the submodule and GMP prerequisites must be present):
cmake --build third_party/rapidsnark/build_prover --target prover --parallel 8
RAPIDSNARK_BIN=/absolute/path/to/prover \
  npm run bench:client-prover:native -- \
  --circuits all --output /tmp/darknyx-native-full.json
```

The definitive x86 result must come from a physical mid-range 8 GiB laptop.
Virtual machines and Apple-to-x86 emulation do not qualify.

Run the ten-minute stability soak separately so it does not contaminate the
latency sample. `VALID_INPUT` is the representative frequent action; the runner
records sustained proof rate, first-to-last-quartile degradation, crashes,
main-thread stalls in Chrome, and browser memory growth:

```sh
npm run bench:client-prover:node -- \
  --circuits input --warm-runs 0 --soak-seconds 600 \
  --output /tmp/darknyx-node-input-soak.json
npm run bench:client-prover:browser -- \
  --circuits input --warm-runs 0 --cold-runs 0 --soak-seconds 600 \
  --output /tmp/darknyx-chrome-input-soak.json
RAPIDSNARK_BIN=/absolute/path/to/prover \
  npm run bench:client-prover:native -- \
  --circuits input --runs 0 --soak-seconds 600 \
  --output /tmp/darknyx-native-input-soak.json
```

## Desktop decision gates

| Gate                       | Target                                                                |
| -------------------------- | --------------------------------------------------------------------- |
| `VALID_INPUT` warm Chrome  | p95 ≤ 1.5 s; p99 ≤ 2.5 s                                              |
| Wallet/deposit warm Chrome | p95 ≤ 2 s each                                                        |
| Spend warm Chrome          | p95 ≤ 2 s                                                             |
| Merge K2 / K4 warm Chrome  | p95 ≤ 5 s / 10 s                                                      |
| Reliability                | zero OOM/crash in sample; x86 peak RSS < 1.5 GiB                      |
| Responsiveness             | proof work stays in Worker; UI-thread stall ≤ 100 ms                  |
| Thermal soak               | degradation < 25% over ten minutes                                    |
| 10 Mbps artifact fetch     | wallet ≤ 6 s, deposit ≤ 7 s, input/spend ≤ 10 s, K2 ≤ 18 s, K4 ≤ 30 s |

Packaging is chosen only after both performance and the browser-custody review:

- Chrome performance pass + custody pass: browser can be tier-1 trader default.
- Chrome performance pass + custody fail: signed Tauri app, native core.
- Chrome performance fail + native pass: signed Tauri app, native core.
- Both fail: protocol/prover optimization ADR before product packaging.

Market makers remain native/headless regardless of the trader result.
