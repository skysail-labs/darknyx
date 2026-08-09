# Apple M3 client-proving baseline — 2026-08-10

This is the first decision-grade run of the current six client circuits. It
qualifies the Apple Silicon leg of the desktop matrix; it does **not** decide
browser packaging because the required physical mid-range x86 run and the
browser-custody investigation remain open.

## Environment and validity

- Apple M3, 16 GiB RAM, 8 logical CPUs; macOS kernel 25.5.0.
- Node 26.5.0 and stable headless Chrome 150.0.7871.187.
- Chrome proving ran in a dedicated, cross-origin-isolated Worker with one
  prover thread. Every proof was locally verified and every public-signal
  vector matched its deterministic fixture.
- Warm sample sizes were 300 for `VALID_INPUT` and 100 for every other circuit,
  after one untimed warm-up. Cold samples used ten fresh Chrome processes and
  profiles per circuit.
- The 10 Mbps run used one aggregate bandwidth cap: WASM and zkey transfers
  were serialized in throttled mode. A wallet smoke measured 3,197.8 ms against
  a byte-derived 3,154.8 ms expectation.
- Artifact SHA-256 values match across every report. The reports contain no
  credentials or private user data.

## Stable Chrome: warm and local cold

All times are milliseconds. Cold results are end-to-end fresh-process proofs
over localhost without an artificial bandwidth cap.

| Circuit       | Warm n | Witness p50 | Prove p50 |       Warm E2E p50 / p95 / p99 |       Cold E2E p50 / p95 / p99 |
| ------------- | -----: | ----------: | --------: | -----------------------------: | -----------------------------: |
| Wallet create |    100 |       22.84 |    163.13 |       191.03 / 218.39 / 252.57 |       263.19 / 291.45 / 301.05 |
| Deposit       |    100 |       33.54 |    131.56 |       170.75 / 206.25 / 264.83 |       255.46 / 272.84 / 275.56 |
| Input         |    300 |       37.99 |    539.93 |       588.68 / 631.48 / 671.88 |       651.55 / 656.58 / 657.45 |
| Spend         |    100 |       37.55 |    550.50 |       599.57 / 620.93 / 644.58 |       665.64 / 732.09 / 747.81 |
| Merge K=2     |    100 |       27.90 |    979.30 | 1,037.30 / 1,092.60 / 1,112.94 | 1,118.53 / 1,137.38 / 1,145.91 |
| Merge K=4     |    100 |       68.79 |  1,895.04 | 1,984.94 / 2,070.53 / 2,095.96 | 1,993.69 / 2,076.10 / 2,121.93 |

The worst observed main-thread stall was 11.11 ms, well below the 100 ms
responsiveness target. Chrome process-tree peak RSS ranged from 1.93 to 2.40
GiB by circuit, with a 2.40 GiB overall maximum. The launch gate is explicitly
for physical x86 RSS, so this Apple number is a warning and sizing input—not a
pass/fail substitute for the missing x86 result.

## Stable Chrome: aggregate 10 Mbps cold gate

| Circuit       | Artifact p50 |               E2E p50 / p95 / p99 |   Gate | Result |
| ------------- | -----------: | --------------------------------: | -----: | ------ |
| Wallet create |     3,192.89 |    3,454.98 / 3,470.49 / 3,477.73 |  6,000 | Pass   |
| Deposit       |     3,664.47 |    3,914.69 / 3,919.90 / 3,920.16 |  7,000 | Pass   |
| Input         |     7,039.30 |    7,695.78 / 7,728.74 / 7,729.07 | 10,000 | Pass   |
| Spend         |     7,238.02 |    7,892.36 / 7,941.25 / 7,957.18 | 10,000 | Pass   |
| Merge K=2     |    12,075.52 | 13,175.30 / 13,200.10 / 13,210.53 | 18,000 | Pass   |
| Merge K=4     |    20,842.27 | 22,755.75 / 22,798.47 / 22,808.42 | 30,000 | Pass   |

## Ten-minute `VALID_INPUT` soaks

| Backend               | Proofs | Proofs/s | E2E p50 / p95 / p99 (ms) | First→last quartile | Memory                                    |
| --------------------- | -----: | -------: | -----------------------: | ------------------: | ----------------------------------------- |
| Chrome Worker/snarkjs |  1,006 |     1.68 | 588.43 / 634.84 / 687.81 |              +5.62% | 2.39 GiB peak; +18.5 MiB steady-state RSS |
| Node/snarkjs          |  1,019 |     1.70 | 585.74 / 613.75 / 639.83 |              +0.09% | 864 MiB process high-water RSS            |

Both backends passed the `<25%` thermal-degradation target with no crash or
invalid proof. The Chrome main-thread stall maximum during the soak was 2.81
ms.

## Node baseline

| Circuit       |   n | Witness p50 | Prove p50 |       E2E p50 / p95 / p99 (ms) |
| ------------- | --: | ----------: | --------: | -----------------------------: |
| Wallet create | 100 |       40.33 |    163.77 |       212.09 / 234.97 / 240.99 |
| Deposit       | 100 |       58.61 |    139.49 |       206.65 / 232.13 / 255.22 |
| Input         | 300 |       62.30 |    540.06 |     613.37 / 794.31 / 1,012.65 |
| Spend         | 100 |       62.69 |    543.87 |       617.12 / 739.46 / 872.28 |
| Merge K=2     | 100 |       77.30 |    978.10 | 1,067.87 / 1,303.47 / 1,477.63 |
| Merge K=4     | 100 |       93.99 |  1,806.71 | 1,912.78 / 2,006.55 / 2,516.74 |

Node's full-run high-water RSS is cumulative across circuits. Use the isolated
input soak for the meaningful Node memory figure.

## Gate interpretation and next actions

- Apple M3 evidence meets the numeric thresholds associated with G1, G2, G3,
  G6, and the thermal/reliability portion of G7. It does not close the
  cross-device gates, but it strongly rejects the premise that current-browser
  proving latency itself forces a native desktop client.
- D1 (browser versus signed Tauri packaging) remains open. Run this exact corpus
  on a physical mid-range x86 laptop with 8 GiB RAM; do not use a VM or
  Apple-to-x86 emulation. The x86 process-tree peak must be below 1.5 GiB.
- Complete I6: test the actual wallet flow under COOP/COEP and resolve whether
  the browser can provide the required custody boundary. A Worker is only a
  responsiveness boundary.
- G4 (cached firm-up retrieval/sign/send), G5 (MM refresh demand), I3 (re-lock
  classifier), and I7 (trader interviews) remain open. Do not begin packaging
  implementation or declare Phase 0 complete until those decision inputs land.
- The Apple native runner remains correctness-only because Circom's portable
  `--no_asm` generator is not an x86-native performance ceiling.

## Raw evidence

- [`chrome-full.json`](chrome-full.json)
- [`chrome-10mbps.json`](chrome-10mbps.json)
- [`chrome-input-soak.json`](chrome-input-soak.json)
- [`node-full.json`](node-full.json)
- [`node-input-soak.json`](node-input-soak.json)

The JSON reports carry raw samples, bootstrap confidence intervals, host and
browser metadata, artifact byte sizes and hashes, Chrome process-tree RSS
samples, and responsiveness measurements.
