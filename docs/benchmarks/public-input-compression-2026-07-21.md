# Groth16 public-input compression benchmark — 2026-07-21

## Decision

The production `VALID_MATCH_BATCH` statement now uses the measured 8→2 design.
It keeps `batch_root` public and replaces the seven governed fee/market fields
with one on-chain-recomputed Poseidon digest. The measured CU saving is
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

The benchmark domains `1001`/`1002` were measurement-local and are not reserved
protocol tags. Production uses `DOMAIN_MATCH_CONFIG = 28` and the two-input
layout only.

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

The unchanged eight-input `verify_match_batch` instruction measured 132,519 CU.
After the production cutover, the real two-input instruction with its
authoritative byte-level Poseidon8 recomputation measured 103,346 CU:

| Production layout | Measured/projected CU | Whole-instruction reduction |
|---|---:|---:|
| Previous 8 inputs (measured) | 132,519 | — |
| Production root + config digest (measured) | 103,346 | 29,173 / 22.01% |
| Full digest comparison (projected) | ~98,755 | ~25.48% |

The 2→1 step buys only another 4,591 CU. Keeping the batch root explicit is the
better implementation and auditability tradeoff. The production hash helper
uses the same byte-level Poseidon path as the CU probe; routing its preimage
through generic Ark field conversions was measured and rejected because that
host-oriented conversion work is prohibitively expensive under SBF.

## Artifact disposition

The one-off benchmark circuits, feature-gated instruction, synthetic proofs,
and scripts were deliberately removed after the decision. This report keeps
the method and raw samples without leaving a second set of security-sensitive
circuit/VK code in the repository. Production source, zkeys, verifier key,
prover helpers, and the committed N=16 fixture move together to the two-input
statement; the instruction wire layout and accounts do not change.
