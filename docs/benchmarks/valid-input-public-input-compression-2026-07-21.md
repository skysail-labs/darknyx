# VALID_INPUT public-input compression benchmark — 2026-07-21

## Decision

Defer a production `VALID_INPUT` public-input change. Both compressed layouts
save compute in `lock_note`, but they also add a stable client-side proving
regression to a proof generated in the user's browser. The present transaction
already has comfortable compute headroom, so the product trade is not justified
until a representative browser benchmark establishes the real UX cost and the
protocol has a concrete need for the saved CU.

If the decision is revisited, prefer the two-input layout
`[merkle_root, note_digest]`. Keeping the root explicit is easier to audit and
the one-input layout saves only another 5,091 CU.

This report preserves the result. The one-off benchmark circuits, feature
gates, fixtures, and scripts were removed after measurement and are not part of
the production tree.

## Scope and method

- Baseline: the exact production `VALID_INPUT` circuit with four public inputs
  `[merkle_root, note_commitment, mint_lo, mint_hi]`.
- Two-input candidate: `[merkle_root, Poseidon4(domain, note_commitment,
  mint_lo, mint_hi)]`.
- One-input comparison: a Poseidon digest over the root and note fields.
- The baseline wrapper compiled to exactly 12,058 constraints, matching the
  production circuit.
- Prover benchmark: snarkjs 0.7.5, Node 26.5.0, Apple M3 (8 cores, 16 GB),
  macOS arm64; 21 interleaved recorded rounds after warm-up.
- CU benchmark: the same feature-gated Anchor verifier instruction and valid
  synthetic Groth16 proofs under litesvm. The unchanged production
  `lock_note`, exercised with a real deposit and real `VALID_INPUT` proof,
  provided the whole-instruction baseline.

The benchmark-only domain tags were measurement-local and are not reserved
protocol tags.

## Circuit and prover results

| Variant | Public inputs | Constraints | Constraint delta | Witness median | Paired witness delta | Prove median | Paired prove delta | Paired witness+prove delta |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Direct | 4 | 12,058 | — | 62.00 ms | — | 520.67 ms | — | — |
| Root + note digest | 2 | 12,794 | +736 / +6.1038% | 75.53 ms | +14.06 ms / +23.13% | 539.33 ms | +17.71 ms / +3.45% | +5.38% |
| Full digest | 1 | 12,893 | +835 / +6.9249% | 78.87 ms | +16.67 ms / +27.38% | 536.85 ms | +16.03 ms / +3.21% | +5.69% |

Unlike the much larger `VALID_MATCH_BATCH` circuit, the added Poseidon work is
material relative to this circuit. The paired 21-round measurements show a
consistent combined regression rather than noise. Extrapolating the 5.38%
two-input delta to a 40-second browser proof suggests roughly two additional
seconds, but that is an inference—not a browser measurement—and must not be
used as a release number.

Raw recorded samples (milliseconds):

| Variant | Witness samples | Prove samples |
|---|---|---|
| Direct | 60.61, 63.64, 64.54, 60.45, 60.89, 61.03, 60.92, 62.56, 61.91, 61.19, 64.84, 60.78, 62.66, 61.44, 63.22, 62.44, 62.00, 62.10, 60.23, 63.27, 63.68 | 508.17, 527.97, 542.64, 520.67, 509.60, 498.91, 501.62, 500.10, 499.68, 522.20, 512.66, 531.89, 532.85, 523.71, 514.29, 522.93, 519.31, 513.26, 718.81, 521.32, 570.57 |
| Root + note digest | 75.53, 75.06, 81.09, 74.43, 73.72, 74.76, 75.22, 74.81, 73.33, 79.11, 81.53, 74.94, 76.72, 86.30, 76.73, 77.29, 75.30, 75.42, 83.14, 76.10, 82.13 | 511.44, 540.31, 525.77, 542.98, 521.16, 514.19, 519.33, 518.14, 527.51, 594.66, 577.90, 559.18, 532.67, 540.30, 545.53, 529.06, 623.84, 557.32, 543.08, 539.33, 538.73 |
| Full digest | 80.23, 82.10, 83.32, 77.43, 77.56, 76.87, 76.59, 76.39, 77.29, 80.39, 79.21, 81.63, 78.24, 80.22, 76.67, 77.96, 79.00, 78.44, 82.06, 78.87, 82.93 | 536.85, 533.90, 547.28, 526.03, 539.56, 514.94, 519.89, 508.83, 527.62, 615.88, 598.54, 536.16, 601.18, 589.21, 538.56, 533.86, 530.73, 538.18, 538.50, 532.80, 538.81 |

## On-chain CU results

| Variant | Measured synthetic verifier CU | Saving from 4 inputs |
|---|---:|---:|
| 4 direct inputs | 97,335 | — |
| Root + note digest | 87,626 | 9,709 |
| Full digest | 82,535 | 14,800 |

The production `lock_note` baseline consumed 110,228 CU. Applying the isolated
verifier deltas gives:

| Production layout | Projected `lock_note` CU | Reduction |
|---|---:|---:|
| Current 4 inputs | 110,228 | — |
| Root + note digest | 100,519 | 9,709 / 8.808% |
| Full digest | 95,428 | 14,800 / 13.427% |

Settlement locks two inputs per match, so the two-input candidate would save
19,418 CU across both locks and the one-input candidate 29,600 CU. Including
the `VALID_MATCH_BATCH` 8→2 result, the measured/projected verifier totals are:

| Layout | `2 × lock_note + verify_match_batch` | Saving from current |
|---|---:|---:|
| Current | 352,975 CU | — |
| Match 2 PI + input 2 PI | 304,384 CU | 48,591 / 13.77% |
| Match 2 PI + input 1 PI | 294,202 CU | 58,773 / 16.65% |

## Revisit gate

Reconsider only after both conditions are met:

1. browser measurements on representative desktop and mobile-class hardware
   report witness, prove, and end-to-end order-placement latency for the direct
   and two-input production candidates; and
2. measured `lock_note` CU or block-packing pressure makes a roughly 9.7k-CU
   per-lock saving operationally valuable.

Any later cutover remains a full circuit migration: new source, zkey, verifier
key, SDK prover inputs, negative tests, devnet reset, and external review.
