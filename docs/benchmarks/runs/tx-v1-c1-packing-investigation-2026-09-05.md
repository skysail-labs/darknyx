# Transaction-v1 C1 packing investigation — 2026-09-05

## Decision

Keep the ordinary saturated C1 run as the post-transaction-v1 CPU baseline.
Do not publish an externally wave-synchronised run as a full-batch capacity
number, and do not retain the experimental loadgen flag that attempted to
produce one. A client outside the CVM could not reliably place sixteen
proof-backed orders inside one two-second matcher interval, even through twenty
independently RA-TLS-verified HTTP/1 transports.

This result does **not** mean full N=16 pages are undesirable. It means packing
is a workload property and cannot be manufactured reliably by timing public
`POST /orders` calls. Measuring a deterministic full-page ceiling would require
an explicitly test-only in-enclave fixture or a configurable matcher cadence;
neither belongs in the production image merely to obtain a flattering number.

## Controlled setup

| Item | Value |
|---|---|
| CVM | `app_9ca3cded105f16923afb0e3f62537882c14db637` |
| instance | prod9 `tdx.xlarge`, 8 vCPU, 16 GB memory, no GPU |
| image | `tee-v3-hardening-92` / `sha256:dd31985fee01d921ed4c8e0ea49e479b25a69583831d95d2e60d8bc8d1a2c0f0` |
| compose hash | `abdc838c3c51a96d9e1f1da44f23e634e9c756658a2bf6135dcd6c0a92f9e726` |
| prover / witness | rapidsnark CPU / native |
| settlement | transaction v1 with inline accounts; no ALT create, extend, or warm-up |
| Solana RPC | private Helius devnet endpoint |
| trees / batch concurrency | K=4 / C1 |
| workload | 16 persistent partial-fill bids × 9 asks = 144 matched pairs |
| client proof concurrency | 1 |

Every attempt started after all four Merkle shards were reset and the CVM was
cold-booted from a post-reset sync floor. The loopback load proxy verified every
RA-TLS connection against the same compose hash, signer-set hash, boot session,
and boot SPKI before carrying private traffic.

## Results

| Run | Submission strategy | Measured batch pattern | Packing | Confirmed throughput | Total P50 / P95 | Interpretation |
|---|---|---|---:|---:|---:|---|
| C1 baseline | bids first, 15 orders/s | alternating `10,6` after warm-up | 49.26% | 1.340 matches/s | 5.726 / 6.579 s | Valid post-v1 production-shaped baseline |
| Burst diagnostic | bids first, nominal 1000 orders/s | alternating `14,2` after warm-up | 52.21% | 1.489 matches/s | 5.559 / 6.138 s | Raising the client offer rate alone did not make full pages |
| Eight-transport wave | one ask per persistent bid after an aligned tick | fragmented, including `2,9,5` and `2,14` | 42.11% | 0.923 matches/s | 5.539 / 6.356 s | Staging added idle time without controlling intake admission |
| Twenty-transport wave | same experiment with twenty verified transports | calibration `16`; then mostly `1,15`, with later `1,12,3` and `1,11,3,1` | 40.00% | 0.866 matches/s | 5.796 / 8.312 s | Final falsification of the external-synchronisation premise |

All four runs accepted all 160 submitted orders and eventually confirmed all
144 intended match outcomes. The tables exclude the first terminal batch as
warm-up, so their measured confirmed-match counts vary with the size of that
first batch. There were no rejected or ambiguous outcomes. The first three
runs had no rebroadcasts; the final run had two, or 0.016 per measured confirmed
match.

The valid C1 baseline removed the former ALT stages entirely:
`alt_tx` and `alt_wait` both had zero samples. Relative to the 2026-07-23 v0 C1
control, its observed confirmed throughput rose from 0.961 to 1.340 matches/s
(+39.4%), total P50 fell from 15.683 to 5.726 seconds (-63.5%), and settle P50
fell from 12.229 seconds to 0.988 seconds (-91.9%). This is a cross-date result,
not an isolated A/B: the N=16 circuit and other implementation details also
changed, so only the disappearance of the ALT stages can be attributed
mechanically to transaction v1.

## Final wave-run detail

The twenty-transport run is useful negative evidence even though it is not a
capacity baseline:

| Metric | Value |
|---|---:|
| submitted / accepted orders | 160 / 160 |
| total confirmed outcomes | 144 |
| measured batches / confirmed matches | 20 / 128 |
| rejected / ambiguous | 0 / 0 |
| client VALID_INPUT wall time | 16.076 s |
| client proof throughput | 9.953 proofs/s |
| client proof P50 / P95 | 96.681 / 130.437 ms |
| witness P50 / P95 | 256 / 279 ms |
| prove-step P50 / P95 | 3287 / 3535 ms |
| full-prove P50 / P95 | 3621 / 3795 ms |
| settle P50 / P95 | 1013 / 3592 ms |
| total P50 / P95 | 5796 / 8312 ms |
| Tx D co-inclusion | 79.69% |
| journal-write P50 / P95 | 5.573 / 7.233 ms |

The first calibration wave reached one 16-match batch in 611 ms. Subsequent
wave submissions took approximately 3.5–8.8 seconds and crossed multiple
matcher ticks. With zero HTTP retries or rejected orders, this points to the
proof-verified intake path—not the client-side rate knob or transport pool—as
the immediate packing boundary. In particular, VALID_INPUT verification is
synchronous inside the asynchronous order handler. This observation warrants
profiling before any production change; it does not by itself justify moving
verification off-thread or changing the matcher cadence.

## Follow-up rule

- Use the ordinary C1 result for transaction-v1 comparisons and future GPU
  same-box baselines.
- Treat packing efficiency as an independently reported workload metric; never
  normalize a partial page to sixteen and call it measured throughput.
- Revisit a deterministic full-page ceiling only if real volume exhibits a
  packing problem or a test-only in-enclave harness can be isolated from the
  production binary and attested deployment.
- Keep CPU settlement concurrency at one. This experiment does not supersede
  the earlier C1/C2 result in which C2 reduced throughput.

Raw JSON and generated Markdown from all four attempts remain in the external
benchmark volume. They intentionally are not copied into Git because
the comparison above contains the durable, reviewable result and the raw run
directory is the controlled evidence archive.
