# Phase 5 release-assurance checkpoint

**Recorded:** 2026-08-25

**Status:** Paused after the principal local, devnet, and CVM validation. The
remaining focused checks are intentionally retained as open work in this
report and the remediation tracker; this checkpoint does not claim release
closure.

## 1. Validated in this phase

### Local and devnet foundation

- The complete local pre-PR gate passed before the hosted run, including the
  devnet-admin SBF fingerprint build, workspace Rust tests, artifact-required
  TEE tests, TypeScript builds/typechecks/tests, parity helpers, browser
  production build, dependency audits, and repository guards.
- The upgraded vault program is
  `C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx`. Upgrade signature:
  `WPdJdigrdMZJBh4zcQJ1es59i8kqTr3zKaSeS84hLSaauNtbWpXkrDbBj1je8eZWTMKjvnwDGXhCSehZQhvSqKw`
  at slot `487696533`.
- VALID_DEPOSIT deposit/withdraw, VALID_MERGE K=2, and event leaf-index devnet
  tests passed against the private Helius endpoint.
- A clean four-shard foundation was used. The final two-epoch rehearsal reset
  signatures were:
  - tree 0: `5yfQWWNu3kciNwSdQijPWY2wKEqapqxgy6zVJ5QmG1TX2fkgZDKtJe6eZKANQ9Ci4tejN4xY38Vwtw5V2JBpmBpq`
  - tree 1: `5F7BRE9vkVFtkprtHxEHxY5zSTQFnJTM1XebhErsJm9FNNSe1dvcjKSV1VAHze1DnqKHPGb2igmMzX5cVrhvG8va`
  - tree 2: `2dyR9VPxVVBWyQatZezRjV7Zajh3PGoPWc7jdQdW1EkvgE3yJH4ES85DHJ2DrgpXVpprgZCiJ4UCVUn5UQiZvdX4`
  - tree 3: `4w1ZSBM5Zn4pdkxQ1jECERGNcBeSGz7yEUByyKsPeraFJy2vvCAiAmyDESYuU8WVxHZVKyEBh1cUJdhXP4N8AmC`

### Immutable CVM deployment

- CPU image tag: `tee-v3-hardening-91`.
- Image digest:
  `sha256:af1a31600f6a5cc9bc0de14df4609cdb73e87906ef7805b482d09360ce123422`.
- App ID: `app_9ca3cded105f16923afb0e3f62537882c14db637`.
- Compose hash:
  `dda6a19ceecee3b8b262c9c43bf2bf4421bdf00ef07da412468eda34459905cf`.
- The CVM was `tdx.xlarge` on prod9 with 8 vCPU, 16 GiB RAM, and zero
  GPUs. RA-TLS live validation passed 6 tests with 1 environment-gated skip.
- All four enclave signers were rotated and funded. Rotation signature:
  `37FtASmtj1vag5m1Vf4LujVUnKBKCGSenoX1FtWSdR1fZEfTs6Ppjr9qVjZ1yfxit8jWtPVAUBJMbntD5HhxcQSu`.

### Settlement and recovery behavior

- Multimatch passed with four matched pairs. Its steady three-match batch
  measured `234 ms` witness generation, `3,098 ms` proof step, `1,258 ms`
  verification, and `9,856 ms` total settlement-pipeline time; all three
  matches were confirmed with no rejected or ambiguous outcome.
- Merge-then-order passed from its own reset and cold boot. It measured
  `365 ms` witness generation, `2,814 ms` proof step, `1,246 ms`
  verification, and `10,188 ms` total pipeline time.
- Epoch A settlement passed with canonical seed-plus-finalized-chain user
  recovery and the existing settle-wire note-use unlinkability assertion. It
  measured `429 ms` witness generation, `3,247 ms` proof step, `1,560 ms`
  verification, and `12,595 ms` total pipeline time.
- The venue drained safely before rotation: `in_flight=0`,
  `safe_to_stop=true`; the two recorded journal writes measured `5,867 us`
  p50 and `6,254 us` p95/max.
- The encrypted fee-key backup was verified, governance advanced from epoch A
  to epoch B without a tree reset, and the same immutable image cold-booted
  from the retained four-shard history. Epoch B governance signature:
  `3xpXa28WWDqoH5t7Wa3KQguYvG7mxcQcEdkTDh8WaT7qdeMRfZiHvzSTB1bbwU2P9T3JqwGZnEDHfR21WanJ91Si`
  at finalized slot `487715811`.
- Epoch B settlement passed on the hydrated tree. Its proof pipeline measured
  `302 ms` witness generation, `3,753 ms` proof step, `1,267 ms`
  verification, and `8,882 ms` total pipeline time. The longer test-process
  wall time was post-settlement chain polling rather than proof latency.
- Finalized archival reconstruction processed 107 transactions and recovered
  14 protocol fee notes with `unresolved=0` and no unsettled-slot casualty.
- One recovered fee note from each epoch was spent through ordinary
  VALID_SPEND:
  - epoch A: `evgYKyfVamF5pNrMnjTKk1H2z747kCUMKNtkDQ8sFgYQ4w9JdSBAc9Z2qu2tTpjhfb8weGZXLgjCPmELxXckEFX`
  - epoch B: `4UqYaz7Ckf6yRyex9rEVPKoBancgP3hA1EwyZGSkf4EqPfChCQKx1SiskzaC3kys8RETo2A3FZM7sdE8MFdzyz8U`

The measured proof times remain in the expected prod9 CPU range. This run did
not expose the earlier host-throttling regression.

## 2. Corrections retained by this branch

The hosted rehearsal exposed four operational defects that the branch fixes:

1. CPU/GPU Compose and scheduled-CVM deployment now forward the governed fee
   epoch key, with a repository guard preventing future secret-forwarding
   drift.
2. Signer rotation and tree reset consume the generated vault account-layout
   manifest instead of a stale hard-coded account size; all relevant devnet
   helpers require an explicit private RPC endpoint.
3. CVM deposit setup retries the exact transient expired-blockhash condition
   by rebuilding the transaction.
4. Finalized-history scanning retries bounded transport/429/5xx failures
   without logging the private RPC URL. The two-epoch spend drill ignores
   historically valid fee notes that belong to deliberately reset trees, and
   the settlement harness supports a pre-populated no-reset tree.

## 3. Intentionally deferred work

Resume these items on this branch before claiming Phase 5/6 completion:

1. **PA-01 observer-negative assertion.** Extend the live settle test to show
   that enumerating the legacy public-data fee-inner dictionary cannot recover
   the actual epoch-keyed fee commitment, then run the focused settlement test.
2. **PA-02 observer-negative assertion.** Extend the live merge test to show
   that public input commitments plus the active bitmap derive only the retired
   merge inner/tag, not the actual private-inner-derived descendant, then run
   the focused merge-then-order test from a fresh reset and cold boot.
3. **Settlement crash-recovery drill.** Follow
   [`../settlement-recovery-drill.md`](../settlement-recovery-drill.md)
   exactly: interrupt from the journal-observed in-flight state, cold restart
   from the same history floor, verify reconciliation/unlock, rerun settlement,
   and capture final drain plus journal latency evidence.
4. **Release bookkeeping.** Fold those results into this report, advance
   tracker rows only as far as evidence supports, run the focused tests for the
   remaining harness changes, and perform the final safe drain/CPU-CVM stop.

Independent privacy/circuit review, Phase-2 ceremony, mainnet-without-
`devnet-admin` verification, authority/hash checks, and the post-ceremony CVM
settlement remain Phase 7 external release gates regardless of the deferred
focused work above.
