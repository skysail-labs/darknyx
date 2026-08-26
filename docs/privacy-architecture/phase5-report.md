# Phase 5/6 release-assurance report

**Recorded:** 2026-08-25; completed 2026-08-26

**Status:** Phase 5 local assurance and Phase 6 hosted CVM assurance are
complete. This report does not claim mainnet release closure: independent
privacy/circuit review, the Phase-2 ceremony, and the remaining mainnet gates
in the remediation tracker are still mandatory.

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
- The no-CVM half ran `devnet-deposit-withdraw` with `RUN_DEVNET_DW=1` and
  passed. A subsequent `cvm-settle-e2e` run passed against the digest-pinned
  CVM and covered the settlement half.
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
- A post-run
  `phala cvms get app_9ca3cded105f16923afb0e3f62537882c14db637 --json`
  control-plane readback reported that exact app ID and compose hash;
  its deployed compose file named source tag `tee-v3-hardening-91` and pinned
  the exact
  `sha256:af1a31600f6a5cc9bc0de14df4609cdb73e87906ef7805b482d09360ce123422`
  image. The same readback reported `status=stopped`, `in_progress=false`, and
  `gpus=0`. This evidence comes from the deployed CVM record, not the deploy
  command exit status.
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
- After this checkpoint was pushed, the CPU CVM was placed in drain mode. It
  reported `in_flight_settlements=0` and `safe_to_stop=true`; the Phala control
  plane then confirmed `status=stopped`, `in_progress=false`, and `gpus=0`.

The focused completion pass then restarted the same digest-pinned CPU image
only for the remaining evidence and used a fresh reset plus cold boot for each
leaf-count-sensitive test:

- **PA-01 observer-negative settle:** a real RA-TLS settlement at slot
  `488187637` passed. Tx D signature:
  `gCoKARWXCLCMpj6GaRzeniZP2G71M27dMRCtS2BewLzk1mA7sDrEuTVrfdMLbBqUbyQQEQi896pasarxqH1QDZ7`.
  The test parsed both fee commitments from the finalized settle payload and
  enumerated the retired bounded public-input fee dictionaries. Neither
  dictionary contained the actual epoch-keyed fee commitment. The existing
  wire assertion also confirmed consumed commitments were absent while output
  commitments were present. Timings were: witness `431 ms`, rapidsnark proof
  step `3,399 ms`, full proof `3,880 ms`, verification `4,017 ms`, and total
  settle pipeline `8,673 ms`; no rebroadcast was required.
- **PA-02 observer-negative merge lineage:** merge-then-order passed at slot
  `488190943`. Tx D signature:
  `2UvzsfCRPxqbi4h3XDQ1wHwPniUhkdEtYDYBvsPyHo14pKuke7fJuRLxAejDbNZmj6V4eg92Wbp67KABVfGZbtxv`.
  The test reconstructed the retired merge inner and use tag from only the
  public input commitments and bitmap, then proved the later settle consumed
  the private-inner-derived tag instead. Timings were: witness `468 ms`, proof
  step `3,257 ms`, full proof `3,743 ms`, verification `981 ms`, and total
  pipeline `8,519 ms`; one overdue transaction was rebroadcast.
- **Settlement crash recovery:** all 11 criteria in
  [`../settlement-recovery-drill.md`](../settlement-recovery-drill.md) passed.
  The journal was observed live with `in_flight_settlements=1`,
  `safe_to_stop=false`, and a first durable write of `5,882 us` before the CVM
  was interrupted. The chain, queried independently through private Helius,
  remained at shard leaf counts `2/0/0/0`: deposits landed and settlement did
  not. On restart the non-empty journal classified one entry as
  `release_expired=1`, with `already_settled=0`, `redrive=0`,
  `indeterminate=0`, and `needs_operator=false`; the lock sweeper replayed one
  persisted lock and the entry retired. POST/GET drain returned
  `safe_to_stop=true`, DELETE reopened trading, and the post-recovery settle
  succeeded at slot `488195348` with Tx D signature
  `45QWShwdu1RV5DvqtAWxeuQ1W5MF88wnqCgoSigMxVt2u8ojn183prGiabGdTMyorNW9E2qo9WRjywFsWyjcs1wJ`.
  That settle measured witness `281 ms`, proof step `3,148 ms`, full proof
  `3,459 ms`, verification `1,453 ms`, and total pipeline `8,810 ms`.
  The planned drain recorded two durable writes at `4,788 us` p50 and
  `6,104 us` p95/max. A final cold restart logged
  `settle journal: present and empty, nothing in flight` and hydrated all nine
  leaves across four shards.
- After the completion pass, drain again reported `safe_to_stop=true`, the
  deployed record again reported `gpus=0`, and the Phala control plane
  confirmed the billable CVM was `stopped`.

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
3. CVM deposit and merge setup retry the exact transient expired-blockhash
   condition by rebuilding the transaction; the merge retry was exercised
   after the first PA-02 attempt hit `Blockhash not found`.
4. Finalized-history scanning retries bounded transport/429/5xx failures
   without logging the private RPC URL. The two-epoch spend drill ignores
   historically valid fee notes that belong to deliberately reset trees, and
   the settlement harness supports a pre-populated no-reset tree.

## 3. Remaining external release gates

Independent privacy/circuit review, Phase-2 ceremony, mainnet-without-
`devnet-admin` verification, authority/hash checks, and the post-ceremony CVM
settlement remain Phase 7 external release gates. Mainnet must initialize a
distinct `operations_admin`
instead of reusing the deployer or cold root/upgrade authority, and rehearse
both the 3-of-5 operations quorum and 4-of-7 cold quorum with every signer
independently verifying the TEE attestation. Per-MM execution-quality
statistics must also be published and monitored so repeated selection of a
colluding market maker is observable rather than hidden inside enclave policy.
No real-value deposit is permitted while any mandatory gate remains open.
