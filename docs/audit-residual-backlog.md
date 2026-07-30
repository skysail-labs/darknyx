# Darknyx residual audit and release backlog

**As of:** 2026-07-31

**Validated against:** `main` @ `d69248b` (PR #90 merged)

This is the canonical entry point for work that remains after the Darknyx
security, protocol, TEE, infrastructure, daemon, and performance reviews. It
does not replace the evidence-rich source trackers: those remain the closure
ledgers for their finding families. This document answers the narrower
question: **what still needs action, what is deliberately waiting on a trigger,
and what has been accepted and must not be reopened without new evidence?**

When this index and an older audit's original status disagree, use the newest
validated tracker for that finding family and then this index. An `Open` label
in an original point-in-time report is not proof that the issue still exists.

## Sources reconciled

This pass reconciled the tracked July 14 cryptography/systems review and
independent validation, the July 18 unique-finding pass, the July 20
full-protocol deep dive, both July 25 reviews, both July 25 remediation
trackers, and the central security tracker. It also swept the throughput, GPU,
multi-market, and public-API roadmaps so conditional engineering was not
mistaken for an unresolved vulnerability.

Historical reports remain immutable point-in-time evidence. Their superseding
ledgers are:

- [`security-remediation-tracker.md`](security-remediation-tracker.md) for
  `CS-`, `P-`, `N-`, and `U-` findings;
- [`audit-2026-07-25-remediation-tracker.md`](audit-2026-07-25-remediation-tracker.md)
  for `S-`, `PF-01…PF-07`, and `AU-` findings;
- [`audit-2026-07-25-tee-infra-daemon-remediation-tracker.md`](audit-2026-07-25-tee-infra-daemon-remediation-tracker.md)
  for `T-`, `PF-08…PF-10`, and related release deliverables;
- this document for the formerly orphaned `A-3` and `D-01…D-09`
  dispositions and for the cross-tracker residual view.

Shelved product features such as mass quote, peg orders, and post-only are not
audit findings and are intentionally left in
[`api-surface-roadmap.md`](api-surface-roadmap.md), not mixed into this
security backlog.

## Status meanings

- **Open:** actionable now; the required invariant or evidence is missing.
- **External gate:** supporting repository work may be ready, but independent
  people, governance, ceremony, or deployment evidence is still required.
- **Measurement-gated:** the mechanism is real, but changing production without
  the named measurement would be speculative.
- **Deferred:** intentionally waits for a concrete platform or product trigger.
- **Accepted risk / Won't Fix:** no work is authorized under the present threat
  model. Reopen only if the recorded assumption changes or new evidence changes
  the risk.
- **Closed / Refuted:** retained here only when an old report would otherwise
  send a future agent toward obsolete work.

## Executive answer

No unresolved Critical or High **code-remediation** finding remains in the
review families consolidated here. Four mainnet/external-use gates remain:
the independent circuit audit, public Phase-2 ceremony, split-governance
rehearsal, and T-03 session-bound transport decision/implementation.

The two directly actionable code-hardening gaps are **D-04**, which should
pause trading when the deployed vault program is upgraded underneath a running
CVM, and the older **A-3**, which still lacks a generated or cross-crate guard
for hand-mirrored on-chain account layouts. **D-02** and **D-03** remain real
liveness/capacity questions, but their next correct step is instrumentation and
representative measurement, not an immediate TTL or account-layout change.

Everything else below is either conditional performance work, a future
multi-cluster/GPU decision, or an explicitly accepted risk.

## Release and external-use gates

| ID             | Owner                            | Required outcome                                                                                                                                                                                                                                                                            | Status / trigger                                                                                                                                             | Closure evidence                                                                                                                                                                                                                                                  |
| -------------- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| F-04 / C-07    | ZK + independent auditor         | Independent review of the final circuit source and artifacts has no unresolved Critical/High finding. Freeze the source only after all code remediation is complete.                                                                                                                        | **External gate — Open**                                                                                                                                     | Published report, exact source/artifact hashes, findings dispositions, and auditor sign-off.                                                                                                                                                                      |
| N-18           | ZK + governance                  | Run a public Phase-2 ceremony for every production Groth16 zkey with at least five independent contributors, transcript and artifact hashes, final random beacon, reproducible verification, auditor artifact sign-off, and a post-ceremony CVM settlement.                                 | **External gate — Open**                                                                                                                                     | Ceremony transcript, contributor evidence, beacon, `snarkjs zkey verify`, regenerated VKs, auditor sign-off, and live settle evidence.                                                                                                                            |
| N-19           | Governance + operations          | Rehearse split Squads control: cold 4-of-7 owns upgrade/root authority; operations 3-of-5 is `VaultConfig.admin`; every TEE-key rotation is independently attestation-verified.                                                                                                             | **External gate — In progress**                                                                                                                              | Rehearsal transaction set, authority/account inspection, attestation records, recovery/rotation drill, and signer runbook.                                                                                                                                        |
| T-03           | TEE + SDK + infrastructure       | Bind the verified enclave identity to the client transport session and govern every component that can terminate or forward the connection. The original “plaintext operator gateway” premise was disproved; the residual is unpinned gateway measurement plus no quote-to-session binding. | **Deferred mainnet/external-user gate.** Re-enter before issuing access outside the operating team, accepting real value, or committing to a browser client. | One of the two costed designs in the TEE tracker: in-enclave RA-TLS for programmatic clients, or attested ingress with governed DNS/certificate handling for browsers; latency/RSS measurements, client negative tests, image pin, attestation, and CVM ceremony. |
| Release bundle | Release engineering + governance | Build without `devnet-admin`; prove destructive instructions absent; independently verify deployed program hash and all authorities; attach recovery drill, transaction-size/CU headroom, dependency audit, and final CVM evidence.                                                         | **External gate — Open until the production candidate exists.**                                                                                              | Reproducible production build and hashes, deployed-program inspection, authority inventory, closed trackers, recovery evidence, and signed release checklist.                                                                                                     |

Source: [`security-remediation-tracker.md`](security-remediation-tracker.md)
and
[`audit-2026-07-25-tee-infra-daemon-remediation-tracker.md`](audit-2026-07-25-tee-infra-daemon-remediation-tracker.md).

## Actionable and measurement-gated residual findings

| ID   | Severity | Owner                             | Current invariant / next implementation                                                                                                                                                                                                                                                                                                                 | Status and closure evidence                                                                                                                                                                                                                                                                                        |
| ---- | -------- | --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| D-04 | Medium   | TEE + operations                  | At boot, record the finalized upgradeable-loader `ProgramData` identity and last-upgrade slot for the configured vault program. Monitor it alongside `VaultConfig`/`MarketConfig`; any change pauses new place/modify/matching while cancel, reconciliation, and safe recovery remain available. Resume only after a compatible, attested CVM redeploy. | **Open — actionable now.** Unit/RPC fixture tests for unchanged, upgraded, missing, and malformed ProgramData; boot fail-closed test; pause/resume policy docs; real CVM spot-check because the boot/governance path changes.                                                                                      |
| A-3  | Low      | Vault + TEE + SDK build assurance | Generate one account-layout fixture from the actual vault structs, or compile a shared cross-crate layout assertion, so TEE/SDK offsets and account lengths cannot agree with their own literals while disagreeing with `VaultConfig`/`MerkleTree`. Keep strict length/discriminator rejection.                                                         | **Open — actionable hardening.** A mutation that inserts/reorders a field must fail the cross-language gate. Cover every hand-parsed field used for governance, sharding, fee/protocol-owner binding, and Merkle root/leaf count. No wire or account migration is required unless the test exposes existing drift. |
| D-02 | Medium   | TEE settlement + operations       | Export the remaining marker runway at first Tx D and at every retry/terminal outcome. Alert before the conservative local deadline. Do not raise the current local `+250`-slot margin or split pages until degraded-RPC data shows expiry pressure.                                                                                                     | **Measurement-gated.** Close after a sustained settlement run records runway p50/p95/p99/min, expiry-related failures, retry age, RPC 429/5xx, and ambiguous outcomes; tune only if the evidence breaches the settlement SLO.                                                                                      |
| D-03 | Medium   | Vault + SDK + TEE capacity        | Measure roots produced per shard under representative deposit/settle traffic against the 64-root on-chain ring and representative browser/mobile proving latency. Choose among a larger ring/account migration, bounded auto-reprove, or documented admission limits only after calculating the measured expiry budget.                                 | **Measurement-gated.** Close when the slow-client proving SLO retains a documented safety margin at admitted per-shard load, with a stale-root recovery test. Any ring-size change requires account-layout migration, SBF/devnet/CVM evidence, and a clean rollout.                                                |

The code anchors are
`crates/darknyx-tee/src/main.rs::spawn_governance_monitor`,
`crates/darknyx-tee/src/settle/worker.rs`'s conservative marker deadline, and
`programs/vault/src/state.rs::ROOT_HISTORY_SIZE`. A-3 originates in
[`audit_2/READINESS.md`](../audit_2/READINESS.md); its current anchors are
`crates/darknyx-tee/src/solana_rpc/vault_config.rs`,
`crates/darknyx-tee/src/merkle/sync.rs`, and
`packages/sdk/src/tee/vault-config.ts`.

## Deferred and conditional engineering backlog

These items are not current vulnerabilities. Pull one into an implementation
slice only when its trigger is demonstrably true.

| ID / source             | Owner                       | Deferred work                                                                                                                 | Re-entry condition and required decision                                                                                                                                                                                                                           |
| ----------------------- | --------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| PF-03                   | Vault + TEE + SDK           | Narrow the 128-byte recovery field by eight bytes.                                                                            | Only with the next change that already bumps `MatchResultPayload`, its canonical signature domain, and Rust/TS/on-chain vectors. Do not spend a standalone three-language migration for 8 bytes.                                                                   |
| PF-07                   | Vault + settlement          | Lower the static settle CU request from 115,000 toward measured use.                                                          | Tree sharding has landed, so the old trigger is obsolete. Re-enter only when per-shard block-CU pressure or real settle-bound volume makes packing material; remeasure the worst case and keep at least 20% CU margin before changing the limit.                   |
| PF-08                   | Daemon custody              | Avoid repeated trading-key derivation.                                                                                        | Only if a daemon/intake profile identifies derivation as material. Then derive once per unlocked keystore session; do not add an unbounded cache or extend key lifetime beyond that session.                                                                       |
| THR-01 / roadmap item 1 | TEE settlement              | Raise batch concurrency above one.                                                                                            | Same-box ICICLE-CUDA C1/C2/C4 must increase confirmed-match throughput without breaching queue/latency/error thresholds. CPU C2 was 3.3% slower than C1, so CPU remains at one and needs no C4 run.                                                                |
| THR-02 / item 2         | TEE settlement              | Add per-worker/per-shard ALT pools.                                                                                           | Only if GPU measurements show `alt_wait_ms`/Tx-C serialization is a material bottleneck. Prefer deleting ALTs when transaction v1 becomes available.                                                                                                               |
| THR-03 / item 3         | TEE settlement              | Relax sequential Tx D confirmation dependencies.                                                                              | Prefer Alpenglow. A manual dependency tracker is justified only if pre-Alpenglow production data shows this latency dominates enough to pay for the added recovery complexity.                                                                                     |
| THR-04 / item 4         | Matcher + scheduler         | Coalesce a trailing partial batch for a bounded wait.                                                                         | Sustained real volume must show a settle queue dominated by underfilled pages. Preserve the one-snapshot, one-fill-per-order, and continuation-ordering invariants.                                                                                                |
| THR-05 / item 6         | ZK + vault + browser SDK    | Compress VALID_INPUT public inputs.                                                                                           | Representative browser/device measurements must justify adding approximately 5.38% combined client proving time in exchange for 9,709 CU per lock, and block packing must be an observed constraint.                                                               |
| THR-06 / item 7         | TEE + SDK                   | Move Tx D to transaction v1 and delete ALT creation/pooling/warmup.                                                           | SIMD-0296/0385 must be active and supported by Solana client crates plus the production RPC. Land as a deletion/cutover, not a speculative dual path.                                                                                                              |
| UX-PROVE                | SDK/product                 | Address approximately 40-second browser VALID_INPUT proving.                                                                  | Decide between in-browser proving, delegated proving with an explicitly changed trust/privacy model, or a faster proof system after representative browser measurements. This is a product/architecture decision, not a settlement-CU tweak.                       |
| GPU-PERF                | TEE prover + performance    | Obtain a valid GPU speed/throughput number.                                                                                   | On the next H100/H200 window, run same-box rapidsnark CPU, ICICLE CPU, and ICICLE-CUDA C1/C2/C4; exclude warmup, use at least eight measured batches, and capture cgroup/GPU/host/RPC identity.                                                                    |
| GPU-TRUST               | TEE + SDK security          | Verify confidential-compute mode and bind NVIDIA evidence to the same nonce as the TDX quote; remove diagnostic `user: root`. | Required only if GPU proving is selected for production, but then it is a hard privacy gate because the GPU receives private witness data. Add `video`/`render` access, drop root, and implement dual TDX/NVIDIA verification before real order intent.            |
| MM-CAPACITY             | TEE + operations            | Determine the safe number of active markets per CVM.                                                                          | Add one market at a time and run the sustained 15-minute admission matrix in the multi-market architecture. Stop when its throughput, queue, latency, CPU/memory, RPC/error, or 20% headroom threshold is breached.                                                |
| MM-DISCOVERY            | Vault + daemon + governance | Support more than one independently attested CVM cluster.                                                                     | First change the on-chain one-cluster signer model. Then finalize a registry generation and content hash on chain and verify a signed, content-addressed venue manifest in the daemon. Do not use a mutable website list or cross-copy endpoint tables among CVMs. |

Detailed methods and thresholds live in
[`throughput-roadmap.md`](throughput-roadmap.md),
[`gpu-tee-runbook.md`](gpu-tee-runbook.md), and
[`multi-market-architecture.md`](multi-market-architecture.md).

## Accepted risks and deliberate non-work

| ID / assumption      | Disposition                                                                                                                                                                                                                                                        | Re-entry condition                                                                                                                                              |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| T-05                 | **Won't Fix.** Confirmed-commitment mirror rollback is accepted as an availability risk, not a custody-authority path. The owner explicitly declined further work.                                                                                                 | Reopen only if the commitment model or accepted Solana finality assumption changes. Do not fold unrelated mirror features into T-05.                            |
| U-07                 | **Won't Fix.** Full Ed25519 instruction scanning is intentional and bounded by the TEE-built transaction's instruction count.                                                                                                                                      | New evidence of material CU/transaction pressure or a correctness-safe bounded alternative.                                                                     |
| PF-06                | **Won't Fix.** `OrderOpening` cloning measured about 0.9 microseconds per N=16 batch.                                                                                                                                                                              | A new profile contradicts the existing measurement by making it material.                                                                                       |
| D-09                 | **Accepted.** Permissionless expired-lock cleanup may award rent to the cleaner; this enables the shipped TEE lock sweeper and does not move note value.                                                                                                           | Governance chooses a different rent-beneficiary policy.                                                                                                         |
| S-02(C)              | **Declined after recovery revalidation.** A failed commitment reservation remains terminal until its recorded lock expiry; immediate release or auto-rebook could race an ambiguous on-chain lock/settle. The daemon may submit a fresh signed order after expiry. | A new chain primitive makes landed-lock attribution and atomic safe reuse possible, or measured lock-failure UX justifies a separately audited recovery design. |
| Price/limit fairness | **Accepted trust boundary.** Asset identity, scaled arithmetic, conservation, fees, and recoverability are circuit-enforced; matching fairness and oracle-policy execution remain TEE-trusted.                                                                     | Threat model changes to require trustless price/limit fairness.                                                                                                 |
| On-chain DCAP        | **Deferred trust-model choice.** Strict client attestation plus multisig-gated key rotation is the accepted model; on-chain quote verification is not currently required.                                                                                          | Client verification or governance rotation can no longer meet the launch trust model, or a practical on-chain verifier becomes an explicit product requirement. |
| S-08(B), S-11(B)     | **Declined.** Do not bind each order into VALID_INPUT or add in-circuit merge ordering solely for already-documented Low/unreachable cases. Existing client proving and the on-chain distinct-input check are the chosen tradeoffs.                                | Circuit opens for a related redesign and the incremental cost can be measured.                                                                                  |

## July-20 deep-dive disposition backfill

This closes the aggregate “D-01…D-09 untriaged” row left in the July-25 tracker.

| ID   | Final disposition        | Evidence / successor                                                                                                                                                                                                                                                                |
| ---- | ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| D-01 | **Closed / superseded.** | N-02 finality-gated outcomes, expiry-aware withdraw/merge and `release_lock`, the lock sweeper, durable settlement journaling/reconciliation, and daemon fresh-order recovery now cover the failure. Definitive failures remain terminal and are intentionally never auto-rebooked. |
| D-02 | **Measurement-gated.**   | Conservative deadline and ambiguous redrive exist; marker-runway telemetry/evidence remains as specified above.                                                                                                                                                                     |
| D-03 | **Measurement-gated.**   | The on-chain ring remains 64; the mirror correctly keeps a permissive 512 entries because it observes flattened leaves. Capacity/browser evidence remains as specified above.                                                                                                       |
| D-04 | **Open.**                | The finalized governance monitor still rereads configuration but does not pin/monitor the vault ProgramData upgrade slot.                                                                                                                                                           |
| D-05 | **Closed / superseded.** | T-01 and RD-01 shipped explicit versioned legacy/upgraded Pyth trust profiles, authenticated Hermes access, and fail-closed refresh. A future signer-profile rotation is an ordinary governed image/profile release.                                                                |
| D-06 | **Refuted.**             | Circom public inputs are already BN254 field elements; the on-chain verifier rejects non-canonical public-input bytes and SDK encoding enforces `< BN254_R`. `Num2Bits(254)` would not prove `< r` and is neither sufficient nor necessary.                                         |
| D-07 | **Closed.**              | AU-04 made revoked JTIs durable in the versioned auth snapshot and prunes them consistently across restart.                                                                                                                                                                         |
| D-08 | **Closed / superseded.** | T-17 exposes venue status plus per-instrument dynamic `trading_enabled`; market-local oracle degradation no longer forces clients to infer readiness from a blanket 503.                                                                                                            |
| D-09 | **Accepted risk.**       | Permissionless expiry cleanup is intentional, documented, and used by the lock sweeper; no custody loss results.                                                                                                                                                                    |

## Recommended execution order

1. Implement **D-04** and **A-3** as focused, independent hardening slices.
   A-3 is cheap and needs no CVM unless it exposes real drift; D-04 changes the
   boot/governance path and does.
2. Add **D-02** runway metrics and collect **D-03** root-production plus
   browser-proving evidence during the next representative capacity run.
3. Make the **T-03** client/transport product decision before any external
   account or real-value launch.
4. Complete the external circuit audit, freeze artifacts, run **N-18**, then
   rehearse **N-19** and the production release bundle.
5. Pull GPU, transaction-v1, higher concurrency, and cross-CVM work only when
   their gates lift. Their runbooks are already concrete enough for a new agent
   to resume without re-deriving the architecture.

## Continuation directive for agents

Before starting a residual item:

1. read this row and its linked source document;
2. revalidate the failure mode against current `main`;
3. move only that row to `In progress` and record the branch/PR in the source
   tracker if it has one;
4. preserve the stated compatibility boundary and cost measurement;
5. attach exact local, hosted, devnet, and CVM evidence required by the row;
6. move a row only as far as the evidence supports;
7. update this index and the owning source tracker in the same closing PR.

Do not reopen an accepted-risk row, implement a measurement-gated change before
measuring it, or use an original audit's stale status without checking its
newer tracker.
