<!-- audit-record -->
> **Audit:** Closure tracker
> **Date:** 2026-08-07 → ongoing
> **Engagement:** `audits/audit_7/`
> **ID prefix:** `SW-`, `PF-12…PF-27`
> **Cross-audit status:** see [`../residual-backlog.md`](../residual-backlog.md), the canonical index of open work.

---

# Darknyx unaudited-surface remediation tracker

This is the canonical closure ledger for
[`unaudited-surface-sweep.md`](unaudited-surface-sweep.md). It owns
`SW-01…SW-34` and `PF-12…PF-27`. The companion
[`client-attestation-review.md`](client-attestation-review.md) is tracked by the
`CA-` rows in [`../residual-backlog.md`](../residual-backlog.md); this document
does not duplicate that ownership.

A finding is not closed by code alone. The closing PR must identify the
invariant restored, compatibility impact, exact tests, measured cost, live
evidence where required, and rollback instructions.

Status values are `Open`, `In progress`, `Code complete`, `Closed`, `Deferred`,
and `Won't Fix`. `Closed` requires merged code and every item of evidence named
in the row. `Code complete` means the merged/local implementation still owes
live or external evidence. `Deferred` requires both a reason and a concrete
re-entry condition.

## Continuation directive for agents

An agent continuing this remediation must:

1. Read `AGENTS.md`, the sweep, this tracker, `audits/residual-backlog.md`, and
   the architecture document for the subsystem being changed.
2. Re-fetch latest `main`, verify the current-execution table below, and take
   the earliest `Open` slice whose prerequisites are satisfied.
3. Preserve unrelated dirty/untracked files, including modified third-party
   submodules and locally generated circuit verification JSON files.
4. Use a `remediation/<topic>` branch. Update this tracker and the residual
   backlog in the same PR as code. Commit with `git commit -s`; add no model,
   agent, or AI trailers.
5. Revalidate the finding against current code before editing. A historical
   audit row is evidence, not present-tense status.
6. Run the affected local CI gates before pushing. GitHub Actions and
   CodeRabbit are available; inspect both before merge.
7. Use a billable CVM only where the slice says it is required. Stop a CPU CVM
   when evidence is complete. Never stop a prepaid on-demand GPU CVM.
8. Move a row only as far as its evidence permits. In particular, SW-32 stays
   `Code complete` until the next confidential-GPU window exercises the guard;
   do not treat the separate `GPU-TRUST` dual-attestation gate as part of this
   finding.
9. Do not reopen SW-18 or SW-34 without their recorded re-entry conditions.
10. Leave a handoff using the template at the end before switching agents.

## Current execution state

| Field | Current value |
|---|---|
| Last verified `main` | `9b2c37dd8c65ac3bd16e1d43ac9da444cb9970ee` (2026-08-07): every SW/PF claim re-anchored against current source; prior remediation commits and residual-backlog evidence inspected. |
| Last merged remediation PR | PR #107, PF-27 RPC batching, merge commit `71e537d` (subsequent PRs did not reopen its boundary). |
| Active slice | Slice 1 — TEE settle/API efficiency (`PF-12…PF-17`), code and live validation complete; merge owed. |
| Active branch / PR | `remediation/audit7-residuals` / PR #115; validation image source `64f01e7`. |
| Next slice | Slice 2 — daemon durability/data access (`SW-10`, `PF-18…PF-23`), then slice 3 (`PF-24…PF-26`). |
| Live state | CPU CVM `nightly-test-cvm` was drained and confirmed **stopped** after the 2026-08-07 validation. No live environment is assumed for the next slice. |
| Hosted state | CodeRabbit completed with no inline findings. The circuit build itself passed, but GitHub rejected its artifact upload because the organization storage quota was exhausted; dependent jobs were therefore skipped. Local artifact-required tests remain the applicable code evidence until hosted storage is restored. |
| Last updated | 2026-08-07 — slice 1 locally and live validated in PR #115; merge is the only remaining closure condition. |

## Revalidation disposition

### Security, correctness, and hygiene findings

| ID | Severity | Owner | Invariant / required evidence | Revalidated disposition |
|---|---|---|---|---|
| SW-01 | High | TEE RPC + API | RPC URLs are allowlist-redacted at source; public failure fields are closed enums. Redaction and transport-error regressions cover query/path/userinfo secrets. | **Closed** — merged `b6797a0`; current types retain the structural boundary and the credential was rotated. |
| SW-02 | Medium | TEE API | Public expensive routes have a venue-wide weighted limit and bounded/cached upstream work; 404s do not consume the bucket. | **Closed** — merged `82772d1`; current router and adversarial tests retain the bound. |
| SW-03 | Medium | TEE settlement | Redrive has an absolute wall-clock deadline independent of successful RPC responses; terminal jobs always receive an outcome. | **Closed** — merged `82772d1`; deadline/429 regressions survive on current source. |
| SW-04 | Low | TEE API | Recent-order routing eviction is insertion ordered and bounded. | **Closed** — merged `d9048f6`; mutation-backed FIFO test retained. |
| SW-05 | Low | TEE API | Raw reserve reads validate account owner and Anchor discriminator and fail stale. | **Closed** — merged `d9048f6`; current transparency parser retains checks. |
| SW-06 | Info | TEE API/docs | Reserves expose per-shard roots/counts and unambiguous aggregate naming; OpenAPI matches. | **Closed** — merged `d9048f6` + `04846b6`. |
| SW-07 | Critical | TEE Merkle sync + SDK | Only vault-scoped events/instructions can mutate mirrors; divergence fails closed for reads and trading. Requires live healthy-mirror evidence. | **Closed** — PR #97, merge `679ffb0`, digest-pinned CPU-CVM root parity and API evidence recorded in the residual backlog. |
| SW-08 | Medium | TEE settlement | Terminal scheduler jobs and retained sensitive match state are deterministically bounded; active/ambiguous jobs are not evicted. | **Closed** — merged `d9048f6` + review follow-up `04846b6`. |
| SW-09 | Info | Matcher + TEE | Pure matcher emits an explicit zero sentinel, never a retired change-note commitment; failure cannot publish an inconsistent memo. | **Closed** — merged `54204fe`; current matcher no longer calls the retired derivation and commit-time derivation fails before memo publication. |
| SW-10 | Low | Daemon | Loss of the rebuildable SQLite cache must not restart an already-used deterministic order-id/trading-key sequence at zero. | **Open** — still valid. `start()` sets `nextIndex = maxSeedIndex()+1`; an empty replacement DB returns `-1`, while order intent has no on-chain counter. This row had disappeared from the residual table and is restored by this tracker. |
| SW-11 | Medium | Daemon recovery | Startup and every stream gap reconcile order state and seed-plus-chain note recovery; failure is surfaced/latching rather than dropped. | **Closed** — PR #101 (`79bbefd`, follow-ups `09f3b95`/`23abaef`). |
| SW-12 | Low | Daemon merge | Auto-merge admits only notes with no potentially live order lock. | **Closed** — merged `6420f54`; terminal-phase allowlist remains fail closed. |
| SW-13 | Low | Daemon accounting | Per-order pending-change count is derived from store truth, never decremented by an account-wide merge delta. | **Closed** — merged `6420f54`. |
| SW-14 | Medium | TEE prover/deploy | Native witness scratch lives in guest RAM (`tmpfs`/`/dev/shm`); production compose refuses disk fallback; a real settle proves the mounted path works. | **Closed** — merged `72c918b` + `c5518d5`; subsequent digest-pinned CPU image 83 completed real settlement on current proving flow. |
| SW-15 | Info | TEE prover | Backend proof coordinates are canonical field elements, on-curve, and subgroup-correct before submission. | **Closed** — merged `72c918b`; malformed-coordinate tests retained. |
| SW-16 | Low | Daemon custody | Keystore load rejects loose modes, passphrases have a floor, and docs state the process boundary accurately. | **Closed** — merged `6420f54`. |
| SW-17 | Low | Daemon attestation | Untrusted gateway reads have timeout, byte cap, and typed field validation. | **Closed** — merged `6420f54`. |
| SW-18 | Info | Attestation/docs | Readers are told `boot_session_id` is not quote-bound and that a wrong value causes rejection, not stale-session acceptance. | **Deferred/documented** — merged `a50f6f6`. Re-enter only if the 64-byte report-data commitment is redesigned or transport/session binding work creates room for it. |
| SW-19 | Medium | Daemon control API | Control authentication is secure by default and browser origins cannot drive state-changing routes. | **Closed** — merged `f030289`. |
| SW-20 | Low | Daemon control API | Bodies and errors are bounded/sanitised, token compare is constant-time, path data encoded. | **Closed** — merged `f030289`. |
| SW-21 | Medium | TEE intake | `tree_id` is range-checked before mirror access; accessor has no shard-0 fallback. | **Closed** — merged `d9048f6`. |
| SW-22 | Low | SDK custody | New backups use scrypt N=2^17; reads accept only explicit legacy/current profiles. | **Closed** — merged `54204fe`, hardened by `e5beb38`. |
| SW-23 | Info | SDK/Rust crypto | Field-element inputs reject out-of-range values consistently; raw byte-domain hashes retain their intentional reduction semantics. | **Closed** — merged `54204fe`, hardened by `e5beb38`. |
| SW-24 | Low | SDK chain decoding | Client event parsing attributes logs to the vault program with nested-CPI correctness. | **Closed** — shipped with SW-07 in `679ffb0`. |
| SW-25 | Info | SDK | Deleted matching-engine PDA seeds remain absent. | **Closed** — merged `54204fe`. |
| SW-26 | Low | SDK prover | Deposit, merge, and withdraw all compare prover signals with locally expected vectors before L1 submission. | **Closed** — merged `54204fe`, with negative regression in `e5beb38`. |
| SW-27 | Low | Loadgen | Accepted and rejected submission latencies are measured and reported separately. | **Closed** — merged `72c918b`; current report keeps separate histograms. |
| SW-28 | Low | Matcher | Chaining stops on zero collateral and production documentation names `PreparedMatchTick::next_page`, not `run_batch`. | **Closed** — merged `54204fe`, strengthened by `e5beb38`. |
| SW-29 | Medium | TEE stream | Session order ownership is pruned at terminal transitions; disconnect cancellation batches under one matcher lock. | **Closed** — merged `d9048f6`. |
| SW-30 | Info | Docs | Lockstep duplication and current persistence/entry-point states are described accurately. | **Closed** — merged `a50f6f6`; later note-use v11 docs preserve the four-way lockstep warning. |
| SW-31 | Medium | TEE stream | Upstream router lag advances a resync epoch and every active client is forced to resynchronise. | **Closed** — merged `d9048f6`, closure regression in `04846b6`. |
| SW-32 | Medium | GPU prover | CUDA boot requires positive confidential-compute evidence and refuses absent/malformed/off evidence. | **Code complete** — merged `72c918b` + `c5518d5`. Close in the next confidential-GPU window by proving OFF/unavailable refusal and ON acceptance on the digest-pinned image. Full NVIDIA evidence-to-TDX nonce binding remains the separate `GPU-TRUST` production gate. |
| SW-33 | Info | Build/CI | Debug endpoints remain impossible in production dependency resolution and a gate fails on any of the four required legs. | **Closed** — merged `54204fe`, hardened by `e5beb38`; gate is in local and hosted CI. |
| SW-34 | Info | Performance tooling | Do not represent the test-only report generator as production telemetry. | **Deferred** — verified still test-only. Re-enter when a production `BatchMetric` source exists; then wire the generator, or delete it if the throughput reporting design supersedes it. |

### Performance findings

| ID | Severity | Owner | Planned slice | Invariant / required evidence | Status |
|---|---|---|---|---|---|
| PF-12 | Perf | TEE journal | Slice 1 | Each batch transition performs one durable snapshot, not one per match; on-disk v2 format and write-ahead ordering stay unchanged. Unit test counts flushes; recovery drill records write p50/p95 after the reduction. | **Code complete; live complete** — N=16 unit fixture records one durable write. Digest-pinned CPU settle reported two lifecycle writes, `p50=3,665 µs`, `p95=max=4,929 µs`; the recovery/drain drill passed all 11 assertions. Close when PR #115 merges. |
| PF-13 | Perf-Nit | TEE settlement | Slice 1 | ALT activation waits before first poll and uses bounded backoff, reducing normal/degraded RPC calls without weakening the activation check. | **Code complete; live complete** — first guaranteed-useless poll removed; 12 s ceiling retained. Real settle passed with `alt_tx_ms=1,331`, `alt_wait_ms=683`. Close when PR #115 merges. |
| PF-14 | Perf-Nit | TEE API | Slice 1 | A transparency cache miss performs independent reserve reads concurrently while preserving owner/discriminator checks and stable response ordering. | **Code complete; evidence complete** — concurrent futures preserve mint order; full HTTP suite passed and the digest-pinned API boot remained healthy. Close when PR #115 merges. |
| PF-15 | Perf-Nit | TEE prover | Slice 1 | `spawn_blocking` shares immutable N=16 witnesses rather than deep-cloning them. | **Code complete; live complete** — immutable `Arc<[MatchSlotWitness]>` crossed the blocking boundary in a real N=16 proof: native witness 239 ms, rapidsnark step 2,762 ms. Close when PR #115 merges. |
| PF-16 | Perf-Nit | TEE scheduler | Slice 1 | Final outcomes for one batch are applied under one scheduler write lock without changing per-match results. | **Code complete; live complete** — grouped outcome updates retained one confirmed result and finality-gated book semantics in the real settle. Close when PR #115 merges. |
| PF-17 | Perf-Nit | TEE oracle | Slice 1 | Config-time feed-id bytes/map are decoded once, not on every refresh; duplicate/missing feed behavior is unchanged. | **Code complete; live complete** — prepared lookup built once at task startup; multiple cold boots authenticated the router-quorum feed and resumed `SOL-USDC`; invalid-config regressions remain green. Close when PR #115 merges. |
| PF-18 | Perf-Nit | Daemon store | Slice 2 | Rebuildable cache tables use documented WAL/NORMAL durability only after SW-10's non-rebuildable sequence state has a separate durable root. | **Open** — valid and previously missing as an individual backlog row. |
| PF-19 | Perf-Nit | Daemon store | Slice 2 | Hot SQL statements are prepared once per store lifetime and finalized with the DB. | **Open** — valid and previously missing as an individual backlog row. |
| PF-20 | Perf | Daemon tracker | Slice 2 | Pending leaf lookup is SQL-filtered, bounded-concurrent, and retry/backoff bounded; successful resolution remains immediate. | **Open** |
| PF-21 | Perf-Nit | Daemon placement | Slice 2 | Collateral selection avoids repeated whole-table/order scans while preserving exact best-fit and lock exclusion. | **Open** |
| PF-22 | Perf-Nit | Daemon merge | Slice 2 | Merge selection does not issue one order query per candidate note. | **Open** |
| PF-23 | Perf-Nit | Daemon crypto | Slice 2 | One operation derives one Ed25519 keypair; no unbounded expanded-secret cache is introduced. | **Open** |
| PF-24 | Perf-Nit | Daemon control API | Slice 3 | A stalled SSE client cannot cause unbounded buffering; it is disconnected with an explicit resync contract. | **Open** |
| PF-25 | Perf-Nit | SDK crypto | Slice 3 | `bytepad` allocates once and remains byte-identical to all KATs/Rust parity. | **Open** |
| PF-26 | Perf | Daemon Merkle | Slice 3 | One immutable tree build serves root plus every witness; a hash-count regression proves O(n), not O(k×n), work for K inputs. | **Open** |
| PF-27 | Perf | TEE recovery | Prior slice | Lock sweep and boot recovery use positional batched account/status reads with fail-closed length checks. | **Closed** — PR #107, commit `67bb473`, request-count regression proves constant-round-trip behavior. |

## Remediation slices

### Slice 1 — TEE settle/API efficiency (`PF-12…PF-17`)

- No wire, circuit, account-layout, or on-disk journal-format change.
- Local evidence: format/clippy; artifact-required TEE tests; focused journal,
  worker, transparency, and oracle regressions.
- Live evidence: because the journal/settle pipeline changes, run the standard
  CPU-CVM recovery/drain drill and one real settle on a digest-pinned image.
  Record journal flush count and `journal_write_us` p50/p95 plus witness/prove,
  ALT, settle, and total timings. Completed evidence is recorded below.
- Rollback: revert the slice and redeploy the prior digest. Journal v2 stays
  readable because the format does not change.

### Slice 2 — daemon durability and hot data access (`SW-10`, `PF-18…PF-23`)

- First restore a durable order-sequence root without making the SQLite cache
  authoritative for seed custody. Do not weaken SQLite sync until that holds.
- Preserve deterministic order-id recovery and exact collateral best-fit/FIFO
  behavior. Any storage migration needs legacy fixtures and crash/reopen tests.
- Local evidence: daemon tests/typecheck plus SDK order-id/recovery tests and
  query/derivation-count assertions. No CVM is required unless the final design
  changes the signed order body or gateway wire (it should not).

### Slice 3 — bounded client work (`PF-24…PF-26`)

- Disconnect slow SSE consumers rather than retaining private event history in
  a server-side queue.
- Keep `darknyxShakeKdfV1` bytes unchanged and verify KAT/parity.
- Build local Merkle levels once and expose a test-only hash counter mirroring
  Rust `BatchMerklePaths` evidence. No CVM required.

### Conditional closure — GPU guard (`SW-32`)

- Next confidential-GPU window: same digest, three boot legs (CC ON succeeds,
  CC OFF refuses, probe unavailable/malformed refuses), then a CUDA proof.
- Do not stop the prepaid GPU CVM between legs. This closes SW-32 only; the
  separate `GPU-TRUST` nonce-bound NVIDIA attestation gate remains open before
  production GPU proving.

## Slice 1 implementation evidence — 2026-08-07

| Evidence | Result |
|---|---|
| Journal durability and cost shape | `record_many` makes an N=16 transition one atomic snapshot. `batch_transition_is_one_durable_write` asserts 16 recovered entries and `write_stats.count == 1`; `forget_many` is durable and best-effort-safe. On-disk `JOURNAL_VERSION` and schema are unchanged. |
| Write-ahead ordering | Signatures are collected from already-signed Tx D bytes, persisted in one batch snapshot, and only entries returned durable are sent. A missing entry/signature or failed snapshot still suppresses the corresponding send. Terminal retirement is safe to delay: a crash before the final flush causes boot recovery to re-examine an already-terminal entry. |
| ALT RPC polling | The activation wait sleeps one slot before its first read, backs off 400 ms → 800 ms → 1.6 s → 2 s, and retains the original 12 s fail-closed ceiling. |
| Transparency reads | Cache-stampede mutex remains; on a miss, mint reads and the two accounts per mint execute concurrently and return in configured mint order. SW-05 owner/discriminator validation is unchanged. |
| Witness allocation | `BatchSettleInputs.witnesses` is now immutable shared storage; the blocking prover receives the same slice without an N=16 deep copy. |
| Scheduler contention | Final outcomes from each natural batch/round are applied under one scheduler write lock, while per-match result events and finality-gated book semantics stay independent. |
| Oracle refresh CPU | The normalized `[u8;32] → feed-id` lookup is built once before the task loop. Bad configuration pauses bound markets and exits; the per-feed failure fallback remains concurrent. |
| Local Rust suite | `cargo test -p darknyx-tee --lib`: **429 passed, 1 ignored**. |
| Artifact-required integration suite | `REQUIRE_CIRCUIT_ARTIFACTS=1 cargo nextest run -p darknyx-tee --tests`: **645 passed, 1 skipped**, 103.742 s. Real N=2 prove/verify and VALID_INPUT proof-backed intake ran. |
| Static gates | `cargo clippy -p darknyx-tee --all-targets -- -D warnings`: pass. `cargo fmt --all -- --check` and `git diff --check`: pass. |

### Slice 1 live evidence — 2026-08-07

Image `tee-v3-hardening-84` (source `64f01e7`) resolved to
`sha256:731741d0fe13b08cc6d9a639e855883fc762b66cc492cf02356e5c3eb27b43c3`
and was deployed by digest on the prod9 `tdx.xlarge` CPU CVM (`gpus=0`, compose
hash `be5ab2d6…`). Every deploy and host-side read used the private Helius
endpoint; boot logs redacted it to `https://devnet.helius-rpc.com`.

| Live evidence | Result |
|---|---|
| Flagship settle | `cvm-settle-e2e`: **passed**, 58.51 s harness test time; one confirmed match, no reject/ambiguous outcome. |
| Prover and pipeline | native witness 239 ms; rapidsnark step 2,762 ms; aggregate prove 3,071 ms; lock 1,326; verify 1,540; ALT tx/wait 1,331/683; settle 9,077; total pipeline 13,711 ms; three rebroadcasts. |
| Journal cost after batching | `/admin/drain` after the settle: `count=2`, `p50_us=3665`, `p95_us=max_us=4929`. The interruption's first write was 4,910 µs. This retires the previous single-sample waiver. |
| Host context | Multiple boots reported eight 2.4 GHz `06/af` CPUs, unlimited `cpu.max`, `nr_throttled=0`; single-thread canaries varied 163.2–380.8 Mops/s. Five auth calls were 1,797/1,767/1,687/1,560/1,479 ms. Phala SSH rejected the local key, so no post-proof `cpu.stat` delta was available. |
| Precise interruption | Mid-flight drain body: `in_flight_settlements=1`, `safe_to_stop=false`; expected harness failure followed. Independent Helius reads showed shard counts `2/0/0/0`, total 2 (deposits only). |
| Recovery classification | `total=1`, `release_expired=1`, all other classes zero, `needs_operator=false`; the lock sweeper replayed persisted locks and the journal retired to `in_flight_settlements=0`. |
| Drain lifecycle | POST/GET returned `draining=true`, `safe_to_stop=true`; DELETE reopened trading; a drained restart logged `settle journal: present and empty, nothing in flight`. Final POST reported safe, CPU metadata was rechecked as `gpus=0`, and the CVM was confirmed stopped. |

Hosted review is complete with no CodeRabbit inline findings. GitHub compiled the
circuit bundle successfully, but organization artifact quota rejected the
upload and mechanically skipped downstream jobs. Local artifact-required tests
above remain the code evidence. Slice 1 rows remain `Code complete` solely
because this tracker's closure rule requires PR #115 to merge.

## Recorded decisions

1. **The sweep was mostly remediated before this tracker existed.** Closure is
   based on merged source plus cited evidence, not the historical report's
   labels. Missing tracker rows are restored rather than silently inferred done.
2. **SW-18 remains documented, not cryptographically bound.** The quote's
   64-byte report data is already committed to nonce + signer set. A wrong boot
   session causes rejection, not stale-session acceptance.
3. **SW-34 remains deferred.** Wiring a test-only report into a production path
   without a settled telemetry design would create an API merely to close an
   informational row.
4. **PF-18 depends on SW-10.** SQLite `NORMAL` is suitable for a rebuildable
   cache only after the order-id high-water mark has a durable non-cache root.
5. **No per-operation keypair cache for PF-23.** Reuse a keypair within one
   operation; do not extend expanded-secret lifetime through an LRU unless
   profiling later justifies that separate trade-off.

## PR evidence template

```md
Findings: SW-/PF-
Invariant restored:
Compatibility/wire/circuit/account impact:
Local commands and exact results:
Measured before/after cost:
Hosted CI and review:
CVM/devnet evidence (or why not required):
Rollback:
Tracker/residual-backlog updates:
Still owed:
```

## Handoff template

```md
Base `main` commit:
Active branch / PR:
Slice and rows in progress:
Files intentionally changed:
Unrelated dirty/untracked files preserved:
Commands run and exact results:
Hosted CI/review state:
Live environment state and billing:
Evidence still owed before closure:
Next exact command/action:
```
