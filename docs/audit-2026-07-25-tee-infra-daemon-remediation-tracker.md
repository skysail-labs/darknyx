# Darknyx TEE, infrastructure, and daemon remediation tracker

This is the canonical closure ledger for
[`audit-2026-07-25-tee-infra-daemon-review.md`](audit-2026-07-25-tee-infra-daemon-review.md).
It covers `T-01…T-16` and `PF-08…PF-10`, plus the release-readiness gaps
confirmed while evaluating the audit. The earlier
[`audit-2026-07-25-remediation-tracker.md`](audit-2026-07-25-remediation-tracker.md)
remains canonical for `S-`, `PF-01…PF-07`, and `AU-` findings; this tracker
links dependencies into it rather than copying their ownership.

A finding is not closed by code alone. The closing PR must identify the
invariant restored, compatibility impact, exact tests, measured cost, live
evidence where required, and rollback instructions.

Status values are `Open`, `In progress`, `Code complete`, `Closed`, `Deferred`,
and `Won't Fix`. `Closed` requires merged code and all evidence named in the
row. `Deferred` requires a reason and re-entry condition. `Won't Fix` records
an explicit accepted risk and is not a synonym for forgotten work.

## Continuation directive for agents

An agent continuing this remediation must:

1. Read `AGENTS.md`, the audit linked above, this tracker, and the
   subsystem-specific architecture documents before editing code.
2. Start from the latest `main` and take the earliest `Open` slice whose
   prerequisites are closed. Move only that slice to `In progress`.
3. **Do not implement or reopen T-05.** It is an owner-approved accepted risk.
   Reconsider it only if the user explicitly reverses that decision.
4. Preserve all unrelated dirty and untracked files. Never discard or fold
   them into a remediation commit.
5. Use a `remediation/<topic>` branch and update this tracker in the same PR as
   the implementation. Do not add model-generated trailers to commit messages.
6. Run the reasonable equivalents of affected CI gates locally. The
   organization artifact quota and CodeRabbit review are currently unavailable;
   do not wait for either or claim that they ran.
7. Use a billable CVM only when the slice's evidence table requires it. Stop a
   CPU CVM when evidence is complete. **Never stop a prepaid on-demand GPU
   CVM.**
8. Move a row only as far as its evidence supports:
   `Open → In progress → Code complete → Closed`. A live-evidence requirement
   keeps a locally green change at `Code complete`.
9. Leave a handoff using the template at the end of this document before
   switching agents.

## Current execution state

Update this table in the same commit as every slice/status transition. It is
the first stop for an agent resuming the work.

| Field | Current value |
|---|---|
| Last verified `main` | `96e870e` |
| Last merged remediation PR | #76 — tracker baseline |
| Active slice | `remediation/tee-oracle-trust` |
| Active branch / PR | `remediation/tee-oracle-trust` / not opened |
| Next slice | `remediation/local-assurance` after oracle live evidence closes |
| Live state | No CVM/devnet mutation yet. Public GHCR lookup confirmed CPU tag `tee-v3-hardening-72` exists at `sha256:a21cc2…fdf485`, H200-validated GPU tag `tee-v3-hardening-68-cuda` exists at `sha256:699fc6…b9d572`, and the stale compose tag `tee-v3-hardening-69-cuda` does not exist. |
| Last updated | 2026-07-27 |

## Validation provenance

- The audit addendum revalidated the earlier remediation suite at
  `30f1b6b` on 2026-07-27.
- This implementation plan and disposition ledger were checked against
  `main` at `8137ab881d18636c83bf551465f0b816c53778ad` on 2026-07-27.
- The current Pyth integration hard-codes the legacy 13-of-19 Wormhole trust
  profile and calls Hermes without an authenticated, versioned cutover path.
- Pyth's current primary-source migration guidance says Pyth Core moves to
  five routers with a 3-of-5 quorum and that Hermes authentication becomes
  mandatory on 2026-08-18:
  [upgrade overview](https://docs.pyth.network/price-feeds/core/upgrade),
  [preparation guide](https://docs.pyth.network/price-feeds/core/upgrade/preparing),
  and
  [upgraded trust model](https://docs.pyth.network/price-feeds/core/upgrade/how-it-works).
- The audit findings and agreed remediation decisions were re-read rather than
  inferred from the status labels in the earlier tracker.

---

## Security and correctness findings

| ID | Severity | Owner | Planned remediation slice | Invariant / required evidence | Status |
|---|---|---|---|---|---|
| T-01 | High | TEE oracle | `remediation/tee-oracle-trust` | Only an explicitly versioned Pyth emitter/signer profile is accepted. A guardian-signed non-Pyth message, wrong emitter, wrong signer set, or insufficient quorum is rejected by fixture tests before its root reaches the cache. | In progress |
| T-02 | High | TEE oracle + matcher | `remediation/tee-oracle-trust` | Freshness uses signed publish time and local arrival health; feed state rejects stale, replayed, or non-monotonic updates. `OracleCache::snapshot` no longer fabricates `publish_slot = slot_now`, and `darkpool_matcher::validate_oracle` enforces the freshness data it reports instead of checking only `twap != 0`. Clock-skew, direct-matcher bypass, and out-of-order boundary tests pin the policy. | In progress |
| T-03 | High | TEE + infrastructure + SDK | `remediation/tee-transport-integrity` | TLS terminates inside the CVM boundary through the supported `dstack-ingress` path; the public route cannot reach plaintext port 8080. A real-CVM test proves HTTPS/WSS, attestation, auth, reconnect, and streaming through the encrypted path. | Open |
| T-04 | High | Release engineering + infrastructure | `remediation/tee-oracle-trust`, then enforced for `remediation/tee-transport-integrity` | The existing CPU/GPU images are pinned by immutable digest in the oracle slice, which already changes the image and compose. Every image introduced later, including ingress, must be digest-pinned before that slice can merge. Release evidence maps source/tag/digest/compose hash, so substituting a tag cannot preserve an accepted measurement. | In progress |
| T-05 | Medium | — | — | Owner accepted the residual append-only-mirror availability risk on 2026-07-27. Confirmed commitment plus on-chain root validation is considered sufficient for the current product; a rollback can stall witness service but cannot authorize custody loss. No code, test, infrastructure, or follow-up task is authorized. | **Won't Fix — accepted risk** |
| T-06 | Medium | TEE settlement + daemon | `remediation/settlement-recovery` | Every side effect in an in-flight settlement is synchronously journaled before submission, then reconciled against signatures, marker/lock/consumed PDAs, and chain state after restart. Resting orders are not resurrected; the daemon submits a fresh signed order when appropriate. | Open |
| T-07 | Medium | Matcher + TEE + SDK + daemon | `remediation/order-canonical-next` | The unused order-level `user_commitment` and the daemon's corrupting workaround are removed across Rust/TS wire and canonical types. Global wallet owner/user-commitment cryptography remains intact. Canonical domains and fixed parity vectors move atomically. | Open |
| T-08 | Medium | Release engineering | `remediation/local-assurance` | Rust and production Node dependencies have locally reproducible vulnerability gates; GitHub Actions use full immutable SHAs and minimum permissions. Findings are triaged rather than hidden by blanket ignores. | Open |
| T-09 | Low | Daemon custody | `remediation/daemon-keystore-v2` | New keystores use the fixed v2 scrypt profile `N=2^17, r=8, p=1` with explicit memory bounds. KATs, wrong-passphrase, and resource-bound tests pin the profile. | Open |
| T-10 | Low | Daemon custody | `remediation/daemon-keystore-v2` | Unauthenticated file fields cannot select weaker KDF work. Version/profile, lengths, and AAD are strict; v1 files migrate through decrypt-validate-atomic-reseal without destructive partial writes. | Open |
| T-11 | Medium | Release engineering + TEE | `remediation/local-assurance` | The complete `darknyx-tee` suite is an explicit local pre-PR gate now and a dedicated hosted job once artifact quota resumes. Slow artifact-backed tests remain separately identifiable. | Open |
| T-12 | Medium | TEE tests + circuits | `remediation/local-assurance` | Artifact-required mode fails loudly when circuit artifacts are absent; no positive proof test can report success without proving. Casual local mode may skip only when the required-mode flag is absent and must report the skip. | Open |
| T-13 | Low | Vault tests + build tooling | `remediation/local-assurance` | All LiteSVM loaders share one SBF artifact guard backed by a build manifest/source fingerprint, not a fragile per-test mtime check. A changed vault source or build configuration makes tests fail until `cargo build-sbf` refreshes the artifact and manifest. | Open |
| T-14 | Low | Vault + TEE + SDK | `remediation/tee-bounds-cleanup` | The retired `NullifierEntry`, seeds, PDA helpers, comments, and public exports are absent across the program, TEE, SDK, scripts, and docs. The commitment-keyed consumed/deposit guards remain untouched. | Open |
| T-15 | Low | Vault tests + tracker | `remediation/local-assurance` | LiteSVM covers live-lock withdraw rejection, expiry-boundary withdraw success, and `release_lock → withdraw` including rent return. The earlier S-03 row names only evidence that exists. | Open |
| T-16 | Medium | TEE oracle + matcher + market config | `remediation/tee-oracle-trust` | Pyth-native price/exponent values are converted with checked integer arithmetic into the governed atomic base/quote price units before circuit-breaker comparison or collateral math. The invariant includes base decimals, quote decimals, exponent, and `price_scale`; unequal-decimal markets, exponent changes, unrepresentable scales, rounding, and overflow fail closed. | In progress |

## Performance findings

| ID | Severity | Owner | Planned remediation slice | Invariant / required evidence | Status |
|---|---|---|---|---|---|
| PF-08 | Perf-Nit | Daemon | — | Repeated trading-key derivation is real but not established as material. Reopen only when an intake/daemon profile identifies it as a material contributor to CPU or placement latency; then derive once per unlocked keystore session rather than add an unbounded cache. | Deferred |
| PF-09 | Perf-Nit | TEE prover | `remediation/tee-bounds-cleanup` | Rapidsnark `SHORT_BUFFER` handling has bounded retries, checked growth, and a maximum output/error buffer. A malicious or broken native prover cannot loop or allocate without bound. | Open |
| PF-10 | Perf-Nit | Matcher + TEE + SDK + daemon | `remediation/order-canonical-next` | The dead order-level `user_commitment` field consumes no wire, heap, serialization, or signature-domain space. Removal is proven by Rust/TS parity, API schema checks, and a repository-wide stale-reference sweep. | Open |

## Additional release-readiness deliverables

These are not new audit finding IDs. They are prerequisites discovered while
turning the accepted fixes into a cutover-safe implementation.

| ID | Owner | Planned remediation slice | Required evidence | Status |
|---|---|---|---|---|
| RD-01 | TEE oracle + operations | `remediation/tee-oracle-trust` | A versioned legacy/upgraded Pyth trust profile supports the 2026-08-18 cutover without a fail-open fallback. Hermes API credentials are encrypted deployment inputs, never logged, and missing/invalid auth pauses new trading. Legacy 13-of-19 and upgraded 3-of-5 fixtures are both explicit; no quorum is guessed from payload data. | In progress |
| RD-03 | Operations docs | `remediation/tee-oracle-trust` | `deploy/docker-compose.gpu.yaml` no longer instructs operators to stop an H200. GPU and CPU lifecycle comments agree with `AGENTS.md` and `docs/gpu-tee-runbook.md`. | In progress |
| DEP-AU-07 | TEE + ingress | `remediation/tee-transport-integrity` | The canonical AU-07 row remains in the earlier tracker. Before public exposure, enforce global and per-account/peer connection caps, bound unauthenticated login time, and prove a ping-only client cannot hold resources indefinitely. Update both trackers with the same PR and evidence. | Open — canonical row linked |

## Recorded implementation decisions

### Oracle trust and scale

- T-01 and T-02 land together. Signature verification, emitter identity,
  freshness, and monotonicity form one fail-closed acceptance contract.
- Do not merely replace 13-of-19 constants with 3-of-5 constants. Select a
  complete, versioned trust profile from configuration approved for the
  deployment, and reject mixed legacy/upgraded envelopes.
- Authenticate Hermes requests with an encrypted deployment secret. A missing
  key, unauthorized response, malformed update, unknown profile, stale
  `publish_time`, replayed sequence, or incompatible exponent pauses new
  place/modify/matching while cancellation and reconciliation continue.
- T-16 is a correctness finding, not documentation. For raw Pyth integer `R`,
  exponent `e`, base decimals `b`, quote decimals `q`, governed scale `S`, the
  matcher price is the exactly checked rational
  `R × S × 10^(e + q - b)`. If raw `R` is used without conversion, the only
  coherent scale is `S = 10^(b - q - e)`. Support arbitrary representable
  governed scales through conversion; reject overflow, precision loss beyond
  the documented floor rule, or an exponent/decimal combination that cannot be
  represented. No floating point and no informational-only exponent remain.
- Batch feed IDs into one Hermes request when multiple markets share a CVM,
  while keeping freshness and replay state per feed.

### Confidential transport and image identity

- Ship the supported `dstack-ingress` sidecar first, with TLS termination
  inside the CVM boundary and no externally reachable plaintext backend.
  In-process RA-TLS may be a later defence-in-depth step; do not claim it has
  shipped until the certificate key is attestation-bound and verified by the
  client.
- Close the present T-04 exposure in the oracle slice by pinning the CPU and GPU
  images with `@sha256:<digest>` while that slice already changes the image,
  encrypted-env references, compose hash, and signer set. A release record must
  include source SHA, image tag, resolved digest, compose hash, attestation
  measurement, and signer set.
- Digest pinning is a release invariant, not a one-time cleanup. The transport
  slice must pin its newly introduced ingress image before merge and will still
  require its own compose-hash rotation for the transport change.
- AU-07 closes in this slice, but its canonical status remains in the earlier
  tracker.

### Settlement restart semantics

- T-06 is an in-flight settlement journal, not a periodic snapshot of only
  `OpeningStore`. Persist the minimum confidential state needed to reconcile
  each settlement stage, including its opening data, order/match identity,
  lock/marker derivations, submitted signatures, and last durable outcome.
- Journal each transition atomically on the dstack-sealed LUKS volume before
  its corresponding external side effect. Use write-temp, sync, atomic rename,
  and directory sync semantics.
- On boot, reconcile the journal with finalized chain state and RPC signatures.
  Redrive only idempotent ambiguous work while the marker/locks remain valid.
  Definitive failures become terminal `settlement_failed`.
- Do not restore resting orders from disk or auto-rebook them. The daemon
  receives terminal/restart state and resubmits a fresh signed order after the
  note is usable.
- Add an orderly drain mode for planned CPU-CVM redeploys, but do not treat it
  as crash recovery.

### Canonical order and client custody

- Remove only the dead order-level `user_commitment`. Do not delete the
  wallet-wide commitment primitive used by notes, wallet recovery, or
  ownership.
- Bump the canonical domain and regenerate Rust/TS fixed vectors in the same
  commit. Old in-memory orders and signatures are intentionally invalidated;
  no compatibility decoder is required before mainnet.
- Propagate the wire removal through TEE REST/stream types, matcher, SDK,
  daemon, loadgen, OpenAPI, and public protocol docs. `apps/demo` remains
  retired and out of scope.
- No modulus-check stopgap is needed while Darknyx has no third-party
  integrations. If an external integration begins before this slice lands,
  immediately replace the incorrect top-byte check with a full BN254 modulus
  comparison and remove the daemon's byte-zeroing workaround; do not make that
  temporary compatibility fix otherwise.
- Keystore v2 accepts exactly the fixed scrypt profile and envelope shape.
  Decode bounded lengths before allocation, authenticate all mutable metadata
  as AAD, and migrate v1 only after successful decryption and semantic
  validation. Preserve the original v1 file until the v2 replacement is
  durable.

### Assurance and bounded native interfaces

- Run `cargo audit` and `npm audit --omit=dev` locally for affected PRs while
  hosted artifacts are unavailable. Record tool versions and triage output.
- Add the future hosted TEE job now, but keep T-11 at `Code complete` until one
  real hosted execution succeeds after quota returns.
- Artifact-backed tests use an explicit required mode. CI/local release gates
  set that mode; missing artifacts are failures, not successful early returns.
- The SBF guard covers every LiteSVM test through shared infrastructure and
  validates a manifest/fingerprint produced with the SBF artifact.
- PF-09 rejects zero progress, integer overflow, excessive size, and retry
  exhaustion. Tests use a fake native boundary to exercise every response
  sequence without allocating the declared hostile size.

## Remediation slices and evidence

| Order | Slice | Findings / deliverables | Prerequisite | Status / PR | Compatibility and rollout | Required evidence before `Closed` |
|---|---|---|---|---|---|---|
| 1 | `remediation/tee-oracle-trust` | T-01, T-02, T-04, T-16, RD-01, RD-03 | Tracker baseline merged | In progress / not opened | TEE oracle, matcher, config, and compose change; new image, encrypted Pyth credential, digest-pinned CPU/GPU images, compose-hash/client-pin/signer rotation. No circuit or on-chain format change. The hazardous GPU stop instruction is corrected while its compose is already changing. | Legacy and upgraded oracle fixture adversarial suite; unequal-decimal/exponent/overflow conversion tests; direct-matcher stale bypass rejection; local TEE gate; digest evidence; upgraded Hermes smoke; real-mint CVM cold boot and controlled crossing settle; stale/replay/auth failure pauses; secrets absent from logs and compose hash. |
| 2 | `remediation/local-assurance` | T-08, T-11, T-12, T-13, T-15 | Slice 1 closed | Open / — | CI/test/build tooling plus LiteSVM tests; no protocol wire change. | Format/clippy/workspace/TEE tests, artifact-required negative, stale-SBF negative, named withdraw/release-lock LiteSVM tests, dependency reports, workflow/action-pin inspection. T-11 remains `Code complete` until a hosted run is available. |
| 3 | `remediation/tee-transport-integrity` | T-03, DEP-AU-07; enforce T-04 for new ingress image | Slice 2 code complete | Open / — | Compose hash and transport endpoint change; digest-pinned ingress image; governance/client pin rotation required. | Local compose validation, connection-cap tests, immutable ingress digest, real CVM HTTPS/WSS/API/attestation checks, plaintext-port negative, signer rotation and compose-hash evidence. |
| 4 | `remediation/settlement-recovery` | T-06 | Slice 3 closed | Open / — | New versioned encrypted journal; no public wire change unless terminal restart reasons are surfaced. | Unit crash points at every durable transition, corrupt/truncated journal failure, finalized-chain reconciliation cases, CPU-CVM restart mid-settlement, lock expiry/release, and daemon terminal/resubmit behavior. |
| 5 | `remediation/order-canonical-next` | T-07, PF-10 | Slice 4 closed, or external-integration trigger documented | Open / — | Canonical signature and order wire break; old orders intentionally invalid. No circuit, note, or vault account change. | Rust/TS fixed-vector parity, REST/stream/daemon/loadgen tests, OpenAPI validation, repository stale-reference sweep, fresh-tree real-mint CVM settle. |
| 6 | `remediation/daemon-keystore-v2` | T-09, T-10 | Slice 5 closed | Open / — | Versioned local keystore migration; v1 read/migrate only, all new writes v2. | Fixed KATs, wrong password, hostile headers/lengths, max-memory enforcement, interrupted migration, v1→v2 roundtrip, backup/import recovery. No CVM required. |
| 7 | `remediation/tee-bounds-cleanup` | T-14, PF-09 | Slice 6 closed | Open / — | SDK removal of dead exports; bounded internal FFI behavior. No live account or circuit migration. | Deletion checklist, SDK type/tests, workspace/TEE tests, bounded FFI adversarial sequences, docs/script stale-reference sweep. No CVM required. |

## Cost to the protocol

Every slice records a before/after measurement for the same workload. The
first implementation commit must capture its baseline before optimization or
hardening changes make it impossible to reconstruct.

| Slice | Expected cost or saving | Mandatory closing measurement |
|---|---|---|
| `tee-oracle-trust` | Checked unit conversion and signature-profile selection add negligible per-update CPU; batched feeds should reduce Hermes requests. Auth/freshness failure intentionally pauses matching and, after the explicit gate closes, place/modify. | Oracle refresh CPU and p50/p95 duration; requests per refresh for 1 and N feeds; conversion benchmark for equal/unequal decimals; time from last good update to matcher and intake pause. |
| `local-assurance` | No protocol runtime cost; longer local/hosted validation. | Wall time and peak disk for the TEE, artifact-required, SBF, dependency, and complete local gates. |
| `tee-transport-integrity` | TLS and connection accounting add handshake cost, request latency, memory per socket, and image size. | Cold/warm HTTP p50/p95, WebSocket connect/login/reconnect p50/p95, RSS per 1/100/limit sockets, CPU under ping-only abuse, and image-size delta. |
| `settlement-recovery` | Synchronous write-ahead journal adds durable-write latency and encrypted-disk traffic to settlement transitions. | Same-box no-journal baseline and journal p50/p95 per durable transition; end-to-end settle p50/p95; steady-state matched-pairs/s; bytes written per match; restart-to-reconciled duration. |
| `order-canonical-next` | Removes one dead 32-byte field plus JSON hex/serialization work; no proving or on-chain cost. | Canonical preimage bytes, REST/WS request bytes, serialized order size, and placement p50/p95 before/after. |
| `daemon-keystore-v2` | Deliberately increases unlock CPU/RAM; no trading hot-path cost after unlock. | v1/v2 unlock p50/p95, peak RSS, wrong-passphrase cost, migration duration, and resulting file size on supported client classes. |
| `tee-bounds-cleanup` | Dead-state deletion is neutral/smaller; bounded FFI retries only affect error paths. | Binary/SDK bundle delta, normal-prove p50/p95 unchanged, and adversarial retry count/allocation ceiling. |

## Cross-tracker corrections

These rows correct evidence bookkeeping in
[`audit-2026-07-25-remediation-tracker.md`](audit-2026-07-25-remediation-tracker.md).
They do not create duplicate finding ownership.

| ID | Required correction | Closure dependency | Status |
|---|---|---|---|
| CT-01 | Qualify S-03's claimed withdraw/release-lock LiteSVM evidence until it exists, then attach the T-15 tests. | T-15 | Open |
| CT-02 | Remove shipped S-03(B) lock sweeping from `Declined` and record its existing implementation/tests/live evidence. | Documentation correction | Open |
| CT-03 | Move AU-06 from `Code complete` to `Closed`; PR #72 merged as `19ae2a4`. | Documentation correction | Open |
| CT-04 | Delete the release-gate bullet that still lists the completed `api/auth.rs` pass as uncommissioned. | Documentation correction | Open |
| CT-05 | Annotate PF-04 with T-14 follow-through; the on-chain removal is valid, but its dead public helpers remain until T-14 closes. | T-14 | Open |

## Pull request evidence template

Every remediation PR must add a section to this tracker containing:

- **Finding IDs and invariant.** What attacker-controlled or failure state is
  no longer possible?
- **Interfaces.** Wire, canonical domain, account layout, circuit, persisted
  data, OpenAPI, compose hash, attestation, and compatibility impact.
- **Tests.** Exact commands and the negative/adversarial cases that ran.
- **Measured effect.** Latency, throughput, CPU/memory, transaction/CU, image,
  or storage delta for the affected path. Replace estimates with like-for-like
  measurements.
- **Live evidence.** Devnet signatures, CVM ID/type, image tag/digest,
  compose hash, attestation, signer set, and relevant logs when required.
- **Rollback.** State invalidated by rollback, required drain/reset/redeploy,
  and whether orders, journals, signatures, or credentials must be discarded.
- **Status.** Move rows only as far as the attached evidence supports.

## Release gates

- T-01, T-02, T-03, T-04, T-06, T-07, T-09, T-10, T-16, and AU-07 must be `Closed`
  before external users or real-value deposits.
- RD-01 and T-16 must close before the Pyth Core cutover. Today a stale cache
  already makes matching ticks no-op; the oracle slice additionally routes
  oracle health through the shared trading gate so place/modify refuse clearly
  while cancel and reconciliation remain available.
- T-08 and T-11…T-13 must be at least `Code complete` before the next formal
  review. T-11 closes only after its hosted job has executed successfully when
  organization artifact capacity returns.
- T-05 is not a release gate. Its accepted-risk decision must not be silently
  converted back into deferred work.
- Mainnet still requires the existing external circuit audit, Phase-2
  ceremony, split-governance rehearsal, recovery drill, deployed-program/image
  verification, and all gates in
  [`security-remediation-tracker.md`](security-remediation-tracker.md).

## Agent handoff template

```text
Last merged PR / main SHA:
Active branch / HEAD:
Dirty or untracked files preserved:
Active slice and finding IDs:
Invariant and compatibility decisions:
Commands run and exact results:
Live state (CVM ID, CPU/GPU type, running/stopped, image tag+digest,
compose hash, signer set, program deployment):
Evidence still missing:
Blockers:
Exact next action:
```
