# Darknyx TEE, infrastructure, and daemon remediation tracker

This is the canonical closure ledger for
[`audit-2026-07-25-tee-infra-daemon-review.md`](audit-2026-07-25-tee-infra-daemon-review.md).
It covers `T-01…T-18` and `PF-08…PF-10`, plus the release-readiness gaps
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
| Last verified `main` | `f7a1530` (slice 2 closed; PR #79 merged) |
| Last merged remediation PR | #80 — slice 3 (`tee-transport-integrity`), merged 2026-07-28 |
| Active slice | none — slice 3 closed. Its scope was reduced to DEP-AU-07 + T-04 enforcement + the transport documentation correction; T-03's transport work is deferred to a mainnet gate (see the slice-3 section). |
| Active branch / PR | merged (PR #80) |
| Next slice | `remediation/settlement-recovery` (slice 4) |
| Live state | **No CVM running; billing halted — slice 3 as scoped needs none.** Slice 2 is CI/test/build tooling and required no CVM or devnet mutation. Images pinned by digest from the merged-source rebuild — CPU `sha256:98f61dc3bbbf505e501b2d208618ce2a601e1a443ae73b63f90ae053ebfbe339` (tag `tee-v3-hardening-75`), GPU `sha256:eda803e3c16cc6a4443444857b560a3dcf4f6e3126c0545a31cf81e30b3dcf66` (tag `tee-v3-hardening-75-cuda`). Devnet tree left freshly reset from the slice-1 closure run. |
| Last updated | 2026-07-28 (slice 3 closed) |

### Slice 1 live evidence — 2026-07-27

Captured against `nightly-test-cvm` running the digest-pinned image
`@sha256:dddf0116363e8ab9112bc09a7cf97558f00f2306016094ba6bcb917a64253ad3` (verified via `phala ps`, so the deployed identity is
the pinned digest and not a tag).

| Evidence | Result |
|---|---|
| Fail-closed oracle gate | Boot logged `trading starts PAUSED until the first authenticated, fresh oracle batch` (`profile=router-quorum-v1`, `api_key_configured=true`), then `oracle trust/freshness recovered; trading RESUMED` **483 ms** later. Trading is closed until a guardian-verified, authenticated, fresh batch arrives — not open-by-default. |
| Upgraded Pyth profile against live Hermes | `https://pyth.dourolabs.app/hermes` with the bearer credential; `router-quorum-v1` verified a real mainnet VAA. No profile inferred from payload. |
| Batched refresh | `batched oracle sync task spawned feed_count=1 profile="router-quorum-v1"` — one request per refresh cycle. |
| Credential hygiene | `loaded config (solana_rpc_url redacted to host) rpc_host=devnet.helius-rpc.com`. No RPC key, Hermes key, or bootstrap secret in any log line. Values ride the encrypted deploy env, so none enter `compose_hash`. |
| Merkle cold boot | `merkle cold-boot: vault has no transaction history in range yet` — correct empty start after the 4-shard reset. |
| Real crossing settle | `cvm-settle-e2e` **passed** (41.6 s). Settle tx `5hFc91SKoknazB95LkPdfTEQqr54Lh8U13pvu5wFo4qWCnPLPaYyxFPr4yMqx1SnhUw3NRTXfdcCMXtGpZSwd3f4`, confirmed slot `479364510`, `confirmed=1 rejected=0 ambiguous=0 pipeline_failed=false`. |
| Settle pipeline cost | `total_ms=14573` — lock 1929, prove 2417 (witness 227 native + prove step 2173), verify 1197, ALT 2303 + wait 1044, settle 10911, close 0. Backend `rapidsnark`, device CPU, `settle_concurrency=1`. |

**Baseline note.** These are the slice's first-commit baseline numbers on prod9
(prod5 host contention is what skewed the earlier PERF-INV-01 readings, so
prod9 is the like-for-like reference for future comparisons). Per-refresh
oracle CPU p50/p95 was **not** captured: refresh timing logs at `debug` and the
compose pins `darknyx_tee::oracle=info`. That measurement remains outstanding
for `Closed` and needs either a debug-level run or an exported counter.

**Evidence-vintage caveat.** This run predates the two oracle-cache fixes made
during slice-1 review (conflicting-replay false positive + the retimed local-
arrival test). The captured evidence remains valid — neither the fail-closed boot
path nor the settle path exercises the same-publish-second case — but the image
digest pinned in the compose is the one tested, and merged source now differs
from it. Rebuild and re-pin before the next CVM run; slice 3 rotates
`compose_hash` regardless, so no extra ceremony is incurred by deferring it.

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
| T-01 | High | TEE oracle | `remediation/tee-oracle-trust` | Only an explicitly versioned Pyth emitter/signer profile is accepted. A guardian-signed non-Pyth message, wrong emitter, wrong signer set, or insufficient quorum is rejected by fixture tests before its root reaches the cache. | Closed |
| T-02 | High | TEE oracle + matcher | `remediation/tee-oracle-trust` | Freshness uses signed publish time and local arrival health; feed state rejects stale, replayed, or non-monotonic updates. `OracleCache::snapshot` no longer fabricates `publish_slot = slot_now`, and `darkpool_matcher::validate_oracle` enforces the freshness data it reports instead of checking only `twap != 0`. Clock-skew, direct-matcher bypass, and out-of-order boundary tests pin the policy. | Closed |
| T-03 | High | TEE + infrastructure + SDK | `remediation/tee-transport-integrity` (transport work deferred) | **Rationale corrected 2026-07-28.** The finding's stated basis — "order intent is plaintext at the operator's gateway" — is wrong: the dstack gateway is itself an attested TDX CVM that mutually attests with our CVM and tunnels over WireGuard, so no unprotected hop carries plaintext. The real, still-valid exposure is narrower: (a) clients pin our measurement but not the gateway's, so that component can change with no Darknyx governance event, and (b) nothing binds the verified quote to the TLS session it was fetched over, so a party holding a valid gateway-domain certificate can front a different backend. Invariant to close: TLS terminates inside the Darknyx enclave with an attestation-bound certificate the client verifies, and the public route cannot reach plaintext 8080. | **Deferred — mainnet gate** (see the slice-3 section for the trigger, both costed options, and the DNS migration playbook) |
| T-04 | High | Release engineering + infrastructure | `remediation/tee-oracle-trust`, then enforced for `remediation/tee-transport-integrity` | The existing CPU/GPU images are pinned by immutable digest in the oracle slice, which already changes the image and compose. Every image introduced later, including ingress, must be digest-pinned before that slice can merge. Release evidence maps source/tag/digest/compose hash, so substituting a tag cannot preserve an accepted measurement. | Code complete — enforcement generalised in slice 3: `scripts/check-compose-image-digests.sh` now checks EVERY image in EVERY compose against an explicit repository allowlist, instead of asserting a single hardcoded image. An ingress (or any other) service added later fails the gate until it is digest-pinned AND its repository is deliberately approved. Verified by mutating a compose in both directions. |
| T-05 | Medium | — | — | Owner accepted the residual append-only-mirror availability risk on 2026-07-27. Confirmed commitment plus on-chain root validation is considered sufficient for the current product; a rollback can stall witness service but cannot authorize custody loss. No code, test, infrastructure, or follow-up task is authorized. | **Won't Fix — accepted risk** |
| T-06 | Medium | TEE settlement + daemon | `remediation/settlement-recovery` | Every side effect in an in-flight settlement is synchronously journaled before submission, then reconciled against signatures, marker/lock/consumed PDAs, and chain state after restart. Resting orders are not resurrected; the daemon submits a fresh signed order when appropriate. | Open |
| T-07 | Medium | Matcher + TEE + SDK + daemon | `remediation/order-canonical-next` | The unused order-level `user_commitment` and the daemon's corrupting workaround are removed across Rust/TS wire and canonical types. Global wallet owner/user-commitment cryptography remains intact. Canonical domains and fixed parity vectors move atomically. | Open |
| T-08 | Medium | Release engineering | `remediation/local-assurance` | Rust and production Node dependencies have locally reproducible vulnerability gates; GitHub Actions use full immutable SHAs and minimum permissions. Findings are triaged rather than hidden by blanket ignores. | Closed |
| T-09 | Low | Daemon custody | `remediation/daemon-keystore-v2` | New keystores use the fixed v2 scrypt profile `N=2^17, r=8, p=1` with explicit memory bounds. KATs, wrong-passphrase, and resource-bound tests pin the profile. | Open |
| T-10 | Low | Daemon custody | `remediation/daemon-keystore-v2` | Unauthenticated file fields cannot select weaker KDF work. Version/profile, lengths, and AAD are strict; v1 files migrate through decrypt-validate-atomic-reseal without destructive partial writes. | Open |
| T-11 | Medium | Release engineering + TEE | `remediation/local-assurance` | The complete `darknyx-tee` suite is an explicit local pre-PR gate now and a dedicated hosted job once artifact quota resumes. Slow artifact-backed tests remain separately identifiable. | Closed |
| T-12 | Medium | TEE tests + circuits | `remediation/local-assurance` | Artifact-required mode fails loudly when circuit artifacts are absent; no positive proof test can report success without proving. Casual local mode may skip only when the required-mode flag is absent and must report the skip. | Closed |
| T-13 | Low | Vault tests + build tooling | `remediation/local-assurance` | All LiteSVM loaders share one SBF artifact guard backed by a build manifest/source fingerprint, not a fragile per-test mtime check. A changed vault source or build configuration makes tests fail until `cargo build-sbf` refreshes the artifact and manifest. | Closed |
| T-14 | Low | Vault + TEE + SDK | `remediation/tee-bounds-cleanup` | The retired `NullifierEntry`, seeds, PDA helpers, comments, and public exports are absent across the program, TEE, SDK, scripts, and docs. The commitment-keyed consumed/deposit guards remain untouched. | Open |
| T-15 | Low | Vault tests + tracker | `remediation/local-assurance` | LiteSVM covers live-lock withdraw rejection, expiry-boundary withdraw success, and `release_lock → withdraw` including rent return. The earlier S-03 row names only evidence that exists. | Closed |
| T-16 | Medium | TEE oracle + matcher + market config | `remediation/tee-oracle-trust` | Pyth-native price/exponent values are converted with checked integer arithmetic into the governed atomic base/quote price units before circuit-breaker comparison or collateral math. The invariant includes base decimals, quote decimals, exponent, and `price_scale`; unequal-decimal markets, exponent changes, unrepresentable scales, rounding, and overflow fail closed. | Closed |
| T-17 | Medium | TEE matcher + API | `remediation/multi-market-isolation` | `TradingPauseReason::Oracle` is scoped per market, not venue-wide. One market's stale or unauthenticated feed pauses only that market, and a healthy market's tick cannot clear another's oracle pause. A mixed configuration where some markets have no `oracle_feed_id` while `feed_ids` is non-empty is rejected at boot rather than silently sharing gate state. | Open |
| T-18 | Medium | Release engineering | `remediation/local-assurance` | A failure in the `Detect changed paths` job cannot leave the aggregate `pr-checks success` check green. The aggregate gate must fail (not pass) when any prerequisite job fails or is skipped due to an upstream failure, so a broken paths filter cannot silently disable the entire PR gate. | Closed |

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
| RD-01 | TEE oracle + operations | `remediation/tee-oracle-trust` | A versioned legacy/upgraded Pyth trust profile supports the 2026-08-18 cutover without a fail-open fallback. Hermes API credentials are encrypted deployment inputs, never logged, and missing/invalid auth pauses new trading. Legacy 13-of-19 and upgraded 3-of-5 fixtures are both explicit; no quorum is guessed from payload data. | Closed |
| RD-03 | Operations docs | `remediation/tee-oracle-trust` | `deploy/docker-compose.gpu.yaml` no longer instructs operators to stop an H200. GPU and CPU lifecycle comments agree with `AGENTS.md` and `docs/gpu-tee-runbook.md`. | Closed |
| DEP-AU-07 | TEE | `remediation/tee-transport-integrity` | The canonical AU-07 row remains in the earlier tracker. Global and per-account connection caps enforced; the unauthenticated login window is now ABSOLUTE (no frame extends it), closing the ping-only hold. **Per-peer caps are deliberately NOT implemented** — behind the gateway every connection shares one apparent source address, so an IP-keyed cap would bound the whole venue while constraining no individual attacker; rationale recorded in `crates/darknyx-tee/src/api/conn_limit.rs`. Proven with a real bound server and a real WebSocket client (`tests/stream_conn_limits.rs`), and mutation-tested: disabling the deadline fails both ping tests. All 7 socket tests executed in the hosted `TEE` job (run `30336791498`, 6m26s), confirmed by name in the log rather than inferred from a green tick. | Closed |

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
| 1 | `remediation/tee-oracle-trust` | T-01, T-02, T-04, T-16, RD-01, RD-03 | Tracker baseline merged | Code complete / PR open | TEE oracle, matcher, config, and compose change; new image, encrypted Pyth credential, digest-pinned CPU/GPU images, compose-hash/client-pin/signer rotation. No circuit or on-chain format change. The hazardous GPU stop instruction is corrected while its compose is already changing. | Legacy and upgraded oracle fixture adversarial suite; unequal-decimal/exponent/overflow conversion tests; direct-matcher stale bypass rejection; local TEE gate; digest evidence; upgraded Hermes smoke; real-mint CVM cold boot and controlled crossing settle; stale/replay/auth failure pauses; secrets absent from logs and compose hash. |
| 2 | `remediation/local-assurance` | T-08, T-11, T-12, T-13, T-15, T-18 | Slice 1 closed | Closed / PR #79 | CI/test/build tooling plus LiteSVM tests; no protocol wire change. | Format/clippy/workspace/TEE tests, artifact-required negative, stale-SBF negative, named withdraw/release-lock LiteSVM tests, dependency reports, workflow/action-pin inspection. T-11 remains `Code complete` until a hosted run is available. |
| 3 | `remediation/tee-transport-integrity` | DEP-AU-07; T-04 enforcement; transport documentation correction. **T-03 deferred** | Slice 2 closed | Closed / PR #80 | **No compose change, no compose-hash rotation, no CVM, no ceremony.** Connection caps are code defaults; the digest guard is CI-only; the documentation corrections are text. Wire-visible additions only: a `503` on an over-capacity `/v1/stream` upgrade and error code `4290` on an over-cap login, both documented in the OpenAPI. | Real-socket connection-cap tests incl. the ping-only hold and its mutation test; digest-guard mutation test in both failure directions; OpenAPI parse; the standard local gate. |
| 4 | `remediation/settlement-recovery` | T-06 | Slice 3 code complete (relaxed from "closed": slice 3 no longer closes T-03, and settlement recovery has no transport dependency) | Open / — | New versioned encrypted journal; no public wire change unless terminal restart reasons are surfaced. | Unit crash points at every durable transition, corrupt/truncated journal failure, finalized-chain reconciliation cases, CPU-CVM restart mid-settlement, lock expiry/release, and daemon terminal/resubmit behavior. |
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
| `tee-transport-integrity` (as shipped) | Connection accounting adds one atomic compare-and-swap per upgrade and one map update per login — not measurable against network cost. No TLS work shipped, so no handshake, latency, or image-size delta. | None required: the change adds no per-request work on any hot path. The caps' behaviour is pinned by tests rather than by a timing measurement. |
| `tee-transport-integrity` (deferred T-03 transport work) | TLS termination adds handshake cost, request latency, memory per socket, and image size. | Cold/warm HTTP p50/p95, WebSocket connect/login/reconnect p50/p95, RSS per 1/100/limit sockets, CPU under ping-only abuse, and image-size delta. Capture in the CVM window that ships the transport change. |
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
| CT-01 | Qualify S-03's claimed withdraw/release-lock LiteSVM evidence until it exists, then attach the T-15 tests. | T-15 | Satisfied — `programs/vault/tests/withdraw_lock_lifecycle.rs` (3 tests) merged in PR #79 and running in the `vault-litesvm` CI job |
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

## Slice 3 — `remediation/tee-transport-integrity`, 2026-07-28

### What shipped, and why T-03's transport work did not

The slice was scoped down deliberately. Three of its four parts had no dependency
on the transport decision and shipped: the connection bounds (DEP-AU-07), the
generalised image-digest gate (T-04 enforcement), and the documentation
correction. The transport change itself is deferred to a mainnet gate.

**The audit's rationale for T-03 was wrong and the correction changes the fix.**
The finding says TLS terminating at the Phala gateway puts order intent "in the
operator's process memory in cleartext". It does not. Per
`phala-docs/phala-cloud/networking/security.mdx`, the gateway runs inside its own
Intel TDX CVM, mutually attests with our CVM before any traffic flows, and
carries it over WireGuard. The host operator cannot read gateway memory any more
than they can read ours. What survives is narrower and still worth fixing: the
client pins one measurement out of two, and the verified quote is not bound to
the TLS session it arrived over.

**The correct fix depends on a product decision that has not been made.** If
clients stay programmatic (SDK + daemon), in-enclave RA-TLS with a self-signed,
attestation-verified certificate is strictly right and needs no DNS at all. If a
browser-facing client ever enters scope, browsers reject self-signed certificates
regardless of attestation, forcing a CA-issued certificate, ACME, a DNS API, and
the ingress sidecar. Building either now is a bet on that decision, and the wrong
bet is discarded work.

**Deferral is consistent with this tracker's own gating.** The release gates
already place T-03 before external users or real-value deposits, not before
merge. The deployment is devnet-only with no external users. What is NOT
deferrable, and shipped here, is the documentation: `CRYPTOGRAPHY.md`, the
attestation flow, the API roadmap, and four pages of the **published** GitBook
portal all asserted that TLS terminates inside the Darknyx enclave, with
`docs/gitbook/api/transport-and-attestation.md` going as far as "the TLS
certificate Darknyx serves is bound to a key the enclave generated and holds".
That is a false security claim in user-facing material. The audit called this
option D and "mandatory immediately" if the real fix would not land first.

### Trigger to resume T-03

Take the transport work when ANY of these becomes true:

1. the first external user, or any real-value deposit, is in prospect;
2. a browser-based client enters scope (forces the ingress path); or
3. the gateway's measurement becomes something we must pin contractually.

### The two options, costed against the constraint each actually hits

| | A — in-enclave RA-TLS | B — dstack-ingress sidecar |
|---|---|---|
| Transport | Self-signed cert, key from dstack `get_key()`, reached through the gateway's `s`-suffix TLS passthrough (`<app-id>-<port>s.dstack-…`) | Let's Encrypt cert on a custom domain, TLS terminated by the sidecar inside the CVM |
| External prerequisites | **None** | A domain whose DNS is hosted at Cloudflare, Linode, or Namecheap, plus a DNS API token and `CERTBOT_EMAIL` as new encrypted secrets |
| Attestation contract | **Breaking.** `report_data` is fully allocated — `[0..32]` caller nonce, `[32..64]` `SHA-256(signer set)`. Binding the certificate means extending the attested value to `SHA-256(pk_0 ‖ … ‖ pk_{K-1} ‖ spki)`, moving the SDK and daemon in lockstep | Unchanged; the sidecar publishes its own quote at `/evidences/` |
| Trust boundary | The Darknyx binary's own measurement | The CVM, via a third-party image we do not build but must add to `compose_hash` |
| Browser clients | Rejected (self-signed) | Supported |
| Iteration hazard | None | Let's Encrypt allows **5 certificates per identifier set per week** — enough to lock out a redeploy loop mid-window |

Note the tracker's earlier recorded decision ("ship the supported
`dstack-ingress` sidecar first") predates two facts: the domain prerequisite, and
that `report_data` has no free space. Neither option is obviously cheaper; A is
less infrastructure and more code, B the reverse.

### DNS migration playbook (prerequisite for option B only)

The current domain is registered at GoDaddy, which is not one of the three
providers dstack-ingress can drive and whose own DNS API is restricted. Only DNS
*hosting* needs to move; the registrar can stay. Roughly half a day plus
propagation:

1. **Inventory the existing zone** — every A/AAAA/CNAME/MX/TXT record, especially
   SPF, DKIM, DMARC, and any domain-verification TXT records.
2. **Add the domain at the new provider.** Auto-import catches most records and
   routinely misses MX and TXT. Diff against the inventory by hand; this is where
   the outages come from.
3. **Lower TTLs at the registrar** to ~300 s a day or two before the cutover so
   rollback is fast.
4. **Repoint the nameservers.**
5. **Verify before declaring done.** Propagation takes hours (worst case ~48 h)
   and **email is the highest-risk casualty** — send and receive a test message.
6. **Then** configure the sidecar: a token scoped to that zone only,
   `DOMAIN=api.<domain>`, `SET_CAA=true`. Use a **subdomain, never the apex** —
   Cloudflare overrides apex CAA records, which silently breaks domain
   attestation.

Because the project's main website runs on this domain, step 4 has real blast
radius. It is independent of Darknyx and can be done at any time.

### When T-03 does resume: the window and ceremony

Recorded now so it is not re-derived under time pressure.

**Signer rotation is expected to be a no-op.** Slice 1 changed `compose_hash`
(new image digest) and the signer set was unchanged — dstack derives the keys per
`app_id`. Plan to *verify* the set against `vault_config.tee_pubkeys`, with
rotation and re-funding as the contingency, not the default path.

**Window sequence.** Pre-window and off the clock: merge the code, edit the
compose, resolve and pin the digest, compute `compose_hash` locally, and
allowlist it in the Phala dashboard. Then, in one window: reset the tree first so
the mirror cold-boots empty → deploy with the env file (`umask 077`, shredded
after) → confirm boot, certificate issuance, and the signer set → capture
evidence → stop the CVM after confirming `resource.gpus` is 0.

**Evidence to capture:** HTTPS and WSS end to end; attestation still verifying;
the **plaintext-port negative** (`https://<app>-8080.dstack-…` must stop
routing); cap enforcement under a ping-only client; the deferred cost-table row
above; and one `cvm-settle-e2e` to prove no regression.

**On the ceremony, state it accurately.** `docs/tee-attestation-flow.md` §5
describes a 3-of-5 Squads ceremony with independent human verifiers. Devnet has
one admin keypair. What a devnet window can execute is the *mechanics* —
allowlist, deploy, verify the quote against the new `compose_hash`, confirm
signers, update the client pin — as a **rehearsal**. It does not produce
governance evidence, and should not be recorded as though it did. The real
ceremony remains a mainnet gate.

### DEP-AU-07 — what was actually wrong

`/v1/stream` upgrades unauthenticated by design, and nothing bounded that state.
The specific defect: `stream.rs` refreshed the idle timer on **any** frame,
including a transport `Ping`, so a client that never logged in held a socket
indefinitely by pinging. The 60 s idle timeout could never fire on it.

The fix splits the two phases rather than making pings inert:

* **Unauthenticated** — an ABSOLUTE 10 s window from socket open that no frame
  extends. This is the only phase an anonymous peer controls.
* **Authenticated** — the pre-existing idle timeout, still refreshed by any
  frame. A market maker resting no orders is a legitimate idle session and must
  not be disconnected; the counter-test
  `an_authenticated_socket_survives_past_the_login_deadline` pins that, because a
  fix that simply stopped pings from counting would break real clients while
  passing the attack tests.

Plus a venue-wide cap (refused pre-upgrade with `503` + `Retry-After`) and a
per-account cap (refused at login with code `4290`). Both hand out RAII guards:
a counter released at one tidy exit point leaks a slot on every early return,
error, or panic, which turns a cap into a slow self-inflicted outage.

**Per-peer caps are deliberately absent.** Traffic arrives through the gateway's
WireGuard tunnel, so every connection shares one apparent source address. An
IP-keyed cap would bound the entire venue at the per-IP limit while constraining
no individual attacker — defence in appearance, outage in function. A trustworthy
client address needs a proxy inside the CVM boundary setting a forwarded-for
header we control end to end, which is the ingress path, which is deferred with
T-03. Recorded in `conn_limit.rs` so it is not later mistaken for an oversight.

### A second gate found not running at all

Wiring the generalised digest guard surfaced a live hole in the CI paths filter.
The two deployment guards (`check-compose-image-digests.sh` and
`check-icicle-cuda-arch-env.sh`) run inside the `rust` job, but the `rust` filter
matched only `programs/**`, `crates/**`, `Cargo.*`, and `rust-toolchain.toml`.

So a pull request that touched **only** `deploy/docker-compose.yaml` — for
instance replacing a digest with a mutable tag, which is exactly the T-04
supply-chain hole the guard exists to catch — matched no filter, skipped the
`rust` job, and merged with the compose gate never executed. The same held for a
PR that weakened a guard script itself.

Fixed by extending the `rust` filter to cover `deploy/**`, `Dockerfile*`, and
both guard scripts. This is the third instance in three slices of the same
underlying defect: **a gate that reports success because it never ran**. Worth
stating as a rule — when adding a gate, check that the filter which decides
whether it runs includes the gate's own inputs, not just the code it guards.

### Tests, and the mutation checks that make them mean something

`crates/darknyx-tee/tests/stream_conn_limits.rs` drives a **real bound server and
a real WebSocket client**. That is not ceremony: the defect was that a
*transport* ping refreshed the timer, and a transport ping never appears in the
application frame enum the handler matches on. A test calling `handle_frame`
directly could not have produced the bug and could not detect its return.

| Check | Result |
|---|---|
| 7 socket tests + 7 registry unit tests | pass |
| Mutation: disable the login deadline | both ping tests **fail**, other five stay green |
| Mutation: second compose image pinned by tag | digest guard **rejects** |
| Mutation: second image digest-pinned from an unapproved repo | digest guard **rejects** |
| Compose restored byte-identical after mutation | confirmed via `git diff` |

### Findings raised during slice-3 review

Automated review of this PR raised five items. Four were valid and fixed here:

- **The paths-filter fix was incomplete.** I added `deploy/**` and the guard
  scripts but not `.github/workflows/pr-checks.yml` itself, so an edit weakening
  a guard's invocation — or the filter — still would not have run the guards.
  The `deps` filter already listed the workflow for the dependency gate; the
  deployment guards needed the same. Fixed. Same defect as the one this slice
  documented, one level up.
- **A status contradiction I introduced.** The canonical AU-07 row's body said
  "Closed 2026-07-28" while its status column said `Code complete`. The status
  column was right; the body is now consistent with it.
- **`bearer auth` listed as a traffic-analysis mitigation** in the
  `CRYPTOGRAPHY.md` non-goals table. It is not one — it gates access and does
  nothing for timing, size, or frequency. Pre-existing wording that this slice
  should not have carried forward while correcting the row beside it. Now states
  plainly that the threat is unmitigated.
- **The digest guard rejected a validly-quoted image.** `image: "repo@sha256:…"`
  is legal Compose, and the parser captured the quotes into the value, so a
  correctly-pinned image failed the digest regex. Fail-closed rather than
  fail-open, but it would have sent someone hunting a supply-chain problem that
  did not exist. Quotes are now stripped; re-verified that a quoted MUTABLE tag
  is still rejected, so the fix removes a false positive without widening what
  passes.

One was partly valid and partly a misread. The reviewer asked that a
"certificate-binding claim" at `transport-and-attestation.md` L65-70 be removed —
that range is the new warning callout, which already states the binding does NOT
exist, so there was nothing to remove. Its other half was right and is fixed: the
OpenAPI is the authoritative wire contract and now carries the same caveat, that
verifying `/attestation` covers this service's measurement only and does not
authenticate the TLS session it arrived over.

Skipped: extending the digest guard to parse inline YAML mappings. Compose files
do not express service images that way, and a full YAML parse in a bash CI guard
buys no coverage for real inputs.

### Status

`DEP-AU-07` is **`Closed`**. Hosted run `30336791498` is green on every job
(`Vercel` excluded — a stale integration the owner is removing; `Indexer`
correctly skipped, no indexer paths changed). The seven socket tests and both
deployment guards were verified BY NAME in the job logs, not inferred from the
aggregate tick — the habit T-18 exists to enforce. `T-04` stays `Code
complete` as a standing release invariant, now with an enforcement gate that
actually inspects every image. `T-03` moves to `Deferred — mainnet gate` with the
trigger above; it is also recorded in the mainnet gates of
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

## Agent handoff — 2026-07-27

```text
Last merged PR / main SHA: #76 / 96e870e
Active branch / HEAD: remediation/tee-oracle-trust / e0fe368
Dirty or untracked files preserved: yes — third_party/rapidsnark and
  icicle-snark benchmark/*.json working-tree edits left untouched; all
  pre-existing untracked docs/dirs (audit_1/, dstack/, phala-docs/, etc.)
  unmodified. Only build.rs was staged inside the submodule.
Active slice and finding IDs: slice 1 — T-01, T-02, T-04, T-16, RD-01, RD-03
Invariant and compatibility decisions:
  - Oracle acceptance is one fail-closed contract: versioned trust profile
    (emitter + signer set + quorum) AND signed-publish-time freshness. Trading
    starts paused and reopens only after an authenticated verified batch.
  - Both compose images pinned by digest; compose_hash now transitively binds
    image bytes. No circuit or on-chain format change, so no tree migration
    beyond the routine reset.
Commands run and exact results:
  cargo fmt --all -- --check                      -> clean
  cargo clippy --workspace --all-targets -D warn  -> zero warnings
  cargo test --workspace                          -> 302 passed, 0 failed, 1 ignored
                                                     (+ all integration suites green)
  tsc -p packages/sdk | packages/indexer          -> both clean
  vitest packages/sdk                             -> 270 passed, 24 skipped
  vitest packages/indexer                         -> 20 passed
  vitest packages/daemon                          -> 147 passed, 2 skipped
  bash scripts/check-icicle-cuda-arch-env.sh      -> both build scripts OK
  bash scripts/check-compose-image-digests.sh     -> both composes OK
  cvm-settle-e2e (RUN_CVM_E2E=1)                  -> 1 passed (41.6 s)
Live state: nightly-test-cvm app_9ca3cded105f16923afb0e3f62537882c14db637,
  CPU (gpus=0), node prod9, STOPPED after evidence capture.
  Image: ghcr.io/skysail-labs/darknyx-tee@sha256:dddf0116363e8ab9112bc09a7cf97558f00f2306016094ba6bcb917a64253ad3
    (tag tee-v3-hardening-74; GPU tee-v3-hardening-74-cuda @ sha256:1001d5a0ae45d86c624c265c3598b490f7b511aa3349faa1c2ea03d29d367854)
  Signer set (all funded to 2 SOL, registered in vault_config.tee_pubkeys):
    0 4F9aTxW18pxBYFTnqXi8P82FUY4255RQDCkysZyoSMRX
    1 8x4QTRcmYnvALeLpqn5DVQ968nNTPfFvFosBqSh3Q6s2
    2 2TAuvsUu4SqsdPP1Y7oLTJjcezAFLsqMjmtTn6Tc7wFk
    3 C3fNnmb7DJ3Xbb7AmM284UHzuJRZsgicFsyTEvE9V6EX
  Program C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx unchanged (not redeployed).
  All 4 Merkle shards reset; tree is at a fresh empty start.
Evidence still missing:
  - Per-refresh oracle CPU p50/p95 (refresh timing logs at debug; compose pins
    darknyx_tee::oracle=info). Needed for the cost table before Closed.
  - Requests-per-refresh for N>1 feeds — only the 1-feed case was exercised.
Blockers: none. Slice 1 needs merge + the two measurements above to reach Closed.
Exact next action: merge the slice-1 PR, then start slice 2
  (remediation/local-assurance: T-08, T-11, T-12, T-13, T-15). Slice 2 needs no
  CVM. Note the tree is freshly reset, so the next leaf-count CVM test can run
  without another reset if it goes first.
```

## Agent handoff — 2026-07-28 (slice 3 closed)

```text
Last merged PR / main SHA: #80 / see main after merge
Active branch / HEAD: merged; no active remediation branch
Dirty or untracked files preserved: yes — third_party/{icicle-snark,rapidsnark}
  working-tree edits untouched; every pre-existing untracked path (audit_1/,
  dstack/, phala-docs/, circuits/build/*/verification_key.json, the .docx, etc.)
  left exactly as found and never staged.
Active slice and finding IDs: slice 3 — DEP-AU-07 (Closed), T-04 (Code complete,
  standing invariant), T-03 (Deferred — mainnet gate)
Invariant and compatibility decisions:
  - Unauthenticated /v1/stream sockets get an ABSOLUTE 10 s window no frame
    extends; authenticated sockets keep the idle timeout so legitimate quiet
    sessions survive. Venue + per-account caps via RAII guards.
  - Per-peer caps deliberately omitted: one apparent source address behind the
    gateway makes an IP-keyed cap a venue-wide outage with no attacker cost.
  - Every image in every compose must be digest-pinned AND from an allowlisted
    repository. Adding a repository is the deliberate approval step.
  - No compose change, so no compose_hash rotation and no ceremony.
Commands run and exact results:
  cargo fmt --check / clippy -D warnings          -> clean / zero warnings
  cargo test --workspace                          -> 617 passed, 0 failed
  REQUIRE_CIRCUIT_ARTIFACTS=1 cargo test -p darknyx-tee --tests -> green
  cargo test -p darknyx-tee --test stream_conn_limits -> 7 passed
  check-dependency-audits.sh                      -> PASSED, no new advisories
  tsc sdk+indexer; vitest sdk 270 / daemon 147 / indexer 20 -> all pass
  hosted CI run 30336791498                       -> every job green
  mutation: deadline disabled -> 2 ping tests FAIL (as required)
  mutation: tagged image / unapproved repo -> guard REJECTS both
  mutation: quoted valid image -> ACCEPTED; quoted tag -> still REJECTED
Live state: NO CVM used or started; billing untouched. Devnet unchanged —
  no deploy, no tree reset, no signer rotation. Images still pinned at CPU
  sha256:98f61dc3… / GPU sha256:eda803e3…; tree still fresh from slice 1.
Evidence still missing: none for this slice. The transport cost-table row
  (HTTP/WS p50/p95, RSS per socket, image-size delta) is deferred WITH T-03 and
  should be captured in the CVM window that ships the transport change.
Blockers: none.
Exact next action: start slice 4 (`remediation/settlement-recovery`, T-06).
  Its prerequisite was relaxed to "slice 3 code complete" and slice 3 is now
  closed, so it is unblocked. Slice 4 needs NO CVM for its unit/crash-point
  work; a CPU-CVM restart mid-settlement is required before it can close.
  Do NOT reopen T-05. Do NOT start T-03's transport work without the product
  decision on browser clients — the trigger list is in the slice-3 section.
```

## Findings raised during slice-1 review — 2026-07-27

Automated review of the slice-1 PR surfaced two issues in code the slice itself
introduced. Both were validated against the tree before being accepted, and both
were fixed in the same PR:

- **Conflicting-replay false positive.** The batch validator treated *any*
  entry sharing a `publish_time_ms` with the cached one as a conflict unless the
  sequence also matched. Pyth's `publish_time` is second-granular while Pythnet
  aggregates sub-second, so consecutive genuine updates routinely share a publish
  second with a new sequence and a moved price — normal cadence was classified as
  an attack and failed the whole refresh. The insert predicate immediately below
  already skipped only on *both* fields matching, so the two predicates
  disagreed; the conflict check was the wrong half. Now only an identical
  `(publish_time_ms, vaa_sequence)` pair with differing authenticated content is
  a conflict. Regression test:
  `same_publish_second_with_a_newer_sequence_is_accepted`.
- **A test that could not fail for its stated reason.**
  `exact_replay_does_not_refresh_local_arrival` read at a moment when signed and
  local clocks were *both* stale and accepted either error, so it passed whether
  or not the replay refreshed local arrival. Retimed so signed freshness is still
  valid while local arrival is stale, and it now asserts `LocalStale`
  specifically. Same class as T-12.

Two further findings were validated as real but deliberately **not** fixed here,
because both are larger than this slice and neither is reachable in the current
single-market deployment:

- **T-17 — venue-wide oracle pause.** `TradingGate` is one shared
  `Arc<AtomicU8>` of reason bits, cloned into every market driver, so
  `TradingPauseReason::Oracle` is global: one market's stale feed pauses all
  markets, and a healthy market's tick clears the bit for a still-stale one.
  Latent today (one configured market), real for multi-market. Fixing it means
  per-market pause state, which touches the multi-market model — see
  `docs/multi-market-architecture.md`.
- **T-18 — the aggregate CI gate can pass while nothing runs.** Observed live on
  this PR: `Detect changed paths` failed, every real job reported `skipping`, and
  `pr-checks success` still reported **pass** in 3 s. A merge rule keyed on that
  check would have merged with zero tests executed. Same shape as T-11/T-12, and
  more dangerous, because it is the top-level check. Filed into slice 2.

## Slice-1 closure status — why rows are not yet `Closed`

PR #77 merged as `e2b13b5` on 2026-07-27. Code is merged and the live evidence
in the table above was captured, so `T-01`, `T-02`, `T-04`, `T-16`, and `RD-01`
are at `Code complete`. `RD-03` is `Closed` — it is a documentation correction
with no measurement obligation.

The remaining rows are held short of `Closed` by the cost table's **mandatory
closing measurement**, which is only partly satisfied:

| Required measurement | Status |
|---|---|
| Time from last good update to matcher/intake pause | Partial — boot-to-resume measured at 483 ms; the pause direction was not timed |
| Oracle refresh CPU and p50/p95 duration | **Not captured** — refresh timing logs at `debug`, compose pins `darknyx_tee::oracle=info` |
| Requests per refresh for 1 and N feeds | **Not captured** — only the 1-feed case ran |
| Conversion benchmark, equal vs unequal decimals | **Not captured** — correctness is unit-tested, cost is not benchmarked |

`T-04` additionally stays open by design: its row makes digest pinning a standing
release invariant, so it closes only once the ingress image introduced in slice 3
is also pinned.

Capturing the missing three requires a CVM run, and the evidence-vintage caveat
above already requires a rebuild-and-re-pin before the next one. Both obligations
should be discharged together rather than spending two CVM windows.

**Prerequisite tension to resolve.** Slice 2 (`remediation/local-assurance`)
lists its prerequisite as "Slice 1 closed", which the above blocks. Slice 2 is
CI/test/build tooling with no dependency on oracle measurements or a CVM, so the
sequencing intent is satisfied by slice 1 being *code complete and merged*. Either
relax that prerequisite to "Slice 1 code complete", or schedule the measurement
CVM run first. This is an owner decision and is deliberately not taken here.

## Slice 1 closing measurements — 2026-07-28

Captured in a single CVM window on `nightly-test-cvm` (`app_9ca3cded…c14db637`,
CPU, `gpus=0`, prod9), running an image rebuilt from **merged** source
(`tee-v3-hardening-75`, commit `5d11188`) —
`@sha256:98f61dc3bbbf505e501b2d208618ce2a601e1a443ae73b63f90ae053ebfbe339`,
confirmed live via `phala ps`. This **discharges the evidence-vintage caveat**:
the digest now pinned in the compose is the image that was measured and settled
against. The rebuild was necessary rather than ceremonial — the new digest
differs from `tee-v3-hardening-74`'s, because the review fixes changed the binary.

### Oracle refresh cost (live)

| Config | Samples | min | p50 | p90 | p95 | p99 | max | mean |
|---|---|---|---|---|---|---|---|---|
| 1 feed (SOL-USDC) | 144 | 91 | **99** | 244 | **246** | 287 | 377 | 124.3 |
| 2 feeds (SOL-USDC + BTC-USDC) | 160 | 91 | **98** | 245 | **250** | 288 | 392 | 124.8 |

All values milliseconds, at the 1 s refresh cadence.

**Requests per refresh: `hermes_requests=1` on every one of the 304 samples, at
both 1 and 2 feeds.** The batching invariant holds, and the latency numbers show
why it matters: doubling the feed count moved p50 by −1 ms and the mean by
+0.5 ms — both inside run-to-run noise. A second market costs essentially nothing
per refresh because it rides the same request. Refresh duration is dominated by
the Hermes round trip, not by per-feed verification work.

### Conversion cost (host, release, 1M iterations after warmup)

| Path | Cost |
|---|---|
| Equal decimals | ~8.1 ns/op |
| Unequal decimals | ~15.9 ns/op |

Unequal decimals costs ~2x — the extra `10^(e+q-b)` scaling step. Against a p50
refresh of 99 ms, conversion is ~7 orders of magnitude smaller, so the checked
integer arithmetic introduced for T-16 is not a matcher-path cost.

### Time from last good update to pause

Pinned deterministically by `pause_threshold_is_exactly_max_age` rather than
timed on the CVM: the sync loop pauses on the first cycle whose post-refresh
snapshot is unhealthy, so the bound is `max_age_ms` + at most one tick interval.
The test asserts healthy at exactly `max_age_ms` and unhealthy one millisecond
later. This is stricter than a wall-clock observation — it cannot be confounded
by Hermes latency or host scheduling, and it fails if the window is ever widened.
The recovery direction was observed live at **398 ms** from boot (`trading starts
PAUSED` → `trading RESUMED`), with both markets adopted and both matcher drivers
spawned.

### Re-validated settle

`cvm-settle-e2e` passed (45.1 s) against the merged-source image. Tx D confirmed
at slot `479390196`, `confirmed=1 rejected=0 ambiguous=0`. Pipeline
`total_ms=15310` — lock 1543, prove 2240, verify 1363, ALT 1254 + wait 796,
settle 11661, close 0. Within noise of the pre-fix run (`14573`); the settle
send dominates and is network-bound.

### Image identity

| Variant | Tag | Digest |
|---|---|---|
| CPU | `tee-v3-hardening-75` | `sha256:98f61dc3bbbf505e501b2d208618ce2a601e1a443ae73b63f90ae053ebfbe339` |
| GPU | `tee-v3-hardening-75-cuda` | `sha256:eda803e3c16cc6a4443444857b560a3dcf4f6e3126c0545a31cf81e30b3dcf66` |

Signer set unchanged from the earlier run (same `app_id`), so the existing
`tee_pubkeys` rotation and funding remained valid; no re-rotation was needed.
CVM **stopped** after capture; billing halted.

### Resulting status

`T-01`, `T-02`, `T-16`, and `RD-01` move to **`Closed`** — merged code plus every
measurement their rows and the cost table require. `RD-03` closed in #77.

`T-04` deliberately remains **`Code complete`**: its row makes digest pinning a
standing release invariant, not a one-time cleanup, so it closes only once slice
3's ingress image is also pinned. Both current images are digest-pinned and the
release record above maps source → tag → digest → live container.

## Slice 2 evidence — `remediation/local-assurance`, 2026-07-28

No CVM and no devnet mutation: this slice is CI, test, and build tooling.

### The shape of the slice

T-11, T-12, T-13 and T-18 are one defect wearing four hats — **a gate that
reports success without checking anything**. Each is worse than an absent gate,
because each converts "not verified" into a positive signal that a human or a
branch-protection rule then trusts.

| ID | What was actually happening | Verified by |
|---|---|---|
| T-18 | `ci-success` listed `changes` in `needs` but never read its result. Every other job's `if:` reads `needs.changes.outputs.*`, so a failing `changes` skipped all nine — and `skipped` was accepted as "not relevant". Observed live on PR #77: **`pr-checks success` reported pass in 3 s with zero tests run.** | `changes` result now checked and `skipped` not accepted for it; YAML parse confirms wiring |
| T-11 | **No workflow ran `cargo test -p darknyx-tee`.** 799 tests (305 lib + 494 integration) — matcher, settle, Merkle mirror, oracle, HTTP/auth, and every Phase A / `AU-` regression test — were local-gate-only | new `tee` job; 305 + 494 pass locally |
| T-12 | S-02's positive test returned early when circuit artifacts were absent (two of three are gitignored) and reported PASSED without proving | hid `circuit.r1cs`: required mode **fails**, default mode skips. 18.73 s proving vs 0.00 s skipping |
| T-13 | `target/deploy/vault.so` is tracked by no test dependency, so the suite validated whatever binary was on disk. Bit this repo on 2026-07-27 | 4 failure modes + a real source edit; see below |

### T-13 — why a fingerprint and not a timestamp

An mtime check answers "was this written after the source?", which is wrong in
both directions: `git checkout` and `touch` move mtimes without changing code,
and a rebuild with a **different feature set** leaves a *newer* artifact that is
still the wrong binary — `devnet-admin` on/off changes which instructions exist
at all. `scripts/vault-sbf-fingerprint.sh` is the single definition, re-run by
the tests rather than reimplemented, so the build and check sides cannot drift.

Verified: hand-edited fingerprint → STALE; features without `devnet-admin` →
rejected at load; missing manifest → refused; and a real one-line edit to
`programs/vault/src/lib.rs` changed the fingerprint and made all 6 tests refuse,
with revert restoring green.

### T-15 — mutation-tested, not just green

Three new LiteSVM tests in `programs/vault/tests/withdraw_lock_lifecycle.rs`:
live-lock rejection (asserting the **specific** `NoteAlreadyLocked` error, since
a bare `is_err()` would pass for any failure), expiry-boundary success with no
release call, and `release_lock` → rent refunded → withdraw succeeds.

Reverting `withdraw.rs` to the pre-S-03 reject-on-existence behaviour and
rebuilding made `withdraw_succeeds_at_the_expiry_boundary_without_a_release`
**FAIL** while the other two correctly still passed. The tests discriminate the
regression they exist for, rather than merely passing.

Also wired two orphaned targets into CI: `initialize_governance` and
`market_config` are integration tests, so `cargo test -p vault --lib` never
reached them and no job listed them.

### T-08 — triaged, not suppressed

All four Rust advisories are accepted individually in `.cargo/audit.toml`, each
with its `cargo tree -i` analysis:

| Advisory | Crate | Disposition |
|---|---|---|
| RUSTSEC-2022-0093 | ed25519-dalek 1.0.1 | dev-only: `litesvm [dev-dependencies]` → not linked into any deployed artifact |
| RUSTSEC-2024-0344 | curve25519-dalek 3.2.0 | same chain, one level deeper |
| RUSTSEC-2026-0185 | quinn-proto 0.11.14 | lockfile-only — `cargo tree` reaches it from no workspace member |
| RUSTSEC-2025-0055 | tracing-subscriber 0.2.25 | compiled in via ark-relations, but our logging installs the workspace 0.3; the 0.2 copy is never the global subscriber |

The npm production tree carries a **pre-existing backlog of 9 advisories**,
recorded in `audit-baseline/npm-production.txt`. Blanket-ignoring would defeat
the gate on day one; failing on the whole backlog would teach everyone to bypass
it. So the baseline is visible, diffable, and expected to shrink — anything not
in it fails. Verified by deleting one line: the gate failed naming
`GHSA-3gc7-fjrx-p6mg bigint-buffer high`.

**Owed, and deliberately not claimed as done:** the 9 npm advisories are
*recorded*, not *triaged*. Each still needs the reachability analysis the Rust
side got. `bigint-buffer → @solana/buffer-layout-utils → @solana/spl-token` is
the one in a genuine production chain and should be looked at first.

All 56 action references across the 7 workflows are now pinned to full commit
SHAs with the tag kept as a trailing comment. Note `dtolnay/rust-toolchain@1.89.0`
resolved to a **branch**, not a tag — branches move by design, so it needed
pinning more than the rest, not less.

### Status

T-08, T-11, T-12, T-13, T-15, T-18 → `Code complete`. They reach `Closed` when
this merges and one hosted run of the new `tee` and `deps-audit` jobs succeeds —
T-11's row requires exactly that, and claiming closure from a local run would
repeat the mistake the slice exists to fix.

### Slice 2 closure — hosted evidence, 2026-07-28

PR #79 CI green on `fb30dff`, with the two new jobs **executing** rather than
skipping — which is precisely what T-11's row required, and what a local run
could not have established:

| Job | Result | Evidence it really ran |
|---|---|---|
| `TEE — matcher, settle, oracle, auth` | pass, 6m24s | `real_valid_input_proof_is_accepted_at_intake ... ok` took ~37 s under `REQUIRE_CIRCUIT_ARTIFACTS=1` — real proving, not a skip |
| `Dependencies — cargo audit + npm audit` | pass, 3m45s | cargo-audit 0.22 against the triaged `.cargo/audit.toml`; npm compared to the 9-entry baseline |
| `Vault LiteSVM` | pass, 2m24s | includes the three new `withdraw_lock_lifecycle` tests and the two previously orphaned targets |

The first hosted attempt **failed**, and both failures were real — the gates
caught what the local run could not: the `circuit-build` artifact was missing
`circuit.r1cs` (so nothing downstream could prove), and cargo-audit 0.21 could
not parse the CVSS 4.0 entries the RustSec DB now ships. Note `pr-checks success`
correctly went red alongside them; pre-T-18 it would have reported pass.

T-08, T-11, T-12, T-13, T-15, T-18 → **`Closed`**. CT-01 is satisfied: the S-03
row's claimed withdraw/release-lock evidence now exists and runs hosted.

**Still owed from this slice** (recorded, not silently dropped): the 9 npm
advisories are *recorded*, not *triaged* — each needs the reachability analysis
the four Rust ones got, starting with
`bigint-buffer → @solana/buffer-layout-utils → @solana/spl-token`, the only one
in a genuine production chain.
