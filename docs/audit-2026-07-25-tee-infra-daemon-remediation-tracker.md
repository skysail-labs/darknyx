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
6. Run the reasonable equivalents of affected CI gates locally before pushing.
   GitHub Actions and CodeRabbit are available again as of 2026-07-29: wait for
   both on every remediation PR, inspect their actual output, and do not infer a
   review from a green aggregate status.
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
| Last verified `main` | `0237cdd` (slice-7 tracker closure PR #89 merged 2026-07-29) |
| Last merged remediation PR | #89 — slice-7 tracker closure, merge commit `0237cdd`, merged 2026-07-29. |
| Active slice | slice 8 — T-17 multi-market oracle isolation |
| Active branch / PR | `remediation/multi-market-isolation` / PR #90 |
| Next slice | none after T-17; T-03 remains explicitly deferred to its mainnet/external-user trigger |
| Live state | **No CVM running; billing halted** after the slice-5 validation window (2026-07-29). Image `tee-v3-hardening-77` @ `sha256:5358ac5bad79cd55c5f7d185bddaafed29fa646d51be3b0ba70b2bc812906436` on `nightly-test-cvm` (CPU, prod9). Devnet tree left freshly reset from the final `cvm-merge-then-order` cycle, holding only that test's leaves. Signer set unchanged; all four shards funded. PRIOR (slice 4): Image `sha256:59e2932f40da51675fd6a9d854715d1fd6681a824f2fc4c8e75c4907ee7bbfda` (tag `tee-v3-hardening-76`, commit `3a93570` — the tag and commit are cross-references only; the digest is the identity). Signer set unchanged; all four shards funded. Devnet tree holds the drill's 2 deposit leaves. Slice 2 is CI/test/build tooling and required no CVM or devnet mutation. Images pinned by digest from the merged-source rebuild — CPU `sha256:98f61dc3bbbf505e501b2d208618ce2a601e1a443ae73b63f90ae053ebfbe339` (tag `tee-v3-hardening-75`), GPU `sha256:eda803e3c16cc6a4443444857b560a3dcf4f6e3126c0545a31cf81e30b3dcf66` (tag `tee-v3-hardening-75-cuda`). Devnet tree left freshly reset from the slice-1 closure run. |
| Last updated | 2026-07-30 (slice 8 T-17 code complete locally; hosted and live evidence pending) |

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
- At the audit baseline, the Pyth integration hard-coded the legacy 13-of-19
  Wormhole trust profile and called Hermes without an authenticated, versioned
  cutover path. Slice 1 replaced that behaviour; the statement is retained as
  historical provenance, not current architecture.
- Pyth's current primary-source migration guidance says Pyth Core moves to
  five routers with a 3-of-5 quorum and that Hermes authentication becomes
  mandatory on 2026-08-18:
  [upgrade overview](https://docs.pyth.network/price-feeds/core/upgrade),
  [preparation guide](https://docs.pyth.network/price-feeds/core/upgrade/preparing),
  and
  [upgraded trust model](https://docs.pyth.network/price-feeds/core/upgrade/how-it-works).
- The audit findings and agreed remediation decisions were re-read rather than
  inferred from the status labels in the earlier tracker.
- Slices 1–5 were independently revalidated against merged `main` at
  `f7ad8c2` on 2026-07-29. The exact code, test, and residual findings are
  recorded in the revalidation section below.

## Slices 1–5 independent revalidation — 2026-07-29

This pass did not infer correctness from merged PR status. It re-read the
finding invariants, followed each changed boundary in the merged code, and
re-ran the relevant local suites from `main` at `f7ad8c2`.

| Slice | Revalidated boundary | Result |
|---|---|---|
| 1 — oracle trust | Versioned trust profiles, authenticated batched Hermes intake, signed-time freshness, matcher-side enforcement, atomic-unit conversion, digest-pinned CPU/GPU compose | Invariants present; digest and CUDA-env guards pass. The recorded live CVM evidence remains the required evidence for the network/attestation path. |
| 2 — local assurance | Aggregate CI dependency wiring, dependency-audit script, required circuit-artifact mode, shared SBF fingerprint, withdraw/lock lifecycle | Source wiring is intact. The SBF guard correctly rejected a stale binary, `build-vault-sbf.sh devnet-admin` refreshed it, and `withdraw_lock_lifecycle` then passed 3/3. |
| 3 — transport integrity | Absolute unauthenticated login deadline, venue/account caps, general compose digest guard, corrected user-facing transport claims | Invariants present and covered by the complete TEE suite. T-03 remains deliberately deferred under its recorded mainnet/external-user trigger; this is not an unimplemented part of the shipped cap work. |
| 4 — settlement recovery | Write-ahead journal ordering, chain/PDA reconciliation, indeterminate retention, batch-id seeding, damaged-journal preservation, drain gate | Invariants present and covered by the complete TEE suite. The earlier CPU-CVM crash/drain drill remains the live evidence; no persistence or settle code changed in this pass. |
| 5 — canonical order v5 | Rust/TS layout and domain parity, removed live wire field, raw daemon commitment, OpenAPI/client compatibility | Live protocol surfaces are clean and the focused SDK canonical tests pass 23/23. The prior six-test CVM run remains valid because no order/TEE/on-chain code changed after its merged baseline. |

Commands and exact results:

- `cargo nextest run -p darknyx-tee -p darkpool-matcher --no-fail-fast`:
  **607 passed, 3 skipped**.
- `cargo test -p vault --test withdraw_lock_lifecycle` after the deliberately
  stale SBF guard fired and `bash scripts/build-vault-sbf.sh devnet-admin`
  refreshed the fingerprint: **3 passed**.
- daemon TypeScript test-config typecheck: pass; pre-slice daemon suite:
  **147 passed, 2 environment-gated skipped**.
- focused SDK canonical/order tests: **23 passed**.
- `check-compose-image-digests`, `check-icicle-cuda-arch-env`, and
  `check-no-doctests`: pass.

The combined Rust run first encountered `ENOSPC` with only 132 MiB free. After a
package-scoped `cargo clean -p darknyx-tee -p darkpool-matcher` reclaimed
9.0 GiB, a sandboxed retry reached a loopback-bind denial and the same command
then passed outside that network sandbox. Neither failure was a product-test
failure.

The dependency audit was not re-run in this pass: the local sandbox could not
write Cargo's advisory database, and approval for the networked npm audit was
denied because it would disclose private dependency metadata. Slice 2 therefore
continues to rely on its already-recorded dependency evidence; this pass does
not claim fresh audit output.

One residual was found in slice 5's evidence wording. Live and public protocol
surfaces are free of the retired field, but
`programs/vault/tests/settle_harness/mod.rs` still contains unused legacy
`PendingOrder`/`DarkCLOB` fixture helpers carrying an order-level
`user_commitment`. No test or production path constructs them. Deleting that
dead fixture belongs with slice 7's repository/deletion sweep, not this
keystore slice. A stale `scripts/dev-commands.md` reference to canonical order
v4 was corrected here. PF-10 remains `Closed`: the wire, heap, signature-domain,
and live-path invariant it owns is satisfied; the earlier phrase
"repository-wide sweep clean" is narrowed accordingly.

---

## Security and correctness findings

| ID | Severity | Owner | Planned remediation slice | Invariant / required evidence | Status |
|---|---|---|---|---|---|
| T-01 | High | TEE oracle | `remediation/tee-oracle-trust` | Only an explicitly versioned Pyth emitter/signer profile is accepted. A guardian-signed non-Pyth message, wrong emitter, wrong signer set, or insufficient quorum is rejected by fixture tests before its root reaches the cache. | Closed |
| T-02 | High | TEE oracle + matcher | `remediation/tee-oracle-trust` | Freshness uses signed publish time and local arrival health; feed state rejects stale, replayed, or non-monotonic updates. `OracleCache::snapshot` no longer fabricates `publish_slot = slot_now`, and `darkpool_matcher::validate_oracle` enforces the freshness data it reports instead of checking only `twap != 0`. Clock-skew, direct-matcher bypass, and out-of-order boundary tests pin the policy. | Closed |
| T-03 | High | TEE + infrastructure + SDK | `remediation/tee-transport-integrity` (transport work deferred) | **Rationale corrected 2026-07-28.** The finding's stated basis — "order intent is plaintext at the operator's gateway" — is wrong: the dstack gateway is itself an attested TDX CVM that mutually attests with our CVM and tunnels over WireGuard, so no unprotected hop carries plaintext. The real, still-valid exposure is narrower: (a) clients pin our measurement but not the gateway's, so that component can change with no Darknyx governance event, and (b) nothing binds the verified quote to the TLS session it was fetched over, so a party holding a valid gateway-domain certificate can front a different backend. Invariant to close: TLS terminates inside the Darknyx enclave with an attestation-bound certificate the client verifies, and the public route cannot reach plaintext 8080. | **Deferred — mainnet gate** (see the slice-3 section for the trigger, both costed options, and the DNS migration playbook) |
| T-04 | High | Release engineering + infrastructure | `remediation/tee-oracle-trust`, then enforced for `remediation/tee-transport-integrity` | The existing CPU/GPU images are pinned by immutable digest in the oracle slice, which already changes the image and compose. Every image introduced later, including ingress, must be digest-pinned before that slice can merge. Release evidence maps source/tag/digest/compose hash, so substituting a tag cannot preserve an accepted measurement. | Code complete — enforcement generalised in slice 3: `scripts/check-compose-image-digests.sh` now checks EVERY image in EVERY compose against an explicit repository allowlist, instead of asserting a single hardcoded image. An ingress (or any other) service added later fails the gate until it is digest-pinned AND its repository is deliberately approved. Verified by mutating a compose in both directions. |
| T-05 | Medium | — | — | Owner accepted the residual append-only-mirror availability risk on 2026-07-27. Confirmed commitment plus on-chain root validation is considered sufficient for the current product; a rollback can stall witness service but cannot authorize custody loss. No code, test, infrastructure, or follow-up task is authorized. | **Won't Fix — accepted risk** |
| T-06 | Medium | TEE settlement + daemon | `remediation/settlement-recovery` | Every side effect in an in-flight settlement is synchronously journaled before submission, then reconciled against signatures, marker/lock/consumed PDAs, and chain state after restart. Resting orders are not resurrected; the daemon submits a fresh signed order when appropriate. | **Closed** — journal, boot reconciliation, and drain merged; live crash-recovery drill passed on `nightly-test-cvm` 2026-07-28 (interruption confirmed on-chain, recovery classified correctly, entries retired, drain lifecycle exercised). Procedure + results: [`settlement-recovery-drill.md`](settlement-recovery-drill.md). |
| T-07 | Medium | Matcher + TEE + SDK + daemon | `remediation/order-canonical-next` | The unused order-level `user_commitment` and the daemon's corrupting workaround are removed across Rust/TS wire and canonical types. Global wallet owner/user-commitment cryptography remains intact. Canonical domains and fixed parity vectors move atomically. | **Closed** — field removed from `OrderCanonical`/`Order`/`OrderSnapshot`/`MatchPair`/`PlaceOrderRequest` + the TS mirrors; the `[0] != 0` intake check and error code 1002 retired; the daemon's `uc[0] = 0` zeroing deleted so `userCommitment()` is again the raw `create_wallet` output. `ORDER_DOMAIN` v4→v5, both pinned digests regenerated from the layout spec independently of either encoder. **Live-validated 2026-07-29**: all six CVM tests passed on the v5 body, incl. two real on-chain settles (`confirmed=1 rejected=0 ambiguous=0`). |
| T-08 | Medium | Release engineering | `remediation/local-assurance` | Rust and production Node dependencies have locally reproducible vulnerability gates; GitHub Actions use full immutable SHAs and minimum permissions. Findings are triaged rather than hidden by blanket ignores. | Closed |
| T-09 | Low | Daemon custody | `remediation/daemon-keystore-v2` | New keystores use the fixed v2 scrypt profile `N=2^17, r=8, p=1` with explicit memory bounds. KATs, wrong-passphrase, and resource-bound tests pin the profile. | **Closed** — fixed profile, explicit 256 MiB ceiling, pinned full-envelope KAT, wrong-passphrase and resource-bound tests merged in PR #86; local and hosted daemon/typecheck gates passed. |
| T-10 | Low | Daemon custody | `remediation/daemon-keystore-v2` | Unauthenticated file fields cannot select weaker KDF work. Version/profile, lengths, and AAD are strict; v1 files migrate through decrypt-validate-atomic-reseal without destructive partial writes. | **Closed** — exact v1/v2 schemas, bounded decode, metadata AAD, semantic plaintext validation, and atomic migration merged in PR #86; destructive-failure and recovery tests passed. |
| T-11 | Medium | Release engineering + TEE | `remediation/local-assurance` | The complete `darknyx-tee` suite is an explicit local pre-PR gate now and a dedicated hosted job once artifact quota resumes. Slow artifact-backed tests remain separately identifiable. | Closed |
| T-12 | Medium | TEE tests + circuits | `remediation/local-assurance` | Artifact-required mode fails loudly when circuit artifacts are absent; no positive proof test can report success without proving. Casual local mode may skip only when the required-mode flag is absent and must report the skip. | Closed |
| T-13 | Low | Vault tests + build tooling | `remediation/local-assurance` | All LiteSVM loaders share one SBF artifact guard backed by a build manifest/source fingerprint, not a fragile per-test mtime check. A changed vault source or build configuration makes tests fail until `cargo build-sbf` refreshes the artifact and manifest. | Closed |
| T-14 | Low | Vault + TEE + SDK | `remediation/tee-bounds-cleanup` | The retired `NullifierEntry`, seeds, PDA helpers, comments, and public exports are absent across the program, TEE, SDK, scripts, and docs. The commitment-keyed consumed/deposit guards remain untouched. | **Closed** — dead program/TEE/SDK surfaces and the self-contained legacy order fixtures were removed in PR #88; deletion sweep, full local gate, hosted CI, and CodeRabbit passed. |
| T-15 | Low | Vault tests + tracker | `remediation/local-assurance` | LiteSVM covers live-lock withdraw rejection, expiry-boundary withdraw success, and `release_lock → withdraw` including rent return. The earlier S-03 row names only evidence that exists. | Closed |
| T-16 | Medium | TEE oracle + matcher + market config | `remediation/tee-oracle-trust` | Pyth-native price/exponent values are converted with checked integer arithmetic into the governed atomic base/quote price units before circuit-breaker comparison or collateral math. The invariant includes base decimals, quote decimals, exponent, and `price_scale`; unequal-decimal markets, exponent changes, unrepresentable scales, rounding, and overflow fail closed. | Closed |
| T-17 | Medium | TEE matcher + API | `remediation/multi-market-isolation` | `TradingPauseReason::Oracle` is scoped per market, not venue-wide. One market's stale or unauthenticated feed pauses only that market, and a healthy market's tick cannot clear another's oracle pause. A mixed configuration where some markets have no `oracle_feed_id` while `feed_ids` is non-empty is rejected at boot rather than silently sharing gate state. | **Code complete — local evidence**. Layered venue/market gates, concurrent per-feed failure fallback, market-routed intake/debug checks, strict config, and dynamic `/instruments[].trading_enabled` pass the local gates. Hosted CI/review, digest-pinned CVM boot/API evidence, merge, and tracker closure remain. |
| T-18 | Medium | Release engineering | `remediation/local-assurance` | A failure in the `Detect changed paths` job cannot leave the aggregate `pr-checks success` check green. The aggregate gate must fail (not pass) when any prerequisite job fails or is skipped due to an upstream failure, so a broken paths filter cannot silently disable the entire PR gate. | Closed |

## Performance findings

| ID | Severity | Owner | Planned remediation slice | Invariant / required evidence | Status |
|---|---|---|---|---|---|
| PF-08 | Perf-Nit | Daemon | — | Repeated trading-key derivation is real but not established as material. Reopen only when an intake/daemon profile identifies it as a material contributor to CPU or placement latency; then derive once per unlocked keystore session rather than add an unbounded cache. | Deferred |
| PF-09 | Perf-Nit | TEE prover | `remediation/tee-bounds-cleanup` | Rapidsnark `SHORT_BUFFER` handling has bounded retries, checked growth, and a maximum output/error buffer. A malicious or broken native prover cannot loop or allocate without bound. | **Closed** — PR #88 merged 3-attempt/64-KiB output ceilings and checked native lengths; eight adversarial tests, real native roundtrip, controlled latency measurements, full local gate, hosted CI, and CodeRabbit passed. |
| PF-10 | Perf-Nit | Matcher + TEE + SDK + daemon | `remediation/order-canonical-next` | The dead order-level `user_commitment` field consumes no wire, heap, serialization, or signature-domain space. Removal is proven by Rust/TS parity, API schema checks, and a live-surface stale-reference sweep. | **Closed** — signed canonical body `203 + S` → `171 + S` bytes (−32; 211 B → 179 B, −15.2% at `SOL-USDC`); one 32-byte field gone from `Order`, `OrderSnapshot`, and `PlaceOrderRequest`, two from `MatchPair`. OpenAPI `required` list and schema verified against the Rust struct by script (20 fields each way, zero drift). Live protocol/API/docs references are clean. The 2026-07-29 revalidation found unused legacy `PendingOrder`/`DarkCLOB` helpers in `programs/vault/tests/settle_harness/mod.rs`; they are not constructed by tests or production and are assigned to slice 7's dead-code sweep. Format-safe: the journal serializes `MatchResultPayload`, which never carried the field. **Live-measured 2026-07-29**: settle `total_ms=14523`, between the two prior samples (14573 / 14210) — the removal costs nothing measurable against a network-bound settle. |

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
| 1 | `remediation/tee-oracle-trust` | T-01, T-02, T-04, T-16, RD-01, RD-03 | Tracker baseline merged | Closed / PR #77, except standing T-04 remains Code complete until the deferred ingress image exists to pin | TEE oracle, matcher, config, and compose change; new image, encrypted Pyth credential, digest-pinned CPU/GPU images, compose-hash/client-pin/signer rotation. No circuit or on-chain format change. The hazardous GPU stop instruction is corrected while its compose is already changing. | Legacy and upgraded oracle fixture adversarial suite; unequal-decimal/exponent/overflow conversion tests; direct-matcher stale bypass rejection; local TEE gate; digest evidence; upgraded Hermes smoke; real-mint CVM cold boot and controlled crossing settle; stale/replay/auth failure pauses; secrets absent from logs and compose hash. |
| 2 | `remediation/local-assurance` | T-08, T-11, T-12, T-13, T-15, T-18 | Slice 1 closed | Closed / PR #79 | CI/test/build tooling plus LiteSVM tests; no protocol wire change. | Format/clippy/workspace/TEE tests, artifact-required negative, stale-SBF negative, named withdraw/release-lock LiteSVM tests, dependency reports, workflow/action-pin inspection. T-11 remains `Code complete` until a hosted run is available. |
| 3 | `remediation/tee-transport-integrity` | DEP-AU-07; T-04 enforcement; transport documentation correction. **T-03 deferred** | Slice 2 closed | Closed / PR #80 | **No compose change, no compose-hash rotation, no CVM, no ceremony.** Connection caps are code defaults; the digest guard is CI-only; the documentation corrections are text. Wire-visible additions only: a `503` on an over-capacity `/v1/stream` upgrade and error code `4290` on an over-cap login, both documented in the OpenAPI. | Real-socket connection-cap tests incl. the ping-only hold and its mutation test; digest-guard mutation test in both failure directions; OpenAPI parse; the standard local gate. |
| 4 | `remediation/settlement-recovery` | T-06 | Slice 3 closed | Closed / PR #81 | New versioned journal, Borsh-serialized in plaintext and protected ONLY by the dstack-sealed LUKS volume — there is no authenticated encryption at the `JournalSnapshot` boundary, and the row must not imply one. Adds `/admin/drain` (admin-gated) and error code `4290`; no other public wire change. | Unit crash points at every durable transition, corrupt/truncated journal failure, finalized-chain reconciliation cases, CPU-CVM restart mid-settlement, lock expiry/release, and daemon terminal/resubmit behavior. |
| 5 | `remediation/order-canonical-next` | T-07, PF-10 | Slice 4 closed, or external-integration trigger documented | **Closed** / PR #84 | Canonical signature and order wire break; old orders intentionally invalid. No circuit, note, or vault account change. | Rust/TS fixed-vector parity, REST/stream/daemon/loadgen tests, OpenAPI validation, repository stale-reference sweep, fresh-tree real-mint CVM settle. |
| 6 | `remediation/daemon-keystore-v2` | T-09, T-10 | Slice 5 closed | **Closed / PR #86** | Versioned local keystore migration; v1 read/migrate only, all new writes v2. Existing v1 files are replaced only after authenticated decryption, semantic validation, and a durable same-directory write. | Fixed KATs, wrong password, hostile headers/lengths, max-memory enforcement, interrupted migration, v1→v2 roundtrip, backup/import recovery. No CVM required. |
| 7 | `remediation/tee-bounds-cleanup` | T-14, PF-09; unused legacy settle-harness order fixtures found in slice-5 revalidation | Slice 6 closed | **Closed / PR #88** | SDK removal of dead exports; bounded internal FFI behavior; removal of the unused `PendingOrder`/`DarkCLOB` fixture helpers in `programs/vault/tests/settle_harness/mod.rs`. No live account or circuit migration. | Deletion checklist, SDK type/tests, workspace/TEE tests, bounded FFI adversarial sequences, docs/script stale-reference sweep including canonical order v4/v5 concepts. No CVM required. |
| 8 | `remediation/multi-market-isolation` | T-17 | Slice 7 closed | **Code complete locally** / PR #90 | Additive `/instruments[].trading_enabled` field; no canonical order, circuit, verifier key, account, transaction, journal, key, or devnet migration. TEE image/compose measurement changes because runtime source changes. | Mixed-feed boot rejection; shared-governance/isolated-oracle gate tests; stale/healthy two-market matcher and intake tests; batched-success plus per-feed-failure sync tests; OpenAPI/docs/daemon type parity; full local/hosted TEE gates. A digest-pinned two-market CVM boot/API spot-check remains before closure. |

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
| `settlement-recovery` | Observed 2026-07-28: settle `total_ms=14210` with the journal enabled, within the spread of the two pre-journal runs (14573 / 15310). Three samples across differing network conditions show the journal is not visible at this resolution — they do not establish that its cost is negligible. ~1684 B journalled per match (~26 KiB per transition for a 16-match batch). Restart→reconciled **436 ms**. | **Partially captured — WAIVER ACCEPTED by the owner 2026-07-29.** End-to-end timing, bytes/match, and restart-to-reconciled are measured ([`settlement-recovery-drill.md`](settlement-recovery-drill.md) §6). **Per-durable-transition write p50/p95 is NOT captured** — no instrumentation exists around `SettleJournal::record`. Accepted on the reasoning that the histogram and the end-to-end figure answer the SAME question (did adding an `fsync` slow settlement?), and the end-to-end figure answers it on the path that reaches a user: the journal-enabled run was the fastest of the three samples (14210 vs 14573 / 15310), so an `fsync` slow enough to matter would already be visible. Residual, stated plainly: three samples support "not visible at this resolution", not "negligible". Add the histogram if the settle path ever becomes CPU- rather than network-bound (e.g. GPU proving lands), because the proxy's whole validity rests on ~14 s of network time dominating. |
| `order-canonical-next` | Removes one dead 32-byte field plus JSON hex/serialization work; no proving or on-chain cost. | Canonical preimage bytes, REST/WS request bytes, serialized order size, and placement p50/p95 before/after. |
| `daemon-keystore-v2` | Deliberately increases unlock CPU/RAM; no trading hot-path cost after unlock. Apple M3/16 GiB measurement: v1 p50/p95 23.22/23.80 ms and 130.14 MiB process peak RSS; v2 203.76/248.25 ms and 247.27 MiB; wrong password 213.23/316.95 ms; migration 237.48/281.19 ms and 261.30 MiB; file 727→760 B. | Captured for the currently supported macOS arm64 development/client class; repeat on any newly supported materially lower-memory client before release. Full method and caveats are in the slice-6 evidence section. |
| `tee-bounds-cleanup` | Dead-state deletion is neutral/smaller; bounded FFI retries only affect error paths. | Binary/SDK bundle delta, normal-prove p50/p95 unchanged, and adversarial retry count/allocation ceiling. |
| `multi-market-isolation` | One additional atomic load per gate check and one market-gate lookup per place/modify; normal oracle refresh remains one Hermes request. Only the error path falls back to at most one request per unique feed (bounded by 16) so a bad feed cannot starve healthy markets. | Exact gate size/allocation delta, healthy batched request count, failed-batch fallback request bound, and targeted two-market intake/status behavior. Record live boot/API evidence only if a CVM spot-check is required. |

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
| CT-05 | Annotate PF-04 with T-14 follow-through; the on-chain removal is valid, but its dead public helpers remain until T-14 closes. | T-14 | Satisfied — PR #88 removed the retired account type and remaining program/TEE/SDK seeds, PDA helpers, and public exports; the earlier tracker now records the follow-through |

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

## Slice 4 evidence — `remediation/settlement-recovery`, 2026-07-28

### What was actually broken

`OpeningStore` and the settle pipeline's state were memory-only. The asymmetry is
what makes it a funds problem rather than an inconvenience: **an on-chain
`NoteLock` survives a restart and the enclave's ability to use or release it does
not.** After a redeploy — the documented way to roll an image or change env — the
enclave has no record it locked those notes, so affected users' collateral stays
frozen until expiry with no fill, no cancel, and no way to re-place, because the
surviving lock blocks a fresh `lock_note`.

### Write-ahead ordering is the design, not an implementation detail

Recording state *after* a side effect is worthless for recovery: the window that
matters is between "we sent something" and "we wrote down that we sent it". So
the settle signature is journaled **before** submission — possible because a
Solana signature is fully determined once the transaction is signed, and read back
out of the already-signed wire bytes. The invariant recovery depends on:

> If a transaction reached the network, its signature is already on disk.

Three write points: before the batch's first transaction (payload, both sides'
lock inputs including the relayed `VALID_INPUT` proof, batch root, deadline);
before the settle send (the signature); and on a terminal outcome (retire).
`Ambiguous` and `Pending` deliberately do NOT retire — those are exactly the
states a restart must reconcile.

The redrive deadline is the **earlier** of the two locks' expiries. Redrive is
only safe while both are live; the later one would authorise retrying a settle
whose buyer lock had already been swept.

### Durability gap found in the existing helpers

`persistence::auth` and `persistence::markers` write tmp → `fsync` → `rename`,
which makes the *contents* durable but not the *rename* — the directory entry
lives in the parent's metadata, so a crash can roll the file back to its previous
version. For rent bookkeeping that costs a sweep; for this journal it would make
recovery act on stale truth, so the journal also fsyncs the parent directory.
Recorded as a deliberate difference. **The older helpers are worth upgrading
separately and are not touched here.**

### Reconciliation trusts the chain, not the journal

The journal records *intent*; only the chain says what took effect.
Consumed-note PDAs are the authority because Tx D creates both atomically — the
same reasoning `worker::reconcile_consumed_pdas` already applies in-process, so
the two agree by construction rather than coincidence.

Two things discovered while wiring, both of which change behaviour:

- **Signature status is nearly useless at boot.** Without
  `searchTransactionHistory` the RPC keeps only ~150 slots, so after any restart
  worth recovering from the status is usually absent. A missing status resolves to
  `None`, not `false`, and falls through to the PDA check.
- **An RPC error is not a chain fact.** It resolves to `Inconsistent`, not
  `NeitherConsumed`, so a transient outage routes an entry to an operator instead
  of authorising a redrive. The convenient default was the dangerous one.

Exactly one PDA present is never inferred either way, and a signature reading
confirmed while neither note is consumed is reported as contradictory rather than
resolved to the convenient half.

Recovery registers every unsettled input note with the lock sweeper. Without
that, recovered entries would be observed and then forgotten — the original bug
with extra steps.

A damaged journal is loud and **non-fatal**: refusing to boot would also refuse to
run the lock sweeper, which is the mechanism that returns the collateral at risk.
"Nothing was in flight" and "the record is gone" are reported as different things.

### Drain (option C)

`GET|POST|DELETE /admin/drain`, admin-gated and documented in the OpenAPI.
`safe_to_stop` requires BOTH trading closed and nothing in flight, computed from
the journal rather than a timer — a timer would grant permission to stop
mid-settlement. Drain is its own pause reason, so a governance resume cannot
un-drain a CVM being taken down and an oracle recovery cannot re-open trading into
a draining enclave.

Resting orders are cancelled going down but not restored coming up. Not a
contradiction: a resting order is memory-only and its collateral is not locked
on-chain, so losing one costs a re-place and freezes nothing, while restoring a
signed intent after an arbitrary gap would re-book at a price chosen under
conditions that no longer hold.

The status discloses a non-persistent journal. A bare `safe_to_stop: true` there
would be technically true and practically misleading.

**Drain is not crash recovery** and the module says so at the top. If the two are
conflated the journal gets quietly weakened on the argument that "we drain before
redeploys anyway".

### Tests, and the mutations that make them mean something

| Check | Result |
|---|---|
| `cargo test --workspace` | 722 passed, 0 failed |
| Journal unit tests (durability, corrupt, truncated, version skew, round-trip) | 11 passed |
| Recovery decision table (every branch incl. both contradiction cases) | 11 passed |
| Pipeline wiring tests | 3 passed |
| Drain unit + endpoint tests | 6 + 6 passed |
| Mutation: settle signature journaled AFTER the send | wiring test **fails** — "the signature is being written AFTER the send" |
| Mutation: `safe_to_stop` ignores in-flight settlements | drain test **fails** — "must wait for in-flight settlements" |

The ordering test proves "before the send" **without a timing race**: the mock RPC
reads the journal from disk inside its own `sendTransaction` handler and reports
what it saw. Asserting after the run cannot distinguish "written before" from
"written after", which is the entire distinction that makes recovery possible.

One test was corrected rather than the code: `resume_for` reports whether the
WHOLE gate opened, not whether a bit cleared, so an early assertion misread the
API. The gate was right.

### Findings raised during slice-4 review

Automated review raised seven items and **all seven were valid**. Two would have
made the CVM window produce misleading evidence, which is the strongest argument
yet for running review before spending a window rather than after.

- **`batch_id` is boot-relative, so a new batch would overwrite recovered
  entries.** The scheduler assigns `batch_id` from 0 on every process start, so
  the journal key `(batch_id, match_idx)` does not survive a restart: the first
  new batch after recovery is batch 0 and `journal_batch_start` would overwrite
  the recovered batch-0 records — destroying a record while a settle may still be
  outstanding. Fixed by draining the journal at the end of the recovery pass,
  which removes the collision rather than papering over it.
- **Recovered entries were classified and logged but never retired.** An
  `AlreadySettled` entry — the common case — stayed on disk forever, so
  `/admin/drain` counted it as in-flight and `safe_to_stop` would never again
  become true on any instance that had ever recovered. Same fix.
- **The redrive deadline used the lock expiry alone.** The binding bound is the
  `BatchValidityMarker`, whose TTL is 300 slots (~2 min) against the lock's
  ~30 min, and which `tee_forced_settle_batched` reads. By the time a CVM has
  restarted the marker is usually dead while the lock is still live, so recovery
  would have classified as `Redrive` batches whose every redrive reverts. Now
  journals `marker_expiry_slot` and takes the min, mirroring
  `worker::settlement_deadline`. `None` (verify never landed) means no marker PDA
  exists and nothing to redrive against.
- **A damaged journal kept a live path, so the next write destroyed the
  evidence.** The boot logs "investigate before trusting settle state" and then
  the next batch renamed a fresh snapshot over the corrupt file — including the
  partially-decodable bytes of the realistic power-loss case. Now moved aside as
  `settle_journal.db.damaged-<ts>` before the new journal starts.
- **`match_idx` and `match_index` held the same value with different meanings**,
  permanently encoding a redundant invariant into an on-disk schema. Dropped.
- **`GatheredChain` implemented `ChainView` with a stub** answering
  `Inconsistent` for every input. Any future `decide(e, &gathered)` would have
  compiled and silently routed the whole journal to an operator. The impl is gone;
  `EntryChain` is the only `ChainView`.
- **A gate test passed without exercising its claim.** It asserted that a
  governance resume cannot open a draining gate, but never paused governance — so
  `resume()` returned `false` because the bit was never set, not because the drain
  blocked it. Same defect class this remediation keeps finding, this time in code
  written during it.

`is_redrivable` is now folded into `decide` rather than left to each caller, and
the `Redrive` log states plainly that **this build performs no automatic
redrive** — the previous wording read as though a resubmission were coming.

Four new tests pin the fixes: a dead marker releasing while the lock is live, an
entry that never verified, an unrebuildable entry released by `decide` itself,
and a damaged journal preserved rather than overwritten.

### Live evidence — crash-recovery drill, 2026-07-28

Full procedure, traps, and raw results:
[`settlement-recovery-drill.md`](settlement-recovery-drill.md). Summary:

| Assertion | Result |
|---|---|
| Journal written during a live settle | `in_flight_settlements: 1`, `safe_to_stop: false` captured mid-flight |
| Interruption confirmed by the chain, not the test | on-chain total `leaf_count=2` (deposits only; 7 would mean it settled) |
| Journal survived an abrupt VM stop on the LUKS volume | boot recovered 1 entry |
| Classification matched chain reality | `release_expired=1`, `already_settled=0`, `redrive=0`, `indeterminate=0`, `needs_operator=false` |
| Entries retired after recovery | `in_flight_settlements: 0` — the `batch_id`-collision fix, live |
| Unsettled notes handed to the sweeper | `lock sweeper: replaying un-released note locks from disk n=2` |
| Drain lifecycle | POST → `safe_to_stop: true`; DELETE → reopened |
| Restart → reconciled | **436 ms** |

`expired_at_slot=0` in the recovery line is the **marker-expiry rule working
live**. The kill landed before `verify_match_batch`, so no `BatchValidityMarker`
exists and there is nothing to redrive against. The pre-review revision
classified on the ~30-minute lock expiry alone and would have reported `Redrive`
here — every attempt would have reverted on the marker check. That review finding
was worth more than the code it corrected.

**Three honest limits on this run**, carried into the drill's §7 rather than
buried:

1. **`phala cvms stop` cannot land inside the ~10 s settle phase** — it is an API
   request for a VM shutdown, and the container outlives it. Three attempts
   completed their settle before the kill took effect. Only killing at the *first*
   journal write buys enough runway, which means the drill exercises the
   `Locking`-stage entry and **not** the `Settling` one. `AlreadySettled` and
   `Indeterminate` remain unit-tested only. Closing that needs `phala ssh` +
   `docker kill`, which needs development-mode SSH keys.
2. **No p50/p95 per durable transition.** No instrumentation exists around
   `SettleJournal::record`; the aggregate settle time is a proxy, recorded as one.
3. **The collateral outcome is not the journal's achievement.** Those two locks
   were already tracked by the pre-existing `pending_locks.db` sweeper (S-03(B)),
   which releases at expiry regardless. What the journal adds is a durable,
   *classified* record of the interrupted settlement in place of a boot that
   reports "nothing in flight" while a settle is incomplete.

A fourth, operational: **a tree reset does not empty the CVM's Merkle mirror.**
The mirror replays from `DARKNYX_TEE_SYNC_FROM_SLOT`, so a reset must be followed
by an env-only redeploy carrying a floor captured *after* the reset. Observed
mid-drill as on-chain `leaf_count=0` against a mirror reporting 7.

### Second review pass — slice 4

A follow-up review raised twelve items. Seven were already fixed in `3a93570`;
five were still open and are fixed here.

**One of my earlier "fixes" had not landed.** The gate test still asserted that a
governance resume cannot open a draining gate *without ever pausing governance* —
so `resume()` returned `false` because the bit was never set, and the assertion
proved nothing. The edit had targeted a string that changed underneath it and I
did not verify the result. Third instance of this defect class in the slice, and
the second time in code written to fix it.

Genuinely new and still open:

- **A failed journal write did not stop the send.** `journal_settle_attempt`
  logged an error and returned; the transaction went out regardless. That defeats
  the entire write-ahead ordering — a settle on the network whose signature never
  reached disk is exactly the unrecoverable orphan the design exists to prevent.
  It now returns a bool, a `None` signature is treated as failure, and only
  successfully-journaled matches reach the send pass. A disk fault now costs
  throughput (retry next round while the marker and locks are valid) instead of
  reconcilability. Pinned by
  `a_settle_is_not_sent_when_its_signature_cannot_be_journaled`.
- **Cleanup keyed differently from the write.** The journal was written under
  `MatchSettleInputs::match_index` and retired under the loop position. Equal
  today; a leak waiting for the first refactor that separates them, and a leaked
  entry looks like an in-flight settlement forever. Both are now passed
  explicitly.
- **Three dead fields in the on-disk schema.** `lock_buyer_sig`,
  `lock_seller_sig`, and `verify_sig` were declared and never written — worse than
  dead code, because a reader assumes recovery consults them. Removed; the module
  doc now promises only the settle signature, which is the one whose orphan is
  unrecoverable.
- **The tracker claimed an "encrypted journal".** There is no authenticated
  encryption at the `JournalSnapshot` boundary; the file is Borsh plaintext
  protected only by the dstack-sealed LUKS volume. Corrected — the row must not
  imply a property the code does not provide.
- **Three OpenAPI operations referenced an undefined `bearerAuth`.** The declared
  scheme is `BearerAuth`. A generated client would have emitted unauthenticated
  requests against `/admin/drain`. Fixed, with a parse-time check that every
  `security` reference resolves.

Also added on review: a drain test that places a **real signed order** and
asserts the book is actually empty afterwards. It is the only coverage of the
cancellation loop in `begin_drain`, which snapshots ids under a read guard and
cancels under a write guard — holding one across the other would deadlock, and no
amount of testing the drain helpers in isolation would reveal it.

Skipped: seeding `batch_id` above the highest recovered value. The recovery pass
already drains the journal, so no recovered key can survive to collide; adding a
second mechanism for the same invariant would mean two things to keep in step.

### Third review pass — slice 4

Twelve more items; two were duplicates already fixed, several were documentation
accuracy, and **one was a real defect in my own previous fix**.

- **Recovery retired `Indeterminate` entries.** The retire-all introduced last
  pass to kill the `batch_id` collision went too far: an indeterminate entry is
  precisely the case a human must inspect, and discarding it destroyed the only
  evidence at the moment it mattered *and* cleared the `/admin/drain` in-flight
  count, letting `safe_to_stop` go true with a settlement genuinely unresolved.
  Now only resolved actions are retired.
  That reinstates the collision risk for retained entries, so the
  `batch_id` seeding I skipped last pass — on the reasoning that retire-all made
  it unnecessary — is now implemented and tested
  (`SettleSchedulerState::seed_next_batch_id`). The reasoning for skipping it was
  only sound because of the behaviour that turned out to be wrong.
- **The evidence claimed more than three samples support.** "Below run-to-run
  noise" was a conclusion; `14210` against `14573 / 15310` supports only "not
  visible at this resolution". Reworded in both the tracker and the drill.
- **T-06 was `Closed` with a mandatory measurement missing.** Per-durable-
  transition write p50/p95 is listed as mandatory in the cost table and was never
  captured — no instrumentation exists around `SettleJournal::record`. Rather
  than let that sit unremarked under a `Closed` row, it is now an **explicitly
  recorded waiver**: T-06 is Closed on the owner's acceptance that the end-to-end
  figure is a sufficient proxy. **Accepted 2026-07-29.** The rationale and the
  condition that would invalidate it are in the cost-table row.
- **Abbreviated image digests.** `sha256:59e2932f…7bbfda` identifies nothing;
  both records now carry the full 64-hex digest, with the tag and commit marked
  as cross-references rather than identity.
- Markdown: a blockquote split by blank lines (MD028) in the runbook, fenced
  output blocks without a language in the drill, and a `SOLANA_RPC_URL` that step
  1a set inline and step 1b then expanded empty.

Skipped: nothing. Every item in this pass was either valid or already fixed.

### Status

`T-06` is **`Closed`**, with one explicitly recorded waiver, **accepted by the owner on 2026-07-29**: per-durable-transition write p50/p95 was not captured (see the cost table row for the rationale and for the condition — a CPU-bound settle path — that would require revisiting it). The waiver covers a PERFORMANCE measurement only. The open *correctness* gap is separate and still stands: the drill only ever exercised the `Locking`-stage journal entry, so `AlreadySettled` and `Indeterminate` remain unit-tested only, because `phala cvms stop` cannot land inside the ~10 s settle window — reaching them needs `phala ssh` + `docker kill` and development-mode SSH keys. Every other live obligation was discharged by the 2026-07-28 drill above, and the code merged in PR #81. The drill is repeatable — [`settlement-recovery-drill.md`](settlement-recovery-drill.md) carries the procedure, the pass criteria, and the traps — so a future settle-pipeline or persistence change can re-establish this evidence rather than re-derive how.

Superseded window plan (kept for provenance):

| Required evidence | Why local tests cannot supply it |
|---|---|
| CPU-CVM restart mid-settlement | The whole finding is about a real process dying with real on-chain locks outstanding |
| Drain → redeploy → clean boot | Proves the planned path leaves zero recovery work |
| Journal write p50/p95 per durable transition | Cost table |
| Bytes written per match | Cost table |
| End-to-end settle p50/p95 vs the no-journal baseline | Cost table |
| Restart-to-reconciled duration | Cost table |

**Window plan.** Pre-window and off the clock: merge, build a fresh tag, resolve
and pin its digest, allowlist the new `compose_hash`. No attestation-contract
change and no signer rotation is expected — dstack derives keys per `app_id`, and
slice 1 confirmed the set survives a digest change. In one window: reset the tree
→ deploy → baseline `cvm-settle-e2e` → **hard-kill mid-settlement and verify
recovery classified and resolved the entry rather than stranding it** → drain,
redeploy, confirm a clean boot → capture the measurements → stop the CVM after
confirming `resource.gpus` is 0.

**The risk to plan around:** the kill must be *hard* and land mid-pipeline. A
graceful stop drains cleanly and proves nothing.

**Post-window, non-optional.** Stop the CVM only after confirming `gpus: 0` —
stopping a GPU CVM deallocates it permanently and forfeits the prepaid window.
Securely delete every deployment secret bundle (`shred -u`, or `rm -P` on macOS)
and unset the exported credential variables; the deploy env carries the Helius
key and the bootstrap admin secret.

**Rollback.** Reverting the slice restores memory-only settle state. The journal
file is additive and simply ignored by an older binary, so no migration or wipe
is needed; `/admin/drain` and the `Drain` pause bit disappear with it. A rollback
does NOT invalidate settled trades, locks, or markers — nothing on-chain depends
on the journal. The only loss is the ability to reconcile an in-flight settlement
across a restart, which returns the deployment to the pre-slice behaviour the
lock sweeper already backstops.


## Slice 5 evidence — `remediation/order-canonical-next`, 2026-07-29

### What was actually broken

Three defects stacked on one field. Intake rejected any order whose
`user_commitment` had a non-zero top byte, justified in the code as "BN254
Fr-safety":

1. **The justification was false at HEAD.** The comment claimed "the matcher
   Poseidon-hashes this during change-note construction". It does not — v3
   output inners derive from the consumed input inner and `owner_commitment`.
   A repo-wide grep confirms `user_commitment` was never passed to Poseidon.
2. **The check was wrong on its own terms.** Fr-safety means "below the BN254
   scalar modulus". That modulus begins `0x30`, so a canonical element's top
   byte is any of `0x00..=0x30` — 49 values. Demanding exactly `0x00` rejected
   roughly **98%** of legitimate field elements.
3. **The client hid it by corrupting data.** `packages/daemon/src/keystore.ts`
   computed the real commitment and then did `uc[0] = 0`. Its own comment
   conceded the result: "this value is NOT a raw `create_wallet` Poseidon
   output" — so it could never match a `WalletEntry` registered on-chain, which
   is the one thing the value exists for.

### Why removal, not repair

Option B (fix the comparison, keep the field) was cheaper and was considered.
It was rejected because it leaves a field that nothing reads while *looking*
like a binding — the exact shape that let defect 1 persist. An unverified
identity field next to a verified one (`owner_commitment`) is worse than no
field, because a future reader reasonably assumes the signed one is load-bearing.

`owner_commitment` already carries the property the order needs, and carries it
honestly: intake re-derives `note_commitment` from it via `verify_commitment`,
so a caller cannot assert an owner for a note they do not own.

### Format-safety check performed before touching `MatchPair`

`MatchPair` derives Borsh and its doc claims it mirrors an on-chain struct, so
removing two fields from it needed proof it is not a persisted or wire type:

- The settle payload is `MatchResultPayload`, a separate struct that has never
  held a `user_commitment`.
- `JournalEntry.payload` (slice 4) is that same `MatchResultPayload` — the
  journal comment states the choice explicitly.
- `user_commitment_buyer` / `_seller` appear only in struct-literal
  construction; no read site exists anywhere in the workspace.

So the on-disk journal format and the on-chain instruction data are both
unchanged by this slice. Only the signed canonical body changes.

### Pinning the new digests honestly

`ORDER_DOMAIN` moves `darknyx-order-v4` → `v5`, which changes both fixture
digests. The replacement value was computed **from the layout spec in an
independent script**, then compared against what the Rust encoder produced —
not copied out of the failing assertion. Refreshing a pin by pasting back the
encoder's own output tests only that the encoder is deterministic, which was
never in question; it would have accepted a wrong-field removal silently.

Both encoders and the independent computation agree on
`d304e770f8f3fb706c7bb2bc6959002d9030b512f896f3fb518ba1ae4bd2b975`.

Two structural tests were added next to the digest pin, because a digest
mismatch is an opaque failure: one asserts the body shrank by **exactly** 32
bytes (a wrong-field removal keeps the total right while changing the meaning of
every later byte), and one asserts `arrival_nonce` now occupies the `+82` offset
that `user_commitment` vacated.

### Test changes, and why they are not just deletions

| Test | Before | After |
|---|---|---|
| `place_rejects_non_fr_safe_user_commitment` | asserted the defective check fired | replaced by `place_accepts_an_fr_safe_owner_commitment_with_a_non_zero_top_byte` — sets `owner_commitment = [0x2F; 32]` (a canonical element the old rule's logic would have refused) and asserts **202 + present in the book** |
| `error_responses_use_the_structured_envelope...` | drove the envelope via code 1002 | re-pointed at the all-zero `order_id` → 1001. What is under test is the envelope, not the validation that produced it |
| `keystore.test.ts` top-byte assertion | `expect(uc[0]).toBe(0)` — pinned the corruption | asserts the value equals the **unmodified** `userCommitmentFromKeys` output, plus full-width `< BN254_R`. A top-byte bound would NOT regress: the fixture's real top byte is `0x18`, and both `0x18` and a corrupted `0x00` satisfy `<= 0x30`. Mutation-tested — reintroducing `uc[0] = 0` fails it |
| `build-order-parity` | asserted `body.user_commitment` matched | asserts `body` has **no** `user_commitment` property |

Error code **1002 is retired, not recycled** — the constructor is deleted and the
number reserved in the catalogue comment, so a stale reference reads as "gone"
rather than silently meaning something new.

### Measured effect (PF-10)

| | v4 | v5 | Δ |
|---|---|---|---|
| Signed canonical body (`SOL-USDC`) | 211 B | 179 B | **−32 B (−15.2%)** |
| Body excluding symbol | `203 + S` | `171 + S` | −32 B |
| 32-byte fields in `Order` / `OrderSnapshot` | — | — | −1 each |
| 32-byte fields in `MatchPair` | — | — | −2 |
| `PlaceOrderRequest` JSON fields | — | — | −1 (−64 hex chars on the wire) |

### Local validation

`cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
`check-compose-image-digests`, `check-icicle-cuda-arch-env`,
`check-brand-namespace`, `check-no-doctests`, `check-dependency-audits`,
`build-vault-sbf.sh devnet-admin`, `cargo nextest run --workspace`
(**732 passed, 3 skipped**), SDK vitest (270 passed), daemon vitest (147
passed), indexer vitest (20 passed), `tsc --noEmit` for sdk/daemon/indexer, and
OpenAPI YAML parse.

`REQUIRE_CIRCUIT_ARTIFACTS=1` was verified against the only binary the flag
gates — `crates/darknyx-tee/tests/valid_input_intake_verify.rs`, the sole file
that reads the variable: **2 passed, 0 skipped**, i.e. the proof-backed tests
really proved rather than silently skipping.

### RETRACTED — the "nextest hang" reported here was an observation error

An earlier revision of this section claimed
`cargo nextest run -p darknyx-tee --tests` hangs at 497/556. **That finding is
wrong and is retracted.** Re-run on a quiet machine: **556 tests, 556 passed,
92.1 s, exit 0.**

How the false finding was produced, because the method matters more than the
conclusion:

1. **The evidence was a bad probe.** "Runner alive, zero children, 0% CPU" came
   from `ps aux | grep -E "[d]arknyx-tee-|[s]narkjs|[n]ode"` and
   `pgrep -f nextest`. Those match the nextest SUPERVISOR — correctly idle,
   because supervising is not compute — and can never match a test binary, which
   lives at `target/debug/deps/<test_name>-<hash>`. Probing again at the same
   497/556 point with the right pattern shows two `prover_roundtrip` processes
   at ~96% CPU each. There were always children; the probe could not see them.
2. **The environment was degraded, not the runner.** Those observations were
   taken with 1.1–3.4 GB free (ENOSPC was hit twice, badly enough that tool
   output could not be written) and with a second `cargo nextest run
   --workspace` executing concurrently — two cargo processes contend on the
   build lock.
3. **The "control experiment" confirmed nothing.** Reproducing the same
   behaviour on `main` felt like proof the defect predated the slice. It only
   showed the same degraded environment produced the same symptom. Agreement
   between two runs of a bad probe is not corroboration.

Nothing needs fixing. The CLAUDE.md §2.5 gate line is correct as written, and no
workaround is required.

Lesson kept deliberately: **before reporting a hang, prove the process is not
working** — check for children by their real path (`target/debug/deps/`), check
free disk, and check for a concurrent build holding the cargo lock. A negative
result from an unvalidated probe is not evidence.

### Second pre-existing defect found while validating: TypeScript is never typechecked in CI

Chasing a review finding on `build-order-parity.test.ts` turned up a gate gap
worth its own row.

**`tsc` does not appear in any workflow.** `grep -rn "tsc" .github/workflows/`
returns nothing. The `SDK`, `daemon`, and `indexer` CI jobs run `vitest` only,
and vitest STRIPS types rather than checking them. The `tsc --noEmit` lines in
CLAUDE.md §2.5 are local-only, so TypeScript type safety depends entirely on a
developer running the local gate by hand.

Compounding it: `packages/sdk/tsconfig.json` has `"include": ["src/**/*"]`. So
even the local gate never sees `tests/`. Test files are checked by **nothing**.

Measured against the root `tsconfig.json`'s own options (`--strict
--skipLibCheck --esModuleInterop --resolveJsonModule --module esnext --target
es2022 --moduleResolution bundler --lib ES2022,DOM`):

| Package | Test files | Type errors |
|---|---|---|
| `packages/sdk` | 65 | 3 |
| `packages/daemon` | 22 | 19 |
| `packages/indexer` | 4 | 1 |
| **Total** | **91** | **23** |

These are pre-existing and present on `main`. One of them —
`spendingKey` passed to `buildOrder`, which `BuildOrderArgs` does not
accept — was reported against this PR as if it were new; it is not, and it is
fixed here because the file was already being edited. The other 22 are untouched.

This is the same class as T-11/T-12/T-13/T-18: a gate that reports success
without checking the thing it appears to check. Not fixed here — adding a
typecheck job would surface 22 unrelated errors and turn a canonical-format
change into a repo-wide cleanup. Filed for a follow-up slice; the fix is a CI
`tsc --noEmit` step plus a tests-inclusive tsconfig per package.

### Rollback effects

Reverting v5 → v4 is a code revert plus a redeploy; there is no data migration
in either direction, which is the main thing an operator needs to know.

| Surface | Effect of reverting |
|---|---|
| Settle journal on disk | **No migration.** `JournalEntry` wraps `MatchResultPayload`, which never carried `user_commitment`. A journal written under v5 replays correctly under v4 and vice-versa. |
| On-chain instruction data | **No migration.** Tx D's payload is unchanged; no vault redeploy, no tree reset. |
| Circuits / proving keys | Untouched. `match_batch_*` does not see this field. |
| In-memory resting orders | Discarded — they die with the process on any redeploy, as they already do on every image roll. |
| Signatures in flight | A v5-signed body fails signature verification against a v4 build (different `ORDER_DOMAIN`), so it is rejected with a 403 rather than mis-parsed. That is the domain tag doing its job in both directions. |
| Boot session | A redeploy rotates `boot_session_id` anyway, so every pre-restart order signature is already stale independent of this change. |

Operationally: a drain is good hygiene before the redeploy (it cancels resting
orders and confirms nothing is mid-settle), but it is **not required for
correctness here** — the journal survives the version change untouched, so a
crash-revert reconciles the same way a crash-restart does.

### Live CVM evidence — 2026-07-29

Captured on `nightly-test-cvm` (CPU, `tdx.xlarge`, `gpus=0`, node prod9) running
image `tee-v3-hardening-77` @
`sha256:5358ac5bad79cd55c5f7d185bddaafed29fa646d51be3b0ba70b2bc812906436`. The
digest was resolved from the registry fail-closed AND cross-checked against the
value the build itself bound (`Bind immutable image identity` step), so the
attested `compose_hash` binds content that was verified twice from independent
sources. Real-mint regime; all four shard signers confirmed REGISTERED in
`vault_config` and funded (~2 SOL each).

**Every CVM test passed on the v5 canonical body:**

| Test | Result | Notes |
|---|---|---|
| `cvm-settle-e2e` | **PASS** 45.4 s | real crossing pair matched AND settled |
| `cvm-api-surface` | **PASS** 10 tests | the wire schema this slice changed |
| `cvm-attestation-e2e` | **PASS** 5 tests | |
| `cvm-multimatch-settle` | **PASS** 57.8 s | |
| `cvm-self-trade` | **PASS** 69.6 s | STP on the note-bound owner identity |
| `cvm-merge-then-order` | **PASS** 44.9 s | merge → order on the new body |

Each leaf-count test ran on its own freshly-reset tree **plus** an env-only
cold-boot redeploy (the Merkle mirror is append-only and cannot rewind), with a
post-reset `DARKNYX_TEE_SYNC_FROM_SLOT` floor each time. Boot logged
`merkle cold-boot complete applied=0 total_leaves=0 shards=4` — the correct
empty start.

Settles confirmed on-chain:

| Test | Settle signature | Slot | Outcome |
|---|---|---|---|
| `cvm-settle-e2e` | `4sx415ofNZYRGyD4c3XfvcW3MQ99bExQLgUN4PU7UKezPNtUJt2EUMWgY2TT7eY7utiE4pPPXV2NYcxKjQVYh64y` | 479704088 | `confirmed=1 rejected=0 ambiguous=0 pipeline_failed=false` |
| `cvm-merge-then-order` | `4G9CtpFXrpCgjdHbJhGCJkGyiXghPVNpomaaiRvQXyAoCt5asuMkvrXJmkSsFW25DDjSt79t3uVLoyvWr3Z3UChS` | 479706278 | `confirmed=1 rejected=0 ambiguous=0 pipeline_failed=false` |

**Cost of the v5 body: none measurable.** Settle `total_ms=14523`
(lock 1214, prove 2218 — witness 289 native + prove step 1885 — verify 1283,
ALT 890 + wait 780, settle 10968, close 0), backend `rapidsnark`, device CPU,
`settle_concurrency=1`. That sits between the two prior samples on the same path
(slice-1 `14573`, slice-4 `14210`), so removing 32 signed bytes is invisible
against a ~14 s network-bound settle — as expected, and stated as "not visible
at this resolution" rather than "faster", since three samples do not support a
stronger claim.

Also re-confirmed incidentally: the fail-closed oracle gate still works —
`trading starts PAUSED until the first authenticated, fresh oracle batch`
(`profile=router-quorum-v1`, `api_key_configured=true`) then
`oracle trust/freshness recovered; trading RESUMED` 310 ms later.

**CVM stopped after the window; billing halted.** GPU check performed
immediately before stopping (`gpus=0`, `tdx.xlarge`) per the standing rule that
an on-demand GPU CVM must never be stopped.

#### One thing that nearly became false evidence

`cvm-attestation-e2e` **silently skipped** on its first invocation: it gates on
`RUN_CVM_ATTEST=1`, not the `RUN_CVM_E2E=1` used by the other CVM tests. The
run reported `1 passed | 1 skipped` and would have been easy to record as a
pass. It was re-run with the correct flag and passed 5/5. Same lesson as
T-11/T-12/T-13/T-18 — a skip is not a pass, and per-file env gates must be
checked individually, not assumed uniform.

## Slice 6 evidence — `remediation/daemon-keystore-v2`, 2026-07-29

### Format and threat boundary

New daemon keystores are always written as v2:

```text
version=2
kdf=scrypt
profile=scrypt-n17-r8-p1-v1
cipher=aes-256-gcm
salt=16 bytes
iv=12 bytes
ciphertext=1..8192 bytes
tag=16 bytes
```

The file carries no caller-selectable `n`, `r`, or `p`. Version 2 maps to the
single compiled profile `N=2^17, r=8, p=1` with `maxmem=256 MiB`; the algorithm
needs approximately 128 MiB and the explicit ceiling prevents runtime defaults
or an untrusted header from selecting startup work. The entire file is bounded
to 32 KiB before JSON parsing, every object has an exact key set, and every
binary field must be canonical lowercase hex of the expected length.

AES-GCM AAD is a binary, unambiguous concatenation of the v2 domain, KDF,
profile, cipher, raw salt, and raw IV. Ciphertext is authenticated by GCM
itself. Altering any accepted header value therefore either fails strict schema
selection before the KDF or fails authentication after deriving the one
permitted key. Derived key buffers are zeroed on both seal and open paths.

The v1 reader accepts exactly what the old writer emitted:
`version=1`, `scrypt`, `N=2^14`, `r=8`, `p=1`, and the legacy field set. A
hostile `N=2^30`, `r`, `p`, extra field, malformed length, or oversized file is
rejected before scrypt. A valid v1 file is decrypted and its identity is
semantically validated (64-byte seed, 32-byte root key, canonical BN254 field
elements) before migration. The v2 replacement is written to a mode-0600
same-directory temporary file, file-synced, atomically renamed, and
directory-synced. A wrong password, invalid plaintext, or pre-rename failure
leaves the original v1 bytes untouched; no partial keystore is exposed.

### Tests

`packages/daemon/tests/keystore.test.ts` now pins:

- a full deterministic v2 envelope KAT, including ciphertext and tag;
- v2 roundtrip, exact profile, absence of `n/r/p`, mode 0600, file sync plus
  directory sync, wrong-password immutability, header/AAD tamper rejection,
  unknown fields, malformed lengths, and the 32 KiB pre-parse bound;
- v1 correct-password migration followed by an independent v2 reopen;
- wrong-password and semantically invalid v1 plaintext leaving the original
  file byte-identical;
- hostile legacy KDF parameters rejected before work selection;
- a simulated rename interruption leaving v1 intact and no temporary file;
- encrypted seed backup/import recovering the same identity and producing a
  v2 keystore.

No CVM, Solana program, circuit, canonical order, OpenAPI, or network interface
changes. This is local daemon custody only, so the tracker correctly requires
no billable CVM run.

Local gate:

- daemon test-config typecheck: pass;
- daemon production build: pass;
- daemon Vitest: **156 passed, 2 environment-gated skipped**;
- targeted Prettier check, namespace guard, and `git diff --check`: pass.

No dependency manifest changed. The dependency audit was not repeated for this
slice for the sandbox/privacy reason recorded in the slices 1–5 revalidation;
the already-merged baseline remains unchanged.

### Measured unlock cost

Measured on Node v26.5.0, macOS arm64, Apple M3 (8 logical CPUs), 16 GiB RAM.
Percentiles use nearest rank. The v1 and v2 unlock sets contain 20 samples after
one warmup; wrong-password and migration sets contain 10 samples. Each process
was isolated so peak RSS is attributable to that mode. Migration includes
legacy decrypt, semantic validation, v2 KDF/seal, file sync, rename, and
directory sync.

| Operation | Samples | p50 | p95 | min–max | Process RSS baseline → peak | Resulting file |
|---|---:|---:|---:|---:|---:|---:|
| v1 legacy unlock baseline | 20 | 23.22 ms | 23.80 ms | 22.73–24.00 ms | 113.61 → 130.14 MiB | 727 B |
| v2 unlock | 20 | 203.76 ms | 248.25 ms | 197.40–386.23 ms | 113.58 → 247.27 MiB | 760 B |
| v2 wrong password | 10 | 213.23 ms | 316.95 ms | 205.39–316.95 ms | 113.94 → 242.67 MiB | unchanged |
| v1→v2 migration | 10 | 237.48 ms | 281.19 ms | 231.72–281.19 ms | 112.98 → 261.30 MiB | 760 B |

The intended cost is roughly 8.8× at p50 versus the legacy unlock and about
134 MiB of additional process peak over the measured baseline. It is paid once
per daemon unlock, not per order or trade. A wrong password deliberately pays
the same class of cost as a correct one, so the stronger offline resistance is
not bypassed by an invalid attempt. Repeat these measurements before supporting
a materially lower-memory client class; 16 GiB macOS arm64 is the only client
class claimed by this evidence.

### Compatibility and rollback

- Valid v1 files migrate transparently on first successful unlock. New writes
  and migrated files are v2 only.
- An older daemon cannot open a migrated v2 file. Rollback therefore requires
  restoring the master seed from the independently encrypted version-2 seed
  backup and creating a legacy keystore with the old binary; it does not
  require a chain, note, order, or CVM migration.
- A failed unlock never migrates. A migration interrupted before rename leaves
  v1 intact; after the atomic rename the visible file is complete v2.
- The keystore contains the custody root secret. Operators must verify their
  encrypted seed backup before deliberately rolling back or deleting either
  file.

Hosted final-head evidence on PR #86:

- `Daemon — keystore, lifecycle, attestation (vitest)`: pass;
- `TypeScript — tsc --noEmit (src + tests)`: pass;
- consistency and aggregate `pr-checks success`: pass;
- CodeRabbit selected all five files but did **not** perform a review: its
  service reported the account's review-rate limit, with no inline findings.
  The green status context is therefore not counted as review evidence.

PR #86 merged as `6f16f6f`; T-09 and T-10 are `Closed`.

## Slice 7 evidence — `remediation/tee-bounds-cleanup`, 2026-07-29

### PF-09 — bounded native-prover output

The rapidsnark wrapper no longer trusts `groth16_prover_prove` to make progress
or to return allocation-safe lengths. Its native boundary now enforces all of
the following before allocating or slicing:

- at most **3** native prove attempts;
- a fixed **1 KiB** error buffer;
- **64 KiB** maxima for each of the proof JSON and public-signal JSON buffers;
- checked `u64 → usize` conversion for every native size;
- rejection of an oversized initial proof-size hint before the first output
  allocation;
- rejection of `SHORT_BUFFER` without a strictly larger required buffer;
- rejection of successful lengths beyond the buffers supplied to native code.

The maximum live Rust-owned output allocation for one attempt is therefore
**132,096 bytes**: 65,536 proof + 65,536 public signals + 1,024 error. A retry
replaces those buffers; it cannot create a fourth attempt or request an
allocation above either 64 KiB ceiling. These ceilings are deliberately
generous relative to every supported Groth16 JSON output and affect only a
broken/native-error path.

Eight fake-native boundary tests cover normal success, selective growth, zero
progress, `u64::MAX`, excessive initial hints, retry exhaustion, success lengths
beyond capacity, and preservation of a native error message. The real native
roundtrip also passes against the N=2 fixture and committed proving key.

### T-14 and legacy fixture removal

The retired `NullifierEntry` account type and its program, TEE, SDK, harness,
script, and current-documentation seeds/helpers are gone. The live
commitment-keyed `ConsumedNoteEntry` and `DepositedNoteEntry` guards are
unchanged. This deletes source-level dead state only: no deployed account is
read or migrated, and there is no instruction, canonical order, circuit,
proving-key, verifier-key, or transaction-layout change.

The same sweep removed the self-contained `PendingOrder` / `DarkCLOB` /
on-chain-matcher fixture layer from `programs/vault/tests/settle_harness/mod.rs`
(677 deleted lines). Those helpers could not exercise the current architecture:
the only matcher is in the TEE and the only on-chain program is `vault`.
Historical audit records retain their original terminology as evidence.

The deletion/stale-reference sweep found no live `NullifierEntry`,
`NULLIFIER_SEED`, `nullifierEntryPda`, `nullifier_pda`, `PendingOrder`,
`DarkCLOB`, `SubmitOrderArgs`, `ME_PROGRAM_ID`, or `.me_id` surface outside
historical findings. Canonical order v5 remains the current contract; no active
v4 fixture was found.

### Roundtrip-test correction discovered during validation

The native witness generator exposed two stale assumptions in
`rapidsnark_roundtrip`: it expected the pre-hashing one-public-input circuit and
constructed both dummy slots with `batch_slot=0`. The current circuit exposes
`[merkle_root, config_digest]`, and C-08 requires slot 1 to carry
`batch_slot=1`. The test now verifies both public inputs and compares the full
public vector across ark and rapidsnark. This is a test-fixture repair, not a
circuit or proof-format change.

### Measured effect

Measurements used the same Apple M3 host, N=2 Wasmer witness generator,
rapidsnark static library, zkey, release profile, and workload on both source
states. The baseline ran from a detached worktree at `729da51`; the candidate
ran from this branch. Each prove set contains 40 samples and reports nearest-rank
percentiles.

| Measurement | Before | After | Delta / interpretation |
|---|---:|---:|---|
| Witness p50 / p95 | 59 / 61 ms | 60 / 62 ms | +1 ms / +1 ms; host noise |
| Native prove p50 / p95 | 353 / 407 ms | 361 / 397 ms | +2.3% / -2.5%; no material normal-path regression |
| Native prove min–max | 329–506 ms | 329–402 ms | candidate remains inside baseline spread |
| `target/deploy/vault.so` | 597,184 B | 597,184 B | unchanged |
| Rapidsnark-enabled release TEE binary | 22,947,664 B | 22,947,664 B | unchanged |
| SDK `dist/` | 618,583 B | 617,846 B | -737 B |
| Affected SDK IDL JS + declarations | 45,975 B | 45,586 B | -389 B |

No CVM or devnet run is required: PF-09 is an internal host/native error
boundary, T-14 removes unused source interfaces, and neither changes the image
contract, circuit, verifier, on-chain instruction, persisted live state, or
network surface.

### Validation and rollback

Completed targeted checks:

- `RAPIDSNARK_LIB_DIR=… RAPIDSNARK_GMP_LIB_DIR=… cargo test -p darknyx-tee
  --features rapidsnark prover::rapidsnark_sys::tests --lib` — **8 passed**;
- the same native-library environment plus
  `REQUIRE_CIRCUIT_ARTIFACTS=1 DARKNYX_TEE_WITNESS=native cargo test
  -p darknyx-tee --features rapidsnark --test rapidsnark_roundtrip
  -- --nocapture` — **2 passed**;
- `cargo test -p vault --tests --no-run` — all vault test targets compile;
- `bash scripts/build-vault-sbf.sh devnet-admin` — pass; fingerprint refreshed;
- SDK production build and test-inclusive TypeScript compile — pass;
- `git diff --check` — pass.

Completed full local gate:

- formatting, compose-digest, CUDA-env, brand-namespace, doctest, and deletion
  guards — pass;
- `cargo build --examples -p darkpool-crypto` and
  `cargo clippy --workspace --all-targets -- -D warnings` — pass;
- `cargo nextest run --workspace` — **732 passed, 3 skipped**. The first
  sandboxed attempt was denied permission to bind one localhost RPC fixture;
  the identical unrestricted run passed 732/732;
- `REQUIRE_CIRCUIT_ARTIFACTS=1 cargo nextest run -p darknyx-tee --tests` —
  **556 passed, 1 skipped**, including the real N=2 match-batch and VALID_INPUT
  proof-backed tests;
- SDK Vitest — **270 passed, 24 environment-gated skipped**; daemon Vitest —
  **156 passed, 2 skipped**; indexer Vitest — **20 passed**;
- SDK, daemon, and indexer test-inclusive TypeScript compiles — pass.

The networked dependency-audit helper was not run locally because the execution
environment refused to disclose private dependency metadata to third-party
advisory services. No dependency manifest changed; hosted run `30483162257`
executed the real `cargo audit + npm audit` job and passed.

Hosted final-head evidence on PR #88:

- aggregate `pr-checks success`: pass;
- circuits, Rust fmt/clippy/unit/examples, SBF mainnet+devnet builds, SDK,
  TypeScript, daemon, Vault ZK, Vault LiteSVM, artifact-required TEE, and
  dependency-audit jobs: pass;
- indexer: correctly skipped because no indexer path changed; its local Vitest
  suite passed 20/20;
- CodeRabbit Pro Plus, assertive profile, run
  `58ca049f-9ed8-4fef-99dc-84f1b8a2909f`: all 24 changed files selected,
  circuit/VK and cross-language parity checks passed, **no actionable or inline
  comments generated**.

PR #88 merged as `923a992` on 2026-07-29. T-14, PF-09, and slice 7 are
`Closed`. Rollback is source-only: revert the PR and rebuild the TEE/SDK/program
artifacts. It does not invalidate notes, orders, proofs, accounts, journals,
keys, signatures, compose hashes, or devnet state.

## Slice 8 evidence — `remediation/multi-market-isolation`, 2026-07-30

### T-17 — layered venue and market gates

`TradingGate` now has two independent layers:

- governance and drain reasons share one venue-wide atomic across every market;
- each market owns its own oracle atomic;
- ordinary clones share both layers for that market, while `fork_market()`
  shares only the venue layer.

The production boot path constructs one exact gate per configured symbol and
passes that same handle to its matcher driver, oracle binding, and API routing
entry. Place and modify resolve the signed symbol through that registry twice
(before and after expensive verification), so an oracle transition cannot race
an accepted mutation. A healthy matcher or sync result has no handle to another
market's oracle state.

Normal oracle refresh still uses one authenticated request containing every
unique feed. If that all-or-nothing request fails, the sync task retries each
unique feed independently and concurrently. An unavailable, malformed, stale,
or unauthenticated feed pauses only its bound markets; healthy feeds continue
to refresh. The config path still bounds a CVM to 16 markets, so a failed cycle
is bounded to **1 batch + at most 16 fallback requests**, and concurrent retries
bound wall-clock delay to one HTTP timeout rather than 16 serial timeouts.

The public status model is additive:

- `/instruments[].trading_enabled` reports current market-local readiness;
- `/system/status.matcher_running` means at least one market is available;
- `/system/status.degraded` remains true if any market is paused or global
  settlement/governance readiness is unavailable;
- order writes remain authoritative and return a racing `503` if the snapshot
  changes.

Strict multi-market JSON already requires `oracle_feed_id` on every row. The
holistic config check now also rejects partial coverage before runtime
construction, and the singular compatibility path rejects multiple legacy
feed IDs instead of creating feeds with no market binding.

### Measured cost and failure-path bound

On the current 64-bit target a `TradingGate` is **16 bytes** (two 8-byte `Arc`
handles), up from 8 bytes. For N markets the old gate used one atomic allocation;
the layered model uses one shared venue atomic plus N market atomics: exactly
N+1 allocations, a delta of N (maximum **17 vs 1**, +16, at the configured
16-market cap). `is_open()` adds one acquire-load. Place/modify adds one
boot-static symbol-map lookup at each existing gate checkpoint.

The adversarial Hermes stub observed exactly **3 requests** for two feeds:
one failed batch plus two concurrent single-feed retries. The good retry
verified the committed signed accumulator and reopened SOL-USDC while the bad
request was deliberately held open; BTC-USDC remained paused. A serial fallback
deadlocks that test. The healthy path remains one request, pinned by the
authenticated multi-feed request builder test and its `hermes_requests=1`
runtime metric.

The corrected in-process loadgen smoke accepted **126** submissions, rate-limited
17 as expected, returned **zero 5xx**, and observed matches. Its fixture now
advertises the same feed it seeds; allowing a debug seed to clear an unrelated
market gate would have hidden the production isolation invariant.

### Local validation

- formatting, OpenAPI YAML parse, diff whitespace, compose-digest, CUDA-env,
  brand-namespace, and no-doctest guards: pass;
- strict workspace clippy and crypto example build: pass;
- default, `debug_endpoints`, and artifact-required full TEE suites: pass;
- `cargo nextest run --workspace --no-fail-fast`: **740 passed, 3 skipped**;
  one unrelated nextest process-leak warning on the random-JTI unit test did
  not reproduce in an isolated rerun (1/1 passed cleanly);
- the final debug-only cross-market seed regression: **5 passed** after the
  workspace run;
- SDK Vitest: **270 passed, 24 environment-gated skipped**;
- daemon Vitest: **156 passed, 2 skipped**; indexer Vitest: **20 passed**;
- SDK, daemon, and indexer test-inclusive TypeScript compiles: pass.

The local dependency-audit wrapper could not run because the execution policy
refused to send private dependency metadata to external advisory services. No
dependency manifest or lockfile changed; the hosted dependency job remains
required before closure.

No circuit, zkey/VK, canonical order, on-chain instruction/account/transaction,
journal, key derivation, program deployment, tree, signer, or devnet state
changes. Because the production TEE boot path and HTTP response changed, the
repository workflow still requires a digest-pinned two-market CVM spot-check
before closure. Exact source `c0f06fc` was built successfully by
`tee-image` run `30488988373` as tag `tee-v3-hardening-78`; the immutable CPU
image is
`sha256:5ae02ce5c9686770289a7c0e036b4f7819ec6a85c427657fc47d240322ff93c2`.
The CPU compose is pinned to that digest. No CVM has been started for this
slice yet. The focused multi-market env generator now also requires and carries
the authenticated Hermes credential into the encrypted deployment env; it
cannot silently produce a deployment where every oracle gate remains paused.

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

## Agent handoff — 2026-07-29 (slice 7 closed)

```text
Last merged PR / main SHA: #88 / 923a992
Active branch / HEAD: remediation/tee-bounds-cleanup-close / tracker-only
  closure PR #89
Dirty or untracked files preserved: yes — modified third_party/icicle-snark and
  third_party/rapidsnark submodules plus every pre-existing untracked path were
  left untouched and are not part of slice 7.
Active slice and finding IDs: none — slice 7 T-14/PF-09 Closed
Invariant and compatibility decisions:
  - Native proof output is bounded to 3 attempts, 64 KiB proof, 64 KiB public,
    and a fixed 1 KiB error buffer, with checked native sizes.
  - NullifierEntry and every dead program/TEE/SDK derivation surface are gone;
    commitment-keyed DepositedNoteEntry/ConsumedNoteEntry guards are unchanged.
  - No circuit, VK/zkey, instruction, account, transaction, canonical order,
    OpenAPI, journal, key, or devnet migration. No CVM was required.
Commands run and exact results:
  cargo nextest run --workspace                       -> 732 passed, 3 skipped
  REQUIRE_CIRCUIT_ARTIFACTS=1 cargo nextest run
    -p darknyx-tee --tests                            -> 556 passed, 1 skipped
  affected vault LiteSVM                              -> 25 passed
  fake-native rapidsnark boundary tests               -> 8 passed
  native N=2 rapidsnark roundtrip                     -> 2 passed
  SDK / daemon / indexer Vitest                       -> 270 / 156 / 20 passed
  SDK / daemon / indexer test-inclusive tsc           -> pass
  hosted run 30483162257, including dependency audit  -> pass
  CodeRabbit assertive review                         -> no actionable comments
Live state: no CVM running; no devnet, signer, compose, image, circuit, or
  program state changed. Slice 7 requires no CVM.
Evidence still missing: none for slice 7.
Blockers: none.
Exact next action: start slice 8, remediation/multi-market-isolation (T-17),
  from the latest main after this closure PR merges. Read
  docs/multi-market-architecture.md and the T-17 audit/tracker anchors first.
  Do not stage the dirty submodules or unrelated untracked files.
```

## Agent handoff — 2026-07-29 (slice 6 closed)

```text
Last merged PR / main SHA: #86 / 6f16f6f
Active branch / HEAD: none after the documentation-only closure update
Dirty or untracked files preserved: yes — modified third_party/icicle-snark and
  third_party/rapidsnark submodules plus every pre-existing untracked path were
  left untouched and are not part of slice 6.
Active slice and finding IDs: none — slice 6 T-09/T-10 Closed
Invariant and compatibility decisions:
  - New writes use only keystore v2 / scrypt N=2^17,r=8,p=1 with a 256 MiB
    max-memory ceiling; the JSON file cannot select KDF work.
  - Exact schema + bounded decode + AES-GCM AAD protect the header. V1 is
    read/migrate-only and is replaced only after authenticated decrypt,
    semantic validation, file fsync, atomic rename, and directory fsync.
  - Old binaries cannot read a migrated v2 file. The independent encrypted
    seed backup is the rollback/recovery path; no chain or CVM migration.
Commands run and exact results:
  cargo nextest run -p darknyx-tee -p darkpool-matcher --no-fail-fast
                                                    -> 607 passed, 3 skipped
  bash scripts/build-vault-sbf.sh devnet-admin      -> pass
  cargo test -p vault --test withdraw_lock_lifecycle -> 3 passed
  tsc -p packages/daemon/tsconfig.test.json --noEmit -> pass
  vitest packages/daemon                            -> 156 passed, 2 skipped
  npm run build (packages/daemon)                   -> pass
  prettier --check affected TS; brand guard; diff check -> pass
Live state: no CVM running; no devnet, signer, compose, image, circuit, or
  program state changed. Slice 6 requires no CVM.
Evidence still missing: none for slice 6. CodeRabbit did not review because its
  account rate limit was reached; this is recorded as unavailable, not passed.
Blockers: none. Dependency audit not repeated because the networked check was
  denied on private-metadata grounds; no dependency manifest changed.
Exact next action: start slice 7 (remediation/tee-bounds-cleanup: T-14 + PF-09
  plus the unused legacy settle-harness fixture cleanup). Do not stage the dirty
  submodules or unrelated untracked files.
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
  cargo clippy --workspace --all-targets -- -D warnings -> zero warnings
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
