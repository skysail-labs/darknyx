# Surfpool local validation and RPC independence tracker

**Created:** 2026-08-27

**Last updated:** 2026-08-30

**Current phase:** Phase 4 is `Code complete` on `infra/surfpool-ci`. A clean
hosted Linux amd64 run and the eventual whole-stack merge remain.

**Active stack base:** `main` at `41a2a518`

**Bottom stack branch:** `infra/surfpool-tracker`

**Cost objective:** remove the permanent paid devnet RPC dependency from
routine development and scheduled SDK integration without weakening the
manual real-Phala/real-devnet release gate

**Mainnet status:** unchanged. Mainnet still requires a dedicated production
RPC and the existing external audit, ceremony, governance, recovery, and CVM
release gates.

This file is the canonical implementation plan, status ledger, evidence index,
and continuation handoff for the Surfpool migration. Do not create a second
overlapping plan. Move a row only as far as its recorded evidence supports.

The abandoned experiment on `remediation/rpc-vendor-independence` is evidence,
not an implementation base. Its commits `d2503a8a`, `10485a97`, `045744cb`, and
`a316d721` are deliberately outside this stack. Do not merge or cherry-pick
them wholesale. Re-implement only a reviewed idea whose phase below calls for
it.

---

## 1. Frozen architecture decision

Darknyx will use four explicitly different validation layers:

| Layer | Solana environment | TEE environment | Required use | What it cannot claim |
| --- | --- | --- | --- | --- |
| Unit/program | LiteSVM and host tests | Test objects | Every PR | Full JSON-RPC, process lifecycle, real TDX |
| Local integration | Pinned Surfpool, offline | Host `darknyx-tee` plus pinned dstack simulator | Routine full-stack development and scheduled integration | Intel quote authenticity, Phala KMS/gateway, real cluster timing |
| Release/demo | Real Solana devnet through a dedicated RPC | Digest-pinned Phala CPU CVM | Manual release, protocol change, and showcase gate | Mainnet production readiness by itself |
| Production | Real Solana mainnet through a dedicated RPC | Governed digest-pinned CVM | Launch only after all mainnet gates | None of the deferred launch gates |

The scheduled SDK workflow currently named `nightly-devnet` moves to Surfpool.
It must stop consuming a real-devnet RPC. The real CVM workflow remains a real
devnet test, but becomes an explicit manual/release gate rather than the
replacement for routine local integration.

Returning from Surfpool to a real CVM must remain configuration-only at the
RPC boundary: the same protocol code and image take a different
`DARKNYX_TEE_SOLANA_RPC_URL`, while SDK/operator callers take the matching
`SOLANA_RPC_URL`. Local and real-cluster state, keypairs, mints, ALTs, and
configuration files must never be shared.

### 1.1 Surfpool capability fact

Surfpool added `getTransactionsForAddress` in
[`6c3896f`](https://github.com/solana-foundation/surfpool/commit/6c3896fecaedd35911d18992f44a148d524f342b).
The implementation is intentionally local-ledger only. That is sufficient for
a hermetic Darknyx run because every deposit, merge, settle, and withdrawal in
that run is created on the Surfnet itself.

As of this tracker date, the latest release is `v1.5.0` and predates that
commit. A Surfpool maintainer likewise confirmed in
[`#784`](https://github.com/solana-foundation/surfpool/issues/784#issuecomment-5427949990)
that gTFA is on `main` and planned for the next release. Phase 1 therefore
starts from a source commit, then records the final tested commit and binary
checksums rather than assuming `6c3896f` alone is the right long-term pin.

The source advertises the required full-detail limit, ascending ordering,
status and slot filters, versioned transaction encoding, and pagination. These
claims are inputs to Phase 1, not closure evidence: Darknyx must exercise every
request shape against the exact pinned revision before depending on it.

Build from a tested immutable commit until the implementation reaches a
release. Never build CI from moving `main`, and never install the unrelated
crate that may occupy the `surfpool` name on crates.io.

### 1.2 Decisions that must not drift

1. **No public Solana RPC for scheduled integration.** Public devnet is
   rate-limited and is not an availability contract for a multi-call suite.
2. **No ordinary tunnel from a laptop as the default CVM RPC.** It creates an
   unauthenticated or independently authenticated control plane, invalid
   performance measurements, and laptop availability as a protocol dependency.
3. **No split public oracle RPC.** The TEE must read settlement state and its
   local oracle fixture from one Surfnet clock during local integration.
4. **No fake attestation acceptance in production code.** The dstack simulator
   may exercise the guest API shape, but its evidence must remain unacceptable
   to production DCAP verification.
5. **No local pass named or reported as a CVM pass.** Local suites use
   `surfpool` or `local-tee` names. `cvm-*` remains reserved for real Phala
   evidence.
6. **No HTTP-429 capability inference.** A successful `getVersion` does not
   distinguish permanent gTFA refusal from a method-specific quota. A future
   standard-RPC fallback must be explicit on 429.
7. **No routine Helius requirement after closure.** Keep the already-paid
   endpoint through the imminent real-CVM demo and final baseline. Remove the
   recurring dependency only after Phases 1–4 pass.
8. **No claim of total RPC independence.** The mainnet fee collector still
   requires finalized archival history, and production still requires a
   dedicated RPC. This project removes a development subscription, not the
   production RPC role.

---

## 2. Status meanings

| Status | Meaning |
| --- | --- |
| `Open` | The deliverable or invariant is not implemented or proven. |
| `Validated` | The current behavior/capability was reproduced, but the production-quality implementation is incomplete. |
| `Design frozen` | Architecture, boundaries, and migration behavior are decided; required code/evidence remains. |
| `Code complete` | Implementation and focused local tests pass; integration or hosted evidence remains. |
| `Surfpool validated` | The required pinned-Surfpool protocol evidence passes, but real-CVM evidence may remain. |
| `CVM validated` | Required digest-pinned Phala/real-devnet evidence passes, but final release/external gates may remain. |
| `Closed` | Every required implementation, local, CI, documentation, cleanup, and applicable hosted gate is complete. |
| `Deferred` | Explicitly outside this stack with a re-entry condition and review date. |

`Code complete` is never synonymous with `Closed`. A dstack simulator result
can advance a local row to `Surfpool validated`; it can never produce `CVM
validated` evidence.

---

## 3. Bird's-eye deliverable tracker

| ID | Priority | Status | Phase | Invariant/deliverable | Wire/circuit/account impact | Cost or fidelity impact | Next action |
| --- | --- | --- | ---: | --- | --- | --- | --- |
| SP-01 | P0 | **Surfpool validated** | 1 | An immutable Surfpool revision is built on supported developer/CI architectures and its version is visible in every run. | None | Cached source build; removes moving-main ambiguity | Retain the exact pin until a released build containing gTFA passes the same matrix. |
| SP-02 | P0 | **Surfpool validated** | 1 | Surfpool native gTFA is byte/semantic compatible with Darknyx's full ascending successful slot-floored history scan. | None unless a genuine incompatibility is found | Replaces provider gTFA during local runs | Carry the proven nonempty history/root contract into the Phase 3 host-TEE restart test. |
| SP-03 | P0 | **Surfpool validated** | 1/2 | The canonical vault program can be installed at its declared ID on a fresh Surfnet without rebranding/recompiling the protocol ID. | Local deployment path only | Avoids dependence on a missing canonical program-ID private key | Reuse the qualified installer in Phase 2's repeatable isolated foundation. |
| SP-04 | P0 | **Surfpool validated** | 1 | Surfpool executes the syscalls and transaction shapes Darknyx relies on: Groth16, Ed25519, v0 messages, ALTs, 1232-byte limits, and commitment/status polling. | None | Determines whether Surfpool can host full integration rather than SDK-only tests | Full host-TEE settlement remains Phase 3; do not report this row as CVM evidence. |
| LF-01 | P0 | **Surfpool validated** | 2 | A single command creates and a single command tears down a hermetic offline Surfnet with no surviving process. | New test/runbook surface only | Makes local runs reproducible and prevents background process leaks | Reuse the supervisor for Phase 3 host-TEE lifecycle and restart evidence. |
| LF-02 | P0 | **Surfpool validated** | 2 | Local keys, mints, ALTs, vault config, K trees/signers, fee config, and output files live in a separate `.surfpool/` namespace. | Local account foundation only | Prevents local/devnet cross-contamination | Keep Phase 3 simulator/process state inside the same isolated namespace without archiving secrets. |
| LF-03 | P0 | **Surfpool validated** | 2 | Local Pyth sponsored-push fixtures satisfy the exact Darknyx owner/PDA/discriminator/full-verification/feed/time/slot checks without external RPC. | No production oracle change | Removes Hermes/public-devnet oracle traffic and adds adversarial coverage | Retain the exact non-vacuous marker when Phase 4 promotes this foundation into scheduled CI. |
| LF-04 | P1 | **Surfpool validated** | 2 | Surfpool-only cheatcodes never become reachable from a real deployment or an internet-exposed default. | Test scripts only | Keeps the local control plane out of product code | Preserve loopback-only control-plane assertions across Phase 3 and Phase 4. |
| LT-01 | P0 | **Surfpool validated** | 3 | The production `darknyx-tee` binary boots locally against the pinned dstack v0.5.9 simulator and Surfpool without a simulator-only protocol fork. | Explicit development configuration; no production fallback | Exercises real process boot, KMS API shape, governance reads, matcher, prover, and settlement | Carry the measured supervisor into Phase 4 hosted integration. |
| LT-02 | P0 | **Surfpool validated** | 3 | Cold boot and restart reconstruct every K-shard Merkle mirror through Surfpool native gTFA and reconcile exact counts and roots before trading. | None | Replaces the paid provider's continuous local mirror traffic | Require the same nonempty exact-root evidence in Phase 4. |
| LT-03 | P0 | **Surfpool validated** | 3 | Deposit/withdraw, merge, settle, multimatch, self-trade, merge-then-order, expiry, and recovery run against local RPC with real proofs. | None | Makes routine full protocol testing free of external RPC/CVM cost | Select a measured hosted cadence in Phase 4 without weakening the full local matrix. |
| LT-04 | P1 | **Surfpool validated** | 3 | Local results state exactly which TDX/RA-TLS/KMS/real-cluster properties remain untested. | Documentation/test naming only | Prevents simulator evidence inflation | Preserve the boundary manifest and simulator-quote rejection in hosted runs. |
| CI-01 | P0 | **Code complete** | 4 | The scheduled SDK integration workflow uses pinned Surfpool instead of real devnet and requires no RPC/keypair provider secrets. | CI/test configuration only | Eliminates routine Helius requests; adds source-build/cache time | Obtain the clean hosted Linux amd64 run, then advance only as far as that evidence supports. |
| CI-02 | P0 | **Code complete** | 4 | CI proves the exact local foundation and TEE integration rather than silently skipping env-gated suites. | CI gates only | Higher local confidence; bounded runner time/memory required | Confirm every required marker and final five-port teardown in hosted output. |
| CI-03 | P1 | **Code complete** | 4 | The real-CVM workflow remains available as a manual/release gate and no longer implies routine RPC billing. | Workflow trigger/config only | Retains TDX and real-cluster evidence at controlled cost | Verify `workflow_dispatch` and unconditional stop remain intact in review; no CVM run is required here. |
| RA-01 | P0 | **Open** | 5 | One final digest-pinned real-CVM run records attestation, RA-TLS, real devnet settle, Merkle reconciliation, signatures, and stage timings before recurring Helius cancellation. | No protocol change expected | One controlled paid run | Execute using the already-paid endpoint after Phases 1–4 and before credential removal. |
| RA-02 | P0 | **Open** | 5 | Runbooks switch between local Surfpool and real CVM/devnet without code changes or state reuse. | Documentation/config only | Preserves rapid return to real evidence for demos/releases | Record exact local and real entry/exit commands and rollback. |
| CL-01 | P1 | **Open** | 5 | Routine docs/workflows/scripts no longer require or call a Helius endpoint; intentional archival/production references remain accurate. | Documentation/config cleanup | Removes accidental paid traffic | Inventory after CI migration; remove only proven-obsolete references/secrets. |
| RP-01 | P2 | **Deferred** | future | A production TEE may explicitly fall back to standard Solana history RPC without O(pages²), unsafe 429 latching, or unbounded fan-out. | TEE RPC behavior only; no wire/circuit/account change expected | Useful provider resilience, but not required for Surfpool local testing | Re-enter if a real-CVM/devnet run must operate without any gTFA-capable dedicated endpoint. Review by 2026-10-01. |
| RP-02 | P2 | **Deferred** | future | Optional indexer and fee collector have provider-neutral history strategies appropriate to live versus archival duties. | Off-chain operator/client behavior | Fee collector still needs archival mainnet service | Re-enter before changing production RPC vendor or mainnet fee recovery provider. Review by 2026-10-01. |

---

## 4. Stacked PR ledger

Branches are linear, bottom to top. Do not implement a higher branch on a
lower branch merely to avoid rebasing; move to the owning branch and rebase the
upstack.

| Phase | Branch | PR purpose | Rows | Required evidence before advancing | Rollback |
| ---: | --- | --- | --- | --- | --- |
| 0 | `infra/surfpool-tracker` | Freeze architecture, scope, status semantics, stack, evidence, and handoff discipline | all design rows | Documentation checks; source links and current anchors revalidated; no runtime behavior changed | Revert the tracker commit. |
| 1 | `infra/surfpool-qualification` | Pin/build Surfpool and prove Darknyx's exact RPC, program-ID, syscall, ALT, and transaction compatibility in a narrow spike | SP-01…SP-04 | All Phase 1 go/no-go criteria in §5; no production scanner fallback | Drop the branch; no protocol/runtime migration has occurred. |
| 2 | `infra/surfpool-foundation` | Reproducible local network, canonical vault foundation, isolated state, and exact Pyth sponsored-push fixtures | LF-01…LF-04 | Fresh boot/setup/teardown twice; fixture positive and adversarial tests; no external RPC observed | Delete ephemeral `.surfpool/` state and revert local tooling. Real devnet is untouched. |
| 3 | `infra/surfpool-tee-e2e` | Host TEE plus dstack simulator lifecycle, native gTFA mirror, proof-backed end-to-end flows, and restart/recovery | LT-01…LT-04 | Non-vacuous protocol matrix, exact K-root reconciliation, real proof verification, simulator evidence boundary | Revert local supervisor/suites; Phala and devnet remain unchanged. |
| 4 | `infra/surfpool-ci` | Move scheduled SDK integration to pinned Surfpool, add local TEE gate at measured cadence, and preserve real CVM as manual | CI-01…CI-03 | Green hosted run from a clean checkout; zero provider secrets; teardown confirmed on failure; real CVM dispatch retained | Re-enable prior workflow while dedicated RPC remains available. |
| 5 | `infra/surfpool-release-assurance` | Real-CVM baseline, switching runbook, Helius cleanup, final tracker/evidence closure | RA-01, RA-02, CL-01 | Digest/image/compose, signatures, timings, RA-TLS and attestation evidence; CVM stopped; no accidental Helius callers | Restore dedicated RPC configuration; no code rollback should be necessary. |

`RP-01` and `RP-02` are not part of this stack. If their re-entry condition
fires, create a separate stack from the then-current `main` rather than
expanding the Surfpool migration after review has begun.

---

## 5. Phase 1 go/no-go qualification

Phase 1 is deliberately small. It decides whether Surfpool is suitable before
the repository accumulates setup abstractions around an unqualified runtime.

### 5.1 Installation and provenance

- Record the exact upstream commit, upstream repository, Rust toolchain, build
  command, binary SHA-256, and `surfpool --version` output.
- Build/test on Apple Silicon arm64 and the Linux amd64 shape used by CI.
- Prefer a released version once it contains the qualified gTFA code. Until
  then, the exact source revision is mandatory.
- Do not commit a platform binary to the repository.

### 5.2 RPC conformance

Seed nonempty local activity and assert:

1. `getVersion` and contextual blockhash/account calls return the fields
   Darknyx parses.
2. gTFA full mode returns successful transactions only when requested.
3. `sortOrder: asc` preserves `(slot, intra-slot execution order)`.
4. `filters.slot.gte` is inclusive and excludes older activity.
5. A result set larger than one page has no overlap or gap.
6. v0 transactions and ALT-loaded addresses/instructions decode correctly.
7. Reverted transactions never create phantom leaves.
8. A nonempty vault history reconstructs the exact on-chain K-shard roots.

An empty validator or empty tree is a failure, not a skip or pass.

### 5.3 Program and runtime conformance

- Install the compiled vault at
  `C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx` without changing
  `declare_id!()`.
- Initialize the real account layouts and K-shard configuration.
- Create and extend both static/per-batch ALTs, advance the required slot, and
  consume them in v0 transactions.
- Verify at least one generated Groth16 proof through the real vault verifier.
- Exercise the worst-case serialized settle transaction and record bytes/CU.
- Confirm confirmation/status polling reaches the commitment expected by the
  caller without hanging or accepting a failed transaction.

### 5.4 Go/no-go result

Advance only if every mandatory item passes without patching production
protocol semantics specifically for Surfpool. A narrowly scoped Surfpool
compatibility adapter in test tooling is acceptable; a second vault program,
different program ID, disabled proof verifier, or fabricated successful RPC
result is not.

If Phase 1 fails, record the exact unsupported primitive and stop. The fallback
is the existing LiteSVM suite plus controlled real-devnet validation, not the
abandoned public-RPC history scan.

---

## 6. Local foundation and oracle contract

### 6.1 State separation

Use `.surfpool/` for generated local material and `.devnet/` only for real
devnet. Local configuration must identify its cluster explicitly and must
refuse a non-loopback RPC unless a future, separately reviewed remote-Surfpool
mode is selected.

Never copy a local mint, ALT, slot floor, keypair, vault config, or transaction
signature into `.devnet/e2e-config.json`. Never use a real upgrade/admin/funder
keypair when an ephemeral local signer suffices.

### 6.2 Pyth fixture

Darknyx reads the sponsored Core push account family pinned in
`crates/darknyx-tee/src/oracle/push.rs`, not Surfpool's different built-in Pyth
template address. The local helper must derive and encode Darknyx's exact
account:

- receiver owner `rec2HHDDnjLfj4kE7VyEtFA1HPGQLK33259532cRyHp`;
- push program `pyt2F414BA6dPttK6RddPZUdHfapoBN24GL5wbrPCou`;
- shard `0` PDA from the configured feed ID;
- `PriceUpdateV2` discriminator and zero padding;
- self-PDA write authority;
- `VerificationLevel::Full`;
- matching feed, positive spot/EMA prices, confidence, and exponent;
- publish time taken from the Surfnet clock; and
- nonzero posted slot not exceeding the serving context slot.

At minimum, mutation tests must make wrong owner, wrong PDA/write authority,
wrong feed, partial verification, stale time, future time, invalid exponent,
nonpositive price, and future posted slot fail or pause exactly as production
code specifies.

### 6.3 Process lifecycle

Every orchestrated run records Surfpool PID/port, dstack simulator socket/PID,
TEE PID/ports, logs, start time, and exit status. Cleanup runs after success,
failure, timeout, and interruption. A passing test must end by proving the
ports are closed and the child processes are gone.

---

## 7. Local TEE evidence boundary

The local suite runs the real `darknyx-tee` host binary, real circuit artifacts,
real proof generation, real SDK request encoders, and real vault SBF against
Surfpool. It may use an architecture-appropriate supported prover backend, but
must print that backend so an Ark run is not reported as rapidsnark evidence.

The dstack simulator supplies the guest API shape and deterministic development
keys. It does not provide hardware isolation or an Intel-valid quote. The local
suite must assert that the production verifier rejects simulator evidence.

Required local protocol matrix:

| Flow | Non-vacuous success marker |
| --- | --- |
| Foundation | K tree accounts, governed market, fee config, mints, and static ALT exist at expected addresses |
| Oracle | Market enables on fresh exact fixture; pauses on stale/malformed fixture; healthy markets remain isolated |
| Deposit/withdraw | Leaf count/root change, consume PDA exists, recipient balance changes |
| Merge | Input tags consumed, output leaf/opening created, withdrawal succeeds |
| Settle | Crossing orders accepted, lock/proof/verify/settle stages complete, output leaves and consumed PDAs match |
| Multimatch N=16 | More than one real match in one proof-backed batch; padding remains inert |
| Self-trade | Policy outcome and conservation match the production test |
| Merge-then-order | Merged note is accepted and settled without stream-history dependence |
| Restart | Cold mirror rebuild exactly matches every on-chain K-shard count and root before trading resumes |
| Recovery/expiry | Interrupted state reconciles; expired locks take only the documented terminal path |

---

## 8. CI migration contract

### 8.1 Scheduled local integration

The former `nightly-devnet` intent is implemented by the scheduled Surfpool
integration job. Logs name the chain `Surfpool` or `local-tee`, never devnet or
CVM. The job must:

- install the checksum-verified pinned Surfpool revision;
- build the devnet-admin SBF with the fingerprint guard;
- create fresh local state;
- run every formerly scheduled SDK flow against localhost;
- run explicit nonempty gTFA/root reconciliation;
- require all env-gated tests to report execution rather than skip;
- use no provider URL, provider token, or persistent devnet keypair secret;
- save concise textual diagnostics without depending on organization artifact
  storage; and
- tear down all local processes with `if: always()`.

### 8.2 Real CVM gate

The Phala workflow remains the only source of real quote, KMS, RA-TLS,
compose-hash, gateway, real confirmation/finality, and real network timing
evidence. Keep `workflow_dispatch`, immutable image digest resolution, signer
rotation/funding, secret-safe RPC injection, and unconditional CVM stop.

Once local CI is green, recurring CVM scheduling may be removed to control
billing. The workflow itself and its non-vacuous gates must remain available.

### 8.3 Public RPC

`https://api.devnet.solana.com` may be used for a small human diagnostic but is
not an accepted scheduled integration dependency and cannot close any
reliability row in this tracker.

---

## 9. Real-CVM release assurance and Helius exit

Do not cancel or delete the currently usable dedicated endpoint before this
sequence:

1. Phases 1–3 pass locally.
2. The Surfpool CI workflow passes from a clean hosted checkout.
3. Build and pin the exact CPU image intended for the showcase/release check.
4. Run real attestation and RA-TLS verification.
5. Reset real devnet correctly and set a post-reset sync floor.
6. Run at least `cvm-settle-e2e`, multimatch, and merge-then-order on their
   required clean-tree boundaries.
7. Record transaction signatures, slots, K-shard roots, image digest,
   compose hash, signer set, witness/prove/verify/settle/total timings, and RPC
   mode.
8. Drain and confirm the CVM is stopped.
9. Prove the runbook can return to real devnet by configuration rather than a
   code revert.
10. Remove or disable recurring Helius-dependent scheduled jobs and then remove
    obsolete development secrets/references.

The endpoint may still be retained temporarily for the imminent demo even if
local migration is complete; the objective is to end recurring development
dependence, not to sabotage a near-term real-CVM showcase.

---

## 10. Experimental-branch disposition

| Existing work | Disposition | Reason |
| --- | --- | --- |
| `DARKNYX_TEE_MERKLE_POLL_SECS` | Reconsider as a small independent change if measurement still justifies it | Useful operational control, unrelated to Surfpool compatibility |
| `scripts/probe-rpc-conformance.mjs` | Reuse ideas; rewrite/narrow under Phase 1 | Nonempty probing is valuable, but the present script mixes public-network funding and broader assumptions |
| `TxScanMode` and standard-RPC scan | Do not carry into Phase 1–4 | Surfpool provides native local gTFA; production fallback is deferred RP-01 |
| Auto fallback on `-32601` | Reassess only under RP-01 | Potentially safe capability signal, but not needed for local migration |
| Auto fallback on HTTP 429 | Reject | Cannot distinguish permanent refusal from method-specific transient quota |
| `RpcError::RateLimited` | Reassess independently | Structured 429 handling may be useful even without fallback |
| `merkle_scan_live.rs` | Replace with pinned-Surfpool and separately named real-RPC evidence | Current public run failed root reconciliation and took about 50 minutes |
| Public-devnet compatibility benchmark | Stop | Rate-limited endpoint plus O(pages²) scan is not a viable product or CI path |
| dstack simulator analysis | Retain as design evidence | Correctly separates guest API/process coverage from real quote authenticity |

No old commit receives credit merely because its unit tests pass. Any retained
idea lands with the owning phase's focused and integration evidence.

---

## 11. Validation gates by phase

Every PR runs formatting, diff checks, applicable static guards, and the
focused tests for its touched surfaces. Additional minimum gates:

| Phase | Minimum local gate | Hosted/live gate |
| ---: | --- | --- |
| 0 | Markdown/link/source-anchor review; `git diff --check` | Ordinary docs CI/review |
| 1 | Surfpool build/version/checksum; seeded RPC conformance; vault/SBF/Groth16/ALT spike | Linux amd64 clean-host repeat before merge |
| 2 | Two clean foundation cycles; oracle fixture positive/negative suite; zero external RPC | Clean-host setup/teardown repeat |
| 3 | Full local protocol matrix; K-root restart reconciliation; process cleanup; production verifier rejects simulator quote | Optional hosted local runner; no CVM required for code-complete status |
| 4 | Workflow/lint/guard tests; local action-equivalent command | Green Surfpool CI with no provider secrets and confirmed teardown |
| 5 | Runbook checks and cleanup inventory | Digest-pinned real Phala/real-devnet evidence and stopped-state confirmation |

Touching circuits, on-chain code, wire formats, or the settle payload expands
the gate to the complete corresponding `CLAUDE.md` requirements. The intended
migration should not require such changes; if it does, stop and update this
tracker before implementation.

---

## 12. PR evidence template

Every stacked PR description and tracker update includes:

```md
Tracker phase / rows:
Invariant restored:
Why this belongs in this stack layer:
Runtime / wire / circuit / account impact:
Surfpool revision and checksum (if applicable):
Local commands and exact results:
Hosted CI and review:
Real devnet/CVM evidence (or why not required):
Measured time/RSS/CU/transaction-size impact:
Security boundary and secrets used:
Rollback:
Tracker rows advanced:
Evidence still owed:
```

Do not mark a row `Closed` from an aggregate green check alone. Record the
non-vacuous test, exact result, and environment that proves the row's invariant.

---

## 13. Continuation directive

An agent continuing this work must follow this order:

1. Read this tracker, `CLAUDE.md` §§2–4, `scripts/dev-commands.md`,
   `docs/cvm-run-runbook.md`, `docs/settlement-recovery-drill.md`, and the
   relevant package READMEs before changing the owning surface.
2. Inspect `git status`, current stack state with `gh stack view --json`, and
   remote PR state. Preserve unrelated dirty/untracked files and dirty
   submodules.
3. Work on the phase's branch. If a lower-layer change is needed, check out
   that branch, commit there, and rebase the upstack.
4. Revalidate upstream Surfpool source at the pinned revision rather than
   relying on this file's prose.
5. Run the phase's focused go/no-go checks before building abstractions above
   it.
6. Update only the rows whose exact evidence was produced. Never infer
   `Surfpool validated` from mocks or `CVM validated` from the dstack simulator.
7. Keep local and real cluster material in their separate namespaces.
8. Before any Phala action, report whether a CVM is already running and follow
   the billing/teardown runbook. Do not start a CVM for Phases 0–4.
9. Before merging a stack, verify every PR base, CI result, review state,
   rollback text, and tracker status. Merge with the stack-aware workflow.

### Handoff template

```md
Base `main` commit:
Current stack (bottom → top):
Active branch / PR:
Phase and rows in progress:
Surfpool revision / version / checksum:
Files intentionally changed:
Unrelated dirty/untracked files preserved:
Commands run and exact results:
Hosted CI/review state:
Local Surfpool/dstack/TEE process state:
Real CVM state and billing:
Secrets or ephemeral files created and cleanup state:
Evidence still owed before advancing rows:
Next exact command/action:
```

---

## 14. Phase evidence log

Append evidence here as phases execute. Keep raw verbose logs outside git when
they contain endpoints, credentials, or excessive runtime output; record only
redacted commands, exact results, hashes, signatures, and stable references.

### Phase 0 — tracker freeze

- Fresh stack created from `main` at `41a2a518`.
- Experimental compatibility-scan commits intentionally excluded.
- Surfpool upstream fact revalidated: gTFA is on main, local-ledger only, and
  pending release.
- Local architecture frozen as Surfpool plus host TEE plus dstack simulator;
  real Phala/devnet retained as a manual release/demo gate.
- Phase 0 implementation and documentation checks landed in `8a4395fd`;
  runtime and hosted evidence intentionally remained pending.

### Phase 1 — Surfpool qualification

Local Apple Silicon evidence, produced on an offline loopback Surfnet:

- Pinned upstream repository `solana-foundation/surfpool` at
  `d419af7a671fca4f2c9e94621a3f9540b639f6f8`, whose upstream build run is
  `33089478745`. The upstream toolchain is Rust `1.95.0`; its exact build
  command and both platform hashes are in `scripts/surfpool/pin.json`. The
  otherwise mutable Studio UI build input is separately pinned to release
  `v0.2.0-alpha.0` and SHA-256
  `84970f226b5e8eabebf75acc266c6db72b9af6c79ffa68e8f5b69351cde85d11`.
- Apple Silicon archive SHA-256
  `2441366d0c0bbcccaee324c8f5baf8d3ead063332f4d457f329c5ba00a8fad18`;
  binary SHA-256
  `326a07455ba6d097c91b8d646c76f26354e6ddc7580175c58e472807831132ab`.
  The binary reports `surfpool 1.5.0`; the immutable commit and hash, not that
  stale version label, identify this pre-release build.
- The corresponding Linux amd64 archive and binary hashes are pinned as
  `63a4effa40681d5dca9ffecb95af2815683cc18878e082077670666cc73489c8`
  and
  `f2b867eda5d3c056a4650043072fdfcd0c680841174d8fde2fb8de6a301164c1`.
  Artifact provenance and checksum were verified locally. The hosted job
  rebuilds the exact source and locked UI input, prints its environment-specific
  ELF hash, and executes that build; it does not falsely require byte equality
  with an upstream binary built under a different absolute checkout path.
- The fingerprinted devnet-admin `vault.so` was installed at canonical program
  ID `C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx`, then read back as an
  executable BPF-upgradeable-loader account. Local SBF SHA-256:
  `6c555594b2541171e79f27b63f5b3254946c74fbc8708181c203b0278b4a2db0`.
- `scripts/surfpool/qualify-rpc.mjs` created nine successful transactions and
  one genuine failed transaction. It proved `status: succeeded`, ascending
  `(slot, transactionIndex)` ordering, inclusive `slot.gte`, exclusive
  `slot.gt`, four-page pagination without overlap/gaps, eight transactions in
  one slot, a valid Ed25519 precompile, and v0 address discovery through an
  ALT-loaded writable address. The failed transaction remained visible only
  under `status: any`.
- A fresh K=2 foundation created real SPL mints, governed vault/market/fee
  configuration, two Merkle shards, and the static settlement ALT. The
  proof-backed deposit/lock/release/expiry/withdraw lifecycle passed and
  generated VALID_DEPOSIT, VALID_INPUT, and VALID_SPEND proofs during the run.
- The production Rust `SolanaRpcClient` plus `MerkleSync::cold_boot` consumed
  nonempty native gTFA history and exactly matched both on-chain shard counts
  and roots: `applied=1`, `total_chain_leaves=1`, `shards=2`.
- The committed N=16 proof passed the production on-chain verifier in Surfpool:
  transaction `919` bytes, `96,371` compute units, and a real batch-validity
  marker account. This is actual Surfpool verifier evidence, not a mocked
  syscall result.
- The existing worst-shape LiteSVM settlement sentinel passed at `58,251` CU
  for six output leaves plus two relocks. The production Tx D compiler sentinel
  passed at `1,172` bytes with `60` bytes of headroom under Solana's 1,232-byte
  cap. These two deterministic sentinels complement the Surfpool verifier run;
  they are not being misreported as a full TEE settlement on Surfpool.
- No public or paid RPC, persistent keypair, dstack simulator, Phala CVM, or
  real devnet was used. Generated keys and configuration lived under a
  temporary/local Surfpool namespace.

Hosted Linux amd64 evidence:

- Workflow run
  [`33123121262`](https://github.com/skysail-labs/darknyx/actions/runs/33123121262)
  passed from a clean Ubuntu 22.04 checkout. It built the exact pinned source,
  installed the canonical vault, exercised nonempty gTFA, Ed25519, ALT/v0,
  generated VALID_DEPOSIT/VALID_INPUT/VALID_SPEND proofs, verified the committed
  N=16 proof on-chain, reconstructed exact K=2 roots, ran the CU/wire sentinels,
  and proved the localhost RPC closed during teardown.
- The ordinary affected CI matrix passed in run
  [`33123121293`](https://github.com/skysail-labs/darknyx/actions/runs/33123121293):
  circuits, Rust, SBF, SDK, TEE, TypeScript, Vault ZK/LiteSVM, dependencies,
  consistency, and aggregate `pr-checks success` were green.
- Source, SBF, circom, and generated circuit artefacts are cached against their
  complete immutable/source input fingerprints. Proof artefacts are required
  before the lifecycle step, so a clean runner cannot turn missing WASM into a
  skipped green test.

Stack-level evidence still owed:

1. Review and merge the Surfpool stack together, as explicitly selected after
   Phase 1, rather than merging PR #213 before starting Phase 2.
2. Preserve the evidence boundary: Phase 1 proves local SVM compatibility, not
   the Phase 3 host-TEE flow or a real Phala CVM.

### Phase 2 — repeatable foundation and oracle fixtures

Local Apple Silicon evidence, produced in two separate offline in-memory
Surfnet processes:

- `scripts/surfpool/foundation.sh cycle local-cycle-1` and
  `cycle local-cycle-2` each installed the canonical fingerprinted vault
  (`6c555594b2541171e79f27b63f5b3254946c74fbc8708181c203b0278b4a2db0`),
  created fresh K=2 mints, market, vault/fee configuration, Merkle shards, TEE
  signers, and settlement ALT, then proved PIDs and RPC/WS/Studio ports closed.
- Both SDK foundation runs passed in approximately 4.5 seconds. The production
  Rust oracle test itself passed in 2.69 seconds cold-run and 2.55 seconds on
  the second cycle; the first run additionally paid 97 seconds for a cold host
  Rust build after local build-cache cleanup.
- Each oracle run emitted the required non-vacuous marker:
  `cases=15 valid=1 rejected=14 recovered=14`. The mutations cover wrong PDA,
  owner, write authority, feed, verification level, stale/future time, invalid
  exponent, nonpositive spot/EMA, future posted slot, discriminator, trailing
  bytes, and truncated data. Every rejection then recovered through the same
  live production poller after installing a corrected account.
- The two ledgers produced distinct mint identities. Both configs named only
  `http://127.0.0.1:18899`, K=2, and their own `.surfpool/` state. Startup used
  the pinned binary with `--offline --host 127.0.0.1`; wildcard RPC and any
  datasource setting failed before process startup.
- Teardown deletes ephemeral keypairs and strips mint secret keys before
  retaining redacted gitignored evidence. No provider credential, public RPC,
  real devnet, dstack simulator, Phala CVM, wire/circuit/account change, CU
  change, or transaction-size change was involved.
- A final `local-cycle-hardening` rerun passed after adding version/hash capture,
  shell-safe environment generation, fixed `.surfpool/` state placement, and
  secret redaction; its archived evidence contained neither keypairs nor mint
  secret-key fields.

Hosted Linux amd64 evidence:

- [Run 33157645224](https://github.com/skysail-labs/darknyx/actions/runs/33157645224)
  passed in 10 minutes 33 seconds from a clean runner. It built the exact pinned
  Surfpool source as `surfpool 1.5.0` with Linux binary SHA-256
  `45773323666b0d3677496641902c846ae2cbd3d3af04de4a2c6f6bd62c0292c2`.
- `hosted-cycle-1` ran the full Phase 1 protocol qualification on a fresh K=2
  foundation, emitted `cases=15 valid=1 rejected=14 recovered=14` at Surfnet
  slot 426, and archived redacted evidence only after proving the PID and all
  three loopback ports closed.
- `hosted-cycle-2` created an independent process and empty ledger, emitted the
  same non-vacuous oracle marker at Surfnet slot 49, and again proved clean
  three-port teardown. Different slots and regenerated foundation identities
  make the repeat non-vacuous.
- The ordinary affected PR matrix also passed: Rust formatting/clippy/tests,
  circuits, SBF, SDK, TypeScript, TEE, vault LiteSVM/ZK, trader host, dependency
  audits, and consistency. CodeRabbit's six comments were individually
  verified: five were addressed and the tracker-status claim was rejected
  because section 9 gates Helius cancellation, not Phase 2 implementation.
- A local `linux/amd64` Docker reproduction with Node 22.23.2 and jq 1.6 passed
  shell/Node syntax, manifest generation, all six negative guards, the provider
  scan, and teardown probes before the final hosted run.

Evidence still owed before Phase 2 is `Closed`:

1. Merge the complete Surfpool stack only after the later phases selected for
   the same merge are ready; Phase 2 itself needs no CVM evidence.

### Phase 3 — production host TEE and proof-backed protocol matrix

Local Apple Silicon evidence, produced with an optimized production TEE binary
and a fresh offline Surfnet per flow:

- `scripts/surfpool/local-tee-matrix.sh all` emitted
  `PHASE3_MATRIX_PASS cases=6 mode=all`. The six independent cases were
  deposit-withdraw, merge, settle, multimatch, self-trade, and
  merge-then-order. The deposit-withdraw case includes release/expiry
  semantics; the settle case enables seed-plus-finalized-chain recovery.
- Every case installed the fingerprinted canonical vault at
  `C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx`, used real committed circuit
  artifacts, generated real client and TEE proofs, and ran the production
  Solana RPC, matcher, journal, and settlement paths. There is no local-only
  matcher, prover, vault program, or RPC adapter.
- The post-review installer check fetched the upgradeable loader's derived
  `ProgramData` account (`E3ndg5U5VT35b4JrJFGWk3h7R5tFFKnsQJRRRbZFVpGe`),
  stripped its 45-byte state header, and compared the deployed bytes with the
  built `target/deploy/vault.so`. Both 271,104-byte artifacts had SHA-256
  `6c555594b2541171e79f27b63f5b3254946c74fbc8708181c203b0278b4a2db0`;
  the devnet-admin build fingerprint was
  `8c28c019d12f9e16f718aae390f7980735426cc40b68887e7109a474112e601c`.
  Each matrix case creates a new empty in-memory ledger before installing the
  program and initializing K=2 trees, so there was no prior program/VK tree
  state to reset. An in-place program or VK change remains subject to the
  mandatory tree-reset rule.
- The guest API was dstack v0.5.9 at exact commit
  `282eeb27d22d8f091ad0fa5a90e638f85cf68751`. Discovery derived the exact K=2
  signer set through the production dstack client; the supervisor then rotated
  and funded both keys before governed boot. `DSTACK_SIMULATOR_ENDPOINT` is now
  rejected unless `DARKNYX_TEE_DEPLOYMENT_TIER=development`, and known test
  authentication remains disabled in this matrix.
- The settle case produced one confirmed crossing match, then cold-restarted
  the TEE without resetting Surfpool. The boot session changed, native gTFA
  replay rebuilt seven leaves, and the production mirror reported exact
  root/count matches: tree 0 had seven leaves at replay slot 114 and tree 1 had
  zero leaves. The empty second shard correctly retained `on_chain_slot = 0`;
  nonempty shards require a nonzero replay slot.
- A separate venue-wide `MerkleReadiness` pause is set before the sync task
  starts. Oracle/governance recovery cannot clear it; the local boot log showed
  it clearing only after every shard reconciled exactly, on both the empty
  first boot and the seven-leaf restart. Orders arriving in the small interval
  between HTTP bind and reconciliation therefore fail closed.
- The production SDK DCAP verifier rejected the simulator quote with
  `AttestationError.kind = quote_invalid`. Each archived result manifest names
  the untested boundary explicitly: Intel TDX isolation, Intel-valid DCAP,
  Phala KMS durability/access control, RA-TLS passthrough, and real-validator
  confirmation/finality/timing are not claimed.
- The four-match N=16 case confirmed all four Tx D settlements in one Surfnet
  slot. Its host-only benchmark record was: witness `659 ms`, Ark prove step
  `1,844 ms`, total prove `2,516 ms`, verify `259 ms`, total pipeline
  `3,137 ms`, with zero rejected/ambiguous results and zero rebroadcasts. These
  numbers qualify the local cadence only; they are not CVM or cluster latency.
- The final single crossing-settle evidence run recorded witness `675 ms`, Ark
  prove step `1,799 ms`, total prove `2,483 ms`, verify `765 ms`, and total
  pipeline `4,072 ms`, with one confirmed result, no rejection/ambiguity, and
  no rebroadcast. The pre-restart log is preserved separately so the cold boot
  cannot erase the timing record.
- The single-match self-trade-policy continuation settled with witness
  `672 ms`, Ark prove step `1,775 ms`, total prove `2,463 ms`, verify `261 ms`,
  and total pipeline `3,048 ms`. Merge-then-order settled with witness
  `693 ms`, Ark prove step `1,962 ms`, total prove `2,673 ms`, verify `259 ms`,
  and total pipeline `3,768 ms`.
- Persona and operator keys, API credentials, journal state, and local ledger
  files remained in `.surfpool/` and were removed on teardown. After every
  case, the supervisor proved RPC, WebSocket, and Studio ports
  `18899/18900/19488` closed. It archived local logs and result manifests only
  after deleting secret env files and state; those gitignored logs are not
  automatically redacted and must remain local.
- The oracle fixture installer refuses non-loopback RPC before issuing any
  request. The full matrix emitted `SURFPOOL_TEE_LOOPBACK_GUARD_PASS`; no
  public or paid Solana RPC and no Phala CVM was used.

Evidence still owed before Phase 3 is `Closed`:

1. Phase 4 must reproduce the selected local-TEE cadence on a clean hosted
   Linux amd64 runner with explicit execution markers and unconditional
   teardown. This is CI evidence, not a reason to weaken the full local matrix.
2. Review and merge the complete Surfpool stack. Phase 3 itself needs no real
   CVM evidence; the controlled real-CVM release gate remains Phase 5.

### Phase 4 — scheduled Surfpool integration and manual real-CVM boundary

Implementation on `infra/surfpool-ci`:

- `.github/workflows/surfpool-qualification.yml` is now the daily scheduled
  integration workflow. It builds the checksum-pinned Surfpool revision, the
  fingerprinted devnet-admin vault, the optimized production TEE, and the
  dstack v0.5.9 simulator at exact commit
  `282eeb27d22d8f091ad0fa5a90e638f85cf68751`. Circuit, Solana, Surfpool,
  workspace Rust, and dstack compiler outputs have source/pin-scoped caches.
- The prior real-devnet `nightly-devnet.yml` workflow is removed. Its only
  effective runtime gate was `RUN_DEVNET_E2E=1`; despite stale comments claiming
  all SDK devnet gates ran, merge/deposit-withdraw/leaf-index each required
  their own different flag and were skipped. The replacement therefore loses
  no executed coverage and adds real deposit/withdraw plus production-TEE
  settlement coverage.
- `scripts/surfpool/hosted-smoke.sh` runs two fresh-ledger cases: the client
  deposit/withdraw/lock-expiry lifecycle and one crossing TEE settlement. It
  fails unless the output contains the loopback guard, both case-pass markers,
  exact nonempty K-root restart reconciliation, simulator-quote rejection, and
  the two-case matrix marker. Its own exit trap and the workflow's independent
  `if: always()` step both stop local processes and require ports
  `18080/18899/18900/19488` to be closed.
- `scripts/check-surfpool-workflow-boundaries.sh` runs in both ordinary PR CI
  and the scheduled workflow. It rejects a provider/public RPC, GitHub secret,
  missing scheduled smoke, missing cleanup assertion, a restored paid-devnet
  workflow, or a recurring real-CVM/sweeper schedule.
- `cvm-e2e.yml` remains fully dispatchable with immutable-image resolution,
  real devnet/TDX/RA-TLS checks, and unconditional CVM stop, but has no recurring
  trigger. The emergency sweeper runs automatically after that workflow
  completes, including cancellation, is also manually dispatchable, and shares
  the existing concurrency group so it cannot race a live release run. Weekly
  GHCR image retention remains scheduled because it starts no CVM and calls no
  Solana RPC; the source guard enforces that separate boundary.
- Local source checks passed: both new shell scripts parse, the workflow
  boundary guard passes, the port probe parses, and `git diff --check` is clean.
  No provider credential, public RPC, Phala CVM, circuit, wire, account layout,
  program behavior, CU, or transaction-size change is involved.
- The first clean hosted attempt reached the production-TEE smoke after both
  foundation cycles, then correctly failed before settlement because Actions
  had checked out `match_batch_n16/circuit_final.zkey` as a 132-byte Git LFS
  pointer. Ark surfaced this late as `read_zkey ... Invalid argument`. The
  independent teardown still proved all five ports closed. The workflow now
  hydrates LFS during checkout, excludes committed zkeys from the generated
  circuit cache, invalidates the pointer-contaminated cache generation, and
  rejects every required proving key smaller than 100,000 bytes before builds.

Evidence still owed before Phase 4 is `Surfpool validated`:

1. A clean hosted Linux amd64 run must emit
   `PHASE4_HOSTED_SMOKE_PASS cases=2 proofs=real` and
   `PHASE4_TEARDOWN_PASS ports=18080,18899,18900,19488`, with all nested required
   markers present and no skipped protocol case.
2. The ordinary affected PR matrix and review must pass. Record the exact run
   URL and elapsed time here before advancing CI-01…CI-03.
3. `Closed` remains reserved for the merged full stack. Phase 4 does not need a
   billable CVM run; the controlled real-CVM baseline is Phase 5.
