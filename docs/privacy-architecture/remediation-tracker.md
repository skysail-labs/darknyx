# Privacy architecture remediation tracker

**Created:** 2026-08-25

**Last updated:** 2026-08-25

**Canonical design:**
[`remediation-plan.md`](remediation-plan.md)

**Phase 0 evidence:**
[`phase0-report.md`](phase0-report.md)

**Frozen formula vectors:**
[`phase0-vectors.json`](phase0-vectors.json)

**Current phase:** Phase 1 implementation complete; review and hosted CI are
pending

**Mainnet status:** blocked on mandatory implementation, devnet/CVM evidence,
independent circuit/privacy review, and Phase-2 ceremony

This file tracks implementation state. It does not rewrite the threat analysis
or formulas in the canonical plan. Finding IDs and severity do not change here.
Move a row only as far as its evidence supports.

---

## 1. Status meanings

| Status | Meaning |
|---|---|
| `Open` | Current code still has the finding and no completed validation/design decision exists. |
| `Validated` | The finding was reproduced or its stale-data/reader claim was confirmed; production code is not fixed. |
| `Design frozen` | The replacement and migration semantics are decided; production code is not fixed. |
| `Code complete` | Implementation and required local tests are complete, but hosted/external gates remain. |
| `Hosted validated` | Required devnet/CVM evidence exists, but audit/ceremony or final release gates remain. |
| `Closed` | Every required code, local, hosted, documentation, audit, and ceremony gate for the row is complete. |
| `Deferred` | Explicitly outside the current release, with a trigger and review date. |

`Code complete` is never synonymous with `Closed`. Circuit findings stay open
through generated-artifact parity, SBF verification, CVM evidence, independent
review, and ceremony.

---

## 2. Bird's-eye tracker

| ID | Severity | Status | Phase | Invariant restored | Circuit/wire impact | Next action |
|---|---|---|---:|---|---|---|
| PA-01 | High privacy | **Validated** | 3/4 | A fee output cannot reveal its input leaf without the governed epoch key, and the protocol can recover inner plus amount from key plus finalized chain. | MATCH_BATCH/config v2; Tx B +280 B; authorized verifier payer; fee epoch config | Implement v2 circuit/config/recovery bundle atomically in Phase 3. |
| PA-02 | High privacy | **Validated** | 3/4 | A merge descendant retains at least one observer-secret input and remains seed-plus-chain recoverable. | VALID_MERGE K2/K4 formula/domain change; public inputs unchanged | Replace public commitments with private input inners in Phase 3. |
| PA-03 | Medium privacy/architecture | **Validated** | 1 | No unused public wallet-identity edge, account, circuit, VK, or key hierarchy remains in the launch surface. | Deletes VALID_WALLET_CREATE and wallet-create wire/API | Review Phase 1 PR and complete hosted CI before moving to Code complete. |
| PA-04 | Low security / High volume cost | **Validated** | 2 | Exact eternal deposit/consume guards retain only the typed existence bit needed for replay safety. | Account data layout changes; PDA seeds unchanged | Implement discriminator-only accounts and compatibility tests in Phase 2. |
| PA-05 | Low security / Medium transient cost | **Validated** | 2 | Locks retain mint/order/expiry enforcement without duplicated tag or unused signer. | `NoteLock` layout and SDK/raw offsets change; seeds unchanged | Remove fields and regenerate layout contracts in Phase 2. |
| PA-06 | Medium recoverability | **Design frozen** | 1 | Normal deposits use a canonical random public nonce; explicit nonce exists only for exact retry/test/recovery. | SDK/API change; VALID_DEPOSIT public-input count unchanged | Review Phase 1 PR; then collect the required devnet exact-retry evidence. |
| PA-07 | Low privacy/complexity | **Validated** | 3 | VALID_SPEND exposes only the shared canonical use tag and no dead nullifier. | VALID_SPEND public inputs/instruction/event shrink | Remove in atomic Phase 3 proof cutover. |
| PA-08 | Design simplification | **Design frozen** | 3 | Owner privacy relies on one high-entropy spend secret, not two same-keystore derivatives presented as independent. | All note circuits/formulas change under domain 32 | Implement `Poseidon2(32, spending_key)` in Phase 3. |
| PA-09 | Design/documentation | **Design frozen** | 3 | Deposit inner contains the public recovery nonce and private note secret without redundantly repeating owner. | VALID_DEPOSIT/formula change under domain 33 | Implement in Phase 3 and prove canonical-client recovery. |
| PA-10 | Low product coherence | **Design frozen** | 1 | Active key documentation/code contains the live X25519 recovery key only; unwired BN254 compliance hierarchy is deferred as a fresh future design. | Keystore/SDK/Rust deletion; no live fill wire change | Review Phase 1 PR and complete hosted CI before moving to Code complete. |
| PA-11 | Medium correctness | **Validated** | 1/2/3 | Commitment and use-tag types cannot be confused internally, and one checked registry owns every domain assignment. | Internal newtypes/brands; no wire change; CI registry becomes authoritative in Phase 3 | Phase 1 clean-output guard is implemented; newtypes remain Phase 2 and registry CI remains Phase 3. |
| PA-12 | Medium review/documentation | **Validated** | 3 | Every descendant note identifies its observer-secret inner input, recovery owner, and constraining circuit accurately. | Documentation/comments only after formulas change | Update with Phase 3 implementation, not before. |

---

## 3. Phase ledger

| Phase | Branch | Scope | Status | PR/commit | Required evidence before advancing |
|---:|---|---|---|---|---|
| 0 | `privacy/coherence-measurements` | PoCs, benchmark, reader inventory, design/domain freeze | **Merged** | PR #202 / `ef111b1b` | Complete; no production behavior changed |
| 1 | `privacy/remove-wallet-identity` | PA-03/06/10 + clean-build part of PA-11 | **Implementation complete; targeted local gates passed; hosted CI pending** | PR pending | hosted full clippy/SBF/workspace gate, review, merge; PA-06 devnet retry remains after merge |
| 2 | `privacy/compact-note-state` | PA-04/05 + commitment/tag internal types | Not started | — | litesvm lifecycle/replay tests, layout parity, rent/CU/Tx measurements |
| 3 | `privacy/note-lineage-v2` | atomic circuit/config/wire flag day | Not started | — | all artifacts/vectors/parity, SBF, serializer sizes, negative mutation tests |
| 4 | `privacy/fee-recovery-v2` | protocol/user recovery operations if not wire-coupled into Phase 3 | Not started | — | journal-loss and epoch-rotation recovery drills |
| 5 | `privacy/release-assurance` | devnet/CVM evidence, docs, external gates | Not started | — | final evidence table, independent review, ceremony, mainnet build/deploy checks |

Phase 3 must not be split into independently deployable old/new semantics. It
may contain reviewable commits, but all consume paths, circuits, artifacts,
config, wire encoders/decoders, and recovery logic land as one flag day.

---

## 4. Phase 0 evidence index

### PA-01

- Legacy fixed vector reproduced.
- Planted fee `37037` recovered in 3,236 ms.
- Full-range measurements: 11.25–11.38k hashes/s serial; 53.89k hashes/s with
  eight workers.
- Frozen domains 35/36 and match-config domain 37.
- Fixed encrypted N=16 Tx B recovery record selected: 256-byte plaintext,
  272-byte ciphertext, explicit 8-byte epoch.
- Projected Tx B size: 931 bytes with priority fee, 301 bytes headroom.
- Production implementation and negative v2 test remain open.

### PA-02

- Legacy K=2 candidate commitments reconstruct later output use tag exactly.
- Frozen domain 34 uses private input inners at unchanged Poseidon6 arity.
- Production circuit/parity/recovery implementation remains open.

### PA-03/04/05/07/11/12

- Current consumers revalidated against source.
- `DepositedNoteEntry` and `ConsumedNoteEntry` payload fields have no production
  authorization/recovery reader; account existence and seeds remain required.
- `NoteLock.note_use_tag` is a duplicated seed read only for a release event;
  `locked_by` is write-only. Mint/order/expiry/bump are live.
- Wallet-create identity has no deposit/order/settle/merge/withdraw authorization
  consumer.
- VALID_SPEND nullifier has no replay-state consumer.
- Domain inventory has active/retired/provisional assignments.

### PA-06/08/09/10

- PA-06: canonical random field nonce with explicit expert retry path selected.
- PA-08: one-secret owner domain 32 selected.
- PA-09: nonce-plus-note-secret deposit inner domain 33 selected.
- PA-10: unwired BN254 compliance hierarchy removed/deferred; live X25519 path
  explicitly preserved.

Full vectors, host measurements, formulas, recovery cryptography, field-reader
table, and commands are in the Phase 0 report rather than duplicated here.

---

## 5. Finding execution records

These records receive concrete PRs, SHAs, commands, signatures, and rollback
instructions as implementation proceeds.

### PA-01 — fee lineage and durable recovery

- **Owner:** unassigned
- **PR/commit:** pending Phase 3
- **Invariant:** no public-data fee dictionary without the governed epoch key;
  protocol recovers every finalized fee note after online-state loss.
- **Local evidence required:** fixed vector parity; wrong-key/stale-epoch proof
  rejection; AEAD tamper/AAD tests; finalized/failed-slot recovery filtering;
  exact serialized Tx B/Tx D assertions.
- **Devnet evidence required:** nonzero fee settle, verifier CU, Tx B/D sizes,
  fee opening recovery from finalized transactions only.
- **CVM evidence required:** settle, multimatch, journal-loss recovery, epoch
  rotation, explicit negative public-data linker.
- **External evidence:** independent circuit/privacy review and Phase-2
  ceremony.
- **Rollback:** before tree reset, revert program/image/config together; after
  reset, rollback requires another complete drain/reset/config/image flag day.

### PA-02 — merge lineage

- **Owner:** unassigned
- **PR/commit:** pending Phase 3
- **Invariant:** public commitments and bitmap cannot derive a merge descendant
  tag; owned private inners recover it byte-for-byte.
- **Local evidence required:** K2/K4 artifacts and parity; cold recovery;
  negative PoC; mutation restoring commitment derivation makes test fail.
- **Devnet evidence required:** K2/K4 merge and consumed-PDA checks.
- **CVM evidence required:** merge-then-order from fresh tree/cold boot and
  observer-negative assertion.
- **External evidence:** independent circuit/privacy review and ceremony.
- **Rollback:** same atomic flag-day rule as PA-01.

### PA-03 / PA-06 / PA-10 — Phase 1 client/identity cleanup

- **Owner:** Phase 1 implementation agent
- **PR/commit:** branch `privacy/remove-wallet-identity`; PR pending
- **Invariant:** launch code has no unused wallet-registration identity or BN254
  disclosure hierarchy; deposit construction is random-nonce and recoverable.
- **Implementation:** deleted VALID_WALLET_CREATE source/zkey/VK, its vault
  instruction/account/PDA, Rust/TS wallet-commitment helpers, and registration
  tests; retained Anchor error slot 6008 as a retired placeholder so later wire
  error codes do not move. Removed unwired BN254 root/viewing derivations while
  preserving the live X25519 fill-recovery path. Daemon keystore v3 persists
  only the master seed, strictly reads v1/v2, and atomically rewrites them to
  v3. Ordinary deposits now rejection-sample a fresh nonzero canonical Fr
  nonce; the separately named retry API accepts an explicit nonce only for an
  exact note/public-statement redrive (proof bytes may be randomized). The
  browser artifact set now contains the five surviving
  client circuits under a fresh set ID.
- **Local evidence recorded:** deletion/reference sweep found no live wallet
  circuit/API consumers; Rust key KATs 7/7; vault layout 4/4; daemon 229/229
  active tests; SDK 408 active tests plus 42/42 localhost transport tests run
  outside the listener sandbox; browser 74/74 and production build; client-core
  21/21; proving-benchmark fixture 1/1; all six TypeScript test-inclusive
  typechecks passed after installing the four lockfile-pinned Wallet Standard
  packages in a disposable test prefix. Clean-output validation exposed and
  fixed stale `tsconfig.tsbuildinfo` retention. Repository guards for image
  digests, CUDA env, namespace, debug endpoints, process markers, doctests, and
  script awaits passed. `cargo fmt --check` and `git diff --check` passed.
- **Pending local/hosted gate:** workspace clippy was stopped without a code
  diagnostic when only 317 MB of disk remained while Cargo materialized a new
  target graph; the disposable target was then cleaned. Hosted CI must supply
  the full clippy/SBF/workspace result before these rows move to Code complete.
- **Local evidence required:** deletion reference sweep, keystore migration,
  backup round-trip, exact-retry/ambiguous-submit tests, seed-plus-chain deposit
  recovery, full local gate.
- **Hosted evidence:** none required solely for deletion; devnet deposit retry
  is required for PA-06 before closure.
- **Rollback:** code-only before new keystore v3 is written; while migrating,
  retain a reader for v2 backups but never regenerate or replace a seed.

### PA-04 / PA-05 — Phase 2 account compaction

- **Owner:** unassigned
- **PR/commit:** pending
- **Invariant:** replay sets remain exact and eternal; lock mint/order/expiry
  semantics remain unchanged under lean layouts.
- **Local evidence required:** layout fixtures, SDK parity, litesvm deposit
  replay, cross-consume guard, live/expired/release/settle tests; measured rent,
  CU, and Tx sizes.
- **Hosted evidence:** devnet reset and lifecycle smoke before reuse.
- **Rollback:** development state is reset; no dual-layout mainnet path is
  required because no mainnet notes exist.

### PA-07 / PA-08 / PA-09 / PA-11 / PA-12 — Phase 3 proof cleanup

- **Owner:** unassigned
- **PR/commit:** pending
- **Invariant:** proof statements contain only live identities, one authoritative
  domain registry, and byte-identical Rust/TS/Circom meanings.
- **Local evidence required:** all circuit artifacts, public-input order tests,
  owner/deposit vectors, registry CI, branded/newtype boundary checks, clean
  `dist/`, full local gate.
- **Hosted/external evidence:** SBF/devnet/CVM plus independent review and
  ceremony.
- **Rollback:** atomic flag-day rule; never mix old notes/proofs with v2.

---

## 6. Open mainnet gates

All remain open:

- [ ] Phase 1 merged with keystore/deposit recovery evidence.
- [ ] Phase 2 merged with exact replay/lock semantics and measured layouts.
- [ ] Phase 3 atomic cutover merged with every source/artifact/vector in sync.
- [ ] Clean reset of every Merkle shard and post-reset sync floor recorded.
- [ ] User seed-plus-chain full-lineage recovery drill passed.
- [ ] Protocol fee key-plus-chain recovery and epoch-rotation drill passed.
- [ ] Devnet SBF/CU/transaction-size evidence recorded.
- [ ] CPU CVM settle, multimatch, merge-then-order, recovery, and observer
  negative checks passed on digest-pinned images.
- [ ] Independent circuit/privacy review has no unresolved Critical/High.
- [ ] Circuit sources frozen after remediation.
- [ ] Public Phase-2 ceremony and reproducible artifact verification complete.
- [ ] Mainnet build excludes `devnet-admin`; program hash and all authorities
  independently verified.

No real-value deposit is permitted while any mandatory gate remains open.

---

## 7. Continuation directive for another agent

An agent can safely resume between phases by following this sequence:

1. Read `CLAUDE.md`, the canonical plan, this tracker, and the Phase 0 report.
2. Fetch latest merged `main`; inspect the worktree before creating the branch.
   Preserve all user-owned dirty/untracked files and submodule state.
3. Select the earliest non-blocked phase. Do not begin Phase 3 piecemeal.
4. Revalidate each row against current code before editing; source may have
   changed since 2026-08-25.
5. Create the branch named in the phase ledger from latest `main`.
6. Keep each PR limited to its PA IDs. List invariant, circuit/wire impact,
   migration, rollback, exact tests, and evidence.
7. Update this tracker in the same PR, but move a row only as far as evidence
   supports.
8. For circuit work, land source, zkey, VK, fixtures, Rust/TS/Circom helpers,
   docs, journal/wire versions, and image tag atomically.
9. Use the private Helius endpoint for devnet/CVM. Never write its key to docs,
   logs, commits, or command output.
10. Do not start a billable CVM until local/devnet gates pass. Record timing,
    signatures, digest, compose hash, app ID, and stop state.

Every handoff must contain:

```text
Phase / PA IDs:
Branch / HEAD SHA / PR:
Merged base SHA:
Dirty or untracked files (and owner):
Code/artifacts changed:
Commands run and exact results:
Devnet signatures / CU / sizes:
CVM app / digest / compose hash / signatures / timings / running state:
Tracker rows moved (and evidence supporting the move):
Blockers or external decisions:
Exact next action:
```

If a phase is only locally complete, say so. Never infer `Closed` from green CI
or a merged PR when hosted, external-review, or ceremony evidence remains.
