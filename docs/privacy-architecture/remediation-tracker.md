# Privacy architecture remediation tracker

**Created:** 2026-08-25

**Last updated:** 2026-08-25

**Canonical design:**
[`remediation-plan.md`](remediation-plan.md)

**Phase 0 evidence:**
[`phase0-report.md`](phase0-report.md)

**Frozen formula vectors:**
[`phase0-vectors.json`](phase0-vectors.json)

**Current phase:** Phase 3 is merged. Phase 4 recovery operations are code
complete on `privacy/fee-recovery-v2`; its PR and hosted evidence are pending.
Devnet and a full CVM settlement remain Phase 5 gates.

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
| PA-01 | High privacy | **Code complete** | 3/4 | A fee output cannot reveal its input leaf without the governed epoch key, and the protocol can recover inner plus amount from key plus finalized chain. | MATCH_BATCH/config v2; Tx B +280 B; authorized verifier payer; fee epoch config | Run the two-epoch finalized-chain recovery/spend drill and negative-linkability check in Phase 5. |
| PA-02 | High privacy | **Code complete** | 3/4 | A merge descendant retains at least one observer-secret input and remains seed-plus-chain recoverable. | VALID_MERGE K2/K4 formula/domain change; public inputs unchanged | Exercise devnet merge and Phase 5 merge-then-order/recovery evidence. |
| PA-03 | Medium privacy/architecture | **Code complete** | 1 | No unused public wallet-identity edge, account, circuit, VK, or key hierarchy remains in the launch surface. | Deletes VALID_WALLET_CREATE and wallet-create wire/API | Retain as code complete pending final external/release assurance. |
| PA-04 | Low security / High volume cost | **Hosted validated** | 2 | Exact eternal deposit/consume guards retain only the typed existence bit needed for replay safety. | Account data layout changes; PDA seeds unchanged | Retain for final release assurance; hosted replay and exact 8-byte layouts passed. |
| PA-05 | Low security / Medium transient cost | **Code complete** | 2 | Locks retain mint/order/expiry enforcement without duplicated tag or unused signer. | `NoteLock` layout and SDK/raw offsets change; seeds unchanged | Exercise settlement-created continuation locks in the Phase 5 CVM run. |
| PA-06 | Medium recoverability | **Hosted validated** | 1 | Normal deposits use a canonical random public nonce; explicit nonce exists only for exact retry/test/recovery. | SDK/API change; VALID_DEPOSIT public-input count unchanged | Retain for final release assurance; exact devnet retry is recorded. |
| PA-07 | Low privacy/complexity | **Code complete** | 3 | VALID_SPEND exposes only the shared canonical use tag and no dead nullifier. | VALID_SPEND public inputs/instruction/event shrink | Retain pending hosted proof verification and external release assurance. |
| PA-08 | Design simplification | **Code complete** | 3 | Owner privacy relies on one high-entropy spend secret, not two same-keystore derivatives presented as independent. | All note circuits/formulas change under domain 32 | Retain pending hosted proof verification and external release assurance. |
| PA-09 | Design/documentation | **Code complete** | 3/4 | Deposit inner contains the public recovery nonce and private note secret without redundantly repeating owner. | VALID_DEPOSIT/formula change under domain 33 | Repeat canonical seed-plus-chain recovery against finalized devnet history in Phase 5. |
| PA-10 | Low product coherence | **Code complete** | 1 | Active key documentation/code contains the live X25519 recovery key only; unwired BN254 compliance hierarchy is deferred as a fresh future design. | Keystore/SDK/Rust deletion; no live fill wire change | Retain as code complete pending final external/release assurance. |
| PA-11 | Medium correctness | **Code complete** | 1/2/3 | Commitment and use-tag types cannot be confused internally, and one checked registry owns every domain assignment. | Internal newtypes/brands; no wire change; CI registry is authoritative | Retain registry CI and semantic-boundary checks through release assurance. |
| PA-12 | Medium review/documentation | **Code complete** | 3 | Every descendant note identifies its observer-secret inner input, recovery owner, and constraining circuit accurately. | Documentation/comments changed with formulas | Revalidate public/internal prose after Phase 4 recovery operations. |

---

## 3. Phase ledger

| Phase | Branch | Scope | Status | PR/commit | Required evidence before advancing |
|---:|---|---|---|---|---|
| 0 | `privacy/coherence-measurements` | PoCs, benchmark, reader inventory, design/domain freeze | **Merged** | PR #202 / `ef111b1b` | Complete; no production behavior changed |
| 1 | `privacy/remove-wallet-identity` | PA-03/06/10 + clean-build part of PA-11 | **Merged; hosted CI and devnet retry passed** | PR #203 / `b11e1fc0` | complete; final external/release assurance remains |
| 2 | `privacy/compact-note-state` | PA-04/05 + commitment/tag internal types | **Merged; CI and non-settlement devnet evidence passed** | PR #204 / `96222ffe` | settlement-created relock evidence remains in the Phase 5 CVM run |
| 3 | `privacy/note-lineage-v2` | atomic circuit/config/wire flag day | **Merged; local gates passed** | PR #206 / `3e720377` | hosted/external gates remain |
| 4 | `privacy/fee-recovery-v2` | finalized-chain fee collector, epoch-key custody, recovery operations, secret-safe diagnostics | **Code complete; PR pending** | pending | focused Rust/TS recovery, tamper, two-epoch, failed-slot, backup, inventory, RPC, and redaction tests pass; hosted drill remains |
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
- Phase 3 cryptography, proof binding, Tx B wire, and negative tests are code
  complete. The Phase 4 finalized-chain collector and rotation tooling are code
  complete; the Phase 5 hosted rotation/recovery drill remains.

### PA-02

- Legacy K=2 candidate commitments reconstruct later output use tag exactly.
- Frozen domain 34 uses private input inners at unchanged Poseidon6 arity.
- Production K2/K4 circuit, parity, and cold-recovery implementation is code
  complete; hosted merge evidence remains.

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

- **Owner:** Phase 3/4 implementation agents
- **PR/commit:** Phase 3 PR #206 / merge `3e720377`; Phase 4
  `privacy/fee-recovery-v2`, PR pending
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
- **Phase 3 implementation:** fee-note inners now use
  `Poseidon4(36, fee_epoch_key, consumed_use_tag, role)` and proofs bind
  `Poseidon2(35, fee_epoch_key)` plus the monotonic epoch through config digest
  domain 37. `verify_match_batch` requires an authorized TEE payer and carries
  an epoch plus a fixed 272-byte XChaCha20-Poly1305 recovery record. Wrong key,
  epoch, root, market, mint, ciphertext, and proof binding all fail closed.
- **Phase 3 local evidence:** worst-case Tx B is 931 bytes (301 bytes
  headroom); the N=16 verifier consumed 96,221 LiteSVM CU; wrong fee key,
  stale epoch, and unregistered payer regressions pass. Fee-recovery AEAD and
  canonical-domain-v12 vectors pass. That evidence alone did not satisfy
  finalized-chain collection or epoch-rotation operations.
- **Phase 4 implementation:** `@darknyx/fee-collector` scans successful
  transactions at finalized commitment, reconstructs Tx D's depth-four batch
  root, authenticates the Tx B recovery record against its historical governed
  epoch/binding and immutable market identity, recomputes fee inners and note
  commitments, and requires the scoped `TradeSettled` leaf. Encrypted epoch
  keyrings retain old keys; encrypted inventories are reproducible caches.
  Rotation, backup verification, deployment-secret handling, archival recovery,
  and disaster recovery are defined in
  [`../protocol-fee-recovery-runbook.md`](../protocol-fee-recovery-runbook.md).
  Private TEE configs, witnesses, and note-opening stores now have redacted
  `Debug` output.
- **Phase 4 local evidence:** two epochs recover four fee notes; non-finalized
  slots create no phantom notes; missing keys/Tx B/config/events, wrong binding,
  ciphertext tamper, and commitment substitution are unresolved failures. Rust
  and TypeScript fee-recovery ciphertexts match byte-for-byte. Keyring backup,
  monotonic rotation, mode-0600 sealed storage, inventory authentication,
  finalized gTFA request shape, credential redaction, and private-debug
  redaction tests pass. Hosted recovery/spend evidence is still required before
  advancing beyond `Code complete`.

### PA-02 — merge lineage

- **Owner:** Phase 3 implementation agent
- **PR/commit:** `privacy/note-lineage-v2`; PR pending
- **Invariant:** public commitments and bitmap cannot derive a merge descendant
  tag; owned private inners recover it byte-for-byte.
- **Local evidence required:** K2/K4 artifacts and parity; cold recovery;
  negative PoC; mutation restoring commitment derivation makes test fail.
- **Devnet evidence required:** K2/K4 merge and consumed-PDA checks.
- **CVM evidence required:** merge-then-order from fresh tree/cold boot and
  observer-negative assertion.
- **External evidence:** independent circuit/privacy review and ceremony.
- **Rollback:** same atomic flag-day rule as PA-01.
- **Phase 3 implementation/evidence:** VALID_MERGE K2/K4 derives the output
  inner from four private input inners plus the active bitmap under domain 34;
  public-input counts remain 6/8. Regenerated artifacts, Rust/TS parity,
  malformed/all-dummy rejection, K2/K4 LiteSVM verification, and cold-recovery
  tests pass.

### PA-03 / PA-06 / PA-10 — Phase 1 client/identity cleanup

- **Owner:** Phase 1 implementation agent
- **PR/commit:** PR #203; merge `b11e1fc0`
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
- **Hosted gate:** PR #203 passed hosted CI before merge. The 2026-08-25 Phase 2
  devnet lifecycle run reused the exact note/public statement, rejected the
  duplicate deposit atomically, and observed the unchanged 8-byte replay
  marker, completing PA-06's explicit retry evidence.
- **Local evidence required:** deletion reference sweep, keystore migration,
  backup round-trip, exact-retry/ambiguous-submit tests, seed-plus-chain deposit
  recovery, full local gate. **Complete.**
- **Hosted evidence:** none required solely for deletion; PA-06's devnet retry
  is recorded with the Phase 2 signatures below.
- **Rollback:** code-only before new keystore v3 is written; while migrating,
  retain a reader for v2 backups but never regenerate or replace a seed.

### PA-04 / PA-05 — Phase 2 account compaction

- **Owner:** Phase 2 implementation agent
- **PR/commit:** PR #204; merge `96222ffe`
- **Invariant:** replay sets remain exact and eternal; lock mint/order/expiry
  semantics remain unchanged under lean layouts.
- **Implementation:** `DepositedNoteEntry` and `ConsumedNoteEntry` are
  discriminator-only 8-byte accounts; `NoteLock` is 72 bytes containing only
  mint, order ID, expiry, bump, and alignment padding. Every on-chain creator,
  manual settle/merge allocation, SDK decoder, TEE lock sweeper, fixture, and
  raw expiry offset uses the generated layout. A 136-byte lock fails closed and
  requires the planned development reset; 56/72-byte replay markers remain
  occupied guards because no payload field is read.
- **Semantic boundary:** Rust `NoteCommitment` and `NoteUseTag` transparent
  newtypes plus TypeScript branded checked constructors separate equal-width
  identities internally. Borsh/JSON boundaries remain byte-identical, and
  compile-time `@ts-expect-error` guards reject commitment-to-tag PDA calls.
- **Rent evidence (lamports):** deposit marker 1,280,640 -> 946,560 (save
  334,080); consumed marker 1,392,000 -> 946,560 (save 445,440); live lock
  1,837,440 -> 1,392,000 (save 445,440). The fixture pins canonical Solana
  rent parameters and exact old/new deltas.
- **Local CU/size evidence:** proof-backed `lock_note` 101,076 CU versus the
  last recorded 117,943-CU devnet baseline; deposit 137,168 CU; merge K=2
  145,711 CU; withdraw 133,774 CU; worst-case six-leaf/two-relock Tx D 58,251
  CU. Tx D is 1,172 bytes with 60 bytes headroom, so packet headroom does not
  regress. Hosted devnet measurements remain mandatory because runtime CU can
  differ from LiteSVM.
- **Local lifecycle evidence:** real deposit replay rejects before a second
  token movement; withdraw->settle, settle->withdraw, and settle->merge collide
  on one tag namespace; live/expired/released locks behave at the exact expiry
  boundary; mismatched order/mint/expiry and continuation TTL checks pass;
  layout JSON parity and lock-sweeper offset/dedup tests pass.
- **Completed local gates:** final `devnet-admin` SBF fingerprint plus 36
  focused vault lifecycle tests; workspace nextest 892/892; artifact-required
  TEE nextest 701/701; clippy with warnings denied; all six test-inclusive
  TypeScript typechecks; SDK 439 non-listener tests plus 42 localhost transport
  tests; browser 74 tests plus production build; indexer/daemon/client-core/
  trader-host 305 tests; repository guards and dependency audits. Localhost
  suites were rerun outside the macOS sandbox after their first attempts were
  denied permission to bind mock servers.
- **Gate repair:** removed stale deleted/default-disabled binary names from the
  nextest heavy-test filter. The obsolete entries made nextest reject its
  configuration before any test could run after Phase 1's deletions.
- **Local evidence required:** layout fixtures, SDK parity, litesvm deposit
  replay, cross-consume guard, live/expired/release/settle tests; measured rent,
  CU, and Tx sizes. **Complete.**
- **Hosted evidence (2026-08-25, private Helius devnet):** upgraded the
  canonical program in place
  (`SRJyPDPMoSrW5KGX77orzeHzc7541h9yUPtxzv6AbG5m11Ukgv6XZJV4h9qNJ8evMsJkJAikDNd3usC66uruipf`),
  regenerated the four-shard foundation with fresh mints and ALT, and reset
  shards 0..3. The repeatable `RUN_DEVNET_DW=1` test then proved a real deposit
  and VALID_INPUT lock, rejected the exact deposit replay atomically, observed
  an 8-byte deposit marker, rejected release while live, observed and parsed a
  72-byte lock, released it at expiry, re-locked, withdrew through the expired
  lock, observed an 8-byte consume marker, rejected re-lock after consumption,
  restored the original four-key signer set in `finally`, and reclaimed the
  temporary signer's balance. The final run passed in 42.29 seconds. The
  isolated `RUN_DEVNET_MERGE=1` deposit -> merge(K=2) -> withdraw test also
  passed.
- **Reset signatures:** shard 0
  `2hMd6V65QUMxjRBCKvA1HFLv2y1pSotCpRmUgabR3YkQWiSw56B2hcmpiUMvRrtL96eofifjnD3r4qq6XQdgesGT`;
  shard 1
  `4bbYNV4dbhGbvUfVrVruUL1u1rSK9VcdcDjgBwuQSSRkz2TBoCXcX1HSxxafjswufVAaL7BiZNJkKXkJv1zxj7Js`;
  shard 2
  `6gWpZR6pyFS3YjnZM4RrKFFrJc2pRNnJSKbvvVRWhLimsza4s1x1repYGaM27skm7A15N6gHiMaLTz2S3kyj9m7`;
  shard 3
  `5LGXjX7dD43cpq5j4yDuPFR66vm7XvagiZQ22dkjgAcB4LE4rjgixaUjg3McWyJpjn6Jkg3rQ7smpZaZ7wWVoocS`.
- **Final lifecycle signatures:** deposit
  `4qrqdP2D1Zm7hKWAea4ANYE4B2uv1pPJpU9TF2vjXZAEsBe339RgLLdFa3WpT4aCKVsvLfjHfb7QurrfnxyeXqY8`;
  temporary signer rotation
  `3t1XAxrHMu3n1pYGBaBbFpQysExFx929YNujnKc4S3J81ZEge4QUgVba7X27LMYbzKDBS79bECxw9FeDuErAau6`;
  first lock
  `5qswkxcy3fmWmCcnY5p8KsggQjix7tJvPG5mbCTBsJjxF4y2sXyLiKDrxRi6CYRJsgM2DMtQQaLmYB1V8t41pLSu`;
  first release
  `34eCzcM1WEvtYiuEjcKExmUgypuMiQDbWkLxQsDohjounu7EaJu7BExbGBSuCjrLS3Lmn6jQdvtFg8iGEUY6vYif`;
  second lock
  `5yQ7rQf9qP9aNUyAQy4QnDLyE3cr6bv32zPBMefwJKJvAk4uCuZnSXhgQ2e3e6Ur69SSCjT4yvwMxJMCgPLE4U5j`;
  withdraw
  `3VrD9mjBndrk8XCr6xZmoHeMaJ8fBgjYWdFZyXes2ved7XiLNvEDvbSvmCJtX5RRMDY4kU3wgk2U8t2bVtU9hCcf`;
  expired-lock release
  `5LZarJgjbAGcHtr58Axm2g9HhpAP3fAPNTcs5gSEpqzVeNgqXaEw1KNU2i7psiiuKUe3ieghM24PY7kvea8jFzce`;
  signer restore
  `2LiWdGxH9f6TmUxxKJj55sBUdQVYYWhKvqKVpwrowHuGaAne9MmjixkdK29ygjs9SV4QV6ADeV3SG3y4mzxrFCWJ`;
  balance reclaim
  `oqmEV65D4YsKBTosRitNJQm2jY3qfUm4xc7fKq2CwJPFpjixU3D8WLQ6jorjdwoaaL6wqmRvSzRAkjjstihqQFy`.
- **Remaining hosted evidence:** no CVM was started. A digest-pinned full settle
  must still prove settlement-created continuation locks use the 72-byte
  layout; that belongs to the Phase 5 CVM suite and is not implied here.
- **Rollback:** development state is reset; no dual-layout mainnet path is
  required because no mainnet notes exist.

### PA-07 / PA-08 / PA-09 / PA-11 / PA-12 — Phase 3 proof cleanup

- **Owner:** Phase 3 implementation agent
- **PR/commit:** `privacy/note-lineage-v2`; PR pending
- **Invariant:** proof statements contain only live identities, one authoritative
  domain registry, and byte-identical Rust/TS/Circom meanings.
- **Local evidence required:** all circuit artifacts, public-input order tests,
  owner/deposit vectors, registry CI, branded/newtype boundary checks, clean
  `dist/`, full local gate.
- **Hosted/external evidence:** SBF/devnet/CVM plus independent review and
  ceremony.
- **Rollback:** atomic flag-day rule; never mix old notes/proofs with v2.
- **Implementation:** owner commitments are `Poseidon2(32, spending_key)`;
  deposit inners are `Poseidon3(33, recovery_nonce, note_secret)`; the dead
  nullifier is removed from VALID_SPEND, Rust, SDK, instruction data, and
  events; VALID_SPEND now has seven public signals. The authoritative checked
  domain registry reserves active and retired assignments, and CI scans
  production Rust/TypeScript declarations plus named consumers. Canonical
  settlement signatures moved to v12 and the persistence journal to v3; old
  proofs, notes, payloads, and journals are intentionally incompatible.
- **Local evidence:** all eight circuits rebuilt (MATCH_BATCH N=16 uses pot19),
  every zkey/VK and the 288-byte N=16 fixture regenerated, N=16 proof accepted
  on-chain, VALID_SPEND/INPUT/DEPOSIT and MERGE K2/K4 proof tests pass, Rust/TS
  KAT and byte-parity tests pass, and public/internal documentation describes
  the live formulas. The regenerated N=16 local run recorded witness execution
  at 4,768 ms and proving at 31,768 ms; these are host measurements, not CVM
  performance claims.
- **Final local gate:** devnet-admin SBF fingerprint
  `2326b4d3c919cd805b337943e64a2575be27553539710101785d06f93b3f75c1`;
  workspace nextest 901/901; artifact-required TEE nextest 702/702; SDK
  447/447 active tests; indexer 21/21; daemon 230/230 active; client-core
  21/21; trader-host 33/33 active; browser 74/74 plus production build. All six
  test-inclusive TypeScript typechecks, formatting, clippy with warnings
  denied, repository guards, public OpenAPI check, and dependency audits pass.

---

## 6. Open mainnet gates

All remain open:

- [x] Phase 1 merged with keystore/deposit recovery evidence.
- [x] Phase 2 merged with exact replay/lock semantics and measured layouts.
- [ ] Phase 3 atomic cutover merged with every source/artifact/vector in sync.
- [x] Clean reset of every Merkle shard recorded; the CVM post-reset sync floor
      remains part of the Phase 5 cold boot.
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
