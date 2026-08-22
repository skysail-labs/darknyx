# `crates/darknyx-tee` — documentation remediation plan

> **Status:** plan, not yet executed. Written 2026-08-22.
> **Scope:** `crates/darknyx-tee` only (108 files, 41,095 lines). Other crates
> are explicitly out of scope and will be handled separately.
> **Goal:** header comments that tell a new developer what a file *is* and what
> it *guarantees*, with no leftover implementation-process narration.

---

## 1. What is actually wrong

Surveyed 2026-08-22. The problem is **not** missing documentation — every one of
the 108 files already has a `//!` header. The problem is what those headers
contain.

### 1.1 Dead process markers — ~130 occurrences

References to an internal PR/phase sequence that no longer exists anywhere.

| marker | count | resolves to a live doc? |
|---|---:|---|
| `4g.3` / `PR 4g.3` | 28 | no |
| `4g.6`, `4g.5`, `4g.1`, `4g.4b`, `4g.7a/c/d/e` … | ~60 | no |
| `PR 4e.1`–`4e.4` | ~17 | no |
| `Phase 1/2/3`, `slice N`, `step N` | ~12 | no |

Verified: `4g.7c` and `4e.2` resolve to **zero** documents outside the crate.
These are unambiguous noise — they tell the reader a change happened without
saying what is true now.

### 1.2 Audit finding IDs — ~155 occurrences

`T-06` (23), `T-03P` (17), `SW-01` (13), `SW-02` (9), `C-08` (7), `F-05` (6),
`U-02` (3), `PF-27` (5), and ~30 others.

**These are different from §1.1: they still resolve.** Each of `T-06`, `SW-01`,
`U-02`, `PF-27`, `C-08`, `T-03P` matches 6–10 live documents under `audits/`
and `docs/`. `audits/residual-backlog.md` is their canonical index and `T-03P`
is *open work*. See §3 for the decision this forces.

### 1.3 Transitional narration — ~22 sites

`"for now"` (4), `"follow-up"` (4), `"will be"` (5), `"not yet"` (7),
`"later PR"` / `"future PR"` (4). These describe the state of the world during
implementation. Some are now false. From the file you cited:

```rust
//! 4g.3 takes the proof bytes as a builder input; integrating it
//! with `POST /orders` (so the TEE actually has a proof to relay)
//! is its own follow-up — for now the LockingNotes stage worker
//! fails the job with a clear "missing valid_input_proof" reason
//! when no proof is attached.
```

A reader cannot tell whether this still holds. **Each of these needs verifying
against current code, not deleting on sight** — see Phase 2.

### 1.4 Thin module headers — 10 `mod.rs` files

The `mod.rs` header is where a new developer learns how a subsystem fits
together. Current depth is inverted against module size:

| module | header lines | code lines |
|---|---:|---:|
| `matcher/` | 5 | 2,350 |
| `oracle/` | 6 | 3,471 |
| `merkle/` | 7 | 2,506 |
| `transport/` | 8 | 813 |
| `api/` | 9 | 8,777 |
| `settle/` | 23 | 12,426 |
| `prover/` | 29 | 3,694 |

`api/` gets nine lines to introduce 8,777 lines across 23 files. This is the
single largest onboarding gap in the crate.

### 1.5 Prose that describes history instead of state

```rust
//! Local Merkle-tree mirror — same depth-20 Poseidon incremental
//! tree as `programs/vault/src/merkle.rs`, lifted into this crate
//! when the parity is set up.          <- when? is it set up? unanswerable
//! Powers `/tree/*` indexer endpoints (D6).   <- D6 explains nothing
```

---

## 2. House style

Applied uniformly. This is the contract for every rewrite below.

### 2.1 A module header answers four questions, in this order

1. **What is this?** One sentence, present tense, no history.
2. **Where does it sit?** What calls it, what it calls, its place in the pipeline.
3. **What must not break?** Wire layouts, ordering constraints, arity caps,
   invariants — and *what fails if violated*, including the error a reader would
   actually see.
4. **Where is the authority?** Cross-reference to the canonical doc or the
   counterpart implementation, when one exists.

### 2.2 Rules

- **Present tense, describing what the code does now.** Never "will be", "for
  now", "was added in", "used to".
- **No process references.** No PR numbers, phase names, slice or step numbers.
- **State invariants as invariants, not as history.** "The account list must
  match the on-chain struct order" — not "PR 4g.3 reordered the accounts".
- **Keep load-bearing numbers.** Byte widths, account indices, discriminators,
  and arities are the contract; they stay and stay exact.
- **Don't restate the code.** `LazyLock` does not need explaining. Explain what
  the code cannot say: why an order is mandatory, what breaks if it changes,
  where the mirrored implementation lives.
- **Name the failure.** Where a subtle invariant exists, say how a violation
  surfaces (`InvalidProof (6000)`, `ConstraintSeeds (2006)`, `AccountNotFound`).
  This is what turns a comment into a debugging aid.

### 2.3 Exemplar — `settle/lock_note.rs`

The existing account/argument tables in this file are **good** and are kept
verbatim. Only the framing changes.

Removed: the `4g.3` follow-up paragraph (§1.3), the `LazyLock` mechanics, the
"see PR 4g.3 doc" pointer, and the bare `(4g.7c)` / `(U-02)` tags.

Kept and sharpened:

```rust
//! Builder for the `vault::lock_note` instruction — Tx A of the settle
//! pipeline, which pins a note between matching and settlement.
//!
//! The TEE relays a **user-supplied** VALID_INPUT Groth16 proof; it does not
//! generate one. The on-chain handler
//! (`programs/vault/src/instructions/lock_note.rs`) enforces
//! `tee_authority ∈ vault_config.tee_pubkeys` and verifies that proof against
//! the shard's recent-roots ring.
//!
//! Two layouts are pinned to the on-chain handler and must change in lockstep
//! with it. Both are covered by tests in this file:
//!
//!   - **Instruction data** — 8-byte Anchor discriminator, then Borsh args in
//!     declaration order: `tree_id: u8`, `note_use_tag: [u8; 32]`, … 385 bytes
//!     total. A reordering deserialises to the wrong fields on-chain rather
//!     than erroring at the boundary.
//!   - **Account list** — 6 accounts, positional, matching `LockNote<'info>`.
//!     `consumed_note` is passed read-only and **must be absent**: its
//!     existence is the consume-once guard, so a note cannot be locked twice.
//!
//! The discriminator is `sha256("global:lock_note")[..8]`, the same constant
//! `packages/sdk/src/idl/vault-client.ts::anchorDiscriminator` produces.
```

Every fact is present-tense, checkable, and states its own failure mode.

---

## 3. Decision required: audit IDs

**§1.1 markers are noise and get deleted. §1.2 audit IDs are a judgment call**,
because unlike the process markers they still resolve to live trackers.

**Recommendation: keep the ID only where it explains *why an invariant exists*,
and only alongside the substance — never as the sole explanation.**

```rust
// bad, and the actual problem:   consumed_note readonly (U-02)
// bad, loses traceability:       consumed_note readonly
// good:  consumed_note is read-only and must be ABSENT — its existence is the
//        consume-once guard that stops a note being locked twice (audit U-02).
```

The confusion you're describing comes from **ID-only references that explain
nothing**. Once the substance is stated in plain language, a trailing `(audit
U-02)` costs one reader-second and buys a path back to `audits/residual-backlog.md`
— which is still the canonical index, and where `T-03P` is *open work*.

**Alternative, if you'd rather:** strip every ID unconditionally. Phase 1 is
mechanical either way; the only change is the regex. Say which you want before
Phase 1 starts — retrofitting IDs afterwards means re-deriving them from git
history, which is expensive.

---

## 4. Phases

Sequenced so that mechanical, low-conflict work lands before prose rewrites, and
so that no rewrite collides with in-flight feature work.

### Phase 0 — Conventions and inventory *(no bulk edits)*

- Land §2 as `crates/darknyx-tee/CONTRIBUTING.md` (or a `docs/` section).
- Convert `settle/lock_note.rs` as the exemplar; **get sign-off on the style
  before touching 107 more files.**
- Generate the full marker inventory to a checked-in worklist so Phase 2's
  verification has a definite scope.
- Resolve the §3 decision.

**Exit:** the style is agreed on one real file.

### Phase 1 — Mechanical marker sweep *(crate-wide, one PR)*

Remove the §1.1 process markers. Where a marker was the only content of a
sentence, the sentence goes with it; where it annotated a real statement, the
statement stays.

- **Gate:** `cargo doc --no-deps` clean, `cargo clippy --workspace --all-targets
  -- -D warnings`, `cargo nextest run -p darknyx-tee`.
- **Guard:** a grep assertion that `4g.`/`4e.`/`PR N`/`slice N` do not reappear
  (§6).
- Comment-only diff. Reviewable by skim; merges cleanly against churn.

### Phase 2 — Transitional-narration audit *(the one that finds real problems)*

The ~22 sites from §1.3. For each: **read the code and decide whether the
statement is still true.**

- True and useful → restate in present tense.
- True but trivial → delete.
- **False → fix the comment, and record the finding.**

The deliverable is the doc fix *plus a list of statements found to be false*.
A header asserting behaviour the code no longer has is worse than no header,
and the `lock_note.rs` `valid_input_proof` claim (§1.3) is the first to check.

### Phase 3 — Module headers *(11 files, highest value per line)*

Rewrite the 10 `mod.rs` files plus `lib.rs` against §2.1 — with §1.4's
inversion corrected, so `api/` and `matcher/` get depth proportional to what
they contain.

Order by size: `settle`, `api`, `prover`, `oracle`, `merkle`, `matcher`,
`solana_rpc`, `persistence`, `transport`, `keys`.

Each header maps the module's files to their roles, so a reader knows which of
23 files to open. **This is the largest onboarding win in the plan** and is only
11 files.

### Phase 4 — File headers, one PR per module *(97 files)*

| # | module | files | 60-day commits | notes |
|---|---|---:|---:|---|
| 4a | `settle/` | 25 | 32 | your worked example; highest churn — do it early |
| 4b | `api/` | 22 | 30 | largest module, thinnest header |
| 4c | `matcher/` | 7 | 14 | |
| 4d | `prover/` | 14 | 9 | |
| 4e | `oracle/` | 7 | 9 | |
| 4f | `persistence/` | 4 | 10 | |
| 4g | `solana_rpc/` | 4 | 8 | |
| 4h | `merkle/` | 3 | 8 | |
| 4i | root files | 6 | — | `main.rs` (1,663), `config.rs` (953), `boot.rs` |
| 4j | `keys/` | 2 | 2 | |
| **4k** | **`transport/`** | **3** | **3** | **deferred — see below** |

> **`transport/` is sequenced last on purpose.** `docs/transport-integrity-remediation-plan.md`
> Phases 1–3 rewrite the RA-TLS listener, and `T-03P` accounts for 17 of the
> markers in §1.2. Documenting it now means documenting it twice. Pick it up
> once that work lands.

`settle/` and `api/` are the highest-churn modules; that argues for doing them
**early**, before more comments accumulate, not for avoiding them.

### Phase 5 — Cross-reference verification and CI guard

- Verify all 25 `docs/*.md` references resolve, **including section anchors**
  (the files exist; the `§N` targets are unverified).
- Add the §6 guard to `pr-checks`.

---

## 5. Effort and risk

| phase | files | risk | why |
|---|---:|---|---|
| 0 | 1 | none | one exemplar |
| 1 | ~60 | very low | mechanical, comment-only, guarded |
| 2 | ~20 | **low-but-real** | requires reading code; may surface actual bugs |
| 3 | 11 | low | new prose, no behaviour |
| 4 | 97 | low | comment-only, chunked per module |
| 5 | — | none | verification |

**No phase changes behaviour.** Every diff is comments, so the standing gate
(`clippy -D warnings`, `cargo nextest run -p darknyx-tee`, `cargo doc`) is
sufficient — with one caveat: doc comments on public items participate in
`cargo doc` link resolution, so intra-doc links must be checked, not assumed.

---

## 6. Guard against regression

Without this the crate re-accumulates markers within a few months.

```sh
# scripts/check-no-process-markers.sh
# Fails if implementation-process markers reappear in crates/darknyx-tee.
```

Matching `\b(PR ?[0-9]+[a-z]?\.[0-9]+|[0-9]+[a-z]\.[0-9]+[a-z]*|slice [0-9]+)\b`
over `crates/darknyx-tee/**/*.rs`, wired into `.github/workflows/pr-checks.yml`
and CLAUDE.md §2.5 alongside the existing `check-brand-namespace.sh` and
`check-no-debug-endpoints.sh`.

Scoped to this crate initially, widened when the other crates are done.

---

## 7. Open questions

1. **§3 — audit IDs: keep-with-substance (recommended) or strip entirely?**
   Needed before Phase 1.
2. **One PR per phase, or a stacked series?** Phase 4 is 10 sub-PRs; `gh-stack`
   handles that well, and comment-only diffs rebase cleanly.
3. **Does `CONTRIBUTING.md` belong in the crate or in `docs/`?** The crate is
   more discoverable for the developer editing it.
