<!-- audit-record -->
> **Audit:** Fuzzing plan (proposal)  
> **Date:** 2026-08-02  
> **Engagement:** `audits/audit_7/`  
> **ID prefix:** `FUZZ-`  
> **Cross-audit status:** see [`residual-backlog.md`](../residual-backlog.md) — the canonical index of what is still open.

---

# Darknyx fuzzing plan

> **Purpose.** A costed, phased plan for property-based and coverage-guided
> testing of the binary parsers and trust boundaries that consume
> attacker-influenced input.
>
> **Motivated by** the 2026-08-01 and 2026-08-02 audit rounds. This is not a
> generic "add fuzzing" proposal — the target list, the tiering, and the CI
> design are each derived from a specific finding or near-miss in those passes.
>
> **Status:** proposal. Nothing here is implemented.

---

## 1. Why, specifically

Three observations from the audit rounds shape everything below.

**1. The parsers read clean — and that is exactly when static review is
weakest.** `oracle/accumulator.rs` and `oracle/vaa.rs` were the two surfaces
both prior passes predicted would hold the next bug. I read them in full and
found nothing: bounds-checked cursors, `checked_add` on every offset,
u8/u16-bounded allocations, correct leaf/node domain separation, two independent
duplicate-guardian guards. That is a good result, but "one careful reader found
nothing" is a much weaker statement about hand-rolled binary parsing over
guardian-signed input than a few CPU-hours of coverage-guided mutation would be.

**2. The Critical we did find was not a byte-level bug.** SW-07 is not
`extract_appended_leaves` mishandling malformed bytes — it decodes correctly. It
is the function being *willing to decode* bytes whose provenance was never
established: any program's `Program data:` line is accepted as a vault event.
**Random byte fuzzing of that function would never have found it**, because
every input it generates is already "from nowhere". Catching SW-07 requires a
property about *where input came from*, not what it looks like.

That distinction is the plan's central design point. A fuzzing effort aimed only
at "does the parser panic" would have passed clean through the most serious
finding in the sweep.

**3. The repo has already learned the relevant CI lesson.** The 2026-07-25 pass
found *three separate instances* of "a gate that reports success because it never
ran," and slice 3 wrote the rule: *when adding a gate, check that the filter
which decides whether it runs includes the gate's own inputs.* Fuzzing is the
most dangerous possible place to repeat that mistake, because **"no crashes
found" and "never executed" produce byte-identical output.** §6 addresses this
explicitly.

---

## 2. Design: two tiers and the bridge between them

| | **Tier A — properties** | **Tier B — coverage-guided** |
|---|---|---|
| Tool | `proptest` (already a workspace dev-dep) | `cargo-fuzz` / libFuzzer |
| Toolchain | stable 1.91 (the pinned channel) | nightly, scheduled job only |
| Runs | **every PR**, in the existing gate | nightly + on-demand, time-boxed |
| Budget | ≤ 30 s total added | 15–30 min/night |
| Finds | semantic, differential, and **provenance** violations | deep byte-level paths, panics, OOM |
| Would have caught | **SW-07** | the class we did *not* find in the parsers |

**Tier A is the priority.** It runs on every PR, needs no toolchain change, uses
a pattern already established in `programs/vault/tests/merkle_fuzz.rs`, and it is
the tier that catches the class of bug this codebase has actually produced.

**Tier B is the complement.** proptest generating random `Vec<u8>` will
essentially never satisfy `"PNAU"` + `major == 1` + `proof_type == 0` + a
coherent `u16` VAA length — it will spend 100% of its budget bouncing off the
magic check. libFuzzer's `memcmp` interception and value profiling crack
constant-comparison gates routinely, which is precisely why coverage-guided
mutation is the right tool for these specific parsers and property testing is
not.

### The bridge (the part that makes this durable)

Every crash or interesting input Tier B finds is **minimized and committed as a
regression case that Tier A replays on stable, on every PR.**

Without this, nightly fuzzing is a one-off exercise whose value evaporates when
the schedule breaks. With it, each discovery becomes a permanent stable-CI
assertion, and the fuzzing infrastructure can lapse without losing what it found.
`proptest` supports this natively via its persisted-failure file; we extend it
with an explicit `corpus/` directory of committed byte inputs replayed by a plain
`#[test]`.

---

## 3. Targets

Ordered by expected value. Each names the **property**, not just the function —
"fuzz the parser" is not an actionable target.

### Tier A — properties (every PR)

| # | Target | Property to assert | Notes |
|---|---|---|---|
| **A1** | `merkle::events::extract_appended_leaves` | **Provenance.** Given a log array mixing genuine vault-scoped events, byte-identical events emitted under a *foreign* program scope, arbitrary non-event lines, and nested CPI scopes at random depth — the function returns **exactly** the vault-scoped events, in order. | **This is the SW-07 regression test.** It fails today. Write it first, as the fix's acceptance criterion. Generator must model `Program <id> invoke [n]` / `success` / `failed` bracketing. |
| **A2** | `accumulator::verify_inclusion` | **Soundness.** Build a reference Pyth-style tree over 2–64 random messages. (a) A genuine proof for member *i* verifies. (b) For any non-member message and **any** proof up to depth+2, verification fails. (c) A proof for member *i* does not verify member *j≠i*. | (b) is the soundness direction, where sorted-pair Merkle bugs live. Requires writing an independent reference tree builder — which is itself valuable, since `accumulator.rs` has no builder and therefore no oracle today. |
| **A3** | `vaa::verify_signatures` | **Quorum integrity.** Random guardian set (1–19), random signing subset, with duplicates / out-of-order / out-of-range indices / wrong-key signatures injected. Accept **iff** indices are strictly increasing, all in range, all recover to the right address, and count ≥ quorum. Specifically: **duplicating a valid signature never increases the accepted count.** | Needs real `k256` signing in the harness; `k256` is already a dependency. This is the single most consequential property in the oracle stack. |
| **A4** | `merkle::sync::apply_leaves` + `MerkleMirror` | **Monotonicity + idempotence.** Random leaf sequences with gaps, duplicates, and permutations. `leaf_count` is non-decreasing; any gap yields `LeafGap`; applying a page twice is a no-op; the root after a permutation equals the root after sorted application. | Directly guards the mirror SW-07 corrupts. Cheap. |
| **A5** | `accumulator::parse` → re-serialize | **Round-trip.** For any input that parses, the borrowed `message`/`proof` slices lie within the source buffer and re-slicing at the recorded offsets reproduces them. | Catches offset drift if the wire format is ever revised. |

### Tier B — coverage-guided (nightly)

| # | Target | Assertion | Seed corpus |
|---|---|---|---|
| **B1** | `accumulator::parse` | never panic; never allocate > 1 MiB | `tests/fixtures/sol_usd_accumulator.bin` |
| **B2** | `vaa::parse` | never panic | `sol_usd_vaa.bin`, `sol_usd_router_vaa.hex` |
| **B3** | `accumulator::parse_price_feed_message` | never panic | messages extracted from B1's fixture |
| **B4** | `accumulator::merkle_root_from_vaa_payload` | never panic | VAA payloads from B2 |
| **B5** | `events::decode_settle_payload` | never panic | a real settle ix from a devnet tx |
| **B6** | `vaa::verify_for_profile` (full path) | never panic; never accept without quorum | B2 corpus |
| **B7** | `sync::parse_merkle_tree_root`, `alt::parse_alt_addresses` | never panic | synthetic |

B1–B4 and B6 are the high-value set. B7 is included because it is nearly free —
both are small and already look correct (`parse_alt_addresses` uses
`chunks_exact`, `parse_merkle_tree_root` length-checks), so expect no findings;
they cost one target definition each.

**No free differential oracle.** `pythnet-sdk` is not in `Cargo.lock` — the
parser was hand-rolled deliberately to avoid the dependency. So a
differential-against-upstream target is not available cheaply. The realistic
substitutes, in order of value per unit of effort:

1. **A2's reference tree builder** — an independent implementation of the
   hashing/tree construction, written from `docs/oracle-accumulator-notes.md`
   rather than from `accumulator.rs`. This is a genuine oracle for the Merkle
   half and should be written by someone reading the spec, not the code.
2. A one-off cross-check of the committed fixture against a Python/JS decoding
   of the same Hermes response. Cheap, one-time, catches systematic
   misinterpretation that self-consistent fuzzing cannot.
3. Vendoring `pythnet-sdk` behind a `dev-dependency` + `cfg(fuzzing)` — strongest
   oracle, but adds a heavy dependency tree for test-only value. Only if 1 and 2
   prove insufficient.

### Explicit non-targets

Stating these prevents wasted effort:

- **The Groth16 verifier** (`groth16-solana`) — vendored third-party; fuzzing it
  tests someone else's code with our budget.
- **Poseidon** — already pinned by cross-language parity tests against
  `light-poseidon` and circomlib; byte behaviour is the *contract*, not a
  hypothesis.
- **The circuits** — circuit soundness is not a fuzzing problem. That is the
  F-04 external audit, and no amount of input mutation substitutes for it.
- **serde-driven RPC response structs** — serde's derive is well-tested;
  hand-rolled offset parsing is the risk, and those are B5/B7.
- **`darknyx-tee-loadgen`** — test tooling, not in the enclave.

---

## 4. Toolchain

`rust-toolchain.toml` pins **stable 1.91.0** with `profile = "minimal"`.
`cargo-fuzz` requires nightly (`-Z sanitizer=address`). Options:

| Option | Cost | Recommendation |
|---|---|---|
| **A — nightly only in the scheduled fuzz job** | The pinned stable channel is untouched; the fuzz workflow installs its own nightly. Tier A stays entirely on stable. | **Recommended.** Isolates the nightly dependency to a job that is allowed to be flaky, and keeps the PR gate on the pinned toolchain. |
| B — `afl.rs` | Also needs setup and a separate binary; no real advantage here. | No. |
| C — Tier A only, byte strategies in proptest | Zero toolchain change. But as noted in §2, random bytes do not get past magic-byte gates, so B1–B6 would be near-worthless. | Fallback only if nightly maintenance proves genuinely disruptive. |

Take **A**. If the nightly job rots, Tier A and the committed corpus keep working
on stable — that is the point of the bridge.

---

## 5. Corpus strategy

```
crates/darknyx-tee/fuzz/
  corpus/<target>/        # seed + discovered inputs (committed, minimized)
  artifacts/<target>/     # crash reproducers (committed on discovery)
```

- **Seed from the real fixtures.** `sol_usd_accumulator.bin`,
  `sol_usd_vaa.bin`, `sol_usd_router_vaa.hex` already exist and are real Hermes
  output. Seeding is what makes B1–B4 productive on night one rather than after
  a week of magic-byte discovery.
- **Minimize before committing** (`cargo fuzz cmin`) so the corpus does not grow
  without bound in git.
- **Cache the working corpus** in CI between scheduled runs; commit only
  minimized additions that increase coverage, and every crash reproducer.
- **Size cap:** if the committed corpus exceeds ~2 MB, minimize harder or move
  to a CI cache with only reproducers committed.

---

## 6. CI integration — and not repeating the "gate that never ran" failure

The T-audit found that defect three times. Fuzzing is uniquely exposed to it: a
target that executes zero inputs and a target that finds no bugs both print
nothing and exit 0.

Three concrete defenses, all required:

1. **Paths filter must include the gate's own inputs.** Per the slice-3 rule,
   the job that runs these must trigger on changes to `crates/darknyx-tee/**`
   *and* `crates/darknyx-tee/fuzz/**` *and* the corpus directory *and* the
   workflow file itself. A PR that weakens a fuzz target must run the fuzz gate.
2. **Assert liveness, not just absence of failure.** The Tier A corpus-replay
   test asserts `corpus_files_replayed > 0` and fails if the corpus directory is
   empty or unreadable. The Tier B job asserts libFuzzer executed ≥ N inputs and
   reports final coverage; a run that executes 0 inputs fails the job.
3. **Name the tests in the log, and check them by name.** The same discipline
   applied to the hosted `TEE` job in slice 3 (*"confirmed by name in the log
   rather than inferred from a green tick"*).

**Wall-time budget.** `CLAUDE.md` §2.5's gate is already ~156 s under nextest,
and the `merkle_fuzz.rs` precedent caps itself explicitly
(`ProptestConfig { cases: 48, .. }`). Tier A must do the same: **cap `cases` per
property and keep total added wall time ≤ 30 s.** The nightly job raises the case
count via `PROPTEST_CASES`.

---

## 7. Phasing and cost

| Phase | Contents | Cost | Gate |
|---|---|---|---|
| **1** | **A1 only** — the SW-07 provenance property, written as the acceptance criterion for the SW-07 fix. | **~1 day** (0.5 harness + 0.5 log-scope generator) | Ships *with* the SW-07 fix, not after |
| **2** | A2 + A3 + A4, the reference tree builder, the corpus-replay harness, and the PR-gate wiring with the §6 liveness assertions. | **~4 days** (A3's signing harness and A2's reference builder are the bulk) | PR gate; ≤ 30 s added |
| **3** | `cargo fuzz` scaffolding, targets B1–B6, seed corpus, nightly workflow with a 20-minute budget. | **~3 days** | Scheduled; allowed to be flaky |
| **4** | B7, the one-off cross-language fixture cross-check, corpus minimization tooling. | **~1.5 days** | Opportunistic |
| | | **~9.5 days total** | |

Phase 1 is independently worth doing even if 2–4 are never funded: it converts
the sweep's Critical into a permanent regression test.

Phases 2 and 3 are separable. If only one is funded, **take Phase 2** — it runs
on every PR, needs no toolchain change, and targets the bug class this codebase
has demonstrably produced.

---

## 8. Success criteria

This effort is complete when:

1. A1 fails against the pre-fix `extract_appended_leaves` and passes after —
   demonstrated, not assumed.
2. A2's soundness direction (b) is shown to fail against a deliberately broken
   `hash_node` that drops the `0x01` node prefix. A property that cannot fail
   proves nothing; mutation-test each property the way slice 3 mutation-tested
   the connection caps.
3. A3 is shown to fail against a `verify_signatures` with the `seen[]` duplicate
   guard removed.
4. B1–B6 each execute ≥ 10⁶ inputs cumulatively with no uncontrolled panic, and
   the final corpus + coverage figure is recorded in the closing PR.
5. Every crash found is committed as a minimized reproducer replayed by the
   stable PR gate.

Criteria 2 and 3 matter most. The repo's own review discipline already
established that a test which cannot fail is not evidence — the same standard
should apply here from the start rather than being retrofitted.

---

## 9. What fuzzing will not do

Recorded so the plan is not over-sold:

- It will not address **F-04** (circuit soundness) or **N-18** (the Phase-2
  ceremony). Those remain the binding mainnet gates.
- It will not find the **SW-07 class in general** — A1 catches that specific
  provenance bug because we now know to ask. Finding the *next* provenance bug
  is a design-review activity: for every decoder consuming external input, ask
  what establishes the input's provenance, and whether the code checks it. That
  question, applied across the remaining unread surfaces in §4 of the August 2
  sweep, is likely worth more than any amount of byte mutation.
- It will not substitute for finishing the read-through of
  `settle/scheduler.rs`, the `solana_rpc` response validators, `config.rs`, and
  the daemon lifecycle modules.
