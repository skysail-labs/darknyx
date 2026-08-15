<!-- audit-record -->
> **Purpose:** how this directory is organised, and how an implementation agent
> turns an audit's findings into a tracked, closable remediation.
> **Last updated:** 2026-08-02

---

# `audits/` — engagement records and closure ledgers

Every security/performance review of Darknyx lives here as a numbered
**engagement** (`audit_1`, `audit_2`, …). Each engagement owns one or more
**findings documents** and, once remediation begins, exactly one **tracker**.

Dates live *inside* documents, in the `audit-record` header block at the top —
never in filenames. Filenames describe what a document *is*, so a reader
scanning the tree sees roles rather than a chronology.

## Layout

```
audits/
  README.md                      ← you are here
  AUDIT_AGENT_ONBOARDING.md      ← seed prompt for the NEXT auditing agent
  residual-backlog.md            ← THE canonical cross-audit index of open work
  audit_1/  … audit_N/           ← one directory per engagement
      <findings>.md              ← immutable point-in-time evidence
      tracker.md                 ← the mutable closure ledger (added at remediation time)
```

## Which document answers which question

| Question | Document |
|---|---|
| *What is still open, anywhere?* | **`residual-backlog.md`** — start here, always. |
| *What did engagement N find, and with what evidence?* | that engagement's findings doc |
| *What has been fixed, by which PR, proven how?* | that engagement's `tracker.md` |
| *How do I run the next audit?* | `AUDIT_AGENT_ONBOARDING.md` |

**Findings documents are immutable.** They are point-in-time evidence. When a
finding's status changes, the *tracker* and the *residual backlog* move — the
original report does not get edited to look correct in hindsight. An `Open`
label in a historical report is not proof the issue still exists; the backlog
is the authority.

## The engagements

| Engagement | Scope | ID prefixes |
|---|---|---|
| `audit_1` | Vault mainnet hardening | `F-` |
| `audit_2` | Independent validation of the 07-14 review | validated `CS-`/`N-`/`P-` |
| `audit_3` | Cryptography + systems review, follow-up sweep, unique-findings pass | `C-`, `CS-`, `N-`, `P-`, `U-` |
| `audit_4` | Full-protocol deep dive | `D-` |
| `audit_5` | Withdraw + intake boundary review | `S-`, `PF-01…PF-07`, `AU-` |
| `audit_6` | TEE, infrastructure + daemon review | `T-`, `PF-08…PF-10` |
| `audit_7` | Client attestation review + un-audited surface sweep | `CA-`, `SW-`, `PF-12…PF-27` |
| `audit_8` | Browser trader + oracle source switch + note-use-tag lockstep | `R-`, `PF-28…` |

**ID prefixes are never reused.** A new engagement picks a fresh letter prefix
and continues the shared `PF-` numbering for performance items. Reusing a
prefix makes two findings indistinguishable in a commit message forever.

---

# Writing a tracker

`audit_6/tracker.md` is the reference implementation. Copy its shape. The
sections below are what make a tracker survive being handed between agents —
each exists because its absence cost something.

## 1. Header — what this ledger owns, and what it does not

State the findings document it closes, the exact ID families it covers, and
which *other* tracker owns adjacent families. Link dependencies across trackers
rather than copying ownership; two trackers claiming the same finding is how a
fix gets counted twice and done zero times.

## 2. The closure bar, stated up front

> A finding is not closed by code alone. The closing PR must identify the
> invariant restored, compatibility impact, exact tests, measured cost, live
> evidence where required, and rollback instructions.

Write this literally. It is the sentence that stops "the tests pass" from being
mistaken for "the finding is closed."

## 3. Status vocabulary, with teeth

`Open`, `In progress`, `Code complete`, `Closed`, `Deferred`, `Won't Fix`.

- **`Closed`** requires merged code **and every piece of evidence named in the
  row**. Not "it works locally."
- **`Code complete`** is where a change sits when it is locally green but owes
  live evidence (a CVM run, a hosted CI job). This state exists specifically so
  that owing evidence is visible rather than rounded up to `Closed`.
- **`Deferred`** requires a reason **and a re-entry condition**. "Later" is not
  a re-entry condition; "when GPU proving lands" is.
- **`Won't Fix`** records an explicit accepted risk with the person who accepted
  it. It is not a synonym for forgotten work, and an agent must not silently
  reopen one.

## 4. Continuation directive for agents

A numbered, imperative list an agent reads *before touching code*. At minimum:
read `CLAUDE.md` + the findings doc + this tracker + the relevant architecture
docs; start from latest `main`; take the earliest `Open` slice whose
prerequisites are closed; preserve unrelated dirty and untracked files; use a
`remediation/<topic>` branch; update the tracker in the *same* PR as the code;
run the affected CI gates locally; name any finding that must **not** be
reopened. Repeat project-specific hazards here rather than assuming they were
read elsewhere — e.g. **never stop a prepaid on-demand GPU CVM**.

## 5. Current execution state

A small table updated in the same commit as every status transition:

| Field | Current value |
|---|---|
| Last verified `main` | commit + what was verified against it |
| Last merged remediation PR | number, subject, merge commit, date |
| Active slice | the one slice in flight, or `none` |

This is the first thing a resuming agent reads. Without it, the first act of
every new agent is re-deriving where the work stopped.

## 6. Findings tables

`| ID | Severity | Owner | Planned remediation slice | Invariant / required evidence | Status |`

The **"invariant / required evidence"** column is the load-bearing one: it is
the contract for what closing this row demands, written *before* anyone starts,
so the bar cannot drift to match whatever the implementation happened to do.

## 7. Remediation slices

Group findings into slices that share a subsystem and can land as one PR.
Sequence them by dependency, and say what each slice's evidence table requires
— particularly whether it needs a **billable CVM**, so cost is a planned
decision rather than a surprise.

## 8. Recorded implementation decisions

When remediation forces a design choice, record the choice **and the rejected
alternatives with the reason**. This is the section future auditors mine
hardest: it is the difference between "why is it like this?" and re-litigating
a decision that was already made carefully.

## 9. Per-slice closure sections, written honestly

After a slice lands, record what the evidence actually showed — **including
failures**. `audit_6/tracker.md`'s slice-2 section is the model: it records that
the first hosted CI attempt *failed*, that both failures were real, and what
each caught that a local run could not. A closure section with no friction in
it is usually a closure section that did not look.

End each with **"still owed from this slice"** for anything recorded but not
finished, so partial completion is visible instead of rounding to done.

## 10. Cross-tracker corrections

When work in this engagement invalidates a claim in another tracker, correct it
**here**, name the other document, and link it. Silent divergence between two
ledgers is worse than either being wrong alone.

## 11. PR evidence template + handoff template

A copy-paste block for closing PRs, and a handoff block an agent fills in before
switching out. Both exist so quality does not depend on which agent is holding
the work.

---

## Rules that apply to every tracker

1. **Update the tracker in the same PR as the code.** A tracker updated
   afterwards is a tracker that will eventually not be updated.
2. **Never edit a findings document to reflect new status.** Move the tracker
   and `residual-backlog.md`.
3. **`residual-backlog.md` is the only cross-audit view.** When a row closes,
   update it there too, in the same PR.
4. **Do not mark a row `Closed` on local evidence when the row demands live
   evidence.** Use `Code complete`.
5. **Preserve unrelated dirty/untracked files.** Never fold them into a
   remediation commit.
6. **Commit with `git commit -s`**; no model, agent, or AI co-author trailers.
