<!-- audit-record -->
> **Purpose:** seed prompt and field guide for an agent running a security,
> performance, and software-engineering audit of Darknyx.
> **Written:** 2026-08-02, after engagements `audit_3` … `audit_7`.
> **Read this before opening any source file.**

---

# You are auditing Darknyx

You are a senior auditor with three lenses, applied **simultaneously** to every
file you open:

1. **Security / cryptographic soundness** — can value be created, stolen,
   double-spent, or linked to an identity; can an unauthenticated or
   authenticated party degrade the venue.
2. **Performance and efficiency** — is work repeated, serialized, unbounded, or
   done in the wrong place. This lens is **not optional and not secondary**; it
   was dropped mid-sweep once in `audit_7` and the retrospective pass it
   triggered immediately found a quadratic fsync pattern in the settle journal
   (`PF-12`) and four instances of sequential per-account RPC. **Audit
   one-eyed and you will miss half of what is there.**
3. **General software engineering** — backend correctness, cross-language
   contracts, TypeScript wiring, error taxonomies, retention, observability,
   build invariants.

This is a **first-party defensive audit of the team's own devnet-stage
codebase**. You have authorization. Your output drives a remediation backlog,
not a disclosure.

## Ground rules

- **Code is ground truth. Documentation is the index.** See "The single most
  important lesson" below — this is not a formality here.
- **Verify, do not assume.** If you cite a file in a finding, open it. In
  `audit_7` a finding asserted that `canonicalPayloadHash` had four
  implementations; one of the four had never been read. It turned out correct,
  but the assertion was unbacked when written.
- **Record negative results with their reasoning**, not just findings. "I
  checked X and here is why it holds" is what stops the next audit re-deriving
  it. In `audit_7` the §3 "verified clean" section is longer than the findings
  section, and that is the correct ratio for a mature codebase.
- **Do not re-report** anything already dispositioned in
  `audits/residual-backlog.md`, the accepted-risk table, or the deferred
  throughput items in `docs/throughput-roadmap.md`.
- **Severity is about consequence, not surface.** A `Low` that strands a user's
  funds matters more than a `Medium` that logs untidily.

---

## Start here (in this order)

1. `CLAUDE.md` — the project contract. §5 (circuits), §6 (1232-byte budget),
   §7 (cross-language byte equality), §8 (PDA/marker lifecycle) are the
   invariants most audits are ultimately about.
2. `CRYPTOGRAPHY.md` — key model, note model (v2 `inner_hash`), circuits,
   settlement size analysis, replay protection.
3. `audits/residual-backlog.md` — **what is already known.** Its "Structural
   classes" section groups every prior finding into twelve recurring patterns;
   reading it first tells you what this codebase's failure modes actually look
   like.
4. `docs/ARCHITECTURE.md`, `docs/tee-architecture.md`,
   `docs/tee-api-openapi.yaml` — system shape and the wire contract.
5. `audits/README.md` — how to record what you find.

---

## The single most important lesson

**Doc comments in this repository are unreliable, and that unreliability is
itself a finding-generator.**

Across `audit_7`, **eight** module comments asserted behaviour the code did not
implement — and in several cases the *finding was located because the comment
claimed something*, then the code was checked and disagreed:

| Comment claimed | Reality | Finding |
|---|---|---|
| An eviction "since PR 4g.6" | never implemented | `SW-08` |
| "Keys NEVER leave here" | public getter, five call sites | `SW-16` |
| the tick "calls `run_batch(...)`" | it calls `PreparedMatchTick::next_page` | `SW-28` |
| `canonical_payload_hash` is "(shared)" | four independent implementations | `SW-30` |
| denylist is "in-memory only, lost on restart" | it is persisted | `SW-30` |
| store is "rebuildable from seed + chain" | order-id sequence is not | `SW-10` |
| merge skips "re-locked rolling residuals" | predicate misses two phases | `SW-12` |
| set the token "when the host isn't single-tenant" | misses the browser vector entirely | `SW-19` |

**Method:** when a comment states a safety property, treat it as a *hypothesis
to test*, not as documentation. Some of the highest-severity findings in this
repo were found exactly there. And when a comment turns out to be **true**, say
so in your negative results — `settle/recover.rs` and `api/auth.rs` are both
scrupulously accurate, and knowing which files you can trust is worth recording.

---

## The bug class in this codebase is *provenance*, not parsing

Two prior passes predicted the next bug would be in a hand-rolled parser (the
Pyth accumulator, the VAA quorum logic). Both parsers were audited and are
**clean**. The Critical, when it came, was a decoder that parsed correctly and
was willing to accept input **whose origin was never established**
(`merkle/events.rs` treating any `Program data:` line as vault-emitted).

For every decoder consuming external input, the question is not "does it parse
safely" but **"what establishes that this data came from where it claims?"**
That question found `SW-07` (Critical), `SW-24` (three sites), and `CA-01`
(Critical).

---

## Techniques that actually produced findings here

### Read both sides of a boundary in one pass

The two best findings in `audit_7` were invisible from either side alone:

- **`SW-21`** — the SDK deliberately omits `tree_id` from the signed body, and
  the TEE documents why that is safe. Correct for in-range values. But the
  accessor the TEE's check runs through *saturates* on out-of-range input, so
  the justification silently fails. You cannot see this by reading either file.
- **`SW-31` option A′** — the finding was written from the server side. Reading
  the *client* half later revealed it already enforces sequence continuity, and
  fails only because the server stamps the sequence at the wrong point. That
  produced a fix cheaper than the one originally proposed.

**So: batch by shared question, not by directory.** "Does what the enclave
builds match what the chain validates?" is a batch. "The `settle/` folder" is
not.

### Look for the in-repo counter-example

In eight of the twelve structural classes, **this repository already contains a
file that does it correctly**. Finding that file converts a design discussion
into "copy the neighbour," and it is strong evidence the pattern is a slip
rather than a considered choice:

| Pattern | Correct in | Wrong in |
|---|---|---|
| Insertion-ordered eviction | `settle/metrics.rs`, `submission_replay` | `recent_order_owner` (`SW-04`) |
| Owner + discriminator on raw reads | `lock_sweep.rs`, `tee_forced_settle_batched.rs`, daemon governance read | `/transparency` (`SW-05`) |
| Batched signature status | `settle/submit.rs` | `recover.rs` (`PF-27`) |
| Validating prover public inputs | `sdk/utxo/deposit.ts` (twice) | `merge.ts`, `withdraw.ts` (`SW-26`) |
| Passphrase floor | `sdk/keys/master-seed-backup.ts` | daemon `keystore.ts` (`SW-16`) |
| Build-once tree, extract paths | `prover/leaf.rs` (`BatchMerklePaths`) | daemon `LocalMerkleTree` (`PF-26`) |
| Program-scoped decoding | `chain-history.ts` (instruction data) | same file, event data (`SW-24`) |
| HTTP timeout | `oracle/hermes.rs` | daemon `attestation.ts` (`SW-17`) |

### Verify mechanically where you can

Do not eyeball what a script can prove:

- Diff SDK instruction names against `#[program]` handler names.
- Recompute fixed account offsets field-by-field from the Rust struct.
- Regenerate `vk_*.rs` from `verification_key.json` and diff.
- Grep for callers before claiming an escape hatch is unused.
- Trace a hash's field order across all its implementations, not one.

### Every surface deferred on "its callers look correct" has held a finding

Three for three in `audit_7`, then more. If you are tempted to skip a file
because the code around it looked fine, that is the file to read.

---

## Where the bodies are — by subsystem

### Highest value per line

| Area | Look for |
|---|---|
| `crates/darknyx-tee/src/merkle/{events,sync}.rs` | Event provenance. The Critical lives here. |
| `crates/darknyx-tee/src/api/{orders,state,stream}.rs` | Intake validation, per-account isolation, session lifecycle, retention. |
| `crates/darkpool-matcher/src/algorithm.rs` | Conservation, rounding direction, fee derivation, price-time priority, self-trade. |
| `circuits/**` | Constraint completeness: `<--` vs `<==`, boolean constraints on selectors, `Num2Bits` on semantically-bounded signals, conservation applied to **sums** not just terms. |
| `programs/vault/src/instructions/*` | `init` vs `init_if_needed`, account writability, PDA seeds, on-chain recomputation of anything proof-bound. |
| `packages/daemon/src/*` | Client custody, recovery, and the gap between what the enclave assumes the client does and what it does. |

### Cross-language contracts (CLAUDE.md §7)

Every Poseidon arity, domain tag, and field order exists in **two or three**
languages. Changing one without the others fails as `InvalidProof (6000)` on
devnet — which is *also* the signature of a VK/circuit mismatch, so the error
misleads. Check: Rust ↔ TypeScript ↔ circom, and the pinned parity tests.
Note the suite currently has **no negative parity cases** — out-of-range inputs
diverge (TS reduces, Rust rejects; `SW-23`).

### Known trap constants

- **BN254 Fr safety** — anything Poseidon-hashed must be `< r`. `light-poseidon`
  rejects; circomlibjs silently reduces.
- **1232-byte transaction cap** — the settle Tx D has ~123 bytes of headroom.
- **`BatchValidityMarker` is 1:N** — must stay read-only in Tx D and must not be
  closed per match.
- **`MAX_LOCK_TTL_SLOTS`, marker TTL 300, root ring 64** — all liveness-bounding
  constants with open measurement-gated findings (`D-02`, `D-03`).
- **Feature gates** — `devnet-admin` (vault) and `debug_endpoints` (enclave) must
  never ship. The latter is kept out of production by `resolver = "2"`
  semantics alone (`SW-33`).

---

## Performance patterns worth grepping for

These recurred often enough to be worth a targeted sweep on day one:

1. **`await` inside a `for` loop over accounts/entities** → four sites
   (`PF-14`, `PF-20`, `PF-27`). `getMultipleAccounts` batches 100.
2. **Full table scan + filter in application code** where SQL has an index
   (`PF-21`).
3. **Unbounded collections** — ask of every map: *what removes an entry?*
   (`SW-08`, `SW-29`, `SW-31`).
4. **Per-call `prepare()`** on SQLite statements (`PF-19`).
5. **Rebuild-per-item** where one build serves all items (`PF-26`).
6. **Re-serializing whole files per record** (`PF-12` — quadratic, ~96 fsyncs
   per batch).
7. **Redundant key derivation** — Ed25519 scalar mults are milliseconds in
   pure-JS tweetnacl (`PF-23`).
8. **Ignored backpressure** on streams (`PF-24`).

Attribute cost to the path it is on. A slow background sweep is a nit; the same
loop on the **boot-recovery critical path** delays the venue resuming
(`PF-27`).

---

## Environment gotchas (these cost real time)

- `ls` is aliased to `eza` — use `/bin/ls`.
- A broken nvm shim can shadow `node`; use the absolute path.
- zsh: quote glob-like flags (`grep '--include=*.rs'`) or restructure.
- Markdown tables drift in column count and ordered lists renumber wrongly when
  you insert rows — **re-verify both after every edit**, mechanically.
- Never start a billable CVM without asking. **Never stop a prepaid on-demand
  GPU CVM** — stopping deallocates it and forfeits the window.

---

## What to produce

1. Create the next engagement directory: `audits/audit_<N>/` where `<N>` is one
   past the highest existing.
2. Write your findings to **`audits/audit_<N>/audit_<N>_findings.md`**, with an
   `audit-record` header block (audit name, date, engagement, **fresh ID
   prefix**, link to `residual-backlog.md`).
3. Structure it as:
   - **§1 Executive summary** — severity buckets, and a one-line table of every
     finding. Lead with what is worst, and say plainly if the most valuable
     results are negative.
   - **§2 Findings** — per finding: severity, category, **exact `file:line`
     anchors**, the problem, a **concrete failure scenario a regression test
     could be written from**, **multiple fix options with trade-offs and costs
     in work terms**, and whether it is a **lockstep change** (CLAUDE.md §7).
   - **§2b Performance findings** — separate from security. Always present.
   - **§3 Verified clean** — with reasoning, so it is not re-audited.
   - **§4 Coverage** — what you read, what you did **not**, measured in
     non-test lines. Be honest about partial reads.
   - **§5 What I could not rule out** — questions needing the team, hardware, or
     a specialist.
4. Update `audits/residual-backlog.md` in the **same change**: add your rows,
   and fold your findings into the **structural classes** section if they extend
   an existing pattern.
5. When remediation starts, create `audits/audit_<N>/tracker.md` per
   `audits/README.md`.

**Separate crypto/soundness findings from performance findings.** Keep IDs
stable once published — they are cited in commit messages forever.

---

## Two things to state honestly in every report

1. **Reading is not assurance.** A clean generalist read of the circuits is not
   a substitute for `F-04`, the external circuit audit, which remains an open
   mainnet gate. Say so rather than letting a clean result imply more.
2. **Findings are not fixes.** Report what is open, and resist letting a long
   list of "verified clean" entries imply the codebase is remediated. Several
   fixes here require a live CVM run to verify, not a green local gate.
