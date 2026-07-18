# Unique findings — 2026-07-18 cryptography/systems pass

> **Purpose.** Delta inventory: vulnerabilities and efficiency notes from the
> 2026-07-16/18 defensive self-audit that are **not already tracked** in
> [`audit-2026-07-14-cryptography-systems-review.md`](./audit-2026-07-14-cryptography-systems-review.md)
> (CS-01…CS-14, P-01…P-04) or
> [`audit-2026-07-14-followup-sweep.md`](./audit-2026-07-14-followup-sweep.md)
> (N-01…N-19 and closed prior art).
>
> **Method.** Each candidate from that pass was compared by **failure mode**,
> not by wording. Inherited gates already listed in those docs (dev Groth16
> setup / N-18, no on-chain DCAP / N-19, external circuit audit, TEE-trusted
> price fairness, fill_recovery 128 B as accepted P-02, throughput-roadmap
> 1–5, deposit C-06) are **excluded** even if restated.
>
> **Code ground truth:** current tree on `remediation/settlement-outcomes`
> (post amount-privacy / per-match fee notes / market public inputs). Several
> July-14 CS findings (CS-01…CS-03 class) describe a **pre-remediation** circuit
> shape; this delta assumes the shipped MatchSlot with per-match fees,
> Poseidon11 leaves, and 8 public inputs.
>
> **ID prefix:** `U-01…` so these do not collide with CS-*, N-*, F-*, C-*.

**Severity:** Critical / High / Medium / Low / Perf-Nit / Info  
**Status:** U-01…U-06 addressed on branch `remediation/audit-2026-07-18-unique`
(one PR); U-07 **Won't Fix** (rationale below). All seven validated against HEAD
before remediation.

> **Remediation outcome (2026-07-18).** Every finding here was code-validated as
> genuine, then remediated as follows. See the per-finding sections for the
> anchors touched.
>
> | ID | Outcome |
> |---|---|
> | U-01 | **Doc** — `MarketConfig` tick/min/breaker labelled TEE-enforced-only (`state.rs` + CRYPTOGRAPHY.md non-goals). No binding (in trust model). |
> | U-02 | **Fixed** — `lock_note` now takes a must-be-absent `consumed_note` account + rejects `NoteAlreadyConsumed` (on-chain + SDK + TEE builders, litesvm regression). |
> | U-03 | **Fixed** — circuit now constrains `quote_amount ≠ 0` on active slots (VK rotation: new zkey + `vk_match_batch_n16.rs` + N=16 fixture). |
> | U-04 | **Doc** — `fill_recovery` labelled a TEE-honesty (not cryptographic) assumption (`tee_forced_settle.rs` + CRYPTOGRAPHY.md). |
> | U-05 | **Fixed (comments)** — settle fee-note comments rewritten to the per-match model. |
> | U-06 | **Fixed** — matcher skips zero-quote clears (`generate_matches`, unit test). Front-line companion to U-03. |
> | U-07 | **Won't Fix** — see §3. |

---

## 1. Severity-ranked backlog

| ID | Severity | Category | Finding |
|---|---|---|---|
| U-01 | Medium | TEE-trust / Consensus | `MarketConfig` tick / min size / circuit-breaker are not proof-bound |
| U-02 | Low–Medium | Replay / Liveness | `lock_note` does not reject already-consumed commitments |
| U-03 | Low | Constraints (hygiene) | Active slots allow `quote_amount = 0` (zero-value `note_d` leaves) |
| U-04 | Low | TEE-trust / recovery | Compromised TEE can strand on-chain fill recovery with garbage ciphertext |
| U-05 | Low | Docs / comment drift | Settle comments still describe batch-slot-0-only fee flush |
| U-06 | Perf-Nit | Allocation | Zero-quote / dust leaves waste Merkle capacity |
| U-07 | Perf-Nit | CU | Ed25519 precompile scan walks every instruction in the settle tx |

---

## 2. Explicitly **not** re-filed (already in July-14 docs)

| Candidate from 07-16/18 pass | Already covered by |
|---|---|
| Dev/deterministic Groth16 contribution | Follow-up **N-18**; CS review “prior art / inherited gates” |
| No on-chain TDX quote binding of `tee_pubkeys` | Follow-up **N-19** + “still deferred by design: on-chain DCAP” |
| External circuit audit still required | Follow-up C-07 / F-04 process open; CS review inherited |
| TEE-trusted price / limit / oracle band | CS review accepted fairness boundary; CRYPTOGRAPHY non-goal |
| Deposit exposes owner/inner (C-06 style) | Follow-up §2.4: **Closed** via `VALID_DEPOSIT` (do not reopen without re-audit of deposit path) |
| `fill_recovery` 128 B on Tx D | Follow-up **P-02 Accepted** |
| Optional client `verifyRoot` / C-09 | Follow-up **N-15** |
| Throughput-roadmap settle concurrency / ALT / witness-gen | Both docs + `docs/throughput-roadmap.md` |
| Dead nullifiers in payload | Follow-up **N-17** / July P-01 (if still present at HEAD) |

---

## 3. Unique findings

### U-01 — `MarketConfig` safety fields are not proof-bound

| | |
|---|---|
| **Severity** | **Medium** |
| **Category** | TEE-trust / Consensus |
| **Anchors** | `programs/vault/src/state.rs` (`MarketConfig.tick_size`, `min_order_size`, `circuit_breaker_bps`); `programs/vault/src/instructions/verify_match_batch.rs` (binds `enabled`, mint halves, `price_scale` only); `circuits/templates/match_batch.circom` public list `[root, fee_rate, protocol_owner, base_lo/hi, quote_lo/hi, price_scale]` |

**Why unique.** July-14 **CS-02** was about **per-slot mint-pair unbound / cross-mint fee aggregation** (largely addressed by batch-level market public inputs + per-match fees). This item is narrower: governance fields that **still live on-chain** but are **never** public inputs or leaf-bound. Follow-up N-03 covers matcher **P\*=0** from market asks, not unbound tick/min/breaker.

**Failure scenario.** Admin sets `circuit_breaker_bps = 100`, nonzero `tick_size`, and `min_order_size`. A compromised or buggy authorized TEE clears off-tick, under min size, and outside the breaker band. `verify_match_batch` still succeeds. Product/docs that imply “on-chain market rules” overclaim: only identity + scale + conservation + exact fees are proof-enforced; tick/min/breaker remain matcher-only.

**Recommended fix (pick one).**

1. **Honest posture:** document next to `MarketConfig` that tick / min / breaker are **TEE-enforced only** (same class as price fairness).  
2. **Hardening:** bind selected fields as public inputs or policy commitments (lockstep circuit + VK + assembler + verify).  
3. **Client detection:** reject fills outside signed limit + published breaker/TWAP policy (extends fill-memo integrity).

**Lockstep:** Only if option 2.

---

### U-02 — `lock_note` does not reject already-consumed commitments

| | |
|---|---|
| **Severity** | **Low–Medium** |
| **Category** | Replay / Liveness |
| **Anchors** | `programs/vault/src/instructions/lock_note.rs` (VALID_INPUT + `NoteLock` `init` only; no `ConsumedNoteEntry`); contrast `withdraw.rs` / `tee_forced_settle_batched.rs` which `init` consumed PDAs |

**Why unique.** Follow-up **N-04** is the inverse lifecycle gap (merge ignores live `NoteLock`). CS-09 is expired-lock **settle**. No July-14 item requires “consumed ⇒ cannot re-lock.”

**Failure scenario.** Note `C` already settled or withdrawn → `ConsumedNoteEntry[C]` exists; Merkle leaf remains. A retained VALID_INPUT proof still proves membership + ownership → authorized TEE can `lock_note` again. Re-settle fails on consumed `init`; withdraw already impossible. Outcome: rent waste, confusing state, optional griefing—not double-spend of value.

**Recommended fix.** In `lock_note`, require the commitment-keyed consumed PDA to be **absent** (empty account / must-not-exist), same seed as settle/withdraw: `[ConsumedNoteEntry::SEED, commitment]`.

**Regression sketch.** After successful settle or withdraw of `C`, `lock_note(C, …)` must fail; unconsumed notes still lock.

**Lockstep:** No circuit change.

---

### U-03 — Active slots allow `quote_amount = 0` (zero-value `note_d`)

| | |
|---|---|
| **Severity** | **Low** |
| **Category** | Constraints (hygiene) |
| **Anchors** | `circuits/templates/match_batch.circom` — active path forces `base_amount ≠ 0` and `clearing_price ≠ 0`, but **not** `quote_amount ≠ 0`; `note_d` always opened (unlike change notes’ `IsZero` path); `tee_forced_settle_batched.rs` always appends `note_c`/`note_d` |

**Why unique.** Follow-up **N-03** is matcher candidate selection at **P\*=0**. This is the **circuit/settle** residual when scaled floor yields zero quote while base and price are positive (or any path that sets quote=0 with `is_active=1`).

**Failure scenario.** `floor(base * price / price_scale) = 0`. Proof verifies. Tx D appends a Poseidon commitment of a **zero-amount** quote note. Withdraw requires `amount > 0` → leaf is permanently unspendable dead weight. Extreme underpricing remains under accepted TEE price trust; this finding is specifically the **always-minted zero-value leaf**.

**Recommended fix.** For `is_active = 1`, constrain `quote_amount ≠ 0` (mirror `baseIsZero`), **or** make `note_d` conditional on nonzero quote like change notes. Matcher should also refuse zero-quote clears.

**Lockstep:** Yes if circuit changes (VK + zkey + N=16 fixture + prover/assembler).

---

### U-04 — Compromised TEE can strand on-chain fill recovery with garbage ciphertext

| | |
|---|---|
| **Severity** | **Low** |
| **Category** | TEE-trust / recovery |
| **Anchors** | `MatchResultPayload.fill_recovery` (opaque to program; covered by TEE signature); `crates/nyx-tee/src/settle/fill_recovery.rs`; client decrypt + commitment recompute in SDK recover / fill-memo paths |

**Why unique.** CS-10 / fill-enc work is about **unsigned / low-order X25519 at intake**. This is post-match: authorized TEE signs a valid settle whose recovery blob is wrong or random. Not a vault drain.

**Failure scenario.** TEE settles correctly (commitments conserved) but writes garbage `fill_recovery`. Clients that missed the live fill stream and rely only on chain recovery fail decrypt or commitment checks → temporary stranding until stream/history backfill or alternative recovery.

**Recommended fix.** Operational: alert on recovery failure; optional redundant off-chain fill-memo backup. Product: document that recovery integrity is TEE-honest for ciphertext content (AEAD protects confidentiality, not “TEE honesty”).

**Lockstep:** No.

---

### U-05 — Settle comments still describe batch-slot-0-only fee flush

| | |
|---|---|
| **Severity** | **Low** (documentation / maintainer hazard) |
| **Category** | Docs / comment drift |
| **Anchors** | `tee_forced_settle_batched.rs` comments (“Only the first settlement in a batch carries them”); `tee_forced_settle.rs` `TradeSettled` fee leaf docs; contrast circuit per-match fee notes + per-Tx D append |

**Why unique.** CS review “Stale or contradictory protocol text” lists other CRYPTOGRAPHY/ARCHITECTURE mismatches, not this post-per-match-fee residual. Misleads anyone remediating CS-01-class issues against the wrong model.

**Failure scenario.** Engineer “optimizes” fee flush back to aggregate slot-0 behavior or misreads leaf append order → reintroduces solvency/aggregation bugs.

**Recommended fix.** Rewrite comments/docs to **per-match** fee notes, Poseidon11 leaf (with active bit), and 8 public inputs. No protocol change.

**Lockstep:** No.

---

### U-06 — Zero-quote / dust leaves waste Merkle capacity

| | |
|---|---|
| **Severity** | **Perf-Nit** |
| **Category** | Allocation |
| **Anchors** | Same path as **U-03**; `append_leaves` always includes `note_c`/`note_d` |

**Why unique.** Not in CS P-01…P-04 or follow-up N-list. Companion efficiency note to U-03.

**Failure scenario.** Pathological tiny prices (or buggy matcher) fill shards with unspendable leaves → earlier `MerkleTreeFull` / more shard pressure.

**Recommended fix.** Couple with U-03 (reject zero quote in circuit and matcher).

**Lockstep:** With U-03 if circuit-gated.

---

### U-07 — Ed25519 precompile scan walks every instruction in the settle tx

| | |
|---|---|
| **Severity** | **Perf-Nit** |
| **Category** | CU |
| **Status** | **Won't Fix (2026-07-18)** |
| **Anchors** | `programs/vault/src/instructions/tee_forced_settle.rs` `verify_tee_signature` — loop `0..total_ix_count` |

**Why unique.** Not in July-14 perf lists (those cover writable marker, Merkle path recompute, book clone/sort, RPC poll fan-out).

**Failure scenario.** Relayer packs many instructions into the settle transaction → linear CU cost scanning for the Ed25519 precompile. Unlikely dominant vs Poseidon/Groth16; cheap hygiene.

**Recommended fix.** Convention: place Ed25519 ix at fixed index 0 and short-circuit; keep full scan as fallback.

**Lockstep:** No.

**Disposition — Won't Fix.** The full scan **intentionally replaced** a prior
`current_ix_idx + 8` window that silently skipped an Ed25519 precompile placed
more than 8 slots after the settle ix (see the comment at
`verify_tee_signature`, "Previous code used `current_ix_idx + 8`…"). The scan
is bounded by the actual tx's instruction count (~3–4; the TEE builds its own
settle tx — it is not adversarial), so the cost is negligible next to the
Poseidon/Groth16 work in the same handler. A fixed-index-0 fast path would
reintroduce the positional assumption the scan was written to remove, for no
measurable gain. Declined deliberately.

---

## 4. Context from the same pass (not new vulns)

These are **verification outcomes**, recorded so the backlog is not confused with July-14 CS open items that may already be remediating:

| Topic | Observation at this HEAD |
|---|---|
| CS-01-style aggregate phantom fee notes | Shipped circuit uses **per-match** fee notes bound in-slot; settle appends fees with that match’s consumes |
| CS-02-style free per-slot mints | Batch fans **one** market’s mint halves + `price_scale` as public inputs into every slot |
| CS-03-style free output inners | User/fee inners derived in-circuit (`Poseidon3(24/25, …)`); not free witnesses |
| P0 no-inflation range checks | `Num2Bits(64)` on all conservation terms + exact fee floor/ceil present |
| F-01/F-02 dev admin ixs | Feature-gated behind `devnet-admin` (follow-up already notes mainnet build hygiene) |

Re-verify anchors before closing any July-14 CS item—line numbers and branch state drift.

---

## 5. Suggested remediation order (this delta only)

1. **U-01** — decide document vs bind for MarketConfig safety fields (product honesty).  
2. **U-02** — `lock_note` consumed-PDA absence check (small on-chain fix + tests).  
3. **U-03 + U-06** — nonzero quote for active slots (circuit lockstep if chosen).  
4. **U-05** — comment/doc truth-up after fee model (cheap).  
5. **U-04 / U-07** — ops/docs and CU polish as capacity allows.

Mainnet process gates (**N-18**, **N-19**, external circuit audit) remain owned by the July-14 follow-up, not duplicated here.

---

## 6. What this pass still could not rule out

Same class of residual as the July-14 CS review, still not new vulns:

1. Formal R1CS underconstraint tooling / external circuit audit.  
2. Live Phala/TDX control-plane and ceremony provenance.  
3. Full matcher economic algorithm line-by-line beyond trust-boundary checks.  
4. Production config always leaving daemon `verifyRoot` + DCAP strict (defaults are good; ops can disable).

---

*Compiled 2026-07-18. Defensive first-party delta only; not a third-party formal audit certificate.*
