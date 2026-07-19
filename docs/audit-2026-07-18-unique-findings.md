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
> **Code ground truth:** current `main` plus
> `remediation/audit-2026-07-18-residuals` (post amount-privacy / per-match fee
> notes / market public inputs). Several
> July-14 CS findings (CS-01…CS-03 class) describe a **pre-remediation** circuit
> shape; this delta assumes the shipped MatchSlot with per-match fees,
> Poseidon11 leaves, and 8 public inputs.
>
> **ID prefix:** `U-01…` so these do not collide with CS-*, N-*, F-*, C-*.

**Severity:** Critical / High / Medium / Low / Perf-Nit / Info  
**Status:** U-01…U-06 addressed on branch `remediation/audit-2026-07-18-unique`
(merged PR #59); U-07 **Won't Fix** (rationale below); U-08…U-10 fixed on
`remediation/audit-2026-07-18-residuals`. All findings were revalidated against
current `main` before the residual remediation.

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
> | U-08 | **Fixed** — non-zero limits are tick-checked at shared intake and defensively excluded by the pure matcher; zero-limit market asks remain eligible. |
> | U-09 | **Fixed** — governed real-market boot requires finalized Vault/Market config, adopts owner+fee+market atomically, and a one-minute monitor pauses place/modify+matching on drift/read failure while cancel/reconcile continue. Placeholder loadgen mode is settlement-disabled. |
> | U-10 | **Fixed (comments/docs)** — exact-fee and already-bound MarketConfig wording restored across active TEE/vault/protocol docs. |
>
> **Independent re-verify (2026-07-18, post-merge `main`).** See §7. U-01…U-04, U-06, U-07
> match the claimed outcomes. U-05 had one residual stale `TradeSettled` fee-leaf
> doc-comment (fixed in the re-verify pass). Second-pass residual items are **U-08…U-10**.

---

## 1. Severity-ranked backlog

| ID | Severity | Category | Finding | Status |
|---|---|---|---|---|
| U-01 | Medium | TEE-trust / Consensus | `MarketConfig` tick / min size / circuit-breaker are not proof-bound | Doc (see U-08 for tick) |
| U-02 | Low–Medium | Replay / Liveness | `lock_note` does not reject already-consumed commitments | **Fixed** |
| U-03 | Low | Constraints (hygiene) | Active slots allow `quote_amount = 0` (zero-value `note_d` leaves) | **Fixed** |
| U-04 | Low | TEE-trust / recovery | Compromised TEE can strand on-chain fill recovery with garbage ciphertext | Doc |
| U-05 | Low | Docs / comment drift | Settle comments still describe batch-slot-0-only fee flush | **Fixed** (+ residual event docs) |
| U-06 | Perf-Nit | Allocation | Zero-quote / dust leaves waste Merkle capacity | **Fixed** |
| U-07 | Perf-Nit | CU | Ed25519 precompile scan walks every instruction in the settle tx | **Won't Fix** |
| U-08 | Medium | TEE-trust | `tick_size` never enforced in matcher/intake | **Fixed** |
| U-09 | Medium | Ops / TEE-trust | Boot fail-open + sticky market/fee config (no re-poll) | **Fixed** |
| U-10 | Low | Docs | Stale fee-FLOOR / future-tense bind comments in TEE boot | **Fixed** |

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

## 7. Independent re-verify + second-pass (post PR #59)

Original re-verify ground truth: `main` after `874bad0` (merge of remediation PR
#59), plus a one-line U-05 residual comment fix on `TradeSettled`. U-08…U-10
were then remediated on `remediation/audit-2026-07-18-residuals`.

### 7.1 U-01…U-07 verification matrix

| ID | Claimed outcome | Code check | Result |
|---|---|---|---|
| **U-01** | Doc: TEE-enforced-only | `MarketConfig` field docs in `state.rs`; CRYPTOGRAPHY.md non-goals row for tick/min/breaker | **Pass** (doc) — but see **U-08**: `tick_size` is not actually enforced in matcher/intake |
| **U-02** | `lock_note` must-be-absent consumed PDA | `lock_note.rs` seeds + `owner != program_id` → `NoteAlreadyConsumed`; SDK account[4]; TEE `lock_note.rs` AccountMeta; `programs/vault/tests/lock_note_consumed_guard.rs` | **Pass** |
| **U-03** | Active `quote_amount ≠ 0` | `match_batch.circom` `quoteIsZero` + `is_active * quoteIsZero.out === 0`; SDK prototype test `[zero_quote_active]` | **Pass** (assumes zkey/VK rotated in same PR — regenerate gate if deploy drifts) |
| **U-04** | Doc: recovery is TEE-honesty | `MatchResultPayload.fill_recovery` U-04 block; CRYPTOGRAPHY non-goals | **Pass** |
| **U-05** | Per-match fee comments | Batched settle fee comments correct; **`TradeSettled` fee leaf docs still said “first settlement only”** | **Partial → fixed** in re-verify (event doc-comments only) |
| **U-06** | Matcher skips zero-quote | `algorithm.rs` `if quote_amt == 0 { continue }`; unit test `generate_matches_skips_zero_quote_clear` | **Pass** |
| **U-07** | Won't Fix | Full `0..total_ix_count` scan retained; comment documents prior `+8` footgun | **Accept Won't Fix** — rationale sound |

Also confirmed closed elsewhere (not re-opened): merge refuses live `NoteLock` (N-04), market-ask zero excluded from price candidates (N-03), production dstack fail refuses boot unless `DARKNYX_TEE_ALLOW_TEST_AUTH=1` (N-01 class).

### 7.2 Second-pass findings (new)

#### U-08 — `tick_size` is config/API surface only; never enforced in matching

| | |
|---|---|
| **Severity** | **Medium** (product honesty / residual of U-01) |
| **Category** | TEE-trust / Other |
| **Anchors** | `darkpool-matcher/src/config.rs` (`tick_size` field); adopted at boot (`darknyx-tee/src/main.rs`); exposed on `/instruments`; **no** `price_limit % tick_size` (or equivalent) in `algorithm.rs` or `api/orders.rs` |
| **Status** | **Fixed (2026-07-19)** |

**Failure scenario.** Governance sets `tick_size = 100`. Clients and instruments report that tick. Orders may still book and clear at off-tick limits (e.g. 150). Unlike min size / circuit breaker (which the matcher *does* apply), tick is dead weight for enforcement. U-01 docs said “TEE-enforced”; for tick that claim is currently **false**.

**Recommended fix.** Enforce at intake and/or at clear: reject or snap limits to tick multiples when `tick_size > 1`. Add a unit test with `tick_size = 10` and off-tick limit. Or stop advertising tick as a market rule until implemented.

**Lockstep:** No circuit change (remains TEE-only policy).

**Remediation.** The common `prepare_order` path used by REST place/modify and
`/v1/stream` now rejects unknown symbols and every non-zero limit that is not a
multiple of the advertised tick (`ApiError` 1009). The pure matcher also skips
off-tick snapshots as defense in depth. A price of zero remains valid only for
the existing market-ask path; zero-price bids retain their separate rejection.
Regressions cover intake rejection, an accepted zero-limit market ask, and a
direct matcher bypass attempt with `tick_size = 10`.

---

#### U-09 — Boot fail-open + sticky MarketConfig / fee rate (no live re-poll)

| | |
|---|---|
| **Severity** | **Medium** (liveness / ops; not custody) |
| **Category** | TEE-trust / Ops |
| **Anchors** | `darknyx-tee/src/main.rs` — on VaultConfig/MarketConfig read **None/Err**: warn and continue with env defaults; comment “live re-poll is intentionally deferred”; fee-rate adopt only at boot |
| **Status** | **Fixed (2026-07-19)** |

**Failure scenario.**

1. **RPC blip at boot** with a real signer present: TEE starts on env `price_scale` / mints / fee rate while chain has different `MarketConfig` / `VaultConfig`. `verify_match_batch` binds the **on-chain** public inputs → every batch proof fails until CVM restart with working RPC and correct adopt.
2. **Mid-life governance:** admin updates `price_scale` or `fee_rate_bps` on-chain; running CVM keeps boot snapshot → same hard settle failure until redeploy/restart.
3. **Fail-open on missing market:** warns and trades against env market parameters (dev-shaped risk if a “prod” binary boots without a deployed MarketConfig).

Contrast: `enabled == false` **does** hard-bail. Fee/scale mismatch does not.

**Recommended fix.** Production: **fail closed** if MarketConfig missing/malformed when settle is enabled; optional periodic re-read of fee rate + market params (or hot-reload on mismatch log + pause placement). Document restart requirement after any `update_market_config` / `set_protocol_config`.

**Lockstep:** No.

**Remediation.** A real-market boot (both mint env vars present) now reads both
accounts at `finalized` commitment and exits if either is missing, wrong-owner,
malformed, disabled, or internally invalid. It adopts
`protocol_owner_commitment` together with `fee_rate_bps` (the re-verify found
that owner drift was the same proof-failure class), plus all market parameters.
The full pinned `VaultConfig` reader is layout-tested.

Every minute, the running CVM re-reads finalized governance. Any RPC/parse
failure, immutable parameter drift, unavailable settle driver, or mismatch
between the derived K signers and the active on-chain set closes a shared trading
gate. Place/modify and matcher ticks stop; cancellation and settlement
reconciliation remain live. Restoring the expected signer set resumes in place;
fee/owner/market changes require a restart so matcher, prover, and settler adopt
one atomic snapshot. `/system/status.degraded` reflects the pause.

Omitting both mint env vars remains the explicitly documented synthetic loadgen
regime, but it is now settlement-disabled; supplying only one mint is a startup
error. This preserves intake/paging load tests without retaining a production
env-fallback settle path.

---

#### U-10 — Stale “fee FLOOR” / future-tense MarketConfig comments in TEE boot

| | |
|---|---|
| **Severity** | **Low** (docs only) |
| **Category** | Docs / comment drift |
| **Anchors** | `darknyx-tee/src/main.rs` boot block: “settle fee FLOOR”; “VALID_MATCH_BATCH v3 will also bind this account” (already binds mints + price_scale) |
| **Status** | **Fixed (2026-07-19)** |

**Failure scenario.** Maintainers re-implement floor-only fee or assume market binding is unfinished.

**Recommended fix.** Comment truth-up to exact fee + already-bound public inputs.

**Lockstep:** No.

**Remediation.** Active boot, assembler, scheduler, vault-handler, OpenAPI, and
cryptography prose now describe the exact governed fee (both inequalities) and
the already-shipped 8-public-input market binding. The stale slot-0 aggregate
fee diagram was also replaced with the per-match fee-note/Poseidon11 model.

### 7.3 Second-pass: nothing Critical found

No new fund-theft / inflation path beyond the known circuit-trust + TEE-trust model. Highest residual process gates remain July-14 **N-18** (ceremony) and **N-19** (multisig / attestation rotation ops) plus external circuit audit.

### 7.4 Residual-remediation validation

- `cargo test -p darkpool-matcher --test parity` — tick enforcement and
  market-ask regression.
- `cargo test -p darknyx-tee --bin darknyx-tee` — governance
  snapshot/adoption policy.
- `cargo test -p darknyx-tee --lib` — full TEE library suite, including full
  VaultConfig parsing and the shared gate (localhost mock-RPC tests run outside
  the filesystem/network sandbox).
- `cargo test -p darknyx-tee --test orders_surface --test matcher_tick --test http_surface`
  — shared intake, cancellation-during-pause, matcher pause, and readiness surface.
- Phala image `tee-v3-hardening-65` — finalized governed real-mint boot and
  `cvm-settle-e2e` passed on prod9. One match settled on devnet with internal
  native witness/prove/aggregate proof timings of 219/1,967/2,215 ms and one
  confirmed / zero rejected / zero ambiguous outcome. The harness aligns its
  live Hermes limits to the finalized tick before signing, exercising the U-08
  intake rule rather than bypassing it.
- Controlled finalized signer drift — rotating away from the derived CVM signer
  produced `params_match=true`, `signers_match=false`,
  `/system/status.degraded=true`, and `matcher_running=false`; restoring the
  signer resumed trading at the next one-minute refresh. The CVM was stopped
  and its protected deploy environment securely deleted after validation.

---

*Compiled 2026-07-18; re-verified post PR #59 and residuals remediated 2026-07-19. Defensive first-party delta only; not a third-party formal audit certificate.*
