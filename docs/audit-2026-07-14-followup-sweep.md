# Audit follow-up sweep — 2026-07-14

> **Purpose.** Verify remediation of every item in
> [`audit-2026-07-12-findings-inventory.md`](./audit-2026-07-12-findings-inventory.md)
> against current `main`, then deep-audit surfaces that the July-12 pass
> **explicitly left unreviewed** (inventory Part C). Produce a new residual
> backlog for mainnet readiness.
>
> **Method.** Code is ground truth. Prior-art IDs (C-01…, F-0x, A-1/A-2) are
> re-verified at HEAD, not re-derived from memory. New findings use IDs
> **N-01…** so they do not collide with the July inventory.
>
> **HEAD context (when this doc was written):** branch `main`, tip around
> `24fbf18` (post PR #30–#37: DCAP, C-01/C-02/C-04/C-05/C-08/C-09, C-08 settler
> fix). Re-check anchors if reading later — line numbers drift.
>
> **Related:** `audit_1/REPORT.md`, `audit_2/READINESS.md`,
> `docs/attestation-dcap-enforcement-plan.md` (now largely implemented).

**Severity:** Critical / High / Medium / Low / Perf-Nit / Info  
**Status:** Closed · Partial · Open · Accepted design · Process

---

## 1. Executive summary

### What improved since 2026-07-12

The team closed **most of the load-bearing fund-safety and attestation gaps**
from the July inventory:

| Area | Outcome |
|---|---|
| **C-01** merge↔settle double-spend | **Closed** — merge writes commitment-keyed `ConsumedNoteEntry` (same as settle/withdraw); VALID_MERGE public inputs are input commitments |
| **C-02** unbounded relock TTL | **Closed** — `create_relock_pda` enforces `MAX_LOCK_TTL_SLOTS` |
| **C-03 / A-1 + B-1…B-4 + K-shard** | **Closed** (client path) — real `@phala/dcap-qvl`, strict default, RTMR3/event-log compose bind, full key-set in `report_data`, `/info.tee_pubkeys`, on-chain set cross-check |
| **C-04** fee confiscation | **Closed** — circuit floor **and** ceiling ⇒ exact `⌊notional·rate/10000⌋` |
| **C-05 / A-2** oracle JSON price | **Closed** — price from guardian-signed accumulator Merkle inclusion, not Hermes `parsed[]` alone |
| **C-08** batch_slot | **Closed** — circuit `batch_slot[i]===i` + on-chain `payload.batch_slot == match_index` + settler pad/leaf fix |
| **C-09** inclusion root | **Partial** — SDK hook exists; **not mandatory** for all callers |
| **Doc-stale / B-5…B-8** | **Mostly closed** — DCAP/SDK modules exist; docs truth-up landed |
| **F-09** zero/dup TEE keys | **Closed** on `set_tee_pubkey` |

**No new Critical on-chain fund-theft path** was found in this pass under the
stated trust model (sound circuits + honest-or-attested TEE for fairness).

### What remains the biggest residual risk

1. **Degraded-boot auth** — if dstack probe fails, production path can still
   serve matcher HTTP with **hardcoded test JWT secret + test admin registry**
   (**N-01**, High).
2. **Book commits before settle success** — match applied to book before
   settle finality; failures are non-restoring (**N-02**, High liveness).
3. **Market-ask `price_limit == 0` as clearing candidate** can select
   **P\* = 0** when CB is wide (**N-03**, High economic semantics).
4. **Still open process gates:** real Groth16 Phase-2 ceremony, external
   circuit audit, mainnet multisig admin (not single-sig).

---

## 2. July-12 inventory — remediation status (re-verified)

### 2.1 Fund safety / replay (A1)

| ID | July-12 | Now | Evidence (anchors) |
|---|---|---|---|
| **C-01** | Open Critical | **Closed** (consume path) | `merge.rs:10–17,131–154,182+` creates `ConsumedNoteEntry`; public inputs = input commitments; circuit `valid_merge.circom` C-01 comments. Residual: merge still does **not** block live `NoteLock` → **N-04** |
| **C-02** | Open High | **Closed** | `tee_forced_settle.rs` `create_relock_pda`: `expiry > clock` and `≤ clock + MAX_LOCK_TTL_SLOTS` |
| **C-08** | Open Low | **Closed** | `match_batch.circom` `batch_slot[i] === i`; `tee_forced_settle_batched.rs` requires `payload.batch_slot == match_index`; TEE settler uses batch index not wall slot (`3df4003`) |

### 2.2 TEE trust / attestation (A2)

| ID | July-12 | Now | Evidence |
|---|---|---|---|
| **C-03 / A-1** | Open | **Closed** (client) | `packages/sdk/src/tee/{dcap,verify-core,attestation}.ts`; daemon strict + `createDcapQuoteVerifier`; stock `bin/daemon.ts` wires DCAP |
| **B-1** mrtd path | Open | **Closed** | Daemon/SDK read `tcb_info.mrtd` |
| **B-2** event_log | Open | **Closed** | Parsed; RTMR3 replay; compose from event |
| **B-3** pins optional | Open | **Closed** in strict | `pin_required` without compose+tee_pubkey |
| **B-4** no QuoteVerifier | Open | **Closed** | Daemon constructs DCAP verifier by default |
| **Shard-0 only** | Open | **Closed** | `/info.tee_pubkeys`; `report_data` binds full set hash; on-chain cross-check |
| **C-05 / A-2** | Open | **Closed** | `oracle/sync.rs` + `oracle/accumulator.rs`: VAA verify → root → Merkle inclusion → price from binary message |

**Still deferred by design:** on-chain DCAP / vault quote verification (attestation §11).

### 2.3 Circuit / economic (A3)

| ID | July-12 | Now | Evidence |
|---|---|---|---|
| **C-04** fee ceiling | Open | **Closed** | `match_batch.circom` floor `GreaterThan` + ceil `LessEqThan` → exact fee |
| **C-07 / F-04** | Process open | **Still open** | External formal circuit audit still required |
| **Trusted setup** | Open | **Still open** | `scripts/build-circuits.sh` beacon dev contribution; `CRYPTOGRAPHY.md` §2 |
| **TEE key ops** | Open | **Partial** | Client DCAP + set binding; admin still single-sig on-chain unless multisig ops |

### 2.4 Privacy / client (A4)

| ID | July-12 | Now | Evidence |
|---|---|---|---|
| **C-06** deposit opens owner+inner | Open / design | **Docs truth-up** (design residual) | Still public ix args (by construction); docs updated not to claim “never revealed” |
| **C-09** inclusion root ring | Open | **Partial** | Optional `verifyRoot` on `fetchInclusionProof`; **not** auto-wired for every daemon/SDK path |

### 2.5 Performance (A5)

| ID | July-12 | Now |
|---|---|---|
| **P-01** dead nullifiers in payload | Open | **Still open** — still in `MatchResultPayload` / canonical hash |
| **P-02** fill_recovery 128 B pad | Accepted | Unchanged |
| **P-03** pad clones | Open | **Closed** — pad sets distinct `batch_slot = index` |
| Throughput roadmap 1–5 | Deferred | Still deferred (correct) |

### 2.6 Docs (A6)

| ID | July-12 | Now |
|---|---|---|
| **B-5** missing SDK attestation | Open | **Closed** — module exists |
| **B-6 / B-7 / B-8** OpenAPI / event_log / report_data | Open | **Mostly closed** (truth-up + code comments); spot-check OpenAPI periodically |
| **Doc-stale-1** shared nullifier claim | Open | **Should be closed** after C-01 docs truth-up — re-read site docs if publishing externally |
| **Doc-stale-2/3** | Open | Addressed in docs truth-up PR |

### 2.7 Suggested July checklist (Part B) progress

1. [x] C-01 dual-guard (consume)  
2. [x] C-02 relock TTL  
3. [x] C-03 / B-1–B-4 DCAP  
4. [x] C-04 exact fee  
5. [x] C-05 oracle inclusion  
6. [ ] External circuit audit + Phase-2 ceremony  
7. [~] C-06/C-08/C-09 — C-08 done; C-06 design; C-09 partial  
8. [ ] P-01 payload trim  
9. [ ] Multisig / ceremony ops for mainnet admin  

---

## 3. New findings (this residual sweep)

IDs are **new** relative to the July inventory.

---

### N-01 — Degraded boot enables matcher with hardcoded test JWT secret

| | |
|---|---|
| **Severity** | **High** |
| **Category** | Auth / ops / TEE deployment |
| **Anchors** | `crates/nyx-tee/src/main.rs:169–177` → `ApiState::for_tests()`; `api/state.rs:491–509` (`TEST_JWT_SECRET = [0x42; 32]`); then `main.rs:394–397` still `with_matcher_runtime(...)` |

**Failure scenario.** If `probe_dstack()` fails on a process that still exposes the public HTTP port (mis-mounted socket, wrong compose, “prod-shaped” binary without dstack), boot continues with:

- JWT HMAC secret = public constant  
- Test admin credential registry  
- **Live matcher / orders API attached**  
- Settle disabled (no signer)

Anyone who knows the constant can forge HS256 JWTs, place/cancel/modify (with their own trading keys), and scrape order privacy (see N-05). Not a direct vault drain (no TEE signer), but **full dark-book API compromise**.

**Fix.** Production: **exit non-zero** on dstack failure, **or** serve only `/health` without matcher/auth. Gate `for_tests()` behind explicit `NYX_TEE_ALLOW_TEST_AUTH=1` forbidden in prod compose. Never attach matcher on degraded boot.

---

### N-02 — Book + fill memos commit before settle finality; settle failures do not restore

| | |
|---|---|
| **Severity** | **High** (liveness / economic UX; not custody drain) |
| **Category** | Matcher ↔ settle pipeline |
| **Anchors** | `matcher/interval.rs:566–614` (`apply_updates` then send to settle); `settle/job.rs` non-retry; worker partial Tx D fail modes |

**Failure scenario.** Tick matches → book rotated / anchors consumed / fill memos emitted → settle later fails (RPC, ALT, prove). Job terminal Failed; **no book restore**. Notes may remain locked until TTL; residual order state lost; clients may treat provisional fills as final.

**Fix (directional).** Pending-settle state; redrive; or only mutate book after settle Done; mark fill memos provisional until chain confirm; per-match reconciliation for partial batches.

---

### N-03 — Zero `price_limit` asks are clearing candidates → can select P\* = 0

| | |
|---|---|
| **Severity** | **High** (market-order semantics / economic correctness) |
| **Category** | Matcher algorithm |
| **Anchors** | `darkpool-matcher/src/algorithm.rs:191–218` (all ask limits are candidates); `api/orders.rs` allows ask `price_limit == 0` as market sell (bids reject zero) |

**Failure scenario.** Market ask (`price_limit = 0`) enters candidate set. At `p = 0`, demand is all bids, supply includes zero-limit asks; volume often ties higher prices; ascending candidate order keeps **P\* = 0**. Then `quote = base * 0`. With a tight circuit breaker this may fail closed (market sell never fills); with wide/disabled CB, **free fills** (buyer pays 0 quote).

**Fix.** Do not use unconstrained market limits as price **candidates** — only for eligibility. Exclude `0` from candidates; or require positive min price for asks; unit test bid@150 + ask@0 clears at positive book price (or rejects).

---

### N-04 — Merge still does not refuse a live `NoteLock` (C-01 residual half)

| | |
|---|---|
| **Severity** | **High** (liveness / counterparty grief) |
| **Category** | Cross-path note lifecycle |
| **Anchors** | `merge.rs` (no NoteLock check) vs `withdraw.rs:128–139` (rejects lock) |

**Failure scenario.** Owner locks note for an order → races `merge` of same note → `ConsumedNoteEntry` created → settle forever fails on consume init; counterparty remains locked until TTL. **Not** a double-spend after C-01 consume unification, but the inventory’s “optionally block merge under NoteLock” is still open.

**Fix.** Same empty-lock check as withdraw for each non-zero input commitment.

---

### N-05 — `GET /orders/{id}` IDOR leaks price/size (darkpool privacy)

| | |
|---|---|
| **Severity** | **Medium** |
| **Category** | AuthZ / privacy |
| **Anchors** | `api/orders.rs:1052–1089` — `_auth` unused; any bearer can read any live order |

**Failure scenario.** Authenticated enumerator learns live order amounts and limits — defeats dark-order privacy.

**Fix.** Require `order_owner[id] == auth.account_id`; 404 on miss (no existence oracle).

---

### N-06 — Same `note_commitment` can back multiple live orders

| | |
|---|---|
| **Severity** | **Medium** |
| **Category** | Intake / book integrity |
| **Anchors** | Book keyed by `order_id` only; openings map can overwrite by commitment |

**Failure scenario.** Two orders share one collateral note → matcher may schedule two spends; first settle wins, second fails; book already advanced (amplifies N-02).

**Fix.** Reject intake if commitment already has a live opening/order.

---

### N-07 — Matcher `generate_matches` hashes change notes with `user_commitment`

| | |
|---|---|
| **Severity** | **Medium** (SSoT; production TEE rebuilds correctly) |
| **Category** | Matcher / crypto consistency |
| **Anchors** | `algorithm.rs:404–424` uses `user_commitment`; TEE `settle/assemble.rs` rebuilds with `owner_commitment` |

**Failure scenario.** Pure `run_batch` / any consumer of raw `MatchPair.note_e/f` gets wrong commitments when `user_commitment ≠ owner_commitment` (normal production). TEE assemble papers over it.

**Fix.** Use `owner_commitment` in matcher change/trade commitment construction; parity test with distinct values.

---

### N-08 — JWT in WebSocket query string

| | |
|---|---|
| **Severity** | **Medium** |
| **Category** | Token leakage |
| **Anchors** | `api/ws.rs`, `api/trading.rs` `?token=` |

**Fix.** Prefer subprotocol / short-lived ticket; avoid access-log exposure.

---

### N-09 — Info logs emit `clearing_price`

| | |
|---|---|
| **Severity** | **Medium** (privacy / ops) |
| **Category** | Logging |
| **Anchors** | `matcher/interval.rs:603–608` |

**Fix.** Drop to debug/trace or log only counts at info.

---

### N-10 — `initialize` accepts zero `tee_pubkey` / zero `root_key`

| | |
|---|---|
| **Severity** | **Medium** (ops) |
| **Category** | Governance init |
| **Anchors** | `initialize.rs` vs F-09 on `set_tee_pubkey` |

Zero root cannot rotate (no private key for default pubkey). Reject defaults at init.

---

### N-11 — `set_tee_pubkey` does not enforce `keys.len() == num_trees`

| | |
|---|---|
| **Severity** | **Medium** (ops footgun) |
| **Category** | Sharding |

Mis-set key count vs shards → round-robin / funding breakage, not direct theft.

---

### N-12 — Marker payer can close before all N settles

| | |
|---|---|
| **Severity** | **Medium** (TEE self-DoS / bug) |
| **Category** | Marker lifecycle |
| **Anchors** | `close_batch_validity_marker.rs` payer path unrestricted |

External parties only post-expiry (good). Compromised/buggy TEE as payer can brick batch early.

---

### N-13 — `VALID_INPUT` missing `Num2Bits(64)` on amount

| | |
|---|---|
| **Severity** | **Medium** (defense-in-depth) |
| **Category** | Circuit hygiene |
| **Anchors** | `valid_input/circuit.circom` vs spend/merge |

On-chain public input is u64 today → no known exploit; parity with other circuits.

**Fix.** Add range check + rebuild zkey/VK lockstep.

---

### N-14 — `VALID_MERGE` allows all-dummy / zero-output merges

| | |
|---|---|
| **Severity** | **Medium** (tree grief) |
| **Category** | Circuit + on-chain |

All inactive → amount 0 output still appends leaves → capacity DoS.

**Fix.** Require ≥1 active and `outputAmount > 0`.

---

### N-15 — C-09 `verifyRoot` optional; not default-on

| | |
|---|---|
| **Severity** | **Low–Medium** |
| **Category** | Client |
| **Anchors** | `valid-input-prover.ts` optional `verifyRoot` |

Partial July fix. Fund safety still ultimately gated by on-chain `contains_root` at lock/withdraw; residual is client wasted proves / TEE-shaped root confusion.

**Fix.** Wire default on-chain ring check in daemon prove path.

---

### N-16 — Fill-memo commitment compare case-sensitive

| | |
|---|---|
| **Severity** | **Low** |
| **Anchors** | `packages/sdk/src/orders/fill-memo.ts` |

Compare lowercased hex or raw bytes.

---

### N-17 — Dead nullifiers still in settle payload (P-01)

| | |
|---|---|
| **Severity** | **Perf-Nit** |
| **Anchors** | `MatchResultPayload.nullifier_a/b` still signed/serialized |

Reclaim ~64 B on Tx D with domain-tag bump if unused.

---

### N-18 — Trusted setup still dev beacon (process)

| | |
|---|---|
| **Severity** | **Critical for mainnet ceremony** (process, not runtime bug) |
| **Anchors** | `scripts/build-circuits.sh`, `CRYPTOGRAPHY.md` §2 |

Real Phase-2 MPC required before mainnet.

---

### N-19 — Single-sig admin / no on-chain attestation gate (process)

| | |
|---|---|
| **Severity** | **High ops for mainnet** |
| **Anchors** | `set_tee_pubkey` admin-only; ceremony docs |

Client DCAP does not replace multisig rotation discipline.

---

## 4. Surfaces audited this pass (Part C of July inventory)

| Surface | Depth | Outcome |
|---|---|---|
| C-01…C-09, A-1/A-2 remediations | Re-verify | See §2 |
| Vault governance + markers + merge residual | Deep | N-04, N-10–N-12 |
| TEE auth / orders / settle pipeline / WS / logs | Deep | N-01, N-02, N-05, N-06, N-08, N-09 |
| Matcher algorithm + fee flush | Medium | N-03, N-07 |
| Circuits spend/input/merge residual | Medium | N-13, N-14 |
| SDK fill-memo | Spot | N-16 |
| C-09 client root | Spot | N-15 |
| Crypto crate full parity re-run | **Not run** | Recommend CI gate only |
| `cargo audit` / `npm audit` | **Not run** | Next ops sweep |
| Live Phala deploy | **Not run** | Use `RUN_CVM_ATTEST` / nightly |
| apps/demo product | Out of scope | — |

---

## 5. What is still **not** fully audited (next next-sweep)

Carry these forward if you want another pass:

- Full line-by-line `settle/worker.rs` ALT pool race matrix under `SETTLE_CONCURRENCY>1` (still pinned to 1)
- Full Merkle mirror reorg/desync adversarial model
- Every SDK `*-transport` builder vs on-chain layout (rely on existing tests)
- Browser-only bundling of `@phala/dcap-qvl` in production portal
- Dependency CVE scan (`cargo audit`, `npm audit`)
- Formal ZK underconstraint tool (circomspect / external auditor)
- Mainnet upgrade-authority multisig **operational** verification

---

## 6. Recommended remediation order (updated)

### P0 — before any long-lived public CVM

1. **N-01** — kill production degraded-boot test auth / matcher attach  
2. **N-03** — fix market-ask / P\*=0 candidate set  
3. **N-04** — merge refuses live `NoteLock`  
4. **N-05 + N-06** — order IDOR + unique collateral note  

### P1 — production darkpool quality

5. **N-02** — settle/book recovery model  
6. **N-07** — matcher `owner_commitment` for change notes  
7. **N-08 / N-09** — WS token + clearing_price log hygiene  
8. **N-13 / N-14** — VALID_INPUT range + merge non-empty  
9. **N-15** — default-on C-09 root ring in daemon prove path  

### P2 — mainnet process gates

10. **N-18** Phase-2 ceremony + external circuit audit (F-04)  
11. **N-19** multisig admin + attestation-gated rotation ops  
12. **N-10 / N-11** init/set key hygiene  
13. **N-17** payload nullifier drop if Tx D tight  

### P3 — polish

14. N-12 marker close policy, N-16 fill-memo case, docs inventory update  

---

## 7. Scorecard vs July-12 “everything green for fund safety”

| Question | July-12 | Now |
|---|---|---|
| Can merge+settle double-spend value? | **Yes** | **No** (C-01 closed) |
| Can TEE forever-lock change notes via relock? | **Yes** | **No** (C-02 closed) |
| Can fake gateway pass client “attestation”? | **Yes** | **No** if strict DCAP + pins (A-1 closed) |
| Can TEE confiscate 100% via fees? | **Yes** | **No** (C-04 exact fee) |
| Can Hermes forge price past VAA? | **Yes** | **No** (C-05 inclusion) |
| Can degraded CVM forge JWT without dstack? | Not examined | **Yes** (N-01) |
| Can market-ask force free trade? | Not examined | **Yes under wide CB** (N-03) |
| Is Phase-2 ceremony done? | No | **Still no** |

---

## 8. How to use this document

1. Treat **§2 Closed** items as regression-tested before reopening.  
2. Track **§3 N-0x** as the active engineering backlog.  
3. Keep July inventory file as historical record; link here as the living follow-up.  
4. After each N-0x fix: add a one-line “Closed YYYY-MM-DD / PR #” under that finding.

---

## 9. File map (new residual)

| Finding | Primary paths |
|---|---|
| N-01 | `crates/nyx-tee/src/main.rs`, `api/state.rs`, `api/auth.rs` |
| N-02 | `matcher/interval.rs`, `settle/scheduler.rs`, `settle/worker.rs` |
| N-03 | `darkpool-matcher/src/algorithm.rs`, `api/orders.rs` |
| N-04 | `programs/vault/src/instructions/merge.rs` |
| N-05 | `api/orders.rs` `get_order` |
| N-06 | `matcher/book.rs`, `matcher/openings.rs`, intake |
| N-07 | `darkpool-matcher/src/algorithm.rs`, `settle/assemble.rs` |
| N-08 | `api/ws.rs`, `api/trading.rs` |
| N-09 | `matcher/interval.rs` |
| N-13 | `circuits/valid_input/circuit.circom` |
| N-14 | `circuits/templates/valid_merge.circom`, `merge.rs` |

---

*Compiled 2026-07-14. Code verified against `main` after PR #30–#37 remediations. This is a defensive self-audit of first-party code for remediation planning, not a third-party formal audit certificate.*
