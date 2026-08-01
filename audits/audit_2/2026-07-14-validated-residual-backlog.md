# audit_2 — validated residual backlog (2026-07-14)

> **What this is.** An independent re-verification of the follow-up sweep
> [`audits/audit_3/followup-sweep.md`](../audit_3/followup-sweep.md)
> against the actual code on `main` (tip `24fbf18`, after PR #30–#37). Every new
> finding **N-01…N-19** and every "Closed" remediation claim was checked at its
> code anchor — code is ground truth, not the sweep's prose. This file is the
> **actionable backlog for the next remediation run**: only findings that
> survived verification are listed, each with the evidence that confirms it, a
> fix direction, and a **surface/effort class** so the run can be planned
> (TEE-only vs on-chain vs circuit-lockstep vs process).
>
> **Verdict:** all 19 new findings are **CONFIRMED genuine**. The sweep's
> remediation validations (§2 "Closed": C-01/C-02/C-04/C-05/C-08, DCAP cluster)
> are **accurate** — independently re-confirmed below.

---

## 0. How to read this

- **VERDICT** — `CONFIRMED` (code matches the finding) / `CONFIRMED — adjusted`
  (genuine, but a detail is refined) / `REFUTED` (none this pass).
- **Surface/effort** — what a fix touches, which sets the validation cost:
  - `TEE-only` — `crates/nyx-tee` (+ maybe `packages/*`); offline-gated, no CVM
    circuit revalidation (though pipeline changes still warrant a live smoke).
  - `matcher` — `crates/darkpool-matcher`; needs the TS↔Rust parity tests.
  - `on-chain` — `programs/vault`; needs `build-sbf` + `deploy-devnet` (+ a
    re-foundation if a `VaultConfig`/account layout changes).
  - `circuit-lockstep` — a circom change → the full §5 chain (regen zkey/VK +
    new CVM image + tree reset + live settle). The most expensive.
  - `process` — no code; ceremony / ops discipline.
- **Closed date/PR** — append `Closed YYYY-MM-DD / PR #NN` under a finding when
  it lands (per the sweep's §8 convention).

---

## 1. Remediation validation (landed changes) — re-confirmed

Independently verified against code; the sweep's "Closed" calls hold.

| Finding | Verified at | Result |
|---|---|---|
| **C-01** merge↔settle double-spend | `valid_merge.circom:46-47,108` exposes `inputCommitments[i] = isActive[i]·computedNote[i]` as public outputs; `merge.rs` inits commitment-keyed `ConsumedNoteEntry` (same guard as withdraw/settle) | **Closed** ✓ |
| **C-02** unbounded relock TTL | `tee_forced_settle.rs:158-160` `require!(expiry > clock.slot)` + `require!(expiry ≤ clock.slot + MAX_LOCK_TTL_SLOTS)` | **Closed** ✓ |
| **C-04** fee confiscation | `match_batch.circom:266-272` FLOOR `GreaterThan(96)` **and** CEIL `LessEqThan(96)` ⇒ fee `== ⌊notional·rate/10000⌋` | **Closed** ✓ |
| **C-05 / A-2** oracle JSON price | `oracle/accumulator.rs` + `oracle/sync.rs`: VAA guardian verify → root from verified payload → Keccak160 Merkle inclusion → price from the binary message (PR #35; live-CVM confirmed image `-47/-48`, 0 refresh failures) | **Closed** ✓ |
| **C-08** batch_slot | `match_batch.circom:442` `batch_slot[i] === i`; `tee_forced_settle_batched.rs` `payload.batch_slot == match_index`; settler uses the batch index (PR #36 `3df4003`, live-CVM confirmed: batch settled, no witness abort) | **Closed** ✓ |
| **C-03 / A-1 + DCAP cluster** | `packages/sdk/src/tee/{dcap,verify-core,attestation}.ts`; daemon strict DCAP; `/info.tee_pubkeys` + `report_data` full-set bind + on-chain cross-check (PR #30) | **Closed** ✓ (client) |

**Still deferred by design (not regressions):** on-chain DCAP/vault quote
verification; `SETTLE_CONCURRENCY` pinned to 1.

---

## 2. Validated residual backlog (N-01 … N-19)

All CONFIRMED. Grouped by the sweep's priority; my verification evidence and
surface class added.

### P0 — before any long-lived public CVM

#### N-01 — Degraded boot serves the live matcher/orders API with a test JWT secret · **High** · TEE-only
**VERDICT: CONFIRMED.** `main.rs:176` — a failed `probe_dstack()` falls to
`ApiState::for_tests()`, which sets `jwt_secret = TEST_JWT_SECRET` (public
constant) + `accounts = test_registry()` (test admin) + `matcher = Some(..)`
(`api/state.rs:497-517`). Critically, the matcher/orders attach at
`main.rs:394` (`with_matcher_runtime`) is **NOT gated** on a real boot — only
the Merkle-sync (`main.rs:408`) and the on-chain config read (`:195`) are. So
degraded boot exposes the full auth'd orders/WS surface under a known HMAC key.
Settle is disabled (no signer) ⇒ not a vault drain, but full dark-book API
compromise (forge HS256 JWTs, place/cancel, and read any order via N-05).
**Fix:** on dstack failure in production, exit non-zero **or** serve only
`/health` with no matcher/auth; gate `for_tests()` behind an explicit
`NYX_TEE_ALLOW_TEST_AUTH=1` that the prod compose must never set.

#### N-03 — Zero `price_limit` asks are clearing candidates ⇒ P\* = 0 · **High** · matcher
**VERDICT: CONFIRMED.** `algorithm.rs:195-196` pushes **every** ask
`price_limit` (incl. 0) into the candidate set; `:203-217` scans candidates
ascending with a strict `>` on matched volume, so on a volume tie the **lowest**
candidate wins. `orders.rs:474` rejects `price_limit == 0` **only for bids**
(comment: asks use 0 as a market sell). Scenario bid@150 + ask@0: at p=0
demand = all bids, supply = zero-asks, matched ties p=150 → P\*=0 kept →
`quote = base·0 = 0` (free fill), gated only by the circuit breaker.
**Fix:** exclude unconstrained market limits from the **candidate** set (use
them only for eligibility); or require a positive ask floor. Unit test:
bid@150 + ask@0 clears at a positive book price or rejects.

#### N-04 — `merge` does not refuse a live `NoteLock` (C-01 residual half) · **High** liveness · on-chain
**VERDICT: CONFIRMED.** `merge.rs` has **no** `NoteLock` check; `withdraw.rs:
130-143` reads `note_lock_slot` and requires `release_lock` first. So a note
locked for an order can be merged → `ConsumedNoteEntry` created → the pinned
settle fails forever on consume-init; the counterparty stays locked to TTL. Not
a double-spend after C-01, but the inventory's "block merge under NoteLock" is
open. **Fix:** add the same empty-lock check as `withdraw` for each non-zero
input commitment (a `note_lock` account per active input, `require!` uninit).

#### N-05 — `GET /orders/{id}` IDOR leaks price/size · **Medium** privacy · TEE-only
**VERDICT: CONFIRMED.** `orders.rs get_order` binds `Extension(_auth)` — the
`_` prefix means it is **never read**; the handler returns any order by id
(`amount`, `price_limit`, `filled_quantity`, side…) to any authenticated bearer.
Defeats dark-order privacy. **Fix:** require `book order owner == auth.account_id`;
return 404 (not 403) on mismatch so it isn't an existence oracle.

#### N-06 — One `note_commitment` can back multiple live orders · **Medium** integrity · TEE-only
**VERDICT: CONFIRMED.** `openings.rs:255-256` `insert(commitment, record)` is a
plain `HashMap::insert` that silently **overwrites** by commitment; intake
(`orders.rs` ~533-552) shows no "commitment already has a live opening" guard,
and the book is keyed by `order_id` (`book.rs:68`). Two orders can share one
collateral note → matcher schedules two spends; first settle wins, second fails
after the book advanced (amplifies N-02). **Fix:** reject intake if the
commitment already has a live opening/order.

### P1 — production darkpool quality

#### N-02 — Book + fill memos commit before settle finality; failures don't restore · **High** liveness · TEE-only
**VERDICT: CONFIRMED.** `interval.rs:572-595` mutates the book
(`apply_updates`, anchor consumption, opening rotation) and **broadcasts fills
to `/ws/orders`** (`:582`) under the tick's write lock, *then* forwards to the
settle scheduler (`:611-614`). Settle failures downstream (RPC/ALT/prove) leave
the job terminal-`Failed` with **no book restore**; notes stay locked to TTL and
clients may treat provisional fills as final. **Fix (directional):** pending-
settle state + redrive; or only mutate the book after settle `Done`; mark fill
memos provisional until chain-confirm; per-match reconciliation for partial
batches. (Bigger design change — sequence after the P0 correctness fixes.)

#### N-07 — Matcher builds change/trade commitments with `user_commitment`, settler with `owner_commitment` · **Medium** SSoT · matcher
**VERDICT: CONFIRMED.** `algorithm.rs:409,421` build `note_e/note_f`
commitments from `bids[bi].user_commitment` / `asks[ai].user_commitment`;
`settle/assemble.rs` rebuilds them from `*_opening.owner_commitment`. When
`user_commitment ≠ owner_commitment` (the normal production case) the raw
`MatchPair.note_e/f` are wrong — the TEE assembler papers over it, but any pure
`run_batch` consumer gets bad commitments. **Fix:** use `owner_commitment` in
the matcher's change/trade commitment construction; add a parity test with
distinct owner/user values.

#### N-08 — JWT in WebSocket query string · **Medium** token leakage · TEE-only
**VERDICT: CONFIRMED.** `trading.rs:49-51,131-141` (`GET /ws/trading?token=<jwt>`)
accepts the bearer in the query string → access-log / referrer exposure.
**Fix:** prefer a WS subprotocol or a short-lived one-time ticket; avoid logging.

#### N-09 — Info logs emit `clearing_price` · **Medium** privacy/ops · TEE-only
**VERDICT: CONFIRMED.** `interval.rs:603-608` logs `clearing_price` at `info`.
**Fix:** drop to `debug`/`trace`, or log only counts at `info`.

#### N-13 — `VALID_INPUT` missing `Num2Bits(64)` on `amount` · **Medium** DiD · circuit-lockstep
**VERDICT: CONFIRMED.** `valid_input/circuit.circom` declares `signal input
amount` (:75) with **no** range check; `valid_spend/circuit.circom:53-58`
explicitly range-checks with `Num2Bits(64)` to stop field-wrap. On-chain the
public input is u64 today (no known exploit), but it's a parity/hygiene gap.
**Fix:** add the range check; regen zkey/VK in lockstep (§5) — batch with N-14.

#### N-14 — `VALID_MERGE` allows all-dummy / zero-output merges · **Medium** tree grief · circuit-lockstep
**VERDICT: CONFIRMED.** `valid_merge.circom` has no "≥1 active" or
"outputAmount > 0" constraint: all-`isActive=0` yields sum 0 → a 0-amount output
note whose commitment still appends a leaf on-chain → cheap tree-capacity spam.
**Fix:** `require ≥1 active` and `outputAmount > 0` (circuit + on-chain check);
regen in lockstep — batch with N-13 into one circuit sweep.

#### N-15 — C-09 `verifyRoot` optional, not default-on in the daemon prove path · **Low–Medium** · TEE-only (SDK/daemon)
**VERDICT: CONFIRMED.** No `verifyRoot` / `onchainRootVerifier` reference exists
under `packages/daemon/src` — the daemon calls `proveAndBuildOrder` /
`fetchInclusionProof` (build-place-request.ts, settlement-tracker.ts) without
the C-09 hook (PR #33 shipped it opt-in). Fund safety is still gated by on-chain
`contains_root` at lock/withdraw, so the residual is wasted proves / root
confusion. **Fix:** wire `onchainRootVerifier` on by default in the daemon prove
path.

### P2 — mainnet process gates

#### N-18 — Trusted setup is a single dev beacon · **Critical for mainnet** (process)
**VERDICT: CONFIRMED.** `build-circuits.sh:5` "snarkjs zkey contribute (single
contribution, deterministic for dev)". A real multi-party Phase-2 MPC is
required before mainnet. **Fix:** run the ceremony; document contributors +
transcript.

#### N-19 — Single-sig admin / no on-chain attestation gate · **High ops for mainnet** (process)
**VERDICT: CONFIRMED.** `set_tee_pubkey.rs` is `vault_config.admin`-only
(single signer). Client DCAP does not replace multisig rotation discipline.
**Fix:** admin = a Squads multisig operationally; attestation-gated rotation
runbook (`docs/governance.md`). Note the on-chain program already *permits* a
multisig PDA as admin — this is an ops/config gate, not a code change.

#### N-10 — `initialize` accepts zero `tee_pubkey` / `root_key` · **Medium** ops · on-chain
**VERDICT: CONFIRMED.** `initialize.rs:91-94` sets `tee_pubkeys[0] = tee_pubkey`
and `root_key = root_key` with **no** non-default guard (contrast F-09 /
`set_tee_pubkey.rs:54` which rejects `Pubkey::default()`). A zero root can never
rotate (no private key for the default pubkey). **Fix:** reject default
`tee_pubkey`/`root_key` at init.

#### N-11 — `set_tee_pubkey` doesn't enforce `keys.len() == num_trees` · **Medium** ops footgun · on-chain
**VERDICT: CONFIRMED.** `set_tee_pubkey.rs:46` checks `!keys.is_empty() &&
keys.len() ≤ MAX_TEE_KEYS` and rejects zero/dup keys (`:54-55`), but never
checks against `cfg.num_trees`. A key-count/shard mismatch breaks round-robin
sends + funding (not theft). **Fix:** `require!(keys.len() == cfg.num_trees)`.

#### N-17 — Dead nullifiers still in the settle payload (P-01) · **Perf-Nit** · TEE-only + on-chain
**VERDICT: CONFIRMED.** `settle/payload.rs:65-66` still carries
`nullifier_a/b`, and `:113-114` folds them into the canonical (signed) hash.
Post-C-01 the consume guard is commitment-keyed, so these are vestigial in the
settle path. **Fix (only if Tx D is tight):** drop the fields + bump the domain
tag; this is a cross-language canonical-hash change (§7) — mirror in TS
`serializePayload` + recompute the fixed-vector, and confirm they're truly
unread on-chain first.

### P3 — polish

#### N-12 — Marker `payer` (the TEE) can close before all N settles · **Medium** TEE self-DoS · on-chain
**VERDICT: CONFIRMED (as intentionally-designed but risky).**
`close_batch_validity_marker.rs:11-24,33-35`: the recorded `payer` may close
**anytime**; any other signer only past `expiry_slot` (good). Since the TEE is
the payer, a compromised/buggy TEE can close a marker early and brick the
remaining matches in the batch. **Fix:** consider restricting the payer's
close-anytime path (e.g., only after the batch's settles are accounted), or
accept + document as a TEE-trust assumption.

#### N-16 — Fill-memo commitment compare is case-sensitive · **Low** · TEE-only (SDK)
**VERDICT: CONFIRMED.** `fill-memo.ts:146` compares the commitment with a string
`!==` (`recomputedHex !== memo.change_note_commitment`), while the inner-hash
check (`:128`) uses `Buffer.compare`. Mixed-case hex would false-mismatch.
**Fix:** compare lowercased hex or raw bytes (mirror the inner-hash path).

---

## 3. Suggested plan for the next run

Grouped by **surface** (which sets validation cost), then priority. Circuit and
on-chain changes should be **batched** to amortize the expensive validation
(one deploy-devnet + one circuit sweep + one billable CVM run).

| Batch | Findings | Surface | Validation cost |
|---|---|---|---|
| **A. TEE correctness (P0)** | N-01, N-05, N-06 | TEE-only | offline gate; live smoke of degraded-boot + orders authz |
| **B. Matcher (P0/P1)** | N-03, N-07 | matcher | TS↔Rust parity tests + matcher unit tests (bid@150+ask@0; distinct owner/user) |
| **C. On-chain vault** | N-04, N-10, N-11, N-12 | on-chain | `build-sbf` + `deploy-devnet`; N-10 touches `initialize` → re-foundation |
| **D. Circuit sweep** | N-13, N-14 | circuit-lockstep | §5 regen + new image + tree reset + **one** live `cvm-settle-e2e` |
| **E. Pipeline (P1)** | N-02 | TEE-only (design) | bigger; settle/book recovery model — do after A–C land |
| **F. Hygiene** | N-08, N-09, N-15, N-16 | TEE-only / SDK | offline gate only |
| **G. Process (mainnet)** | N-18, N-19 | process | ceremony + multisig ops — out of the code run |

**Recommended order:** A → B → C → D (one CVM run validates C + D together via
`cvm-settle-e2e` + `devnet-merge`) → E → F. G runs on the mainnet track.

**Note on N-02 vs N-06:** N-06 (reject duplicate collateral) is a cheap partial
mitigation of the N-02 blast radius — land it in batch A even though the full
N-02 recovery model is P1.

---

## 4. What was NOT re-verified this pass (carry forward)

Mirrors the sweep's §5; not blockers for the backlog above:

- Full `settle/worker.rs` ALT-pool race matrix under `SETTLE_CONCURRENCY > 1`
  (still pinned to 1).
- Merkle-mirror reorg/desync adversarial model.
- Dependency CVE scan (`cargo audit` / `npm audit`) — recommend a CI gate.
- Formal ZK under-constraint tooling (circomspect / external auditor) — F-04.
- Browser bundling of `@phala/dcap-qvl` in the production portal.
- Live Phala DCAP e2e (`RUN_CVM_ATTEST` / nightly).

---

*Compiled 2026-07-14 by re-verifying `audits/audit_3/followup-sweep.md`
against `main@24fbf18`. This is a defensive self-audit of first-party code for
remediation planning — not a third-party formal audit certificate. Append
`Closed YYYY-MM-DD / PR #NN` under each finding as it lands.*
