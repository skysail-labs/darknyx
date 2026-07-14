# audit_2 — cryptography/systems review, validated (2026-07-14)

> **What this is.** An independent re-verification of
> [`docs/audit-2026-07-14-cryptography-systems-review.md`](../docs/audit-2026-07-14-cryptography-systems-review.md)
> against the code on `main@24fbf18`. Every finding (CS-01…CS-14, P-01…P-04)
> was checked at its anchor — code is ground truth, not the report's prose.
>
> **Verdict: ALL 18 findings are CONFIRMED real.** One refinement (CS-09) noted.
> This is a high-signal audit — the findings are missing-invariant / cross-stage
> gaps, precisely the class that the passing Rust↔TS parity suite cannot catch.
> **CS-01 is a genuine Critical fund-safety hole** that holds even under a sound
> Groth16 setup + collision-resistant hashes.

**These are pre-mainnet blockers on devnet-stage code — not evidence of a live
exploit.** But CS-01/02/03 break the core promise that the ZK circuits enforce
fund safety even against a compromised TEE, so they gate any real-value deploy.

---

## 1. Immediate interim mitigation (before the circuit redesign lands)

Set the protocol fee rate to **zero** on-chain and in the CVM env
(`VaultConfig.fee_rate_bps = 0` via `set_protocol_config`; `NYX_TEE_FEE_RATE_BPS=0`).
The circuit's exact-fee constraint then forces every slot fee to 0 and the
`IsZero` gate zeroes the fee notes — which **removes the CS-01 phantom-fee mint
and CS-08 fee-nullifier reuse entirely**. This is the audit's #1 recommendation
and it is correct.

**Caveat — this does NOT cover CS-02 or CS-03.** A malicious TEE can still
(CS-02) settle a victim into a different asset pair and (CS-03) choose
unrecoverable output `inner_hash`es that permanently destroy user funds, both
independent of fees. Those need the circuit fix. So fee=0 buys time on the
solvency drain but is not "safe to run with real value."

---

## 2. Findings — verified

### CS-01 — Aggregate fee notes backed by phantom, never-settled slots · **Critical** · CONFIRMED
The crux, verified end-to-end:
- **No per-slot membership in the circuit.** `match_batch.circom`'s `merkle_root`
  is the **batch's own internal root** over its 16 leaves (`MerkleRoot(N)`,
  DOMAIN_BATCH_ROOT=22) — not a proof that each slot's input notes exist in the
  vault tree. Vault membership is proven only at `lock_note` (VALID_INPUT) time.
- **Fees aggregate across all 16 slots into slot 0.** `match_batch.circom:465-476`
  sums `buyer_fee_amt[i]`/`seller_fee_amt[i]` over **all** slots; `:490-512` binds
  the totals into slot 0's two fee notes using slot 0's mints + protocol owner.
- **On-chain, slot 0's settle appends them with no all-slots requirement.**
  `tee_forced_settle_batched.rs:457` appends the fee note whenever slot 0's
  payload carries a non-zero commitment; it consumes only slot 0's two inputs.
  `verify_match_batch.rs` verifies the proof + creates one root-marker tracking
  **no** active slots.
- **Exploit (malicious TEE):** slot 0 = one real locked pair; slots 1..15 =
  fabricated openings that conserve locally with fees; prove; settle **only**
  slot 0. The aggregate fee note (fees of all 16 slots) mints to the protocol
  owner without the phantom inputs ever being consumed → over-mint → the shared
  SPL vault becomes insolvent when those fees are withdrawn.
- **Distinct from N-12** (which was liveness on early marker close): CS-01 is a
  **solvency** break that occurs on a *normal* slot-0 settle, before any close.
- **Fix:** per-match fee notes appended in the same Tx D that consumes that
  slot's inputs; or an on-chain finalization that mints the aggregate only after
  every active slot has consumed its inputs (with an on-chain active bitmap).
  Circuit-lockstep.

### CS-02 — Batch not bound to one market/mint pair · **High** · CONFIRMED
`match_batch.circom:424-427` gives each slot **independent** mint halves with
**no** cross-slot equality; the fee notes (`:490-512`) denominate in slot 0's
mints while summing fees from slots that may use *other* mints. Even if every
slot settles, fee liabilities move from slot-1 mints onto slot-0 mints in raw
units → a later slot-0 fee withdrawal drains a mint whose obligations were never
reduced. Independently, a malicious TEE can settle a victim into a different
asset pair. **Fix:** constrain `base_mint[i]==base_mint[0]`,
`quote_mint[i]==quote_mint[0]` (incl. pads); make the market mints public inputs
bound to on-chain `VaultConfig`/market state. Circuit-lockstep (with CS-01).

### CS-03 — Output `inner_hash` values are free witnesses · **High** · CONFIRMED
`match_batch.circom:118-123` declares `c_inner..f_inner` as plain `signal input`;
`:164-197` uses them **only** inside the output-note commitment hashes with no
derivation constraint, and `match_id` is **entirely absent** from the circuit. A
malicious TEE picks arbitrary Fr-safe output inners → the user cannot derive the
nullifier → outputs are permanently unspendable while inputs are permanently
consumed (fund destruction; detectable post-hoc via fill-memo mismatch, not
preventable). **Fix:** derive each output inner in-circuit via domain-separated
Poseidon from the consumed input inner + role + a batch-unique value; constrain
the continuation-anchor chain. Circuit-lockstep (with CS-01/02).

### CS-04 — `match_id` restarts at zero across reboots · **High** · CONFIRMED
`interval.rs:60,101` `next_match_id: 0`; `MatcherState::new()` is fresh each boot
(`main.rs`); `persistence/snapshot.rs` is a stub (no restore). `change_note::
derive_inner(match_id, role)` → output inner depends only on the low `u64`
match_id. Same user, same role, recurring match_id across a restart → identical
amount-independent nullifier → spending one bricks the other. **Fix:** a
globally-unique settlement id (rollback-resistant boot epoch + monotonic
counter) consumed in all inner derivations; anti-rollback story for the durable
counter. (CS-03's input-inner construction removes the global-counter dependence
for user outputs.)

### CS-05 — A fixed wallet signature is the entire master secret · **High** · CONFIRMED
`key-generators.ts` `seedFromWalletSignature = SHA-512(signature)[:64]` over the
**fixed public** message `MASTER_SEED_MESSAGE = "NYX_DARKPOOL_SEED_V1"`, exposed
as a normal no-backup mode. Ed25519 is deterministic, so **any dapp/phishing page
that gets the wallet to sign that string derives the same seed → spending key →
drains the user's notes**, with no Nyx origin/session secret involved. **Fix:**
don't make an exportable message signature the spend authority — random seed
wrapped under a wallet-backed key, or a wallet PRF; origin-scoped messages are
only a transitional mitigation; needs a migration plan for existing accounts.
Not a circuit change.

### CS-06 — Matcher and prover derive fee notes from different slots · **High** · CONFIRMED
`scheduler.rs:332,338` **re-samples** `driver.current_slot` as `fee_slot` instead
of using the matcher's `output.batch_slot`; the matcher already built the fee
commitment from *its* `now_slot` (`lib.rs:217-239`, `algorithm.rs:610-637`). If
the slot ticks between match production and `drive_batch`, the fee commitment and
the witness `fee_inner` disagree → the circuit's fee binding fails → the **whole
batch fails to prove**. (Adjacent to the C-08 settler fix I landed, but not the
same bug — that fixed the *leaf* `batch_slot`; this is the *fee* slot re-sample.)
Unit tests use one slot and miss the race. **Fix:** carry one explicit
fee/batch identifier in `RunBatchOutput` and use it for both commitment and
witness; do not re-sample time at the consumer. Rust-only (unless folded into the
CS-01 fee redesign).

### CS-07 — `lock_note` publicly discloses the note amount · **Medium** · CONFIRMED
`valid_input/circuit.circom:115` makes `amount` a **public** input; `lock_note.rs`
carries it in ix data + verifier inputs and **emits it in `NoteLocked`** (:156),
even though `NoteLock` no longer stores it. Locking a settlement-created trade
note republishes its previously-private amount, linked to commitment/mint/order.
Overlaps N-13 (which is the missing range check on the same signal) — fix
together: make `amount` a private witness **and** add `Num2Bits(64)`, dropping it
from the ix/event. Circuit-lockstep.

### CS-08 — Multiple fee batches in one tick reuse fee nullifiers · **Medium** · CONFIRMED
`interval.rs:462` samples `now_slot` once per tick and `:508-536` passes the same
value to every page; the matcher derives both fee inners from `(slot, role)`
only. Two pages in one tick → identical fee nullifiers → withdrawing one bricks
the other (equal totals also collide commitments). Same root cause family as
CS-04/CS-06/CS-12. **Fix:** unique per-batch/page identifier, shared with the
CS-06 fix.

### CS-09 — Settlement accepts expired input locks · **Medium** · CONFIRMED (refined)
`tee_forced_settle_batched.rs:380` **does** check the *marker* expiry
(`clock.slot < expiry_slot`), but there is **no** check of the individual
`NoteLock.expiry_slot`; `release_lock.rs:21-24` treats a lock as releasable at
`clock.slot >= expiry_slot`. So an expired lock can still be settled (marker
still valid, no one raced `release_lock`), and the E boundary is inconsistent
(release valid at E; settle also valid at E). The report's core claim holds; the
refinement is that the marker expiry *is* enforced, the per-lock expiry is not.
**Fix:** cache both lock expiries in the existing loads and require
`clock.slot < lock_{a,b}.expiry_slot` before mutation; add boundary litesvm
tests. No wire/circuit change.

### CS-10 — Recovery X25519 key unsigned + low-order points accepted · **Medium** · CONFIRMED
`fill_encryption.rs:81,109` calls `x25519_dalek diffie_hellman` with **no**
`was_contributory()` / low-order rejection; `viewingPubkey` is **absent** from
`canonical.ts` (unsigned). A request-mutating gateway can swap the viewing key
(redirect recovery) while the trading signature stays valid; an all-zero
recipient key yields an all-zero shared secret (report-confirmed empirically) →
the on-chain change amount becomes publicly decryptable. **Fix:** add
`viewing_pubkey` to a versioned canonical body; reject non-contributory X25519;
KATs for zero/low-order. No circuit change.

### CS-11 — `arrival_nonce` is signed but never enforced · **Medium** · CONFIRMED
`orders.rs:73,443` only stores/copies `arrival_nonce`; a repo-wide search finds
**no** per-trading-key high-water mark — replay defense rests on the bounded,
volatile order-ID idempotency map. After a restart or ~16k-order eviction, a
captured signed (later-canceled) request can be re-booked without a fresh
signature. **Fix:** persist a per-trading-key nonce high-water mark (or a durable
used-order-ID set) with defined rollback semantics. TEE state only.

### CS-12 — Daemon merge-output counter resets to zero · **Medium** · CONFIRMED
`merge-runner.ts:69` `mergeIndex = startMergeIndex ?? 0`, an in-memory counter
(`:75,104`); `store.ts` does **not** persist it. Restart → index 0 reused → same
output inner → same nullifier → one merged note bricks the other. Client-side
sibling of CS-04. **Fix:** persist/reserve the index transactionally before
submit, or derive the output inner from the consumed commitments. Daemon store +
SDK derivation.

### CS-13 — Strict daemon attestation fails open on on-chain key-check errors · **Medium** · CONFIRMED
`daemon.ts crossCheckOnchainTeePubkeys` `console.warn(...); return;` on an RPC
error or a missing `VaultConfig` — the authoritative key-set comparison is
**skipped** (documented as intentional). A genuinely-attested but stale CVM
(signer rotated out) + an unavailable RPC ⇒ the daemon sends private orders to an
enclave outside the rotation window. **Fix:** fail closed in strict mode on
RPC/missing config; or cache the last finalized key set with a short, binding
expiry; keep a separate dev-only fail-open switch. Daemon only.

### CS-14 — The function named KMAC256 is not NIST KMAC256 · **Low** · CONFIRMED
`keys.rs:53,145-197` feeds SP 800-185 encodings into **raw `Shake256`**, not
cSHAKE/KMAC; `key-generators.ts` mirrors it; parity tests pass because both ports
share the non-standard function (no NIST KAT). Report-confirmed the output
differs from standards KMAC256. No known attack (still SHAKE-based +
domain-separated) — the issue is misstated assurance + interop. **Fix:** rename
it a Nyx-specific SHAKE KDF and pin KATs, **or** migrate to real cSHAKE/KMAC with
a versioned wallet migration (viewing/blinding/inner derivations are versioned
state — don't silently swap).

### Performance — P-01…P-04 · all CONFIRMED
- **P-01** (marker writable in Tx D): `tee_forced_settle_batched.rs` leaves the
  marker OPEN but declares it `mut`; every batch Tx D takes a **shared write
  lock** on the one marker → serializes the otherwise K-shard-parallel Tx Ds
  (worker.rs even comments, wrongly, that concurrent Tx Ds share no writable
  account). Higher-value than "nit" — it undercuts the sharding design. **Fix:**
  mark the marker read-only in the Anchor accounts + both builders; add a
  "zero shared writable keys across a batch's Tx Ds" test.
- **P-02** (`leaf.rs:136-150` rebuilds the full 16-leaf tree per requested path,
  called once per match → 240 hashes vs 15): build levels once, extract all paths.
- **P-03** (book cloned + re-sorted + O(P×N) clearing scan per page, `book.rs:
  210-233` / `interval.rs:508-545` / `algorithm.rs:184-218,693-704`): compute
  demand/supply from price-level prefix sums; reuse ordered levels across pages.
- **P-04** (`submit.rs` polls `getSignatureStatuses([one_sig])` per Tx D despite
  a batched multi-sig helper existing): poll all pending signatures in one
  request → less Helius 429 pressure. Distinct from the deferred
  `SETTLE_CONCURRENCY` bump.

---

## 3. Relationships + how to batch the fixes

The findings cluster — fixing by cluster amortizes the expensive circuit/CVM
validation:

| Cluster | Findings | Nature | Surface |
|---|---|---|---|
| **Circuit soundness** | **CS-01**, CS-02, CS-03 (+ CS-07) | missing in-circuit binding (membership/mint/inner/amount-privacy) | one **circuit-lockstep** sweep (regen zkey/VK + N=16 fixture + new image + one CVM settle) |
| **Non-unique slot/counter ids** | CS-04, CS-06, CS-08, CS-12 | slot/counter-derived nullifiers collide across boots/pages | matcher + daemon; a shared globally-unique id design |
| **Client custody** | CS-05, CS-12, CS-10 | seed exportability, counter, unsigned viewing key | SDK/daemon; versioned key/canonical migration |
| **On-chain hygiene** | CS-09, P-01 | lock-expiry check, read-only marker | `programs/vault`; one deploy-devnet |
| **Daemon/ops** | CS-13, CS-11 | fail-open cross-check, nonce not enforced | daemon/TEE state; no circuit |
| **Perf** | P-02, P-03, P-04 | redundant tree/book work, per-tx polls | TEE-only; parity tests |
| **Naming/assurance** | CS-14 | KMAC misnomer | KDF rename + KATs (or migration) |

**Suggested order (agrees with the report):**
1. **Now:** set fee rate to 0 on-chain + CVM (kills CS-01 mint + CS-08) — interim.
2. **CS-01 + CS-02 + CS-03 (+ CS-07)** as ONE circuit version → regenerate all
   artifacts + the N=16 fixture in a single §5 lockstep cycle + one CVM run.
3. **CS-06** immediately for honest-path liveness (Rust-only), then replace
   slot-derived ids under **CS-04/CS-08/CS-12** before re-enabling fees.
4. **CS-05** — remove/gate the wallet-signature seed mode before any real value.
5. Narrow non-circuit fixes **CS-09, CS-10, CS-11, CS-13, P-01** in parallel.
6. **P-02/P-03/P-04** as throughput polish.

---

## 4. Stale/contradictory docs (verified, fix alongside remediation — not security bugs)

All six the report lists check out and should be corrected with the fixes:
`CRYPTOGRAPHY.md:451-453` (conservation-from-lock-amounts — stale after
NoteLock.amount removal), `:646` (price-band claim vs the accepted TEE-trusted
decision + actual circuit), `:493-507` (fee_rate_bps called vestigial though the
verifier binds it as a public input); `docs/ARCHITECTURE.md:3-7` (order amount
never on-chain — ignores public LockNote amount, see CS-07);
`tee_forced_settle_batched.rs:307-319` (leaf-needs-lock-mints comment vs
`compute_match_leaf` hashing only commitments + batch_slot);
`match_result.rs` / `fee.rs` headers still referencing the deleted
`matching_engine` / on-chain `submit_order`.

---

## 5. Relation to the other 2026-07-14 backlog

Companion to [`2026-07-14-validated-residual-backlog.md`](./2026-07-14-validated-residual-backlog.md)
(the N-01…N-19 sweep). Overlaps/complements:
- **CS-07 ⊃ N-13** — same VALID_INPUT `amount` signal (privacy + range check).
- **CS-01 ≠ N-14** — N-14 was VALID_MERGE all-dummy tree-grief; CS-01 is
  VALID_MATCH_BATCH phantom-slot fee inflation (a solvency drain). Distinct.
- **CS-04/CS-12 ⊃ the persistence/rollback theme** the N-sweep flagged (N-01
  degraded boot, snapshot stub).
- The circuit sweep here (CS-01/02/03/07) should absorb N-13/N-14 so the
  ceremony/artifact churn is paid **once**.

---

*Compiled 2026-07-14 by re-verifying `docs/audit-2026-07-14-cryptography-systems-review.md`
against `main@24fbf18`. Defensive self-audit for remediation planning — not a
third-party formal audit certificate. Append `Closed YYYY-MM-DD / PR #NN` as each
lands.*
