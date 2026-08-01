<!-- audit-record -->
> **Audit:** Full-protocol deep dive  
> **Date:** 2026-07-20  
> **Engagement:** `audits/audit_4/`  
> **ID prefix:** `D-`  
> **Cross-audit status:** see [`residual-backlog.md`](../residual-backlog.md) — the canonical index of what is still open.

---

# Full-protocol deep dive — 2026-07-20

> **Scope.** First-party defensive review of the current Darknyx stack on
> `main` @ `3bce379` (post U-01…U-10 remediations): vault program, all six
> Groth16 circuits, `darkpool-crypto` / `darkpool-matcher`, `darknyx-tee`
> (intake, matcher, settle, oracle, auth, governance monitor), SDK + daemon
> custody boundary.
>
> **Method.** Code is ground truth. Prior inventories are treated as known:
> `audit_1/`, July-12 inventory, July-14 CS/N, July-18 U-01…U-10. This pass
> only **reopens** a residual when HEAD still exhibits the failure mode, and
> prioritizes **new** issues.
>
> **ID prefix:** `D-01…` (deep-dive 2026-07-20).

**Severity:** Critical / High / Medium / Low / Perf-Nit / Info / Process

---

## 1. Executive summary

No **new Critical** fund-theft / inflation path was found under the stated
trust model (sound circuits + honest or attested TEE for price fairness +
governance keys). The post-amount-privacy settle path still rests on
VALID_MATCH_BATCH soundness (range + conservation + exact fee + fee-note
binding + market public inputs); that architecture remains **externally
un-audited** (process gate).

What this pass adds is mostly **liveness / ops / privacy-adjacent** residual
risk under load or after governance/binary moves — plus a short list of
hygiene items. The U-09 60s governance monitor is correctly stricter than
“place/modify only”: it also pauses **matching**, which is the right fail-closed
shape for proof-bound parameters.

| Bucket | Count (new or still-open residual) |
|---|---|
| Critical (new) | 0 |
| High | 1 residual liveness (settle failure freezes inventory) |
| Medium | 4 |
| Low / Perf / Info | 5 |
| Process (unchanged mainnet gates) | 3 |

---

## 2. Explicitly **not** re-filed as new work

| Topic | Status at HEAD |
|---|---|
| CS-01…CS-03 class (aggregate fees, free mints, free inners) | Remediated (per-match fees, 8 PIs, derived inners) |
| C-01…C-05, C-08, N-03, N-04, N-05 IDOR, etc. | Closed per July-14 follow-up + later PRs |
| U-01…U-10 | Closed / Won't Fix as documented in `../audit_3/unique-findings.md` |
| Exact fee (C-04), oracle accumulator (C-05) | Present |
| Price fairness / limit / TWAP band in-circuit | **Accepted TEE-trust** (CRYPTOGRAPHY.md) |
| Dev Groth16 setup, no on-chain DCAP, single-sig admin | **Process open** N-18 / N-19 / F-04 — not re-derived |
| Throughput roadmap 1–5, `SETTLE_CONCURRENCY=1` | Deferred by design |
| U-07 full Ed25519 ix scan | Won't Fix (accepted) |

---

## 3. Severity-ranked findings (this pass)

### D-01 — Settlement rejection freezes notes until lock expiry (no rebook)

| | |
|---|---|
| **Severity** | **High** (liveness / UX; not custody theft) |
| **Category** | Matcher ↔ settle pipeline |
| **Status** | **Open residual** of July-14 **N-02** (still true at HEAD) |
| **Anchors** | `matcher/interval.rs` `reject_match` / `failed_reservations`; `settle/scheduler.rs` reject path; book `PendingSettlement` |

**Failure scenario.** Match reserved → settle fails definitively (RPC, marker
window, ALT, prove) → `SettlementFailed` emitted, order removed from book,
**not** re-queued. Input notes remain `NoteLock`ed until `expiry_slot` (up to
`MAX_LOCK_TTL_SLOTS` ≈ 30 min) before `release_lock` + re-place.

**Why still material.** Inventory is dark-pool illiquid for the lock window
after any hard settle failure. Under RPC 429 / marker expiry storms this is a
systemic availability issue.

**Recommended fix (directional).** Explicit recovery policy: (a) auto-release
path for TEE when settle Rejected and locks still held; (b) optional client
re-place after `settlement_failed` with same note once lock GC’d; (c) shorter
lock TTL for production if match→settle SLA is << 30 min.

**Lockstep:** No circuit change.

---

### D-02 — `BatchValidityMarker` settle runway (~250 slots) vs degraded RPC

| | |
|---|---|
| **Severity** | **Medium** (liveness under load) |
| **Category** | Settlement / Ops |
| **Anchors** | `MAX_BATCH_VALIDITY_MARKER_TTL_SLOTS = 300` (`state.rs`); worker `MARKER_EXPIRY_MARGIN_SLOTS = 250` (`settle/worker.rs` ~530–539); shared marker for all N≤16 Tx Ds |

**Failure scenario.** One `verify_match_batch` opens a marker usable for
~250 slots (~100 s at 400 ms). All matches in the batch must complete Tx D
inside that window (or reconcile via consumed PDAs). Concurrent sends help
under healthy RPC; under sustained 429 / leader congestion, unresolved matches
hit `settlement window expired` → D-01 freeze path.

**Recommended fix.** Metric + alert on `marker_expiry − now` at first Tx D;
consider slightly higher margin within the 300 cap for prod; or split verify
per smaller pages under backpressure (cost: more proves).

**Lockstep:** No.

---

### D-03 — Per-shard recent-root ring (64) can burn under deposit/settle flood

| | |
|---|---|
| **Severity** | **Medium** (liveness / client prove UX) |
| **Category** | Merkle / client proving |
| **Anchors** | `ROOT_HISTORY_SIZE = 64` (`state.rs:15`); `MerkleTree::push_root` / `contains_root`; `lock_note` / `withdraw` / `merge` `StaleMerkleRoot` |

**Failure scenario.** Comment assumes ~1 root/slot → ~26 s of history. Under
burst traffic a single shard can push many roots per second (deposits +
settles). A client whose VALID_INPUT / VALID_SPEND / VALID_MERGE proof takes
tens of seconds (browser snarkjs path) can see `StaleMerkleRoot` even though
the note is real. Looks like a liveness / DoS-against-slow-provers issue, not
theft.

**Recommended fix.** Raise ring size for mainnet; and/or TEE/SDK auto-reprove
on stale root; document max deposits/sec per shard vs prove latency budget.

**Lockstep:** Account layout change if ring grows (Vault/MerkleTree size).

---

### D-04 — Program upgrade not covered by governance monitor

| | |
|---|---|
| **Severity** | **Medium** (ops / binary skew) |
| **Category** | TEE-trust / Ops |
| **Anchors** | `spawn_governance_monitor` only re-reads `VaultConfig` + `MarketConfig` (`main.rs`); no BPF `ProgramData.slot` pin |

**Failure scenario.** Admin upgrades vault program (new ix layout / VK / PDA
rules). Running CVM keeps old binary until image redeploy. Config hashes may
be unchanged → **gate stays open**. Settles can fail mysteriously or, worse in
a bad upgrade, interact with unexpected on-chain semantics until operators
notice.

**Recommended fix.** At boot, pin vault `ProgramData` last-upgrade `slot` (or
programdata account hash). Monitor: any increase → `trading_gate.pause()` +
loud log “program upgraded; redeploy CVM”.

**Lockstep:** No.

---

### D-05 — Hardcoded Wormhole guardian set (oracle freeze on rotation)

| | |
|---|---|
| **Severity** | **Medium** (availability of matching) |
| **Category** | Oracle / Ops |
| **Anchors** | `oracle/vaa.rs` `MAINNET_GUARDIAN_SET_INDEX = 7`, `MAINNET_GUARDIANS` |

**Failure scenario.** Wormhole rotates guardian set. Until a TEE image ships
with the new set, every oracle refresh fails → matcher skips ticks (no TWAP)
→ **no matches**. Funds remain withdrawable on L1; dark pool halts.

**Recommended fix.** Runbook + monitoring for guardian set index; config-driven
set with attestation-bound allowlist; or multi-set accept during rotation
window.

**Lockstep:** No (unless multi-set is code-changed carefully).

---

### D-06 — `VALID_DEPOSIT` `recoveryNonce` not bit-range constrained

| | |
|---|---|
| **Severity** | **Low** (circuit hygiene) |
| **Category** | Constraints |
| **Anchors** | `circuits/valid_deposit/circuit.circom` — `Num2Bits` on mints + amount only; `recoveryNonce` fed raw into Poseidon |

**Failure scenario.** Honest SDK derives Fr-safe nonces. A malformed public
`recoveryNonce` (≥ r) can fail host/on-chain public-input encoding or create
ambiguous recovery depending on reduction path. Not a known inflation path
(amount still range-checked; owner still requires `spendingKey`).

**Recommended fix.** `Num2Bits(254)` or explicit `< r` pattern on
`recoveryNonce` (and document that deposit indices must yield Fr-safe
nonces — already true for SDK KDF).

**Lockstep:** Yes if circuit changes (VK + zkey + deposit fixture).

---

### D-07 — JWT revoke denylist is memory-only across restart

| | |
|---|---|
| **Severity** | **Low** |
| **Category** | Auth |
| **Anchors** | `auth.rs` revoke handler comments (~564–568); denylist not in `accounts.db` |

**Failure scenario.** Admin revokes a JWT; CVM restarts within remaining TTL
(default ~1h) → token works again until `exp`. Bound by short TTL; still a
gap for long-lived tokens if TTL is raised.

**Recommended fix.** Persist revoked `jti` set next to `accounts.db` (comment
already points at Phase 1b).

**Lockstep:** No.

---

### D-08 — Trading gate state not first-class on `/info`

| | |
|---|---|
| **Severity** | **Low** / Info |
| **Category** | Ops / client UX |
| **Anchors** | `TradingGate` single bit; `/info` lacks `trading_paused`; `system` only exposes `matcher_running` |

**Failure scenario.** Daemons/ops must infer pause from 503s on place + logs.
Slower response to governance drift or signer mismatch.

**Recommended fix.** Publish `trading_open: bool` + last pause reason enum on
`/info` (no secrets).

**Lockstep:** No.

---

### D-09 — `release_lock` rent sniping (anyone closes expired lock)

| | |
|---|---|
| **Severity** | **Info** |
| **Category** | Economic grief |
| **Anchors** | `release_lock.rs` — any signer, `close = rent_receiver` after expiry |

**Failure scenario.** Bot closes expired locks and takes rent. User must
re-create locks via TEE for new orders; no fund loss. Acceptable Solana pattern;
document for MM operators.

**Fix:** Optional: always close to a protocol treasury or original `locked_by`.

---

## 4. Areas reviewed and found **healthy** (high confidence)

| Area | Notes |
|---|---|
| VALID_MATCH_BATCH no-inflation gate | 64-bit range on all conservation terms; exact fee floor+ceil; fee notes bound; inactive padding; `batch_slot===i`; quote≠0 active (U-03) |
| Market public inputs | 8 PIs bound in `verify_match_batch` to VaultConfig + MarketConfig |
| Consume-once | Commitment-keyed `ConsumedNoteEntry` shared settle/withdraw/merge; U-02 lock guard |
| Relock TTL | Capped to `MAX_LOCK_TTL_SLOTS` |
| Marker 1:N lifecycle | Not closed in settle; close only post-expiry |
| Ed25519 TEE sig inspect | Full-tx scan; inlined pk/msg only; binds v10 payload incl. fill_recovery |
| VALID_DEPOSIT | Hides owner/inner; amount still public by design |
| Order GET IDOR | Account ownership map; uniform 404 |
| Self-trade | Owner_commitment + trading_key; Sybil second wallet accepted |
| Tick (U-08) | Intake + matcher partition |
| Governance monitor (U-09) | Finalized 60s; pauses place/modify/**match**; cancel+settle continue |
| Oracle | Guardian VAA + accumulator inclusion (not Hermes `parsed[]` alone) |
| JWT | HS256 via `Validation::default()` → algorithms HS256; Argon2 gated |
| Settlement IDs | `derive_settlement_id` binds boot session; output safety not uniqueness-dependent |
| Daemon custody | Spending key stays local in place/build path |

---

## 5. Process gates still blocking “mainnet ready” (unchanged)

1. **Real Phase-2 MPC** for all circuit zkeys (N-18).  
2. **External circuit audit** (F-04 / C-07).  
3. **Multisig admin + attestation-gated `set_tee_pubkey` ops** (N-19); optional future on-chain quote verify.

---

## 6. Suggested remediation order

1. **D-01** — product decision on settle-fail recovery / shorter lock TTL.  
2. **D-02 / D-03** — measure under load; tune marker margin + root ring before public volume.  
3. **D-04 / D-05** — program-slot pin + guardian rotation runbook (cheap ops wins).  
4. **D-06…D-08** — hygiene as capacity allows.  
5. Keep ceremony + external audit as hard ship gates.

---

## 7. What this pass still could not rule out

1. Full R1CS underconstraint / circomspect / external auditor findings.  
2. Live Phala TDX quote + KMS + compose allowlist ceremony (static code only).  
3. Adversarial ALT pool races at `SETTLE_CONCURRENCY>1` (still pinned to 1).  
4. Supply-chain (`cargo audit` / `npm audit`) not run.  
5. Browser dcap-qvl bundling / portal product surface (out of scope).

---

*Defensive first-party review only — not a third-party formal audit certificate.*
