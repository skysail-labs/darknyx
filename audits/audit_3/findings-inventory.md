<!-- audit-record -->
> **Audit:** Findings inventory  
> **Date:** 2026-07-12  
> **Engagement:** `audits/audit_3/`  
> **ID prefix:** `C-`  
> **Cross-audit status:** see [`residual-backlog.md`](../residual-backlog.md) — the canonical index of what is still open.

---

# Audit findings inventory + next-sweep scope

**Purpose:** Single checklist of everything found in the 2026-07-12 pre-mainnet self-audit + DCAP deep-dive, and what was **not** reviewed so the next pass has a backlog.

**Related docs in repo:**
- **[`audits/audit_3/followup-sweep.md`](followup-sweep.md)** — **follow-up:** re-verified remediations + residual-surface audit (use this as the living backlog after this file)
- `docs/attestation-dcap-enforcement-plan.md` — DCAP implementation plan (largely shipped)
- `audit_1/REPORT.md` — prior vault audit (F-01..F-10)
- `audit_2/READINESS.md` — readiness pass (A-1, A-2)

**Severity key:** Critical / High / Medium / Low / Perf-Nit / Info  
**Status key:** Open · Prior-art open · Remediated (verify still) · Accepted design · Doc-only

---

## Part A — Findings from this audit run (actionable backlog)

Work these **one by one**. Order is suggested priority, not assignment.

### A1. Fund safety / replay (on-chain)

| ID | Severity | Title | Status | Anchors | One-line fix |
|---|---|---|---|---|---|
| **C-01** | **Critical** | Merge ↔ settle double-spend: disjoint consume guards | Open | `merge.rs` only `NullifierEntry`; `tee_forced_settle_batched.rs` only `ConsumedNoteEntry`; `withdraw.rs` writes **both** | Make merge `init` `ConsumedNoteEntry` per input commitment (public inputs lockstep); optionally block merge under `NoteLock` |
| **C-02** | **High** | Re-lock ignores `MAX_LOCK_TTL_SLOTS` → unbounded censorship | Open | `create_relock_pda` in `tee_forced_settle.rs`; TTL only in `lock_note.rs`; `release_lock` needs `clock >= expiry` | Cap relock expiry like `lock_note` |
| **C-08** | Low | `batch_slot` unconstrained vs tree `match_index` | Open | `match_batch.circom`; `tee_forced_settle_batched.rs` walk uses `match_index` only; pad dummies all `batch_slot=0` | Circuit `batch_slot[i]===i`; on-chain equality check |

### A2. TEE trust / attestation

| ID | Severity | Title | Status | Anchors | One-line fix |
|---|---|---|---|---|---|
| **C-03 / A-1** | **High** | Client DCAP never wired; fake gateway passes | Open (plan written) | `packages/daemon/src/attestation.ts`; no `quoteVerifier` in `bin/daemon.ts` | See `docs/attestation-dcap-enforcement-plan.md` |
| **B-1** | Medium | `/info` `mrtd` path mismatch — pin never works | Open | Daemon reads top-level `mrtd`; server returns `tcb_info.mrtd` (`info.rs`) | Parse `tcb_info.mrtd` (+ legacy top-level) |
| **B-2** | Medium | Client ignores `event_log` | Open | Server returns it; daemon `fetchAttestation` drops it | Parse + later RTMR3/compose bind |
| **B-3** | Medium | Measurement pins fully optional | Open | `config.ts` `parseExpected` | Require compose+pubkey in strict mode |
| **B-4** | High | Stock binary never constructs DCAP verifier | Open | `bin/daemon.ts` | Wire CLI/`QuoteVerifier` |
| **C-05 / A-2** | Medium | Oracle price not bound to guardian-signed accumulator root | Open (prior art) | `crates/nyx-tee/src/oracle/vaa.rs:34–41` | Verify Pyth Merkle inclusion under VAA root |
| **Shard-0 only** | Medium | `/info` + `/attestation` expose only primary TEE key | Open | `info.rs`, `attestation.rs`; K keys in boot log only | Extend `/info` with `tee_pubkeys[]` |

### A3. Circuit / economic soundness

| ID | Severity | Title | Status | Anchors | One-line fix |
|---|---|---|---|---|---|
| **C-04** | Medium (High if TEE+admin collude) | No fee **ceiling** — TEE can confiscate 100% to protocol via fees | Open | `match_batch.circom` floor only (`GreaterThan` fee floor) | Add fee ceiling / exact floor equality (lockstep VK) |
| **C-07 / F-04** | Medium (process) | Settlement solvency rests on circuit soundness | Prior-art open | `VALID_MATCH_BATCH` + settle path | External circuit audit before mainnet |
| **Trusted setup** | Critical for mainnet | Groth16 Phase-2 is dev contribution | Known open | `CRYPTOGRAPHY.md` §2 | Real Phase-2 MPC |
| **TEE binary / key binding** | High ops | Software Ed25519 keys; rotation process not code-enforced | Known open | `set_tee_pubkey`, attestation ceremony docs | Multisig + DCAP ceremony; later on-chain |

**F-04 dry-run conclusion (this pass):** P1 range checks + fee floor + fee-note binding **are present** in `match_batch.circom`. No-inflation under Fr wraparound is **plausibly closed** for conservation terms; residual is external audit + C-04 ceiling + fairness non-goals.

### A4. Privacy / client

| ID | Severity | Title | Status | Anchors | One-line fix |
|---|---|---|---|---|---|
| **C-06** | Medium (privacy) | Deposit ix publishes `owner_commitment` + `inner_hash` | Open / design | `deposit.rs` ix args; docs claim owner “never revealed” | Doc fix short-term; deposit-with-proof long-term |
| **C-09** | Low | Inclusion witness from TEE not re-checked vs on-chain root ring | Open | `valid-input-prover.ts` `fetchInclusionProof` | SDK assert root ∈ on-chain ring |

### A5. Performance (not gated roadmap items)

| ID | Severity | Title | Status | Anchors | One-line fix |
|---|---|---|---|---|---|
| **P-01** | Perf-Nit | `nullifier_a/b` still in settle payload but not written on-chain | Open | `MatchResultPayload` ~64 B dead | Domain-tag v9 drop if unused |
| **P-02** | Perf-Nit | `fill_recovery` always 128 B (borsh pad) | Accepted cost | payload field | Only redesign if Tx D fails |
| **P-03** | Perf-Nit | Pad path clones identical dummies | Open | `witness.rs` `pad_batch` | Minor; set `batch_slot=i` |
| **P-04** | Info | No large missed CU win beyond shipped `append_leaves` | N/A | `merkle.rs` | — |

**Do not re-open** (deliberately deferred in `docs/throughput-roadmap.md`): SETTLE_CONCURRENCY>1, per-shard ALT pools, optimistic settle, adaptive batch cadence, witness-gen GPU follow-on.

### A6. Documentation / contract bugs (not fund loss, still track)

| ID | Severity | Title | Status | Anchors |
|---|---|---|---|---|
| **B-5** | Doc | Docs invent `packages/sdk/src/tee/attestation.ts` / `verifyTeeAttestation` — **missing** | Open | `tee-attestation-flow.md` §4.3, site, portal, OpenAPI |
| **B-6** | Doc/API | OpenAPI requires `vm_config` on `/attestation`; handler omits it | Open | `tee-api-openapi.yaml` vs `attestation.rs` |
| **B-7** | Doc | `event_log` called “hex-encoded”; dstack returns JSON string | Open | comments + OpenAPI |
| **B-8** | Doc | Some doc sections describe `report_data` as TLS-cert bind; **as-built** is `SHA-256(tee_pubkey)` | Open | `tee-attestation-flow.md` §2 vs code |
| **Doc-stale-1** | Doc | Site/docs claim settle+merge share nullifier guard — **false** after settle dropped nullifier writes | Open | `docs/site/05-cryptography.md`, `07-settlement-pipeline.md` |
| **Doc-stale-2** | Doc | `tee_forced_settle_batched` header still says marker closed in settle | Open | file header vs body |
| **Doc-stale-3** | Doc | CRYPTOGRAPHY table sometimes says VALID_MATCH_BATCH public inputs = 1; code has 3 | Open | public inputs order |

### A7. Prior art status (do not re-discover; verify still)

| ID | Original | Status after this pass |
|---|---|---|
| F-01 `reset_merkle_tree` | Always compiled | **Remediated** — `#[cfg(feature = "devnet-admin")]` |
| F-02 `close_vault_config` | Always compiled | **Remediated** — same feature gate |
| F-03 first-caller `initialize` | No upgrade authority | **Remediated** on mainnet build — ProgramData bind |
| F-04 circuit dependency | Open | **Still open** (external audit) |
| F-05 lock censorship ~TTL | Accepted | Accepted; **plus new C-02** on relock |
| F-06..F-10 | Info/ops | Treat as still relevant ops hygiene |
| A-1 DCAP | Open | **Still open** — plan in `docs/attestation-dcap-enforcement-plan.md` |
| A-2 oracle root | Open | **Still open** |

### A8. Accepted design (not bugs — record so they are not “fixed” by accident)

| Item | Recorded where | Residual |
|---|---|---|
| Price fairness (limit + oracle band) is TEE-trusted | `CRYPTOGRAPHY.md` §2 | Bounded by attestation + client fill memo detection |
| Aggregate trade analytics public on settle | Threat model | By design |
| Deposit/withdraw amounts public at pool boundary | Amount-privacy docs | By design |
| On-chain DCAP deferred | Attestation §11 | Client DCAP is separate |

---

## Part B — Suggested remediation order (checklist)

Use this as a sequential backlog:

1. [ ] **C-01** merge dual-guard + regression tests (P0 fund safety)  
2. [ ] **C-02** relock TTL cap (P0 liveness)  
3. [ ] **C-03 / B-1–B-4** DCAP plan Phase 0–3 (`docs/attestation-dcap-enforcement-plan.md`)  
4. [ ] **C-04** fee ceiling circuit (lockstep)  
5. [ ] **C-05** oracle inclusion under VAA root  
6. [ ] External **circuit audit** + real **Phase-2** setup  
7. [ ] **C-06/C-08/C-09** + doc-stale hygiene  
8. [ ] **P-01** payload trim if Tx D pressure  
9. [ ] Multisig / ceremony ops (F-10 + A-1 ceremony)  

---

## Part C — What this run did **not** audit (next review sweep)

Treat every row as **unreviewed or only spot-sampled**. Assign a next-pass owner.

### C1. On-chain program (vault) — residual

| Surface | Depth this pass | Next sweep focus |
|---|---|---|
| Full instruction-by-instruction re-audit of all ixs | Spot: lock, settle, verify, withdraw, merge, deposit, release_lock, initialize | Full `programs/vault/src/instructions/*` for post-audit_1 changes |
| `set_tee_pubkey` / `set_protocol_config` / `rotate_root_key` | Not deep | Zero-key, duplicate keys, governance |
| `close_batch_validity_marker` / marker sweeper | Not deep | Rent, premature close, race |
| Merkle `append_leaf` / `append_leaves` differential | Mentioned, not re-proven | Keep `merkle_host` / fuzz green |
| CU budgets under mainnet | Not measured | litesvm CU logs vs limits |
| Account discriminator / type cosplay on all UncheckedAccount | Spot on marker | All remaining Unchecked paths |
| Upgrade authority / ProgramData ops | Not operationally verified | `solana program show` multisig |

### C2. Circuits (ZK)

| Surface | Depth this pass | Next sweep focus |
|---|---|---|
| `VALID_MATCH_BATCH` MatchSlot + fee bind | Deep read | Formal underconstraint hunt |
| `VALID_SPEND` / `VALID_INPUT` / `VALID_MERGE` | Moderate | Dummy-slot, nullifier=0, ownership |
| `VALID_WALLET_CREATE` | Not reviewed | — |
| N=2/4 match_batch instances | Not reviewed | Dev-only drift |
| snarkjs / circom version / VK generation scripts | Not reviewed | Determinism, ceremony |
| Committed N=16 proof fixture freshness | Not re-generated | After any circuit change |
| Cross-language domain tags matrix | Spot | Full parity suite run as gate |

### C3. TEE binary (`crates/nyx-tee`)

| Surface | Depth this pass | Next sweep focus |
|---|---|---|
| HTTP auth (JWT/bearer), rate limits | Not reviewed | Auth bypass, token mint |
| `POST /orders` intake validation | Spot comments only | Commitment, anchors, Fr checks, logging of secrets |
| Cancel / modify / anchor top-up | Not reviewed | Auth + canonical sig |
| Matcher algorithm full | Not reviewed (audit_2 sampled clearing price) | Fairness, self-trade, partial fill, fee math |
| Settle pipeline (assemble, sign, ALT, RPC) | Spot payload | Failure recovery, double-submit, ALT pool corruption |
| Prover ark/rapidsnark/icicle paths | Spot allocation only | Witness correctness vs circuit |
| Merkle mirror indexer (multi-shard) | Not reviewed | Stale root, reorg, desync |
| WS fills/orders streams | Not reviewed | Auth, leak, reconnect |
| Boot / dstack key derivation K-shard | Spot | Wrong path, key reuse |
| Order-book memory / DoS | Not reviewed | Resource exhaustion |
| Logging of sensitive fields | Spot via audit_2 claim | Full `tracing` audit |

### C4. Matcher crate (`darkpool-matcher`)

| Surface | Depth | Next |
|---|---|---|
| `run_batch` / `run_batch_capped` | Not reviewed | Conservation at matcher layer |
| `order_canonical` / cancel / topup | Not reviewed | Malleability, domain tags |
| `change_note::derive_inner` | Mentioned | Parity only if changed |
| Fee accumulation / flush_fee_notes | Not reviewed | vs circuit fee notes |

### C5. Client packages

| Surface | Depth | Next |
|---|---|---|
| `packages/sdk` transport builders (all ixs) | Spot settle/canonical | Full `*-transport.test` gate |
| SDK wallet / note store / consolidate | Not reviewed | Key leakage, wrong tree_id |
| Fill memo Vuln-4 integrity | Mentioned not re-read | Substitution attacks |
| `packages/daemon` lifecycle, merge, deposit | Spot attestation only | Full lifecycle state machine |
| `packages/indexer` | Not reviewed | Optional path; no authority assumed |
| Browser demo `apps/demo` | Out of scope (per audit rules) | Secrets, demo keypairs F-06 |

### C6. Crypto crate (`darkpool-crypto`)

| Surface | Depth | Next |
|---|---|---|
| Poseidon / note / nullifier / keys | Spot via docs | Re-run all parity tests as gate |
| `fill_encryption` | Spot read | Nonce reuse, recipient binding |
| Field Fr safety helpers | Spot | Fixture abuse |

### C7. Ops / deploy / supply chain

| Surface | Depth | Next |
|---|---|---|
| Dockerfile / compose / image tags | Not reviewed | Secrets in image, compose_hash process |
| CI workflows | Not reviewed | Gating, secret scan |
| `cargo audit` / `npm audit` | Not run | Dependency CVEs |
| Phala deploy runbooks execution | Not run | Live CVM |
| Keypair handling `.devnet/` | Not reviewed | Leak paths |

### C8. Cross-cutting threat scenarios not fully exercised

| Scenario | Status |
|---|---|
| Malicious TEE + honest admin (fee confiscation C-04, bad price) | Reasoned, no exploit PoC |
| Malicious admin alone (F-01 remediated; multisig?) | Ops unknown |
| Race lock vs withdraw vs merge vs settle | C-01 only; more races possible |
| Batch marker reuse after close | Not deep |
| Tree shard confusion (wrong tree_id) | Not reviewed |
| ALT / Tx size regressions | Not measured |
| Client forced to trust `/tree/*` for privacy | Spot C-09 only |
| Network traffic analysis / TLS MITM without RA-TLS | Not reviewed |
| Governance pin compromise (wrong compose_hash allowlisted) | Process |

---

## Part D — Surfaces intentionally treated as “out of scope this run”

(From the original audit brief + agent judgment)

- Website / portal product UX (docs claims audited only)  
- Demo app as product  
- Already-deferred throughput roadmap items 1–5  
- Live mainnet (devnet-stage only)  
- Full formal ZK audit (dry-run of F-04 only)  
- Writing exploits/PoCs against third parties  

---

## Part E — How to use this in the next review sweep

1. Pick one Part A ID per PR/session; do not batch C-01 with DCAP.  
2. For each Part C table, mark **Reviewed YYYY-MM-DD** or **Finding X** when touched.  
3. Re-run workspace green gate after any on-chain/circuit change (`CLAUDE.md` §2.5).  
4. After C-01/C-02, update stale docs that claim shared nullifier across settle+merge.  
5. After DCAP ship, close A-1 in `audit_2/READINESS.md` and flip site/portal claims.

---

## Part F — File map quick reference (highest value)

| Area | Paths |
|---|---|
| Merge gap | `programs/vault/src/instructions/merge.rs` |
| Settle consume | `programs/vault/src/instructions/tee_forced_settle_batched.rs` |
| Withdraw dual guard | `programs/vault/src/instructions/withdraw.rs` |
| Relock TTL | `programs/vault/src/instructions/tee_forced_settle.rs` `create_relock_pda` |
| Circuit match | `circuits/templates/match_batch.circom` |
| Client attest | `packages/daemon/src/attestation.ts`, `bin/daemon.ts` |
| TEE quote API | `crates/nyx-tee/src/api/attestation.rs`, `info.rs` |
| Oracle | `crates/nyx-tee/src/oracle/vaa.rs` |
| DCAP plan | `docs/attestation-dcap-enforcement-plan.md` |

---

*Inventory compiled from the 2026-07-12 self-audit conversation. Re-verify anchors against HEAD before implementation — line numbers drift.*
