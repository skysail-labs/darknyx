<!-- audit-record -->
> **Audit:** Un-audited surface sweep  
> **Date:** 2026-08-02  
> **Engagement:** `audits/audit_7/`  
> **ID prefix:** `SW-`, `PF-12…PF-27`  
> **Cross-audit status:** see [`residual-backlog.md`](../residual-backlog.md) — the canonical index of what is still open.

---

# Darknyx un-audited surface sweep — 2026-08-02

> **Scope.** Follow-through on §4.1 of
> [`client-attestation-review.md`](client-attestation-review.md):
> the surfaces that no prior pass had read. Priority order was taken from that
> inventory. This document records what was covered, what was found, what was
> confirmed clean, and — explicitly — what is still unread.
>
> **ID prefix:** `SW-01…` (surface sweep, 2026-08-02). Distinct from `CA-`
> (08-01), `S-`/`PF-` (07-25 pass 1), `T-` (07-25 pass 2), `D-` (07-20),
> `U-` (07-18), `CS-`/`N-`/`P-` (07-14), `C-` (07-12), `F-` (audit_1),
> `A-` (audit_2), `AU-`/`RD-`/`DEP-`/`DOC-` (trackers).
>
> **Baseline.** `main` @ `d69248b`.
>
> **Severity:** Critical / High / Medium / Low / Perf-Nit / Info

---

## 1. Executive summary

**One Critical.** The Merkle-mirror sync decodes Anchor events out of a
transaction's `logMessages` **without scoping them to the vault program**
(`merkle/events.rs:181-250`). Any program can emit a `Program data:` line, and
Helius `getTransactionsForAddress` returns transactions that merely *reference*
the vault address. So an unauthenticated attacker can publish a forged
`NoteCreated` event, at an index they read from the public `/tree/root`, and have
the enclave append an arbitrary 32-byte value to its mirror as a real leaf. The
mirror is append-only with no rewind, and `reconcile` — which does detect the
resulting root divergence — is explicitly "never fatal": it logs one latched
`WARN`, misattributes the cause to a devnet `reset_merkle_tree`, and keeps
serving inclusion proofs. Cost to the attacker is one transaction; the effect is
a permanent halt of both order intake and settlement (SW-07).

**One High.** The Solana RPC client interpolates its own endpoint URL into the
error it raises on any non-success, non-429 HTTP status
(`solana_rpc/client.rs:805-809`). That endpoint is
`DARKNYX_TEE_SOLANA_RPC_URL`, which carries the Helius API key as a query
parameter. The error string propagates into a settle job's `failed_reason`,
which `GET /settlement/status/{batch_id}` serves to **any authenticated
account**. Any trader can therefore extract the operator's paid RPC credential
by reading the status of a batch that failed on an upstream 5xx — and upstream
5xx/quota errors are exactly the condition under which it happens.

**Three Medium.** The public router applies no rate limiting, and two of its
routes do unbounded upstream work per request: `/transparency` performs
`2 × N_mints` Solana RPC calls with no caching, and `/attestation` triggers a
TDX quote generation. Both are reachable with no credential at all, and both
consume the exact resources the settle pipeline depends on (SW-02). The settle
worker's per-round loop has no bound on consecutive RPC failures, so a sustained
RPC outage produces a non-terminating batch that holds a scheduler slot and
never records an outcome (SW-03). And the settle scheduler retains every job
ever created — the eviction its module doc has promised since "PR 4g.6" was
never implemented, so both memory and the in-enclave retention of per-match
commitments grow without bound for the process lifetime (SW-08).

**Five Medium.** The public router applies no rate limiting (SW-02); the settle
worker's per-round loop is unbounded on RPC failure (SW-03); the settle
scheduler never evicts (SW-08); the daemon **has no reconciliation path at
all**, neither after a stream gap nor after a restart, despite four separate
module docs describing one (SW-11) — the SDK's 1011 "you lagged past the buffer"
signal is plumbed through two layers and then dropped, and fill memos are the
*only* in-band source of a change note's opening, so a lag disconnect silently
strands residual notes in a UTXO view the daemon believes is complete.

The fifth came out of the prover slice and is the one worth reading twice.
**The enclave writes the full private match witness in plaintext to `/tmp` on
every batch** (SW-14). The native circom witness generator is a subprocess, so
`native_witness_wtns` serializes every circuit signal — including
`a_amount`, `b_amount`, `clearing_price`, both owner commitments, and every
per-slot fill amount — into an `input.json` under `std::env::temp_dir()`. That
resolves to the container's writable layer, **not** the one LUKS-encrypted
volume the compose file provisions and documents for state. These are precisely
the values the amount-privacy work removed from the leaf hash and the settle
payload; the witness file puts all of them back on disk. The native generator is
the default, not an opt-in, and the cleanup guard does not survive a crash — the
exact scenario `settlement-recovery-drill.md` exists to exercise. The fix is a
`tmpfs` mount and fifteen minutes.

**The most valuable results in this sweep are negative.** The two surfaces both
prior passes predicted would hold the next bug — the hand-rolled Pyth
accumulator parser and the `fills`/`orders` cross-account routing — are clean,
and demonstrably so. So is the settle journal's write-ahead ordering, the VAA
quorum logic, the client-side recovery self-verification, and the daemon's
lifecycle reducer (whose edge-triggering genuinely does prevent the merge
hot-loop its comment claims to). Those are recorded in §3 so they are not
re-audited.

| Bucket | Count |
|---|---|
| Critical | 1 |
| High | 1 |
| Medium | 10 |
| Low | 13 |
| Info | 9 |

| ID | Severity | Category | Finding |
|---|---|---|---|
| SW-07 | **Critical** | Data integrity / DoS | Merkle-mirror sync ingests unscoped `Program data:` events; any program can forge a leaf |
| SW-01 | **High** | Credential exposure | RPC API key leaks into settle failure reasons, served by an authenticated endpoint |
| SW-02 | Medium | DoS / resource amplification | Unauthenticated public routes perform unbounded upstream work with no rate limit |
| SW-03 | Medium | Liveness | Settle round loop is unbounded on sustained RPC failure |
| SW-08 | Medium | Resource exhaustion / retention | Settle jobs are retained forever; the eviction the module has promised since "4g.6" was never implemented |
| SW-11 | Medium | Client recovery / fund visibility | Daemon never reconciles after a stream gap or a restart; the `onResync` signal is dropped and no resume path exists |
| SW-14 | Medium | Confidentiality at rest | The full private match witness — including the amounts P1b removed from the leaf and payload — is written in plaintext to `/tmp` on every batch, outside the one encrypted volume |
| SW-19 | Medium | Access control / CSRF | The daemon's control plane is unauthenticated by default and has no browser-origin defences, while exposing `POST /orders` and `POST /deposit` |
| SW-21 | Medium | Griefing / settlement integrity | An out-of-range `tree_id` — a field deliberately excluded from the signed body — passes intake via a saturating mirror accessor and then guarantees a settle-time lock failure, letting a client burn a chosen counterparty's fill at will |
| SW-29 | Medium | Resource exhaustion / venue liveness | A stream session's order-id set is never pruned on fill or expiry, so it grows for the socket's lifetime — and cancel-on-disconnect then takes the matcher write lock once per entry, stalling matching for every other trader |
| SW-31 | Medium | Silent data loss | When the server's own fan-out routers lag the matcher broadcast they drop fills and order updates with **no** client-visible signal — the 1011 resync contract protects only against a slow client, not a slow server |
| SW-32 | Medium *(pre-merge, PR #65)* | Confidentiality | The ICICLE backend's CUDA mode is documented as requiring a confidential GPU, but nothing enforces it — an env var alone moves the private witness into device memory |
| SW-04 | Low | Delivery loss | `recent_order_owner` keeps the arbitrary-eviction pattern S-10 fixed elsewhere |
| SW-05 | Low | Account validation | `/transparency` raw reads lack the owner + discriminator checks the vault applies |
| SW-10 | Low | Client recovery / replay | Daemon order-id sequence restarts at 0 after DB loss; the store's "rebuildable from seed + chain" claim does not hold for it |
| SW-12 | Low | Wasted work / self-DoS | Auto-merge selects notes with a live on-chain `NoteLock`; the vault rejects them, but the daemon burns a VALID_MERGE proof per attempt and re-picks the same doomed batch |
| SW-13 | Low | Accounting | `pendingChangeNotes` is a per-order counter decremented by an account-wide merge count; it drifts in both directions |
| SW-16 | Low | Custody boundary | The keystore's at-rest and in-process boundaries are softer than its module doc states: no mode check on load, a public getter that hands out the master seed, and no passphrase floor |
| SW-17 | Low | Untrusted input handling | The attestation client fetches from the explicitly-untrusted gateway with no timeout, no response-size bound, and no field validation on the quote response |
| SW-20 | Low | Input / error hygiene | The control server reads unbounded request bodies, echoes internal error messages (which can carry the RPC credential), compares its token non-constant-time, and forwards one path parameter unencoded |
| SW-22 | Low | Key derivation strength | The portable master-seed backup uses scrypt N=2¹⁴ while the daemon keystore protecting the same seed uses N=2¹⁷ — the weaker KDF guards the more exposed artifact |
| SW-24 | Low | Data integrity | The SDK's leaf-index decoder is SW-07's unscoped `Program data:` pattern on the client side; a hostile RPC can strand the client's own note |
| SW-26 | Low | Diagnosability | Only the deposit prove path validates its prover's public signals locally; merge and withdraw do not, so a witness-assembly bug presents on-chain as `InvalidProof (6000)` — indistinguishable from the repo's most-documented foot-gun |
| SW-27 | Low *(test tooling)* | Measurement fidelity | The loadgen's latency histogram mixes accepted and rejected submits, so the documented wrong-mint-regime run reports a flattering P99 next to a 0% success rate |
| SW-28 | Low | Latent correctness | The uncapped `run_batch` wrapper can emit matches whose collateral note is the zero sentinel, and the TEE's own module docs name it as the production entry point when it is not |
| SW-15 | Info | Defence in depth | Prover-backend output is deserialized into curve points with no on-curve or subgroup validation; a backend defect surfaces on-chain as `InvalidProof` rather than locally |
| SW-18 | Info | Attestation scope | `bootSessionId` is returned inside the DCAP-verified `AttestationResult` but is not bound to the quote; the S-07 session scoping rests on an unattested field |
| SW-23 | Info | Cross-language contract | TypeScript silently reduces out-of-range Poseidon inputs where Rust rejects them — a divergence in failure mode on the exact hazard CLAUDE.md §7.2 names |
| SW-25 | Info | Stale code | Four PDA seed constants for the deleted `matching_engine` program survive in the SDK, unused, against CLAUDE.md's explicit instruction to remove such references |
| SW-30 | Info | Documentation accuracy | `canonical_payload_hash` is documented as "shared" but exists in four independent implementations; two other module docs describe retired or unbuilt states |
| SW-34 | Info *(test tooling)* | Measurement fidelity | `settlement_benchmark.rs` is a complete, tested report generator with **no production data path** — nothing outside its own test fixture ever constructs a `BatchMetric` |
| SW-33 | Info | Build invariant | The unauthenticated `/__debug/` routes are kept out of production by `resolver = "2"` semantics alone — a load-bearing build setting with no comment, no CI gate, and no equivalent of the vault's documented `devnet-admin` discipline |
| SW-09 | Info | Cross-language contract | Stale `algorithm.rs` change-note commitment leaks into a `FillMemo` on the failure path |
| SW-06 | Info | Public API clarity | `merkle_root` and `leaf_count` are paired in the reserves response but describe different scopes |

---

## 2. Findings

### SW-07 — Merkle-mirror sync ingests unscoped events; any program can forge a leaf

| | |
|---|---|
| **Severity** | **Critical** |
| **Category** | Data integrity / denial of service |

**Anchors**

- `crates/darknyx-tee/src/merkle/events.rs:181-250` — `extract_appended_leaves`
  scans every line of `logs` for the `"Program data: "` prefix, decodes the
  base64, and dispatches on the 8-byte Anchor event discriminator. **Nothing
  identifies which program emitted the line.**
- `crates/darknyx-tee/src/merkle/sync.rs:257` — it is handed
  `&tx.log_messages`, the transaction's *complete* log array.
- `crates/darknyx-tee/src/merkle/sync.rs:216-225` — transactions come from
  `get_transactions_for_address(&self.vault_program_id, …)`. Address-indexed
  history returns transactions that **reference** the address in their account
  keys, not only those that invoke it.
- `crates/darknyx-tee/src/merkle/sync.rs:453-476` — `apply_leaves` appends any
  leaf whose `leaf_index` equals `mirror.leaf_count()`.
- `crates/darknyx-tee/src/api/mod.rs:85` — `/tree/root` is **public and
  unauthenticated**, publishing the exact `leaf_count` the attacker needs.
- `crates/darknyx-tee/src/merkle/sync.rs:299-380` — `reconcile` detects
  divergence but is documented "never fatal".

**The problem**

`Program data: <base64>` is not a vault-specific marker. It is the output of
`sol_log_data`, which **any** Solana program can call; Anchor's `emit!` is just
a wrapper around it. A transaction's `meta.logMessages` interleaves the logs of
every program it invokes. The decoder treats that combined stream as if it were
the vault's private event channel.

Solana logs *do* carry program scope — `Program <id> invoke [n]` … `Program <id>
success` brackets — but the decoder never tracks it.

`NoteCreated` and `NoteMerged` are fully self-describing (the event carries both
the index and the value), so forging either requires nothing from the vault.

**Amendment (2026-08-02, after reading `solana_rpc/client.rs`): `TradeSettled`
is forgeable too, by the same root cause on a second path.** The settle payload
that supplies its leaf *values* is located by discriminator alone:

```rust
// merkle/sync.rs:252-256
let settle_ix_data = tx.instructions.iter()
    .map(|ix| ix.data.as_slice())                       // program_id discarded
    .find(|d| d.len() >= 8 && d[..8] == *SETTLE_BATCHED_DISCRIMINATOR);
```

`RpcAddressTx.instructions[]` **does** carry a resolved `program_id`
(`client.rs:124-132`) — it is dropped here. So an attacker supplies both halves
in one transaction: a forged `TradeSettled` event for the indices, and an
instruction to their own program whose data begins with the 8-byte settle
discriminator followed by a chosen 488-byte payload for the values.

The field's own doc comment records why it was not used:

> *"Empty if the index refers to an ALT-loaded address (the sync identifies the
> settle instruction by its data discriminator, not the program id, so this is
> best-effort metadata for logging)."*

**That rationale appears to be incorrect.** Solana requires an instruction's
`program_id_index` to point into a message's *static* account keys — program ids
cannot be resolved through an address lookup table — so `program_id` should be
reliably populated for every instruction, including in the v0 settle
transactions. Worth confirming against the current agave `sanitize` rules before
relying on it, because if it is wrong the instruction-side fix changes shape.
If it is right, that half of the fix is a one-line filter on data the client
already returns.

**Failure scenario**

1. Attacker reads `GET /tree/root?tree_id=0` — public, no credential — and gets
   `leaf_count = L`.
2. They submit **one** transaction containing a single instruction to their own
   trivial program, which calls `sol_log_data` with:
   ```
   sha256("event:NoteCreated")[..8] ‖ borsh(NoteCreatedEvent {
       tree_id: 0, leaf_index: L, commitment: <arbitrary 32 bytes>, … })
   ```
   with the vault program id included among the instruction's account keys so
   the transaction lands in the vault's address history. **No vault instruction
   is invoked and no vault state is touched.**
3. The transaction succeeds, so `sync.rs:249`'s `tx.err.is_some()` filter does
   not exclude it.
4. The next sync tick decodes the forged event, `group_by_shard` routes it to
   shard 0, and `apply_leaves` finds `leaf_index == expected` and **appends the
   attacker's arbitrary value as a genuine leaf**.
5. The mirror's root now diverges permanently from the on-chain root. The mirror
   is append-only with **no rewind** — the property T-05 accepted as an
   availability risk.

**Impact — a permanent venue halt**

Everything downstream of the mirror is now built on a root the chain never had:

- **`/tree/inclusion`** serves sibling paths that fold to the corrupted root.
  Clients build `VALID_INPUT` witnesses from them, so every subsequent
  `lock_note` fails `StaleMerkleRoot (6004)` → **nothing settles**.
- **Order intake**, post-S-02, requires the relayed proof's `merkle_root` to be
  in the mirror's recent-root ring. Honest clients' genuine roots are no longer
  in the corrupted mirror's ring → **all intake rejected**.
- The daemon's `/tree/leaves` local tree and `/transparency`'s reported root are
  poisoned identically.

Recovery needs a code fix plus advancing `DARKNYX_TEE_SYNC_FROM_SLOT` past the
poisoned transaction — which also skips every genuine leaf in between, so in
practice a tree reset. On a real deployment that is a full outage.

**The existing detection does not save it.** `reconcile` (`sync.rs:299-380`)
compares each mirror root to `MerkleTree[j].current_root` and would classify this
as `Diverged`. But it is advisory only:

- it emits **one latched `WARN`** per shard (`self.diverged[tree_id]`) and never
  escalates;
- it does **not** halt the mirror or stop `/tree/inclusion` from serving;
- it does **not** route through the shared trading gate — contrast T-17/U-09,
  where oracle degradation correctly pauses place/modify/matching;
- and its documented interpretation of `Diverged` is hard-coded to one benign
  cause: *"an on-chain `reset_merkle_tree` ran underneath it (a DEVNET op;
  production never resets)"*. Poisoning is misread as a devnet reset.

So the system detects the corruption, logs it once, and keeps serving.

**Recommended fixes**

| Option | Description | Trade-off |
|---|---|---|
| **A — Scope log parsing to the vault program (recommended, necessary)** | Track program scope while walking the log array — `Program <vault_id> invoke [n]` opens a scope, `Program <id> success/failed` closes it — and accept a `Program data:` line only while the vault is the innermost active program. **Also filter the settle-payload finder on `ix.program_id == vault_program_id`** (see the amendment above) — that half is one line on data already returned. | The direct fix for the root cause, on both paths. Must handle nesting and CPI depth correctly; the depth marker in the invoke line makes that tractable. |
| **B — Derive leaves from instruction data, not logs** | Decode vault instructions in the transaction (already done for the settle payload at `sync.rs:252-256`) and take leaf values from those, using events only for indices. | Structurally stronger — instruction data is attributable to the program by construction, no scope tracking needed. Larger change; `deposit`/`merge` values must be read from their own ix data. |
| **C — Make root divergence fail closed** | On `ReconcileState::Diverged`, stop serving `/tree/inclusion` and `/tree/leaves` and pause new trading through the shared gate, as the oracle path already does. | Does not prevent poisoning, but converts a silent wrong-proof service into a loud, safe stop. **Do this regardless of A/B** — it also covers mirror divergence from any future cause. |
| **D — Rely on the existing WARN** | Rejected. One latched log line is not a control, and its documented interpretation actively misdirects an operator toward "someone ran a devnet reset". | — |

Ship **A (or B) + C**. C is independently valuable and is the smaller change.

**Cost**

| Item | Estimate |
|---|---|
| A: program-scope tracking in `extract_appended_leaves` + signature change to take the full log array with the vault id | ~1 day |
| C: `Diverged` → stop serving tree reads + pause trading via the shared gate | ~1 day |
| Tests: forged `NoteCreated`/`NoteMerged` from a foreign program ignored; nested-CPI scope correctness; divergence halts reads and pauses trading | ~1 day |
| CVM spot-check (the sync/boot path changes) | ~0.5 day |
| **Total** | **~3.5 days** + one CVM window |

**Regression test.** Construct a log array containing a genuine vault
`NoteCreated` bracketed by `Program <vault> invoke [1]` / `Program <vault>
success`, plus a byte-identical forged one bracketed by `Program <attacker>
invoke [1]` / `Program <attacker> success`, and assert `extract_appended_leaves`
returns exactly one leaf. Add the mirror case for the instruction path: a
forged settle payload carried by a non-vault instruction must not supply
`TradeSettled` values.

---

### SW-08 — Settle jobs are retained forever; the promised eviction was never implemented

| | |
|---|---|
| **Severity** | Medium |
| **Category** | Resource exhaustion + in-enclave data retention |

**Anchors**

- `crates/darknyx-tee/src/settle/scheduler.rs:43-57` —
  `SettleSchedulerState { jobs: HashMap<SettleJobId, SettleJob>, by_batch: … }`.
- `:19-20` (module doc) — *"Retention: jobs accumulate forever in 4g.1. PR 4g.6
  adds an eviction policy (keep last N batches, or last T minutes)."*
- `:45` — *"4g.6 evicts terminal jobs older than N seconds."*
- `:146` — *"Returns false if the job has been evicted (4g.6)…"*

**PR 4g.6 landed other work but never added the eviction.** A repo-wide search
finds no prune, retain, evict, or cap on `jobs`/`by_batch` — only the three
comments above promising one, and `main.rs` which constructs the state
(`:425`), seeds `next_batch_id` (`:1065`), and shares it. Nothing ever removes a
job. `SettleSchedulerState::update`'s "evicted" return path is therefore dead.

**Two consequences.**

*Memory.* Every match ever settled is retained for the process lifetime. Each
`SettleJob` holds a full `MatchPair` (6 × 32-byte commitments and trading keys
plus amounts), five `Option<String>` base58 signatures (~88 bytes each once
populated), two `SystemTime`s, and — on failure paths — `String` reasons.
Conservatively ~800 B/job. The matcher ticks every 2 s and pages up to 16
matches per batch, so at a sustained 1 match/s this is ~70 MB/day and at 8
match/s ~550 MB/day, on an 8-vCPU `tdx.xlarge`. It is a certainty over uptime
rather than a possibility, and it degrades fastest exactly when the venue
succeeds.

*Retention.* The adjacent `metrics` field is documented as the privacy-conscious
counterpart: *"Unlike `jobs`, this has a strict recent-record cap and never
retains order ids, commitments, amounts, prices or proof witnesses"* (`:53-56`).
That comment states plainly what `jobs` does retain — unbounded, in the enclave's
memory, for its whole lifetime. A confidential-compute service accumulating the
complete commitment and trading-key history of every match it has ever processed
is a larger disclosure surface than the design intends, and it enlarges the blast
radius of any memory-disclosure bug (the same reasoning that made S-09 worth
closing).

**Recommended fixes**

| Option | Description | Trade-off |
|---|---|---|
| **A — Implement the promised eviction (recommended)** | Evict terminal jobs (`Confirmed`/`Rejected`) older than a TTL, keeping the last N batches. Insertion-ordered, not `keys().next()` — see SW-04. | What the module has always said it does. Must not evict `Ambiguous`/`Pending`: those are exactly what a restart reconciles, and T-06's journal is keyed to them. |
| **B — Shrink what a terminal job retains** | On transition to a terminal outcome, drop `match_pair` and keep only ids, stage, timings, and signatures — everything `JobStatus` actually serializes. | Complementary and cheap. Removes the privacy half immediately even before A lands, since `JobStatus` never exposes `match_pair`. |
| **C — Cap `jobs` by count with rejection** | Refuse new jobs at a ceiling. | Rejected — converts a slow leak into a hard trading outage. |

Do **B then A**. B is a few lines and closes the retention concern; A closes the
memory bound.

**Interaction to respect.** `/settlement/status/{batch_id}` returns 404 for an
unknown batch, and `seed_next_batch_id` (`:68-72`) exists precisely so recovery's
preserved journal keys are not overwritten. Eviction must keep those two
consistent: evicting a batch turns its status query into a 404, which is correct,
but the TTL should exceed the marker/lock window so an operator investigating a
live settlement still finds it.

**Cost:** ~1 day for B + A with a retention test (terminal jobs evicted after
TTL, `Ambiguous` never evicted, `by_batch` shrinks with `jobs`), plus a soak
assertion that `job_count()` plateaus.

---

### SW-01 — RPC API key leaks into settle failure reasons and is served to any authenticated account

| | |
|---|---|
| **Severity** | **High** |
| **Category** | Credential exposure |

**Anchors — the full chain**

1. `crates/darknyx-tee/src/solana_rpc/client.rs:243`, `:263` — the endpoint is
   stored raw: `endpoint: String`, no redaction wrapper.
2. `crates/darknyx-tee/src/solana_rpc/client.rs:804-810` — on any non-success,
   non-429 HTTP status:
   ```rust
   return Err(RpcError::Schema(format!(
       "HTTP {status} from {endpoint}: {body}",
       endpoint = self.endpoint,        // ← full URL, including ?api-key=<secret>
       body = preview(&bytes)
   )));
   ```
3. `crates/darknyx-tee/src/settle/worker.rs:210-212` —
   `WorkerError::Rpc(#[from] RpcError)` with `#[error("rpc: {0}")]`.
4. `crates/darknyx-tee/src/settle/worker.rs:543-544` —
   `ctx.fail_all(batch_id, n, format!("{e}")).await`.
5. `crates/darknyx-tee/src/settle/worker.rs:255-272` → `job.fail(reason)` →
   `SettleJobStage::Failed { reason }`.
6. `crates/darknyx-tee/src/settle/job.rs:188-189`, `:206-210` —
   `JobStatus.failed_reason = Some(reason.clone())`, a serialized JSON field.
7. `crates/darknyx-tee/src/api/settlement.rs:39-56` —
   `GET /settlement/status/{batch_id}` returns `Vec<JobStatus>` to any caller
   holding a valid bearer token.

**The problem**

`CLAUDE.md` §3.2 provisions the RPC URL as
`https://devnet.helius-rpc.com/?api-key=<key>` — the credential is *in the URL*.
The client stores and formats that URL verbatim.

The exposure decision in `api/settlement.rs:4-9` is explicit and was reasonable
when written:

> *"Per-account scoping isn't a meaningful security boundary here … the response
> leaks only stage labels + tx signatures (which are observable on-chain
> anyway)."*

That premise is no longer true. `failed_reason` is a free-form error string, not
a label from a closed set, and it can carry the endpoint URL.

**Failure scenario**

1. Helius returns HTTP 402/403/429-after-retries/500/503 — quota exhausted, plan
   limit, or a provider incident. Any of these is routine; the 429 path retries
   six times and then falls through to the same `!status.is_success()` branch.
2. `run_batch_settle_inner` returns `WorkerError::Rpc`, and `fail_all` stamps
   every job in the batch with the formatted string.
3. A trader polls `GET /settlement/status/{batch_id}` — an endpoint they are
   authorised for, over a range of batch ids — and reads
   `"rpc: HTTP 503 from https://devnet.helius-rpc.com/?api-key=<key>: …"`.
4. They now hold a paid credential for the RPC endpoint the enclave's entire
   settle pipeline depends on, and can exhaust its quota at will — turning a
   credential leak into a settlement denial of service, compounding **D-02**
   (marker runway under degraded RPC) and **SW-03** below.

**Amendment (2026-08-02, after reading `config.rs`): both the policy and the
type to prevent this already exist in the codebase — applied to the other
endpoint.**

- `config.rs:22-35` defines `SecretString`, whose `Debug` prints `[REDACTED]`,
  pinned by `pyth_api_key_debug_is_redacted`. It wraps `pyth_api_key`.
  `solana_rpc_url` is a plain `String` (`config.rs:68`).
- `config.rs:210-227` `validate_hermes_endpoint` **rejects a URL carrying
  credentials, query parameters, or a fragment**, and requires HTTPS off
  loopback. The test at `:726-731` asserts
  `https://pyth.example/hermes?key=secret` is refused. There is no equivalent
  validator for `DARKNYX_TEE_SOLANA_RPC_URL`, which CLAUDE.md §3.2 provisions
  as exactly that shape: `https://devnet.helius-rpc.com/?api-key=<key>`.

The asymmetry is defensible in itself — Hermes accepts a bearer header, so the
"no secrets in URLs" rule is enforceable there, whereas Helius's standard auth
*is* a query parameter. But that makes redaction more important, not less: if
the credential must live in the URL, the URL must never reach a formatted error
or log. `SecretString` is the existing mechanism; SW-01's fix is to apply it.

**Why the existing hardening did not catch it.** Slice 1's recorded evidence
states *"`loaded config (solana_rpc_url redacted to host) rpc_host=devnet.helius-rpc.com`.
No RPC key, Hermes key, or bootstrap secret in any log line."* That redaction is
real, but it is on the **config-load** path. This is a second, independent path
that reconstructs the full URL from the client's own field, and it bypasses the
redaction entirely. The `RpcError::Schema` variant also reaches operator logs
wherever a settle error is traced, so the log-hygiene claim needs re-testing too,
not just the API surface.

**Recommended fixes**

| Option | Description | Trade-off |
|---|---|---|
| **A — Redact at the source (recommended)** | Store a pre-computed display form (scheme + host, no query) alongside the endpoint and use it in every error/log format. The client already has `endpoint()` for real use. | Fixes every current and future formatting site at once. This is the same shape as the existing `Debug` redaction on the Pyth key (`config.rs:97`), so the pattern is established. |
| **B — Move the credential out of the URL** | Send the key as a header instead of a query parameter, where supported. | Structurally better — a URL is a natural thing to log — but provider-dependent, and does not fix the class if any other secret ever lands in a formatted field. |
| **C — Sanitise at the API boundary** | Map `failed_reason` to a closed set of stage labels before serializing, and keep the free-form string internal. | Restores `api/settlement.rs`'s stated premise, and is worth doing **in addition to A**: it stops the *next* secret from reaching a client through the same channel. |
| **D — Restrict `/settlement/status` to the owning account** | Per-account scoping. | Defensible but insufficient alone — the operator's own credential should not be readable by *any* account, including a legitimate one. |

Ship **A + C**. A is the fix; C is the boundary that makes the class not recur.

**Cost**

| Item | Estimate |
|---|---|
| Redacted display form on `SolanaRpcClient` + sweep all format sites | ~0.5 day |
| Closed-set `failed_reason` mapping at the API boundary | ~0.5 day |
| Tests: error string contains no `api-key`; `JobStatus` serializes only labels | ~0.5 day |
| **Rotate the currently-provisioned Helius key** — it must be assumed disclosed if any authenticated account ever queried a failed batch | ops |
| **Total** | **~1.5 days** + a credential rotation |

---

### SW-02 — Unauthenticated public routes perform unbounded upstream work with no rate limit

| | |
|---|---|
| **Severity** | Medium |
| **Category** | DoS / resource amplification |

**Anchors**

- `crates/darknyx-tee/src/api/mod.rs:77-96` — the `public` router:
  `/health`, `/info`, `/attestation`, `/auth/token`, `/tree/root`,
  `/instruments`, `/transparency`, `/system/status`, `/time`, `/v1/stream`.
- `crates/darknyx-tee/src/api/mod.rs:110-118` — `rate_limit_middleware` is
  applied inside `build_protected_router`, **not** to `public`.
- `crates/darknyx-tee/src/api/transparency.rs:167-172` — two
  `get_account_info` RPC calls per market mint, per request, uncached.
- `crates/darknyx-tee/src/api/attestation.rs:109` —
  `dstack.get_quote(report_data)` per request.

**The problem**

Most public routes are in-memory reads and are fine. Two are not:

- **`/transparency`** issues `2 × N_mints` Solana RPC calls on every request,
  with no caching of a value that can change at most once per slot. An
  unauthenticated attacker converts cheap HTTP requests into metered upstream
  RPC consumption against the same Helius quota the settle pipeline needs.
- **`/attestation`** triggers a TDX quote generation per request. It cannot be
  cached — the caller-supplied nonce is the whole point — so rate limiting is
  the only available control.

The `api/mod.rs:73-74` doc comment says `/auth/token` is *"rate-limited at the
reverse-proxy layer in production"*. The T-audit's **AU-05** established that
this reverse proxy does not exist in this repository, and closed AU-05 by adding
an in-process per-account login bucket. The same reasoning applies to these two
routes and has not been carried across.

**Failure scenario.** A sustained unauthenticated request flood against
`/transparency` exhausts the Helius plan's request budget. The settle worker's
RPC calls then start failing, which (a) triggers **SW-03**'s unbounded loop,
(b) risks the marker-runway pressure **D-02** tracks, and (c) with **SW-01**
publishes the credential to any authenticated account. The three compose into a
credential-leak-plus-DoS chain from an unauthenticated starting position.

**Recommended fixes**

| Option | Description | Trade-off |
|---|---|---|
| **A — Rate-limit the public router (recommended)** | Apply a per-IP-independent global bucket to `public`, sized well above honest polling. Per-peer keying is useless behind the gateway (one apparent source address — the reasoning already recorded in `conn_limit.rs`), so a venue-wide bucket plus per-route weights is the right shape. | Bounds both routes. Consistent with how AU-07's connection caps were sized: a stated bound, cheap to re-tune. |
| **B — Cache `/transparency`** | Short TTL (400 ms – 2 s) on the reserve reads. | Removes the amplification factor entirely for the RPC-backed route and improves honest-path latency. Does nothing for `/attestation`. Do **A + B**. |
| **C — Authenticate `/transparency`** | Move it behind the bearer. | Rejected — it is proof-of-reserves; public verifiability is the point. |

**Cost:** ~1 day for A + B, including a load check that honest polling is not
throttled. No wire change beyond a `429` + `Retry-After` on the public routes,
which should be added to the OpenAPI.

---

### SW-03 — The settle round loop is unbounded on sustained RPC failure

| | |
|---|---|
| **Severity** | Medium |
| **Category** | Liveness |

**Anchors:** `crates/darknyx-tee/src/settle/worker.rs:973-984`

```rust
while !unresolved.is_empty() {
    let bh = match ctx.rpc.get_latest_blockhash().await {
        Ok(bh) => bh,
        Err(error) => {
            /* mark every unresolved match ambiguous */
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;                       // `unresolved` is NOT drained
        }
    };
    …
```

**The problem**

Every other exit from this loop is correctly bounded by
`settlement_deadline(...)` — the min of the marker expiry and both lock
expiries. But that deadline is evaluated from `bh.context_slot`, which requires
a **successful** `get_latest_blockhash`. On the error path the loop `continue`s
without draining `unresolved`, so the bound is unreachable in exactly the
condition that triggers the error path.

If RPC is unavailable for an extended period, the batch task spins at one
iteration per second indefinitely: no terminal outcome is recorded, the journal
entries are never retired, the orders stay reserved, and the scheduler's
`settle_batch_concurrency` slot is held. Recovery on restart is unaffected (the
journal is durable and reconciles), but a *running* enclave does not
self-heal — it needs a restart.

Note this is reachable without an outage: SW-02 lets an unauthenticated attacker
drive the RPC quota to exhaustion, and `client.rs:804-810` turns a sustained
5xx/402 into exactly this error.

**Recommended fixes**

| Option | Description | Trade-off |
|---|---|---|
| **A — Wall-clock deadline computed at entry (recommended)** | Derive an absolute `Instant` deadline once from `marker_expiry_slot` and the nominal slot time, and break out of the loop when exceeded regardless of RPC health. Fail the remaining matches; the lock sweeper releases the collateral at expiry as designed. | Makes the bound independent of the failing dependency. Preserves the existing slot-based logic on the healthy path. |
| **B — Cap consecutive RPC failures** | e.g. 60 consecutive errors, then fail the batch. | Simpler, but a counter reset by one lucky success can still extend indefinitely under a flapping endpoint. |
| **C — Leave it** | Rejected. A non-terminating worker task that holds a concurrency slot is exactly the shape that turns a degraded dependency into a stuck venue. | — |

**Cost:** ~0.5 day plus a test that injects a permanently-failing RPC and asserts
the batch terminates with every match `Rejected`/`Ambiguous` rather than hanging.

---

### SW-11 — The daemon never reconciles after a stream gap or a restart

| | |
|---|---|
| **Severity** | Medium |
| **Category** | Client recovery / fund visibility |

**Anchors**

- `packages/daemon/src/daemon.ts:454-476` — `start()` constructs `FillsListener`
  and `OrdersListener`. Neither is given an `onResync` callback. Both accept one.
- `packages/daemon/src/fills-listener.ts:51-53` — declares `onResync` as *"the
  gap must be re-backfilled from the chain (the orchestrator's job; this surfaces
  it)."* It forwards it to the SDK at `:79`.
- `packages/daemon/src/orders-listener.ts:27-28, :55` — *"the orchestrator should
  reconcile via `GET /orders/:id`."* Forwarded at `:106`.
- `packages/sdk/src/orders/trading-ws-client.ts:324, :363` — on close code 1011
  the SDK calls `notifyResync`, which fans out to listener hooks. **It performs
  no backfill of its own.**
- `packages/daemon/src/daemon.ts:450-451` — the entire restart path:
  `this.started = true; this.nextIndex = this.store.maxSeedIndex() + 1;`
- `packages/daemon/src/store.ts:281-291` — `listActiveOrders()`, documented
  *"Non-terminal orders — the set to resume after a restart"*, **has no
  production caller** (only `tests/store.test.ts:132`).
- `packages/daemon/src/order-lifecycle.ts:194-201` + `types.ts:60` —
  `mergeInFlight` is persisted (`store.ts:48`) and cleared only by a
  `merge-confirmed` / `merge-failed` event. Nothing clears it at boot.

**The problem**

The daemon is documented, in `types.ts:6-8` and again in the `store.ts` module
header, as holding *"enough to recover after a crash."* Three further comments
name a specific recovery duty and assign it to "the orchestrator." The
orchestrator is `daemon.ts`, and it implements none of them.

The gap that matters is the fills channel. A `FillMemo` is the only in-band
delivery of a continuation change note's **opening** — the amount and
`inner_hash` the daemon needs to ever spend that note again. The TEE buffers
these; a client that falls behind the buffer is closed with 1011, which is the
protocol's explicit "you have missed messages, go re-derive them from the chain"
signal. The SDK raises it faithfully. The daemon does not subscribe, so the
signal is discarded at the top of the stack and the daemon carries on as though
the stream were complete.

The consequences compose:

1. **Silently stranded value.** Notes minted during the gap never enter the
   store. `balances()` (`daemon.ts:684-698`) sums the store and therefore
   under-reports. The value is not lost — SDK recovery v3 can reconstruct the
   openings from seed + chain — but nothing in the daemon ever invokes it, and
   nothing tells the operator a recovery run is needed.
2. **Phase desync.** Orders keep whatever phase they last observed. An order that
   went `fully_filled` inside the gap stays `open` forever, so
   `lockedCommitments()` (`daemon.ts:599-614`) keeps excluding its collateral
   from selection — the daemon quietly loses access to its own inventory.
3. **Restart is not recovery.** `start()` re-opens live tails positioned at
   "now." Persisted orders are never reconciled against `GET /orders/:id`, so a
   restart across any transition produces the same desync permanently.
4. **A stuck automation latch.** Crash while a merge intent is in flight and
   `mergeInFlight = true` is what survives. `reduceOrder` gates every future
   intent on `!next.mergeInFlight` (`order-lifecycle.ts:194`), so that order
   never auto-merges again for the life of the database.

`listActiveOrders()` also carries a latent defect that would bite whoever
finally wires it up: its SQL terminal set is
`('cancelled','rejected','settlement_failed','closed')`, but `TERMINAL_PHASES`
in `types.ts:36-42` also contains `'expired'`. The query would therefore resume
expired orders as live. The test that appears to cover this
(`tests/store.test.ts:132-140`, *"excludes terminal phases"*) exercises only
`closed` and `rejected`, so neither the omission nor the divergence is caught.

**Failure scenario (regression test)**

Run a daemon against a CVM with the fills buffer sized small. Place an order and
let it take several partial fills. Stall the daemon's socket read long enough to
exceed the buffer; the server closes 1011. Resume. Assert — with today's code —
that `daemon.listNotes()` is missing the change notes minted during the stall,
that `balances()` under-reports by their sum, and that no error or event was
emitted. Then kill the process mid-merge and restart: assert the order's
`mergeInFlight` is still `true` and that no subsequent fill ever produces a
merge intent for it.

**Recommended fixes**

| Option | Description | Trade-off |
|---|---|---|
| **A — Wire `onResync` to a real backfill (recommended)** | Pass `onResync` on both listeners. On fire, pause placement, run the SDK recovery-v3 scan over the affected seed indices to re-derive missed openings, re-fetch each non-terminal order via `GET /orders/:id`, then resume. | The correct fix and the one every comment already assumes. Recovery v3 exists and self-verifies (§3), so this is wiring plus an orchestration routine, not new crypto. |
| **B — Reconcile on every `start()` as well** | Make the same routine the boot path: reconcile `listActiveOrders()` against the CVM, clear `mergeInFlight`, re-resolve phases. Fix the `'expired'` omission and extend the store test to all five terminal phases. | Should ship with A — a gap and a restart leave the daemon in the same state, and one routine serves both. |
| **C — Minimum viable: surface it** | Wire `onResync` to `emitError` + `pauseTrading` so the operator sees a hard stop instead of silent drift, and clear `mergeInFlight` at boot. | ~1 hour. Does not recover anything, but converts silent fund invisibility into a loud halt. Worth landing immediately even if A is scheduled later. |
| **D — Leave it** | Rejected. The daemon is the reference non-custodial client; "your notes silently stopped appearing" is the worst failure mode a non-custodial client can have. | — |

**Cost:** C ~1 hour. A + B together ~2–3 days: the reconcile routine (~1 day),
wiring and pause/resume ordering (~0.5 day), the `listActiveOrders` fix and test
widening (~1 hour), and a gap-injection integration test using the existing
`subscribeFn` seam (~1 day). **Not a lockstep change** — daemon-local.

---

### SW-14 — The private match witness is written in plaintext to `/tmp` on every batch

| | |
|---|---|
| **Severity** | Medium (**High** if the container overlay is not on the CVM's encrypted disk — see §5) |
| **Category** | Confidentiality at rest |

**Anchors**

- `crates/darknyx-tee/src/prover/snarkjs.rs:78-94` — `native_witness_wtns`
  creates `std::env::temp_dir().join("darknyx-wtns-<pid>-<seq>")` and writes
  `input.json` there.
- `crates/darknyx-tee/src/prover/ark_prover.rs:389-421` — what `input.json`
  contains, via `push_all_inputs`: **the private witnesses**
  `a_owner_commit`, `b_owner_commit`, `a_amount`, `b_amount`, `a_inner`,
  `b_inner`, `clearing_price`, `price_remainder`, plus every per-slot
  `base_amount`, `quote_amount`, `buyer_change_amt`, `seller_change_amt`,
  `buyer_fee_amt`, `seller_fee_amt`.
- `crates/darknyx-tee/src/prover/rapidsnark_prover.rs:68-93` — the native
  generator is the **default**; wasmer is the fallback taken only when the
  binary is missing, or when `DARKNYX_TEE_WITNESS=wasm` is set explicitly.
- `deploy/docker-compose.yaml:41-49, :177-182` — the compose mounts exactly one
  persistent volume, `darknyx_state:/var/lib/darknyx-tee`, documented as *"the
  CVM's LUKS-encrypted data disk (sealing key from dstack-kms)."* No `tmpfs`
  mount, no `TMPDIR`, no `VOLUME` in the Dockerfile — verified by grep across
  `Dockerfile`, `deploy/`, and `crates/darknyx-tee/src/`. Every other
  `tempfile` use in the crate is `#[cfg(test)]`.

**The problem**

`std::env::temp_dir()` with no `TMPDIR` set resolves to `/tmp` — the container's
writable overlay layer, which is **not** the encrypted named volume the compose
file goes out of its way to provision and document for state. On the default
production path the enclave therefore serializes, per settled batch, a JSON
document containing the plaintext trade amounts and both counterparties' owner
commitments, and writes it to that location.

These are exactly the values the amount-privacy work (P1b) was built to remove.
`leaf.rs:27-34` records the achievement: the leaf became commitment-only *"so
the leaf no longer hashes the plaintext amounts the old two-stage leaf did — and
they can leave the settle payload entirely."* The settle payload no longer
carries them and the leaf no longer binds them; the witness file re-materializes
all of them in plaintext, one file per batch.

Two aggravating details:

- The `Cleanup` guard (`snarkjs.rs:83-89`) removes the directory on every
  *return* path, including errors — but not on `SIGKILL`, a panic-abort, an OOM
  kill, or a CVM crash. A crash during the settle phase is a first-class
  scenario here; `docs/settlement-recovery-drill.md` exists specifically to
  exercise it, and it would leave the last batch's witness on disk.
- Even on the clean path the file is `unlink`ed, not shredded. Unlinked contents
  remain recoverable from the underlying block device until overwritten.

The threat model makes this matter more than it would elsewhere: the entire
reason the matcher runs inside TDX is that the *operator and host* are not
trusted with order contents. Any plaintext order data that reaches a
host-visible medium defeats that, regardless of who is expected to look.

**What I could not determine** — whether the container's overlay filesystem in a
dstack CVM is itself on encrypted storage. If it is, this is a defence-in-depth
and crash-residue issue (Medium as filed). If it is not, the enclave is leaking
plaintext trade amounts to the host on every batch and this is High. Listed in
§5; it needs a dstack disk-layout answer from the team, not more code reading.

**Failure scenario (regression test)**

Run a settle batch on a CVM with the native witness generator active. Before the
prove completes, snapshot `/tmp`: assert `darknyx-wtns-*/input.json` exists and
contains decimal amount strings. Then kill the container mid-settle
(`docs/settlement-recovery-drill.md`'s kill trigger) and assert the directory
survives the restart. Both should be impossible after the fix.

**Recommended fixes**

| Option | Description | Trade-off |
|---|---|---|
| **A — RAM-backed `tmpfs` for the witness path (recommended)** | Add a small `tmpfs` mount (say 256 MB) to the compose and point `TMPDIR` at it. Contents never reach any block device and vanish on crash and restart. | ~15 minutes, no code change, and it fixes the crash-residue case as well as the at-rest case. Needs sizing headroom for the N=16 `input.json`. |
| **B — Keep the witness off the filesystem entirely** | The `.wtns` bytes already never need a file: `serialize_wtns` produces them in memory and `groth16_prover_prove` takes a buffer (`rapidsnark_sys.rs:33-43`). Only the circom `--c` generator needs paths, because it is a subprocess. Feed it through `/dev/fd/N` or a named pipe, or link the generator in-process. | The strongest fix — no plaintext materialization at all — but it changes how the generator is invoked and needs revalidation of the ~8–10× native speedup the current path buys. |
| **C — Shred on cleanup** | Overwrite before unlink. | Rejected as a primary fix: it does nothing for the crash path, and on a copy-on-write or overlay filesystem overwriting in place is not guaranteed to hit the original blocks. |
| **D — Force `DARKNYX_TEE_WITNESS=wasm`** | The wasmer path keeps the witness in memory. | Rejected: gives up the measured 8–10× witness-generation speedup to fix something a `tmpfs` mount fixes for free. |

**Cost:** A is ~15 minutes plus a CVM spot-check confirming the mount is active
and the settle path still proves. B is ~1–2 days including re-benchmarking.
Ship A now regardless of whether B is scheduled. **Not a lockstep change.**

---

### SW-15 — Prover-backend output is turned into curve points without validation

| | |
|---|---|
| **Severity** | Info |
| **Category** | Defence in depth |

**Anchors:** `crates/darknyx-tee/src/prover/snarkjs.rs:52-58`, `:64-68`

```rust
let a = G1Affine::new_unchecked(fq_dec(&p.pi_a[0])?, fq_dec(&p.pi_a[1])?);
let b = G2Affine::new_unchecked(/* … */);
let c = G1Affine::new_unchecked(fq_dec(&p.pi_c[0])?, fq_dec(&p.pi_c[1])?);
```

`new_unchecked` skips both the on-curve check and the subgroup check, and
`fq_dec` uses `Fq::from_le_bytes_mod_order`, which silently reduces an
out-of-range value rather than rejecting it. The shape check at `:41-50` covers
array lengths only.

This is **not** a soundness hole. The input is the enclave's own rapidsnark or
icicle backend, not a remote party, and a malformed point fails on-chain in
`verify_match_batch`, so the system fails closed. The public inputs are
independently guarded on this path by `assert_public_inputs` (`:121-153`),
which compares both against the locally computed vector.

What it costs is *where* a backend defect surfaces: as `InvalidProof (6000)`
from Tx B after a ~2 s prove and a network round-trip, attributed to the
circuit, rather than as a prover error naming the backend. Given SW-07's lesson
— the boundary around a clean parser matters as much as the parser — validating
here is cheap insurance against a future backend swap (the icicle/GPU path in
particular) landing a subtle encoding bug that presents as a circuit failure.

**Fix.** Use the checked constructors, or call `is_on_curve()` +
`is_in_correct_subgroup_assuming_on_curve()` after construction, and have
`fq_dec` reject a value ≥ p instead of reducing it. Microseconds against a
multi-second prove. ~1 hour. **Not a lockstep change** — the wire format is
unchanged; only local acceptance tightens.

---

### SW-21 — An out-of-range `tree_id` passes intake and guarantees a settle-time lock failure

| | |
|---|---|
| **Severity** | Medium |
| **Category** | Griefing / settlement integrity |

**Anchors**

- `crates/darknyx-tee/src/api/orders.rs:127-135` — `tree_id` is deliberately
  **not** in the signed canonical body, with the reasoning stated inline:
  *"the proof's `merkle_root` + the shard's recent-roots ring already bind the
  note; a wrong `tree_id` only self-harms (lock fails)."*
- `packages/sdk/src/orders/canonical.ts:146-189` — confirms it: the canonical
  layout covers symbol, side, type, the four u64s, order id, note commitment,
  arrival nonce, viewing pubkey and session id. No `tree_id`.
- `crates/darknyx-tee/src/api/state.rs:530-534` — the accessor the intake check
  depends on:
  ```rust
  pub fn merkle_mirror(&self, tree_id: usize) -> &Arc<RwLock<MerkleMirror>> {
      self.merkle_mirrors.get(tree_id).unwrap_or(&self.merkle_mirrors[0])
  }
  ```
- `crates/darknyx-tee/src/api/orders.rs:566-575` — intake validates
  `lock_merkle_root` against **that** mirror.
- `crates/darknyx-tee/src/api/orders.rs:618`, `:664` — the raw `req.tree_id` is
  stored on the order's opening.
- `crates/darknyx-tee/src/settle/lock_note.rs:131` —
  `merkle_tree_pda(args.tree_id)` derives the on-chain account from that raw
  value at settle time.
- Intake performs **no** range check: `num_mirror_shards()` / `num_trees`
  appear nowhere in `orders.rs`.

**The problem**

The decision to leave `tree_id` unsigned is sound, and for an *in-range* wrong
value the stated justification holds exactly: a note in shard 2 declared as
shard 1 has its root checked against shard 1's recent-roots ring, which will not
contain it, and intake returns `stale_merkle_root`. I verified that path.

It breaks for an **out-of-range** value, because the accessor the check runs
through does not fail — it *saturates to shard 0*. With `num_trees = 4`, a
client that submits `tree_id = 200` for a note genuinely held in shard 0 has its
root checked against shard 0's ring, which contains it, and **intake accepts**.
The unvalidated 200 is then persisted on the opening and, when the order
matches, reaches `merkle_tree_pda(200)` — an address no `MerkleTree` account was
ever created at. `lock_note` fails, so the match fails.

The comment's "only self-harms" is therefore wrong twice over. The value is not
caught by the mechanism the comment relies on, and the harm is not confined to
the sender: settlement is a two-sided operation, so the counterparty's matched
leg fails with it. The counterparty is an *honest resting order* whose price and
size the griefer chose by construction — so this is a cheap, deterministic,
repeatable way to select a maker on the book and guarantee their fill does not
settle. They get their collateral released and have to re-quote; the attacker
pays nothing but a rejected order. For a venue whose value proposition is that
resting liquidity gets filled, that is a market-integrity problem rather than a
mere wasted round.

The cost per attempt is modest — the pipeline locks before it proves, so a
failed lock is caught before the ~2 s N=16 proof — but it is one failed lock
transaction and one destroyed maker fill, repeatable at the attacker's chosen
rate.

**Failure scenario (regression test)**

Deposit a note into shard 0 on a CVM configured with `num_trees > 1`. Place a
valid order for it with `tree_id = 200`. Assert — with today's code — that
intake **accepts**. Match it against a resting counterparty and assert the
settle round fails at `lock_note` and the counterparty's leg is released
unfilled. After the fix, assert intake rejects the placement outright.

**Recommended fixes**

| Option | Description | Trade-off |
|---|---|---|
| **A — Range-check `tree_id` at intake (recommended)** | In `prepare_order`, reject `req.tree_id as usize >= state.num_mirror_shards()` with a malformed/invalid-field error before any other work. | One line plus a test. Restores exactly the property the inline comment already claims, and does it at the cheapest point in the pipeline. |
| **B — Make the accessor fail instead of saturate** | Change `merkle_mirror` to return `Option<&…>` and force every caller to handle the miss. | Better long-term — a silent fallback to shard 0 is a hazard for *any* future caller, not just this one — but it touches every call site. Worth doing with A, not instead of it. |
| **C — Sign `tree_id`** | Add it to the canonical body. | Rejected. A **lockstep change** across `canonical.ts`, `order_canonical.rs`, the pinned parity fixtures, and the domain tag, to fix something a range check fixes for free. The original decision to leave it unsigned was correct. |

**Cost:** A ~1 hour including the test. B ~0.5 day. **A is not a lockstep
change**; C would be, which is the reason not to choose it.

---

### SW-32 — ICICLE's CUDA mode requires a confidential GPU but does not enforce one

| | |
|---|---|
| **Severity** | Medium — **pre-merge gate for PR #65**, not live today |
| **Category** | Confidentiality |

**Anchors**

- `crates/darknyx-tee/src/prover/icicle_prover.rs:114-120` — the device is read
  from `DARKNYX_TEE_ICICLE_DEVICE`, defaulted to `"CPU"`, and passed through
  **unvalidated**. The comment immediately above states the requirement:
  *"CUDA (Phase 2) requires a confidential-GPU TEE + the ICICLE CUDA backend in
  the image."*
- Grepping `crates/darknyx-tee/src/` and `deploy/` for any
  confidential-compute check — `nvtrust`, CC-mode, GPU attestation — returns
  **nothing** but that comment and a compose filename.
- `crates/darknyx-tee/src/prover/icicle_prover.rs:36` — the backend imports
  `native_witness_wtns`, so it also inherits **SW-14** unchanged.

**The problem**

The `.wtns` handed to `groth16_prove` encodes the complete private witness — the
per-slot amounts, both owner commitments, the clearing price — the same values
SW-14 covers on the filesystem. Proving on CUDA moves that witness into **GPU
device memory**. On a confidential-compute GPU that memory is encrypted and
attested; on an ordinary GPU it is plainly accessible to the host driver.

So the confidentiality guarantee TDX provides for CPU memory ends the moment the
witness crosses to the accelerator, and the only thing standing between "correct"
and "the operator can read every trade amount" is an environment variable set by
hand. The requirement is written down; it is simply not checked. Given that
CLAUDE.md §3.5 already records a GPU-window incident that cost most of a paid
24-hour H200, a hand-set env var is not the right place to hold this invariant.

This is **not exploitable today** — the feature sits behind the `icicle` cargo
feature, PR #65 is deliberately unmerged awaiting hardware, and the default is
`CPU`. That is exactly why it is worth filing now: the guard can land *with* the
feature rather than being retrofitted after a GPU is in production.

**Failure scenario (regression test)**

Set `DARKNYX_TEE_ICICLE_DEVICE=CUDA` on a host whose GPU is not in
confidential-compute mode and start the enclave. Assert — after the fix — that
boot fails closed with a named error rather than proving successfully.

**Fixes.** Require positive evidence of confidential compute before accepting
`CUDA`: query the driver's CC mode (or the platform's GPU attestation, which is
what `docs/gpu-tee-runbook.md` covers) at prover load, and refuse to start
otherwise. Fail closed — an unavailable check must reject CUDA, not fall through
to it. Pair with SW-14's `tmpfs` fix, which lands for all three backends at once
because they share `native_witness_wtns`. ~0.5 day, and it should be a merge
condition on PR #65. **Not a lockstep change.**

---

### SW-31 — A lagging server-side router drops fills and order updates silently

| | |
|---|---|
| **Severity** | Medium |
| **Category** | Silent data loss |

**Anchors**

- `crates/darknyx-tee/src/api/fills_router.rs:29-31` — on
  `RecvError::Lagged(skipped)` the fills router logs a warning and continues.
  The skipped `FillMemo`s are **never** passed to `route_fill`.
- `crates/darknyx-tee/src/api/order_router.rs:148-150` — identical handling for
  order-lifecycle updates: warn, continue, skipped updates never routed and
  never archived.
- **Contrast** `crates/darknyx-tee/src/api/stream.rs:449-464` — the *per-client*
  lag path does the right thing: closes with code **1011** and a reason naming
  the channel and the skipped count, *"reopen to resync"*.
- `crates/darknyx-tee/src/matcher/interval.rs:108-109` — both matcher
  broadcasts are capacity **1024**.

**The problem**

There are two places a message can be lost, and only one of them is handled.

The 1011 contract protects against a **slow client**: the client's own
per-account receiver lags, the socket closes, and the client knows to
re-synchronize. That mechanism is correct and well built.

It does nothing when the **server's own router** falls behind the matcher
broadcast, because the drop happens *upstream* of the per-account channels. The
client's socket stays perfectly healthy; it simply never receives messages that
were discarded before reaching its channel. There is no signal to drop —
the signal is never generated.

The consequences differ per channel and the fills one is worse:

- **Fills.** A `FillMemo` is the only in-band delivery of a continuation change
  note's opening — the amount and `inner_hash` needed to ever spend it (the same
  property that makes SW-11 serious). If the fills router lags, the memo is
  discarded before reaching the account's channel, so the client gets neither
  the memo nor a 1011. This is strictly worse than SW-11: there, a signal existed
  and the daemon ignored it; here no signal is produced at all, and the note is
  recoverable only by an out-of-band recovery-v3 scan nobody knows to run.
- **Order updates.** Skipped lifecycle updates are never routed, so orders that
  filled or expired can appear open to the client indefinitely. Worse, the same
  `Ok(...)` arm is what calls `archive_order_owner` (`order_router.rs:145`), so a
  terminal order whose update was skipped is **never archived** — its
  `order_owner` entry is never removed, converting a bounded map into a leak.

**Why the client's own gap detector does not save it.** `trading-ws-client.ts`
enforces connection-global sequence continuity and raises `onSequenceGap` on any
discontinuity — so transport loss *between the socket and the client* is caught.
Router loss is not, because `stream.rs:267-273` stamps `seq` at **socket-send
time**: a message discarded upstream never consumes a sequence number, so the
client sees a perfectly contiguous stream with messages simply missing from it.
The detector exists, is correct, and is watching the wrong boundary — which is
also what makes fix **A′** cheap.

**Reachability is not hypothetical, and SW-29 is one of its triggers.** Capacity
1024 is a burst limit, and bursts are structural here: a matcher tick emits up
to 16 matches' worth of updates plus fills, mass expiry lands on a slot
boundary, and **SW-29's cancel-on-disconnect sweep emits one update per swept
order** — potentially millions. The routers are single tasks doing async work per
message, and `archive_order_owner` alone takes four lock acquisitions per
terminal update (`state.rs:950-965`), which is precisely what makes the order
router fall behind under the burst SW-29 creates.

**Failure scenario (regression test)**

Drive the matcher broadcast past 1024 pending messages while a subscribed client
is connected and reading promptly. Assert — with today's code — that the client
receives neither the dropped fills nor any close frame, and that `order_owner`
retains entries for orders that reached a terminal state during the burst.

**Recommended fixes**

| Option | Description | Trade-off |
|---|---|---|
| **A — Propagate lag to affected clients** | On router `Lagged`, mark the routing state degraded and close every currently-subscribed session with the same 1011 resync frame the per-client path already sends. | Restores one consistent contract: *any* gap, wherever it occurred, tells the client to resynchronize. Reuses the existing frame and the client handling built for it. |
| **A′ — Move the sequence origin upstream (cheapest, recommended)** | The client **already enforces sequence continuity** — `sdk/orders/trading-ws-client.ts:203-218` rejects a frame with a missing/invalid `seq`, fires `onSequenceGap(expected, received)`, and errors on any discontinuity. It does not help today because `stream.rs:267-273` (`seq_json`) assigns `seq` **at socket-send time**, so a message the router dropped upstream never consumes a sequence number and the stream stays contiguous. Carry a per-channel origin counter from the matcher broadcast through the routers instead, so a dropped message leaves a visible hole. | **This makes the existing client-side detector work for free.** No new close-frame plumbing, no client change at all — the gap surfaces through machinery that already ships on both sides. Strictly less code than A, and it also catches router loss that A would miss if the session reconnects between the drop and the sweep. |
| **B — Make the routers cheaper so they lag later** | Batch `archive_order_owner`'s lock acquisitions (one write lock, not four) and hoist the terminal-archive work off the receive path. | Raises the threshold rather than handling the case. Worth doing — it also directly reduces SW-29's blast radius — but not a substitute for A. |
| **C — Increase the broadcast capacity** | Raise 1024. | Rejected as a fix: it moves the cliff without removing it, and a larger buffer means more messages lost when it is finally exceeded. |
| **D — Leave it** | Rejected. Silent loss of the only in-band delivery of a spendable note's opening is the same class of harm as SW-11, which is already filed as Medium. | — |

**Cost:** A ~1 day (the degraded-marking and the sweep of affected sessions), B
~0.5 day. Ship A; take B alongside the SW-29 work since it touches the same
locks. **Not a lockstep change.**

---

### SW-29 — A stream session retains every order id it ever placed, and sweeps them one matcher-lock at a time

| | |
|---|---|
| **Severity** | Medium |
| **Category** | Resource exhaustion / venue liveness |

**Anchors**

- `crates/darknyx-tee/src/api/stream.rs:231` — `session_orders: HashSet<String>`
  on the per-connection `Session`.
- Its **only** mutations, confirmed by exhaustive grep: insert on a successful
  place (`:748`), remove on cancel (`:774`), remove+insert on modify
  (`:801-802`). **Nothing removes an id when the order fills or expires.**
- `crates/darknyx-tee/src/api/stream.rs:403-417` — the disconnect sweep
  iterates the whole set, calling `state.matcher_for_order(oid)` and then
  `cancel_resting_unchecked` for each.
- `crates/darknyx-tee/src/api/orders.rs:890-909` — each of those calls takes
  `matcher.write().await` **before** discovering the order is already gone
  (`:900-902` returns `false` only after the lock is held).
- `packages/daemon/src/order-placer.ts:142` — the reference market-maker daemon
  sets `cancelOnDisconnect: true` by default.

**The problem**

Two independent defects that compose badly.

**Growth.** A resting order leaves the book by being cancelled, filled, or
expired. Only the first of those removes it from `session_orders`. So a session's
set accumulates every order it ever placed and never traded out of by explicit
cancel — which, for a market maker, is most of them. At a modest 50 orders/s
over a 12-hour session that is ~2.16 M entries; at roughly 80 bytes per entry
(32-char `String` plus `HashSet` slot overhead) that is on the order of 170 MB
of enclave memory for a *single* socket, and it scales with connection count.
This is the same unbounded-retention family as SW-08, and the same fix
discipline applies.

**The sweep.** The second defect is what raises this above a memory leak. On
disconnect the handler walks all N ids and acquires the **matcher write lock
once per id** — including for the overwhelming majority that filled hours ago
and will return `false`. That lock is the one the matcher tick needs to run.
So a long-lived client's disconnect converts into a burst of N write-lock
acquisitions that serializes against matching for **every other trader on the
venue**. A client does not need to be malicious to trigger it; a daemon
restarting after a 12-hour session is the ordinary case, and cancel-on-disconnect
is on by default precisely so that restart sweeps its quotes.

**Failure scenario (regression test)**

Open a stream session with `cancel_on_disconnect: true`. Place M orders and let
them all fill (or expire) rather than cancelling them. Assert `session_orders`
has shrunk to the still-resting set rather than M. Then close the socket and
assert the sweep acquires the matcher write lock a bounded number of times —
ideally once — not M times.

**Recommended fixes**

| Option | Description | Trade-off |
|---|---|---|
| **A — Prune on terminal transitions (recommended)** | The session already receives this account's `orders` channel, which carries `fully_filled` / `expired` / `cancelled`. Remove the id from `session_orders` when one of those arrives. | Fixes the growth at its source using a signal already flowing through the same task. No new plumbing. |
| **B — Sweep under one lock** | At disconnect, take the matcher write lock **once** and cancel all still-resting session orders inside that single critical section. | Fixes the venue-wide stall independently of A, and is the half that protects other traders. Do both: A bounds memory, B bounds the disconnect's blast radius. |
| **C — Cap the set** | Bound `session_orders` with insertion-ordered eviction. | Only if A proves awkward. Eviction would silently drop cancel-on-disconnect coverage for the evicted orders, which is a correctness regression — and note SW-04's warning about `keys().next()` arbitrary eviction if this is attempted. |

**Cost:** A ~0.5 day, B ~0.5 day, plus the two assertions above. **Not a
lockstep change.**

---

### SW-19 — The daemon's control plane is unauthenticated by default and has no browser-origin defences

| | |
|---|---|
| **Severity** | Medium |
| **Category** | Access control / CSRF |

**Anchors**

- `packages/daemon/bin/daemon.ts:287` —
  `controlToken: process.env.DARKNYX_DAEMON_CONTROL_TOKEN`. Unset by default,
  and nothing warns when it is absent.
- `packages/daemon/src/control-api.ts:88-93` — the auth block is inside
  `if (controlToken)`. No token configured ⇒ no authentication at all.
- `packages/daemon/src/control-api.ts:120-142` — the value-moving routes:
  `POST /orders` (places a real order spending a real note) and
  `POST /deposit` (moves funds on-chain).
- `packages/daemon/src/control-api.ts:68-73` — `readJson` parses the body
  regardless of `Content-Type`.
- `packages/daemon/src/control-api.ts:94-96` — no `Host`, `Origin`, or
  `Sec-Fetch-Site` check anywhere in `handle`.
- `packages/daemon/src/control-api.ts:163-186` — the `/tee/*` proxy, which
  attaches the operator's gateway bearer token (`tee-read.ts:38-40`).
- `packages/daemon/src/control-api.ts:18-19` — the guidance:
  *"bind to loopback. An optional bearer token (`controlToken`) gates every
  route — set it whenever the host isn't single-tenant."*

**The problem**

Binding to loopback stops other *hosts*. It does not stop the operator's own
browser, and that is the vector this design leaves open.

Any web page the operator visits can issue a cross-origin `POST` to
`http://127.0.0.1:8770`. A `POST` carrying `Content-Type: text/plain` (or
`application/x-www-form-urlencoded`) is a CORS **simple request**: the browser
sends it with no preflight. `readJson` never inspects `Content-Type` — it
concatenates the body and `JSON.parse`s it — so a body that is JSON but labelled
`text/plain` is accepted exactly as if it were a legitimate call. The attacker
cannot *read* the response without CORS, and does not need to: the side effect
has already happened. `POST /orders` and `POST /deposit` are both reachable this
way. (`DELETE /orders/:id` is not a simple method and would be preflighted, so
cancellation is not directly reachable — but placing orders and depositing are
the two that move value.)

With no `Host` header validation the stronger version also works: **DNS
rebinding**. An attacker domain that resolves to `127.0.0.1` makes the page
same-origin with the daemon, at which point every `GET` becomes readable too —
`/notes`, `/balances`, `/orders`, and the `/tee/*` proxy, which the daemon
services using the operator's own gateway credential. For a privacy protocol,
an attacker reading the operator's complete note set and order flow is a
first-class failure, not a secondary one.

The guidance in the module doc is what makes this likely to be encountered
rather than avoided. *"Set it whenever the host isn't single-tenant"* frames the
threat as **other users on the machine**, so an operator running the daemon on
their own workstation — a single-tenant host, and precisely the machine where a
browser is running — reads that line and correctly concludes they do not need a
token. The advice points away from the actual risk.

Whether this is reachable at all depends on deployment: a headless server with
no browser is unaffected. The code cannot assume that, and the documentation
currently encourages the configuration where it is.

**Failure scenario (regression test)**

Start the daemon with no `DARKNYX_DAEMON_CONTROL_TOKEN`. From a different
origin, issue
`fetch("http://127.0.0.1:8770/orders", { method: "POST", mode: "no-cors",
headers: { "content-type": "text/plain" }, body: JSON.stringify(validOrder) })`.
Assert — with today's code — that the order is placed. After the fix, assert it
is rejected on `Origin`/`Sec-Fetch-Site` before `mapPlace` is reached. Separately
assert a request with `Host: evil.example.com` is rejected.

**Recommended fixes**

| Option | Description | Trade-off |
|---|---|---|
| **A — Require the token, and generate one (recommended)** | Make `controlToken` mandatory. When unset, generate a random token at boot, write it `0600` next to the DB, and print the path — the pattern Jupyter and similar local servers use. The strategy reads it from the file. | Closes both CSRF and rebinding, because a cross-origin page cannot read the token file. No configuration burden: it works out of the box and is secure out of the box. |
| **B — Origin and Host allowlisting** | Reject any request carrying an `Origin`/`Referer` header, or `Sec-Fetch-Site` other than `same-origin`/`none`, and require `Host` to be `127.0.0.1:<port>` or `localhost:<port>`. | Cheap (~20 lines), and needed *in addition* to A as defence in depth. A browser cannot forge `Origin` or `Sec-Fetch-*`. Alone it is weaker than A, since a non-browser local process bypasses it entirely. |
| **C — Require a non-simple Content-Type** | Reject `POST`/`DELETE` unless `Content-Type: application/json`, which forces a preflight. | One line, and worth having, but it only closes the simple-request path — not rebinding. Not sufficient alone. |
| **D — Fix the documentation only** | Rewrite `:18-19` to name the browser vector. | Necessary regardless, but on its own it leaves a default-insecure server. |

**Cost:** A + B + C together ~0.5 day including tests, and they compose. Ship A
at minimum; the doc correction should go in the same change so the next reader
is not steered the same way. **Not a lockstep change** — daemon-local.

---

### SW-20 — Control-server input and error hygiene

| | |
|---|---|
| **Severity** | Low |
| **Category** | Input handling / information disclosure |

**Anchors**

- `packages/daemon/src/control-api.ts:68-73` — `readJson` accumulates
  `for await (const c of req) chunks.push(c)` with **no size limit**.
- `packages/daemon/src/control-api.ts:79-81` — every thrown error is returned
  to the caller as `{ error: err.message }`.
- `packages/daemon/src/control-api.ts:90` —
  `auth !== \`Bearer ${controlToken}\``, an ordinary string comparison.
- `packages/daemon/src/tee-read.ts:60-62` — `settlementStatus` interpolates
  `batchId` into the path **unencoded**, while its sibling `instrument`
  (`:54-58`) correctly uses `encodeURIComponent`. `control-api.ts:174-179`
  feeds it an arbitrary caller-controlled string.

**The problem**

Four small ones on the same server, all cheap to close:

1. **Unbounded body.** A local client can stream gigabytes into `readJson` and
   exhaust the daemon's memory before any handler runs. With SW-19's default
   (no token) this is unauthenticated.
2. **Error echo — SW-01's twin on the client side.** Any internal error message
   is returned verbatim. The daemon holds `DARKNYX_DAEMON_RPC_URL`, which
   carries the Helius API key as a query parameter, and a transport-level
   failure from the Solana client typically embeds the request URL in its
   message. That path ends here, in an HTTP response, from a server that by
   default has no authentication. This is the same defect class as SW-01 and
   deserves the same fix shape: a closed set of error labels at the boundary,
   with detail going to the log rather than the response.
3. **Non-constant-time token comparison.** `!==` on strings short-circuits at
   the first differing byte. Over loopback there is no network jitter to mask
   the signal, though HTTP-stack noise still dominates and this is not the
   practical way in. `crypto.timingSafeEqual` over equal-length buffers costs
   nothing and removes the question.
4. **Unencoded path parameter.** I could not construct an exploit:
   `new URL(req.url, …)` normalizes `../` out of `url.pathname` before the
   `/tee/` prefix test, and percent-encoded traversal stays encoded through both
   `URL` constructions, so it does not match a different axum route. But the
   sibling method encodes and this one does not, and the only thing standing
   between them is two layers of incidental normalization that nothing documents
   as load-bearing. That is exactly the shape that breaks when a router or a URL
   library is upgraded.

**Fixes.** Cap `readJson` (64 KB is generous for every route here) and reject
over-length with 413; return a fixed error label plus a correlation id and log
the detail; use `timingSafeEqual`; add `encodeURIComponent` to
`settlementStatus`. ~0.5 day for all four with tests, including one asserting no
`api-key` substring can appear in any control-API response body. **Not a
lockstep change.**

---

### SW-04 — `recent_order_owner` keeps the arbitrary-eviction pattern S-10 fixed elsewhere

| | |
|---|---|
| **Severity** | Low |
| **Category** | Delivery loss (not a leak) |

**Anchor:** `crates/darknyx-tee/src/api/state.rs:955-962`

```rust
if recent.len() >= RECENT_ORDER_OWNER_CAP && !recent.contains_key(order_id) {
    if let Some(evicted) = recent.keys().next().cloned() {   // HashMap order, not oldest
        recent.remove(&evicted);
    }
}
```

S-10 fixed exactly this pattern in `submission_replay.idempotency`. The same
construction survives in a second map in the same file, and was not covered by
that remediation.

**Impact.** `archive_order_owner` moves a terminal order's routing identity here
so a late `FillMemo` can still be delivered (`route_fill` falls back to `recent`
at `state.rs:1014-1020`). Evicting an arbitrary entry rather than the oldest
means a burst of terminal orders can drop a *still-live* entry before its memo
arrives; `route_fill` then returns `false` and the owner **silently never
receives that fill**.

This **fails closed** — there is no cross-account delivery, and the amounts
remain recoverable from the on-chain recovery-v3 ciphertext via
`recoverFillFromChain`. So it is a degradation of the low-latency path, not a
loss of funds or a confidentiality break.

**Fix.** Insertion-ordered eviction (or an LRU), matching the S-10 remediation.
~0.5 day including an eviction-order test. Worth auditing for any third instance
of the pattern in the same commit.

---

### SW-05 — `/transparency` raw account reads lack the owner + discriminator checks the vault applies

| | |
|---|---|
| **Severity** | Low |
| **Category** | Account validation |

**Anchors:** `crates/darknyx-tee/src/api/transparency.rs:96-132`, `:32-34`

`read_reserve` reads `OutstandingMint.outstanding` at a fixed byte offset and
the SPL `TokenAccount.amount` at another, with no check of `account.owner` and
no Anchor discriminator check. Contrast the vault's own raw read in
`tee_forced_settle_batched.rs:377-386`, where F-08 added exactly these checks
with the note that *"owner + length + PDA address are checked above, but the
discriminator is what proves the bytes are a `BatchValidityMarker`."*

**Assessment.** Currently **not exploitable**: both addresses are program-derived,
and an account at a vault PDA can only be assigned data by the vault. A
lamport-only transfer to the address yields empty data, which `read_u64_le`
rejects and reports as `stale`. So this is defence in depth, not a live hole.

It is worth closing anyway because the endpoint publishes a **solvency claim**.
The `stale` flag is well designed and documented (`transparency.rs:44-49`), but
it only fires on RPC error or short data — not on data that is the right length
and wrong type. Adding owner + discriminator validation makes `stale` mean what
its documentation says.

**Fix:** ~0.5 day. Check `acc.owner` against the vault program (for
`OutstandingMint`) and the SPL Token program (for the vault token account), plus
the Anchor discriminator on the former; set `stale` rather than failing the
endpoint.

---

### SW-10 — The daemon's order-id sequence is not recoverable, contradicting the store's stated guarantee

| | |
|---|---|
| **Severity** | Low |
| **Category** | Client recovery / replay hygiene |

**Anchors:** `packages/daemon/src/store.ts:12-15` (the claim), `:293-299`
(`maxSeedIndex`) · `packages/sdk/src/orders/build-order.ts:84`
(`deriveOrderId(masterSeed, n)`)

The store's module doc states:

> *"The chain + the keystore remain the durable roots of truth; this DB is a
> local cache that can be rebuilt by re-syncing chain recovery data from the
> master seed."*

That is true for **notes** — `recoverNotesFromChain` genuinely rebuilds them. It
is **false for `seed_index`**. Order ids are HD-derived as
`deriveOrderId(masterSeed, n)`, and orders never touch L1 (that is the core
privacy property), so `n` has no on-chain trace. `maxSeedIndex()` returns `-1`
on an empty table, so a daemon that loses its DB restarts the deterministic
sequence **from index 0** and re-derives ids it has already used.

**Consequences, in increasing order of awkwardness.** The TEE's idempotency map
rejects a reused id carrying a different body (`"order_id already used with a
different order"`), so placement fails closed — but the daemon has no way to know
how far to skip. After a CVM restart that map is empty, so the collision passes
silently and two distinct orders share an id, which breaks per-order fill routing
(`order_owner` is keyed by order-id hex) and the client's own reconciliation. And
it makes **S-07** materially more reachable: a captured cancel for order id *N*
becomes valid again the moment the daemon re-derives *N*.

**Fixes.** Either derive order ids from seed + a persisted random salt (so a
rebuilt daemon can never collide), or seed the starting index from a monotonic
external value (current slot) rather than 0, or — minimally — correct the module
doc and require an explicit operator-supplied starting index on a fresh DB. The
first is the only one that restores the documented guarantee. ~0.5–1 day.

---

### SW-12 — Auto-merge selects notes with a live on-chain `NoteLock`

| | |
|---|---|
| **Severity** | Low |
| **Category** | Wasted work / self-inflicted stall |

**Anchors**

- `packages/daemon/src/merge-runner.ts:122-131` — `isMergeable`. The doc comment
  says a note qualifies only when it *"isn't a re-locked rolling residual."* The
  code checks `o.phase !== "pending" && o.phase !== "open"`.
- `packages/daemon/src/merge-runner.ts:106-120` — `selectBatch` returns the
  **first** mint group with ≥ 2 members and slices the first 4.
- `programs/vault/src/instructions/merge.rs:110-124` — the on-chain backstop:
  every active input's `NoteLock` PDA must be absent or expired
  (`note_lock_is_live`), else `NoteAlreadyLocked`.

**The problem**

`pending_settlement` and `filled` are exactly the phases in which the order's
rolling residual is pinned by a **live** `NoteLock` on chain — the TEE has run
Tx A and Tx D is in flight. Neither is `pending` nor `open`, so `isMergeable`
returns true for the one note that provably cannot be merged. The comment
describes the intended rule correctly; the predicate implements a different one.

The vault holds. `merge.rs:110-124` (the N-04 / S-03 guard) rejects the
transaction, so this is **not** a double-spend and not a griefing vector against
the counterparty — that hole was closed. What is left is cost, borne entirely by
the daemon operator:

- A VALID_MERGE proof is generated client-side before the failure is knowable —
  seconds of CPU and, on a K=4 merge, the larger proving key.
- The transaction lands and fails, paying fees.
- Selection is **account-wide** (`merge-runner.ts:76-82`), so an unrelated
  order's fill can trigger a batch built around another order's locked note.
- `selectBatch` is deterministic first-group-wins, so every retry until lock
  expiry re-picks the same doomed batch. Other genuinely mergeable notes sitting
  in a later mint group are never reached — head-of-line blocking on
  consolidation for the duration of the lock.

Merges are edge-triggered (`order-lifecycle.ts:176-181`), so this is not a hot
loop, and locks expire, so it self-heals. That is what keeps it Low.

**Failure scenario (regression test)**

Store two same-mint notes, one belonging to an order in `pending_settlement`.
Trigger a merge from a *different* order's fill. Assert `selectBatch` excludes
the settling order's note. Against today's code it is included and first.

**Fixes.** Extend the exclusion to every phase in which a lock can be live —
cleanest is to invert it: mergeable only when the owning order is **terminal**
(`TERMINAL_PHASES.has(o.phase)`), which is what the comment describes and covers
`pending_settlement`/`filled` for free. Optionally also make `selectBatch` fall
through to the next mint group rather than committing to the first. ~2 hours
including the test. **Not a lockstep change.**

---

### SW-13 — `pendingChangeNotes` is decremented by an account-wide count

| | |
|---|---|
| **Severity** | Low |
| **Category** | Accounting / observability |

**Anchors**

- `packages/daemon/src/merge-runner.ts:75-104` — `run` ignores the intent's
  `noteCount`, scans the whole store, and returns `batch.length` — a count of
  notes that may belong to **any** orders.
- `packages/daemon/src/action-executor.ts:28-29` — that count becomes
  `merge-confirmed { consumed }`.
- `packages/daemon/src/lifecycle-engine.ts:113` — dispatched to
  `order.orderId`, the order that *triggered* the intent.
- `packages/daemon/src/order-lifecycle.ts:151-157` — decrements only that
  order's `pendingChangeNotes`.

**The problem**

`pendingChangeNotes` is documented (`types.ts:61-62`) as "residual change notes
awaiting consolidation" for *one* order, and it is incremented per-order by the
fills channel. But consolidation was deliberately made account-wide when v3
continuations reduced each order to a single rolling residual — the comment at
`merge-runner.ts:76-82` explains exactly why. The counter was never adjusted to
match.

So a merge of 4 notes belonging to 4 different orders subtracts 4 from the
trigger order and 0 from the other three. The counter drifts both ways:

- **Trigger order → under-counts** (clamped at 0 by the `Math.max`), so its own
  real residual becomes invisible to the automation.
- **Other orders → over-count permanently**, sitting at or above
  `mergeThreshold` forever. Every subsequent fill or quiescent transition on
  them fires a merge intent that is usually a no-op — and each no-op still costs
  a full `store.list()` scan plus an N+1 `getOrder` per note (see PF-22).

Nothing is lost — `selectBatch` reads the store, not the counter, so merges
still pick correct inputs. The damage is that the counter is reported to the
operator through `listOrders()` / the control API as a live figure, and it is
not one.

**Fixes.** Either (a) make the counter account-level, since the decision it
drives is account-level — move it off `ManagedOrder` into a single store-backed
figure derived from `SELECT COUNT(*) FROM notes WHERE order_id IS NOT NULL AND
leaf_index IS NOT NULL`, which also makes it self-correcting after a gap; or
(b) have `MergeRunner.run` return the consumed commitments and have the engine
fan out one `merge-confirmed` per affected order. (a) is simpler and removes a
persisted derived value that can drift. ~0.5 day. **Not a lockstep change.**

---

### SW-16 — The keystore's custody boundary is softer than its module doc states

| | |
|---|---|
| **Severity** | Low |
| **Category** | Custody boundary / key hygiene |

**Anchors**

- `packages/daemon/src/keystore.ts:2` — *"Keystore — the daemon's on-device
  crypto identity. **Keys NEVER leave here.**"*
- `packages/daemon/src/keystore.ts:106-108` — `get masterSeed(): Uint8Array`
  returns the live 64-byte root secret by reference.
- Its five consumers: `daemon.ts:459` (into `FillsListener` → the SDK),
  `build-place-request.ts:82, :86`, `merge-client.ts:62`,
  `daemon-client.ts:69`, `fills-listener.ts:44, :70`.
- `packages/daemon/src/keystore.ts:427-441` — `parseFile` validates the
  keystore's size and that it is a regular file. It never checks its mode.
- `packages/daemon/src/keystore.ts:389` — the writer is careful in the other
  direction: `fs.openSync(tempPath, "wx", 0o600)`, and
  `bin/keystore-init.ts:110-113` additionally `chmodSync(…, 0o600)` the seed
  backup and prints *"(encrypted, 0600)"*.
- `packages/daemon/bin/daemon.ts:104-107` — the passphrase arrives as
  `DARKNYX_DAEMON_KEYSTORE_PASSPHRASE`. Neither `saveKeystore` nor the init CLI
  imposes any length or entropy floor.

**The problem**

Three small gaps, all in the same direction, on the one file whose stated job is
to be the custody boundary.

1. **The headline claim is not true.** The master seed leaves the `Keystore`
   through a plain public getter at five call sites, including into SDK
   functions. The *security posture* is unchanged — everything stays in-process,
   and line 16 states the real boundary correctly (*"In memory the seed is
   plaintext (it has to be, to sign); the process is the trust boundary"*). But
   line 2 is the sentence a reader takes away, and it says the opposite of what
   the class does. Anyone auditing "where can the seed be observed?" by trusting
   that line will look in one file instead of six. This is the same
   comment-versus-code pattern as SW-07, SW-08, SW-10 and SW-12, and it is worth
   correcting precisely *because* the underlying design is fine.
2. **The reader is less careful than the writer.** Every write path sets `0600`
   and says so. The load path accepts any mode. A keystore restored from a
   backup, extracted from a tar, or copied with `cp` commonly lands `0644`, and
   nothing warns. OpenSSH refuses to use a group- or world-readable private key
   for exactly this reason. The file is encrypted, so this is not immediate
   exposure — it is the setup step for an offline attack.
3. **Which lands entirely on passphrase entropy.** The scrypt profile is strong
   (N=2^17, r=8 — `:206-214`), but a world-readable ciphertext plus a short
   passphrase is a tractable offline problem, and nothing anywhere enforces a
   minimum. The init CLI does enforce that the seed-backup and keystore
   passphrases *differ* (`bin/keystore-init.ts:63-65`), so the authors were
   thinking about this class of mistake; the strength floor is the piece that
   is missing.

**Failure scenario (regression test)**

`chmod 0644` a valid keystore and call `loadKeystore` — it succeeds silently.
Assert, after the fix, that it throws or warns. Separately, assert
`saveKeystore` rejects a passphrase below the chosen floor.

**Fixes.** All small and independent:
(a) correct line 2 to say what line 16 already says, or narrow the getter — the
cleanest version replaces `get masterSeed()` with the specific derivations each
consumer needs (`deriveFillKeys()`, `orderId(index)`), so the raw seed genuinely
does not leave;
(b) in `parseFile`, reject or loudly warn on `stat.mode & 0o077` on POSIX hosts;
(c) impose a minimum passphrase length in `saveKeystore` — enforced at the seal,
not only in the CLI, so a programmatic caller cannot bypass it.
~0.5 day for all three including tests. **Not a lockstep change.**

Also noted, not filed: `parseFile` stats and reads by path in two separate
syscalls (`:428`, `:436`), a TOCTOU window. Exploiting it needs write access to
the keystore directory, at which point the file can simply be replaced — so the
window grants nothing new. Using a single `open` + `fstat` + read would close it
for free if the file is touched anyway.

---

### SW-17 — The attestation client reads the untrusted gateway with no timeout, size bound, or field validation

| | |
|---|---|
| **Severity** | Low |
| **Category** | Untrusted input handling / availability |

**Anchors**

- `packages/daemon/src/attestation.ts:82-102` — `getJson` issues
  `fetchImpl(url, { headers })` with **no `AbortSignal`**, then `res.json()`
  with **no size limit**. The default `fetchImpl` is Node's global `fetch`,
  which has no default timeout.
- `packages/daemon/src/attestation.ts:120-122` — `fetchInfo` *does* validate:
  `boot_session_id` must match `/^[0-9a-fA-F]{64}$/`.
- `packages/daemon/src/attestation.ts:144-155` — `fetchAttestation` validates
  **nothing**. `quote`, `event_log`, `report_data` and `tee_pubkey` are returned
  as whatever the JSON contained, including `undefined` for a missing field.
- `packages/daemon/src/attestation.ts:50-51, :221` — `fromHex(att.quote)` calls
  `h.replace(…)` on that value.
- `packages/daemon/src/daemon.ts:421` — `start()` awaits `verifyAttestationFn`.

**The problem**

This module's entire premise, stated at `:4-6`, is that the gateway *"is not a
genuine enclave until proven otherwise — not a normal server that fabricates
JSON."* It is the one place in the daemon where the peer is explicitly
adversarial. It is also the one place with no input bounds.

- **No timeout.** A gateway that accepts the connection and then stalls makes
  `verifyAttestation` never settle. `daemon.start()` awaits it, so the daemon
  hangs at boot — no error, no diagnostic, indistinguishable from a hang. This
  is technically fail-closed (it never trades) but it is the worst possible
  operational presentation of that.
- **No size bound.** `res.json()` will buffer whatever is sent. `quote` and
  `event_log` are gateway-chosen strings of arbitrary length, and
  `parseEventLog` → `replayEventLogRtmr` then walks and hashes every entry a
  large log contains. Compare `keystore.ts:218-219`, which bounds a *local,
  operator-owned* file to 32 KB; the actively hostile input has no bound at all.
- **No field validation, asymmetrically.** `fetchInfo` checks its one hex field.
  `fetchAttestation` checks none of its four. A response omitting `quote`
  produces a raw `TypeError` from `h.replace` rather than an
  `AttestationError`, so it escapes the typed `AttestationFailure` taxonomy the
  daemon's error handling and pause logic key on.

None of this lets a gateway *pass* attestation — the DCAP verification and the
`report_data` binding are unaffected, which is why this is Low rather than
higher. It is availability and diagnosability, on a module that already assumes
the peer is malicious.

**Failure scenario (regression test)**

Inject a `fetchImpl` that never resolves; assert `verifyAttestation` rejects
within the configured timeout instead of hanging. Inject one returning a
100 MB `event_log`; assert it is rejected on size. Inject one returning
`{ event_log, report_data, tee_pubkey }` with no `quote`; assert the rejection
is an `AttestationError` with a typed failure code, not a `TypeError`.

**Fixes.** Give `getJson` an `AbortSignal.timeout(...)` (a few seconds is
generous for both endpoints) and a `Content-Length` / streamed byte cap, and
validate `fetchAttestation`'s four fields the way `fetchInfo` already validates
its one — `quote` and `report_data` as even-length hex, `report_data` as exactly
64 bytes, `tee_pubkey` as base58, `event_log` as a non-empty string within the
cap. ~0.5 day including the tests. **Not a lockstep change.**

---

### SW-18 — `bootSessionId` rides inside the verified result but is not quote-bound

| | |
|---|---|
| **Severity** | Info |
| **Category** | Attestation scope |

**Anchors**

- `crates/darknyx-tee/src/api/attestation.rs:11-12, :105-107` — the quote's
  `report_data` is exactly `nonce ‖ SHA-256(pk_0 ‖ … ‖ pk_{K-1})`. The boot
  session is not part of it.
- `packages/daemon/src/attestation.ts:189, :248` — `bootSessionId` is read from
  `/info`, a separate unauthenticated-to-the-quote HTTP response, and placed in
  `AttestationResult` — the value returned with `dcapVerified: true`.
- `packages/daemon/src/daemon.ts:429` — `this.bootSessionId =
  fromHex(this.attestationResult.bootSessionId)`, subsequently signed into every
  order and cancel (`daemon.ts:646-648`, the S-07 scoping).

**The problem**

`AttestationResult` presents a single verified identity, and every other field in
it is either DCAP-derived (`mrtd` from the verified report) or quote-bound (the
K-shard `teePubkeys`, via `teeKeySetBytes` → `report_data` — done properly, see
§3). `bootSessionId` is neither. A malicious gateway picks it freely.

The exploitation ceiling is low, and worth stating so nobody over-reads this:
S-07 exists so a captured cancel body cannot kill a re-placed order after a
restart, and the TEE validates the session id at intake. A gateway that serves a
wrong session gets every order rejected — a denial of service it could achieve
by simply not answering. It cannot produce *acceptance* of a stale session,
because that requires the TEE to accept it, and it will not.

What is worth recording is the structural point: **S-07's session scoping rests
on a field the attestation does not cover.** Today the enclave is the only party
that can validate it, so the property holds. It would stop holding if any future
check moved client-side, or if a client ever used `bootSessionId` to decide
whether the enclave had restarted.

**Fix.** Either include the boot session in the attested surface — extend the
`report_data` right half to `SHA-256(signer set ‖ boot_session_id)`, a lockstep
change across `api/attestation.rs`, `verify-core.ts` and any other client — or,
much cheaper, document in `AttestationResult` that `bootSessionId` is
transport-supplied and not covered by `dcapVerified`. The cheap option is
correct unless the threat model changes; the field's current placement is what
makes it look otherwise. ~1 hour for the doc fix.

---

### SW-22 — The master-seed backup uses a weaker KDF than the keystore holding the same seed

| | |
|---|---|
| **Severity** | Low |
| **Category** | Key derivation strength |

**Anchors**

- `packages/sdk/src/keys/master-seed-backup.ts:22` —
  `const KDF = { name: "scrypt", n: 16_384, r: 8, p: 1 }` → **N = 2¹⁴**.
- `packages/daemon/src/keystore.ts:206-214` — the keystore's v2 profile:
  **N = 2¹⁷**, with `maxmem` raised to 256 MB to accommodate it.
- `packages/daemon/src/keystore.ts:200-205` — N = 2¹⁴ is what the keystore
  calls `LEGACY_SCRYPT`, retained only to read and migrate v1 files.

**The problem**

Both artifacts protect the **same secret** — the 64-byte master seed from which
every spending key, viewing key, trading key and blinding factor derives. The
daemon keystore was deliberately hardened to N = 2¹⁷ and treats N = 2¹⁴ as
legacy to be migrated away from. The portable backup still uses N = 2¹⁴, an 8×
smaller work factor.

The exposure profile runs the wrong way. The keystore is an operational file on
a running host. The backup is the artifact explicitly designed to be *portable
and offline* — the copy that ends up on a USB stick, in a password manager, in
cloud storage, or in a printout's QR code, and that survives for the lifetime of
the account. It is the copy an attacker is most likely to obtain and can attack
entirely offline, at leisure, with no rate limit. It has the weaker KDF.

This is Low rather than higher because scrypt at N = 2¹⁴ is not broken, and the
12-character passphrase floor (`:25`, `:45-51`) genuinely raises the bar. But
the asymmetry is backwards, and the repo already contains the decision that
N = 2¹⁴ is not the parameter to use for this secret.

**Fixes.** Raise the backup to N = 2¹⁷ behind a `version: 3` envelope, keeping
v2 readable for existing backups exactly as the keystore keeps v1 readable —
the migration pattern is already implemented in `keystore.ts:547-563` and can be
copied. Note the parse path pins KDF parameters by exact match (`:132-144`), so
a version bump is the correct mechanism rather than making `n` variable; keeping
the parameters non-negotiable is the right call and should survive the change.
~0.5 day. **Not a lockstep change** — the backup format is client-only.

Worth pairing with **SW-16(c)**: this file enforces a passphrase floor on both
export *and* import, which is exactly what the daemon keystore lacks. The fix
for that finding already exists here and can be lifted directly.

---

### SW-23 — TypeScript reduces out-of-range Poseidon inputs where Rust rejects them

| | |
|---|---|
| **Severity** | Info |
| **Category** | Cross-language contract |

**Anchors**

- `packages/sdk/src/utxo/note.ts:32-40` — `getPoseidon` wraps every input in
  `p.F.e(i)`, which reduces modulo the field rather than rejecting.
- `packages/sdk/src/utxo/note.ts:91-115` — `noteCommitmentV2` and `nullifierV2`
  pass `amount`, `ownerCommitment` and `innerHash` straight through, unchecked.
- `packages/sdk/src/utxo/match-output.ts:14-19` — `bytesToBigIntBE` checks the
  *length* is 32 but not the *value* against the modulus.
- `packages/sdk/src/keys/key-generators.ts:211-214` — `bn254ToBE32` **does**
  range-check, but only on the way *out*.
- Rust counterpart: `light-poseidon`'s `hash_bytes_be` rejects a value ≥ the
  modulus, surfacing as `PoseidonFailed (6030)`.

**The problem**

CLAUDE.md §7.2 names this exact hazard — *"Raw `[0xFFu8; 32]` passes through
almost everything WITHOUT an obvious error"* — and calls it the silent killer.
The Rust side is the one that fails loudly; the TypeScript side silently reduces
and produces a commitment for a *different* value than the caller supplied.

No live exploit path: every value that actually reaches these functions is
either a u64 amount or a Poseidon output, both in range by construction, and the
one place hostile bytes could enter — `recover.ts` decrypting a TEE-supplied
blob — recomputes the commitment and compares it against the on-chain value, so
it fails closed.

What makes it worth recording is that the two languages disagree about *where a
bug surfaces*. A future caller passing an out-of-range value gets a wrong-but-
plausible commitment from TypeScript and a hard error from Rust — so the parity
tests that pin these contracts would pass on valid vectors while the languages
diverge on invalid ones, which is precisely the gap the parity suite is meant to
close.

**Fix.** Range-check inputs in `poseidonHashBytesBE` (and `bytesToBigIntBE`)
against `BN254_R`, throwing rather than reducing, so both languages fail at the
same input. Add a parity test asserting *both* implementations reject the same
out-of-range vector — a negative parity case, which the suite currently has none
of. ~2 hours. **Lockstep-adjacent**: no wire format changes, but the parity
suite should gain the negative case in the same commit.

---

### SW-24 — The SDK's leaf-index decoder repeats SW-07's unscoped-event pattern

| | |
|---|---|
| **Severity** | Low |
| **Category** | Data integrity |

**Anchors**

- `packages/sdk/src/utxo/leaf-index.ts:54-80` — `noteCreatedFromLogs` iterates
  `logs`, takes any line starting with `"Program data: "`, base64-decodes it,
  matches the 8-byte Anchor event discriminator, and returns the `tree_id` and
  `leaf_index` it finds. **No program attribution.**
- `packages/sdk/src/utxo/leaf-index.ts:88-110` — `leafIndexFromLogs` is the same
  loop, generalized over an arbitrary discriminator.
- **Third site, found in Batch Z:** `packages/sdk/src/fills/chain-history.ts:77-80`
  runs the identical unscoped `"Program data: "` scan — and this one feeds
  **`cold-recovery.ts`**, the seed-plus-chain disaster-recovery path a user runs
  precisely when their local state is already gone. Its transactions come from
  `getSignaturesForAddress(programId)`, the same address-indexed source SW-07
  exploits, so a forged event in a transaction that merely *references* the
  vault is injectable. Note the same file scopes **instruction** data correctly
  (`:208-218` checks `keys[ci.programIdIndex].equals(programId)`), so the
  author applied the check in one decoder and not its neighbour — which is the
  clearest possible argument for fixing the pattern rather than the instance.
- Compare `crates/darknyx-tee/src/merkle/events.rs:181-250` — the identical
  construction, which is **SW-07 (Critical)**.

**The problem**

`Program data:` is the output of `sol_log_data`, callable by any program;
Anchor's `emit!` is a thin wrapper. Matching only on the event discriminator
means the decoder will accept a `NoteCreated` emitted by anything.

The client-side severity is far below SW-07's, and the reason is worth stating
precisely rather than assuming symmetry. The enclave reads *address-indexed
history* — transactions it did not build, which merely reference the vault — so
an attacker can inject one for the price of a transaction, and the corrupted
mirror is shared, permanent, and load-bearing. The SDK instead reads the logs of
**its own just-submitted transaction**, which it constructed. The realistic
attacker is therefore the **RPC endpoint**, which can return arbitrary
`logMessages` for the client's signature.

What that buys is bounded. A forged `leaf_index` is stored against the client's
own note; the next spend builds a Merkle witness at that index, the path does
not fold to a root containing the commitment, and VALID_SPEND simply fails to
prove. The note becomes unspendable-looking until re-read through an honest RPC.
It fails closed, it is self-inflicted, and it is recoverable — a nuisance, not a
loss.

It is worth fixing anyway for one reason: it is the *same decoder pattern*, and
the SDK has the vault program id available at every call site. When SW-07's fix
lands, the natural scope of that work is "make event decoding program-scoped,"
and doing it in one language while leaving the identical construction in the
other is how a pattern survives a remediation. A fuzz/property target written
for SW-07 (see `fuzzing-plan.md` Tier A) applies here unchanged.

**Failure scenario (regression test)**

Feed `noteCreatedFromLogs` a log array containing a well-formed `NoteCreated`
payload preceded by a `Program <foreign_id> invoke [1]` line. Assert it is
ignored once the decoder is scoped. Today it is accepted.

**Fix.** Track the `Program <id> invoke` / `Program <id> success` nesting the way
the SW-07 fix must, and accept only events emitted inside a vault-program frame;
pass the program id into all three functions — `chain-history.ts` already has it
in scope for its instruction-data path, so the plumbing exists. Alternatively, read the leaf index from
the vault account state rather than from logs — `SettlementTracker` already
prefers `/tree/inclusion` over a log-derived prediction for exactly this class of
reason (`settlement-tracker.ts:12-16`). ~0.5 day, and it should ship **with**
SW-07 so the pattern is closed in both languages at once. **Not a lockstep
change** in the byte-equality sense.

---

### SW-26 — Only one of the SDK's three prove paths validates its prover's public signals

| | |
|---|---|
| **Severity** | Low |
| **Category** | Diagnosability / defence in depth |

**Anchors**

- `packages/sdk/src/zk/valid-deposit-prover.ts:62-70` — the deposit prover
  compares `publicInputsBE` against a locally computed `expected`, by length and
  element-wise, and throws on any difference.
- `packages/sdk/src/utxo/deposit.ts:164-171` — the deposit *builder* repeats the
  same check independently: *"VALID_DEPOSIT prover returned unexpected public
  inputs."* The path is guarded twice.
- `packages/sdk/src/utxo/merge.ts` — **no `publicInputs` reference at all.**
- `packages/sdk/src/utxo/withdraw.ts` — likewise none.
- `packages/daemon/src/merge-prover.ts:68-82` — the daemon's merge prover
  returns `publicInputsBE` straight from `formatGroth16ForOnChain` with no
  cross-check against what the instruction will carry.
- Contrast the enclave, which guards *both* of its backends:
  `prover/ark_prover.rs:249-270` compares the circuit's own public inputs
  against the off-circuit vector by count and per index, and
  `prover/snarkjs.rs:121-153` (`assert_public_inputs`) does the same for the
  native path.

**The problem**

The on-chain verifier builds its public-input vector from the **instruction
arguments**, not from anything the proof carries. So if a witness-assembly bug
makes the prover's public signals disagree with the arguments the SDK is about
to send, the transaction fails closed — no soundness issue. What differs is
*where the failure appears and what it looks like*.

The deposit path catches it locally, immediately, with a message naming the
cause. The merge and withdraw paths do not, so the same class of bug costs a
full client-side snarkjs proof (seconds), a submitted transaction and its fees,
and then surfaces as **`InvalidProof (6000)`**.

That error code is the problem. CLAUDE.md §5 — the section that exists because
this already broke the deployed program once — teaches that `InvalidProof (6000)`
means a circuit/VK lockstep failure: *"the program compiles fine but rejects
every proof the new circuit makes, surfacing at runtime as `InvalidProof (6000)`,
not 'you forgot the VK.'"* A witness-assembly bug in `merge-prover.ts` therefore
presents **identically to the repo's most-documented foot-gun**, sending whoever
debugs it to regenerate `.zkey` and `vk_valid_merge_k4.rs` for a problem that is
neither. The deposit path already demonstrates the fix.

**Failure scenario (regression test)**

Inject a merge prover that returns correct proof points but one altered public
signal. Assert the SDK rejects locally, before building the instruction, with a
message naming the prover — mirroring
`deposit.ts:170`'s. Today the transaction is built, submitted, and rejected
on-chain.

**Fix.** Lift the deposit pattern into `merge.ts` and `withdraw.ts`: compute the
expected public-input vector from the same values already being passed to the
instruction builder, and compare before building. The values are all in hand at
that point, so it is a dozen lines per path. Better still, factor the check into
a shared helper so a fourth prove path cannot be added without it. ~0.5 day.
**Not a lockstep change** — no wire format moves; the check is purely local.

Note this is the client-side counterpart of **SW-15** (the enclave not
validating curve points from its own backend). Same principle in both: work done
by a prover should be checked before it is paid for on-chain.

---

### SW-27 — The loadgen's latency histogram mixes accepted and rejected submits

| | |
|---|---|
| **Severity** | Low — **test tooling, not production** |
| **Category** | Measurement fidelity |

> **Scope note.** `darknyx-tee-loadgen` is a test harness, not shipped code. It
> was audited against one question only — *does it measure honestly?* — because
> a load generator that overstates performance is worse than no measurement: it
> produces false confidence in exactly the numbers `throughput-roadmap.md`
> reasons against. Everything else (credential handling, DoS, input validation)
> is deliberately out of scope for a tool we point at our own CVM.

**Anchors**

- `crates/darknyx-tee-loadgen/src/trader.rs:158`, `:185-186` — `run_submit`
  captures `elapsed_us` and then calls `record_submit_latency_us` **for every
  outcome**: `Ok`, `Status4xx`, `RateLimited`, `Status5xx` and `NetworkError`
  all land in the same histogram.
- `crates/darknyx-tee-loadgen/src/report.rs:77-86` — the report's `Latency (ms)`
  table prints `submit` P50/P95/P99/P99.9/max with no outcome qualifier.

**The problem**

An intake rejection is fast — it fails before any matcher work — so a run where
most submits are rejected reports a *better* latency distribution than a healthy
one. CLAUDE.md §3.2 documents the exact scenario in which this happens, in bold:
*"If you run the loadgen against a real-mint CVM you get 100% 4xx"* (and
vice-versa). That is not a hypothetical misconfiguration; it is the mint-regime
trap the runbook warns about because it has already cost a deploy.

In that state the report shows a healthy-looking P99 next to a 0% success rate.
The success-rate table is adjacent and correct, so the mistake is *discoverable*
— but the two numbers are presented as peers, and a reader scanning for "what's
our P99" gets a figure that measures rejection speed.

`NetworkError` compounds it from the other direction: a connection failure's
elapsed time is a timeout, not a service time, and it inflates the tail.

**Secondary, worth a footnote rather than a fix:** each trader is paced by
`tokio::time::interval` with `MissedTickBehavior::Delay` (`trader.rs:75-76`), so
when the server slows the harness issues *fewer* requests and the histogram
never sees the ones it skipped — textbook coordinated omission, meaning the tail
is optimistic whenever the run falls behind its target rate. The report already
makes this detectable by printing target rate, actual rate **and the
achieved/target ratio** (`report.rs:52-66`), which is genuinely the right
instinct; the latency table just doesn't reference it.

**Fix (small, matches the tool's level of care)**

1. Record latency **only for `SubmitOutcome::Ok`** in the headline stream, or
   keep per-outcome histograms and print accepted/rejected as separate rows.
   ~30 minutes, and it is the change that matters.
2. Add one footnote under the latency table: percentiles cover issued requests
   only, so treat them as optimistic when achieved/target is below ~95%.
3. Optional: note in the report header that synthetic orders carry stub proofs,
   so the run exercises intake and matcher paging but **not** settlement. That
   is already in CLAUDE.md §3.4, but the markdown report is the artifact that
   gets pasted into a perf discussion, and it currently doesn't say so.

---

### SW-28 — `run_batch`'s chaining path can emit a zero-sentinel collateral note

| | |
|---|---|
| **Severity** | Low — latent; not on the production path |
| **Category** | Latent correctness / stale documentation |

**Anchors**

- `crates/darkpool-matcher/src/algorithm.rs:505-517` — after a partial fill the
  matcher writes the **zero sentinel** into the snapshot's collateral note:
  `note_e_commitment = [0u8; 32]`, with the reasoning that real change-note
  commitments *"are NOT derivable here"* and the settle assembler overwrites
  them. *"Emitting the zero sentinel makes 'not yet derived' explicit and
  unusable."*
- `crates/darkpool-matcher/src/algorithm.rs:584-592` — on relock the sentinel is
  assigned into the live snapshot: `bids[bi].collateral_note = note_e_commitment;`
- `crates/darkpool-matcher/src/algorithm.rs:603-612` — in the **non**
  `single_fill_per_order` branch, a partially-filled order **stays** at its
  index to match the next counterparty.
- `crates/darkpool-matcher/src/algorithm.rs:551-552` — the next `MatchPair`
  therefore takes `note_buyer: bids[bi].collateral_note`, i.e. `[0u8; 32]`.
- `crates/darkpool-matcher/src/lib.rs:267-283` — `run_batch`, which is `pub`,
  passes `single_fill_per_order: false`.

**The problem**

The sentinel is deliberately "explicit and unusable," and in the production path
it is never used: `PreparedMatchTick::next_page` (`lib.rs:163-176`) passes
`true`, so both pointers advance and a relocked order is not re-matched within
the batch. I confirmed that is the path the enclave takes.

But the chaining branch keeps the relocked order in play, and it has just had
its collateral note replaced by the sentinel. A second fill in the same batch
therefore produces a `MatchPair` whose `note_buyer` (or `note_seller`) is 32
zero bytes — a commitment no opening exists for and the tree can never contain.
The value that was made deliberately unusable is then consumed as a match input.

Impact today is confined to whoever calls `run_batch`, which appears to be tests
and legacy callers. What raises it above a curiosity is the documentation around
it:

- `crates/darknyx-tee/src/matcher/interval.rs:7` and `:14` both state that the
  tick *"Calls `darkpool_matcher::run_batch(...)`"*. It does not — it goes
  through `PreparedMatchTick::next_page`. A reader auditing the matcher from the
  enclave inward lands on the wrong function and reasons about chaining
  semantics the enclave never uses.
- CLAUDE.md names *"`run_batch`/`run_batch_capped`"* as the matcher's single
  source of truth, which reads as an endorsement of both entry points.

So the trap is set for the next person to wire up the "simple" wrapper.

**Failure scenario (regression test)**

Build a book where one bid can be partially filled by two asks at `P*`. Call
`run_batch` (uncapped). Assert — with today's code — that the second emitted
`MatchPair` carries `note_buyer == [0u8; 32]`. There is no such test today.

**Fixes.** Cheapest and clearest: make the chaining branch refuse to re-match an
order whose `collateral_note` is the sentinel — one guard, and it converts a
silently-invalid match into no match. Better, if no caller needs chaining: delete
`run_batch`'s `false` and have it delegate with `true` like every real caller,
or remove the wrapper entirely. Either way, correct `interval.rs:7,14` to name
`PreparedMatchTick::next_page`. ~2 hours including the regression test.
**Not a lockstep change.**

---

### SW-34 — The settlement benchmark has no production data path, and a latent metric trap

| | |
|---|---|
| **Severity** | Info — **test tooling**, per SW-27's scope note |
| **Category** | Measurement fidelity |

**Anchors**

- `crates/darknyx-tee-loadgen/src/lib.rs:32` — `pub mod settlement_benchmark;`
- `crates/darknyx-tee-loadgen/src/settlement_benchmark.rs:165-300` —
  `render_markdown` produces throughput, offered-order rate, batch packing,
  slot co-inclusion, rebroadcasts-per-confirmed and client proof rate.
- `:404-411` — the **only** construction of a `BatchMetric` anywhere in the
  crate is the `batch()` test fixture.
- `real_settle/`, `run.rs` and `main.rs` contain **no** reference to
  `BatchMetric`, `SettlementBenchmark`, or the module at all.

**The problem**

The module compiles, its unit tests pass, and it renders a polished benchmark
report — from data nothing populates. Someone looking for "the settlement
benchmark" finds a module named exactly that, producing exactly the tables the
throughput work reasons about, and can reasonably conclude that running the
loadgen produces them. CI gives no contrary signal, because the tests exercise
the renderer against synthetic fixtures and pass.

That alone is a documentation-vs-reality gap. The sharper risk is what happens
when it *is* wired, because `padded_slots` carries a semantic trap:

```rust
let packing = 100.0 * active as f64 / padded as f64;
```

This is correct only if `padded_slots` means **total slots after padding** (16).
The single populated example — the test fixture at `:411`, `padded_slots: 16`
with `active_matches: 1` — implies that reading, giving a correct 6.25%. But the
field *name* reads as "slots that are padding," and under that reading the
metric inverts catastrophically: a **fully packed** 16/16 batch has
`padded == 0` and hits the guard at `:184`, reporting **0% packing**; a 12/16
batch reports **300%**. The name and the arithmetic disagree, and one test
fixture is the only disambiguating evidence.

A benchmark that silently reports a full batch as 0%-packed is worse than no
benchmark — and `docs/throughput-roadmap.md` reasons against exactly this
number.

**Fix.** Either wire it to `real_settle/` so it reports real batches, or delete
it — a tested renderer with no data source is a trap either way. If wiring:
rename `padded_slots` to `total_slots` (or store `padding_slots` and compute
`active / (active + padding)`), and add an assertion that
`active_matches <= padded_slots`, which would have made the ambiguity fail loudly
the first time it was populated wrongly. ~2 hours.

---

### SW-33 — The debug endpoints' exclusion from production rests on `resolver = "2"` alone

| | |
|---|---|
| **Severity** | Info — the property holds today |
| **Category** | Build invariant / undocumented dependency |

**Anchors**

- `crates/darknyx-tee/src/api/debug.rs:1-9` — `POST /__debug/oracle/seed` writes
  a `CachedPrice` straight into the `OracleCache`, bypassing Hermes and VAA
  verification entirely. The module doc is accurate about the stakes: *"The
  feature MUST be off in production builds — there is no auth on these routes,
  so a feature-on production deploy would allow anyone reaching the HTTP port to
  rewrite the matcher's price view."*
- `crates/darknyx-tee/Cargo.toml:198` — `default = []`, and `:230`
  `debug_endpoints = []`. Correctly opt-in.
- `crates/darknyx-tee-loadgen/Cargo.toml:100-103` — the loadgen requests it:
  `darknyx-tee = { path = "…", features = ["debug_endpoints"] }` — but under
  **`[dev-dependencies]`**.
- `Cargo.toml:2` — `resolver = "2"`.
- An exhaustive grep finds **no** Dockerfile, workflow, or script that enables
  the feature.

**The problem**

The property holds, and it holds for a good reason: resolver v2 specifically
does not unify features requested only by dev-dependencies into normal builds,
so even `cargo build --workspace --release` leaves `debug_endpoints` off. Under
resolver v1 that same command **would** have enabled it, shipping an
unauthenticated oracle-write endpoint inside the enclave.

So a genuine security boundary rests on a single word in the root `Cargo.toml`
that reads like a routine build setting. Nothing marks it load-bearing: there is
no comment at `resolver = "2"` explaining what it protects, no comment at the
loadgen's dev-dependency noting why the placement matters, and no CI assertion.

Compare how the analogous case is handled on-chain. CLAUDE.md §2.3 documents the
vault's `--features devnet-admin` explicitly — *"OFF by default (audit_1
F-01/F-02) so a MAINNET build ships neither backdoor"* — because audit_1 treated
exactly this shape as a significant finding. The enclave's equivalent has the
same correct default and none of the surrounding discipline.

**Fix.** Cheap and in keeping with the repo's existing gate-script habit: add a
`scripts/check-no-debug-endpoints.sh` to the §2.5 gate that greps the built
binary (or the cargo feature resolution) and fails if `/__debug/` is present,
mirroring `check-compose-image-digests.sh`. Then add a one-line comment at
`resolver = "2"` and at the loadgen's dev-dependency naming what each protects.
~1 hour. **Not a code change** — the code is already correct; this makes the
invariant explicit and testable rather than incidental.

---

### SW-25 — Dead `matching_engine` seed constants survive in the SDK

| | |
|---|---|
| **Severity** | Info |
| **Category** | Stale code |

**Anchors**

- `packages/sdk/src/idl/seeds.ts:25-28` — `DARK_CLOB_SEED`,
  `MATCHING_CONFIG_SEED`, `BATCH_RESULTS_SEED`, `PENDING_ORDER_SEED`.
- `programs/vault/src/state.rs` — the on-chain `SEED` set is exactly nine
  constants; none of these four is among them.
- Verified unused: no reference to any of the four anywhere in
  `packages/sdk/src`, `packages/sdk/tests`, `packages/daemon/src`, or
  `packages/indexer/src` outside the declaring file.

**The problem**

These are the PDA seeds of the deleted `matching_engine` program. CLAUDE.md §0
is unusually direct about this class of leftover: *"There is no legacy CLOB /
MagicBlock-ER / `matching_engine` program anymore. It was deleted. If you find a
reference to `matching_engine`, `run_batch`, `submit_order` (on-chain), PER
sessions, or ER delegation in any doc or comment, it is stale — fix it."*

No functional risk — nothing derives a PDA from them. The cost is that
`seeds.ts` presents itself as the mirror of the on-chain seed set, and a reader
comparing the two files finds four extra entries with no counterpart, which
invites the conclusion that the mirror is incomplete or that some other program
is in play.

**Fix.** Delete the four constants. Confirm `VAULT_TOKEN_SEED` stays — unlike
the others it is live, matching the literal `b"vault_token"` in
`programs/vault/src/instructions/withdraw.rs:50`, which is declared inline in the
account constraint rather than as a `SEED` associated constant, and so does not
appear in the `state.rs` list. ~15 minutes.

---

### SW-30 — `canonical_payload_hash` is duplicated four ways, not shared

| | |
|---|---|
| **Severity** | Info |
| **Category** | Documentation accuracy |

**Anchors**

- CLAUDE.md §7.1 lists the contract as
  *"`vault::tee_forced_settle.rs::canonical_payload_hash` **(shared)** +
  `darknyx-tee/src/settle/payload.rs`"*.
- The four actual implementations:
  `programs/vault/src/instructions/tee_forced_settle.rs:245-277` (on-chain),
  `crates/darknyx-tee/src/settle/payload.rs:52` (its own `CANONICAL_DOMAIN`),
  `programs/vault/tests/settle_harness/mod.rs:367` (test harness), and
  `packages/sdk/src/settlement/settle-builder.ts::canonicalPayloadHash` (TS).
- Two further stale module docs found in the same batch:
  `crates/darkpool-crypto/src/poseidon.rs:78-84` — a test named
  `poseidon_7_arity_matches_note_commitment_use` whose comment describes the
  **retired v1** construction (*"arity 7: domain_tag + tokenMint[lo] +
  tokenMint[hi] + amount + ownerCommitment + nonce + blindingR"*). The live v2
  note commitment is Poseidon**6** with a single `inner_hash` replacing
  `nonce + blindingR`.
  `crates/darknyx-tee/src/keys/mod.rs` — *"Phase 1: stub. Phase 2 will: call
  `dstack.get_key(...)`, construct an Ed25519 signing key…"*, describing as
  unbuilt what `keys/ed25519.rs` fully implements.
  `crates/darknyx-tee/src/api/auth.rs:793-796` — `revoke_token_handler`'s doc
  states *"In-memory only (Phase 1a): the denylist is lost on restart… Phase 1b
  persists the denylist alongside `accounts.db`."* Phase 1b landed: the denylist
  IS persisted (`persistence/auth.rs:92`, `api/state.rs:1174-1180`), and the
  backlog records AU-04 closed for exactly this. A reader reasoning about how
  long a revocation survives a restart would reach the wrong conclusion.

**The problem**

The duplication itself is **correct and unavoidable** — the enclave cannot
depend on the vault's BPF crate (the same constraint CLAUDE.md records for
`MAX_LOCK_TTL_SLOTS`), and it is properly mitigated: `payload.rs` carries a
drift assertion (`:170`, *"canonical_payload_hash drifted from on-chain"*) and a
pinned `canonical_payload_hash_fixed_vector` test. Nothing is broken.

What is wrong is the word "shared." Someone planning a payload change reads §7.1,
looks for the one function to edit, changes it plus the TS mirror, and misses the
enclave copy and the test harness — and the failure mode is a settle whose
signature the vault rejects, on devnet, after a CVM rebuild. The pinned vector
catches it, but only once the change has been made and the test run; the doc is
what determines whether the author knows to look in four places before starting.

The construction itself I verified as sound: every field is fixed-size
(`[u8;32]`, `[u8;16]`, `u64` LE), so the `hashv` concatenation is unambiguous
with no length-prefixing needed, and the domain tag `b"darknyx-match-v10"` is
bumped on each layout change with the history recorded inline (v7 dropped the
plaintext amounts, v8 appended `fill_recovery`, v9 removed the vestigial
nullifiers, v10 the namespace cutover).

**Fix.** Correct §7.1 to say *four implementations pinned by
`canonical_payload_hash_fixed_vector`* and name all four, so the lockstep
checklist is complete. Fix the `poseidon.rs` test comment to describe the v2
Poseidon6 construction (or rename the test, which asserts nothing
commitment-specific). Delete the "Phase 1: stub" paragraph from `keys/mod.rs`.
~1 hour. **Documentation only** — no code changes, and the code is correct.

This is the eighth instance of the pattern in this sweep (SW-07, SW-08, SW-10,
SW-12, SW-16, SW-19, SW-28, SW-30). Worth treating as a class rather than
individually: a doc-accuracy pass over module headers would find the rest more
cheaply than the next audit will.

---

### SW-09 — The stale `algorithm.rs` change-note derivation leaks into a `FillMemo` on the failure path

| | |
|---|---|
| **Severity** | Info (unreachable under current intake validation) |
| **Category** | Cross-language contract / client signal |

**Anchors:** `crates/darkpool-matcher/src/algorithm.rs:519-540` ·
`crates/darknyx-tee/src/matcher/interval.rs:214-258`, `:441-452`

`algorithm.rs` still writes `note_e/f_commitment` using the retired v2 SHA
`derive_inner` (the subject of **S-06**). `prepare_derived_continuations`
overwrites it with the correct v3 value on the success path — but on every
failure path it clears the relock flag and **leaves the stale commitment in
place**.

`commit_confirmed_match` then sends the `FillMemo` *outside* the relock guard
(`:444-452`), carrying `m.note_e_commitment` (potentially stale) alongside an
`inner` freshly recomputed at `:442` (correct). The result is an internally
inconsistent memo whose commitment matches neither its own inner nor the
commitment the assembler actually put on chain.

**Impact is contained**, in two ways: the failure path requires a non-Fr-safe
`inner_hash`/`owner_commitment`, which intake already rejects via
`verify_commitment`, so it is unreachable today; and the client's Vuln-4 memo
guard (`settle-memo-integrity.test.ts`) recomputes `Poseidon3(24, input_inner,
role)` and rejects a substituted commitment, falling back to the self-verifying
`recoverFillFromChain`.

**Why it is worth recording anyway.** It is a concrete argument for **S-06
option A (delete) over option B (deprecate)**: as long as `algorithm.rs` writes
a plausible-looking wrong value into a live field, every downstream consumer has
to be individually checked for whether it is overwritten first. Two of the three
consumers here are; one is not.

**Secondary note.** The same derivation failure is handled inconsistently:
`prepare_derived_continuations` degrades it to a cancelled continuation, while
`commit_confirmed_match:442-443` propagates it with `?` *after* already removing
the consumed openings (`:435-438`) — and the scheduler only logs that error. If
it were reachable, it would strand a confirmed match's continuation until lock
expiry. Same class as the accepted D-01 / S-02(C) disposition.

**Fix:** delete the stale derivation (S-06 A); move the `FillMemo` send inside
the relock guard, or clear `note_e/f_commitment` on the failure path.

---

### SW-06 — `merkle_root` and `leaf_count` are paired but describe different scopes

| | |
|---|---|
| **Severity** | Info |
| **Category** | Public API clarity |

**Anchor:** `crates/darknyx-tee/src/api/transparency.rs:144-155`, `:52-57`

`leaf_count` is the **sum across all shards**; `merkle_root` is **shard 0's root
only**. The code comment says so explicitly, but the `Reserves` struct presents
them as adjacent sibling fields with no marker, and this is a public,
unauthenticated response. A consumer reasonably reads them as a matched pair and
concludes the root covers that many leaves.

**Fix:** rename to `shard0_merkle_root` / `total_leaf_count`, or return a
per-shard array. Wire change — coordinate with the OpenAPI and any consumer.
~0.5 day.

---

## 2b. Performance and efficiency findings

Added 2026-08-02 after a retrospective pass over the same files with an
efficiency lens. Calibrated against `docs/throughput-roadmap.md`; roadmap items
1–5 are excluded as known and gated. **P-03** (book clone/sort per page) is
confirmed **already addressed** — `PreparedMatchTick::new` takes ownership of one
snapshot and prepares reusable sorted views that `next_page` reuses — and is not
re-reported.

| ID | Severity | Category | Finding |
|---|---|---|---|
| PF-12 | **Perf** | Durable I/O | Settle journal rewrites the whole file per entry: ~96 fsyncs and O(n²) serialization per N=16 batch |
| PF-18 | Perf-Nit | Durable I/O | Daemon SQLite commits at `synchronous=FULL` for an explicitly rebuildable cache |
| PF-19 | Perf-Nit | CPU | Daemon SQLite statements re-prepared on every call (11 sites) |
| PF-13 | Perf-Nit | RPC | ALT activation wait polls `getLatestBlockhash` up to 30× per batch |
| PF-14 | Perf-Nit | RPC | `/transparency` issues its `2 × N_mints` reads fully sequentially |
| PF-15 | Perf-Nit | Allocation | The full N=16 witness set is deep-cloned per batch for `spawn_blocking` |
| PF-16 | Perf-Nit | Lock contention | `record_final_outcome` takes the scheduler write lock once per match |
| PF-17 | Perf-Nit | CPU | The oracle's requested-feed map is rebuilt and hex-decoded on every refresh |
| PF-20 | **Perf** | Client throughput | Settlement tracker resolves leaf indices one sequential round-trip at a time, with no give-up — it gates note spendability |
| PF-21 | Perf-Nit | Client CPU / IO | Every order placement does two full `SELECT * FROM notes` scans plus a full orders scan, all filtered in JS |
| PF-22 | Perf-Nit | Client IO | `selectBatch` issues one `getOrder` query per note (N+1), each a freshly prepared statement |
| PF-23 | Perf-Nit | Client CPU | Each order op derives the Ed25519 trading keypair twice, doing two redundant scalar multiplications in pure-JS tweetnacl on the event loop |
| PF-24 | Perf-Nit | Memory | The control API's SSE stream ignores `res.write` backpressure, so one slow strategy consumer buffers every event without bound |
| PF-25 | Perf-Nit | Client CPU | `bytepad` reallocates and full-copies once per padding byte, on the per-note recovery-scan path |
| PF-26 | **Perf** | Client CPU | The daemon's local Merkle tree is rebuilt in full once per witness — five constructions per K=4 merge, the same waste `BatchMerklePaths` already fixed in Rust |
| PF-27 | **Perf** | RPC / recovery latency | Sequential per-account reads in the lock sweeper and on the **boot-recovery critical path** — up to 3N round-trips before the enclave can resume settling |

### PF-12 — The settle journal rewrites the entire file on every entry

**Anchors:** `persistence/journal.rs:303-307` (`record` → `flush`), `:338-347`
(`flush` serializes **all** entries), `:350-363` (`write_snapshot`: tmp → fsync
file → rename → fsync dir) · `settle/worker.rs:326-340`, `:356-398`, `:401-403`

`record()` is not an append — it re-serializes every in-flight entry and performs
a full durable snapshot write with **two fsyncs**. `journal_batch_start` calls it
**once per match**:

```rust
for m in inputs.matches.iter() {          // worker.rs:328
    j.record(entry)                        // → full snapshot + 2 fsyncs, each time
}
```

For one N=16 batch that is:

| Phase | `record`/`flush` calls | Full-journal serializations | fsyncs |
|---|---|---|---|
| `journal_batch_start` | 16 | 1+2+…+16 = **136 entry-writes** | 32 |
| `journal_settle_attempt` (per send) | 16 | ~136 | 32 |
| `journal_forget` (per terminal outcome) | 16 | ~136 | 32 |
| **Total** | **48** | **~408** | **~96** |

Three durable writes would suffice. The serialization cost is **quadratic in
batch size** because the k-th `record` in a loop writes k entries. With
`settle_batch_concurrency > 1`, concurrent batches also contend on the single
journal mutex while doing this.

**This is the concrete answer to the T-06 measurement waiver.** That waiver
accepted the missing per-transition write histogram on the reasoning that
end-to-end settle is network-bound (~14 s), so an added fsync could not matter —
and explicitly said to revisit *"if the settle path ever becomes CPU- rather than
network-bound (e.g. GPU proving lands)"*. The reasoning holds for the measured
1–2 match batches, but the cost is quadratic, so it does not extrapolate to a
full N=16 batch, and GPU proving removes the ~2.2 s that currently masks it.

**Fix.** Add a deferred-flush API — `record_many(entries)` or a
`JournalTxn` guard that flushes once on drop — and use it for the three
per-match loops. One flush per phase instead of N. Then capture the histogram the
waiver deferred, which becomes meaningful once the count is 3 rather than 48.
**~1 day**, no format change (the on-disk `JournalSnapshot` is unchanged).

### PF-18 / PF-19 — Daemon SQLite: full-durability writes and per-call statement preparation

**Anchors:** `packages/daemon/src/store.ts:132` (`PRAGMA journal_mode = WAL`,
no `synchronous` pragma) · 11 `this.db.prepare(...)` sites, none cached.

**PF-18.** WAL is set but `synchronous` is left at SQLite's default `FULL`, so
every commit fsyncs. The module itself frames this DB as a rebuildable local
cache, and in WAL mode `synchronous = NORMAL` is durable against *process*
crashes — it only risks the last transactions on power loss. Given notes are
chain-recoverable, NORMAL is the better trade on the fill/note-insert hot path.
**Caveat:** this interacts with **SW-10** — `seed_index` is *not* rebuildable, so
either fix SW-10 first or keep FULL for the orders table. A judgment call, not an
unconditional win.

**PF-19.** Statements are prepared on every call rather than cached on the class.
SQLite `prepare` re-parses and re-plans; on the per-fill note-insert path that is
repeated work with a trivial fix (prepare once in the constructor, reuse).

Both are small. Take them together when the store is next touched.

### PF-13 — ALT activation wait polls RPC up to 30× per batch

**Anchor:** `settle/worker.rs:899-915`

```rust
let alt_landed_slot = ctx.rpc.get_latest_blockhash().await?.context_slot;
for _ in 0..30 {
    if ctx.rpc.get_latest_blockhash().await?.context_slot > alt_landed_slot { break }
    tokio::time::sleep(Duration::from_millis(400)).await;
}
```

Each iteration is a full RPC round trip, so detecting a single ~400 ms slot
advance costs 2 calls in the good case and up to 31 in the bad one — per batch,
against the quota **SW-02** shows an unauthenticated attacker can already drain,
and which **SW-03** makes the failure mode for. `alt_wait_ms` is a known roadmap
cost; the *polling mechanism* is not, and is separable from it.

**Fix.** Sleep the known slot time first and poll on a backoff, or subscribe to
slot updates. Cheap: one fewer round trip in the common case, ~30 fewer in the
degraded one. **~0.5 day.**

### PF-14 — `/transparency` issues its reads fully sequentially

**Anchor:** `api/transparency.rs:167-172`, and `read_reserve:101-132` awaits its
two `get_account_info` calls in sequence.

```rust
for mint in &mints { per_mint.push(read_reserve(rpc, mint).await); }
```

For a 2-mint market that is **4 fully serialized RPC round trips** per request.
`join_all` over the mints, and over the two reads inside `read_reserve`, makes it
one round-trip of latency. Compounds with the missing cache noted in **SW-02** —
do both together. **~0.5 day.**

### PF-15 — The N=16 witness set is deep-cloned per batch

**Anchor:** `settle/worker.rs:721-723` — `let witnesses = inputs.witnesses.clone();`
to move into `spawn_blocking`.

`MatchSlotWitness` carries eight 32-byte commitments plus mints, amounts, owners
and inners per slot; the padded set is always N=16. `Arc<Vec<MatchSlotWitness>>`
(or `Arc<[MatchSlotWitness]>`) removes the copy — the prover only reads it.
Small in absolute terms; free to fix when that line is next touched.

### PF-16 — Scheduler write lock taken once per match at finalization

**Anchor:** `settle/worker.rs:429-448` — `record_final_outcome` takes
`ctx.settle_state.write().await` for a single job update, and is called once per
match. `set_all_stages` already demonstrates the better shape (one lock, loop
inside). Matters more as `settle_batch_concurrency` rises, since concurrent
batches contend on the same lock.

### PF-17 — Oracle requested-feed map rebuilt on every refresh

**Anchor:** `oracle/sync.rs:254-264` — `cfg.feed_ids` is hex-decoded into a fresh
`HashMap<[u8;32], String>` on every `apply_batch_update_at`, i.e. every refresh
cycle. The set is fixed at config time. Precompute it once in `SyncConfig`.
Trivial, but it is per-refresh work on the enclave's hot polling path.

Also noted: `sync.rs:281` recomputes `compute_root(pu.message, &pu.proof)` a
second time purely to populate the `InclusionFailed` error message. Only on the
failure path, so immaterial — but it is a second full Merkle fold.

### PF-20 — Leaf-index resolution is sequential, unfiltered, and never gives up

**Anchors:** `packages/daemon/src/settlement-tracker.ts:64-79`, `:83-104`

```ts
const pending = this.opts.store
  .list()                                            // SELECT * FROM notes — every row
  .filter((n) => n.orderId !== undefined && n.leafIndex === undefined);
for (const note of pending) {
  if (await this.resolveNote(note)) resolved += 1;   // one awaited HTTP RTT each
}
```

Three compounding costs on a 5 s timer:

1. **Full table scan per pass.** `list()` is `SELECT * FROM notes`
   (`store.ts:205-210`) and every row is converted through `rowToNote` —
   three `BigInt` parses and a hex→`Uint8Array` allocation each — only for the
   predicate to discard nearly all of them. The predicate is expressible in SQL
   and the `leaf_index IS NULL` set is exactly the small one.
2. **Fully sequential round-trips.** *P* pending notes cost *P* × RTT serially.
   At P = 20 and a 150 ms gateway RTT that is 3 s of a 5 s budget; a fill burst
   pushes a pass past its own interval and the `running` guard
   (`:65-66`) then *drops* subsequent ticks. The guard is correct — but it
   converts overload into delayed resolution rather than backpressure.
3. **No give-up.** A note whose settlement failed will never resolve, and is
   re-polled every 5 s forever. The pending set is monotonic in that case, so
   cost 2 degrades permanently.

This is not cosmetic: a note is unspendable until its leaf index resolves
(`note-select.ts:30-32` gates on it, and `merge-runner.ts:127` skips leaf-less
notes). Slow resolution directly throttles the market maker's re-quote rate and
delays consolidation.

**Fix:** push the predicate into SQL (add `WHERE order_id IS NOT NULL AND
leaf_index IS NULL`, backed by a partial index), run resolution with bounded
concurrency (8 is ample), and add per-note exponential backoff with a
quarantine after N failed attempts so dead notes stop consuming the budget.
~0.5 day. Interacts with SW-11: after a proper gap-reconcile exists, quarantined
notes are precisely the set to hand it.

### PF-21 / PF-22 — Daemon hot paths scan the whole note table, and merge selection is N+1

**PF-21 anchors:** `packages/daemon/src/daemon.ts:587-593`, `:599-614`;
`store.ts:205-210`, `:274-279`

Each `placeOrder` runs `lockedCommitments()` — a full `listOrders()` **plus** a
full `list()` — and then `selectNote()`, a *second* full `list()`, filtered and
sorted in JS by `selectCollateralNote`. So one placement is three full table
materializations, every row converted to `BigInt`/`Uint8Array`, to pick a single
note. `balances()` (`:684-698`) adds a fourth on every call. For a daemon whose
purpose is high-frequency quoting this is the hottest path there is, and it
grows linearly with the note set the daemon accumulates.

The predicate is a plain SQL query: `WHERE token_mint = ? AND leaf_index IS NOT
NULL AND amount >= ? ORDER BY amount LIMIT 1` — except `amount` is stored as
`TEXT` (`store.ts:31`), so numeric comparison and ordering do not work in SQL
today. Storing it zero-padded (or as two integer columns) makes the whole
best-fit selection a single indexed query.

**PF-22 anchor:** `packages/daemon/src/merge-runner.ts:126-131`

```ts
private isMergeable(n: StoredNote): boolean {
  if (n.leafIndex === undefined) return false;
  if (n.orderId === undefined) return true;
  const o = this.opts.store.getOrder(n.orderId);   // one query per note
  ...
```

Called from inside the `filter` at `:108`, so it is a classic N+1 over the whole
note set on every merge trigger — and because of PF-19 each of those is also a
fresh `prepare()` compilation. Load the order map once per `selectBatch` (a
single `listOrders()`, or a join), and the scan drops to one query.

**Fix:** add the `notes(token_mint, leaf_index)` index and a store-level
`selectCollateral`/`listMergeable` query; keep the pure `selectCollateralNote`
for unit tests over an explicit candidate list. Preload orders in `selectBatch`.
~1 day for both, and it composes with PF-19's statement cache. **Not a lockstep
change.**

### PF-27 — Sequential per-account RPC reads in the lock sweeper and, worse, on the boot-recovery critical path

**Anchors:** `settle/lock_sweep.rs:229-231`; `settle/recover.rs:304-308`, `:332`

Two more instances of a pattern this sweep has now found **four** times
(PF-14 `/transparency`, PF-20 the daemon's settlement tracker, and these):
an `await`ed single-account RPC read inside a `for` loop, where Solana's
`getMultipleAccounts` batches up to 100 per call.

```rust
// lock_sweep.rs — every sweep tick, one round-trip per pending lock
for commitment in commitments {
    let (lock_pda, _) = note_lock_pda(&commitment);
    match rpc.get_account_info(&lock_pda).await { … }
}

// recover.rs — at BOOT, two round-trips per journal entry, plus a third
for e in entries {
    let a = rpc.get_account_info(&a_pda).await;
    let b = rpc.get_account_info(&b_pda).await;
    …
    if let Ok(statuses) = rpc.get_signature_statuses(&[sig.to_string()]).await { … }
}
```

The sweeper case is ordinary background cost. **The recovery case is not**: it
sits on the cold-start critical path, and the enclave cannot resume settling
until reconciliation finishes. Up to **3N sequential round-trips** for N
surviving journal entries — at 50 entries and 150 ms latency that is roughly
22 seconds of added downtime after a crash, on top of proving-key load and
Merkle cold-boot. `docs/settlement-recovery-drill.md` measures recovery
end-to-end, so this is directly in the path of a number the team already tracks.

**Fix:** batch both through `getMultipleAccounts` — the recovery loop collapses
from 2N reads to ⌈2N/100⌉, and the signature statuses into one
`get_signature_statuses` call (which already takes a slice, so it is a pure
call-site change). The decision logic is untouched: `decide()` is pure over
`ConsumedState` and stays exactly as audited. ~0.5 day for both, and it should
be measured against the recovery drill's existing timings rather than assumed.

### PF-26 — The daemon's local Merkle tree is rebuilt once per witness

**Anchors:** `packages/daemon/src/merkle-tree.ts:86-130`, `:62-80`;
`packages/daemon/src/tree-merkle-provider.ts:152-160`

`witness(targetIndex)` pads the leaf array to a power of two and then hashes
**every level of the whole tree** to walk one path — and it shares nothing with
`root()`, which has just hashed the same tree. `getInclusionProof` calls
`witness()` once per input, so a K=4 auto-merge over a snapshot of *n* leaves
costs five full tree constructions (one root plus four witnesses) where one
would do, each ~2n awaited circomlibjs Poseidon calls on the main thread.

At a realistic shard size this dominates merge latency: circomlibjs Poseidon is
roughly two orders of magnitude slower than the Rust implementation, so a
100k-leaf snapshot is on the order of 200k hashes *per rebuild*.

The repo has already solved this exact problem on the Rust side and wrote down
why: `prover/leaf.rs:119-122` introduced `BatchMerklePaths` because *"the prior
per-index helper rebuilt the whole tree 16 times (240 hashes)"*, and it now
builds once and extracts every path from the retained levels — with
`internal_hash_count()` exposed specifically to regression-test the property.
The client-side provider is the same shape with the same fix available.

**Fix:** build the level arrays once in `LocalMerkleTree` (at `fromLeaves`, or
lazily on first use), retain them, and serve `root()` and every `witness()` from
those levels — the direct port of `build_batch_merkle_paths`. Cache invalidation
is trivial because the tree is immutable after construction; `refresh()` already
replaces the whole object. ~0.5 day, and it should carry the same
hash-count assertion `internal_hash_count()` enables in Rust.

### PF-25 — `bytepad` reallocates once per padding byte

**Anchor:** `packages/sdk/src/keys/key-generators.ts:251-263`

```ts
while (out.length % w !== 0) {
  const padded = new Uint8Array(out.length + 1);
  padded.set(out, 0);              // full copy, per byte
  padded[out.length] = 0;
  out = padded;
}
```

`w` is 136, so this allocates and fully copies the buffer up to 135 times to
append at most 135 zero bytes — roughly 36 KB of copying and 135 allocations
where a single `new Uint8Array(paddedLen)` would do. It runs twice per
`darknyxShakeKdfV1` call (header and key), and that KDF backs
`deriveBlindingFactor`, which is called **once per note index** during a
seed-only recovery gap-scan. Scanning a few thousand indices turns a trivial
pad into hundreds of thousands of allocations on the client's main thread.

**Fix:** compute the padded length once and allocate a single buffer. Five
lines, no behaviour change — the output bytes are identical, so the
cross-language fixed vectors continue to pin it. ~15 minutes.

### PF-24 — The SSE stream ignores write backpressure

**Anchor:** `packages/daemon/src/control-api.ts:190-201`

```ts
const unsub = daemon.subscribe((e: DaemonEvent) => {
  res.write(`data: ${JSON.stringify(serializeEvent(e))}\n\n`);   // return value ignored
});
res.on("close", unsub);
```

`res.write` returning `false` means Node has buffered the chunk because the
socket is not draining. Ignoring it means a strategy that stops reading — paused
in a debugger, blocked on its own I/O, or simply slower than the fill rate —
causes the daemon to accumulate every subsequent event in memory with no bound
and no signal. The `close` handler only fires when the socket actually closes,
which a stalled-but-open consumer never does.

This stream carries every fill and every order transition, so its volume scales
with exactly the activity that matters. The fix is the standard one: on
`write() === false`, stop writing and either buffer to a bounded queue that
drops oldest with a gap marker (SSE has `id:` for resumption) or disconnect the
consumer with a 1011-equivalent — the same "you lagged, resynchronize" contract
the TEE already applies to its own subscribers, which would make the two stream
layers consistent. Resume on `res.on("drain")`. ~2 hours.

### PF-23 — Each order op derives the trading keypair twice

**Anchors:** `packages/daemon/src/keystore.ts:154-170`;
`build-place-request.ts:89-90`; `daemon.ts:644-649`

```ts
private tradingKeypair(index: number): nacl.SignKeyPair {
  const { secretKey } = deriveTradingKeyAtOffset(this.identity.masterSeed, BigInt(index));
  return nacl.sign.keyPair.fromSeed(secretKey);     // full scalarbase mult
}
tradingPublicKey(index)          { return this.tradingKeypair(index).publicKey; }
signWithTradingKey(index, digest){ return nacl.sign.detached(digest, this.tradingKeypair(index).secretKey); }
```

Both consumers call the pair together — `build-place-request.ts:89-90` and
`daemon.ts:644-649` each take `tradingPublicKey(idx)` *and*
`signWithTradingKey(idx, …)`. That is two independent `tradingKeypair` calls, so
two `nacl.sign.keyPair.fromSeed` invocations, each performing an Ed25519
scalar-base multiplication to recover a public key — and `signWithTradingKey`
throws its copy away, since `nacl.sign.detached` derives what it needs from the
64-byte secret internally.

So an order costs three scalar multiplications where one is required. The HKDF
step (`sdk/src/keys/key-generators.ts:118-129`) is negligible; the scalar mults
are not — tweetnacl is pure JavaScript, where these are on the order of
milliseconds rather than microseconds, and they run synchronously on the event
loop that also serves fills, order updates and the settlement tracker. On a
market-maker daemon re-quoting continuously this is a real share of placement
latency. It should be measured rather than assumed, but the redundancy is
unconditional and removing it needs no measurement to justify.

**Fix.** Either return the keypair once and let the caller use both halves, or
memoize a small bounded LRU keyed by `index`. Worth stating the security
tradeoff explicitly, because nothing in the file does: caching retains expanded
secret keys in memory — but the master seed they derive from is already held in
memory for the process lifetime by design (`keystore.ts:13-16`), so a bounded
cache introduces no new exposure class. If the non-caching is in fact
deliberate, say so in the comment; today it reads as an oversight. ~2 hours.
**Not a lockstep change.**


## 3. Verified clean

Recorded so these are not re-audited. Several were predicted by prior passes to
be where the next bug lived; they are not.

### 3.1 Pyth accumulator + VAA (predicted #2 target — clean)

- **`oracle/accumulator.rs`** (393 lines, read in full). The `Cursor` is
  bounds-checked with `checked_add` on every read and cannot panic on a short
  buffer. All allocations are bounded by `u8`/`u16` length prefixes
  (`num_updates ≤ 255`, `proof_count ≤ 255`), so an attacker-supplied length
  cannot force a large allocation. `parse_price_feed_message`'s
  `.try_into().unwrap()` calls are safe — each follows a `take(n)` that returns
  exactly `n` bytes.
- **The sorted-pair Merkle is correctly domain-separated.** `hash_leaf` prefixes
  `0x00`, `hash_node` prefixes `0x01` (`:299-308`). This is the standard and
  necessary mitigation for the sorted-Merkle second-preimage attack, where an
  attacker submits an internal node as a leaf; it is correctly applied.
  (`Keccak160`'s 80-bit collision bound is inherited from `pythnet-sdk`, not a
  Darknyx choice.)
- **`oracle/sync.rs:241-298`** wires it correctly, in the only safe order:
  parse → `vaa::verify_for_profile` against the **deployment-selected** profile
  (never inferred from the payload) → root extracted from the **verified**
  payload → per-update `verify_inclusion` against **the same `pu.message` bytes
  that were decoded** → duplicate-feed bail → every requested feed must be
  present. Every branch fails closed.
- **`oracle/vaa.rs` quorum logic** resists the classic VAA bugs with two
  independent guards: strictly-increasing guardian indices at parse
  (`:343-348`, `<=` rejected) **and** a `seen[256]` array in `verify_signatures`
  (`:427-434`). Guardian index bounds-checked, recovery id constrained to
  `{0,1}`, guardian set index pinned to the trusted profile, and the correct
  Wormhole `keccak256(keccak256(body))` double-hash.

### 3.2 `fills` / `orders` cross-account routing (predicted #5 target — clean)

- `api/stream.rs:663-711` — `subscribe` reads the account **only** from
  `s.authed`, set exclusively by a verified in-band `login`. There is no
  client-supplied account parameter on any channel, and subscription without
  login is refused with `4010`.
- `api/stream.rs:603-607` — a session cannot re-login as a different account.
- `api/state.rs:1010-1028` — `route_fill` resolves `order_id → account` and
  sends **only** to that account's channel; an unresolvable memo is dropped
  (`return false`), with no broadcast fallback.
- `api/state.rs:947-965` — `archive_order_owner` inserts into `recent` **before**
  removing from `order_owner`, so the two independent routers cannot race into a
  window where neither resolves. Ordering is correct and deliberately commented.
- `api/state.rs:936-945` — `account_owns_order` returns a bare boolean so
  missing and foreign orders share one response path and cannot become an
  order-existence oracle.

The only defect found in this area is SW-04, which is a delivery loss, not a
leak.

### 3.3 Settle worker write-ahead ordering (predicted #1 target — sound)

- `worker.rs:356-398` — `journal_settle_attempt` returns `false` and the caller
  **skips the send** when the signature cannot be read back or the journal write
  fails (`:1099-1118`). Refusing to send a transaction whose signature is not
  durable is the correct WAL discipline, and the reasoning is documented.
- `worker.rs:295-316` — the journal's `lock_expiry_slot` is the **earlier** of
  the two sides, so redrive is bounded by the first lock to lapse, not the last.
- `worker.rs:482-500` — `reconcile_consumed_pdas` treats only *both* PDAs
  vault-owned as proof of settlement, and explicitly refuses to guess on exactly
  one (`Inconsistent` → terminal rejection rather than an assumed success).
- `worker.rs:747-749` — the local marker deadline uses a 250-slot margin against
  the on-chain 300, a deliberate under-estimate so the worker gives up early
  rather than redriving past a real expiry. Correct direction.
- `worker.rs:1252-1258` — a send task that ends without an attributable result is
  treated as ambiguous and retried, never as success.
- **Shard indexing is safe.** `shard = idx % num_settle_shards()` is bounded by
  `tee_keypairs.len()`, and `main.rs:1195-1204` asserts
  `vault.num_trees == cfg.num_trees` and `num_tee_keys == num_trees`, with
  `derive_set(cfg.num_trees)` producing exactly that many signers. A settle
  cannot target a non-existent `merkle_tree[tree_id]`.

The only defect found is SW-03.

### 3.4 Other

- **`solana_rpc/client.rs` request path** — bounded 429 retries (6) with
  exponential backoff capped at 4 s; non-429 HTTP and JSON-RPC errors are not
  retried; `"result": null` handling is deliberate and documented. Sound apart
  from SW-01's formatting.
- **`merkle/mirror.rs`** — append-only with no rewind API. The `expect()` calls
  are over fixed inputs (zero-subtree roots, empty root) and documented as
  build-level regressions. `inclusion_proof` is tested to fold back to the root
  across randomized appends.
- **`packages/sdk/src/fills/recover.ts:81-121`** — recovery genuinely
  self-verifies: after decrypting `(trade, change)` it recomputes
  `noteCommitmentV2` and returns `null` unless the result is byte-equal to the
  on-chain commitment. This is what makes U-04's accepted "hostile TEE writes
  garbage ciphertext" risk fail closed rather than produce a bogus note.
- **The VK generation chain is correct, which closes §5.1 end to end.**
  `scripts/parse-vk-to-rust.js` is the step that turns snarkjs'
  `verification_key.json` into the `vk_*.rs` consts the on-chain verifier uses —
  the link in CLAUDE.md §5.1's chain I had verified the *process* around
  (regenerate + commit in lockstep) without reading the generator itself.
  It is right on the points that matter: `g2ToBytes:58-70` reads snarkjs'
  `[[x0,x1],[y0,y1]]` and emits `[x1, x0, y1, y0]`, the **same Fq2 swap**
  `convert.rs` applies to `pi_b` (verified in Batch D against its round-trip
  tests) — so proof points and VK points use one consistent convention;
  `bnToBytesBE:38` **throws** rather than truncating when a value exceeds 32
  bytes; and `:83-84` rejects a non-`groth16`/non-`bn128` key file outright, so
  a wrong-protocol VK cannot be silently transcribed. With the circuits
  (circuits batch), the public-input assembly and leaf hash (Batch D), the proof
  byte conversion (Batch D) and now the VK generation all checked, §5.1's full
  source→zkey→VK→verifier chain has been read.
  Minor observation, not a defect: the generator emits
  `{PREFIX}_NR_PUBLIC_INPUTS = nPublic` while `verify.rs:108` independently
  derives `nr_pubinputs` from `IC.len() - 1`. The two agree for any well-formed
  snarkjs key, so the emitted constant is documentation rather than
  load-bearing.
- **A settle-capability failure pauses trading rather than accepting orders that
  cannot complete.** This was the concern I opened `main.rs` with: `:455-467`
  degrades to "enqueue-only" and merely `warn!`s when `build_settle_driver`
  fails (absent N=16 proving key, RPC construction failure), and the enclave
  keeps booting. If intake stayed open, users would place orders that match,
  reserve collateral in the opening store, and sit in `pending_settlement`
  forever — a fail-*open* posture in a codebase that is otherwise fail-closed.
  It does not: `main.rs:476-479` pauses the trading gate when
  `governed_market && tee_signer_pubkey.is_some() && !settle_enabled`, logging
  *"governed real-market settle driver is unavailable; trading starts PAUSED."*
  The condition is exactly the production shape — a real governed market with a
  derived signer — so local dev and simulator runs still proceed enqueue-only as
  intended, and only the "production-shaped but broken" case halts.
  This also explains a detail from Batch A: `settle_enabled` is the single
  switch that decides both *can we settle* and *do we enforce settle-time
  preconditions at intake* (`api/orders.rs:565`, the S-02 root check). The
  loadgen regime runs settle-disabled with stub proofs, so the root check is
  skipped there and enforced in every configuration that can actually settle —
  one switch, coherently applied at both ends.
- **`main.rs`'s boot is fail-closed at the trust root.** `:184` terminates
  production startup on a dstack/KMS probe failure, and the only path that
  tolerates it requires `DARKNYX_TEE_ALLOW_TEST_AUTH=1` explicitly (`:189`).
  Downstream subsystems degrade individually and say so — the Merkle mirror
  (`:577`, *"/tree/* serves an empty mirror"*), the slot poller (`:660`), and
  the priority-fee poller (`:717`) each warn and continue, which is correct
  since none of them is authorization-bearing.
- **`verify.rs::verify_valid_input` assembles the public inputs in the circuit's
  order.** `:104-114` builds `[merkle_root, note_commitment, mint_lo, mint_hi]`,
  matching `valid_input/circuit.circom:123`'s
  `public [merkleRoot, noteCommitment, tokenMint]` as verified in the circuits
  batch, and sets `nr_pubinputs = IC.len() - 1` per the Groth16 convention. The
  mirrored upstream typo `vk_gamme_g2` is flagged in a comment rather than
  silently copied.
- **The persistence snapshots are atomic and version-checked, with per-sweeper
  isolation.** `persistence/markers.rs:152-161` writes sibling `*.tmp` → fsync →
  rename (mirroring `auth::save_auth_snapshot`), `:124-141` version-checks on
  load and treats a mismatch or corruption as an empty set rather than failing
  boot, and `:50` keeps **separate files per sweeper** *"so a corrupt or
  version-skewed snapshot of one cannot"* take the other down — which is
  precisely what `lock_sweep.rs`'s module doc claimed, now confirmed at the
  implementation. Fail-to-empty is the right posture here: the state is
  rent-reclamation bookkeeping, so losing it costs rent, not correctness.
- **The one script that could deploy to the wrong network refuses to.**
  `scripts/deploy-devnet.sh:35-38` resolves the RPC from `SOLANA_RPC_URL` (or
  the `solana` CLI config) and hard-fails if it does not contain `devnet`:
  *"ERROR: deployment RPC is not a devnet endpoint."* It also runs under
  `set -euo pipefail` and refuses to proceed unless the SBF artifact was built
  with `--features devnet-admin`, naming the exact command. Program deployment
  is the one irreversible, real-value operation in `scripts/`, and it is the one
  with an explicit cluster assertion.
- **The destructive admin scripts have no prompt — and the guard that matters
  is on-chain instead, which is stronger.** `close-vault-config.mjs` and
  `reset-merkle-tree.mjs` wipe governance state and the Merkle tree
  respectively, take `SOLANA_RPC_URL` from the environment (devnet default), and
  ask for no confirmation. That looks alarming until you follow it through:
  both `close_vault_config` and `reset_merkle_tree` are compiled **only** under
  `--features devnet-admin` (audit_1 F-01/F-02), so a mainnet build ships
  neither instruction and a mainnet-pointed run fails on a discriminator that
  does not exist. A client-side prompt would be strictly weaker than a program
  that cannot execute the operation at all. The residual is operational rather
  than security: pointing either script at a *different devnet* deployment would
  succeed, so the blast radius is "wrong devnet tree," which CLAUDE.md §2.4
  already treats as routine to rebuild.
- **`check-dependency-audits.sh` gates on a baseline diff, not on the tools'
  exit codes.** The `|| true` at `:83` is not a swallowed failure — `npm audit`
  exits non-zero merely *because* findings exist, so the script captures the
  JSON and then compares the current advisory set against a recorded baseline
  (`:120-141`), failing on anything new. That is the correct shape for "new
  advisories only," and DEP-01 — a RustSec advisory the backlog records as
  currently failing this gate — is live proof that it fires rather than
  silently passing.
- **SW-30's four-implementation claim is verified, not asserted.** I cited
  `sdk/settlement/settle-builder.ts` in that finding without having read it.
  Reading it now (`:162-186`) confirms it matches
  `vault/instructions/tee_forced_settle.rs:245-277` field-for-field: same
  `"darknyx-match-v10"` domain, then `matchId(16)`, `noteA..noteF(32)`,
  `noteFeeBase`, `noteFeeQuote`, `orderIdA(16)`, `orderIdB(16)`,
  `buyerRelockOrderId(16)`, `buyerRelockExpiry(u64 LE)`,
  `sellerRelockOrderId(16)`, `sellerRelockExpiry(u64 LE)`, `batchSlot(u64 LE)`,
  `fillRecovery(128)` — identical order and widths. The `fixed(x, n)` helper
  enforces each width, so a wrong-length input throws rather than silently
  truncating into the hash. The four implementations agree today; SW-30 remains
  a documentation fix, not a latent divergence.
- **The SDK stream client enforces sequence continuity — at the wrong
  boundary.** `orders/trading-ws-client.ts:203-218` rejects any frame missing a
  positive integer `seq`, fires `onSequenceGap(expected, received)`, and errors
  on discontinuity. That is real, correct gap detection, and discovering it
  materially improved SW-31: the reason it does not catch router lag is that the
  server stamps `seq` at socket-send time rather than at the message's origin.
  Moving the counter upstream makes an existing client-side detector do the work
  — recorded as SW-31 option **A′**, which is cheaper than the fix I proposed
  from the server side alone.
- **`modify_core` contains the loose end Batch A left open.** That pass noted
  the cancel signature covers `(order_id, trading_key, cancel_nonce,
  session_id)` and therefore does not bind *which* replacement it authorizes.
  Reading `api/orders.rs:990-1075` shows the composition is nonetheless safe,
  because every dangerous pairing is blocked by a separate check: the cancel is
  verified against `trading_key` (`:990`), the **old order must be owned by that
  same key** or the request is `not_owner` (`:1057-1060`), the replacement may
  not move markets (`:992-999`, *"cancel and place a fresh order"*), and the
  replacement carries its own canonical signature with its own
  monotonic `arrival_nonce` (`:1026-1032`). So the worst a mismatched pairing
  achieves is "cancel A and place B" — both of which that key independently
  authorized. Two further details are right: **both preconditions are checked
  before either mutation** (`:1047-1051`) so there is no window where the user
  has neither order, and the collateral conflict check
  (`:1069-1075`) runs *before* the cancel, deliberately, since reusing the old
  order's own reservation is safe while any other reservation is a hard
  conflict. The thread is closed: not cryptographically fixed, but soundly
  contained.
- **The §8.2 marker invariant holds on both sides — the one CLAUDE.md says
  bricks every match after the first.** This was the specific thing to check in
  the Tx D builder, and it is right at both ends. Builder:
  `settle/settle_batched.rs:116` passes the marker as
  `AccountMeta::new_readonly(marker, false)`. Handler:
  `tee_forced_settle_batched.rs:570-577` carries an explicit *"DO NOT close
  `batch_validity_marker` here"* with the reasoning (a second match in the same
  batch would see `lamports() == 0`), and the marker's own `expiry_slot` plus
  the separate `close_batch_validity_marker` ix reclaim the rent once. So
  neither the cross-shard write conflict nor the brick-after-first-match bug is
  present, and `test_two_matches_share_one_marker` guards it.
  Adjacent detail worth noting: the handler's **raw** marker read
  (`:367-377`) checks the derived PDA address *and* `marker_info.owner ==
  crate::ID` before borrowing data — the F-08 discipline again present in the
  settle path and absent in `/transparency` (SW-05). That is now three files
  doing it correctly next to the one that does not.
- **The lock_e/lock_f writability is conditional, matching the §6 size budget.**
  `settle_batched.rs:106-113` marks them writable only when a relock actually
  occurs and read-only otherwise, which is what lets the encoder dedup the
  all-zero PDA on exact fills without ever passing a writable account the
  handler will not write.
- **`confirm_signatures` already uses the batched idiom PF-27 recommends.**
  `settle/submit.rs:408-425` passes the whole signature slice to a single
  `get_signature_statuses` call and iterates the returned statuses. So the fix
  for `recover.rs`'s per-entry loop is copying a pattern that exists two files
  away, not introducing one. (`send_and_confirm_with_rebroadcast` polls a single
  signature by nature, and its rebroadcast cadence is justified inline: a
  freshly-created ALT otherwise leaves Tx D unconfirmed for ~10–14 s on devnet.)
- **The two sweepers' authority split is stated consistently in both files.**
  `marker_sweep.rs:81-83` requires the **primary (shard-0)** key because it pays
  for `verify_match_batch` and is therefore every marker's `payer`, which the
  on-chain close enforces via `has_one = payer`; `lock_sweep.rs:20-26`
  independently explains why `release_lock` has no such constraint and any shard
  key may pay. Two files, one coherent model, no drift.
- **`alt_pool.rs` rotates ahead of the cooldown rather than blocking on it.**
  It creates a replacement ALT as the current one nears Solana's 256-address
  limit and tracks deactivated tables with their slot so rent is reclaimed after
  the ~512-slot cooldown — *"never blocking on the 512-slot deactivation
  cooldown"* — which is the design CLAUDE.md §6 describes.
- **CI supply-chain pinning is exemplary.** Every third-party action across
  `.github/workflows/*.yml` is pinned to a **full 40-character commit SHA** with
  a trailing version comment — `actions/*`, `docker/*`, `dorny/paths-filter`,
  `Swatinem/rust-cache`, and `dtolnay/rust-toolchain`, which additionally
  carries the note *"(a BRANCH upstream, so it moves — pin it)"*. Tag-pinning is
  the usual failure here and it is absent; someone reasoned about the difference
  between a tag, a branch and a SHA and wrote the conclusion down. Combined with
  `check-compose-image-digests.sh` enforcing `@sha256:` on compose images, the
  build inputs are pinned at both ends.
- **`verify_match_batch.rs` closed a griefing vector structurally identical to
  SW-21 — and the remedy it chose is the one SW-21 should use.** The S-04 note
  at `:82-99` records that `expiry_slot` was once a caller argument, bounded but
  free. Combined with a deliberately unauthenticated `payer` (*"anyone can push
  a valid proof — a real liveness property worth keeping"*) and an `init` marker
  that lets exactly one party set the TTL per root, that handed any observer a
  lever: replay the same proof and root with `expiry_slot = clock.slot + 1`,
  land first, and the TEE's own verify then fails on the `init` collision while
  all N settles fail `BatchValidityMarkerExpired` — with the 2N `lock_note`
  transactions already landed, pinning **up to 32 users' notes for the full lock
  TTL, for one transaction fee**. The fix was not to authenticate the payer
  (which would have cost the liveness property) but to **derive the TTL and
  remove the degree of freedom entirely** — and, as the comment observes,
  *"strictly LESS code than the two bounds it replaces."*

  That is SW-21's shape exactly: an unconstrained field that costs the attacker
  nothing and burns an honest counterparty's settlement. It is worth citing when
  fixing SW-21, because the in-repo precedent both establishes the severity
  class and picks the same remedy — constrain the value at intake rather than
  add it to the signed encoding.
- **The on-chain half of the settle binding is correct.**
  `verify_match_batch.rs:104-121` recomputes the `config_digest` **on-chain**
  from `VaultConfig`'s `fee_rate_bps` and `protocol_owner_commitment` plus
  `MarketConfig`'s mint halves and `price_scale`, so the enclave cannot prove
  against a fee rate or market parameter governance did not set — the C-04
  exact-fee binding, enforced where it must be. It also checks `market.enabled`
  (the kill switch) and `price_scale > 0` before verifying. The marker uses
  `init`, not `init_if_needed`, per §8.1, and the comment correctly notes that
  post-expiry re-verification is harmless because the consumed-note PDAs
  independently prevent settled inputs from replaying.
- **`lock_note.rs` confirms SW-21's mechanism and enforces the F-05 cap on both
  sides.** The `MerkleTree` account is seeded `[MerkleTree::SEED, &[tree_id]]`
  (`:57`) — which is precisely where an out-of-range `tree_id` dies, exactly as
  SW-21 describes, since no account exists at that address. `tee_authority` is a
  `Signer` checked against the K-key set via `is_authorized_tee` (`:106-108`),
  and `expiry_slot` is bounded on **both** ends: strictly future (`:128`) and
  no further than `clock.slot + MAX_LOCK_TTL_SLOTS` (`:132-133`), with the right
  framing recorded — *"the lock window is also the censorship window."*
- **`merkle.rs::append_leaf` is the standard incremental construction and
  matches the client mirror.** Capacity is checked against `2^MERKLE_DEPTH`
  before any hashing (`:74-77`), and the right-path/zero-subtree walk is
  byte-identical in shape to the `LocalMerkleTree` I verified in Batch D. Under
  sharding, the per-shard `MerkleTree` account carries the mutable state while
  `zero_subtree_roots` stays global in `VaultConfig` — tree-independent by
  construction, so the shards cannot diverge on the empty-subtree constants.
- **The opening store's reservation lifecycle is conservative in the safe
  direction.** This is the store SW-21's `collateral_in_use` guard depends on,
  so its release rules decide whether a note can be double-booked.
  `matcher/interval.rs:572-582` releases a reservation only when **both**
  conditions hold: the match is already terminal-failed *and* its lock expiry
  has passed. Ambiguous matches *"remain in the book as `Matched` and are never
  swept by this path"* — the same refusal-to-guess posture `recover.rs` takes,
  and the correct one, since releasing while the on-chain lock may still be live
  is exactly how a note gets booked twice. The sweep runs lazily at both the
  matcher tick (`:706`) and at intake (`api/orders.rs:636`, immediately before
  the `is_reserved` check), so no separate sweeper task is needed and a stale
  reservation cannot outlive the next order that would collide with it.
- **`matcher/openings.rs` records two design decisions worth preserving.**
  First, why accepting a note opening over the wire is safe without expanding
  the signed encoding (`:14-21`): the trading key signs `note_commitment`,
  intake checks `commitment_from_fields_v2(opening) == note_commitment`, and
  Poseidon collision-resistance pins the opening to the signature — *"without
  having to expand the canonical order encoding (and therefore without a
  cross-language signing-contract change)."* That is the same reasoning SW-21
  concludes should keep `tree_id` unsigned. Second, the S-09 removal of the
  intake nullifier (`:23-34`), whose rationale is the sharpest privacy argument
  in the codebase: the enclave was holding `Poseidon3(DOMAIN_NULL, spending_key,
  inner_hash)` — precisely what the note's eventual `withdraw` publishes on
  chain — so anyone who could read enclave memory *"could join intake nullifiers
  against published ones and deanonymise which orders became which
  withdrawals,"* defeating unlinkability with no custody compromise at all.
  Holding it was worse than useless, and it is gone.
- **`darkpool-crypto`'s key derivation matches the TypeScript byte-for-byte,
  verified from the Rust side rather than only through the parity tests.**
  `keys.rs:49-53` declares the same five info strings as
  `sdk/keys/key-generators.ts`, applies the same split (HKDF-SHA256 for
  spending/trading/root; `DarknyxShakeKdfV1` for viewing and note blinding), and
  reduces the same **64-byte** output mod r — so the negligible-bias property I
  checked in Batch B holds on both sides. The custom SHAKE construction is
  additionally pinned by a frozen known-answer test (`:289`).
- **`field.rs` rejects out-of-range field elements *deliberately, for parity* —
  which strengthens SW-23.** `fr_from_be_bytes:23-40` calls
  `from_be_bytes_mod_order` and then verifies the round-trip equals the input,
  with the reasoning stated: *"ark-ff `from_be_bytes_mod_order` never fails — it
  silently reduces. We want strict 'in-field' semantics **for cross-env
  parity**, so check first."* So strictness is not incidental here; it is an
  explicit cross-language contract. That makes the TypeScript side's silent
  reduction (SW-23) a deviation from a stated design goal rather than merely an
  asymmetry between two reasonable choices.
- **The oracle cache fails closed at the READ boundary, which is the property
  that matters.** The accumulator and VAA parsers were cleared in an earlier
  pass; the caching layer around them had never been read, and it is where a
  stale price would actually reach the matcher. It does not:
  - **Freshness is enforced on read, not merely on write.**
    `oracle/cache.rs:277-311` (`snapshot_at`) requires **both**
    `validate_signed_freshness` (the Pyth-signed `publish_time_ms`) **and** a
    local-arrival check (`observed_at_ms - last_updated_ms > max_age_ms →
    LocalStale`) before returning anything. That two-dimensional gate is the
    right decomposition and the comment at `:36-39` says why: *"a healthy local
    fetch loop cannot make an old signed update fresh."* Signed-time alone would
    admit a replayed old-but-validly-signed update; local-arrival alone would
    let a stalled loop serve an old price indefinitely. Requiring both closes it
    in both directions, and a stalled fetch loop therefore **halts matching**
    rather than trading on a stale band.
  - **Nothing bypasses the gate.** A raw `get()` (`:263-265`) exists without
    freshness checks, but the only consumer is the matcher tick, which calls
    `snapshot(&self.cfg.feed_id, freshness, self.cfg.oracle_units)`
    (`matcher/interval.rs:685`). I grepped for raw `get()` callers outside
    `cache.rs` and there are none — so the escape hatch is unused rather than
    merely discouraged. This is the mechanism behind U-09's fail-closed posture,
    now confirmed at the boundary that enforces it.
  - **The write side rejects the whole oracle-attack family atomically.**
    `apply_verified_batch` (`:161-172`) documents that *"stale, future-dated,
    out-of-order, and conflicting replay batches leave the entire cache
    unchanged"* — all-or-nothing, so a mixed batch cannot partially poison the
    map. Rollback is blocked (`publish_time_ms < previous` rejected), advancing
    time requires an increasing VAA sequence, an exact replay is recognised and
    deliberately does **not** refresh `last_updated_ms` (so a replayer cannot
    launder local freshness), and a shared publish time with a strictly newer
    sequence is correctly distinguished from a replay.
  - **Unit conversion is fully checked** — `ZeroPriceScale`,
    `ExponentOutOfRange`, and `IntermediateOverflow` are explicit error
    variants, so a hostile exponent cannot silently wrap the scaled price.
  - `hermes.rs:121-123` sets a 5-second HTTP timeout with the expected-latency
    rationale recorded — notably the bound SW-17 found missing on the daemon's
    attestation fetch.
- **`settle/recover.rs` is the best-reasoned file in the repository, and its
  decision table matches its documentation exactly.** T-06's boot reconciliation
  gets right the thing crash-recovery usually gets wrong — it never resolves an
  ambiguous case by guessing:
  - **The authority is the consumed-note PDA, not the signature** (`:8-18`). A
    signature can read unknown because the RPC dropped it from its status cache
    or the node is behind, none of which says whether the tx landed;
    `tee_forced_settle_batched` creates **both** commitment-keyed PDAs
    atomically, so their existence is durable, node-independent proof. On
    `BothConsumed` (`:107-118`) the signature only changes *how the outcome is
    described*, never the conclusion.
  - **A contradiction is reported, not resolved in the convenient direction.**
    If the signature reads confirmed while neither PDA exists (`:120-135`), the
    result is `Indeterminate` with the reasoning stated: *"a redrive under a
    genuinely-confirmed settle is a double-settle attempt, and declaring success
    under a genuinely unconsumed one strands the notes."*
  - **Exactly one PDA is never inferred from.** `ConsumedState::Inconsistent`
    (`:55-56`, `:165`) escalates to a human — and an RPC read failure also lands
    there (`:273`, `:322`), so the fail-safe direction is toward escalation
    rather than toward a guess.
  - **The redrive deadline is `min(marker_expiry, lock_expiry)`**, mirroring
    `worker::settlement_deadline`, with a genuinely subtle justification: the
    marker TTL is ~300 slots against the lock's ~30 minutes, so considering only
    the lock *"would classify as `Redrive` a batch whose marker died long before
    the CVM finished restarting, and every redrive it authorised would revert."*
    A missing marker expiry means `verify_match_batch` never landed, so the
    deadline is 0 and there is nothing to settle against.
  - **The in-process ambiguity path and the boot path share the reasoning by
    construction**, not by coincidence — `:14-17` says so explicitly and points
    at `worker::reconcile_consumed_pdas`.

  **One cross-component gap worth carrying to SW-11.** `:34-42` records that
  resting orders are deliberately *not* restored, which is the right call — an
  order is a signed client intent bound to a nonce and a boot session, and
  resurrecting one after an arbitrary gap would re-enter the book on the
  client's behalf at a price chosen under different conditions. But the stated
  premise for that decision is that *"the daemon observes the terminal/restart
  state and submits a fresh signed order once the note is usable again"* — and
  **SW-11 established the daemon does no such thing**: it drops the `onResync`
  signal and has no boot reconciliation. So the enclave correctly declines to
  recover, expecting a counterpart that does not. The two halves of the recovery
  contract do not meet, which raises SW-11's practical impact without changing
  anything about this file.
- **The settle assembler independently re-derives the matcher's arithmetic
  before signing — a third layer on conservation.** `settle/assemble.rs:143-202`
  does not trust the `MatchPair` it was handed. It re-checks both conservation
  equalities with `checked_add` (`:161-184`) and re-derives the floor pricing
  and its remainder (`:187-202`), rejecting any mismatch as
  `AssembleError::Conservation`. Crucially it validates against
  **`inp.buyer_opening.amount` / `seller_opening.amount`** — the values the
  on-chain note commitment actually binds — rather than the matcher's own
  `note_amount` snapshot, so a drift between the book and the real note is
  caught here rather than at proof time. It also asserts the openings are for
  the correct sides (`:149-155`: a bid locks quote, an ask locks base). So
  conservation is enforced three independent times: in the matcher
  (`algorithm.rs`), in the assembler, and in-circuit — with the assembler being
  the one that checks against the authoritative opening.
- **`settle/lock_sweep.rs` performs exactly the account validation SW-05 asks
  `/transparency` to adopt.** `lock_expiry_slot:129-134` checks
  `account.owner == vault_program_id()`, a minimum length, **and** the
  `NOTE_LOCK` discriminator before parsing any bytes — the raw-read discipline
  the transparency endpoint lacks, in the same codebase. Beyond that:
  `lock_has_expired` uses `>=`, matching the on-chain `clock.slot >=
  expiry_slot` with the CS-09 boundary noted; the confirmed slot is read **once
  per sweep** with the reasoning (a pre-expiry release would fail
  `LockNotExpired` every tick for the whole TTL); and the `Ok(None)` arm handles
  a genuinely subtle race — an absent lock usually means gone-for-good, but also
  means *"not created yet"* for a commitment registered moments ago, since
  registration is optimistic and precedes the lock tx. Dropping one of those
  would be unrecoverable (an untracked lock whose rent is never reclaimed), so
  young entries are retained under a grace period and re-checked. The module doc
  is also honest about its own severity: S-03(C) demoted the sweeper from
  liveness recovery to rent reclamation, *"which is why it is built after that
  relaxation rather than before it, and why a failure here is a cost issue, not
  a user-facing one."*
- **`submit_lock.rs` records why the two `lock_note` transactions are not
  batched**, and the reason is the §6 size budget: pre-ALT, two txs is the only
  shape that stays under 1232 bytes, and independence means a single-side
  failure can be resubmitted alone instead of re-sending both proofs. The
  upgrade path once the per-batch ALT exists is named rather than left implicit.
- **Per-account routing is bounded and does not leak an order-existence
  oracle.** `order_owner` (`state.rs:243-248`) looked like another unbounded map,
  but it holds only *live* orders: `archive_order_owner` (`:950-965`) moves a
  terminal order's entry into the capped `recent_order_owner` and removes it,
  and the insert-before-remove ordering has a stated race rationale — *"so
  `route_fill` can always resolve one of the two maps even when the independent
  routers race."* (Its one gap is SW-31's skipped-update path.) Separately,
  `account_owns_order` (`:936-945`) returns only a boolean *"so missing and
  foreign orders share one response path and cannot become an order-existence
  oracle"* — a real privacy consideration for a darkpool, handled deliberately.
  `conn_limit.rs` caps concurrent streams per account (default 8) with a
  10-second login deadline so unauthenticated sockets cannot accumulate.
- **`api/auth.rs` is the most carefully defended file in the repository, and
  several of its choices encode incidents rather than theory.** It was the
  standout coverage gap — 1,111 lines deciding *who is authenticated* on a
  surface whose routing and intake had been audited around it. Findings: none.
  What it gets right, checked rather than assumed:
  - **`TOKEN_EXPIRY_LEEWAY_SECONDS = 0`**, deliberately overriding
    `jsonwebtoken`'s default of 60. The comment (`:60-73`) identifies a
    *compound* bug the default caused: the leeway made an expired token usable
    for a further minute, **and** — because the revocation denylist evicts an
    entry once that entry's `exp` passes — it made a **revoked** token usable
    again inside the same window once any later revocation triggered a prune.
    That interaction is easy to miss and they found it. I verified the claim
    that the two cannot drift: the prune at `:812-813` computes
    `cutoff = now - TOKEN_EXPIRY_LEEWAY_SECONDS` and retains while
    `exp > cutoff`, deriving from the same constant.
  - **`validate_token` is the single convergence point for both transports**,
    and the comment says why (`:743-752`): a check placed in the HTTP
    middleware alone would not apply to the WebSocket, *"which is exactly how
    the WebSocket once escaped the per-account rate limiter."* Account-state
    checks live here rather than in the middleware for that reason.
  - **The registry is re-read on every request** rather than trusting the
    signed claims, so a suspension takes effect immediately instead of after
    the longest outstanding token expires.
  - **`claims.iat <= creds.tokens_valid_from` is inclusive**, with the
    reasoning recorded: `iat` has one-second resolution, so a token minted
    moments before an invalidation carries the same timestamp as one minted
    after, and refusing both fails closed at the cost of one client retry.
  - **The JWT secret is dstack-sealed**, not configured:
    `main.rs:766-781` derives it from `"darknyx/jwt-secret/v2"` with an explicit
    32-byte length assertion, so it never appears in env, compose, or the
    attested `compose_hash`.
  - **`jti` is 128 bits of CSPRNG** (`:565-568`), ample against denylist-key
    collision, and `Validation::default()` pins the algorithm list to HS256 so
    `alg: none` / algorithm-confusion is rejected at decode.
  - **The public test credential cannot reach production, two ways.**
    `config.rs:441` rejects `DARKNYX_TEE_API_KEY == TEST_API_KEY` at boot, and
    `state.rs:1199-1202` additionally *strips* the test account when loading a
    persisted snapshot — so even a dev `accounts.db` carried forward is
    sanitized, with a warning. `state.rs:1289-1291` regression-tests both.
- **The enclave's signer derivation is sound.** `keys/ed25519.rs` pins one
  derivation-path prefix (`"darknyx/ed25519-signer/v2"`) whose bump is
  explicitly tied to the multisig rotation ceremony, derives shard `i` at
  `"{prefix}/{i}"`, asserts the dstack-returned seed is exactly 32 bytes before
  constructing the key, and range-checks the shard count to `1..=16` matching
  the vault's `MAX_TEE_KEYS`. `signer_set_hash` concatenates fixed 32-byte
  pubkeys in shard order, so the SHA-256 preimage is unambiguous without
  length-prefixing — which is what lets a client bind the *whole* key set to
  the quote (verified against `api/attestation.rs` in the attestation batch).
  The one-key-three-roles unification (payload signer, on-chain `tee_authority`,
  tx fee-payer) is documented with the reasoning for the PR 4g.3 walk-back
  rather than left implicit.
- **The TEE-key rotation ceremony script validates its input properly.**
  `scripts/rotate-tee-pubkey.mjs:36-70` — the most consequential governance
  action in the repo, since it sets the key set the vault accepts settle
  payloads from — rejects more than 16 keys, non-base58 input, the default
  (all-zero) pubkey, and duplicates before submitting. Those mirror the
  on-chain guards that `initialize_governance.rs:140`
  (`initialize_rejects_partial_and_duplicate_shard_key_sets`) tests, so a
  typo'd ceremony fails locally rather than half-writing a broken signer set.
- **`darkpool-crypto`'s Poseidon layer is a thin, correct delegation.**
  `poseidon.rs` dispatches to `solana_poseidon::hashv` under
  `target_os = "solana"` and `light-poseidon`'s `hash_bytes_be` otherwise —
  the same parameter set and endianness on both sides, which is what makes the
  host/on-chain byte equality hold by construction rather than by test. (Its
  rejection of inputs ≥ the modulus is the Rust half of SW-23.)
- **`/v1/stream`'s session and auth handling is correct on every axis I
  tested.** This is the venue's only authenticated socket, so the checks matter:
  - **Token expiry is genuinely enforced**, not merely warned about. `:379-390`
    closes the socket once `exp <= now` with *"bearer token expired; reconnect
    and login"*, and emits the `auth_expired` warning at the 60-second mark. The
    module doc's claim at `:30-32` holds.
  - **An authenticated socket cannot switch identity.** `login:604-615` rejects
    a re-login under a different `account_id` — so a socket that has already
    subscribed or placed under account A cannot be re-pointed at account B while
    retaining A's subscriptions.
  - **Token refresh cannot exhaust the connection cap.** The account slot is
    claimed only on the *first* successful login (`:616-620`), with the
    reasoning written down: *"a re-login (token refresh) on an already-attributed
    socket must not take a second slot — that would let a client exhaust its own
    cap by renewing."* The `auth_expired_warned` latch is likewise reset only
    when `exp` actually advances (`:651-656`), so a replayed stale token cannot
    re-arm the warning.
  - **Cancel-on-disconnect is scoped to the session, not the account.** The
    sweep walks `s.session_orders`, so closing one socket cannot cancel orders
    another socket of the same account placed — which is the failure mode the
    doc at `:34-36` promises to avoid, and it delivers. (Its cost is SW-29.)
  - **`cancel_resting_unchecked` is safe despite the name.** It skips the
    trading-key signature — correct for a server-initiated sweep — and ownership
    is established structurally instead: the ids can only have come from
    `:748`, a successful `place_core` on *this* authenticated session.
- **The matcher's per-match conservation is exact, and there is no rounding
  dust.** This was the question I most wanted answered in `algorithm.rs`, since
  `quote = floor(base × P* / price_scale)` looks like the classic place value
  leaks. It does not, because the floored `quote_amt` is used **identically on
  both sides** — the buyer pays exactly it, the seller receives exactly it — so
  the flooring picks a price point rather than splitting a quantity. Ledgering
  both mints from `algorithm.rs:442-505`: quote out = `quote_amt + buyer_fee +
  buyer_change` = buyer's `note_amount` by construction of `buyer_change_amt`;
  base out = `crossable + seller_fee + seller_change` = seller's `note_amount`.
  Both balance exactly, with the two fee notes as the only other sinks. The
  residual effect is that the seller absorbs sub-unit rounding (always < 1 quote
  atomic unit, always in the buyer's favour) — standard for any integer
  exchange, and the degenerate case where it floors to zero is explicitly caught
  by the U-06 guard at `:462-469` rather than minting an unspendable
  zero-amount note.
- **Every arithmetic path in the match loop is overflow-checked.**
  `checked_mul` into `u128` for the notional with an explicit `u64::MAX` bound
  (`:445-453`), `u64::try_from` on both fee narrowings with the reasoning
  written down (`:474-481`), `checked_add` for both charges, and — the one that
  matters — **`checked_sub` for both change amounts, returning
  `MatchError::Conservation` rather than wrapping** (`:487-504`). A collateral
  note that cannot cover its charge fails the batch loudly instead of underflowing
  into a huge change note.
- **Price-time priority is correctly implemented.** `algorithm.rs:762-771` sorts
  bids by descending price then ascending `arrival_slot`, asks by ascending
  price then ascending `arrival_slot` — standard price-time priority, with the
  FIFO tie-break explicit rather than left to sort stability. Note that orders
  sharing both a price *and* an arrival slot (common, since a Solana slot is
  ~400 ms) fall back to book iteration order; that is unspecified rather than
  unfair, and matcher fairness is already a documented TEE-trusted property in
  `CRYPTOGRAPHY.md`, so it is recorded as an observation, not a finding.
- **Self-trade prevention is keyed on the right identity, and says so honestly.**
  `:403-405` matches on `owner_commitment` — which intake pins to the collateral
  note via `verify_commitment`, so a settling wash cannot lie about it — rather
  than on `trading_key`, which a single user re-derives freely per order. The
  comment states the residual Sybil limitation plainly (a user can fund a second
  wallet and wash across the two) instead of overclaiming.
- **The circuit set is sound on independent review — no finding.** This closes
  the largest value-at-risk gap in the coverage map. Prior passes had read only
  `templates/match_batch.circom` (the F-04 re-derivation) and
  `valid_spend` (S-01); the remaining five circuits and both shared templates
  had never been reviewed by anyone. Checked for the standard circom soundness
  failures — assignment without constraint (`<--` where `<==` is needed),
  missing boolean constraints on selectors, missing range checks on
  semantically-bounded signals, unconstrained public outputs, and conservation
  overflow:
  - **`templates/merkle.circom`** — both `MerkleTreeChecker` and
    `MerkleRootFromLeaf` carry `pathIndices[i] * (1 - pathIndices[i]) === 0`
    (`:29`, `:64`). This is *the* classic Merkle-circuit soundness bug: without
    it a prover picks arbitrary selector values and forges membership against
    any root. It is present in both. Every signal uses `<==`; the checker ends
    in a hard `root === levelHashes[depth]`, and the root-computing variant
    correctly exposes the root for the caller's conditional binding instead.
  - **`valid_input`** — `Num2Bits(64)` plus an `IsZero`-forced non-zero on
    `amount` (`:86-90`), commitment bound with `===` (`:110`), membership
    hard-constrained. Its `tokenMint[2]` carries no range check, which is
    correct rather than an omission: the halves are public inputs the *verifier*
    supplies from the real mint account, so a prover cannot choose them.
  - **`valid_deposit`** — same amount constraints, plus `Num2Bits(128)` on both
    mint halves. I confirmed against `deposit.rs:98-116` that every public input
    is on-chain-derived (`pubkey_pair_be32` over the real mint, `u64_be32` over
    the transferred amount), so those range checks are defence in depth. The
    asymmetry with `valid_input` is cosmetic — worth knowing before someone
    "fixes" either one.
  - **`valid_merge`** — the most constraint-dense of the set, and correct on
    every axis that matters: `isActive` is boolean (`:84`); each amount is
    64-bit-bounded with active ⇒ non-zero (`:93`) **and inactive ⇒ exactly zero**
    (`:94`, which is what stops a padding slot smuggling witness-only value);
    membership is bound conditionally (`:114`); dummy slots emit a public
    commitment of 0 (`:119`); at least one slot must be active (`:129-131`).
    **Conservation holds because `Num2Bits(64)` is applied to the *sum*
    (`:136-137`)** — four u64 addends reach at most 2⁶⁶, far below the field
    modulus, so no silent wraparound is possible and an overflowing merge is
    rejected outright rather than truncated.
  - **`valid_wallet_create`** — `Num2Bits(128)` on both root-key halves, five
    distinct domain tags across the five Poseidon calls preventing cross-role
    second-preimage collisions, and a `===`-bound public commitment. Its
    comment at `:31-34` is the single most useful line in the circuit tree:
    *"Range checks on field elements are NOT automatic in circom."*
  - **The one genuine in-circuit gap is known, deliberate, and closed
    on-chain.** `valid_merge` does **not** constrain the K input commitments to
    be pairwise distinct, so a witness using the same note in two active slots
    would double-count it in the sum. `merge.rs:100-110` closes this with an
    explicit O(K²) scan (S-11) that runs **before** proof verification, and the
    comment there records exactly why it exists rather than relying on the
    System Program's duplicate-`create_account` rejection: *"the whole guarantee
    resting on one runtime behaviour, with no in-circuit backstop and no
    negative test, is not a place to leave value conservation."*
  - **Negative-test coverage is real, not assumed.** `merge-prover.test.ts`
    exercises the failure side in-circuit — membership violation (`:139`),
    all-dummy witness (`:162`), active zero-amount input (`:187`), and
    **u64 output overflow (`:202`)** — and `merge_verify.rs:473` covers the
    on-chain duplicate scan. The constraints that carry conservation are the
    ones with negative tests behind them.
- **The loadgen's measurement plumbing is sound where it counts.** Audited only
  for measurement honesty (see SW-27's scope note). `metrics.rs:65-76` **clamps**
  each sample into the histogram's bounds before recording, with the reasoning
  written down — an out-of-range value would make `record` return `Err`, and
  discarding that would silently drop the sample and *bias P99 downward*. That
  is the failure mode a careless harness has, and it was anticipated. The
  histograms are HdrHistogram with explicit bounds and 3 significant figures;
  429s are counted in both `submits_4xx` and `submits_429` so the totals stay
  consistent (`:99-103`); the non-atomicity of `snapshot_counters` across
  counters is acknowledged rather than assumed away (`:120-123`); a panicked
  trader task is surfaced rather than swallowed because *"a silently-dropped
  JoinError would skew the benchmark numbers"* (`run.rs:203-208`); and the 429
  backoff sleep is deliberately taken **after** `elapsed_us` is captured
  (`trader.rs:158` vs `:175`), so retry waiting never contaminates a latency
  sample. Most importantly the report prints target rate, actual rate **and the
  achieved/target ratio** (`report.rs:52-66`), which is precisely the number
  that makes a harness's own back-pressure visible to the reader.
- **The daemon's `/tree/leaves` snapshot is trust-minimizing, and correctly so.**
  `tree-merkle-provider.ts:99-150` does not take the TEE's word for anything it
  can check: it bounds the page size against what it asked for, requires the
  advertised root to be **stable across every page** (catching a tree that moves
  mid-snapshot), verifies each `leaf_index` equals its expected sequential
  position, bounds the total against the 2²⁰ capacity, then **rebuilds the root
  locally from the leaves and requires it to equal the advertised root** — and
  finally passes it through `verifyRoot` against the on-chain shard's finalized
  recent-root ring. A gateway that serves wrong leaves cannot produce a matching
  root, so the client detects it without trusting the enclave at all. This is
  also what makes SW-23 unreachable here: a leaf ≥ the field modulus would
  reduce differently and fail the root comparison.
- **`LocalMerkleTree`'s arithmetic matches the on-chain construction.** I traced
  `root()` and `witness()` against each other at n = 1, 2 and 3 leaves — the
  cases where the power-of-two padding and the `smallDepth === 0` special case
  bite — and they agree, and both agree with the incremental construction in
  `programs/vault/src/merkle.rs` (depth 20, `poseidon2(left,right)`,
  `zero_subtree_roots[i] = poseidon2^i(0)`). The leaf-level padding uses literal
  32 zero bytes, which is correct precisely because `zeroSubtreeRoots[0]` is
  defined as that same value, and the upper-path extension folds
  `zeroSubtreeRoots[d]` on the right, matching a tree that grows on its right
  edge. Only its efficiency is wrong (PF-26).
- **Both enclave prove backends guard against witness drift.**
  `prover/ark_prover.rs:249-270` extracts the circuit's *own* computed public
  inputs and compares them to the off-circuit vector by count, then by index in
  order — with a dedicated `RootMismatch` error for the first element. The
  native/snarkjs-format path gets the equivalent from
  `assert_public_inputs` (`snarkjs.rs:121-153`). So a witness-assembly bug in
  the enclave fails locally with a naming error rather than as an on-chain
  `InvalidProof`. SW-26 is the observation that the client SDK does this on only
  one of its three prove paths.
- **The hand-coded wire layer has not drifted — checked mechanically, not by
  eye.** CLAUDE.md §8.3 warns that `idl/vault-client.ts` hand-mirrors every
  discriminator and Borsh layout with no Anchor IDL runtime and that *"CI
  doesn't catch this — only the integration tests do,"* so this was the batch's
  main question. Results:
  - **Discriminators cannot drift from bytes**, because
    `anchorDiscriminator` (`vault-client.ts:53-58`) computes
    `sha256("global:<name>")[..8]` at runtime rather than hardcoding arrays. The
    risk therefore reduces to the name string, and I diffed all 15 names the SDK
    uses against the `#[program]` handler names in `programs/vault/src/lib.rs`:
    every one matches. The three on-chain handlers the SDK omits
    (`tee_forced_settle_batched`, `close_batch_validity_marker`,
    `close_vault_config`) are enclave- and admin-only, correctly out of scope.
  - **`VaultConfig`'s fixed offsets are arithmetically correct.**
    `sdk/tee/vault-config.ts:23,27,29,30` asserts `TEE_PUBKEYS_OFFSET = 40`,
    `NUM_TEE_KEYS_OFFSET = 1258`, `NUM_TREES_OFFSET = 1259`,
    `VAULT_CONFIG_ACCOUNT_LEN = 1264`. Recomputed field-by-field from
    `state.rs` with `MERKLE_DEPTH = 20` and `MAX_TEE_KEYS = 16`:
    8 disc + 32 admin = 40; + 512 tee_pubkeys = 552; + 32 root_key = 584;
    + 640 zero_subtree_roots = 1224; + 32 protocol_owner_commitment = 1256;
    + 2 fee_rate_bps = **1258**; num_tee_keys 1258, num_trees **1259**, bump
    1260, `_padding[3]` → **1264**. All four constants land exactly, and the
    struct declares explicit tail padding so `zero_copy` introduces no implicit
    gaps.
  - **The `merge` instruction's Borsh layout matches its handler signature**
    field-for-field (`vault-client.ts:1046-1062` vs `lib.rs::merge`):
    `tree_id: u8`, `Vec<[u8;32]>` as u32-LE length + elements,
    `output_commitment`, `token_mint`, `merkle_root`, `k: u8`, proof — in that
    order — and the account list matches the `Merge` accounts struct.
- **The S-01 recipient binding landed in lockstep, end to end.** The Critical
  from the 07-25 pass required a client-side change that CLAUDE.md §5.2 warns is
  easy to miss. It is present: `sdk/utxo/withdraw.ts:134-147` splits
  `params.destinationTokenAccount` via `pubkeyPairBE` and passes
  `recipient: [destLo, destHi]` into the VALID_SPEND prover, matching
  `withdraw.rs:167-178`'s `[note_commitment, merkle_root, nullifier, mint_lo,
  mint_hi, amount, dest_lo, dest_hi]`. I also confirmed the halves are not
  transposed: both `pubkeyToFrPair` (TS) and `pubkey_pair_be32` (Rust) return
  `[lo, hi]` with `lo` from bytes 16..32.
- **The daemon's on-chain governance read has a complete validation chain** —
  and is the direct contrast to SW-05, which found the TEE's own raw reads
  lacking it. `daemon.ts:80-93` derives the address as a PDA, **checks the
  account owner equals the program id**, and reads at `finalized`;
  `sdk/tee/vault-config.ts:39-75` then checks the exact account length, the
  `account:VaultConfig` discriminator, that `num_tee_keys` is in 1..=16, that
  `num_tee_keys == num_trees`, and that no key is the default pubkey or a
  duplicate. Every one of those is a check SW-05 asks the TEE side to adopt.
- **Fill encryption is the strongest crypto in the client, and its one
  catastrophic failure mode is closed at the call site.** ChaCha20-Poly1305
  loses everything under (key, nonce) reuse — plaintext XOR *and* Poly1305 key
  recovery — so the question is whether the enclave can ever repeat a pair.
  It cannot: `settle/fill_recovery.rs:127-129` draws a fresh 32-byte ephemeral
  secret from `OsRng` **per fill**, and `:166-167` a fresh 12-byte nonce **per
  side**, so the AEAD key differs per fill even before the nonce does. The
  surrounding construction is equally careful:
  `isContributoryX25519PublicKey` (`fill-encryption.ts:46-56`) rejects
  low-order points on **both** directions — the recipient key when encrypting
  and the ephemeral key when decrypting, the RFC 7748 contributory check that
  most implementations omit; the HKDF `info` binds both public keys
  (`:59-70`), foreclosing key-substitution and unknown-key-share; the
  recipient's public key is **recomputed from the secret** rather than accepted
  as a parameter (`:128`), so it cannot be spoofed into the KDF; and every
  failure path returns `null` with no distinguishing error, giving no
  padding/validity oracle.
- **The master-seed backup envelope is well built.** The AAD binds a fixed
  domain string; `parseBackup:132-144` pins every KDF parameter by exact match,
  so a hostile envelope cannot dictate the work factor (the attack SW-16 notes
  the keystore also closes); hex fields are length-exact; and both the derived
  key and the plaintext seed are zeroed in `finally` on both paths. It also
  enforces a 12-character passphrase minimum on export **and** import
  (`:25`, `:45-51`, `:153`) — the guard SW-16(c) finds missing in the daemon
  keystore. Only the work factor is wrong (SW-22).
- **Key derivation has negligible modular bias and clean domain separation.**
  `deriveSpendingKey`, `deriveMasterViewingKey` and `deriveBlindingFactor` all
  reduce a **64-byte** (512-bit) KDF output modulo the ~254-bit BN254 scalar
  field (`key-generators.ts:104-150`), so the reduction bias is ~2⁻²⁵⁸ —
  the correct wide-reduction practice rather than the common 32-byte mistake.
  Every derivation uses a distinct info string, and although two KDF families
  are in play (HKDF-SHA256 for spend/trade/root/order-id/viewing-enc,
  `darknyxShakeKdfV1` for viewing and blinding), they are different primitives
  over the same seed, so no cross-domain collision is reachable. The SHAKE
  construction is explicitly *not* claimed to be KMAC (`:216-218`, `:272-274`),
  which is the honest framing.
- **`userCommitmentFromKeys` makes the trading-key exclusion structural.**
  `user-commitment.ts:51-58` notes that `UserCommitmentInputs` has no
  `tradingKey` field at all, so the Rust `test_commitment_excludes_trading_key`
  property is enforced by the type rather than by a test — the right way to pin
  an exclusion. Domain tags are distinct per tree level (10/11/12/13/14),
  preventing cross-role second-preimage collisions, and the output is
  range-checked through `bn254ToBE32`.
- **`modify` needs no domain tag of its own, and the composition is sound.**
  `canonical.ts` defines only `ORDER_DOMAIN` and `CANCEL_DOMAIN`, which looked
  like a gap given `PUT /orders/{id}` exists. It is not:
  `order-client.ts:63-67` shows `ModifyOrderRequest` is
  `{ cancel_signature, cancel_nonce, replacement: PlaceOrderRequest }` — a
  modify is literally a signed cancel plus a fully, independently signed
  replacement order, each under its own domain. So no third layout exists to
  confuse with the other two, and the v5 property ("a body of one shape can
  never verify as the other") is preserved by construction. Residual worth
  noting only: the cancel signature covers `(order_id, trading_key,
  cancel_nonce, session_id)` and therefore does not bind *which* replacement it
  authorizes — harmless today because the replacement carries its own signature
  over its own nonce and session, but it means the pairing is not cryptographically
  fixed.
- **The canonical order encoding is unambiguous and its documented length is
  correct.** Every field is fixed-width except the symbol, which is
  length-prefixed and bounded to 32 (`canonical.ts:147-151`), so no two distinct
  intents can serialize identically. I recomputed the stated total: 16 domain +
  1 length + S + 1 + 1 + 4×8 + 16 + 32 + 8 + 32 + 32 = `171 + S`, matching both
  the header comment and the running-offset block. Lengths of all five
  fixed-size fields are validated before use.
- **A retried placement cannot double-place, and three independent mechanisms
  cover the lost-response case.** `WsOrderPlacer.withReconnect`
  (`order-placer.ts:170-193`) resends the same signed body after a transport
  error, and `place.ts:43-48` treats *any* throw as terminal `rejected` — which
  looked like a state-divergence bug (order live on the book, daemon believes it
  rejected, collateral released for re-spending). It is defended three times
  over: `api/orders.rs:720-732` makes an exact retry **idempotent**, returning
  the original `arrival_slot` when the `canonical_digest` matches, and rejecting
  only a *different* body under the same `order_id`; `commit_order:645-649`
  refuses a second order against a reserved collateral note
  (`collateral_in_use`), so the released-collateral path fails closed; and
  cancel-on-disconnect is on by default (`order-placer.ts:142`), so the socket
  drop that caused the transport error also sweeps the phantom order. The
  residual is narrow — an error on a *healthy* socket, or two consecutive
  transport failures, still lands the order in terminal `rejected` while it
  rests — and is exactly what SW-11's reconcile routine would resolve. Note
  `ensureConnected()` is called outside the `try` in the retry loop, so a failed
  reconnect propagates without consuming a retry.
- **`Daemon.emit` really does isolate a failing subscriber.** `daemon.ts:708-716`
  wraps each listener call in its own `try/catch` with the comment *"a bad
  subscriber must not break the daemon"*, and it does exactly that — a throwing
  SSE writer (a disconnected control-API consumer, the obvious case) cannot
  prevent the remaining listeners from receiving the event, and cannot escape
  into the fill/settlement paths that emit. Checked because a broken
  event fan-out would have compounded PF-24 into a correctness problem rather
  than a memory one; it does not.
- **The `/tee/*` proxy is an allowlist, not a pass-through.**
  `control-api.ts:163-186` dispatches on a fixed set of seven sub-paths and
  returns 404 for anything else, so the control API cannot be used to reach an
  arbitrary TEE route (`/admin/drain` in particular). The two parameterized
  entries are the only caller-controlled inputs, and SW-20 covers the encoding
  gap in one of them. Worth recording explicitly because a proxy that forwards
  the operator's gateway credential is precisely where a pass-through would be
  severe.
- **Strict attestation genuinely fails closed without governance pins — the
  claim I most expected to fail.** `attestation.ts:17-18` promises that *"strict
  mode requires a working DCAP verifier **AND** the governance pins
  (`compose_hash` + `tee_pubkey`)"*, but `attestation.ts:212-218` checks only
  `opts.quoteVerifier`. Given how many comments in this repo have overstated
  what the code does, and given that CA-04 records `EXPECTED_COMPOSE_HASH` as
  still unpopulated, the obvious hypothesis was that strict mode runs today with
  no measurement pinning while reporting `dcapVerified: true`. **It does not.**
  The enforcement is real, just located one layer down:
  `packages/sdk/src/tee/verify-core.ts:288-290` returns `"pin_required"` when
  `strict && (!expected.composeHash || !expected.teePubkey)`. A daemon started
  strict without pins refuses to start. I traced the config path too
  (`config.ts:118-126`): a missing, empty, partial, or typo'd
  `DARKNYX_DAEMON_EXPECT_*` all collapse to `attestation: undefined` or a
  partial object, and every one of those ends at `pin_required`. A malformed
  pin value cannot match the event-log hash and ends at `compose_mismatch`.
  Fail-closed on every branch.
- **The K-shard signer set is properly quote-bound, and shard 0 is
  cross-checked.** `attestation.ts:203-210` hashes the *whole ordered* key set
  from `/info` into `boundKeySetBytes`, which `verifyReportAgainstExpected`
  compares against the `report_data` inside the verified quote
  (`verify-core.ts:279-284`) — and `crates/darknyx-tee/src/api/attestation.rs:105-107`
  confirms the enclave builds exactly that preimage. So `/info.tee_pubkeys` is
  not self-reported: a gateway cannot substitute a key set. `:190-202`
  additionally requires `/info.tee_pubkey` and `/info.tee_pubkeys[0]` to equal
  `/attestation.tee_pubkey`, closing the gap between the two separate HTTP
  responses. This is the part of the module that most needed to be right, and it
  is.
- **`composeHash ?? info.composeHash` (`attestation.ts:244`) is unreachable on
  the strict path, not a fallback to self-reported data.** Reaching line 244
  requires `verifyReportAgainstExpected` to have returned `null`, which under
  `strict: true` requires `expected.composeHash` to be present *and*
  `composeHashFromEventLog` to have returned a value equal to it
  (`verify-core.ts:288-302`). So the left operand is always defined there. Noted
  because it is a latent hazard rather than a live one: if the pin requirement
  were ever relaxed, this line would silently start stamping a self-reported
  `/info` value as `dcapVerified: true`. Deleting the `??` would make the
  invariant explicit at no cost.
- **The keystore's v2 sealing design is sound; SW-16 is about its edges, not
  its cryptography.** Checked specifically for the ways encrypted key files
  usually fail:
  *KDF-parameter injection* — the classic attack, where a hostile file sets
  `n=1` and the loader obeys, is closed twice over: v2 pins the profile by exact
  string (`:483-490`) and v1 requires `n`/`r`/`p` to equal the only values the
  old writer ever emitted (`:510-518`), so file fields never control the work
  factor or the allocation (`:210-213` says so deliberately).
  *Header substitution* — the v2 AAD (`:336-345`) binds domain, KDF name,
  profile, cipher, salt and IV into the GCM tag, so none can be swapped without
  failing authentication; v1 lacks AAD but pins the same values by equality
  instead.
  *Version downgrade* — `requireExactKeys` (`:232-245`) rejects any file
  carrying both field sets, and a v2 ciphertext fails GCM auth under a
  legacy-derived key regardless.
  *Nonce reuse* — salt and IV are both freshly random per seal (`:350-351`), so
  the key changes with the IV and GCM's catastrophic-reuse condition cannot
  arise.
  *Parser abuse* — file and ciphertext sizes are bounded (`:218-219`,
  `:262-275`), hex must be lowercase and exact-length, and scalars must be
  canonical decimal **and** below the BN254 modulus (`:277-286`).
  *Key material* — the derived key is zeroed in a `finally` on both the seal and
  the open path (`:375-377`, `:472-474`).
  *Migration atomicity* — the v1→v2 path decrypts, constructs a `Keystore` to
  prove the identity is usable, and only then atomically replaces
  (`:467-471`, `:552-561`), with `atomicReplace` doing tmp→fsync→rename→fsync(dir)
  and cleaning up on every error path (`:380-425`). A failed migration leaves
  the original v1 file intact and exposes no partial file.
- **The match-leaf hash is byte-identical across all three languages.** Checked
  directly rather than trusting the comments:
  `prover/leaf.rs:75-90` (Rust prover),
  `programs/vault/src/instructions/tee_forced_settle_batched.rs:111-130`
  (on-chain), and `packages/sdk/tests/helpers/match-batch-prover.ts:233-257`
  (TS) all hash the same 11 fields in the same order under the same
  `DOMAIN_LEAF_V2 = 23`. The on-chain side pins `is_active` to the constant `1`
  with the correct justification — Tx D can only settle an active slot — rather
  than reading it from the payload. 11 inputs, within the `MAX_X5_LEN`
  ceiling CLAUDE.md §5.3 requires.
- **The Groth16 on-chain byte conversion is correct and pinned.**
  `prover/convert.rs:42-62` performs the two easy-to-get-wrong steps — the pi_a
  y-negation and the pi_b Fq2 `(c0,c1)→(c1,c0)` swap — and its tests
  (`:97-142`) assert each *observably*: pi_a's y decodes to `-y` and
  `assert_ne!` against the raw `y`, the Fq2 slots are reconstructed and compared
  against the original, and pi_c is asserted **not** negated. That last
  assertion is the one that catches a symmetric mistake, and it is present.
- **`prover/rapidsnark_sys.rs` is the most defensively written code in this
  sweep.** The FFI boundary treats the native library as potentially hostile and
  proves it: `checked_output_len` (`:246-254`) rejects a reported length beyond
  the buffer before any slicing; `checked_required_capacity` (`:256-269`) caps a
  `SHORT_BUFFER` retry size against `MAX_*_CAPACITY` *before* allocating it; a
  `SHORT_BUFFER` that does not request more space is rejected rather than
  retried (`:221-226`); retries are bounded at 3. Each of these has a test,
  including one that feeds `u64::MAX` as the required size and asserts nothing
  is allocated. The zkey-lifetime hazard is documented at `:19-24` with the
  reason the buffer variant is used instead of the file variant, and `RawProver`
  is `Send` but deliberately not `Sync` — so Rust's own type system, not the
  comment, enforces the "one prove at a time" requirement.
- **`prover/inputs.rs:47-64` reads batch-level config from `slots[0]` without
  asserting slot 0 is active, and this is still safe.** `pad_batch`
  (`witness.rs:152-175`) appends padding only after the real slots, so slot 0 is
  active whenever the batch has any real match. If it somehow were not, the
  consistency loop compares every *active* slot against slot 0's padding values
  and returns `MixedBatchConfig`; and an all-padding batch would produce a
  digest that `verify_match_batch` recomputes and rejects on-chain. Fails closed
  on both paths.
- **`prover/constraints.rs:73-120` validates padding correctly, and the reason
  is subtle.** It runs over every slot including inactive padding, and the
  checks pass for a dummy only because `dummy_slot()` sets `price_scale: 1`
  rather than `0` (`witness.rs:138`) — `0` would trip the explicit
  `PriceScale` guard at `:77-79`. All arithmetic is `u128`, so a product that
  would overflow `u64` surfaces as a constraint violation rather than a wrap or
  a panic, as the module doc claims.
- **`prover/wtns.rs` is a serializer, not a parser.** It emits the `.wtns` v2
  framing from an in-memory `Vec<Fr>`; nothing external is decoded, so it is
  outside the fuzzing plan's Tier B. The one `debug_assert` (`:32-35`) covers a
  `u32` bound that a 137 GB witness would be needed to reach.
- **The daemon's lifecycle reducer is sound, and its edge-triggering claim is
  true.** `order-lifecycle.ts:82-204` is genuinely pure — no mutation of the
  input order, no I/O, `now` injected. The comment at `:168-175` claims that
  deriving intents only from `fill` / `filled` / `cancelled` / `expired` /
  `settlement-failed` — and *not* from action outcomes — is what stops a
  permanently-failing merge from hot-looping. That holds: `merge-failed` clears
  `mergeInFlight` but is excluded from `triggersIntents`, so clearing the latch
  cannot re-fire the intent in the same turn. Every phase transition is
  correctly guarded by `isTerminal` or an explicit source-phase whitelist, so a
  late duplicate update cannot revive a terminal order. This is one of the few
  places in the sweep where a comment asserting a subtle safety property
  actually matches the code.
- **`lifecycle-engine.ts:81-105` atomicity claim holds.** `dispatch` does
  `getOrder` → `reduceOrder` → `putOrder` with no `await` between the read and
  the write, and both store calls are synchronous (`node:sqlite`). On Node's
  single thread each transition is therefore atomic with respect to the store,
  as documented at `:12-16`, and interleaved fills and action outcomes compose
  without a lock. `runAction` is correctly detached and its catch converts an
  executor throw into `merge-failed` without letting the rejection escape.
- **`orders-listener.ts:64-88` update mapping is correct and complete.** Every
  `OrderUpdate` kind maps to the phase event its module doc claims, unknown
  kinds return `null` rather than defaulting to a transition, and a dispatch
  failure for an untracked order is caught so it cannot tear down the socket
  (`:115-121`). The deliberate split — `fills` owns residual-note bookkeeping,
  `orders` owns phase — is respected on both sides: `partially_filled` maps to a
  phase-only event and does **not** touch `pendingChangeNotes`.
- **The merge/settle collision is contained on-chain.** SW-12 lets the daemon
  *attempt* a merge of a note pinned by a live `NoteLock`, but
  `programs/vault/src/instructions/merge.rs:110-124` rejects it
  (`NoteAlreadyLocked`), and `:100-110` independently rejects duplicate active
  inputs. The N-04 / S-03 / S-11 guards are all present and correctly ordered
  *before* proof verification and any state mutation. The daemon-side defect is
  therefore wasted work, not a double-spend.
- **CS-12 is genuinely closed.** `packages/sdk/src/utxo/merge.ts:73,191` derives
  the merged output inner from the consumed input commitments
  (`deriveMergeOutputInnerHash`), and `packages/daemon/src/merge-runner.ts:54`
  confirms *"the daemon has no restart-sensitive counter to persist or
  reserve."* The mutable counter is gone. The 07-25 pass-2 carry-forward item
  asking for this re-verification can be closed.

---

## 4. Coverage after this sweep

| Surface | LOC | Status after this pass |
|---|---|---|
| `settle/worker.rs` | 1,810 | **Audited** (non-test body; ~1,390 lines). SW-03. |
| `oracle/accumulator.rs` | 393 | **Audited** in full. Clean. |
| `oracle/vaa.rs` verify path | ~200 of 442 | **Audited** (parse ordering + `verify_signatures` + profile selection). Clean. |
| `oracle/sync.rs` apply path | ~120 of 189 | **Audited**. Clean. |
| `api/stream.rs` subscription auth | ~120 of 775 | **Audited** for the routing/authorization question. Clean. |
| `api/state.rs` routing | ~160 of 969 | **Audited**. SW-04. |
| `api/transparency.rs` | 227 | **Audited** in full. SW-05, SW-06. |
| `api/mod.rs` router topology | 173 | **Audited**. SW-02. |
| `solana_rpc/client.rs` | ~1,000 | **Audited** — request path (SW-01), per-method response validation, commitment ranking, gTFA decoding. No new standalone finding; yielded the **SW-07 amendment** (`program_id` is available and discarded). |
| `settle/job.rs` + `api/settlement.rs` | ~250 | **Audited** (exposure path). SW-01. |
| `merkle/mirror.rs` | ~470 | **Audited** — append/no-rewind, proof folding. Clean. |
| `merkle/events.rs` + `sync.rs` | ~1,000 | **Audited** in full. **SW-07.** |
| `matcher/interval.rs` | ~1,140 | **Audited** — tick, paging loop, gate re-check, reservation lifecycle, continuation rotation. **SW-09.** |
| `settle/scheduler.rs` | 894 | **Audited** — state, ingest, concurrency, reservation lifecycle, batch-error path. **SW-08.** Paging interaction with the matcher tick still not read. |
| `prover/leaf.rs` | 420 | **Audited** in full. Three-way leaf lockstep verified against on-chain + TS; single-build path extraction correct. Clean. |
| `prover/convert.rs`, `witness.rs`, `inputs.rs`, `constraints.rs`, `wtns.rs` | ~850 | **Audited** in full. Clean — see §3 for each. |
| `prover/snarkjs.rs` | 154 | **Audited** in full. **SW-14**, **SW-15**. |
| `prover/rapidsnark_sys.rs` + `rapidsnark_prover.rs` | 654 | **Audited** — FFI boundary, buffer/retry bounds, zkey lifetime, witness-backend selection. Clean (§3); the native-default selection is what makes SW-14 the production path. |
| `prover/ark_prover.rs` input assembly | ~140 of 469 | **Partial** — `push_all_inputs` / `circom_input_json` read for SW-14. The ark prove path and its drift guard are not yet read. |
| `config.rs` + `boot.rs` | ~860 | **Audited** — env parsing/validation, secret handling, auth-mode gate, market/oracle invariant, boot pause wiring. No new finding; yielded the **SW-01 amendment** (`SecretString` + the Hermes URL policy already exist). |
| `packages/sdk/src/fills/recover.ts` | ~130 | **Audited**. Clean. |
| daemon `merge-runner` + `sdk/utxo/merge.ts` | ~200 | **Audited** in full (was CS-12 only). **SW-12**, PF-22. |
| daemon `order-lifecycle.ts` + `lifecycle-engine.ts` | 328 | **Audited** in full. Reducer + engine clean (§3). **SW-13.** |
| daemon `store.ts` | 304 | **Audited** in full. SW-10, PF-18, PF-19, PF-21; `listActiveOrders` defect folded into **SW-11**. |
| daemon `daemon.ts` orchestration | ~724 | **Audited** — start/stop, listener wiring, note pruning, collateral selection, trust refresh. **SW-11**, PF-21. |
| daemon `fills-listener.ts`, `orders-listener.ts`, `settlement-tracker.ts`, `note-select.ts`, `action-executor.ts`, `types.ts` | ~600 | **Audited** in full. **PF-20**; listener mapping clean (§3). |
| daemon `keystore.ts` + `bin/keystore-init.ts` | ~680 | **Audited** in full — derivation, v2 sealing, v1 migration, atomic write, parsing. **SW-16**, **PF-23**; the sealing cryptography is clean (§3). |
| daemon `attestation.ts` + `config.ts` | 408 | **Audited** in full, plus the `verify-core.ts` enforcement path and the TEE's `report_data` construction it depends on. **SW-17**, **SW-18**; strict-mode fail-closed and key-set binding verified (§3). |
| daemon `control-api.ts` + `tee-read.ts` | 338 | **Audited** in full — routing, auth gate, SSE, the `/tee/*` proxy. **SW-19**, **SW-20**, **PF-24**; proxy allowlist and subscriber isolation verified (§3). |
| **Batch A — order-signing path**: daemon `build-place-request`, `order-placer`, `place` + sdk `orders/canonical`, `order-client`, and the TEE intake (`api/orders.rs` `prepare_order`/`place_core`/`commit_order`) it is signed against | ~900 | **Audited** as one cluster, tracing each signed and *unsigned* field to its consumer. **SW-21.** Canonical encoding, modify composition, and retry idempotency verified (§3). |

### Documentation-surface audit (2026-08-02 restructure)

Migrating every audit document into `audits/` surfaced three things worth
recording here rather than losing in a move commit:

- **`docs/attestation-dcap-enforcement-plan.md` was the only non-audit document
  still citing the old root `audit_2/` path** (five references, now repointed).
  It is a remediation plan, not an audit record, so it correctly stays in
  `docs/` — but it owns **A-1**, an `audit_2/READINESS.md` finding, and is the
  implementation plan for **CA-01**'s family. It is *not* tracked by any
  `tracker.md`, which makes it the one piece of remediation work in the repo
  with no closure ledger. Worth folding into a tracker when CA-01 is scheduled.
- **`scripts/check-brand-namespace.sh` hard-coded four audit paths** in its
  exclusion list (`audit_1/**`, `audit_2/**`, `docs/audit-*.md`,
  `docs/security-remediation-tracker.md`). Collapsed to `audits/**`. Any future
  gate script that enumerates audit paths will silently stop excluding them
  after a rename — the single-prefix form removes that class of breakage.
- **No CI workflow referenced any audit document**, so the move could not break
  a gate. Verified by grep across `.github/`, `scripts/`, and `docs/` before
  moving.

### Repo-wide gap analysis — re-measured after Batch R

Measured exhaustively across `crates/`, `programs/`, `packages/`, `circuits/`
and `scripts/` (non-test lines only). **Read: ~26,500. Unread: ~12,900.**

| Remaining batch | Files | Code | Why it is next |
|---|---|---|---|
| ~~**S — settle tail**~~ | `settle/{metrics,pipeline,drain,verify_match_batch,close_marker,vault,priority,sign}` | ~1,600 | **Partially closed** — `settle_batched`, `submit`, `marker_sweep`, `alt_pool` audited (§3). The remainder is metrics/orchestration glue with no untrusted input. |
| ~~**T — API tail**~~ | `api/{state remainder,error,tree,account,rate_limit,drain,instruments,metrics,health,system,info}` | ~2,000 | **Partially closed** — `orders.rs` and `debug.rs` audited. Remainder is read-only endpoints + `error.rs`/`rate_limit.rs`, both already scoped by SW-01/SW-20/SW-02. |
| ~~**U — SDK tail**~~ | `sdk/{zk,wallet,utxo remainder,idl remainder,orders/build-order,orders/builders,fills/ws-client}` | ~2,400 | **Partially closed** — `settlement/` and `trading-ws-client.ts` audited (§3). Remainder is builders and prover wrappers already covered indirectly by parity tests and Batches B–D. |
| ~~**V — ops scripts**~~ | — | ~~2,185~~ | **Closed** — audited, no finding (§3): deploy asserts devnet, destructive ops are gated on-chain by `devnet-admin`, dependency gate diffs against a baseline. |
| ~~**W — loadgen `real_settle`**~~ | — | ~~3,280~~ | **Closed** — measurement-fidelity lens applied. **SW-34.** |
| *descoped* | `packages/indexer` | 753 | Owner-descoped: optional locator, no consumer. |
| *audit_1 covered* | vault admin/governance ix | ~1,000 | `initialize*`, `create_wallet`, `release_lock`, `rotate_root_key`, `set_*`, `close_*`. Unchanged in shape by sharding. |

**Closed:** circuits, `algorithm.rs`, `stream.rs`, `auth.rs`, the API routing
layer, `darkpool-crypto`, `matcher/{book,openings}`, `oracle/*`, `merkle/*`,
`solana_rpc/*`, `prover/*`, the daemon in full, `vault/{verify_match_batch,
lock_note,merge,withdraw,deposit,tee_forced_settle,merkle}`, CI/compose.

### Still unread — carry forward

| Surface | LOC | Why it still matters |
|---|---|---|
| `prover/ark_prover.rs` prove path, `icicle_prover.rs`, `groth16.rs` | ~900 | The remaining prover surface: the ark backend's prove + drift guard, the GPU backend, and the `Prover` trait. The GPU path is gated behind PR #65 and unmerged, so it is not yet on any production route. |
| **Batch B — note-lifecycle crypto**: sdk `keys/` (all four files), `utxo/note`, `match-output`, `user-commitment`, plus the TEE's `fill_recovery.rs` call site | ~1,200 | **Audited** as one cluster. **SW-22**, **SW-23**, **PF-25**; fill encryption, the backup envelope, KDF bias/domain separation and the user-commitment structure all verified clean (§3). `utxo/deposit`, `withdraw`, `merge`, `leaf-index`, `note-store`, `match-config` and `wallet/` still unread — carried into Batch C. |
| **Batch C — on-chain-facing client**: sdk `idl/vault-client.ts`, `seeds.ts`, `tee/vault-config.ts`, `utxo/withdraw`, `merge`, `leaf-index`, checked against `programs/vault/src/{lib,state}.rs` | ~2,000 | **Audited** as one cluster. **SW-24**, **SW-25**; discriminators, `VaultConfig` offsets, the `merge` Borsh layout, the S-01 recipient lockstep and the governance-read validation chain all verified clean (§3). `utxo/deposit`, `note-store`, `match-config` and `wallet/` read only incidentally — low residual. |
| **Batch D — client proving + witness**: daemon `merkle-tree`, `tree-merkle-provider`, `merge-prover` + `prover/ark_prover`'s witness/drift path, checked against the SDK's three prove paths | ~1,100 | **Audited** as one cluster. **SW-26**, **PF-26**; the snapshot trust model, the local tree arithmetic and both enclave drift guards verified clean (§3). `icicle_prover.rs` (336) unread — gated behind unmerged PR #65, not on any production path. |
| **Batch E — indexer** | 765 | **Descoped by the owner** — optional locator, no consumer, vestigial. |
| **Batch F — loadgen**: `metrics.rs`, `trader.rs`, `run.rs`, `report.rs` | ~950 of 8,207 | **Audited for measurement fidelity only** — test tooling, not shipped in the enclave, so credential/DoS/input-validation questions were deliberately skipped. **SW-27**; histogram clamping, outcome accounting and the achieved/target ratio verified sound (§3). `real_settle/` (~2,900) and `settlement_benchmark.rs` (480) not read — apply the same lens if their numbers are ever quoted. |
| `packages/indexer` | 765 | Documented as an optional locator with no consumer. Low risk. |
| `packages/sdk/src/utxo/` beyond recovery, `orders/`, `wallet/`, `zk/`, `idl/` | ~5,000 | Partially covered incidentally by earlier passes; never swept. |
| `crates/darknyx-tee-loadgen` | 5,790 | Test tooling, not shipped in the enclave. |
| No dynamic testing | — | Still no fuzzing of the accumulator/VAA parsers, no reorg simulation. The parsers read clean statically; a fuzz harness is the correct confirmation. |

---

## 5. What I could not rule out — needs the team

These are not open findings. They are questions where reading this repository
cannot produce the answer, and where the answer changes a severity or closes an
assumption.

| Question | Why it matters | Who can answer |
|---|---|---|
| **Is a dstack CVM's container overlay filesystem on encrypted storage?** The compose provisions and documents exactly one LUKS-encrypted volume (`darknyx_state`), which implies the rest is something else — but "something else" could still be an encrypted root disk. | Decides whether **SW-14** is Medium (crash residue + defence in depth) or High (plaintext trade amounts leaving the enclave boundary on every batch). The `tmpfs` fix is cheap enough to apply either way, so this does not block remediation — only the severity record. | Phala/dstack platform documentation or support; a `mount`/`lsblk` inspection inside a running CVM would settle it in a minute. |
| **Does the TEE's fills buffer depth, and the 1011 close it triggers, occur in practice at target volume?** SW-11's impact scales with how often a client actually lags past the buffer. | Decides whether SW-11's full reconcile routine is urgent or whether the one-hour mitigation suffices for launch. | A loadgen or daemon soak run measuring 1011 closes per client-hour under representative fill rates. |
| **Was the native witness generator's `input.json` ever present on a CVM that has since been snapshotted, migrated, or imaged?** | If so, historical witness data may exist outside the current instance, and rotating forward does not remove it. | Whoever holds the CVM lifecycle history for the devnet instances. |
| **Does my clean circuit review substitute for F-04?** **No — and it should not be recorded as if it did.** I read all nine circuits and both templates for the standard soundness failure modes and found none (§3), which raises confidence and closes the *coverage* gap. It does not close the *assurance* gap. | F-04 (independent circuit audit) remains an open mainnet gate. A generalist reading circom for known bug classes is a different artifact from a specialist who does only circuit soundness — the failures that survive a review like mine are the ones that need tooling (formal underconstrained-signal analysis, e.g. Picus/Ecne) or deep familiarity with the proving stack's own edge cases. | An external circuit auditor. Budget it as originally planned; treat §3's result as evidence the code is in good shape to hand over, not as a reason to descope. |

---

## 6. Suggested order

1. **SW-07 first.** It is the only Critical, it is unauthenticated, it costs the
   attacker one transaction, and its effect is a permanent venue halt with no
   in-band recovery. Ship the fail-closed half (option C) even if the scope fix
   takes longer — it is the smaller change and converts silent wrong-proof
   service into a loud stop.
2. **SW-01, and rotate the Helius key.** A live credential exposure reachable by
   any authenticated trader. Rotation is independent of the code fix; do it
   immediately. Fix is ~1.5 days.
3. **SW-02 and SW-03 together.** They compose with SW-01 into an
   unauthenticated → RPC-exhaustion → credential-disclosure chain, and both are
   under a day each.
4. **SW-14 option A — the `tmpfs` mount.** Fifteen minutes, no code change, and
   it stops the enclave writing plaintext trade amounts to a non-encrypted path
   on every batch. Do not wait on the disk-layout question in §5 to land it.
5. **SW-19.** Make the control token mandatory (generating one at boot if unset)
   and add the `Origin`/`Host`/`Content-Type` checks. Half a day, and it closes
   a default-insecure server that can place orders and deposit funds. Correct
   the module doc in the same change — its "single-tenant host" guidance is what
   makes the insecure configuration look reasonable.
6. **SW-11 option C now, options A+B scheduled.** Wiring `onResync` to a pause +
   error and clearing `mergeInFlight` at boot is about an hour and converts
   silent fund invisibility into a loud halt. The real reconcile routine can
   follow. Fold in SW-12 (~2 h) and SW-13 while in the same files.
7. **SW-04, SW-05, SW-06** as hygiene, alongside a sweep for any third instance
   of the arbitrary-eviction pattern.
8. **Finish the carry-forward list** in §4 — the `prover/` encoders and the
   remaining daemon surface, `control-api.ts` first (it is the daemon's own
   listening socket).
9. **Commission a fuzz harness** for `oracle::accumulator::parse` and
   `oracle::vaa::parse`. Both read clean, and both are precisely the shape where
   static reading is weakest. Note SW-07 is a reminder that the *boundary*
   around a clean parser matters as much as the parser: `events.rs` decodes
   correctly and is exploited through what it is willing to decode.
