# Darknyx remediation tracker — 2026-07-25 review

This is the closure ledger for
[`docs/audit-2026-07-25-withdraw-intake-boundary-review.md`](audit-2026-07-25-withdraw-intake-boundary-review.md)
(soundness `S-01…S-12`, performance `PF-01…PF-07`) plus the `AU-01…AU-07`
authentication findings — `AU-01…AU-05` surfaced while validating S-02, and
`AU-06…AU-07` from the follow-up complete pass of `api/auth.rs` on 2026-07-26.

It follows the conventions of
[`docs/security-remediation-tracker.md`](security-remediation-tracker.md): a
finding is not closed by code alone. The closing PR must link the invariant
restored, wire/circuit impact, tests, devnet/CVM evidence where applicable, the
measured cost-to-protocol delta, and rollback instructions.

Status values are `Open`, `In progress`, `Code complete`, `Closed`, `Deferred`,
and `Won't Fix`. `Closed` requires merged code and the evidence named in the row.
`Deferred` requires a recorded reason and a re-entry condition.

## Validation provenance

Every `S-` finding was independently reproduced against `main` @ `698facb`
before any remediation was planned — anchors were re-read in the code, not
taken from the audit prose. Two anchors in the audit are inaccurate and are
corrected in the rows below (S-03, S-01). Three cost estimates are corrected
(S-02, S-02(C), PF-03).

**Prior-art note.** The 2026-07-20 `D-01…D-09` deep-dive pass is referenced by
this audit as known prior art but was **never entered in the tracker**. See the
backfill row at the end of this document.

---

## Soundness findings

| ID | Severity | Owner | Planned remediation slice | Invariant / required evidence | Status |
|---|---|---|---|---|---|
| S-01 | **Critical** | ZK + vault + SDK | `remediation/audit-2026-07-25-vault` | A `VALID_SPEND` proof authorises a destination, not merely a note: the withdraw destination is bound as a circuit public input, so a copied proof submitted with a substituted `destination_token_account` fails `InvalidProof (6000)`. Regenerated `.zkey` + `vk_valid_spend.rs`; negative roundtrip test; devnet redeploy + mandatory tree reset + `devnet-deposit-withdraw` | **Validated** — devnet 2026-07-25 |
| S-02 | High | TEE | `remediation/audit-2026-07-25-availability` | Order intake verifies the relayed `VALID_INPUT` Groth16 against the circuit VK and requires its `merkle_root` to be in the mirror's recent-root ring for the declared `tree_id`; a fabricated note, a garbage proof, or a stale root is rejected at intake with a 4xx instead of freezing an honest counterparty's collateral on-chain | **Validated** — live CVM 2026-07-25 |
| S-03 | High | Vault + SDK + TEE | `remediation/audit-2026-07-25-availability` (A), `remediation/audit-2026-07-25-vault` (B/C) | An expired `NoteLock` is recoverable through a shipped interface: SDK instruction builder + expiry-aware note status (**done**), `withdraw`/`merge` rejecting only on a **non-expired** lock, and a durable TEE sweeper for rent. Litesvm `lock → expire → withdraw` and `→ release_lock → withdraw` (currently zero coverage) | **Validated** — devnet + CVM 2026-07-25 |
| S-04 | Medium | Vault + TEE + SDK | `remediation/audit-2026-07-25-vault` | The batch marker's TTL is not a caller-chosen value: `expiry_slot` is derived on-chain from `clock.slot + MAX_BATCH_VALIDITY_MARKER_TTL_SLOTS`. Litesvm regression proving a front-run replay with a 1-slot TTL is rejected | **Validated** — devnet 2026-07-25 |
| S-05 | Medium | Vault + SDK | `remediation/audit-2026-07-25-vault` | A duplicate note commitment cannot be deposited twice: a commitment-keyed `DepositedNoteEntry` `init` makes it structurally impossible and fails loudly at the point of the mistake. SDK seed + PDA helper per CLAUDE.md §8.3; litesvm duplicate-deposit rejection | Code complete; positive path on devnet, duplicate-rejection litesvm-only |
| S-06 | Medium | Matcher + SDK | `remediation/audit-2026-07-25-availability` | No retired v2 (SHA-256) change-note derivation is reachable from a shipped surface: `derive_inner`/`deriveChangeInner` removed, the SDK public index no longer exports it, and `run_batch` emits no commitment the chain will never create. `CHANGE_ROLE_*` constants retained (still live) | Code complete — offline gate only |
| S-07 | Low | TEE + matcher + SDK | `remediation/audit-2026-07-25-availability` | A captured cancel signature is not valid in a later boot session: `CancelCanonical` binds `session_id` and `cancel_nonce` is strictly increasing per trading key. Both pinned fixture digests regenerated in the same commit | Code complete — offline gate only |
| S-08 | Low (in-model) | Docs | `remediation/audit-2026-07-25-availability` | `CRYPTOGRAPHY.md` §2 states that a `VALID_INPUT` proof authorises **the note, not the order**, for the root-ring window — so a compromised TEE's bound is the note size and extends to orders the user believes cancelled | Code complete — offline gate only |
| S-09 | Low | TEE + SDK | `remediation/audit-2026-07-25-availability` | The enclave does not hold a value it never uses: the `nullifier` field is removed from `PlaceOrderRequest`, `NoteOpening`, and the OpenAPI schema, so a memory disclosure cannot join intake nullifiers to on-chain withdrawals | Code complete — offline gate only |
| S-10 | Low | TEE | `remediation/audit-2026-07-25-availability` | Both replay maps are bounded with insertion-ordered eviction and a slot TTL; a burst can no longer evict live idempotency records and turn legitimate retries into `duplicate` rejections. Eviction-order and TTL tests plus a loadgen soak | Code complete — offline gate only |
| S-11 | Low (defense-in-depth) | Vault | `remediation/audit-2026-07-25-vault` | `merge` asserts active input commitments are pairwise distinct **in the program**, so value conservation does not rest solely on Solana runtime duplicate-account behaviour. Litesvm negative test | Code complete — offline gate only |
| S-12 | Info | Docs | `remediation/audit-2026-07-25-availability` | `CRYPTOGRAPHY.md` describes the shipped protocol: §6 root ring is 64 (not 32) with the corrected freshness figure, §8 steps 5/6 no longer describe a removed on-chain conservation backstop, §10 attributes net-zero `outstanding` to the circuit | Code complete — offline gate only |

## Performance findings

| ID | Severity | Owner | Planned remediation slice | Invariant / required evidence | Status |
|---|---|---|---|---|---|
| PF-01 | Perf-Nit | Vault | `remediation/audit-2026-07-25-vault` | Settle reads stored bumps for both `NoteLock` accounts and derives the marker with `create_program_address`; litesvm CU trace shows the reduction against the 115,000 limit | **Validated** — devnet settle 2026-07-25 |
| PF-02 | Perf-Nit | Vault | `remediation/audit-2026-07-25-vault` | `lock_note` reads `vault_config.bump` from account data rather than re-deriving; CU trace per lock transaction | **Validated** — devnet settle 2026-07-25 |
| PF-03 | Perf-Nit | — | — | **Deferral CONFIRMED 2026-07-26.** Verified real: the field is `[u8; 128]` (`settle/payload.rs`), and Tx D sits at 1109 B with 123 B headroom, so narrowing to 120 would take it to 131 B. But 8 bytes of 1232 costs a canonical-hash bump plus cross-language fixture regeneration in Rust AND TypeScript. Not worth it standalone. **Re-entry condition:** the next change that already bumps `MatchResultPayload`. The audit's claim that this rides S-01's ceremony is incorrect — different circuit, different hash | Deferred |
| PF-04 | Perf-Nit | Vault + SDK | `remediation/audit-2026-07-25-vault` | `withdraw` allocates one guard PDA, not two. `NullifierEntry` (zero readers repo-wide) is removed, eliminating the latent brick where two notes sharing an `inner_hash` collide on a mint- and amount-independent nullifier. Shipped in the same commit as S-05, which it funds | **Validated** — devnet withdraw carries 13 account keys, not 14 |
| PF-05 | Perf-Nit | — | — | **PREMISE DISPROVED 2026-07-26 — no work required.** The audit asserted the intake mutex is the ~27 ord/s ceiling. Read against the code: the global `submission_replay` lock (`orders.rs:729–768`) holds only two HashMap gets, an atomic gate read, `commit_order`, and the replay record — microseconds. The expensive work is deliberately OUTSIDE it; the VALID_INPUT verify sits at `orders.rs:585`, the lock is taken at 729. 27 ord/s implies ~37 ms serialized per order and nothing in that section costs that. The historical loadgen figure was client-bound, not server-bound. **Separately noted:** `try_consume_rate` takes a GLOBAL WRITE lock on `rate_buckets` for every request including read-only routes (`state.rs:900`). Its critical section is tiny and it is not a bottleneck today, but it is the only unconditional global write lock on the hot path and is the credible version of this finding if throughput ever binds | **Closed** — premise disproved |
| PF-06 | Perf-Nit | — | — | **MEASURED, NOT WORTH DOING 2026-07-26.** `OrderOpening` is **456 bytes** (not the 256 the audit cited — that is the embedded proof alone) and a clone costs **28.6 ns** (1M iterations, `black_box`ed, release). At ~32 copies per N=16 batch that is **~0.9 µs against a ~2.2 s prove**, about 0.00004% of the batch. An `Arc` would add indirection and lifetime coupling to save nothing measurable | **Won't Fix** — measured negligible |
| PF-07 | Perf-Nit | — | — | **Deferral CONFIRMED 2026-07-26, mechanism quantified.** Real: settle requests `SETTLE_COMPUTE_UNIT_LIMIT = 115_000` (`settle/pipeline.rs:109`) while consuming ~79,786 measured, so 31% of the per-writable-account block ceiling (12M CU) is wasted — 104 vs 150 settles per block against one writable account. That ceiling is roughly 250x above the current ~1 settle/s. **Re-entry condition:** the tree-sharding throughput work, which is what would raise concurrent settles against a shared account | Deferred |

## Authentication findings — surfaced during S-02 validation

The audit deferred `api/auth.rs` (§5.3) while noting that bearer auth is the
only gate in front of S-02. Reviewing it produced these. AU-01 is material to
S-02: it removes the rate bound the audit's blast-radius reasoning assumes.

`AU-01…AU-05` came out of a **partial** read taken while validating something
else. `AU-06` and `AU-07` come from the **complete** pass of that file
(2026-07-26), commissioned precisely because a partial read is not evidence of
absence. That pass found one live vulnerability — and it was one this
remediation effort had itself introduced, which is the argument for auditing a
surface after changing it rather than only before.

| ID | Severity | Owner | Planned remediation slice | Invariant / required evidence | Status |
|---|---|---|---|---|---|
| AU-01 | Medium | TEE | `remediation/audit-2026-07-25-availability` | Order operations are rate-limited on **every** transport. `/v1/stream` is on the public router with no `rate_limit_middleware`, so `order.place`/`modify`/`cancel` frames bypassed the per-account token bucket entirely. WS ops now charge the same bucket at the same weights, pinned by a parity test against `route_cost` | **Validated** — live CVM 2026-07-25 |
| AU-02 | Medium | TEE | `hardening/enclave-auth-controls` | A compromised account can be stopped: account disable plus revoke-all-tokens-for-account. Today the registry carries only `is_admin` and revocation kills only the caller's own `jti`, so there is no eviction path | **Closed** — live-enclave validated 2026-07-26 (image -72): an issued token stops working at suspension (403), a suspended account cannot mint a new one, bulk invalidation refuses old tokens while the account keeps working |
| AU-03 | Low ops | TEE | `hardening/enclave-auth-controls` | Env-based admin credential rotation is a no-op once `accounts.db` exists (`ensure_admin` inserts only when the `api_key` is absent). Either honour an env change or document that rotation is API-only. **Re-entry condition:** operational runbook work before mainnet | **Closed** — live-enclave validated 2026-07-26: redeploying the same api_key with a new secret logs the divergence warning and the original secret still authenticates, so the stored registry is provably authoritative |
| AU-04 | Low | TEE | `hardening/enclave-auth-controls` | The `jti` revocation denylist has no expiry-based eviction and grows without bound — the same class as S-10. Fold into S-10's bounded-map work if cheap, else track. **Re-entry condition:** S-10 implementation | **Closed** — each entry carries its token expiry, pruned on write and at boot; the v2 snapshot round-tripped a restart (`revoked_expired_dropped` reported at boot) |
| AU-05 | Low | TEE + ops | `hardening/enclave-auth-controls` | `POST /auth/token` has no in-process rate limit; the router comment defers to a reverse-proxy limit that does not exist in this repo. The argon2 semaphore bounds concurrency and RAM, not request rate. **Re-entry condition:** ingress configuration before mainnet | **Closed** — unknown keys refused before hashing, per-account login bucket (bounded by registered accounts; an outsider cannot throttle a real account), and permits taken without waiting so excess is shed not queued |
| AU-06 | **Medium** | TEE | `hardening/token-expiry-leeway` (PR #72) | A revoked token stays refused for as long as it is still decodable. `Validation::default()` carries `leeway: 60`, so a token was accepted until `exp + 60`, while the AU-04 denylist prune drops an entry once `exp` has passed — between those two moments a REVOKED token was off the denylist AND still decodable, and any later revocation triggered the prune. Demonstrated with a failing test (revoked token returned 204 where 401 was required) before the fix. Leeway pinned to 0 and the prune margin derived from the same constant, so raising one widens the other. **Regression introduced by AU-04 in this same effort** | **Code complete** — PR #72, offline gate green |
| AU-07 | Medium | TEE + ops | — | An unauthenticated client cannot hold enclave resources indefinitely. `/v1/stream` upgrades unauthenticated by design (login is in-band) and closes after 60 s idle, but ANY frame — including a transport `ping` — refreshes the idle timer, and there is no cap on concurrent connections, so sockets can be held open indefinitely at near-zero attacker cost. Not fixed in the auth pass: the mitigation is partly at ingress, and the in-process half needs a connection cap chosen against real client behaviour rather than guessed. **Largest remaining item on this surface** | Open |

---

## Declined

| ID | Rationale |
|---|---|
| S-08(B) | Binding `order_id` into `VALID_INPUT` would force the client to prove **per order** rather than per note. Client-side proving is already the placement-latency bottleneck, so this is a permanent UX regression bought for a Low finding that sits inside an explicitly accepted trust boundary. S-08(A) — documenting the widened boundary — is the appropriate remedy for an accepted risk. |
| S-11(B) | In-circuit strict ordering of merge inputs costs a full circuit + zkey + VK cycle and a tree reset for an issue that is **currently unreachable** and that a two-line on-chain `require!` closes completely. Reconsider only if the merge circuit is opened for an unrelated reason. |
| S-02(C) | Releasing the enclave reservation on *confirmed* lock failure requires per-note lock attribution that does not exist: the lock branch short-circuits on the first error and discards the remaining `JoinSet` results, so "buyer landed, seller did not" is not observable. S-02(A) removes the attack that made this urgent and S-03(C) removes the user-visible harm. **Re-entry condition:** settle-worker crash-recovery work, which must add per-note outcome attribution anyway. |
| S-03(B) | **Moved to the Phase B slice, not dropped.** The TEE lock sweeper is a near-clone of `settle/marker_sweep.rs`, but S-03(C) in that same slice relaxes the withdraw/merge guards to honour `expiry_slot` — removing the liveness dependency on releasing at all and demoting the sweeper from recovery mechanism to rent reclamation. Building it against today's semantics would produce a liveness-critical component the next slice immediately makes non-critical. **Re-entry condition:** land S-03(C), then design the sweeper against the relaxed guard. Simpler there too: `release_lock` has no `has_one = payer`, so any shard key can pay, unlike the marker sweeper which must use the primary. |

---

## Cost to the protocol

Recorded because a security fix that silently taxes the hot path is not free.
Figures are pre-implementation estimates and **must be replaced with measured
values** in the closing PR evidence.

| Change | Latency | Compute units | Rent | Transaction bytes |
|---|---|---|---|---|
| S-01 recipient binding | client proving unchanged (2 constraints) | withdraw **+~8.3k** (2 public inputs) | — | none (derived from an account already present) |
| S-02 intake verification | **+2–5 ms per order, outside every lock** | — | — | — |
| S-02 mirror root ring | +~1 µs lookup | — | — | +2 KB RAM per shard |
| S-03(A) SDK builder | — | — | **reclaims** ~0.0011 SOL | +1 transaction only when a stale lock exists |
| S-03(B) sweeper | background | batched | **reclaims** rent | — |
| S-03(C) honour expiry | — | ~0 (data already borrowed) | — | removes a transaction from the user path |
| S-04 derive expiry | — | **−~100** | — | **−8 on Tx B** |
| S-05 deposit guard | — | +1 init CPI (~2–3k) | +0.00128 SOL | +1 account |
| PF-04 drop nullifier entry | — | **−1 init CPI (~2–3k)** | **−0.00128 SOL** | **−1 account** |
| **S-05 + PF-04 net** | — | **~0** | **~0** | **~0** |
| S-11(A) | — | ~50 (O(K²), K ≤ 4) | — | — |
| PF-01 | — | **−3–5k per settle** | — | — |
| PF-02 | — | **−1.5–3k per lock × 2N** | — | — |
| S-07 | — | — | — | +32 B cancel body |
| S-09 | negligible reduction | — | — | **−64 hex characters** per order |
| S-10 / AU-01 / AU-02 | ~0 | — | — | — |

**Expected net:** settle **~50–100k CU cheaper per N=16 batch**; deposit and
withdraw rent-neutral in aggregate; Tx B 8 bytes smaller; withdraw +~8.3k CU on
a standalone transaction that is not on the settle hot path. The only added
recurring runtime cost is intake proof verification, placed where no lock is
held so it cannot stall the matcher tick.

---

## Remediation slices

| Slice | Findings | Chain impact | Ceremony |
|---|---|---|---|
| `remediation/audit-2026-07-25-availability` | S-02, S-03(A/B), S-06, S-07, S-08(A), S-09, S-10, S-12, AU-01, AU-02 | none — no redeploy | none |
| `remediation/audit-2026-07-25-vault` | S-01, S-03(C), S-04, S-05, S-11(A), PF-01, PF-02, PF-04 | one devnet deploy + **mandatory tree reset** + one CVM run | S-01 freezes a circuit ahead of the external audit and Phase-2 ceremony |

**Sequencing.** Circuit changes must be frozen **before** the external circuit
audit (`F-04`) and the Phase-2 ceremony (`N-18`); those are terminal steps, not
parallel ones. Landing S-01 is therefore on the critical path *to* the ceremony,
not blocked by it.

---

## Measured, replacing estimates

For the first three rows both columns are the **same workload**: one
`tee_forced_settle_batched` at the N=16 worst case, measured by the litesvm CU
trace. Stating that explicitly because an estimate and a measurement taken at
different N are not a comparison, and the PF-01 numbers are far enough apart to
invite that misreading.

The rows below the rule are from the 2026-07-26 follow-up pass and are **not**
that workload — each names its own, because a table of numbers with an implied
shared denominator is how the misreading starts.

| Change | Estimated | **Measured** |
|---|---|---|
| PF-01 + PF-02 stored bumps, combined | 3–5k CU | **−1,392 CU** (81,178 → 79,786) |
| S-05 + PF-04 net rent | ~0 | **0** — 56 B and one init CPI out of withdraw, the same in to deposit |
| S-04 Tx B size | −8 B | **−8 B** (304 → 296) |
| — *follow-up pass, own workloads* | — | — |
| PF-06 `OrderOpening` clone | "256-byte deep clone" | **456 B struct, 28.6 ns/clone** (1M iters, black_box, release) — ~0.9 µs per N=16 batch |
| PF-07 settle CU over-request | unquantified | **115,000 requested vs ~79,786 used** = 31% of the 12M per-writable-account block ceiling; 104 vs 150 settles/block |
| S-02 intake verify | "adds latency to intake" | **2.49 ms** isolated (500 iters, release). The 331 ms order-submit figure reported earlier is a laptop→prod9 round trip, NOT this |

The 3–5k estimate was written as a combined PF-01 + PF-02 figure, but its bulk
sat in PF-01, and PF-01 fell short because that figure assumed the marker's
explicit `find_program_address` was replaced too; it was not. The remaining
~700 CU does not justify hand-rolling the ordering that would require
(reading the bump from raw data after the owner/discriminator/length checks)
on the settle hot path. Recorded rather than quietly counted as done.

The first PF-01 reading looked like a REGRESSION against a stale 78,388 figure
from an older tracker entry. An A/B — stash, rebuild, re-measure — is what
showed the real baseline had moved to 81,178. **Do not compare a CU number
against a remembered baseline; re-measure both sides.**

## Implementation decisions worth recording

**S-02 verification is gated on `settle_enabled`.** The check runs in every
configuration that can actually settle, and is skipped where a live settle
driver was never constructed — placeholder/loadgen mode (U-09) and the
simulator. Those boots are enqueue-only: their orders can never produce a
`lock_note`, and the loadgen sends stub proofs against synthetic roots by
design. Verifying there would reject traffic that is harmless by construction
while changing nothing about S-02, whose harm is entirely on-chain. The
consequence to be aware of: **a loadgen run does not exercise the S-02 path**,
so intake-verification latency must be measured with a real-mint CVM, not the
loadgen.

**The mirror's root window is intentionally 8x the on-chain ring.** On-chain,
`append_leaves` performs one `push_root` per instruction for up to
`MAX_BATCH_APPEND` leaves; the mirror is fed leaf-by-leaf and cannot see
instruction boundaries. Equal sizing would make the mirror evict roots up to 8x
faster than the chain, rejecting orders the vault would accept. The asymmetry
guarantees the check is permissive-only, with `lock_note` authoritative.

**S-02 reuses the on-chain verifier rather than an ark-groth16 port.** The
verifying key is pulled from the vault's generated `vk_valid_input.rs` by
`#[path]`, so it cannot drift, and the relayed proof bytes are consumed in
their existing `groth16-solana` layout with no conversion. This removed the
planned proof-decoder entirely — and with it the `pi_a`-negation and Fq2-swap
failure modes.

**Two findings the positive test caught that a negative-only suite would not.**
The first fixture proved with ark's default `LibsnarkReduction` rather than
`CircomReduction` and produced an invalid proof; a suite that only asserted
"garbage is rejected" would have passed a verifier that rejected *every*
legitimate order. Incidentally, the same test confirms the committed
`vk_valid_input.rs` matches `circuit_final.zkey`, independently corroborating
the audit's §2.1 no-drift finding.

## Pull request evidence template

Every remediation PR must record:

- Finding IDs and the invariant restored.
- Wire, account-layout, canonical-domain, circuit, and compatibility impact.
- Exact validation commands and negative/adversarial cases.
- **Measured** cost delta replacing the estimate in the table above.
- Devnet transaction signatures and CVM image/attestation evidence when required.
- Rollback instructions, including whether rollback invalidates notes, roots,
  orders, payloads, proofs, or deployed circuit artifacts.
- Tracker rows moved only as far as the available evidence supports.

---

## Devnet + CVM validation run — 2026-07-25

Program `C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx` (devnet, upgraded in
place), CVM `app_9ca3cded…db637` on node **prod9**, image
`ghcr.io/skysail-labs/darknyx-tee:tee-v3-hardening-70`
(`sha256:7a310fe2e99c95505732b0709843d181796cef837df549e6788ea83a74db9be6`),
`compose_hash=1ec96e587c0ecdf75a36a7db696f9f0aa21a85174690d1ed6dcce11953aa83ae`.

| Step | Evidence |
|---|---|
| Vault upgrade | `GHALqaENZForLfHiwqhShTdfwiP997JyAn1BDSfEhfZxXkWLmqkL3Cz6LqZgJQZRTWUYHPn4rvkGCrTew8MTpjz`, slot 478688292 |
| Tree reset (mandatory — S-01 rotated `vk_valid_spend`) | all K=4 shards to `leaf_count=0`, verified by direct account read |
| **S-01** VALID_SPEND with recipient bound | `devnet-deposit-withdraw` PASS. Withdraw `21nZD34zBdtHN2UtCyfbmuibACmgRAxUfcFPviTvPLpM9mqT1vYtoJpjtC9kfFQ1YfUa2VWxyE9iV7Pz7p7Hnrxb` — a real 8-public-input proof verified on-chain against the rotated VK |
| **PF-04** `NullifierEntry` dropped | same withdraw tx carries **13** account keys (11 declared + vault + ComputeBudget); the nullifier slot is gone. 148,018 CU |
| **S-03(C)** merge honours lock expiry | `devnet-merge` PASS — deposit×2 → VALID_MERGE(K=2) → VALID_SPEND withdraw, 5,000,000 tokens round-tripped |
| Leaf-index read path | `devnet-leaf-index` PASS |
| Merkle mirror cold-boot | `applied=0 total_leaves=0 shards=4` — empty, so the mirror could not mask a stale root |
| **S-03(B)** lock sweeper | boot log `lock sweeper spawned (expiry-gated NoteLock rent reclamation)` |
| **S-02** intake VALID_INPUT verify | live (gated on `settle_enabled`, and the boot log shows `settle pipeline ENABLED`). Order submit **331 ms buyer / 332 ms seller**, end to end including network — see the cost note below |
| **F-05** regression | over-cap expiry still rejected at intake (596 ms step) |
| Flagship | `cvm-settle-e2e` **PASS** in 45.9 s, on-chain `leaf_count 2 → 7` (+5: note_c/d + buyer change + base & quote fee notes) |
| Settle pipeline | `lock_ms=1321 prove_ms=2286 verify_ms=1301 alt_tx_ms=962 alt_wait_ms=818 parallel_ms=3588 settle_ms=11317 total_ms=14951` |
| Prover health | `witness_ms=281 prove_step_ms=1958` against the prod9 baseline 219/1967 — no PERF-INV-01 regression. Host probe `singlethread_mops_per_s=380.1`, `nr_throttled=0` |
| CVM stopped | confirmed `stopped` in `phala cvms list`; CPU CVM (`gpus=0`), so the GPU carve-out does not apply |

**S-02's measured intake cost.** The 331/332 ms figures are the whole
`POST /orders` round trip from a laptop to prod9, not the verification alone, so
they bound the added cost from above rather than isolating it. The Groth16
verify is a fixed 4-public-input pairing check with no network or disk in it;
the honest read is that S-02 did not move intake latency into a range anyone
would notice, and a tighter number needs in-enclave instrumentation rather than
a wall-clock client measurement.

**One real defect was found by this run.** `devnet-merge.test.ts` still built
the pre-S-01 VALID_SPEND witness with no `recipient` input, so witness
generation failed outright. Both devnet tests are env-gated
(`RUN_DEVNET_DW` / `RUN_DEVNET_MERGE`), so the offline gate cannot reach either
— a circuit signature change can only surface on a real devnet run. Fixed in
`18f3ce2`; the merge path passes on the retry. This is the concrete argument
against treating the offline gate as sufficient for circuit changes.

---

## Follow-up pass — `api/auth.rs` + deferred performance, 2026-07-26

Commissioned because `AU-01…AU-05` came out of a partial read, and because four
performance items had been deferred on reasoning rather than measurement.

### The auth surface

One live vulnerability (`AU-06`), and **this effort had introduced it**. The
revocation-list pruning added for `AU-04` evicts an entry once that entry's
`exp` passes, while `Validation::default()` honours a token until `exp + 60`.
Between those two moments a revoked token was off the denylist and still
decodable, and any later revocation triggered the prune. It was demonstrated
with a failing test — the revoked token returning `204` where `401` was
required — before being fixed, rather than asserted from reading.

The lesson worth keeping is not the library default. It is that a change which
bounds a data structure can silently weaken a security property enforced
somewhere else, and only a pass over the whole surface *after* the change finds
it.

One issue was found and deliberately **not** fixed (`AU-07`): the mitigation is
partly at ingress, and the in-process half needs a connection cap chosen
against real client behaviour rather than guessed at the end of an audit.

Checked and clean: algorithm confusion (HS256 pinned, no `alg` trust),
credential-verification timing (the non-short-circuit `&` keeps both argon2
verifies unconditional), privilege escalation through `/account/settings` (it
can only reach `AccountSettings`), the admin-lockout guard's TOCTOU (count and
mutation share one write guard), and secrets in logs.

### The deferred performance items

All four deferrals hold, but for materially different reasons than recorded,
and two are now closed rather than deferred:

| ID | Was | Now | Why |
|---|---|---|---|
| PF-03 | Deferred | Deferred (confirmed) | Real, but 8 bytes of 1232 against a three-language lockstep change |
| PF-05 | Deferred pending measurement | **Closed — premise disproved** | The expensive work is outside the lock; the cited ceiling was client-bound |
| PF-06 | Deferred | **Won't Fix** | Measured at 28.6 ns/clone — 0.00004% of a batch |
| PF-07 | Deferred | Deferred (confirmed, quantified) | Real 31% waste against a ceiling ~250x above current throughput |

The pattern across all four: every one named a **real mechanism**, and three had
an effect too small to act on. Only measurement separates those — which is why
"deferred pending measurement" was the right disposition for PF-05, and why
acting on the audit's estimate would have meant optimising a lock that was never
the constraint.

---

## Backfill — 2026-07-20 `D-01…D-09` pass

`docs/audit-2026-07-20-full-protocol-review.md` is cited as prior art by the
2026-07-25 review (S-03 sharpens D-01/D-09; S-08 relates to D-03; AU-02 relates
to D-07) but has **no rows in either tracker**. Its findings were never formally
dispositioned.

| ID | Owner | Required action | Status |
|---|---|---|---|
| D-01…D-09 | Security | Triage the 2026-07-20 pass into per-finding rows with the same validate-then-disposition discipline used here. Note that D-01's assumed recovery step (`release_lock` + re-place) was **not implemented at the time it was written** — S-03 is the correction | Open |

---

## Release gates touched by this pass

- **S-01 is release-blocking.** No real-value deposits before the withdrawal
  recipient is bound and the change has been through the external circuit audit.
- The audit's §5.1 finding sharpens `N-18`: amount privacy (P1b/P3b) removed the
  on-chain plaintext conservation backstop, so `VALID_MATCH_BATCH` is now the
  **sole** conservation guarantor. A recovered trapdoor mints value with zero
  on-chain check. This makes the Phase-2 ceremony a hard blocker rather than a
  best practice, and it must be stated as such in the ceremony's scope.
- **`AU-07` (unauthenticated socket hold) is the one open finding on the auth
  surface** and should be closed before an account is issued outside the
  operating team, alongside whatever ingress limiting fronts the gateway.
- `api/auth.rs` has now had a **complete** pass (2026-07-26), so it is no longer
  in the uncommissioned list below. `settle/worker.rs` crash recovery and
  `oracle/*` still are.

- Deferred review surfaces from §5 that remain uncommissioned, in priority order:
  `api/auth.rs` (partially covered here by AU-01…AU-05), `settle/worker.rs`
  crash recovery interleaved with partial-batch failure, and `oracle/*`.
