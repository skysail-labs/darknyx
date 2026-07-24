# Darknyx remediation tracker — 2026-07-25 review

This is the closure ledger for
[`docs/audit-2026-07-25-withdraw-intake-boundary-review.md`](audit-2026-07-25-withdraw-intake-boundary-review.md)
(soundness `S-01…S-12`, performance `PF-01…PF-07`) plus the `AU-01…AU-05`
authentication findings surfaced while validating S-02.

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
| S-01 | **Critical** | ZK + vault + SDK | `remediation/audit-2026-07-25-vault` | A `VALID_SPEND` proof authorises a destination, not merely a note: the withdraw destination is bound as a circuit public input, so a copied proof submitted with a substituted `destination_token_account` fails `InvalidProof (6000)`. Regenerated `.zkey` + `vk_valid_spend.rs`; negative roundtrip test; devnet redeploy + mandatory tree reset + `devnet-deposit-withdraw` | Open |
| S-02 | High | TEE | `remediation/audit-2026-07-25-availability` | Order intake verifies the relayed `VALID_INPUT` Groth16 against the circuit VK and requires its `merkle_root` to be in the mirror's recent-root ring for the declared `tree_id`; a fabricated note, a garbage proof, or a stale root is rejected at intake with a 4xx instead of freezing an honest counterparty's collateral on-chain | Open |
| S-03 | High | Vault + SDK + TEE | `remediation/audit-2026-07-25-availability` (A/B), `remediation/audit-2026-07-25-vault` (C) | An expired `NoteLock` is recoverable through a shipped interface: SDK instruction builder + `Wallet.withdraw` pre-flight, a durable TEE sweeper, and `withdraw`/`merge` rejecting only on a **non-expired** lock. Litesvm `lock → expire → withdraw` and `→ release_lock → withdraw` (currently zero coverage) | Open |
| S-04 | Medium | Vault + TEE + SDK | `remediation/audit-2026-07-25-vault` | The batch marker's TTL is not a caller-chosen value: `expiry_slot` is derived on-chain from `clock.slot + MAX_BATCH_VALIDITY_MARKER_TTL_SLOTS`. Litesvm regression proving a front-run replay with a 1-slot TTL is rejected | Open |
| S-05 | Medium | Vault + SDK | `remediation/audit-2026-07-25-vault` | A duplicate note commitment cannot be deposited twice: a commitment-keyed `DepositedNoteEntry` `init` makes it structurally impossible and fails loudly at the point of the mistake. SDK seed + PDA helper per CLAUDE.md §8.3; litesvm duplicate-deposit rejection | Open |
| S-06 | Medium | Matcher + SDK | `remediation/audit-2026-07-25-availability` | No retired v2 (SHA-256) change-note derivation is reachable from a shipped surface: `derive_inner`/`deriveChangeInner` removed, the SDK public index no longer exports it, and `run_batch` emits no commitment the chain will never create. `CHANGE_ROLE_*` constants retained (still live) | Open |
| S-07 | Low | TEE + matcher + SDK | `remediation/audit-2026-07-25-availability` | A captured cancel signature is not valid in a later boot session: `CancelCanonical` binds `session_id` and `cancel_nonce` is strictly increasing per trading key. Both pinned fixture digests regenerated in the same commit | Open |
| S-08 | Low (in-model) | Docs | `remediation/audit-2026-07-25-availability` | `CRYPTOGRAPHY.md` §2 states that a `VALID_INPUT` proof authorises **the note, not the order**, for the root-ring window — so a compromised TEE's bound is the note size and extends to orders the user believes cancelled | Open |
| S-09 | Low | TEE + SDK | `remediation/audit-2026-07-25-availability` | The enclave does not hold a value it never uses: the `nullifier` field is removed from `PlaceOrderRequest`, `NoteOpening`, and the OpenAPI schema, so a memory disclosure cannot join intake nullifiers to on-chain withdrawals | Open |
| S-10 | Low | TEE | `remediation/audit-2026-07-25-availability` | Both replay maps are bounded with insertion-ordered eviction and a slot TTL; a burst can no longer evict live idempotency records and turn legitimate retries into `duplicate` rejections. Eviction-order and TTL tests plus a loadgen soak | Open |
| S-11 | Low (defense-in-depth) | Vault | `remediation/audit-2026-07-25-vault` | `merge` asserts active input commitments are pairwise distinct **in the program**, so value conservation does not rest solely on Solana runtime duplicate-account behaviour. Litesvm negative test | Open |
| S-12 | Info | Docs | `remediation/audit-2026-07-25-availability` | `CRYPTOGRAPHY.md` describes the shipped protocol: §6 root ring is 64 (not 32) with the corrected freshness figure, §8 steps 5/6 no longer describe a removed on-chain conservation backstop, §10 attributes net-zero `outstanding` to the circuit | Open |

## Performance findings

| ID | Severity | Owner | Planned remediation slice | Invariant / required evidence | Status |
|---|---|---|---|---|---|
| PF-01 | Perf-Nit | Vault | `remediation/audit-2026-07-25-vault` | Settle reads stored bumps for both `NoteLock` accounts and derives the marker with `create_program_address`; litesvm CU trace shows the reduction against the 115,000 limit | Open |
| PF-02 | Perf-Nit | Vault | `remediation/audit-2026-07-25-vault` | `lock_note` reads `vault_config.bump` from account data rather than re-deriving; CU trace per lock transaction | Open |
| PF-03 | Perf-Nit | — | — | Deferred: narrowing `fill_recovery` to `[u8; 120]` reclaims 8 of 123 spare bytes but requires a canonical-hash bump and cross-language fixture regeneration. **Re-entry condition:** the next change that already bumps `MatchResultPayload`. Note the audit's claim that this rides S-01's ceremony is incorrect — different circuit, different hash | Deferred |
| PF-04 | Perf-Nit | Vault + SDK | `remediation/audit-2026-07-25-vault` | `withdraw` allocates one guard PDA, not two. `NullifierEntry` (zero readers repo-wide) is removed, eliminating the latent brick where two notes sharing an `inner_hash` collide on a mint- and amount-independent nullifier. Shipped in the same commit as S-05, which it funds | Open |
| PF-05 | Perf-Nit | — | — | Deferred pending measurement. The audit asserts the intake mutex is the ~27 ord/s ceiling while §5.9 records that no measurements were taken. **Re-entry condition:** a loadgen profile attributing intake latency to lock contention rather than to compute | Deferred |
| PF-06 | Perf-Nit | — | — | Deferred: `Arc<OrderOpening>` instead of a 256-byte deep clone. **Re-entry condition:** the next change that touches `matcher/openings.rs` | Deferred |
| PF-07 | Perf-Nit | — | — | Deferred: scaling the settle CU request to the actual leaf count raises the per-block writable-account ceiling. Not a bottleneck at ~1 settle/s. **Re-entry condition:** the tree-sharding throughput work | Deferred |

## Authentication findings — surfaced during S-02 validation

The audit deferred `api/auth.rs` (§5.3) while noting that bearer auth is the
only gate in front of S-02. Reviewing it produced these. AU-01 is material to
S-02: it removes the rate bound the audit's blast-radius reasoning assumes.

| ID | Severity | Owner | Planned remediation slice | Invariant / required evidence | Status |
|---|---|---|---|---|---|
| AU-01 | Medium | TEE | `remediation/audit-2026-07-25-availability` | Order operations are rate-limited on **every** transport. `/v1/stream` is on the public router with no `rate_limit_middleware`, so `order.place`/`modify`/`cancel` frames currently bypass the per-account token bucket entirely. WS flood regression showing the same threshold as HTTP | Open |
| AU-02 | Medium | TEE | `remediation/audit-2026-07-25-availability` | A compromised account can be stopped: account disable plus revoke-all-tokens-for-account. Today the registry carries only `is_admin` and revocation kills only the caller's own `jti`, so there is no eviction path | Open |
| AU-03 | Low ops | TEE | — | Env-based admin credential rotation is a no-op once `accounts.db` exists (`ensure_admin` inserts only when the `api_key` is absent). Either honour an env change or document that rotation is API-only. **Re-entry condition:** operational runbook work before mainnet | Open |
| AU-04 | Low | TEE | — | The `jti` revocation denylist has no expiry-based eviction and grows without bound — the same class as S-10. Fold into S-10's bounded-map work if cheap, else track. **Re-entry condition:** S-10 implementation | Open |
| AU-05 | Low | TEE + ops | — | `POST /auth/token` has no in-process rate limit; the router comment defers to a reverse-proxy limit that does not exist in this repo. The argon2 semaphore bounds concurrency and RAM, not request rate. **Re-entry condition:** ingress configuration before mainnet | Open |

---

## Declined

| ID | Rationale |
|---|---|
| S-08(B) | Binding `order_id` into `VALID_INPUT` would force the client to prove **per order** rather than per note. Client-side proving is already the placement-latency bottleneck, so this is a permanent UX regression bought for a Low finding that sits inside an explicitly accepted trust boundary. S-08(A) — documenting the widened boundary — is the appropriate remedy for an accepted risk. |
| S-11(B) | In-circuit strict ordering of merge inputs costs a full circuit + zkey + VK cycle and a tree reset for an issue that is **currently unreachable** and that a two-line on-chain `require!` closes completely. Reconsider only if the merge circuit is opened for an unrelated reason. |
| S-02(C) | Releasing the enclave reservation on *confirmed* lock failure requires per-note lock attribution that does not exist: the lock branch short-circuits on the first error and discards the remaining `JoinSet` results, so "buyer landed, seller did not" is not observable. S-02(A) removes the attack that made this urgent and S-03(C) removes the user-visible harm. **Re-entry condition:** settle-worker crash-recovery work, which must add per-note outcome attribution anyway. |

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
- Deferred review surfaces from §5 that remain uncommissioned, in priority order:
  `api/auth.rs` (partially covered here by AU-01…AU-05), `settle/worker.rs`
  crash recovery interleaved with partial-batch failure, and `oracle/*`.
