<!-- audit-record -->
> **Audit:** Client attestation review  
> **Date:** 2026-08-01  
> **Engagement:** `audits/audit_7/`  
> **ID prefix:** `CA-`  
> **Cross-audit status:** see [`residual-backlog.md`](../residual-backlog.md) — the canonical index of what is still open.

---

# Darknyx client-attestation review + un-audited surface inventory — 2026-08-01

> **Scope.** Focused review of the client-side DCAP verification path —
> `packages/sdk/src/tee/verify-core.ts`, `dcap.ts`, `attestation.ts`, and the
> daemon's `packages/daemon/src/attestation.ts` entry point. This is item 6 of
> the `../audit_6/tee-infra-daemon-review.md` §5 carry-forward list
> ("Client-side DCAP internals … the SDK implementations themselves were not
> read") and item 5.5 of the pass-1 review's §5.
>
> Part 2 of this document is a **coverage inventory** of the whole repository:
> what every audit pass to date has and has not read, so the next reviewer
> starts from an accurate frontier instead of re-deriving one.
>
> **ID prefix:** `CA-01…` (client attestation, 2026-08-01). Distinct from
> `S-`/`PF-` (07-25 pass 1), `T-` (07-25 pass 2), `D-` (07-20), `U-` (07-18),
> `CS-`/`N-`/`P-` (07-14), `C-` (07-12), `F-` (audit_1), `A-` (audit_2),
> `AU-`/`RD-`/`DEP-` (remediation trackers).
>
> **Severity:** Critical / High / Medium / Low / Perf-Nit / Info
>
> **Baseline.** `main` after PR #90 (`d69248b`), with the S-/PF-/T- remediation
> families closed per their trackers.

---

## 1. Executive summary

**One Critical.** `composeHashFromEventLog` selects the compose-hash event by
IMR and event name but never checks `event_type`. Because dstack only derives an
event's RTMR digest from its payload when `event_type == DSTACK_RUNTIME_EVENT_TYPE`
— for every other type the digest is taken verbatim from the log — a compose-hash
entry re-typed to a non-runtime type carries an attacker-chosen payload that
contributes *nothing* to the measurement chain. The RTMR3 replay still matches
the attested value, and the client reads a compose hash the enclave never
measured.

That is precisely the attack the module's own header says it exists to prevent:

> *"without (2)+(3) a client can only compare a self-reported `/info.compose_hash`
> — which an operator running a genuine-but-malicious build forges freely."*

It is also the compensating control `CRYPTOGRAPHY.md` §2 leans on for the
accepted price-fairness trust boundary — *"compromised TEE means breaking TDX or
subverting governance, **not merely running modified code**."* With CA-01,
running modified code is sufficient. Both the SDK and the daemon are affected;
they share the verification core, so the anti-drift design means they share the
defect.

The remaining three findings are a self-referential pin that reads stricter than
it is (CA-02) and two clarity items (CA-03, CA-04).

**Everything else in this path verified clean**, including the parts most likely
to be wrong: `eventDigest` and `replayEventLogRtmr` are faithful ports of
dstack's Rust, confirmed line-by-line, and covered by a real-CVM fixture that
exercises both the computed-digest (RTMR3) and pre-filled-digest (RTMR0) paths.
`dcap.ts` correctly avoids the WASM builds affected by CVE-2026-22696, pins the
PCCS endpoint against gateway-supplied SSRF, and fails closed on field drift.

| Bucket | Count |
|---|---|
| Critical | 1 |
| Low | 1 |
| Info | 2 |

| ID | Severity | Category | Finding |
|---|---|---|---|
| CA-01 | **Critical** | Attestation / measurement binding | `composeHashFromEventLog` reads an unauthenticated payload; compose-hash pinning is bypassable |
| CA-02 | Low | Attestation / API clarity | The `teePubkey` strict-mode pin is satisfied by a self-referential default |
| CA-03 | Info | Attestation / API clarity | Dead `?? info.compose_hash` fallback models the self-reported value as acceptable |
| CA-04 | Info | Release engineering | `EXPECTED_COMPOSE_HASH` is still the empty string |

---

## 2. Findings

### CA-01 — `composeHashFromEventLog` reads an unauthenticated payload

| | |
|---|---|
| **Severity** | **Critical** |
| **Category** | Attestation / measurement binding |
| **Affects** | `packages/sdk` **and** `packages/daemon` (shared core) |

**Anchors**

- `packages/sdk/src/tee/verify-core.ts:196-203` — the finder. Selects on
  `imr === 3 && e.event === COMPOSE_HASH_EVENT`; `event_type` is never examined.
- `packages/sdk/src/tee/verify-core.ts:152-173` — `eventDigest`. Correctly
  branches on `event_type === DSTACK_RUNTIME_EVENT_TYPE`.
- `packages/sdk/src/tee/verify-core.ts:294-302` — the consumer: replay is checked
  against the attested RTMR3, then the compose hash is read from "the now-trusted
  log".
- `packages/sdk/src/tee/attestation.ts:181` and
  `packages/daemon/src/attestation.ts:240` — both clients call the same finder.
- Upstream ground truth: `dstack/cc-eventlog/src/tdx.rs:69-75`
  (`TdxEvent::digest`), `:77-79` (`is_runtime_event`),
  `dstack/cc-eventlog/src/runtime_events.rs:17` (`DSTACK_RUNTIME_EVENT_TYPE`).

**Root cause**

The TS port of the digest rule is *correct*. dstack computes an event's
contribution to its RTMR as:

```rust
pub fn digest(&self) -> Vec<u8> {
    if let Some(runtime_event) = self.to_runtime_event() {
        return runtime_event.sha384_digest().to_vec();  // COMPUTED from event + payload
    }
    self.digest.clone()                                  // TAKEN verbatim from the log
}
```

`to_runtime_event()` returns `Some` only when
`event_type == DSTACK_RUNTIME_EVENT_TYPE` (`0x08000001`). `verify-core.ts`
mirrors this exactly.

The defect is in the *consumer*. The measurement chain authenticates
`event_payload` **only for runtime events**. For any other event type the payload
is inert — it is never hashed into anything. But `composeHashFromEventLog`
retrieves `event_payload` from an entry matched purely on `imr` and `event`
name, so it will happily read a payload that no RTMR ever covered.

Put plainly: the module proves the event *log* is the one behind the quote, then
reads a field out of that log which the proof does not cover.

**Failure scenario**

An operator runs a malicious `darknyx-tee` build whose real compose hash is
`H_evil`, and wants a client pinned to the audited `H_good` to accept it.

1. The malicious build's genuine RTMR3 event is a runtime event:

   ```json
   { "imr":3, "event_type":134217729, "digest":"",
     "event":"compose-hash", "event_payload":"<H_evil>" }
   ```

   Its contribution to RTMR3 is
   `D = SHA-384( LE32(0x08000001) ‖ ":" ‖ "compose-hash" ‖ ":" ‖ bytes(H_evil) )`.
   The operator computes `D` themselves — it needs no secret.

2. `GET /attestation` returns the genuine, unmodified quote, but a doctored
   `event_log` in which that one entry becomes:

   ```json
   { "imr":3, "event_type":1, "digest":"<D as hex>",
     "event":"compose-hash", "event_payload":"<H_good>" }
   ```

3. `eventDigest` sees `event_type !== 0x08000001`, takes the verbatim branch, and
   returns `D` — a **byte-identical** contribution. Every other entry is
   untouched. `replayEventLogRtmr(log, 3)` therefore still equals the attested
   `rtmr3`, and the `event_log_invalid` check at `:295` passes.

4. `composeHashFromEventLog` returns `H_good`. The `compose_mismatch` check at
   `:298-302` passes.

5. Every remaining check passes **legitimately**: the quote is real TDX hardware
   with a genuine Intel signature, `tcbStatus` is `UpToDate`, `report_data` binds
   the client's fresh nonce and the operator's real K-shard signer set, and MRTD
   is the correct dstack-OS measurement — which, as the module header itself
   notes, is shared across all dstack apps and does not distinguish builds.

The client accepts a malicious enclave and begins sending order intent to it.

**No collision or preimage is required.** The attack works because the doctored
entry reproduces the *same digest bytes* through a different code path, not
because it finds a second preimage.

**Impact**

Complete bypass of measurement pinning — the only mechanism that distinguishes
*our audited build* from *any genuine TDX enclave the operator controls*. What an
attacker gains is everything the enclave is trusted with but the chain does not
enforce: full visibility of resting order intent (side, price, size, trading key,
note commitment), clearing prices anywhere inside the accepted price-fairness
boundary, and selective censorship. Custody remains proof-enforced — this is not
a fund-theft path — but the entire confidentiality and fairness argument rests on
the client refusing to talk to an unattested build, and that refusal currently
does not work.

**Threat-model note.** The attack requires controlling the CVM or the gateway
response — the operator, or someone who has compromised the deployment. That is
not a mitigating caveat: it is exactly the adversary remote attestation exists to
defeat, and the one the accepted-risk boundaries in `CRYPTOGRAPHY.md` §2 name
explicitly.

**Why the tests did not catch it**

`packages/sdk/tests/tee-verify-core.test.ts` is otherwise a strong suite (27
cases, including a real-CVM fixture). But every synthetic fixture uses
`event_type: 1` — the verbatim-digest path — while the real-CVM fixture
exercises the computed path. Both paths are individually correct and individually
tested. The *crossing* — a runtime event **name** carried on a non-runtime
**type** — is never constructed, and it is the crossing that is exploitable.

**Recommended fixes**

| Option | Description | Trade-off |
|---|---|---|
| **A — Require the runtime event type (recommended)** | Filter on `event_type === DSTACK_RUNTIME_EVENT_TYPE` in `composeHashFromEventLog`, and require exactly one match. | Directly restores the invariant: the payload read is the payload hashed. ~10 lines. No wire, protocol, or on-chain change. |
| **B — Reject structurally impossible entries in `eventDigest`** | dstack's `TdxEvent::stripped()` gives runtime events an empty `digest` and non-runtime events an empty `event_payload`; an entry carrying **both** cannot occur in a genuine log. Reject it. | Good defence in depth and catches the whole class rather than this instance. Should be done **in addition to** A, not instead — A is the precise fix. |
| **C — Validate every runtime-named event** | Maintain a list of dstack runtime event names (`compose-hash`, `app-id`, `instance-id`, `key-provider`) and require any entry bearing one to be a runtime event. | Broadest, but couples us to an upstream name list that can drift. A + B cover the exploitable surface without that coupling. |
| **D — Compare `/info.compose_hash` as a cross-check** | Rejected. The self-reported value is attacker-controlled; agreement between two attacker-controlled values proves nothing. Listed to be explicitly ruled out. | — |

Ship **A + B**.

```ts
export function composeHashFromEventLog(
  eventLog: EventLogEntry[],
): string | undefined {
  // The payload is only bound to RTMR3 when the digest is COMPUTED from it —
  // i.e. for dstack runtime events. On any other event type the digest is
  // taken verbatim from the log and `event_payload` is unauthenticated.
  const evs = eventLog.filter(
    (e) =>
      e.imr === 3 &&
      e.event === COMPOSE_HASH_EVENT &&
      e.event_type === DSTACK_RUNTIME_EVENT_TYPE,
  );
  if (evs.length !== 1) return undefined; // absent, or ambiguous → refuse
  return normHex(evs[0].event_payload);
}
```

**Lockstep:** None in the cryptographic sense — no circuit, canonical body,
account layout, or hash domain changes. But the SDK and daemon share the core, so
both ship together, and any pinned client version must be bumped in the same
release.

**Cost of the fix**

| Item | Estimate |
|---|---|
| `composeHashFromEventLog` guard + `eventDigest` structural rejection | ~0.5 day |
| Three regression tests: re-typed compose-hash rejected; duplicate compose-hash rejected; entry carrying both `digest` and `event_payload` rejected | ~0.5 day |
| SDK + daemon release, client pin bump | ~0.5 day |
| **Total** | **~1.5 days**, no ceremony, no CVM, no redeploy of the vault |

A live-CVM run is *not* required to close this: the fix is a pure-function guard
and the existing real-CVM fixture already provides the positive case. The
negative cases are constructed from that same fixture by mutation.

---

### CA-02 — The `teePubkey` strict-mode pin is self-referential

| | |
|---|---|
| **Severity** | Low |
| **Category** | Attestation / API clarity |

**Anchors**

- `packages/sdk/src/tee/attestation.ts:166` —
  `teePubkey: opts.expectedTeePubkey ?? att.tee_pubkey`.
- `packages/sdk/src/tee/verify-core.ts:310` — compared against
  `teePubkeyBase58`, which `attestation.ts:174` sets to `att.tee_pubkey`.
- `packages/sdk/src/tee/verify-core.ts:288-290` — strict mode returns
  `pin_required` unless `expected.teePubkey` is present.

**The problem**

When a caller omits `expectedTeePubkey` — which `attestation.ts:56-57`
explicitly documents as supported — the `??` fills it with the attested key, and
step 6 then compares that key against itself. The comparison can never fail.
Worse, the `strict` gate at `:288` requires `expected.teePubkey` to be *present*,
and the `??` guarantees presence, so `pin_required` can never fire for the pubkey
half from this entry point.

The result is a strict mode that reads as though it enforces two governance pins
(compose hash **and** signer key) while enforcing one.

**Why it is Low, not higher.** The signer key is genuinely bound to the quote by
the `report_data` check at step 2, which covers the full K-shard set — so an
attacker cannot substitute a key. What is missing is the *separate* question of
whether that key is the one `vault_config.tee_pubkeys` authorises, and the daemon
already performs that on-chain comparison independently (the CS-13 fail-open was
fixed). So there is no exploitable gap — only a misleading API contract.

**Recommended fixes**

| Option | Description | Trade-off |
|---|---|---|
| **A — Require it in strict mode (recommended)** | Drop the `??` fallback; in strict mode a caller must pass `expectedTeePubkey` explicitly, sourced from on-chain `vault_config`. | Makes strict mode mean what it says. Small breaking change for any caller relying on the default. |
| **B — Remove it from `pin_required`** | Keep the fallback but stop counting `teePubkey` as a required pin, and document that the on-chain comparison is the real key pin. | No caller breakage; honest naming. Weaker than A. |
| **C — Leave and document** | Comment the tautology in place. | Insufficient — the failure mode is that a reader trusts the label. |

**Cost:** ~0.5 day for either A or B, including updating the two call sites and
the `strict`-mode tests.

---

### CA-03 — Dead `?? info.compose_hash` fallback models the wrong thing

| | |
|---|---|
| **Severity** | Info |
| **Category** | Attestation / API clarity |

**Anchors:** `packages/sdk/src/tee/attestation.ts:181` ·
`packages/daemon/src/attestation.ts:240`

Both read `composeHashFromEventLog(eventLog) ?? info.compose_hash` for the
returned value. On the strict path the right-hand side is unreachable:
`verifyReportAgainstExpected` has already required a non-`undefined`,
pin-matching log-derived hash, so the `??` never fires.

Harmless today, but it presents the **self-reported** `/info.compose_hash` as an
acceptable substitute for the attested one — the precise substitution this module
exists to reject, and the one CA-01 turns into a live bypass. Delete the
fallback, or make it throw.

**Cost:** ~15 minutes.

---

### CA-04 — `EXPECTED_COMPOSE_HASH` is still the empty string

| | |
|---|---|
| **Severity** | Info |
| **Category** | Release engineering |

**Anchor:** `packages/sdk/src/tee/attestation.ts:38`

The source-committed pin is `""`. This **fails closed** —
`verifyTeeAttestation:105-110` throws `pin_required` on an empty
`expectedComposeHash` — so it is not a hole. But it means there is no committed
value for a reviewer to check against a release record, and every caller must
supply the pin out of band, which is exactly where a wrong value goes unnoticed.

Populate it as part of the release bundle, alongside the source SHA / image tag /
resolved digest / compose hash / attestation measurement / signer set record the
TEE tracker already requires.

**Cost:** part of the release bundle; no engineering.

---

## 3. Verified clean

Recorded so a later reviewer does not repeat the work.

- **`eventDigest` is a faithful port.** Checked line-by-line against
  `dstack/cc-eventlog/src/tdx.rs:69-75` and `runtime_events.rs:17,100-112`:
  LE32-encoded event type, the two `:` separators, hex-decoded payload,
  SHA-384, and pad-up-never-truncate for short pre-filled digests. The
  `>= 48` early return matches dstack's `self.digest.clone()`, which likewise
  does not truncate.
- **`replayEventLogRtmr` is a faithful port** of `mr₀ = 48 zero bytes`,
  `mrᵢ₊₁ = SHA-384(mrᵢ ‖ digestᵢ)`, IMR-filtered and order-preserving. The
  zero-event early return is equivalent to the empty loop.
- **The real-CVM fixture test is genuinely strong** — it reproduces a real
  quote's RTMR3 (computed app-event digests) *and* RTMR0 (pre-filled boot-event
  digests) from the same log. That is the right shape of test; it simply does not
  cover the crossing described in CA-01.
- **`checkReportDataBinding`** is correct: 64-byte length gate, `[0..32]` equals
  the client nonce (freshness), `[32..64]` equals `SHA-256` of the concatenated
  K-shard pubkeys. The K-shard case is explicitly tested, so the binding covers
  the whole settle-authorising set rather than shard 0 alone.
- **`dcap.ts`** — uses the pure-JS `@phala/dcap-qvl`, correctly avoiding the
  unpatched WASM `-node`/`-web` builds per CVE-2026-22696; `^0.3.9` cannot
  resolve below the patched release and `package-lock.json` pins `0.3.9`; the
  PCCS URL defaults to `PHALA_PCCS_URL` and is never taken from gateway-supplied
  input (SSRF guard); DCAP failure throws `quote_invalid` rather than degrading;
  a non-TDX quote with no TD10/TD15 body is rejected.
- **Fails closed on library field drift** — a missing or renamed `tcbStatus`
  yields `undefined`, which is not in the allowlist, so verification fails rather
  than skipping.
- **TCB allowlist defaults to `["UpToDate"]` only** — correctly excludes
  `SWHardeningNeeded`, `ConfigurationNeeded`, and `OutOfDate`.
- **Nonce handling** — 32 bytes from `node:crypto` `randomBytes` (CSPRNG),
  generated per call, sent as `reportData` and re-checked against the verified
  quote.
- **`/info` ↔ `/attestation` cross-checks** — `tee_pubkey` equality,
  `tee_pubkeys[0]` shard-0 agreement, and `boot_session_id` shape validation. The
  full key set is then quote-bound via `report_data`, so `/info.tee_pubkeys`
  cannot be forged even though `/info` is otherwise unauthenticated.

---

## 4. Un-audited surface inventory

The user asked what remains unreviewed. This section answers that for the whole
repository, not just this pass. It merges the carry-forward lists from
`../audit_5/withdraw-intake-boundary-review.md` §5 and
`../audit_6/tee-infra-daemon-review.md` §5, marks what has since been
closed, and adds surfaces neither list named.

**Coverage key.** *Audited* — read line-by-line in a named pass. *Partial* —
specific boundaries examined, not the whole module. *None* — no pass has read it.
"Mentioned in a report" is not coverage and is not counted as such here.

### 4.1 No audit coverage from any pass — ranked by value

| # | Surface | LOC | Coverage | Why it matters |
|---|---|---|---|---|
| 1 | `crates/darknyx-tee/src/settle/worker.rs` | 1,810 | **None** | Named the single most valuable remaining target by **both** prior passes. The reconciliation state machine, ALT pool recycling, and durable marker-queue replay are unread. Partial-batch failure interleaved with a CVM restart is the highest-risk untested path in the codebase. T-06 built the journal *underneath* this without auditing the consumer. |
| 2 | `crates/darknyx-tee/src/oracle/accumulator.rs` | 393 | **None** | Hand-rolled binary parsing (PNAU envelope, Keccak160 sorted-pair Merkle, `parse_price_feed_message`) over attacker-influenced input. T-01/T-02 were found at the *boundaries* around it. This is where the next parser bug lives. |
| 3 | `crates/darknyx-tee/src/merkle/mirror.rs` + `events.rs` | ~1,150 | **None** | The event decoder and the mirror's internal consistency. Feeds `/tree/inclusion`, which clients use to build VALID_INPUT witnesses, and now (post S-02) feeds the intake root-ring check. T-05 established only the commitment level and no-rewind property. |
| 4 | `crates/darknyx-tee/src/solana_rpc/client.rs` | ~1,000 | **Partial** | Only the commitment model was examined (yielding T-05). Retry/backoff, response validation, and error classification unread — and error *classification* is what decides whether a settle is retried or declared terminal. |
| 5 | `crates/darknyx-tee/src/api/stream.rs` | 775 | **Partial** | Auth, expiry, rate parity, and lag handling spot-checked and correct. **Not** reviewed: per-channel subscription authorization, and whether `fills`/`orders` routing can leak across accounts under the archive / `recent_order_owner` race. A cross-account fill leak would be a direct confidentiality break. |
| 6 | `crates/darknyx-tee/src/settle/scheduler.rs` | 894 | **Partial** | CS-06 touched its fee-slot sampling; the paging/reservation interaction with the matcher tick is unread. |
| 7 | `packages/sdk/src/utxo/` recovery path | ~1,208 | **None** | `recoverNotesFromChain` / `recoverFillFromChain` are the durable amount-recovery backstop the whole amount-privacy design falls back on. Zero mentions in any audit document. |
| 8 | `packages/sdk/src/fills/` | 1,224 | **Partial** | `fills/recover.ts` appears in CS-03/CS-04 anchors; the module as a whole is unread. |
| 9 | `packages/daemon/src/` store / order-lifecycle / merge-runner / lifecycle-engine | ~4,381 total | **None** | CS-12 (merge counter resets to zero) was a finding *in this area*; whether `merge-runner` still derives from a mutable counter was never re-verified. Client-custody-adjacent. |
| 10 | `packages/indexer` | 765 | **None** | Documented as an optional locator with no consumer, so low risk — but unread. |
| 11 | `crates/darknyx-tee/src/config.rs` + `boot.rs` | ~860 | **None** | U-09's fail-open boot posture was fixed but never independently re-derived. |
| 12 | `crates/darknyx-tee/src/api/transparency.rs`, `order_router.rs` | ~460 | **None** | Zero mentions in any audit document. `transparency.rs` publishes reserves/identity — a misstatement there is a user-facing solvency claim. |
| 13 | `crates/darknyx-tee/src/prover/` (witness, convert, leaf, inputs, constraints) | ~3,113 | **Partial** | PF-09 bounded the rapidsnark FFI. The witness-assembly and field-conversion path — where a silent encoding divergence would produce a proof that fails only on-chain — is unread. Cross-backend parity tests exist but are env-gated (`RUN_ICICLE_PROVE=1`), so they do not run in the default gate. |
| 14 | `crates/darknyx-tee-loadgen` | 5,790 | **None** | Test tooling, not shipped in the enclave. Low priority; listed for completeness. |

### 4.2 Closed since the carry-forward lists were written

| Item | Where it was closed |
|---|---|
| Client-side DCAP internals (`verify-core.ts`, `parseEventLog`, RTMR3 replay) | **This pass** — yielded CA-01 |
| `api/auth.rs` | AU-01…AU-07, 2026-07-26 |
| `oracle/*` boundaries (`vaa.rs`, `sync.rs`, `cache.rs`) | T-01, T-02, T-16, RD-01 |
| `settle` journal + persistence layer | T-06 (+ live crash/drain drill) |
| Daemon keystore | T-09, T-10 |
| Prover FFI bounds | PF-09 |
| Fresh CU / byte / latency measurement | Measured throughout the S-/T- remediation |

### 4.3 Standing gaps that are not code-review items

| Item | Disposition |
|---|---|
| Groth16 Phase-2 ceremony | External gate — N-18, Open |
| Independent circuit audit | External gate — F-04 / C-07, Open |
| Third-party primitives (`k256`, `sha3`, `argon2`, `chacha20poly1305`, `jsonwebtoken`, `dcap-qvl`, rapidsnark, ICICLE, arkworks, Poseidon parameters, `alt_bn128` syscalls) | Treated as external assumptions by every pass. DEP-01 covers the advisory edge. |
| No dynamic testing | No pass has run fuzzing against the VAA/accumulator parsers, reorg simulation, or adversarial live-CVM testing. Item 2 above is the natural first fuzz target. |
| `enabled` kill-switch semantics mid-batch | `tee_forced_settle_batched` reads no `MarketConfig`, so a market disabled via `update_market_config` still settles its in-flight batches for the marker window (~300 slots). Almost certainly correct behaviour — cancelling would strand locked collateral — but it is an **undocumented governance semantic**, recorded only in a prior audit's §5. Needs one paragraph in `governance.md`, not code. |
| `try_consume_rate` global write lock | Found during the PF-05 disproof (`api/state.rs:900`): the only unconditional global write lock on the hot path, taken for every request including read-only routes. Currently lives **only** inside a Closed tracker row, so it is invisible to the residual backlog. Should be its own measurement-gated row. |

---

## 5. Suggested order

1. **CA-01 immediately.** It is 1.5 days, needs no ceremony or CVM, and until it
   ships the attestation guarantee that underpins every accepted trust boundary
   in `CRYPTOGRAPHY.md` §2 does not hold. Ship CA-02 and CA-03 in the same PR —
   they are the same file and together they remove the "looks pinned, isn't"
   class from this module.
2. **`settle/worker.rs` (§4.1 #1).** Two independent passes have now named it the
   highest-value remaining target and neither has read it. T-06 added a journal
   beneath an unaudited consumer.
3. **`oracle/accumulator.rs` (§4.1 #2)**, ideally with a fuzz harness rather than
   a reading pass alone — hand-rolled binary parsing is the case where fuzzing
   beats review.
4. **`merkle/mirror.rs` + `api/stream.rs` cross-account routing (§4.1 #3, #5).**
   Both are confidentiality-relevant rather than solvency-relevant, which is the
   half of the threat model the chain does not backstop.
5. **Two bookkeeping items** from §4.3 — document the kill-switch semantic, and
   promote the `rate_buckets` observation into `../residual-backlog.md` with a
   re-entry condition so it is findable when throughput binds.
6. **CA-04** with the release bundle.
