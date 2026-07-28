# Settlement crash-recovery + drain drill

How to prove, on a real CVM, that an interrupted settlement is recovered rather
than stranded — and that a planned stop leaves nothing behind.

This is the live half of **T-06**
([`audit-2026-07-25-tee-infra-daemon-remediation-tracker.md`](audit-2026-07-25-tee-infra-daemon-remediation-tracker.md)).
The unit and integration tests pin the decision logic; this drill is the only
thing that exercises a real process dying with real on-chain locks outstanding,
on the real LUKS volume.

Run it when: the settle pipeline changes, the journal schema changes, the
persistence layer changes, or before any release that claims restart safety.

---

## 1. What the drill proves that local tests cannot

| Property | Why a local test cannot establish it |
|---|---|
| The journal is written to the **dstack LUKS volume** during a real settle | Tests write to `tempfile` on tmpfs; nothing proves the sealed volume behaves the same |
| It **survives an abrupt VM stop** | A test's "crash" is a dropped struct, not a killed VM |
| Recovery classifies against **real chain state** | Fakes answer whatever the test says; devnet answers what happened |
| Entries are **retired**, so the key cannot collide with the next boot's `batch_id` | Needs two real process lifetimes sharing one volume |
| `/admin/drain` reports readiness from the **same journal the worker writes** | Only meaningful when both halves run in one deployed binary |

---

## 2. The two traps — read before scheduling a window

### 2.1 `phala cvms stop` is slower than the settle phase

This is the trap that costs attempts. `cvms stop` is an **API request** for a VM
shutdown; the container keeps running for some seconds afterwards (a graceful
`docker stop` grace period plus VM teardown). The settle phase is only ~10 s.

Measured on 2026-07-28: killing 5 s after the pipeline started still let the
settle confirm. **Three attempts failed this way** before the timing was
understood.

The kill must therefore be issued at the **earliest possible moment** — the very
first journal write — to buy the whole pipeline's runway (~14 s) rather than
whatever is left of it.

Two approaches that do **not** work, recorded so they are not retried:

* **Waiting for a log line.** `phala logs` costs seconds per call, so a polling
  loop observes the batch several seconds late. Attempt 1 issued the kill 47 s
  after enqueue.
* **A fixed timer from test start.** The deposit phase varies with devnet
  latency, so `+31 s` landed differently between runs. Attempt 2's test ran 95 s
  against a 47 s baseline and still completed its settle.

### 2.2 A tree reset does not empty the mirror

The CVM's Merkle mirror is append-only and reconstructs from
`DARKNYX_TEE_SYNC_FROM_SLOT`. Resetting the on-chain tree and restarting is **not
enough**: the mirror replays post-floor history and re-applies the old leaves.

Observed on 2026-07-28: after a reset, on-chain `leaf_count=0` on all four shards
while the mirror reported `leaf_count=7` on shard 0.

**Every reset must be followed by an env-only redeploy with a fresh floor slot
captured AFTER the reset.** A restart alone will not do it.

---

## 3. The trigger that works: the journal reports on itself

`GET /admin/drain` returns `in_flight_settlements` read straight from the settle
journal. The moment it goes above zero, the first durable write has landed and a
settlement is genuinely in flight.

Polling that endpoint is both the **precise kill trigger** and, on its own, the
**proof that the journal is being written during a real settle**. Nothing else
available from outside the enclave gives that.

```bash
# Poll tightly (no sleep — the window is short), kill on first detection.
while :; do
  N=$(curl -s --max-time 3 "$GW/admin/drain" -H "authorization: Bearer $TOK" \
        | jq -r '.in_flight_settlements // 0')
  [ "${N:-0}" -gt 0 ] && break
done
phala cvms stop "$CVM"
```

Killing at first detection interrupts during lock/prove, which journals the entry
at `Locking` with **no marker expiry** — recovery must then classify it
`ReleaseExpired`. To exercise the `Settling` path instead (entry carrying a settle
signature), the kill has to land inside the settle phase, which needs a faster
kill than `cvms stop` — see [§7](#7-known-gaps-in-this-drill).

---

## 4. Full procedure

Prerequisites: `.devnet/` populated, `packages/sdk/.env` with `SOLANA_RPC_URL`,
`.devnet/pyth-hermes.env`, a CPU CVM, and the image digest pinned in
`deploy/docker-compose.yaml`.

> **Confirm the CVM is CPU before anything.**
> `phala cvms get <app_id> --json | grep -E '"instance_type"|"gpus"'`
> **Never stop a GPU CVM** — it is deallocated permanently and the prepaid window
> is forfeited. See [`gpu-tee-runbook.md`](gpu-tee-runbook.md).

### Step 0 — deploy the build under test

Standard flow from [`cvm-run-runbook.md`](cvm-run-runbook.md). Keep the generated
API key / secret / passphrase — the drill needs an **admin** bearer token, and the
deploy env is shredded immediately after use.

### Step 1 — fresh tree, matching mirror

```bash
# Export once — the floor capture below needs it too. Setting it inline on the
# reset command alone leaves it unset for 1b, and the curl then posts to an
# empty URL.
export SOLANA_RPC_URL="$HELIUS"

# 1a. reset on-chain
ADMIN_KEYPAIR=.devnet/keypairs/admin.json node scripts/reset-merkle-tree.mjs

# 1b. capture a floor AFTER the reset, then env-only redeploy (see §2.2)
FLOOR=$(curl -s "$SOLANA_RPC_URL" -X POST -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getSlot","params":[{"commitment":"confirmed"}]}' \
  | jq -r .result)
# …write the deploy env with DARKNYX_TEE_SYNC_FROM_SLOT=$FLOOR, umask 077…
phala deploy --cvm-id "$CVM" -c deploy/docker-compose.yaml -e .devnet/darknyx-deploy.env --wait
shred -u .devnet/darknyx-deploy.env   # rm -P on macOS
```

Verify before continuing — all four shards must read `leaf_count: 0`, and the
boot log must say `merkle cold-boot: vault has no transaction history in range yet`.

> **Beware shell colour codes.** Reading the slot via `node -e "console.log(...)"`
> emits ANSI escapes that corrupt the env value. The CVM fails closed on a
> malformed variable, but it wastes a deploy. Use `curl | jq -r` and validate:
> `echo "$FLOOR" | grep -qE '^[0-9]+$'`.

### Step 2 — baseline

Run `cvm-settle-e2e` to completion. This is the before-measurement **and** proves
the journal has not broken the happy path. Record `total_ms` and the per-stage
breakdown from the `settle pipeline timing` log line.

### Step 3 — reset again (step 1 in full), then interrupt

Start the e2e in the background, poll `/admin/drain`, kill on first detection
([§3](#3-the-trigger-that-works-the-journal-reports-on-itself)).

**Capture the mid-flight response body** — it is primary evidence.

The test is **expected to fail**. Confirm the interruption on-chain rather than
trusting the failure: total leaf count must be **2** (the deposits alone), not 7
(deposits + 5 settle outputs).

### Step 4 — restart and read recovery

```bash
phala cvms start "$CVM"
phala logs dstack-darknyx-tee-1 --cvm-id "$CVM" -n 80 | grep -iE "journal|recovery|sweeper"
```

Then confirm entries were retired:

```bash
curl -s "$GW/admin/drain" -H "authorization: Bearer $TOK" | jq -c .
# in_flight_settlements must be 0
```

### Step 5 — drain lifecycle

```bash
curl -s -X POST   "$GW/admin/drain" -H "authorization: Bearer $TOK" | jq -c .
curl -s           "$GW/admin/drain" -H "authorization: Bearer $TOK" | jq -c .
curl -s -X DELETE "$GW/admin/drain" -H "authorization: Bearer $TOK" | jq -c .
```

### Step 6 — planned stop, then stop the CVM

Drain, confirm `safe_to_stop: true`, re-confirm `gpus: 0`, then
`phala cvms stop`. Wait for `status: stopped`. Remove any staged credentials and
`unset DARKNYX_TEE_API_KEY DARKNYX_TEE_API_SECRET DARKNYX_TEE_PASSPHRASE`.

---

## 5. Pass criteria

A run passes only if **every** line holds. Anything else is a finding.

| # | Assertion | Where observed |
|---|---|---|
| 1 | `in_flight_settlements` > 0 during a live settle | `GET /admin/drain`, mid-flight |
| 2 | `safe_to_stop` is `false` while in flight | same response |
| 3 | Interruption confirmed by chain, not by test failure | total on-chain `leaf_count == 2` |
| 4 | Boot reports a **non-empty** journal and runs recovery | boot log |
| 5 | Classification matches chain reality | `already_settled` / `release_expired` consistent with §3's leaf count |
| 6 | `needs_operator=false` when the chain view is unambiguous | recovery summary line |
| 7 | Entries retired after recovery | `in_flight_settlements == 0` |
| 8 | Unsettled notes handed to the lock sweeper | `lock sweeper: replaying un-released note locks from disk n=…` |
| 9 | Drain closes trading and reports ready | POST/GET `/admin/drain` |
| 10 | Abandoning a drain reopens trading | DELETE `/admin/drain` |
| 11 | A drained redeploy boots with `present and empty` | boot log |

**Assertion 5 is the one that matters most.** A recovery pass that runs but
classifies wrongly is worse than one that does not run, because it looks healthy.
Check it against the leaf count, never against the log's own confidence.

---

## 6. Results — 2026-07-28

Image `ghcr.io/skysail-labs/darknyx-tee@sha256:59e2932f40da51675fd6a9d854715d1fd6681a824f2fc4c8e75c4907ee7bbfda`
(tag `tee-v3-hardening-76`, commit `3a93570`).
CVM `nightly-test-cvm` = `app_9ca3cded105f16923afb0e3f62537882c14db637`,
`tdx.xlarge`, `gpus: 0`, node prod9. Program
`C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx`, `numTrees=4`.
Signer set **unchanged** from slice 1 (dstack derives per `app_id`), so no
rotation or refunding was needed; all four shards held ≥ 1.98 SOL.

### Mid-flight journal state (assertions 1–2)

```json
{"draining":false,"cancelled_resting":0,"in_flight_settlements":1,"safe_to_stop":false}
```

Note the **absent `caveat` field** — correct, since this CVM has a persistent
state dir. The caveat appears only for a non-persistent journal.

### Interruption (assertion 3)

```text
shard 0: leaf_count=2   shard 1..3: leaf_count=0
TOTAL=2   (7 would mean the settle landed)
```

### Recovery (assertions 4–8)

```text
INFO lock sweeper: replaying un-released note locks from disk n=2
WARN settle recovery: lock window closed; collateral returns via the lock sweeper
       batch_id=0 match_idx=0 expired_at_slot=0
WARN settle journal recovery complete; entries retired (locks now owned by the sweeper)
       total=1 already_settled=0 redrive=0 release_expired=1 indeterminate=0
       needs_operator=false
```

`expired_at_slot=0` is the **marker-expiry rule working live**: the kill landed
before `verify_match_batch`, so no `BatchValidityMarker` exists and there is
nothing to redrive against. An earlier revision classified on the ~30-minute lock
expiry alone and would have reported `Redrive` here — every attempt would have
reverted on the marker check.

Post-recovery: `in_flight_settlements: 0`.

### Drain (assertions 9–11)

```text
POST   → {"draining":true, "in_flight_settlements":0,"safe_to_stop":true}
GET    → {"draining":true, "in_flight_settlements":0,"safe_to_stop":true}
DELETE → {"draining":false,"in_flight_settlements":0,"safe_to_stop":false}
WARN drain requested: new trading closed, resting orders cancelled newly_requested=true cancelled_resting=0
WARN drain abandoned gate_fully_reopened=true
```

Boots observed `settle journal: present and empty, nothing in flight` on every
clean cycle.

### Measurements

| Metric | Value | Note |
|---|---|---|
| Settle end-to-end, journal enabled | `total_ms=14210` | lock 1162, prove 2226, verify 1173, ALT 1300 + wait 462, settle 10762 |
| Slice-1 baselines (pre-journal) | 14573 / 15310 | The journalled run is **within the spread of the two prior runs**. Three samples across different network conditions cannot establish that the journal's cost is negligible — only that it is not visible at this resolution. Stated as an observation, not a conclusion. |
| Restart → reconciled | **436 ms** | `20:21:46.195` sweeper spawn → `.631` recovery complete |
| Journal bytes per match | **~1684 B** | payload 488 + 2×378 lock inputs + 440 scalars/signatures/timestamp |
| Full 16-match batch | **~26 KiB** | rewritten per durable transition (snapshot, not append) |

### Honest limitations of this run

* **Per-transition write p50/p95 was not captured.** The cost table lists this
  as a *mandatory* closing measurement, and it is missing: no instrumentation
  exists around `SettleJournal::record`, and three end-to-end samples are not
  percentiles. T-06's `Closed` status therefore rests on an **explicitly recorded
  waiver** (see the tracker's cost-table row), not on complete evidence. The
  instrumentation is the first thing to add before the next drill.
* **The `Settling`-stage recovery path was not exercised.** The kill necessarily
  lands at the first journal write, so the entry was at `Locking`. The
  `AlreadySettled` and `Indeterminate` branches remain covered by unit tests only.
* **The collateral outcome is not a journal achievement.** Those two locks were
  already tracked by the pre-existing `pending_locks.db` sweeper (S-03(B)), which
  releases them at expiry regardless. What the journal adds is a durable,
  *classified* record of the interrupted settlement instead of a boot that
  reports "nothing in flight" while a settle is incomplete. State it that way;
  do not let assertion 8 be read as the journal returning funds.

---

## 7. Known gaps in this drill

Worth closing when the tooling allows.

1. **No fast kill.** `phala cvms stop` cannot land inside the ~10 s settle phase.
   `phala ssh` + `docker kill` would allow targeting any stage, but needs
   development-mode SSH keys on the CVM. Until then the drill can only exercise
   an interruption at the first journal write.
2. **No p50/p95 for journal writes.** Would need a timing histogram around
   `SettleJournal::record`, emitted at `info`. Cheap to add; not yet done.
3. **A journal write failure is now fail-closed, and that path is untested live.**
   A settle whose signature cannot be journaled is skipped and retried rather
   than sent, so a disk fault degrades throughput instead of creating orphans.
   Unit-tested (`a_settle_is_not_sent_when_its_signature_cannot_be_journaled`);
   reproducing it on a CVM would need an induced volume fault.
4. **`AlreadySettled` is untested live.** Requires killing after Tx D confirms but
   before the outcome is recorded — a window of milliseconds, so it needs (1).
5. **Multi-match batches untested.** Every run used a single match. A 16-match
   batch would exercise the snapshot rewrite at ~26 KiB and partial-batch
   recovery, where some matches settled and others did not.
