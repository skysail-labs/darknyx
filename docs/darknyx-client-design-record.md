# Darknyx Client — design record and implementation plan

> Status: **ACTIVE DESIGN RECORD — Phase 0 benchmark foundation in progress.**
>
> Supersedes the August 2026 native-first client notes. Their product
> decomposition, security boundaries and MM framing are carried forward; their
> packaging conclusion is **downgraded to a decision gated on measurement** (see
> §2 and §5), because it was reached without measuring the current client
> circuits.
>
> Companion document: `liquidity-mm-and-block-matching-design-record.md`
> ("the liquidity record"). Its proposed product layers remain decision-gated.
> **§3 of this document is the mechanism by which client work stays valid when
> they move.**
>
> **Read §2 and §5 before implementing anything.** Six decisions are blocked on
> measurements that have not been taken. Three of those measurements are client
> work and are also blocking the liquidity record's §9.

---

## 0. How to read this document

- **§1** is the implementation ordering and the argument for it.
- **§2** separates what is *invariant* from what is *decision-gated*. This is the
  single most important section: it is why client work can start now despite the
  liquidity record being unstable.
- **§3** is the architecture, expressed as two planes with a hard interface.
- **§4** is Phase 0 — the investigations and benchmarks, with concrete gates.
- **§5** is the decision register: every gated decision, who answers it, what it
  changes, and what happens if it stays unanswered.
- **§6–§7** are the components: invariant ones to build now, gated ones to defer,
  and the seams left for them.
- **§8–§11** are keys, security, acceptance criteria and phasing.

Decisions made on judgement rather than evidence are marked **[JUDGEMENT]** with
the opposing argument stated. Numbers marked **[TARGET]** are proposed gates, not
measurements. **[MEASURED]** values name their committed evidence artifact.

---

## 1. Implementation ordering

### 1.1 The ordering

```
Phase 0   Investigations + benchmarks          ← start here, ~3-4 weeks
            │
            ├─→ feeds liquidity record §9.1, §9.2, §9.4
            │
Phase 1   Invariant core (inventory plane)      ← no tier dependency at all
            │
Phase 2   Decision point: resolve D1-D3         ← evidence now exists
            │
Phase 3   Intent plane + tier 1 rails           ← built together with the matcher
            │
Phase 4   Tier 2 client surface + packaging     ← shape determined by D2
            │
Phase 5   MM daemon hardening + institutional
```

### 1.2 Why the client goes first, not second

**The client's lower half is invariant.** The liquidity record §11 commits to: no
new circuits, no VK bump, no new note type, no settlement-path changes, and tier
state living permanently in the enclave and off-chain API. Everything the client
does below the order-intent line — note discovery and decryption, key custody,
Merkle synchronisation, witness construction, proving, proof caching, transaction
construction, settlement reconciliation, recovery — is untouched by every open
question in that document. It can be built now and cannot be invalidated by a
tier redesign.

**The client is the instrument that answers the protocol's blocking questions.**
Liquidity record §9.1 asks whether the re-lock heartbeat is legible on-chain.
The client is the thing emitting that heartbeat; the classifier is a client-side
experiment. §6.3 justifies the indication layer partly on the premise that
client-side proving is the placement-latency bottleneck — that premise is a
measurement nobody has taken. Sequencing the client after the protocol decision
means making the protocol decision blind.

**The order surface needed for Phase 1 already exists.** Deposit → `VALID_INPUT`
→ order → match → settle is implemented and end-to-end tested against a live
CVM. Phase 1 targets that surface. Tier work extends it; it does not replace it.

**Counter-argument, recorded [JUDGEMENT]:** building the client first risks
building against an order API that the tier work reshapes, causing rework in the
intent plane. This is accepted because §3's plane split confines that rework to
the thin, fast half. If the plane boundary is not held rigorously, this argument
wins and the ordering should be revisited.

### 1.3 What must NOT be built in Phase 1

- Any component that names a tier.
- Any order-attribute schema treated as closed.
- Any coupling from the intent plane into the prover.
- Any packaging commitment (installer, extension, native-messaging host) before
  D1 resolves.

---

## 2. Invariance — what is stable and what is gated

This section is the forward-compatibility mechanism. Every component in §6–§7 is
classified here.

### 2.1 Invariant under every open question

| Concern | Why it cannot move |
|---|---|
| Note model, commitments, nullifiers, inner hashes | Frozen; no new note type (liquidity §11) |
| `VALID_INPUT` binding `(merkle_root, note_use_tag, token_mint)` | Circuit frozen; the commitment remains the private Merkle leaf |
| Proof scope: **per note, per root epoch** — not per order, price, side or market | Follows from the binding above |
| `VALID_MERGE(K)` lock precondition | Circuit + program frozen |
| Settlement path: `VALID_MATCH_BATCH` + `tee_forced_settle_batched` | Explicitly unchanged (liquidity §6.4, §11) |
| Continuation re-lock (`buyer_relock_order_id`, `note_lock_e`) | Exists; tier 2 reuses it as-is |
| 64-root shard window, `MAX_LOCK_TTL_SLOTS = 4,500` semantics | Program constant (`programs/vault/src/state.rs`) |
| TEE attestation, DCAP + RTMR3 replay + measurement pinning | Independent of matching design |
| Key derivation and domain separation | Frozen |
| Chain-derived recovery | Independent of matching design |

**Everything in this table is Phase 1 scope.** None of it is at risk.

### 2.2 Decision-gated

| Concern | Gated on |
|---|---|
| Trader packaging (browser / desktop app / agent + extension) | D1 |
| Whether tier 2 is flags-only or has an indication layer | D2 (liquidity §9.2) |
| Firm-up model and therefore client liveness requirements | D3 |
| Prover backend and threading model | D4 |
| Whether the client keeps local reputation/firm-up records | D5 (liquidity §9.3) |
| Signer model for resting tier-2 orders | D6 |
| Order attribute set (`min_execution_size`, `allow_mm_counterparty`, `residual_policy`, others) | Tier design; **treated as open by construction** |

### 2.3 The four seams that absorb change

1. **Order intent is a versioned, extensible attribute map.** The client core
   never enumerates attributes. It carries `{protocol_version, attributes: {...}}`
   and canonicalises deterministically. Unknown attributes from the server are a
   hard version error with a legible message, never a silent drop. Adding MES,
   `allow_mm_counterparty`, `residual_policy` or anything else later is a schema
   bump and a UI change, not a core change.
2. **Proof handles are note-scoped, never order-scoped.** The proof cache is keyed
   `(local_note_commitment, note_use_tag, tree_id, merkle_root,
   circuit_version, pk_version)`. The local commitment identifies the opening;
   the public tag is what the proof and lock bind. No tier concept can invalidate
   this, because the circuit binding makes it true.
   Indications, quote curves, ladders and firm-ups all resolve to "is there a
   ready proof for this note?"
3. **The intent plane cannot call the prover.** It may only read readiness. This
   makes every future latency-sensitive flow (quote curves, firm-up) correct by
   construction rather than by scheduling discipline.
4. **Transport is behind one interface.** REST, `/v1/stream`, and any future
   invitation/curve channel are implementations of a single client-side
   `IntentTransport`. An async server-push flow (invitation) is a new message
   type, not a new architecture.
5. **Authorisation is typed.** The intent plane receives only an
   `authorizeIntent(canonicalIntent)` capability. It never receives a trading
   secret or a generic `sign(bytes)` function. This preserves the current
   canonical trading-key signature requirement without widening the bridge into
   an arbitrary signer.

---

## 3. Architecture — two planes

The previous client document described one agent with a proof manager. The
liquidity record forces a sharper structure, because two loops with three orders
of magnitude of cadence difference now coexist.

```
┌─────────────────────────────────────────────────────────┐
│ INTENT PLANE            cadence: per auction (~seconds) │
│   order intents · quote curves · indications · cancels  │
│   firm-up responses · cancel-on-disconnect              │
│   NO PROVING. NO WITNESS ACCESS. NO SECRETS.            │
└───────────────────────┬─────────────────────────────────┘
                        │  readiness handles only
                        │  (never witnesses, never keys)
┌───────────────────────▼─────────────────────────────────┐
│ INVENTORY PLANE         cadence: lock epochs / root age  │
│   note discovery · decryption · balances · reservations  │
│   Merkle sync + root verification · witness construction │
│   proving · proof cache + refresh · tranche scheduling   │
│   merge scheduling · tx construction · settlement recon  │
│   recovery · fill-quality audit                          │
└──────────────────────────────────────────────────────────┘
```

**The boundary is structural, not advisory.** The intent plane may ask "is note
N order-ready?" and receive a handle. It may not ask for a witness, a proof blob
it did not receive a handle for, a key, or a proving operation. Enforce this in
types, not in review.

Two properties fall out for free:

- The liquidity record's requirement that an MM's quoting loop never synchronously
  invokes the prover is satisfied by construction.
- A market maker who cannot back a quote is structurally unable to send it, rather
  than policy-checked out of sending it.

### 3.1 Why the proof cache is cheaper than it looks

`VALID_INPUT` binds only `(merkle_root, note_use_tag, token_mint)`. The circuit
privately recomputes the commitment and proves its Merkle inclusion. It does
**not** bind `order_id`, price, side, expiry or market. Therefore:

> **One proof per note per root epoch covers every quote level, every price, and
> every same-mint market that note backs.**

An MM quoting an eight-level ladder on both sides needs proofs proportional to
its *note count*, not its *quote count*. A trader may reuse one proof across
candidate or sequential intents. It **cannot** use one note to back multiple
simultaneous live or pending orders: collateral reservation and on-chain locking
permit at most one such order per note. This is the enabling primitive for both
tiers, and it is the same design decision that creates the S-08 blast radius
(liquidity §8.4) — noted so the two are never traded off in ignorance of each
other.

### 3.2 As-built client baseline

Phase 0 is not starting from an empty client. The daemon and SDK already ship:

- encrypted, versioned seed storage and backup/import;
- a local note database, seed-plus-chain recovery, and merge automation;
- strict TEE attestation, finalized governance refresh, shared-stream sequence
  reconciliation, and market-local trading gates;
- deposit, withdrawal, order placement/cancellation, settlement tracking, and
  injected Node prover adapters for the active paths.

The remaining product work is packaging, a complete browser prover suite,
proof-cache scheduling, a typed intent bridge, polished recovery/onboarding, and
measured trader/MM operating envelopes. Phase 1 extends the as-built daemon; it
does not replace it.

---

## 4. Phase 0 — investigations and benchmarks

**Nothing in §6 onward should be scoped until this completes.** Phase 0 is
roughly three to four weeks and unblocks both this document and the liquidity
record.

### 4.1 Investigations (non-benchmark)

| # | Question | Method | Feeds |
|---|---|---|---|
| **I1** | Current circuit sizes and artifact identities | Record committed R1CS constraints plus WASM/zkey bytes and SHA-256 for all six client circuits | Everything. Do this on day one. |
| **I2** | Safe lock lifetime around `MAX_LOCK_TTL_SLOTS = 4,500` | Model the fixed ceiling against prove, submit, finality, and refresh latency | Liquidity §9.1, D2 |
| **I3** | Is the re-lock pulse legible on-chain? | **Build the classifier.** Simulate a resting order re-locking on a heartbeat; attempt to distinguish it from ordinary activity in devnet traffic | Liquidity §9.1, D2, D6 |
| **I4** | Can one note back a full ladder? **Resolved: no for simultaneous firm levels.** | One note may serve candidate/sequential intents, but one live/pending reservation per collateral commitment requires inventory per simultaneous firm level | Liquidity §5.5, MM tranche sizing |
| **I5** | Residual re-proving window **Resolved.** | Settlement can continuation-relock its derived output without a new client proof. A later independent order needs a fresh `VALID_INPUT` after that output leaf enters an accepted root | `residual_reproving` state, D3 |
| **I6** | Can the client hold a Solana wallet connection under cross-origin isolation? | Test Phantom / wallet-adapter flows with `COOP: same-origin` + `COEP: require-corp` enabled | D1, D4 |
| **I7** | Would block traders leave software running to hold an order? | **Add as a fourth question** to the liquidity record's §9.4 trader interviews | D1, D2, D6 |

I3 and I7 are jointly the single most consequential pieces of work in Phase 0:
together they decide whether traders need a persistent process at all.

### 4.2 Benchmark matrix

**Circuits:** `VALID_WALLET_CREATE`, `VALID_DEPOSIT`, `VALID_INPUT` (primary),
`VALID_SPEND`, `VALID_MERGE(2)`, `VALID_MERGE(4)`.

**Backends:**

| Backend | Purpose |
|---|---|
| snarkjs, Node | Baseline; already exists (`nodeValidInputProver`) |
| snarkjs, Chrome Worker | Zero-install desktop candidate; UI-thread isolation measured |
| rapidsnark, native | Native ceiling |

**Devices:**

| Class | Rationale |
|---|---|
| M-series Mac | Best case; developer machines |
| Mid x86 laptop, 8 GB | Realistic trader desktop |
| Linux server-class | MM daemon proxy |

Desktop launch qualification is deliberately first: Apple Silicon plus a
**physical** mid-range x86 laptop, both on stable Chrome. Mobile/Safari becomes a
separate qualification pass after desktop packaging is selected; emulation does
not count as evidence.

**Phases — record separately, never blended:**

```
artifact fetch (cold / warm from Cache API)
artifact parse + WASM instantiate
prover initialisation
witness generation
FFT / H-polynomial
MSM
proof serialisation
local verification
```

**Per-run metadata (mandatory):** device model, SoC, total RAM, OS + browser
version, `self.crossOriginIsolated`, peak process memory, tab foreground state,
thermal/power state, artifact hashes, and run index (to expose warmup).

Run ten cold starts per circuit. After one untimed warm-up, run 300 warm
`VALID_INPUT` samples and 100 for every other circuit, plus a ten-minute soak per
backend. Report p50 / p95 / p99 with bootstrap 95% intervals. Means are allowed
only for throughput calculations, never as the UX latency result.

The existing Apple-M3 `VALID_INPUT` spike is **[MEASURED]** at 62 ms witness
p50, 520.67 ms prove p50, approximately 583 ms combined; see
`docs/benchmarks/valid-input-public-input-compression-2026-07-21.md`. Witness
generation was not dominant in that run. Phase 0 therefore measures each stage
instead of assuming which backend work will matter.

### 4.3 Proposed gates **[TARGET]**

| # | Gate | Decides |
|---|---|---|
| **G1** | `VALID_INPUT` warm p95 ≤ 1,500 ms, browser, mid laptop | Browser viable for tier 1 |
| **G2** | Desktop Chrome: wallet/deposit p95 ≤ 2 s; spend ≤ 2 s; merge K2 ≤ 5 s; merge K4 ≤ 10 s | Complete trader flow is viable, not merely order placement |
| **G3** | `VALID_INPUT` warm p99 ≤ 2,500 ms, zero OOM, and no UI-thread stall > 100 ms | Tail UX and Worker isolation |
| **G4** | Firm-up path p99 ≤ 200 ms (cached-proof retrieval + sign + send, **no proving**) | Tier 2 client-side feasibility |
| **G5** | Sustained proving throughput ≥ MM refresh demand (§4.4) | MM daemon prover sizing |
| **G6** | At 10 Mbps: wallet ≤ 6 s, deposit ≤ 7 s, input/spend ≤ 10 s, merge K2 ≤ 18 s, merge K4 ≤ 30 s background | Per-action artifact caching/streaming strategy |
| **G7** | Zero crash/OOM in the sample; peak x86 RSS < 1.5 GiB; ten-minute thermal degradation < 25% | Ship/no-ship per desktop class |

G4 is a *different measurement* from order submission and must be gated
separately: it is a reactive response to an async push, benchmarked against the
sub-second firm-up rates the liquidity record cites as the industry reference.
If pre-proving works (§7.2), G4 is trivially met. If it does not, tier 2 is not
buildable client-side in its current shape.

### 4.4 Throughput model for MM inventory

Latency is the trader constraint. **Throughput is the MM constraint**, and the
previous document did not measure it.

```
proofs_per_epoch  =  (inventory_value ÷ max_warm_note_size) × sides
refresh_rate      =  max(lock_epoch_rate, root_rotation_rate)
sustained_demand  =  proofs_per_epoch × refresh_rate
```

`max_warm_note_size` is capped by the S-08 mitigation (liquidity §8.4), which
means the cap *directly sets* the client's proving throughput requirement.
Smaller cap → smaller worst case → more notes → more proofs. **Model this jointly
with the security team; it is one decision, not two.**

Also measure: proof-refresh queue depth under sustained load, and merge
throughput given the tranche rotation in §6.4.

### 4.5 Phase 0 implementation scope

The benchmark foundation lives in `packages/client-prover-bench` and uses one
deterministic witness corpus for all backends. It records raw JSON separately
from a reviewed Markdown summary. Node/snarkjs, Chrome Worker/snarkjs, and native
Circom witness + rapidsnark are the only Phase 0 backends.

No benchmark-only circuits, zkeys, verifier keys, feature gates, Poseidon2
variants, or Merkle-depth experiments enter the repository. Those would change
the protocol and ceremony surface before the current-client question is
answered. WebGPU is likewise not a Phase 0 implementation target; only the
current browser backend is measured.

### 4.6 What Phase 0 does *not* do

It does not decide the architecture. It produces the numbers that let §5 be
decided. If Phase 0 output cannot change the answer, it is not a measurement
phase — this was the structural flaw in the previous document, where Phase 0 was
"measure before redesigning" followed by a fully-specified redesign with no
branch point.

---

## 5. Decision register

| ID | Decision | Gated on | Default if unresolved |
|---|---|---|---|
| **D1** | Trader packaging | G1–G3, G7, I6, custody review | Evidence branch: embedded Chrome only if performance and custody both pass; otherwise Tauri/native |
| **D2** | Tier 2 shape: flags-only vs indication layer | Liquidity §9.2 ← I2, I3, I7 | Undecided. **Blocks Phase 4 entirely.** |
| **D3** | Firm-up model | D2, I5, G4 | Pre-proved-and-held (§7.2) — strictly better than behavioural, cheaper than auto-firm. |
| **D4** | Prover backend + threading | G1–G7 | Chrome Worker/snarkjs or native Circom+rapidsnark. Backend stays abstract behind the existing injected-prover interface. |
| **D5** | Local reputation/firm-up record keeping | Liquidity §9.3 | Client keeps its own local record regardless, for self-monitoring and dispute. Cheap and independent of where authoritative state lives. |
| **D6** | Signer model for resting tier-2 orders | D2, I3, I7 | Unresolved. **See §8.3 — the current external-wallet default does not survive flags-only tier 2.** |

### 5.1 D1 and D2 are coupled decisions

They share liveness evidence, but they are not identical: D1 can select a
desktop client for ordinary trading while D2 remains blocked on the product
shape of block flow.

Liquidity §9.1 observes that firm resting orders emit an on-chain re-lock
heartbeat. **The client emits that heartbeat.** Every mitigation — jitter,
fee-payer rotation, relayed locks, re-locking while nobody is watching — requires
a process that is alive when no screen is open. A browser tab is not.

- **Flags-only tier 2** ⟹ live locks, periodic re-locking ⟹ traders who want
  block execution need a **persistent agent**. Not for proving latency; for
  liveness and heartbeat hygiene.
- **Indication layer** removes the public lock heartbeat, but local
  pre-prove-and-hold still requires an awake client at invitation time. Only a
  separately authorised delegated auto-firm policy removes that liveness
  requirement; an external-wallet popup does not.

This adds an argument to the liquidity record's §6.6 that it does not currently
make: the structural anti-last-look mitigation is *also* what makes browser-based
block trading possible. It should be weighed against the §7.3 capital-commitment
cost, not only against leak prevention.

**Resolve D1 and D2 in the same session, with the same evidence, including the
same three block traders.**

### 5.2 Packaging tiers mirror protocol tiers

| Protocol tier | Client packaging | Why |
|---|---|---|
| Tier 1, ordinary clips | Browser, pre-proved, one proof per note | Small circuits; no liveness requirement; zero-install matters most for adoption |
| Tier 2 with indications | Browser conditionally viable | No lock heartbeat; local firm-up still needs an awake tab/session signer |
| Tier 2 flags-only | **Native agent required** | Re-lock heartbeat needs a persistent, jittering, non-popup signer |
| Market maker | Native daemon, headless | Never in question; MMs already run daemons |

---

## 6. Invariant core — build in Phase 1

All of this is §2.1 material. None of it can be invalidated by D1–D6.

### 6.1 Secure storage
Note credential, encrypted note database, recovery material, configuration,
pairing credentials, optional operational signer. Encrypted at rest; OS secure
storage where available; locked on inactivity; no secrets in logs, crash dumps or
telemetry; frozen derivation and domain separation preserved.

**Deferred to D1:** whether this lives in a native process, a browser extension,
or a page-scoped store behind WebAuthn-PRF-derived encryption. Build the
interface first; the three implementations differ below it.

### 6.2 Chain and tree synchroniser
Poll/subscribe Solana state; reconstruct user note state; verify roots against the
finalized on-chain ring before proving (`onchainRootVerifier` already exists);
maintain paths; handle reorg and ambiguous confirmation; invalidate stale
assumptions. Track root age against the 64-root window as a first-class signal —
it drives proof refresh scheduling.

### 6.3 Note manager
Discover and decrypt notes; compute spendable balances; select notes; maintain
local reservations; prevent local double-use; track consumed / locked / pending /
recovered states. Reservations must be **soft and revocable**, because tier 1
quote curves and tier 2 indications both reserve speculatively.

### 6.4 Tranche scheduler *(new — not in the previous document)*
`VALID_MERGE` requires every active commitment's lock to be absent or expired, so
consolidation and quoting are mutually exclusive (liquidity §8.3). An active MM
accrues a change note per fill, so fragmentation is continuous. The previous
document scheduled merges "when the user is idle" — **an MM is never idle.**

Required: partition inventory into N tranches; quote from N−1; stand down and
merge the Nth; rotate. N is sized against `MAX_LOCK_TTL_SLOTS`, the S-08 warm-note
size cap, merge proving cost and fill rate. Applies to traders too, at a much
slower cadence.

Also: select K ∈ {2,4} for merges on **measured end-to-end cost** — witness time,
proving time, transaction count, fees and CU, root churn, resulting note
distribution. Do not assume one K=4 merge beats two K=2 merges.

### 6.5 Proof manager
Version circuits and artifacts; construct witnesses; prove; **verify locally
before submission**; cache; refresh before root expiry; expose readiness only.

Cache key: `(local_note_commitment, note_use_tag, tree_id, merkle_root,
circuit_version, pk_version)`.
Tracked metadata: creation time, root-history position, readiness state,
invalidation reason, and — once tier 2 exists — `backing_intent_ids[]`.

Refresh is driven by root-ring eviction risk, artifact/version changes, and new
output notes. A lock epoch does not by itself invalidate a proof while its root
remains accepted.

States: `absent → proving → ready → refreshing → stale`, plus
`residual_reproving` (see I5) for change notes emerging from settlement.

### 6.6 Transaction coordinator
Build Solana transactions; route to external wallet or operational signer per
policy; submit and reconcile; distinguish terminal failure from ambiguous status;
retry without duplicate effects.

### 6.7 TEE client
Verify attestation before any sensitive communication; strict by default; refresh
the finalized governance key set on schedule and pause placement on mismatch;
maintain stream state; reconcile fill and settlement state. Already largely built
— carry forward unchanged.

**Carry the cross-layer release gate:** the gateway-pinning gap (liquidity §9.5,
T-03). Clients pin the CVM measurement but nothing pins the dstack gateway.
Closing it requires transport/infrastructure support as well as client
verification; it is not a client-only patch. The client must consume and enforce
the selected authenticated endpoint binding once that contract exists.

### 6.8 Fill-quality auditor *(API-gated)*
Liquidity §8.5 names the client-side memo guard, extended into published per-MM
execution statistics, as the **only compensating control that scales** against a
compromised enclave in a standing relationship with a colluding maker.

The previous document verifies proofs *before* submission and audits nothing
*after*. The desired control checks every fill against the oracle band at the
recorded slot, tracks realised-versus-expected execution, and alerts on
systematic drift. It is **not implementable from the current fill memo**, which
does not carry clearing price, oracle snapshot, observation slot, or counterparty
classification. First specify and privacy-review that API/event extension; do
not infer missing values or label a partial check an auditor.

Because it is the sole defence against that threat class, this belongs in the
non-negotiables (§9), not in observability.

### 6.9 Recovery
Chain-derived note reconstruction from seed. Must be testable by the user
*before* meaningful funds are deposited.

---

## 7. Decision-gated surface — defer, but leave the seam

### 7.1 Intent plane
Order intents, cancels, and later quote curves, indications and firm-up
responses. Built in Phase 3 against whatever tier 1 lands.

**Seam:** one `IntentTransport` interface over REST and `/v1/stream`; versioned
extensible attribute map; readiness handles only.

### 7.2 Pre-prove-and-hold *(proposed resolution for D3)*
Liquidity §6.3 says indications need no proof and no lock — that is the capital
multiplexing win. §6.6's structural mitigation wants the indication to carry a
pre-authorised proof. And firm-up latency demands a proof that already exists.

These reconcile by separating **generating** a proof from **submitting** it:

> The client proves every note backing a live indication, holds the proof
> locally, and submits it only on invitation.

Proving is local computation. It costs no capital, takes no lock, and has zero
on-chain footprint — so §6.3's multiplexing survives intact. Because proofs are
note-scoped (§3.1), one proof covers indications at every price level across
every same-mint market. Firm-up becomes "retrieve cached blob, sign, send."

This yields a **third option in liquidity §6.6**, between behavioural policing
and full auto-firm: the client is *capable* of instant firm-up, the enclave scores
firm-up **latency** as well as firmed-to-indicated size ratio, and a decline is
visibly a decision rather than a capacity limit. It still requires the client to
be awake and able to authorise the intent. An external-wallet approval cannot
realistically meet a 200 ms gate; that gate applies only to a scoped session
signer or a deliberately delegated auto-firm policy. Weaker than auto-firm;
stronger than scoring alone; commits no capital before firm-up.

### 7.3 Order attributes
`min_execution_size`, `allow_mm_counterparty`, `residual_policy` and successors.
Carried as opaque attributes by the core (§2.3 seam 1); surfaced by the UI.

UI notes for when they land:
- **MES** in trader language ("don't fill me in pieces smaller than X"), with the
  per-execution / per-order trade-off stated honestly, since the liquidity record
  itself flags the fill-rate tension. If per-order is ever offered, enforce the
  per-counterparty floor client-side too.
- **`allow_mm_counterparty`** is the buy side's "choose your exposure" lever and
  the direct answer to the standing buy-side objection to MM presence. It is a
  **first-class visible control**, not an advanced-panel flag.
- **`residual_policy`** needs plain-language framing of the trade-off. `expire`
  is probably the conservative default for block flow.

### 7.4 Heartbeat privacy manager
**Only if D2 resolves flags-only.** Re-lock jitter, fee-payer rotation, possible
relay so the same address does not sign every cycle. Design informed by the I3
classifier — the mitigation and the measurement are the same work.

### 7.5 Packaging
Deferred to D1. Candidates, in rough order of preference pending evidence:
1. **Browser, multi-threaded WASM** — zero install; the default unless G1–G3 fail.
2. **Single signed desktop app (Tauri) bundling UI + native prover** — internal
   IPC, no localhost port, no CORS, no DNS-rebinding surface, no local-network
   permission prompt.
3. **Agent + extension over native messaging** — a legitimate pattern that avoids
   the localhost problems, at the cost of two installs and a pairing flow.
4. **Loopback HTTP** — acceptable only for a founder-assisted pilot, and only
   hardened: loopback bind only, random port, one-time pairing secret,
   short-lived session tokens, strict origin allowlist, no wildcard CORS,
   CSRF and DNS-rebinding protection, no debug endpoints. Note that browser
   local-network permission prompts now gate this pattern for hosted pages.

**WebGPU: do not build it in Phase 0.** There is no production WebGPU Groth16
backend in this repository, backend maturity is a larger risk than the plausible
gain for these circuit sizes, and the measured M3 split does not show witness
generation dominating. Revisit only if current-browser measurements fail and a
maintained backend can be evaluated without changing circuit semantics.

**Delegated proving is not the fallback.** The current order CVM does not expose
a least-privilege client-proving service, and a client witness includes the note
opening and spending key. Sending it to that CVM would materially broaden the
custody/trust boundary. A future proving enclave would need a separate threat
model, attestation policy, API, resource isolation, and explicit user consent.

---

## 8. Key and signer model

Carried forward from the previous document, with one correction.

### 8.1 Two key roles, never collapsed
1. **Note credential** — note ownership, witness construction, recovery,
   protocol-specific derivations. Held by the client core. **Never reaches a web
   page** in any packaging.
2. **Solana transaction signer** — authorises and pays for on-chain transactions.

### 8.2 Defaults by participant
| Profile | Note credential | Solana signer |
|---|---|---|
| Human trader | Client core | External wallet (Phantom / hardware / custodian) |
| Power trader | Client core | External by default; optional scoped session key |
| Market maker | Headless daemon | Dedicated operational key, HSM or custody adapter, separate from treasury |
| Development | Local | Test-only keypair |

Darknyx must never ask a trader to paste an external wallet seed phrase.

### 8.3 Correction: the external-wallet default does not survive flags-only tier 2
A resting block order that re-locks on a heartbeat cannot prompt an external
wallet on every cycle. Under flags-only, either the scoped operational signer
stops being MM-only and becomes available to block traders, or tier 2 needs
indications. **This is D6 and it is currently unowned.**

### 8.4 Browser key custody, if D1 resolves browser-first

A Worker isolates secrets from the UI thread; it does not isolate them from a
same-origin compromise. Non-extractable WebCrypto keys can still be *used* by
malicious same-origin code, while witness values and note scalars necessarily
enter WASM memory. WebAuthn PRF plus ciphertext-only IndexedDB remains worth
prototyping, with a recovery path, but it is not proof that a pure page is
non-custodial under XSS.

Browser packaging therefore requires a focused custody review covering CSP and
Trusted Types, dependency/supply-chain integrity, cross-origin isolation,
service-worker/update rollback, memory lifetime, backup recovery, and an
adversarial same-origin test. Passing performance alone selects nothing. If the
review fails, use a signed Tauri shell with native custody/proving and internal
IPC; do not bridge secrets over localhost HTTP.

---

## 9. Non-negotiable security properties

1. UI components never receive note secrets, witnesses, or decrypted note
   records. A browser Worker is an execution boundary, not a same-origin security
   boundary; a browser build ships only after §8.4's review.
2. The client never asks for the user's primary wallet seed phrase.
3. An automated signer is separate from the treasury key.
4. The intent plane cannot request arbitrary signing or arbitrary proving.
5. Any local transport binds to loopback or local IPC only, never `0.0.0.0`.
6. Every bridge request is origin-bound, authenticated, typed, replay-protected.
7. Circuit and proving-key versions are verified before proving.
8. Proofs are verified locally before submission.
9. Once the required fill fields exist, every fill is audited against the oracle
   band after settlement (§6.8); until then this remains an explicit open gate.
10. Attestation is strict by default; placement pauses on governance key mismatch.
11. Logs and telemetry contain no secrets, note preimages, or private order detail.
12. Updates and proving artifacts are signed and verified.
13. Ambiguous chain results are reconciled, never blindly retried.
14. No **firm** intent may be sent whose backing note has no ready proof.
    Non-firm indications are exempt unless D3 chooses pre-prove-and-hold.

---

## 10. Acceptance criteria

**[TARGET] — these are proposed gates, not measurements.** Phase 0 replaces the
placeholders with evidence.

### Trader
- No command line for install or pairing (whatever D1 selects).
- No manual proving-key download; no manual proof management.
- Order submission does not wait on proof generation in the normal path.
- Wallet approvals describe the economic action, not the cryptography.
- Recovery is testable before meaningful funds are deposited.
- `VALID_INPUT` warm p95 within G1/G2 for the target device class.

### Market maker
- One-command or managed install.
- Quote engine starts only after inventory and proofs are ready.
- Proof refresh never blocks the quote loop (structural per §3).
- Sustained proving throughput meets §4.4 demand with queue depth stable.
- Tranche rotation sustains quoting while consolidating.
- Operational signer is bounded, rotatable, revocable.
- Restart recovers reservations and settlement state safely.

### Tier 2 (once D2 resolves)
- Firm-up p99 within G4.
- Under flags-only: re-lock pulse indistinguishable per the I3 classifier.
- Under indications: no capital committed before invitation.

### Observability
Cold and warm proving metrics separated; p50/p95/p99 not means; proof-cache hit
rate; root-expiry refresh rate; proof queue depth; merge queue depth and tranche
state; settlement reconciliation status; fill-quality audit deviations;
signer-policy rejections; version compatibility.

---

## 11. Phasing

### Phase 0 — investigate and measure *(blocks everything)*
I1–I7; the current-circuit benchmark matrix; G1–G7 evaluated.
**Output: D1, D3, D4 decided on evidence, and the client-side inputs to liquidity
§9.1/§9.2 delivered.**

### Phase 1 — invariant core
§6.1–§6.9 against the existing order surface. No tier vocabulary anywhere. Ends
with a headless client that can deposit, prove, place, cancel, settle, merge,
recover, and expose the fill-auditor seam — with a warm proof cache and tranche
rotation. The auditor itself waits for §6.8's API fields.

### Phase 2 — decision point
Resolve D1, D2, D6 jointly with the liquidity record's §9.2. Same session, same
evidence, same trader interviews.

### Phase 3 — intent plane and tier 1
Order attributes; quote curves; MM adapter (soft reservation, capacity, quote
expiry, fill reporting, external risk integration); packaging per D1. Built in
step with the matcher work, not after it.

### Phase 4 — tier 2 client surface
Shape per D2. If indications: pre-prove-and-hold (§7.2), invitation handling,
residual policy. If flags-only: heartbeat privacy manager (§7.4) and the D6
signer resolution.

### Phase 5 — institutional hardening
Enterprise policy, admin configuration, audit logs without secret leakage,
multi-user isolation, disaster recovery, signed artifact and circuit manifests,
upgrade/rollback, independent security review, gateway pinning (§6.7) closed.

---

## 12. What this document does not settle

- **D2** and therefore Phase 4's entire shape. Owned by the liquidity record.
- **Liquidity §9.3** (reputation state home). The client keeps a local record
  regardless; where authoritative state lives is a protocol question.
- **Poseidon2 or Merkle-depth migration.** Excluded from Phase 0; either requires
  a protocol/security review and ceremony and is considered only if current
  backends fail the desktop gates.
- **Whether the S-08 warm-note cap and MM proving throughput can be jointly
  satisfied.** §4.4 models it; the answer may constrain MM onboarding size.
- **Priority flow allocation mechanics** (liquidity §8.1) and how the MM API
  surfaces allocation status.

---

## Cross-references

- Tier design, MES, residual policy, MM access:
  [`liquidity-mm-and-block-matching-design-record.md`](liquidity-mm-and-block-matching-design-record.md)
- Circuits, constraint counts, ceremony status: [`CRYPTOGRAPHY.md`](../CRYPTOGRAPHY.md)
- Matcher, prover backends, API surface: [`tee-architecture.md`](tee-architecture.md)
- Attestation and the T-03 gateway gap: [`tee-attestation-flow.md`](tee-attestation-flow.md)
- Lock semantics and `MAX_LOCK_TTL_SLOTS`:
  [`lock_note.rs`](../programs/vault/src/instructions/lock_note.rs) and
  [`state.rs`](../programs/vault/src/state.rs)
- Existing client surfaces: [`packages/daemon`](../packages/daemon) and
  [`valid-input-prover.ts`](../packages/sdk/src/zk/valid-input-prover.ts)
- API contract to extend: [`tee-api-openapi.yaml`](tee-api-openapi.yaml)
