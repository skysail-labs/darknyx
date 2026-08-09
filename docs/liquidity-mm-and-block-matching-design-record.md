# Liquidity, market-maker access, and block matching — design record

> Status: **DESIGN RECORD — nothing here is implemented.** Captures the full
> reasoning chain from a July 2026 design session, including proposals that were
> raised and **rejected**, and the arguments on both sides of every decision.
>
> Scoped so that **no circuit change, no VK bump and no ceremony is required.**
> Everything lives in the matcher, the API surface, or governance config. Any
> proposal that would touch a circuit is called out explicitly and deferred.
>
> **Read §9 before implementing anything.** Three decisions are blocked on
> measurements that have not been taken.

---

## 0. How to read this document

Sections 1–2 establish why liquidity is a protocol-level problem. Sections 3–4
record two designs that were **investigated and rejected**, and why — do not
re-propose them without reading the counterarguments. Sections 5–8 are the
surviving design. Section 9 is the open-questions list that gates
implementation. Section 10 is the phased plan.

Where a decision was made on judgement rather than evidence, it is marked
**[JUDGEMENT]** and the opposing argument is stated.

---

## 1. Why liquidity is a protocol problem, not a growth problem

### 1.1 A dark pool that does not fill is a privacy leak

The protocol's core promise is that order intent never touches L1. That promise
holds only for orders that **fill inside the enclave**. An order that rests,
fails to find a counterparty, and expires has not been kept private — it has been
*delayed*. The trader then routes the same intent to a lit venue, later, into a
market that has had time to move.

Worse: the residual is now correlated with a public vault deposit. An observer
who sees a large deposit followed some interval later by matching size hitting
the lit market recovers both the existence and the direction of the order — the
exact inference the venue exists to prevent.

**Thin liquidity does not degrade the privacy guarantee gracefully. It inverts
it.** Fill rate is therefore a security parameter, not a growth metric.

### 1.2 Cold start is structural

Every functioning dark pool in TradFi solved cold start by either broker/bank
internalisation of captive flow, or a pre-existing member network (Liquidnet
scraped the order-management-system blotters of ~740 buy-side firms). Neither is
available to us.

The pure "buy-side only, no market makers" model is the closest analogue to a
naive launch, and it is the documented failure case: Luminex was built exactly
that way and still had to bolt on an external routing bridge to backstop its own
thin book. The standing critique is that buy-side firms cluster on the same side,
so natural crosses are rare. **That critique is sharper in crypto** — we launch
with a handful of liquid pairs whose participants hold highly correlated
directional views.

### 1.3 The oracle band removes the escape hatch, correctly

A lit AMM never has a cold-start problem because it manufactures counterparties
by moving price until someone bites. That is also why its execution at size is
bad.

Our matcher cannot do this. Fills are constrained near the external market price
by the circuit-breaker band. This is the right design and it has a direct
consequence:

> **We cannot clear a one-sided book by conceding price. Either a real
> counterparty exists, or the order does not fill.**

Price concession is the standard remedy for illiquidity and we have deliberately
given it up. That leaves one remedy: more counterparties in the book.

---

## 2. What market makers give and what they cost

Natural counterparties are **episodic** — two institutions with opposite intent,
comparable size, overlapping price, at the same moment. Market makers are
**continuous**. Venues that bet on natural crosses alone have repeatedly
under-delivered.

The cost: an MM with ordinary access will probe the book with small orders to
detect resting size and direction, then trade ahead on lit venues. In a dark
venue the probe is the *only* way to see, which makes it correspondingly more
valuable and more likely.

**Design objective: admit market makers as a liquidity source while denying them,
structurally, the pre-trade information that makes predation profitable.**

### 2.1 The buy-side objection, recorded in full

Adding market makers is frequently a **negative** signal to a head of trading.
Luminex was founded specifically to exclude proprietary/HFT liquidity, backed by
nine buy-side firms. Empirical work finds that introducing a high-frequency
trader into an existing dark pool increases the information leakage of trades.

**The reconciliation, and the standard we must meet:** the buy side tolerates MMs
when (a) they are anonymous, (b) they compete to provide price improvement, and
(c) the buy side chooses its exposure. It rejects MMs when they can **detect and
front-run** resting institutional intent. §5 and §6 are built to satisfy (a)–(c);
§8.2 is the mandatory disclosure obligation that follows.

---

## 3. REJECTED — venue-initiated, imbalance-triggered RFQ

### 3.1 What was proposed

A worker scans the book at randomized intervals, detects an imbalance, and issues
a blind two-sided RFQ to gated market makers to supply the missing side.

### 3.2 Why it was rejected

**The solicitation event is itself the leak.** The request's *existence* signals
the book's state: a request arrived ⟹ the venue needs a side ⟹ one-sided pressure
exists in this asset right now. Every polled MM learns that, **including the ones
who lose**. Losers acquire free, actionable information about a book they are not
permitted to see, and nothing prevents them acting on it on a lit venue minutes
later.

Blinding direction reduces this but provably does not eliminate it. The theory
(Baldauf & Mollner) is explicit: the winning dealer always learns direction, the
loser infers it after one period, and **the pattern of solicitations leaks the
side** — polling frequency and dealer count are themselves signals. Repeated
solicitations in one asset let a gated MM build a timing classifier of when the
book gets stressed.

**Supporting evidence.** No mainstream equity ATS runs venue-initiated dealer
solicitation off a hidden book. Liquidnet Targeted Invitations, Turquoise Plato
OSRs and BIDS conditionals are all **firm-up invitations between two natural
counterparties**, not dealer price-solicitations. The industry converged on
natural-to-natural firm-up specifically to avoid this leak.

**Also note the inversion:** lit closing auctions publish imbalance deliberately,
to pull in offsetting liquidity. A venue-initiated RFQ re-imports the closing
auction's imbalance-disclosure mechanic into a venue whose premise is
concealment.

### 3.3 Do not re-propose without

A simulation against a classifier adversary demonstrating that randomized-timing
blind RFQ leaks no more than continuous unprompted quoting. The burden of proof
sits on the RFQ design.

---

## 4. REJECTED (as a distinct mechanism) — "option (a)" as an RFQ variant

### 4.1 What was proposed, and the flaw

The replacement for §3 was: MMs quote continuously and unprompted into every
batch auction, so no solicitation event ever occurs. This is correct and is
retained — **but it was initially framed as an RFQ mechanism, and it is not.**

Once solicitation is removed there is no request, no response cycle and no dealer
selection. What remains is a market maker placing two-sided orders into a book
nobody can see. **That is ordinary market making on the standard trader rails.**
The RFQ framing was vestigial and is discarded.

### 4.2 The reason this matters

Zama built an FHE-based RFQ layer, including a zero-amount opposite-leg
construction, **because they have no trusted evaluator** and needed machinery to
prevent dealers seeing direction. On a public chain an MM can watch the book, see
imbalance, and pull.

**We have no such problem.** An MM placing orders into the enclave sees nothing —
not the book, not the imbalance, not whether anything is resting at all.
Direction is hidden by default, structurally, not by mechanism.

> **The RFQ layer was solving a problem this architecture does not have.**

### 4.3 What survives, what dies

**Survives and becomes more important:** batch auctions; MES; minimum resting
time; firm-up reputation scoring. These are now the *only* things distinguishing
a market maker from a prober, since both use the same API.

**Dies:** the RFQ endpoint, the solicitation worker, the dealer-count question,
the requested-size question, the reference-price-for-solicitation question. All
were downstream of a mechanism we do not need.

---

## 5. Tier 1 — continuous matching, market makers permitted

### 5.1 Mechanism

Per auction, per market:

1. MMs submit **two-sided quote curves** — size/price schedules, not single
   prices. Both sides, every auction, unconditionally.
2. The MM is told **nothing** in advance. No imbalance, no size, no side, no
   indication anything is resting. Its inputs are the oracle price, its own
   inventory and its own risk model.
3. The enclave collects resting trader orders and all MM curves and computes a
   uniform clearing price within the oracle band.
4. **Natural crosses match first**, trader against trader at mid, paying no
   spread to anyone.
5. The residual clears against the best MM curves at the uniform price.

### 5.2 Why unprompted quoting beats solicitation

Under solicitation, every polled MM learns something. Under unprompted quoting,
**an MM learns only by having already traded** — it discovers there was buy
pressure by having sold into it, at which point the trade is settled, there is
nothing left to front-run, and its incentive is to hedge rather than hunt. MMs
that did not win learn nothing at all; they cannot distinguish an empty auction
from an enormous one.

Information obtained *by trading* is far less dangerous than information obtained
*by being asked*, because the former is paid for in inventory risk while the
latter is free and declinable.

### 5.3 Why MMs will quote without an information edge

- Flow cannot be sniped: no continuous book to pick off, randomized clearing
  instant.
- Flow is structurally less toxic: the oracle band means nobody is here to move
  price, and naturals are netted out before MMs see anything.
- Quoting is nearly free: `VALID_INPUT` is note-scoped, so inventory is proved
  once per lock epoch and signed curves stream after that. Unfilled quotes expire
  at zero cost.

This is the Paradex retail-price-improvement argument, which reports materially
tighter quoting under exactly these conditions. **[Self-reported — treat as
directional.]**

### 5.4 Costs, stated honestly

- MMs must hold provable inventory on **both** sides at all times.
- Note fragmentation is worse than under a request model — every won auction
  produces a change note, and `VALID_MERGE` will not consolidate notes with live
  locks (§8.3).
- MMs will quote **wider** initially than they would with information. That is
  the honest price of denying them information; it should narrow as they measure
  the flow and find it clean.
- **Option (a) does not guarantee MMs show up.** It makes participation safe for
  traders. Recruiting MMs remains a business problem, and priority flow
  allocation is the only lever available (§8.1).

### 5.5 Open implementation question

A trader backs one order with one note. An MM wanting depth at eight price levels
on both sides needs enough provable inventory to back all of it simultaneously.
Continuation re-lock helps for *sequential* fills within a batch, but whether one
note per side can back a full ladder — or whether MMs need fragmented inventory
per level — must be worked out against lock semantics. **Unresolved.**

---

## 6. Tier 2 — block matching, naturals only

### 6.1 Why tier 1 cannot serve blocks

An MM quoting blind faces adverse selection that grows with size. Its optimal
blind curve is therefore **thin in the tail** — tight and deep near mid,
vanishing beyond it, because committing to absorb very large size from an unseen
counterparty is precisely how one gets run over by the informed order.

Tier 1 sources liquidity well for ordinary clips and **structurally cannot source
it for block size.** Block size is the product.

### 6.2 Mechanism

1. **Indication.** A trader submits non-firm interest:
   `{side, max_size, MES, limit_price, market, expiry}`. It commits no capital,
   locks no note, cannot be executed against.
2. **Enclave-side matching.** The enclave holds all indications and computes
   compatibility: opposite sides, overlapping size, prices meeting inside the
   band. **The enclave knows all sizes — what is hidden is that the counterparty
   never learns them.**
3. **Invitation**, fired only when `overlap ≥ A.MES AND overlap ≥ B.MES`. The
   invitation carries **no size, no price, no side, no counterparty identity**.
   Its entire content is: *a match may exist for you, firm up now.*
4. **Firm-up.** Each side submits the real order plus `VALID_INPUT`. If both
   firm, they cross at mid. If either does not, nothing happens.

No market maker is in this loop. The only parties who learn anything are two
people who each already had a real order in that asset.

### 6.3 Why this fits the architecture

Indications need **no proof and no lock** — non-firm by construction, so there is
nothing to prove. The `VALID_INPUT` proof is generated only at firm-up, when a
match is near-certain. This matters more here than for equity venues because
CRYPTOGRAPHY.md records client-side proving as the placement-latency bottleneck.

One note can back indications at many price levels across several markets,
because only one ever converts. That is **capital multiplexing across the book**.

**Precedent:** Turquoise Plato reports >90% of invitations firming within half a
second, and independent measurement found the reference mid moved in under 10% of
cases one second after execution, versus ~50% for continuous dark pools. That
second figure is a direct measure of information leaked into the market.

### 6.4 Settlement — no separate rail

There is **no separate settlement path**. `VALID_MATCH_BATCH` +
`tee_forced_settle_batched` is the only way anything settles. A tier-2 cross is
an ordinary match: same circuit, same batch, same instruction, same
`BatchValidityMarker`.

The tiers differ **only pre-matching** — how interest is expressed, who is
eligible as counterparty, what the enclave requires before assembling a match.
Once a match exists the tiers are indistinguishable to the chain. **Tier 2
therefore requires no circuit work.**

### 6.5 Firm-up sequencing — the anti-griefing requirement

**Firm-up is an enclave-level commitment, not an on-chain lock.**

Each side submits order + proof to the enclave, which validates and **holds**
it. Only when **both** sides have firmed does it proceed to Tx A.

Consequence: if B never firms, A has landed nothing on-chain, paid no fees and
locked no note — the proof is discarded. This kills the obvious griefing vector
(spray indications, trigger invitations, never firm, make honest counterparties
burn locks and fees on nothing). **This sequencing is mandatory, not an
optimisation.**

### 6.6 The residual leak in the firm-up window

A participant can receive an invitation, learn a counterparty exists, decline to
firm, and trade that knowledge elsewhere. **This is last look wearing a different
hat.**

Two mitigations:

- **Behavioural (what Turquoise does).** Score firm-up rate, eject failures.
  Policing, not prevention. Score the **ratio of firmed size to indicated size**,
  not binary firm/no-firm — someone habitually indicating 10k and firming 2k is
  fishing, and a binary score misses it.
- **Structural, available to us specifically.** If the indication carries a
  pre-authorized proof the enclave can act on unilaterally, firm-up becomes
  automatic: no decline option, therefore no leak. **Strictly stronger than
  anything Turquoise can offer**, because the enclave can hold a note-scoped
  proof and act without a client round trip.

Cost of the structural option: auto-firm means capital is genuinely committed
(see §7.3 — this is also what collapses tier 2 toward tier 1).

---

## 7. MES, residual, and slots

### 7.1 MES semantics — per-execution default **[JUDGEMENT]**

**MES = Minimum Execution Size**, trader-specified per order: "do not fill me for
less than this."

It is the anti-probing primitive. Without it, someone trades 50 SOL against a
resting 10k block and has confirmed both existence and side for almost nothing.
MES sets the price of that discovery.

| Semantics | Rule | Effect |
|---|---|---|
| **Per-execution** | every individual print ≥ MES | fewer fills, harder leakage guarantee |
| **Per-order** | total filled in the matching event ≥ MES; components may be smaller | more fills, cheaper discovery for counterparties |

**Worked example.** A wants 10k, MES 5k. Available: 4k, 3k, 3k.
- *Per-execution:* no invitation fires — nobody individually clears 5k. A stays
  unfilled.
- *Per-order:* invitation fires, A fills 10k across three prints. **But A now has
  three counterparties who each know a large buyer was present, and the cheapest
  learned it for 3k.**

**DECISION: per-execution by default, per-order as explicit opt-in.**

*Argument for the default:* our users are explicitly size-sensitive; the whole
product is not being discovered. Per-execution guarantees that only a
counterparty willing to commit ≥ MES learns anything.

*Argument against (recorded):* per-order fills more often, and fill rate is a
security parameter per §1.1. A trader who never fills gets no privacy either.
This is a real tension and the default may need revisiting under measurement.

*Known hole in per-order:* nothing stops one leg being tiny, letting an attacker
ride along in an aggregate for 500 and learn what MES was meant to cost 5k. **If
per-order is offered, pair it with a separate per-counterparty floor.**

> ⚠️ **Confirm this decision.** It was requested in the inverse form (per-order
> default, per-execution opt-in). Written here as recommended. If per-order
> default is genuinely wanted, flip it and add the per-counterparty floor as
> mandatory rather than optional.

### 7.2 Residual handling — continuation re-lock is already the right primitive

A firms 10k; 6k crosses against B. The settle path consumes A's input note and
produces trade + change, and `buyer_relock_order_id` / `note_lock_e` re-locks the
change **atomically in the same transaction**. A's 4k residual is a locked,
provable, immediately-usable note the instant the block cross settles — no new
proof, no client round trip, no window where the residual is unprotected.

**This primitive already exists and was built for a different purpose.**

Residual policy should be a **client-elected order parameter**, not a venue
default:

| Policy | Behaviour | Trade-off |
|---|---|---|
| `rest_as_indication` | change note backs a fresh tier-2 indication | keeps waiting for a natural, keeps mid |
| `cascade_to_tier1` | residual enters the next batch auction, MMs may absorb | faster fill, pays MM spread |
| `expire` | release the lock, return control | client routes elsewhere |

**On the Drift JIT analogy:** correct in shape, but Drift's cascade terminates in
an AMM that *always* fills because it is a curve. **We must not build that.** A
protocol-operated curve taking the other side of block flow is the internaliser
problem and the Pipeline fact pattern with extra steps (§8.2). Our cascade
terminates in "no fill," and the client decides. Less convenient; correct.

### 7.3 Many-to-one aggregation

A wants 10k; counterparties offer 4k, 3k, 3k. Mechanically supported by the same
primitive: A's note is consumed by match 1, produces change, change is re-locked,
consumed by match 2, and so on. **A single large order can chain through several
counterparties inside one batch.**

Two consequences:
- It burns match slots (§7.4).
- It forces the MES semantics decision (§7.1) — aggregation is exactly what
  per-order MES permits and per-execution MES forbids.

### 7.4 Batch slots — shared pool, soft cap **[JUDGEMENT]**

**The batch pads to 16 regardless.** Tx B proves a padded N=16 batch, so a batch
carrying three real matches costs the same proving time and on-chain verification
as one carrying sixteen. This kills the two intuitive options:

- *Reserved partitions (e.g. 12/4):* wastes real proving cost whenever a tier is
  idle.
- *Alternating batches:* halves each tier's cadence and makes an empty tier-2
  batch a full-price proof of nothing.

**DECISION: one shared slot pool, packed opportunistically, with a
governance-tunable soft cap on tier-2 slot consumption per batch.** The cap
exists because one block chaining through three counterparties consumes 3/16 and
can starve MM matching that cycle. Soft rather than hard, so an idle tier fills
with the other's flow instead of padding.

**Measure once running:** what fraction of batches are actually full. Heavy
padding means cadence is too fast and we are paying for proofs of air.

---

## 8. Constraints the current architecture imposes

### 8.1 We cannot pay a maker rebate

`fee_rate_bps` is a single `u16` in `VaultConfig`, hashed into
`config_digest = Poseidon8(28, fee_rate_bps, protocol_owner, base_lo, base_hi, quote_lo, quote_hi, price_scale)`,
a public input to `VALID_MATCH_BATCH`. Both legs pay their own fee; conservation
is `input = trade + change + fee`. **No maker/taker asymmetry, no negative fee.**

Every crypto venue surveyed bootstraps MMs with rebates or negative maker fees.
We structurally cannot without a circuit change and a full ceremony.

> **MM economics must therefore be priority flow, not price.** What we can offer
> is a guaranteed share of non-toxic, near-mid, size-bearing flow with no sniping
> exposure. That offer must stand on its own.

### 8.2 Disclosure is mandatory — the Pipeline constraint

Pipeline Trading was penalised because its affiliate was counterparty to the vast
majority of orders while it marketed "natural liquidity" and "no pre-trade
information leakage." Reported volume collapsed and the firm wound down.

**Requirements:**
- Disclose MM presence unambiguously in the rulebook.
- Never represent the pool as purely natural liquidity.
- Publish tier rules, scoring inputs and ejection criteria (§8.5).
- Architect so MMs cannot see resting intent — §5 does this, and the enclave
  attestation makes it *verifiable*, which Pipeline could not offer.

**Cryptography makes operator honesty verifiable. It does not cure the economic
conflict.** If an MM is on the other side of most flow, we are a wholesaler with
a ZK proof.

### 8.3 Quoting and consolidation are mutually exclusive

`VALID_MERGE` requires every active commitment's `NoteLock` to be absent or
expired before proof verification or state mutation. An active MM accrues a
change note per fill, so fragmentation accumulates and consolidating requires
standing down from quoting on those notes. **MMs must run inventory in tranches
and rotate.** This belongs in onboarding documentation.

### 8.4 S-08 blast radius scales with note size

A `VALID_INPUT` proof binds only `(merkle_root, note_commitment, token_mint)`;
`order_id` and `expiry_slot` are unconstrained `lock_note` arguments. A
compromised-but-authorised enclave key can retain a relayed proof and re-lock the
note against an arbitrary `order_id` while the root remains in the shard's
64-root window. **The documented practical bound is the note size.**

For a retail trader that is one order. For an MM keeping a large warm quoting
note, it is the whole note. **Mitigation without a circuit change is operational:
cap the size of any single warm quoting note; require MMs to run more, smaller
notes.** Costs them fragmentation, buys a smaller worst case.

*Note that this same property is what makes MM participation viable at all* (one
proof per note per epoch rather than per quote). The security gap and the
enablement primitive are the same design decision.

### 8.5 New threat-model row required

**The enclave chooses which MM wins.** A compromised enclave plus a colluding
maker can extract within the band, repeatedly, from a standing counterparty
relationship. Per-trade loss remains bounded by order size and value inflation
remains proof-prevented — but the existing "bounded loss" argument was reasoned
about as a one-off, not a recurring relationship.

**Add this row to the §2 threat table in CRYPTOGRAPHY.md.** The compensating
control that scales is the client-side memo guard extended into **published
per-MM execution-quality statistics**, so traders can detect systematic bias even
where they cannot prevent it.

---

## 9. OPEN QUESTIONS — resolve before implementing

### 9.1 ⚠️ BLOCKING — the `MAX_LOCK_TTL_SLOTS` question

**This single measurement decides whether tier 2 needs a non-firm indication
layer at all.**

The strongest argument for indications is that **firm resting orders emit an
on-chain heartbeat.** Every lock has `expiry_slot ≤ clock.slot + MAX_LOCK_TTL_SLOTS`.
Block interest is patient by definition — potentially hours. A firm resting order
therefore needs periodic re-locking: a fresh `lock_note` transaction each cycle,
plus possibly a fresh proof if the root has aged out of the 64-root window.

**Repeated `lock_note` transactions from one account on a heartbeat is an on-chain
signature of resting interest.** We would have built a venue where intent never
touches L1, then made patient block orders emit a periodic on-chain pulse.
Indications have zero on-chain footprint until they cross.

**To measure:**
1. What is `MAX_LOCK_TTL_SLOTS` actually set to, and what is the safe ceiling?
2. Is the re-lock pulse legible on-chain — can an observer distinguish a
   re-locking resting order from ordinary activity? **Build the classifier and
   try.**
3. How long does block interest realistically rest? (Requires talking to
   traders — §9.4.)

**Decision rule:** if TTL is short relative to realistic resting time and the
pulse is legible, indications are justified. If TTL can safely be raised, or
resting times are short, the argument largely evaporates and the §9.2
simplification wins.

### 9.2 The indication-layer-versus-flags decision

If indications carry a pre-authorized proof and the enclave auto-firms
unilaterally (§6.6), **tier 2 stops being a separate mechanism.** An auto-firming
indication *is* a resting order with hidden size. What then distinguishes it from
tier 1 is only two things: a high MES, and MMs excluded as counterparties.

Which suggests **one matching engine with three per-order flags**:

```
min_execution_size     // the block gate
allow_mm_counterparty  // naturals-only when false
residual_policy        // rest | cascade | expire
```

**For:** dramatically less to build, less attack surface, no new circuit, closer
to how equity venues actually work (order attributes, not parallel venues).
Removes cross-tier timing inference for free — one cadence, one batch.

**Against:** without a non-firm stage, resting block interest requires proving and
locking. Expressing interest at five price levels means five locked notes. Locked
capital cannot be withdrawn (`withdraw` refuses on live locks) or consolidated
(§8.3). And the §9.1 heartbeat problem applies.

**A correction worth recording:** an earlier version of this argument claimed
indications let traders rest simultaneously on Jupiter. **That is wrong.** Capital
must be in the vault as notes before anything can be proved, so it is not on
Jupiter either way — the commitment happened at deposit. The real difference is
**intra-venue** (multi-level expression, withdrawal availability, on-chain
silence), not cross-venue.

### 9.3 Where does reputation state live?

Firm-up scoring and MM execution-quality statistics need **durable
per-participant state.** The fills-history work deliberately removed the
enclave's persistence layer (`persistence/fills.rs`, `api/fills.rs` retired under
Proposal C) on the principle that **the TEE keeps no history DB and the chain is
the durable record.** Scoring state has no on-chain home and cannot be derived
from chain data.

Options, none free:
- Accept a bounded, explicitly-scoped exception to the no-history-DB rule.
- Derive scores from a recomputable window; accept loss on restart.
- Externalise to a governed off-TEE service; accept a new trust component.

**This blocks §6.6 behavioural scoring and §8.5's published MM statistics.**

### 9.4 Empirical questions for actual block traders

Three inputs decide §9.2 and cannot be answered from the code:
1. Do they want to rest interest at **multiple price levels**, or do they mostly
   have one price in mind?
2. Are they **capital-constrained** — does frozen locked capital bite, or are
   they parking a dedicated allocation anyway?
3. How long does block interest **realistically rest**?

**Ask the first three block traders you speak to.**

### 9.5 Lower-priority open items

- **Auction cadence** — trader latency versus anti-gaming strength, bounded above
  by `MAX_LOCK_TTL_SLOTS` minus prove-and-land latency.
- **Max warm quoting note size** (§8.4) — trades MM capital efficiency against
  S-08 worst case.
- **MM ladder note economics** (§5.5) — can one note per side back a full ladder?
- **Quote-curve wire format** — expressive enough to be useful, bounded enough to
  evaluate under CU budget.
- **Oracle band on-chain?** Out of scope here but relevant: the byte-budget half
  of the original rejection dissolves under the v1 transaction format (4096
  bytes), leaving oracle-update CU cost and T0→T1 drift as the real blockers.
  **Institutional MMs are precisely the counterparty who asks whether the venue
  can prove it filled inside the band or merely asserts it.**
- **T-03 gateway pinning.** Order intent in transit terminates TLS at Phala's
  dstack gateway, itself a TDX CVM, but clients pin our MRTD and compose hash and
  nothing pins the gateway's. **A market-making desk's security review will find
  this in an afternoon.** Resolve before institutional onboarding.

---

## 10. Phased plan

### Phase 0 — measure and ask (blocks everything)
- Read `MAX_LOCK_TTL_SLOTS`; determine the safe ceiling (§9.1).
- Build the re-lock-pulse classifier; test on-chain legibility (§9.1).
- Talk to three block traders; answer §9.4.
- Decide §9.3 (reputation state home).
- **Output: the §9.2 decision, made on evidence.**

### Phase 1 — anti-gaming first
MES (per-execution default), minimum resting time, firm-up/ratio scoring, and the
disclosure rulebook (§8.2).

**These must exist *before* external market makers are admitted, not after.**
Admitting MMs into a venue without them is how you learn about probing from the
fill data. Note MES sits in the same trust class as existing controls (U-01:
tick size, min size and the band are governance rules the matcher honours, **not**
`VALID_MATCH_BATCH` public inputs) — do not describe it as on-chain-enforced.

### Phase 2 — batch auctions
Randomized cadence within a bounded window; uniform clearing price; close instant
never exposed in advance; cadence bounded by `MAX_LOCK_TTL_SLOTS` minus
prove-and-land latency. Governance-tunable per `MarketConfig`.

Protective on its own, and everything else integrates into it. **No circuit
change.**

### Phase 3 — tier 1 MM participation
MM role on the auth surface, gated onboarding, elevated rate limits, size caps,
two-sided obligation, quote TTL scoped to the auction, priority flow allocation.
Warm-note size cap per §8.4. **No new circuit, no new note type, no settlement
change.**

### Phase 4 — block tier
Implement per the §9.2 decision — flags-only, or flags plus an indication layer.
Residual policy as a client-elected parameter (§7.2). Soft tier-2 slot cap
(§7.4).

**Sequencing note, stated plainly:** tier 1 works immediately; tier 2 is the
actual product. Block execution is what we sell; ordinary clips are already well
served by prop AMMs and we do not beat them on that flow. Tier 2 only fires when
two naturals coincide, so on day one it fires never — the Luminex failure mode.

The early pitch is therefore *"rest indications here, and meanwhile your normal
flow executes fine,"* which is a harder sell than "we have liquidity." **Know
that going in rather than discovering it in the first ten sales conversations.**

### Design constraint carried across all phases

**Keep the block gate as an order attribute, not a separate order type.** This
preserves the option to add an indication layer in front of it later without
reworking the matcher, whichever way §9.2 resolves.

---

## 11. What this explicitly does not require

- **No new circuits, no VK bump, no ceremony.** All mechanisms are matcher, API
  and governance-config changes.
- **No new note type.** MM inventory notes and block notes are ordinary notes.
- **No settlement-path changes.** Nothing tier-specific or MM-specific belongs in
  `MatchResultPayload`. Counterparty identity in settlement would de-anonymise the
  maker side of every trade. **MM and tier state live in the enclave and the
  off-chain API, permanently.**
- **No change to custody or conservation guarantees.** Every participant is
  bounded by the same proofs.

---

## Cross-refs

- Matcher, auth model: `docs/tee-architecture.md`, `crates/darknyx-tee/src/matcher/`
- Trust boundaries, S-08, U-01, price-fairness decision: `CRYPTOGRAPHY.md` §2, §7.4, §7.5
- Batch settlement: `VALID_MATCH_BATCH`, `tee_forced_settle_batched`, `BatchValidityMarker`
- Lock semantics: `lock_note.rs`, `MAX_LOCK_TTL_SLOTS`, the 64-root shard window
- Continuation re-lock: `buyer_relock_order_id`, `note_lock_e`
- Note consolidation constraint: `vault::merge`, `VALID_MERGE(K)`
- Enclave persistence decision (conflicts with §9.3): `docs/fills-history-architecture.md`
- API surface to extend: `docs/tee-api-openapi.yaml`
- Attestation and the T-03 gateway gap: `docs/tee-attestation-flow.md`
