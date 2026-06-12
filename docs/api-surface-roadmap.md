# Public API surface — roadmap & competitive analysis

> Scope: the **public** endpoints the CVM serves traders — the HTTP/WS surface in
> `crates/nyx-tee/src/api/` and the order model in `crates/darkpool-matcher/`. This
> doc compares us against a representative competitor (**GoDark**, `godarkdex_docs_md/`),
> records what to add (and what *not* to), and is the reference the implementation
> phases execute against. See also `docs/tee-api-openapi.yaml` (the wire contract) and
> `docs/tee-architecture.md` §10–§11 (auth + transport).

## 0. The framing that decides everything

GoDark and Nyx are both "Solana dark pools," but they are **different products**:

| | **GoDark** | **Nyx** |
|---|---|---|
| Instrument | **Perpetual futures** (positions, leverage 5–10×, funding, liquidation) | **Spot** |
| Settlement | Encrypted commitments + margin accounting | **ZK notes (UTXO)** — every order is collateralized by *one deposited note*, locked with a `VALID_INPUT` proof |
| Matching | **Continuous CLOB**, price–time priority, MPC-held book | **Frequent batch auction**, *uniform clearing price* anchored to a Pyth oracle TWAP |
| Transport trust | Separate gateway → MPC committee (needs app-layer crypto between them) | **Single attested enclave** — the endpoint the client talks to *is* the matcher (RA-TLS terminates inside the TEE) |

Two facts flow from this and gate the whole roadmap:

1. **Perp primitives (positions / margin / funding / TP-SL / liquidation) are N/A** — not
   gaps, a different product.
2. **Note-collateral is the real constraint.** In GoDark a resting quote is just memory in
   the MPC book — an MM reprices for free. In Nyx, *every resting order pins a locked note +
   a 256-byte proof.* This single fact decides how far we can chase market-maker features.

## 1. HTTP endpoints

| Capability | GoDark | Nyx (today) | Action |
|---|---|---|---|
| Auth (bearer) | `POST /auth/token`, `/revoke` | ✅ | — |
| Place / Cancel / Get order | ✅ | ✅ `POST /orders`, `DELETE`/`GET /orders/:id` | — |
| **Modify order** | `op: order.modify` | ❌ | **add — Tier 2 (A5)** |
| Mass-quote (batch cancel-replace) | `POST /orders/mass-quote` (Prime/Apex) | ❌ | **shelved** (§5) |
| Settlement status | ✅ | ✅ `/settlement/status/:batch` | — |
| Account / Instruments | ✅ | ✅ | — |
| Transparency / proof-of-reserves | (stats) | ✅ `/transparency` (we're ahead) | — |
| **System/degraded status** | `/system-status` | ❌ | **add — Tier 1 (A4)** |
| **Server time** | "Server Time" | ❌ | **add — Tier 1 (A2, `/time`)** |
| Positions / tiers / referrals | ✅ (perp) | N/A | not a gap |

## 2. WebSocket

| Channel | GoDark | Nyx (today) | Action |
|---|---|---|---|
| **Order lifecycle** | `/ws/orders` | ❌ — we stream **fills only** | **add — Tier 1 (A1), the headline win** |
| **Order submission** | `/ws/trading` (`place/cancel/modify`) | ❌ — HTTP POST only | **add — Tier 2 (Phase B)** |
| User events / positions | `/ws/user` | ❌ (positions N/A) | later |
| External market data | `/ws/gomarket` | ❌ (oracle is internal) | not planned |
| Fills | (part of orders) | ✅ `/ws/fills` (per-account, Vuln-4 integrity check) | — |

**The biggest gap:** the matcher *already computes* `OrderUpdate`s (FullyFilled /
PartiallyFilled / Cancelled / Expired, `darkpool-matcher/src/book.rs`) and **drops them**
after mutating the book. Clients today only see fills + poll `GET /orders/:id`. Streaming
those updates reuses the existing per-account `fills_router` fan-out almost verbatim.

## 3. Order types & execution attributes

| Feature | GoDark | Nyx | Action |
|---|---|---|---|
| Limit / IOC / FOK | ✅ | ✅ `OrderType::{Limit, Ioc, Fok}` | — |
| GTC | ✅ | ✅ (Limit rests) | — |
| GTT / GTD (time expiry) | ✅ | ✅ via `expiry_slot` | **SDK sugar — Tier 1 (A2)** |
| Min-fill size | ✅ | ✅ `min_fill_qty` | — |
| **All-or-None (resting)** | ✅ | ⚠️ implicit: `min_fill_qty == amount` (already honored, `algorithm.rs:303-310`) | **SDK helper + doc — Tier 1 (A2)** |
| **Market** | ✅ | ⚠️ ≈ IOC at a `price_limit` cap | **SDK sugar — Tier 1 (A2)** |
| **Self-trade prevention** | 3 modes | ❌ **stub** (`matcher/selftrade.rs` TODO) — self-pairs can wash-trade | **implement baseline — Tier 1 (A3)** |
| Peg-to-mid/bid/ask | ✅ | ❌ | **shelved** (§5) |
| Post-only | ✅ | ❌ | **shelved** (§5 — semantic mismatch) |
| Reduce-only / TP-SL | ✅ (perp) | N/A | not a gap |

## 4. The two semantic mismatches to internalize

1. **Batch auction ≠ continuous CLOB.** We clear each tick at a *single uniform
   oracle-anchored price*; there is no maker/taker ordering *within* a tick. So **post-only**
   ("don't take") and **STP taker/maker/both modes** don't carry their CLOB meaning — the
   honest analog is a single STP behavior ("two orders from one `trading_key` never match
   each other") and, if ever wanted, a "rest-only this tick" flag. Don't copy CLOB semantics
   that don't hold.
2. **Resting liquidity costs collateral.** Their MMs reprice for free; ours pin a note per
   quote. Everything MM-facing (mass-quote, dense ladders, fast modify) hits this. Without a
   *multi-quote-per-note* primitive, Nyx suits taker flow + periodic-auction / RFQ-style
   making better than dense continuous quoting.

## 5. Explicitly shelved (with rationale)

- **Mass-quote (batch cancel-replace)** — *the* MM feature, and the one our model fights
  hardest: each quote level needs its own locked note + proof. Making it viable needs a new
  **"one note collateralizing a *set* of quotes"** primitive (vault + circuit work), not an
  endpoint. Revisit only if dense MM quoting becomes a product goal — design-first.
- **Peg-to-mid/bid/ask** — low value *and* off-model: a dark pool has no public bid/ask to
  peg to, and peg needs continuous repricing while our orders are signed+collateralized at a
  fixed price. Our **uniform clearing is already oracle-anchored**, so the "fair mid" peg
  chases is native to every batch — we get the benefit without the order type.
- **Session-layer WS encryption** (AES-GCM `session.setup`/rekey) — GoDark needs it because
  their gateway sits *outside* the MPC trust zone. Our RA-TLS terminates *inside* the attested
  enclave, so TLS-to-enclave already gives confidentiality to the trust boundary (which is why
  our OpenAPI *removed* `session.setup`). A simpler, arguably stronger posture — not a gap.
- **Perp primitives** (positions / leverage / funding / TP-SL / liquidation) — a different
  product.

## 6. Roadmap

### Tier 1 — high value, feasible, aligned
- **A1 — `/ws/orders` order-lifecycle channel.** Stream the `OrderUpdate`s the matcher already
  emits; reuse the `fills_router` per-account fan-out.
- **A2 — market / AON / GTT sugar** (SDK builders) + **`GET /time`** (server slot + unix, for
  GTT conversion).
- **A3 — baseline self-trade prevention** (skip self-crossing pairs in `generate_matches`).
- **A4 — `/system/status`** (matcher / settle / oracle-freshness / slot / `degraded`).

### Tier 2 — valuable, more work
- **A5 — `order.modify`** as atomic cancel+replace (`PUT /orders/:id`): compose the existing
  `CancelCanonical` + `OrderCanonical` (no new signed type); swap under one matcher lock. Win =
  atomicity (no cancel/replace gap) + one round-trip. The new order carries its own
  note + `VALID_INPUT` proof (may reuse the same note+proof while the root is in the 64-root
  window).
- **Phase B (staged fast-follow) — `/ws/trading` submission + cancel-on-disconnect.** Submit
  `order.place/cancel/modify` over the socket; track `session → {order_id}` and cancel the
  session's resting orders on disconnect (authenticated server action). Account-level default +
  per-session opt-in (like GoDark's `cancel_on_disconnect`). Done after A1's plumbing is proven.

## 7. What we already do better (differentiators)

- **Trustless per-order collateral** — the `VALID_INPUT` proof means collateral can't be
  phantom-locked.
- **Anchor-pool continuations** — partial fills re-lock the residual without a client
  round-trip (no analog on GoDark's surface).
- **Note-merge** for collateral consolidation.
- **Single attested hop** (RA-TLS to the enclave) vs gateway-then-committee.
- **`/transparency`** proof-of-reserves (per-mint outstanding vs vault balance) — public and
  unauthenticated.
