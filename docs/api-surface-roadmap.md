# Public API surface — roadmap & competitive analysis

> Scope: the **public** endpoints the CVM serves traders — the HTTP/WS surface in
> `crates/darknyx-tee/src/api/` and the order model in `crates/darkpool-matcher/`. This
> doc compares us against a representative competitor (**GoDark**, `godarkdex_docs_md/`),
> records what to add (and what *not* to), and is the reference the implementation
> phases execute against. See also `docs/tee-api-openapi.yaml` (the wire contract) and
> `docs/tee-architecture.md` §10–§11 (auth + transport).

## 0. The framing that decides everything

GoDark and Darknyx are both "Solana dark pools," but they are **different products**:

| | **GoDark** | **Darknyx** |
|---|---|---|
| Instrument | **Perpetual futures** (positions, leverage 5–10×, funding, liquidation) | **Spot** |
| Settlement | Encrypted commitments + margin accounting | **ZK notes (UTXO)** — every order is collateralized by *one deposited note*, locked with a `VALID_INPUT` proof |
| Matching | **Continuous CLOB**, price–time priority, MPC-held book | **Frequent batch auction**, *uniform clearing price* anchored to a Pyth oracle TWAP |
| Transport trust | Separate gateway → MPC committee (needs app-layer crypto between them) | **Two attested hops, no untrusted one** — TLS terminates at the dstack gateway (itself a TDX CVM), which reaches the matcher over a mutually attested WireGuard tunnel. In-enclave RA-TLS is NOT shipped; earlier revisions of this table claimed it was. See T-03 in `audit-2026-07-25-tee-infra-daemon-remediation-tracker.md`. |

Two facts flow from this and gate the whole roadmap:

1. **Perp primitives (positions / margin / funding / TP-SL / liquidation) are N/A** — not
   gaps, a different product.
2. **Note-collateral is the real constraint.** In GoDark a resting quote is just memory in
   the MPC book — an MM reprices for free. In Darknyx, *every resting order pins a locked note +
   a 256-byte proof.* This single fact decides how far we can chase market-maker features.

## 1. HTTP endpoints

| Capability | GoDark | Darknyx (today) | Action |
|---|---|---|---|
| Auth (bearer) | `POST /auth/token`, `/revoke` | ✅ | — |
| Place / Cancel / Get order | ✅ | ✅ `POST /orders`, `DELETE`/`GET /orders/:id` | — |
| **Modify order** | `op: order.modify` | ✅ REST + `/v1/stream` | **✅ done (Tier 2, A5)** |
| Mass-quote (batch cancel-replace) | `POST /orders/mass-quote` (Prime/Apex) | ❌ | **shelved** (§5) |
| Settlement status | ✅ | ✅ `/settlement/status/:batch` | — |
| Account / Instruments | ✅ | ✅ | — |
| Transparency / proof-of-reserves | (stats) | ✅ `/transparency` (we're ahead) | — |
| **System/degraded status** | `/system-status` | ✅ `/system/status` plus per-instrument `trading_enabled` | **✅ done (Tier 1, A4; T-17 market isolation)** |
| **Server time** | "Server Time" | ✅ `/time` | **✅ done (Tier 1, A2)** |
| Positions / tiers / referrals | ✅ (perp) | N/A | not a gap |

## 2. WebSocket

| Channel | GoDark | Darknyx (today) | Action |
|---|---|---|---|
| **Order lifecycle** | `/ws/orders` | ✅ `/v1/stream` `orders` channel | **✅ done (Tier 1, A1)** |
| **Order submission** | `/ws/trading` (`place/cancel/modify`) | ✅ `/v1/stream` framed ops + cancel-on-disconnect | **✅ done (Phase B)** |
| User events / positions | `/ws/user` | ❌ (positions N/A) | later |
| External market data | `/ws/gomarket` | ❌ (oracle is internal) | not planned |
| Fills | (part of orders) | ✅ `/v1/stream` `fills` channel (per-account, Vuln-4 integrity check) | — |

The matcher-produced `OrderUpdate`s (FullyFilled / PartiallyFilled / Cancelled /
Expired, `darkpool-matcher/src/book.rs`) are now delivered on the authenticated
per-account `/v1/stream` `orders` channel. Clients no longer need to infer every
lifecycle transition by polling `GET /orders/:id`.

## 3. Order types & execution attributes

| Feature | GoDark | Darknyx | Action |
|---|---|---|---|
| Limit / IOC / FOK | ✅ | ✅ `OrderType::{Limit, Ioc, Fok}` | — |
| GTC | ✅ | ✅ (Limit rests) | — |
| GTT / GTD (time expiry) | ✅ | ✅ via `expiry_slot` + SDK builder | **✅ done (Tier 1, A2)** |
| Min-fill size | ✅ | ✅ `min_fill_qty` | — |
| **All-or-None (resting)** | ✅ | ✅ `min_fill_qty == amount` + SDK helper | **✅ done (Tier 1, A2)** |
| **Market** | ✅ | ✅ IOC with a required price cap | **✅ done (Tier 1, A2)** |
| **Self-trade prevention** | 3 modes | ✅ owner-commitment baseline appropriate to a batch auction | **✅ done (Tier 1, A3)** |
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
   *multi-quote-per-note* primitive, Darknyx suits taker flow + periodic-auction / RFQ-style
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
  their gateway sits *outside* the MPC trust zone — ordinary software on an ordinary host. Ours
  terminates at a gateway that is itself an attested TDX CVM and tunnels to the enclave over
  mutual attestation, so no unprotected hop sees plaintext (which is why our OpenAPI *removed*
  `session.setup`). Still a stronger posture, but state it accurately: the client currently pins
  the engine's measurement and not the gateway's, and the TLS session is not bound to the quote.
  Closing that is T-03, gated ahead of external users.
- **Perp primitives** (positions / leverage / funding / TP-SL / liquidation) — a different
  product.

## 6. Roadmap

### Tier 1 — high value, feasible, aligned — ✅ DONE
- **A1 — `orders` order-lifecycle channel.** ✅ Streams the `OrderUpdate`s the matcher
  emits; reuses the `fills_router` per-account fan-out (`api/order_router.rs`).
- **A2 — market / AON / GTT sugar** (SDK builders, `packages/sdk/src/orders/builders.ts`) +
  **`GET /time`** (server slot + unix, for GTT conversion). ✅
- **A3 — baseline self-trade prevention** (skip self-crossing pairs in `generate_matches`). ✅
- **A4 — `/system/status`** (matcher / settle / oracle-presence / slot / `degraded`). ✅

### Tier 2 — valuable, more work — ✅ DONE
- **A5 — `order.modify`** as atomic cancel+replace (`PUT /orders/:id`): ✅ composes the existing
  `CancelCanonical` + `OrderCanonical` (no new signed type); swaps under one matcher lock with
  both preconditions checked first. Win = atomicity (no cancel/replace gap) + one round-trip.
  The new order carries its own note + `VALID_INPUT` proof (may reuse the same note+proof while
  the root is in the 64-root window).
- **Phase B — `/v1/stream` submission + cancel-on-disconnect.** ✅ A bidirectional socket
  streams framed `order.place/cancel/modify`, each dispatched to the SAME intake the REST
  handlers call (`orders::{place,cancel,modify}_core` — no second verification path). With
  `login { cancel_on_disconnect: true }`, the handler tracks `session → {order_id}` and tears down the
  session's still-resting orders on close via a server-initiated cancel (no client sig — the
  order was placed on this authed session; a cancel only un-rests, never settles). The
  per-order trading-key signature is still required on every place/cancel/modify frame.
  - ✅ An account-level cancel-on-disconnect default is available through
    `PUT /account/settings`; an explicit login value overrides it per session.
  - ✅ *Done:* the **SDK order-submission layer** (`buildOrder` + REST `order-client` + the
    multiplexed `TradingClient` + the VALID_INPUT prover/witness fetch). The SDK
    now builds, signs, and submits orders end to end; `buildOrder`'s canonical digest is byte-parity
    guarded against the Rust matcher (`build-order-parity.test.ts`). The `snarkjs` prover is a
    dynamically-imported Node adapter (pluggable), so it isn't forced on browser consumers.

> **Status:** Phase A + Phase B are consolidated on the sole `/v1/stream`
> session; the dedicated legacy sockets are deleted.

## 7. What we already do better (differentiators)

- **Trustless per-order collateral** — the `VALID_INPUT` proof means collateral can't be
  phantom-locked.
- **Input-derived continuations** — partial fills deterministically derive and
  re-lock the residual from the consumed input without a client round-trip.
- **Note-merge** for collateral consolidation.
- **No unprotected hop** (attested gateway → mutually attested tunnel → enclave) vs gateway-then-committee.
- **`/transparency`** proof-of-reserves (per-mint outstanding vs vault balance) — public and
  unauthenticated.
