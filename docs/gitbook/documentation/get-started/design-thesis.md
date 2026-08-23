---
description: "The product thesis behind Darknyx, the guarantees each layer provides, and the tradeoffs a technical evaluator should understand."
---


# Why Darknyx

Public markets make price discovery transparent, but they also make intent a
resource other participants can exploit. A large resting order advertises side,
size, urgency, and often strategy. Moving the book off-chain hides that intent,
but usually replaces market transparency with trust in an operator that can see
orders, control custody, or both.

Darknyx separates those powers:

- **Solana holds custody and verifies value movement.** The vault accepts only
  proof-valid deposits, withdrawals, merges, and settlements.
- **An attested confidential VM matches private orders.** Its code identity and
  complete settlement-signer set are bound into an Intel TDX quote that clients
  can verify before disclosing intent. The programmatic transport model binds a
  boot-random TLS certificate to a separate nonce-challenged quote, so the
  gateway passes ciphertext rather than terminating the protected session.
  Launch qualification still requires connector-level refusal of a substituted
  replacement socket and supervised recovery after a genuine boot rotation.
- **The client keeps custody secrets.** Spending and viewing keys remain with the
  trader; the venue receives only the material needed to validate and match an
  order.

The product is a fully collateralized spot venue with private order flow,
uniform batch clearing, on-chain custody, and recoverable shielded balances.

The current product direction is programmatic access through the SDK and
non-custodial daemon. Browser trading is deferred and is not part of the launch
claim; its ordinary hosting boundary must be removed or cryptographically
crossed before that path can serve external users or real value.

## The trust decomposition

Darknyx does not collapse every guarantee into the phrase "trustless." Each layer
has a narrower, inspectable job.

| Property | Enforced by | What it means |
|---|---|---|
| Custody and solvency | Solana vault + SPL balances | The matcher cannot unilaterally transfer pooled assets. |
| Asset identity, arithmetic, conservation, fees, and output derivation | Groth16 settlement proof verified on-chain | A confirmed settlement cannot create value, switch mints, redirect outputs, or change the configured fee. |
| Order ownership and collateral validity | Client signatures + VALID_INPUT | A request is tied to a trading key and a real committed note. |
| Private matching, limit-price compliance, oracle policy, FIFO, and execution attributes | Attested matcher code | These properties depend on verifying the expected confidential-VM image. |
| Counterparty-selection fairness | Attested matcher + published per-market-maker execution-quality statistics | A compromised matcher could repeatedly prefer a colluding maker; launch requires selection share, price improvement, failure rate, and settlement latency to make persistent bias externally detectable. |
| Note ownership and recovery | Client seed + finalized chain | The venue never receives the spending key needed to claim a note. |

This division is deliberate. Zero knowledge makes settlement correctness
independent of the operator, while attestation makes the remaining matching
policy auditable without publishing the book.

## Why uniform batch clearing

Orders that cross in one matching interval trade at one clearing price. That
reduces the value of nanosecond ordering within the interval and gives both sides
the same execution price. The matcher respects each order's limit and an
oracle-based circuit-breaker policy, while the settlement proof constrains the
scaled price arithmetic and resulting notes.

Batching also amortizes one proof across several matches. It is therefore both a
market-structure choice and a practical way to make private settlement fit a
high-throughput chain.

## What privacy does and does not cover

Darknyx hides the live book, settled trade amounts and prices, shielded note owners,
and the link between commitments. It does not make the public edges of a token
transfer disappear:

- a deposit reveals its Solana signer, mint, and gross amount, but VALID_DEPOSIT
  hides the wallet-wide note owner and the note's inner value;
- a withdrawal reveals its destination, mint, and amount, but not which note
  commitment or prior trade supplied it;
- the confidential matcher sees order plaintext inside protected memory;
  privacy therefore depends on current TDX security and verification of the
  expected image;
- network timing and venue-level aggregate activity may still be observable.

The useful guarantee is not "nothing is visible." It is that public custody can
be audited without turning every balance, order, and fill into public market
intelligence.

## Product boundaries

Darknyx is intentionally narrow today:

- spot assets only; no leverage, funding, liquidations, or unsecured credit;
- fully collateralized orders backed by one shielded note;
- a confidential matching service can be halted or censored, so liveness is not
  decentralized even though custody enforcement is on-chain;
- fair matching and oracle/limit enforcement remain part of the attested code
  trust boundary rather than the settlement circuit;
- production launch remains gated on an external circuit audit, a public
  proving-key ceremony, governance rehearsal, and recovery drill.

Those boundaries make the claim legible: Darknyx is not trying to hide trust. It is
trying to minimize it, isolate it, and make the remaining assumptions
verifiable.

## Continue

- [Trade Flow](../how-it-works/trade-flow.md) follows one order end to end.
- [Privacy & Attestation](../how-it-works/privacy-and-attestation.md) explains how
  clients verify the confidential matcher.
- [Programmatic Access](./programmatic-access.md) maps the integration surface.
