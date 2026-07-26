---
description: "Darknyx is a privacy-preserving spot darkpool on Solana, with hidden orders matched inside an attested confidential VM and value movement proven on-chain."
---


# Overview

{% hint style="info" %}
**TL;DR**

Darknyx is a **privacy-preserving spot darkpool on Solana**. Hidden orders match
inside an attested Intel TDX Confidential VM (a "CVM"); custody and proven value
movement remain on-chain. Solana sees deposits, withdrawals, commitments, and
proofs, but never the order book or a settled trade's plaintext price and size.
{% endhint %}

## What Darknyx is

Darknyx is a dark pool: an order book where resting orders are not public. Side,
size, and limit price never appear in a Solana transaction, a log, or an
account. They live only inside a hardware-isolated enclave whose exact compiled
code is measured and remotely verifiable.

Unlike an off-chain matching desk, Darknyx does not give one ordinary operator both
custody and readable order flow:

- **Custody is on-chain.** Funds sit in a Solana program. Withdrawals, merges,
  and matched transfers must satisfy the corresponding proof and replay guards.
- **Matching is in an attested enclave.** The operator runs the machine but
  cannot read enclave memory, and the enclave's signing keys are bound to one
  specific measured image. Swap the code and the keys no longer derive, and
  clients detect it at attestation time.

The result is a venue where matching policy is enforced by code you can attest,
while asset identity, arithmetic, conservation, fees, and output ownership are
enforced by a proof the chain verifies. See [Why Darknyx](./design-thesis.md) for the
full trust decomposition.

## What "private" means here

Darknyx enforces three distinct privacy properties, each by a separate mechanism.

| Property | What is hidden | How |
|---|---|---|
| **Order privacy** | Side, size, limit price | Order intent exists only inside the attested TEE, never in any Solana tx, log, or account. |
| **Trader privacy** | The link from an order or trade to your wallet | You sign orders with a **trading key**, not your wallet. Deposits and withdrawals retain their unavoidable public transfer boundaries. |
| **Position privacy** | What you hold | Balances are UTXO-style **notes** stored on-chain as Poseidon hashes. Owner, value, and token are sealed inside the hash until you spend it with a proof. |

Deposits reveal the funding signer, mint, and gross amount; withdrawals reveal
the destination, mint, and amount. VALID_DEPOSIT prevents the funding transaction
from publishing the wallet-wide note owner, so that public boundary does not by
itself label the rest of the wallet's notes.

## The three layers

Darknyx is three layers that compose into one trust chain.

```text
┌──────────────────────────────────────────────────────────────┐
│  CUSTODY — the Solana "vault" program                         │
│  Holds funds. Owns the Merkle tree of note commitments,       │
│  replay guards, and the Groth16 verifier. The only layer     │
│  that can move pooled tokens, subject to protocol rules.      │
└──────────────────────────────────────────────────────────────┘
                         ▲  attested, signed settle txs + ZK proofs
┌──────────────────────────────────────────────────────────────┐
│  MATCHING — the in-enclave engine (the "CVM")                 │
│  Takes hidden orders, runs a uniform-clearing-price batch     │
│  auction, and drives the settlement transactions directly.    │
│  Never sees your spending key; cannot move funds itself.      │
└──────────────────────────────────────────────────────────────┘
                         ▲  signed orders + ZK input proofs over HTTPS/WS
┌──────────────────────────────────────────────────────────────┐
│  CLIENT — your wallet + the SDK                               │
│  Builds notes, generates the input proofs, signs orders with  │
│  a trading key, and verifies the enclave's attestation.       │
└──────────────────────────────────────────────────────────────┘
```

- **Custody (Solana).** A single program owns custody: the incremental Merkle
  tree of note commitments, the nullifier and consumed-note sets that prevent
  double-spends, the Groth16 verifier, and the atomic batched-settlement path.
- **Matching (the CVM).** The engine accepts orders over an authenticated
  HTTPS/WebSocket surface, enforces limits and an oracle circuit-breaker policy,
  routes each signed symbol to an isolated market book, clears crossing orders
  at one price per market batch, proves the resulting value movement, and
  submits settlement to Solana. Several pairs can share one endpoint and one
  attestation session, but their books and proof batches never mix. Your order
  never becomes a Solana transaction; the enclave settles the *result*.
- **Client (the SDK).** Your software builds the collateral note, generates the
  zero-knowledge input proof, signs the order with your trading key, and (if you
  want the full guarantee) verifies the running enclave against an expected
  measurement before trusting it.

## Spot, not perps

Darknyx is a **spot** venue. There are no positions, no leverage, no funding, and no
liquidations. Every order is fully collateralized up front by a note you already
deposited, and a trade is an atomic swap of value between two notes. If you have
traded a perps dark pool before, the concepts that carry over are order types,
time-in-force, and execution attributes; the concepts that do not (positions,
margin, funding) simply are not part of the model.

## Who it is for

- **Traders** who do not want their resting orders read by the venue or the
  chain.
- **Market makers and systematic desks** that want programmatic order
  management (REST and WebSocket) with order intent kept private.
- **Integrators** building privacy-preserving trading flows who need custody to
  stay on-chain and verifiable.

## Next steps

- [Why Darknyx](./design-thesis.md): the product thesis, exact trust boundary, and
  tradeoffs.
- [Programmatic Access](./programmatic-access.md): the API surface, the auth
  model, and a quick start.
- [Base URLs](../api/base-urls.md): where the endpoints live and the common
  response conventions.
- [Trade Flow](../how-it-works/trade-flow.md): the end-to-end lifecycle of an
  order, from submission to on-chain settlement.
- [Multi-Market Venue](../how-it-works/multi-market.md): how several isolated
  books share one attested endpoint.
