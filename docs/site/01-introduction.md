---
sidebar_position: 1
title: Introduction
description: Nyx is a privacy-preserving CLOB darkpool on Solana — hidden orders matched inside an attested TEE, settled trustlessly with zero-knowledge proofs.
---

# Introduction

:::info TL;DR
Nyx is a privacy-preserving central-limit-order-book darkpool on Solana.
Hidden orders are matched inside an **attested Intel TDX Confidential VM**;
settlement lands **trustlessly on Solana**, with zero-knowledge proofs binding
every transfer to a verified note commitment. Solana sees custody and proofs —
never your order. The enclave sees your order — but can never move your funds.
:::

## The problem

Public order books leak. Every resting limit order is a free signal — to a
sandwich bot, to a market maker fading your flow, to a counterparty content to
wait you out. On-chain order books make this *worse* than a centralized venue,
because the leak is permanent, public, and indexed forever.

The usual escape is to take the order off-chain: an RFQ desk, an off-chain
matching engine, a custodial dark pool. That trades information risk for
**custody risk**. The operator sees every order, every fill, every position —
and can front-run, leak, get subpoenaed, or get hacked. The Mt. Gox shape never
goes away.

**Nyx is the third option.** Orders enter an enclave whose code is *attested*
and whose keys are cryptographically bound to one specific compiled image. The
operator cannot read order intent. The enclave cannot move funds without a
zero-knowledge proof verified on Solana. Matching happens in private; settlement
happens trustlessly.

## What "private" means here

Nyx enforces three distinct privacy properties, each by a separate mechanism:

| Property | What's hidden | Enforced by |
|---|---|---|
| **Order privacy** | Side, size, limit price | Order intent lives only inside the attested TEE — never in any Solana tx, log, or account. |
| **Trader privacy** | The link from a trade to your wallet | You authenticate with a fresh trading key, not your wallet. The wallet ↔ trade link only ever exists inside your own withdraw proof. |
| **Position privacy** | What you hold | Assets are UTXO-style **notes** stored on-chain as Poseidon hashes. Owner, value, and token are sealed inside the hash until *you* spend it with a proof. |

No single component — not Solana, not the operator, not an observer — sees
enough to deanonymize your trading.

## How it fits together

Nyx is three layers that compose into one trust chain:

```text
┌──────────────────────────────────────────────────────────────┐
│  CUSTODY — Solana program (the "vault")                       │
│  Holds funds. Owns the Merkle tree of note commitments.       │
│  The only layer that can move tokens — and only against a     │
│  zero-knowledge proof.                                        │
└──────────────────────────────────────────────────────────────┘
                         ▲  attested, signed settle txs
┌──────────────────────────────────────────────────────────────┐
│  MATCHING — Intel TDX Confidential VM                         │
│  Runs the hidden order book, the clearing-price auction, the  │
│  in-enclave prover, and the settle scheduler. Sees orders;    │
│  cannot exit funds. Its image is pinned on-chain.             │
└──────────────────────────────────────────────────────────────┘
                         ▲  signed order intents
┌──────────────────────────────────────────────────────────────┐
│  CLIENT — TypeScript SDK                                      │
│  Builds your proofs locally, verifies the enclave's           │
│  attestation before trusting it, and keeps your spending key  │
│  on your device — never on the wire.                          │
└──────────────────────────────────────────────────────────────┘
```

The split *is* the privacy story:

- **Solana sees** note commitments (hashes), Merkle roots, and settlement
  transactions carrying trading keys — never wallet keys, never order intent.
- **The enclave sees** orders signed by trading keys and the match it computes
  — and nothing it can act on to steal.
- **You see** your own wallet ↔ trading-key link, your own notes, your own
  secrets — which never leave your device.

## Why matching runs in a TEE

Matching is stateful and latency-sensitive. Run it on-chain (or on a rollup, or
a sidechain) and every order leaks to a sequencer or validator. Run it inside an
**attested enclave** and order intent is invisible to everyone except the
enclave's exact compiled image — and that image is fixed by a measurement
(`compose_hash`) registered on-chain. Only that image can produce settlements
the vault will accept.

The result is a short, verifiable trust chain — *you → SDK → TEE attestation →
Solana* — with no extra rollup, sequencer, or custodian in the middle. Clients
verify the enclave's Intel-signed attestation before sending a single order.

:::note Worst case is bounded
Even a fully compromised enclave **cannot withdraw your funds** — every exit
needs a proof only you can generate. The most it can do is refuse to match
(censorship) or reorder within a single batch tick — both blunted by the
uniform-clearing-price, frequent-batch-auction design. See
[Trust model](./trust-model).
:::

## Who it's for

| You are… | Why Nyx |
|---|---|
| **An active trader** | Large limit orders that don't telegraph intent. The clearing-price auction sidesteps sandwich slippage; the hidden book ends the "wait it out" game. |
| **A market maker** | A two-sided venue where quotes don't leak to flow before they fill. Inventory rebalancing stays private. |
| **An institution / desk** | Trustless custody (the venue can never withdraw your funds) plus off-chain matching speed — and a verifiable attestation + governance story a black-box pool can't offer. |
| **An OTC block** | One-shot trades with no market impact; the settle batches with others, so even the on-chain tx doesn't single you out. |

## Where to go next

- New to the design? → [Architecture overview](./architecture-overview)
- Evaluating the trust story? → [Trust model](./trust-model)
- Want the on-chain mechanics? → [Settlement pipeline](./settlement-pipeline)
- Building on it? → [Integration](./integration) and the
  [API reference](./api-reference)
</content>
