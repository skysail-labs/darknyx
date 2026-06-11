---
sidebar_position: 1
title: How Nyx compares
description: Honest comparisons against on-chain order books, TEE rollups, ZK dark pools, and centralized venues — and the one combination only Nyx holds.
---

# How Nyx compares

:::info TL;DR
Nyx's claim is a specific *combination*: **order privacy** and **self-custody**
at the same time, with a trust chain short enough to verify yourself. Plenty of
venues offer one side of that. The comparisons below are about who offers both.
:::

## The one-line positioning

| Approach | Order privacy | Self-custody | Trust chain |
|---|---|---|---|
| Public on-chain CLOB | None | Yes | Just Solana — but fully exposed to MEV |
| Centralized exchange | From the public | No | The operator, entirely |
| Custodial dark pool | From the public | No | The operator, entirely |
| ZK-only dark pool | Strong | Yes | Heavy proving; usually thin liquidity |
| TEE rollup venue | Partial | Yes | Enclave **plus** a rollup sequencer + consensus |
| **Nyx** | **Strong** | **Yes** | **You → SDK → enclave attestation → Solana** |

## vs. public on-chain order books

A public CLOB is maximally trustless and maximally transparent — which is exactly
the problem. Every resting order is a permanent, indexed signal for sandwich
bots and adverse selection. Nyx keeps the self-custody of an on-chain book but
removes the leak: orders are never on-chain, and a uniform-price batch auction
erases the intra-block timing race those bots exploit.

## vs. TEE rollup designs

Some venues run matching in a TEE on top of an *ephemeral rollup* — a second
chain with its own sequencer, delegation, and undelegation choreography to
trust. Nyx runs matching in a single attested enclave that drives Solana
directly. The trust chain is shorter (no rollup consensus in the middle), and
the enclave can be verified independently by any client against Intel's
attestation and the image registered on-chain.

## vs. ZK-only dark pools

Pure-ZK dark pools get strong privacy without any hardware trust — an admirable
property — but pay for it in proving cost and, usually, liquidity: continuous
private matching against a shielded pool is heavy, and bootstrapping two-sided
flow is hard. Nyx uses ZK where it's cheap and decisive (custody, withdrawal,
settlement validity) and an attested enclave where matching needs to be fast and
stateful. The result is a venue that can run a real frequent-batch auction at
practical latency while keeping custody trustless.

## vs. other privacy chains

App-agnostic privacy chains (shielded pools, private state machines) are
powerful general substrates but aren't order books — building a competitive
matching venue on top is its own large project. Nyx is purpose-built for hidden
order flow on Solana, with the matching engine, oracle banding, and
continuation mechanics that a trading venue actually needs.

## vs. centralized venues

A CEX gives you deep liquidity and speed — and complete custody and information
risk. The operator sees everything and holds everything. Nyx targets the same
*experience* for hidden order flow (place an order, get filled, don't leak)
without the custody: the venue can never withdraw your funds, and can't read
your orders to begin with.

## What makes it defensible

- **Privacy is the architecture, not a setting.** There is no mode where order
  intent reaches the chain — so there's nothing to misconfigure or leak.
- **The trust floor is the chain.** Compromise everything above the vault and
  the worst case is that trading stops, not that funds move.
- **It composes with Solana, not around it.** Custody, settlement, and proof of
  reserves are all native on-chain state anyone can audit.

The honest caveats are the same ones any serious version of this must clear — a
real trusted-setup ceremony and fully on-chain attestation — and they're tracked
on the [roadmap](./roadmap), not papered over.
</content>
