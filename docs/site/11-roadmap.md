---
sidebar_position: 2
title: Roadmap
description: Where Nyx is today and where it's going — validated end-to-end on devnet, with a clear path to mainnet through the trusted-setup ceremony and on-chain attestation.
---

# Roadmap

:::info TL;DR
The full protocol — custody, in-enclave matching, batched tree-sharded
settlement, and the fills stream — is built and validated **end-to-end on
devnet**: a deployed enclave matches and settles real crossing trades on Solana.
The path to mainnet is about hardening the trust story (a real trusted-setup
ceremony, on-chain attestation) and scaling the prover, not redesigning the
system.
:::

## Where it is

Nyx works today on Solana devnet, end to end:

- The **vault** runs on devnet with the full proof-gated instruction set —
  deposit, merge, lock, verify, settle, close, withdraw.
- The **matcher** runs the uniform-clearing-price batch auction against a
  verified oracle, with self-trade prevention and round-free partial-fill
  continuations.
- The **enclave** boots inside a real TDX Confidential VM, derives its keys from
  the sealed root, serves the authenticated API and the live fills stream, and
  drives the settle pipeline on Solana.
- Settlement is **batched, tree-sharded, and concurrent**, so a batch's settles
  co-include in a single block.
- The **SDK** is parity-tested against the host-side cryptography so the three
  languages agree byte-for-byte on every primitive.

The bottleneck is now where you'd want it: proving, which scales with hardware,
rather than the on-chain settle path.

## What's next

| Direction | What it adds |
|---|---|
| **Trusted-setup ceremony** | Replace the development Groth16 contribution with a real multi-party ceremony — independent contributors, publicly verifiable transcripts — required before mainnet value. |
| **On-chain attestation** | Bind the enclave-key rotation to an on-chain verification of the TDX quote against a governance-approved measurement set, so the chain itself enforces "only an attested enclave can settle." |
| **Prover scaling** | With on-chain settlement no longer the limit, push end-to-end throughput by scaling proving — larger enclaves, accelerated proving, or multiple provers. |
| **Mainnet deployment** | Custody, governance, and operational hardening for production funds. |
| **Deeper market structure** | More instruments and order types on top of the batch-auction core. |

## What Nyx is deliberately not

A few things are out of scope by design, so the trust story stays simple:

- **Not a custodian.** The protocol can never move your funds without your
  proof; there's no "trust us to let you withdraw" path to remove later.
- **Not a rollup or sidechain.** Matching is a single attested enclave, not a
  second chain with its own sequencer and consensus to trust.
- **Not a perpetuals or lending venue.** Nyx is a spot darkpool; leverage and
  borrowing are different risk surfaces that belong elsewhere.
- **Not a public order book with a privacy toggle.** Privacy is the architecture,
  not a feature flag — there is no mode where order intent lands on-chain.

## Following along

The protocol is developed in the open. The conceptual docs here track the
*design*; the canonical engineering reference and the running devnet deployment
are the source of truth for exactly what's live at any moment.
</content>
