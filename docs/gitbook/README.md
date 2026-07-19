---
description: "Darknyx — a privacy-preserving darkpool on Solana. API, SDK, and protocol documentation."
---

# Introduction

**Darknyx** is a privacy-preserving CLOB-style darkpool on Solana. Order intent
is matched and settled inside an Intel TDX confidential VM; per-trade amounts and
the execution price stay hidden on-chain, and balances are encrypted UTXO notes
committed to an on-chain Merkle tree.

This portal is the reference documentation for trading the venue: the API
surface, the TypeScript SDK, the account and settlement model, and the protocol
internals.

## Start here

* [Overview](get-started/overview.md) — what Darknyx is and how the venue fits together.
* [Programmatic Access](get-started/programmatic-access.md) — the REST + WebSocket API at a glance.
* [TypeScript Client](sdk/typescript-client.md) — authenticate, build orders, stream fills.

## Explore

* **How It Works** — the trade lifecycle, the confidential VM, privacy + attestation, settlement.
* **Trading Concepts** — order types, time in force, uniform clearing price, self-trade prevention.
* **Account** — the note model, Merkle proofs, deposits, withdrawals, transparency.
* **Orders / WebSocket / API** — the full endpoint and channel reference.
* **Reference** — error codes, system status, and a glossary.
