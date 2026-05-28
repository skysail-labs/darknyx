# Introduction

> Nyx is a privacy-preserving central-limit-order-book (CLOB) darkpool
> on Solana. Hidden orders meet inside an attested Intel TDX
> Confidential VM; settlement happens trustlessly on Solana with
> zero-knowledge proofs binding every transfer to a verified note
> commitment. The on-chain footprint is custody and proofs;
> matching is invisible to mempools, sequencers, and validators.

---

## The problem Nyx solves

Public order books bleed information. Every limit order resting on a
DEX is a free signal to a sandwich bot, a market maker rebalancing
inventory against you, or a counterparty looking to wait you out.
The literature calls it "informational alpha leakage"; the daily
PnL drain on Solana DEXes is measurable in tens of millions of
dollars per year. On-chain order books make this worse, not better,
than centralized venues — because the leak is permanent, public, and
indexed.

The traditional response is to take the order off-chain entirely:
quote-driven RFQ venues, off-chain matching engines, or dark pools
operated by a custodian. These solutions cost custody risk. The
operator can see every order, every fill, and every position. They
can front-run, they can leak, they can be subpoenaed, they can be
hacked. The Mt. Gox shape never goes away.

**Nyx is the third option.** Orders enter an enclave whose code is
attested and whose key material is cryptographically gated to a
specific compiled image. The operator cannot read order intent
inside the enclave; the enclave cannot exit funds without a
zero-knowledge proof verified on Solana. The matching engine sees
hidden orders, computes a uniform clearing price, and emits a
batched validity proof that lets settlement land atomically on-chain.

---

## What "privacy-preserving" actually means in Nyx

Three distinct privacy properties, each enforced by a separate
mechanism:

### 1. Order privacy

Order side (buy/sell), size, and limit price are visible only to the
TEE. They are not in any Solana transaction, log, or account that an
external observer can read. The TEE cannot reveal them — the
hardware attestation prevents code substitution, and the on-chain
verifier rejects any settlement that doesn't come from the attested
binary. (See [trust-model](./trust-model.md) for the full chain.)

### 2. Trader privacy

A user's Solana wallet pubkey is never a parameter in any Nyx API
request. Users authenticate to the TEE with a separate trading-key
keypair (Ed25519, freshly generated client-side). The on-chain
settlement instructions carry only the trading key; the link from
trading key to wallet exists only in the user's own withdraw-time
VALID_SPEND proof, where the spending key never leaves their device.

### 3. Position privacy

Notes (the UTXO-style commitments Nyx uses for assets) are stored
on-chain only as Poseidon hashes. The note's owner, value, and token
are bound inside the hash; nothing about them is observable on-chain
until the user themselves spends the note via a zero-knowledge proof.

---

## Who Nyx is for

| Segment | Why they use Nyx |
|---|---|
| **Active traders** | Large limit orders that don't telegraph intent. The clearing-price auction sidesteps slippage from sandwich bots; the hidden order book stops the "wait it out" game. |
| **Market makers** | A two-sided venue where quotes don't leak to retail flow before they fill. Quote turnover and inventory rebalancing remain private — the venue can't see them, competitors can't infer them. |
| **Institutions** | Trustless custody (the TEE can never withdraw funds without a user-generated ZK proof) combined with off-chain matching speed. The auditability properties (TDX attestation, multisig governance, deterministic image) satisfy compliance teams who would not approve a black-box dark pool. |
| **Treasury / OTC desks** | One-shot block trades with no market impact. The order is visible only to the TEE; the resulting on-chain settle batches with other trades, so even the settle tx doesn't single out the block. |

---

## Headline architecture

Nyx is three layers that compose:

```text
┌────────────────────────────────────────────────────────────────┐
│  CUSTODY LAYER  — Solana program (vault)                       │
│                                                                │
│  Holds funds. Owns the Merkle tree of UTXO note commitments.   │
│  Verifies every withdraw with a VALID_SPEND ZK proof; verifies │
│  every settlement with a VALID_MATCH_BATCH proof. The only     │
│  layer that can move tokens.                                   │
└────────────────────────────────────────────────────────────────┘
                              ▲
                              │  signed settle txs (attested TEE)
                              │
┌────────────────────────────────────────────────────────────────┐
│  MATCHING LAYER  — Intel TDX Confidential VM (nyx-tee)         │
│                                                                │
│  Runs the order book, the matching engine, the in-TEE Groth16  │
│  prover, and the settle scheduler. Receives orders over RA-    │
│  TLS, runs a frequent-batch auction every 2 seconds, signs     │
│  settlement payloads with a key derived inside the enclave.    │
│  The enclave's compose_hash is on-chain in vault_config; only  │
│  that compiled image can produce valid signatures.             │
└────────────────────────────────────────────────────────────────┘
                              ▲
                              │  signed order intents (Ed25519)
                              │
┌────────────────────────────────────────────────────────────────┐
│  CLIENT LAYER  — TypeScript SDK                                │
│                                                                │
│  Generates ZK proofs (VALID_INPUT for deposits, VALID_SPEND    │
│  for withdraws), signs canonical order bodies, attests the     │
│  TEE's measurement chain before trusting it, and manages       │
│  three distinct user identities (wallet / trading key / API    │
│  credentials).                                                 │
└────────────────────────────────────────────────────────────────┘
```

The three-layer separation is the privacy story:

- **Solana sees**: deposit notes (Poseidon hashes), Merkle root
  updates, settlement transactions (with trading keys, not wallet
  keys), withdraw VALID_SPEND proofs.
- **The TEE sees**: orders signed by trading keys, the matching
  results, the canonical payload it signs.
- **Each user sees**: their own wallet → trading-key link, their
  own notes, their own spending keys.

No single component sees enough to deanonymize a user's trading.

---

## The TEE migration (v2)

As of mid-2026, Nyx is migrating its matching layer from
MagicBlock's Permission-Group Ephemeral Rollup (PER) to a dedicated
Intel TDX Confidential VM operated under the open-source
[dstack](https://github.com/Dstack-TEE/dstack) framework on Phala
Cloud. The migration is the "TEE v2" workstream.

The motivation is twofold:

1. **Architectural simplification.** The PER added a second cluster
   that ran a forked Solana rollup, with its own attestation,
   delegation, and undelegation choreography. The TDX CVM is a
   single-process Rust daemon; the trust chain shrinks from
   "[user → SDK → PER attestation → MagicBlock → Solana]" to
   "[user → SDK → dstack attestation → Solana]".

2. **Trust minimisation.** PER attestation is built on MagicBlock's
   own infrastructure. TDX attestation chains to Intel's cert root
   directly; multisig governance rotates the registered
   `compose_hash` on-chain in the vault. The TEE itself can be
   independently verified by any client running the existing
   `dcap-qvl` tool.

The migration is being executed sub-PR-by-sub-PR with each piece
landing independently testable. The [roadmap](./roadmap-and-status.md)
page tracks shipped vs in-flight work.

---

## What's already in production

| Layer | Status | Notes |
|---|---|---|
| **Custody (vault program)** | Live on Solana devnet | Six instructions: `create_wallet`, `deposit`, `lock_note`, `verify_match_batch`, `tee_forced_settle_batched`, `close_batch_validity_marker`, `withdraw`. v3.5 hardening complete. |
| **Matching algorithm** | Live (single source of truth in `darkpool-matcher` crate) | Uniform clearing price, FIFO tie-break, Pyth-band circuit breaker. Same Rust crate consumed by both the on-chain ix and the in-TEE matcher. |
| **ZK circuits** | All six circuits compiled + verifying keys on-chain | VALID_INPUT, VALID_WALLET_CREATE, VALID_SPEND, VALID_MATCH_BATCH (N=2, N=4, N=16). N=16 is the production wired instantiation. |
| **TypeScript SDK** | Parity-tested against Rust host-side primitives | Cross-language byte equality enforced on Poseidon, key derivation, note commitments, nullifiers, canonical payload hashes. |
| **TEE v2 daemon (`nyx-tee`)** | Boot path live; matcher + oracle + HTTP surface live; settle scheduler skeleton live | See [roadmap-and-status](./roadmap-and-status.md). |

---

## Where to go from here

If you're skimming for the **technology overview**, continue to
[architecture-overview](./architecture-overview.md).

If you're evaluating the **trust model**, jump to
[trust-model](./trust-model.md).

If you want the **settlement details** (what actually happens
on-chain), go to [settlement-pipeline](./settlement-pipeline.md).

If you're an integrator, [api-and-integration](./api-and-integration.md)
is the wire contract.

---

*Last updated 2026-05-29. Source of truth for the technical claims
on this page is the `nyx-monorepo` repository; specifically
`CRYPTOGRAPHY.md`, `docs/ARCHITECTURE.md`, `docs/tee-architecture.md`,
and `docs/tee-attestation-flow.md`.*
</content>
