---
sidebar_position: 1
title: Architecture overview
description: The three layers of Nyx — Solana custody, in-TEE matching, client-side proofs — and how every cross-layer message is either an on-chain tx or an attested API call.
---

# Architecture overview

:::info TL;DR
Three layers, two boundaries, one trust chain. **Custody** on Solana,
**matching** inside an Intel TDX enclave, **clients** generating proofs locally.
Every message that crosses a boundary is either an on-chain transaction or a
TEE-attested API call — there are no hidden side channels.
:::

## The three layers

### Layer 1 — Custody, on Solana

A single Solana program (the **vault**) owns everything that must be trusted:
the user funds, the Merkle tree of note commitments (sharded across several
tree accounts for throughput), the spent-note and nullifier sets, the on-chain
Groth16 verifier, and the atomic batched-settlement path.

There is **no on-chain order book or matching program**. Matching happens
entirely inside the enclave, which drives the vault's settlement instructions
directly.

Custody is the only layer that can move tokens, and it moves them only against
proofs:

- Every **withdraw** needs a `VALID_SPEND` proof: you own a note in the current
  tree, you haven't spent it before, and your change note is well-formed.
- Every **settlement** needs a `VALID_MATCH_BATCH` proof plus a signature from a
  registered enclave key: the match was valid against the inputs the enclave
  declared.

### Layer 2 — Matching, inside a TDX Confidential VM

A single Rust process runs inside an Intel TDX Confidential VM. Inside it:

```text
nyx-tee  (one process inside the enclave)
  │
  ├── boot — derives its signing keys from the enclave's sealed root key
  │
  ├── API server — orders, auth, settlement status, live fills (WS),
  │                public attestation + transparency endpoints
  │
  ├── matcher — a frequent batch auction (every ~2s): reads the hidden
  │             order book + a verified oracle price, computes a uniform
  │             clearing price
  │
  ├── oracle sync — pulls and verifies a signed Pyth price feed
  │
  └── settle scheduler — proves each batch, then drives the settle path
                         on Solana (locks → verify → settle → close)
```

The boundary below this layer is the **settlement pipeline** (a batched,
tree-sharded sequence of Solana transactions —
see [Settlement pipeline](./settlement-pipeline)). The boundary above is the
**HTTPS + WebSocket API** (see [API reference](./api-reference)).

### Layer 3 — Client, the TypeScript SDK

The SDK is the user-side bridge. It:

1. **Generates your zero-knowledge proofs locally** — for registering a wallet,
   depositing, and withdrawing. These involve your spending key, so they never
   leave your device. (The *matching* proof is generated inside the enclave.)
2. **Verifies the enclave's attestation** before trusting it — checking the
   Intel-signed measurement chain and comparing it to the keys and image
   registered on-chain.
3. **Signs orders** with your trading key — distinct, by construction, from your
   Solana wallet.
4. **Submits Solana transactions** through whatever RPC you choose.

## System map

```text
        USER DEVICE
        ┌───────────────────────────────────────────┐
        │  TypeScript SDK                            │
        │  • local ZK provers   • tx builders        │
        │  • attestation check  • trading-key signer │
        └───────────────────────────────────────────┘
            │ Solana RPC                  │ HTTPS / WSS
            │ (deposit, withdraw,         │ (orders, status,
            │  register, merge)           │  live fills)
            ▼                             ▼
   ┌──────────────────────┐     ┌──────────────────────────┐
   │  SOLANA              │     │  TDX Confidential VM      │
   │  vault program      │◄────┤  nyx-tee                  │
   │  • custody (SPL)    │     │  • hidden order book      │
   │  • sharded Merkle   │     │  • clearing-price matcher │
   │    tree of notes    │     │  • oracle (verified Pyth) │
   │  • nullifier set    │     │  • in-enclave prover      │
   │  • on-chain verifier│     │  • settle scheduler       │
   │  • global config    │     │                           │
   │    (registered      │     │  Keys derived at boot     │
   │     enclave keys)   │     │  from the sealed root key │
   └──────────────────────┘     └──────────────────────────┘
            ▲                             │
            └──────── settle pipeline ────┘
              (signed by the enclave's shard keys)
```

## The cross-layer messages

### Client → Solana

Direct, user-signed interactions — no enclave involved:

- **Register** — open an account by recording your `user_commitment` on-chain.
- **Deposit** — move tokens from your wallet into a fresh note (with a
  `VALID_INPUT` proof binding the note's mint and amount).
- **Withdraw** — move a note's value back to a wallet (with a `VALID_SPEND`
  proof; emits a change note if you withdraw less than the full value).
- **Merge** — consolidate several small notes into one, so a single order can be
  larger than any one note you hold (with a `VALID_MERGE` proof).

### Client → TEE

Over HTTPS + a bearer token:

- **Authenticate** — exchange API credentials for a short-lived token (an
  operational identity for rate-limiting, *not* a custody boundary).
- **Place / cancel / query orders** — each order is signed with your trading
  key over a canonical body.
- **Stream fills** — subscribe to a per-account WebSocket that pushes your fills
  the moment they settle.

### TEE → Solana

The **settlement pipeline**: per batch, the enclave locks the input notes,
submits the batch proof, settles each match, and closes out. Under the hood the
settles are spread across multiple tree shards and fee-payer keys so they
co-include in a single block — the full story is in
[Settlement pipeline](./settlement-pipeline).

## Why this shape

Each boundary earns its place:

- **Custody at the bottom.** If the enclave or the client is compromised, funds
  are still safe — no withdraw without your proof, no settle without the
  registered enclave signature. The worst a rogue enclave can do is censor or
  reorder within one batch.
- **Matching in the middle.** It's stateful and private; an attested enclave is
  the only place it can run without leaking every order.
- **Clients on top.** Local proof generation keeps your spending key off both
  the chain and the enclave. The chain from "I have a seed phrase" to "I own
  this note" exists only on your device.

## What lives where

| Concern | Location | Why |
|---|---|---|
| Token custody | On-chain (vault SPL accounts) | Solana enforces transfers atomically. |
| Merkle tree of notes | On-chain (sharded tree accounts) | Auditable; trustless withdraw with no indexer needed. |
| Nullifier / spent-note sets | On-chain (per-note PDAs) | Double-spend prevention as a simple init-collision check. |
| Order book | In-TEE | Visible only to attested code. |
| Oracle price | In-TEE | Pyth signature verified on entry; matcher reads each tick. |
| Match proof | In-TEE | The match must stay private; the proof is what makes the settle trustless. |
| Spending key | Client-only | Never on the wire; used only by the local withdraw prover. |
| Trading key | Client-only | Only the pubkey appears in the order body. |

The pattern: **what must be trusted goes on-chain; what must be private goes
in-TEE; what must stay secret stays on your device.**

## Read on

- [Custody layer](./custody-layer) — the vault, notes, and the sharded tree.
- [Matching layer](./matching-layer) — the batch auction, the oracle, partial-fill continuations.
- [Cryptography](./cryptography) — keys, the note model, the ZK circuits.
- [Trust model](./trust-model) — attestation, governance, threat model.
- [Settlement pipeline](./settlement-pipeline) — the batched, sharded settle path.
- [API reference](./api-reference) — the wire contract.
</content>
