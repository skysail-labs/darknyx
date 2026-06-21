---
sidebar_position: 5
title: Trust model
description: What you actually trust in Nyx — the TDX attestation chain, on-chain governance of the enclave's keys, and a precise account of what a malicious operator can and cannot do.
---

# Trust model

:::info TL;DR
You don't trust the operator. You trust **Intel's attestation** that a specific,
measured image is running, and **Solana's** record of which image and keys the
vault accepts. The operator can't read your orders (the enclave seals them) and
can't move your funds (every exit needs a proof only you can make). The worst a
fully malicious operator can do is **stop matching** — not steal.
:::

## What "trust" reduces to

Strip Nyx down and you're trusting three things, each independently verifiable:

1. **The hardware does what Intel says.** TDX seals the enclave's memory and
   produces a quote — a signed statement of exactly what image is running —
   chaining to Intel's certificate root.
2. **The running image is the one Nyx published.** The quote includes a
   measurement (`compose_hash`); you compare it to the image registered on-chain
   in the vault. A different image produces a different measurement and is
   rejected.
3. **Only that image can settle.** The vault accepts settlements only from
   signing keys derived *inside* that measured image, and the set of accepted
   keys changes only through governance.

You can check all three yourself, before sending a single order.

## The attestation chain

```text
   Intel cert root
        │  signs
        ▼
   TDX quote  ──────────────────────────────────────────┐
   • measured image (compose_hash)                       │
   • bound to the enclave's signing pubkey               │
        │                                                │
        ├── client verifies the quote (Intel TCB chain)  │  before trusting
        ├── compose_hash  ==  on-chain registered image  │  any enclave data
        └── signing key   ==  on-chain registered key  ◄─┘
```

A client (the SDK ships this as one call) fetches the enclave's quote, verifies
it against Intel's chain, confirms the measured image and signing key match what
the vault has registered on-chain, and only then trusts the connection. The
enclave also fronts its API with a TLS certificate whose private key lives
*inside* the enclave, so the attestation covers the transport too.

:::note Simulator quotes fail on purpose
During development the enclave can run against a simulator that returns a
well-formed but stub-signed quote. Real attestation verification rejects it by
design — the same check that keeps the dev loop fast is the one that stops a
fake attestation from fooling a client.
:::

## Governance: rotating the enclave's keys

When Nyx ships a new enclave image, its measurement changes, so its derived
signing keys change too — and the old keys stop being able to settle. Bringing a
new image online is a deliberate, multi-party **ceremony**, not a unilateral
flip:

1. The new enclave boots and publishes its quote and new keys.
2. Each governance signer independently verifies the quote off-chain and
   confirms the measured image is the expected one.
3. Only with a threshold of signatures does governance update the vault's
   registered keys to the new enclave's set.

The registered keys can *only* be changed this way. No single party — including
the operator — can point the vault at a rogue enclave.

:::tip The enclave uses a set of keys, not one
For settlement throughput, the enclave derives several signing keys (one per
tree shard) and the vault accepts any of them. They are rotated together as one
set during the ceremony — it doesn't change the trust story, only the
throughput. See [Settlement pipeline](./settlement-pipeline).
:::

## What a malicious operator can and cannot do

| Can it…? | Outcome |
|---|---|
| Read your order? | **No** — order intent is sealed inside the enclave; the operator sees ciphertext and attested code, not contents. |
| Withdraw your funds? | **No** — every exit needs a `VALID_SPEND` proof only you can generate. |
| Forge a settlement? | **No** — settlements need a valid batch proof *and* a registered enclave signature. |
| Swap in a rogue image? | **No** — a different image fails attestation and isn't registered on-chain. |
| Lie about an inclusion proof? | **No** — inclusion proofs self-verify against the on-chain root. |
| Refuse to match you (censor)? | **Yes** — but it can't take anything; you withdraw your notes and leave. |
| Reorder within a single batch tick? | **Limited** — the uniform clearing price means there's no price edge to gain, and the band keeps the clearing price honest. |

The honest summary: a compromised Nyx is a Nyx that **stops working**, not one
that steals. That's the property a custodial dark pool can never offer.

## Deposit first, trust never

Because withdrawal is trustless, your exposure to the operator is bounded the
moment you deposit. You can put funds in, trade, and — if the venue ever
misbehaves or simply goes away — pull everything out with nothing but your seed
and the on-chain tree. There is no "the operator must cooperate to let me leave"
step anywhere in the system.

## Compared to the alternatives

| Venue type | Who sees your order | Who can take your funds |
|---|---|---|
| Public on-chain order book | Everyone, forever | No one (but you're fully exposed to MEV) |
| Custodial dark pool / CEX | The operator | The operator |
| **Nyx** | **The attested enclave only** | **No one but you** |

Nyx is the only column where order privacy and self-custody hold at the same
time. The remaining honest caveats — the Groth16 trusted setup, and binding the
on-chain key rotation to a fully on-chain quote verification — are tracked
openly on the [roadmap](./roadmap).
</content>
