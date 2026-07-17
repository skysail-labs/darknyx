---
sidebar_position: 3
title: Privacy & Attestation
description: What Darknyx hides, what remains public, and how clients verify the confidential matcher and its complete on-chain signer set.
---

# Privacy & Attestation

:::info TL;DR
Darknyx keeps order intent inside an attested confidential VM and balances inside
on-chain commitments. The host operator should not be able to read protected
memory, but this guarantee depends on Intel TDX and the exact image being run.
Clients verify the hardware quote, image measurement, and complete on-chain
settlement-signer set before sending orders.
:::

## Who can see your orders?

| Venue type | Who sees your orders | Risk |
|---|---|---|
| **Centralized exchange** | The operator | Can front-run, trade against you, or leak data. |
| **On-chain order book** | The sequencer / validators, and anyone indexing the chain | Reorder, censor, sandwich (MEV); the leak is permanent and public. |
| **Off-chain dark desk** | The operator | Custody and order intent both exposed to one party. |
| **Darknyx** | The measured matcher inside protected VM memory | The host and chain do not receive plaintext orders; clients verify the code allowed to read them. |

The difference from "encrypted on-chain orders" is that on Darknyx your order is
**never a transaction at all** (see [Trade Flow](./trade-flow)). What lands on
Solana is the settled *result*, with a zero-knowledge proof, never the order.

## The three privacy properties

| Property | What is hidden | Mechanism |
|---|---|---|
| **Order privacy** | Side, size, limit price | Order intent exists only inside the attested enclave, never in a tx, log, or account. |
| **Trader privacy** | The link from an order or settled note to your wallet | Orders use a **trading key**. Deposit and withdrawal transfers remain visible, but do not publish the shielded note owner. |
| **Position privacy** | What you hold | Balances are on-chain **note commitments** (Poseidon hashes) that seal owner, value, and token until you spend them. |
| **Amount privacy** | The size and price of a settled trade | Settlement publishes only note commitments and a zero-knowledge proof of conservation; the traded amounts and the clearing price never appear on-chain. |

Deposits reveal the signer, mint, and gross amount. Withdrawals reveal the
destination, mint, and amount. Network timing and aggregate activity are also
observable. The privacy claim covers the book, note ownership, and settled
trade plaintext; it is not a claim that all protocol activity is invisible.

## Privacy is a guarantee, not a promise

The point of attestation is that a client can check which code receives its
order. Confidentiality comes from hardware isolation of a *measured* image;
settlement integrity comes from a narrower proof the chain verifies. Neither
substitutes for the other.

## Verifying the engine

Verification is a client-side step (the SDK ships a helper). In order, you confirm:

```text
 1. Hardware attestation valid?
        TDX quote signature checks out; platform TCB is current.
                          │  yes
                          ▼
 2. Right code?
        quote event log commits to the compose_hash YOU expect.
                          │  yes
                          ▼
 3. Same engine end-to-end?
        quote report_data binds the ordered full signer set, and that set ==
        finalized VaultConfig.tee_pubkeys on Solana.
                          │  all three hold
                          ▼
                 trust the channel with order intent
```

- **Step 1** is standard DCAP verification of the hardware quote.
- **Step 2** derives the trusted compose hash from the DCAP-verified event log
  (RTMR3) and compares it with a release measurement obtained independently.
  `/info` and `/transparency` are useful displays, not the root of trust.
- **Step 3** checks every shard signer, in order. The quote commits to the full
  set; `tee_pubkey` is simply the first member exposed for convenience. The
  client compares the complete set with a finalized on-chain `VaultConfig` read.

:::caution TLS alone is not verification
Connecting over TLS gives you a private channel to *some* machine. Only attestation
tells you the machine runs the real engine. A client that skips the attestation
check has confidentiality without integrity. Pin an expected measurement and
verify it before sending orders.
:::

## What attestation does not cover

- **Your own keys.** Custody of your trading and spending keys is yours; losing
  them is on you, not the protocol.
- **Liveness and censorship.** Attestation does not force the operator to keep
  the venue running, include a particular order, or provide timely service.
- **Matching fairness beyond the measured code.** Limit prices, FIFO, execution
  attributes, and oracle circuit-breaker policy are enforced by the attested
  matcher, not re-proven by the settlement circuit.
- **Your client's correctness.** Attestation verifies the *server*. That you
  submitted the order you intended is your client's responsibility.
