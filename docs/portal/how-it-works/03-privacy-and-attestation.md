---
sidebar_position: 3
title: Privacy & Attestation
description: Who can see your orders on Nyx (no one), and how you verify the engine cryptographically rather than trusting it.
---

# Privacy & Attestation

:::info TL;DR
On Nyx, **no party — not even the operator — can see your orders, balances, or
strategy**. Order intent lives only inside an attested enclave; balances are
sealed inside on-chain note commitments. You do not take this on trust: you
**verify** the running engine against an expected measurement, and confirm it is
the same engine that settles on-chain.
:::

## Who can see your orders?

| Venue type | Who sees your orders | Risk |
|---|---|---|
| **Centralized exchange** | The operator | Can front-run, trade against you, or leak data. |
| **On-chain order book** | The sequencer / validators, and anyone indexing the chain | Reorder, censor, sandwich (MEV); the leak is permanent and public. |
| **Off-chain dark desk** | The operator | Custody and order intent both exposed to one party. |
| **Nyx** | **No party** — order intent lives only inside a hardware-isolated, attested enclave; it is never a transaction | No party can read or replay your orders; an observer of Solana learns nothing about them. |

The difference from "encrypted on-chain orders" is that on Nyx your order is
**never a transaction at all** (see [Trade Flow](./trade-flow)). What lands on
Solana is the settled *result*, with a zero-knowledge proof — never the order.

## The three privacy properties

| Property | What is hidden | Mechanism |
|---|---|---|
| **Order privacy** | Side, size, limit price | Order intent exists only inside the attested enclave — never in a tx, log, or account. |
| **Trader privacy** | The link from a trade to your wallet | You sign with a **trading key**, not your wallet. The wallet ↔ trade link exists only inside your own withdraw proof. |
| **Position privacy** | What you hold | Balances are on-chain **note commitments** (Poseidon hashes) that seal owner, value, and token until you spend them. |

Each is enforced by a separate mechanism, so a weakness in one does not collapse
the others.

## Privacy is a guarantee, not a promise

The point of attestation is that you do not have to *believe* the operator is
running the honest engine — you can check. The enclave's privacy comes from
hardware memory encryption keyed to a *measured* image, and the integrity of
settlement comes from a *proof the chain verifies*. Both are cryptographic facts
you can inspect, not terms of service.

## Verifying the engine

Verification is a client-side step (the SDK ships a helper). In order, you confirm:

```text
 1. Hardware attestation valid?
        TDX quote signature checks out; platform TCB is current.
                          │  yes
                          ▼
 2. Right code?
        measured compose_hash == the value YOU expect for a trusted build.
                          │  yes
                          ▼
 3. Same engine end-to-end?
        the quote binds the enclave's signing key, and that key == the
        on-chain settlement signer.
                          │  all three hold
                          ▼
                 trust the channel with order intent
```

- **Step 1** is standard DCAP verification of the hardware quote.
- **Step 2** is the decisive check: a different `compose_hash` means different
  code. Pin the value you trust and compare. (`/info` and `/transparency` both
  surface it; `/attestation` proves it.)
- **Step 3** closes the loop: the engine you are talking to is the same engine
  whose key the Solana program accepts for settlement.

:::caution TLS alone is not verification
Connecting over TLS gives you a private channel to *some* machine. Only attestation
tells you the machine runs the real engine. A client that skips the attestation
check has confidentiality without integrity. Pin an expected measurement and
verify it before sending orders.
:::

## What attestation does not cover

- **Your own keys.** Custody of your trading and spending keys is yours; losing
  them is on you, not the protocol.
- **Liveness.** Attestation proves the engine is genuine, not that the operator
  will keep it running. The operator can halt the venue (deny service) but cannot
  cheat it. See [Confidential VM Architecture](./tee-architecture).
- **Your client's correctness.** Attestation verifies the *server*. That you
  submitted the order you intended is your client's responsibility.
