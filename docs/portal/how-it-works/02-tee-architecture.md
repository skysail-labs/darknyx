---
sidebar_position: 2
title: Confidential VM Architecture
description: The matching engine runs inside a single attested Intel TDX confidential VM whose keys are bound to one measured image — the privacy and integrity root of the venue.
---

# Confidential VM Architecture

:::info TL;DR
Nyx matches orders inside a single **Intel TDX Confidential VM** — a hardware-
isolated enclave whose memory the operator cannot read and whose signing keys are
**derived from its measured image**. Change the code and the keys no longer
derive, so a substituted engine cannot sign settlements or decrypt order intent.
Privacy and integrity come from hardware attestation plus on-chain proof
verification, not from trusting the operator.
:::

## Why a confidential VM

A dark pool's central problem is: who runs the matching engine, and why can't they
cheat? Most private venues answer "an operator you have to trust" or "a committee
of operators, most of whom you have to trust." Nyx answers with hardware: the
engine runs inside an Intel TDX confidential VM (a "CVM") — an enclave the CPU
isolates from everything else on the host, including the operator, the
hypervisor, and other tenants.

Two properties matter:

- **Confidentiality.** The enclave's memory is encrypted by the CPU. The operator
  running the machine cannot read order intent out of RAM, logs, or a memory dump.
- **Measured integrity.** The exact code running in the enclave is *measured* into
  a hardware register at boot, and that measurement is part of a hardware-signed
  attestation quote anyone can verify.

## Keys bound to the image

The decisive property is **key binding**. The enclave's secrets — the TLS
certificate key, the Ed25519 key it signs settlements with — are derived through a
key-management flow that ties them to the enclave's measurement. A different
image produces different keys.

```text
   measured image (compose hash)
            │  key derivation bound to the measurement
            ▼
   ┌──────────────────────────────────────────┐
   │  enclave keys                              │
   │   • TLS cert key (terminates TLS inside)   │
   │   • Ed25519 settlement signer (on-chain)   │
   └──────────────────────────────────────────┘
            │
   swap the code → different measurement → different keys →
   can't decrypt the TLS channel, can't sign a settlement the
   on-chain program accepts
```

This is what makes attestation actionable. It is not enough to *measure* the code;
the measurement has to *gate* the capability. On Nyx:

- The TLS key is bound to the image, so a substituted engine cannot terminate your
  encrypted channel — you would be talking to a different key, detectable at
  attestation.
- The settlement signer is bound to the image **and registered on-chain**, so a
  substituted engine cannot produce a settlement transaction the vault program
  will accept.

## What the operator can and cannot do

| The operator can | The operator cannot |
|---|---|
| Run, restart, or stop the VM | Read order intent from enclave memory |
| Control networking and uptime | Forge a settlement (the vault verifies a ZK proof + the registered signer) |
| Deploy a new image (a new measurement) | Move user funds (custody is on-chain, gated by proofs) |
| Observe encrypted traffic | Substitute the engine without changing the attestation a client checks |

The worst a malicious operator can do is **deny service** — stop the VM. They
cannot steal funds and cannot deanonymize orders, because neither capability lives
on the machine they control: funds are guarded by on-chain proof verification, and
order intent is sealed inside hardware-encrypted memory keyed to the measured
image.

## Single enclave vs. a committee

Some private venues split the matching engine across a committee of operators so
no single one sees an order. Nyx takes a different route: a single enclave, but one
whose operator sees *nothing* and whose integrity is hardware-attested and
on-chain-enforced. The trust assumption is the CPU vendor's attestation and the
soundness of the zero-knowledge proofs — not the honesty of a quorum of operators.
The practical consequences:

- **No collusion surface.** There is no committee whose members could collude;
  the privacy boundary is the silicon.
- **Verifiable, not social.** You verify a measurement and a proof, not the
  reputation or jurisdiction of node operators.
- **Liveness is the operator's job.** A single VM means the operator's uptime
  matters; the protection is that the operator can only ever halt, never cheat.

## How you rely on it

As an integrator you do not have to take any of this on faith. You verify the
running enclave against an expected measurement before trusting it with order
intent, and you can confirm that the engine you talk to is the same engine that
signs settlements on-chain. See [Privacy & Attestation](./privacy-and-attestation)
for the verification chain.
