---
description: "What Darknyx hides, what remains public, and how clients verify the confidential matcher and its complete on-chain signer set."
---


# Privacy & Attestation

{% hint style="info" %}
**TL;DR**

On the programmatic path, Darknyx keeps order intent inside the measured matcher
and balances inside on-chain commitments. The engine terminates TLS with a
boot-random key inside its confidential VM; the deployment gateway passes that
encrypted stream through. The SDK and daemon verify that live certificate,
hardware quote, image measurement, boot session, and complete on-chain
settlement-signer set before sending credentials or orders.
{% endhint %}

## Who can see your orders?

| Venue type | Who sees your orders | Risk |
|---|---|---|
| **Centralized exchange** | The operator | Can front-run, trade against you, or leak data. |
| **On-chain order book** | The sequencer / validators, and anyone indexing the chain | Reorder, censor, sandwich (MEV); the leak is permanent and public. |
| **Off-chain dark desk** | The operator | Custody and order intent both exposed to one party. |
| **Darknyx programmatic path** | The measured matcher inside protected VM memory | The host and chain do not receive plaintext orders. The client verifies that the certificate on its connection belongs to the approved matcher boot. |

The difference from "encrypted on-chain orders" is that on Darknyx your order is
**never a transaction at all** (see [Trade Flow](./trade-flow.md)). What lands on
Solana is the settled *result*, with a zero-knowledge proof, never the order.

## The three privacy properties

| Property | What is hidden | Mechanism |
|---|---|---|
| **Order privacy** | Side, size, limit price | On the supported programmatic path, order intent crosses enclave-terminated RA-TLS and stays inside matcher memory; it never appears in a tx, log, or account. |
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
 1. Transport belongs to a live enclave boot?
        A fresh quote binds the certificate on the actual connection.
                          │  yes
                          ▼
 2. Hardware attestation and code valid?
        TDX quote signature checks out; platform TCB is current;
        quote event log commits to the compose_hash YOU expect.
                          │  yes
                          ▼
 3. Same boot and settlement authority end-to-end?
        transport quote binds the boot session and ordered full signer set;
        that set == finalized VaultConfig.tee_pubkeys on Solana.
                          │  all three hold
                          ▼
                 trust the channel with order intent
```

- **Step 1** observes the self-signed certificate on the connection that will
  carry the request and verifies a fresh transport quote binding its SPKI. A
  probe to a different socket is not a substitute. Before launch, the remaining
  replacement-socket race must be closed inside the connector so a pooled
  connection cannot disappear after the preflight gate and be replaced before
  dispatch.
- **Step 2** performs DCAP verification, rejects malformed or ambiguous event
  logs, requires exactly one
  runtime-typed compose event, derives the trusted compose hash from the
  DCAP-verified RTMR3 log, and compares it with a release measurement obtained
  independently. `/info` and `/transparency` are useful displays, not the root
  of trust.
- **Step 3** checks the boot session and every shard signer, in order. The
  transport quote commits to both; `tee_pubkey` is simply the first signer
  exposed for convenience. The client compares the complete set with a
  finalized on-chain `VaultConfig` read.

The SDK verifies the transport evidence and returns the quote-bound identity;
the client still supplies the independently approved compose hash and compares
the full returned signer set with finalized on-chain configuration. The
reference daemon performs these checks automatically and pauses new trading
when its evidence becomes stale or mismatched. The current single-connection,
single-flight adapter narrows replacement churn, but connector-level refusal and
supervised boot-rotation recovery remain pre-release gates; the internal
cryptography record tracks their closure evidence.

{% hint style="warning" %}
**TLS alone is not verification**

Connecting over ordinary TLS gives you a private channel to *some* machine.
Darknyx clients instead bind the certificate on the connection they use to a
fresh enclave quote and an independently approved measurement. Disabling
certificate checks or verifying a separate probe connection defeats that
guarantee.
{% endhint %}

{% hint style="warning" %}
**Browser access is deferred.** The implemented browser prototype currently
relays sensitive traffic through an ordinary trader host that can read it. It is
not the supported external-access path and is not launch-qualified. Use the SDK
or daemon for the programmatic trust model described on this page.
{% endhint %}

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
