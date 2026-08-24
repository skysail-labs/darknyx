---
description: "The Darknyx REST and WebSocket API: base URLs, authentication, and the full endpoint reference for trading, account state, Merkle proofs and settlement."
---

# API Reference

Everything a client needs to trade on Darknyx programmatically. The engine runs
inside an Intel TDX confidential VM, so the transport and attestation sections
are not boilerplate — they are how you verify you are talking to the real
enclave before you send it an order.

{% hint style="warning" %}
**Verify the enclave before authenticating.** The engine terminates TLS itself
with a boot-random, quote-bound certificate. Clients check that certificate
against [`GET /transport-attestation`](getting-started/transport-and-attestation.md)
rather than against a public CA. Sending a bearer token over an unverified
connection defeats the guarantee this venue exists to provide.
{% endhint %}

## Start here

| Page | What it covers |
|---|---|
| [Base URLs](getting-started/base-urls.md) | Hosts, health and time. |
| [Authentication](getting-started/authentication.md) | Exchanging credentials for a short-lived bearer token. |
| [Transport & Attestation](getting-started/transport-and-attestation.md) | Verifying the enclave and its TLS certificate. |
| [Error Codes](getting-started/error-codes.md) | The error envelope and every code it can carry. |

## Services

| Group | Endpoints | Purpose |
|---|---|---|
| [Orders](orders/README.md) | `POST`/`GET`/`PUT`/`DELETE /orders` | The order lifecycle. |
| [Instruments](instruments/README.md) | `/instruments` | Tradable markets, tick sizes, price scales. |
| [Account](account/README.md) | `/account`, `/account/settings` | Your open orders and trading settings. |
| [Merkle Tree](tree/README.md) | `/tree/*` | Roots, inclusion proofs and leaf pagination. |
| [Settlement](settlement/settlement-status.md) | `/settlement/status/{batch_id}` | Per-match outcomes and on-chain signatures. |
| [Transparency](settlement/transparency.md) | `/transparency` | Public solvency snapshot and engine identity. |
| [System](system/system-status.md) | `/system/status`, `/health`, `/time`, `/info` | Liveness, degraded modes, server clock. |
| [WebSocket](websocket/session-stream.md) | `/v1/stream` | Multiplexed orders and fills channels. |

## Conventions

- **Integers, never floats.** Prices and sizes are integers scaled by the
  instrument's `price_scale`. Read it from
  [`GET /instruments`](instruments/list-instruments.md) at startup.
- **Bearer tokens are short-lived.** Mint one with
  [`POST /auth/token`](getting-started/authentication.md) and refresh it; do not
  embed long-lived credentials in a client.
- **Every error shares one envelope.** Match on the machine-readable `code`,
  not on the human-readable message, which may change.

{% hint style="info" %}
Operator and administrative endpoints are intentionally absent from this
reference and from its OpenAPI document.
{% endhint %}
