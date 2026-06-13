---
sidebar_position: 3
title: Transport & Attestation
description: How the Nyx transport is secured — RA-TLS terminating inside the enclave — and how a client verifies it is talking to the real, measured engine.
---

# Transport & Attestation

:::info TL;DR
TLS terminates **inside the attested enclave**, with a certificate whose private
key is generated in the VM and never leaves it. There is no separate gateway in
the trust path and no in-band session-encryption envelope to negotiate — the TLS
channel already reaches the measured code. Clients can **verify** they are
talking to the real engine by checking the attestation quote against an expected
image measurement.
:::

## The trust boundary

On many private venues, your connection terminates at a gateway or load balancer
that sits *outside* the system's trust zone, and a separate in-band encryption
handshake is layered inside TLS to defend against that gateway. Nyx does not have
that gap.

The TLS certificate Nyx serves is bound to a key the enclave generated and holds.
TLS therefore terminates *inside* the confidential VM — the same boundary that
runs the matching engine. There is no intermediate hop that sees plaintext, so
there is no need for a second encryption layer:

```text
        TLS (key generated inside the enclave, never exported)
client ───────────────────────────────────────────────► ┌───────────────┐
                                                         │  Confidential │
                  plaintext exists ONLY here ──────────► │  VM (enclave) │
                                                         └───────────────┘
        no gateway / load balancer in the trust path
```

What this gives you:

- **Confidentiality and integrity to the enclave.** Order intent is encrypted on
  the wire and decrypted only inside the measured code.
- **No extra handshake.** You use ordinary HTTPS and `wss://`; there is no
  `session.setup`, key-exchange, or rekey step to implement.

## Verifying the engine

TLS proves you have a private channel to *something*. Attestation proves that
something is the **specific, measured Nyx engine** and not a substituted binary.
Verification is a client-side step you run once at connect (or whenever you want
the strong guarantee).

### GET /info

Returns the identity of the running image.

```text
GET /info
```

```json
{
  "app_id": "…",
  "instance_id": "…",
  "compose_hash": "…",
  "tee_pubkey": "…",
  "nyx_version": "…"
}
```

| Field | Description |
|---|---|
| `app_id` | Deterministic id derived from the deployer and the compose configuration. |
| `instance_id` | Identifier of this specific VM instance. |
| `compose_hash` | SHA-256 of the canonicalised deployment manifest. **This is the value a client pins** — it must equal the measurement the client expects for a trusted build. |
| `tee_pubkey` | The enclave's Ed25519 signer (base58); the key that signs settlement payloads on-chain. |
| `nyx_version` | Build version tag of the engine. |

### GET /attestation

Returns an Intel TDX attestation quote plus the data needed to verify it.

```text
GET /attestation?reportData=<optional-nonce>
```

The quote is a hardware-signed measurement of the running VM. A client passing a
fresh `reportData` nonce gets a quote bound to that nonce (freshness) and to the
enclave's signing key (so the channel, the quote, and the on-chain signer are all
the same engine).

| Field | Description |
|---|---|
| `quote` | Hex-encoded TDX quote (DCAP format) — the hardware-signed measurement. |
| `event_log` | The boot event log, replayed during verification to confirm the recorded compose hash and instance identity. |
| `report_data` | 64 bytes bound into the quote: the caller's nonce in the first half, a hash of the enclave signing key in the second. |
| `vm_config` | The VM hardware configuration the quote attests to (used to recompute the OS measurement). |
| `tee_pubkey` | The enclave Ed25519 signer the quote binds to. |

### The verification chain

A verifying client confirms, in order:

1. The TDX quote's hardware signature is valid and the platform's trusted
   computing base is current (standard DCAP verification).
2. The measured `compose_hash` equals the client's **expected** value for a build
   it trusts. A different compose hash means different code — stop.
3. The quote's `report_data` binds the enclave's signing key, and that key equals
   the on-chain settlement signer — so the engine you are talking to is the same
   engine that settles on Solana.

The SDK ships a helper that runs this chain for you against an expected
measurement. Only when all three hold should a client trust the channel with
order intent.

:::caution Pin the measurement, not the host
The security guarantee comes from the **measurement**, not from the hostname.
A client that connects over TLS but skips attestation has confidentiality to
*some* machine; it has not verified that the machine runs the real engine. Pin an
expected `compose_hash` and verify it.
:::

### The TLS certificate is attested too

The files under `/evidences/` (`quote.json`, `cert.pem`, and an integrity
checksum) let a client confirm that the **served TLS certificate** is bound to a
key held inside the enclave — closing the loop between "I have a TLS channel" and
"the TLS channel reaches the attested code." A client that verifies this binding
does not have to take the certificate authority's word for which machine holds
the key.

## What attestation does and does not give you

| Guarantees | Does not guarantee |
|---|---|
| You are talking to the exact, measured engine build. | That you submitted the order you meant to (that is on your client). |
| The engine that matches is the engine that signs settlements on-chain. | Anything about another party's order — privacy is per-order, enforced inside the enclave. |
| Order intent is confidential in transit and at rest inside the enclave. | Protection against losing your own keys — custody of the trading and spending keys is yours. |
