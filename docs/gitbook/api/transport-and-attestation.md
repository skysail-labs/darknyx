---
description: "How HTTPS reaches the confidential VM and how a client verifies the quote-bound image and complete on-chain signer set."
---


# Transport & Attestation

{% hint style="info" %}
**TL;DR**

TLS terminates at the **dstack gateway**, which is itself an attested TDX
confidential VM, and reaches the Darknyx engine over an encrypted, mutually
attested tunnel. No ordinary server or cloud operator sees your order intent —
but the trust path spans two enclaves, and today your client verifies the
measurement of only one of them. There is no in-band session-encryption envelope
to negotiate. Clients **verify** they are talking to the real engine by checking
the attestation quote against an expected image measurement.
{% endhint %}

## The trust boundary

On many private venues your connection terminates at a gateway or load balancer
running as ordinary software, outside any hardware-protected boundary, and a
separate in-band encryption handshake is layered inside TLS to defend against it.
Darknyx does not have that gap — but the reason is more specific than "TLS
terminates at the engine", and it is worth stating precisely.

TLS terminates at the **dstack gateway**. The gateway is not a conventional load
balancer: it runs inside its own Intel TDX confidential VM, generates its
certificate key inside that VM, and establishes a WireGuard tunnel to the Darknyx
CVM only after the two mutually verify each other's attestation. Plaintext order
intent therefore exists only inside hardware-protected memory, on both hops:

```text
        TLS (key generated inside the gateway's TEE)
client ──────────────────────────────► ┌─────────────┐   WireGuard,   ┌───────────────┐
                                        │   dstack    │  mutually      │  Darknyx      │
                     plaintext here ──► │  gateway    │  attested ───► │  CVM (engine) │
                                        │  (TDX CVM)  │                └───────────────┘
                                        └─────────────┘
        no untrusted hop — but two measured boundaries, not one
```

What this gives you:

- **Confidentiality from the infrastructure operator.** Neither the host OS nor
  the platform operator can read order intent at either hop; TDX memory
  encryption prevents it.
- **No extra handshake.** You use ordinary HTTPS and `wss://`; there is no
  `session.setup`, key-exchange, or rekey step to implement.

{% hint style="warning" %}
**What this does not yet give you**

Two limits are worth knowing before you rely on the transport for anything of
real value:

- **You pin one measurement, not two.** The verification below covers the
  Darknyx engine's image. Nothing in it covers the *gateway's* image, so that
  component can change without any Darknyx governance event.
- **The TLS session is not bound to the quote.** You fetch and verify a quote
  *over* a TLS connection, but nothing cryptographically ties that connection's
  certificate to the quote you verified.

Closing both means terminating TLS inside the Darknyx enclave itself with an
attestation-bound certificate. That work is tracked and gated ahead of external
users and real-value deposits; it has not shipped. Earlier revisions of this page
described it as though it had. Until it does, treat the transport as protected
from the operator but resting on a second enclave you are not yet pinning.
{% endhint %}

## Verifying the engine

TLS proves you have a private channel to *something*. Attestation proves that
something is the **specific, measured Darknyx engine** and not a substituted binary.
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
  "tee_pubkeys": ["…", "…"],
  "boot_session_id": "…",
  "version": "…"
}
```

| Field | Description |
|---|---|
| `app_id` | Deterministic id derived from the deployer and the compose configuration. |
| `instance_id` | Identifier of this specific VM instance. |
| `compose_hash` | Self-reported SHA-256 of the deployment manifest. Useful for display; the authoritative value comes from the quote-bound event log. |
| `tee_pubkey` | Primary (shard-0) Ed25519 settlement signer, kept as a convenience field. |
| `tee_pubkeys` | Full ordered signer set, one per tree shard. Verify the entire set against finalized `VaultConfig.tee_pubkeys`. |
| `boot_session_id` | Fresh process-boot id signed into every canonical place and cancel intent, preventing cross-restart replay. |
| `version` | Build version tag of the engine. |

### GET /attestation

Returns an Intel TDX attestation quote plus the data needed to verify it.

```text
GET /attestation?reportData=<optional-nonce>
```

The quote is a hardware-signed measurement of the running VM. A client passing a
fresh `reportData` nonce gets a quote bound to that nonce (freshness) and to the
hash of the complete ordered signer set.

| Field | Description |
|---|---|
| `quote` | Hex-encoded TDX quote (DCAP format), the hardware-signed measurement. |
| `event_log` | The boot event log, replayed during verification to confirm the recorded compose hash and instance identity. |
| `report_data` | 64 bytes bound into the quote: caller nonce in bytes 0–31, then `SHA-256(pk0 || … || pkK-1)` in bytes 32–63. |
| `tee_pubkey` | Primary signer, for convenience. Fetch `/info.tee_pubkeys` to recompute the bound set hash. |

### The verification chain

A verifying client confirms, in order:

1. The TDX quote's hardware signature is valid and the platform's trusted
   computing base is current (standard DCAP verification).
2. Replaying the returned event log reproduces the DCAP-verified quote's RTMR3;
   the `compose-hash` event then equals the independently pinned release value.
3. The quote's `report_data` binds the full ordered signer set advertised by
   `/info`, and that exact set equals a **finalized** on-chain
   `VaultConfig.tee_pubkeys` read.

The SDK ships a helper that runs this chain for you against an expected
measurement. Only when all three hold should a client trust the channel with
order intent.

{% hint style="warning" %}
**Pin the measurement, not the host**

The security guarantee comes from the **measurement**, not from the hostname.
A client that connects over TLS but skips attestation has confidentiality to
*some* machine; it has not verified that the machine runs the expected engine.
Pin a release measurement independently, then verify the quote and event log.
{% endhint %}

### The TLS certificate is attested too

The files under `/evidences/` (`quote.json`, `cert.pem`, and an integrity
checksum) let a client confirm that the **served TLS certificate** is bound to a
key held inside the enclave, closing the loop between "I have a TLS channel" and
"the TLS channel reaches the attested code." A client that verifies this binding
does not have to take the certificate authority's word for which machine holds
the key.

## What attestation does and does not give you

| Guarantees | Does not guarantee |
|---|---|
| You are talking to the exact, measured engine build. | That you submitted the order you meant to (that is on your client). |
| The engine that matches controls the complete signer set accepted on-chain. | That matching obeyed an unmeasured policy or that the service will remain live. |
| Order intent is confidential in transit and at rest inside the enclave. | Protection against losing your own keys; custody of the trading and spending keys is yours. |
