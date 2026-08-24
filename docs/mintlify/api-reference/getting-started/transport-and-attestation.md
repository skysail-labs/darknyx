---
description: "How HTTPS reaches the confidential VM and how a client verifies the quote-bound image and complete on-chain signer set."
---


# Transport & Attestation

{% hint style="info" %}
**TL;DR**

This page describes the current programmatic path: the Node SDK and reference
daemon connect to the engine over **RA-TLS terminated inside the Darknyx CVM**.
The deployment gateway passes the encrypted TLS stream through without seeing
the request. Before sending credentials or order intent, the client checks that
the certificate on its actual connection is bound by a fresh TDX quote to the
approved engine image, boot session, and settlement-signer set.
{% endhint %}

## The trust boundary

At each engine boot, Darknyx generates a random TLS key in memory and never
persists it. The engine serves HTTPS and WebSocket traffic with that key. The
deployment gateway routes the connection by hostname but does not terminate its
TLS, so plaintext first appears inside the measured engine:

```text
client ═════ TLS encrypted end-to-end ═══► gateway (passthrough) ═══► Darknyx CVM
                                                                        │
                                                               plaintext only here
```

What this gives you:

- **Fresh transport identity.** A later boot has a different certificate and
  must be verified again.
- **Connection binding.** The SDK compares the quote-bound SPKI with the
  certificate observed on the socket carrying the session; a quote fetched from
  an unrelated probe is not enough.
- **One boundary for REST and streams.** HTTPS and `wss://` use the same
  boot-scoped enclave identity.

{% hint style="warning" %}
**Pre-release status.** The programmatic RA-TLS path is implemented and has
completed live devnet settlement tests, but it remains under launch
qualification. Replacement-connection handling, restart recovery, safe-default
policy, and GPU deployment parity must all pass their release gates before
mainnet or external real-value use.
{% endhint %}

## Browser status

{% hint style="warning" %}
The browser trader is deferred and is not a supported external-access path.
Its current prototype talks through an ordinary **trader host**, which can read
orders, cancellations, and fill streams in plaintext:

```text
browser ──TLS──► trader host ──verified RA-TLS──► Darknyx CVM
                (ordinary server)
                plaintext here
```

On-device signatures and custody still prevent that host from forging orders or
extracting the user's seed, but they do not hide order flow from it. Browser
launch requires a separate design and security review that removes this
plaintext boundary. Use the SDK or daemon for the trust model documented here.
{% endhint %}

## Verifying the engine

The programmatic client establishes trust before authentication. It first
observes the engine's self-signed certificate, requests fresh transport evidence
over that connection, and verifies the complete chain below. A reconnect or boot
change must be gated again; a hostname or ordinary CA certificate is not the
root of trust.

### GET /transport-attestation

Returns a nonce-bound TDX quote whose manifest commits to the TLS SPKI, boot
session, application identity, and complete settlement-signer set.

{% openapi src="https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml" path="/transport-attestation" method="get" %}
https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml
{% endopenapi %}

The certificate is self-signed **by design**. Never work around that with
`curl -k`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, or a custom client that simply
accepts every certificate. The SDK accepts it only after the quote proves the
SPKI belongs to the approved enclave boot.

### GET /info

Returns the identity of the running image.

{% openapi src="https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml" path="/info" method="get" %}
https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml
{% endopenapi %}

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
| `boot_session_id` | Fresh process-boot id signed into every canonical place and cancel intent, preventing cross-restart replay. Verify that it matches the value bound by the transport-attestation manifest. |
| `version` | Build version tag of the engine. |

### GET /attestation

Returns an Intel TDX attestation quote plus the data needed to verify it.

{% openapi src="https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml" path="/attestation" method="get" %}
https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml
{% endopenapi %}

The quote is a hardware-signed measurement of the running VM. A client passing a
fresh `reportData` nonce gets a quote bound to that nonce (freshness) and to the
hash of the complete ordered signer set.

| Field | Description |
|---|---|
| `quote` | Hex-encoded TDX quote (DCAP format), the hardware-signed measurement. |
| `event_log` | The boot event log, replayed during verification to confirm the recorded compose hash and instance identity. |
| `report_data` | 64 bytes bound into the quote: caller nonce in bytes 0–31, then `SHA-256(pk0 ∥ … ∥ pkK-1)` in bytes 32–63. |
| `tee_pubkey` | Primary signer, for convenience. Fetch `/info.tee_pubkeys` to recompute the bound set hash. |

### The verification chain

A verifying client confirms, in order:

1. The caller nonce is fresh and the transport quote's hardware signature is
   valid with a current platform trusted computing base.
2. Rebuilding the canonical transport manifest reproduces the quote-bound
   digest, and its `tls_spki_sha256` equals the certificate on the **actual
   socket** carrying the session.
3. The event log is structurally valid, contains exactly one runtime-typed
   `compose-hash` event, and has no impossible entry carrying both a supplied
   digest and a payload. Replaying it reproduces the DCAP-verified quote's
   RTMR3, and the measured compose hash equals the independently pinned release
   value.
4. The manifest's boot session matches `/info`; its complete ordered signer set
   equals a **finalized** on-chain `VaultConfig.tee_pubkeys` read.

The Node SDK's verified transport performs the socket, nonce, quote, event-log,
measurement, boot and signer-set checks. The reference daemon also refreshes
the finalized on-chain comparison and pauses new trading when it becomes stale
or mismatched. Only after all four checks hold should a client authenticate or
send order intent.

{% hint style="warning" %}
**Pin the measurement, not the host**

The security guarantee comes from the **measurement**, not from the hostname.
A client that connects over TLS but skips attestation has confidentiality to
*some* machine; it has not verified that the machine runs the expected engine.
Pin a release measurement independently, then verify the quote and event log.
{% endhint %}

### Gateway evidence is not the programmatic trust root

The dstack gateway also serves files under `/evidences/` (`quote.json`,
`cert.pem`, ACME-account metadata, and an integrity checksum). Those files
describe the **gateway's** certificate and confidential deployment; they are
not the Darknyx engine quote returned by `/attestation`.

They are useful when evaluating the surrounding deployment, but they are not
needed to authenticate the programmatic session: the gateway does not terminate
that session's TLS. Fetching the evidence bundle cannot replace checking the
enclave certificate and `/transport-attestation` response on the connection the
client actually uses.

## What attestation does and does not give you

| Guarantees | Does not guarantee |
|---|---|
| You are talking to the exact, measured engine build. | That you submitted the order you meant to (that is on your client). |
| The engine that matches controls the complete signer set accepted on-chain. | That matching obeyed an unmeasured policy or that the service will remain live. |
| Order intent is confidential in transit and at rest inside the enclave. | Protection against losing your own keys; custody of the trading and spending keys is yours. |

## Raw evidence bundle

Served by the deployment's ingress rather than by the engine, these expose the
underlying artifacts so a third party can reproduce the verification independently.

{% openapi src="https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml" path="/evidences/quote.json" method="get" %}
https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml
{% endopenapi %}

{% openapi src="https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml" path="/evidences/cert.pem" method="get" %}
https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml
{% endopenapi %}

{% openapi src="https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml" path="/evidences/acme-account.json" method="get" %}
https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml
{% endopenapi %}

{% openapi src="https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml" path="/evidences/sha256sum.txt" method="get" %}
https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml
{% endopenapi %}
