---
description: "Where the Darknyx API lives, the common request and response conventions, and the health and time endpoints."
---


# Base URLs

{% hint style="info" %}
**TL;DR**

Engine REST and WebSocket endpoints are served from the same RA-TLS origin. The
Darknyx engine terminates TLS itself with a boot-random, attestation-bound key;
the dstack `s`-suffix route passes that TLS stream through without terminating
it. Use the HTTPS origin for engine REST and swap the scheme to `wss://` for the
shared stream. Static `/evidences/*` files are served separately by dstack
infrastructure and are supporting artifacts, not proof of the live engine
socket.
{% endhint %}

## The RA-TLS origin

The public hostname routes raw TLS to port `8443` inside the Darknyx CVM. Its
certificate is self-signed by design: clients authenticate its public key with
`GET /transport-attestation`, not with a public certificate authority. A single
verified origin serves the engine API:

```text
HTTPS     https://<app-id>-8443s.dstack-pha-<node>.phala.network
WebSocket wss://<app-id>-8443s.dstack-pha-<node>.phala.network
```

- REST paths are mounted at the root (`/auth/token`, `/orders`, `/instruments`, …).
- The sole WebSocket path is `/v1/stream`; connect with the `wss://` scheme and
  authenticate in-band with `op: login`.

The exact host and approved measurement are published with the reviewed
release. The `s` suffix selects TLS passthrough; omitting it reaches a different
gateway-terminated transport and is not equivalent. Verify the connection
before authentication as described in
[Transport & Attestation](./transport-and-attestation.md).

{% hint style="warning" %}
The browser trader is deferred and not a supported external access path. Its
ordinary trader host has a different trust boundary and must not be assumed to
inherit the direct SDK/daemon guarantee described here.
{% endhint %}

## Common headers

| Header | When | Value |
|---|---|---|
| `Authorization` | authenticated requests | `Bearer <access_token>` from `POST /auth/token` |
| `Content-Type` | requests with a body | `application/json` |

The `/v1/stream` WebSocket upgrades without credentials; authenticate afterward
with an in-band `login` frame so bearer tokens never appear in URLs.

## Response conventions

REST handlers return JSON. A successful read returns the resource directly; a
successful write returns a small result object (for example, a placed order
returns `{ "order_id", "status", "arrival_slot" }`).

Errors return an HTTP status code plus a structured JSON
`{ "code": <number>, "message": <string> }` body. Every REST response also
carries `x-request-id` for support correlation.

| Status | Meaning |
|---|---|
| `400 Bad Request` | Malformed input: bad hex, wrong field width, a field that fails a field-element safety check, a zero order id. |
| `401 Unauthorized` | Missing or invalid bearer token. |
| `403 Forbidden` | The trading-key signature did not verify, the caller does not own the order, the route requires admin, or the account is suspended. |
| `404 Not Found` | No such order / batch / instrument. |
| `409 Conflict` | Duplicate order id, or a replay-protection nonce that did not advance. |
| `429 Too Many Requests` | Rate limited. Back off and retry. |
| `503 Service Unavailable` | New trading is paused because a required subsystem or finalized governance view is unavailable; a requested tree shard's mirror is unsafe; or credential verification is momentarily at capacity. |

See [Error Codes](error-codes.md) for the full catalogue of conditions
per status.

## Health

{% openapi src="https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml" path="/health" method="get" %}
https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml
{% endopenapi %}

A liveness probe. Returns `200` with the process uptime when the engine is up.
Use it for load-balancer health checks; use [`/system/status`](../system/system-status.md)
for a richer, trading-relevant readiness signal (is matching running, is
settlement wired).

## Server time

{% openapi src="https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml" path="/time" method="get" %}
https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml
{% endopenapi %}

Returns the venue's current Solana slot and wall-clock time. Use it to convert a
wall-clock "good-till-time" into an `expiry_slot` without running your own RPC,
and for clock-skew diagnostics.

```json
{
  "slot": 309482113,
  "unix_ms": 1839975000123
}
```

| Field | Type | Description |
|---|---|---|
| `slot` | integer | The TEE's current view of the Solana slot. |
| `unix_ms` | integer | Server wall-clock time, milliseconds since the Unix epoch. |

{% hint style="success" %}
**Order expiry is slot-based**

Darknyx orders expire at a **Solana slot**, not a wall-clock timestamp. To place a
"good for the next ten minutes" order, read `/time`, project the wall-clock
target onto a slot using the current slot as the anchor (Solana targets roughly
400 ms per slot), and pass that as `expiry_slot`. The SDK does this conversion
for you. See [Time in Force](/documentation/trading-concepts/time-in-force).
{% endhint %}
