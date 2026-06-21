---
sidebar_position: 1
title: Base URLs
description: Where the Nyx API lives, the common request and response conventions, and the health and time endpoints.
---

# Base URLs

:::info TL;DR
Every endpoint — REST and WebSocket — is served by the **same enclave gateway**
over RA-TLS. There is no separate gateway tier in the trust path: TLS terminates
inside the attested VM. Use the gateway origin for HTTPS and the same origin
(swap the scheme to `wss://`) for WebSocket.
:::

## The gateway

Nyx is served directly by the confidential VM behind a TLS endpoint whose
certificate key is generated inside the enclave and never leaves it (see
[Transport & Attestation](./transport-and-attestation)). A single origin serves
everything:

```text
HTTPS    https://<gateway-host>
WebSocket wss://<gateway-host>
```

- REST paths are mounted at the root (`/auth/token`, `/orders`, `/instruments`, …).
- WebSocket paths are mounted at the same root (`/ws/trading`, `/ws/orders`,
  `/ws/fills`); connect with the `wss://` scheme.

The exact host for a given deployment is published with that deployment. The
identity of the code behind the host is independently verifiable — see
[`/info` and `/attestation`](./transport-and-attestation).

## Common headers

| Header | When | Value |
|---|---|---|
| `Authorization` | authenticated requests | `Bearer <access_token>` from `POST /auth/token` |
| `Content-Type` | requests with a body | `application/json` |

WebSocket upgrades cannot set an `Authorization` header from a browser, so the
WebSocket routes also accept the bearer token as a `?token=` query parameter.

## Response conventions

REST handlers return JSON. A successful read returns the resource directly; a
successful write returns a small result object (for example, a placed order
returns `{ "order_id", "status", "arrival_slot" }`).

Errors return an HTTP status code that encodes the class of failure, with a
plain-text or JSON message describing the specific reason:

| Status | Meaning |
|---|---|
| `400 Bad Request` | Malformed input: bad hex, wrong field width, a field that fails a field-element safety check, a zero order id. |
| `401 Unauthorized` | Missing or invalid bearer token. |
| `403 Forbidden` | The trading-key signature did not verify, or the caller does not own the order. |
| `404 Not Found` | No such order / batch / instrument. |
| `409 Conflict` | Duplicate order id, or a replay-protection nonce that did not advance. |
| `429 Too Many Requests` | Rate limited — back off and retry. |
| `503 Service Unavailable` | A required subsystem (matching or settlement) is not available; see `/system/status`. |

See [Error Codes](../reference/error-codes) for the full catalogue of conditions
per status.

## Health

```text
GET /health
```

A liveness probe. Returns `200` with the process uptime when the gateway is up.
Use it for load-balancer health checks; use [`/system/status`](../reference/system-status)
for a richer, trading-relevant readiness signal (is matching running, is
settlement wired).

## Server time

```text
GET /time
```

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

:::tip Order expiry is slot-based
Nyx orders expire at a **Solana slot**, not a wall-clock timestamp. To place a
"good for the next ten minutes" order, read `/time`, project the wall-clock
target onto a slot using the current slot as the anchor (Solana targets roughly
400 ms per slot), and pass that as `expiry_slot`. The SDK does this conversion
for you. See [Time in Force](../trading-concepts/time-in-force).
:::
