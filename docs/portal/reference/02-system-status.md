---
sidebar_position: 2
title: System Status
description: How Nyx signals readiness and degraded mode — check it before trading and back off when subsystems are down.
---

# System Status

:::info TL;DR
`GET /system/status` is a public readiness snapshot: is matching running, is
settlement wired, is an oracle attached, and what slot the engine is on. A
`degraded` flag tells you, in one boolean, whether to back off before you hit a
write failure.
:::

## GET /system/status

```text
GET /system/status
```

Public — no authentication.

### Response

```json
{
  "degraded": false,
  "matcher_running": true,
  "settle_enabled": true,
  "oracle_configured": true,
  "current_slot": 309482113,
  "nyx_version": "…"
}
```

| Field | Type | Description |
|---|---|---|
| `degraded` | boolean | `true` when matching **or** settlement is unavailable. The one flag to gate trading on. |
| `matcher_running` | boolean | The matching tick is running (orders can be accepted and matched). |
| `settle_enabled` | boolean | The on-chain settlement pipeline is wired (matches will settle). |
| `oracle_configured` | boolean | A price oracle is attached (the clearing-price reference). |
| `current_slot` | integer | The engine's current view of the Solana slot. |
| `nyx_version` | string | The running engine's build version. |

## When degradation occurs

The venue is `degraded` when a core subsystem is not available — for example, the
matching tick is not running, or the settlement pipeline is not wired. While
degraded, order submission may fail with `503 Service Unavailable`.

## How it manifests

| Surface | Behavior under degradation |
|---|---|
| REST order management | May return `503`; reads (`/instruments`, `/transparency`, `/tree/*`) generally remain available. |
| WebSocket trading | An `order.place` / `order.cancel` / `order.modify` frame may return an `error` with `code: 503`. |
| `/health` | Still returns `200` (the gateway process is up) — which is why `/system/status` is the better readiness signal for a trading client. |

## Best practices

- **Gate trading on `degraded`.** Check `/system/status` before a burst of order
  activity and pause when `degraded` is `true`.
- **Use it, not `/health`, for readiness.** `/health` answers "is the process
  up"; `/system/status` answers "can I trade right now."
- **Back off and poll.** On a `503`, poll `/system/status` and resume when matching
  and settlement are both available again.
- **Surface it.** It is public and leaks nothing, so it is safe to show on a status
  page or wire into client-side health checks.
