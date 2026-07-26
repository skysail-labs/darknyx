---
description: "How Darknyx signals readiness and degraded mode, so you can check it before trading and back off when subsystems are down."
---


# System Status

{% hint style="info" %}
**TL;DR**

`GET /system/status` is a public readiness snapshot: is matching running, is
settlement wired, is an oracle attached, and what slot the engine is on. A
`degraded` flag tells you, in one boolean, whether to back off before you hit a
write failure.
{% endhint %}

## GET /system/status

```text
GET /system/status
```

Public, with no authentication.

### Response

```json
{
  "degraded": false,
  "matcher_running": true,
  "settle_enabled": true,
  "oracle_configured": true,
  "current_slot": 309482113,
  "version": "…"
}
```

| Field | Type | Description |
|---|---|---|
| `degraded` | boolean | `true` when matching **or** settlement is unavailable. The one flag to gate trading on. |
| `matcher_running` | boolean | The matching tick is running (orders can be accepted and matched). |
| `settle_enabled` | boolean | The on-chain settlement pipeline is wired (matches will settle). |
| `oracle_configured` | boolean | A price oracle is attached (the clearing-price reference). |
| `current_slot` | integer | The engine's current view of the Solana slot. |
| `version` | string | The running engine's build version. |

## When degradation occurs

The venue is `degraded` when a core subsystem is unavailable: the matching tick
is not running, the settlement pipeline is not wired, or the finalized
governance/signer view no longer matches the boot-approved configuration. On a
multi-market venue, a governed-market mismatch pauses new trading venue-wide
rather than leaving some books running against uncertain authority.

While degraded, new place and modify operations fail closed with `503 Service
Unavailable`. Cancels, authenticated reads, and reconciliation continue so a
trader can reduce risk and the engine can resolve already-pending settlements.

## How it manifests

| Surface | Behavior under degradation |
|---|---|
| REST order management | New place/modify may return HTTP `503` with stable code `5001`; cancel remains available. Reads (`/instruments`, `/transparency`, `/tree/*`) generally remain available. |
| WebSocket trading | `order.place` / `order.modify` may return an `error` with `code: 5001`; cancellation remains available. |
| `/health` | Still returns `200` (the gateway process is up), which is why `/system/status` is the better readiness signal for a trading client. |

## Best practices

- **Gate trading on `degraded`.** Check `/system/status` before a burst of order
  activity and pause when `degraded` is `true`.
- **Use it, not `/health`, for readiness.** `/health` answers "is the process
  up"; `/system/status` answers "can I trade right now."
- **Back off and poll.** On a `503`, poll `/system/status` and resume when matching
  and settlement are both available again.
- **Surface it.** It is public and leaks nothing, so it is safe to show on a status
  page or wire into client-side health checks.
