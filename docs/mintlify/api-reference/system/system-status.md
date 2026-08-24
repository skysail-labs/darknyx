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

{% openapi src="https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml" path="/system/status" method="get" %}
https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml
{% endopenapi %}

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
| `degraded` | boolean | `true` when settlement is unavailable, global readiness fails, or at least one market is paused. |
| `matcher_running` | boolean | At least one market can currently accept and match orders. |
| `settle_enabled` | boolean | The on-chain settlement pipeline is wired (matches will settle). |
| `oracle_configured` | boolean | A price oracle is attached (the clearing-price reference). |
| `current_slot` | integer | The engine's current view of the Solana slot. |
| `version` | string | The running engine's build version. |

## When degradation occurs

The venue is `degraded` when a core subsystem is unavailable: the matching tick
is not running, the settlement pipeline is not wired, or the finalized
governance/signer view no longer matches the boot-approved configuration. On a
multi-market venue, a governed-market mismatch pauses new trading venue-wide
rather than leaving some books running against uncertain authority. An oracle
failure is narrower: it pauses only markets bound to the affected feed. In that
partial state `degraded` is true, `matcher_running` can remain true, and each
`/instruments` entry reports its own `trading_enabled` value.

Under a venue-wide readiness failure, new place and modify operations fail
closed with `503 Service Unavailable` for every market. Under market-local
oracle degradation, only place/modify for the affected market fails; a healthy
symbol whose own `trading_enabled` remains true can continue even while the
venue-level `degraded` summary is true. Cancels, authenticated reads, and
reconciliation continue so a trader can reduce risk and the engine can resolve
already-pending settlements.

## How it manifests

| Surface | Behavior under degradation |
|---|---|
| REST order management | New place/modify may return HTTP `503` with stable code `5001`; cancel remains available. Reads (`/instruments`, `/transparency`, `/tree/*`) generally remain available, except a diverged tree shard fails its `/tree/*` reads closed with `5002`. |
| WebSocket trading | `order.place` / `order.modify` may return an `error` with `code: 5001`; cancellation remains available. |
| `/health` | Still returns `200` (the engine process is up), which is why `/system/status` is the better readiness signal for a trading client. |

## Best practices

- **Use both readiness levels.** Check `/system/status` for venue health, then
  the chosen `/instruments/{symbol}` entry's `trading_enabled` value. Always
  handle a racing `503` from place/modify. Do not block a healthy symbol merely
  because another market makes the venue-level `degraded` summary true.
- **Use it, not `/health`, for readiness.** `/health` answers "is the process
  up"; `/system/status` answers "can I trade right now."
- **Back off and poll.** On a `503`, refresh `/system/status` plus the requested
  instrument. Resume that symbol when its own `trading_enabled` is true; do not
  wait for `degraded=false` when only another market remains paused. A
  venue-wide failure keeps every instrument disabled until global readiness
  recovers.
- **Surface it.** It is public and leaks nothing, so it is safe to show on a status
  page or wire into client-side health checks.
