---
description: "The Darknyx API surface at a glance: the two-layer auth model, the REST and WebSocket endpoints, and a quick start."
---


# Programmatic Access

{% hint style="info" %}
**TL;DR**

Darknyx exposes a **REST + WebSocket API** from the confidential-VM deployment.
Authentication is **two layers**: an account **bearer token** (who is
allowed to talk to the venue) plus a per-order **trading-key signature** (who
cryptographically owns the order). Market and health reads are public; private
state and order management are authenticated. The Node SDK and daemon first
verify the enclave's boot-scoped RA-TLS certificate on the connection they will
use; only then do they disclose credentials or order intent.
{% endhint %}

## The authentication model

Two independent layers gate the API. They answer different questions and you
need both to trade.

| Layer | Credential | Answers | Used on |
|---|---|---|---|
| **Account** | Bearer token from `POST /auth/token` | "Is this caller allowed to use the venue?" (rate-limiting, audit) | Every authenticated request, as `Authorization: Bearer <token>` |
| **Order** | Ed25519 **trading-key** signature over the canonical order body | "Who cryptographically owns this order?" | Every place / cancel / modify |

The separation is deliberate. One account may operate many trading keys (sub-
portfolios, a market-maker fleet), and the **trading key, not the account, is
the cryptographic identity** that authorizes settlement. The bearer token only
enables operational controls; it cannot, by itself, move or cancel another key's
orders.

See [Authentication](/api-reference/getting-started/authentication) for the full credential model and
[Place Order](/api-reference/orders/place-order) for how the order signature is constructed.

## Available APIs

| Surface | Use it for |
|---|---|
| **REST** | One-off calls, cold starts, snapshots: auth, instruments, order management, account state via Merkle proofs, transparency, settlement status. |
| **WebSocket** | Long-running clients: order operations plus `orders`, `fills`, and `tree` subscriptions multiplexed over one `/v1/stream` session. |

REST is simplest to start with. A long-running trading client should use one
warm, in-band-authenticated `/v1/stream` connection for order operations and
subscribe to lifecycle and fill events. Sequence numbers let it detect gaps and
reconcile after reconnecting.

## Endpoint map

### REST

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/auth/token` | public | Exchange API credentials for a bearer token |
| `POST` | `/auth/token/revoke` | bearer | Revoke the calling token |
| `GET` | `/instruments` | public | List tradable markets |
| `GET` | `/instruments/{symbol}` | public | One market's metadata |
| `POST` | `/orders` | bearer + sig | Place an order |
| `DELETE` | `/orders/{order_id}` | bearer + sig | Cancel an order |
| `PUT` | `/orders/{order_id}` | bearer + sig | Modify (atomic cancel + replace) |
| `GET` | `/orders/{order_id}` | bearer | Order status |
| `GET` | `/account` | bearer | Open orders owned by the account |
| `GET/PUT` | `/account/settings` | bearer | Account stream preferences |
| `GET` | `/tree/root` | public | Current Merkle root of a shard |
| `GET` | `/tree/inclusion` | bearer | Inclusion proof for a note commitment |
| `GET` | `/tree/leaves` | bearer | Paginated leaf read |
| `GET` | `/transparency` | public | Proof-of-reserves + engine identity + stats |
| `GET` | `/settlement/status/{batch_id}` | bearer | On-chain settlement status of a batch |
| `POST` | `/admin/accounts` | admin bearer | Provision an API account |
| `POST` | `/admin/accounts/{api_key}/disable` | admin bearer | Suspend an account immediately |
| `POST` | `/admin/accounts/{api_key}/enable` | admin bearer | Reinstate a suspended account |
| `POST` | `/admin/accounts/{api_key}/revoke-tokens` | admin bearer | Invalidate the account's current tokens |
| `GET/POST/DELETE` | `/admin/drain` | admin bearer | Inspect, begin, or cancel a planned-stop drain |
| `GET` | `/admin/metrics/settlement` | admin bearer | Bounded settlement queue, throughput, and latency telemetry |
| `GET` | `/system/status` | public | Liveness / degraded-mode snapshot |
| `GET` | `/time` | public | Server slot + unix time |
| `GET` | `/transport-attestation` | public | Quote binding the live TLS certificate, boot, image and signer set |
| `GET` | `/attestation` | public | TDX attestation quote |
| `GET` | `/info` | public | Running image identity (compose hash, app id, signer) |
| `GET` | `/health` | public | Liveness probe |

### WebSocket

| Path | Direction | Purpose |
|---|---|---|
| `/v1/stream` | bidirectional | In-band login; framed order operations; `orders`, `fills`, and `tree` subscriptions; cancel-on-disconnect |

Open `/v1/stream` without query credentials and authenticate with an `op: login`
frame within 10 seconds. The SDK multiplexes all channels and order operations
on that session, refreshes tokens in-band, and reconnects/resubscribes when the
connection drops.

## Quick start

```ts
import { createVerifiedTransport } from "@darknyx/sdk/transport-node";

// Obtain these pins from the independently approved release and finalized
// VaultConfig, not from the server you are about to verify.
const transport = await createVerifiedTransport({
  baseUrl: process.env.DARKNYX_URL!,
  deps: verifierDependencies,
  expectedComposeHash,
  expectedSignerSetSha256,
  createWebSocket,
});

const tokenResponse = await transport.fetch(
  new URL("/auth/token", process.env.DARKNYX_URL!),
  {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ api_key, api_secret, passphrase }),
  },
);
const { access_token } = (await tokenResponse.json()) as {
  access_token: string;
};

const instruments = await transport.fetch(
  new URL("/instruments", process.env.DARKNYX_URL!),
);

const account = await transport.fetch(
  new URL("/account", process.env.DARKNYX_URL!),
  { headers: { authorization: `Bearer ${access_token}` } },
);
// Pass transport.fetch and transport.webSocketFactory to the SDK order and
// stream clients so every private operation stays on the verified transport.
```

The verifier dependency and pin-loading setup is deployment-specific; the
reference daemon is the complete integration example. Raw `curl` is useful for
public diagnostics only after an operator has independently verified the
endpoint. Do not use `curl -k` or disable Node TLS verification for credentials
or orders: accepting an arbitrary self-signed certificate removes the RA-TLS
guarantee.

{% hint style="success" %}
**Use the SDK**

A raw place-order body is large: it includes a note commitment, a 256-byte
zero-knowledge input proof, the note opening needed for intake validation, a
contributory viewing key, and the current boot session, all of which the **TypeScript SDK** signs
for you from your keys and a deposited note. Hand-building the body is possible
(the wire contract is documented), but the SDK is the intended path. See
[SDK → TypeScript Client](../sdk/typescript-client.md).
{% endhint %}

{% hint style="warning" %}
The browser trader is currently deferred and is not the supported access path.
Its prototype relays sensitive traffic through an ordinary trader host, so the
programmatic trust model above must not be assumed for browser sessions.
{% endhint %}

## Rate limits

Credential verification and authenticated order management have separate,
per-account limits. Cache bearer tokens for their lifetime, back off on `429`
(order-operation responses include `Retry-After`; authentication errors include
an approximate delay in the message), and prefer the shared `/v1/stream`
session for high-frequency order management. Authentication can also return a
short-lived `503` when expensive credential verification is at capacity. See
[System Status](/api-reference/system/system-status) for how the venue signals
degradation.
