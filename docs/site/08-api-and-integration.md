# API and integration

> Nyx's TEE exposes a small HTTPS surface for clients: a public
> health/info/attestation set, a bearer-token issuance endpoint, an
> authenticated orders + settlement-status surface, and a feature-
> gated debug endpoint used only during development. The full wire
> contract is pinned in `docs/tee-api-openapi.yaml`; this page is
> the narrative-level walkthrough.

---

## The endpoint map

| Method | Path | Auth | Lands in PR |
|---|---|---|---|
| GET | `/health` | public | 4d |
| GET | `/info` | public | 4d |
| GET | `/attestation` | public | 4d |
| POST | `/auth/token` | public | 4e.2 |
| POST | `/orders` | bearer + signature | 4e.3 |
| DELETE | `/orders/{id}` | bearer + signature | 4e.3 |
| GET | `/orders/{id}` | bearer | 4e.3 |
| GET | `/settlement/status/{batch_id}` | bearer | 4g.1 |
| POST | `/__debug/oracle/seed` | feature-gated, no auth | 4f.1 |

The `__debug` route is only compiled when the `debug_endpoints`
cargo feature flag is on; production builds don't ship it.

---

## Authentication: a two-layer model

Every authenticated request goes through both layers:

### Layer A — Bearer JWT (operational)

The user calls `POST /auth/token` with their account credentials:

```http
POST /auth/token HTTP/1.1
Content-Type: application/json

{
  "api_key":    "your-api-key",
  "api_secret": "your-api-secret",
  "passphrase": "your-passphrase"
}
```

The TEE responds with a short-lived JWT:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type":   "Bearer",
  "expires_in":   3600
}
```

The JWT is HS256-signed with a 32-byte secret derived inside the
TEE via `dstack.get_key("nyx/jwt-secret/v1", "jwt")`. The user
includes it in subsequent requests:

```http
POST /orders HTTP/1.1
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

The TEE's bearer middleware validates the JWT (signature +
expiration) before the request body is even parsed. Failures
return `401 Unauthorized`.

Layer A is **operational** — it enables rate-limiting,
audit logging, and account-level blocking. It does **not**
authorize specific operations on specific funds.

### Layer B — Trading-key Ed25519 signature (cryptographic)

Every order body is signed with the user's trading-key Ed25519
keypair. The signature is over the SHA-256 of the canonical body
bytes:

```text
canonical_body =
    "nyx-order-v1"
 || symbol_len_u8
 || symbol_bytes
 || side_byte
 || order_type_byte
 || amount_le_u64
 || price_limit_le_u64
 || min_fill_size_le_u64
 || expiry_slot_le_u64
 || order_id_16
 || note_commitment_32
 || user_commitment_32
 || arrival_nonce_le_u64

signature = ed25519_sign(SHA-256(canonical_body), trading_key)
```

The order body sent to the TEE includes both the trading-key
pubkey AND the signature:

```json
{
  "symbol": "SOL-USDC",
  "side": "bid",
  "order_type": "limit",
  "amount": 10000000,
  "price_limit": 150000000,
  "min_fill_size": 0,
  "expiry_slot": 320145000,
  "order_id": "11111111111111111111111111111111",
  "note_commitment": "ef0d8b6f...",
  "user_commitment": "fcb31d19...",
  "arrival_nonce": 42,
  "trading_key": "abc12345...",
  "trading_key_signature": "def67890..."
}
```

The TEE's `POST /orders` handler verifies the signature using
`ed25519_dalek::VerifyingKey::verify_strict(...)` BEFORE accepting
the order into the matcher's book. Failures return `403 Forbidden`.

Layer B is **cryptographic** — it authorizes a specific operation
on specific funds. The trading-key pubkey is what ends up in the
on-chain settle's `MatchResult.owner_buyer` / `owner_seller`
field; the on-chain verifier checks that signature too. So even if
Layer A is compromised, Layer B independently prevents
unauthorized orders.

---

## Why two layers

The two layers solve different problems:

| Concern | Layer A handles | Layer B handles |
|---|---|---|
| Rate limiting | ✅ (per account) | ❌ (per trading key, which is ephemeral) |
| Account blocking | ✅ | ❌ |
| Audit logs | ✅ (account_id is on every log) | ⚠️ (only trading_key visible) |
| Custody authorization | ❌ | ✅ |
| Cross-account replay protection | ✅ (per-account session token) | ✅ (signature binds to order_id) |
| Front-running protection (if Layer A leaks) | ❌ | ✅ |

A single layer can't do both because they have different
identity models. The account is operational (linked to the
user's API credentials, persistent across sessions); the trading
key is cryptographic (linked to the user's funds, ephemeral by
design).

The same shape is used by godarkdex and other dark-pool venues
where this distinction matters.

---

## Order lifecycle

```text
1. Client constructs an order intent
   - Selects (symbol, side, amount, price_limit)
   - Derives a fresh order_id (UUID v4)
   - Builds the canonical body bytes
   - Signs with the trading-key Ed25519 keypair
   - Wraps in JSON with the bearer token

2. Client POSTs /orders
   - TEE verifies the bearer → 401 on fail
   - TEE verifies the signature → 403 on fail
   - TEE inserts into the in-memory OrderBook
   - Responds 202 Accepted with {order_id, status: "accepted"}

3. Matcher tick (every BATCH_MS)
   - Snapshots the book
   - Reads oracle
   - Computes clearing price
   - Matches FIFO at clearing price
   - Emits RunBatchOutput on mpsc

4. Settle scheduler picks up the batch
   - Each match flows through the 5-tx pipeline
   - GET /settlement/status/{batch_id} reflects progress
     ("queued" → "locking_notes" → ... → "done" or "failed")

5. Client polls GET /orders/{id} for fill status
   - Status fields:
     * pending  — in the book, not yet matched
     * matched  — matched, settle in progress
     * filled   — settle confirmed on-chain
     * expired  — expiry_slot reached without filling
     * cancelled — user cancelled before fill

6. Client polls GET /settlement/status/{batch_id} for on-chain
   confirmation
   - Returns array of per-match jobs with current stage + tx sigs

7. Client computes the user's new note from the on-chain
   TradeSettled event
   - The note's plaintext is reconstructed from the user's wallet
     key + the per-note nonce/blinding pair
   - The new note is now spendable via VALID_SPEND withdraw
```

---

## Cancellation

A user can cancel any of their open orders by submitting a signed
cancel request:

```http
DELETE /orders/{order_id} HTTP/1.1
Authorization: Bearer eyJ...

{
  "trading_key": "abc12345...",
  "cancel_nonce": 1,
  "trading_key_signature": "..."
}
```

The cancel body's signature is over a different canonical form:

```text
"nyx-cancel-v1" || order_id_16 || trading_key_32 || cancel_nonce_le_u64
```

The TEE verifies:
1. The bearer token is valid (Layer A)
2. The signature is from the SAME trading-key that owns the order
3. The cancel_nonce hasn't been seen before for this trading_key

Cancellation is cryptographically bound to the original order — an
attacker who knows the order_id can't cancel an order they don't
own. The same property the on-chain `cancel_order` ix enforces via
PDA seed checks.

---

## Order types

| Type | Behavior |
|---|---|
| `limit` | Stays in the book until matched, cancelled, or expired |
| `ioc` (Immediate-or-Cancel) | Matches against the next batch; any unmatched residual is cancelled |
| `fok` (Fill-or-Kill) | Matches fully against the next batch OR is cancelled; no partial fills |

`fok` is the strictest: if the next batch's clearing-price
allocation would only fill, say, 60% of the order, the entire
order is cancelled. `ioc` accepts the partial fill and cancels
only the residual. `limit` keeps the residual in the book for
future batches.

The `min_fill_size` parameter sets a floor for partial fills.
Setting `min_fill_size = amount` is equivalent to `fok` behavior
even on a `limit` order.

---

## Settlement status polling

Once a match settles, the user polls
`GET /settlement/status/{batch_id}` to track on-chain
confirmation:

```http
GET /settlement/status/0 HTTP/1.1
Authorization: Bearer eyJ...
```

Response:

```json
{
  "batch_id": 0,
  "jobs": [
    {
      "batch_id": 0,
      "match_idx": 0,
      "stage": "settling",
      "created_at_ms": 1716951230000,
      "last_transition_at_ms": 1716951232000,
      "lock_buyer_sig": "5XJSj7sP...",
      "lock_seller_sig": "3KMpqQz...",
      "verify_sig": "8vTrSwK...",
      "settle_sig": null,
      "close_sig": null
    },
    {
      "batch_id": 0,
      "match_idx": 1,
      "stage": "done",
      "created_at_ms": 1716951230000,
      "last_transition_at_ms": 1716951234500,
      "lock_buyer_sig": "abc...",
      "lock_seller_sig": "def...",
      "verify_sig": "8vTrSwK...",
      "settle_sig": "ghi...",
      "close_sig": "jkl..."
    }
  ]
}
```

Stages progress through:

```text
queued → locking_notes → proving → verifying → settling → closing → done
                                                       ↘ failed { reason }
```

Each stage emits a discrete status the client can render in a
progress UI. Failures carry a human-readable reason; operators
consume them via the same endpoint.

---

## SDK shape

The TypeScript SDK (in `packages/sdk`) provides typed wrappers
for each endpoint:

```ts
import { NyxClient } from '@nyx/sdk';

const client = new NyxClient({
  endpoint: 'https://tee.nyx.example.com',
  apiKey: 'your-api-key',
  apiSecret: 'your-api-secret',
  passphrase: 'your-passphrase',
});

// Layer A handled automatically — bearer cached across calls
const order = await client.submitOrder({
  symbol: 'SOL-USDC',
  side: 'bid',
  amount: 10_000_000n,
  priceLimit: 150_000_000n,
  expirySlot: currentSlot + 1_000_000n,
  noteCommitment,
  userCommitment,
  // SDK derives the signature internally from the trading key
});

// Poll for fill
const filled = await client.waitForFill(order.orderId);

// Poll for on-chain settlement
const settled = await client.waitForSettleConfirmation(filled.batchId);

// Compute new spendable note
const newNote = await client.deriveChangeNote(settled.matchPair);
```

The SDK handles:
- Bearer caching (one bearer for the session; auto-refresh on expiry)
- Canonical-body construction + Ed25519 signing
- TEE attestation verification on first connection
- Polling helpers with exponential backoff

Source: `packages/sdk/src/` is the public API.

---

## Rate limiting

Layer A enables rate-limit enforcement at the account level.
Defaults (configurable per-deployment):

| Endpoint | Limit | Window |
|---|---|---|
| `POST /auth/token` | 5 requests | 60 seconds |
| `POST /orders` | 100 requests | 10 seconds |
| `DELETE /orders/{id}` | 100 requests | 10 seconds |
| `GET /orders/{id}` | 1000 requests | 10 seconds |
| `GET /settlement/status/{id}` | 1000 requests | 10 seconds |

The rate-limit is enforced at the bearer middleware layer (Layer
A), so an attacker spamming with bad bearers gets 401-throttled
before the body is parsed.

A future PR adds per-account customisation (institutional
accounts get higher limits) and IP-based pre-throttle for
unauthenticated `/auth/token` traffic.

---

## Attestation flow from a client's perspective

Before a client sends any orders, it should verify the TEE's
attestation. The SDK's `verifyTeeAttestation()` does this in three
steps:

```ts
// Step 1: Fetch TEE info + a fresh attestation quote
const info = await client.fetchInfo();
const nonce = randomBytes(32);
const attestation = await client.fetchAttestation(nonce);

// Step 2: Verify the TDX quote via dcap-qvl
//   (locally if you have the binary; otherwise via Phala's
//    verification API)
const quoteVerification = await dcapVerify(attestation.quote);
if (!quoteVerification.valid) throw new Error('TDX quote invalid');

// Step 3: Cross-check against on-chain state
const vaultConfig = await fetchVaultConfig(solanaRpc);
if (vaultConfig.tee_pubkey !== attestation.tee_pubkey) {
  throw new Error('TEE pubkey mismatch');
}
if (vaultConfig.tee_compose_hash !== quoteVerification.compose_hash) {
  throw new Error('TEE compose_hash mismatch');
}

// Step 4: Verify the report_data binding
const expectedBinding = sha256(attestation.tee_pubkey);
if (attestation.report_data.slice(32, 64) !== expectedBinding) {
  throw new Error('Report data binding mismatch');
}
if (attestation.report_data.slice(0, 32) !== nonce) {
  throw new Error('Quote not fresh for our nonce');
}

// All four steps passed; we trust this TEE
client.markTrusted();
```

This flow runs ONCE per session (or per attestation rotation).
The resulting trust state is cached client-side. Subsequent
requests use the same bearer token without re-attesting.

---

## Wire-format reference

The full machine-readable wire contract is in
`docs/tee-api-openapi.yaml`. It's an OpenAPI 3.1 schema covering:

- Every endpoint's request and response shapes
- Every error code and its associated body shape
- Authentication schemes (bearer)
- Server URL templates
- Example values

The schema is consumed by:
- The Rust handler code (verified to match via a wire-format
  test in `tests/orders_surface.rs`)
- The TypeScript SDK (generated via `openapi-typescript`)
- Auto-generated documentation pages on the site

Any change to the wire format requires updating the YAML + the
SDK + the Rust handlers + the parity tests in a single commit.
CLAUDE.md §6 documents the byte-equality contracts.

---

*Last updated 2026-05-29. Source of truth:
`docs/tee-api-openapi.yaml`, `crates/nyx-tee/src/api/`,
`docs/tee-architecture.md` §11.*
</content>
