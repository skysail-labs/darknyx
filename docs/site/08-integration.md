---
sidebar_position: 1
title: Integration
description: The end-to-end lifecycle of trading on Nyx — register, deposit, trade, follow your fills, merge, and withdraw — and the identities and SDK that tie it together.
---

# Integration

:::info TL;DR
A full trade on Nyx is: **register** an account, **deposit** into notes,
**place** signed orders to the enclave, **follow** your fills over a live
stream, and **withdraw** with your own proof. Custody steps (register, deposit,
merge, withdraw) are Solana transactions; trading steps go to the enclave over
HTTPS. The SDK does the proofs, the signing, and the attestation check for you.
:::

## Three identities

Nyx deliberately keeps three identities separate, all derived from one seed on
your device:

| Identity | Used for | Seen by |
|---|---|---|
| **Wallet key** | Solana transactions (deposit, withdraw) | Solana |
| **Trading key** | Signing orders to the enclave | The enclave (but never linked to your wallet) |
| **Account credentials** | A throwaway token for rate-limiting | The enclave (operational only) |

Keeping the trading key distinct from the wallet is what gives you *trader
privacy* — the enclave authorizes your trades without ever learning which wallet
is behind them.

## The lifecycle

```text
   register ──▶ deposit ──▶ place order ──▶ (fills stream) ──▶ withdraw
                  │              │                                 ▲
                  └── merge ─────┘  (consolidate notes for size)   │
                                                                   │
                            partial fills continue automatically ──┘
```

### 1. Register

Record your account commitment on-chain once. This is the "open an account"
step; it carries a `VALID_WALLET_CREATE` proof and reveals nothing about you.

### 2. Deposit

Move tokens from your wallet into a fresh **note**. The deposit carries a
`VALID_INPUT` proof binding the note to its declared mint and amount. After it
confirms, the SDK records the note (its position in the tree and its opening) so
your wallet view and coin-selection can see it.

### 3. Place an order

Build an order — symbol, side, size, limit price — and sign its canonical body
with your **trading key**. The order also carries the opening of the note backing
it and a small **anchor pool** (pre-committed continuation tags). Submit it to
the enclave; it rests in the hidden book until a batch auction crosses it.

:::tip Orders larger than one note
An order can only be as large as the note backing it. To trade more, **merge**
several notes into one first (a Solana transaction with a `VALID_MERGE` proof) —
including the change notes that pile up from partial fills.
:::

### 4. Follow your fills

Order intent never appears on-chain, so you follow fills through the enclave:

- Subscribe to the per-account `/ws/fills` WebSocket — each fill arrives the
  moment it settles, with everything needed to store the resulting change note.
- For history or to recover after a disconnect, the off-enclave indexer serves
  your fills **by order ID** (derived from your own seed), so the SDK can
  "backfill then tail."

Partial fills continue on their own: the matcher rotates your residual forward
using the next anchor and re-matches it on the following tick — no resubmission.

### 5. Withdraw

When you want out, burn a note back to wallet tokens with a `VALID_SPEND` proof.
If you withdraw less than the note's full value, the proof also creates a change
note for the remainder. This step needs nothing but your seed and the on-chain
tree — the enclave is not in the loop.

## What the SDK handles

The TypeScript SDK is the integration surface. It:

- **generates your proofs** locally (wallet, deposit, withdraw, merge) so your
  spending key never leaves the device;
- **verifies the enclave's attestation** before trusting it — one call that
  checks the Intel-signed quote against the keys and image registered on-chain;
- **signs orders** with your trading key over the exact canonical body the
  enclave expects;
- **builds and tracks notes** — recovering each note's tree position from the
  on-chain event, so a fill is always spendable;
- **manages the fills stream** — the backfill-then-tail flow, change-note
  reconstruction, and dedup across the live and historical paths.

You bring your own Solana RPC; the SDK doesn't run one.

:::caution Verify before you trade
The attestation check is not optional theater — it's the step that proves you're
talking to the real, measured enclave and not an impostor. Always run it before
sending order data. The SDK makes it a single call; see
[Trust model](./trust-model).
:::

## The wire contract

The exact endpoints, request/response shapes, auth headers, and the live fills
stream are in the [API reference](./api-reference). Field encodings and the
canonical order body are enforced byte-for-byte between the SDK and the enclave
— use the SDK builders rather than hand-rolling requests.
</content>
