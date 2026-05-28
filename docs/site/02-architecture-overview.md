# Architecture overview

> Three layers, two boundaries, one trust chain.
> Custody on Solana, matching inside an Intel TDX enclave, clients
> running zero-knowledge proofs locally. Every cross-layer message
> is either an on-chain transaction or a TEE-attested API call;
> there are no hidden side channels.

---

## The three layers

### Layer 1 — Custody (on Solana)

Two Solana programs, both Anchor 0.32:

- **`vault`** (program id `C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx`
  on devnet) — owns the funds, the Merkle tree of UTXO note
  commitments, the nullifier set, the consumed-note set, the
  note-lock set, and the per-batch validity markers.
- **`matching_engine`** (program id `6EasFxo6RCWrK4KAwcdUJqL4KjReLC3rtah8EtHgHSqe`
  on devnet) — owns the on-chain order metadata and the batch
  results buffer. This program is being deprecated in the TEE v2
  migration; matching is moving into the enclave, but the program
  remains for the v1 path and as the on-chain entry point during
  the cutover.

Custody is the only layer that can hold or move user tokens. Every
withdraw requires a VALID_SPEND zero-knowledge proof that proves
the user owns a note in the current Merkle tree, has not previously
spent it (nullifier check), and is generating the correct
change-note commitment. Every settle requires a VALID_MATCH_BATCH
proof that attests the match was valid against the inputs the TEE
declared, plus an Ed25519 signature from the registered TEE pubkey.

### Layer 2 — Matching (inside a TDX CVM)

A single-process Rust daemon, `nyx-tee`, runs inside a Phala Cloud
Confidential Virtual Machine. Inside that process:

```text
nyx-tee  (single Rust process, ~3 GB RAM, ~4 vCPU)
  │
  ├── dstack handshake (boot)
  │   └── derives Ed25519 signer + JWT secret from
  │       dstack-kms-managed root key
  │
  ├── HTTP server (axum on :8080 / TLS on :443 via dstack-ingress)
  │   ├── GET /health, /info, /attestation       (public)
  │   ├── POST /auth/token                       (public)
  │   ├── POST/DELETE/GET /orders                (bearer-protected)
  │   ├── GET /settlement/status/{batch_id}      (bearer-protected)
  │   └── POST /__debug/oracle/seed              (feature-gated)
  │
  ├── matcher driver (tokio interval)
  │   ├── runs every BATCH_MS = 2000 ms
  │   ├── pulls from in-memory OrderBook
  │   ├── pulls oracle snapshot from cache
  │   ├── calls darkpool_matcher::run_batch()
  │   └── emits RunBatchOutput on mpsc channel
  │
  ├── oracle sync (tokio background)
  │   ├── fetches from Pyth Hermes pull oracle every 1 s
  │   ├── verifies Wormhole VAA via secp256k1 ecrecover
  │   └── writes verified prices to OracleCache
  │
  └── settle scheduler (tokio task)
      ├── consumes matches from mpsc channel
      ├── for each match:
      │   ├── builds Tx A (lock_note × 2)
      │   ├── runs in-TEE Groth16 prover (VALID_MATCH_BATCH)
      │   ├── builds Tx B (verify_match_batch) + ALT
      │   ├── builds Tx D (tee_forced_settle_batched)
      │   └── builds Tx E (close_batch_validity_marker)
      └── exposes per-batch status via the HTTP surface
```

The boundary between this layer and Solana is the settle pipeline
(five transactions per batch, documented in
[settlement-pipeline](./settlement-pipeline.md)). The boundary
between this layer and clients is the HTTPS API (documented in
[api-and-integration](./api-and-integration.md)).

### Layer 3 — Client (TypeScript SDK)

The SDK is the user-side bridge. It:

1. Generates the ZK proofs (currently via snarkjs; v3 work explores
   in-browser ark-groth16). The matching prover lives in the TEE;
   user proofs (VALID_INPUT for deposits, VALID_SPEND for
   withdraws, VALID_WALLET_CREATE for wallet registration) stay
   client-side because they involve the user's spending key.

2. Verifies the TEE's attestation chain before trusting any data
   from it. The SDK ships a `verifyTeeAttestation()` function that
   runs against the t16z TEE Attestation Explorer's verification
   logic plus a comparison against the on-chain `vault_config.tee_pubkey`
   and `vault_config.tee_compose_hash`.

3. Signs canonical order bodies with the user's trading-key Ed25519
   keypair (see [api-and-integration](./api-and-integration.md) §
   authentication). The trading key is distinct from the user's
   Solana wallet keypair by construction.

4. Submits Solana transactions through any RPC the user chooses;
   the SDK doesn't operate its own RPC.

---

## Component map

```text
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  USER DEVICE                                                    │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  TypeScript SDK                                          │   │
│  │  ├── ZK provers (VALID_INPUT, VALID_SPEND, ...)         │   │
│  │  ├── Solana tx builders                                  │   │
│  │  ├── TEE attestation verifier                            │   │
│  │  └── HTTPS client + Ed25519 trading-key signer           │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                 │
└──────────────────────────────────────────────────────────────────┘
        │                                          │
        │ Solana RPC                               │ HTTPS
        │ (deposits, withdraws, register)          │ (orders, status)
        ▼                                          ▼
┌────────────────────────────────────────┐   ┌─────────────────────┐
│                                        │   │                     │
│  SOLANA                                │   │  TDX CVM            │
│  ┌──────────────────────────────────┐  │   │  (Phala Cloud)      │
│  │  vault program                   │  │   │                     │
│  │  ├── create_wallet               │  │   │  nyx-tee daemon     │
│  │  ├── deposit                     │  │   │  ├── HTTP / RA-TLS  │
│  │  ├── lock_note                   │◄─┼───┼──┤ matcher driver   │
│  │  ├── verify_match_batch          │  │   │  ├── oracle sync    │
│  │  ├── tee_forced_settle_batched   │  │   │  ├── settle sched   │
│  │  ├── close_batch_validity_marker │  │   │  └── in-TEE prover  │
│  │  └── withdraw                    │  │   │     (VALID_MATCH    │
│  │                                  │  │   │     _BATCH n=16)    │
│  │  STATE:                          │  │   │                     │
│  │  - Merkle tree                   │  │   │  Keys derived from  │
│  │  - nullifier set                 │  │   │  dstack-kms at boot:│
│  │  - consumed-note set             │  │   │  - tee_authority    │
│  │  - VaultConfig (tee_pubkey)      │  │   │    (Ed25519)        │
│  │  - per-batch markers             │  │   │  - JWT secret       │
│  └──────────────────────────────────┘  │   │  - Solana fee-payer │
│                                        │   │    (same key as     │
│  ┌──────────────────────────────────┐  │   │     tee_authority)  │
│  │  matching_engine program         │  │   │                     │
│  │  (deprecating in TEE v2)         │  │   └─────────────────────┘
│  └──────────────────────────────────┘  │            │
└────────────────────────────────────────┘            │
        ▲                                              │
        │                                              │
        └──────────────────────────────────────────────┘
                    settle pipeline (Tx A..E)
                    signed by the TEE keypair
```

---

## The cross-layer messages

### Client → Solana

Three direct interactions:

1. **`create_wallet`** — Register the user's `user_commitment` (the
   Poseidon hash of `spending_key, r_owner`). This is the
   "I am opening an account" moment.

2. **`deposit`** — Move tokens from the user's wallet into a fresh
   note. Requires a VALID_INPUT proof (proves the note is correctly
   formed with the declared mint and amount).

3. **`withdraw`** — Move tokens from a note back to a wallet.
   Requires a VALID_SPEND proof (proves note ownership, generates a
   nullifier to prevent double-spend, and creates a change-note
   commitment if the withdrawal amount is less than the note's
   full value).

### Client → TEE

Three interactions, all via HTTPS + JWT bearer auth:

1. **`POST /auth/token`** — Exchange `(api_key, api_secret, passphrase)`
   for a short-lived JWT. Operational layer; gives the TEE an
   account-level identity for rate-limiting.

2. **`POST /orders`** — Submit a signed order intent. The signature
   is over a canonical body (see
   [api-and-integration](./api-and-integration.md)) using the
   trading-key Ed25519 keypair.

3. **`DELETE /orders/{id}`**, **`GET /orders/{id}`**,
   **`GET /settlement/status/{batch_id}`** — Cancel an order,
   query order state, poll settle progress.

### TEE → Solana

The five-transaction settle pipeline, one cycle per batch:

| Tx | Instruction | What it does |
|---|---|---|
| **A** | `lock_note × 2` | Pins the buyer's and seller's input notes for the duration of settlement. Requires the user's VALID_INPUT proof (relayed by the TEE). |
| **B** | `verify_match_batch` | Submits the TEE's VALID_MATCH_BATCH Groth16 proof + the batch Merkle root. Creates a `BatchValidityMarker` PDA the settle ix will consume. |
| **C** | `createLookupTable` + `extendLookupTable` | Builds a per-batch Address Lookup Table holding the five derivable PDAs (`note_lock_a/b/e/f` + `batch_validity_marker`). Lets Tx D stay under the 1232-byte size cap. |
| **D** | `tee_forced_settle_batched` | The atomic settle. Consumes both input notes, creates change notes (if any), transfers tokens between users' note values, and emits a `TradeSettled` event. Signed by the TEE's Ed25519 key over a canonical payload hash. |
| **E** | `close_batch_validity_marker` | Reclaims the rent locked in the `BatchValidityMarker`. Closes the loop. |

The five-tx structure is documented in detail in
[settlement-pipeline](./settlement-pipeline.md).

---

## Why this shape

The three-layer split is not arbitrary. Each boundary is doing
real work:

### Custody at the bottom

If the matching layer or the client layer is compromised, funds
should still be safe. The vault program is the floor: no withdraw
without a VALID_SPEND proof; no settle without a VALID_MATCH_BATCH
proof; no settle without the registered TEE signature. The TEE
itself **cannot exit funds** without a user proof — the worst it
can do is censor (refuse to match) or front-run within a single
batch tick, both of which are limited by the matcher's uniform
clearing price + frequent batch auctions design.

### Matching in the middle

Matching is fundamentally stateful and latency-sensitive. Running
it on-chain (or on a rollup, or on a sidechain) leaks every order
to a sequencer or validator. Running it inside an attested enclave
keeps order intent invisible from everyone except the enclave's
compiled image, which is itself fixed by `compose_hash` and can
only sign settles for its own measurements.

### Clients on top

User-side ZK proof generation keeps the spending key off both the
TEE and the chain. The cryptographic chain of trust from "I have a
seed phrase" to "I own this note" only ever exists inside the
user's device.

---

## What's on-chain vs in-TEE vs client-side

| Concern | Location | Why |
|---|---|---|
| Token custody | On-chain (vault SPL token accounts) | Solana enforces transfers atomically; the only authority is the vault program itself |
| Merkle tree of note commitments | On-chain (vault state account) | Auditable by any observer; allows trustless withdraw without a centralized indexer |
| Nullifier set | On-chain (per-nullifier PDA) | Double-spend prevention; allows withdraw checks to be a simple `init` constraint failure |
| Order book | In-TEE (matcher's `OrderBook` struct) | Visible only to attested code; new orders enter via signed HTTPS; matched fills emit settle txs |
| Per-account state | In-TEE (`AccountRegistry`) | Operational rate-limit and audit only — never a custody boundary |
| Oracle prices | In-TEE (`OracleCache` populated by the oracle sync task) | Pyth VAA verified on entry; matcher reads on every tick |
| Settle proofs | Generated in-TEE | The match data must stay private; the proof is what makes the settle trustless |
| User spending key | Client-side only | Never sent over the wire; the SDK's `VALID_SPEND` prover uses it locally |
| User trading key | Client-side only | Ed25519 sigs are made client-side; only the pubkey is in the order body |

The pattern: **whatever needs to be trusted goes on-chain;
whatever needs to be private goes in-TEE; whatever needs to remain
the user's secret stays on their device.**

---

## What the rest of these docs cover

- [Custody layer](./custody-layer.md) — the vault program, the note
  system, the Merkle tree, the on-chain instructions in detail.
- [Matching layer](./matching-layer.md) — the in-TEE matcher
  architecture, the frequent-batch-auction algorithm, oracle
  integration, why TDX specifically.
- [Cryptography](./cryptography.md) — the key derivation chain, the
  Poseidon hash spec, the six ZK circuits, replay protection.
- [Trust model](./trust-model.md) — the attestation chain, multisig
  governance, threat model, what a malicious TEE can and cannot do.
- [Settlement pipeline](./settlement-pipeline.md) — the five-tx
  batched flow, the 1232-byte size budget, the ALT story.
- [API & integration](./api-and-integration.md) — wire contract,
  authentication, order lifecycle, settlement status polling.

---

*Last updated 2026-05-29.*
</content>
