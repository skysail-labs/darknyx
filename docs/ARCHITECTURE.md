# Darknyx Darkpool — Architecture

> As-built system map for contributors. Read
> [`../CRYPTOGRAPHY.md`](../CRYPTOGRAPHY.md) for the note/circuit/wire details,
> [`tee-architecture.md`](tee-architecture.md) for the CVM internals, and
> [`tee-api-openapi.yaml`](tee-api-openapi.yaml) for the API contract.
>
> **Last reviewed:** 2026-08-28.

Darknyx is a privacy-preserving, CLOB-style darkpool on Solana. Users keep
custody through shielded notes and client-generated Groth16 proofs. Hidden
order intake, uniform-price matching, match proving, and settlement
orchestration run inside an attested Intel TDX confidential VM (CVM). The
Solana vault is the sole custody and settlement authority.

There is no on-chain order book: `vault` is the only program.

## System overview

```text
Client / daemon
  keys + VALID_DEPOSIT / VALID_INPUT / VALID_SPEND / VALID_MERGE proofs
  canonical order/cancel signatures
  TDX attestation + finalized-governance verification
                         │ authenticated HTTPS + /v1/stream
                         ▼
Intel TDX CVM (crates/darknyx-tee)
  1..16 configured markets, one book + 2 s matcher driver per symbol
  proof verification at intake, collateral reservation, Pyth guardrails
  N=16 VALID_MATCH_BATCH proving
  K Merkle mirrors + K dstack-derived settle signers
  lock → verify → ALT → settle → expiry-gated sweep
                         │ signed Solana transactions
                         ▼
Solana vault (programs/vault)
  SPL custody + per-mint outstanding accounting
  K append-only Merkle-tree shards
  VALID_* Groth16 verifiers
  commitment-keyed deposit guard + tag-keyed consume guards/locks
  one enabled MarketConfig per mint pair
```

The trust split is deliberate:

| Layer | Enforces | Trust boundary |
|---|---|---|
| `vault` | Custody, proof verification, note conservation, exact fees, market identity/price scale, consume-once, TTLs | Solana program + Groth16 soundness |
| CVM | Order confidentiality, signature/session/nonce policy, uniform-price fairness, limit/tick/min/breaker rules, liveness | Attested code and governance-approved measurement |
| client/daemon | Seed custody, proofs, intent signatures, fill/recovery validation, strict attestation refresh | User device |

The proof prevents a malicious CVM from inflating value, changing the asset
pair, misrouting output ownership, or selecting arbitrary output randomness.
Price fairness remains TEE-trusted: the circuit proves scaled floor arithmetic
and conservation, but not order-limit signatures or the Pyth band.

## Project layout

```text
programs/vault/                 only on-chain program
  src/state.rs                  VaultConfig, MarketConfig, MerkleTree, guards
  src/instructions/             deposit, lock, verify, settle, merge, withdraw
  src/zk/                       Groth16 verifier + committed VK constants
  tests/                        litesvm circuit/account/settlement tests

circuits/
  valid_deposit/
  valid_spend/
  valid_input/
  valid_merge_k2/ valid_merge_k4/
  match_batch_n2/ n4/ n16/
  templates/                    parameterized shared circuit components
  build/                        generated wasm, zkeys, verification keys

crates/darkpool-crypto/         Rust Poseidon/note/use-tag/key primitives
crates/darkpool-matcher/        canonical orders + matching source of truth
crates/darknyx-tee/             in-CVM API, books, prover, mirrors, settlement
crates/darknyx-tee-loadgen/     authenticated intake/settlement load driver

packages/sdk/                   TypeScript keys, provers, transport, recovery
packages/daemon/                non-custodial reference trading daemon
packages/indexer/               optional by-order-id commitment locator

deploy/                         CPU/GPU compose manifests
docs/mintlify/                  public documentation source of truth
docs/                           internal architecture, audit, and runbooks
scripts/                        build, parity, deploy, reset, rotation helpers
```

`apps/demo` is retired and is not an integration target.

## Notes, keys, and recovery

Every note uses the v2 amount-independent inner:

```text
commitment = Poseidon6(2, mint_lo, mint_hi, amount,
                       owner_commitment, inner_hash)
use_tag    = Poseidon3(29, commitment, inner_hash)
```

`owner_commitment = Poseidon2(32, spending_key)` is wallet-wide but
private throughout deposit, spend, merge, order lock, and settlement. The
deposit signer and gross SPL amount remain public; VALID_DEPOSIT hides the
owner and inner while binding the public mint, amount, commitment, and recovery
nonce.

There is no on-chain wallet-registration account or wallet-create circuit. The
owner commitment is useful only as a private note field constrained by the
active note circuits; publishing a permanent wallet-to-identity edge would add
linkability without authorizing any current protocol action.

The SDK supports only a securely generated 64-byte CSPRNG master seed. A
versioned encrypted backup/import format preserves custody across devices;
wallet-signature-derived seeds are not supported.

Recovery is seed plus chain:

- ordinary deposits sample a fresh canonical public recovery nonce; an explicit
  nonce is accepted only by the separately named exact-retry path;
- deposit openings derive from that nonce plus a seed-derived note secret;
- trade and continuation outputs derive from consumed input inners;
- merge outputs derive from the active private input inners/bitmap;
- each settlement carries a 128-byte X25519/ChaCha20-Poly1305 recovery
  envelope for both sides' trade/change amounts.

Live `/v1/stream` fills are the low-latency delivery path. The chain is the
durable recovery source. `packages/indexer` can locate settlement commitments
by deterministic order ID, but it is optional and has no daemon dependency.

See [`fills-history-architecture.md`](fills-history-architecture.md).

## Vault and account model

### Global and market governance

`VaultConfig` is global and read-only on the settle hot path. It contains:

- a distinct operations admin and protocol root key;
- a fixed `[Pubkey; 16]` signer array plus `num_tee_keys`;
- `num_trees` and the shared empty-subtree roots;
- the protocol fee owner commitment and fee rate;
- the public binding of the current fee-recovery epoch key and its monotonic
  governance epoch.

Initialization requires non-default root/signer keys and
`num_tee_keys == num_trees`. Production governance is intended to split
operations (3-of-5 Squads) from root/upgrade authority (cold 4-of-7 Squads).

Each mint pair has a `MarketConfig` PDA containing:

- base/quote mint and decimals;
- nonzero fixed-point `price_scale`;
- tick size, minimum order size, circuit-breaker band, and enabled flag.

The proof-bound governed digest covers fee rate, protocol owner, both mints,
price scale, fee-key binding, and fee-key epoch. Tick/minimum/breaker compliance
is enforced by the attested matcher, not by the circuit. A disabled market
cannot verify new batches.

### Sharded Merkle state

The vault has K independent depth-20 `MerkleTree` PDAs, each with:

- 1,048,576-leaf capacity;
- a current root;
- a 64-entry recent-root ring;
- the incremental right path.

Deposits choose a `tree_id`; settlement outputs round-robin across K trees.
Separate tree accounts and fee-payer signers remove two Solana write conflicts
that otherwise serialize settlement. Proofs always bind one specific shard
root.

### PDA reference

| Account | Seeds | Purpose |
|---|---|---|
| `VaultConfig` | `[b"vault_config"]` | global authorities, signers, fee config, shard count |
| `MarketConfig` | `[b"market_config", base_mint, quote_mint]` | one governed market |
| `MerkleTree` | `[b"merkle_tree", tree_id]` | one append-only note tree shard |
| `DepositedNoteEntry` | `[b"deposited_note", note_commitment]` | strict deposit-once guard |
| `ConsumedNoteEntry` | `[b"consumed_note", note_use_tag]` | shared settle/withdraw consume-once guard |
| `NoteLock` | `[b"note_lock", note_use_tag]` | bounded order lock; amount remains private |
| `OutstandingMint` | `[b"outstanding_mint", mint]` | live-note liability counter |
| `BatchValidityMarker` | `[b"batch_validity", batch_root]` | one verified N=16 batch |
| vault token account | `[b"vault_token", mint]` | SPL custody for one mint |

The strict deposit-once marker is commitment-keyed. The shared consume-once
marker is note-use-tag-keyed, so withdrawal, merge, and settlement collide in
one replay namespace without republishing the Merkle-leaf commitment.
Both permanent replay markers are discriminator-only 8-byte accounts. A live
`NoteLock` is 72 bytes and stores only mint, order ID, expiry, bump, and explicit
alignment padding; its tag is already present in the PDA seed.

## Circuit boundaries

| Circuit | Public signals | What it proves |
|---|---:|---|
| VALID_DEPOSIT | 5 | recoverable note construction for public mint/amount/nonce without exposing owner/inner |
| VALID_SPEND | 7 | note opening, ownership, inclusion, shared use tag, public amount/mint, and exact destination account |
| VALID_INPUT | 4 | owned positive-u64 note with a public use tag/mint at a recent root |
| VALID_MERGE K=2/K=4 | 6/8 | active positive same-owner/same-mint inputs sum to one derived output |
| VALID_MATCH_BATCH N=16 | 2 | up to 16 matches under one market/config digest and Poseidon batch root |

VALID_MATCH_BATCH derives:

- user-output inners from consumed input inners;
- per-match base/quote fee inners from the governed epoch key, consumed use
  tag, and role;
- `quote = floor(base × clearing_price / price_scale)` with a bounded
  remainder;
- all output commitments and a tag-keyed Poseidon12 leaf per slot.

Only N=16 is wired on-chain. N=2/N=4 are development instances.

## End-to-end flow

### 1. Deposit

The client derives a recoverable opening and creates VALID_DEPOSIT. `deposit`:

1. verifies the five public signals;
2. initializes `DepositedNoteEntry` so an identical commitment cannot be
   deposited twice;
3. transfers SPL tokens into the vault;
4. appends the commitment to the chosen tree;
5. increments `OutstandingMint`.

The instruction is atomic. The chain sees the signer, mint, gross amount,
commitment, and recovery nonce, but not the wallet-wide owner or note inner.

### 2. Place an order

The client fetches `/info` and `/time`, verifies attestation/governance, builds
a VALID_INPUT proof, and signs canonical order v5. The signed intent includes
the symbol, economics, 16-byte order ID, collateral commitment, strictly
increasing arrival nonce, contributory X25519 viewing key, and 32-byte boot
session ID.

The CVM:

- authenticates the account;
- verifies the canonical Ed25519 signature;
- checks session, nonce, market rules, collateral opening, and root recency;
- verifies VALID_INPUT before reserving the collateral commitment;
- books the order in the requested market.

Each commitment can back at most one live/pending order across the venue.
Ownership failures are indistinguishable 404 responses. Exact idempotent
retries succeed before nonce monotonicity is enforced.

### 3. Match

Every configured market has an independent book and a 2,000 ms frequent-batch
driver. It uses price-level aggregates and reusable prefix/suffix demand curves
while preserving FIFO, tie-breaking, IOC/FOK/AON, self-trade prevention, and
one fill per order per tick.

The oracle/tick/minimum/circuit-breaker checks are TEE-enforced. Zero-limit
market asks remain eligible but are excluded from price candidates.

Matched quantities are reserved as `pending_settlement`; the public book and
fill stream are not committed optimistically.

### 4. Settle

Each market emits proof batches containing at most 16 matches. A proof never
mixes markets even when one CVM serves several.

```text
Tx A: two independent VALID_INPUT-backed lock_note transactions per match
Tx B: one authorized VALID_MATCH_BATCH verify transaction per batch, carrying
      the governed fee-key epoch and encrypted fee-recovery record
Tx D: one Ed25519-authenticated v1 atomic settle transaction per active match
      (all accounts inline; resource limits live in the v1 message config)
Tx E: marker sweep at/after its on-chain-derived expiry
```

`verify_match_batch` derives marker expiry as `current_slot + 300`; the relayer
cannot shorten it. Tx D reads the shared marker without mutating it, validates
the slot's depth-4 Poseidon inclusion proof, requires both input locks to be
unexpired, initializes two `ConsumedNoteEntry` accounts, appends user/change
and per-match fee commitments, and atomically relocks continuation notes.

Tx D outcomes are collected independently at the RPC client's configured
commitment (Confirmed for the settlement hot path):

- `confirmed`: commit only that match's book quantities and emit fills;
- `ambiguous`: retain pending state and reconcile signatures/consumed PDAs;
- `rejected`: emit `settlement_failed` with reason and lock expiry.

Failed orders are terminal and never auto-rebooked. The user submits a fresh
signed order after unlock. Expired lock and marker accounts are swept
asynchronously; expiry makes them non-blocking but does not erase them.

### 5. Withdraw or merge

VALID_SPEND binds the exact destination token account. `withdraw` rejects a
live lock, permits an expired lock, initializes the shared
`ConsumedNoteEntry`, decrements outstanding liability, and transfers SPL
tokens atomically.

VALID_MERGE consolidates two to four live notes without leaving the pool. It
requires positive active inputs, proves lock accounts absent/non-live, and
derives the output inner from the active private input inners and bitmap. K=2/K=4
merges can be chained.

## Multi-market CVMs

`DARKNYX_TEE_MARKETS_JSON` configures 1..16 boot-static markets. The singular
base/quote env path remains for a one-market deployment, but it cannot be mixed
with the JSON table.

One CVM shares:

- attestation and authentication;
- K signer keys and Merkle mirrors;
- oracle cache and prover artifacts;
- ALT pool, RPC client, and a venue-wide settlement concurrency semaphore.

Each market has its own symbol, mint pair, matcher state, lifecycle publisher,
and scheduler. Oracle pause state is also per market; governance and drain
reasons remain venue-wide. `/instruments` is the authoritative list for that
CVM and exposes current `trading_enabled` readiness per symbol.
Cross-market modify is rejected; clients cancel and place a fresh order.

Because `VaultConfig.tee_pubkeys` is a single global set, the current vault
assumes one authorized TEE cluster rather than several independently attested
CVMs. Cross-CVM discovery/routing is therefore deferred; clients should not
trust an endpoint registry copied between CVMs. See
[`multi-market-architecture.md`](multi-market-architecture.md).

The 16-market parser cap is a safety ceiling, not a sizing target. Stop adding
markets before any of these measured gates is crossed:

- settlement queue wait p95 ≥ 2 s or p99 ≥ 4 s;
- p95 end-to-end settlement latency regresses by more than 10%;
- confirmed throughput loses the required 20% headroom over offered load;
- sustained CPU or memory exceeds 70%;
- RPC/ambiguous/definitive-settlement error rate exceeds 0.1%.

## API, streams, and attestation

The OpenAPI source of truth is [`tee-api-openapi.yaml`](tee-api-openapi.yaml).
The only WebSocket is `/v1/stream`; clients log in and subscribe to:

- `orders` for lifecycle updates;
- `fills` for per-account private fill memos;
- `tree` for Merkle progress.

The stream preserves sequence-gap detection, token refresh, reconnect, and
cancel-on-disconnect. Retired `/ws/fills`, `/ws/orders`, and `/ws/trading`
endpoints do not exist.

Strict clients:

1. verify the DCAP quote and replay RTMR3;
2. pin compose hash/MRTD;
3. verify the quoted K signer set;
4. read finalized `VaultConfig` and `MarketConfig` accounts;
5. require exact key/config agreement.

The daemon refreshes finalized governance every minute, pauses new
place/modify immediately on mismatch, and pauses after five minutes without a
successful finalized refresh. Cancellation and reconciliation remain
available. On-chain DCAP verification is deferred.

## Security and recovery boundaries

- TDX protects order/witness confidentiality only when the measured image and
  hardware mode are verified.
- A CUDA prover receives private amounts, prices, owner commitments, and
  openings. Production GPU proving therefore requires NVIDIA Confidential
  Computing mode and GPU attestation bound into the CVM trust decision.
- The Groth16 development zkeys are deterministic and are not mainnet-safe.
- Market fairness is attested-code trust; custody/conservation is circuit/L1
  enforcement.
- Network metadata and deposit/withdraw boundaries remain observable.
- The off-TEE indexer is not trusted for custody or note reconstruction.

## Validation and deployment

The authoritative commands are in [`../CLAUDE.md`](../CLAUDE.md) and
[`../scripts/dev-commands.md`](../scripts/dev-commands.md).

For code that changes the vault, circuits, or TEE:

1. run the full local formatting, SBF, clippy, Rust, TypeScript, SDK, and
   indexer gates that are reasonable for the touched surface;
2. regenerate circuit source/zkey/VK/fixtures atomically when a circuit changes;
3. upgrade devnet and reset tree state after a circuit/VK migration;
4. rebuild/tag/redeploy the CVM image for TEE or embedded-prover changes;
5. run each leaf-count CVM test against its own reset + cold boot.

The flagship real-settle test is `cvm-settle-e2e`. Additional live gates cover
multi-match, self-trade, merge-then-order, multi-market, API, and attestation.
The load generator measures intake and settlement telemetry but synthetic
placeholder orders are not a substitute for real proof-backed settlement.

Stop billable CPU CVMs after the required window. Never stop an on-demand GPU
CVM: Phala deallocates it permanently and forfeits the remaining prepaid
window. Use [`cvm-run-runbook.md`](cvm-run-runbook.md) and
[`gpu-tee-runbook.md`](gpu-tee-runbook.md) verbatim.

## Deployed program

| Network | Vault program |
|---|---|
| devnet | `C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx` |

Mainnet launch remains gated on remediation closure, an external circuit audit
with no unresolved Critical/High findings, a public Phase-2 ceremony, split
Squads rehearsal, recovery drills, reproducible artifact verification, and
post-ceremony CVM settlement evidence.
