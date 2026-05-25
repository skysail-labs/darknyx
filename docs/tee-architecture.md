# Nyx TEE v2 — Internal Architecture

> Design of the in-TEE matching engine that replaces the MagicBlock-PER
> matching layer. Read after `docs/tee-v2-migration.md` (the migration
> brief) and `docs/tee-api-openapi.yaml` (the wire contract). Pairs
> with `docs/tee-attestation-flow.md` (the attestation deep-dive).
>
> **Last revised:** 2026-05-25.
> **Status:** v2 design, pre-implementation. Reflects the constraints
> agreed on after the dstack docs deep-dive on 2026-05-25.
> **Branch:** `nyx-v2-onchain-hardening`.

---

## 0. Decisions locked in for v2

Before any of the design below makes sense, these four choices are
load-bearing. They were chosen after reading the Phala / dstack docs
end-to-end:

| # | Decision | Choice | Why |
|---|---|---|---|
| D1 | **Hosting** | Phala Cloud (managed) | Fastest path to a real attested deployment. Same container image runs on dstack-cloud / self-hosted bare metal later — Phala Cloud is the v2 deployment target, not a lock-in. |
| D2 | **TEE pubkey rotation gate** | Admin multisig only | The multisig verifies the TDX quote off-chain (via `dstack-verifier` Docker image) before signing `set_tee_pubkey`. On-chain `dcap-qvl` port deferred to v3. |
| D3 | **API edge** | Custom domain via dstack-ingress | `api.nyx.example.com` with ACME inside the TEE, `/evidences/` endpoint for RA-TLS verification, CAA-locked Let's Encrypt account. Branding ours, end-to-end TLS into the enclave. |
| D4 | **Prover location** | Inside the TEE | Witness never leaves the enclave. ~5-10% TDX overhead on top of ~0.7s Groth16 time is within budget. Benchmark in Phase 1 — if memory-encryption pushes us above 3s, fall back to TEE-signed-public-input + external prover. |
| D5 | **Matching cadence** | Frequent-batch-auction with `BATCH_MS = 2000` default, tunable per market via on-chain `MatchingConfig` | Settle-latency floor (~2-3 s) means ticks faster than that pipeline up. 2 s is the aggressive setting; per-market tunable so we can dial liquid markets faster and thin markets slower without a code change. **Hot order book, batched clearing** — orders are visible the moment they arrive over WS; only the actual matching is batched. See §5.4. |
| D6 | **Indexer architecture** | Inside the TEE, shared in-memory state via `tokio RwLock` | The TEE already holds the Merkle mirror + nullifier set + lock state in RAM to do matching — exposing `/tree/*` over the same state is essentially free. One deployment, one attestation chain. Clients who don't trust the TEE retain the trustless fallback (read `VaultConfig.current_root` + PDAs directly from Solana). See §5.5. |

Everything below assumes those six choices. Section 13 documents the
trigger conditions that would flip any of them.

---

## 1. What runs where

```
┌────────────────────── Client (browser / SDK) ────────────────────────────┐
│ wss://api.nyx.example.com  (TLS 1.3, cert generated inside the TEE)      │
│   - On connect: fetch GET /evidences/ → verify RA-TLS binding            │
│   - On connect: fetch GET /attestation → verify TDX quote + compose-hash │
│   - All order intent, all account reads, all WS messages go through this │
│     channel, end-to-end into the enclave.                                │
└──────────────────────────────────┬───────────────────────────────────────┘
                                   │ TLS 1.3 (RA-HTTPS)
                                   ▼
┌──────────────────── dstack-gateway (Phala-managed) ──────────────────────┐
│  TLS passthrough mode — does NOT terminate our TLS.                      │
│  WireGuard tunnel to our CVM, encrypted inside Phala's network.          │
└──────────────────────────────────┬───────────────────────────────────────┘
                                   │ WireGuard
                                   ▼
┌──────────────────── Our Nyx CVM (Intel TDX) ─────────────────────────────┐
│                                                                          │
│  docker-compose.yaml (compose_hash committed to dstack governance)       │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │ Container: nyx-tee                                                  │ │
│  │ ─ Rust binary, single process, multi-threaded tokio runtime         │ │
│  │ ─ Mounts /var/run/dstack.sock for KMS calls + attestation           │ │
│  │ ─ Listens on :8443 (TLS) and :8444 (RA-HTTPS evidence)              │ │
│  │ ─ Components:                                                       │ │
│  │   ┌───────────────────────────────────────────────────────────────┐│ │
│  │   │  HTTP / WS server (axum + tokio-tungstenite)                  ││ │
│  │   │  Order book (per-market BTreeMap + indices)                   ││ │
│  │   │  Matching loop (tokio interval, every batch_interval slots)   ││ │
│  │   │  Groth16 prover (snarkjs-equivalent in Rust — ark-groth16)    ││ │
│  │   │  Settle scheduler (solana-client async)                       ││ │
│  │   │  Merkle mirror (programs/vault/src/merkle.rs lifted)          ││ │
│  │   │  Persistence (encrypted disk snapshots)                       ││ │
│  │   └───────────────────────────────────────────────────────────────┘│ │
│  └────────────────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │ Container: dstack-ingress                                          │ │
│  │ ─ Phala-published image (no fork; we configure via env)            │ │
│  │ ─ Runs ACME inside the TEE; CAA-locks Let's Encrypt account        │ │
│  │ ─ Serves /evidences/ (quote.json + cert.pem + sha256sum.txt + …)   │ │
│  │ ─ TLS-terminates port 8443 inside the enclave                      │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│  Memory is TDX-encrypted at the silicon level. RTMR3 records           │
│  compose_hash + key-provider-id + instance-id at boot. dstack-kms       │
│  verified the TDX quote off-chain before delivering app keys.          │
└──────────────────────────────────┬───────────────────────────────────────┘
                                   │ Helius RPC (HTTPS out)
                                   ▼
┌──────────────────────────── Solana mainnet ──────────────────────────────┐
│  vault (custody, unchanged from v3.5)                                    │
│  matching_engine (~200 LOC after Phase 5: init_market + init_oracle      │
│    + configure_access only)                                              │
│  admin-multisig (Squads, 3-of-5) — signs set_tee_pubkey + governance     │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 2. The `nyx-tee` Rust binary

Single process, single container, multi-threaded tokio runtime. New
crate at `crates/nyx-tee/`.

### 2.1 Cargo skeleton

```toml
[package]
name = "nyx-tee"
version = "0.1.0"
edition = "2021"

[dependencies]
# dstack runtime
dstack-rust = { git = "https://github.com/Dstack-TEE/dstack.git", package = "dstack-rust" }

# Network
tokio = { version = "1", features = ["full"] }
axum = { version = "0.7", features = ["ws", "macros"] }
tokio-tungstenite = "0.21"
rustls = "0.23"

# Cryptography (must keep byte-identical to darkpool-crypto)
darkpool-crypto = { path = "../darkpool-crypto" }
ark-groth16 = "0.4"
ark-bn254 = "0.4"
ed25519-dalek = "2"

# Matching (lifted from programs/matching_engine/src/instructions/run_batch.rs)
darkpool-matcher = { path = "../darkpool-matcher" }

# Solana
solana-client = "1.18"
solana-sdk = "1.18"
anchor-lang = "0.32"

# Order-book primitives
indexmap = "2"
priority-queue = "2"

# Borsh for on-chain payloads
borsh = "0.10"
```

### 2.2 Modules

```
crates/nyx-tee/src/
├── main.rs              # entry: boot, configure dstack, start server
├── boot.rs              # KMS key derivation, attestation export, sanity checks
├── api/                 # HTTP + WS surface (mirrors docs/tee-api-openapi.yaml)
│   ├── mod.rs
│   ├── auth.rs          # OAuth2 client_credentials → JWT
│   ├── orders.rs        # POST /orders, DELETE /orders/{id}, mass-quote
│   ├── account.rs       # GET /account
│   ├── tree.rs          # GET /tree/root, /tree/inclusion, /tree/leaves
│   ├── settlement.rs    # GET /settlement/status/{batch_id}
│   ├── transparency.rs  # GET /transparency (unauthenticated)
│   ├── attestation.rs   # GET /attestation (unauthenticated)
│   └── ws.rs            # /v1/stream multiplexed socket
├── matcher/             # in-memory order book + matching loop
│   ├── mod.rs
│   ├── book.rs          # per-market BTreeMap<Price, FifoQueue<OrderId>>
│   ├── interval.rs      # tokio interval driver; runs run_batch each tick
│   └── selftrade.rs     # self-trade prevention (moved from run_batch.rs)
├── prover/              # in-process Groth16 prover for VALID_MATCH_BATCH
│   ├── mod.rs
│   ├── witness.rs       # build witness from matcher output
│   └── groth16.rs       # ark-groth16 wrapper (N=16 instantiation)
├── settle/              # on-chain settle pipeline
│   ├── mod.rs
│   ├── payload.rs       # MatchResultPayload construction
│   ├── sign.rs          # Ed25519 signing using the TEE-derived key
│   ├── pipeline.rs      # verify_match_batch → settles → close (v3.5 path)
│   └── alt.rs           # per-batch ALT creation
├── merkle/              # local mirror of vault's incremental Merkle tree
│   ├── mod.rs
│   └── sync.rs          # poll VaultConfig + leaf-append events to stay current
├── persistence/         # LUKS-encrypted snapshots (book + leaves + outbox)
│   ├── mod.rs
│   └── snapshot.rs
├── keys/                # dstack-derived keypair management
│   ├── mod.rs
│   └── ed25519.rs       # getKey("nyx/ed25519-signer/v1") → Ed25519 keypair
└── config.rs            # env-driven config (Helius URL, market params, etc.)
```

### 2.3 Two crates split from existing code

Two pieces of today's matching_engine that move into the TEE binary
get extracted as standalone crates so the litesvm parity tests can
still depend on them:

- `crates/darkpool-matcher/` — the uniform-clearing-price + FIFO
  algorithm currently in `programs/matching_engine/src/instructions/run_batch.rs`
  and adjacent state structs. No Anchor / Solana deps. Pure input
  (open orders) → output (matches + fees + clearing price). The
  litesvm test for `run_batch` becomes a thin wrapper around this
  crate, and `nyx-tee` consumes the same crate. **Single source of
  truth for the matching algorithm.**

- `crates/nyx-tee-types/` — Borsh structs shared between the SDK
  TypeScript types (via `wasm-bindgen` for one-way generation) and
  the binary. `OrderIntent`, `MatchResultPayload` (re-exported from
  vault), tree-inclusion request/response types, etc.

---

## 3. Boot sequence

A new CVM coming up under our compose-hash:

```
1.  Intel TDX module loads OVMF, measures into MRTD.
2.  OVMF loads dstack OS kernel + initramfs, measures into RTMR0-2.
3.  dstack guest agent (in initrd) extends RTMR3 with:
      • compose-hash (our app-compose.json SHA-256)
      • key-provider info (which dstack-kms instance we use)
      • instance-id (this specific CVM's identifier)
4.  Guest agent contacts dstack-kms over RA-TLS.
      • KMS verifies our TDX quote off-chain (Intel TCB cert chain).
      • KMS checks compose-hash is allowlisted (Phala Cloud dashboard
        OR — if/when we move to Onchain KMS — DstackApp on Base).
      • KMS derives our app's root key from (deployer_id, app_hash, …).
      • KMS provisions: LUKS disk encryption key + TLS cert via
        dstack-ingress + a deterministic seed pool.
5.  dstack-ingress container starts:
      • Generates TLS keypair inside the enclave (key never exposed).
      • Runs ACME against Let's Encrypt with TEE-controlled account.
      • Sets CAA DNS record locking issuance to that account.
      • Publishes /evidences/{quote.json, cert.pem, sha256sum.txt,
        acme-account.json}.
6.  nyx-tee container starts:
      • Calls `client.info()` — reads app_id, instance_id, RTMRs.
      • Calls `client.get_key("nyx/ed25519-signer/v1")` — deterministic
        32-byte seed.
      • Derives Ed25519 keypair from the seed. The pubkey is stable
        for the lifetime of this compose-hash.
      • Loads persistence snapshot from LUKS disk (if present) and
        replays since the last snapshot.
      • Syncs Merkle mirror from on-chain VaultConfig.
      • Verifies its Ed25519 pubkey matches the on-chain
        vault_config.tee_pubkey. If not, refuses to settle until
        admin runs the rotation ceremony (§7).
      • Starts the matching loop, the settle scheduler, and the API
        server.
7.  Container marks itself healthy. Phala gateway routes traffic.
```

Boot time end-to-end is ~30-60s under normal conditions: the TDX
attestation + KMS handshake + ACME cert (if cold) dominate.

---

## 4. Key bootstrap — the Ed25519 signer

The single most important key in this system. It's what
`vault.tee_forced_settle_batched` checks every settle.

### 4.1 Derivation

```rust
// crates/nyx-tee/src/keys/ed25519.rs
use dstack_sdk::DstackClient;
use ed25519_dalek::SigningKey;

pub async fn derive_signer(client: &DstackClient) -> Result<SigningKey> {
    // dstack returns 32 bytes of deterministic KDF output keyed by
    // (deployer_id, app_hash, path). Same compose-hash → same bytes.
    let key_resp = client
        .get_key(Some("nyx/ed25519-signer/v1".to_string()), None)
        .await?;
    let seed: [u8; 32] = key_resp.decode_key().try_into()
        .expect("dstack getKey returned non-32-byte material");

    // Standard Ed25519 expansion. The pubkey we register on Solana is
    // exactly SigningKey::from_bytes(&seed).verifying_key().to_bytes().
    Ok(SigningKey::from_bytes(&seed))
}
```

### 4.2 Lifecycle

| Event | Effect on the signer key |
|---|---|
| CVM restart | None. Key is deterministic from the dstack KMS seed. |
| Hardware migration | None. dstack-kms hands the new host the same seed. |
| KMS root key share rotation (internal to dstack-kms) | None. Application-level KDF outputs unchanged. |
| KMS root key full rotation (rare, security incident) | All app keys re-derive. Our signer pubkey changes. Admin multisig must run `set_tee_pubkey` with the new pubkey. |
| Image upgrade (new compose-hash) | New `app_hash` → KDF emits new seed → new signer pubkey. Admin runs the rotation ceremony before the new image can settle. |
| Path change (e.g. `nyx/ed25519-signer/v2`) | Same as image upgrade — but we should bump the path ONLY when we want a clean break, never as a quiet operational reroll. |

### 4.3 What is NOT used

We do not use dstack-kms's "ECDSA Key" derivation that's labelled
"Ethereum-compatible signing keys" — that key is k256
(secp256k1), incompatible with Solana's native Ed25519 path and
incompatible with our existing on-chain Ed25519-precompile
verification in `vault::verify_tee_signature`. Deriving an Ed25519
keypair locally from a dstack-supplied 32-byte seed is the clean
path.

---

## 5. The in-TEE order book

### 5.1 Data structure

Per market, RAM-resident:

```rust
pub struct OrderBook {
    /// Buys, descending by price (best bid first).
    bids: BTreeMap<Price, FifoQueue<OrderId>>,
    /// Asks, ascending by price (best ask first).
    asks: BTreeMap<Price, FifoQueue<OrderId>>,
    /// Open orders, keyed by id.
    orders: HashMap<OrderId, Order>,
    /// Per-trader index for cancel-by-owner ops.
    by_trader: HashMap<TradingPubkey, HashSet<OrderId>>,
    /// Per-expiry-slot index for expiry sweeps.
    by_expiry: BTreeMap<Slot, HashSet<OrderId>>,
    /// Tracks which notes are locked by which open orders, so a
    /// second order against the same note is rejected at submit time
    /// (matches the on-chain NoteLock invariant pre-emptively).
    locked_notes: HashMap<NoteCommitment, OrderId>,
}
```

Sizing: assume 100k open orders steady-state. Each `Order` ≈ 256 B,
plus ~200 B amortised in the indices → ~50 MB per market. 4-market
TDX VM with 16 GB RAM is comfortable.

### 5.2 Submit path

```
POST /orders (or WS op:order.place)
    1. Bearer-token / OAuth verification.
    2. Trading-key signature verification on the canonical body.
    3. Note ownership + freshness check (Merkle inclusion against
       the current root + nullifier-set check).
    4. Note-lock check (is this note already locked?).
    5. Append to book; index updates.
    6. Echo Order JSON back; emit on `orders` WS channel.
```

Latency target: P99 under 5 ms end-to-end inside the TEE. The
TDX-Lab benchmarks (1244 QPS at 1000 concurrency, P99 822 ms) include
TLS handshake — for keep-alive WS, real bottleneck is our
signature-verification + Merkle witness check.

### 5.3 Cancel + mass-quote

`DELETE /orders/{id}` and `POST /orders/mass-quote` are straight book
mutations. Mass-quote (up to 20 cancel-replace pairs atomically) is
implemented as a single critical section over the affected price
levels.

### 5.4 Match loop — frequent batch auctions

Per D5: **hot order book, batched clearing.** The book is updated
the moment any order arrives over WS; matching ticks fire every
`BATCH_MS` (default 2 s, configurable per market) and run a
uniform-clearing-price auction over whatever's in the book at the
tick instant.

```rust
let mut interval = tokio::time::interval(market.config().batch_ms_duration());
loop {
    interval.tick().await;
    let now = solana_slot_clock.current_slot().await;

    for market in markets.iter() {
        // Sweep expired orders into a "cancelled" event stream.
        market.book().write().await.sweep_expired(now);

        // Run uniform-clearing-price matching.
        let result = darkpool_matcher::run_batch(
            &market.book().read().await,
            &oracle.pyth_twap(market).await,
            market.config(),
            now,
        );

        if !result.matches.is_empty() {
            // Hand off to the settle pipeline. Async; the matcher
            // continues immediately to the next interval.
            settle_scheduler.enqueue(market.id(), result).await;
        }
    }
}
```

#### Why batched and not continuous

Three structural constraints force batched matching:

1. **`VALID_MATCH_BATCH` is a batch primitive.** The N=16 circuit
   binds *one* clearing price, *one* Merkle root, *one* oracle TWAP,
   *one* expiry, *one* fee rate to a Poseidon-hashed batch root.
   Continuous matching would degenerate it to N=1 — which is the
   v3.1 per-match `VALID_CREATE` + `VALID_PRICE` shape we deleted in
   Phase 1c-hard. Not going back.
2. **`BatchValidityMarker` PDA is keyed by `[seed, merkle_root]`.**
   Two batches racing on the same root collide on the PDA. The
   serialised pipeline is structural: one batch's `close_batch_validity_marker`
   must confirm before the next batch's `verify_match_batch` can run
   (because the next batch's root binds to the new tree state).
3. **Uniform-clearing-price is, by definition, a batch construct.**
   All trades in a batch fill at the same price. UCP is the privacy
   pattern dark pools rely on — continuous matching would leak fill
   timing as a covert channel.

#### Why `BATCH_MS = 2000` and how to tune it

The lower bound is **settle finality** ≈ 2-3 s end-to-end:
- `verify_match_batch`: 1-2 slots
- N × `tee_forced_settle_batched` (concurrent): 1-2 slots
- `close_batch_validity_marker`: 1 slot

Ticking faster than that just queues batches in memory (`settle_scheduler.enqueue`
backs up). Per market we expose `batch_ms` in the on-chain
`MatchingConfig` so liquid markets can run tighter (2 s) and thin
markets can run looser (10 s) without a TEE redeploy. The default
across new markets is 2 s.

If the Phase-1 benchmark on TDX-Lab shows settle finality
consistently above 3 s under load, bump the default to 3 s and
revisit.

#### Implications for clients

- **Order placement → fill notification**: worst-case `BATCH_MS + matching_time ≈ 2 s`. Best case (order arrives just before tick): low ms after the tick fires.
- **Fill notification → on-chain finality**: ~3 s additional (the settle pipeline).
- **The `orders` and `fills` WS channels** push state changes the instant they happen inside the TEE — so client UIs feel "live" even though clearing is batched. The `tree` WS channel pushes leaf-append events as `tee_forced_settle_batched` confirms, so balance views update without polling.

### 5.5 Indexer surface — same process, shared state

Per D6: **the indexer is `nyx-tee` itself.** The TEE already holds
everything an indexer needs (Merkle mirror, nullifier set, lock set,
order book) to do its matching job. The `/tree/*` + `/transparency`
endpoints are read-only views over that same in-memory state.

```rust
// Roughly:
struct NyxTeeState {
    // Mutated by matcher + settle scheduler:
    books: HashMap<MarketId, Arc<RwLock<OrderBook>>>,

    // Mutated by the Merkle sync task:
    merkle_mirror: Arc<RwLock<MerkleMirror>>,
    nullifier_set: Arc<RwLock<HashSet<Nullifier>>>,
    consumed_notes: Arc<RwLock<HashSet<NoteCommitment>>>,
    locks: Arc<RwLock<HashMap<NoteCommitment, NoteLockSnapshot>>>,

    // Read-only after initial load:
    config: Arc<MarketConfig>,
}
```

`tokio::sync::RwLock` — readers don't block each other; the matcher
takes the write lock only inside its 2 s tick (microsecond window),
the settle scheduler takes it only when applying confirmed leaves.
Indexer reads (HTTP + WS) hold the read lock for the duration of a
single response.

#### Cold-boot sync

A brand-new CVM that just got its dstack keys doesn't have any
Merkle history. The boot sequence (see §3 step 6) does:

```
1. Read VaultConfig once (current_root, leaf_count, deployed_slot).
2. Paginate getSignaturesForAddress(vault_program_id) from
   deployed_slot forward, in batches of 1000.
3. For each tx, parse the leaf-append events emitted by
   deposit / withdraw / tee_forced_settle_batched.
4. Replay each leaf into the local Merkle mirror in order.
5. Stop when local root == VaultConfig.current_root.
```

For ~1 year of mainnet activity this is 30-60 s on cold boot. The
LUKS snapshot path (warm restart) skips this entirely and replays
only the deltas since the snapshot timestamp.

#### Read endpoints

Documented in `docs/tee-api-openapi.yaml`. The shape:

| Endpoint | Latency target | Notes |
|---|---|---|
| `GET /tree/root` | <5 ms | Current Merkle root + leaf count + on_chain_slot. |
| `GET /tree/inclusion?commitment=…` | <20 ms | 20-level sibling path against current root. |
| `GET /tree/leaves?from=N&to=M` | <50 ms per 1k leaves | Pagination for cold-syncing clients. |
| `GET /transparency` | <50 ms | Reserves + attestation + 24h stats. Unauthenticated. |
| WS channel `tree` | push, ~10 ms after on-chain confirm | Live leaf-append events. |

#### Trustless fallback

This is the critical property that makes TEE-as-indexer
defensible. **Clients who don't trust the TEE for read queries can
always:**

- Read `VaultConfig.current_root` directly from Solana (~1 RPC call,
  trustless).
- Read `NullifierEntry`, `ConsumedNoteEntry`, `NoteLock`,
  `WalletEntry` PDAs directly (one PDA per object, trustless).
- Re-derive their own Merkle tree from on-chain leaf-append events
  (the legacy `MerkleShadow` path — slower, but trustless).

So `/tree/*` is a **convenience layer**, not a trust layer. A
malicious or compromised TEE serving `/tree/inclusion` can return
a path that doesn't verify against the real on-chain root — but
the client can detect this by verifying every inclusion proof
against the root they fetched directly from Solana. Best-of-both:
fast happy-path, trustless when you need it.

#### Why not a separate service

We considered (and rejected) a separate untrusted indexer service.
Trade-offs:

- **Pro separate**: TEE memory stays leaner; scales independently;
  enables cross-app reuse.
- **Pro shared (chosen)**: zero extra ops surface; user verifies one
  attestation; the TEE already holds this state.

At v2 scale (sub-1M leaves, sub-1k orders/sec sustained) the shared
design wins. Re-evaluate when (a) TEE host RAM becomes a real
constraint, (b) we want read replicas, or (c) we want to expose the
indexer to non-Nyx consumers.

---

## 6. Settle scheduler — the v3.5 batched pipeline, server-side

For each batch with ≥1 real matches, sequentially:

1. **Pad to N=16**: same logic the SDK's `batched-settle.ts` uses
   today. Real matches first, dummy slots after.
2. **Generate VALID_MATCH_BATCH Groth16 proof.**
   - In-process `ark-groth16` against `circuits/build/match_batch_n16/circuit_final.zkey`.
   - The zkey is baked into the Docker image, so its bytes are
     covered by compose-hash.
   - Witness assembly mirrors `packages/sdk/tests/helpers/match-batch-prover.ts`.
3. **Build `MatchResultPayload` for each real match.**
   - Same Borsh shape as today (24 fields, 448 bytes).
   - Same `canonical_payload_hash(payload)` — see CLAUDE.md §6.
4. **Sign each payload's canonical hash with the Ed25519 signer key.**
5. **Submit the v3.5 settle pipeline:**
   - `verify_match_batch(merkle_root, expiry, proof)` — once per batch
   - Per-batch ALT create + extend (see CRYPTOGRAPHY.md §9)
   - `tee_forced_settle_batched(payload, match_index, merkle_proof)`
     — once per real match, fired concurrently
   - `close_batch_validity_marker(merkle_root)` — once per batch,
     after all settles confirm
6. **Update local Merkle mirror** with the new leaves the on-chain
   handler just appended (we know the leaf hashes ahead of time —
   compose them locally as the on-chain code does).
7. **Mark `batch_id` settled** in the in-memory ledger; emit on
   `settlement` WS channel.

This is exactly the path `packages/sdk/tests/helpers/batched-settle.ts`
implements today — we move it server-side, swap snarkjs for
`ark-groth16` (same proving key, byte-identical proofs), and the
on-chain handler doesn't notice the difference.

---

## 7. Image upgrade ceremony

When we ship a new version (new `compose-hash`):

```
1. Build the new Docker image. Compute compose-hash.
2. Whitelist the new compose-hash in Phala Cloud dashboard
   (or, if we move to Onchain KMS, call DstackApp.addComposeHash
    on Base via our governance multisig).
3. Phala Cloud deploys the new image. Old CVM continues running
   under the old compose-hash (Phala supports rolling deploys).
4. New CVM boots:
     • dstack-kms derives a NEW Ed25519 seed (because app_hash is
       in the KDF input).
     • New CVM's pubkey is different from the on-chain
       vault_config.tee_pubkey.
     • New CVM exposes the new pubkey via GET /attestation.
5. Admin (one signer of the 3-of-5 multisig):
     • Fetches the new attestation: curl https://api.nyx.example.com/attestation
     • Verifies the quote off-chain:
         docker run -p 8080:8080 dstacktee/dstack-verifier:latest &
         curl -d @quote.json localhost:8080/verify | jq
     • Confirms compose-hash in event_log matches expected.
     • Constructs set_tee_pubkey(new_pubkey) tx; posts to Squads as a
       proposal.
6. Other multisig signers independently repeat step 5's verification.
7. Three signatures collected → multisig executes set_tee_pubkey on
   the vault.
8. Old CVM's signatures now fail verification — Phala drains traffic
   to the new CVM and shuts the old one down.
```

Total: ~15 minutes for the cutover, dominated by signer review time.
No on-chain TDX quote verification — the trust assumption is "the
multisig honestly ran step 5." Future v3 work (§9) closes that.

---

## 8. State + persistence

The TEE's authoritative state at any moment:

- **Open orders + book structure** (≪50 MB per market).
- **Merkle leaves seen** (32 B × leaf_count; grows ~1 leaf per match
  pair → ~50 MB after 1.5M trades).
- **Settle outbox** — pending L1 txs that haven't confirmed yet,
  needed for crash-recovery so we don't double-submit.
- **Per-batch ALT lookup** — `batch_id → ALT pubkey` mapping for
  in-flight settles.

Persistence strategy (Phase 1):

- LUKS-encrypted disk volume provisioned by dstack-kms at boot. Key
  is deterministic from `app_id` — survives instance migration, lost
  if the entire compose-hash is retired.
- Periodic snapshots every 5 s (sync from in-memory state). Use
  `bincode` for compact encoding. Atomic write-rename pattern.
- On boot: load latest snapshot; for events since the snapshot
  timestamp, replay from on-chain history (leaf-append events) +
  client resubmission for open orders.

Persistence is **best-effort + complement, not the source of truth**.
On-chain state is canonical for note ownership / settled balances.
Order intent is signed by the client — clients are expected to
resubmit if the TEE loses an order on restart. Market makers using
the WS `cancel_on_disconnect: true` opt-in are auto-cancelled on
TEE crash, which is the safe default.

---

## 9. The Groth16 prover, inside the TEE

Concrete plan for Phase 1:

- Use `ark-groth16` 0.4 with `ark-bn254` 0.4.
- Load the proving key from `/circuits/build/match_batch_n16/circuit_final.zkey`
  at startup. (The zkey ships in the Docker image; baked into
  compose-hash, so any tampering changes attestation.)
- Witness assembly: a Rust port of
  `packages/sdk/tests/helpers/match-batch-prover.ts`. Same Poseidon
  arity calls into `darkpool-crypto`.
- Verify against the SAME `vk_match_batch_n16.rs` consts the on-chain
  vault uses — byte-for-byte. This is the most likely class of bug
  during the port (Fr endianness, point compression). We'll add a
  parity test that proves the same input in `ark-groth16` and in
  snarkjs, and verifies both proofs against the on-chain verifier
  (using litesvm).

**Benchmark to gate the design** (Phase 1 sign-off):

- Run the same N=16 proof on:
  - Bare-metal control (M3 MacBook or a non-TEE EC2 r6i.4xlarge)
  - Phala Cloud TDX-Lab tier (the one whose benchmarks we cited)
- Acceptance: proof time on TDX-Lab ≤ 3 × bare-metal. (Phala's
  published zkTLS-in-CPU-TEE was 3.78x — Groth16 should be similar or
  better, since it's smaller and has tighter memory patterns.)
- If we miss the 3× bound, switch to the external-prover design:
  TEE signs the public input hash, sidecar generates the proof,
  vault verifies both. The external prover sees the witness but the
  witness is mostly already-public-after-settle info anyway.

---

## 10. Networking — RA-TLS via dstack-ingress

D3 chose custom domain via dstack-ingress. Concretely:

### 10.1 Domain setup (one-time)

1. Buy `api.nyx.example.com` (or use a subdomain of a domain we own).
2. Add DNS A record pointing at the dstack-gateway IP.
3. Add CAA record: `0 issue "letsencrypt.org;validationmethods=dns-01"`.
4. The dstack-ingress container, on first boot, registers its own
   Let's Encrypt account (the private key stays in the TEE), gets
   a cert via DNS-01 challenge (the API token for our DNS provider
   is passed in via dstack encrypted env vars — Phala's UI does the
   client-side encryption).
5. dstack-ingress then tightens the CAA record to lock it to its own
   account URI.

### 10.2 What clients see

- TLS to `api.nyx.example.com:443`. Standard browser TLS.
- The certificate's public key is provable to be bound to a TEE-held
  private key, verifiable via the `/evidences/` directory:
  - `GET /evidences/quote.json` — TDX quote
  - `GET /evidences/cert.pem` — current TLS cert
  - `GET /evidences/sha256sum.txt` — SHA-256 of cert.pem + acme-account.json
  - `GET /evidences/acme-account.json` — the Let's Encrypt account URI

- Verifying: `sha256(sha256sum.txt) ∈ quote.report_data` proves the
  TEE generated all of these files at the same time. `cert.pem`'s
  pubkey must match the cert served over TLS. CT logs (crt.sh)
  should show no certs issued outside our account.

### 10.3 Endpoint mapping inside the CVM

- `dstack-ingress` container listens on `:443`, terminates TLS,
  forwards plaintext over the CVM's loopback to `nyx-tee:8080`.
- `nyx-tee` runs `axum` on `:8080`. **All app logic sees plaintext;
  the TLS termination is inside the encrypted CVM memory, so this
  is safe.**
- The `/evidences/` path is served by `dstack-ingress` directly, not
  by `nyx-tee`.

### 10.4 What we DROP from the prior OpenAPI design

The earlier OpenAPI spec had an X25519 + AES-GCM "session envelope
inside TLS" for clients that distrust the LB. **RA-TLS supersedes
that entirely** — there is no LB in the trust path, the TLS endpoint
is inside the enclave. We'll remove the `session.setup` / `rekey`
WS ops in the revised OpenAPI spec.

---

## 11. Encrypted secrets management

Operational secrets we need inside the TEE: Helius RPC URL +
API key, DNS provider API token (for ACME DNS-01), perhaps a
Slack webhook for monitoring.

Pattern (per dstack docs):

1. On Phala Cloud dashboard, set these as **encrypted env vars** when
   deploying. The dashboard encrypts them client-side to the TEE's
   `env_encrypt_pubkey` (which itself is derived from the dstack-kms
   root key + the path `env`).
2. When the CVM boots, dstack decrypts them before passing to the
   containers as standard env vars.
3. The plaintext lives only in encrypted CVM memory.

Notes:

- `allowed_envs` in `app-compose.json` is a whitelist of env var
  names the workload may read. Adding a new var changes compose-hash,
  which requires a new authorization in dstack governance and a new
  multisig rotation on Solana. **Treat env var additions like code
  changes.**
- We do NOT use long-lived secrets inside the TEE that we couldn't
  re-acquire. RPC keys can be rotated; the Ed25519 signer cannot be
  recovered if lost, but it's deterministic so it's always
  re-derivable from dstack-kms.

---

## 12. Dev workflow

For local development, no TDX hardware needed.

```sh
# One-time: build the dstack simulator (Rust)
git clone https://github.com/Dstack-TEE/dstack.git ~/dstack
cd ~/dstack/sdk/simulator
./build.sh

# Each session: start the simulator
~/dstack/sdk/simulator/dstack-simulator &
export DSTACK_SIMULATOR_ENDPOINT=$(realpath ~/dstack/sdk/simulator/dstack.sock)

# Then in the repo:
cd nyx-monorepo
cargo run -p nyx-tee -- --config crates/nyx-tee/dev.toml
```

The simulator exposes the same Unix-socket API the production TEE
does. `getQuote()` returns a stub quote (not Intel-signed), `getKey()`
returns deterministic bytes from a local seed file. All other API
shapes are identical to production.

For TS SDK development that depends on a running TEE, we'll add an
`SDK_TEE_ENDPOINT` env var the SDK reads; tests skip if unset.

### 12.1 Integration test surface

New test files to add as part of Phase 1:

| File | Purpose |
|---|---|
| `crates/darkpool-matcher/tests/parity.rs` | Lift the run_batch litesvm test into the new crate; assert byte-for-byte identical output between the lifted matcher and the (still-present) litesvm version. Sunset the litesvm version at Phase 5. |
| `crates/nyx-tee/tests/boot.rs` | Spin up the simulator + nyx-tee; assert /attestation, /info, /tree/root return sane data. |
| `crates/nyx-tee/tests/settle.rs` | Drive the full pipeline (place orders → wait for match cycle → assert on-chain settle tx confirmed). Uses litesvm as the L1 mock. |
| `packages/sdk/tests/tee-attestation-verifier.test.ts` | Client-side: fetch /attestation from the simulator, assert dcap-qvl (Phala API or local) accepts the quote, compose-hash matches. |
| `packages/sdk/tests/tee-trade-flow.test.ts` (env-gated, replaces `er-trade-flow.test.ts`) | The full devnet flow against a Phala-deployed staging CVM. |

---

## 13. When to revisit the six decisions

The six locked-in choices have explicit re-evaluation triggers:

| Decision | Re-evaluate when |
|---|---|
| **D1 (Phala Cloud)** | (a) we hit Phala's free-tier limits and managed pricing exceeds $1.5k/mo, OR (b) a security audit flags Phala's KMS-operator key handling as a risk for our user base, OR (c) we close a fundraise that funds bare-metal procurement. |
| **D2 (Admin multisig rotation)** | (a) we ship a working `dcap-qvl` port to Solana BPF (community work or our own), OR (b) we get a finding that the multisig is the actual concentration of risk in our threat model, OR (c) Solana ships a higher-CU-budget tx mode that makes on-chain quote verification cheap. |
| **D3 (Custom domain)** | (a) we want to support hardware wallets that pin the dstack-gateway domain natively — gateway domain becomes viable; OR (b) we want per-user subdomains for routing (custom only). |
| **D4 (In-TEE prover)** | The Phase-1 benchmark shows ≥3× slowdown vs bare metal, or memory pressure forces a TEE host size > 32 GB RAM. Flip to external-prover. |
| **D5 (`BATCH_MS = 2000` default)** | (a) the Phase-1 settle-pipeline benchmark shows finality consistently above 3 s — bump the default to 3 s or 5 s; (b) a specific market needs faster fills (sub-second) — investigate the queue-batching pattern or split that market to its own circuit instantiation; (c) a market is very thin and the fixed 2 s tick wastes RPC — tune that market's `batch_ms` in `MatchingConfig` higher (10-30 s). The per-market knob is in place from day one; the default is just the new-market template. |
| **D6 (TEE-as-indexer)** | (a) TEE host RAM hits 70%+ utilisation on the indexer side under load — split the indexer to its own service; (b) we want read-replica scaling for hot devnets / mainnet → run multiple `nyx-tee` containers behind a load balancer (all derive the same dstack keys; matcher leader-election needed); (c) a non-Nyx app wants to consume our indexer reads — expose a public read-only mirror. |

Each flip is small-scoped — none of them change the wire contract,
the on-chain code, or the cryptographic invariants.

---

## 14. What this document is NOT covering

- **Attestation deep-dive** → `docs/tee-attestation-flow.md`
- **Migration sequence + component classification** → `docs/tee-v2-migration.md`
- **API wire contract** → `docs/tee-api-openapi.yaml`
- **Cryptographic invariants** → `CRYPTOGRAPHY.md`
- **Custody-layer architecture** → `docs/ARCHITECTURE.md`
- **Pre-PR validation discipline** → `CLAUDE.md`

---

## 15. Reading list before implementation

For whoever picks up Phase 1:

1. This whole doc.
2. `docs/tee-attestation-flow.md` (sister doc).
3. `docs/tee-v2-migration.md` for the broader plan.
4. `docs/tee-api-openapi.yaml` for the wire contract.
5. Phala docs: `phala-docs/dstack/overview.mdx` + `local-development.mdx` + `getting-started.mdx`.
6. Phala docs: `phala-cloud/cvm/create-with-docker-compose.mdx` + `cvm/set-secure-environment-variables.mdx`.
7. Phala docs: `phala-cloud/networking/setup-custom-domain.mdx` + `phala-cloud/networking/domain-attestation.mdx`.
8. dstack source: `dstack/sdk/rust/` (the SDK we'll consume) + `dstack/sdk/simulator/`.
9. ark-groth16 docs + the existing snarkjs prover at
   `packages/sdk/tests/helpers/match-batch-prover.ts` (the spec
   we're porting).

Only then — write code.

---

*Maintained as the single source of truth for in-TEE design. Any PR
that changes the binary's structure, the boot sequence, the
persistence model, the key-derivation paths, or the dstack SDK calls
used must update this doc in the same PR.*
