# Nyx TEE — Internal Architecture

> Design of the in-CVM matching engine + settler (`crates/nyx-tee/`).
> Read with `docs/tee-api-openapi.yaml` (the wire contract). Pairs with
> `docs/tee-attestation-flow.md` (the attestation deep-dive).
>
> **Status:** implemented and validated end-to-end on a live Phala CVM
> (`cvm-settle-e2e` real settle + load generator).
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
| D6 | **Indexer architecture** | Inside the TEE, shared in-memory state via `tokio RwLock` | The TEE already holds the Merkle mirror + nullifier set + lock state in RAM to do matching — exposing `/tree/*` over the same state is essentially free. One deployment, one attestation chain. Clients who don't trust the TEE retain the trustless fallback (read `MerkleTree[tree_id].current_root` + PDAs directly from Solana). See §5.5. |

Everything below assumes those six choices. Section 14 documents the
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
│  │   │  Groth16 prover (in-Rust — ark-groth16 | rapidsnark FFI)     ││ │
│  │   │  Settle scheduler (concurrent, K shard fee-payers)            ││ │
│  │   │  K Merkle mirrors (programs/vault/src/merkle.rs lifted)       ││ │
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
┌──────────────────────────── Solana devnet ───────────────────────────────┐
│  vault (the only on-chain program — custody + Groth16 verifier +         │
│    batched atomic settlement)                                            │
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

# Cryptography (must keep byte-identical to darkpool-crypto).
# arkworks pinned at 0.5 to match the workspace (darkpool-crypto +
# ark-circom 0.5.0 both use ark-* 0.5). The in-TEE prover uses
# ark-circom 0.5.0 (added in PR 4g.4b), which re-exports
# ark-groth16 — we don't depend on ark-groth16 directly.
darkpool-crypto = { path = "../darkpool-crypto" }
ark-circom = "0.5.0"
ark-bn254 = "0.5"
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
├── oracle/              # Pyth pull-pattern: Hermes fetch + VAA verify + cache (§5.6)
│   ├── mod.rs
│   ├── cache.rs         # Arc<RwLock<OracleCache>> shared with matcher tick
│   ├── hermes.rs        # HTTPS client for hermes.pyth.network
│   ├── vaa.rs           # Wormhole VAA parser + guardian-set sig verification
│   └── sync.rs          # background tokio task that refreshes the cache
├── prover/              # in-process Groth16 prover for VALID_MATCH_BATCH
│   ├── mod.rs
│   ├── witness.rs       # build witness from matcher output
│   └── groth16.rs       # ark | rapidsnark backend (NYX_TEE_PROVER), N=16
├── settle/              # on-chain settle pipeline
│   ├── mod.rs
│   ├── payload.rs       # MatchResultPayload construction
│   ├── sign.rs          # Ed25519 signing using the TEE-derived shard key
│   ├── worker.rs        # concurrent lock/extend/settle + (key[j],tree[j]) round-robin
│   ├── lock_note.rs     # per-match input-note locks (concurrent Tx A)
│   ├── assemble.rs      # tag each match with output tree_id + fee-payer
│   ├── alt.rs           # per-batch ALT create + chunked extend (MAX_EXTEND_ADDRESSES=25)
│   └── alt_pool.rs      # rolling pool of per-batch ALTs (512-slot cooldown recycle)
├── merkle/              # K local mirrors of vault's sharded Merkle trees
│   ├── mod.rs
│   ├── mirror.rs        # one MerkleMirror per shard
│   └── sync.rs          # route leaf-append events to mirrors[tree_id]; reconcile each
├── persistence/         # LUKS-encrypted snapshots (book + leaves + outbox)
│   ├── mod.rs
│   └── snapshot.rs
├── keys/                # dstack-derived keypair management
│   ├── mod.rs
│   └── ed25519.rs       # getKey("nyx/ed25519-signer/v1/{j}") → K Ed25519 keypairs
└── config.rs            # env-driven config (Helius URL, num_trees, prover, concurrency)
```

### 2.3 Two crates carrying the matching logic

The matching logic lives in standalone crates (extracted from the
former on-chain matching program when it was removed) so it has no
Anchor / Solana deps and can be unit-tested directly:

- `crates/darkpool-matcher/` — the uniform-clearing-price + FIFO
  algorithm (`run_batch` / `run_batch_capped`) and adjacent state
  structs. No Anchor / Solana deps. Pure input (open orders) →
  output (matches + fees + clearing price). `nyx-tee` consumes this
  crate directly, and `tests/parity.rs` pins its behavior. **Single source of
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
      • Calls `client.get_key("nyx/ed25519-signer/v1/{j}")` for
        j∈0..num_trees — K deterministic 32-byte seeds.
      • Derives K Ed25519 keypairs (one per shard fee-payer). The
        pubkeys are stable for the lifetime of this compose-hash.
      • Loads persistence snapshot from LUKS disk (if present) and
        replays since the last snapshot.
      • Syncs the K Merkle mirrors from on-chain MerkleTree[0..K]
        (cold-boot from NYX_TEE_SYNC_FROM_SLOT).
      • Verifies each Ed25519 pubkey is registered in the on-chain
        vault_config.tee_pubkeys set. If not, refuses to settle until
        admin runs the rotation ceremony (§7).
      • Spawns the `oracle_sync` background task (§5.6) — does an
        initial Pyth fetch + guardian-sig verify so the cache is
        warm before matching starts. Refuses to run if Hermes is
        unreachable at boot.
      • Starts the matching loop, the settle scheduler, and the API
        server.
7.  Container marks itself healthy. Phala gateway routes traffic.
```

Boot time end-to-end is ~30-60s under normal conditions: the TDX
attestation + KMS handshake + ACME cert (if cold) dominate.

---

## 4. Key bootstrap — the K Ed25519 shard signers

The most important keys in this system. They're what
`vault.tee_forced_settle_batched` checks every settle. Tree-sharding
derives **K = `num_trees`** of them (one per shard) so concurrent settle
Tx D's carry distinct fee-payers and share zero writable accounts (§6).
With `num_trees = 1` this collapses to the single-signer case.

### 4.1 Derivation

```rust
// crates/nyx-tee/src/keys/ed25519.rs
use dstack_sdk::DstackClient;
use ed25519_dalek::SigningKey;

// One signer per shard: path nyx/ed25519-signer/v1/{j}, j ∈ 0..num_trees.
pub async fn derive_signer(client: &DstackClient, tree_id: u8) -> Result<SigningKey> {
    // dstack returns 32 bytes of deterministic KDF output keyed by
    // (deployer_id, app_hash, path). Same compose-hash + path → same bytes;
    // distinct paths → independent keys, so each shard's fee-payer differs.
    let path = format!("nyx/ed25519-signer/v1/{tree_id}");
    let key_resp = client.get_key(Some(path), None).await?;
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
| KMS root key full rotation (rare, security incident) | All app keys re-derive. All K signer pubkeys change. Admin multisig must run `set_tee_pubkey` with the new K-pubkey set. |
| Image upgrade (new compose-hash) | New `app_hash` → KDF emits new seeds → new signer pubkeys. Admin runs the rotation ceremony (registers all K) before the new image can settle. |
| `num_trees` increase | The new shards' signer paths (`…/v1/{j}` for the new j) derive fresh keys; admin registers the expanded K-pubkey set + funds the new fee-payers. |
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

#### Who triggers a batch (conceptual shift vs v3.5)

In v3.5 the matching algorithm was an on-chain ix; **someone had
to call `run_batch` from outside the chain** to make matching
happen. The TEE-pubkey signer gate restricted *who* could call it,
but the trigger itself was an external Solana transaction.

In v2 the matching algorithm lives inside a long-running daemon
process. **No external party can trigger a match.** The TEE's own
`tokio::time::interval` decides when each tick fires. Three
consequences:

* Clients can't rush their own fill. A market maker can't pay
  extra fees to "settle now" — they wait for the next tick like
  everyone else.
* MEV searchers can't sandwich a batch by front-running its
  trigger tx. There is no trigger tx.
* A batch with zero matches leaves zero on-chain trace. Network
  observers see only the TEE's idle uptime, not whether it
  matched orders this tick.

The trade-off is **TEE liveness becomes the matching SLA**. If the
CVM stops ticking (crash, host migration, dstack-kms revocation),
matching stops too. The settle scheduler is decoupled — already-
matched batches can keep settling after a TEE restart via the
LUKS persistence path (§8) — but new fills require the daemon up.
That's the same liveness story as Phala Cloud's general SLA + our
restart-from-snapshot recovery.

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
1. Read each MerkleTree[j] once (current_root, leaf_count) +
   VaultConfig (num_trees, deployed/floor slot).
2. Scan getTransactionsForAddress(vault_program_id) — Helius gTFA, full
   txs, status: succeeded, sortOrder asc — from the floor slot forward,
   paged by paginationToken (≤1000 full txs/call). One call per page
   replaces the old getSignaturesForAddress + per-signature getTransaction
   fan-out (1 + N calls).
3. For each tx, parse the leaf-append events emitted by
   deposit / withdraw / merge / tee_forced_settle_batched (each carries tree_id).
4. Replay each leaf into mirrors[tree_id] in order.
5. Stop when every mirror[j].root() == MerkleTree[j].current_root.
```

The live loop re-scans gTFA from the last-seen slot each interval (the
boundary slot is re-included; the append-only mirror skips already-applied
indices, so overlap is harmless). gTFA is Helius-exclusive and retains ~2
weeks on devnet — fine, since the mirror always cold-boots from a recent
`from_slot` floor (deploy / reset slot), never genesis. (With `num_trees =
1` this is the original single-mirror path.)

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

**Status (Phase 2a + 2b, live):** the per-shard `MerkleMirror`
(`crate::merkle::mirror`, held as `Vec<MerkleMirror>` indexed by
`tree_id`) + the `/tree/root` (public), `/tree/inclusion` +
`/tree/leaves` (bearer) endpoints are implemented, with byte-parity to
`programs/vault/src/merkle.rs` and inclusion proofs ported from the
SDK's `MerkleShadow`. The `/tree/*` endpoints take an optional
`?tree_id` (default 0) selecting the shard; `/tree/root` echoes it back,
and transparency `leaf_count` sums across shards. The cold-boot + live
**sync** (`crate::merkle::sync`) fills the mirrors from on-chain
leaf-append events — `NoteCreated` (deposit, index+value) and
`TradeSettled` (settle; indices from the event, values from the settle
ix's `MatchResultPayload`), each carrying `tree_id` — routes them to
`mirrors[tree_id]`, applies them in per-shard `leaf_index` order, and
reconciles each `mirror.root()` against its `MerkleTree[j].current_root`
(best-effort; on-chain stays canonical). Reconcile classifies a
mismatch as **Behind** (mirror lagging on-chain — transient, warns once)
vs **Diverged** (roots at the same count disagree — a real fault); an
append-only mirror cannot self-heal from an on-chain `reset_merkle_tree`
(there is no reset event), so a deliberate tree reset requires a CVM
cold-boot from the new floor slot. Spawned at boot in `main.rs`
against the configured cluster. `/instruments` (public market metadata)
+ `/transparency` (public proof-of-reserves — the mirror root/count +
per-mint on-chain `OutstandingMint.outstanding` vs vault SPL balance +
engine identity + scheduler stats) are live (Phase 2c); `/account` is
deferred by design (501 — clients compute balances/notes from `/tree/*`
+ their keys, §11.3). The `tree` WS channel is a later phase. The live
RPC paths validate on devnet.

#### Trustless fallback

This is the critical property that makes TEE-as-indexer
defensible. **Clients who don't trust the TEE for read queries can
always:**

- Read `MerkleTree[tree_id].current_root` directly from Solana (~1 RPC
  call per shard, trustless).
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

### 5.6 Oracle sync — pull-pattern from Pyth Hermes

The matcher's circuit-breaker check + the `pyth_at_match` field on
every `MatchPair` need a fresh oracle TWAP. In v3.5 this came from
an on-chain Pyth `PriceUpdateV2` account that someone else had to
update. In v2 the TEE reads Pyth directly via the Hermes pull API,
verifies the Wormhole-guardian signature in-process, and caches
the result for the matching tick to consume.

#### Two-stage pattern

```
┌─── oracle_sync background task ──────────────────────┐
│                                                       │
│  tokio interval (~1 s):                              │
│    GET https://hermes.pyth.network/v2/updates/       │
│        price/latest?ids[]=<feed_id>                  │
│    → parse VAA (Wormhole guardian signed)            │
│    → verify signature against guardian set (cached)  │
│    → write cache: {                                  │
│        twap, confidence, exponent,                   │
│        publish_time, publish_slot                    │
│      }                                               │
└──────────────────────┬───────────────────────────────┘
                       │ writes
                       ▼
                 OracleCache (Arc<RwLock>)
                       │ reads
                       ▼
┌─── matching tick (every BATCH_MS = 2 s) ─────────────┐
│                                                       │
│  oracle = cache.snapshot(market)                     │
│  if (now_slot − oracle.publish_slot) > MAX_STALE:    │
│      tracing::warn!("oracle stale, skipping tick");  │
│      continue                                         │
│  darkpool_matcher::run_batch(book, oracle, ...)      │
└──────────────────────────────────────────────────────┘
```

The two stages are **independent tokio tasks** communicating only
through `Arc<RwLock<OracleCache>>`. The matching tick reads from
cache in sub-microsecond time — no HTTPS in the critical path.

#### Why Hermes, not on-chain Pyth

Pyth runs a "pull oracle" model — fresh prices live on the
Hermes web service, signed by Wormhole's guardian set. The
Solana on-chain `PriceUpdateV2` account only refreshes when
someone pushes an update tx, which costs CU and tx fees. In v2:

- The TEE pulls directly from Hermes over HTTPS (no on-chain
  read needed for matching).
- Hermes is a public CDN — no API keys, no auth, no rate-limit
  per IP under normal load. Fallback Hermes endpoints exist
  (hermes-beta.pyth.network etc.) for redundancy.
- Wormhole guardian signature verification happens entirely
  in-process. The TEE doesn't need to trust Pyth's web infra;
  it only needs to trust the guardian set (whose pubkeys are
  baked into the TEE binary, covered by compose-hash).

#### Cache structure

```rust
// crates/nyx-tee/src/oracle/cache.rs (PR 4)
pub struct OracleCache {
    /// Per-market entries — one Pyth feed per market.
    entries: HashMap<MarketId, CachedPrice>,
}

pub struct CachedPrice {
    pub twap: u64,
    pub confidence: u64,
    pub exponent: i32,
    /// Pyth's reported publish_time, translated to Solana slot.
    /// Drives the staleness check inside the matching tick.
    pub publish_slot: u64,
    /// The full VAA bytes — kept so the settle scheduler can
    /// optionally attach a PriceUpdateV2 update tx alongside
    /// `verify_match_batch` for v3 on-chain-verified Pyth (future).
    pub vaa: Vec<u8>,
}
```

`MAX_STALE` is configurable (default 5 slots ≈ 2 seconds — same
order as the batch tick). If Hermes is unreachable for long
enough, the cache goes stale and matching ticks pause. Orders
accumulate in the book; matching resumes when the next sync
succeeds.

#### Trust chain post-PR-4

When the TEE submits `verify_match_batch` on-chain, the trust
chain for `pyth_at_match` is:

```
TEE Ed25519 signature over MatchResultPayload
   (verified on-chain against vault_config.tee_pubkeys —
    the signing shard key must be in the registered set,
    rotated only by the multisig per D2)
   ↓
contains pyth_at_match as a field
   ↓
VALID_MATCH_BATCH Groth16 proof binds pyth_at_match into
the batch root via the circuit-breaker constraint
(∀ slot: |price − pyth_twap| ≤ band · pyth_twap / 10000)
   ↓
on-chain verifier accepts the proof + reads pyth_at_match
out of the payload + trusts the TEE's attestation that
this came from real Pyth.
```

The on-chain side **trusts the TEE's word** that `pyth_at_match`
is a genuine Pyth value. The trust is rooted in:

1. The TEE Ed25519 key is registered via the multisig rotation
   ceremony (D2 / `docs/tee-attestation-flow.md` §5).
2. The TEE compose-hash is allowlisted in dstack governance.
3. Inside that compose-hash, the `oracle_sync` task is the
   one that verifies the Hermes guardian signature before
   caching.

#### What a malicious TEE could actually do

A compromised TEE *could* claim a false `pyth_twap`, but the
worst it can do is **defeat the circuit breaker** — clear a
batch when the real Pyth says it shouldn't. The
note-conservation invariant (`note.amount == trade_leg +
change_leg + fee`) holds independently of `pyth_twap` because
it's enforced inside VALID_MATCH_BATCH against the matcher's
own claimed amounts. So no funds are lost; the worst-case
attack is "the TEE lets a non-economic batch through."

This is the v2 trade-off we accepted to skip the per-batch
on-chain Pyth-verification cost. v3 closes the gap: attach a
fresh Pyth `PriceUpdateV2` to `verify_match_batch`, have the
vault read the on-chain Pyth account directly, compare to the
`pyth_at_match` claimed in the payload. ~100k CU + one ALT
entry per batch — the architecture supports it whenever we
decide to enable it.

#### Module layout (to land in PR 4)

```
crates/nyx-tee/src/oracle/
├── mod.rs        Public surface: OracleCache + OracleSnapshot
├── cache.rs      Arc<RwLock> wrapper + staleness check
├── hermes.rs     HTTPS client for the Pyth Hermes API
├── vaa.rs        Wormhole VAA parser + guardian-sig verification
└── sync.rs       The background tokio task driving the cache
```

The interval task in §5.4 reads from `OracleCache` — no direct
network calls, no shared state with the matching algorithm
beyond the snapshot.

---

## 6. Settle scheduler — the v3.5 batched pipeline, server-side

For each batch with ≥1 real matches:

1. **Pad to N=16**: same logic the SDK's `batched-settle.ts` uses
   today. Real matches first, dummy slots after.
2. **Generate VALID_MATCH_BATCH Groth16 proof.**
   - In-process prover against `circuits/build/match_batch_n16/circuit_final.zkey`.
   - Backend selectable at boot via `NYX_TEE_PROVER` = `ark` (default,
     `ark-groth16`) | `rapidsnark` (FFI). The image ships both (built
     `--features rapidsnark`); see §9.4. Both emit byte-identical proofs.
   - The zkey is baked into the Docker image, so its bytes are
     covered by compose-hash.
   - Witness assembly mirrors `packages/sdk/tests/helpers/match-batch-prover.ts`.
3. **Build `MatchResultPayload` for each real match.**
   - Borsh shape `canonical_payload_hash(payload)` — see CLAUDE.md §6.
   - Each match is round-robined onto an **output shard** `j = idx %
     num_trees`, paired with the shard's fee-payer key `tee_keypairs[j]`
     (§4, §8). The continuation/change note inherits the same shard so
     the re-lock targets the right `merkle_tree[j]`.
4. **Sign each payload's canonical hash** with that shard's Ed25519
   signer key (`tee_keypairs[j]`, which is also the tx fee-payer and the
   `tee_authority` — one key, three roles, no extra signature).
5. **Submit the v3.5 settle pipeline (concurrent throughout):**
   - **Tx A — lock**: the per-match input-note locks, two-pass
     (build/sign sequentially off a shared blockhash, then send all
     **concurrently**) so 32 locks confirm in ~one block window instead
     of serially. Each lock reads its note's shard `merkle_tree[tree_id]`.
   - **Tx B — `verify_match_batch(merkle_root, expiry, proof)`** — once
     per batch.
   - **Tx C — per-batch ALT create + chunked extend**: the per-batch ALT
     now holds 9 PDAs/match (locks + consumed + nullifier + marker), so
     the extend is **chunked** (`MAX_EXTEND_ADDRESSES = 25`) and the
     chunks fired **concurrently**; the worker re-reads the ALT's
     canonical on-chain address order before building any settle tx (see
     CRYPTOGRAPHY.md §9). A rolling ALT pool (`settle/alt_pool.rs`)
     recycles tables past the 512-slot deactivation cooldown.
   - **Tx D — `tee_forced_settle_batched(tree_id, payload, match_index,
     merkle_proof)`** — once per real match, all fired **concurrently**
     (bounded by `NYX_TEE_SETTLE_SEND_CONCURRENCY`, default 16). Because
     each carries a distinct `(tee_keypairs[j], merkle_tree[j])`, the
     concurrent Tx D's share **zero** writable accounts, so the leader
     co-includes them in one block instead of spreading them across
     slots (the single-tree, single-fee-payer plateau).
   - **Tx E — `close_batch_validity_marker(merkle_root)`** — once per
     batch, after all settles confirm.
6. **Update the local Merkle mirrors** — route each appended leaf to
   `mirrors[tree_id]` (we know the leaf hashes ahead of time — compose
   them locally as the on-chain code does). §8.
7. **Mark `batch_id` settled** in the in-memory ledger; emit on
   `settlement` WS channel.

This is the server-side evolution of the path
`packages/sdk/tests/helpers/batched-settle.ts` implements: moved
in-enclave, snarkjs swapped for the in-process backend, and the whole
lock→extend→settle pipeline restructured from serial awaits to
concurrent sends + tree-sharded fee-payers. The residual latency tail is
ALT-activation finality (~1 slot), not darkpool compute — it closes
under Alpenglow sub-second finality, not via code here.

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
     • dstack-kms derives K NEW Ed25519 seeds (because app_hash is
       in the KDF input) — one per shard path …/v1/{j}.
     • The new CVM's K shard pubkeys differ from the on-chain
       vault_config.tee_pubkeys set.
     • New CVM exposes all K pubkeys via GET /attestation + /info.
5. Admin (one signer of the 3-of-5 multisig):
     • Fetches the new attestation: curl https://api.nyx.example.com/attestation
     • Verifies the quote off-chain:
         docker run -p 8080:8080 dstacktee/dstack-verifier:latest &
         curl -d @quote.json localhost:8080/verify | jq
     • Confirms compose-hash in event_log matches expected.
     • Constructs set_tee_pubkey([k0..k_{K-1}]) tx (registers the whole
       new K-key set in one ix); posts to Squads as a proposal. Funds
       each new shard fee-payer.
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
- **K Merkle-leaf mirrors** — one `MerkleMirror` per shard
  (`Vec<MerkleMirror>`, indexed by `tree_id`). The on-chain tree is
  split into `num_trees` per-shard `MerkleTree` accounts; the sync
  routes each appended leaf (`NoteCreated`/`TradeSettled`, now carrying
  `tree_id`) to `mirrors[tree_id]`, and reconcile compares each
  `mirror.root()` against its `MerkleTree[j].current_root`. 32 B ×
  total leaf_count; transparency `leaf_count` = sum across shards.
- **K Ed25519 signer keys** — `tee_keypairs[0..num_trees]`, derived from
  indexed dstack paths `nyx/ed25519-signer/v1/{0..K-1}` (§4). Each is a
  shard fee-payer / `tee_authority` / settle-signer.
- **Settle outbox** — pending L1 txs that haven't confirmed yet,
  needed for crash-recovery so we don't double-submit.
- **Per-batch ALT pool** — a rolling pool of per-batch ALTs
  (`settle/alt_pool.rs`) recycled past the 512-slot deactivation
  cooldown, plus the `batch_id → ALT pubkey` mapping for in-flight
  settles.

Persistence strategy (Phase 1):

- LUKS-encrypted disk volume provisioned by dstack-kms at boot. Key
  is deterministic from `app_id` — survives instance migration, lost
  if the entire compose-hash is retired. Encryption-at-rest is
  transparent to the app: it just does file I/O to `NYX_TEE_STATE_DIR`
  (default `/var/lib/nyx-tee`).
- `bincode` for compact encoding. Atomic write-rename pattern
  (`*.tmp` → fsync → rename).
- **Auth state (`accounts.db`) — live (Phase 1b).** The account
  registry + JWT revocation denylist are low-churn, so they're
  persisted **write-on-change** (after each register/revoke) rather
  than on a timer; see `crate::persistence::auth` + §11.6.
- **Book / Merkle leaves / settle outbox — scaffold.** These are
  high-churn, so they take the **periodic 5 s snapshot** path
  (`crate::persistence::snapshot`, not yet wired). On boot: load latest
  snapshot; for events since the snapshot timestamp, replay from
  on-chain history (leaf-append events) + client resubmission for open
  orders.

Persistence is **best-effort + complement, not the source of truth**.
On-chain state is canonical for note ownership / settled balances.
Order intent is signed by the client — clients are expected to
resubmit if the TEE loses an order on restart. Market makers using
the WS `cancel_on_disconnect: true` opt-in are auto-cancelled on
TEE crash, which is the safe default.

---

## 9. The Groth16 prover, inside the TEE

### 9.1 Implementation plan (split across PR 4g.4a + 4g.4b)

The prover is built in two stages so the byte-equality-critical
foundation lands and is tested independently of the witness-calc +
proving dep wrangling:

**PR 4g.4a — deterministic foundation (DONE, commit `e9962b0`).**
Pure-Rust port of the byte-critical pieces of
`packages/sdk/tests/helpers/match-batch-prover.ts`, behind a
`Prover` trait whose stub returns `NotYetWired`:

- `prover/witness.rs` — `MatchSlotWitness` type + `dummy_slot` +
  `pad_batch`. All Poseidon goes through `darkpool-crypto` for
  parity.
- `prover/leaf.rs` — two-stage Poseidon12 → Poseidon9 leaf hash +
  Merkle root + inclusion path. Pinned regression hex for the
  dummy-slot leaf.
- `prover/constraints.rs` — conservation validators (quote = base
  × price; a/b-amount sums) surfacing named errors before the
  circuit ever sees a bad witness.
- `prover/inputs.rs` — the snarkjs-format single-element public-
  input vector (the batch Merkle root).
- `prover/groth16.rs` — the `Prover` trait + `NotYetWiredProver`
  stub.

**PR 4g.4b — ark-circom 0.5.0 wiring (planned).** Replaces the
stub's `Err(NotYetWired)` branch with a real proof:

- Use **`ark-circom` 0.5.0** (the published crates.io version —
  it depends on `ark-*` 0.5.0 from crates.io with NO
  `[patch.crates-io]` hack, so it's a clean drop-in for our
  arkworks-0.5 workspace; `darkpool-crypto` already pulls ark-*
  0.5). `ark-circom` bundles three things we need in one dep:
  witness generation (wasmer 4.4.0 consuming `circuit.wasm`),
  `.zkey` parsing, and `ark-groth16` proof generation.
- Load `circuit.wasm` + `circuit.r1cs` from
  `/circuits/build/match_batch_n16/` at startup; cache the
  `CircomBuilder`. (The artifacts ship in the Docker image; baked
  into compose-hash, so any tampering changes attestation.)
- Push the ~30 named inputs per slot from `MatchSlotWitness`;
  call `ark-groth16` prove with `CircomReduction`.
- Convert `ark-groth16`'s `Proof<Bn254>` to the on-chain
  `groth16-solana` BE-32 byte format (pi_a negated; pi_b/c in
  the snarkjs G1/G2 encoding). ~80 LOC converter. This is the
  most likely class of bug during the port (Fr endianness, point
  compression) — gated by a parity test that verifies a generated
  proof against the SAME `vk_match_batch_n2` consts the on-chain
  verifier compiles (N=2 for a lighter test; pot16 sufficient).

The `Prover` trait surface stays identical between 4g.4a and
4g.4b — the swap is internal.

### 9.2 Why ark-circom (and not circom-witnesscalc)

Researched 2026-05-29. Our `match_batch.circom` uses circom 2.2.2
+ circomlib (poseidon, comparators, bitify) with compile-time-
bound loops and no signal-conditional ternaries or EdDSA — it sits
on ark-circom's happy path. The earlier candidate,
`circom-witnesscalc`, has documented gaps (EdDSA, signal ternary,
a perf regression) and only does witness gen — we'd still wire
ark-groth16 + a zkey parser separately. ark-circom does all three
in one battle-tested dep with zero dep-graph friction against our
workspace. Decision recorded in PR 4g.4b's task.

### 9.3 Benchmark to gate the design (D4 re-evaluation trigger)

- Run the same N=16 proof on:
  - Bare-metal control (M3 MacBook or a non-TEE EC2 r6i.4xlarge)
  - Phala Cloud TDX tier (the one whose benchmarks we cited)
- Acceptance: proof time on TDX ≤ 3 × bare-metal. (Phala's
  published zkTLS-in-CPU-TEE was 3.78x — Groth16 should be similar
  or better, since it's smaller and has tighter memory patterns.)

### 9.4 Perf-swap — rapidsnark backend (LANDED), and what's left

The prover backend is selectable at boot via `NYX_TEE_PROVER` = `ark`
(default) | `rapidsnark`, behind the same `Prover` trait — the swap is
internal, the trait surface unchanged.

- **Option A — rapidsnark via FFI (LANDED).** The image is built
  `--features rapidsnark` and ships **both** backends, so the same image
  + instance can A/B-prove by flipping one env var. The C++ build
  pipeline does widen the compose-hash + audit surface — that's the cost
  we accepted. **Measured result:** the real lever is **vCPU count**,
  not the backend — rapidsnark is ~**1.4×** ark on an 8-vCPU CVM (not
  the 5-10× the single-thread literature suggests), and on 1 vCPU the
  two are close. A full ark/rapidsnark × 1/8-vCPU table is in the
  `rapidsnark-ab-results` engineering note. Net: proving (~4-5 m/s) is
  now the throughput ceiling — on-chain settle (post tree-sharding) is
  no longer the bottleneck.
- **Option B — external-prover design (still deferred).** TEE signs the
  public-input hash, a sidecar generates the proof, the vault verifies
  both. The external prover sees the witness, but the witness is mostly
  already-public-after-settle info anyway. Deferred: we don't pay the
  external-prover trust-surface cost yet.

Pushing total throughput past the ~5 m/s prover ceiling now needs
prover-hardware scaling (more vCPUs / GPU / multi-TEE), a separate
track. The roadmap row is "In-TEE prover perf swap" in
`docs/site/09-roadmap-and-status.md` § Near-term.

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

## 11. User authentication model

**At a glance:** three identities serve three different roles. The
user's Solana wallet pubkey is **never** a parameter in a TEE API
request — privacy of the wallet-to-trading-key link is a core
dark-pool property, not an implementation detail.

### 11.1 The three identities

| Identity | Form | Where it lives | What it authenticates |
|---|---|---|---|
| **Solana wallet** (spending key) | Solana Ed25519 keypair | User's wallet / HSM — **never** sent to the TEE | On-chain `create_wallet`, `deposit`, `withdraw` ixs only |
| **Trading key** | Ed25519 keypair, freshly generated client-side (or derived from the spending key via a documented KDF for convenience) | Client-side, rotatable | Each individual order body sent to the TEE |
| **API credentials** | `(api_key, api_secret, passphrase)` triple | Provisioned at account-register time, stored client-side | `POST /auth/token` to exchange for a short-lived JWT bearer |

The wallet pubkey and the trading key are deliberately decoupled. An
observer who somehow penetrates RA-TLS sees only the trading key,
never the wallet. An on-chain observer of `MatchResult.owner_*` sees
the trading key too — also unlinkable to the wallet without insider
knowledge.

### 11.2 Two-layer per-request auth

Every authenticated TEE request carries both layers:

```http
POST /orders HTTP/1.1
Authorization: Bearer <JWT from /auth/token>          # Layer A — operational
Content-Type: application/json

{
  "symbol": "SOL-USDC",
  "side": "buy",
  "order_type": "limit",
  "amount": "10",
  "price_limit": "150",
  "min_fill_size": "0",
  "expiry_slot": 320145000,
  "order_id": "0x6f7c…",
  "arrival_nonce": 42,
  "note_commitment": "0xef0d8b6f…",
  "user_commitment": "0xfcb31d19…",
  "trading_key": "ed25519:bs58…",
  "trading_key_signature": "ed25519:bs58…"            # Layer B — cryptographic
}
```

**Layer A — bearer token (operational auth)**

- One-time per session: `POST /auth/token` with `(api_key,
  api_secret, passphrase)` → returns `{access_token: JWT,
  expires_in: 3600}`.
- The JWT carries an `account_id` claim. The TEE uses it for rate
  limiting, account-level blocking, and audit logging.
- Layer A failures (no token, expired, wrong account) return 401
  BEFORE the body is parsed. Order intent is never even seen by an
  unauthenticated caller. Implemented as a `tower::Layer` so every
  authenticated route inherits the check uniformly.

**Layer B — trading-key signature (cryptographic auth)**

For each order, the client signs the canonical hash of the order
body with their trading key:

```
SHA-256(
    b"nyx-order-v1"
  || symbol_bytes
  || side_byte
  || order_type_byte
  || amount_le               // u64 LE
  || price_limit_le          // u64 LE
  || min_fill_size_le        // u64 LE
  || expiry_slot_le          // u64 LE
  || order_id                // 32 bytes
  || note_commitment         // 32 bytes
  || user_commitment         // 32 bytes
  || arrival_nonce_le        // u64 LE
)
```

The order body includes both `trading_key` (the 32-byte pubkey) and
`trading_key_signature` (the 64-byte detached signature). The TEE
verifies via `ed25519_dalek::VerifyingKey::verify_strict(...)` BEFORE
accepting the order into the book.

The `trading_key` bytes are what eventually land in
`MatchResult.owner_buyer` / `owner_seller` and gate on-chain
settlement. Layer B is therefore the load-bearing custody auth.
Layer A is operational only — useful for rate-limit / blocklist /
audit, not for cryptographic finality.

### 11.3 Why is the Solana wallet pubkey NOT in the request?

It isn't, and that's intentional. The chain of trust is:

```
User's wallet (spending key, NEVER sent to the TEE)
   │
   ├──► On-chain: signs create_wallet / deposit / withdraw
   │
   └──► Derives user_commitment = Poseidon2(spending_key, r_owner)
            │
            └──► Goes into each order body as 32 opaque bytes.
                 The TEE cannot invert this to recover the wallet.

Trading key (Ed25519, fresh per user)
   │
   └──► Signs each order body. Its 32-byte pubkey ends up in
        MatchResult.owner_buyer / owner_seller and is what on-chain
        settle verifies — but is NOT linkable to the wallet by any
        observer.
```

The cryptographic linkage from `trading_key` back to the wallet is
something the user provides **on-chain** at withdraw time via the
`VALID_SPEND` proof. That proof's witness includes the spending key,
and the spending key never leaves the user. The TEE is therefore
never in a position to deanonymise a user — even an actively malicious
TEE that ignores the attestation chain.

**Privacy property summarised:** an in-TEE observer sees `(account_id,
trading_key, user_commitment)` — three opaque identifiers. An
on-chain observer sees `MatchResult.owner_buyer = trading_key`. Only
the user themselves holds the keys to link the three.

### 11.4 Replay protection and cancel binding

- `arrival_nonce` (client-supplied monotonic counter, scoped by
  trading_key) prevents submit-replay; the TEE rejects any submit
  whose `(trading_key, arrival_nonce)` pair has been seen.
- `order_id` (client-supplied UUID, scoped globally) gives a stable
  handle for cancel / status lookups.
- `DELETE /orders/{order_id}` requires a fresh signature from the
  SAME `trading_key` that signed the original submit. This mirrors
  the on-chain `cancel_order` ix's PDA-seed enforcement — a
  malicious party who learns the order_id cannot cancel an order
  they didn't place.

### 11.5 Where this is implemented

| Concern | File | Lands in |
|---|---|---|
| JWT issuance (Layer A) | `crates/nyx-tee/src/api/auth.rs` | PR 4e |
| Bearer-token middleware (Layer A) | `crates/nyx-tee/src/api/auth.rs` as a `tower::Layer` | PR 4e |
| Argon2id credential hashing + admin registration + revocation (Layer A) | `crates/nyx-tee/src/api/auth.rs` (`register_account_handler`, `revoke_token_handler`, `ApiCredentials::{from_plaintext,verify_credentials}`) | Phase 1a |
| Per-order signature verification (Layer B) | `crates/nyx-tee/src/api/orders.rs` POST handler | PR 4e |
| `cancel_order` signature check (Layer B) | `crates/nyx-tee/src/api/orders.rs` DELETE handler | PR 4e |
| Canonical body encoding (cross-language) | `crates/darkpool-matcher/src/order_canonical.rs` (shared) + parity test against TS in `packages/sdk/tests/order-canonical-parity.test.ts` | PR 4e |

The wire shapes are pinned by `docs/tee-api-openapi.yaml` (the
`PlaceOrderRequest`, `CancelOrderRequest`, and `TokenResponse`
schemas). Any change to either Layer A or Layer B is a wire-contract
change and lands in lockstep with an SDK update.

### 11.6 Account credential lifecycle (Phase 1a)

API accounts (the Layer-A `(api_key, api_secret, passphrase)` triple)
are **permissioned**, not open-registration — a dark pool shouldn't let
anyone mint operational credentials.

- **Storage.** Credentials are never stored in plaintext. Both the
  `api_secret` and `passphrase` are kept as independent **argon2id**
  PHC strings (random salt + params embedded). `POST /auth/token`
  verifies via argon2's own constant-time check.
- **Bootstrap admin.** *Something* has to create the first account, so
  the TEE seeds one **admin** account from the `NYX_TEE_API_KEY` /
  `NYX_TEE_API_SECRET` / `NYX_TEE_PASSPHRASE` env at boot. The env
  plaintext is hashed and dropped. With persistence on (below), the env
  admin is *merged* into the loaded snapshot only if its `api_key` is
  absent — a persisted registry is authoritative, so rotating the env
  creds after first boot requires the API or a snapshot wipe. If the
  env vars are unset and no snapshot exists, the registry is empty and
  auth rejects everything.
- **Registration.** `POST /admin/accounts` (admin-gated) registers
  further accounts. The admin check is **authoritative against the live
  registry**, not trusted from a JWT claim, so an admin demotion takes
  effect immediately rather than waiting for outstanding tokens to
  expire. A duplicate `api_key` is rejected (409) — registration never
  silently overwrites existing credentials.
- **Revocation.** Each issued JWT carries a random `jti`.
  `POST /auth/token/revoke` denylists the calling token's `jti`; the
  bearer middleware rejects any denylisted token even while its
  signature + `exp` are still valid.
- **Persistence (Phase 1b, live).** The registry + revocation denylist
  are persisted to `accounts.db` under `NYX_TEE_STATE_DIR` (default
  `/var/lib/nyx-tee`, the dstack LUKS mount — see §8). It's
  **write-on-change**: each `register` / `revoke` snapshots the full
  state via an atomic write-tmp→fsync→rename, so a registration or
  revocation survives a restart. Boot loads the snapshot, then merges
  the env admin if absent (first boot seeds + persists immediately).
  Persistence is **best-effort** (§8): a failed write logs but never
  fails the request — auth is off-chain, so the worst case on data loss
  is the admin re-registering. When `NYX_TEE_STATE_DIR` is unset (no
  mounted volume / tests), persistence is disabled and behaviour falls
  back to the in-memory Phase-1a path. Only argon2 hashes are written —
  never plaintext — and the file lives on the encrypted volume.

---

## 12. Encrypted secrets management

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

## 13. Dev workflow

### 13.1 The iterate / spot-check / ceremony loop

TEE work splits across three execution targets — each suited to a
different slice of the dev cycle.

| Slice | Where | What it tests | Cost / cycle |
|---|---|---|---|
| **Iterate locally** (≈ 90%) | `nyx-tee` binary + dstack-simulator on the dev machine | Handler logic, matcher tick, oracle parsing, HTTP shape, integration tests, deterministic key derivation | ~5–15 s rebuild |
| **Spot-check on Phala** (≈ 5%) | Phala Cloud devnet CVM | Phala gateway latency, dstack-ingress RA-HTTPS termination, real `compose_hash` measurements, real dstack-kms key delivery | ~3 min round-trip, ~$0.003 / smoke deploy |
| **Full ceremony rehearsal** (≈ 5%) | Phala Cloud devnet CVM + multisig signers | Real TDX quote signature, Intel TCB chain, MRTD vs governance-approved set, ACME RA-HTTPS binding, end-to-end client `verifyTeeAttestation()` | ~10 min, only when compose-hash changes |

**When to use each:**

* **Iterate locally** for any handler tweak, matcher-algorithm change,
  oracle module change, OpenAPI schema change. Default mode — should
  be where 9 out of 10 commits are written + validated.
* **Spot-check on Phala** before opening a PR that touches the boot
  path (`crates/nyx-tee/src/boot.rs`, `keys/`), the dstack handshake,
  the HTTP surface (`api/`), or anything that affects `compose_hash`.
  One smoke deploy is enough — confirm `info()` returns the
  governance-recorded measurements and `/attestation` returns a quote
  that the t16z Attestation Explorer accepts.
* **Full ceremony rehearsal** only when the compose-hash has
  meaningfully changed (any change to `Dockerfile`,
  `deploy/docker-compose.yaml`, `crates/nyx-tee/Cargo.toml`, or
  `crates/nyx-tee/src/`). Runs the multisig rotation flow from
  `docs/tee-attestation-flow.md` §5 against actually-attested
  measurements. Catches problems the simulator can't see.

### 13.2 What the dstack simulator can and can't do

The simulator (built from `dstack/sdk/simulator/`) exposes the same
Unix-socket API a real TDX CVM does. Same wire format, same JSON
shapes, same error variants — so the `nyx-tee` code path is
**byte-identical** against simulator vs production. That's by design:
it's the lever that lets us spend 90% of dev time off-hardware.

| API call | Simulator | Real TDX CVM |
|---|---|---|
| `info()` | Stub `app_id` / `instance_id` / `compose_hash` / MRTD / RTMR0-3 (deterministic from a local seed file) | Real measurements baked into the running CVM's TDX state |
| `get_key(path, purpose)` | Deterministic 32-byte HKDF output keyed by `(seed, path, purpose)` | Deterministic 32-byte output from dstack-kms's MPC-managed RootKey + the same KDF |
| `get_quote(report_data)` | Well-formed but **cryptographically stub-signed** TDX quote | Real Intel-signed quote, verifiable against TCB cert chain |

The crucial gap: `get_quote()`'s simulator output is structurally
identical to a real quote (every field at every offset is in the
right place), but the signature is from a stub key. So:

- **Byte-level parsing** (VAA wrapper, quote header, event log replay
  against RTMR3) works identically against both.
- **Cryptographic verification** — `dcap-qvl verify`, the TEE
  Attestation Explorer at https://proof.t16z.com/ — **fails** against
  the simulator.
- The SDK's `verifyTeeAttestation()` therefore fails against the
  simulator at the signature step. Clients cannot be fooled by the
  simulator without explicit opt-in.

What that buys us:

| You can validate locally | You cannot validate locally |
|---|---|
| Handler shape (status codes, JSON, headers) | Real Intel TCB signature verification |
| Key derivation determinism + the load-bearing Solana pubkey | MRTD / RTMR3 vs the actual committed `compose_hash` |
| `info()` parsing into `BootAppInfo` | Multisig rotation flow against attested measurements |
| `/attestation` request/response shape (caller bytes + binding hash) | Phala load-balancer hop + `dstack-ingress` RA-HTTPS termination |
| Matcher tick determinism + book throughput | dstack-kms MPC quorum behaviour during key requests |
| Oracle VAA verification (real Hermes works fine — the simulator isn't in this path) | Real on-chain settle confirmation (need Solana devnet too) |

### 13.3 Concrete dev commands

```sh
# One-time: build the dstack simulator (Rust)
git clone https://github.com/Dstack-TEE/dstack.git ~/dstack
cd ~/dstack/sdk/simulator
./build.sh

# Each session — start it in the background
~/dstack/sdk/simulator/dstack-simulator > /tmp/sim.log 2>&1 &
export DSTACK_SIMULATOR_ENDPOINT=$(realpath ~/dstack/sdk/simulator/dstack.sock)

# Then in the repo
cd ~/nyx-monorepo
NYX_TEE_HTTP_BIND=127.0.0.1:8080 cargo run -p nyx-tee
```

For spot-checking on Phala Cloud devnet:

```sh
# Build + push the image, deploy a fresh CVM, smoke, tear down.
phala deploy -c deploy/docker-compose.yaml -n nyx-tee-spike
phala logs nyx-tee-spike                    # confirm boot
phala cvms attestation nyx-tee-spike        # pull a real quote
curl https://nyx-tee-spike.<custom-domain>/info | jq .
phala cvms delete nyx-tee-spike             # stop billing
```

For TS SDK tests that depend on a running TEE, the SDK reads
`SDK_TEE_ENDPOINT`; tests skip when unset.

### 13.4 Load-gen harness — why and what shape

(Plan; lands as PR 4f after PR 4e ships `POST /orders`.)

The current single-order matcher tests
(`crates/nyx-tee/tests/matcher_tick.rs`) are functional smoke tests,
not performance tests. Before mainnet we need numbers on:

- Sustained orders/sec throughput before backpressure
- Submit-to-accept / submit-to-match / submit-to-settle-confirmed
  latency, P50 / P95 / P99
- Whether the matcher tick keeps up with realistic submit rates at
  `BATCH_MS = 2000`
- Whether the `tokio::sync::RwLock` on `MatcherState` contends under
  concurrent submits
- Whether the settle pipeline (verify_match_batch + N×settle txs)
  becomes the bottleneck

**Design** (PR 4f):

```
crates/nyx-tee-loadgen/                # dev-tool crate; not in production binary
├── Cargo.toml
└── src/
    ├── main.rs        # CLI: --traders N --rate λ --duration D --endpoint URL
    ├── trader.rs      # Per-virtual-trader state machine (auth → submit → maybe-cancel)
    ├── workload.rs    # Order generators: uniform / lognormal / market-maker mass-quote
    ├── auth.rs        # Bearer-token acquisition + per-order trading-key signing
    └── metrics.rs     # Per-request latency histogram + aggregator → BENCHMARK.md
```

It runs against any of the three execution targets from §13.1 — same
binary, different `--endpoint` URL. The resulting numbers feed the
D5 (matching cadence) decision-revisit row in §14.

**Why a dedicated Rust load-gen and not just k6 / wrk / JS:**

- We need to generate cryptographically valid orders (Ed25519 sigs
  over the canonical body documented in §11). Easier from the same
  Rust crate that already owns the canonical encoding
  (`darkpool-matcher`).
- We need to track in-TEE state side-effects (orders placed → fills
  observed → settle confirmed). A protocol-aware generator can
  correlate these; a generic HTTP load tool cannot.
- The same workload generator is the natural foundation for chaos /
  fuzz testing later (malformed orders, signature mismatches,
  trading-key replay attempts).

**Why not now:** premature before PR 4e ships `POST /orders` — there's
nothing to load-test yet. Right move: ship 4e, then PR 4f = load-gen
crate + a `BENCHMARK.md` report capturing local-simulator numbers and
Phala-devnet numbers side-by-side.

### 13.5 Integration test surface

Test files added as part of Phase 1:

| File | Purpose |
|---|---|
| `crates/darkpool-matcher/tests/parity.rs` | **LANDED** (TEE v2 PR 2, 2026-05-27). 8 scenarios translated from `programs/matching_engine/tests/run_batch.rs`; all green. PR 3 cut the on-chain ix over to call the matcher; the 12 existing litesvm scenarios all still pass against the new shape (proves the lift is behavior-preserving end-to-end). |
| `crates/nyx-tee/tests/http_surface.rs` | **LANDED** (TEE v2 PR 4d). 7 in-process tests over the PR-4d HTTP surface (`/health`, `/info`, `/attestation`) via `tower::ServiceExt::oneshot` — no TCP, deterministic across CI. |
| `crates/nyx-tee/tests/matcher_tick.rs` | **LANDED** (TEE v2 PR 4c). 7 single-tick tests driving `MatcherDriver::tick()` directly (NOT via `tokio::time::pause` + spawn — that pattern deadlocks; see PR 4c commit). |
| `crates/nyx-tee/tests/oracle_vaa.rs` | **LANDED** (TEE v2 PR 4b). 5 tests over a captured 1311-byte Hermes VAA, including the core "verifies under mainnet guardians" test + the negative cases that prove signature verification actually rejects tampering. |
| `crates/nyx-tee/tests/boot.rs` | Planned (PR 4e). Spin up the simulator + nyx-tee; assert `/attestation`, `/info`, `/tree/root` return sane data end-to-end. |
| `crates/nyx-tee/tests/settle.rs` | Planned. Drive the full pipeline (place orders → wait for match cycle → assert on-chain settle tx confirmed). Uses litesvm as the L1 mock. |
| `packages/sdk/tests/tee-attestation-verifier.test.ts` | Planned. Client-side: fetch `/attestation` from a real Phala CVM, assert `dcap-qvl` (Phala API or local) accepts the quote, compose-hash matches the governance-approved set. |
| `packages/sdk/tests/tee-trade-flow.test.ts` (env-gated, replaces `er-trade-flow.test.ts`) | Planned. The full devnet flow against a Phala-deployed staging CVM. |

---

## 14. When to revisit the six decisions

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

## 15. What this document is NOT covering

- **Attestation deep-dive** → `docs/tee-attestation-flow.md`
- **API wire contract** → `docs/tee-api-openapi.yaml`
- **Cryptographic invariants** → `CRYPTOGRAPHY.md`
- **Custody-layer architecture** → `docs/ARCHITECTURE.md`
- **Pre-PR validation discipline** → `CLAUDE.md`

---

## 16. Reading list

1. This whole doc.
2. `docs/tee-attestation-flow.md` (sister doc).
3. `docs/tee-api-openapi.yaml` for the wire contract.
4. Phala docs: `phala-docs/dstack/overview.mdx` + `local-development.mdx` + `getting-started.mdx`.
5. Phala docs: `phala-cloud/cvm/create-with-docker-compose.mdx` + `cvm/set-secure-environment-variables.mdx`.
6. Phala docs: `phala-cloud/networking/setup-custom-domain.mdx` + `phala-cloud/networking/domain-attestation.mdx`.
7. dstack source: `dstack/sdk/rust/` (the SDK we consume) + `dstack/sdk/simulator/`.
8. ark-groth16 docs + the existing snarkjs prover at
   `packages/sdk/tests/helpers/match-batch-prover.ts` (the spec
   we're porting).

Only then — write code.

---

*Maintained as the single source of truth for in-TEE design. Any PR
that changes the binary's structure, the boot sequence, the
persistence model, the key-derivation paths, or the dstack SDK calls
used must update this doc in the same PR.*
