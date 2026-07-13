//! Shared HTTP server state. Captured at boot, threaded into
//! every handler via `axum::extract::State<Arc<ApiState>>`.
//!
//! Two construction paths:
//!   - `ApiState::from_boot(...)` — production. Captures the
//!     dstack `info()` snapshot + the derived signer pubkey at
//!     boot. Keeps an `Arc<DstackClient>` so `/attestation` can
//!     fetch a fresh quote per request.
//!   - `ApiState::for_tests(...)` — integration tests. No
//!     dstack client; `/attestation` returns 503; everything else
//!     serves the captured fields verbatim.
//!
//! Boot-time capture (rather than per-request `info()` calls) is
//! a perf choice: app_id / instance_id / compose_hash / MRTD don't
//! change for the lifetime of the CVM, so we pull them once and
//! hand them to every `/info` request from memory.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use dstack_sdk::dstack_client::DstackClient;

use serde::Serialize;
use tokio::sync::{broadcast, RwLock, Semaphore};

use super::auth::{test_registry, AccountRegistry, DEFAULT_JWT_TTL_SECONDS, TEST_JWT_SECRET};
use super::instruments::InstrumentInfo;
use crate::keys::ed25519::DerivedSigner;
use crate::matcher::{FillMemo, MatcherState};
use crate::merkle::{MerkleMirror, TreeAppendEvent};
use crate::oracle::OracleCache;
use crate::persistence;
use crate::settle::SettleSchedulerState;
use crate::solana_rpc::SolanaRpcClient;

/// Build `num_trees.max(1)` empty shard mirrors (one per `tree_id`).
fn new_shard_mirrors(num_trees: u8) -> Vec<Arc<RwLock<MerkleMirror>>> {
    (0..num_trees.max(1))
        .map(|_| Arc::new(RwLock::new(MerkleMirror::new())))
        .collect()
}

/// Fields we captured from `dstack.info()` at boot. Stable for
/// the CVM's lifetime — no need to re-fetch per request.
#[derive(Debug, Clone)]
pub struct BootAppInfo {
    pub app_id: String,
    pub instance_id: String,
    pub app_name: String,
    pub device_id: String,
    pub compose_hash: String,
    pub mrtd: String,
}

impl BootAppInfo {
    /// Stub used by integration tests + by the production binary
    /// when the dstack socket isn't reachable (degraded boot).
    pub fn stub() -> Self {
        Self {
            app_id: "stub-app-id".to_string(),
            instance_id: "stub-instance-id".to_string(),
            app_name: "nyx-tee-stub".to_string(),
            device_id: "stub-device-id".to_string(),
            compose_hash: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            mrtd: "0".repeat(96),
        }
    }
}

/// Everything the HTTP handlers need to serve a request. Wrapped
/// in `Arc` and cloned cheaply into each request's State extractor.
pub struct ApiState {
    pub app_info: BootAppInfo,
    /// Solana base58 encoding of the TEE-derived Ed25519 pubkey.
    /// This is what an operator would register as
    /// `vault_config.tee_pubkey` via the multisig rotation
    /// ceremony.
    pub signer_pubkey_base58: String,
    /// Hex encoding of the same pubkey — useful for the
    /// `report_data` binding when clients call `get_quote`.
    pub signer_pubkey_hex: String,
    /// The FULL K-shard TEE signer set (base58, shard order) — `signers[j]`
    /// is shard `j`'s Solana fee-payer/authority. The vault accepts settle
    /// payloads from EVERY key in `vault_config.tee_pubkeys`, so `/info`
    /// advertises the whole set (not just shard 0) and a client cross-checks
    /// it against on-chain governance. Defaults to `[signer_pubkey_base58]`
    /// until `main.rs` supplies the derived set via `with_shard_pubkeys`.
    pub signer_pubkeys_base58: Vec<String>,
    /// SHA-256 over the concatenated raw pubkeys of the FULL K-shard set
    /// (shard order) — the value `/attestation` puts in `report_data[32..64]`
    /// so a client binds the ENTIRE settle-key set to the DCAP-verified quote,
    /// not just shard 0. For a single-shard TEE this equals `SHA-256(pk_0)`
    /// (backward-compatible). Set by `main.rs` via `with_signer_set_hash`.
    pub signer_set_hash: [u8; 32],
    /// `None` when the dstack socket isn't reachable (degraded
    /// boot or test mode). `/attestation` returns 503 in that
    /// case; `/health` + `/info` still work.
    pub dstack: Option<Arc<DstackClient>>,
    /// Stamped at construction. `/health` returns the elapsed
    /// milliseconds since this instant.
    pub start: Instant,
    /// Build version surfaced on `/info` so operators can quickly
    /// see which `nyx-tee` revision is running. Pulled from
    /// `CARGO_PKG_VERSION` at compile time.
    pub nyx_version: &'static str,

    // ── Layer A (operational) auth state ────────────────────────
    /// HS256 secret for the bearer JWT. Production derives this
    /// once at boot from dstack via
    /// `get_key("nyx/jwt-secret/v1", "jwt")`; test mode uses
    /// `auth::TEST_JWT_SECRET`. Treat the bytes as opaque — never
    /// log, never expose via any endpoint.
    pub jwt_secret: [u8; 32],
    /// Account registry consulted by `POST /auth/token` (read) and
    /// mutated by the admin-gated `POST /admin/accounts` (write).
    /// Behind a `RwLock` for that runtime mutation. Production seeds
    /// the bootstrap admin from `NYX_TEE_API_*` env via
    /// `AccountRegistry::from_env_bootstrap`; tests seed `test_registry()`.
    pub accounts: Arc<RwLock<AccountRegistry>>,
    /// Denylist of revoked JWT `jti`s. `POST /auth/token/revoke`
    /// inserts; `bearer_middleware` rejects any token whose `jti` is
    /// present. Persisted to `accounts.db` alongside the registry
    /// (Phase 1b) so revocations survive a restart.
    pub revoked_jtis: Arc<RwLock<HashSet<String>>>,
    /// Concurrency limiter for Argon2id work. `/auth/token` (public,
    /// unauthenticated) and `/admin/accounts` run Argon2id, which costs
    /// ~19 MiB + tens of ms of CPU per hash. The handlers offload it to
    /// `spawn_blocking` (so the async reactor isn't blocked) and acquire
    /// a permit here first, so an unauthenticated `/auth/token` flood
    /// can't spawn unbounded heavy jobs and exhaust the small CVM's RAM
    /// (1 vCPU / 2 GB) — excess requests queue on the semaphore instead.
    pub argon2_limiter: Arc<Semaphore>,
    /// Directory the auth snapshot (`accounts.db`) is read from at boot
    /// and written to after each registry/denylist mutation. `None`
    /// disables persistence (tests + any deploy with no mounted
    /// volume). In production this is the dstack LUKS mount
    /// (`NYX_TEE_STATE_DIR`, default `/var/lib/nyx-tee`).
    pub state_dir: Option<PathBuf>,
    /// Lifetime of each issued JWT. Configurable per instance;
    /// defaults to [`super::auth::DEFAULT_JWT_TTL_SECONDS`].
    pub jwt_ttl_seconds: u64,

    /// Tradable instruments served by `GET /instruments` (Phase 2c).
    /// Static for the CVM's lifetime — captured at boot from the
    /// market `MatchConfig` + the configured oracle feed. One market
    /// for now; a multi-market deploy populates more.
    pub instruments: Vec<InstrumentInfo>,

    // ── Merkle mirrors (Phase 2 indexer surface; sharded Phase 3) ───
    /// One in-memory mirror per Merkle-tree shard, indexed by `tree_id`.
    /// Backs the `/tree/*` read endpoints (D6, §5.5). Always present
    /// (pure in-memory) — each starts empty and is fed by the sync task,
    /// which routes every appended leaf to `merkle_mirrors[leaf.tree_id]`.
    /// `len() == num_trees` (1 for a single-shard / `for_tests` build).
    /// Use [`Self::merkle_mirror`] to index by `tree_id` safely.
    pub merkle_mirrors: Vec<Arc<RwLock<MerkleMirror>>>,

    // ── Matcher state (PR 4e.3 / 4e.4) ──────────────────────────
    /// Shared order book + match-id counter. `None` in degraded
    /// boot or during early initialisation — the `/orders` handlers
    /// return 503 in that case. PR 4e.4 will populate this with the
    /// long-running `MatcherDriver`'s state on every production
    /// boot.
    pub matcher: Option<Arc<RwLock<MatcherState>>>,
    /// Monotonic counter the orders handler reads to stamp
    /// `arrival_slot` on incoming orders before they land in the
    /// book. Driven by a separate Solana-RPC poller in production
    /// (PR 4e.4); advanced manually in tests via `set_current_slot`.
    pub current_slot: Arc<std::sync::atomic::AtomicU64>,
    /// Shared oracle cache the `MatcherDriver` reads on every tick.
    /// `None` in degraded boot — same convention as `matcher`. The
    /// `debug_endpoints` cargo feature uses this to back the
    /// `POST /__debug/oracle/seed` endpoint; in production it's
    /// written by `spawn_oracle_sync` (PR 4b) and read by the
    /// matcher tick.
    pub oracle: Option<OracleCache>,

    // ── Settle scheduler state (PR 4g.1) ────────────────────────
    /// Shared state the `SettleScheduler` task writes into. The
    /// `GET /settlement/status/{batch_id}` handler reads it; future
    /// stage workers (4g.3 / 4g.5 / 4g.6) take brief write locks to
    /// advance jobs. `None` until `main.rs` spawns the scheduler.
    pub settle_state: Option<Arc<RwLock<SettleSchedulerState>>>,

    // ── Solana RPC (PR 4g.2 / walk-back in 4g.3) ────────────────
    /// Hand-rolled JSON-RPC client pointed at the configured
    /// Solana cluster URL. `None` in degraded boot; populated by
    /// `main.rs` after construction. Cloneable cheaply (the inner
    /// reqwest::Client is internally Arc) — stage workers in
    /// 4g.3+ clone it into their per-job tasks.
    ///
    /// The Solana fee-payer pubkey is `signer_pubkey_base58`
    /// above: PR 4g.3 unified the TEE Ed25519 signer with the
    /// Solana fee-payer (see `keys::ed25519::DerivedSigner::solana_keypair`
    /// for the rationale + conversion).
    pub solana_rpc: Option<SolanaRpcClient>,

    // ── Per-account fills routing (fills-history) ───────────────
    /// `order_id (hex) → account_id`. Written at accepted intake (the one
    /// moment the bearer/account and the order_id are visible together) and
    /// read by the fills router to route each `FillMemo` to its owner. Kept
    /// in-memory in the enclave and NEVER persisted off-TEE — the off-TEE
    /// indexer is account-agnostic by design.
    pub order_owner: Arc<RwLock<HashMap<String, String>>>,
    /// `account_id → per-account fill-memo broadcast`. Created lazily when an
    /// account opens `/ws/fills`. The fills router fans the matcher's global
    /// broadcast into these per-account channels, so a subscriber sees ONLY
    /// its own order's memos (the leak guard that gated the old global route).
    pub fills_routes: Arc<RwLock<HashMap<String, broadcast::Sender<FillMemo>>>>,
    /// `account_id → per-account order-lifecycle broadcast`. Same per-account
    /// fan-out as `fills_routes`, but for `/ws/orders`: the order router fans
    /// the matcher's global `OrderUpdate` broadcast into these channels keyed
    /// by `order_owner`, so a subscriber sees ONLY its own orders' updates.
    pub order_routes: Arc<RwLock<HashMap<String, broadcast::Sender<OrderUpdateMsg>>>>,

    // ── Per-account rate limiting ───────────────────────────────
    /// `account_id → weighted token bucket`. A second middleware on the
    /// protected router (after `bearer_middleware`, so `Authorized.account_id`
    /// is present) charges each request a route-dependent weight against its
    /// account's bucket — cancels cheap, place/modify heavier — and returns
    /// `429` when the bucket is empty. Mirrors the `argon2_limiter` intent
    /// (protect the small CVM) but per-account + weighted. Created lazily.
    pub rate_buckets: Arc<RwLock<HashMap<String, TokenBucket>>>,

    // ── Idempotency (POST /orders safe retries) ─────────────────
    /// `order_id (hex) → (canonical_digest, arrival_slot)` recorded at accept
    /// time. A duplicate `order_id` whose signed body hashes to the SAME digest
    /// is a true retry → return the original acceptance; a DIFFERENT digest is a
    /// real conflict → `409`. Persists past order terminal (so a retry after a
    /// fill still de-dupes rather than re-booking a consumed-note order), bounded
    /// by [`IDEMPOTENCY_CAP`].
    pub idempotency: Arc<RwLock<HashMap<String, IdempotencyRecord>>>,

    // ── Live tree channel (/v1/stream `tree`) ───────────────────
    /// GLOBAL leaf-append broadcast feeding the multiplexed `/v1/stream`
    /// `tree` channel. Unlike fills/orders this is NOT per-account: every
    /// appended leaf is already on-chain (public), and clients reconstruct
    /// their own portfolio from the stream + their keys. The Merkle sync task
    /// publishes here (`MerkleSync::with_tree_publisher`); subscribers attach
    /// via [`Self::subscribe_tree_appends`]. The `Sender` is held so the
    /// channel survives periods with zero subscribers (sends then no-op).
    pub tree_appends: broadcast::Sender<TreeAppendEvent>,
}

/// What an accepted order records for idempotent-retry detection:
/// `(canonical_digest, arrival_slot)`.
pub type IdempotencyRecord = ([u8; 32], u64);

/// A simple per-account token bucket: `tokens` refill at `RATE_REFILL_PER_SEC`
/// up to `RATE_CAPACITY` (the burst), and each request costs a route weight.
#[derive(Debug)]
pub struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

/// Burst size (max tokens) per account.
pub const RATE_CAPACITY: f64 = 40.0;
/// Sustained refill rate (tokens per second). At weight 1.0/place this is ~20
/// places/sec sustained, ~100 cancels/sec (weight 0.2), with a 40-token burst.
pub const RATE_REFILL_PER_SEC: f64 = 20.0;

impl TokenBucket {
    fn new() -> Self {
        Self {
            tokens: RATE_CAPACITY,
            last_refill: Instant::now(),
        }
    }

    /// Refill for elapsed time, then try to spend `cost`. On success returns
    /// `Ok(())`; on insufficient tokens returns `Err(retry_after_secs)`.
    fn try_spend(&mut self, cost: f64) -> Result<(), f64> {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * RATE_REFILL_PER_SEC).min(RATE_CAPACITY);
        self.last_refill = now;
        if self.tokens >= cost {
            self.tokens -= cost;
            Ok(())
        } else {
            Err(((cost - self.tokens) / RATE_REFILL_PER_SEC).max(0.001))
        }
    }
}

/// Wire form of a `darkpool_matcher::book::OrderUpdate` streamed on `/ws/orders`.
/// `kind` is the lifecycle tag; the numeric fields are present only for the
/// kinds that carry them (flattened from `OrderUpdateKind`).
#[derive(Clone, Debug, Serialize)]
pub struct OrderUpdateMsg {
    /// 16-byte order id, hex.
    pub order_id: String,
    /// `"fully_filled" | "partially_filled" | "cancelled" | "expired"`.
    pub kind: &'static str,
    /// Cumulative filled quantity (fully/partially filled only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filled_quantity: Option<u64>,
    /// Remaining order size after a partial fill (partially filled only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_amount: Option<u64>,
    /// New collateral-note value after a partial-fill re-lock (partially filled only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_note_amount: Option<u64>,
}

/// Per-account fill-memo channel depth. A CONNECTED-but-slow `/ws/fills` client
/// that lags past this is closed with a 1011 resync. The live channel is a
/// low-latency fast path only — a memo sent while no `/ws/fills` client is
/// attached is NOT a loss: the change-note amount is recoverable from the
/// permanent on-chain ciphertext (change-amount recovery, Proposal B) via the
/// indexer + `recoverChangeFromChain`, which is why the durable per-account memo
/// log (the old P7 `fill_log` + `GET /fills/replay`) was retired.
const FILLS_CHANNEL_CAP: usize = 1024;

/// Global `tree`-channel depth. Sized larger than the per-account channels
/// because every settle/deposit appends to ONE shared channel (so it carries
/// every account's leaves), and a settle can append several leaves at once. A
/// subscriber that still lags past this is closed with a 1011 resync (it
/// re-reads `/tree/*`).
const TREE_CHANNEL_CAP: usize = 4096;

/// Max retained idempotency records (order_id → accepted body). Bounds the map;
/// the oldest entries age out (best-effort retry window).
const IDEMPOTENCY_CAP: usize = 16_384;

/// Max concurrent Argon2id hash/verify jobs allowed across the auth
/// handlers. Sized to the host's parallelism (clamped) so legitimate
/// auth still pipelines, while a flood queues rather than exhausting
/// the small CVM's RAM (each job is ~19 MiB). See `argon2_limiter`.
fn argon2_permits() -> usize {
    std::thread::available_parallelism()
        .map_or(2, |n| n.get())
        .clamp(2, 16)
}

impl ApiState {
    /// Build production state from a successful boot. `jwt_secret`
    /// is the 32-byte value derived via dstack `get_key`. The account
    /// registry + revocation denylist are loaded from the persisted
    /// `accounts.db` snapshot if present (Phase 1b), then the env
    /// bootstrap admin is merged in if its key is absent. On first
    /// boot (no snapshot yet) the seeded state is persisted immediately
    /// so the admin survives the next restart.
    pub fn from_boot(
        app_info: BootAppInfo,
        signer: &DerivedSigner,
        dstack: Arc<DstackClient>,
        jwt_secret: [u8; 32],
        num_trees: u8,
    ) -> Self {
        let state_dir = persistence::state_dir_from_env();
        let (registry, revoked) = Self::load_or_seed_auth(state_dir.as_deref());
        Self {
            app_info,
            signer_pubkey_base58: signer.pubkey_base58.clone(),
            signer_pubkey_hex: signer.pubkey_hex.clone(),
            // Defaults to the primary; `main.rs` overrides with the full derived
            // K-shard set via `with_shard_pubkeys` + `with_signer_set_hash`.
            signer_pubkeys_base58: vec![signer.pubkey_base58.clone()],
            signer_set_hash: crate::keys::ed25519::signer_set_hash(std::slice::from_ref(signer)),
            dstack: Some(dstack),
            start: Instant::now(),
            nyx_version: env!("CARGO_PKG_VERSION"),
            jwt_secret,
            accounts: Arc::new(RwLock::new(registry)),
            revoked_jtis: Arc::new(RwLock::new(revoked)),
            argon2_limiter: Arc::new(Semaphore::new(argon2_permits())),
            state_dir,
            jwt_ttl_seconds: DEFAULT_JWT_TTL_SECONDS,
            // Populated by main.rs via `with_instruments` from the
            // market MatchConfig; empty until then.
            instruments: Vec::new(),
            // K empty shard mirrors — the sync task fills each from chain.
            merkle_mirrors: new_shard_mirrors(num_trees),
            // `from_boot` doesn't construct the matcher — PR 4e.4
            // spawns the `MatcherDriver` and plumbs its state in via
            // a separate construction path. Until then the orders
            // handlers see `None` and return 503.
            matcher: None,
            current_slot: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            oracle: None,
            settle_state: None,
            solana_rpc: None,
            order_owner: Arc::new(RwLock::new(HashMap::new())),
            fills_routes: Arc::new(RwLock::new(HashMap::new())),
            order_routes: Arc::new(RwLock::new(HashMap::new())),
            rate_buckets: Arc::new(RwLock::new(HashMap::new())),
            idempotency: Arc::new(RwLock::new(HashMap::new())),
            tree_appends: broadcast::channel(TREE_CHANNEL_CAP).0,
        }
    }

    /// The Merkle mirror for shard `tree_id`. Out-of-range (a bad
    /// `?tree_id` query) clamps to shard 0 so a malformed request reads the
    /// primary shard instead of panicking.
    pub fn merkle_mirror(&self, tree_id: usize) -> &Arc<RwLock<MerkleMirror>> {
        self.merkle_mirrors
            .get(tree_id)
            .unwrap_or(&self.merkle_mirrors[0])
    }

    /// Number of shard mirrors (== `num_trees`).
    pub fn num_mirror_shards(&self) -> usize {
        self.merkle_mirrors.len()
    }

    /// Advertise the full K-shard TEE signer set (base58, shard order) on
    /// `/info`. Called once by `main.rs` with the `derive_set` output so a
    /// client can cross-check the WHOLE set the vault trusts, not just the
    /// primary. An empty vec is ignored (keeps the `from_boot` default).
    pub fn with_shard_pubkeys(mut self, keys: Vec<String>) -> Self {
        if !keys.is_empty() {
            self.signer_pubkeys_base58 = keys;
        }
        self
    }

    /// Bind the FULL K-shard signer set into the attestation `report_data`
    /// right-half: `report_data[32..64] = SHA-256(pk_0 ‖ … ‖ pk_{K-1})`. Called
    /// once by `main.rs` with `keys::ed25519::signer_set_hash(&signers)` so a
    /// client verifies the whole settle-key set against the DCAP-verified quote,
    /// not just shard 0. Must be kept in shard order + lockstep with
    /// `with_shard_pubkeys` (same source `signers`).
    pub fn with_signer_set_hash(mut self, hash: [u8; 32]) -> Self {
        self.signer_set_hash = hash;
        self
    }

    /// Attach the Solana RPC client. Called by `main.rs` after
    /// constructing the client; stage workers in 4g.3+ read
    /// `solana_rpc` to submit txs. The fee-payer pubkey is
    /// `signer_pubkey_base58` (set at `from_boot` time) — no
    /// separate field needed since 4g.3 unified the two.
    /// Idempotent.
    pub fn with_solana_rpc(mut self, rpc: SolanaRpcClient) -> Self {
        self.solana_rpc = Some(rpc);
        self
    }

    /// Attach a freshly-constructed `MatcherState` + shared
    /// `current_slot` source + shared `OracleCache` to a boot-time
    /// `ApiState`. Called once by `main.rs` after the
    /// `MatcherDriver` is spawned in PR 4e.4 — the `Arc<AtomicU64>`
    /// and `OracleCache` must be the SAME instances the driver
    /// holds, so order arrivals + matcher ticks see a single
    /// clock + the same oracle view. Callers that build state via
    /// [`Self::for_tests`] don't need to invoke this — `for_tests()`
    /// already seeds the matcher + slot; pass an oracle here if a
    /// test needs `/__debug/oracle/seed` to write somewhere.
    pub fn with_matcher_runtime(
        mut self,
        matcher: Arc<RwLock<MatcherState>>,
        current_slot: Arc<std::sync::atomic::AtomicU64>,
        oracle: OracleCache,
    ) -> Self {
        self.matcher = Some(matcher);
        self.current_slot = current_slot;
        self.oracle = Some(oracle);
        self
    }

    /// Attach the shared [`SettleSchedulerState`]. Called once by
    /// `main.rs` after [`crate::settle::SettleScheduler::spawn`].
    /// Idempotent; calling twice replaces the prior handle.
    pub fn with_settle_state(mut self, settle_state: Arc<RwLock<SettleSchedulerState>>) -> Self {
        self.settle_state = Some(settle_state);
        self
    }

    /// Enable auth-state persistence to `dir`. `from_boot` sets this
    /// from `NYX_TEE_STATE_DIR`; this builder is for tests + any caller
    /// that wants persistence on a state built via [`Self::for_tests`].
    /// Only flips the target directory — it does NOT reload from disk
    /// (use [`Self::load_or_seed_auth`] for that).
    pub fn with_state_dir(mut self, dir: PathBuf) -> Self {
        self.state_dir = Some(dir);
        self
    }

    /// Set the tradable instruments served by `GET /instruments`.
    /// Called once by `main.rs` from the market `MatchConfig`.
    pub fn with_instruments(mut self, instruments: Vec<InstrumentInfo>) -> Self {
        self.instruments = instruments;
        self
    }

    /// Build degraded state when dstack isn't reachable. Used by
    /// integration tests + by the dev-mode binary that falls back
    /// to serving `/health` + a stub `/info` when no simulator
    /// is running. `/attestation` returns 503; auth uses
    /// `TEST_JWT_SECRET` + the single seeded account from
    /// [`super::auth::test_registry`].
    pub fn for_tests() -> Self {
        Self {
            app_info: BootAppInfo::stub(),
            signer_pubkey_base58: "stub-pubkey".to_string(),
            signer_pubkey_hex: "00".repeat(32),
            signer_pubkeys_base58: vec!["stub-pubkey".to_string()],
            signer_set_hash: [0u8; 32],
            dstack: None,
            start: Instant::now(),
            nyx_version: env!("CARGO_PKG_VERSION"),
            jwt_secret: TEST_JWT_SECRET,
            accounts: Arc::new(RwLock::new(test_registry())),
            revoked_jtis: Arc::new(RwLock::new(HashSet::new())),
            argon2_limiter: Arc::new(Semaphore::new(argon2_permits())),
            // Persistence disabled in tests — they assert on in-memory
            // behaviour and must not touch the host filesystem. Tests
            // that exercise persistence drive the `persistence` module
            // (or `persist_auth`) against an explicit tempdir.
            state_dir: None,
            jwt_ttl_seconds: DEFAULT_JWT_TTL_SECONDS,
            // One placeholder instrument so /instruments tests have
            // something to read. Mints match the orders_surface fixtures
            // (zeroed market) — not the dev_match_config mints.
            instruments: vec![InstrumentInfo {
                symbol: "SOL-USDC".to_string(),
                base_mint: [0u8; 32],
                quote_mint: [0u8; 32],
                tick_size: 1,
                min_order_size: 0,
                oracle_feed_id: "ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d"
                    .to_string(),
            }],
            merkle_mirrors: new_shard_mirrors(1),
            matcher: Some(Arc::new(RwLock::new(MatcherState::new()))),
            // Tests that exercise expiry need to bump this; the
            // default starting slot is 1 so an order with
            // `expiry_slot = 1_000_000` (the test default) lives
            // long enough to be matched without intervention.
            current_slot: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            oracle: Some(OracleCache::new()),
            // No scheduler running by default — tests that need
            // to drive the `/settlement/status/*` endpoint must
            // spawn one and call `with_settle_state(...)`.
            settle_state: None,
            // No Solana RPC client by default — tests that need
            // one construct it manually and attach via
            // `with_solana_rpc(...)`.
            solana_rpc: None,
            order_owner: Arc::new(RwLock::new(HashMap::new())),
            fills_routes: Arc::new(RwLock::new(HashMap::new())),
            order_routes: Arc::new(RwLock::new(HashMap::new())),
            rate_buckets: Arc::new(RwLock::new(HashMap::new())),
            idempotency: Arc::new(RwLock::new(HashMap::new())),
            tree_appends: broadcast::channel(TREE_CHANNEL_CAP).0,
        }
    }

    // ── Per-account fills routing ───────────────────────────────

    /// Record `order_id → account_id` at accepted intake. Idempotent.
    pub async fn record_order_owner(&self, order_id: String, account_id: String) {
        self.order_owner.write().await.insert(order_id, account_id);
    }

    /// Drop an order's owner mapping. Called on explicit cancel AND by the
    /// order-update router on any TERMINAL matcher update (fully-filled /
    /// cancelled / expired — see `order_router::spawn_order_router`), so the
    /// `order_owner` map stays bounded over the engine's lifetime.
    pub async fn forget_order(&self, order_id: &str) {
        self.order_owner.write().await.remove(order_id);
    }

    /// Get-or-create the caller account's fill-memo channel and subscribe. A
    /// receiver created here only sees memos sent AFTER it subscribes — earlier
    /// fills (sent before this subscribe, or while the account was disconnected)
    /// are recovered from the PERMANENT on-chain ciphertext (change-amount
    /// recovery, Proposal B) via the indexer + `recoverChangeFromChain`, which is
    /// where the change-note amount durably lives after amount-privacy made the
    /// off-TEE indexer a commitment-only locator. "Tail then backfill": the client
    /// tails this channel + backfills any gap from the chain.
    pub async fn subscribe_account_fills(&self, account_id: &str) -> broadcast::Receiver<FillMemo> {
        let mut routes = self.fills_routes.write().await;
        // Opportunistic GC: drop channels whose `/ws/fills` subscribers have all
        // disconnected (`receiver_count() == 0`), so the map stays bounded by the
        // number of CURRENTLY-connected accounts rather than every account ever
        // seen. Safe because we hold the write lock here — `subscribe` is the only
        // path that inserts, so no concurrent caller can be mid-flight holding a
        // just-created receiver. Discarding a disconnected account's channel drops
        // any in-flight broadcast memo, but that's not a loss: the amount is
        // recoverable from the on-chain ciphertext (Proposal B). Cheap:
        // `receiver_count()` is an atomic load, subscribes are rare.
        routes.retain(|_, tx| tx.receiver_count() > 0);
        let tx = routes
            .entry(account_id.to_string())
            .or_insert_with(|| broadcast::channel(FILLS_CHANNEL_CAP).0);
        tx.subscribe()
    }

    /// Route one memo to its owning account's live `/ws/fills` channel. Returns
    /// true when delivered to at least one LIVE subscriber; false when the order
    /// is unknown or no client is currently attached.
    ///
    /// The live channel is a low-latency fast path only. A `false` (no attached
    /// client) is not a loss: the change-note amount rides the settle ix
    /// ENCRYPTED on-chain (change-amount recovery, Proposal B), so an offline
    /// client recovers it from the indexer + `recoverChangeFromChain`. The old
    /// durable per-account memo log (`fill_log` + `GET /fills/replay`, P7) was
    /// retired once the chain became the permanent source.
    pub async fn route_fill(&self, memo: &FillMemo) -> bool {
        let account = self.order_owner.read().await.get(&memo.order_id).cloned();
        let Some(account) = account else { return false };

        let tx = self.fills_routes.read().await.get(&account).cloned();
        match tx {
            Some(tx) => tx.send(memo.clone()).is_ok(),
            None => false,
        }
    }

    /// Subscribe to the GLOBAL live `tree` leaf-append channel (the
    /// `/v1/stream` `tree` channel). Unlike fills/orders there is no
    /// per-account fan-out — every leaf is public. The receiver only sees
    /// appends AFTER it subscribes; earlier leaves come from `/tree/leaves`.
    pub fn subscribe_tree_appends(&self) -> broadcast::Receiver<TreeAppendEvent> {
        self.tree_appends.subscribe()
    }

    /// A `Sender` clone for the Merkle sync task to publish leaf-appends into
    /// (see [`crate::merkle::MerkleSync::with_tree_publisher`]).
    pub fn tree_publisher(&self) -> broadcast::Sender<TreeAppendEvent> {
        self.tree_appends.clone()
    }

    /// Get-or-create the caller account's order-update channel and subscribe.
    /// Same lazy create + opportunistic GC of disconnected channels as
    /// [`Self::subscribe_account_fills`].
    pub async fn subscribe_account_order_updates(
        &self,
        account_id: &str,
    ) -> broadcast::Receiver<OrderUpdateMsg> {
        let mut routes = self.order_routes.write().await;
        routes.retain(|_, tx| tx.receiver_count() > 0);
        let tx = routes
            .entry(account_id.to_string())
            .or_insert_with(|| broadcast::channel(FILLS_CHANNEL_CAP).0);
        tx.subscribe()
    }

    /// Route one order-update to its owning account's `/ws/orders` channel.
    /// Returns true when delivered to ≥1 live subscriber. `order_id` is the
    /// update's 16-byte order id, hex-encoded (the `order_owner` key).
    pub async fn route_order_update(&self, order_id: &str, msg: &OrderUpdateMsg) -> bool {
        let account = self.order_owner.read().await.get(order_id).cloned();
        let Some(account) = account else { return false };
        let tx = self.order_routes.read().await.get(&account).cloned();
        match tx {
            Some(tx) => tx.send(msg.clone()).is_ok(),
            None => false,
        }
    }

    /// Charge `cost` weighted tokens against `account_id`'s rate bucket
    /// (created lazily at full burst). `Ok(())` allows the request; `Err(secs)`
    /// is the suggested `Retry-After` when the bucket is empty. The map is
    /// bounded by the number of accounts that have made a request — small in
    /// practice — so no GC is needed.
    pub async fn try_consume_rate(&self, account_id: &str, cost: f64) -> Result<(), f64> {
        let mut buckets = self.rate_buckets.write().await;
        buckets
            .entry(account_id.to_string())
            .or_insert_with(TokenBucket::new)
            .try_spend(cost)
    }

    /// Look up a prior acceptance for `order_id_hex` — `(canonical_digest,
    /// arrival_slot)` if this id was accepted before.
    pub async fn idempotency_lookup(&self, order_id_hex: &str) -> Option<([u8; 32], u64)> {
        self.idempotency.read().await.get(order_id_hex).copied()
    }

    /// Record an accepted order for idempotent-retry detection. Bounded: when
    /// the map is at [`IDEMPOTENCY_CAP`], an arbitrary old entry is evicted (the
    /// dedup window is best-effort, like a TTL).
    pub async fn idempotency_record(
        &self,
        order_id_hex: String,
        digest: [u8; 32],
        arrival_slot: u64,
    ) {
        let mut m = self.idempotency.write().await;
        if m.len() >= IDEMPOTENCY_CAP && !m.contains_key(&order_id_hex) {
            if let Some(k) = m.keys().next().cloned() {
                m.remove(&k);
            }
        }
        m.insert(order_id_hex, (digest, arrival_slot));
    }

    /// Boot-time auth load (Phase 1b). Loads the `accounts.db`
    /// snapshot from `state_dir` if present, merges in the env
    /// bootstrap admin if its key is absent, and — when seeding added
    /// the admin to a previously-absent/empty snapshot — persists the
    /// result so the admin survives the next restart. Returns the
    /// `(registry, revoked_jtis)` to install on `ApiState`.
    ///
    /// `state_dir == None` (persistence disabled) falls back to the
    /// pure env bootstrap, identical to the Phase-1a behaviour.
    fn load_or_seed_auth(
        state_dir: Option<&std::path::Path>,
    ) -> (AccountRegistry, HashSet<String>) {
        let Some(dir) = state_dir else {
            return (AccountRegistry::from_env_bootstrap(), HashSet::new());
        };

        let path = persistence::accounts_db_path(dir);
        let (mut registry, revoked) = match persistence::load_auth_snapshot(&path) {
            Some(snap) => {
                tracing::info!(
                    accounts = snap.accounts.len(),
                    revoked = snap.revoked_jtis.len(),
                    path = %path.display(),
                    "loaded auth snapshot"
                );
                (
                    AccountRegistry::from_snapshot(snap.accounts),
                    snap.revoked_jtis.into_iter().collect::<HashSet<_>>(),
                )
            }
            None => (AccountRegistry::new(), HashSet::new()),
        };

        // Merge the env admin (no-op if a persisted account already
        // owns that api_key). Persist immediately on first-boot seed so
        // a crash before the first registration doesn't lose the admin.
        if registry.ensure_admin() {
            let snapshot = persistence::AuthSnapshot::new(registry.snapshot(), &revoked);
            if let Err(e) = persistence::save_auth_snapshot(&path, &snapshot) {
                tracing::warn!(error = %e, path = %path.display(), "first-boot auth persist failed (best-effort)");
            }
        }

        (registry, revoked)
    }

    /// Best-effort snapshot of the current auth state (registry +
    /// revocation denylist) to `accounts.db`. Called after each
    /// `register` / `revoke` mutation. A `None` `state_dir` (tests,
    /// no-volume deploys) is a no-op. A write failure is logged but
    /// never surfaced to the caller — persistence is a complement to
    /// the canonical on-chain state, not a hard dependency (§8).
    pub async fn persist_auth(&self) {
        let Some(dir) = self.state_dir.as_deref() else {
            return;
        };
        let snapshot = {
            let accounts = self.accounts.read().await.snapshot();
            let revoked = self.revoked_jtis.read().await;
            persistence::AuthSnapshot::new(accounts, &revoked)
        };
        let path = persistence::accounts_db_path(dir);
        // The snapshot is small (a handful of accounts) — a synchronous
        // write here costs well under a millisecond and keeps the
        // durability point precisely after the mutation.
        if let Err(e) = persistence::save_auth_snapshot(&path, &snapshot) {
            tracing::warn!(error = %e, path = %path.display(), "auth snapshot persist failed (best-effort)");
        }
    }
}

#[cfg(test)]
mod persist_tests {
    use super::*;
    use crate::api::auth::ApiCredentials;

    /// A registration that's persisted is recovered by a subsequent
    /// boot-load from the same directory — the core Phase-1b
    /// durability guarantee. Drives `persist_auth` (write) +
    /// `load_or_seed_auth` (read) end to end.
    #[tokio::test]
    async fn register_then_persist_then_reload_recovers_account() {
        let dir = tempfile::tempdir().unwrap();
        let st = ApiState::for_tests().with_state_dir(dir.path().to_path_buf());

        // Register a fresh account + revoke a token, then persist.
        let bob =
            ApiCredentials::from_plaintext("bob", "bob-secret", "bob-pass", false).expect("hash");
        assert!(st.accounts.write().await.register(bob));
        // Flip bob's cancel-on-disconnect default so we can prove settings persist.
        assert!(st.accounts.write().await.set_settings(
            "bob",
            crate::api::auth::AccountSettings {
                cancel_on_disconnect_default: true,
            },
        ));
        st.revoked_jtis.write().await.insert("jti-xyz".to_string());
        st.persist_auth().await;

        // Simulate a restart: load the snapshot from the same dir.
        let (registry, revoked) = ApiState::load_or_seed_auth(Some(dir.path()));

        let bob = registry.lookup("bob").expect("bob survived restart");
        assert!(bob.verify_credentials("bob-secret", "bob-pass"));
        assert!(!bob.is_admin);
        // The per-account setting survived the snapshot round-trip.
        assert!(bob.settings.cancel_on_disconnect_default);
        // The seeded test admin also persisted.
        assert!(registry.lookup(crate::api::auth::TEST_API_KEY).is_some());
        // The revocation survived too.
        assert!(revoked.contains("jti-xyz"));
    }

    /// No snapshot + persistence disabled ⇒ falls back to the env
    /// bootstrap (here: empty, since NYX_TEE_API_* is unset in tests),
    /// never touching the filesystem.
    #[test]
    fn no_state_dir_uses_env_bootstrap() {
        let (registry, revoked) = ApiState::load_or_seed_auth(None);
        // NYX_TEE_API_* is not set in the test process → empty.
        assert!(registry.is_empty());
        assert!(revoked.is_empty());
    }

    /// A persisted snapshot is authoritative: load_or_seed_auth returns
    /// exactly its accounts (env-admin merge is a no-op when unset).
    #[test]
    fn existing_snapshot_is_loaded() {
        let dir = tempfile::tempdir().unwrap();
        let creds = ApiCredentials::from_plaintext("carol", "s", "p", true).expect("hash");
        let snap = persistence::AuthSnapshot::new(vec![creds], &HashSet::new());
        persistence::save_auth_snapshot(&persistence::accounts_db_path(dir.path()), &snap).unwrap();

        let (registry, _) = ApiState::load_or_seed_auth(Some(dir.path()));
        assert!(registry
            .lookup("carol")
            .unwrap()
            .verify_credentials("s", "p"));
        assert!(registry.lookup("carol").unwrap().is_admin);
    }

    /// `route_fill` is a live-only fast path (the durable per-account memo log
    /// was retired in favour of the on-chain ciphertext, Proposal B). It returns
    /// false when no `/ws/fills` client is attached, and delivers to a live
    /// subscriber when one is. A dropped live memo is not a loss — the amount is
    /// recoverable from the chain.
    #[tokio::test]
    async fn route_fill_delivers_live_and_is_false_without_a_subscriber() {
        let st = ApiState::for_tests();
        let order_id = [0xABu8; 16];
        st.record_order_owner(hex::encode(order_id), "alice".to_string())
            .await;
        let memo =
            crate::matcher::FillMemo::new(order_id, 3, 777, [0xCC; 32], [0x11; 32], [0x22; 32]);

        // No subscriber attached → not delivered live (no error; just false).
        assert!(!st.route_fill(&memo).await, "no subscriber → false");

        // With a live subscriber, the memo is delivered.
        let mut rx = st.subscribe_account_fills("alice").await;
        assert!(st.route_fill(&memo).await, "live subscriber → delivered");
        let got = rx.try_recv().expect("memo on the live channel");
        assert_eq!(got.change_amount, 777);
        assert_eq!(got.anchor_index, 3);
    }
}
