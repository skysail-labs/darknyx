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

use tokio::sync::{broadcast, RwLock, Semaphore};

use super::auth::{test_registry, AccountRegistry, DEFAULT_JWT_TTL_SECONDS, TEST_JWT_SECRET};
use super::instruments::InstrumentInfo;
use crate::keys::ed25519::DerivedSigner;
use crate::matcher::{FillMemo, MatcherState};
use crate::merkle::MerkleMirror;
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
}

/// Per-account fill-memo channel depth. A slow `/ws/fills` client that lags
/// past this is closed with a 1011 resync (it backfills via the indexer).
const FILLS_CHANNEL_CAP: usize = 1024;

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
        }
    }

    // ── Per-account fills routing ───────────────────────────────

    /// Record `order_id → account_id` at accepted intake. Idempotent.
    pub async fn record_order_owner(&self, order_id: String, account_id: String) {
        self.order_owner.write().await.insert(order_id, account_id);
    }

    /// Drop an order's owner mapping (on cancel; full-fill/expiry eviction is a
    /// follow-up that needs the matcher to signal the API layer).
    pub async fn forget_order(&self, order_id: &str) {
        self.order_owner.write().await.remove(order_id);
    }

    /// Get-or-create the caller account's fill-memo channel and subscribe. A
    /// receiver created here only sees memos sent AFTER it subscribes — earlier
    /// fills are recovered via the indexer backfill (the "backfill then tail"
    /// contract).
    pub async fn subscribe_account_fills(&self, account_id: &str) -> broadcast::Receiver<FillMemo> {
        let mut routes = self.fills_routes.write().await;
        // Opportunistic GC: drop channels whose `/ws/fills` subscribers have all
        // disconnected (`receiver_count() == 0`), so the map stays bounded by the
        // number of CURRENTLY-connected accounts rather than every account ever
        // seen. Safe because we hold the write lock here — `subscribe` is the only
        // path that inserts, so no concurrent caller can be mid-flight holding a
        // just-created receiver; and a reconnecting client backfills from the
        // indexer ("backfill then tail"), so discarding its stale channel loses
        // nothing. Cheap: `receiver_count()` is an atomic load, subscribes are rare.
        routes.retain(|_, tx| tx.receiver_count() > 0);
        let tx = routes
            .entry(account_id.to_string())
            .or_insert_with(|| broadcast::channel(FILLS_CHANNEL_CAP).0);
        tx.subscribe()
    }

    /// Route one memo to its owning account's channel. Returns true when it was
    /// delivered to at least one live subscriber; false when the order is
    /// unknown or no `/ws/fills` client is currently attached (the client will
    /// backfill from the indexer).
    pub async fn route_fill(&self, memo: &FillMemo) -> bool {
        let account = self.order_owner.read().await.get(&memo.order_id).cloned();
        let Some(account) = account else { return false };
        let tx = self.fills_routes.read().await.get(&account).cloned();
        match tx {
            Some(tx) => tx.send(memo.clone()).is_ok(),
            None => false,
        }
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
        st.revoked_jtis.write().await.insert("jti-xyz".to_string());
        st.persist_auth().await;

        // Simulate a restart: load the snapshot from the same dir.
        let (registry, revoked) = ApiState::load_or_seed_auth(Some(dir.path()));

        let bob = registry.lookup("bob").expect("bob survived restart");
        assert!(bob.verify_credentials("bob-secret", "bob-pass"));
        assert!(!bob.is_admin);
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
}
