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

use std::sync::Arc;
use std::time::Instant;

use dstack_sdk::dstack_client::DstackClient;

use tokio::sync::RwLock;

use super::auth::{test_registry, AccountRegistry, DEFAULT_JWT_TTL_SECONDS, TEST_JWT_SECRET};
use crate::keys::ed25519::DerivedSigner;
use crate::matcher::MatcherState;
use crate::oracle::OracleCache;
use crate::settle::SettleSchedulerState;
use crate::solana_rpc::SolanaRpcClient;

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
    /// Account registry consulted by `POST /auth/token` to
    /// validate `(api_key, api_secret, passphrase)` triples. In
    /// this PR it's populated only via `for_tests()` (one seeded
    /// account) and is empty in production until a separate
    /// admin-registration endpoint lands.
    pub accounts: Arc<AccountRegistry>,
    /// Lifetime of each issued JWT. Configurable per instance;
    /// defaults to [`super::auth::DEFAULT_JWT_TTL_SECONDS`].
    pub jwt_ttl_seconds: u64,

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

    // ── Solana RPC + fee-payer (PR 4g.2) ────────────────────────
    /// Hand-rolled JSON-RPC client pointed at the configured
    /// Solana cluster URL. `None` in degraded boot; populated by
    /// `main.rs` after construction. Cloneable cheaply (the inner
    /// reqwest::Client is internally Arc) — stage workers in
    /// 4g.3+ will clone it into their per-job tasks.
    pub solana_rpc: Option<SolanaRpcClient>,
    /// Base58 of the dstack-derived fee-payer pubkey. The keypair
    /// itself stays inside the settle pipeline's stage workers
    /// (not exposed via HTTP). Surfacing the pubkey on `/info`
    /// lets operators verify the address they pre-funded matches
    /// the one this CVM derives. Filled by `main.rs` after
    /// successful boot; `None` in degraded boot + tests.
    pub fee_payer_pubkey_base58: Option<String>,
}

impl ApiState {
    /// Build production state from a successful boot. `jwt_secret`
    /// is the 32-byte value derived via dstack `get_key`; the
    /// account registry starts empty — populated by the (future)
    /// admin-registration endpoint.
    pub fn from_boot(
        app_info: BootAppInfo,
        signer: &DerivedSigner,
        dstack: Arc<DstackClient>,
        jwt_secret: [u8; 32],
    ) -> Self {
        Self {
            app_info,
            signer_pubkey_base58: signer.pubkey_base58.clone(),
            signer_pubkey_hex: signer.pubkey_hex.clone(),
            dstack: Some(dstack),
            start: Instant::now(),
            nyx_version: env!("CARGO_PKG_VERSION"),
            jwt_secret,
            accounts: Arc::new(AccountRegistry::new()),
            jwt_ttl_seconds: DEFAULT_JWT_TTL_SECONDS,
            // `from_boot` doesn't construct the matcher — PR 4e.4
            // spawns the `MatcherDriver` and plumbs its state in via
            // a separate construction path. Until then the orders
            // handlers see `None` and return 503.
            matcher: None,
            current_slot: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            oracle: None,
            settle_state: None,
            solana_rpc: None,
            fee_payer_pubkey_base58: None,
        }
    }

    /// Attach the Solana RPC client + the fee-payer pubkey display
    /// string. Called by `main.rs` once both are constructed; the
    /// stage workers in 4g.3+ read `solana_rpc` to submit txs.
    /// Idempotent.
    pub fn with_solana_rpc(
        mut self,
        rpc: SolanaRpcClient,
        fee_payer_pubkey_base58: String,
    ) -> Self {
        self.solana_rpc = Some(rpc);
        self.fee_payer_pubkey_base58 = Some(fee_payer_pubkey_base58);
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
            accounts: Arc::new(test_registry()),
            jwt_ttl_seconds: DEFAULT_JWT_TTL_SECONDS,
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
            fee_payer_pubkey_base58: None,
        }
    }
}
