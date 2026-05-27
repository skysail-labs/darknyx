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

use super::auth::{test_registry, AccountRegistry, DEFAULT_JWT_TTL_SECONDS, TEST_JWT_SECRET};
use crate::keys::ed25519::DerivedSigner;

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
        }
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
        }
    }
}
