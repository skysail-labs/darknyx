//! Layer A — operational auth.
//!
//! Issues short-lived HS256 JWTs from `(api_key, api_secret,
//! passphrase)` credentials and enforces `Authorization: Bearer
//! <token>` on protected routes. See `docs/tee-architecture.md` §11.2
//! for the design rationale.
//!
//! Layout overview:
//!
//! - [`token_handler`] backs `POST /auth/token` — public; takes
//!   credentials, returns a JWT with `expires_in` seconds TTL.
//! - [`bearer_middleware`] is `axum::middleware::from_fn_with_state`
//!   friendly — mount it on a sub-router that holds all protected
//!   routes (PR 4e.3 mounts `/orders` under it).
//! - [`Authorized`] is what the middleware injects into the request
//!   extensions on success; downstream handlers read it via
//!   `axum::Extension<Authorized>`.
//!
//! Credential storage (Phase 1a) is **argon2id PHC hashes** held
//! in-memory in [`AccountRegistry`] — never plaintext. The registry
//! is mutated at runtime by the admin-gated `POST /admin/accounts`
//! registration endpoint ([`register_account_handler`]); the first
//! admin is seeded from the `NYX_TEE_API_*` env at boot
//! ([`AccountRegistry::from_env_bootstrap`]) since *something* has to
//! seed the bootstrap admin (chicken-and-egg). Token revocation is an
//! in-memory `jti` denylist on [`ApiState`]; [`bearer_middleware`]
//! rejects revoked tokens.
//!
//! Phase 1b (live): the registry + denylist are persisted to
//! `accounts.db` under `NYX_TEE_STATE_DIR` (the dstack LUKS mount) —
//! write-on-change, best-effort, via [`crate::persistence::auth`].
//! `ApiState::from_boot` loads the snapshot then merges the env admin;
//! the register/revoke handlers call `ApiState::persist_auth` after
//! mutating. This module is still Layer A only (operational); the
//! load-bearing custody auth is Layer B (the per-order trading-key
//! signature), untouched here. See `docs/tee-architecture.md` §11.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::Argon2;
use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
    Json,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use super::state::ApiState;

/// Default bearer token TTL — 1 hour. Configurable per `ApiState`.
pub const DEFAULT_JWT_TTL_SECONDS: u64 = 3600;

/// JWT claim shape. `sub` is the `account_id` (which equals
/// `api_key` for now — they'll diverge if we ever support multiple
/// API keys per account). `iat` / `exp` are unix-seconds. `jti` is a
/// random per-token id; `POST /auth/token/revoke` denylists it and
/// [`bearer_middleware`] rejects any token whose `jti` is denylisted.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub iat: u64,
    pub exp: u64,
    pub jti: String,
}

/// Wire request body for `POST /auth/token`. Mirrors
/// `docs/tee-api-openapi.yaml`'s `TokenRequest` schema.
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub api_key: String,
    pub api_secret: String,
    pub passphrase: String,
}

/// Wire response body. `token_type` is always `"Bearer"`.
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

/// Wire request body for `POST /admin/accounts`. Admin-gated
/// registration of a new API account. The provided `(api_secret,
/// passphrase)` are argon2id-hashed before storage — the plaintext
/// is never persisted. `is_admin` lets an admin mint another admin
/// (defaults false via serde when omitted).
#[derive(Debug, Deserialize)]
pub struct RegisterAccountRequest {
    pub api_key: String,
    pub api_secret: String,
    pub passphrase: String,
    #[serde(default)]
    pub is_admin: bool,
}

/// Wire response for a successful registration. Echoes back the
/// `api_key` + role so the caller can confirm what was created.
/// Never echoes the secret/passphrase.
#[derive(Debug, Serialize)]
pub struct RegisterAccountResponse {
    pub api_key: String,
    pub is_admin: bool,
}

/// Injected into request extensions by [`bearer_middleware`] on
/// successful auth. Downstream handlers extract it via
/// `axum::Extension<Authorized>` to identify the caller. `jti` is the
/// token id carried so `POST /auth/token/revoke` can denylist the
/// exact token that authenticated the request.
#[derive(Clone, Debug)]
pub struct Authorized {
    pub account_id: String,
    pub jti: String,
}

/// One account's stored credentials. The `api_secret` and
/// `passphrase` are kept ONLY as argon2id PHC-string hashes
/// (salt + params embedded) — never plaintext. `is_admin` gates the
/// `POST /admin/accounts` registration endpoint.
///
/// `Serialize`/`Deserialize` back the Phase-1b `accounts.db` snapshot
/// ([`crate::persistence`]). Only the argon2 hashes are persisted —
/// never plaintext — and the file lives on the dstack LUKS volume.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiCredentials {
    pub api_key: String,
    pub secret_hash: String,
    pub passphrase_hash: String,
    pub is_admin: bool,
    /// Per-account preferences. `#[serde(default)]` so snapshots written before
    /// this field existed still deserialize (older `accounts.db` files have no
    /// `settings` key → `AccountSettings::default()`).
    #[serde(default)]
    pub settings: AccountSettings,
}

/// Per-account, mutable preferences served by `GET`/`PUT /account/settings`.
/// Persisted in the `accounts.db` snapshot alongside the credential hashes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountSettings {
    /// Account-wide default for `/ws/trading` cancel-on-disconnect. A socket's
    /// explicit `?cancel_on_disconnect=` query param overrides this; absent, the
    /// account default applies.
    #[serde(default)]
    pub cancel_on_disconnect_default: bool,
}

impl ApiCredentials {
    /// Hash a plaintext `(api_secret, passphrase)` pair into stored
    /// credentials. Each field gets its own random salt + a fresh
    /// argon2id PHC string. Returns an error only if argon2 hashing
    /// fails (effectively never for these short inputs).
    ///
    /// This is CPU-bound by design (argon2 is deliberately slow).
    /// It runs at registration time + once per `from_env_bootstrap`
    /// / `test_registry` construction — never on the per-order hot
    /// path — so a synchronous hash is fine.
    pub fn from_plaintext(
        api_key: impl Into<String>,
        api_secret: &str,
        passphrase: &str,
        is_admin: bool,
    ) -> Result<Self, argon2::password_hash::Error> {
        Ok(Self {
            api_key: api_key.into(),
            secret_hash: hash_secret(api_secret)?,
            passphrase_hash: hash_secret(passphrase)?,
            is_admin,
            settings: AccountSettings::default(),
        })
    }

    /// Verify `(api_secret, passphrase)` against the stored argon2id
    /// hashes. `api_key` is NOT compared here — the registry already
    /// used it as the lookup key, so equality is structurally implied.
    ///
    /// BOTH factors are verified unconditionally (note the
    /// non-short-circuiting `&`): a `&&` would skip the passphrase
    /// Argon2 when the secret check fails, so a wrong `api_secret` would
    /// return after ~1 hash while a correct secret + wrong passphrase
    /// returns after ~2 — a timing oracle leaking whether the secret
    /// alone matched. Argon2 is deliberately slow, so that gap is
    /// measurable; verifying both every time closes it.
    ///
    /// A malformed stored hash (shouldn't happen — we only ever store
    /// hashes we produced) verifies as `false` rather than panicking.
    pub fn verify_credentials(&self, api_secret: &str, passphrase: &str) -> bool {
        let secret_ok = verify_secret(&self.secret_hash, api_secret);
        let passphrase_ok = verify_secret(&self.passphrase_hash, passphrase);
        secret_ok & passphrase_ok
    }
}

/// Argon2id-hash a single secret with a fresh random salt, returning
/// the PHC string (`$argon2id$v=19$m=...,t=...,p=...$salt$hash`).
fn hash_secret(plaintext: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default().hash_password(plaintext.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

/// Verify a plaintext secret against a stored argon2id PHC string.
/// Returns `false` on any parse/verify failure (never panics).
fn verify_secret(stored_phc: &str, plaintext: &str) -> bool {
    match PasswordHash::new(stored_phc) {
        Ok(parsed) => Argon2::default()
            .verify_password(plaintext.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// In-memory account registry. Held behind a `RwLock` on
/// [`ApiState`] so the admin-gated `POST /admin/accounts` endpoint can
/// insert at runtime ([`Self::register`]) while `POST /auth/token`
/// takes read locks to look credentials up.
#[derive(Clone, Debug, Default)]
pub struct AccountRegistry {
    by_api_key: std::collections::HashMap<String, ApiCredentials>,
}

impl AccountRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder-style entry insert. Test-helper-ergonomic — used by
    /// `test_registry()` + `from_env_bootstrap()` to seed accounts at
    /// construction time. Takes already-hashed [`ApiCredentials`].
    #[must_use]
    pub fn with_entry(mut self, creds: ApiCredentials) -> Self {
        self.by_api_key.insert(creds.api_key.clone(), creds);
        self
    }

    /// Runtime registration of a new account. Rejects a duplicate
    /// `api_key` (returns `false`) so a registration can't silently
    /// overwrite an existing account's credentials — the admin must
    /// pick a fresh key. Returns `true` on a successful insert.
    pub fn register(&mut self, creds: ApiCredentials) -> bool {
        if self.by_api_key.contains_key(&creds.api_key) {
            return false;
        }
        self.by_api_key.insert(creds.api_key.clone(), creds);
        true
    }

    pub fn lookup(&self, api_key: &str) -> Option<&ApiCredentials> {
        self.by_api_key.get(api_key)
    }

    /// Remove an account by API key. Production boot uses this to scrub the
    /// historical public test account from persisted snapshots.
    pub(crate) fn remove(&mut self, api_key: &str) -> bool {
        self.by_api_key.remove(api_key).is_some()
    }

    /// Replace an account's [`AccountSettings`]. Returns `true` if the account
    /// existed (and was updated). The caller persists the registry afterwards.
    pub fn set_settings(&mut self, api_key: &str, settings: AccountSettings) -> bool {
        match self.by_api_key.get_mut(api_key) {
            Some(creds) => {
                creds.settings = settings;
                true
            }
            None => false,
        }
    }

    /// Number of registered accounts. Used by the boot path to decide
    /// whether a loaded snapshot was non-empty.
    pub fn len(&self) -> usize {
        self.by_api_key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_api_key.is_empty()
    }

    /// Snapshot all credentials as a `Vec` for persistence
    /// ([`crate::persistence`]). Order is unspecified (HashMap
    /// iteration) — the snapshot is a set, not a sequence.
    pub fn snapshot(&self) -> Vec<ApiCredentials> {
        self.by_api_key.values().cloned().collect()
    }

    /// Rebuild a registry from a persisted snapshot. Later duplicates
    /// for the same `api_key` overwrite earlier ones (shouldn't happen
    /// — the map that produced the snapshot was already keyed).
    pub fn from_snapshot(entries: Vec<ApiCredentials>) -> Self {
        let mut reg = Self::new();
        for creds in entries {
            reg.by_api_key.insert(creds.api_key.clone(), creds);
        }
        reg
    }

    /// BOOTSTRAP the admin account from the `NYX_TEE_API_KEY` /
    /// `NYX_TEE_API_SECRET` / `NYX_TEE_PASSPHRASE` env vars when all
    /// three are set and non-empty; otherwise return an empty registry
    /// — byte-identical to `new()`, so a deploy that doesn't set them
    /// behaves exactly as before (auth rejects everything until an
    /// admin exists).
    ///
    /// The env-seeded account is the **bootstrap admin** (`is_admin =
    /// true`): the chicken-and-egg seed that can then register every
    /// other account via `POST /admin/accounts`. Its credentials are
    /// argon2id-hashed here exactly as a registered account's would
    /// be — the env plaintext is hashed and dropped, never stored.
    ///
    /// With Phase-1b persistence the env seed is merged into a loaded
    /// `accounts.db` snapshot (see [`Self::ensure_admin`] +
    /// `ApiState::from_boot`): the env admin is added only if its
    /// `api_key` is absent, so a persisted registry is authoritative
    /// and rotating the env creds after first boot needs the API or a
    /// file wipe.
    #[must_use]
    pub fn from_env_bootstrap() -> Self {
        match env_admin_credentials() {
            Some(creds) => {
                tracing::warn!(
                    api_key = %creds.api_key,
                    "BOOTSTRAP auth: seeding the ADMIN account from NYX_TEE_API_* env \
                     (argon2id-hashed). Register further accounts via POST /admin/accounts."
                );
                Self::new().with_entry(creds)
            }
            None => {
                tracing::debug!(
                    "no NYX_TEE_API_* bootstrap creds set; account registry left as-is \
                     (auth rejects unknown credentials until an admin exists)"
                );
                Self::new()
            }
        }
    }

    /// Ensure the bootstrap admin from the `NYX_TEE_API_*` env exists
    /// in this (possibly snapshot-loaded) registry. Adds it only if its
    /// `api_key` is absent — a persisted account with the same key is
    /// never overwritten. Returns `true` if an account was added (so
    /// the caller can persist the seeded state on first boot).
    pub fn ensure_admin(&mut self) -> bool {
        match env_admin_credentials() {
            Some(creds) if self.lookup(&creds.api_key).is_none() => {
                tracing::warn!(
                    api_key = %creds.api_key,
                    "BOOTSTRAP auth: admin not in persisted registry — seeding from \
                     NYX_TEE_API_* env (argon2id-hashed)."
                );
                self.register(creds)
            }
            _ => false,
        }
    }
}

/// Read + argon2-hash the bootstrap admin credentials from the
/// `NYX_TEE_API_KEY` / `NYX_TEE_API_SECRET` / `NYX_TEE_PASSPHRASE` env
/// vars. `Some` only when all three are set, non-empty, and hashing
/// succeeds; `None` otherwise (logged at error level on a hash
/// failure). The env plaintext is hashed and dropped — never stored.
fn env_admin_credentials() -> Option<ApiCredentials> {
    match (
        std::env::var("NYX_TEE_API_KEY"),
        std::env::var("NYX_TEE_API_SECRET"),
        std::env::var("NYX_TEE_PASSPHRASE"),
    ) {
        (Ok(api_key), Ok(api_secret), Ok(passphrase))
            if !api_key.is_empty() && !api_secret.is_empty() && !passphrase.is_empty() =>
        {
            match ApiCredentials::from_plaintext(&api_key, &api_secret, &passphrase, true) {
                Ok(creds) => Some(creds),
                Err(e) => {
                    tracing::error!(
                        %api_key, error = %e,
                        "BOOTSTRAP auth: argon2 hashing of the admin seed FAILED; \
                         no admin will be seeded from env"
                    );
                    None
                }
            }
        }
        _ => None,
    }
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        // Pre-1970 systems shouldn't exist — but if they do, treat
        // as epoch. The JWT will have iat=0 which is unambiguous.
        .unwrap_or(0)
}

/// Generate a random 128-bit token id, hex-encoded. Used as the JWT
/// `jti` so a specific issued token can be revoked
/// (`POST /auth/token/revoke`) without invalidating other tokens for
/// the same account. 128 bits of OS randomness makes collisions
/// (and guessing) a non-issue.
fn new_jti() -> String {
    let bytes: [u8; 16] = rand::random();
    hex::encode(bytes)
}

/// `POST /auth/token` handler.
///
/// Returns 401 on:
///   - unknown `api_key`,
///   - `api_secret` / `passphrase` mismatch.
///
/// Returns 500 only if the JWT library itself fails to encode
/// (which is a programmer error — HS256 with a fixed 32-byte secret
/// has no runtime failure modes).
pub async fn token_handler(
    State(state): State<Arc<ApiState>>,
    Json(req): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, super::error::ApiError> {
    // Clone the stored creds out of the read lock so the (CPU-bound)
    // argon2 verify runs without holding the registry lock.
    let creds = {
        let registry = state.accounts.read().await;
        registry.lookup(&req.api_key).cloned()
    }
    .ok_or((StatusCode::UNAUTHORIZED, "invalid credentials".to_string()))?;

    // Argon2id verify is CPU-bound + ~19 MiB per hash. Run it off the
    // async reactor (spawn_blocking) and behind the concurrency limiter
    // so an unauthenticated /auth/token flood can't starve the runtime
    // or exhaust the small CVM's RAM. The permit is held for the whole
    // verify, bounding concurrent Argon2 jobs.
    let verified = {
        let _permit = state.argon2_limiter.acquire().await.map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "auth limiter closed".to_string(),
            )
        })?;
        let creds = creds.clone();
        let api_secret = req.api_secret.clone();
        let passphrase = req.passphrase.clone();
        tokio::task::spawn_blocking(move || creds.verify_credentials(&api_secret, &passphrase))
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("verify task failed: {e}"),
                )
            })?
    };
    if !verified {
        return Err(super::error::ApiError::unauthorized("invalid credentials"));
    }

    let iat = now_unix_seconds();
    let exp = iat.saturating_add(state.jwt_ttl_seconds);
    let claims = Claims {
        sub: creds.api_key.clone(),
        iat,
        exp,
        jti: new_jti(),
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(&state.jwt_secret),
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("jwt encode failed: {e}"),
        )
    })?;

    Ok(Json(TokenResponse {
        access_token: token,
        token_type: "Bearer".to_string(),
        expires_in: state.jwt_ttl_seconds,
    }))
}

/// Bearer-token middleware.
///
/// Mount via `axum::middleware::from_fn_with_state(state, bearer_middleware)`
/// on a sub-router holding all routes that require authentication.
/// On success, the request continues with an `Authorized` extension
/// containing the caller's `account_id`. On failure, returns 401
/// without ever invoking the inner handler.
pub async fn bearer_middleware(
    State(state): State<Arc<ApiState>>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, super::error::ApiError> {
    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "missing Authorization header".to_string(),
        ))?;

    let token = auth_header.strip_prefix("Bearer ").ok_or((
        StatusCode::UNAUTHORIZED,
        "Authorization must use the 'Bearer ' scheme".to_string(),
    ))?;

    let authorized = validate_token(&state, token).await?;
    req.extensions_mut().insert(authorized);
    Ok(next.run(req).await)
}

/// Validate a raw JWT string against the signing secret + revocation denylist,
/// returning the caller's [`Authorized`] identity. Shared by
/// [`bearer_middleware`] (header-based) and the `/ws/fills` handler (which takes
/// the token as a `?token=` query param, since browsers + the global
/// `WebSocket` can't set an Authorization header on the upgrade request).
pub async fn validate_token(
    state: &ApiState,
    token: &str,
) -> Result<Authorized, super::error::ApiError> {
    let claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret(&state.jwt_secret),
        &Validation::default(),
    )
    .map_err(|e| (StatusCode::UNAUTHORIZED, format!("invalid token: {e}")))?
    .claims;

    // Revocation check: a `jti` on the denylist (added by
    // `POST /auth/token/revoke`) is rejected even though the signature
    // + expiry are still valid.
    if state.revoked_jtis.read().await.contains(&claims.jti) {
        return Err(super::error::ApiError::unauthorized("token revoked"));
    }

    Ok(Authorized {
        account_id: claims.sub,
        jti: claims.jti,
    })
}

/// `POST /auth/token/revoke` handler.
///
/// Bearer-protected: mounted under [`bearer_middleware`], so the
/// caller's [`Authorized`] (with the token's `jti`) is already in the
/// request extensions. Adds that `jti` to the in-memory denylist and
/// returns `204 No Content`. Idempotent — revoking an already-revoked
/// `jti` (the token would have been rejected by the middleware before
/// reaching here, so in practice this only fires once per token) is a
/// no-op insert.
///
/// In-memory only (Phase 1a): the denylist is lost on restart, which
/// is sound because every issued token also has a hard `exp` (default
/// 1h) — a revoked token can outlive a restart by at most its
/// remaining TTL. Phase 1b persists the denylist alongside
/// `accounts.db`.
pub async fn revoke_token_handler(
    State(state): State<Arc<ApiState>>,
    axum::Extension(authorized): axum::Extension<Authorized>,
) -> StatusCode {
    state.revoked_jtis.write().await.insert(authorized.jti);
    // Persist the denylist so the revocation survives a restart
    // (best-effort — see ApiState::persist_auth).
    state.persist_auth().await;
    StatusCode::NO_CONTENT
}

/// `POST /admin/accounts` handler — admin-gated account registration.
///
/// Bearer-protected AND admin-gated: the caller's account is looked up
/// in the registry and must have `is_admin = true`. We re-check the
/// registry (rather than trusting a JWT claim) so an admin demotion
/// takes effect immediately, without waiting for outstanding tokens
/// to expire.
///
/// On success registers a fresh argon2id-hashed account and returns
/// `201 Created`. Returns `403` for a non-admin caller and `409` if
/// the `api_key` already exists.
pub async fn register_account_handler(
    State(state): State<Arc<ApiState>>,
    axum::Extension(authorized): axum::Extension<Authorized>,
    Json(req): Json<RegisterAccountRequest>,
) -> Result<(StatusCode, Json<RegisterAccountResponse>), super::error::ApiError> {
    // Authoritative admin check against the live registry.
    let caller_is_admin = {
        let registry = state.accounts.read().await;
        registry
            .lookup(&authorized.account_id)
            .map(|c| c.is_admin)
            .unwrap_or(false)
    };
    if !caller_is_admin {
        return Err(super::error::ApiError::forbidden(
            "admin privileges required",
        ));
    }

    if req.api_key.is_empty() || req.api_secret.is_empty() || req.passphrase.is_empty() {
        return Err(super::error::ApiError::malformed(
            "api_key, api_secret, and passphrase must all be non-empty",
        ));
    }

    // Hash the new credentials off the async reactor (argon2 is
    // CPU-bound + ~19 MiB/hash) and behind the concurrency limiter,
    // BEFORE taking the write lock (don't hold the registry lock across
    // it). Admin-gated, so lower risk than /auth/token, but the same
    // offload keeps a slow hash from blocking the runtime.
    let creds = {
        let _permit = state.argon2_limiter.acquire().await.map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "auth limiter closed".to_string(),
            )
        })?;
        let api_key = req.api_key.clone();
        let api_secret = req.api_secret.clone();
        let passphrase = req.passphrase.clone();
        let is_admin = req.is_admin;
        tokio::task::spawn_blocking(move || {
            ApiCredentials::from_plaintext(api_key, &api_secret, &passphrase, is_admin)
        })
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("hash task failed: {e}"),
            )
        })?
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("credential hashing failed: {e}"),
            )
        })?
    };

    let inserted = state.accounts.write().await.register(creds);
    if !inserted {
        return Err(super::error::ApiError::duplicate(format!(
            "api_key '{}' already registered",
            req.api_key
        )));
    }

    // Persist the new account before returning 201 so a restart
    // doesn't drop it (best-effort — see ApiState::persist_auth).
    state.persist_auth().await;

    tracing::info!(
        api_key = %req.api_key,
        is_admin = req.is_admin,
        registered_by = %authorized.account_id,
        "registered new API account"
    );
    Ok((
        StatusCode::CREATED,
        Json(RegisterAccountResponse {
            api_key: req.api_key,
            is_admin: req.is_admin,
        }),
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// Test fixtures — exported so integration tests under tests/ can use them
// without re-declaring the credentials.
// ─────────────────────────────────────────────────────────────────────────────

/// Test API key seeded into `ApiState::for_tests()`. NEVER use in
/// production — there's no path that wires it into a real CVM's
/// boot sequence. The presence of a hardcoded test key is
/// intentional so unit tests have something to authenticate as.
pub const TEST_API_KEY: &str = "nyx-test-api-key";
pub const TEST_API_SECRET: &str = "nyx-test-secret";
pub const TEST_PASSPHRASE: &str = "nyx-test-passphrase";
pub const TEST_JWT_SECRET: [u8; 32] = [0x42; 32];

/// Build a registry pre-seeded with `TEST_*` credentials, registered
/// as an **admin** so integration tests can drive the admin-gated
/// `POST /admin/accounts` endpoint. Used by `ApiState::for_tests()`
/// and by integration tests that want to drive `POST /auth/token`
/// with a known-good payload.
pub fn test_registry() -> AccountRegistry {
    AccountRegistry::new().with_entry(
        ApiCredentials::from_plaintext(TEST_API_KEY, TEST_API_SECRET, TEST_PASSPHRASE, true)
            .expect("argon2 hashing of test credentials"),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests — focused on the algebraic surface (credential compare +
// JWT round-trip). End-to-end HTTP behaviour lives in tests/auth_surface.rs.
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn creds(api_key: &str, secret: &str, pass: &str) -> ApiCredentials {
        ApiCredentials::from_plaintext(api_key, secret, pass, false).expect("hash")
    }

    #[test]
    fn verify_accepts_matching_credentials() {
        assert!(creds("k", "s", "p").verify_credentials("s", "p"));
    }

    #[test]
    fn verify_rejects_mismatched_secret() {
        assert!(!creds("k", "s", "p").verify_credentials("s2", "p"));
    }

    #[test]
    fn verify_rejects_mismatched_passphrase() {
        assert!(!creds("k", "s", "p").verify_credentials("s", "p2"));
    }

    #[test]
    fn verify_rejects_both_empty() {
        assert!(!creds("k", "s", "p").verify_credentials("", ""));
    }

    #[test]
    fn stored_creds_are_hashed_not_plaintext() {
        // The PHC strings must never equal the plaintext, and must be
        // argon2id. This is the regression guard against accidentally
        // reverting to plaintext storage.
        let c = creds("k", "super-secret", "pass-phrase");
        assert_ne!(c.secret_hash, "super-secret");
        assert_ne!(c.passphrase_hash, "pass-phrase");
        assert!(c.secret_hash.starts_with("$argon2id$"));
        assert!(c.passphrase_hash.starts_with("$argon2id$"));
        // Same plaintext hashed twice → different PHC strings (random
        // salt), but both verify.
        let c2 = creds("k", "super-secret", "pass-phrase");
        assert_ne!(c.secret_hash, c2.secret_hash);
        assert!(c2.verify_credentials("super-secret", "pass-phrase"));
    }

    #[test]
    fn registry_lookup_by_api_key() {
        let r = AccountRegistry::new().with_entry(creds("alpha", "x", "y"));
        assert!(r.lookup("alpha").is_some());
        assert!(r.lookup("beta").is_none());
    }

    #[test]
    fn register_rejects_duplicate_api_key() {
        let mut r = AccountRegistry::new().with_entry(creds("alpha", "x", "y"));
        // Fresh key → inserts.
        assert!(r.register(creds("beta", "x", "y")));
        // Existing key → rejected, original creds untouched.
        assert!(!r.register(creds("alpha", "different", "creds")));
        assert!(r.lookup("alpha").unwrap().verify_credentials("x", "y"));
    }

    #[test]
    fn bootstrap_admin_flag_is_set() {
        let admin = ApiCredentials::from_plaintext("a", "s", "p", true).expect("hash");
        assert!(admin.is_admin);
        let user = ApiCredentials::from_plaintext("u", "s", "p", false).expect("hash");
        assert!(!user.is_admin);
    }

    #[test]
    fn jti_is_random_and_hex() {
        let a = new_jti();
        let b = new_jti();
        assert_ne!(a, b);
        assert_eq!(a.len(), 32); // 16 bytes hex
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn jwt_roundtrip_decodes_with_same_secret() {
        let secret = [0x11u8; 32];
        let claims = Claims {
            sub: "user-42".to_string(),
            iat: now_unix_seconds(),
            exp: now_unix_seconds() + 60,
            jti: new_jti(),
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(&secret),
        )
        .unwrap();
        let decoded = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(&secret),
            &Validation::default(),
        )
        .unwrap();
        assert_eq!(decoded.claims.sub, "user-42");
    }

    #[test]
    fn jwt_decode_with_wrong_secret_fails() {
        let secret = [0x11u8; 32];
        let wrong = [0x22u8; 32];
        let claims = Claims {
            sub: "x".to_string(),
            iat: now_unix_seconds(),
            exp: now_unix_seconds() + 60,
            jti: new_jti(),
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(&secret),
        )
        .unwrap();
        let result = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(&wrong),
            &Validation::default(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_registry_has_seeded_account() {
        let r = test_registry();
        let creds = r.lookup(TEST_API_KEY).expect("seeded entry missing");
        assert!(creds.verify_credentials(TEST_API_SECRET, TEST_PASSPHRASE));
    }
}
