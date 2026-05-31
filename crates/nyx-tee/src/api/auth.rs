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
//! Credential storage (this PR) is plaintext in-memory in
//! [`AccountRegistry`]. That's fine while the registry is populated
//! only from `ApiState::for_tests()` (single test account) and the
//! production binary boots with an empty registry. A future PR will
//! add (a) an admin endpoint to register accounts, (b) Argon2-based
//! credential hashing, and (c) dstack-encrypted persistence to
//! `/var/lib/nyx-tee/accounts.db`. The `verify_credentials` method
//! already uses constant-time comparison so the hashing migration
//! won't change call-sites.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

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
use subtle::ConstantTimeEq;

use super::state::ApiState;

/// Default bearer token TTL — 1 hour. Configurable per `ApiState`.
pub const DEFAULT_JWT_TTL_SECONDS: u64 = 3600;

/// JWT claim shape. `sub` is the `account_id` (which equals
/// `api_key` for now — they'll diverge if we ever support multiple
/// API keys per account). `iat` / `exp` are unix-seconds.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub iat: u64,
    pub exp: u64,
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

/// Injected into request extensions by [`bearer_middleware`] on
/// successful auth. Downstream handlers extract it via
/// `axum::Extension<Authorized>` to identify the caller.
#[derive(Clone, Debug)]
pub struct Authorized {
    pub account_id: String,
}

/// One account's credentials. Stored plaintext in this PR (see
/// module-level doc). Comparison goes through [`Self::verify_credentials`],
/// which already uses `subtle::ConstantTimeEq` so the future Argon2
/// migration is a one-spot change.
#[derive(Clone, Debug)]
pub struct ApiCredentials {
    pub api_key: String,
    pub api_secret: String,
    pub passphrase: String,
}

impl ApiCredentials {
    /// Constant-time verification of `(api_secret, passphrase)`.
    /// `api_key` is NOT compared here — the registry already used
    /// it as the lookup key, so equality is structurally implied.
    pub fn verify_credentials(&self, api_secret: &str, passphrase: &str) -> bool {
        let a = self.api_secret.as_bytes().ct_eq(api_secret.as_bytes());
        let b = self.passphrase.as_bytes().ct_eq(passphrase.as_bytes());
        (a & b).into()
    }
}

/// In-memory account registry. Read-only for the API surface;
/// mutated only at construction time (in this PR, via
/// `ApiState::for_tests()` or the boot path's `from_boot(...)`
/// which currently boots with no accounts).
#[derive(Clone, Debug, Default)]
pub struct AccountRegistry {
    by_api_key: std::collections::HashMap<String, ApiCredentials>,
}

impl AccountRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder-style entry insert. Test-helper-ergonomic — used by
    /// `ApiState::for_tests()` to seed one known account.
    #[must_use]
    pub fn with_entry(mut self, creds: ApiCredentials) -> Self {
        self.by_api_key.insert(creds.api_key.clone(), creds);
        self
    }

    pub fn lookup(&self, api_key: &str) -> Option<&ApiCredentials> {
        self.by_api_key.get(api_key)
    }

    /// BOOTSTRAP (dev / bench only). Seed a single account from the
    /// `NYX_TEE_API_KEY` / `NYX_TEE_API_SECRET` / `NYX_TEE_PASSPHRASE`
    /// env vars when all three are set and non-empty; otherwise return
    /// an empty registry — byte-identical to `new()`, so a deploy that
    /// doesn't set them behaves exactly as before.
    ///
    /// This is a deliberate STOPGAP so authenticated load / bench runs
    /// can target a real `from_boot` CVM before the production account
    /// system exists. It is explicitly NOT that system: one account,
    /// plaintext from env, no registration / rotation / revocation. The
    /// real plan (admin registration endpoint + Argon2 hashing +
    /// dstack-encrypted `accounts.db`) is in this module's top doc.
    /// TODO(auth): delete once the registration endpoint lands.
    #[must_use]
    pub fn from_env_bootstrap() -> Self {
        match (
            std::env::var("NYX_TEE_API_KEY"),
            std::env::var("NYX_TEE_API_SECRET"),
            std::env::var("NYX_TEE_PASSPHRASE"),
        ) {
            (Ok(api_key), Ok(api_secret), Ok(passphrase))
                if !api_key.is_empty() && !api_secret.is_empty() && !passphrase.is_empty() =>
            {
                tracing::warn!(
                    %api_key,
                    "BOOTSTRAP auth: seeding ONE account from NYX_TEE_API_* env \
                     (dev/bench stopgap — NOT the production account system)"
                );
                Self::new().with_entry(ApiCredentials {
                    api_key,
                    api_secret,
                    passphrase,
                })
            }
            _ => {
                tracing::debug!(
                    "no NYX_TEE_API_* bootstrap creds set; account registry empty \
                     (auth rejects all credentials until the registration feature lands)"
                );
                Self::new()
            }
        }
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
) -> Result<Json<TokenResponse>, (StatusCode, String)> {
    let creds = state
        .accounts
        .lookup(&req.api_key)
        .ok_or((StatusCode::UNAUTHORIZED, "invalid credentials".to_string()))?;

    if !creds.verify_credentials(&req.api_secret, &req.passphrase) {
        return Err((StatusCode::UNAUTHORIZED, "invalid credentials".to_string()));
    }

    let iat = now_unix_seconds();
    let exp = iat.saturating_add(state.jwt_ttl_seconds);
    let claims = Claims {
        sub: creds.api_key.clone(),
        iat,
        exp,
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
) -> Result<Response, (StatusCode, String)> {
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

    let claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret(&state.jwt_secret),
        &Validation::default(),
    )
    .map_err(|e| (StatusCode::UNAUTHORIZED, format!("invalid token: {e}")))?
    .claims;

    req.extensions_mut().insert(Authorized {
        account_id: claims.sub,
    });

    Ok(next.run(req).await)
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

/// Build a registry pre-seeded with `TEST_*` credentials. Used by
/// `ApiState::for_tests()` and by integration tests that want to
/// drive `POST /auth/token` with a known-good payload.
pub fn test_registry() -> AccountRegistry {
    AccountRegistry::new().with_entry(ApiCredentials {
        api_key: TEST_API_KEY.to_string(),
        api_secret: TEST_API_SECRET.to_string(),
        passphrase: TEST_PASSPHRASE.to_string(),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests — focused on the algebraic surface (credential compare +
// JWT round-trip). End-to-end HTTP behaviour lives in tests/auth_surface.rs.
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_accepts_matching_credentials() {
        let creds = ApiCredentials {
            api_key: "k".into(),
            api_secret: "s".into(),
            passphrase: "p".into(),
        };
        assert!(creds.verify_credentials("s", "p"));
    }

    #[test]
    fn verify_rejects_mismatched_secret() {
        let creds = ApiCredentials {
            api_key: "k".into(),
            api_secret: "s".into(),
            passphrase: "p".into(),
        };
        assert!(!creds.verify_credentials("s2", "p"));
    }

    #[test]
    fn verify_rejects_mismatched_passphrase() {
        let creds = ApiCredentials {
            api_key: "k".into(),
            api_secret: "s".into(),
            passphrase: "p".into(),
        };
        assert!(!creds.verify_credentials("s", "p2"));
    }

    #[test]
    fn verify_rejects_both_empty() {
        let creds = ApiCredentials {
            api_key: "k".into(),
            api_secret: "s".into(),
            passphrase: "p".into(),
        };
        assert!(!creds.verify_credentials("", ""));
    }

    #[test]
    fn registry_lookup_by_api_key() {
        let r = AccountRegistry::new().with_entry(ApiCredentials {
            api_key: "alpha".into(),
            api_secret: "x".into(),
            passphrase: "y".into(),
        });
        assert!(r.lookup("alpha").is_some());
        assert!(r.lookup("beta").is_none());
    }

    #[test]
    fn jwt_roundtrip_decodes_with_same_secret() {
        let secret = [0x11u8; 32];
        let claims = Claims {
            sub: "user-42".to_string(),
            iat: now_unix_seconds(),
            exp: now_unix_seconds() + 60,
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
