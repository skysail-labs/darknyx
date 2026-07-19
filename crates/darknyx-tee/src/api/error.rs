//! Structured API errors + per-request correlation id.
//!
//! Error responses render as `{ "code": <u32>, "message": <str> }` with the
//! mapped HTTP status. Every response — success AND error — carries an
//! `x-request-id` header set by [`request_id_middleware`], so a client can
//! correlate a failure with a server log line.
//!
//! The envelope is **error-only by design**: success bodies stay as their typed
//! JSON (a place response is still `{ order_id, status, arrival_slot }`), so the
//! change touches only the error path. Handlers return `Result<_, ApiError>`;
//! inner helpers that still produce `(StatusCode, String)` convert through the
//! [`From`] impl, so the migration is mechanical (the `?` operator does it).
//!
//! ## Code catalogue (stable)
//!
//! | Range | Class | Examples |
//! |-------|-------|----------|
//! | 1000–1099 | request validation (400) | 1001 malformed, 1002 fr_unsafe, 1003 below_collateral, 1004 min_notional, 1009 off_tick |
//! | 1100–1199 | auth (401/403) | 1101 unauthorized, 1102 sig_invalid, 1103 not_owner |
//! | 1200–1299 | conflict (409) | 1201 duplicate, 1202 stale_nonce, 1203 id_in_use, 1204 collateral_in_use |
//! | 1300–1399 | not found (404) | 1301 not_found |
//! | 1400–1499 | rate limit (429) | 1401 rate_limited |
//! | 5000+ | server | 5000 internal, 5001 degraded |

use axum::{
    extract::Request,
    http::{HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use rand::RngCore;
use serde_json::json;

/// A structured API error: a stable numeric `code`, the HTTP `status` it maps
/// to, and a human-readable `message`.
#[derive(Debug, Clone)]
pub struct ApiError {
    pub code: u32,
    pub status: StatusCode,
    pub message: String,
}

impl ApiError {
    pub fn new(code: u32, status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            code,
            status,
            message: message.into(),
        }
    }

    // 1000–1099 — request validation (400)
    /// Generic bad request (used by the `From` fallback for an unclassified 400).
    pub fn bad_request(m: impl Into<String>) -> Self {
        Self::new(1000, StatusCode::BAD_REQUEST, m)
    }
    /// Malformed input — bad hex, wrong field width, zero/illegal id.
    pub fn malformed(m: impl Into<String>) -> Self {
        Self::new(1001, StatusCode::BAD_REQUEST, m)
    }
    /// A value that must be a canonical BN254 field element is not.
    pub fn fr_unsafe(m: impl Into<String>) -> Self {
        Self::new(1002, StatusCode::BAD_REQUEST, m)
    }
    /// The collateral note does not cover the order's nominal cost + fee.
    pub fn below_collateral(m: impl Into<String>) -> Self {
        Self::new(1003, StatusCode::BAD_REQUEST, m)
    }
    /// The order amount is below the market's minimum.
    pub fn min_notional(m: impl Into<String>) -> Self {
        Self::new(1004, StatusCode::BAD_REQUEST, m)
    }
    /// A bid was submitted with a zero price limit.
    pub fn zero_price_bid(m: impl Into<String>) -> Self {
        Self::new(1005, StatusCode::BAD_REQUEST, m)
    }
    /// The note opening does not re-derive the signed `note_commitment`.
    pub fn bad_opening(m: impl Into<String>) -> Self {
        Self::new(1006, StatusCode::BAD_REQUEST, m)
    }
    /// The order's `expiry_slot` is further out than `MAX_LOCK_TTL_SLOTS`
    /// (F-05): the settler stamps the note lock with this expiry, and the vault
    /// caps the lock window, so an order this long-lived could never settle.
    pub fn expiry_too_far(m: impl Into<String>) -> Self {
        Self::new(1007, StatusCode::BAD_REQUEST, m)
    }
    /// Required X25519 viewing key is a low-order/non-contributory point.
    pub fn invalid_viewing_key(m: impl Into<String>) -> Self {
        Self::new(1008, StatusCode::BAD_REQUEST, m)
    }
    /// A non-zero order limit is not an integer multiple of the market tick.
    pub fn off_tick(m: impl Into<String>) -> Self {
        Self::new(1009, StatusCode::BAD_REQUEST, m)
    }

    // 1100–1199 — auth (401/403)
    /// Missing / invalid / expired / revoked bearer token, or bad credentials.
    pub fn unauthorized(m: impl Into<String>) -> Self {
        Self::new(1101, StatusCode::UNAUTHORIZED, m)
    }
    /// The trading-key signature did not verify over the canonical body.
    pub fn sig_invalid(m: impl Into<String>) -> Self {
        Self::new(1102, StatusCode::FORBIDDEN, m)
    }
    /// The trading key does not own the targeted order.
    pub fn not_owner(m: impl Into<String>) -> Self {
        Self::new(1103, StatusCode::FORBIDDEN, m)
    }
    /// Generic forbidden (e.g. admin-gated route, non-admin caller).
    pub fn forbidden(m: impl Into<String>) -> Self {
        Self::new(1150, StatusCode::FORBIDDEN, m)
    }

    // 1200–1299 — conflict (409)
    /// A different order already exists with this id.
    pub fn duplicate(m: impl Into<String>) -> Self {
        Self::new(1201, StatusCode::CONFLICT, m)
    }
    /// A replay-protection nonce did not strictly advance.
    pub fn stale_nonce(m: impl Into<String>) -> Self {
        Self::new(1202, StatusCode::CONFLICT, m)
    }
    /// A modify's replacement order id is already booked.
    pub fn id_in_use(m: impl Into<String>) -> Self {
        Self::new(1203, StatusCode::CONFLICT, m)
    }
    /// A collateral note commitment is already reserved by another live or
    /// settlement-pending order.
    pub fn collateral_in_use(m: impl Into<String>) -> Self {
        Self::new(1204, StatusCode::CONFLICT, m)
    }
    /// Signed order targets a prior or unrelated CVM boot session.
    pub fn stale_session(m: impl Into<String>) -> Self {
        Self::new(1205, StatusCode::CONFLICT, m)
    }

    // 1300–1399 — not found (404)
    pub fn not_found(m: impl Into<String>) -> Self {
        Self::new(1301, StatusCode::NOT_FOUND, m)
    }

    // 1400–1499 — rate limit (429)
    pub fn rate_limited(m: impl Into<String>) -> Self {
        Self::new(1401, StatusCode::TOO_MANY_REQUESTS, m)
    }

    // 5000+ — server
    pub fn internal(m: impl Into<String>) -> Self {
        Self::new(5000, StatusCode::INTERNAL_SERVER_ERROR, m)
    }
    /// A required subsystem (matching / settlement) is unavailable.
    pub fn degraded(m: impl Into<String>) -> Self {
        Self::new(5001, StatusCode::SERVICE_UNAVAILABLE, m)
    }
}

/// Mechanical migration path: any handler/helper still returning
/// `(StatusCode, String)` converts to an `ApiError` through `?`. The numeric
/// code is derived from the status class (coarse); call a specific constructor
/// above where a precise code is wanted.
impl From<(StatusCode, String)> for ApiError {
    fn from((status, message): (StatusCode, String)) -> Self {
        let code = match status {
            StatusCode::BAD_REQUEST => 1000,
            StatusCode::UNAUTHORIZED => 1101,
            StatusCode::FORBIDDEN => 1150,
            StatusCode::NOT_FOUND => 1301,
            StatusCode::CONFLICT => 1200,
            StatusCode::TOO_MANY_REQUESTS => 1400,
            StatusCode::SERVICE_UNAVAILABLE => 5001,
            _ => 5000,
        };
        Self {
            code,
            status,
            message,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({ "code": self.code, "message": self.message })),
        )
            .into_response()
    }
}

/// A per-request correlation id, injected into request extensions by
/// [`request_id_middleware`] and echoed as the `x-request-id` response header.
#[derive(Debug, Clone)]
pub struct RequestId(pub String);

fn gen_request_id() -> String {
    let mut b = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut b);
    format!("req_{}", hex::encode(b))
}

/// Stamp every response with an `x-request-id` header (and make the id readable
/// by handlers via `Extension<RequestId>`). Mounted once on the top-level
/// router so it wraps success, error, and 404-fallback responses alike.
pub async fn request_id_middleware(mut req: Request, next: Next) -> Response {
    let id = gen_request_id();
    req.extensions_mut().insert(RequestId(id.clone()));
    let mut resp = next.run(req).await;
    if let Ok(hv) = HeaderValue::from_str(&id) {
        resp.headers_mut().insert("x-request-id", hv);
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specific_constructors_pin_code_and_status() {
        let e = ApiError::sig_invalid("nope");
        assert_eq!(e.code, 1102);
        assert_eq!(e.status, StatusCode::FORBIDDEN);

        let e = ApiError::min_notional("too small");
        assert_eq!(e.code, 1004);
        assert_eq!(e.status, StatusCode::BAD_REQUEST);

        let e = ApiError::degraded("down");
        assert_eq!(e.code, 5001);
        assert_eq!(e.status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn from_tuple_maps_status_class_to_a_code() {
        let e: ApiError = (StatusCode::NOT_FOUND, "missing".to_string()).into();
        assert_eq!(e.code, 1301);
        assert_eq!(e.status, StatusCode::NOT_FOUND);
        assert_eq!(e.message, "missing");

        let e: ApiError = (StatusCode::CONFLICT, "dup".to_string()).into();
        assert_eq!(e.code, 1200);
    }

    #[test]
    fn request_ids_are_unique_and_prefixed() {
        let a = gen_request_id();
        let b = gen_request_id();
        assert!(a.starts_with("req_"));
        assert_ne!(a, b);
    }
}
