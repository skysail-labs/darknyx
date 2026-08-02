//! Weighted per-account rate limiting for the protected router.
//!
//! Mounted as a second `route_layer` INNER to `bearer_middleware`, so the
//! caller's [`super::auth::Authorized`] (with `account_id`) is already in the
//! request extensions. Each request costs a route-dependent weight — cancels
//! cheap, place/modify heavier — charged against the account's
//! [`super::state::TokenBucket`]. An empty bucket returns `429` with a
//! `Retry-After` header. This protects the small CVM from a single account's
//! flood without throttling legitimate bursts (the bucket has a burst capacity).

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{HeaderValue, Method},
    middleware::Next,
    response::{IntoResponse, Response},
};

use super::auth::Authorized;
use super::error::ApiError;
use super::state::ApiState;

/// The MPC-style weight of a request, by route. Cancels are cheap (a
/// position-indexed removal); place/modify are the expensive matcher inserts.
/// Reads + auth ops are nearly free. Mirrors the intent of a maker-friendly
/// weighted limiter (cancel-heavy market makers aren't penalised).
pub(crate) fn route_cost(method: &Method, path: &str) -> f64 {
    let is_order_subpath = path.starts_with("/orders/");
    match *method {
        // order.place
        Method::POST if path == "/orders" => 1.0,
        // order.cancel
        Method::DELETE if is_order_subpath => 0.2,
        // order.modify (atomic cancel + replace)
        Method::PUT if is_order_subpath => 1.2,
        // everything else on the protected router (reads, revoke, admin) is cheap
        _ => 0.1,
    }
}

/// Cost of a PUBLIC (unauthenticated) request, by route.
///
/// SW-02. Two public routes do real work per request and the rest are in-memory
/// reads, so a flat limit would either throttle honest polling or fail to bound
/// the expensive paths. The weights follow the actual cost:
///
/// * `/attestation` generates a **TDX quote** per request. It cannot be cached —
///   the caller-supplied nonce is the entire point — so rate limiting is the
///   only available control, and it carries the heaviest weight.
/// * `/transparency` reads Solana. It is now cached (see `api::transparency`),
///   which removes the amplification, so its weight reflects the residual
///   deserialise-and-serialise cost rather than the RPC round trip.
/// * Everything else is an in-memory read.
///
/// **`/auth/token` is deliberately EXEMPT** (cost `0.0`), and that is the one
/// weight here worth arguing with. It runs argon2id, so charging it looks
/// obviously right — but its expensive half is already shed by
/// `ApiState::argon2_limiter` (a saturated hasher returns `503` rather than
/// queueing), and an **unknown** api_key is refused before any hashing at all,
/// so the cheap half really is cheap. Charging it venue-wide would buy no
/// protection and would hand an attacker a login outage: exhausting one shared
/// bucket with junk credentials would lock every legitimate account out of
/// authenticating. That is exactly the property AU-05 established and pinned in
/// `auth_surface::unknown_credentials_cannot_throttle_a_real_account` — which
/// is how this was caught. Login stays bounded by that per-account bucket plus
/// the hash semaphore, both of which distinguish callers; this bucket cannot.
pub(crate) fn public_route_cost(method: &Method, path: &str) -> f64 {
    match (method, path) {
        (&Method::GET, "/attestation") => 10.0,
        (&Method::GET, "/transparency") => 2.0,
        (&Method::POST, "/auth/token") => 0.0,
        _ => 0.1,
    }
}

/// Venue-wide rate limit for the unauthenticated public router (SW-02).
///
/// There is no account to key on and no usable client address — every request
/// arrives through the dstack gateway's WireGuard tunnel, so all of them share
/// one apparent source (`conn_limit.rs` records the same reasoning). A single
/// venue-wide bucket bounds total upstream work; per-account limits continue to
/// bound what one credential can occupy once past `/auth/token`.
pub async fn public_rate_limit_middleware(
    State(state): State<Arc<ApiState>>,
    req: Request,
    next: Next,
) -> Response {
    let cost = public_route_cost(req.method(), req.uri().path());
    match state.try_consume_public_rate(cost).await {
        Ok(()) => next.run(req).await,
        Err(retry_after_secs) => {
            let mut resp = ApiError::rate_limited(format!(
                "public rate limit exceeded; retry in ~{retry_after_secs:.2}s"
            ))
            .into_response();
            let secs = retry_after_secs.ceil().max(1.0) as u64;
            if let Ok(hv) = HeaderValue::from_str(&secs.to_string()) {
                resp.headers_mut().insert("retry-after", hv);
            }
            resp
        }
    }
}

/// Per-account weighted rate-limit middleware. Allows the request when the
/// account's bucket covers the route cost; otherwise short-circuits with a
/// `429` carrying a `Retry-After` header. Requests with no `Authorized`
/// extension (should not happen inside the protected router) pass through
/// unthrottled.
pub async fn rate_limit_middleware(
    State(state): State<Arc<ApiState>>,
    req: Request,
    next: Next,
) -> Response {
    let account_id = req
        .extensions()
        .get::<Authorized>()
        .map(|a| a.account_id.clone());

    let Some(account_id) = account_id else {
        return next.run(req).await;
    };

    let cost = route_cost(req.method(), req.uri().path());
    match state.try_consume_rate(&account_id, cost).await {
        Ok(()) => next.run(req).await,
        Err(retry_after_secs) => {
            let mut resp = ApiError::rate_limited(format!(
                "rate limit exceeded; retry in ~{retry_after_secs:.2}s"
            ))
            .into_response();
            let secs = retry_after_secs.ceil().max(1.0) as u64;
            if let Ok(hv) = HeaderValue::from_str(&secs.to_string()) {
                resp.headers_mut().insert("retry-after", hv);
            }
            resp
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_route_costs_price_the_expensive_routes_highest() {
        // `/attestation` generates a TDX quote per request and cannot be
        // cached — the caller's nonce is the point — so it carries the most.
        assert_eq!(public_route_cost(&Method::GET, "/attestation"), 10.0);
        // Exempt on purpose — see the doc comment. Bounding login here would
        // let junk credentials lock every real account out.
        assert_eq!(public_route_cost(&Method::POST, "/auth/token"), 0.0);
        // Cached now, so this prices the render, not the RPC round trip.
        assert_eq!(public_route_cost(&Method::GET, "/transparency"), 2.0);
        // In-memory reads.
        assert_eq!(public_route_cost(&Method::GET, "/health"), 0.1);
        assert_eq!(public_route_cost(&Method::GET, "/time"), 0.1);
        assert_eq!(public_route_cost(&Method::GET, "/tree/root"), 0.1);
    }

    /// The bucket must bound the expensive route without throttling the honest
    /// polling the venue actually sees. Both halves matter: a limit that stops
    /// legitimate clients is an outage wearing a control's clothes.
    #[tokio::test]
    async fn the_public_bucket_bounds_attestation_but_not_honest_polling() {
        use crate::api::state::{ApiState, PUBLIC_RATE_CAPACITY};
        let st = ApiState::for_tests();

        // A flood of quote requests drains the burst and is then refused.
        let quote_cost = public_route_cost(&Method::GET, "/attestation");
        let burst = (PUBLIC_RATE_CAPACITY / quote_cost) as u32;
        for i in 0..burst {
            assert!(
                st.try_consume_public_rate(quote_cost).await.is_ok(),
                "attestation {i} within the burst must be served"
            );
        }
        assert!(
            st.try_consume_public_rate(quote_cost).await.is_err(),
            "a sustained attestation flood must be throttled"
        );

        // Meanwhile a cheap read is ~100x lighter, so ordinary polling still
        // has headroom left even right after that flood.
        let st2 = ApiState::for_tests();
        for _ in 0..200 {
            assert!(st2
                .try_consume_public_rate(public_route_cost(&Method::GET, "/time"))
                .await
                .is_ok());
        }
    }

    #[test]
    fn route_costs_match_the_weight_model() {
        assert_eq!(route_cost(&Method::POST, "/orders"), 1.0);
        assert_eq!(route_cost(&Method::DELETE, "/orders/abc"), 0.2);
        assert_eq!(route_cost(&Method::PUT, "/orders/abc"), 1.2);
        assert_eq!(route_cost(&Method::GET, "/orders/abc"), 0.1);
        assert_eq!(route_cost(&Method::GET, "/tree/leaves"), 0.1);
    }

    /// A place-weighted burst drains the bucket, then the next request is
    /// throttled — and a different account is unaffected (per-account).
    #[tokio::test]
    async fn bucket_exhausts_per_account_then_throttles() {
        use crate::api::state::{ApiState, RATE_CAPACITY};
        let st = ApiState::for_tests();

        // Spend the full burst at weight 1.0 (tight loop → negligible refill).
        for _ in 0..(RATE_CAPACITY as u32) {
            assert!(st.try_consume_rate("acct_a", 1.0).await.is_ok());
        }
        // Bucket empty → throttled with a positive retry-after.
        let retry = st.try_consume_rate("acct_a", 1.0).await.unwrap_err();
        assert!(retry > 0.0);

        // A different account has its own full bucket.
        assert!(st.try_consume_rate("acct_b", 1.0).await.is_ok());
    }
}
