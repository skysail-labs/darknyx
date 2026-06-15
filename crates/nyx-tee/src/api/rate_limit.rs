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
fn route_cost(method: &Method, path: &str) -> f64 {
    let is_order_subpath = path.starts_with("/orders/");
    match *method {
        // order.place
        Method::POST if path == "/orders" => 1.0,
        // anchor top-up
        Method::POST if is_order_subpath && path.ends_with("/anchors") => 0.5,
        // order.cancel
        Method::DELETE if is_order_subpath => 0.2,
        // order.modify (atomic cancel + replace)
        Method::PUT if is_order_subpath => 1.2,
        // everything else on the protected router (reads, revoke, admin) is cheap
        _ => 0.1,
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
    fn route_costs_match_the_weight_model() {
        assert_eq!(route_cost(&Method::POST, "/orders"), 1.0);
        assert_eq!(route_cost(&Method::DELETE, "/orders/abc"), 0.2);
        assert_eq!(route_cost(&Method::PUT, "/orders/abc"), 1.2);
        assert_eq!(route_cost(&Method::POST, "/orders/abc/anchors"), 0.5);
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
