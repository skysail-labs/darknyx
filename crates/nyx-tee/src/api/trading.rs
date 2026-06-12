//! `GET /ws/trading` — the bidirectional order-submission socket (Phase B).
//!
//! A single authenticated WebSocket over which a client streams framed
//! `order.place` / `order.cancel` / `order.modify` requests and receives a
//! reply per frame. The intake logic is exactly the REST path's — each frame
//! dispatches to the same `orders::{place,cancel,modify}_core` the
//! `POST/DELETE/PUT /orders` handlers call — so there is no second
//! verification path to keep in sync. The win over REST is one warm,
//! pre-authenticated connection (no per-request TLS + bearer round-trip) and
//! **cancel-on-disconnect**.
//!
//! AUTH: same self-auth as `/ws/fills` + `/ws/orders` — the bearer rides as
//! `?token=` (or an `Authorization: Bearer` header), validated once at upgrade.
//! The order-level trading-key signature is still required on every
//! place/cancel/modify frame (the JWT identifies the *account*; the
//! trading_key is the cryptographic *owner*), so the socket being authed does
//! NOT let it move another key's orders.
//!
//! CANCEL-ON-DISCONNECT (`?cancel_on_disconnect=true`): the handler tracks the
//! orders placed on THIS socket and, when it closes, cancels the ones still
//! resting. That teardown is server-initiated (no client signature — see
//! `orders::cancel_resting_unchecked`): the order was placed on this
//! authenticated session, so the session's authority covers cancelling it, and
//! a cancel only removes a resting order (it never settles). A market maker
//! that loses connectivity therefore doesn't leave stale quotes crossing.

use std::collections::HashSet;
use std::sync::Arc;

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use super::auth::validate_token;
use super::orders::{
    cancel_core, cancel_resting_unchecked, modify_core, place_core, CancelOrderRequest,
    CancelOrderResponse, ModifyOrderRequest, ModifyOrderResponse, PlaceOrderRequest,
    PlaceOrderResponse,
};
use super::state::ApiState;

#[derive(Debug, Deserialize)]
pub struct TradingQuery {
    /// Bearer JWT as a query param (the WS-friendly auth path).
    pub token: Option<String>,
    /// Opt into cancel-on-disconnect for this session. Default `false`.
    #[serde(default)]
    pub cancel_on_disconnect: bool,
}

/// A client → server frame. Internally tagged by `op`; each variant's body
/// carries the same request shape its REST sibling takes.
#[derive(Debug, Deserialize)]
#[serde(tag = "op")]
pub enum TradingRequest {
    /// Place an order (mirror of `POST /orders`).
    #[serde(rename = "order.place")]
    Place {
        #[serde(default)]
        request_id: Option<String>,
        params: Box<PlaceOrderRequest>,
    },
    /// Cancel a resting order (mirror of `DELETE /orders/{id}`).
    #[serde(rename = "order.cancel")]
    Cancel {
        #[serde(default)]
        request_id: Option<String>,
        order_id: String,
        params: CancelOrderRequest,
    },
    /// Atomic cancel + replace (mirror of `PUT /orders/{id}`).
    #[serde(rename = "order.modify")]
    Modify {
        #[serde(default)]
        request_id: Option<String>,
        order_id: String,
        params: Box<ModifyOrderRequest>,
    },
    /// Application-level heartbeat.
    #[serde(rename = "ping")]
    Ping {
        #[serde(default)]
        request_id: Option<String>,
    },
}

/// A server → client frame. `request_id` echoes the request's (when it had one)
/// so a client can correlate replies on a multiplexed socket.
#[derive(Debug, Serialize)]
#[serde(tag = "op")]
pub enum TradingResponse {
    #[serde(rename = "order.place")]
    Place {
        request_id: Option<String>,
        result: PlaceOrderResponse,
    },
    #[serde(rename = "order.cancel")]
    Cancel {
        request_id: Option<String>,
        result: CancelOrderResponse,
    },
    #[serde(rename = "order.modify")]
    Modify {
        request_id: Option<String>,
        result: ModifyOrderResponse,
    },
    #[serde(rename = "pong")]
    Pong { request_id: Option<String> },
    /// A frame failed: `code` is the HTTP-equivalent status the REST path would
    /// have returned (400/403/404/409/503), `message` the same reason string.
    #[serde(rename = "error")]
    Error {
        request_id: Option<String>,
        code: u16,
        message: String,
    },
}

/// `GET /ws/trading?token=<jwt>[&cancel_on_disconnect=true]` — authenticate,
/// then upgrade to the order-submission socket.
pub async fn trading_ws(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Query(q): Query<TradingQuery>,
    ws: WebSocketUpgrade,
) -> Response {
    let token = q.token.or_else(|| {
        headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .map(str::to_string)
    });
    let Some(token) = token else {
        return (
            StatusCode::UNAUTHORIZED,
            "missing token (?token= or Bearer)",
        )
            .into_response();
    };

    let account_id = match validate_token(&state, &token).await {
        Ok(auth) => auth.account_id,
        Err((code, msg)) => return (code, msg).into_response(),
    };

    let cod = q.cancel_on_disconnect;
    ws.on_upgrade(move |socket| handle_trading(socket, state, account_id, cod))
}

async fn handle_trading(
    mut socket: WebSocket,
    state: Arc<ApiState>,
    account_id: String,
    cancel_on_disconnect: bool,
) {
    // A `/ws/trading` socket on a degraded (matcher-less) boot can't do
    // anything — tell the client and close rather than 503 every frame.
    let Some(matcher) = state.matcher.clone() else {
        let _ = socket
            .send(Message::Text(
                serde_json::to_string(&TradingResponse::Error {
                    request_id: None,
                    code: StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                    message: "matcher state not initialised on this instance".to_string(),
                })
                .unwrap_or_default(),
            ))
            .await;
        return;
    };

    // Order ids placed on THIS socket and not yet known-terminal. Drives
    // cancel-on-disconnect; hex-keyed so the cancel path can decode them.
    let mut session_orders: HashSet<String> = HashSet::new();

    while let Some(incoming) = socket.recv().await {
        match incoming {
            Ok(Message::Text(txt)) => {
                let resp =
                    process_frame(&state, &matcher, &account_id, &mut session_orders, &txt).await;
                let json = serde_json::to_string(&resp).unwrap_or_else(|e| {
                    format!(r#"{{"op":"error","code":500,"message":"serialize: {e}"}}"#)
                });
                if socket.send(Message::Text(json)).await.is_err() {
                    break; // client gone
                }
            }
            // Reply to a transport-level ping so a half-open socket is detected.
            Ok(Message::Ping(p)) => {
                if socket.send(Message::Pong(p)).await.is_err() {
                    break;
                }
            }
            Ok(Message::Close(_)) | Err(_) => break,
            Ok(_) => {}
        }
    }

    // Socket closed. Tear down the session's still-resting orders if asked.
    if cancel_on_disconnect && !session_orders.is_empty() {
        let n = session_orders.len();
        let mut cancelled = 0usize;
        for oid in &session_orders {
            if cancel_resting_unchecked(&state, &matcher, oid).await {
                cancelled += 1;
            }
        }
        tracing::info!(
            account = %account_id,
            tracked = n,
            cancelled,
            "ws/trading closed: cancel-on-disconnect swept the session's resting orders"
        );
    }
}

/// Parse one text frame, dispatch it to the shared intake core, and keep the
/// session's order set in step (place adds, cancel removes, modify swaps).
async fn process_frame(
    state: &ApiState,
    matcher: &Arc<tokio::sync::RwLock<crate::matcher::MatcherState>>,
    account_id: &str,
    session_orders: &mut HashSet<String>,
    txt: &str,
) -> TradingResponse {
    let req: TradingRequest = match serde_json::from_str(txt) {
        Ok(r) => r,
        Err(e) => {
            return TradingResponse::Error {
                request_id: None,
                code: StatusCode::BAD_REQUEST.as_u16(),
                message: format!("malformed frame: {e}"),
            }
        }
    };

    match req {
        TradingRequest::Ping { request_id } => TradingResponse::Pong { request_id },

        TradingRequest::Place { request_id, params } => {
            match place_core(state, matcher, &params, account_id).await {
                Ok(result) => {
                    session_orders.insert(result.order_id.clone());
                    TradingResponse::Place { request_id, result }
                }
                Err((code, message)) => TradingResponse::Error {
                    request_id,
                    code: code.as_u16(),
                    message,
                },
            }
        }

        TradingRequest::Cancel {
            request_id,
            order_id,
            params,
        } => match cancel_core(state, matcher, &order_id, &params).await {
            Ok(result) => {
                session_orders.remove(&order_id);
                TradingResponse::Cancel { request_id, result }
            }
            Err((code, message)) => TradingResponse::Error {
                request_id,
                code: code.as_u16(),
                message,
            },
        },

        TradingRequest::Modify {
            request_id,
            order_id,
            params,
        } => match modify_core(state, matcher, &order_id, &params, account_id).await {
            Ok(result) => {
                // Old id left the book; the (possibly same) new id now rests.
                session_orders.remove(&order_id);
                session_orders.insert(result.order_id.clone());
                TradingResponse::Modify { request_id, result }
            }
            Err((code, message)) => TradingResponse::Error {
                request_id,
                code: code.as_u16(),
                message,
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A ping frame round-trips to a pong with the echoed request_id.
    #[test]
    fn ping_frame_deserializes() {
        let f: TradingRequest =
            serde_json::from_value(json!({ "op": "ping", "request_id": "r1" })).unwrap();
        match f {
            TradingRequest::Ping { request_id } => assert_eq!(request_id.as_deref(), Some("r1")),
            _ => panic!("expected ping"),
        }
    }

    /// `order.cancel` carries the order id + a cancel body (trading-key sig).
    #[test]
    fn cancel_frame_deserializes_with_params() {
        let f: TradingRequest = serde_json::from_value(json!({
            "op": "order.cancel",
            "request_id": "c1",
            "order_id": "aa".repeat(16),
            "params": {
                "trading_key": "00".repeat(32),
                "cancel_nonce": 7,
                "trading_key_signature": "00".repeat(64),
            }
        }))
        .unwrap();
        match f {
            TradingRequest::Cancel {
                order_id, params, ..
            } => {
                assert_eq!(order_id, "aa".repeat(16));
                assert_eq!(params.cancel_nonce, 7);
            }
            _ => panic!("expected cancel"),
        }
    }

    /// An unknown `op` is a deserialize error (surfaces as a 400 error frame).
    #[test]
    fn unknown_op_is_rejected() {
        let r: Result<TradingRequest, _> =
            serde_json::from_value(json!({ "op": "order.teleport" }));
        assert!(r.is_err());
    }

    /// Responses serialize with their `op` tag + echoed request_id.
    #[test]
    fn responses_carry_op_tag() {
        let pong = TradingResponse::Pong {
            request_id: Some("r1".into()),
        };
        let v = serde_json::to_value(&pong).unwrap();
        assert_eq!(v["op"], "pong");
        assert_eq!(v["request_id"], "r1");

        let err = TradingResponse::Error {
            request_id: None,
            code: 404,
            message: "nope".into(),
        };
        let v = serde_json::to_value(&err).unwrap();
        assert_eq!(v["op"], "error");
        assert_eq!(v["code"], 404);
    }
}
