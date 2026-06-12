//! WebSocket surface. Wire contract: `docs/tee-api-openapi.yaml`.
//!
//! `GET /ws/fills` streams [`crate::matcher::FillMemo`]s — one per continuation
//! fill — so a client learns which anchor each fill consumed, runs the
//! settle-memo integrity check, and stores the change note.
//!
//! PER-ACCOUNT ROUTING (the leak guard): the matcher publishes memos to a single
//! global broadcast; a router task (`api::fills_router`) fans each memo to its
//! owning account's channel using the `order_id → account` map recorded at
//! intake. This handler authenticates the caller and subscribes to ONLY that
//! account's channel, so a subscriber never sees another account's memos. (The
//! old global route leaked every memo to every subscriber and was fail-closed
//! behind `debug_endpoints`; that gate is now gone.)
//!
//! AUTH: the token is taken from `?token=` (browsers + the global `WebSocket`
//! can't set an `Authorization` header on the upgrade) or, as a fallback, the
//! `Authorization: Bearer` header — both validated via `auth::validate_token`.
//! This route therefore self-authenticates and is mounted OUTSIDE the
//! header-only bearer middleware.

use std::sync::Arc;

use axum::{
    extract::{
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use tokio::sync::broadcast::error::RecvError;

use super::auth::validate_token;
use super::state::ApiState;

#[derive(Debug, Deserialize)]
pub struct FillsQuery {
    /// Bearer JWT as a query param (the WS-friendly auth path).
    pub token: Option<String>,
}

/// `GET /ws/fills?token=<jwt>` — authenticate, then upgrade to a per-account
/// fill-memo stream.
pub async fn fills_ws(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Query(q): Query<FillsQuery>,
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

    ws.on_upgrade(move |socket| handle_fills(socket, state, account_id))
}

async fn handle_fills(mut socket: WebSocket, state: Arc<ApiState>, account_id: String) {
    // Subscribe to THIS account's channel only. Created lazily if first here.
    let mut rx = state.subscribe_account_fills(&account_id).await;

    loop {
        tokio::select! {
            memo = rx.recv() => match memo {
                Ok(memo) => {
                    let json = match serde_json::to_string(&memo) {
                        Ok(j) => j,
                        Err(e) => {
                            // Should be unreachable for a plain FillMemo, but
                            // don't swallow it silently if it ever fires.
                            tracing::error!(account = %account_id, error = %e, "ws/fills: FillMemo serialize failed; dropping");
                            continue;
                        }
                    };
                    if socket.send(Message::Text(json)).await.is_err() {
                        break; // client gone
                    }
                }
                // Slow client lagged past the buffer. Don't silently swallow:
                // close with a resync reason so the client reopens + backfills
                // the gap from the off-TEE indexer.
                Err(RecvError::Lagged(skipped)) => {
                    tracing::warn!(account = %account_id, skipped, "ws/fills lagged; closing for resync");
                    let _ = socket
                        .send(Message::Close(Some(CloseFrame {
                            code: 1011,
                            reason: format!("lagged: {skipped} memos skipped — reopen to resync")
                                .into(),
                        })))
                        .await;
                    break;
                }
                Err(RecvError::Closed) => break,
            },
            // Drain inbound frames so a half-open socket is detected promptly.
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Close(_))) | None => break,
                Some(Ok(_)) => {}
                Some(Err(_)) => break,
            },
        }
    }
}

/// `GET /ws/orders?token=<jwt>` — authenticate, then upgrade to a per-account
/// order-lifecycle stream (accepted/partial/filled/cancelled/expired). Same
/// per-account routing + self-auth as `/ws/fills`.
pub async fn orders_ws(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Query(q): Query<FillsQuery>,
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

    ws.on_upgrade(move |socket| handle_orders(socket, state, account_id))
}

async fn handle_orders(mut socket: WebSocket, state: Arc<ApiState>, account_id: String) {
    let mut rx = state.subscribe_account_order_updates(&account_id).await;

    loop {
        tokio::select! {
            update = rx.recv() => match update {
                Ok(update) => {
                    let json = match serde_json::to_string(&update) {
                        Ok(j) => j,
                        Err(e) => {
                            tracing::error!(account = %account_id, error = %e, "ws/orders: OrderUpdateMsg serialize failed; dropping");
                            continue;
                        }
                    };
                    if socket.send(Message::Text(json)).await.is_err() {
                        break; // client gone
                    }
                }
                Err(RecvError::Lagged(skipped)) => {
                    tracing::warn!(account = %account_id, skipped, "ws/orders lagged; closing for resync");
                    let _ = socket
                        .send(Message::Close(Some(CloseFrame {
                            code: 1011,
                            reason: format!("lagged: {skipped} updates skipped — reopen + poll GET /orders/:id")
                                .into(),
                        })))
                        .await;
                    break;
                }
                Err(RecvError::Closed) => break,
            },
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Close(_))) | None => break,
                Some(Ok(_)) => {}
                Some(Err(_)) => break,
            },
        }
    }
}
