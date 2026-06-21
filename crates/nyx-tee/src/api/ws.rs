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

/// Serialize a per-account stream message and inject a top-level monotonic
/// `seq` field. Injecting (rather than wrapping in `{seq, data}`) keeps the
/// message shape backward-compatible — parsers that ignore unknown fields read
/// the message as before, while seq-aware clients detect gaps. Shared by the
/// `/ws/fills`, `/ws/orders`, and `/ws/trading` send loops.
pub(crate) fn seq_json<T: serde::Serialize>(
    msg: &T,
    seq: u64,
) -> Result<String, serde_json::Error> {
    let mut v = serde_json::to_value(msg)?;
    if let Some(obj) = v.as_object_mut() {
        obj.insert("seq".to_string(), serde_json::Value::from(seq));
    }
    serde_json::to_string(&v)
}

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
        Err(e) => return e.into_response(),
    };

    ws.on_upgrade(move |socket| handle_fills(socket, state, account_id))
}

async fn handle_fills(mut socket: WebSocket, state: Arc<ApiState>, account_id: String) {
    // Subscribe to THIS account's channel only. Created lazily if first here.
    let mut rx = state.subscribe_account_fills(&account_id).await;
    // Per-connection monotonic sequence. A gap (or a 1011 lag-close) tells the
    // client exactly how many memos it missed; recovery is the indexer backfill.
    let mut seq: u64 = 0;

    loop {
        tokio::select! {
            memo = rx.recv() => match memo {
                Ok(memo) => {
                    seq += 1;
                    let json = match seq_json(&memo, seq) {
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
        Err(e) => return e.into_response(),
    };

    ws.on_upgrade(move |socket| handle_orders(socket, state, account_id))
}

async fn handle_orders(mut socket: WebSocket, state: Arc<ApiState>, account_id: String) {
    let mut rx = state.subscribe_account_order_updates(&account_id).await;
    // Per-connection monotonic sequence (gap detection; 1011 on lag).
    let mut seq: u64 = 0;

    loop {
        tokio::select! {
            update = rx.recv() => match update {
                Ok(update) => {
                    seq += 1;
                    let json = match seq_json(&update, seq) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::state::OrderUpdateMsg;

    #[test]
    fn seq_json_injects_seq_and_preserves_fields() {
        let msg = OrderUpdateMsg {
            order_id: "ab".repeat(16),
            kind: "fully_filled",
            filled_quantity: Some(7),
            new_amount: None,
            new_note_amount: None,
        };
        let s = seq_json(&msg, 42).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        // seq added at the top level...
        assert_eq!(v["seq"], 42);
        // ...alongside the original fields (not nested under `data`), so a
        // parser that ignores unknown fields still reads the message as before.
        assert_eq!(v["order_id"], "ab".repeat(16));
        assert_eq!(v["kind"], "fully_filled");
        assert_eq!(v["filled_quantity"], 7);
        // Optional fields stay omitted (skip_serializing_if), not nulled.
        assert!(v.get("new_amount").is_none());
    }
}
