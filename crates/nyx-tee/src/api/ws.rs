//! WebSocket surface. Wire contract: `docs/tee-api-openapi.yaml`.
//!
//! `GET /ws/fills` (Phase 7) streams [`crate::matcher::FillMemo`]s — one
//! per continuation fill — so a client learns which anchor each fill
//! consumed, runs the settle-memo integrity check, and stores the change
//! note. The matcher publishes memos to a broadcast channel
//! (`MatcherState::subscribe_fills`); this handler forwards them as JSON
//! text frames.
//!
//! NOTE (pre-production): the stream is currently UNFILTERED — every
//! subscriber sees every order's fill memos. A production deployment MUST
//! filter to the bearer's own orders (the route is bearer-protected, so
//! the identity is available via the `Authorized` extension; the
//! per-account order-id index is the missing piece). Acceptable for the
//! devnet/test phase where memos carry only the user's own fill info over
//! TLS. Tracked for the per-user-channel follow-up.

use std::sync::Arc;

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::Response,
};
use tokio::sync::broadcast::error::RecvError;

use super::state::ApiState;

/// `GET /ws/fills` — upgrade to a WebSocket that streams fill memos.
pub async fn fills_ws(ws: WebSocketUpgrade, State(state): State<Arc<ApiState>>) -> Response {
    ws.on_upgrade(move |socket| handle_fills(socket, state))
}

async fn handle_fills(mut socket: WebSocket, state: Arc<ApiState>) {
    // Subscribe to the matcher's fill-memo broadcast. With no matcher
    // wired (degraded boot / tests without one), close immediately.
    let mut rx = match &state.matcher {
        Some(m) => m.read().await.subscribe_fills(),
        None => {
            let _ = socket.send(Message::Close(None)).await;
            return;
        }
    };

    loop {
        tokio::select! {
            memo = rx.recv() => match memo {
                Ok(memo) => {
                    let Ok(json) = serde_json::to_string(&memo) else { continue };
                    if socket.send(Message::Text(json)).await.is_err() {
                        break; // client gone
                    }
                }
                // A slow client lagged past the buffer — skip the gap and
                // keep streaming the newest memos rather than disconnecting.
                Err(RecvError::Lagged(_)) => continue,
                Err(RecvError::Closed) => break,
            },
            // Drain inbound frames (ping/pong handled by axum; we only act
            // on Close / errors) so a half-open socket is detected promptly.
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Close(_))) | None => break,
                Some(Ok(_)) => {}
                Some(Err(_)) => break,
            },
        }
    }
}
