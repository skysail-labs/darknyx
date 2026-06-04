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
//! subscriber sees every order's fill memos. The route is therefore
//! FAIL-CLOSED: it is only mounted under the `debug_endpoints` cargo
//! feature (see `api::mod::build_protected_router`), so it cannot ship on
//! hardened builds until per-account (per-bearer) filtering lands. Until
//! then production clients reconstruct change notes deterministically from
//! their seed + the Merkle mirror.

use std::sync::Arc;

use axum::{
    extract::{
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
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
                // A slow client lagged past the buffer + missed memos. Don't
                // silently swallow it: log + close with a resync reason so the
                // client reopens with a fresh cursor (it can backfill any
                // missed change notes deterministically from its seed + the
                // Merkle mirror).
                Err(RecvError::Lagged(skipped)) => {
                    tracing::warn!(skipped, "ws/fills subscriber lagged; closing for resync");
                    let _ = socket
                        .send(Message::Close(Some(CloseFrame {
                            code: 1011, // internal/server-side condition
                            reason: format!("lagged: {skipped} memos skipped — reopen to resync")
                                .into(),
                        })))
                        .await;
                    break;
                }
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
