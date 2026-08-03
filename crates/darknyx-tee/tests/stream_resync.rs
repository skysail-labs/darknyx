//! `/v1/stream` server-side resync — SW-31.
//!
//! When the SERVER's fan-out lags, messages are lost before any per-account
//! channel sees them. The affected sockets are not slow, so `push_or_close`
//! never fires on them: they would sit there holding a silently incomplete view
//! of their own orders and fills. The router cannot say which accounts lost
//! what, so the only sound response is to close every live session and let each
//! one re-derive from the chain.
//!
//! That is the whole failure mode, and it is invisible from the client side —
//! which is exactly why it needs a test at the wire. The handler compares a
//! per-connection baseline of `resync_epoch`, captured at accept, against the
//! shared counter on each lifecycle tick. Two things have to be true, and a
//! plausible implementation can get either one wrong:
//!
//!   1. a session live at the time of the bump IS closed, with code 1011; and
//!   2. a session opened AFTERWARDS is NOT — an implementation that compared
//!      against a constant, or latched a flag, would close every future socket
//!      for the life of the process. That is an outage, not a resync, and it
//!      would look like a passing test if only (1) were asserted.
//!
//! Run with: `cargo test -p darknyx-tee --test stream_resync`

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use darknyx_tee::api::conn_limit::ConnectionLimits;
use darknyx_tee::api::{build_router, ApiState};
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;
use tower::ServiceExt;

/// The handler polls `resync_epoch` on a 1 s lifecycle tick, so every wait here
/// has to clear that. Generous enough not to flake on a loaded CI box.
const CLOSE_WAIT: Duration = Duration::from_secs(6);

/// A login window long enough that it can never be what closes these sockets —
/// otherwise a passing test would prove nothing about the resync path.
fn test_limits() -> ConnectionLimits {
    ConnectionLimits {
        max_total: 8,
        max_per_account: 8,
        login_deadline: Duration::from_secs(30),
    }
}

async fn serve(state: Arc<ApiState>) -> String {
    let app = build_router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("ws://{addr}/v1/stream")
}

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn connect(url: &str) -> Socket {
    let (socket, _) = tokio_tungstenite::connect_async(url)
        .await
        .expect("/v1/stream upgrade");
    socket
}

async fn mint_token(state: Arc<ApiState>) -> String {
    use darknyx_tee::api::auth::{TEST_API_KEY, TEST_API_SECRET, TEST_PASSPHRASE};
    let app = build_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/token")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "api_key":    TEST_API_KEY,
                        "api_secret": TEST_API_SECRET,
                        "passphrase": TEST_PASSPHRASE,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("token request");
    assert_eq!(resp.status(), StatusCode::OK, "token mint must succeed");
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v["access_token"]
        .as_str()
        .expect("access_token")
        .to_string()
}

/// Open a socket and complete `login`, so the connection under test is a real
/// authenticated session rather than an anonymous one.
async fn logged_in(url: &str, token: &str) -> Socket {
    let mut socket = connect(url).await;
    socket
        .send(Message::Text(
            json!({ "op": "login", "token": token }).to_string(),
        ))
        .await
        .expect("send login");
    let ack = tokio::time::timeout(Duration::from_secs(2), socket.next())
        .await
        .expect("login reply")
        .expect("frame")
        .expect("ok");
    let v: serde_json::Value = serde_json::from_str(&ack.into_text().unwrap()).unwrap();
    assert_ne!(
        v["op"], "error",
        "login must succeed before the resync assertion means anything: {v}"
    );
    socket
}

/// The close code the SERVER sent, or `None` if it never closed within
/// `timeout`. Returning the code rather than a bool is the point: closing for
/// the wrong reason (a normal 1000, an idle timeout) must not pass.
async fn server_close_code(socket: &mut Socket, timeout: Duration) -> Option<u16> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match tokio::time::timeout(remaining, socket.next()).await {
            Ok(Some(Ok(Message::Close(frame)))) => {
                return Some(frame.map(|f| u16::from(f.code)).unwrap_or(0))
            }
            // The stream ending without a close frame is still a hang-up, but
            // it is not the graceful 1011 the contract promises.
            Ok(None) | Ok(Some(Err(_))) => return Some(0),
            Ok(Some(Ok(_))) => continue,
            Err(_) => return None,
        }
    }
}

/// THE SW-31 REGRESSION TEST: a live session is closed with 1011 when the
/// server's fan-out lags.
///
/// Before the fix nothing consumed `resync_epoch` in the stream handler, so
/// this socket stayed open indefinitely with a gap in its view. Without the
/// close, this test times out and fails.
#[tokio::test]
async fn a_live_session_is_closed_1011_when_the_server_fanout_lags() {
    let state = Arc::new(ApiState::for_tests().with_stream_limits(test_limits()));
    let token = mint_token(Arc::clone(&state)).await;
    let url = serve(Arc::clone(&state)).await;

    let mut socket = logged_in(&url, &token).await;

    // The socket must be healthy first — otherwise the assertion below could be
    // satisfied by a close that had nothing to do with the epoch.
    assert_eq!(
        server_close_code(&mut socket, Duration::from_millis(1500)).await,
        None,
        "the session must be stable before the fan-out lag is signalled"
    );

    // What `fills_router` / `order_router` do when a broadcast send lags.
    state.resync_epoch.fetch_add(1, Ordering::Release);

    assert_eq!(
        server_close_code(&mut socket, CLOSE_WAIT).await,
        Some(1011),
        "a session live across a fan-out lag must be closed with 1011 so the \
         client re-derives; it was left holding an incomplete view"
    );
}

/// The other half: the epoch is a per-connection BASELINE, not a latch.
///
/// A session opened after the bump has missed nothing, so closing it would turn
/// one lag event into a permanent reconnect loop for every client.
#[tokio::test]
async fn a_session_opened_after_the_lag_is_not_closed() {
    let state = Arc::new(ApiState::for_tests().with_stream_limits(test_limits()));
    let token = mint_token(Arc::clone(&state)).await;
    let url = serve(Arc::clone(&state)).await;

    // Lag happens BEFORE this client ever connects.
    state.resync_epoch.fetch_add(1, Ordering::Release);

    let mut socket = logged_in(&url, &token).await;

    assert_eq!(
        server_close_code(&mut socket, Duration::from_secs(3)).await,
        None,
        "a session that opened after the lag missed nothing and must be left \
         alone; closing it makes one lag event a permanent reconnect loop"
    );
}
