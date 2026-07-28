//! `/v1/stream` connection bounds — audit finding AU-07 / DEP-AU-07.
//!
//! The socket upgrades before the client authenticates, so an anonymous peer
//! holds real process state from the moment it connects. Three bounds now apply,
//! and each is exercised here against a **real bound server and a real WebSocket
//! client** rather than by calling the handler directly:
//!
//!   1. an absolute window to complete `login`, which no traffic extends;
//!   2. a venue-wide cap on concurrent sockets; and
//!   3. a per-account cap once the socket is attributable.
//!
//! The reason for a live socket is specific. The defect being fixed is that a
//! transport `Ping` refreshed the idle timer, and a transport ping is a frame
//! the *client library* sends — it never appears in the application-level frame
//! enum the handler matches on. A test that drove `handle_frame` directly could
//! not have produced the bug and could not detect its return. Proving this one
//! needs the wire.
//!
//! Run with: `cargo test -p darknyx-tee --test stream_conn_limits`

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

/// Deadlines short enough to test in milliseconds, caps small enough to reach.
fn test_limits() -> ConnectionLimits {
    ConnectionLimits {
        max_total: 2,
        max_per_account: 1,
        login_deadline: Duration::from_millis(600),
    }
}

/// Bind the real router on an ephemeral port and return its `ws://` origin.
///
/// Port 0 so parallel test binaries cannot collide.
async fn serve(state: Arc<ApiState>) -> String {
    let app = build_router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("ws://{addr}/v1/stream")
}

async fn connect(
    url: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let (socket, _) = tokio_tungstenite::connect_async(url)
        .await
        .expect("/v1/stream upgrade");
    socket
}

/// Mint a real bearer token through `POST /auth/token`, exactly as a client
/// would. Using the real endpoint rather than hand-forging a JWT keeps this test
/// honest about what a client can actually obtain.
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

/// Read frames until the socket closes or `timeout` elapses. Returns `true` if
/// the SERVER closed it.
///
/// Generic over the stream half so the ping tests can `split()` the socket and
/// send concurrently with reading — sending and watching the same socket needs
/// two independent borrows.
async fn closed_by_server<S>(socket: &mut S, timeout: Duration) -> bool
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return false;
        }
        match tokio::time::timeout(remaining, socket.next()).await {
            // Close frame, or the stream ending, both mean the server hung up.
            Ok(Some(Ok(Message::Close(_))) | None) => return true,
            Ok(Some(Ok(_))) => continue,
            Ok(Some(Err(_))) => return true,
            Err(_) => return false, // timed out with the socket still open
        }
    }
}

// ─────── the unauthenticated window ─────────────────────────────────────────

/// THE AU-07 REGRESSION TEST. A client that never logs in but keeps pinging
/// must still be disconnected.
///
/// Before the fix this socket lived forever: every transport `Ping` refreshed
/// `last_activity`, so the 60 s idle timer never fired, and nothing else bounded
/// an unauthenticated connection. Sending pings faster than the deadline is
/// exactly the attack — if the deadline were still idle-based, this test would
/// hang until its own timeout and fail.
#[tokio::test]
async fn ping_only_client_cannot_hold_an_unauthenticated_socket() {
    let state = Arc::new(ApiState::for_tests().with_stream_limits(test_limits()));
    let url = serve(Arc::clone(&state)).await;
    let (mut tx, mut rx) = connect(&url).await.split();

    // Ping every 100 ms against a 600 ms window — six refreshes if pings still
    // counted as activity.
    let pinger = async {
        loop {
            if tx.send(Message::Ping(Vec::new())).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    let watcher = closed_by_server(&mut rx, Duration::from_secs(5));

    tokio::pin!(pinger);
    let closed = tokio::select! {
        _ = &mut pinger => false,
        c = watcher => c,
    };

    assert!(
        closed,
        "an unauthenticated ping-only client must be closed at the login deadline; \
         it held the socket instead"
    );
}

/// The same for application-level `op: ping`, which IS in the frame enum and so
/// reaches the idle-timer refresh directly.
#[tokio::test]
async fn app_level_ping_also_cannot_extend_the_unauthenticated_window() {
    let state = Arc::new(ApiState::for_tests().with_stream_limits(test_limits()));
    let url = serve(Arc::clone(&state)).await;
    let (mut tx, mut rx) = connect(&url).await.split();

    let sender = async {
        loop {
            let frame = json!({ "op": "ping" }).to_string();
            if tx.send(Message::Text(frame)).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    let watcher = closed_by_server(&mut rx, Duration::from_secs(5));

    tokio::pin!(sender);
    let closed = tokio::select! {
        _ = &mut sender => false,
        c = watcher => c,
    };

    assert!(
        closed,
        "`op: ping` must not extend the unauthenticated window either"
    );
}

/// The counter-test, and the one that stops the fix from being a regression.
///
/// A market maker resting no orders is a legitimate idle session and must NOT be
/// disconnected at the login deadline. A fix that simply stopped pings from
/// refreshing the timer, or applied the absolute deadline to every socket, would
/// pass the two tests above and break real clients. This is the assertion that
/// pins the deadline to the unauthenticated phase only.
#[tokio::test]
async fn an_authenticated_socket_survives_past_the_login_deadline() {
    let state = Arc::new(ApiState::for_tests().with_stream_limits(test_limits()));
    let token = mint_token(Arc::clone(&state)).await;
    let url = serve(Arc::clone(&state)).await;
    let mut socket = connect(&url).await;

    socket
        .send(Message::Text(
            json!({ "op": "login", "token": token }).to_string(),
        ))
        .await
        .expect("send login");

    // Drain the login reply.
    let reply = tokio::time::timeout(Duration::from_secs(2), socket.next())
        .await
        .expect("login reply in time")
        .expect("frame")
        .expect("ok frame");
    let text = reply.into_text().expect("text frame");
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["op"], "login", "expected a login ack, got: {text}");

    // Idle well past the unauthenticated deadline, sending nothing at all.
    let closed = closed_by_server(&mut socket, Duration::from_millis(1_500)).await;
    assert!(
        !closed,
        "an authenticated socket must not be closed by the login deadline"
    );
}

// ─────── the venue-wide cap ─────────────────────────────────────────────────

/// At capacity the next client is refused with a readable `503` BEFORE the
/// upgrade, rather than being upgraded and immediately closed.
#[tokio::test]
async fn venue_cap_refuses_the_next_connection() {
    let state = Arc::new(ApiState::for_tests().with_stream_limits(test_limits()));
    let url = serve(Arc::clone(&state)).await;

    // max_total = 2.
    let _a = connect(&url).await;
    let _b = connect(&url).await;
    // Let both upgrades register before probing capacity.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(state.stream_conns.live_total(), 2, "both sockets counted");

    let third = tokio_tungstenite::connect_async(&url).await;
    match third {
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
            assert_eq!(
                resp.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "over-cap upgrade must be refused with 503"
            );
        }
        Err(other) => panic!("expected an HTTP 503, got transport error: {other}"),
        Ok(_) => panic!("third connection was admitted over a cap of 2"),
    }
}

/// A closed socket must return its slot. A cap that only ever counts up is a
/// self-inflicted outage on a long-running process.
#[tokio::test]
async fn a_closed_socket_returns_its_slot_to_the_venue() {
    let state = Arc::new(ApiState::for_tests().with_stream_limits(test_limits()));
    let url = serve(Arc::clone(&state)).await;

    let a = connect(&url).await;
    let _b = connect(&url).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(state.stream_conns.live_total(), 2);

    drop(a);
    // Give the server task time to observe the close and drop its guard.
    for _ in 0..50 {
        if state.stream_conns.live_total() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        state.stream_conns.live_total(),
        1,
        "the closed socket's slot must be released"
    );

    // And the freed capacity is genuinely reusable.
    let _c = connect(&url).await;
}

// ─────── the per-account cap ────────────────────────────────────────────────

/// One credential cannot occupy more than its share of the venue. The second
/// login is refused at the application layer (the socket was already admitted),
/// so this asserts on the error frame rather than an HTTP status.
#[tokio::test]
async fn per_account_cap_refuses_a_second_concurrent_login() {
    let state = Arc::new(ApiState::for_tests().with_stream_limits(test_limits()));
    let token = mint_token(Arc::clone(&state)).await;
    let url = serve(Arc::clone(&state)).await;

    let mut first = connect(&url).await;
    first
        .send(Message::Text(
            json!({ "op": "login", "token": token }).to_string(),
        ))
        .await
        .expect("send login 1");
    let ack = tokio::time::timeout(Duration::from_secs(2), first.next())
        .await
        .expect("reply")
        .expect("frame")
        .expect("ok");
    let v: serde_json::Value = serde_json::from_str(&ack.into_text().unwrap()).unwrap();
    assert_eq!(v["op"], "login", "first login must succeed");

    // max_per_account = 1, so the second socket's login must be refused even
    // though the venue still has room for the socket itself.
    let mut second = connect(&url).await;
    second
        .send(Message::Text(
            json!({ "op": "login", "token": token }).to_string(),
        ))
        .await
        .expect("send login 2");
    let reply = tokio::time::timeout(Duration::from_secs(2), second.next())
        .await
        .expect("reply")
        .expect("frame")
        .expect("ok");
    let text = reply.into_text().unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        v["op"], "error",
        "second concurrent login must be refused, got: {text}"
    );
    assert_eq!(v["code"], 4290, "expected the connection-limit code");
}

/// A token refresh on an already-authenticated socket must not consume a second
/// account slot — otherwise a well-behaved client that renews its token locks
/// itself out of its own account.
#[tokio::test]
async fn re_login_on_the_same_socket_does_not_consume_another_slot() {
    let state = Arc::new(ApiState::for_tests().with_stream_limits(test_limits()));
    let token = mint_token(Arc::clone(&state)).await;
    let url = serve(Arc::clone(&state)).await;

    let mut socket = connect(&url).await;
    for attempt in 1..=3 {
        socket
            .send(Message::Text(
                json!({ "op": "login", "token": token }).to_string(),
            ))
            .await
            .expect("send login");
        let reply = tokio::time::timeout(Duration::from_secs(2), socket.next())
            .await
            .expect("reply")
            .expect("frame")
            .expect("ok");
        let text = reply.into_text().unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            v["op"], "login",
            "re-login #{attempt} must succeed, got: {text}"
        );
    }
}
