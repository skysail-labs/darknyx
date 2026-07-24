//! `GET /v1/stream` — the multiplexed session socket. Wire contract:
//! `docs/tee-api-openapi.yaml` (`/v1/stream`).
//!
//! The sole authenticated WebSocket surface. A client logs in IN-BAND
//! (`op: login` carrying a bearer token), subscribes to channels, places/cancels/
//! modifies orders, and receives both per-request replies and channel pushes on
//! the one connection.
//!
//! CHANNELS (server → client pushes, each tagged with a top-level `channel`):
//!   - `orders` — this account's order-lifecycle updates (per-account routed).
//!   - `fills`  — this account's fill memos (per-account routed).
//!   - `tree`   — GLOBAL leaf-append events (public; not per-account).
//!   - `account` / `settlement` — NOT served here (account mirrors the 501 GET
//!     /account; settlement has no event plumbing yet) — a `subscribe` to either
//!     returns an error frame, the rest of the request still applies.
//!
//! OPS (client → server): `login`, `logout`, `ping`, `subscribe`,
//! `unsubscribe`, `order.place`, `order.cancel`, `order.modify`. The order ops
//! dispatch to the SAME `orders::{place,cancel,modify}_core` the REST + the
//! REST paths call, so there is no second intake/verification path to keep in
//! sync. `account.info` replies not-implemented; clients use the `tree` channel
//! plus their keys, or `GET /tree/inclusion`.
//!
//! AUTH: in-band. The socket upgrades unauthenticated; every op except `ping`
//! is rejected until a successful `op: login`. A later `login` on the same
//! socket refreshes the token (auto-renewal) but may not switch account. The
//! order-level trading-key signature is STILL required on every place/cancel/
//! modify frame, exactly as on the REST order endpoints.
//!
//! TOKEN LIFECYCLE: the server emits `auth_expired` 60 seconds before the JWT
//! expires. A fresh `login` for the same account refreshes the session without
//! dropping subscriptions; an actually expired token closes the socket.
//!
//! CANCEL-ON-DISCONNECT: `login { cancel_on_disconnect: true }` (or the
//! account's stored default) makes the handler sweep this session's still-
//! resting orders when the socket closes.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::Response,
};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast::{error::RecvError, Receiver};
use tokio::time::{interval, Duration, Instant, MissedTickBehavior};

use super::auth::validate_token;
use super::orders::{
    cancel_core, cancel_resting_unchecked, modify_core, place_core, CancelOrderRequest,
    CancelOrderResponse, ModifyOrderRequest, ModifyOrderResponse, PlaceOrderRequest,
    PlaceOrderResponse,
};
use super::state::{ApiState, OrderUpdateMsg};
use crate::matcher::{FillMemo, MatcherState};
use crate::merkle::TreeAppendEvent;

type Matcher = Arc<tokio::sync::RwLock<MatcherState>>;

/// A client → server frame, internally tagged by `op`.
#[derive(Debug, Deserialize)]
#[serde(tag = "op")]
pub enum StreamRequest {
    #[serde(rename = "login")]
    Login {
        #[serde(default)]
        request_id: Option<String>,
        token: String,
        #[serde(default)]
        cancel_on_disconnect: Option<bool>,
    },
    #[serde(rename = "logout")]
    Logout {
        #[serde(default)]
        request_id: Option<String>,
    },
    #[serde(rename = "ping")]
    Ping {
        #[serde(default)]
        request_id: Option<String>,
    },
    #[serde(rename = "subscribe")]
    Subscribe {
        #[serde(default)]
        request_id: Option<String>,
        channels: Vec<String>,
    },
    #[serde(rename = "unsubscribe")]
    Unsubscribe {
        #[serde(default)]
        request_id: Option<String>,
        channels: Vec<String>,
    },
    #[serde(rename = "order.place")]
    Place {
        #[serde(default)]
        request_id: Option<String>,
        params: Box<PlaceOrderRequest>,
    },
    #[serde(rename = "order.cancel")]
    Cancel {
        #[serde(default)]
        request_id: Option<String>,
        order_id: String,
        params: CancelOrderRequest,
    },
    #[serde(rename = "order.modify")]
    Modify {
        #[serde(default)]
        request_id: Option<String>,
        order_id: String,
        params: Box<ModifyOrderRequest>,
    },
    /// DEFERRED — mirrors GET /account (501); replies not-implemented.
    #[serde(rename = "account.info")]
    AccountInfo {
        #[serde(default)]
        request_id: Option<String>,
    },
}

/// A server → client reply (per-request; channel pushes are serialized
/// separately with a `channel` tag). `request_id` echoes the request's so a
/// client can correlate replies on the multiplexed socket.
#[derive(Debug, Serialize)]
#[serde(tag = "op")]
pub enum StreamResponse {
    #[serde(rename = "login")]
    Login {
        request_id: Option<String>,
        account_id: String,
    },
    #[serde(rename = "pong")]
    Pong { request_id: Option<String> },
    #[serde(rename = "auth_expired")]
    AuthExpired { expires_at: u64 },
    #[serde(rename = "subscribed")]
    Subscribed {
        request_id: Option<String>,
        channels: Vec<String>,
    },
    #[serde(rename = "unsubscribed")]
    Unsubscribed {
        request_id: Option<String>,
        channels: Vec<String>,
    },
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
    /// A frame failed: `code` is the stable numeric error code from the REST
    /// error catalogue (`api::error`), `message` the same reason string REST
    /// would have returned.
    #[serde(rename = "error")]
    Error {
        request_id: Option<String>,
        code: u32,
        message: String,
    },
}

impl StreamResponse {
    fn error(request_id: Option<String>, code: u32, message: impl Into<String>) -> Self {
        StreamResponse::Error {
            request_id,
            code,
            message: message.into(),
        }
    }
}

/// Charge an order operation against the session account's rate bucket
/// (AU-01). Returns `Some(error frame)` when the bucket is empty.
///
/// `cost` MUST mirror `super::rate_limit::route_cost` for the equivalent HTTP
/// route (place 1.0, cancel 0.2, modify 1.2) so a client cannot get a cheaper
/// allowance simply by switching transport.
///
/// Unauthenticated frames are let through here and rejected by the `*_core`
/// login check immediately after — there is no account to charge, and
/// pre-login frames are already bounded by the socket's own limits.
async fn order_rate_guard(
    state: &ApiState,
    s: &Session,
    request_id: Option<String>,
    cost: f64,
) -> Option<StreamResponse> {
    let account = s.authed.as_ref()?;
    match state.try_consume_rate(account, cost).await {
        Ok(()) => None,
        Err(retry_after_secs) => Some(StreamResponse::error(
            request_id,
            1401,
            format!("rate limit exceeded; retry after {retry_after_secs:.1}s"),
        )),
    }
}

/// What `handle_frame` decided: reply with these frames, and/or close.
enum Action {
    Reply(Vec<StreamResponse>),
    Close,
}

/// Per-connection session state.
#[derive(Default)]
struct Session {
    /// `Some(account_id)` once `op: login` succeeded.
    authed: Option<String>,
    token_exp: Option<u64>,
    auth_expired_warned: bool,
    cancel_on_disconnect: bool,
    /// Order ids placed on THIS socket and not yet known-terminal (drives
    /// cancel-on-disconnect).
    session_orders: HashSet<String>,
    sub_orders: Option<Receiver<OrderUpdateMsg>>,
    sub_fills: Option<Receiver<FillMemo>>,
    sub_tree: Option<Receiver<TreeAppendEvent>>,
}

/// `GET /v1/stream` — upgrade unconditionally; auth happens in-band via
/// `op: login`. Mounted on the PUBLIC router (no header bearer middleware),
/// like the other WS routes.
pub async fn stream_ws(State(state): State<Arc<ApiState>>, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |socket| handle_stream(socket, state))
}

/// Serialize a reply and inject the connection-global monotonic sequence.
fn seq_json<T: Serialize>(msg: &T, seq: u64) -> Result<String, serde_json::Error> {
    let mut v = serde_json::to_value(msg)?;
    if let Some(obj) = v.as_object_mut() {
        obj.insert("seq".to_string(), serde_json::Value::from(seq));
    }
    serde_json::to_string(&v)
}

/// Serialize a channel push, injecting a top-level `channel` + `seq`. Keeps the
/// message shape flat (parsers that ignore unknown fields read it as before)
/// while a multiplexing client demuxes on `channel` and detects gaps on `seq`.
fn channel_json<T: Serialize>(
    msg: &T,
    channel: &str,
    seq: u64,
) -> Result<String, serde_json::Error> {
    let mut v = serde_json::to_value(msg)?;
    if let Some(obj) = v.as_object_mut() {
        obj.insert("channel".to_string(), serde_json::Value::from(channel));
        obj.insert("seq".to_string(), serde_json::Value::from(seq));
    }
    serde_json::to_string(&v)
}

/// Future that resolves only when `rx` is `Some` — lets `tokio::select!` skip an
/// unsubscribed channel (a `None` arm parks forever via `pending`).
async fn opt_recv<T: Clone>(rx: &mut Option<Receiver<T>>) -> Result<T, RecvError> {
    match rx {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

async fn handle_stream(mut socket: WebSocket, state: Arc<ApiState>) {
    let matcher = state.matcher.clone();
    let mut s = Session::default();
    let mut seq: u64 = 0;
    let mut last_activity = Instant::now();
    let mut lifecycle_tick = interval(Duration::from_secs(1));
    lifecycle_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            inbound = socket.recv() => match inbound {
                Some(Ok(Message::Text(txt))) => {
                    last_activity = Instant::now();
                    let action = handle_frame(&state, &matcher, &mut s, &txt).await;
                    let (frames, close) = match action {
                        Action::Reply(f) => (f, false),
                        Action::Close => (Vec::new(), true),
                    };
                    for f in &frames {
                        seq += 1;
                        let json = seq_json(f, seq).unwrap_or_else(|e| {
                            format!(r#"{{"op":"error","code":5000,"message":"serialize: {e}","seq":{seq}}}"#)
                        });
                        if socket.send(Message::Text(json)).await.is_err() {
                            return; // client gone
                        }
                    }
                    if close {
                        let _ = socket.send(Message::Close(None)).await;
                        break;
                    }
                }
                // Reply to a transport ping so a half-open socket is detected.
                Some(Ok(Message::Ping(p))) => {
                    last_activity = Instant::now();
                    if socket.send(Message::Pong(p)).await.is_err() { break; }
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                Some(Ok(_)) => {}
            },

            r = opt_recv(&mut s.sub_orders) => {
                if push_or_close(&mut socket, "orders", r, &mut seq).await { break; }
            }
            r = opt_recv(&mut s.sub_fills) => {
                if push_or_close(&mut socket, "fills", r, &mut seq).await { break; }
            }
            r = opt_recv(&mut s.sub_tree) => {
                if push_or_close(&mut socket, "tree", r, &mut seq).await { break; }
            }

            _ = lifecycle_tick.tick() => {
                if last_activity.elapsed() > Duration::from_secs(60) {
                    let _ = socket.send(Message::Close(Some(CloseFrame {
                        code: 1008,
                        reason: "heartbeat timeout".into(),
                    }))).await;
                    break;
                }
                if let Some(exp) = s.token_exp {
                    let now = now_unix_seconds();
                    if now >= exp {
                        let _ = socket.send(Message::Close(Some(CloseFrame {
                            code: 1008,
                            reason: "bearer token expired; reconnect and login".into(),
                        }))).await;
                        break;
                    }
                    if exp.saturating_sub(now) <= 60 && !s.auth_expired_warned {
                        s.auth_expired_warned = true;
                        seq += 1;
                        let frame = StreamResponse::AuthExpired { expires_at: exp };
                        let json = seq_json(&frame, seq).unwrap_or_else(|e| {
                            format!(r#"{{"op":"error","code":5000,"message":"serialize: {e}","seq":{seq}}}"#)
                        });
                        if socket.send(Message::Text(json)).await.is_err() { break; }
                    }
                }
            }
        }
    }

    // Socket closed. Tear down the session's still-resting orders if asked.
    if let (true, Some(account)) = (s.cancel_on_disconnect, s.authed.as_ref()) {
        if let Some(matcher) = matcher.as_ref() {
            if !s.session_orders.is_empty() {
                let mut cancelled = 0usize;
                for oid in &s.session_orders {
                    if cancel_resting_unchecked(&state, matcher, oid).await {
                        cancelled += 1;
                    }
                }
                tracing::info!(
                    account = %account, tracked = s.session_orders.len(), cancelled,
                    "/v1/stream closed: cancel-on-disconnect swept the session's resting orders"
                );
            }
        }
    }
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Send one channel push (or close the socket on lag). Returns `true` if the
/// loop should break (client gone, or a lag-close was sent).
async fn push_or_close<T: Serialize + Clone>(
    socket: &mut WebSocket,
    channel: &str,
    r: Result<T, RecvError>,
    seq: &mut u64,
) -> bool {
    match r {
        Ok(msg) => {
            *seq += 1;
            let json = match channel_json(&msg, channel, *seq) {
                Ok(j) => j,
                Err(e) => {
                    tracing::error!(channel, error = %e, "/v1/stream: channel serialize failed; dropping");
                    return false;
                }
            };
            socket.send(Message::Text(json)).await.is_err()
        }
        // Slow client lagged past the buffer. Close with a resync reason so it
        // reopens + re-reads (indexer backfill for fills; /tree/* for tree).
        Err(RecvError::Lagged(skipped)) => {
            tracing::warn!(
                channel,
                skipped,
                "/v1/stream channel lagged; closing for resync"
            );
            let _ = socket
                .send(Message::Close(Some(CloseFrame {
                    code: 1011,
                    reason: format!("lagged: {skipped} {channel} msgs skipped — reopen to resync")
                        .into(),
                })))
                .await;
            true
        }
        // The global/per-account sender was dropped (shouldn't happen for a live
        // instance) — stop pushing this channel but keep the socket.
        Err(RecvError::Closed) => false,
    }
}

/// Parse + dispatch one text frame.
async fn handle_frame(
    state: &ApiState,
    matcher: &Option<Matcher>,
    s: &mut Session,
    txt: &str,
) -> Action {
    let req: StreamRequest = match serde_json::from_str(txt) {
        Ok(r) => r,
        Err(e) => {
            return Action::Reply(vec![StreamResponse::error(
                None,
                1001,
                format!("malformed frame: {e}"),
            )])
        }
    };

    match req {
        // Ping is the only op allowed pre-login.
        StreamRequest::Ping { request_id } => {
            Action::Reply(vec![StreamResponse::Pong { request_id }])
        }

        StreamRequest::Login {
            request_id,
            token,
            cancel_on_disconnect,
        } => Action::Reply(vec![
            login(state, s, request_id, &token, cancel_on_disconnect).await,
        ]),

        StreamRequest::Logout { .. } => Action::Close,

        StreamRequest::Subscribe {
            request_id,
            channels,
        } => Action::Reply(subscribe(state, s, request_id, channels).await),

        StreamRequest::Unsubscribe {
            request_id,
            channels,
        } => {
            if s.authed.is_none() {
                return Action::Reply(vec![StreamResponse::error(
                    request_id,
                    4010,
                    "login required",
                )]);
            }
            for ch in &channels {
                match ch.as_str() {
                    "orders" => s.sub_orders = None,
                    "fills" => s.sub_fills = None,
                    "tree" => s.sub_tree = None,
                    _ => {}
                }
            }
            Action::Reply(vec![StreamResponse::Unsubscribed {
                request_id,
                channels,
            }])
        }

        // Order ops require login + a live matcher; the trading-key signature in
        // `params` is still verified inside *_core (login auths the ACCOUNT, the
        // trading key is the cryptographic owner).
        //
        // AU-01 (audit 2026-07-25): each is rate-limited with the SAME
        // per-account bucket and the SAME weights as its HTTP twin. `/v1/stream`
        // is mounted on the PUBLIC router, so it never passed through
        // `rate_limit_middleware` — the WebSocket order path bypassed the
        // limiter entirely, which is exactly the throttle S-02's blast radius
        // depends on. One credentialed client could place at line rate.
        StreamRequest::Place { request_id, params } => {
            if let Some(e) = order_rate_guard(state, s, request_id.clone(), 1.0).await {
                return Action::Reply(vec![e]);
            }
            Action::Reply(vec![place(state, matcher, s, request_id, &params).await])
        }
        StreamRequest::Cancel {
            request_id,
            order_id,
            params,
        } => {
            if let Some(e) = order_rate_guard(state, s, request_id.clone(), 0.2).await {
                return Action::Reply(vec![e]);
            }
            Action::Reply(vec![
                cancel(state, matcher, s, request_id, &order_id, &params).await,
            ])
        }
        StreamRequest::Modify {
            request_id,
            order_id,
            params,
        } => {
            if let Some(e) = order_rate_guard(state, s, request_id.clone(), 1.2).await {
                return Action::Reply(vec![e]);
            }
            Action::Reply(vec![
                modify(state, matcher, s, request_id, &order_id, &params).await,
            ])
        }

        StreamRequest::AccountInfo { request_id } => {
            if s.authed.is_none() {
                Action::Reply(vec![StreamResponse::error(
                    request_id,
                    4010,
                    "login required",
                )])
            } else {
                Action::Reply(vec![StreamResponse::error(
                    request_id,
                    5010,
                    "account.info not implemented — reconstruct account state client-side from the `tree` \
                     channel + your keys (mirrors GET /account 501)",
                )])
            }
        }
    }
}

async fn login(
    state: &ApiState,
    s: &mut Session,
    request_id: Option<String>,
    token: &str,
    cancel_on_disconnect: Option<bool>,
) -> StreamResponse {
    let authorized = match validate_token(state, token).await {
        Ok(auth) => auth,
        Err(e) => return StreamResponse::error(request_id, e.code, e.message),
    };
    let account_id = authorized.account_id;
    // A re-login refreshes the token but must not switch identity on a socket
    // that already placed/subscribed under another account.
    if let Some(existing) = &s.authed {
        if existing != &account_id {
            return StreamResponse::error(
                request_id,
                4030,
                "cannot switch account on an authenticated socket; open a new one",
            );
        }
    }
    let previous_exp = s.token_exp;
    s.cancel_on_disconnect = match cancel_on_disconnect {
        Some(v) => v,
        None => state
            .accounts
            .read()
            .await
            .lookup(&account_id)
            .map(|c| c.settings.cancel_on_disconnect_default)
            .unwrap_or(false),
    };
    s.authed = Some(account_id.clone());
    s.token_exp = Some(authorized.exp);
    if match previous_exp {
        None => true,
        Some(old) => authorized.exp > old,
    } {
        s.auth_expired_warned = false;
    }
    StreamResponse::Login {
        request_id,
        account_id,
    }
}

async fn subscribe(
    state: &ApiState,
    s: &mut Session,
    request_id: Option<String>,
    channels: Vec<String>,
) -> Vec<StreamResponse> {
    let Some(account) = s.authed.clone() else {
        return vec![StreamResponse::error(request_id, 4010, "login required")];
    };
    let mut out = Vec::new();
    let mut subscribed = Vec::new();
    for ch in channels {
        match ch.as_str() {
            "orders" => {
                if s.sub_orders.is_none() {
                    s.sub_orders = Some(state.subscribe_account_order_updates(&account).await);
                }
                subscribed.push(ch);
            }
            "fills" => {
                if s.sub_fills.is_none() {
                    s.sub_fills = Some(state.subscribe_account_fills(&account).await);
                }
                subscribed.push(ch);
            }
            "tree" => {
                if s.sub_tree.is_none() {
                    s.sub_tree = Some(state.subscribe_tree_appends());
                }
                subscribed.push(ch);
            }
            "account" | "settlement" => out.push(StreamResponse::error(
                request_id.clone(),
                5010,
                format!("channel `{ch}` not served on /v1/stream"),
            )),
            other => out.push(StreamResponse::error(
                request_id.clone(),
                1002,
                format!("unknown channel `{other}`"),
            )),
        }
    }
    out.push(StreamResponse::Subscribed {
        request_id,
        channels: subscribed,
    });
    out
}

/// Resolve the matcher + login gate shared by the three order ops.
fn order_guard<'a>(
    matcher: &'a Option<Matcher>,
    s: &Session,
    request_id: &Option<String>,
) -> Result<(&'a Matcher, String), StreamResponse> {
    let Some(account) = s.authed.clone() else {
        return Err(StreamResponse::error(
            request_id.clone(),
            4010,
            "login required",
        ));
    };
    let Some(matcher) = matcher.as_ref() else {
        return Err(StreamResponse::error(
            request_id.clone(),
            5001,
            "matcher state not initialised on this instance",
        ));
    };
    Ok((matcher, account))
}

async fn place(
    state: &ApiState,
    matcher: &Option<Matcher>,
    s: &mut Session,
    request_id: Option<String>,
    params: &PlaceOrderRequest,
) -> StreamResponse {
    let (matcher, account) = match order_guard(matcher, s, &request_id) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match place_core(state, matcher, params, &account).await {
        Ok(result) => {
            s.session_orders.insert(result.order_id.clone());
            StreamResponse::Place { request_id, result }
        }
        Err(e) => StreamResponse::error(request_id, e.code, e.message),
    }
}

async fn cancel(
    state: &ApiState,
    matcher: &Option<Matcher>,
    s: &mut Session,
    request_id: Option<String>,
    order_id: &str,
    params: &CancelOrderRequest,
) -> StreamResponse {
    let (matcher, _account) = match order_guard(matcher, s, &request_id) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match cancel_core(state, matcher, order_id, params).await {
        Ok(result) => {
            s.session_orders.remove(order_id);
            StreamResponse::Cancel { request_id, result }
        }
        Err(e) => StreamResponse::error(request_id, e.code, e.message),
    }
}

async fn modify(
    state: &ApiState,
    matcher: &Option<Matcher>,
    s: &mut Session,
    request_id: Option<String>,
    order_id: &str,
    params: &ModifyOrderRequest,
) -> StreamResponse {
    let (matcher, account) = match order_guard(matcher, s, &request_id) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match modify_core(state, matcher, order_id, params, &account).await {
        Ok(result) => {
            // Old id left the book; the (possibly same) new id now rests.
            s.session_orders.remove(order_id);
            s.session_orders.insert(result.order_id.clone());
            StreamResponse::Modify { request_id, result }
        }
        Err(e) => StreamResponse::error(request_id, e.code, e.message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn login_frame_deserializes_with_cod() {
        let f: StreamRequest = serde_json::from_value(json!({
            "op": "login", "request_id": "l1", "token": "jwt", "cancel_on_disconnect": true
        }))
        .unwrap();
        match f {
            StreamRequest::Login {
                token,
                cancel_on_disconnect,
                ..
            } => {
                assert_eq!(token, "jwt");
                assert_eq!(cancel_on_disconnect, Some(true));
            }
            _ => panic!("expected login"),
        }
    }

    #[test]
    fn subscribe_frame_lists_channels() {
        let f: StreamRequest = serde_json::from_value(json!({
            "op": "subscribe", "channels": ["orders", "fills", "tree"]
        }))
        .unwrap();
        match f {
            StreamRequest::Subscribe { channels, .. } => {
                assert_eq!(channels, vec!["orders", "fills", "tree"]);
            }
            _ => panic!("expected subscribe"),
        }
    }

    #[test]
    fn unknown_op_is_rejected() {
        let r: Result<StreamRequest, _> = serde_json::from_value(json!({ "op": "order.teleport" }));
        assert!(r.is_err());
    }

    #[test]
    fn responses_carry_op_tag_and_request_id() {
        let v = serde_json::to_value(StreamResponse::Login {
            request_id: Some("l1".into()),
            account_id: "acct".into(),
        })
        .unwrap();
        assert_eq!(v["op"], "login");
        assert_eq!(v["request_id"], "l1");
        assert_eq!(v["account_id"], "acct");

        let e = serde_json::to_value(StreamResponse::error(None, 4010, "login required")).unwrap();
        assert_eq!(e["op"], "error");
        assert_eq!(e["code"], 4010);
    }

    #[test]
    fn auth_expiry_warning_is_sequenced() {
        let encoded = seq_json(&StreamResponse::AuthExpired { expires_at: 123 }, 7).unwrap();
        let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(value["op"], "auth_expired");
        assert_eq!(value["expires_at"], 123);
        assert_eq!(value["seq"], 7);
    }

    #[test]
    fn channel_json_injects_channel_and_seq() {
        let leaf = TreeAppendEvent {
            channel: "tree",
            tree_id: 2,
            leaf_index: 5,
            commitment: "ab".repeat(32),
        };
        let s = channel_json(&leaf, "tree", 9).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["channel"], "tree");
        assert_eq!(v["seq"], 9);
        assert_eq!(v["tree_id"], 2);
        assert_eq!(v["leaf_index"], 5);
    }

    /// AU-01: the WebSocket order path must charge the SAME per-account cost
    /// as its HTTP twin. If these drift, a client gets a cheaper allowance by
    /// switching transport — which is how the bypass existed in the first
    /// place (the WS route is on the public router and never saw the
    /// rate-limit middleware at all).
    #[test]
    fn ws_order_costs_match_the_http_route_costs() {
        use crate::api::rate_limit::route_cost;
        use axum::http::Method;

        // These literals are the ones passed to `order_rate_guard` in
        // `handle_frame`; keep the three in lockstep.
        assert_eq!(route_cost(&Method::POST, "/orders"), 1.0, "place");
        assert_eq!(route_cost(&Method::DELETE, "/orders/abc"), 0.2, "cancel");
        assert_eq!(route_cost(&Method::PUT, "/orders/abc"), 1.2, "modify");
    }
}
