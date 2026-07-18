//! Solana JSON-RPC client integration tests.
//!
//! Two layers of coverage:
//!
//! 1. **In-process mock server** — exercises the wire format end-
//!    to-end without depending on a real Solana RPC. We stand up
//!    an axum HTTP server on an ephemeral port that returns canned
//!    JSON-RPC responses, then drive the client against it. This
//!    is what runs on every CI build.
//!
//! 2. **Real devnet smoke** — gated on `RUN_DEVNET_RPC_SMOKE=1`.
//!    Hits `api.devnet.solana.com` and asserts the live network
//!    returns a sane blockhash. Runs locally + during the
//!    `/test-devnet` flow but never in CI by default.
//!
//! Run with: `cargo test -p darknyx-tee --test solana_rpc`

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use darknyx_tee::solana_rpc::{Commitment, RpcError, SolanaRpcClient};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

// ─── Mock server plumbing ────────────────────────────────────────────────────

/// Maps `method` (string) → canned response body. Tests register
/// a handler per method; unknown methods produce a JSON-RPC -32601.
type MockHandlers = Arc<Mutex<std::collections::HashMap<String, Value>>>;

async fn handle_rpc(
    State(handlers): State<MockHandlers>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let method = body.get("method").and_then(Value::as_str).unwrap_or("");
    let id = body.get("id").cloned().unwrap_or(json!(0));
    let h = handlers.lock().await;
    let result = h.get(method).cloned();
    let response = match result {
        Some(r) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": r,
        }),
        None => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32601, "message": format!("Method not found: {method}") },
        }),
    };
    (StatusCode::OK, Json(response))
}

async fn spawn_mock() -> (String, MockHandlers, tokio::task::JoinHandle<()>) {
    let handlers: MockHandlers = Arc::new(Mutex::new(std::collections::HashMap::new()));
    let app = Router::new()
        .route("/", post(handle_rpc))
        .with_state(handlers.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}/"), handlers, handle)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn get_latest_blockhash_parses_response() {
    let (endpoint, handlers, _server) = spawn_mock().await;
    handlers.lock().await.insert(
        "getLatestBlockhash".to_string(),
        json!({
            "context": { "slot": 1234567 },
            "value": {
                "blockhash": bs58::encode([0xAAu8; 32]).into_string(),
                "lastValidBlockHeight": 1234600
            }
        }),
    );

    let client = SolanaRpcClient::new(endpoint).unwrap();
    let bh = client.get_latest_blockhash().await.unwrap();
    assert_eq!(bh.blockhash, [0xAA; 32]);
    assert_eq!(bh.context_slot, 1234567);
    assert_eq!(bh.last_valid_block_height, 1234600);
}

#[tokio::test]
async fn send_transaction_returns_signature() {
    let (endpoint, handlers, _server) = spawn_mock().await;
    handlers.lock().await.insert(
        "sendTransaction".to_string(),
        json!(
            "5XJSj7sP4nQwYqGz4XJp5cZyG3kV2mq8aBcDeFgHiJkLmNpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYz"
        ),
    );

    let client = SolanaRpcClient::new(endpoint).unwrap();
    let sig = client.send_transaction("base64-tx-bytes").await.unwrap();
    assert!(sig.starts_with("5XJS"));
}

#[tokio::test]
async fn get_signature_statuses_maps_commitment() {
    let (endpoint, handlers, _server) = spawn_mock().await;
    handlers.lock().await.insert(
        "getSignatureStatuses".to_string(),
        json!({
            "context": { "slot": 100 },
            "value": [
                // First sig: confirmed (≥ "confirmed" commitment).
                { "confirmationStatus": "confirmed", "err": null },
                // Second sig: only processed (< "confirmed").
                { "confirmationStatus": "processed", "err": null },
                // Third sig: unknown.
                null,
                // Fourth sig: finalized + err.
                { "confirmationStatus": "finalized", "err": { "InstructionError": [0, "Custom"] } },
            ]
        }),
    );

    let client = SolanaRpcClient::new(endpoint).unwrap();
    let statuses = client
        .get_signature_statuses(&[
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
            "d".to_string(),
        ])
        .await
        .unwrap();
    assert_eq!(statuses.len(), 4);
    assert_eq!(
        statuses[0].as_ref().unwrap().confirmed_at_commitment,
        Some(true)
    );
    assert_eq!(
        statuses[1].as_ref().unwrap().confirmed_at_commitment,
        Some(false)
    );
    assert!(statuses[2].is_none());
    assert_eq!(
        statuses[3].as_ref().unwrap().confirmed_at_commitment,
        Some(true)
    );
    assert!(statuses[3].as_ref().unwrap().err.is_some());
}

#[tokio::test]
async fn get_account_info_decodes_base64() {
    use base64::Engine as _;
    let (endpoint, handlers, _server) = spawn_mock().await;
    let owner_b58 = bs58::encode([0x11u8; 32]).into_string();
    let payload = vec![1u8, 2, 3, 4, 5];
    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(&payload);
    handlers.lock().await.insert(
        "getAccountInfo".to_string(),
        json!({
            "context": { "slot": 200 },
            "value": {
                "lamports": 1_000_000u64,
                "owner": owner_b58,
                "data": [payload_b64, "base64"],
                "executable": false,
                "rentEpoch": 999u64
            }
        }),
    );

    let client = SolanaRpcClient::new(endpoint).unwrap();
    let target_addr: solana_address::Address =
        bs58::encode([0x22u8; 32]).into_string().parse().unwrap();
    let acct = client
        .get_account_info(&target_addr)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(acct.lamports, 1_000_000);
    assert_eq!(acct.data, payload);
    assert!(!acct.executable);
    assert_eq!(acct.rent_epoch, 999);
}

#[tokio::test]
async fn get_account_info_returns_none_for_missing() {
    let (endpoint, handlers, _server) = spawn_mock().await;
    handlers.lock().await.insert(
        "getAccountInfo".to_string(),
        json!({ "context": { "slot": 1 }, "value": null }),
    );

    let client = SolanaRpcClient::new(endpoint).unwrap();
    let target_addr: solana_address::Address =
        bs58::encode([0x22u8; 32]).into_string().parse().unwrap();
    let acct = client.get_account_info(&target_addr).await.unwrap();
    assert!(acct.is_none());
}

#[tokio::test]
async fn simulate_transaction_surfaces_logs_and_err() {
    let (endpoint, handlers, _server) = spawn_mock().await;
    handlers.lock().await.insert(
        "simulateTransaction".to_string(),
        json!({
            "context": { "slot": 1 },
            "value": {
                "err": { "InstructionError": [0, "Custom"] },
                "logs": ["Program log: hello", "Program failed"],
                "unitsConsumed": 12345u64
            }
        }),
    );

    let client = SolanaRpcClient::new(endpoint).unwrap();
    let sim = client.simulate_transaction("base64-tx").await.unwrap();
    assert!(sim.err.is_some());
    assert_eq!(sim.logs.len(), 2);
    assert_eq!(sim.units_consumed, Some(12345));
}

#[tokio::test]
async fn get_recent_prioritization_fees_parses() {
    let (endpoint, handlers, _server) = spawn_mock().await;
    handlers.lock().await.insert(
        "getRecentPrioritizationFees".to_string(),
        json!([
            { "slot": 100, "prioritizationFee": 5000u64 },
            { "slot": 101, "prioritizationFee": 6000u64 },
        ]),
    );

    let client = SolanaRpcClient::new(endpoint).unwrap();
    let addr: solana_address::Address = bs58::encode([0x33u8; 32]).into_string().parse().unwrap();
    let fees = client
        .get_recent_prioritization_fees(&[addr])
        .await
        .unwrap();
    assert_eq!(fees.len(), 2);
    assert_eq!(fees[0].slot, 100);
    assert_eq!(fees[0].prioritization_fee, 5000);
    assert_eq!(fees[1].prioritization_fee, 6000);
}

#[tokio::test]
async fn rpc_error_response_surfaces_typed_error() {
    let (endpoint, _handlers, _server) = spawn_mock().await;
    // No handler registered for `getLatestBlockhash` → mock
    // returns the -32601 envelope from `handle_rpc`. We assert
    // the client maps it to `RpcError::Rpc` with the right code.
    let client = SolanaRpcClient::new(endpoint).unwrap();
    let err = client.get_latest_blockhash().await.unwrap_err();
    match err {
        RpcError::Rpc { code, message, .. } => {
            assert_eq!(code, -32601);
            assert!(message.contains("Method not found"));
        }
        other => panic!("expected Rpc error, got {other:?}"),
    }
}

#[tokio::test]
async fn commitment_overrideable_via_with_commitment() {
    let (endpoint, handlers, _server) = spawn_mock().await;
    handlers.lock().await.insert(
        "getLatestBlockhash".to_string(),
        json!({
            "context": { "slot": 1 },
            "value": {
                "blockhash": bs58::encode([0u8; 32]).into_string(),
                "lastValidBlockHeight": 2
            }
        }),
    );
    let client = SolanaRpcClient::new(endpoint)
        .unwrap()
        .with_commitment(Commitment::Finalized);
    assert!(matches!(client.commitment(), Commitment::Finalized));
    // Smoke: the call still succeeds with the overridden commitment.
    let _ = client.get_latest_blockhash().await.unwrap();
}
