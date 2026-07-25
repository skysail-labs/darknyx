//! `verify_match_batch` (Tx B) submission integration test.
//!
//! Drives `build_verify_match_batch_ix` + the shared `submit_ixs`
//! / `confirm_signatures` helpers against an in-process mock
//! JSON-RPC server (same pattern as `tests/lock_note_submit.rs`).
//!
//! Coverage:
//!   - happy path: ix submits, the wire tx is base64, one
//!     blockhash fetch + one sendTransaction;
//!   - confirm: a confirmed sig returns Ok;
//!   - confirm: a reverted sig surfaces an error.
//!
//! On-chain acceptance (real groth16-solana verification of an
//! N=16 proof) lands in PR 4g.6 via litesvm.
//!
//! Run with: `cargo test -p darknyx-tee --test verify_match_batch_submit`

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use darknyx_tee::settle::{
    build_verify_match_batch_ix, confirm_signatures, submit_ixs, Groth16ProofBytes,
    VerifyMatchBatchArgs,
};
use darknyx_tee::solana_rpc::SolanaRpcClient;
use serde_json::{json, Value};
use solana_keypair::Keypair;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

#[derive(Default, Clone)]
struct MockState {
    handlers: std::collections::HashMap<String, Value>,
    captured: std::collections::HashMap<String, Vec<Value>>,
}
type Mock = Arc<Mutex<MockState>>;

async fn handle_rpc(
    State(state): State<Mock>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let method = body
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let id = body.get("id").cloned().unwrap_or(json!(0));
    let mut s = state.lock().await;
    s.captured
        .entry(method.clone())
        .or_default()
        .push(body.clone());
    let result = s.handlers.get(&method).cloned();
    let response = match result {
        Some(r) => json!({ "jsonrpc": "2.0", "id": id, "result": r }),
        None => json!({
            "jsonrpc": "2.0", "id": id,
            "error": { "code": -32601, "message": format!("no handler for {method}") },
        }),
    };
    (StatusCode::OK, Json(response))
}

async fn spawn_mock() -> (String, Mock, tokio::task::JoinHandle<()>) {
    let state: Mock = Arc::new(Mutex::new(MockState::default()));
    let app = Router::new()
        .route("/", post(handle_rpc))
        .with_state(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}/"), state, handle)
}

fn keypair() -> Keypair {
    Keypair::new_from_array([0x42u8; 32])
}

fn args() -> VerifyMatchBatchArgs {
    VerifyMatchBatchArgs {
        merkle_root: [0xAB; 32],
        proof: Groth16ProofBytes {
            pi_a: [0x11; 64],
            pi_b: [0x22; 128],
            pi_c: [0x33; 64],
        },
    }
}

fn seed_blockhash(s: &mut MockState) {
    s.handlers.insert(
        "getLatestBlockhash".to_string(),
        json!({
            "context": { "slot": 1000 },
            "value": {
                "blockhash": bs58::encode([0xEE; 32]).into_string(),
                "lastValidBlockHeight": 1100
            }
        }),
    );
}

#[tokio::test]
async fn verify_match_batch_submits_one_tx() {
    let (endpoint, mock, _server) = spawn_mock().await;
    {
        let mut s = mock.lock().await;
        seed_blockhash(&mut s);
        s.handlers
            .insert("sendTransaction".to_string(), json!("verify-sig-aaaa"));
    }
    let client = SolanaRpcClient::new(endpoint).unwrap();
    let kp = keypair();

    let payer = {
        use solana_signer::Signer;
        kp.pubkey()
    };
    let ix = build_verify_match_batch_ix(&payer, &[0x44; 32], &[0x55; 32], args());
    let sig = submit_ixs(&client, &kp, &[ix]).await.unwrap();
    assert_eq!(sig, "verify-sig-aaaa");

    let s = mock.lock().await;
    assert_eq!(s.captured.get("getLatestBlockhash").unwrap().len(), 1);
    let sends = s.captured.get("sendTransaction").unwrap();
    assert_eq!(sends.len(), 1);
    let tx_b64 = sends[0]["params"][0].as_str().unwrap();
    assert!(tx_b64
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c)));
}

#[tokio::test]
async fn confirm_ok_when_confirmed() {
    let (endpoint, mock, _server) = spawn_mock().await;
    {
        let mut s = mock.lock().await;
        s.handlers.insert(
            "getSignatureStatuses".to_string(),
            json!({
                "context": { "slot": 1010 },
                "value": [ { "confirmationStatus": "confirmed", "err": null } ]
            }),
        );
    }
    let client = SolanaRpcClient::new(endpoint).unwrap();
    confirm_signatures(&client, &["sig-a".to_string()], Duration::from_secs(2))
        .await
        .expect("should confirm");
}

#[tokio::test]
async fn confirm_errors_on_revert() {
    let (endpoint, mock, _server) = spawn_mock().await;
    {
        let mut s = mock.lock().await;
        s.handlers.insert(
            "getSignatureStatuses".to_string(),
            json!({
                "context": { "slot": 1010 },
                "value": [ { "confirmationStatus": "confirmed", "err": { "InstructionError": [0, "Custom"] } } ]
            }),
        );
    }
    let client = SolanaRpcClient::new(endpoint).unwrap();
    let err = confirm_signatures(&client, &["sig-a".to_string()], Duration::from_secs(2))
        .await
        .unwrap_err();
    assert!(format!("{err}").contains("reverted"));
}
