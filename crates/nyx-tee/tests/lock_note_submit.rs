//! `submit_lock_note_pair` + `confirm_lock_pair` integration test.
//!
//! Drives both helpers against a mock JSON-RPC server (the same
//! pattern as `tests/solana_rpc.rs`). Coverage:
//!
//!   - Happy path: both lock_note txs reach the mock, both confirm,
//!     `confirm_lock_pair` returns Ok.
//!   - `sendTransaction` failure on the seller side surfaces an
//!     `RpcError::Rpc`.
//!   - `confirm_lock_pair` returns an error when one tx reverts
//!     with an `err` field.
//!   - `confirm_lock_pair` times out cleanly when statuses never
//!     reach "confirmed".
//!
//! End-to-end against a real on-chain vault BPF is deferred to PR
//! 4g.6 (where the full pipeline + the proof story land together).
//!
//! Run with: `cargo test -p nyx-tee --test lock_note_submit`

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use nyx_tee::settle::{
    confirm_lock_pair, submit_lock_note_pair, Groth16ProofBytes, LockSideInputs,
};
use nyx_tee::solana_rpc::{Commitment, SolanaRpcClient};
use serde_json::{json, Value};
use solana_keypair::Keypair;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

// ─── Mock plumbing (mirrors tests/solana_rpc.rs, but tracks call
// counts + captured request bodies so the test can assert about
// what hit the wire) ────────────────────────────────────────────────────────

#[derive(Default, Clone)]
struct MockState {
    /// Method → canned `result` value.
    handlers: std::collections::HashMap<String, Value>,
    /// Method → captured request body history.
    captured: std::collections::HashMap<String, Vec<Value>>,
    /// Method → next-call result override stack (popped per call).
    /// Useful for "first call succeeds, second call fails" tests.
    overrides: std::collections::HashMap<String, Vec<Value>>,
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

    let result = s
        .overrides
        .get_mut(&method)
        .and_then(|v| {
            if v.is_empty() {
                None
            } else {
                Some(v.remove(0))
            }
        })
        .or_else(|| s.handlers.get(&method).cloned());

    let response = match result {
        Some(r) if r.get("__error").is_some() => json!({
            "jsonrpc": "2.0", "id": id,
            "error": r["__error"].clone(),
        }),
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

// ─── Fixture builders ───────────────────────────────────────────────────────

fn fixed_keypair() -> Keypair {
    Keypair::new_from_array([0x42u8; 32])
}

fn dummy_proof() -> Groth16ProofBytes {
    Groth16ProofBytes {
        pi_a: [0x11; 64],
        pi_b: [0x22; 128],
        pi_c: [0x33; 64],
    }
}

fn buyer_inputs() -> LockSideInputs {
    LockSideInputs {
        tree_id: 0,
        note_commitment: [0xAA; 32],
        order_id: [0xBB; 16],
        expiry_slot: 1_000_000,
        amount: 100,
        token_mint: [0xCC; 32],
        merkle_root: [0xDD; 32],
        proof: dummy_proof(),
        already_locked: false,
    }
}

fn seller_inputs() -> LockSideInputs {
    LockSideInputs {
        tree_id: 0,
        note_commitment: [0x55; 32],
        order_id: [0x66; 16],
        expiry_slot: 1_000_000,
        amount: 10,
        token_mint: [0x77; 32],
        merkle_root: [0xDD; 32],
        proof: dummy_proof(),
        already_locked: false,
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

// ─── Tests ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn submit_lock_note_pair_sends_two_distinct_txs() {
    let (endpoint, mock, _server) = spawn_mock().await;
    {
        let mut s = mock.lock().await;
        seed_blockhash(&mut s);
        // Two sendTransaction calls — return distinct sigs.
        s.overrides.insert(
            "sendTransaction".to_string(),
            vec![json!("sig-buyer-aaaa"), json!("sig-seller-bbbb")],
        );
    }

    let client = SolanaRpcClient::new(endpoint).unwrap();
    let keypair = fixed_keypair();

    let outcome = submit_lock_note_pair(&client, &keypair, buyer_inputs(), seller_inputs(), 0)
        .await
        .unwrap();

    assert_eq!(outcome.buyer_sig.as_deref(), Some("sig-buyer-aaaa"));
    assert_eq!(outcome.seller_sig.as_deref(), Some("sig-seller-bbbb"));

    // Wire-level assertions: exactly one blockhash fetch + two
    // sendTransaction calls, and the two tx bodies differ (different
    // notes → different ix data → different tx wire bytes).
    let s = mock.lock().await;
    assert_eq!(s.captured.get("getLatestBlockhash").unwrap().len(), 1);
    let sends = s.captured.get("sendTransaction").unwrap();
    assert_eq!(sends.len(), 2);

    let tx0_b64 = sends[0]["params"][0].as_str().unwrap();
    let tx1_b64 = sends[1]["params"][0].as_str().unwrap();
    assert_ne!(
        tx0_b64, tx1_b64,
        "buyer + seller txs should differ in wire bytes"
    );
    // Sanity: both look like base64 (no random bytes outside the
    // base64 alphabet).
    for b64 in [tx0_b64, tx1_b64] {
        assert!(b64
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c)));
    }
}

#[tokio::test]
async fn submit_lock_note_pair_skips_relocked_side() {
    // A relocked continuation input (already_locked) was locked by a PRIOR
    // batch's re-lock PDA; re-issuing lock_note would collide. The pair
    // submitter must SKIP it — only the fresh side hits the wire.
    let (endpoint, mock, _server) = spawn_mock().await;
    {
        let mut s = mock.lock().await;
        seed_blockhash(&mut s);
        s.overrides.insert(
            "sendTransaction".to_string(),
            vec![json!("sig-seller-only")],
        );
    }

    let client = SolanaRpcClient::new(endpoint).unwrap();
    let keypair = fixed_keypair();
    let mut buyer = buyer_inputs();
    buyer.already_locked = true; // relocked continuation note

    let outcome = submit_lock_note_pair(&client, &keypair, buyer, seller_inputs(), 0)
        .await
        .unwrap();

    assert_eq!(
        outcome.buyer_sig, None,
        "relocked buyer side must be skipped"
    );
    assert_eq!(outcome.seller_sig.as_deref(), Some("sig-seller-only"));

    // Exactly ONE sendTransaction (the fresh seller); the buyer was skipped.
    let s = mock.lock().await;
    assert_eq!(s.captured.get("sendTransaction").unwrap().len(), 1);

    // confirm_lock_pair confirms only the present sig (no panic on the None).
    // (Confirmation status is seeded as confirmed below in a focused unit; here
    // we only assert the skip wiring.)
}

#[tokio::test]
async fn submit_lock_note_pair_propagates_rpc_error_on_second_tx() {
    let (endpoint, mock, _server) = spawn_mock().await;
    {
        let mut s = mock.lock().await;
        seed_blockhash(&mut s);
        // First send: ok. Second send: simulated -32002 (blockhash
        // not found) — typical resubmit-required signal.
        s.overrides.insert(
            "sendTransaction".to_string(),
            vec![
                json!("sig-buyer-aaaa"),
                json!({ "__error": { "code": -32002, "message": "Blockhash not found" } }),
            ],
        );
    }

    let client = SolanaRpcClient::new(endpoint).unwrap();
    let keypair = fixed_keypair();
    let err = submit_lock_note_pair(&client, &keypair, buyer_inputs(), seller_inputs(), 0)
        .await
        .unwrap_err();
    use nyx_tee::solana_rpc::RpcError;
    match err {
        RpcError::Rpc { code, message, .. } => {
            assert_eq!(code, -32002);
            assert!(message.contains("Blockhash"));
        }
        other => panic!("expected RpcError::Rpc, got {other:?}"),
    }
}

#[tokio::test]
async fn confirm_lock_pair_returns_ok_when_both_confirmed() {
    let (endpoint, mock, _server) = spawn_mock().await;
    {
        let mut s = mock.lock().await;
        s.handlers.insert(
            "getSignatureStatuses".to_string(),
            json!({
                "context": { "slot": 1010 },
                "value": [
                    { "confirmationStatus": "confirmed", "err": null },
                    { "confirmationStatus": "confirmed", "err": null }
                ]
            }),
        );
    }
    let client = SolanaRpcClient::new(endpoint)
        .unwrap()
        .with_commitment(Commitment::Confirmed);
    let outcome = nyx_tee::settle::LockPairOutcome {
        buyer_sig: Some("sig-a".to_string()),
        seller_sig: Some("sig-b".to_string()),
    };
    confirm_lock_pair(&client, &outcome, Duration::from_secs(2))
        .await
        .expect("both should confirm immediately");
}

#[tokio::test]
async fn confirm_lock_pair_fails_when_one_reverts() {
    let (endpoint, mock, _server) = spawn_mock().await;
    {
        let mut s = mock.lock().await;
        s.handlers.insert(
            "getSignatureStatuses".to_string(),
            json!({
                "context": { "slot": 1010 },
                "value": [
                    { "confirmationStatus": "confirmed", "err": null },
                    { "confirmationStatus": "confirmed", "err": { "InstructionError": [0, "Custom"] } }
                ]
            }),
        );
    }
    let client = SolanaRpcClient::new(endpoint).unwrap();
    let outcome = nyx_tee::settle::LockPairOutcome {
        buyer_sig: Some("sig-a".to_string()),
        seller_sig: Some("sig-b".to_string()),
    };
    let err = confirm_lock_pair(&client, &outcome, Duration::from_secs(2))
        .await
        .unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("seller") && (msg.contains("reverted") || msg.contains("InstructionError")),
        "expected revert message; got {msg}"
    );
}

#[tokio::test]
async fn confirm_lock_pair_times_out_when_never_confirmed() {
    let (endpoint, mock, _server) = spawn_mock().await;
    {
        let mut s = mock.lock().await;
        // Always returns processed-only (below confirmed) → never
        // satisfies the loop, so the deadline hits.
        s.handlers.insert(
            "getSignatureStatuses".to_string(),
            json!({
                "context": { "slot": 1010 },
                "value": [
                    { "confirmationStatus": "processed", "err": null },
                    { "confirmationStatus": "processed", "err": null }
                ]
            }),
        );
    }
    let client = SolanaRpcClient::new(endpoint).unwrap();
    let outcome = nyx_tee::settle::LockPairOutcome {
        buyer_sig: Some("sig-a".to_string()),
        seller_sig: Some("sig-b".to_string()),
    };
    let err = confirm_lock_pair(&client, &outcome, Duration::from_millis(500))
        .await
        .unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("did not confirm"),
        "expected timeout message; got {msg}"
    );
}
