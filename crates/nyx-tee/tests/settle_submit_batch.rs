//! Batched Tx D confirmation/rebroadcast regression (P-04).
//!
//! The mock confirms A/B/C on their first/second/third appearances. The helper
//! must therefore poll `[A,B,C] -> [B,C] -> [C]`, and rebroadcast only B/C,
//! then C. This pins the RPC call-count and pending-set semantics independently
//! of a live validator.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use nyx_tee::settle::{send_and_confirm_many_with_rebroadcast, TransactionConfirmationOutcome};
use nyx_tee::solana_rpc::SolanaRpcClient;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

#[derive(Default)]
struct MockState {
    send_calls: Vec<(usize, String, bool)>,
    status_calls: Vec<Vec<String>>,
    appearances: HashMap<String, usize>,
    status_round: usize,
    revert_signature: Option<String>,
    never_confirm_signature: Option<String>,
}

type Mock = Arc<Mutex<MockState>>;

fn signature_for_tx(tx: &str) -> &str {
    match tx {
        "tx-a" => "sig-a",
        "tx-b" => "sig-b",
        "tx-c" => "sig-c",
        other => panic!("unexpected mock transaction: {other}"),
    }
}

async fn handle_rpc(
    State(state): State<Mock>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let id = body.get("id").cloned().unwrap_or(json!(0));
    let method = body.get("method").and_then(Value::as_str).unwrap_or("");
    let mut state = state.lock().await;

    let result = match method {
        "sendTransaction" => {
            let tx = body["params"][0]
                .as_str()
                .expect("sendTransaction tx")
                .to_string();
            let skip_preflight = body["params"][1]["skipPreflight"]
                .as_bool()
                .expect("skipPreflight bool");
            let status_round = state.status_round;
            state
                .send_calls
                .push((status_round, tx.clone(), skip_preflight));
            json!(signature_for_tx(&tx))
        }
        "getSignatureStatuses" => {
            state.status_round += 1;
            let signatures: Vec<String> = body["params"][0]
                .as_array()
                .expect("signature array")
                .iter()
                .map(|value| value.as_str().expect("signature string").to_string())
                .collect();
            state.status_calls.push(signatures.clone());

            let mut statuses = Vec::with_capacity(signatures.len());
            for signature in signatures {
                let should_revert = state.revert_signature.as_deref() == Some(signature.as_str());
                let appearances = {
                    let appearances = state.appearances.entry(signature.clone()).or_default();
                    *appearances += 1;
                    *appearances
                };
                if should_revert {
                    statuses.push(json!({
                        "confirmationStatus": "confirmed",
                        "err": { "InstructionError": [0, "Custom"] },
                        "slot": 999,
                    }));
                    continue;
                }
                if state.never_confirm_signature.as_deref() == Some(signature.as_str()) {
                    statuses.push(Value::Null);
                    continue;
                }
                let confirm_after = match signature.as_str() {
                    "sig-a" => 1,
                    "sig-b" => 2,
                    "sig-c" => 3,
                    other => panic!("unexpected signature: {other}"),
                };
                if appearances >= confirm_after {
                    statuses.push(json!({
                        "confirmationStatus": "confirmed",
                        "err": null,
                        "slot": 100 + confirm_after,
                    }));
                } else {
                    statuses.push(Value::Null);
                }
            }
            json!({ "context": { "slot": 1000 }, "value": statuses })
        }
        other => {
            return (
                StatusCode::OK,
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32601, "message": format!("unexpected method {other}") },
                })),
            );
        }
    };

    (
        StatusCode::OK,
        Json(json!({ "jsonrpc": "2.0", "id": id, "result": result })),
    )
}

async fn spawn_mock(revert_signature: Option<&str>) -> (String, Mock) {
    let state = Arc::new(Mutex::new(MockState {
        revert_signature: revert_signature.map(str::to_string),
        ..MockState::default()
    }));
    let app = Router::new()
        .route("/", post(handle_rpc))
        .with_state(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{address}/"), state)
}

#[tokio::test]
async fn polls_one_shrinking_pending_set_and_rebroadcasts_only_overdue() {
    let (endpoint, state) = spawn_mock(None).await;
    let client = SolanaRpcClient::new(endpoint).unwrap();
    let outcomes = send_and_confirm_many_with_rebroadcast(
        &client,
        vec![
            (0, "tx-a".to_string()),
            (1, "tx-b".to_string()),
            (2, "tx-c".to_string()),
        ],
        Duration::from_secs(3),
        Duration::ZERO,
        2,
    )
    .await;

    assert_eq!(
        outcomes
            .iter()
            .map(|outcome| match outcome {
                TransactionConfirmationOutcome::Confirmed(outcome) => (
                    outcome.transaction_index,
                    outcome.signature.as_str(),
                    outcome.slot,
                    outcome.rebroadcasts,
                ),
                other => panic!("unexpected outcome: {other:?}"),
            })
            .collect::<Vec<_>>(),
        vec![
            (0, "sig-a", Some(101), 0),
            (1, "sig-b", Some(102), 1),
            (2, "sig-c", Some(103), 2),
        ]
    );

    let state = state.lock().await;
    assert_eq!(
        state.status_calls,
        vec![
            vec!["sig-a", "sig-b", "sig-c"],
            vec!["sig-b", "sig-c"],
            vec!["sig-c"],
        ]
    );

    let mut initial: Vec<_> = state
        .send_calls
        .iter()
        .filter(|(_, _, skip)| !skip)
        .map(|(_, tx, _)| tx.as_str())
        .collect();
    initial.sort_unstable();
    assert_eq!(initial, vec!["tx-a", "tx-b", "tx-c"]);

    let mut first_round: Vec<_> = state
        .send_calls
        .iter()
        .filter(|(round, _, skip)| *round == 1 && *skip)
        .map(|(_, tx, _)| tx.as_str())
        .collect();
    first_round.sort_unstable();
    assert_eq!(first_round, vec!["tx-b", "tx-c"]);
    assert_eq!(
        state
            .send_calls
            .iter()
            .filter(|(round, _, skip)| *round == 2 && *skip)
            .map(|(_, tx, _)| tx.as_str())
            .collect::<Vec<_>>(),
        vec!["tx-c"]
    );
    assert!(state
        .send_calls
        .iter()
        .all(|(_, tx, skip)| !skip || tx != "tx-a"));
}

#[tokio::test]
async fn revert_reports_the_original_transaction_index() {
    let (endpoint, _state) = spawn_mock(Some("sig-b")).await;
    let client = SolanaRpcClient::new(endpoint).unwrap();
    let outcomes = send_and_confirm_many_with_rebroadcast(
        &client,
        vec![(3, "tx-a".to_string()), (7, "tx-b".to_string())],
        Duration::from_secs(2),
        Duration::from_secs(1),
        2,
    )
    .await;

    assert!(matches!(
        &outcomes[0],
        TransactionConfirmationOutcome::Confirmed(outcome)
            if outcome.transaction_index == 3 && outcome.signature == "sig-a"
    ));
    let message = match &outcomes[1] {
        TransactionConfirmationOutcome::Rejected {
            transaction_index,
            reason,
            ..
        } if *transaction_index == 7 => reason,
        other => panic!("unexpected outcome: {other:?}"),
    };
    assert!(
        message.contains("settle tx[7] (sig-b) reverted"),
        "{message}"
    );
}

#[tokio::test]
async fn timeout_is_ambiguous_and_does_not_discard_confirmed_siblings() {
    let (endpoint, state) = spawn_mock(None).await;
    state.lock().await.never_confirm_signature = Some("sig-c".to_string());
    let client = SolanaRpcClient::new(endpoint).unwrap();
    let outcomes = send_and_confirm_many_with_rebroadcast(
        &client,
        vec![(0, "tx-a".to_string()), (2, "tx-c".to_string())],
        Duration::from_millis(20),
        Duration::from_secs(1),
        2,
    )
    .await;

    assert!(matches!(
        &outcomes[0],
        TransactionConfirmationOutcome::Confirmed(outcome)
            if outcome.transaction_index == 0
    ));
    assert!(matches!(
        &outcomes[1],
        TransactionConfirmationOutcome::Ambiguous {
            transaction_index: 2,
            signature: Some(signature),
            reason,
        } if signature == "sig-c" && reason.contains("did not confirm")
    ));
}
