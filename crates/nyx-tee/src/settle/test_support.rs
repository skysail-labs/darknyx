//! Shared test scaffolding for the settle pipeline.
//!
//! `cfg(test)` + `pub(crate)` so any settle module's unit tests can
//! drive a full batch through the worker without circuit artifacts or
//! a real Solana cluster:
//!
//!   - [`spawn_mock_rpc`] — an in-process axum server answering the
//!     three JSON-RPC methods the pipeline calls (getLatestBlockhash /
//!     sendTransaction / getSignatureStatuses), always confirming.
//!   - [`FakeProver`] — a `Prover` that computes the REAL public
//!     inputs (leaves + root, so Merkle paths + the marker PDA are
//!     genuine) but returns a canned proof. The mock RPC doesn't
//!     verify proofs, so this exercises the full orchestration in
//!     milliseconds instead of the minutes a real N=16 proof costs.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::prover::{
    build_batch_public_inputs, MatchSlotWitness, ProofWithInputs, Prover, ProverError,
};
use crate::settle::lock_note::Groth16ProofBytes;

/// A `Prover` that skips Groth16 but produces real public inputs.
pub(crate) struct FakeProver {
    pub n: usize,
}

impl Prover for FakeProver {
    fn prove(&self, slots: &[MatchSlotWitness]) -> Result<ProofWithInputs, ProverError> {
        let public = build_batch_public_inputs(slots)?;
        Ok(ProofWithInputs {
            proof: Groth16ProofBytes {
                pi_a: [0x07; 64],
                pi_b: [0x07; 128],
                pi_c: [0x07; 64],
            },
            public,
        })
    }
    fn n(&self) -> usize {
        self.n
    }
}

/// Spawn a minimal JSON-RPC mock on a random port; returns its URL.
pub(crate) async fn spawn_mock_rpc() -> String {
    use axum::{extract::State, routing::post, Json, Router};
    use serde_json::{json, Value};

    async fn handle(State(counter): State<Arc<AtomicU64>>, Json(req): Json<Value>) -> Json<Value> {
        let id = req.get("id").cloned().unwrap_or(json!(1));
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let result = match method {
            "getLatestBlockhash" => json!({
                "context": { "slot": 1000 },
                "value": {
                    "blockhash": bs58::encode([7u8; 32]).into_string(),
                    "lastValidBlockHeight": 2000u64,
                }
            }),
            "sendTransaction" => {
                let nth = counter.fetch_add(1, Ordering::SeqCst);
                let mut sig = [0u8; 64];
                sig[..8].copy_from_slice(&nth.to_le_bytes());
                json!(bs58::encode(sig).into_string())
            }
            "getSignatureStatuses" => {
                let want = req
                    .get("params")
                    .and_then(|p| p.get(0))
                    .and_then(|s| s.as_array())
                    .map(|a| a.len())
                    .unwrap_or(1);
                let value: Vec<Value> = (0..want)
                    .map(|_| json!({ "confirmationStatus": "confirmed", "err": null }))
                    .collect();
                json!({ "context": { "slot": 1000 }, "value": value })
            }
            other => json!({ "error": format!("unexpected method {other}") }),
        };
        Json(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
    }

    let counter = Arc::new(AtomicU64::new(0));
    let app = Router::new().route("/", post(handle)).with_state(counter);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}
