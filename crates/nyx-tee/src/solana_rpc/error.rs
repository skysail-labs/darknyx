//! Typed errors for the JSON-RPC client.
//!
//! JSON-RPC 2.0 splits failures across three layers:
//!   1. Transport — TCP/TLS/timeout. `reqwest::Error`.
//!   2. Protocol — `{"error":{"code":..,"message":..,"data":..}}`
//!      in the response envelope. We expose `code` + `message`
//!      so call-sites can match on code (e.g. -32002 = signature
//!      not found, -32601 = method not found).
//!   3. Schema — the response shape doesn't match what we expect.
//!      This is a bug on either side; we surface enough context
//!      to debug.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RpcError {
    /// Network / TLS / DNS / timeout failure. The transport never
    /// completed.
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),

    /// Response body couldn't be parsed as JSON. Includes the raw
    /// bytes for debugging (truncated to 512 chars to keep logs
    /// reasonable).
    #[error("response body is not valid JSON: {error}; body[..512]={body_preview}")]
    InvalidJson {
        body_preview: String,
        #[source]
        error: serde_json::Error,
    },

    /// Server returned a JSON-RPC `error` object. `code` is the
    /// standard JSON-RPC error code; reach for the Solana-specific
    /// codes (e.g. -32002 = "Signature not found", -32602 =
    /// "Invalid params") when retrying or surfacing to operators.
    #[error("rpc error code {code}: {message}")]
    Rpc {
        code: i64,
        message: String,
        /// Solana sometimes puts useful state in `data`, e.g.
        /// preflight failure logs. Kept as raw JSON for the caller
        /// to introspect.
        data: Option<serde_json::Value>,
    },

    /// Response envelope was valid JSON but didn't match the shape
    /// the call-site expected. Usually means the RPC server is on a
    /// version we haven't seen — needs a human.
    #[error("unexpected response shape: {0}")]
    Schema(String),

    /// `decode_key` returned bytes that don't fit the expected
    /// shape. Currently surfaces from `keys::solana` when dstack
    /// hands back a wrong-length seed.
    #[error("malformed key material: {0}")]
    KeyMaterial(String),
}
