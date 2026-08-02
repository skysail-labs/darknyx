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
//!
//! ## No RPC URL in an error string (SW-01)
//!
//! `DARKNYX_TEE_SOLANA_RPC_URL` carries its credential **in the URL**
//! (`https://devnet.helius-rpc.com/?api-key=<secret>`) — that is Helius' standard
//! auth, so unlike the Hermes endpoint we cannot forbid query parameters. The
//! URL must therefore never reach a formatted error: these errors propagate
//! through `WorkerError` into a settle job's failure reason, which
//! `GET /settlement/status/{batch_id}` serves to any authenticated account.
//!
//! Two independent paths had to be closed, and the transport one is the
//! likelier to fire:
//!
//! * **Schema** — the client used to interpolate `self.endpoint` verbatim. It
//!   now formats a scheme+host display form (`SolanaRpcClient::endpoint_host`).
//! * **Network** — `reqwest::Error`'s own `Display` embeds the request URL
//!   (`error sending request for url (https://…?api-key=…)`), so a connect
//!   timeout, DNS failure, TLS error, or request timeout leaked the credential
//!   with no help from our formatting at all. The `From` impl below strips it
//!   with `without_url()`. **Do not restore `#[from]` here** — the derive would
//!   silently reinstate the leak.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RpcError {
    /// Network / TLS / DNS / timeout failure. The transport never
    /// completed.
    ///
    /// Constructed only through the `From` impl below, which strips the URL.
    #[error("network error: {0}")]
    Network(reqwest::Error),

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

/// Strip the request URL out of every transport error.
///
/// Hand-written on purpose. `#[from]` would derive an identity conversion and
/// re-open SW-01's second leak path: `reqwest::Error`'s `Display` renders as
/// `error sending request for url (<the full URL>)`, and our RPC URL carries
/// `?api-key=<secret>`. `without_url()` drops the URL and keeps the cause, so
/// operators still see "connect timeout" / "dns error" / the TLS failure —
/// which is the part that is actually diagnostic.
impl From<reqwest::Error> for RpcError {
    fn from(e: reqwest::Error) -> Self {
        RpcError::Network(e.without_url())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The credential lives in the URL, so a transport error that renders the
    /// URL discloses it. This is SW-01's *second* path — not the one the
    /// finding named, and the likelier of the two to fire, because a connect
    /// timeout, DNS failure, TLS error, or request timeout all reach it while
    /// the HTTP-status path needs the server to answer at all.
    #[tokio::test]
    async fn a_transport_error_does_not_render_the_url() {
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_millis(50))
            .build()
            .unwrap();
        // TEST-NET-1 (RFC 5737) — reserved for documentation, never routable,
        // so this fails at connect without depending on the sandbox's DNS.
        let raw = client
            .post("https://192.0.2.1/?api-key=SUPERSECRET")
            .json(&serde_json::json!({ "jsonrpc": "2.0" }))
            .send()
            .await
            .expect_err("connect to a reserved address must fail");

        // Establishes that the guard is doing the work: reqwest's own Display
        // DOES carry the secret. Without this the assertion below could pass
        // for an unrelated reason and the test would prove nothing.
        assert!(
            format!("{raw}").contains("SUPERSECRET"),
            "precondition: reqwest embeds the URL, so the conversion must strip it"
        );

        let converted: RpcError = raw.into();
        let rendered = format!("{converted}");
        assert!(
            !rendered.contains("SUPERSECRET"),
            "RpcError must not disclose the API key: {rendered}"
        );
        assert!(
            !rendered.contains("192.0.2.1"),
            "without_url() drops the host too: {rendered}"
        );
    }
}
