//! Env-driven config. The full set of allowed env vars must also
//! appear in `app-compose.json::allowed_envs` — changing this list
//! changes `compose_hash` and therefore requires a new image
//! authorization in dstack governance + a multisig rotation of
//! `vault_config.tee_pubkey` on Solana. See
//! `docs/tee-architecture.md` §11.

use anyhow::Result;

#[derive(Debug, Clone)]
#[allow(dead_code)] // Phase 1 stub: fields are read once the api/settle modules wire in.
pub struct Config {
    /// HTTP listen address. Defaults to 0.0.0.0:8080 inside the
    /// CVM; dstack-ingress fronts this on :443.
    pub http_bind: String,

    /// Solana RPC URL (Helius or equivalent). Passed in via an
    /// encrypted env var; the plaintext never touches a Phala
    /// console.
    pub solana_rpc_url: String,

    /// Optional override of the dstack socket path. When
    /// `DSTACK_SIMULATOR_ENDPOINT` is set we use that; otherwise
    /// `/var/run/dstack.sock`.
    pub dstack_socket: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            http_bind: std::env::var("NYX_TEE_HTTP_BIND")
                .unwrap_or_else(|_| "0.0.0.0:8080".to_string()),
            solana_rpc_url: std::env::var("NYX_TEE_SOLANA_RPC_URL")
                .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string()),
            dstack_socket: std::env::var("DSTACK_SIMULATOR_ENDPOINT").ok(),
        })
    }
}
