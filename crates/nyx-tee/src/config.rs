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

    /// Comma-separated list of Pyth Hermes feed ids the oracle
    /// sync task should refresh on every tick. Empty by default —
    /// dev-machine boots without network access skip oracle sync
    /// entirely and the matcher's tick simply no-ops (stale oracle
    /// is treated as "skip cycle"). Production sets one feed per
    /// market via `NYX_TEE_FEED_IDS`. Each entry is the
    /// 64-char-hex Pyth feed id.
    pub feed_ids: Vec<String>,

    /// Merkle cold-boot floor slot. `getSignaturesForAddress` history
    /// below this slot is ignored, so the sync only replays leaves from
    /// here forward. This is the `deployed_slot` the indexer design
    /// (§5.5) assumed: set it to the program's deploy slot (or, on a
    /// devnet that ran `reset_merkle_tree`, to the reset slot) so the
    /// mirror reconstructs the CURRENT tree rather than double-counting
    /// pre-reset leaves whose indices repeat post-reset. `0` (default)
    /// = replay from genesis (correct for a never-reset vault).
    pub sync_from_slot: u64,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let feed_ids = std::env::var("NYX_TEE_FEED_IDS")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(|t| t.trim().to_string())
                    .filter(|t| !t.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        Ok(Self {
            http_bind: std::env::var("NYX_TEE_HTTP_BIND")
                .unwrap_or_else(|_| "0.0.0.0:8080".to_string()),
            solana_rpc_url: std::env::var("NYX_TEE_SOLANA_RPC_URL")
                .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string()),
            dstack_socket: std::env::var("DSTACK_SIMULATOR_ENDPOINT").ok(),
            feed_ids,
            sync_from_slot: std::env::var("NYX_TEE_SYNC_FROM_SLOT")
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0),
        })
    }
}
