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

    /// Market base mint (32 bytes). Order intake verifies ASK-side note
    /// openings against this. From `NYX_TEE_BASE_MINT` (base58); defaults
    /// to a deterministic placeholder so dev/loadgen behaviour is
    /// unchanged when unset. For a REAL settle it MUST equal the on-chain
    /// mint the deposited notes use (else intake rejects the opening on a
    /// mint mismatch).
    pub base_mint: [u8; 32],
    /// Market quote mint (32 bytes). BID-side openings verify against
    /// this. From `NYX_TEE_QUOTE_MINT` (base58).
    pub quote_mint: [u8; 32],
    /// Price tick. `NYX_TEE_TICK_SIZE`, default 1.
    pub tick_size: u64,
    /// Minimum order size. `NYX_TEE_MIN_ORDER_SIZE`, default 0.
    pub min_order_size: u64,
    /// On-chain address of the STATIC settle ALT (the one devnet-setup
    /// creates holding `vault_config`, `instructions_sysvar`,
    /// `system_program` — see SDK `static_alt_addresses()`). From
    /// `NYX_TEE_SETTLE_LOOKUP_TABLE` (base58). When set, the settle
    /// worker stacks it UNDER the per-batch ALT so the v0 settle tx
    /// stays under Solana's 1232-byte cap; without it the tx is ~93 B
    /// larger and overflows on the real-mint settle path. Unset → the
    /// worker uses only the per-batch ALT (fine for the smaller test
    /// payloads, NOT for a real settle).
    pub settle_lookup_table: Option<[u8; 32]>,
}

/// The placeholder base mint used when `NYX_TEE_BASE_MINT` is unset —
/// matches the historical hardcoded dev value (`[1, 0…, 0xb1]`).
fn default_base_mint() -> [u8; 32] {
    let mut m = [0u8; 32];
    m[0] = 1;
    m[31] = 0xb1;
    m
}

fn default_quote_mint() -> [u8; 32] {
    let mut m = [0u8; 32];
    m[0] = 1;
    m[31] = 0x9e;
    m
}

/// Parse a 32-byte mint from a base58 env var, falling back to
/// `default` when unset/empty/malformed.
fn parse_mint_env(var: &str, default: [u8; 32]) -> [u8; 32] {
    match std::env::var(var) {
        Ok(s) if !s.trim().is_empty() => match bs58::decode(s.trim()).into_vec() {
            Ok(b) if b.len() == 32 => {
                let mut m = [0u8; 32];
                m.copy_from_slice(&b);
                m
            }
            _ => {
                tracing::warn!(var, "invalid mint env (need 32-byte base58); using default");
                default
            }
        },
        _ => default,
    }
}

/// Parse an optional 32-byte pubkey from a base58 env var. Returns
/// `None` when unset/empty/malformed (logging a warn on malformed).
fn parse_pubkey_env(var: &str) -> Option<[u8; 32]> {
    let s = std::env::var(var).ok()?;
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    match bs58::decode(s).into_vec() {
        Ok(b) if b.len() == 32 => {
            let mut k = [0u8; 32];
            k.copy_from_slice(&b);
            Some(k)
        }
        _ => {
            tracing::warn!(var, "invalid pubkey env (need 32-byte base58); ignoring");
            None
        }
    }
}

fn parse_u64_env(var: &str, default: u64) -> u64 {
    std::env::var(var)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(default)
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
            base_mint: parse_mint_env("NYX_TEE_BASE_MINT", default_base_mint()),
            quote_mint: parse_mint_env("NYX_TEE_QUOTE_MINT", default_quote_mint()),
            tick_size: parse_u64_env("NYX_TEE_TICK_SIZE", 1),
            min_order_size: parse_u64_env("NYX_TEE_MIN_ORDER_SIZE", 0),
            settle_lookup_table: parse_pubkey_env("NYX_TEE_SETTLE_LOOKUP_TABLE"),
        })
    }
}
